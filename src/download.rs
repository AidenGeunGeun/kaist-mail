//! Saving a message's attachments, or the whole message as `.eml`, to new
//! private files.

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

use serde::Serialize;
use serde_json::json;

use crate::{
    client::{Client, Limits, Size},
    error::AppError,
    mail::{self, Attachment, MailId},
    output::{self, CommandResult},
    private_fs,
};

/// Bounds a raw message, whose size Dooray states only in the detail.
const MAX_EML: u64 = 1 << 30;
/// Common filesystems cap a name at 255 bytes.
const MAX_NAME_BYTES: usize = 255;

#[derive(Serialize)]
struct Saved {
    part: u32,
    path: String,
    bytes: u64,
}

#[derive(Serialize)]
struct Downloads {
    id: String,
    marked_read: bool,
    files: Vec<Saved>,
}

/// Downloads the attachments in `parts` (all when empty). Finding them
/// fetches the message detail, which marks it read.
pub fn attachments(
    client: &Client,
    id: &MailId,
    parts: &[u32],
    out: &Path,
    limits: Limits,
) -> Result<CommandResult, AppError> {
    if !out.is_dir() {
        check_free(out, &out.display().to_string())?;
    }
    let detail = mail::fetch(client, id)?;
    let mut warnings = Vec::new();
    let mut chosen: Vec<&Attachment> = Vec::new();
    for part in parts {
        let file = detail
            .file_list
            .iter()
            .find(|file| file.part == *part)
            .ok_or_else(|| {
                AppError::not_found(format!("message {id} has no attachment part {part}"))
                    .with_hint(format!("`kaist-mail read {id}` lists its attachments"))
            })?;
        if file.deleted {
            return Err(AppError::not_found(format!(
                "attachment part {part} was deleted from Dooray"
            )));
        }
        chosen.push(file);
    }
    if parts.is_empty() {
        for file in &detail.file_list {
            match file.deleted {
                true => warnings.push(format!("skipped part {}: deleted from Dooray", file.part)),
                false => chosen.push(file),
            }
        }
    }
    if chosen.is_empty() {
        return Err(AppError::not_found(format!(
            "message {id} has no attachments to download"
        )));
    }
    // Errors name the part and the user's --out, never Dooray's file name.
    let shown = out.display();
    let targets: Vec<(&Attachment, PathBuf, String)> = match out.is_dir() {
        true => chosen
            .iter()
            .map(|file| {
                let path = out.join(file_name(&file.name, file.part));
                (*file, path, format!("part {} in {shown}", file.part))
            })
            .collect(),
        false if chosen.len() == 1 => vec![(chosen[0], out.to_path_buf(), shown.to_string())],
        false => {
            return Err(AppError::usage(format!(
                "--out must be an existing directory for {} attachments",
                chosen.len()
            )));
        }
    };
    let mut seen = HashMap::new();
    for (file, path, label) in &targets {
        let key = path
            .file_name()
            .map(|name| same_file_key(&name.to_string_lossy()));
        if let Some(earlier) = seen.insert(key, file.part) {
            return Err(AppError::usage(format!(
                "parts {earlier} and {} would get the same file name in {shown}",
                file.part
            ))
            .with_hint("save them one at a time with --part and --out FILE"));
        }
        check_free(path, label)?;
    }
    let mut files = Vec::new();
    for (file, path, label) in &targets {
        let saved = private_fs::publish_new(path, label, |out| {
            let shown = format!("part {} of message {id}", file.part);
            client.download(
                &file.download_url,
                &shown,
                Size::Exact(file.size),
                limits,
                out,
            )
        });
        let ((bytes, retried), published) = match saved {
            Ok(saved) => saved,
            Err(error) => return Err(with_saved(error, &files)),
        };
        warnings.extend(retried.into_iter().chain(published));
        files.push(Saved {
            part: file.part,
            path: absolute(path),
            bytes,
        });
    }
    let human = files
        .iter()
        .map(|file| {
            format!(
                "Saved part {} ({} bytes) to {}",
                file.part, file.bytes, file.path
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let data = Downloads {
        id: id.to_string(),
        marked_read: detail.marked_read(),
        files,
    };
    let mut result = output::result("download", &data, human)?;
    result.warnings = warnings;
    Ok(result)
}

#[derive(Serialize)]
struct Export {
    id: String,
    path: String,
    bytes: u64,
}

/// Saves the message as Dooray stores it (RFC 5322 `.eml`). The raw message
/// endpoint leaves the read state alone.
pub fn eml(
    client: &Client,
    id: &MailId,
    out: &Path,
    limits: Limits,
) -> Result<CommandResult, AppError> {
    let path = match out.is_dir() {
        true => out.join(format!("{id}.eml")),
        false => out.to_path_buf(),
    };
    let label = path.display().to_string();
    check_free(&path, &label)?;
    let ((bytes, mut warnings), published) = private_fs::publish_new(&path, &label, |file| {
        client.download(
            &format!("/v2/wapi/mails/{id}?type=raw"),
            &format!("message {id}"),
            Size::AtMost(MAX_EML),
            limits,
            file,
        )
    })?;
    let export = Export {
        id: id.to_string(),
        path: absolute(&path),
        bytes,
    };
    let human = format!("Saved {} bytes to {}", export.bytes, export.path);
    warnings.extend(published);
    let mut result = output::result("export", &export, human)?;
    result.warnings = warnings;
    Ok(result)
}

/// Fails before any download when `path`, shown as `label`, is taken;
/// publication checks again.
fn check_free(path: &Path, label: &str) -> Result<(), AppError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(private_fs::exists(label)),
        Err(_) => Ok(()),
    }
}

/// Names that a case-insensitive, normalization-insensitive filesystem
/// (APFS, HFS+, NTFS) may store as one share a key: Unicode's compatibility
/// caseless match, NFKD(fold(NFKD(fold(NFD(name))))), which errs toward
/// treating names as the same.
fn same_file_key(name: &str) -> String {
    let fold = |text: &str| {
        icu_casemap::CaseMapper::new()
            .fold_string(text)
            .into_owned()
    };
    let nfd = icu_normalizer::DecomposingNormalizerBorrowed::new_nfd();
    let nfkd = icu_normalizer::DecomposingNormalizerBorrowed::new_nfkd();
    let once = nfkd.normalize(&fold(&nfd.normalize(name))).into_owned();
    nfkd.normalize(&fold(&once)).into_owned()
}

fn with_saved(error: AppError, files: &[Saved]) -> AppError {
    if files.is_empty() {
        return error;
    }
    let saved: Vec<u32> = files.iter().map(|file| file.part).collect();
    let mut details = error.details.clone().unwrap_or_else(|| json!({}));
    details["saved_parts"] = json!(saved);
    error.with_details(details)
}

fn absolute(path: &Path) -> String {
    fs::canonicalize(path)
        .unwrap_or_else(|_| PathBuf::from(path))
        .display()
        .to_string()
}

/// `name` as one safe file name: no path separators, control or bidi
/// characters, characters Windows or Finder reject, or leading dots, and at
/// most 255 bytes with the extension kept. Korean and other text stays.
fn file_name(name: &str, part: u32) -> String {
    let cleaned: String = crate::output::sanitize_terminal(name)
        .chars()
        .map(|c| match c {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            c if c.is_control() => '_',
            c => c,
        })
        .collect();
    let cleaned = cleaned.trim_matches(|c: char| c.is_whitespace() || c == '.');
    if cleaned.is_empty() {
        return format!("attachment-{part}");
    }
    if cleaned.len() <= MAX_NAME_BYTES {
        return cleaned.to_owned();
    }
    let extension = cleaned
        .rfind('.')
        .map(|dot| &cleaned[dot..])
        .filter(|extension| extension.len() <= 32)
        .unwrap_or("");
    let mut stem_end = MAX_NAME_BYTES - extension.len();
    while !cleaned.is_char_boundary(stem_end) {
        stem_end -= 1;
    }
    format!("{}{extension}", &cleaned[..stem_end])
}

#[cfg(test)]
mod tests {
    use super::file_name;

    #[test]
    fn attachment_names_become_one_safe_file_name_and_keep_korean() {
        let long = format!("{}.pdf", "가".repeat(100));
        for (name, expected) in [
            (
                "2026학년도 수강신청 안내.pdf",
                "2026학년도 수강신청 안내.pdf",
            ),
            ("../../.ssh/authorized_keys", "_.._.ssh_authorized_keys"),
            ("..", "attachment-3"),
            ("", "attachment-3"),
            (".bashrc", "bashrc"),
            ("invoice\u{202e}fdp.exe", "invoicefdp.exe"),
            ("a\nb\tc:d?.txt", "a_b_c_d_.txt"),
            (&long, &format!("{}.pdf", "가".repeat(83))),
        ] {
            let got = file_name(name, 3);
            assert_eq!(got, expected, "{name:?}");
            assert!(got.len() <= 255);
        }
    }
}
