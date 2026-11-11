//! Owner-only files, their no-overwrite publication, and XDG base directories.
use std::{
    fs::{self, File, Metadata, OpenOptions},
    io::{self, ErrorKind},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::error::AppError;

pub(crate) fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

pub(crate) fn xdg_home(name: &str, home: Option<&Path>, fallback: &str) -> Option<PathBuf> {
    env_path(name).or_else(|| home.map(|home| home.join(fallback)))
}

/// Write-only options that create files with mode 0600 on Unix.
pub(crate) fn private_file_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.write(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options
}

const TEMPORARY_PREFIX: &str = ".kaist-mail-";
const TEMPORARY_SUFFIX: &str = ".part";
/// Longer than any transfer may run (`--max-seconds` stops at a day).
const STALE_AFTER: Duration = Duration::from_secs(48 * 60 * 60);

/// The error for a destination, shown as `label`, that is already taken.
pub(crate) fn exists(label: &str) -> AppError {
    AppError::config(format!(
        "{label} already exists; kaist-mail never overwrites"
    ))
}

/// Creates `destination` as a new 0600 file and never replaces an existing
/// one; messages show it as `label`. `fill` writes, and may read back, a
/// hidden temporary beside it, which is hard-linked into place, or copied
/// where the filesystem has no hard links, so a failed or interrupted
/// transfer never leaves a partial file under the real name. Returns
/// `fill`'s value and warnings for the user.
pub(crate) fn publish_new<T>(
    destination: &Path,
    label: &str,
    fill: impl FnOnce(&mut File) -> Result<T, AppError>,
) -> Result<(T, Vec<String>), AppError> {
    let parent = match destination.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let temporary = parent.join(temporary_name());
    let mut file = private_file_options()
        .read(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|error| {
            AppError::config(format!(
                "cannot create a file in {}: {error}",
                parent.display()
            ))
        })?;
    if let Ok(own) = file.metadata() {
        sweep_stale(parent, &own);
    }
    let filled = fill(&mut file).and_then(|value| {
        file.sync_all()
            .map(|()| value)
            .map_err(|error| AppError::config(format!("cannot write {label}: {error}")))
    });
    drop(file);
    let value = match filled {
        Ok(value) => value,
        Err(error) => {
            let _ = fs::remove_file(&temporary);
            return Err(error);
        }
    };
    let mut warnings = Vec::new();
    let published = match fs::hard_link(&temporary, destination) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::AlreadyExists => Err(exists(label)),
        Err(_) => match copy_new(&temporary, destination) {
            Ok(true) => Err(exists(label)),
            Ok(false) => {
                warnings.push(format!(
                    "{label} was copied into place because its filesystem has no hard links"
                ));
                Ok(())
            }
            Err(error) => Err(AppError::config(format!("cannot create {label}: {error}"))),
        },
    };
    if let Err(error) = fs::remove_file(&temporary) {
        warnings.push(format!("could not remove {}: {error}", temporary.display()));
    }
    published.map(|()| (value, warnings))
}

/// Link-less publication: `Ok(true)` when `destination` already exists. What
/// this call created is removed again on any failure.
fn copy_new(temporary: &Path, destination: &Path) -> io::Result<bool> {
    let mut copy = match private_file_options().create_new(true).open(destination) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::AlreadyExists => return Ok(true),
        Err(error) => return Err(error),
    };
    let written = File::open(temporary)
        .and_then(|mut source| io::copy(&mut source, &mut copy))
        .and_then(|_| copy.sync_all());
    if let Err(error) = written {
        drop(copy);
        let _ = fs::remove_file(destination);
        return Err(error);
    }
    Ok(false)
}

fn temporary_name() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.subsec_nanos());
    format!(
        "{TEMPORARY_PREFIX}{}-{nanos:x}{TEMPORARY_SUFFIX}",
        std::process::id()
    )
}

/// Removes temporaries that interrupted runs of this user left in `parent`.
fn sweep_stale(parent: &Path, own: &Metadata) {
    let Ok(entries) = fs::read_dir(parent) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let ours = name.to_str().is_some_and(|name| {
            name.strip_prefix(TEMPORARY_PREFIX)
                .and_then(|rest| rest.strip_suffix(TEMPORARY_SUFFIX))
                .and_then(|rest| rest.split_once('-'))
                .is_some_and(|(pid, nanos)| {
                    pid.parse::<u32>().is_ok() && u32::from_str_radix(nanos, 16).is_ok()
                })
        });
        let stale = |meta: &Metadata| {
            meta.is_file()
                && meta.uid() == own.uid()
                && meta
                    .modified()
                    .ok()
                    .and_then(|modified| modified.elapsed().ok())
                    .is_some_and(|age| age > STALE_AFTER)
        };
        if ours && entry.metadata().is_ok_and(|meta| stale(&meta)) {
            let _ = fs::remove_file(entry.path());
        }
    }
}
