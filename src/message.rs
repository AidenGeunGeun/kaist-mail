//! One message as `list` and `search` show it: Dooray's list item, which
//! costs about 2 KB of JSON, reduced to a row of a few short fields.

use serde::{Deserialize, Serialize};

use crate::{error::AppError, time};

/// A message item as Dooray lists it (`contents[]` of a list, `mailMap` of a search).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Item {
    id: String,
    created_at: String,
    #[serde(default)]
    subject: Option<String>,
    #[serde(default)]
    file_count: u32,
    mail_summary: MailSummary,
    users: Users,
    #[serde(default)]
    folder_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MailSummary {
    flags: Flags,
    #[serde(default)]
    preview_text: Option<String>,
}

#[derive(Deserialize)]
struct Flags {
    read: bool,
    favorite: bool,
}

#[derive(Deserialize)]
struct Users {
    #[serde(default)]
    from: Option<Address>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Address {
    #[serde(default)]
    email_user: Option<EmailUser>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EmailUser {
    #[serde(default)]
    name: Option<String>,
    email_address: String,
}

/// A message row. Flags appear only when true, `files` only when nonzero.
#[derive(Serialize)]
pub struct Summary {
    pub id: String,
    /// Received time, RFC 3339 with the offset Dooray reports.
    pub at: String,
    pub from: String,
    pub subject: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub unread: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub favorite: bool,
    #[serde(skip_serializing_if = "is_zero")]
    pub files: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub folder: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview: Option<String>,
    /// `at` in Unix seconds, the order continuation keys on.
    #[serde(skip)]
    pub time: i64,
}

fn is_zero(value: &u32) -> bool {
    *value == 0
}

impl Item {
    pub fn folder_id(&self) -> Option<&str> {
        self.folder_id.as_deref()
    }

    /// The row, with `folder` named by the caller and the preview kept on request.
    pub fn summary(self, folder: Option<String>, preview: bool) -> Result<Summary, AppError> {
        let time = time::parse_rfc3339(&self.created_at).ok_or_else(|| {
            AppError::shape("Dooray listed a message without an RFC 3339 received time")
        })?;
        let from = match self.users.from.and_then(|from| from.email_user) {
            Some(EmailUser {
                name: Some(name),
                email_address,
            }) if !name.trim().is_empty() && name != email_address => {
                format!("{} <{email_address}>", name.trim())
            }
            Some(user) => user.email_address,
            None => String::new(),
        };
        Ok(Summary {
            id: self.id,
            at: self.created_at,
            from,
            subject: self.subject.unwrap_or_default(),
            unread: !self.mail_summary.flags.read,
            favorite: self.mail_summary.flags.favorite,
            files: self.file_count,
            folder,
            preview: self
                .mail_summary
                .preview_text
                .filter(|_| preview)
                .map(|text| one_line(&text)),
            time,
        })
    }
}

fn one_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Tab-separated rows for people: received time to the minute, sender name,
/// flags (U unread, F favorite, A attachments).
pub fn table(rows: &[Summary]) -> String {
    let folders = rows.iter().any(|row| row.folder.is_some());
    let header = match folders {
        true => "ID\tRECEIVED\tFLAGS\tFOLDER\tFROM\tSUBJECT",
        false => "ID\tRECEIVED\tFLAGS\tFROM\tSUBJECT",
    };
    let mut lines = vec![header.to_owned()];
    for row in rows {
        let flags: String = [(row.unread, 'U'), (row.favorite, 'F'), (row.files > 0, 'A')]
            .into_iter()
            .filter_map(|(set, flag)| set.then_some(flag))
            .collect();
        let sender = row.from.split(" <").next().unwrap_or_default();
        let mut cells = vec![
            row.id.clone(),
            row.at.get(..16).unwrap_or(&row.at).replace('T', " "),
            if flags.is_empty() { "-".into() } else { flags },
        ];
        cells.extend(row.folder.as_deref().map(one_line));
        cells.extend([one_line(sender), one_line(&row.subject)]);
        lines.push(cells.join("\t"));
        if let Some(preview) = &row.preview {
            lines.push(format!("\t{preview}"));
        }
    }
    lines.join("\n")
}
