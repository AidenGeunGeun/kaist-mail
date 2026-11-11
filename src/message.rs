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
    sent_at: Option<String>,
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

/// A person as Dooray names one in any message field.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailUser {
    #[serde(default)]
    name: Option<String>,
    email_address: String,
}

impl EmailUser {
    /// `Name <address>`, or the bare address when the name is blank or repeats it.
    pub fn label(&self) -> String {
        let name = self.name.as_deref().map(str::trim).unwrap_or_default();
        if name.is_empty() || name == self.email_address {
            self.email_address.clone()
        } else {
            format!("{name} <{}>", self.email_address)
        }
    }
}

/// A message row. Flags appear only when true, `files` only when nonzero.
#[derive(Serialize)]
pub struct Summary {
    pub id: String,
    /// Received time, RFC 3339 with the offset Dooray reports.
    at: String,
    from: String,
    subject: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    unread: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    favorite: bool,
    #[serde(skip_serializing_if = "is_zero")]
    files: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    folder: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    preview: Option<String>,
    /// Unix seconds of the time the query orders by, which continuation keys on.
    #[serde(skip)]
    pub time: i64,
}

/// The time Dooray orders a query by: `list` by received time, `search` by
/// sent time (the Date header), falling back to received time without one.
#[derive(Clone, Copy)]
pub enum Order {
    Received,
    Sent,
}

fn is_zero(value: &u32) -> bool {
    *value == 0
}

impl Item {
    pub fn folder_id(&self) -> Option<&str> {
        self.folder_id.as_deref()
    }

    /// The row, with `folder` named by the caller and the preview kept on request.
    pub fn summary(
        self,
        order: Order,
        folder: Option<String>,
        preview: bool,
    ) -> Result<Summary, AppError> {
        let key = match (order, &self.mail_summary.sent_at) {
            (Order::Sent, Some(sent)) => sent,
            _ => &self.created_at,
        };
        let time = time::parse_rfc3339(key)
            .ok_or_else(|| AppError::shape("Dooray listed a message without an RFC 3339 time"))?;
        let from = self
            .users
            .from
            .and_then(|from| from.email_user)
            .map(|user| user.label())
            .unwrap_or_default();
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

#[cfg(test)]
mod tests {
    use super::EmailUser;

    #[test]
    fn labels_drop_blank_or_repeated_names() {
        for (name, label) in [
            (Some(" "), "x@example.test"),
            (None, "x@example.test"),
            (Some("x@example.test"), "x@example.test"),
            (Some(" 학사팀 "), "학사팀 <x@example.test>"),
        ] {
            let user = EmailUser {
                name: name.map(str::to_owned),
                email_address: "x@example.test".into(),
            };
            assert_eq!(user.label(), label, "{name:?}");
        }
    }
}
