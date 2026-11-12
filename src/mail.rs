//! One message as an agent reads it: the detail fetch, which marks the
//! message read, its headers and attachments, and a window of its text.

use std::{fmt, str::FromStr};

use icu_normalizer::ComposingNormalizerBorrowed;
use serde::{Deserialize, Serialize};

use crate::{
    cli::ReadArgs,
    client::Client,
    error::AppError,
    html_text,
    message::EmailUser,
    output::{self, CommandResult},
};

/// Recipients listed per field unless `--recipients` asks for all.
const SHORT_RECIPIENTS: usize = 3;

/// A Dooray mail id: the decimal string `list` and `search` print. Being
/// digits only, it is safe to place in a request path.
#[derive(Clone)]
pub struct MailId(String);

impl FromStr for MailId {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, String> {
        match !value.is_empty() && value.len() <= 32 && value.bytes().all(|b| b.is_ascii_digit()) {
            true => Ok(Self(value.to_owned())),
            false => Err("a mail id is the string of digits that `list` prints".into()),
        }
    }
}

impl fmt::Display for MailId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Deserialize)]
struct DetailPage {
    content: Detail,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Detail {
    subject: String,
    mail: Mail,
    users: Users,
    body: Body,
    #[serde(default)]
    pub file_list: Vec<Attachment>,
}

impl Detail {
    /// Whether the fetch that returned this detail marked the message read:
    /// Dooray's flag reports the state from before the fetch.
    pub fn marked_read(&self) -> bool {
        !self.mail.flags.read
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Mail {
    sent_at: Option<String>,
    flags: Flags,
}

#[derive(Deserialize)]
struct Flags {
    read: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Users {
    from: Option<User>,
    #[serde(default)]
    to: Vec<User>,
    #[serde(default)]
    cc: Vec<User>,
    #[serde(default)]
    bcc: Vec<User>,
    #[serde(default)]
    reply_to: Vec<User>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct User {
    #[serde(rename = "type")]
    kind: String,
    email_user: Option<EmailUser>,
}

impl User {
    fn label(&self) -> String {
        match &self.email_user {
            Some(user) => user.label(),
            None => format!("({})", self.kind),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Body {
    mime_type: String,
    content: String,
}

/// An attachment as Dooray lists it. `part` is its stable reference within
/// the message; `download_url` never leaves the process.
#[derive(Deserialize, Serialize)]
pub struct Attachment {
    #[serde(rename(deserialize = "partNumber"))]
    pub part: u32,
    pub name: String,
    pub size: u64,
    #[serde(rename(deserialize = "mimeType"))]
    pub mime: String,
    #[serde(rename(deserialize = "downloadUrl"), skip_serializing)]
    pub download_url: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub deleted: bool,
}

/// GETs the message detail, which marks it read on Dooray's side.
pub fn fetch(client: &Client, id: &MailId) -> Result<Detail, AppError> {
    let page: DetailPage = client.wapi(&format!("/v2/wapi/mails/{id}?render=html"))?;
    Ok(page.content)
}

#[derive(Serialize)]
struct Reading<'a> {
    id: String,
    subject: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    from: Option<String>,
    to: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    cc: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    bcc: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    reply_to: Vec<String>,
    #[serde(skip_serializing_if = "is_zero")]
    more_recipients: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    date: Option<&'a str>,
    read: bool,
    marked_read: bool,
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    attachments: &'a [Attachment],
    body: Window,
}

#[derive(Serialize)]
struct Window {
    text: String,
    offset: usize,
    total_chars: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_offset: Option<usize>,
}

fn is_zero(value: &usize) -> bool {
    *value == 0
}

pub fn read(client: &Client, args: &ReadArgs) -> Result<CommandResult, AppError> {
    let detail = fetch(client, &args.id)?;
    let text = match detail.body.mime_type.as_str() {
        "text/html" => html_text::to_text(&detail.body.content)?,
        _ => detail.body.content.clone(),
    };
    // Composed, so `--find` matches what search matches.
    let text = ComposingNormalizerBorrowed::new_nfc().normalize(&text);
    let users = &detail.users;
    let limit = if args.recipients {
        usize::MAX
    } else {
        SHORT_RECIPIENTS
    };
    let mut more_recipients = 0;
    let mut list = |users: &[User]| {
        more_recipients += users.len().saturating_sub(limit);
        users
            .iter()
            .take(limit)
            .map(User::label)
            .collect::<Vec<_>>()
    };
    let reading = Reading {
        id: args.id.to_string(),
        subject: &detail.subject,
        from: users.from.as_ref().map(User::label),
        to: list(&users.to),
        cc: list(&users.cc),
        bcc: list(&users.bcc),
        reply_to: list(&users.reply_to),
        more_recipients,
        date: detail.mail.sent_at.as_deref(),
        read: true,
        marked_read: detail.marked_read(),
        attachments: &detail.file_list,
        body: window(&text, args),
    };
    let human = human(&reading, args.find.as_deref());
    output::result("read", &reading, human)
}

fn window(text: &str, args: &ReadArgs) -> Window {
    let chars: Vec<char> = text.chars().collect();
    let offset = match &args.find {
        Some(needle) => found(&chars, args.offset, needle, args.max_chars),
        None => args.offset,
    };
    let text: String = chars.iter().skip(offset).take(args.max_chars).collect();
    let end = offset.min(chars.len()) + text.chars().count();
    Window {
        text,
        offset,
        total_chars: chars.len(),
        next_offset: (end < chars.len()).then_some(end),
    }
}

/// Where a `--find` window starts: the line holding the first match of
/// `needle` at or after `from` (but not before `from`), or the match itself
/// when the match would not fit in `max_chars` from there; the end of the
/// text when nothing matches.
fn found(chars: &[char], from: usize, needle: &str, max_chars: usize) -> usize {
    let needle: Vec<char> = needle.chars().collect();
    let matches = |window: &[char]| {
        window
            .iter()
            .zip(&needle)
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
    };
    let Some(at) = chars.windows(needle.len()).skip(from).position(matches) else {
        return chars.len();
    };
    let at = from + at;
    let line = chars[..at]
        .iter()
        .rposition(|c| *c == '\n')
        .map_or(0, |newline| newline + 1);
    let start = line.max(from);
    if at + needle.len() - start <= max_chars {
        start
    } else {
        at
    }
}

fn human(reading: &Reading, find: Option<&str>) -> String {
    let mut lines = vec![format!("Subject: {}", reading.subject)];
    if let Some(from) = &reading.from {
        lines.push(format!("From: {from}"));
    }
    for (label, users) in [
        ("To", &reading.to),
        ("Cc", &reading.cc),
        ("Bcc", &reading.bcc),
        ("Reply-To", &reading.reply_to),
    ] {
        if !users.is_empty() {
            lines.push(format!("{label}: {}", users.join(", ")));
        }
    }
    if reading.more_recipients > 0 {
        lines.push(format!(
            "(+{} more recipients: --recipients lists all)",
            reading.more_recipients
        ));
    }
    if let Some(date) = reading.date {
        lines.push(format!("Date: {date}"));
    }
    if !reading.attachments.is_empty() {
        lines.push("Attachments (PART  BYTES  TYPE  NAME):".into());
        for file in reading.attachments {
            let deleted = if file.deleted { "  (deleted)" } else { "" };
            lines.push(format!(
                "  {}  {}  {}  {}{deleted}",
                file.part, file.size, file.mime, file.name
            ));
        }
    }
    if reading.marked_read {
        lines.push("(marked read)".into());
    }
    lines.push(String::new());
    lines.push(reading.body.text.clone());
    if let Some(needle) = find.filter(|_| reading.body.text.is_empty()) {
        lines.push(format!("[no match for `{needle}` at or after --offset]"));
    }
    if let Some(next) = reading.body.next_offset {
        lines.push(format!(
            "\n[characters {}-{next} of {}; more: kaist-mail read {} --offset {next}]",
            reading.body.offset, reading.body.total_chars, reading.id
        ));
    }
    lines.join("\n")
}
