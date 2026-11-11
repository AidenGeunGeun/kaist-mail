//! `list` and `search`: Dooray mail queries reduced to thin rows, with cursors
//! that continue after the last message shown even when messages arrived or
//! left the result (read, moved) in between.

use std::{collections::HashMap, fmt, str::FromStr};

use icu_normalizer::ComposingNormalizerBorrowed;
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::{
    cli::{PageArgs, SearchArgs},
    client::Client,
    error::AppError,
    message::{self, Item, Summary},
    output::{self, CommandResult, ListMeta},
    time,
};

/// Dooray counts at most this many search hits and returns no page past them.
const SEARCH_CAP: u64 = 2000;
/// Rows read per call while looking for a cursor's place in a changed list.
const STEP: u64 = 100;
/// Dooray calls one page may take before the cursor is declared too stale.
const MAX_CALLS: u64 = 10;

/// Where a query looks: a system folder by its stable name, or any folder by id.
#[derive(Clone)]
pub enum Folder {
    Name(String),
    Id(String),
}

impl FromStr for Folder {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, String> {
        const NAMES: [&str; 6] = ["inbox", "sent", "draft", "archive", "spam", "trash"];
        if NAMES.contains(&value) {
            Ok(Self::Name(value.to_owned()))
        } else if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
            Ok(Self::Id(value.to_owned()))
        } else {
            Err(format!(
                "expected {} or a folder id from `kaist-mail folders`",
                NAMES.join(", ")
            ))
        }
    }
}

/// A search term in NFC (Dooray matches nothing for decomposed Hangul) and
/// under Dooray's length limit, which it reports as error -13207002.
pub fn term(value: &str) -> Result<String, String> {
    let term = ComposingNormalizerBorrowed::new_nfc()
        .normalize(value.trim())
        .into_owned();
    match term.chars().count() {
        0 => Err("search terms must not be empty".into()),
        100.. => Err("Dooray accepts search terms of at most 99 characters".into()),
        _ => Ok(term),
    }
}

/// A position in a newest-first message order: just after the message
/// received at `time` whose id is last in `seen`. `seen` lists every message
/// shown at that second, so equal timestamps neither repeat nor vanish;
/// `offset` is where the next message stood, a hint for page-number paging.
#[derive(Clone)]
pub struct Cursor {
    offset: u64,
    time: i64,
    seen: Vec<String>,
}

impl Cursor {
    fn follows(&self, row: &Summary) -> bool {
        row.time < self.time || (row.time == self.time && !self.seen.contains(&row.id))
    }

    /// The cursor after `rows`, the last of which stood at `offset - 1`.
    fn after(rows: &[Summary], offset: u64, previous: Option<&Cursor>) -> Option<Self> {
        let time = rows.last()?.time;
        let carried = previous.filter(|cursor| cursor.time == time);
        let seen = carried
            .into_iter()
            .flat_map(|cursor| cursor.seen.iter().cloned())
            .chain(
                rows.iter()
                    .filter(|row| row.time == time)
                    .map(|row| row.id.clone()),
            )
            .collect();
        Some(Self { offset, time, seen })
    }
}

impl fmt::Display for Cursor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.offset, self.time, self.seen.join("."))
    }
}

impl FromStr for Cursor {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, String> {
        let invalid = || "not a cursor from this command's meta.next_cursor".to_owned();
        let mut parts = value.split('.');
        let offset = parts.next().and_then(|part| part.parse().ok());
        let time = parts.next().and_then(|part| part.parse().ok());
        let seen: Vec<String> = parts.map(str::to_owned).collect();
        let ids = !seen.is_empty()
            && seen
                .iter()
                .all(|id| !id.is_empty() && id.bytes().all(|byte| byte.is_ascii_digit()));
        match (offset, time) {
            (Some(offset), Some(time)) if ids => Ok(Self { offset, time, seen }),
            _ => Err(invalid()),
        }
    }
}

struct Page {
    rows: Vec<Summary>,
    /// The query's match count, when this call learned it.
    total: Option<u64>,
    next: Option<Cursor>,
}

type Fetched = (Vec<Summary>, u64);

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Listed {
    total_count: u64,
    contents: Vec<Item>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Found {
    total_count: u64,
    contents: Vec<Hit>,
    references: References,
}

#[derive(Deserialize)]
struct Hit {
    id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct References {
    #[serde(default)]
    mail_map: HashMap<String, Item>,
    #[serde(default)]
    folder_map: HashMap<String, FolderRef>,
}

#[derive(Deserialize)]
struct FolderRef {
    name: String,
}

pub fn list(client: &Client, args: &PageArgs) -> Result<CommandResult, AppError> {
    let mut fixed: Vec<(&str, String)> = vec![
        match &args.folder {
            Some(Folder::Id(id)) => ("folderId", id.clone()),
            Some(Folder::Name(name)) => ("folderName", name.clone()),
            None => ("folderName", "inbox".into()),
        },
        ("view", "timeline".into()),
        ("order", "-createdAt".into()),
        ("preview", args.preview.to_string()),
    ];
    for (set, key, value) in [
        (args.unread, "read", "false"),
        (args.favorited, "favorited", "true"),
        (args.attachments, "hasAttachment", "true"),
    ] {
        if set {
            fixed.push((key, value.into()));
        }
    }
    let fetch = |page: u64, size: u64| -> Result<Fetched, AppError> {
        let paging = [("page", page.to_string()), ("size", size.to_string())];
        let query = crate::url::form_urlencode(
            fixed
                .iter()
                .chain(&paging)
                .map(|(key, value)| (*key, value.as_str())),
        );
        let listed: Listed = client.wapi(&format!("/v2/wapi/mails?{query}"))?;
        let rows = listed
            .contents
            .into_iter()
            .map(|item| item.summary(None, args.preview))
            .collect::<Result<_, _>>()?;
        Ok((rows, listed.total_count))
    };
    let page = list_page(fetch, args.limit, args.cursor.as_ref())?;
    render("list", page, false)
}

/// One page of a newest-first list that Dooray pages by number. With a
/// cursor, the call that reads the cursor's old position also reads the
/// message before it, so an unchanged list costs one call; when that message
/// left (the cursor stands too far) or new mail arrived (too near), the
/// page is found by reading on in steps.
fn list_page(
    mut fetch: impl FnMut(u64, u64) -> Result<Fetched, AppError>,
    limit: u64,
    cursor: Option<&Cursor>,
) -> Result<Page, AppError> {
    let follows = |row: &Summary| cursor.is_none_or(|cursor| cursor.follows(row));
    let mut calls = 0;
    let mut range = |start: u64, len: u64| -> Result<Fetched, AppError> {
        calls += 1;
        if calls > MAX_CALLS {
            return Err(stale_cursor());
        }
        let size = (len..)
            .find(|size| start / size == (start + len - 1) / size)
            .expect("a page as large as start + len holds the range");
        let page = start / size;
        let (rows, total) = fetch(page, size)?;
        let skip = (start - page * size) as usize;
        Ok((
            rows.into_iter().skip(skip).take(len as usize).collect(),
            total,
        ))
    };
    let mut start = cursor.map_or(0, |cursor| cursor.offset.saturating_sub(1));
    let (mut rows, mut total) = range(start, limit + u64::from(cursor.is_some()))?;
    start = start.min(total);
    while cursor.is_some() && start > 0 && rows.first().is_none_or(follows) {
        let from = start.saturating_sub(STEP);
        let (mut earlier, count) = range(from, start - from)?;
        earlier.append(&mut rows);
        (rows, total, start) = (earlier, count, from);
    }
    let mut end = start + rows.len() as u64;
    while (rows.iter().filter(|row| follows(row)).count() as u64) < limit && end < total {
        let (more, count) = range(end, STEP)?;
        if more.is_empty() {
            break;
        }
        end += more.len() as u64;
        total = count;
        rows.extend(more);
    }
    let mut shown = std::collections::HashSet::new();
    let mut fresh: Vec<(Summary, u64)> = rows
        .into_iter()
        .zip(start..)
        .filter(|(row, _)| follows(row) && shown.insert(row.id.clone()))
        .collect();
    let more = fresh.len() as u64 > limit || end < total;
    fresh.truncate(limit as usize);
    let offset = fresh.last().map_or(0, |(_, position)| position + 1);
    let rows: Vec<Summary> = fresh.into_iter().map(|(row, _)| row).collect();
    Ok(Page {
        next: Cursor::after(&rows, offset, cursor).filter(|_| more),
        rows,
        total: Some(total),
    })
}

pub fn search(client: &Client, args: &SearchArgs) -> Result<CommandResult, AppError> {
    let PageArgs {
        folder,
        unread,
        favorited,
        attachments,
        limit,
        preview,
        cursor,
    } = &args.page;
    let mut body = Map::new();
    for (key, values) in [
        ("all", &args.terms),
        ("subjects", &args.subject),
        ("bodies", &args.body),
        ("fileNames", &args.file),
        ("fromList", &args.from),
        ("toList", &args.to),
        ("ccList", &args.cc),
    ] {
        if !values.is_empty() {
            body.insert(key.into(), json!(values));
        }
    }
    if body.is_empty() && args.since.is_none() && args.before.is_none() {
        return Err(
            AppError::usage("search needs a term, a field filter, --since or --before").with_hint(
                "For unread, favorited or attachment filters alone use `kaist-mail list`.",
            ),
        );
    }
    if let (Some(since), Some(before)) = (args.since, args.before) {
        if since >= before {
            return Err(AppError::usage("--since must be earlier than --before"));
        }
    }
    let (scope, value) = match folder {
        Some(Folder::Name(name)) => ("folderNames", json!([name])),
        Some(Folder::Id(id)) => ("folderIds", json!([id])),
        None => ("exceptFolders", json!(["spam", "trash"])),
    };
    body.insert(scope.into(), value);
    for (set, key, value) in [
        (*unread, "seenFlag", false),
        (*favorited, "favoritedFlag", true),
        (*attachments, "attachedFlag", true),
    ] {
        if set {
            body.insert(key.into(), value.into());
        }
    }
    if let Some(since) = args.since {
        body.insert("since".into(), time::format_korea(since).into());
    }
    body.insert("order".into(), "-createdAt".into());
    let path = format!("/v2/wapi/mails/search?preview={preview}");
    let fetch = |before: Option<i64>, page: u64, size: u64| -> Result<Fetched, AppError> {
        let mut body = body.clone();
        if let Some(before) = before {
            body.insert("before".into(), time::format_korea(before).into());
        }
        body.insert("page".into(), page.into());
        body.insert("size".into(), size.into());
        let mut found: Found = client.wapi_post(&path, &Value::Object(body))?;
        let rows = found
            .contents
            .iter()
            .map(|hit| {
                let item = found.references.mail_map.remove(&hit.id).ok_or_else(|| {
                    AppError::shape("Dooray search hit has no entry in references.mailMap")
                })?;
                let folder = folder.is_none().then(|| {
                    let id = item.folder_id().unwrap_or_default();
                    found
                        .references
                        .folder_map
                        .get(id)
                        .map_or_else(|| id.to_owned(), |folder| folder.name.clone())
                });
                item.summary(folder, *preview)
            })
            .collect::<Result<_, _>>()?;
        Ok((rows, found.total_count))
    };
    let page = search_page(fetch, *limit, cursor.as_ref(), args.before)?;
    let capped = page.total.is_some_and(|total| total >= SEARCH_CAP);
    render("search", page, capped)
}

/// One page of a newest-first search. Each continuation searches again
/// with `before` just past the cursor's second, from Dooray's first page, so
/// no page lies past Dooray's 2000-hit cap and messages that left the
/// result in between move nothing.
fn search_page(
    mut fetch: impl FnMut(Option<i64>, u64, u64) -> Result<Fetched, AppError>,
    limit: u64,
    cursor: Option<&Cursor>,
    before: Option<i64>,
) -> Result<Page, AppError> {
    let follows = |row: &Summary| cursor.is_none_or(|cursor| cursor.follows(row));
    let before = match (cursor, before) {
        (Some(cursor), Some(before)) => Some(before.min(cursor.time + 1)),
        (Some(cursor), None) => Some(cursor.time + 1),
        (None, before) => before,
    };
    // Messages already shown at the cursor's second come back first.
    let size = limit + cursor.map_or(0, |cursor| cursor.seen.len() as u64);
    let (mut fresh, mut consumed, mut first_total, mut total) = (Vec::new(), 0, None, 0);
    for page in 0.. {
        if page == MAX_CALLS {
            return Err(stale_cursor());
        }
        let rows;
        (rows, total) = fetch(before, page, size)?;
        if rows.windows(2).any(|pair| pair[1].time > pair[0].time) {
            return Err(AppError::shape(
                "Dooray search results are not ordered by received time",
            ));
        }
        first_total.get_or_insert(total);
        consumed += rows.len() as u64;
        let full = rows.len() as u64 == size;
        fresh.extend(rows.into_iter().filter(follows));
        if fresh.len() as u64 >= limit || !full || consumed >= total {
            break;
        }
    }
    let more = fresh.len() as u64 > limit || consumed < total;
    fresh.truncate(limit as usize);
    let offset = cursor.map_or(0, |cursor| cursor.offset) + fresh.len() as u64;
    Ok(Page {
        next: Cursor::after(&fresh, offset, cursor).filter(|_| more),
        rows: fresh,
        total: first_total.filter(|_| cursor.is_none()),
    })
}

fn stale_cursor() -> AppError {
    AppError::limit("the mailbox changed too much since this cursor was issued")
        .with_hint("Run the command again without --cursor to start from the newest message.")
}

fn render(command: &'static str, page: Page, capped: bool) -> Result<CommandResult, AppError> {
    let returned = page.rows.len();
    let mut human = match returned {
        0 => "No messages found.".to_owned(),
        _ => message::table(&page.rows),
    };
    if returned > 0 || page.next.is_some() {
        let total = match page.total {
            Some(total) => format!(" of {total}{}", if capped { "+" } else { "" }),
            None => String::new(),
        };
        human.push_str(&format!("\n{returned}{total} shown"));
        if let Some(next) = &page.next {
            human.push_str(&format!("; more: --cursor {next}"));
        }
    }
    let mut result = output::result(command, &page.rows, human)?;
    result.meta = Some(ListMeta {
        returned,
        total: page.total,
        total_capped: capped,
        next_cursor: page.next.map(|cursor| cursor.to_string()),
    });
    Ok(result)
}
