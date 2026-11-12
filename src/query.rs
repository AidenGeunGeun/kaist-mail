//! `list` and `search`: Dooray mail queries reduced to thin rows, with cursors
//! that continue after the last message shown even when messages arrived or
//! left the result (read, moved) in between.

use std::{
    collections::{HashMap, HashSet},
    fmt,
    str::FromStr,
};

use icu_normalizer::ComposingNormalizerBorrowed;
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::{
    cli::{PageArgs, SearchArgs},
    client::Client,
    error::AppError,
    mail::MailId,
    message::{self, Item, Order, Summary},
    output::{self, CommandResult, ListMeta},
    time,
};

/// Dooray counts at most this many search hits and returns no page past them.
const SEARCH_CAP: u64 = 2000;
/// Rows one response may carry. Live list pages of 1000 and search pages
/// of 1000 arrived truncated (about 2 MB); 500 arrived whole.
const MAX_WINDOW: u64 = 500;
/// Dooray calls one page may take before the cursor is declared too stale.
const MAX_CALLS: u64 = 10;
/// Messages shown at one second of the order that a cursor can carry. Dooray
/// may order a second's messages differently on every response, so a cursor
/// inside one names every message of it already shown; past this many, the
/// query must be narrowed.
const MAX_SEEN: usize = 100;
/// Offsets past any mailbox, which keep page arithmetic small.
const MAX_OFFSET: u64 = 10_000_000;

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

/// Text to look for, trimmed and in NFC: Dooray matches nothing for
/// decomposed Hangul, and `read` shows bodies composed.
pub fn needle(value: &str) -> Result<String, String> {
    let needle = ComposingNormalizerBorrowed::new_nfc()
        .normalize(value.trim())
        .into_owned();
    if needle.is_empty() {
        return Err("the text to look for must not be empty".into());
    }
    Ok(needle)
}

/// A search term: a `needle` under Dooray's length limit, which it reports
/// as error -13207002.
pub fn term(value: &str) -> Result<String, String> {
    let term = needle(value)?;
    match term.chars().count() {
        100.. => Err("Dooray accepts search terms of at most 99 characters".into()),
        _ => Ok(term),
    }
}

/// A position in a newest-first message order: just after the messages
/// ordered at second `time` whose ids are in `seen`, which lists every
/// message of that second shown so far. `offset` is where the next message
/// stood, a hint for page-number paging.
#[derive(Clone)]
pub struct Cursor {
    offset: u64,
    time: i64,
    seen: Vec<String>,
}

impl Cursor {
    /// The cursor, if it keeps every request it leads to representable.
    fn new(offset: u64, time: i64, seen: Vec<String>) -> Option<Self> {
        let ids = (1..=MAX_SEEN).contains(&seen.len())
            && seen.iter().all(|id| id.parse::<MailId>().is_ok());
        (ids && offset <= MAX_OFFSET && time::RANGE.contains(&time)).then_some(Self {
            offset,
            time,
            seen,
        })
    }

    fn follows(&self, row: &Summary) -> bool {
        row.time < self.time || (row.time == self.time && !self.seen.contains(&row.id))
    }

    /// The cursor after `rows`, the last of which stood at `offset - 1`.
    fn after(
        rows: &[Summary],
        offset: u64,
        previous: Option<&Cursor>,
    ) -> Result<Option<Self>, AppError> {
        let Some(time) = rows.last().map(|row| row.time) else {
            return Ok(None);
        };
        let carried = previous.filter(|cursor| cursor.time == time);
        let seen = carried
            .into_iter()
            .flat_map(|cursor| cursor.seen.iter().cloned())
            .chain(
                rows.iter()
                    .filter(|row| row.time == time)
                    .map(|row| row.id.clone()),
            )
            .collect::<Vec<_>>();
        if seen.len() > MAX_SEEN {
            return Err(AppError::limit(format!(
                "more than {MAX_SEEN} messages share the time {}, past which kaist-mail cannot page reliably",
                time::format_korea(time)
            ))
            .with_hint("Narrow the query, for example with search --from, --subject or --before."));
        }
        Self::new(offset, time, seen)
            .map(Some)
            .ok_or_else(|| AppError::shape("Dooray listed a message id that is not a mail id"))
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
        let mut parts = value.split('.');
        let offset = parts.next().and_then(|part| part.parse().ok());
        let time = parts.next().and_then(|part| part.parse().ok());
        let seen = parts.map(str::to_owned).collect();
        offset
            .zip(time)
            .and_then(|(offset, time)| Self::new(offset, time, seen))
            .ok_or_else(|| "not a cursor from this command's meta.next_cursor".to_owned())
    }
}

/// One Dooray response: a run of a newest-first order, read as one snapshot.
/// Every decision about a tied second is made inside one window, because
/// Dooray may order a second's messages differently on the next response.
struct Window {
    rows: Vec<Summary>,
    /// Starts at the order's first message.
    top: bool,
    /// Reaches the order's last message.
    end: bool,
}

/// What one window shows after a cursor.
struct Selection {
    /// Up to `limit` rows with their index in the window.
    rows: Vec<(usize, Summary)>,
    /// Rows follow these, in this window or past its end.
    more: bool,
    /// The window ended before `limit` rows.
    short: bool,
    /// Rows leading the window that precede the cursor's second.
    newer: usize,
}

/// The rows after `cursor` in `window`, or `None` when the window starts
/// inside or after the cursor's second, so that part of it may lie earlier.
fn select(
    window: Window,
    cursor: Option<&Cursor>,
    limit: u64,
    wanted: impl Fn(&Summary) -> bool,
) -> Result<Option<Selection>, AppError> {
    if window
        .rows
        .windows(2)
        .any(|pair| pair[1].time > pair[0].time)
    {
        return Err(AppError::shape(
            "Dooray returned messages out of time order",
        ));
    }
    let newer = window
        .rows
        .iter()
        .take_while(|row| cursor.is_some_and(|cursor| row.time > cursor.time))
        .count();
    if !window.top && (cursor.is_none() || newer == 0) {
        return Ok(None);
    }
    let mut ids = HashSet::new();
    let mut rest = window.rows.into_iter().enumerate().filter(|(_, row)| {
        cursor.is_none_or(|cursor| cursor.follows(row)) && wanted(row) && ids.insert(row.id.clone())
    });
    let rows: Vec<_> = rest.by_ref().take(limit as usize).collect();
    let short = (rows.len() as u64) < limit && !window.end;
    let more = rest.next().is_some() || !window.end;
    Ok(Some(Selection {
        rows,
        more,
        short,
        newer,
    }))
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
struct Hit {
    id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Found {
    total_count: u64,
    contents: Vec<Hit>,
    /// Absent when nothing matched.
    #[serde(default)]
    references: References,
}

#[derive(Default, Deserialize)]
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
            .map(|item| item.summary(Order::Received, None, args.preview))
            .collect::<Result<_, _>>()?;
        Ok((rows, listed.total_count))
    };
    let page = list_page(fetch, args.limit, args.cursor.as_ref())?;
    render("list", page, false)
}

/// One page of a newest-first list that Dooray pages by number, taken from
/// one window that starts just before the cursor's second. The window is
/// placed by the cursor's offset, so an unchanged list costs one call; when
/// messages left or arrived, it moves earlier or later and is read again.
fn list_page(
    mut fetch: impl FnMut(u64, u64) -> Result<Fetched, AppError>,
    limit: u64,
    cursor: Option<&Cursor>,
) -> Result<Page, AppError> {
    let behind = cursor.map_or(0, |cursor| cursor.seen.len() as u64 + 1);
    let mut start = cursor.map_or(0, |cursor| cursor.offset.saturating_sub(behind));
    let (mut len, mut back) = (limit + behind, limit + behind);
    for _ in 0..MAX_CALLS {
        // One page of at most 2 * len - 1 rows holds any run of len rows.
        let size = (len..)
            .find(|size| start / size == (start + len - 1) / size)
            .expect("a page as large as start + len holds the range");
        let first = start / size * size;
        let (rows, total) = fetch(first / size, size)?;
        let end = first + rows.len() as u64 >= total || (rows.len() as u64) < size;
        let window = Window {
            rows,
            top: first == 0,
            end,
        };
        match select(window, cursor, limit, |_| true)? {
            None => {
                // Read earlier, still through where this window would have reached.
                let from = start.min(total).saturating_sub(back);
                len = (len + start.min(total) - from).min(MAX_WINDOW / 2);
                (start, back) = (from, back * 2);
            }
            Some(selection) if selection.short && selection.newer > 1 => {
                start = first + selection.newer as u64 - 1;
            }
            Some(selection) if selection.short && len < MAX_WINDOW / 2 => {
                len = (len * 2).min(MAX_WINDOW / 2);
            }
            Some(selection) => {
                let offset = selection
                    .rows
                    .last()
                    .map_or(0, |(index, _)| first + *index as u64 + 1);
                return finish(selection, offset, cursor, Some(total));
            }
        }
    }
    Err(stale_cursor())
}

/// The page a selection makes, or an error when it shows nothing yet more follows.
fn finish(
    selection: Selection,
    offset: u64,
    cursor: Option<&Cursor>,
    total: Option<u64>,
) -> Result<Page, AppError> {
    if selection.more && selection.rows.is_empty() {
        return Err(AppError::limit(
            "Dooray reports more matches than kaist-mail can reach from here",
        )
        .with_hint("Narrow the query, for example with search --from, --subject or --before."));
    }
    let rows: Vec<Summary> = selection.rows.into_iter().map(|(_, row)| row).collect();
    Ok(Page {
        next: Cursor::after(&rows, offset, cursor)?.filter(|_| selection.more),
        rows,
        total,
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
    // Bounds go out a second wider, whichever inclusivity Dooray applies,
    // and the user's are enforced on the rows.
    if let Some(since) = args.since {
        body.insert("since".into(), time::format_korea(since - 1).into());
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
                item.summary(Order::Sent, folder, *preview)
            })
            .collect::<Result<_, _>>()?;
        Ok((rows, found.total_count))
    };
    let page = search_page(fetch, *limit, cursor.as_ref(), args.since, args.before)?;
    let capped = page.total.is_some_and(|total| total >= SEARCH_CAP);
    render("search", page, capped)
}

/// One page of a newest-first search sent in `[since, before)`, taken from
/// Dooray's first page of a search narrowed to `before` just past the
/// cursor's second. No page lies past Dooray's 2000-hit cap, and the window
/// grows when messages already shown or newer ones crowd it.
fn search_page(
    mut fetch: impl FnMut(Option<i64>, u64, u64) -> Result<Fetched, AppError>,
    limit: u64,
    cursor: Option<&Cursor>,
    since: Option<i64>,
    before: Option<i64>,
) -> Result<Page, AppError> {
    let wanted = |row: &Summary| {
        since.is_none_or(|since| row.time >= since) && before.is_none_or(|before| row.time < before)
    };
    let upstream_before = match (cursor, before) {
        (Some(cursor), Some(before)) => Some(before.min(cursor.time + 1)),
        (Some(cursor), None) => Some(cursor.time + 1),
        (None, before) => before,
    };
    let mut size = limit + cursor.map_or(0, |cursor| cursor.seen.len() as u64);
    let mut first_total = None;
    for _ in 0..MAX_CALLS {
        let (rows, total) = fetch(upstream_before, 0, size)?;
        first_total.get_or_insert(total);
        // A capped count says nothing about what lies past it.
        let end = (rows.len() as u64) < size || (rows.len() as u64 >= total && total < SEARCH_CAP);
        let window = Window {
            rows,
            top: true,
            end,
        };
        let selection = select(window, cursor, limit, wanted)?
            .expect("a window from the first page starts at the top");
        if selection.short && size < MAX_WINDOW {
            size = (size * 2).min(MAX_WINDOW);
            continue;
        }
        let offset = cursor.map_or(0, |cursor| cursor.offset) + selection.rows.len() as u64;
        return finish(
            selection,
            offset.min(MAX_OFFSET),
            cursor,
            first_total.filter(|_| cursor.is_none()),
        );
    }
    Err(stale_cursor())
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
