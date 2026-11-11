//! `list` and `search` against a synthetic Dooray mailbox that pages by
//! number, caps search at 2000 hits, and changes between commands.

use std::sync::{Arc, Mutex};

use serde_json::{Value, json};

use super::{Home, envelope, live};
use crate::server::{Request, Response, Server};

const LIST: &str = include_str!("../fixtures/mails-list.json");
const SEARCH: &str = include_str!("../fixtures/mails-search.json");

#[derive(Clone)]
struct Message {
    id: String,
    at: String,
    sender: (&'static str, &'static str),
    subject: String,
    body: &'static str,
    unread: bool,
    folder: &'static str,
}

/// Messages newest first, as Dooray orders them; equal times keep their order.
type Mailbox = Arc<Mutex<Vec<Message>>>;

/// Received time of slot `n`, ten minutes apart going back from 2026-10-31 23:50 KST.
fn stamp(slot: usize) -> String {
    let minute = 1430 - (slot % 144) * 10;
    format!(
        "2026-10-{:02}T{:02}:{:02}:00+09:00",
        31 - slot / 144,
        minute / 60,
        minute % 60
    )
}

/// `count` messages; 30 of them (indexes 15..45) share one second, and every
/// tenth is not about a seminar. Seminars alternate English and Korean.
fn messages(count: usize) -> Vec<Message> {
    (0..count)
        .map(|index| {
            let (sender, subject, body) = match (index % 10, index % 2) {
                (3, _) => (
                    ("Cafeteria", "food@kaist.ac.kr"),
                    format!("Lunch menu {index}"),
                    "점심",
                ),
                (_, 0) => (
                    ("EE Office", "ee@kaist.ac.kr"),
                    format!("Weekly Seminar {index}"),
                    "Room 101",
                ),
                _ => (
                    ("학사팀", "academic@kaist.ac.kr"),
                    format!("주간 세미나 {index}"),
                    "seminar room 세미나실",
                ),
            };
            Message {
                id: format!("{}", 4_470_000_000_000_000_000_u64 - index as u64),
                at: stamp(if (15..45).contains(&index) { 15 } else { index }),
                sender,
                subject,
                body,
                unread: index % 3 != 0,
                folder: match index % 50 {
                    7 => "trash",
                    11 => "sent",
                    _ => "inbox",
                },
            }
        })
        .collect()
}

fn folder_id(name: &str) -> String {
    let index = ["inbox", "sent", "trash"]
        .iter()
        .position(|folder| *folder == name)
        .unwrap();
    format!("310000000000000000{}", index + 1)
}

/// Dooray's list item, from the recorded fixture with this message's fields.
fn item(message: &Message) -> Value {
    let mut item: Value =
        serde_json::from_str::<Value>(LIST).unwrap()["result"]["contents"][0].clone();
    item["id"] = json!(message.id);
    item["createdAt"] = json!(message.at);
    item["subject"] = json!(message.subject);
    item["fileCount"] = json!(0);
    item["folderId"] = json!(folder_id(message.folder));
    item["mailSummary"]["flags"]["read"] = json!(!message.unread);
    item["users"]["from"]["emailUser"] =
        json!({"name": message.sender.0, "emailAddress": message.sender.1});
    item
}

fn envelope_of(result: Value) -> Response {
    let body = json!({"header": {"isSuccessful": true, "resultCode": 0, "resultMessage": ""}, "result": result});
    Response::bytes("application/json;charset=UTF-8", body.to_string())
}

fn contains(text: &str, term: &Value) -> bool {
    text.to_lowercase()
        .contains(&term.as_str().unwrap().to_lowercase())
}

/// Search as these tests assume Dooray runs it: every term matches, `since`
/// is inclusive and `before` exclusive on the received time, newest first,
/// counted and paged only through the first 2000 hits.
fn search(mailbox: &[Message], body: &Value) -> Response {
    let bound = |key: &str| {
        body.get(key).map(|value| {
            let value = value.as_str().unwrap().to_owned();
            assert!(value.len() == 25 && value.ends_with("+09:00"), "{value}");
            value
        })
    };
    let (since, before) = (bound("since"), bound("before"));
    let terms = |key: &str| {
        body.get(key)
            .map_or(vec![], |terms| terms.as_array().unwrap().clone())
    };
    assert_eq!(body["order"], "-createdAt");
    let hits: Vec<&Message> = mailbox
        .iter()
        .filter(|message| {
            let fields = [
                message.subject.as_str(),
                message.body,
                message.sender.0,
                message.sender.1,
            ];
            let excluded = terms("exceptFolders").contains(&json!(message.folder));
            let scoped = body
                .get("folderNames")
                .is_none_or(|names| names[0] == message.folder);
            !excluded
                && scoped
                && terms("all")
                    .iter()
                    .all(|term| fields.iter().any(|field| contains(field, term)))
                && terms("subjects")
                    .iter()
                    .all(|term| contains(&message.subject, term))
                && terms("fromList")
                    .iter()
                    .all(|term| fields[2..].iter().any(|field| contains(field, term)))
                && body
                    .get("seenFlag")
                    .is_none_or(|seen| *seen == json!(!message.unread))
                && since.as_ref().is_none_or(|since| message.at >= *since)
                && before.as_ref().is_none_or(|before| message.at < *before)
        })
        .take(2000)
        .collect();
    let (page, size) = (
        body["page"].as_u64().unwrap() as usize,
        body["size"].as_u64().unwrap() as usize,
    );
    let shown: Vec<&&Message> = hits.iter().skip(page * size).take(size).collect();
    let folder_map: Value = ["inbox", "sent", "trash"]
        .iter()
        .map(|name| {
            (
                folder_id(name),
                json!({"id": folder_id(name), "name": name, "type": "system"}),
            )
        })
        .collect::<serde_json::Map<_, _>>()
        .into();
    envelope_of(json!({
        "totalCount": hits.len(),
        "contents": shown.iter().map(|message| json!({"id": message.id, "subject": message.subject, "sentAt": message.at})).collect::<Vec<_>>(),
        "references": {
            "mailMap": shown.iter().map(|message| (message.id.clone(), item(message))).collect::<serde_json::Map<_, _>>(),
            "folderMap": folder_map,
        },
    }))
}

fn list(mailbox: &[Message], target: &str) -> Response {
    let query = target.split_once('?').unwrap().1;
    let param = |key: &str| {
        query
            .split('&')
            .find_map(|pair| pair.strip_prefix(&format!("{key}=")))
    };
    assert_eq!(
        (param("order"), param("view")),
        (Some("-createdAt"), Some("timeline"))
    );
    let folder = param("folderName").unwrap();
    let matching: Vec<&Message> = mailbox
        .iter()
        .filter(|message| {
            message.folder == folder && (param("read") != Some("false") || message.unread)
        })
        .collect();
    let (page, size): (usize, usize) = (
        param("page").unwrap().parse().unwrap(),
        param("size").unwrap().parse().unwrap(),
    );
    envelope_of(json!({
        "totalCount": matching.len(),
        "contents": matching.iter().skip(page * size).take(size).map(|message| item(message)).collect::<Vec<_>>(),
    }))
}

fn dooray(mailbox: &Mailbox) -> Server {
    let mailbox = Arc::clone(mailbox);
    Server::new(move |request: &Request| {
        let mailbox = mailbox.lock().unwrap();
        match (
            request.method.as_str(),
            request.target.split_once('?').unwrap().0,
        ) {
            ("GET", "/v2/wapi/mails") => list(&mailbox, &request.target),
            ("POST", "/v2/wapi/mails/search") => {
                search(&mailbox, &serde_json::from_str(&request.body).unwrap())
            }
            other => panic!("unexpected request {other:?}"),
        }
    })
}

fn page(home: &Home, server: &Server, args: &[&str], cursor: Option<&str>) -> (Vec<String>, Value) {
    let mut args = args.to_vec();
    args.extend(cursor.iter().flat_map(|cursor| ["--cursor", cursor]));
    let output = home.run(Some(server), &args);
    assert!(output.status.success(), "{output:?}");
    let json = envelope(&output.stdout);
    let ids = json["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["id"].as_str().unwrap().to_owned())
        .collect();
    (ids, json["meta"].clone())
}

/// Every id of `args` and its continuations, and the meta of the first page.
fn walk(home: &Home, server: &Server, args: &[&str]) -> (Vec<String>, Value) {
    let (mut ids, first) = page(home, server, args, None);
    let mut cursor = first["next_cursor"].as_str().map(str::to_owned);
    while let Some(next) = cursor {
        let (more, meta) = page(home, server, args, Some(&next));
        assert!(!more.is_empty() || meta["next_cursor"].is_null(), "{meta}");
        assert!(more.iter().all(|id| !ids.contains(id)), "repeated rows");
        ids.extend(more);
        cursor = meta["next_cursor"].as_str().map(str::to_owned);
    }
    (ids, first)
}

#[test]
fn list_rows_are_thin_and_flags_appear_only_when_set() {
    let server = Server::new(|_: &Request| Response::bytes("application/json;charset=UTF-8", LIST));
    let home = Home::new(Some(&live()));

    let output = home.run(
        Some(&server),
        &["--json", "list", "--unread", "--limit", "3"],
    );
    assert!(output.status.success(), "{output:?}");
    let json = envelope(&output.stdout);
    assert_eq!(
        json["data"][0],
        json!({"id":"4460000000000000001","at":"2026-11-12T09:41:07+09:00","from":"학사팀 <academic@kaist.ac.kr>","subject":"[학사] 2026학년도 봄학기 수강신청 안내","unread":true,"files":2})
    );
    assert_eq!(json["data"][1]["from"], "EE Office <ee-office@kaist.ac.kr>");
    assert_eq!(json["data"][1].get("unread"), None);
    assert_eq!(json["meta"]["total"], 8343);
    assert_eq!(
        json["meta"]["next_cursor"],
        "3.1794316500.4460000000000000003"
    );
    assert_eq!(
        server.requests()[0],
        "GET /v2/wapi/mails?folderName=inbox&view=timeline&order=-createdAt&preview=false&read=false&page=0&size=3 HTTP/1.1"
    );

    let output = home.run(Some(&server), &["list", "--preview", "--limit", "3"]);
    let stdout = String::from_utf8(output.stdout).unwrap();
    let lines: Vec<_> = stdout.lines().collect();
    assert_eq!(lines[0], "ID\tRECEIVED\tFLAGS\tFROM\tSUBJECT");
    assert_eq!(
        lines[1],
        "4460000000000000001\t2026-11-12 09:41\tUA\t학사팀\t[학사] 2026학년도 봄학기 수강신청 안내"
    );
    assert!(
        lines[2].starts_with('\t') && lines[2].len() > 100,
        "{stdout}"
    );
    assert_eq!(
        lines.last().unwrap(),
        &"3 of 8343 shown; more: --cursor 3.1794316500.4460000000000000003"
    );
}

#[test]
fn unread_triage_shows_each_unread_message_once_while_reading_and_arrivals_change_the_set() {
    let mailbox: Mailbox = Arc::new(Mutex::new(messages(130)));
    let unread: Vec<String> = mailbox
        .lock()
        .unwrap()
        .iter()
        .filter(|message| message.unread && message.folder == "inbox")
        .map(|message| message.id.clone())
        .collect();
    let server = dooray(&mailbox);
    let home = Home::new(Some(&live()));
    let args = ["--json", "list", "--unread"];

    let (mut last, mut meta) = page(&home, &server, &args, None);
    let mut shown = last.clone();
    let mut pages = 1;
    while let Some(cursor) = meta["next_cursor"].as_str().map(str::to_owned) {
        let mut mailbox = mailbox.lock().unwrap();
        // The agent reads every other message it was shown; new mail arrives.
        for id in last.iter().step_by(2) {
            mailbox
                .iter_mut()
                .find(|message| message.id == *id)
                .unwrap()
                .unread = false;
        }
        if pages == 2 {
            let mut arrival = messages(1).remove(0);
            (arrival.id, arrival.at, arrival.unread) = (
                "4480000000000000000".into(),
                "2026-11-12T09:00:00+09:00".into(),
                true,
            );
            mailbox.insert(0, arrival);
        }
        drop(mailbox);
        let requests = server.requests().len();
        (last, meta) = page(&home, &server, &args, Some(&cursor));
        assert!(server.requests().len() - requests <= 2, "{meta}");
        shown.extend(last.iter().cloned());
        pages += 1;
    }
    assert_eq!(shown, unread);

    let (first, _) = page(&home, &server, &args, None);
    assert_eq!(first[0], "4480000000000000000");
    assert_eq!(first[1], unread[1]);
}

#[test]
fn an_unchanged_list_continues_in_one_request() {
    let mailbox: Mailbox = Arc::new(Mutex::new(messages(130)));
    let inbox: Vec<String> = mailbox
        .lock()
        .unwrap()
        .iter()
        .filter(|message| message.folder == "inbox")
        .map(|message| message.id.clone())
        .collect();
    let server = dooray(&mailbox);
    let home = Home::new(Some(&live()));

    let (_, meta) = page(&home, &server, &["--json", "list"], None);
    let (second, meta) = page(
        &home,
        &server,
        &["--json", "list"],
        meta["next_cursor"].as_str(),
    );
    assert_eq!(second, inbox[20..40]);
    assert_eq!(server.requests().len(), 2);
    let (third, _) = page(
        &home,
        &server,
        &["--json", "list", "--limit", "7"],
        meta["next_cursor"].as_str(),
    );
    assert_eq!(third, inbox[40..47]);
}

#[test]
fn search_continues_past_the_2000_hit_cap_in_english_and_korean() {
    let mailbox: Mailbox = Arc::new(Mutex::new(messages(2600)));
    let all = mailbox.lock().unwrap().clone();
    let server = dooray(&mailbox);
    let home = Home::new(Some(&live()));

    let seminars: Vec<String> = all
        .iter()
        .filter(|message| {
            message.folder != "trash"
                && (message.subject.contains("Seminar") || message.body.contains("seminar"))
        })
        .map(|message| message.id.clone())
        .collect();
    assert!(seminars.len() > 2100);
    let (ids, first) = walk(&home, &server, &["--json", "search", "SEMINAR"]);
    assert_eq!(first["total"], 2000);
    assert_eq!(first["total_capped"], true);
    assert_eq!(ids.len(), seminars.len());
    assert_eq!(ids, seminars);

    // Decomposed Hangul (as macOS file names carry it) finds the composed subjects.
    let (since, before) = (stamp(400), stamp(100));
    let korean: Vec<String> = all
        .iter()
        .filter(|message| {
            message.folder == "inbox"
                && message.subject.contains("세미나")
                && message.unread
                && message.at >= since
                && message.at < before
        })
        .map(|message| message.id.clone())
        .collect();
    let decomposed = "\u{1109}\u{1166}\u{1106}\u{1175}\u{1102}\u{1161}";
    let (ids, first) = walk(
        &home,
        &server,
        &[
            "--json",
            "search",
            "--subject",
            decomposed,
            "--from",
            "학사",
            "--folder",
            "inbox",
            "--unread",
            "--since",
            &since,
            "--before",
            &before,
            "--limit",
            "7",
        ],
    );
    assert_eq!(ids, korean);
    assert_eq!(first["total"], korean.len());
    assert_eq!(first.get("total_capped"), None);
}

#[test]
fn search_rows_name_their_folder_and_hits_come_from_the_mail_map() {
    let server =
        Server::new(|_: &Request| Response::bytes("application/json;charset=UTF-8", SEARCH));
    let home = Home::new(Some(&live()));

    let output = home.run(Some(&server), &["--json", "search", "수강신청"]);
    assert!(output.status.success(), "{output:?}");
    let json = envelope(&output.stdout);
    assert_eq!(json["data"][0]["folder"], "inbox");
    assert_eq!(json["data"][1]["subject"], "Re: 실험 데이터 공유 건");
    assert_eq!(json["meta"]["total"], 157);
    let body: Value = serde_json::from_str(&server.recorded()[0].body).unwrap();
    assert_eq!(body["all"], json!(["수강신청"]));
    assert_eq!(body["exceptFolders"], json!(["spam", "trash"]));
}
