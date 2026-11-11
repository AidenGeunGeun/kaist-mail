//! Reading a message, downloading its attachments and exporting it.

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    sync::atomic::{AtomicUsize, Ordering},
};

use serde_json::{Value, json};
use tempfile::TempDir;

use super::{
    Home, envelope, live,
    server::{Request, Response, Server},
};

const ID: &str = "4460000000000000001";
const DETAIL: &str = include_str!("../fixtures/mail-detail.json");
const RAW: &[u8] = include_bytes!("../fixtures/mail-raw.eml");
const DELETED: &str = include_str!("../fixtures/error-mail-deleted.json");
const DETAIL_PATH: &str = "/v2/wapi/mails/4460000000000000001?render=html";
const RAW_PATH: &str = "/v2/wapi/mails/4460000000000000001?type=raw";
const PDF_PATH: &str = "/mails/4460000000000000001/parts/3?type=raw&t=1794400000000000000";
const DOCX_PATH: &str = "/mails/4460000000000000001/parts/4?type=raw&t=1794400000000000000";
const PDF_NAME: &str = "2026학년도 봄학기 수강신청 안내.pdf";

fn file_bytes(size: usize, seed: u8) -> Vec<u8> {
    (0..size)
        .map(|i| (i as u8).wrapping_mul(31) ^ seed)
        .collect()
}

/// The fixture message (unread) with its two attachments.
fn mailbox(detail: String) -> Server {
    Server::new(move |request: &Request| match request.target.as_str() {
        DETAIL_PATH => Response::bytes("application/json;charset=UTF-8", detail.clone()),
        PDF_PATH => Response::bytes("application/pdf", file_bytes(152_031, 1)),
        DOCX_PATH => Response::bytes("application/octet-stream", file_bytes(28_417, 2)),
        other => panic!("unexpected request {other}"),
    })
}

fn data(output: &std::process::Output) -> Value {
    assert!(output.status.success(), "{output:?}");
    envelope(&output.stdout)["data"].clone()
}

#[test]
fn read_renders_bounded_text_and_reports_that_it_marked_the_message_read() {
    let home = Home::new(Some(&live()));
    let server = mailbox(DETAIL.to_owned());
    let full = data(&home.run(Some(&server), &["--json", "read", ID]));
    assert_eq!(
        (&full["read"], &full["marked_read"]),
        (&json!(true), &json!(true))
    );
    assert_eq!(full["subject"], "[학사] 2026학년도 봄학기 수강신청 안내");
    assert_eq!(full["from"], "학사팀 <academic@kaist.ac.kr>");
    assert_eq!(full["to"], json!(["홍길동 <gildong@kaist.ac.kr>"]));
    assert_eq!(full["cc"].as_array().unwrap().len(), 3);
    assert_eq!(full["more_recipients"], 2);
    assert_eq!(
        full["attachments"][0],
        json!({"part": 3, "name": PDF_NAME, "size": 152_031, "mime": "application/pdf"})
    );
    let text = full["body"]["text"].as_str().unwrap();
    for expected in [
        "안녕하세요, 학사팀입니다.\n\n2026학년도",
        "신청은 포털 <https://portal.kaist.ac.kr/apply?term=2026-1>에서 하세요.",
        "1. 예비수강신청: 1월 20일(화) 10:00 ~ 1월 22일(목) 17:00",
        "문의\nacademic@kaist.ac.kr\n",
        "[수강신청 포스터]",
        "> 2026년 11월 10일 (화) 오후 3:00, 교무처 <registrar@kaist.ac.kr> 작성:\n> 원문: 일정 확정 부탁드립니다.",
    ] {
        assert!(
            text.contains(expected),
            "{expected:?} missing from {text:?}"
        );
    }
    for absent in ["\n\n\n", "mailto:", "track()", "color:red", "<p>"] {
        assert!(!text.contains(absent), "{absent:?} in {text:?}");
    }
    assert_eq!(full["body"]["total_chars"], text.chars().count());
    assert_eq!(full["body"].get("next_offset"), None);

    let all = data(&home.run(Some(&server), &["--json", "read", ID, "--recipients"]));
    assert_eq!(all["cc"].as_array().unwrap().len(), 5);
    assert_eq!(all.get("more_recipients"), None);

    let head = data(&home.run(Some(&server), &["--json", "read", ID, "--max-chars", "7"]));
    assert_eq!(head["body"]["text"], "안녕하세요, ");
    assert_eq!(head["body"]["next_offset"], 7);
    let tail = data(&home.run(
        Some(&server),
        &[
            "--json",
            "read",
            ID,
            "--offset",
            "7",
            "--max-chars",
            "100000",
        ],
    ));
    assert_eq!(
        format!("안녕하세요, {}", tail["body"]["text"].as_str().unwrap()),
        text
    );
    assert_eq!(tail["body"].get("next_offset"), None);
    let human = home.run(Some(&server), &["read", ID, "--max-chars", "7"]);
    let human = String::from_utf8(human.stdout).unwrap();
    assert!(human.contains("(marked read)"), "{human}");
    assert!(
        human.ends_with(&format!("more: kaist-mail read {ID} --offset 7]\n")),
        "{human}"
    );

    let already_read = mailbox(DETAIL.replace(r#""read": false"#, r#""read": true"#));
    let reread = data(&home.run(Some(&already_read), &["--json", "read", ID]));
    assert_eq!(
        (&reread["read"], &reread["marked_read"]),
        (&json!(true), &json!(false))
    );

    let output = home.run(
        Some(&server),
        &["--json", "read", "4460000000000000001/../1"],
    );
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        server.requests().len(),
        5,
        "an invalid id never reaches Dooray"
    );
}

#[test]
fn download_saves_korean_named_private_files_and_never_overwrites() {
    let home = Home::new(Some(&live()));
    let server = mailbox(DETAIL.to_owned());
    let out = TempDir::new().unwrap();
    let dir = out.path().to_str().unwrap();
    let saved = data(&home.run(Some(&server), &["--json", "download", ID, "--out", dir]));
    assert_eq!(saved["marked_read"], true);
    let pdf = out.path().join(PDF_NAME);
    let docx = out.path().join("Course registration guide (EN).docx");
    assert_eq!(fs::read(&pdf).unwrap(), file_bytes(152_031, 1));
    assert_eq!(fs::read(&docx).unwrap(), file_bytes(28_417, 2));
    assert_eq!(
        saved["files"][0],
        json!({"part": 3, "path": fs::canonicalize(&pdf).unwrap(), "bytes": 152_031})
    );
    assert_eq!(
        fs::metadata(&pdf).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let again = home.run(Some(&server), &["--json", "download", ID, "--out", dir]);
    let error = &envelope(&again.stderr)["error"];
    assert_eq!(error["code"], "CONFIG_ERROR");
    let message = error["message"].as_str().unwrap();
    assert!(
        message.contains("part 3") && message.contains(dir),
        "{message}"
    );
    assert!(
        !message.contains(PDF_NAME),
        "the server's file name stays out of errors"
    );
    assert_eq!(fs::read(&pdf).unwrap(), file_bytes(152_031, 1));
    let names: Vec<_> = fs::read_dir(out.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(names.len(), 2, "{names:?}");

    let one = out.path().join("guide.docx");
    let args = [
        "--json",
        "download",
        ID,
        "--part",
        "4",
        "--out",
        one.to_str().unwrap(),
    ];
    assert_eq!(data(&home.run(Some(&server), &args))["files"][0]["part"], 4);
    assert_eq!(fs::read(&one).unwrap(), file_bytes(28_417, 2));
    let taken = home.run(Some(&server), &args);
    assert_eq!(envelope(&taken.stderr)["error"]["code"], "CONFIG_ERROR");

    let missing = home.run(
        Some(&server),
        &["--json", "download", ID, "--part", "9", "--out", dir],
    );
    assert_eq!(envelope(&missing.stderr)["error"]["code"], "NOT_FOUND");
    let requests = server.requests();
    let parts = |path: &str| requests.iter().filter(|line| line.contains(path)).count();
    assert_eq!((parts(PDF_PATH), parts(DOCX_PATH)), (1, 2));
}

#[test]
fn transfers_stream_past_the_json_limit_even_for_json_files_and_never_publish_a_short_file() {
    let home = Home::new(Some(&live()));
    let out = TempDir::new().unwrap();
    let large = file_bytes(9 * 1024 * 1024 + 1, 3);
    let served = large.clone();
    let detail = DETAIL.replace(r#""size": 152031"#, &format!(r#""size": {}"#, large.len()));
    let server = Server::new(move |request: &Request| match request.target.as_str() {
        DETAIL_PATH => Response::bytes("application/json", detail.clone()),
        PDF_PATH => Response::open_ended(served.clone()).content_type("application/json"),
        DOCX_PATH => Response::open_ended(vec![0; 100]),
        other => panic!("unexpected request {other}"),
    });
    let dir = out.path().to_str().unwrap();
    let saved = data(&home.run(
        Some(&server),
        &["--json", "download", ID, "--part", "3", "--out", dir],
    ));
    assert_eq!(saved["files"][0]["bytes"], large.len());
    assert_eq!(fs::read(out.path().join(PDF_NAME)).unwrap(), large);

    let short = home.run(
        Some(&server),
        &["--json", "download", ID, "--part", "4", "--out", dir],
    );
    assert_eq!(envelope(&short.stderr)["error"]["code"], "NETWORK_ERROR");
    assert_eq!(
        fs::read_dir(out.path()).unwrap().count(),
        1,
        "no partial or temporary file"
    );
}

#[test]
fn download_errors_name_the_part_never_the_download_link() {
    const CANARY: &str = "/files/SERVER-FILENAME-CANARY.txt";
    let home = Home::new(Some(&live()));
    let out = TempDir::new().unwrap();
    let dir = out.path().to_str().unwrap();
    let detail = DETAIL.replace(DOCX_PATH, CANARY);
    let answers: [fn() -> Response; 3] = [
        || Response::bytes("text/html", "gone").status("404 Not Found"),
        || Response::bytes("text/plain", vec![0; 10]),
        || Response::open_ended(vec![0; 10]),
    ];
    for answer in answers {
        let detail = detail.clone();
        let server = Server::new(move |request: &Request| match request.target.as_str() {
            DETAIL_PATH => Response::bytes("application/json", detail.clone()),
            CANARY => answer(),
            other => panic!("unexpected request {other}"),
        });
        let output = home.run(
            Some(&server),
            &["--json", "download", ID, "--part", "4", "--out", dir],
        );
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(
            !output.status.success() && stderr.contains("part 4"),
            "{stderr}"
        );
        assert!(!stderr.contains("CANARY"), "{stderr}");
    }
}

#[test]
fn names_the_filesystem_treats_as_one_fail_before_any_download() {
    let home = Home::new(Some(&live()));
    let out = TempDir::new().unwrap();
    let dir = out.path().to_str().unwrap();
    for (first, second) in [
        ("가.txt", "\u{1100}\u{1161}.txt"),
        ("A.txt", "a.txt"),
        ("Straße.txt", "STRASSE.txt"),
        ("σ.txt", "ς.txt"),
        ("S.txt", "ſ.txt"),
        ("ﬀ.txt", "ff.txt"),
    ] {
        let detail = DETAIL
            .replace(&format!(r#""{PDF_NAME}""#), &format!(r#""{first}""#))
            .replace(
                r#""Course registration guide (EN).docx""#,
                &format!(r#""{second}""#),
            );
        let server = mailbox(detail);
        let output = home.run(Some(&server), &["--json", "download", ID, "--out", dir]);
        let error = &envelope(&output.stderr)["error"];
        assert_eq!(error["code"], "USAGE", "{first} and {second}");
        assert_eq!(server.requests().len(), 1, "only the detail was fetched");
        assert_eq!(fs::read_dir(out.path()).unwrap().count(), 0);
    }
}

#[test]
fn export_saves_the_raw_message_byte_for_byte_without_reading_it() {
    let home = Home::new(Some(&live()));
    let out = TempDir::new().unwrap();
    let server = Server::new(|request: &Request| match request.target.as_str() {
        RAW_PATH => Response::bytes("message/rfc822", RAW),
        "/v2/wapi/mails/4460000000000000002?type=raw" => {
            Response::bytes("application/json;charset=UTF-8", DELETED)
        }
        other => panic!("unexpected request {other}"),
    });
    let dir = out.path().to_str().unwrap();
    let saved = data(&home.run(Some(&server), &["--json", "export", ID, "--out", dir]));
    assert_eq!(saved["bytes"], RAW.len());
    assert_eq!(fs::read(out.path().join(format!("{ID}.eml"))).unwrap(), RAW);
    assert_eq!(
        server.requests(),
        [format!("GET /v2/wapi/mails/{ID}?type=raw HTTP/1.1")],
        "only the raw endpoint, which leaves the read state alone"
    );

    let gone = home.run(
        Some(&server),
        &["--json", "export", "4460000000000000002", "--out", dir],
    );
    let error = &envelope(&gone.stderr)["error"];
    assert_eq!(error["code"], "UPSTREAM_ERROR");
    assert_eq!(error["details"]["result_code"], -100_207);
    assert_eq!(fs::read_dir(out.path()).unwrap().count(), 1);
}

#[test]
fn transfers_dooray_cuts_short_start_over_and_give_up_after_three_attempts() {
    let home = Home::new(Some(&live()));
    let out = TempDir::new().unwrap();
    let dir = out.path().to_str().unwrap();
    let pdf = file_bytes(152_031, 1);
    let served = AtomicUsize::new(0);
    let server = Server::new(move |request: &Request| match request.target.as_str() {
        DETAIL_PATH => Response::bytes("application/json;charset=UTF-8", DETAIL),
        PDF_PATH if served.fetch_add(1, Ordering::Relaxed) == 0 => {
            Response::bytes("application/pdf", &pdf[..122_031]).declared_length(152_031)
        }
        PDF_PATH => Response::bytes("application/pdf", pdf.clone()),
        RAW_PATH => Response::bytes("message/rfc822", &RAW[..RAW.len() / 2])
            .declared_length(RAW.len() as u64),
        other => panic!("unexpected request {other}"),
    });
    let output = home.run(
        Some(&server),
        &["--json", "download", ID, "--part", "3", "--out", dir],
    );
    assert!(output.status.success(), "{output:?}");
    assert!(
        fs::read(out.path().join(PDF_NAME)).unwrap() == file_bytes(152_031, 1),
        "the saved PDF is not the whole served file"
    );
    let warnings = &envelope(&output.stdout)["warnings"];
    assert!(
        warnings[0]
            .as_str()
            .is_some_and(|warning| warning.contains("122031 of 152031 bytes")),
        "{warnings}"
    );

    let export = home.run(Some(&server), &["--json", "export", ID, "--out", dir]);
    let error = &envelope(&export.stderr)["error"];
    assert_eq!(error["code"], "NETWORK_ERROR");
    assert!(
        error["message"].as_str().unwrap().contains("3 attempts"),
        "{error}"
    );
    assert_eq!(
        fs::read_dir(out.path()).unwrap().count(),
        1,
        "only the PDF, no partial or temporary file"
    );
    let requests = server.requests();
    let count = |path: &str| requests.iter().filter(|line| line.contains(path)).count();
    assert_eq!((count(PDF_PATH), count(RAW_PATH)), (2, 3));
}
