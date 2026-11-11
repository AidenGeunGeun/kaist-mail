//! The real binary against a loopback Dooray, with synthetic sessions and
//! mail data only.

#[allow(dead_code)]
#[path = "../fixture/server.rs"]
mod server;

mod query;

use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
};

use serde_json::Value;
use server::{Request, Response, Server};
use tempfile::TempDir;

const SYSTEM: &str = include_str!("../fixtures/mail-folders-system.json");
const USER: &str = include_str!("../fixtures/mail-folders-user.json");

/// A HOME whose XDG state directory has a Hangul name, holding `session`.
struct Home {
    dir: TempDir,
}

impl Home {
    fn new(session: Option<&str>) -> Self {
        let home = Self {
            dir: TempDir::new().unwrap(),
        };
        if let Some(session) = session {
            fs::create_dir_all(home.state().join("kaist-mail")).unwrap();
            fs::write(home.state().join("kaist-mail/session.json"), session).unwrap();
        }
        home
    }

    fn state(&self) -> PathBuf {
        self.dir.path().join("상태")
    }

    fn run(&self, server: Option<&Server>, args: &[&str]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_kaist-mail"));
        command
            .args(args)
            .env("HOME", self.dir.path())
            .env("XDG_STATE_HOME", self.state())
            .env("XDG_CONFIG_HOME", self.dir.path().join("config"))
            .env_remove("NO_PROXY")
            .env_remove("HTTPS_PROXY")
            .env_remove("HTTP_PROXY")
            .env_remove("ALL_PROXY");
        if let Some(server) = server {
            command.env("KAIST_MAIL_BASE_URL", server.url());
        }
        command.output().unwrap()
    }
}

fn session(cookies: &str) -> String {
    format!(r#"{{"version":1,"origin":"http://127.0.0.1:0","created_at":1,"cookies":[{cookies}]}}"#)
}

fn live() -> String {
    session(r#"{"name":"SESSION","value":"synthetic-session"}"#)
}

/// Dooray's folder API with the synthetic fixtures; one user folder name
/// carries a terminal escape.
fn folders_api() -> Server {
    Server::new(|request: &Request| {
        let user = USER.replace(r#""name": "Receipts""#, r#""name": "\u001b[31mReceipts""#);
        let body = match request.target.as_str() {
            "/v2/wapi/mail-folders?type=system&size=10000&page=0" => SYSTEM.to_owned(),
            "/v2/wapi/mail-folders?type=user&size=10000&page=0" => user,
            other => panic!("unexpected request {other}"),
        };
        Response::bytes("application/json;charset=UTF-8", body)
    })
}

fn envelope(output: &[u8]) -> Value {
    serde_json::from_slice(output).unwrap()
}

#[test]
fn folders_list_system_and_user_folders_with_korean_names_intact() {
    let server = folders_api();
    let home = Home::new(Some(&live()));

    let output = home.run(Some(&server), &["--json", "folders"]);
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains(r#""name":"연구실 공지""#), "{stdout}");
    let json = envelope(stdout.as_bytes());
    assert_eq!(json["command"], "folders");
    let data = json["data"].as_array().unwrap();
    assert_eq!(
        data[0],
        serde_json::json!({"id":"3100000000000000001","name":"inbox","type":"system","total":8343,"unread":2785})
    );
    assert_eq!(
        data[7],
        serde_json::json!({"id":"3100000000000000102","name":"\u{1b}[31mReceipts","type":"user","total":15,"unread":0,"parent":"3100000000000000101"})
    );
    assert_eq!(json["meta"], serde_json::json!({"returned":8,"total":8}));
    let request = &server.recorded()[0];
    for (name, value) in [
        ("cookie", "SESSION=synthetic-session"),
        ("dooray-caller", "WEB"),
        ("dooray-api-version", "1.1"),
        ("dooray-mail-api-version", "1.2"),
    ] {
        assert_eq!(request.header_value(name), Some(value), "{name}");
    }

    let output = home.run(Some(&server), &["folders"]);
    let stdout = String::from_utf8(output.stdout).unwrap();
    let lines: Vec<_> = stdout.lines().collect();
    assert_eq!(lines[0], "ID\tUNREAD\tTOTAL\tNAME");
    assert_eq!(lines[7], "3100000000000000101\t3\t120\t연구실 공지");
    assert_eq!(lines[8], "3100000000000000102\t0\t15\t[31mReceipts");
}

#[test]
fn a_rejected_or_redirected_session_is_auth_expired() {
    let rejected = Server::new(|_: &Request| Response::html("").status("401 Unauthorized"));
    let redirected = Server::new(|_: &Request| {
        Response::html("")
            .status("302 Found")
            .header("Location", "/auth/signin")
    });
    let home = Home::new(Some(&live()));
    for server in [&rejected, &redirected] {
        let output = home.run(Some(server), &["--json", "folders"]);
        assert_eq!(output.status.code(), Some(10));
        let error = &envelope(&output.stderr)["error"];
        assert_eq!(error["code"], "AUTH_EXPIRED");
        assert!(
            error["hint"]
                .as_str()
                .unwrap()
                .contains("kaist-mail auth login")
        );
    }
    assert_eq!(redirected.requests().len(), 1, "sign-in is never followed");
}

#[test]
fn dooray_errors_report_their_code_whatever_the_result_and_message_language() {
    let inline = |message: &str, result: &str| {
        format!(
            r#"{{"header":{{"isSuccessful":false,"resultCode":-403,"resultMessage":"{message}"}},"result":{result}}}"#
        )
    };
    let korean =
        "요청한 내용에 오류가 있습니다. 해당 오류는 서비스 운영자에게 자동으로 보고됩니다.";
    for (body, code, message) in [
        (
            include_str!("../fixtures/error-invalid-request.json").to_owned(),
            -200200,
            korean,
        ),
        (
            inline("Permission denied.", "{}"),
            -403,
            "Permission denied.",
        ),
        (inline("", "[]"), -403, ""),
    ] {
        let server =
            Server::new(move |_: &Request| Response::bytes("application/json", body.clone()));
        let output = Home::new(Some(&live())).run(Some(&server), &["--json", "folders"]);
        assert_eq!(output.status.code(), Some(31), "{message}");
        let error = &envelope(&output.stderr)["error"];
        assert_eq!(error["code"], "UPSTREAM_ERROR");
        assert_eq!(
            error["details"],
            serde_json::json!({"result_code": code, "result_message": message})
        );
    }
}

#[test]
fn errors_never_echo_mail_data_server_text_or_rejected_secrets() {
    let canary = "CANARY";
    let shape = r#"{"header":{"isSuccessful":true,"resultCode":0},"result":{"totalCount":"PRIVATE-MAIL-BODY-CANARY","contents":[]}}"#;
    let hostile = format!(
        r#"{{"header":{{"isSuccessful":false,"resultCode":-1,"resultMessage":"\u001b[2JBad session COOKIE-CANARY {}"}},"result":null}}"#,
        "x".repeat(500)
    );
    for body in [shape.to_owned(), hostile] {
        let server =
            Server::new(move |_: &Request| Response::bytes("application/json", body.clone()));
        let output = Home::new(Some(&live())).run(Some(&server), &["--json", "folders"]);
        let error = &envelope(&output.stderr)["error"];
        assert!(
            !error["message"].as_str().unwrap().contains(canary),
            "{error}"
        );
        if let Some(message) = error["details"]["result_message"].as_str() {
            assert!(
                message.chars().count() <= 200 && !message.contains('\u{1b}'),
                "{message}"
            );
        }
    }

    let output = Home::new(None).run(
        None,
        &[
            "--json",
            "--base-url",
            "https://user:password-CANARY@kaist.gov-dooray.com:bogus",
            "auth",
            "status",
        ],
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(canary));

    let session = session(r#"{"name":"SESSION","value":"v","expires_at":"COOKIE-CANARY"}"#);
    let server = folders_api();
    let output = Home::new(Some(&session)).run(Some(&server), &["--json", "auth", "status"]);
    assert_eq!(envelope(&output.stderr)["error"]["code"], "CONFIG_ERROR");
    assert!(!String::from_utf8_lossy(&output.stderr).contains(canary));
}

#[test]
fn status_is_secret_free_and_expired_sessions_never_reach_the_network() {
    let expired = session(
        r#"{"name":"SESSION","value":"synthetic-secret","expires_at":1},{"name":"other","value":"synthetic-secret","expires_at":2}"#,
    );
    let home = Home::new(Some(&expired));
    let server = folders_api();
    let output = home.run(Some(&server), &["--json", "auth", "status"]);
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(!stdout.contains("synthetic-secret"), "{stdout}");
    let data = &envelope(stdout.as_bytes())["data"];
    assert!(
        data["path"]
            .as_str()
            .unwrap()
            .contains("상태/kaist-mail/session.json")
    );
    assert_eq!(
        data["cookies"][0],
        serde_json::json!({"name":"SESSION","expires_at":1,"expired":true})
    );

    let output = home.run(Some(&server), &["--json", "folders"]);
    assert_eq!(envelope(&output.stderr)["error"]["code"], "AUTH_EXPIRED");
    let output = Home::new(None).run(Some(&server), &["--json", "folders"]);
    assert_eq!(envelope(&output.stderr)["error"]["code"], "AUTH_REQUIRED");
    assert!(server.requests().is_empty());
}

#[test]
fn only_dooray_or_a_loopback_fixture_is_accepted_as_base_url() {
    let home = Home::new(None);
    for base in [
        "https://evil.example",
        "http://kaist.gov-dooray.com",
        "https://user@kaist.gov-dooray.com",
    ] {
        let output = home.run(None, &["--json", "--base-url", base, "auth", "status"]);
        assert_eq!(output.status.code(), Some(2), "{base}");
    }
}
