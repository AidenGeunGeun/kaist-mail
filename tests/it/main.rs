//! The real binary against a loopback Dooray, with synthetic sessions and
//! mail data only.

#[allow(dead_code)]
#[path = "../fixture/server.rs"]
mod server;

use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
};

use serde_json::Value;
use server::{Request, Response, Server};
use tempfile::TempDir;

const FOLDERS: &str = r#"{"header":{"isSuccessful":true,"resultCode":0,"resultMessage":""},"result":{"totalCount":3,"contents":[{"id":"1001","name":"Inbox"},{"id":1002,"name":"받은편지함/연구실"},{"id":"1003","name":"\u001b[31mred\u001b[0m"}]}}"#;

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

fn api(body: &'static str) -> Server {
    Server::new(move |request: &Request| {
        assert_eq!(request.target, "/v2/wapi/mail-folders");
        Response::bytes("application/json;charset=UTF-8", body)
    })
}

fn envelope(output: &[u8]) -> Value {
    serde_json::from_slice(output).unwrap()
}

#[test]
fn folders_keep_korean_names_intact_in_json_and_terminal_output() {
    let server = api(FOLDERS);
    let home = Home::new(Some(&live()));

    let output = home.run(Some(&server), &["--json", "folders"]);
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains(r#""name":"받은편지함/연구실""#), "{stdout}");
    let json = envelope(stdout.as_bytes());
    assert_eq!(json["command"], "folders");
    assert_eq!(
        json["data"][1],
        serde_json::json!({"id":"1002","name":"받은편지함/연구실"})
    );
    assert_eq!(json["meta"], serde_json::json!({"returned":3,"total":3}));
    let request = &server.recorded()[0];
    assert_eq!(
        request.header_value("cookie"),
        Some("SESSION=synthetic-session")
    );

    let output = home.run(Some(&server), &["folders"]);
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(
        stdout,
        "ID\tNAME\n1001\tInbox\n1002\t받은편지함/연구실\n1003\t[31mred[0m\n"
    );
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
fn dooray_errors_keep_their_code_and_localized_message() {
    for message in ["권한이 없습니다.", "Permission denied."] {
        let body = format!(
            r#"{{"header":{{"isSuccessful":false,"resultCode":-403,"resultMessage":"{message}"}},"result":null}}"#
        );
        let server =
            Server::new(move |_: &Request| Response::bytes("application/json", body.clone()));
        let output = Home::new(Some(&live())).run(Some(&server), &["--json", "folders"]);
        assert_eq!(output.status.code(), Some(31));
        let error = &envelope(&output.stderr)["error"];
        assert_eq!(error["code"], "UPSTREAM_ERROR");
        assert_eq!(
            error["details"],
            serde_json::json!({"result_code": -403, "result_message": message})
        );
    }
}

#[test]
fn status_is_secret_free_and_expired_sessions_never_reach_the_network() {
    let expired = session(
        r#"{"name":"SESSION","value":"synthetic-secret","expires_at":1},{"name":"other","value":"synthetic-secret","expires_at":2}"#,
    );
    let home = Home::new(Some(&expired));
    let server = api(FOLDERS);
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
