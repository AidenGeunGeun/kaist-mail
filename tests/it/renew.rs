//! Commands renew a session Dooray rejects from the saved KAIST SSO session,
//! once, and retry the rejected request.

use std::{
    fs,
    sync::{Arc, OnceLock},
};

use serde_json::{Value, json};
use tempfile::TempDir;

use super::{
    Home, SYSTEM, USER, envelope,
    server::{Request, Response, Server},
};

const ID: &str = "4460000000000000001";
const DETAIL: &str = include_str!("../fixtures/mail-detail.json");
const SEARCH: &str = include_str!("../fixtures/mails-search.json");
const RAW: &[u8] = include_bytes!("../fixtures/mail-raw.eml");
const DETAIL_PATH: &str = "/v2/wapi/mails/4460000000000000001?render=html";
const PDF_PATH: &str = "/mails/4460000000000000001/parts/3?type=raw&t=1794400000000000000";

type Route = Box<dyn Fn(&Request) -> Response + Send + Sync>;

/// Dooray behind a KAIST SAML sign-in, and a KAIST SSO that answers its
/// SAML request from the `JSESSIONID=live` session. The stale session gets
/// 401 wherever `rejects` says; the renewed one, and the stale one elsewhere,
/// reach `mail`, except for the system folders a new session is checked with.
fn renewing(rejects: fn(&Request) -> bool, mail: Route) -> (Server, Server) {
    let (dooray_url, sso_url) = (
        Arc::new(OnceLock::<String>::new()),
        Arc::new(OnceLock::<String>::new()),
    );
    let sso_for_dooray = sso_url.clone();
    let dooray = Server::new(move |request: &Request| {
        let stale = request.header_value("cookie") == Some("SESSION=stale");
        match (request.method.as_str(), request.target.split('?').next().unwrap()) {
            ("GET", "/auth/signin") => Response::html(
                r#"<script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{"buttons":[{"name":"Students","url":"/idp/login/saml?redirectUrl=%2F"}]}}}</script>"#,
            )
            .header("Set-Cookie", "SESSION=anon; Path=/"),
            ("GET", "/idp/login/saml") => Response::html("").status("302 Found").header(
                "Location",
                &format!(
                    "{}/auth/kaist/user/saml/login/link/redirect?SAMLRequest=req",
                    sso_for_dooray.get().unwrap()
                ),
            ),
            ("POST", "/idp/login/saml/process") => Response::html("")
                .status("302 Found")
                .header("Location", "/auth/signin/finalize")
                .header("Set-Cookie", "SESSION=renewed; Path=/"),
            ("GET", "/auth/signin/finalize") => Response::html(""),
            _ if stale && rejects(request) => Response::html("").status("401 Unauthorized"),
            // How kaist-mail checks a new session.
            ("GET", "/v2/wapi/mail-folders") if !stale && request.target.contains("type=system") => {
                Response::bytes("application/json", SYSTEM)
            }
            _ => mail(request),
        }
    });
    let dooray_for_sso = dooray_url.clone();
    let sso = Server::new(move |request: &Request| {
        let live = request
            .header_value("cookie")
            .is_some_and(|c| c.contains("JSESSIONID=live"));
        assert!(
            live && request.target.contains("SAMLRequest"),
            "unexpected SSO request {}",
            request.target
        );
        Response::html(format!(
            r#"<form method="post" action="{}/idp/login/saml/process"><input type="hidden" name="SAMLResponse" value="PHNhbWw+"></form>"#,
            dooray_for_sso.get().unwrap()
        ))
    });
    dooray_url.set(dooray.url()).unwrap();
    sso_url.set(sso.url()).unwrap();
    (dooray, sso)
}

fn always(_: &Request) -> bool {
    true
}

fn folders(request: &Request) -> Response {
    let body = if request.target.contains("type=user") {
        USER
    } else {
        SYSTEM
    };
    Response::bytes("application/json", body)
}

/// A session Dooray no longer accepts, with KAIST SSO's session beside it.
fn stale_home(sso: &Server) -> Home {
    Home::new(Some(&format!(
        r#"{{"version":1,"origin":"http://127.0.0.1:0","created_at":1,"cookies":[{{"name":"SESSION","value":"stale"}}],"sso":{{"cookies":[{{"name":"JSESSIONID","value":"live","domain":"127.0.0.1","path":"/auth","secure":false,"source_origin":"{}"}}],"devices":[]}}}}"#,
        sso.url()
    )))
}

fn run(home: &Home, servers: &(Server, Server), args: &[&str]) -> Value {
    let output = home.run_with_sso(Some(&servers.0), Some(&servers.1), args);
    assert!(output.status.success(), "{output:?}");
    envelope(&output.stdout)
}

fn count(server: &Server, needle: &str) -> usize {
    let requests = server.requests();
    requests.iter().filter(|line| line.contains(needle)).count()
}

#[test]
fn a_command_renews_a_rejected_session_from_the_kaist_sso_session_and_retries() {
    let servers = renewing(always, Box::new(folders));
    let home = stale_home(&servers.1);

    let json = run(&home, &servers, &["--json", "folders"]);
    assert_eq!(json["meta"]["total"], 8);
    let warning = json["warnings"][0].as_str().unwrap();
    assert!(
        warning.contains("renewed it with the KAIST SSO session"),
        "{warning}"
    );
    let saved = fs::read_to_string(home.state().join("kaist-mail/session.json")).unwrap();
    assert!(saved.contains(r#""value": "renewed""#), "{saved}");

    let renewal = &run(&home, &servers, &["--json", "auth", "status"])["data"]["renewal"];
    assert_eq!(renewal["available"], json!(["sso-session"]));
    assert_eq!(renewal["last"]["via"], "sso-session");
}

#[test]
fn a_session_dooray_keeps_rejecting_is_renewed_only_once_per_command() {
    // Dooray takes the renewed session for system folders only.
    let mail = |_: &Request| Response::html("").status("401 Unauthorized");
    let servers = renewing(always, Box::new(mail));
    let home = stale_home(&servers.1);

    let output = home.run_with_sso(Some(&servers.0), Some(&servers.1), &["--json", "folders"]);
    assert_eq!(envelope(&output.stderr)["error"]["code"], "AUTH_EXPIRED");
    assert_eq!(count(&servers.0, "/idp/login/saml/process"), 1);
}

#[test]
fn a_rejected_search_post_is_sent_again_with_the_renewed_session() {
    let mail = |_: &Request| Response::bytes("application/json;charset=UTF-8", SEARCH);
    let servers = renewing(always, Box::new(mail));
    let home = stale_home(&servers.1);

    let json = run(&home, &servers, &["--json", "search", "수강신청"]);
    assert_eq!(json["meta"]["total"], 157);
    let posts: Vec<_> = (servers.0.recorded().into_iter())
        .filter(|request| request.line.starts_with("POST /v2/wapi/mails/search"))
        .collect();
    assert_eq!(posts.len(), 2);
    assert_eq!(posts[0].body, posts[1].body);
    let body: Value = serde_json::from_str(&posts[1].body).unwrap();
    assert_eq!(body["all"], json!(["수강신청"]));
}

#[test]
fn a_retried_read_reports_that_it_marked_the_message_read() {
    let mail = |request: &Request| {
        assert_eq!(request.target, DETAIL_PATH);
        Response::bytes("application/json;charset=UTF-8", DETAIL)
    };
    let servers = renewing(always, Box::new(mail));
    let home = stale_home(&servers.1);

    let data = &run(&home, &servers, &["--json", "read", ID])["data"];
    assert_eq!(
        (&data["read"], &data["marked_read"]),
        (&json!(true), &json!(true))
    );
    assert_eq!(count(&servers.0, DETAIL_PATH), 2);
}

#[test]
fn a_download_rejected_before_its_first_byte_publishes_exactly_one_file() {
    let pdf: Vec<u8> = (0..152_031usize)
        .map(|i| (i as u8).wrapping_mul(31) ^ 1)
        .collect();
    let body = pdf.clone();
    let mail = move |request: &Request| match request.target.as_str() {
        DETAIL_PATH => Response::bytes("application/json;charset=UTF-8", DETAIL),
        PDF_PATH => Response::bytes("application/pdf", body.clone()),
        other => panic!("unexpected request {other}"),
    };
    let servers = renewing(|request| request.target == PDF_PATH, Box::new(mail));
    let home = stale_home(&servers.1);
    let out = TempDir::new().unwrap();
    let dir = out.path().to_str().unwrap();

    let args = ["--json", "download", ID, "--part", "3", "--out", dir];
    let saved = &run(&home, &servers, &args)["data"];
    assert_eq!(saved["files"][0]["bytes"], 152_031);
    let files: Vec<_> = fs::read_dir(out.path())
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(files.len(), 1);
    assert_eq!(fs::read(files[0].path()).unwrap(), pdf);
    assert_eq!(count(&servers.0, PDF_PATH), 2);
}

#[test]
fn a_rejected_export_saves_the_message_once_with_the_renewed_session() {
    let mail = |_: &Request| Response::bytes("message/rfc822", RAW);
    let servers = renewing(always, Box::new(mail));
    let home = stale_home(&servers.1);
    let out = TempDir::new().unwrap();

    let args = [
        "--json",
        "export",
        ID,
        "--out",
        out.path().to_str().unwrap(),
    ];
    assert_eq!(run(&home, &servers, &args)["data"]["bytes"], RAW.len());
    assert_eq!(fs::read_dir(out.path()).unwrap().count(), 1);
    assert_eq!(fs::read(out.path().join(format!("{ID}.eml"))).unwrap(), RAW);
}
