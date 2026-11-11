//! The login against loopback Dooray and KAIST SSO servers that play the
//! SAML round trip, with a fake keychain. All data is synthetic.

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    sync::{Arc, Mutex, OnceLock},
};

use tempfile::TempDir;

use super::*;
use crate::fixture_server::{Request, Response, Server};

const SAML_BUTTON: &str = "/idp/login/saml?redirectUrl=%2Fauth%2Fsignin%2Ffinalize";
const ACS: &str = "/idp/login/saml/process";

fn path(target: &str) -> &str {
    target.split('?').next().unwrap_or_default()
}

fn redirect(location: &str) -> Response {
    Response::html("")
        .status("302 Found")
        .header("Location", location)
}

fn json(body: &str) -> Response {
    Response::bytes("application/json", body.to_owned())
}

/// Dooray: sign-in entry, IdP chooser, SAML request, assertion consumer.
fn dooray_route(
    sso: Arc<OnceLock<String>>,
    accept: bool,
) -> impl Fn(&Request) -> Response + Send + Sync {
    move |request| match (request.method.as_str(), path(&request.target)) {
        ("GET", "/auth/signin") => redirect("/idp/init?redirectUrl=%2F")
            .header("Set-Cookie", "SESSION=anon; Path=/; HttpOnly"),
        ("GET", "/idp/init") => redirect("/idp/multi?redirectUrl=%2F"),
        ("GET", "/idp/multi") => Response::html(format!(
            r#"<script id="__NEXT_DATA__" type="application/json">{{"props":{{"pageProps":{{"buttons":[{{"name":"업무 계정","url":"/idp/login?x"}},{{"name":"Students","url":"{SAML_BUTTON}"}}]}}}}}}</script>"#
        )),
        ("GET", "/idp/login/saml") => redirect(&format!(
            "{}auth/kaist/user/saml/login/link/redirect?SAMLRequest=req&SigAlg=alg&Signature=sig",
            sso.get().unwrap()
        )),
        ("POST", ACS) if accept => redirect("/auth/signin/finalize?nextUrl=%2F")
            .header("Set-Cookie", "SESSION=authed; Path=/; HttpOnly")
            .header("Set-Cookie", "scoped=x; Path=/idp"),
        ("POST", ACS) => redirect("/auth/signin"),
        ("GET", "/auth/signin/finalize") => Response::html("<script>location.href='/'</script>"),
        (method, path) => panic!("unexpected Dooray request {method} {path}"),
    }
}

/// KAIST SSO in its SAML variant. `password_result` answers the password step.
fn sso_route(
    dooray: Arc<OnceLock<String>>,
    agent: &'static str,
    password_result: Arc<Mutex<String>>,
) -> impl Fn(&Request) -> Response + Send + Sync {
    move |request| match path(&request.target) {
        "/auth/kaist/user/saml/login/link/redirect" if request.target.contains("SAMLRequest") => {
            redirect("/auth/kaist/user/login/view")
                .header("Set-Cookie", "JSESSIONID=sso; Path=/auth; HttpOnly")
        }
        "/auth/kaist/user/login/view" => Response::html(format!(
            r#"<form><input type="hidden" id="agt_id" name="agt_id" value="{agent}"></form>"#
        )),
        "/auth/kaist/user/saml/login/link/redirect" => Response::html(format!(
            r#"<form method="post" action="{}{}"><input type="hidden" name="SAMLResponse" value="PHNhbWw+"></form><script>document.forms[0].submit()</script>"#,
            dooray.get().unwrap(),
            &ACS[1..]
        )),
        "/auth/user/login/init" => json(&format!(r#"{{"result_data":"{}"}}"#, "00".repeat(48))),
        "/auth/user/login/auth" => json(&password_result.lock().unwrap()),
        "/auth/kaist/user/login/second/view" | "/auth/twofactor/mfa/login2Factor" => {
            Response::html(r#"<div class="auth_number"><div class="sr-only">42</div></div>"#)
        }
        "/auth/kaist/user/login/second/ajaxSendMail" => json(r#"{"errorCode":"SS0001"}"#),
        "/auth/kaist/user/login/second/ajaxValidCrtfcNo" => json(r#"{"result_code":"SS0001"}"#),
        "/auth/twofactor/mfa/init" | "/auth/twofactor/mfa/auth" => {
            json(r#"{"errorCode":"SS0001"}"#)
        }
        "/auth/kaist/user/login/check/policy" => json(r#"{"result":true}"#),
        other => panic!("unexpected SSO request {other}"),
    }
}

struct Fixture {
    dooray: Server,
    sso: Server,
    dooray_url: Url,
    sso_url: Url,
    password_result: Arc<Mutex<String>>,
    dirs: Dirs,
    keychain: Keychain,
    _root: TempDir,
}

impl Fixture {
    fn new(agent: &'static str, accept: bool) -> Self {
        let root = tempfile::tempdir().unwrap();
        let (dooray_cell, sso_cell) = (Arc::new(OnceLock::new()), Arc::new(OnceLock::new()));
        let password_result = Arc::new(Mutex::new(r#"{"result_code":"SS0098"}"#.to_owned()));
        let dooray = Server::new(dooray_route(sso_cell.clone(), accept));
        let sso = Server::new(sso_route(
            dooray_cell.clone(),
            agent,
            password_result.clone(),
        ));
        dooray_cell.set(format!("{}/", dooray.url())).unwrap();
        sso_cell.set(format!("{}/", sso.url())).unwrap();
        let bin = root.path().join("bin");
        let store = root.path().join("keychain");
        fs::create_dir_all(&bin).unwrap();
        fs::create_dir_all(&store).unwrap();
        Self {
            dooray_url: Url::parse(dooray_cell.get().unwrap()).unwrap(),
            sso_url: Url::parse(sso_cell.get().unwrap()).unwrap(),
            dooray,
            sso,
            password_result,
            dirs: Dirs {
                config: root.path().join("config/kaist-mail"),
                state: root.path().join("state/kaist-mail"),
            },
            keychain: secret::tests::fake_security(&bin, &store),
            _root: root,
        }
    }

    fn login(&self, options: &LoginOptions, interactive: bool) -> Result<CommandResult, AppError> {
        let env = Env {
            dirs: &self.dirs,
            dooray: &self.dooray_url,
            sso: &self.sso_url,
            timeout: 5,
            keychain: &self.keychain,
            interactive,
            defer_code: !interactive,
            json: true,
        };
        login_with(&env, options, Terminal)
    }

    /// A remembered password login whose password is in the keychain.
    fn remember_password(&self) {
        let mut identity =
            Identity::new("student", LoginMethod::Password, Some(SecondFactor::Email));
        identity.password_saved = true;
        store::save_json(&self.dirs.identity(), &identity, "remembered login").unwrap();
        self.keychain.store("student", "s3cret").unwrap();
    }

    fn session(&self) -> String {
        fs::read_to_string(self.dirs.session()).unwrap_or_default()
    }

    fn sso_paths(&self) -> Vec<String> {
        self.sso
            .requests()
            .iter()
            .map(|line| path(line.split_whitespace().nth(1).unwrap()).to_owned())
            .collect()
    }
}

struct Terminal;

impl AuthPrompt for Terminal {
    fn identifier(&mut self) -> Result<String, AppError> {
        Ok("student".into())
    }
    fn password(&mut self) -> Result<Zeroizing<String>, AppError> {
        Ok(Zeroizing::new("s3cret".into()))
    }
    fn otp(&mut self, _channel: &str) -> Result<Zeroizing<String>, AppError> {
        Ok(Zeroizing::new("123456".into()))
    }
}

fn password() -> LoginOptions {
    LoginOptions {
        method: Some(LoginMethod::Password),
        ..LoginOptions::default()
    }
}

#[test]
fn easy_login_follows_dooray_saml_to_sso_and_posts_the_response_back() {
    let fixture = Fixture::new("kaist-prod-dooray", true);
    let result = fixture.login(&LoginOptions::default(), true).unwrap();
    assert_eq!(result.data["cookies"], serde_json::json!(["SESSION"]));

    let dooray: Vec<_> = fixture.dooray.requests();
    let lines: Vec<_> = dooray
        .iter()
        .map(|line| path(line.split_whitespace().nth(1).unwrap()))
        .collect();
    assert_eq!(
        lines,
        [
            "/auth/signin",
            "/idp/init",
            "/idp/multi",
            "/idp/login/saml",
            ACS,
            "/auth/signin/finalize"
        ]
    );
    let acs = &fixture.dooray.recorded()[4];
    assert_eq!(acs.body, "SAMLResponse=PHNhbWw%2B");
    // The SAML request is bound to the anonymous Dooray session cookie.
    assert_eq!(acs.header_value("cookie"), Some("SESSION=anon"));
    let challenge = fixture
        .sso
        .recorded()
        .into_iter()
        .find(|r| r.line.contains("login2Factor"));
    assert_eq!(
        challenge.unwrap().body,
        "linkUrl=%2Fkaist%2Fuser%2Fsaml%2Flogin%2Flink%2Fredirect"
    );

    let session = fixture.session();
    assert!(session.contains(r#""value": "authed""#), "{session}");
    assert!(
        !session.contains("JSESSIONID") && !session.contains("scoped"),
        "{session}"
    );
    let mode = fs::metadata(fixture.dirs.session())
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn password_login_without_a_terminal_runs_in_two_steps() {
    let fixture = Fixture::new("kaist-prod-dooray", true);
    fixture.remember_password();

    let error = fixture.login(&password(), false).unwrap_err();
    assert_eq!((error.code, error.exit_code()), ("CODE_REQUIRED", 12));
    assert_eq!(error.details.as_ref().unwrap()["channel"], "email");
    let pending = fs::read_to_string(fixture.dirs.pending()).unwrap();
    assert!(!pending.contains("s3cret"));
    assert!(fixture.session().is_empty());

    let options = LoginOptions {
        code: Some("123456".into()),
        ..LoginOptions::default()
    };
    let result = fixture.login(&options, false).unwrap();
    assert_eq!(result.data["method"], "password");
    assert!(!fixture.dirs.pending().exists());
    assert!(fixture.session().contains("authed"));
    let validate = fixture
        .sso
        .recorded()
        .into_iter()
        .find(|r| r.line.contains("ajaxValidCrtfcNo"));
    assert!(validate.unwrap().body.contains("123456"));
}

#[test]
fn sso_results_map_by_code_whatever_the_message_language() {
    for message in [
        "아이디 또는 비밀번호가 일치하지 않습니다.",
        "The ID or password is incorrect.",
    ] {
        let fixture = Fixture::new("kaist-prod-dooray", true);
        fixture.remember_password();
        *fixture.password_result.lock().unwrap() =
            format!(r#"{{"errorCode":"EAU001","errorMessage":"{message}"}}"#);
        let error = fixture.login(&password(), false).unwrap_err();
        assert_eq!(error.code, "CREDENTIALS_REJECTED", "{message}");
        // A rejected stored password must never be resent.
        assert!(fixture.keychain.lookup("student").unwrap().is_none());
        let identity = store::load_identity(&fixture.dirs.identity())
            .unwrap()
            .unwrap();
        assert!(!identity.password_saved);
    }
}

#[test]
fn a_login_page_for_another_sso_agent_is_refused_before_credentials() {
    let fixture = Fixture::new("kaist-prod-klms", true);
    let error = fixture.login(&LoginOptions::default(), true).unwrap_err();
    assert_eq!(error.code, "AUTH_PROTOCOL_CHANGED");
    assert_eq!(
        fixture.sso_paths(),
        [
            "/auth/kaist/user/saml/login/link/redirect",
            "/auth/kaist/user/login/view"
        ]
    );
}

#[test]
fn dooray_bouncing_the_saml_response_back_to_sign_in_saves_nothing() {
    let fixture = Fixture::new("kaist-prod-dooray", false);
    let error = fixture.login(&LoginOptions::default(), true).unwrap_err();
    assert_eq!(error.code, "AUTH_PROTOCOL_CHANGED");
    assert!(
        error.message.contains("did not accept"),
        "{}",
        error.message
    );
    assert!(!fixture.dirs.session().exists());
}
