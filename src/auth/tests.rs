//! The login against loopback Dooray and KAIST SSO servers that play the
//! SAML round trip, with a fake keychain. All data is synthetic.

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
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

/// How the fixture servers deviate from a well-behaved sign-in.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Variant {
    Normal,
    /// The SSO login page is rendered for another agent.
    ForeignAgent,
    /// Dooray's ACS sends the browser back to sign-in.
    Bounce,
    /// Dooray's ACS redirects to the SSO origin with this status.
    AcsToSso(&'static str),
    /// The SSO link page holds a GET form to an ordinary Dooray page.
    GetForm,
    /// Dooray's ACS finishes without authenticating the session.
    Anonymous,
    /// Dooray's SAML request redirects to a third origin.
    Offsite,
}

/// What the fixture servers remember between requests.
#[derive(Default)]
struct State {
    /// The Dooray sessions the API accepts; the ACS issues `authed`, then
    /// `authed2`, `authed3`, ...
    issued: Mutex<Vec<String>>,
    accepted: Mutex<Vec<String>>,
    /// KAIST SSO completed a sign-in on its `JSESSIONID=sso` session and
    /// still honours it.
    sso_alive: AtomicBool,
    /// Milliseconds KAIST SSO takes to answer a SAML request.
    sso_pause: AtomicU64,
    /// Milliseconds KAIST takes to answer the password, and whether that
    /// answer is cut off mid-body.
    password_pause: AtomicU64,
    password_cut: AtomicBool,
    /// Milliseconds Dooray takes to answer the folder list a new session is
    /// checked with.
    folders_pause: AtomicU64,
}

impl State {
    fn issue(&self) -> String {
        let mut issued = self.issued.lock().unwrap();
        let value = match issued.len() {
            0 => "authed".to_owned(),
            n => format!("authed{}", n + 1),
        };
        issued.push(value.clone());
        self.accepted.lock().unwrap().push(value.clone());
        value
    }

    fn accepts(&self, request: &Request) -> bool {
        let session = request
            .header_value("cookie")
            .and_then(|c| c.strip_prefix("SESSION="));
        session.is_some_and(|session| self.accepted.lock().unwrap().iter().any(|s| s == session))
    }

    /// Dooray ends every session it issued, as its idle timeout does.
    fn expire_dooray(&self) {
        self.accepted.lock().unwrap().clear();
    }
}

/// Dooray: sign-in entry, IdP chooser, SAML request, assertion consumer, and
/// the API, which answers only a session it accepts.
fn dooray_route(
    sso: Arc<OnceLock<String>>,
    offsite: String,
    variant: Variant,
    state: Arc<State>,
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
            if variant == Variant::Offsite {
                &offsite
            } else {
                sso.get().unwrap()
            }
        )),
        ("POST", ACS) => match variant {
            Variant::Bounce => redirect("/auth/signin"),
            Variant::AcsToSso(status) => {
                redirect(&format!("{}{}", sso.get().unwrap(), &ACS[1..])).status(status)
            }
            Variant::Anonymous => redirect("/auth/signin/finalize?nextUrl=%2F"),
            _ => redirect("/auth/signin/finalize?nextUrl=%2F")
                .header(
                    "Set-Cookie",
                    &format!("SESSION={}; Path=/; HttpOnly", state.issue()),
                )
                .header("Set-Cookie", "scoped=x; Path=/idp"),
        },
        ("GET", "/auth/signin/finalize") => Response::html("<script>location.href='/'</script>"),
        ("GET", "/v2/wapi/mail-folders") if state.accepts(request) => {
            std::thread::sleep(Duration::from_millis(
                state.folders_pause.load(Ordering::SeqCst),
            ));
            json(
                r#"{"header":{"isSuccessful":true,"resultCode":0,"resultMessage":""},"result":{"totalCount":0,"contents":[]}}"#,
            )
        }
        ("GET", "/v2/wapi/mail-folders") => Response::html("").status("401 Unauthorized"),
        (method, path) => panic!("unexpected Dooray request {method} {path}"),
    }
}

/// KAIST SSO in its SAML variant. `password_result` answers the password step.
fn sso_route(
    dooray: Arc<OnceLock<String>>,
    variant: Variant,
    password_result: Arc<Mutex<String>>,
    state: Arc<State>,
) -> impl Fn(&Request) -> Response + Send + Sync {
    let agent = match variant {
        Variant::ForeignAgent => "kaist-prod-klms",
        _ => "kaist-prod-dooray",
    };
    let saml_form = {
        let dooray = dooray.clone();
        move || {
            Response::html(format!(
                r#"<form method="post" action="{}{}"><input type="hidden" name="SAMLResponse" value="PHNhbWw+"></form><script>document.forms[0].submit()</script>"#,
                dooray.get().unwrap(),
                &ACS[1..]
            ))
        }
    };
    move |request| {
        if request.target.contains("SAMLRequest") {
            let pause = state.sso_pause.load(Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(pause));
        }
        match path(&request.target) {
            "/auth/kaist/user/saml/login/link/redirect"
                if request.target.contains("SAMLRequest")
                    && state.sso_alive.load(Ordering::SeqCst)
                    && request
                        .header_value("cookie")
                        .is_some_and(|c| c.contains("JSESSIONID=sso")) =>
            {
                saml_form()
            }
            "/auth/kaist/user/saml/login/link/redirect"
                if request.target.contains("SAMLRequest") =>
            {
                redirect("/auth/kaist/user/login/view")
                    .header("Set-Cookie", "JSESSIONID=sso; Path=/auth; HttpOnly")
            }
            "/auth/kaist/user/login/view" => Response::html(format!(
                r#"<form><input type="hidden" id="agt_id" name="agt_id" value="{agent}"></form>"#
            )),
            "/auth/kaist/user/saml/login/link/redirect" if variant == Variant::GetForm => {
                Response::html(format!(
                    r#"<form action="{}auth/signin/finalize"><input type="hidden" name="notSAMLResponse" value="x"></form>"#,
                    dooray.get().unwrap(),
                ))
            }
            "/auth/kaist/user/saml/login/link/redirect" => {
                state.sso_alive.store(true, Ordering::SeqCst);
                saml_form()
            }
            "/auth/user/login/init" => json(&format!(r#"{{"result_data":"{}"}}"#, "00".repeat(48))),
            "/auth/user/login/auth" => {
                let pause = state.password_pause.load(Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(pause));
                let answer = json(&password_result.lock().unwrap());
                match state.password_cut.load(Ordering::SeqCst) {
                    true => answer.declared_length(4096),
                    false => answer,
                }
            }
            "/auth/kaist/user/login/second/view" | "/auth/twofactor/mfa/login2Factor" => {
                Response::html(r#"<div class="auth_number"><div class="sr-only">42</div></div>"#)
            }
            "/auth/kaist/user/login/second/ajaxSendMail" => json(r#"{"errorCode":"SS0001"}"#),
            "/auth/kaist/user/login/second/ajaxValidCrtfcNo" => json(r#"{"result_code":"SS0001"}"#),
            "/auth/twofactor/mfa/init" | "/auth/twofactor/mfa/auth" => {
                json(r#"{"errorCode":"SS0001"}"#)
            }
            "/auth/kaist/user/login/check/policy" => json(r#"{"result":true}"#),
            other => {
                Response::html(format!("unexpected SSO request {other}")).status("404 Not Found")
            }
        }
    }
}

struct Fixture {
    dooray: Server,
    sso: Server,
    offsite: Server,
    dooray_url: Url,
    sso_url: Url,
    password_result: Arc<Mutex<String>>,
    state: Arc<State>,
    dirs: Dirs,
    keychain: Keychain,
    root: TempDir,
}

impl Fixture {
    fn new(variant: Variant) -> Self {
        let root = tempfile::tempdir().unwrap();
        let (dooray_cell, sso_cell) = (Arc::new(OnceLock::new()), Arc::new(OnceLock::new()));
        let password_result = Arc::new(Mutex::new(r#"{"result_code":"SS0098"}"#.to_owned()));
        let state = Arc::new(State::default());
        let offsite = Server::new(|_: &Request| Response::html(""));
        let dooray = Server::new(dooray_route(
            sso_cell.clone(),
            format!("{}/", offsite.url()),
            variant,
            state.clone(),
        ));
        let sso = Server::new(sso_route(
            dooray_cell.clone(),
            variant,
            password_result.clone(),
            state.clone(),
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
            offsite,
            password_result,
            state,
            dirs: Dirs {
                config: root.path().join("config/kaist-mail"),
                state: root.path().join("state/kaist-mail"),
            },
            keychain: secret::tests::fake_security(&bin, &store),
            root,
        }
    }

    fn login(&self, options: &LoginOptions, interactive: bool) -> Result<CommandResult, AppError> {
        let env = Env {
            dirs: &self.dirs,
            dooray: &self.dooray_url,
            sso: &self.sso_url,
            timeout: 5,
            deadline: None,
            keychain: &self.keychain,
            interactive,
            code: if interactive {
                CodeStep::Prompt
            } else {
                CodeStep::Defer
            },
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
        self.keychain.store("student", "s3cret", None).unwrap();
    }

    /// Renew as a command does once Dooray rejected `SESSION=authed`.
    fn renew(&self) -> Result<renew::Renewed, AppError> {
        let env = Env {
            dirs: &self.dirs,
            dooray: &self.dooray_url,
            sso: &self.sso_url,
            timeout: 5,
            deadline: None,
            keychain: &self.keychain,
            interactive: false,
            code: CodeStep::Refuse,
            json: true,
        };
        renew::renew_with(&env, renew::Trigger::Rejected("SESSION=authed"))
    }

    /// Signed in by Easy Login, then Dooray ends the session.
    fn expired() -> Self {
        let fixture = Self::new(Variant::Normal);
        fixture.login(&LoginOptions::default(), true).unwrap();
        fixture.state.expire_dooray();
        fixture
    }

    fn password_posts(&self) -> usize {
        let posts = self.sso_paths();
        posts
            .iter()
            .filter(|path| *path == "/auth/user/login/auth")
            .count()
    }

    fn fail_keychain_delete(&self) {
        fs::write(self.root.path().join("keychain/fail-delete"), "").unwrap();
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
    let fixture = Fixture::new(Variant::Normal);
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
            "/auth/signin/finalize",
            "/v2/wapi/mail-folders"
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
    assert!(!session.contains("scoped"), "{session}");
    let session: serde_json::Value = serde_json::from_str(&session).unwrap();
    assert_eq!(session["cookies"][0]["value"], "authed");
    assert_eq!(session["cookies"].as_array().unwrap().len(), 1);
    // KAIST SSO's session is kept apart, bound to the SSO origin.
    let sso = &session["sso"]["cookies"];
    assert_eq!(
        (sso[0]["name"].as_str(), sso.as_array().unwrap().len()),
        (Some("JSESSIONID"), 1)
    );
    assert_eq!(
        sso[0]["source_origin"],
        fixture.sso_url.origin().ascii_serialization()
    );
    let mode = fs::metadata(fixture.dirs.session())
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn password_login_without_a_terminal_runs_in_two_steps() {
    let fixture = Fixture::new(Variant::Normal);
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
        let fixture = Fixture::new(Variant::Normal);
        fixture.remember_password();
        *fixture.password_result.lock().unwrap() =
            format!(r#"{{"errorCode":"EAU001","errorMessage":"{message}"}}"#);
        let error = fixture.login(&password(), false).unwrap_err();
        assert_eq!(error.code, "CREDENTIALS_REJECTED", "{message}");
        // A rejected stored password must never be resent.
        assert!(fixture.keychain.lookup("student", None).unwrap().is_none());
        let identity = store::load_identity(&fixture.dirs.identity())
            .unwrap()
            .unwrap();
        assert!(!identity.password_saved);
    }
}

#[test]
fn a_login_page_for_another_sso_agent_is_refused_before_credentials() {
    let fixture = Fixture::new(Variant::ForeignAgent);
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
    let fixture = Fixture::new(Variant::Bounce);
    let error = fixture.login(&LoginOptions::default(), true).unwrap_err();
    assert_eq!(error.code, "AUTH_PROTOCOL_CHANGED");
    assert!(
        error.message.contains("did not accept"),
        "{}",
        error.message
    );
    assert!(!fixture.dirs.session().exists());
}

/// A failed sign-in must save nothing and leave no session behind.
fn assert_refused(fixture: &Fixture, error: &AppError) {
    assert_eq!(error.code, "AUTH_PROTOCOL_CHANGED", "{}", error.message);
    assert!(!fixture.dirs.session().exists());
}

#[test]
fn the_saml_request_may_only_lead_to_the_sso_origin() {
    let fixture = Fixture::new(Variant::Offsite);
    let error = fixture.login(&LoginOptions::default(), true).err().unwrap();
    assert_refused(&fixture, &error);
    assert!(fixture.offsite.requests().is_empty());
}

#[test]
fn the_assertion_submission_never_leaves_dooray() {
    for status in ["307 Temporary Redirect", "302 Found"] {
        let fixture = Fixture::new(Variant::AcsToSso(status));
        let error = fixture.login(&LoginOptions::default(), true).err().unwrap();
        assert_refused(&fixture, &error);
        let after_acs = fixture
            .sso
            .recorded()
            .into_iter()
            .any(|r| r.line.contains(ACS));
        assert!(
            !after_acs,
            "{status}: the submission followed Dooray to the SSO origin"
        );
    }
}

#[test]
fn only_a_saml_post_to_the_acs_that_authenticates_dooray_counts_as_login() {
    for variant in [Variant::GetForm, Variant::Anonymous] {
        let fixture = Fixture::new(variant);
        let error = fixture.login(&LoginOptions::default(), true).err().unwrap();
        assert_refused(&fixture, &error);
    }
}

#[test]
fn unrecognized_sso_codes_are_never_echoed() {
    // A misbehaving server could reflect the password or the code here.
    for code in ["XYZ123", "s3cret", "COOKIE-CANARY; x=1"] {
        let fixture = Fixture::new(Variant::Normal);
        fixture.remember_password();
        *fixture.password_result.lock().unwrap() = format!(r#"{{"errorCode":"{code}"}}"#);
        let error = fixture.login(&password(), false).err().unwrap();
        assert_eq!(error.code, "AUTH_PROTOCOL_CHANGED");
        assert!(!error.message.contains(code), "{}", error.message);
    }
}

/// Requests that would put a code or a push in front of the user.
const ASKS_THE_USER: [&str; 3] = [
    "/auth/kaist/user/login/second/ajaxSendMail",
    "/auth/twofactor/mfa/init",
    "/auth/twofactor/mfa/login2Factor",
];

fn asks_the_user(paths: &[String]) -> bool {
    paths
        .iter()
        .any(|path| ASKS_THE_USER.contains(&path.as_str()))
}

#[test]
fn a_rejected_session_is_renewed_from_the_kaist_sso_session_without_credentials() {
    let fixture = Fixture::expired();
    let before = fixture.sso_paths().len();

    let renewed = fixture.renew().unwrap();
    assert_eq!(renewed.header, "SESSION=authed2");
    assert_eq!(renewed.via, Some(Via::SsoSession));
    assert_eq!(
        fixture.sso_paths()[before..],
        ["/auth/kaist/user/saml/login/link/redirect"]
    );
    let session: serde_json::Value = serde_json::from_str(&fixture.session()).unwrap();
    assert_eq!(session["cookies"][0]["value"], "authed2");
    assert_eq!(session["renewal"]["via"], "sso-session");
    assert_eq!(session["renewal"]["sso"]["alive"], true);
}

#[test]
fn an_ended_sso_session_falls_back_to_a_password_login_kaist_lets_through() {
    let fixture = Fixture::expired();
    fixture.state.sso_alive.store(false, Ordering::SeqCst);
    fixture.remember_password();
    // KAIST skips the second factor for a trusted device.
    *fixture.password_result.lock().unwrap() = r#"{"result_code":"SS0001"}"#.to_owned();
    let before = fixture.sso_paths().len();

    let renewed = fixture.renew().unwrap();
    assert_eq!(
        (renewed.header.as_str(), renewed.via),
        ("SESSION=authed2", Some(Via::Password))
    );
    let paths = &fixture.sso_paths()[before..];
    assert!(
        paths.iter().any(|path| path == "/auth/user/login/auth"),
        "{paths:?}"
    );
    assert!(!asks_the_user(paths), "{paths:?}");
    let session: serde_json::Value = serde_json::from_str(&fixture.session()).unwrap();
    assert_eq!(session["renewal"]["sso"]["alive"], false);
}

#[test]
fn renewal_never_sends_a_code_or_starts_easy_login() {
    // A password KAIST accepts but follows with a code request.
    let fixture = Fixture::expired();
    fixture.state.sso_alive.store(false, Ordering::SeqCst);
    fixture.remember_password();
    let before = fixture.sso_paths().len();
    let error = fixture.renew().err().unwrap();
    assert_eq!(error.code, "AUTH_EXPIRED");
    assert!(error.hint.unwrap().contains("--method password"));
    assert!(!asks_the_user(&fixture.sso_paths()[before..]));

    // Easy Login remembered and no password: nothing to try without the phone.
    let fixture = Fixture::expired();
    fixture.state.sso_alive.store(false, Ordering::SeqCst);
    let before = fixture.sso_paths().len();
    let error = fixture.renew().err().unwrap();
    assert_eq!(error.code, "AUTH_EXPIRED");
    assert!(error.hint.unwrap().contains("--remember-password"));
    assert!(!asks_the_user(&fixture.sso_paths()[before..]));
    // The ended SSO session is dropped, so the next attempt skips it.
    assert!(!fixture.session().contains("JSESSIONID"));
}

#[test]
fn concurrent_renewals_sign_in_once_and_share_the_new_session() {
    let fixture = Fixture::expired();
    let acs_posts = || {
        fixture
            .dooray
            .requests()
            .iter()
            .filter(|line| line.contains(ACS))
            .count()
    };
    let before = acs_posts();

    let headers: Vec<_> = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..4).map(|_| scope.spawn(|| fixture.renew())).collect();
        workers
            .into_iter()
            .map(|worker| worker.join().unwrap().unwrap().header)
            .collect()
    });
    assert_eq!(headers, ["SESSION=authed2"; 4]);
    assert_eq!(acs_posts(), before + 1);
    let session: serde_json::Value = serde_json::from_str(&fixture.session()).unwrap();
    assert_eq!(session["cookies"][0]["value"], "authed2");
}

#[test]
fn a_password_kaist_refuses_is_never_resent_by_renewal() {
    for (code, hint) in [
        ("EAU001", "--remember-password"),
        ("SS0006", "in a browser"),
    ] {
        let fixture = Fixture::expired();
        fixture.state.sso_alive.store(false, Ordering::SeqCst);
        fixture.remember_password();
        *fixture.password_result.lock().unwrap() = format!(r#"{{"result_code":"{code}"}}"#);

        let error = fixture.renew().err().unwrap();
        assert_eq!(error.code, "AUTH_EXPIRED", "{code}");
        assert!(error.hint.unwrap().contains(hint), "{code}");
        let before = fixture.sso_paths().len();
        assert_eq!(fixture.renew().err().unwrap().code, "AUTH_EXPIRED");
        let paths = &fixture.sso_paths()[before..];
        assert!(
            !paths.iter().any(|path| path == "/auth/user/login/auth"),
            "{code}: {paths:?}"
        );
    }
}

fn password_login() -> LoginOptions {
    LoginOptions {
        method: Some(LoginMethod::Password),
        ..LoginOptions::default()
    }
}

#[test]
fn login_holds_the_session_lock_from_reading_the_password_to_saving_the_session() {
    let fixture = Fixture::new(Variant::Normal);
    fixture.remember_password();
    *fixture.password_result.lock().unwrap() = r#"{"result_code":"EAU001"}"#.to_owned();
    let held = store::lock_session(&fixture.dirs.session_lock(), Duration::ZERO, None).unwrap();

    std::thread::scope(|scope| {
        let login = scope.spawn(|| fixture.login(&password_login(), false));
        std::thread::sleep(Duration::from_millis(400));
        assert_eq!(fixture.password_posts(), 0);
        drop(held);
        assert_eq!(
            login.join().unwrap().err().unwrap().code,
            "CREDENTIALS_REJECTED"
        );
    });
    assert_eq!(fixture.password_posts(), 1);
}

#[test]
fn waiting_for_the_session_lock_is_bounded() {
    let fixture = Fixture::new(Variant::Normal);
    let path = fixture.dirs.session_lock();
    let _held = store::lock_session(&path, Duration::ZERO, None).unwrap();
    // Measured against a zero-wait attempt so slow CI file opens do not count; a whole 50 ms poll past the wait does.
    let started = Instant::now();
    let _ = store::lock_session(&path, Duration::ZERO, None);
    let overhead = started.elapsed();
    let started = Instant::now();
    let error = store::lock_session(&path, Duration::from_millis(10), None)
        .err()
        .unwrap();
    assert_eq!(error.code, "NETWORK_ERROR");
    assert!(
        started.elapsed() < overhead + Duration::from_millis(40),
        "{:?} with {overhead:?} overhead",
        started.elapsed()
    );
}

#[test]
fn simultaneous_logins_send_a_refused_stored_password_once() {
    let fixture = Fixture::new(Variant::Normal);
    fixture.remember_password();
    *fixture.password_result.lock().unwrap() = r#"{"result_code":"EAU001"}"#.to_owned();

    std::thread::scope(|scope| {
        let logins: Vec<_> = (0..6)
            .map(|_| scope.spawn(|| fixture.login(&password_login(), false)))
            .collect();
        for login in logins {
            assert!(login.join().unwrap().is_err());
        }
    });
    assert_eq!(fixture.password_posts(), 1);
}

#[test]
fn logout_waits_for_a_renewal_and_stays_signed_out() {
    let fixture = Fixture::expired();
    fixture.state.sso_pause.store(400, Ordering::SeqCst);

    std::thread::scope(|scope| {
        let renewal = scope.spawn(|| fixture.renew());
        std::thread::sleep(Duration::from_millis(100));
        logout_with(&fixture.dirs, Duration::from_secs(5)).unwrap();
        assert!(renewal.join().unwrap().is_ok());
    });
    assert!(!fixture.dirs.session().exists());
}

#[test]
fn a_refused_password_that_cannot_be_removed_is_still_never_resent() {
    let fixture = Fixture::expired();
    fixture.state.sso_alive.store(false, Ordering::SeqCst);
    fixture.remember_password();
    *fixture.password_result.lock().unwrap() = r#"{"result_code":"EAU001"}"#.to_owned();
    fixture.fail_keychain_delete();
    // An immutable login.json keeps naming the password as stored.
    let immutable = |flag| {
        let identity = fixture.dirs.identity();
        let status = std::process::Command::new("chflags")
            .arg(flag)
            .arg(identity)
            .status();
        assert!(status.unwrap().success());
    };
    immutable("uchg");

    let error = fixture.renew().err().unwrap();
    let second = fixture.renew().err().unwrap();
    immutable("nouchg");
    assert!(error.hint.unwrap().contains("could not remove it"));
    assert_eq!(second.code, "AUTH_EXPIRED");
    assert_eq!(fixture.password_posts(), 1);
}

#[test]
fn a_code_request_stops_password_renewal_until_the_next_login() {
    let fixture = Fixture::expired();
    fixture.state.sso_alive.store(false, Ordering::SeqCst);
    fixture.remember_password();

    for _ in 0..3 {
        assert_eq!(fixture.renew().err().unwrap().code, "AUTH_EXPIRED");
    }
    assert_eq!(fixture.password_posts(), 1);
    let hold = store::read_hold(&fixture.dirs.password_hold()).unwrap();
    assert_eq!(hold, Some(store::PasswordHold::CodeRequired));

    // An explicit login, even one stopped at the code, lifts the hold.
    assert_eq!(
        fixture.login(&password_login(), false).err().unwrap().code,
        "CODE_REQUIRED"
    );
    assert!(fixture.renew().is_err());
    assert_eq!(fixture.password_posts(), 3);
}

#[test]
fn a_failed_renewal_never_moves_last_used_back() {
    let fixture = Fixture::expired();
    fixture.state.sso_alive.store(false, Ordering::SeqCst);
    fixture.state.sso_pause.store(300, Ordering::SeqCst);
    let used = fixture.dirs.session_used();
    let long_ago = std::time::UNIX_EPOCH + Duration::from_secs(1_000);
    fs::File::open(&used)
        .unwrap()
        .set_modified(long_ago)
        .unwrap();

    let marked = std::thread::scope(|scope| {
        let renewal = scope.spawn(|| fixture.renew());
        std::thread::sleep(Duration::from_millis(100));
        store::mark_used(&used).unwrap();
        let marked = store::last_used(&used).unwrap();
        assert!(renewal.join().unwrap().is_err());
        marked
    });
    assert!(store::last_used(&used).unwrap() >= marked);
}

/// Signed in by Easy Login, Dooray ended the session, the KAIST SSO session
/// is gone, and the password is remembered: renewal will use the password.
fn by_password() -> Fixture {
    let fixture = Fixture::expired();
    fixture.state.sso_alive.store(false, Ordering::SeqCst);
    fixture.remember_password();
    fixture
}

fn hold(fixture: &Fixture) -> Option<store::PasswordHold> {
    store::read_hold(&fixture.dirs.password_hold()).unwrap()
}

#[test]
fn a_refusal_cut_off_in_transit_still_stops_the_password() {
    let fixture = by_password();
    *fixture.password_result.lock().unwrap() = r#"{"result_code":"EAU001"}"#.to_owned();
    fixture.state.password_cut.store(true, Ordering::SeqCst);

    for _ in 0..3 {
        assert!(fixture.renew().is_err());
    }
    assert!(fixture.login(&password_login(), false).is_err());
    assert_eq!(fixture.password_posts(), 1);
    assert_eq!(hold(&fixture), Some(store::PasswordHold::Unresolved));
}

#[test]
fn renewal_while_kaist_is_unreachable_keeps_the_password_usable() {
    let fixture = by_password();
    let unreachable = Url::parse("http://127.0.0.1:9/").unwrap();
    let env = Env {
        dirs: &fixture.dirs,
        dooray: &unreachable,
        sso: &unreachable,
        timeout: 2,
        deadline: None,
        keychain: &fixture.keychain,
        interactive: false,
        code: CodeStep::Refuse,
        json: true,
    };
    let error = renew::renew_with(&env, renew::Trigger::Rejected("SESSION=authed"))
        .err()
        .unwrap();
    assert_eq!(error.code, "NETWORK_ERROR", "{}", error.message);
    assert_eq!(hold(&fixture), None);
}

#[test]
fn every_wait_of_a_renewal_ends_at_the_command_deadline() {
    let slow_sso_check = Fixture::expired();
    let slow_password_check = by_password();
    *slow_password_check.password_result.lock().unwrap() = r#"{"result_code":"SS0001"}"#.to_owned();
    for slow in [&slow_sso_check, &slow_password_check] {
        slow.state.folders_pause.store(1_500, Ordering::SeqCst);
    }
    let locked = Fixture::expired();
    let _held = store::lock_session(&locked.dirs.session_lock(), Duration::ZERO, None).unwrap();
    let mut hung_keychain = by_password();
    let bin = hung_keychain.root.path().join("bin");
    hung_keychain.keychain.program = secret::tests::script(&bin, "hung-security", "sleep 10");

    for (case, fixture, code, says) in [
        (
            "checking the SSO session's login",
            &slow_sso_check,
            "NETWORK_ERROR",
            "could not renew",
        ),
        (
            "checking the password's login",
            &slow_password_check,
            "NETWORK_ERROR",
            "could not renew",
        ),
        (
            "waiting for the session lock",
            &locked,
            "NETWORK_ERROR",
            "--max-seconds",
        ),
        (
            "reading the password",
            &hung_keychain,
            "AUTH_EXPIRED",
            "--max-seconds",
        ),
    ] {
        let started = Instant::now();
        let env = Env {
            dirs: &fixture.dirs,
            dooray: &fixture.dooray_url,
            sso: &fixture.sso_url,
            timeout: 5,
            deadline: Some(started + Duration::from_millis(500)),
            keychain: &fixture.keychain,
            interactive: false,
            code: CodeStep::Refuse,
            json: true,
        };
        let error = renew::renew_with(&env, renew::Trigger::Rejected("SESSION=authed"))
            .err()
            .unwrap_or_else(|| panic!("{case}: renewed"));
        assert!(
            error.code == code && error.message.contains(says),
            "{case}: {} {}",
            error.code,
            error.message
        );
        assert!(
            started.elapsed() < Duration::from_millis(1_200),
            "{case} took {:?}",
            started.elapsed()
        );
    }
}

#[test]
fn a_hold_that_cannot_be_written_sends_no_password() {
    let fixture = by_password();
    // A directory where the hold's temporary file goes makes writing it fail.
    let temp = format!("password-hold.json.{}.tmp", std::process::id());
    fs::create_dir_all(fixture.dirs.state.join(temp).join("x")).unwrap();

    let renewed = fixture.renew();
    let logged_in = fixture.login(&password_login(), false);
    assert!(renewed.is_err() && logged_in.is_err());
    assert_eq!(fixture.password_posts(), 0);
}

#[test]
fn a_sign_in_cut_off_after_the_password_left_is_never_resent() {
    let fixture = by_password();
    fixture.state.password_pause.store(600, Ordering::SeqCst);

    // While KAIST holds the answer, the disk shows what a process killed now leaves.
    let left = std::thread::scope(|scope| {
        let renewal = scope.spawn(|| fixture.renew());
        while fixture.password_posts() == 0 {
            std::thread::sleep(Duration::from_millis(10));
        }
        let left = fs::read(fixture.dirs.password_hold()).ok();
        assert!(renewal.join().unwrap().is_err());
        left
    });
    fs::write(
        fixture.dirs.password_hold(),
        left.expect("no hold while the password was out"),
    )
    .unwrap();
    assert!(fixture.renew().is_err());
    assert!(fixture.login(&password_login(), false).is_err());
    assert_eq!(fixture.password_posts(), 1);
}
