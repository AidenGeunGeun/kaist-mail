//! The sign-in conversation: Dooray's SAML request, the KAIST SSO prompts,
//! result-code tables, SEED-CBC login payload and password / second-factor /
//! Easy Login steps, and the `SAMLResponse` handoff back to Dooray.
//!
//! KAIST SSO answers every step with a result code; logic keys on those codes
//! and on page structure, never on message text, so Korean and English pages
//! behave the same.

use std::{
    io::{self, Write},
    thread,
    time::Duration,
};

use cbc::cipher::{BlockEncryptMut, KeyIvInit, block_padding::AnsiX923};
use kisaseed::SEED;
use serde::Serialize;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::{error::AppError, url::Url};

use super::{
    LoginMethod, SecondFactor,
    store::{PendingLogin, StoredCookie, validate_username},
    transport::SsoTransport,
};

/// The SSO agent Dooray's SAML request selects; the login page must say so.
const AGENT_ID: &str = "kaist-prod-dooray";
/// Where KAIST SSO pages send the browser after a successful step: the SAML
/// variant of KLMS's `/user/login/link`. It answers with the `SAMLResponse` form.
const LINK_URL: &str = "/kaist/user/saml/login/link/redirect";
const LOGIN_VIEW: &str = "/auth/kaist/user/login/view";
// 60 polls x 3 s = the "three minutes" quoted to the user.
const EASY_POLLS: u32 = 60;
const EASY_POLL_SECS: u64 = 3;

// ---- prompts ----

pub trait AuthPrompt {
    fn identifier(&mut self) -> Result<String, AppError>;
    fn password(&mut self) -> Result<Zeroizing<String>, AppError>;
    fn otp(&mut self, channel: &str) -> Result<Zeroizing<String>, AppError>;
}

pub struct TerminalPrompt;

impl AuthPrompt for TerminalPrompt {
    fn identifier(&mut self) -> Result<String, AppError> {
        eprint!("KAIST ID or email: ");
        io::stderr().flush().ok();
        let mut value = String::new();
        io::stdin()
            .read_line(&mut value)
            .map_err(|error| AppError::config(format!("cannot read login identifier: {error}")))?;
        let value = value.trim().to_owned();
        if value.is_empty() {
            return Err(AppError::usage("login identifier cannot be empty"));
        }
        Ok(value)
    }

    fn password(&mut self) -> Result<Zeroizing<String>, AppError> {
        rpassword::prompt_password("KAIST password: ")
            .map(Zeroizing::new)
            .map_err(|error| {
                AppError::config(format!("cannot read password from terminal: {error}"))
            })
    }

    fn otp(&mut self, channel: &str) -> Result<Zeroizing<String>, AppError> {
        rpassword::prompt_password(format!("Six-digit code sent by {channel}: "))
            .map(Zeroizing::new)
            .map_err(|error| AppError::config(format!("cannot read verification code: {error}")))
    }
}

// ---- result codes ----

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Password,
    Otp,
    Policy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Next {
    Link,
    Device,
    SecondFactor,
}

fn denied<T>(message: &str, hint: &str) -> Result<T, AppError> {
    Err(AppError::auth(message.to_owned(), hint))
}

/// What KAIST's result `code` means at this `stage`; unknown codes are a
/// protocol change.
fn next(stage: Stage, code: &str) -> Result<Next, AppError> {
    use Stage::{Otp, Password, Policy};
    match (stage, code) {
        (_, "SS0001" | "SS0007") | (Policy, "") => Ok(Next::Link),
        (_, "SS0099") => Ok(Next::Device),
        (Password, "SS0098") => Ok(Next::SecondFactor),
        (Password | Policy, "SS0004" | "SS0005" | "SS0006") => Err(AppError::auth_required(
            "KAIST requires a password update before this account can sign in",
        )),
        (Password, "EAU001") => Err(AppError::credentials_rejected(
            "KAIST rejected the login identifier or password",
        )),
        (Password, "EAU005" | "EAU006" | "EAU007") => denied(
            "KAIST temporarily locked password login after repeated failures",
            "Wait for the lockout to expire, then retry.",
        ),
        (Otp, "E001") => Err(AppError::code_incorrect(
            "The verification code is incorrect",
        )),
        (Otp, "E002") => Err(AppError::code_expired("The verification code expired")),
        (Otp, "E003") => denied(
            "Too many verification attempts",
            "Retry login to request a new code.",
        ),
        (_, "ES0017") | (Password | Policy, "EAU016" | "EAU017" | "EAU018") => {
            let what = match stage {
                Password => "login",
                Otp => "verification",
                Policy => "login policy",
            };
            Err(AppError::auth_protocol(format!(
                "KAIST rejected the {what} transaction"
            )))
        }
        _ => Err(AppError::auth_protocol(format!(
            "KAIST SSO returned unknown result code {code:?}"
        ))),
    }
}

/// `Ok(true)` once the Easy Login request is approved, `Ok(false)` while pending.
fn easy_approved(code: &str) -> Result<bool, AppError> {
    match code {
        "" | "SS0001" => Ok(true),
        "ESY020" => Ok(false),
        "ESY021" => denied(
            "Easy Login is temporarily blocked",
            "Wait and retry after the block expires.",
        ),
        "ESY022" => denied(
            "Easy Login is blocked for this account",
            "Use password login or contact KAIST support.",
        ),
        "ESY023" => denied(
            "Easy Login was cancelled",
            "Run `kaist-mail auth login --method easy` to start again.",
        ),
        "ESY024" => denied(
            "Easy Login verification did not match",
            "Start a new Easy Login request.",
        ),
        "E004" => denied("Easy Login expired", "Start a new Easy Login request."),
        other => Err(AppError::auth_protocol(format!(
            "KAIST SSO returned unknown result code {other:?}"
        ))),
    }
}

// ---- login payload encryption ----

fn encrypt_user_data(login_key: &str, json: &[u8]) -> Result<String, AppError> {
    let malformed = || AppError::auth_protocol("KAIST SSO returned malformed hexadecimal data");
    let unhex = |hex: &str| -> Result<Vec<u8>, AppError> {
        let nibble = |byte: &u8| (*byte as char).to_digit(16).map(|digit| digit as u8);
        hex.as_bytes()
            .chunks_exact(2)
            .map(|pair| Some(nibble(&pair[0])? << 4 | nibble(&pair[1])?))
            .collect::<Option<_>>()
            .ok_or_else(malformed)
    };
    if login_key.len() < 96 || !login_key.is_ascii() {
        return Err(AppError::auth_protocol(
            "KAIST SSO returned a malformed login key",
        ));
    }
    let key = Zeroizing::new(unhex(&login_key[..64])?);
    let iv = Zeroizing::new(unhex(&login_key[64..96])?);
    // CryptoJS accepts a 256-bit parsed key, but KISA SEED is a 128-bit cipher.
    // Its implementation consumes the first 128 bits, matching the live site.
    let cipher = cbc::Encryptor::<SEED>::new_from_slices(&key[..16], &iv)
        .map_err(|_| AppError::auth_protocol("KAIST SSO returned an invalid login key"))?;
    let encrypted = cipher.encrypt_padded_vec_mut::<AnsiX923>(json);
    Ok(encrypted.iter().map(|byte| format!("{byte:02x}")).collect())
}

// ---- the conversation ----

pub struct CompletedLogin {
    pub cookies: Vec<StoredCookie>,
    pub devices: Vec<String>,
}

pub enum Outcome {
    Complete(CompletedLogin),
    CodeRequired(PendingLogin),
}

/// Everything one login attempt needs besides its prompt.
pub struct Attempt<'a> {
    pub dooray: &'a Url,
    pub sso: &'a Url,
    pub timeout: u64,
    pub method: LoginMethod,
    pub factor: Option<SecondFactor>,
    pub previous_devices: &'a [String],
    /// Stop after sending a second-factor code instead of prompting for it.
    pub defer_code: bool,
    /// Answers already known (`--user`, a remembered identifier or password);
    /// the prompt is asked for the rest.
    pub username: Option<String>,
    pub password: Option<Zeroizing<String>>,
}

pub struct Begun {
    pub outcome: Outcome,
    /// The identifier and (password method) password that KAIST accepted.
    pub username: String,
    pub password: Option<Zeroizing<String>>,
}

pub fn begin(attempt: Attempt<'_>, prompt: &mut impl AuthPrompt) -> Result<Begun, AppError> {
    let Attempt {
        dooray,
        sso,
        timeout,
        method,
        factor,
        previous_devices,
        defer_code,
        username,
        password,
    } = attempt;
    let mut transport = SsoTransport::new(dooray.clone(), sso.clone(), timeout)?;
    start_saml(&mut transport)?;
    let username = match username {
        Some(username) => username,
        None => {
            let typed = prompt.identifier()?;
            validate_username(&typed)?;
            typed
        }
    };
    let mut password_used = None;
    let mut pending = None;
    if method == LoginMethod::Easy {
        easy_login(&mut transport, &username, previous_devices)?;
    } else {
        let password = match password {
            Some(password) => password,
            None => prompt.password()?,
        };
        if password.is_empty() {
            return Err(AppError::usage("password cannot be empty"));
        }
        let factor = factor.unwrap_or(SecondFactor::Email);
        let payload = PasswordLogin {
            agt_id: AGENT_ID,
            device_cd: previous_devices,
            link_url: LINK_URL,
            login_id: &username,
            login_pwd: &password,
        };
        let response = auth_request(&mut transport, &payload, "/auth/user/login/auth")?;
        match next(Stage::Password, result_code(&response)?)? {
            Next::Link => link(&mut transport)?,
            Next::Device => register_device(&mut transport)?,
            Next::SecondFactor => {
                if second_factor(&mut transport, factor, prompt, defer_code)? {
                    pending = Some(PendingLogin::new(
                        dooray,
                        &username,
                        factor,
                        transport.document_url(),
                        previous_devices,
                        &transport.cookies,
                    ));
                }
            }
        }
        password_used = Some(password);
    }
    let outcome = match pending {
        Some(pending) => Outcome::CodeRequired(pending),
        None => Outcome::Complete(finish(&transport, previous_devices)?),
    };
    Ok(Begun {
        outcome,
        username,
        password: password_used,
    })
}

/// Finish a login whose code was requested by an earlier process. The flag
/// is false when KAIST gave no answer to the code (a NETWORK_ERROR while
/// sending it), so the same pending login can be retried.
pub fn resume(
    dooray: &Url,
    sso: &Url,
    timeout: u64,
    pending: &PendingLogin,
    code: &str,
) -> (bool, Result<CompletedLogin, AppError>) {
    let mut transport = match prepare(dooray, sso, timeout, pending) {
        Ok(transport) => transport,
        Err(error) => return (true, Err(error)),
    };
    let answer = send_code(&mut transport, code);
    let answered = !matches!(&answer, Err(error) if error.code == "NETWORK_ERROR");
    let completed = answer
        .and_then(|response| check_code(&mut transport, &response))
        .and_then(|()| finish(&transport, &pending.previous_devices));
    (answered, completed)
}

fn prepare(
    dooray: &Url,
    sso: &Url,
    timeout: u64,
    pending: &PendingLogin,
) -> Result<SsoTransport, AppError> {
    let mut transport = SsoTransport::new(dooray.clone(), sso.clone(), timeout)?;
    transport.cookies = pending.jar.clone().checked()?;
    if let Some(document) = &pending.document_url {
        let url = Url::parse(document)
            .map_err(|_| AppError::config("saved login state has an invalid document URL"))?;
        transport.set_document_url(url)?;
    }
    Ok(transport)
}

fn finish(transport: &SsoTransport, previous: &[String]) -> Result<CompletedLogin, AppError> {
    let cookies = transport.cookies.dooray_cookies(transport.dooray());
    if cookies.is_empty() {
        return Err(AppError::auth_protocol(
            "KAIST SSO did not establish a Dooray session",
        ));
    }
    let mut devices = previous.to_vec();
    devices.extend(transport.cookies.device_values());
    devices.sort();
    devices.dedup();
    Ok(CompletedLogin { cookies, devices })
}

/// The password step's JSON body, serialized straight into a zeroized buffer
/// (fields in the order the SSO page's own script emits them).
#[derive(Serialize)]
struct PasswordLogin<'a> {
    agt_id: &'a str,
    device_cd: &'a [String],
    #[serde(rename = "linkUrl")]
    link_url: &'a str,
    login_id: &'a str,
    login_pwd: &'a str,
}

/// Serialize `value` into a buffer sized exactly up front, so no copy of a
/// secret is left behind by a reallocation, and zeroized on drop.
fn encode_secret_json(value: &impl Serialize) -> Result<Zeroizing<Vec<u8>>, AppError> {
    struct Count(usize);
    impl Write for Count {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0 += bytes.len();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let failed = |error: serde_json::Error| {
        AppError::internal(format!("failed to encode login request: {error}"))
    };
    let mut count = Count(0);
    serde_json::to_writer(&mut count, value).map_err(failed)?;
    let mut buffer = Zeroizing::new(Vec::with_capacity(count.0));
    serde_json::to_writer(&mut *buffer, value).map_err(failed)?;
    Ok(buffer)
}

/// Encrypt `payload` with a fresh login key and POST it to `path`.
fn auth_request(
    transport: &mut SsoTransport,
    payload: &impl Serialize,
    path: &str,
) -> Result<Value, AppError> {
    let init = transport.ajax("/auth/user/login/init", &[])?;
    let key = init
        .get("result_data")
        .or_else(|| init.get("resultData"))
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::auth_protocol("KAIST SSO login init omitted its key"))?;
    let payload = encode_secret_json(payload)?;
    let encrypted = encrypt_user_data(key, &payload)?;
    transport.ajax(path, &[("user_data", encrypted.as_str())])
}

/// Ask KAIST to send the code. `Ok(true)` means it was sent and (with
/// `defer_code`) is still to be entered by a later `--code` run.
fn second_factor(
    transport: &mut SsoTransport,
    factor: SecondFactor,
    prompt: &mut impl AuthPrompt,
    defer_code: bool,
) -> Result<bool, AppError> {
    let form = [("user_gubun", "user"), ("linkUrl", LINK_URL)];
    transport.post("/auth/kaist/user/login/second/view", &form)?;
    let (endpoint, channel) = match factor {
        SecondFactor::Email => ("/auth/kaist/user/login/second/ajaxSendMail", "email"),
        SecondFactor::Sms => ("/auth/kaist/user/login/second/ajaxSendSms", "SMS"),
    };
    let response = transport.ajax(endpoint, &[])?;
    match result_code(&response)? {
        "SS0001" => {}
        "ES0003" => {
            return denied(
                "KAIST has no usable destination for that verification method",
                "Retry with the other `--second-factor` value.",
            );
        }
        "ES0018" => {
            return denied(
                "KAIST verification requests are temporarily limited",
                "Wait, then retry login.",
            );
        }
        "EMS_FAIL" | "UMS_FAIL" | "EMS_ERR_CONNECT" | "UMS_ERR_CONNECT" => {
            return Err(AppError::network(
                "KAIST could not deliver the verification code",
            ));
        }
        other => {
            return Err(AppError::auth_protocol(format!(
                "KAIST returned unknown verification-send code {other:?}"
            )));
        }
    }
    if defer_code {
        return Ok(true);
    }
    eprintln!("KAIST sent a verification code. It expires in three minutes.");
    let otp = prompt.otp(channel)?;
    verify_code(transport, &otp)?;
    Ok(false)
}

/// Check a six-digit code with KAIST and finish the link/device step.
fn verify_code(transport: &mut SsoTransport, otp: &str) -> Result<(), AppError> {
    let response = send_code(transport, otp)?;
    check_code(transport, &response)
}

fn send_code(transport: &mut SsoTransport, otp: &str) -> Result<Value, AppError> {
    check_code_format(otp)?;
    let path = "/auth/kaist/user/login/second/ajaxValidCrtfcNo";
    transport.ajax(path, &[("crtfc_no", otp)])
}

fn check_code(transport: &mut SsoTransport, response: &Value) -> Result<(), AppError> {
    let step = next(Stage::Otp, result_code(response)?)?;
    proceed(transport, step)
}

pub fn check_code_format(otp: &str) -> Result<(), AppError> {
    if otp.len() != 6 || !otp.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(AppError::usage(
            "verification code must contain exactly six digits",
        ));
    }
    Ok(())
}

fn easy_login(
    transport: &mut SsoTransport,
    username: &str,
    previous_devices: &[String],
) -> Result<(), AppError> {
    let payload = json!({"login_id": username, "agt_id": AGENT_ID});
    let response = auth_request(transport, &payload, "/auth/twofactor/mfa/init")?;
    let code = result_code(&response)?;
    if code == "ESY008" {
        return Err(AppError::auth(
            "Easy Login is not registered for this account",
            "Use `kaist-mail auth login --method password`.",
        ));
    }
    if !matches!(code, "" | "SS0001") {
        return Err(AppError::auth_protocol(format!(
            "KAIST returned unknown Easy Login init code {code:?}"
        )));
    }
    let (_, challenge) =
        transport.post("/auth/twofactor/mfa/login2Factor", &[("linkUrl", LINK_URL)])?;
    let display = super::parse::easy_login_code(&challenge).or_else(|| {
        ["display_code", "displayCode", "auth_no", "authNo"]
            .iter()
            .find_map(|key| response.get(key).and_then(Value::as_str))
            .map(str::to_owned)
    });
    match display {
        Some(code) => eprintln!("Approve Easy Login in the KAIST app. Confirmation code: {code}"),
        None => eprintln!("Approve the Easy Login request in the KAIST app within three minutes."),
    }
    let mut approved = false;
    for _ in 0..EASY_POLLS {
        let response = transport.ajax("/auth/twofactor/mfa/auth", &[])?;
        approved = easy_approved(result_code(&response)?)?;
        if approved {
            break;
        }
        thread::sleep(Duration::from_secs(EASY_POLL_SECS));
    }
    if !approved {
        return Err(AppError::auth(
            "Easy Login timed out",
            "Run `kaist-mail auth login --method easy` to start again.",
        ));
    }
    let devices = transport.cookies.device_values();
    let form: Vec<_> = previous_devices
        .iter()
        .chain(&devices)
        .map(|device| ("device", device.as_str()))
        .collect();
    let response = transport.ajax("/auth/kaist/user/login/check/policy", &form)?;
    let step = next(Stage::Policy, result_code(&response)?)?;
    proceed(transport, step)
}

/// Finish a login whose password or code step was accepted.
fn proceed(transport: &mut SsoTransport, step: Next) -> Result<(), AppError> {
    match step {
        Next::Device => register_device(transport),
        _ => link(transport),
    }
}

/// Walk Dooray's sign-in entry to its KAIST SAML button and follow it to the
/// SSO login page, which must be rendered for Dooray's agent.
fn start_saml(transport: &mut SsoTransport) -> Result<(), AppError> {
    let signin = dooray_url(transport, "/auth/signin")?;
    let (url, html) = transport.get(signin.as_str())?;
    let (url, html) = if transport.is_dooray_origin(&url) {
        let button = super::parse::saml_button(&html).ok_or_else(|| {
            AppError::auth_protocol("Dooray's sign-in page has no KAIST SAML login option")
        })?;
        let button = dooray_url(transport, &button)?;
        transport.get(button.as_str())?
    } else {
        (url, html)
    };
    if url.path() != LOGIN_VIEW || super::parse::agent_id(&html).as_deref() != Some(AGENT_ID) {
        return Err(AppError::auth_protocol(format!(
            "Dooray's SAML request did not reach the KAIST SSO login page for {AGENT_ID} (ended at {}{})",
            url.host_str().unwrap_or("unknown-host"),
            url.path()
        )));
    }
    Ok(())
}

fn dooray_url(transport: &SsoTransport, reference: &str) -> Result<Url, AppError> {
    transport
        .dooray()
        .join(reference)
        .ok()
        .filter(|url| transport.is_dooray_origin(url))
        .ok_or_else(|| AppError::auth_protocol("Dooray sent an off-site sign-in link"))
}

/// Ask KAIST SSO for the `SAMLResponse`, as its own pages do after a
/// successful step, and hand it to Dooray.
fn link(transport: &mut SsoTransport) -> Result<(), AppError> {
    let (url, html) = transport.get(&format!("/auth{LINK_URL}"))?;
    handoff(transport, url, &html)
}

/// Post the SSO page's `SAMLResponse` form to Dooray's assertion consumer
/// and check that Dooray did not bounce the browser back to sign-in.
fn handoff(transport: &mut SsoTransport, url: Url, html: &str) -> Result<(), AppError> {
    let url = if transport.is_dooray_origin(&url) {
        url
    } else {
        let form = super::parse::handoff_form(html, &url, transport.dooray())?;
        let fields: Vec<_> = form
            .fields
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        transport.post(form.action.as_str(), &fields)?.0
    };
    if !transport.is_dooray_origin(&url) || is_signin_path(url.path()) {
        return Err(AppError::auth_protocol(format!(
            "Dooray did not accept the KAIST SSO sign-in (ended at {}{})",
            url.host_str().unwrap_or("unknown-host"),
            url.path()
        )));
    }
    Ok(())
}

/// Dooray pages that mean "not signed in": the entry and the IdP chooser,
/// but not `/auth/signin/finalize`, where a successful login lands.
pub fn is_signin_path(path: &str) -> bool {
    path == "/auth/signin" || path.starts_with("/idp/")
}

fn result_code(value: &Value) -> Result<&str, AppError> {
    [
        "result_code",
        "resultCode",
        "errorCode",
        "error_code",
        "code",
    ]
    .iter()
    .find_map(|key| value.get(key).and_then(Value::as_str))
    .or_else(|| value.as_bool().and_then(|ok| ok.then_some("")))
    .or_else(|| {
        let ok = value.get("result").and_then(Value::as_bool);
        (ok == Some(true) || value.get("result_data").is_some()).then_some("")
    })
    .ok_or_else(|| {
        let keys = value
            .as_object()
            .map(|object| object.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        AppError::auth_protocol(format!(
            "KAIST SSO response omitted its result code (fields: {keys:?})"
        ))
    })
}

fn register_device(transport: &mut SsoTransport) -> Result<(), AppError> {
    const REGISTER: &str = "/auth/kaist/user/device/ajaxRegist";
    const COMPLETE: &str = "/auth/kaist/user/device/login";
    let (_, html) = transport.get("/auth/kaist/user/device/view")?;
    let actions = super::parse::auth_policy_shape(&html);
    if ![REGISTER, COMPLETE]
        .iter()
        .all(|wanted| actions.iter().any(|action| action == wanted))
    {
        return Err(AppError::auth_protocol(
            "KAIST device-registration page omitted its expected actions",
        ));
    }
    let response = transport.ajax(REGISTER, &[])?;
    let code = result_code(&response)?;
    if !matches!(code, "" | "SS0001") {
        return Err(AppError::auth_protocol(format!(
            "KAIST returned unknown device-registration code {code:?}"
        )));
    }
    let device = response
        .get("device_cd")
        .or_else(|| response.get("deviceCd"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            AppError::auth_protocol("KAIST device registration omitted its identifier")
        })?;
    transport.cookies.remember_device(device)?;
    let (url, html) = transport.get(COMPLETE)?;
    if url.path() == format!("/auth{LINK_URL}") || transport.is_dooray_origin(&url) {
        return handoff(transport, url, &html);
    }
    link(transport)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_body_is_exactly_sized_and_matches_the_page_json() {
        let devices = ["d1".to_owned(), "d\"2".to_owned()];
        let body = encode_secret_json(&PasswordLogin {
            agt_id: AGENT_ID,
            device_cd: &devices,
            link_url: LINK_URL,
            login_id: "student",
            login_pwd: "pa\"ss\\é",
        })
        .unwrap();
        let old = json!({
            "login_id": "student",
            "login_pwd": "pa\"ss\\é",
            "agt_id": AGENT_ID,
            "linkUrl": LINK_URL,
            "device_cd": devices,
        });
        assert_eq!(body.as_slice(), serde_json::to_vec(&old).unwrap());
        assert_eq!(body.capacity(), body.len(), "never reallocated");
    }

    #[test]
    fn result_codes_map_per_stage_and_unknown_ones_are_protocol_changes() {
        use Stage::{Otp, Password, Policy};
        for (stage, code, expected) in [
            (Password, "SS0001", Next::Link),
            (Password, "SS0098", Next::SecondFactor),
            (Password, "SS0099", Next::Device),
            (Otp, "SS0007", Next::Link),
            (Policy, "", Next::Link),
        ] {
            assert_eq!(next(stage, code).unwrap(), expected, "{code}");
        }
        for (stage, code, error) in [
            (Password, "SS0004", "AUTH_REQUIRED"),
            (Password, "EAU001", "CREDENTIALS_REJECTED"),
            (Password, "EAU005", "AUTH_REQUIRED"),
            (Password, "EAU016", "AUTH_PROTOCOL_CHANGED"),
            (Otp, "E001", "CODE_INCORRECT"),
            (Otp, "E002", "CODE_EXPIRED"),
            (Otp, "E003", "AUTH_REQUIRED"),
            (Otp, "ES0017", "AUTH_PROTOCOL_CHANGED"),
            (Otp, "SS0098", "AUTH_PROTOCOL_CHANGED"),
            (Policy, "SS0005", "AUTH_REQUIRED"),
            (Password, "NEW_CODE", "AUTH_PROTOCOL_CHANGED"),
            (Otp, "NEW_CODE", "AUTH_PROTOCOL_CHANGED"),
        ] {
            assert_eq!(next(stage, code).unwrap_err().code, error, "{code}");
        }
        assert!(easy_approved("SS0001").unwrap() && !easy_approved("ESY020").unwrap());
        assert_eq!(easy_approved("ESY021").unwrap_err().code, "AUTH_REQUIRED");
        assert_eq!(
            easy_approved("NEW_CODE").unwrap_err().code,
            "AUTH_PROTOCOL_CHANGED"
        );
    }

    #[test]
    fn seed_cbc_vector_and_malformed_keys() {
        let key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f101112131415161718191a1b1c1d1e1f";
        // Cross-checked against OpenSSL's legacy-provider SEED-CBC output.
        assert_eq!(
            encrypt_user_data(key, b"{}").unwrap(),
            "d558576b3e0adc65644f932e64d5a1e1"
        );
        // 63 ASCII bytes, then a 2-byte char straddling byte 64, padded past
        // 96: an error, not a panic. Non-hex digits are rejected too.
        let straddling = format!("{}é{}", "0".repeat(63), "0".repeat(40));
        assert!(straddling.len() >= 96 && !straddling.is_char_boundary(64));
        for bad in [straddling, "+f".repeat(48), "zz".repeat(48)] {
            let error = encrypt_user_data(&bad, b"{}").unwrap_err();
            assert_eq!(error.code, "AUTH_PROTOCOL_CHANGED", "{bad}");
        }
    }

    #[test]
    fn code_format_is_six_digits() {
        assert!(check_code_format("012345").is_ok());
        for bad in ["12ab", "1234567", "", "12 456"] {
            assert_eq!(check_code_format(bad).unwrap_err().code, "USAGE", "{bad}");
        }
    }
}
