//! Renewing the saved session without the user once Dooray rejects it: first
//! by answering a fresh SAML request with the saved KAIST SSO session, as a
//! browser still signed in to KAIST does, then by a password login with the
//! remembered password from a device KAIST trusts. Neither can start Easy
//! Login, send a verification code or prompt. Renewals run one at a time
//! across processes, under the session lock.

use std::{
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use serde_json::json;
use zeroize::Zeroizing;

use crate::{
    client::Client,
    error::AppError,
    output::{self, CommandResult, duration},
    url::Url,
};

use super::{
    Attempt, AuthPrompt, CodeStep, Dirs, Env, Identity, Keychain, LoginMethod, Outcome,
    PasswordHold, Renewal, SecondFactor, Via, adopt,
    cookies::Jar,
    epoch_now, flow, settle_stored, sso_url,
    store::{self, SsoCheck},
};

const MEMBERS_ME: &str = "/v2/wapi/members/me";

/// One command renews at most once, so a session Dooray keeps rejecting
/// cannot loop into repeated logins.
static RENEWED: AtomicBool = AtomicBool::new(false);
/// Set once this process has recorded that Dooray accepted the session.
static USED: AtomicBool = AtomicBool::new(false);
/// What renewal did in this process, for the command's warnings.
static NOTES: Mutex<Vec<String>> = Mutex::new(Vec::new());

pub fn take_notes() -> Vec<String> {
    NOTES
        .lock()
        .map(|mut notes| std::mem::take(&mut *notes))
        .unwrap_or_default()
}

/// Dooray rejected the saved session sent as `rejected`: renew it and
/// return the `Cookie` header to retry with.
pub fn renew(
    base_url: &Url,
    timeout: u64,
    deadline: Option<Instant>,
    rejected: &str,
) -> Result<String, AppError> {
    if RENEWED.swap(true, Ordering::SeqCst) {
        return Err(AppError::auth_expired(
            "Dooray rejected the session kaist-mail had just renewed",
        ));
    }
    let renewed = with_env(base_url, timeout, deadline, |env| {
        renew_with(env, Trigger::Rejected(rejected))
    })?;
    if let Ok(mut notes) = NOTES.lock() {
        notes.push(renewed.note);
    }
    Ok(renewed.header)
}

/// `auth renew`: replace a working session now, as a rejected one would be.
pub fn renew_now(base_url: &Url, timeout: u64) -> Result<CommandResult, AppError> {
    let renewed = with_env(base_url, timeout, None, |env| {
        renew_with(env, Trigger::Requested)
    })?;
    let data = json!({"via": renewed.via.map(Via::label)});
    output::result("auth.renew", &data, renewed.note)
}

/// `auth extend`: one call Dooray counts as activity, which restarts its
/// idle timer; a session it already rejected is renewed as for any command.
pub fn extend(base_url: &Url, timeout: u64) -> Result<CommandResult, AppError> {
    Client::new(base_url.clone(), timeout)?.wapi::<serde::de::IgnoredAny>(MEMBERS_ME)?;
    let renewed = RENEWED.load(Ordering::SeqCst);
    let human = match renewed {
        true => "Dooray had ended the session; kaist-mail renewed it (see warnings).",
        false => "Dooray session extended.",
    };
    output::result(
        "auth.extend",
        &json!({"renewed": renewed}),
        human.to_owned(),
    )
}

/// Dooray accepted the saved session: move its last-used time and keep the
/// longest idle gap Dooray has accepted. A failure here loses only that
/// measurement, never the command's result, so it is not reported.
pub fn record_use(base_url: &Url) {
    if USED.swap(true, Ordering::SeqCst) {
        return;
    }
    let Ok(dirs) = Dirs::from_env() else {
        return;
    };
    let path = dirs.session();
    let used = dirs.session_used();
    let last_used = store::last_used(&used);
    let _ = store::mark_used(&used);
    let Some(idle) = last_used.map(|at| epoch_now().saturating_sub(at)) else {
        return;
    };
    let longer = |session: &store::StoredSession| {
        session
            .longest_idle_accepted
            .is_none_or(|longest| idle > longest)
    };
    // Most calls follow a short gap: look before waiting for the lock.
    if !matches!(store::read_session(&path, base_url), Ok(Some(session)) if longer(&session)) {
        return;
    }
    let Ok(_lock) = store::lock_session(&dirs.session_lock(), Duration::ZERO) else {
        return;
    };
    if let Ok(Some(mut session)) = store::read_session(&path, base_url) {
        if longer(&session) {
            session.longest_idle_accepted = Some(idle);
            let _ = store::save_session(&path, &session);
        }
    }
}

fn with_env<T>(
    base_url: &Url,
    timeout: u64,
    deadline: Option<Instant>,
    run: impl FnOnce(&Env<'_>) -> Result<T, AppError>,
) -> Result<T, AppError> {
    let dirs = Dirs::from_env()?;
    let sso = sso_url(base_url)?;
    // Each wait (the lock, the check of a new session) fits in what is left.
    let left = deadline.map(|deadline| deadline.saturating_duration_since(Instant::now()));
    let timeout = left.map_or(timeout, |left| timeout.min(left.as_secs() + 1));
    run(&Env {
        dirs: &dirs,
        dooray: base_url,
        sso: &sso,
        timeout,
        deadline,
        keychain: &Keychain::system().unattended(),
        interactive: false,
        code: CodeStep::Refuse,
        json: true,
    })
}

#[derive(Clone, Copy)]
pub(super) enum Trigger<'a> {
    /// Dooray rejected this `Cookie` header.
    Rejected(&'a str),
    /// The user asked for a new session (`auth renew`).
    Requested,
}

pub(super) struct Renewed {
    pub header: String,
    /// `None` when another process had already renewed the session.
    pub via: Option<Via>,
    pub note: String,
}

pub(super) fn renew_with(env: &Env<'_>, trigger: Trigger<'_>) -> Result<Renewed, AppError> {
    let path = env.dirs.session();
    let _lock = store::lock_session(&env.dirs.session_lock(), env.lock_wait())?;
    let now = epoch_now();
    let mut stored = store::read_session(&path, env.dooray)?
        .ok_or_else(|| AppError::auth_required("there is no saved Dooray session to renew"))?;
    let last_used = store::last_used(&env.dirs.session_used()).unwrap_or(stored.created_at);
    let rejected_after = match trigger {
        Trigger::Rejected(rejected) => {
            if let Some(header) = stored
                .cookie_header(now)
                .filter(|header| header != rejected)
            {
                return Ok(Renewed {
                    header,
                    via: None,
                    note: "another kaist-mail process had already renewed the session".to_owned(),
                });
            }
            Some(now.saturating_sub(last_used))
        }
        Trigger::Requested => None,
    };
    let mut record = Renewal {
        at: now,
        via: None,
        dooray_rejected_after: rejected_after,
        sso: None,
    };
    let mut reasons = Vec::new();
    let mut network = None;
    let mut hint = None;

    if !stored.sso.is_empty() {
        let idle = now.saturating_sub(stored.created_at);
        let reused = flow::reuse_sso(
            env.dooray,
            env.sso,
            env.timeout,
            env.deadline,
            stored.sso.clone(),
            &stored.devices,
        );
        match reused {
            Ok(Some(completed)) => {
                record.sso = Some(SsoCheck { idle, alive: true });
                record.via = Some(Via::SsoSession);
                match adopt(env, completed, Some(record.clone())) {
                    Ok(header) => return Ok(renewed(header, &record)),
                    Err(error) => reasons.push(format!(
                        "Dooray refused the session from the KAIST SSO session: {}",
                        error.message
                    )),
                }
                record.via = None;
            }
            Ok(None) => {
                record.sso = Some(SsoCheck { idle, alive: false });
                stored.sso = Jar::default();
                reasons.push(format!(
                    "the KAIST SSO session had ended after {} idle",
                    duration(idle)
                ));
            }
            Err(error) => {
                reasons.push(format!(
                    "could not reuse the KAIST SSO session: {}",
                    error.message
                ));
                network = network.or((error.code == "NETWORK_ERROR").then_some(error));
            }
        }
    }

    let hold = store::read_hold(&env.dirs.password_hold());
    match (store::load_identity(&env.dirs.identity()), hold) {
        (Err(error), _) | (_, Err(error)) => reasons.push(error.message),
        (Ok(Some(identity)), Ok(Some(hold))) if identity.password_saved => {
            reasons.push(format!(
                "the stored password is not used: {}",
                hold.reason()
            ));
            hint = Some(
                match hold {
                    PasswordHold::CodeRequired => CODE_HINT,
                    _ => ENABLE_PASSWORD,
                }
                .to_owned(),
            );
        }
        (Ok(Some(identity)), Ok(None)) if identity.password_saved => {
            match password_login(env, identity, &stored.devices) {
                Ok(completed) => {
                    record.via = Some(Via::Password);
                    match adopt(env, completed, Some(record.clone())) {
                        Ok(header) => return Ok(renewed(header, &record)),
                        Err(error) => reasons.push(error.message),
                    }
                    record.via = None;
                }
                Err(error) => {
                    reasons.push(error.message.clone());
                    hint = error.hint.clone();
                    network = network.or((error.code == "NETWORK_ERROR").then_some(error));
                }
            }
        }
        (Ok(_), Ok(_)) => reasons.push("no password is remembered".to_owned()),
    }

    stored.renewal = Some(record);
    if let Err(error) = store::save_session(&path, &stored) {
        reasons.push(error.message);
    }
    let reasons = reasons.join("; ");
    if let Some(error) = network {
        // Retrying can succeed, so say so instead of asking for a login.
        let mut failed =
            AppError::network(format!("could not renew the Dooray session: {reasons}"));
        failed.hint = error.hint;
        return Err(failed);
    }
    let hint = hint.unwrap_or_else(|| ENABLE_PASSWORD.to_owned());
    Err(match trigger {
        Trigger::Rejected(_) => AppError::auth_expired(format!(
            "Dooray rejected the saved session and kaist-mail could not renew it: {reasons}"
        )),
        Trigger::Requested => {
            AppError::auth_required(format!("could not renew the session: {reasons}"))
        }
    }
    .with_hint(hint))
}

const CODE_HINT: &str = "Sign in once from a terminal with `kaist-mail auth login --method password` and enter the code; renewal uses the password again after that login, and skips the code once KAIST registers this device.";

const ENABLE_PASSWORD: &str = "Run `kaist-mail auth login`. To let kaist-mail renew the session without your phone once the KAIST SSO session has also ended, sign in once with `kaist-mail auth login --method password --remember-password`.";

fn renewed(header: String, record: &Renewal) -> Renewed {
    let cause = match record.dooray_rejected_after {
        Some(idle) => format!(
            "Dooray rejected the session after {} idle; ",
            duration(idle)
        ),
        None => String::new(),
    };
    let how = match (record.via, record.sso) {
        (Some(Via::SsoSession), Some(sso)) => {
            format!(
                "renewed it with the KAIST SSO session, {} after it was last used",
                duration(sso.idle)
            )
        }
        (_, Some(sso)) if !sso.alive => format!(
            "renewed it by password login (the KAIST SSO session had ended after {} idle)",
            duration(sso.idle)
        ),
        _ => "renewed it by password login".to_owned(),
    };
    Renewed {
        header,
        via: record.via,
        note: format!("{cause}{how}"),
    }
}

/// A password login with the remembered password that succeeds only when
/// KAIST asks for no second factor, which it skips for a trusted device.
fn password_login(
    env: &Env<'_>,
    identity: Identity,
    devices: &[String],
) -> Result<flow::CompletedLogin, AppError> {
    let password = env.keychain.lookup(&identity.username)?.ok_or_else(|| {
        AppError::auth_expired("the remembered password is no longer in the keychain")
    })?;
    let hold_unresolved = || store::write_hold(&env.dirs.password_hold(), PasswordHold::Unresolved);
    let begun = flow::begin(
        Attempt {
            dooray: env.dooray,
            sso: env.sso,
            timeout: env.timeout,
            deadline: env.deadline,
            method: LoginMethod::Password,
            factor: Some(identity.second_factor.unwrap_or(SecondFactor::Email)),
            previous_devices: devices,
            code: CodeStep::Refuse,
            username: Some(identity.username.clone()),
            password: Some(password),
            before_password: Some(&hold_unresolved),
        },
        &mut NoPrompt,
    );
    let mut warnings = Vec::new();
    let begun = settle_stored(env, Some(identity), begun, &mut warnings)
        .map_err(|error| store::with_cleanup_warnings(error, &warnings))?;
    match begun.outcome {
        Outcome::Complete(completed) => Ok(completed),
        Outcome::CodeDeclined => Err(AppError::auth_expired(
            "KAIST asked for a verification code, so it does not trust this device for password login; renewal stops using the password until the next `kaist-mail auth login`",
        )
        .with_hint(CODE_HINT)),
        Outcome::CodeRequired(_) => Err(AppError::internal(
            "a renewal login stopped for a code it must never request",
        )),
    }
}

/// Renewal has every answer up front; reaching a prompt is a bug.
struct NoPrompt;

impl AuthPrompt for NoPrompt {
    fn identifier(&mut self) -> Result<String, AppError> {
        Err(AppError::internal("renewal never prompts for a KAIST ID"))
    }
    fn password(&mut self) -> Result<Zeroizing<String>, AppError> {
        Err(AppError::internal("renewal never prompts for a password"))
    }
    fn otp(&mut self, _channel: &str) -> Result<Zeroizing<String>, AppError> {
        Err(AppError::internal("renewal never prompts for a code"))
    }
}
