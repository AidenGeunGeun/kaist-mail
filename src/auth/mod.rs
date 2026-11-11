//! Native KAIST SSO login to Dooray and the files it leaves behind. This
//! module is the orchestration (`login`, `logout`, `forget`, `load`); renewal
//! without the user is in `renew`, the sign-in conversation in `flow`, the
//! on-disk state in `store`, password storage in `secret`.

mod cookies;
mod flow;
mod parse;
mod renew;
mod secret;
mod store;
mod transport;

use std::{
    io::IsTerminal,
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use serde_json::json;
use zeroize::Zeroizing;

use crate::{
    error::AppError,
    output::{self, CommandResult},
    url::Url,
};

pub use flow::is_signin_path;
use flow::{Attempt, AuthPrompt, CodeStep, Outcome, TerminalPrompt};
pub use renew::{extend, record_use, renew, renew_now, take_notes};
use secret::Keychain;
pub use store::epoch_now;
use store::{Dirs, Identity, PasswordHold, Renewal, StoredSession, Via};

pub const PRODUCTION_SSO: &str = "https://sso.kaist.ac.kr/";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum LoginMethod {
    Easy,
    Password,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum SecondFactor {
    Email,
    Sms,
}

impl LoginMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Easy => "easy",
            Self::Password => "password",
        }
    }
}

impl SecondFactor {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::Sms => "sms",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AuthStatus {
    pub configured: bool,
    pub path: String,
    pub created_at: Option<u64>,
    /// Cookie names and expiry only; values never leave the session file.
    pub cookies: Vec<CookieStatus>,
    pub device_count: usize,
    /// The remembered login (`login.json`), without any secret.
    pub remembered: Option<Remembered>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remembered_error: Option<String>,
    pub renewal: RenewalStatus,
}

/// How the session can be renewed without the user, and what is known
/// about how long Dooray and KAIST SSO keep an idle session.
#[derive(Debug, Clone, Default, Serialize)]
pub struct RenewalStatus {
    pub available: Vec<Via>,
    pub last_used_at: Option<u64>,
    /// Why renewal will not use the stored password, if it will not.
    pub password_hold: Option<PasswordHold>,
    pub longest_idle_accepted: Option<u64>,
    pub last: Option<Renewal>,
}

impl RenewalStatus {
    /// `auth status` lines for people.
    pub fn lines(&self, now: u64) -> Vec<String> {
        let ago = |at: u64| output::duration(now.saturating_sub(at));
        let ways: Vec<_> = self.available.iter().map(|via| via.label()).collect();
        let mut lines = vec![match ways.is_empty() {
            true => "Renewal: none (any `kaist-mail auth login` keeps the KAIST SSO session; `--method password --remember-password` adds password renewal)".to_owned(),
            false => format!("Renewal: {}", ways.join(", ")),
        }];
        if let Some(hold) = self.password_hold {
            let lift = match hold {
                PasswordHold::CodeRequired => "the next `kaist-mail auth login` lifts this",
                _ => {
                    "store it again with `kaist-mail auth login --method password --remember-password`"
                }
            };
            lines.push(format!(
                "Password renewal stopped: {}; {lift}",
                hold.reason()
            ));
        }
        if let Some(at) = self.last_used_at {
            lines.push(format!("Last used: {} ago", ago(at)));
        }
        if let Some(idle) = self.longest_idle_accepted {
            lines.push(format!(
                "Dooray accepted the session after up to {} idle",
                output::duration(idle)
            ));
        }
        if let Some(last) = &self.last {
            let mut line = format!(
                "Last renewal: {} ago, {}",
                ago(last.at),
                last.via.map_or("failed", Via::label)
            );
            if let Some(idle) = last.dooray_rejected_after {
                line.push_str(&format!(
                    "; Dooray had rejected the session after {} idle",
                    output::duration(idle)
                ));
            }
            if let Some(sso) = last.sso {
                let state = if sso.alive { "still valid" } else { "ended" };
                line.push_str(&format!(
                    "; KAIST SSO session {state} after {} idle",
                    output::duration(sso.idle)
                ));
            }
            lines.push(line);
        }
        lines
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CookieStatus {
    pub name: String,
    pub expires_at: Option<u64>,
    pub expired: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Remembered {
    pub username: String,
    pub method: String,
    pub second_factor: Option<String>,
    pub password_saved: bool,
}

pub struct AuthSession {
    pub status: AuthStatus,
    /// The unexpired saved cookies; `None` when there are none.
    pub cookie_header: Option<String>,
    pub devices: Vec<String>,
}

pub fn load(base_url: &Url) -> Result<AuthSession, AppError> {
    let dirs = Dirs::from_env()?;
    let mut session = store::load_session(&dirs.session(), base_url, epoch_now())?;
    let renewal = &mut session.status.renewal;
    renewal.last_used_at = store::last_used(&dirs.session_used());
    renewal.password_hold = store::read_hold(&dirs.password_hold())?;
    let hold = renewal.password_hold;
    match store::load_identity(&dirs.identity()) {
        Ok(found) => {
            if found
                .as_ref()
                .is_some_and(|identity| identity.password_saved)
                && hold.is_none()
            {
                session.status.renewal.available.push(Via::Password);
            }
            session.status.remembered = found.map(|identity| Remembered {
                username: identity.username,
                method: identity.method.as_str().to_owned(),
                second_factor: identity.second_factor.map(|f| f.as_str().to_owned()),
                password_saved: identity.password_saved,
            });
        }
        Err(error) => session.status.remembered_error = Some(error.message),
    }
    Ok(session)
}

/// Flags of `kaist-mail auth login`, already parsed.
#[derive(Default)]
pub struct LoginOptions {
    pub user: Option<String>,
    pub method: Option<LoginMethod>,
    pub factor: Option<SecondFactor>,
    pub remember_password: bool,
    pub code: Option<String>,
}

/// Where a login runs: endpoints plus how interactive the process is.
struct Env<'a> {
    dirs: &'a Dirs,
    dooray: &'a Url,
    sso: &'a Url,
    timeout: u64,
    /// The command's own deadline (`--max-seconds`), which a renewal keeps to.
    deadline: Option<Instant>,
    keychain: &'a Keychain,
    /// Standard input is a terminal, so prompts can be answered.
    interactive: bool,
    code: CodeStep,
    /// `--json`: stderr carries only the JSON error document, so stay quiet.
    json: bool,
}

impl Env<'_> {
    /// How long to wait for another sign-in, renewal or sign-out.
    fn lock_wait(&self) -> Duration {
        Duration::from_secs(self.timeout)
    }
}

/// The SSO origin for `base_url`: KAIST's for production Dooray, and for a
/// loopback fixture the one named by `KAIST_MAIL_SSO_URL`.
fn sso_url(base_url: &Url) -> Result<Url, AppError> {
    if !crate::url::is_http_loopback(base_url) {
        return Ok(Url::parse(PRODUCTION_SSO).expect("valid SSO URL"));
    }
    std::env::var("KAIST_MAIL_SSO_URL")
        .ok()
        .and_then(|value| Url::parse(&value).ok())
        .ok_or_else(|| AppError::config("a loopback --base-url needs KAIST_MAIL_SSO_URL"))
}

pub fn login(
    base_url: &Url,
    timeout: u64,
    options: &LoginOptions,
    json: bool,
) -> Result<CommandResult, AppError> {
    let sso = sso_url(base_url)?;
    let dirs = Dirs::from_env()?;
    let interactive = std::io::stdin().is_terminal();
    let env = Env {
        dirs: &dirs,
        dooray: base_url,
        sso: &sso,
        timeout,
        deadline: None,
        keychain: &match interactive {
            true => Keychain::system(),
            false => Keychain::system().unattended(),
        },
        interactive,
        code: if interactive && !json {
            CodeStep::Prompt
        } else {
            CodeStep::Defer
        },
        json,
    };
    login_with(&env, options, TerminalPrompt)
}

fn login_with(
    env: &Env<'_>,
    options: &LoginOptions,
    mut terminal: impl AuthPrompt,
) -> Result<CommandResult, AppError> {
    // From reading the stored password to saving the session: one sign-in
    // or renewal at a time, so none resends a password another just had refused.
    let _lock = store::lock_session(&env.dirs.session_lock(), env.lock_wait())?;
    if let Some(code) = &options.code {
        return resume_login(env, code);
    }
    let remembered = store::load_identity(&env.dirs.identity())?;
    let method = options
        .method
        .or(remembered.as_ref().map(|found| found.method))
        .unwrap_or(LoginMethod::Easy);
    let password_login = method == LoginMethod::Password;
    if options.factor.is_some() && !password_login {
        return Err(AppError::usage(
            "--second-factor applies only to password login",
        ));
    }
    if options.remember_password && !password_login {
        return Err(AppError::usage(
            "--remember-password applies only to password login (Easy Login has no password)",
        ));
    }
    if options.remember_password && !env.interactive {
        return Err(AppError::usage(
            "--remember-password needs a terminal to read the password; run it once from an interactive shell",
        ));
    }
    // Refuse before any network traffic when there is nowhere to keep a password.
    if options.remember_password && !env.keychain.available() {
        return Err(AppError::config(
            "cannot remember the password: the macOS keychain is not available here",
        )
        .with_hint("Omit `--remember-password` and enter the password each time."));
    }
    if !password_login && !env.interactive {
        return Err(AppError::auth(
            "Easy Login needs you to approve a request in the KAIST app, so it cannot run without a terminal",
            "Use `kaist-mail auth login --method password --second-factor email`; after one interactive `kaist-mail auth login --method password --remember-password`, that works non-interactively in two steps (the first prints CODE_REQUIRED, then `kaist-mail auth login --code CODE`).",
        ));
    }
    let factor = password_login.then(|| {
        options
            .factor
            .or(remembered.as_ref().and_then(|found| found.second_factor))
            .unwrap_or(SecondFactor::Email)
    });
    let username = options
        .user
        .clone()
        .or_else(|| remembered.as_ref().map(|found| found.username.clone()));
    if let Some(username) = &username {
        store::validate_username(username)?;
    }
    if username.is_none() && !env.interactive {
        return Err(AppError::usage(
            "no KAIST ID is remembered; pass `--user ID` (an interactive login also remembers it)",
        ));
    }

    let mut warnings = Vec::new();
    let hold_path = env.dirs.password_hold();
    let hold = store::read_hold(&hold_path)?;
    if hold == Some(PasswordHold::CodeRequired) {
        // An explicit login is what lifts this hold.
        settle_hold(env, Settle::Clear, &mut warnings);
    }
    let held = hold.filter(|hold| *hold != PasswordHold::CodeRequired);
    let stored = if password_login && !options.remember_password && held.is_none() {
        let same_account = remembered
            .as_ref()
            .filter(|found| found.password_saved && Some(&found.username) == username.as_ref());
        stored_password(env, same_account, &mut warnings)?
    } else {
        None
    };
    if password_login && !env.interactive && stored.is_none() {
        let who = username.as_deref().unwrap_or("ID");
        let message = match held {
            Some(hold) => format!(
                "kaist-mail will not send the stored password for {who} again: {}",
                hold.reason()
            ),
            None => {
                format!("no stored password for {who}, and there is no terminal to ask for one")
            }
        };
        return Err(AppError::auth(
            message,
            "Store it once from an interactive shell with `kaist-mail auth login --method password --remember-password`.",
        ));
    }
    if let Some(username) = username.as_ref().filter(|_| !env.json) {
        eprintln!("Signing in as {username} ({})", method.as_str());
    }

    let previous_devices = store::load_session(&env.dirs.session(), env.dooray, epoch_now())
        .map(|session| session.devices)
        .unwrap_or_default();
    let used_stored = stored.is_some();
    let hold_unresolved = || store::write_hold(&hold_path, PasswordHold::Unresolved);
    let begun = flow::begin(
        Attempt {
            dooray: env.dooray,
            sso: env.sso,
            timeout: env.timeout,
            deadline: None,
            method,
            factor,
            previous_devices: &previous_devices,
            code: env.code,
            username,
            password: stored,
            before_password: used_stored.then_some(&hold_unresolved as _),
        },
        &mut terminal,
    );
    let begun = match used_stored {
        true => settle_stored(env, remembered.clone(), begun, &mut warnings),
        false => begun,
    }
    .map_err(|error| store::with_cleanup_warnings(error, &warnings))?;
    // KAIST accepted the credentials (even if it still wants a code), so it
    // is safe to remember them now.
    let new_password = begun
        .password
        .as_ref()
        .filter(|_| options.remember_password);
    let identity = remember_login(
        env,
        remembered.as_ref(),
        Identity::new(&begun.username, method, factor),
        new_password,
        &mut warnings,
    );
    match begun.outcome {
        Outcome::Complete(completed) => {
            let result = finish_login(env, completed, &identity, warnings)?;
            if new_password.is_some() && identity.password_saved && !env.json {
                eprintln!("Password saved to the macOS keychain.");
            }
            Ok(result)
        }
        Outcome::CodeRequired(pending) => {
            store::save_json(&env.dirs.pending(), &pending, "pending login")
                .map_err(|error| store::with_cleanup_warnings(error, &warnings))?;
            let error = AppError::code_required(pending.second_factor.as_str(), pending.expires_at);
            Err(store::with_cleanup_warnings(error, &warnings))
        }
        Outcome::CodeDeclined => Err(AppError::internal(
            "a login declined the code it was asked to handle",
        )),
    }
}

/// What KAIST's answer to the stored password means for its hold.
enum Settle {
    /// KAIST accepted it.
    Clear,
    Hold(PasswordHold),
    /// No clear answer: the [`PasswordHold::Unresolved`] written just before
    /// the password left stays (and none was written if it never left).
    Keep,
}

/// Record KAIST's verdict on an automatic use of the stored password; a
/// refusal also drops it.
fn settle_stored(
    env: &Env<'_>,
    remembered: Option<Identity>,
    begun: Result<flow::Begun, AppError>,
    warnings: &mut Vec<String>,
) -> Result<flow::Begun, AppError> {
    let settle = match &begun {
        Ok(flow::Begun {
            outcome: Outcome::CodeDeclined,
            ..
        }) => Settle::Hold(PasswordHold::CodeRequired),
        Ok(_) => Settle::Clear,
        // Wrong or stale password, password change due, lockout.
        Err(error) if matches!(error.code, "CREDENTIALS_REJECTED" | "AUTH_REQUIRED") => {
            Settle::Hold(PasswordHold::Refused)
        }
        Err(_) => Settle::Keep,
    };
    let refused = matches!(settle, Settle::Hold(PasswordHold::Refused));
    settle_hold(env, settle, warnings);
    match begun {
        Err(error) if refused => Err(drop_rejected_password(
            env,
            remembered,
            error,
            std::mem::take(warnings),
        )),
        begun => begun,
    }
}

/// Record KAIST's verdict on the stored password. A failure leaves the hold
/// written before the attempt, which keeps automatic use stopped.
fn settle_hold(env: &Env<'_>, settle: Settle, warnings: &mut Vec<String>) {
    let path = env.dirs.password_hold();
    let settled = match settle {
        Settle::Clear => store::remove_file(&path, "password hold").map(drop),
        Settle::Hold(hold) => store::write_hold(&path, hold),
        Settle::Keep => Ok(()),
    };
    if let Err(error) = settled {
        warnings.push(format!(
            "could not record the stored password's state: {}",
            error.message
        ));
    }
}

/// Look up the remembered password; `Ok(None)` when nothing usable is stored.
fn stored_password(
    env: &Env<'_>,
    remembered: Option<&Identity>,
    warnings: &mut Vec<String>,
) -> Result<Option<Zeroizing<String>>, AppError> {
    let Some(found) = remembered else {
        return Ok(None);
    };
    match env.keychain.lookup(&found.username) {
        Err(error) if env.interactive => {
            warnings.push(format!(
                "could not read the stored password ({}); asking for it instead",
                error.message
            ));
            Ok(None)
        }
        other => other,
    }
}

/// KAIST refused the stored password: rejected it, or wants it changed, or
/// locked password login. Every later non-interactive login would resend it,
/// and KAIST locks password login after repeated failures, so login.json
/// stops naming it even when the keychain cannot delete it now; `auth forget`
/// purges the whole service without that metadata.
fn drop_rejected_password(
    env: &Env<'_>,
    remembered: Option<Identity>,
    error: AppError,
    mut warnings: Vec<String>,
) -> AppError {
    let mut removed = true;
    if let Some(mut identity) = remembered {
        identity.password_saved = false;
        if let Err(cleared) = env.keychain.clear(&identity.username) {
            removed = false;
            warnings.push(format!(
                "could not remove the rejected password from the keychain: {}",
                cleared.message
            ));
        }
        if let Err(saved) = store::save_json(&env.dirs.identity(), &identity, "remembered login") {
            removed = false;
            warnings.push(format!(
                "could not update the remembered login: {}",
                saved.message
            ));
        }
    }
    // Its hold, written before the attempt, keeps it from being sent again.
    let what = if removed {
        "The stored password was removed."
    } else {
        "kaist-mail will not send the stored password again, but could not remove it (see warnings); `kaist-mail auth forget` removes it."
    };
    let next = match error.code {
        "CREDENTIALS_REJECTED" => "Store the current one from a terminal with `kaist-mail auth login --method password --remember-password`.".to_owned(),
        _ => error.hint.clone().unwrap_or_default(),
    };
    let error = error.with_hint(format!("{what} {next}"));
    store::with_cleanup_warnings(error, &warnings)
}

/// Persist `login.json` (and the password, when given) after KAIST accepted
/// the credentials. Failures are warnings: the sign-in itself already worked.
fn remember_login(
    env: &Env<'_>,
    previous: Option<&Identity>,
    mut identity: Identity,
    new_password: Option<&Zeroizing<String>>,
    warnings: &mut Vec<String>,
) -> Identity {
    let username = identity.username.clone();
    let same = previous.filter(|found| found.username == username);
    identity.second_factor = identity
        .second_factor
        .or(same.and_then(|found| found.second_factor));
    identity.password_saved = same.is_some_and(|found| found.password_saved);
    // A different account: its password must not linger.
    if let Some(old) = previous.filter(|found| found.username != username && found.password_saved) {
        if let Err(error) = env.keychain.clear(&old.username) {
            warnings.push(format!(
                "could not remove the stored password of {}: {}",
                old.username, error.message
            ));
        }
    }
    if let Some(password) = new_password {
        match env.keychain.store(&username, password) {
            Ok(()) => {
                identity.password_saved = true;
                settle_hold(env, Settle::Clear, warnings);
            }
            Err(error) => {
                warnings.push(format!(
                    "could not remember the password: {}",
                    error.message
                ));
                // The old password is now stale: never keep using it.
                if std::mem::take(&mut identity.password_saved) {
                    if let Err(error) = env.keychain.clear(&username) {
                        warnings.push(format!(
                            "the previously remembered password is no longer used but could not be removed: {}",
                            error.message
                        ));
                    }
                }
            }
        }
    }
    if let Err(error) = store::save_json(&env.dirs.identity(), &identity, "remembered login") {
        warnings.push(format!("could not remember the login: {}", error.message));
        if new_password.is_some() && std::mem::take(&mut identity.password_saved) {
            if let Err(error) = env.keychain.clear(&username) {
                warnings.push(format!(
                    "could not roll back the stored password: {}; run `kaist-mail auth forget`",
                    error.message
                ));
            }
        }
    }
    identity
}

/// Save the session a sign-in produced once Dooray treats it as signed in,
/// keeping what the old session measured; returns its `Cookie` header.
fn adopt(
    env: &Env<'_>,
    completed: flow::CompletedLogin,
    renewal: Option<Renewal>,
) -> Result<String, AppError> {
    let path = env.dirs.session();
    let earlier = store::read_session(&path, env.dooray).ok().flatten();
    let mut session = StoredSession::new(
        env.dooray,
        completed.cookies,
        completed.devices,
        completed.sso,
        earlier.as_ref(),
    );
    session.renewal = renewal.or(session.renewal);
    let header = session.cookie_header(epoch_now()).unwrap_or_default();
    crate::client::Client::with_cookie(env.dooray.clone(), header.clone(), env.timeout)
        .wapi::<serde::de::IgnoredAny>(crate::client::SYSTEM_FOLDERS)
        .map_err(|error| match error.code {
            "AUTH_EXPIRED" => AppError::auth_protocol(
                "Dooray did not accept the session the KAIST SSO sign-in produced",
            ),
            _ => error,
        })?;
    store::save_session(&path, &session)?;
    // Only a measurement: a failure must not fail the sign-in.
    let _ = store::mark_used(&env.dirs.session_used());
    Ok(header)
}

fn finish_login(
    env: &Env<'_>,
    completed: flow::CompletedLogin,
    identity: &Identity,
    mut warnings: Vec<String>,
) -> Result<CommandResult, AppError> {
    let cookie_names: Vec<_> = completed.cookies.iter().map(|c| c.name.clone()).collect();
    let device_count = completed.devices.len();
    let session_path = env.dirs.session();
    adopt(env, completed, None).map_err(|error| store::with_cleanup_warnings(error, &warnings))?;
    store::remove_owned(&env.dirs.pending(), "pending login", &mut warnings);
    let method = identity.method.as_str();
    let human = format!(
        "Signed in to Dooray with {method} login.\nSession: {}",
        session_path.display()
    );
    let data = json!({
        "method": method,
        "second_factor": identity.second_factor.filter(|_| identity.method == LoginMethod::Password).map(SecondFactor::as_str),
        "user": identity.username,
        "session_path": session_path.display().to_string(),
        "cookies": cookie_names,
        "device_count": device_count,
        "password_saved": identity.password_saved,
    });
    let mut result = output::result("auth.login", &data, human)?;
    result.warnings = warnings;
    Ok(result)
}

fn resume_login(env: &Env<'_>, code: &str) -> Result<CommandResult, AppError> {
    flow::check_code_format(code)?;
    let pending_path = env.dirs.pending();
    let pending = store::load_pending(&pending_path, env.dooray, epoch_now())?;
    let (answered, completed) = flow::resume(env.dooray, env.sso, env.timeout, &pending, code);
    // Once KAIST has answered, the challenge is used up whether or not the
    // code was right; without an answer the same code can be retried.
    let mut warnings = Vec::new();
    if answered {
        store::remove_owned(&pending_path, "pending login", &mut warnings);
    }
    let completed = completed.map_err(|error| store::with_cleanup_warnings(error, &warnings))?;
    let previous = store::load_identity(&env.dirs.identity()).ok().flatten();
    let login = Identity::new(
        &pending.username,
        LoginMethod::Password,
        Some(pending.second_factor),
    );
    let identity = remember_login(env, previous.as_ref(), login, None, &mut warnings);
    finish_login(env, completed, &identity, warnings)
}

pub fn logout(timeout: u64) -> Result<CommandResult, AppError> {
    logout_with(&Dirs::from_env()?, Duration::from_secs(timeout))
}

fn logout_with(dirs: &Dirs, wait: Duration) -> Result<CommandResult, AppError> {
    // A renewal in flight finishes first, so it cannot bring the session back.
    let _lock = store::lock_session(&dirs.session_lock(), wait)?;
    let path = dirs.session();
    let mut warnings = Vec::new();
    let removed = store::remove_owned(&path, "Dooray session", &mut warnings);
    store::remove_owned(&dirs.session_used(), "last-used marker", &mut warnings);
    let pending_removed = store::remove_owned(&dirs.pending(), "pending login", &mut warnings);
    let human = if !warnings.is_empty() {
        "Local logout cleanup was incomplete; see warnings.".to_owned()
    } else if removed {
        format!("Removed local Dooray session: {}", path.display())
    } else {
        format!("No local Dooray session was present at {}", path.display())
    };
    let data = json!({"session_path": path.display().to_string(), "removed": removed,
        "pending_removed": pending_removed, "cleanup_complete": warnings.is_empty()});
    let mut result = output::result("auth.logout", &data, human)?;
    result.warnings = warnings;
    Ok(result)
}

pub fn forget() -> Result<CommandResult, AppError> {
    forget_with(&Dirs::from_env()?, &Keychain::system())
}

fn forget_with(dirs: &Dirs, keychain: &Keychain) -> Result<CommandResult, AppError> {
    let mut warnings = Vec::new();
    // Purge the whole service, including accounts absent from login.json.
    let password_removed = match keychain.available().then(|| keychain.clear_all()) {
        None => false,
        Some(Ok(removed)) => removed,
        Some(Err(error)) => {
            warnings.push(format!(
                "could not purge keychain passwords: {}; retry `kaist-mail auth forget` when the keychain is unlocked",
                error.message
            ));
            false
        }
    };
    // Keep login.json while its password may still be in the keychain, so
    // the next forget knows to retry.
    let login_removed = if warnings.is_empty() {
        store::remove_owned(&dirs.identity(), "remembered login", &mut warnings)
    } else {
        false
    };
    let pending_removed = store::remove_owned(&dirs.pending(), "pending login", &mut warnings);
    let human = if !warnings.is_empty() {
        "Forget cleanup was incomplete; see warnings. The saved Dooray session is unchanged."
            .to_owned()
    } else {
        "Remembered login cleanup finished. The saved Dooray session is unchanged; `kaist-mail auth logout` removes it.".to_owned()
    };
    let data = json!({
        "login_removed": login_removed,
        "password_removed": password_removed,
        "pending_removed": pending_removed,
        "cleanup_complete": warnings.is_empty(),
    });
    let mut result = output::result("auth.forget", &data, human)?;
    result.warnings = warnings;
    Ok(result)
}

#[cfg(test)]
mod tests;
