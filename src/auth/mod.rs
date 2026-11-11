//! Native KAIST SSO login to Dooray and the files it leaves behind. This
//! module is the orchestration (`login`, `logout`, `forget`, `load`); the
//! sign-in conversation is in `flow`, the on-disk state in `store`, password
//! storage in `secret`.

mod cookies;
mod flow;
mod parse;
mod secret;
mod store;
mod transport;

use std::io::IsTerminal;

use serde::{Deserialize, Serialize};
use serde_json::json;
use zeroize::Zeroizing;

use crate::{
    error::AppError,
    output::{self, CommandResult},
    url::Url,
};

pub use flow::is_signin_path;
use flow::{Attempt, AuthPrompt, Outcome, TerminalPrompt};
use secret::Keychain;
pub use store::epoch_now;
use store::{Dirs, Identity};

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

#[derive(Debug)]
pub struct AuthSession {
    pub status: AuthStatus,
    /// The unexpired saved cookies; `None` when there are none.
    pub cookie_header: Option<String>,
    pub devices: Vec<String>,
}

pub fn load(base_url: &Url) -> Result<AuthSession, AppError> {
    let dirs = Dirs::from_env()?;
    let mut session = store::load_session(&dirs.session(), base_url, epoch_now())?;
    match store::load_identity(&dirs.identity()) {
        Ok(found) => {
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
#[derive(Debug, Default)]
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
    keychain: &'a Keychain,
    /// Standard input is a terminal, so prompts can be answered.
    interactive: bool,
    /// Stop after sending a second-factor code instead of prompting for it.
    defer_code: bool,
    /// `--json`: stderr carries only the JSON error document, so stay quiet.
    json: bool,
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
        keychain: &Keychain::system(),
        interactive,
        defer_code: !interactive || json,
        json,
    };
    login_with(&env, options, TerminalPrompt)
}

fn login_with(
    env: &Env<'_>,
    options: &LoginOptions,
    mut terminal: impl AuthPrompt,
) -> Result<CommandResult, AppError> {
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
    let stored = if password_login && !options.remember_password {
        let same_account = remembered
            .as_ref()
            .filter(|found| found.password_saved && Some(&found.username) == username.as_ref());
        stored_password(env, same_account, &mut warnings)?
    } else {
        None
    };
    if password_login && !env.interactive && stored.is_none() {
        let who = username.as_deref().unwrap_or("ID");
        return Err(AppError::auth(
            format!("no stored password for {who}, and there is no terminal to ask for one"),
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
    let begun = match flow::begin(
        Attempt {
            dooray: env.dooray,
            sso: env.sso,
            timeout: env.timeout,
            method,
            factor,
            previous_devices: &previous_devices,
            defer_code: env.defer_code,
            username,
            password: stored,
        },
        &mut terminal,
    ) {
        Err(error) if used_stored && error.code == "CREDENTIALS_REJECTED" => {
            return Err(drop_rejected_password(env, remembered, error, warnings));
        }
        begun => begun?,
    };
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

/// KAIST rejected the stored password. Every later non-interactive login would
/// resend it, and KAIST locks password login after repeated failures, so
/// login.json stops naming it even when the keychain cannot delete it now;
/// `auth forget` purges the whole service without that metadata.
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
            warnings.push(format!(
                "could not update the remembered login: {}",
                saved.message
            ));
        }
    }
    let what = if removed {
        "The stored password was removed."
    } else {
        "The stored password is no longer used but could not be deleted; run `kaist-mail auth forget`."
    };
    let error = error.with_hint(format!(
        "{what} Store the current one from a terminal with `kaist-mail auth login --method password --remember-password`."
    ));
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
            Ok(()) => identity.password_saved = true,
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

fn finish_login(
    env: &Env<'_>,
    completed: flow::CompletedLogin,
    identity: &Identity,
    mut warnings: Vec<String>,
) -> Result<CommandResult, AppError> {
    let cookie_names: Vec<_> = completed.cookies.iter().map(|c| c.name.clone()).collect();
    let device_count = completed.devices.len();
    let session_path = env.dirs.session();
    store::save_session(
        &session_path,
        env.dooray,
        completed.cookies,
        completed.devices,
    )
    .map_err(|error| store::with_cleanup_warnings(error, &warnings))?;
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

pub fn logout() -> Result<CommandResult, AppError> {
    let dirs = Dirs::from_env()?;
    let path = dirs.session();
    let mut warnings = Vec::new();
    let removed = store::remove_owned(&path, "Dooray session", &mut warnings);
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
