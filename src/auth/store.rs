//! Everything `kaist-mail auth` keeps on disk, all private (0700 directory,
//! 0600 file, atomic replace): the Dooray session cookies, the remembered
//! login (`login.json`, in the config directory so `auth logout` leaves it)
//! and the pending second-factor login.

use std::{
    env, fs,
    io::{ErrorKind, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    error::AppError,
    url::{Url, is_http_loopback},
};

use super::{
    AuthSession, AuthStatus, CookieStatus, LoginMethod, SecondFactor,
    cookies::{self, Jar},
};

const VERSION: u32 = 1;
const PENDING_TTL_SECS: u64 = 300;
const APP: &str = "kaist-mail";

pub fn epoch_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

#[derive(Debug, Clone)]
pub struct Dirs {
    /// `$XDG_CONFIG_HOME/kaist-mail` or `~/.config/kaist-mail`.
    pub config: PathBuf,
    /// `$XDG_STATE_HOME/kaist-mail` or `~/.local/state/kaist-mail`.
    pub state: PathBuf,
}

fn xdg(var: &str, fallback: &str) -> Result<PathBuf, AppError> {
    let home = env::var_os("HOME").map(PathBuf::from);
    crate::private_fs::xdg_home(var, home.as_deref(), fallback)
        .map(|root| root.join(APP))
        .ok_or_else(|| AppError::config(format!("HOME or {var} is required for Dooray login")))
}

impl Dirs {
    pub fn from_env() -> Result<Self, AppError> {
        Ok(Self {
            config: xdg("XDG_CONFIG_HOME", ".config")?,
            state: xdg("XDG_STATE_HOME", ".local/state")?,
        })
    }
    pub fn session(&self) -> PathBuf {
        self.state.join("session.json")
    }
    pub fn pending(&self) -> PathBuf {
        self.state.join("pending-login.json")
    }
    pub fn identity(&self) -> PathBuf {
        self.config.join("login.json")
    }
}

/// Atomically replace `path` with `bytes` at mode 0600 inside a 0700 parent.
/// `what` names the file in error messages.
fn write_private(path: &Path, bytes: &[u8], what: &str) -> Result<(), AppError> {
    let parent = path
        .parent()
        .ok_or_else(|| AppError::internal(format!("invalid {what} path")))?;
    fs::create_dir_all(parent).map_err(|error| {
        AppError::config(format!("cannot create {}: {error}", parent.display()))
    })?;
    let secure = |path: &Path, mode| {
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .map_err(|error| AppError::config(format!("cannot secure {}: {error}", path.display())))
    };
    secure(parent, 0o700)?;
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".{}.tmp", std::process::id()));
    let temp = path.with_file_name(name);
    remove_file(&temp, what)?;
    let written = crate::private_fs::private_file_options()
        .create_new(true)
        .open(&temp)
        .map_err(|error| AppError::config(format!("cannot create private {what} file: {error}")))
        .and_then(|mut file| {
            file.write_all(bytes)
                .and_then(|()| file.sync_all())
                .map_err(|error| AppError::config(format!("cannot write {what} file: {error}")))
        })
        .and_then(|()| {
            fs::rename(&temp, path)
                .map_err(|error| AppError::config(format!("cannot install {what} file: {error}")))
        });
    if let Err(error) = written {
        let warnings = remove_file(&temp, what)
            .err()
            .map(|error| error.message)
            .into_iter()
            .collect::<Vec<_>>();
        return Err(with_cleanup_warnings(error, &warnings));
    }
    secure(path, 0o600)
}

pub fn save_json(path: &Path, value: &impl Serialize, what: &str) -> Result<(), AppError> {
    let bytes = Zeroizing::new(
        serde_json::to_vec_pretty(value)
            .map_err(|error| AppError::internal(format!("failed to encode {what}: {error}")))?,
    );
    write_private(path, &bytes, what)
}

/// The file's bytes, or `None` when it does not exist.
pub fn read_file(path: &Path, what: &str) -> Result<Option<Zeroizing<Vec<u8>>>, AppError> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(Zeroizing::new(bytes))),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(AppError::config(format!(
            "cannot read {what} {}: {error}",
            path.display()
        ))),
    }
}

/// Remove `path`; `Ok(false)` when it was already absent.
pub fn remove_file(path: &Path, what: &str) -> Result<bool, AppError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => Err(AppError::config(format!(
            "cannot remove {what} {}: {error}",
            path.display()
        ))),
    }
}

/// Remove an owned file and its crash-leftover `<filename>.<pid>.tmp` files.
/// Continue after failures so one bad path cannot prevent the rest of cleanup.
pub fn remove_owned(path: &Path, what: &str, warnings: &mut Vec<String>) -> bool {
    let removed = match remove_file(path, what) {
        Ok(removed) => removed,
        Err(error) => {
            warnings.push(error.message);
            false
        }
    };
    let parent = path.parent().expect("auth file has a parent");
    let entries = match fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(error) if error.kind() == ErrorKind::NotFound => return removed,
        Err(error) => {
            warnings.push(format!("cannot scan {}: {error}", parent.display()));
            return removed;
        }
    };
    let prefix = format!("{}.", path.file_name().unwrap().to_string_lossy());
    for entry in entries.flatten() {
        let name = entry.file_name();
        let is_temp = name
            .to_string_lossy()
            .strip_prefix(&prefix)
            .and_then(|name| name.strip_suffix(".tmp"))
            .is_some_and(|pid| !pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit()));
        if is_temp {
            if let Err(error) = remove_file(&entry.path(), what) {
                warnings.push(error.message);
            }
        }
    }
    removed
}

pub fn with_cleanup_warnings(mut error: AppError, warnings: &[String]) -> AppError {
    if !warnings.is_empty() {
        error.details.get_or_insert_with(|| serde_json::json!({}))["warnings"] =
            serde_json::json!(warnings);
        // Human error output prints the message, not details.
        error
            .message
            .push_str(&format!("; cleanup warnings: {}", warnings.join("; ")));
    }
    error
}

// ---- session ----

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredCookie {
    pub name: String,
    pub value: String,
    /// Unix seconds from `Max-Age`/`Expires`; `None` for a browser-session cookie.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

#[derive(Serialize, Deserialize)]
struct StoredSession {
    version: u32,
    origin: String,
    created_at: u64,
    cookies: Vec<StoredCookie>,
    /// KAIST SSO trusted-device ids, offered on the next login.
    #[serde(default)]
    devices: Vec<String>,
}

fn check_cookies(cookies: &[StoredCookie]) -> Result<(), AppError> {
    if cookies
        .iter()
        .all(|cookie| cookies::valid_cookie(&cookie.name, &cookie.value))
    {
        return Ok(());
    }
    Err(AppError::config("saved session contains an invalid cookie"))
}

/// Load the saved session, leaving out cookies whose expiry has passed.
pub fn load_session(path: &Path, base_url: &Url, now: u64) -> Result<AuthSession, AppError> {
    let mut status = AuthStatus {
        configured: false,
        path: path.display().to_string(),
        created_at: None,
        cookies: Vec::new(),
        device_count: 0,
        remembered: None,
        remembered_error: None,
    };
    let Some(bytes) = read_file(path, "Dooray session")? else {
        return Ok(AuthSession {
            status,
            cookie_header: None,
            devices: Vec::new(),
        });
    };
    let stored: StoredSession = serde_json::from_slice(&bytes).map_err(|error| {
        AppError::config(format!(
            "invalid Dooray session {}: {error}",
            path.display()
        ))
    })?;
    if stored.version != VERSION {
        return Err(AppError::config(format!(
            "unsupported Dooray session version {}; sign in again",
            stored.version
        )));
    }
    if !origin_matches(&stored.origin, base_url) {
        return Err(AppError::config(
            "saved Dooray session belongs to a different origin; sign in again",
        ));
    }
    check_cookies(&stored.cookies)?;
    let live = stored
        .cookies
        .iter()
        .filter(|cookie| cookie.expires_at.is_none_or(|at| at > now))
        .collect::<Vec<_>>();
    let header = live
        .iter()
        .map(|cookie| format!("{}={}", cookie.name, cookie.value))
        .collect::<Vec<_>>()
        .join("; ");
    status.configured = true;
    status.created_at = Some(stored.created_at);
    status.device_count = stored.devices.len();
    status.cookies = stored
        .cookies
        .iter()
        .map(|cookie| CookieStatus {
            name: cookie.name.clone(),
            expires_at: cookie.expires_at,
            expired: cookie.expires_at.is_some_and(|at| at <= now),
        })
        .collect();
    Ok(AuthSession {
        status,
        cookie_header: (!header.is_empty()).then_some(header),
        devices: stored.devices,
    })
}

pub fn save_session(
    path: &Path,
    base_url: &Url,
    cookies: Vec<StoredCookie>,
    devices: Vec<String>,
) -> Result<(), AppError> {
    if cookies.is_empty() {
        return Err(AppError::auth_protocol(
            "KAIST SSO completed without Dooray issuing a session cookie",
        ));
    }
    check_cookies(&cookies)?;
    let stored = StoredSession {
        version: VERSION,
        origin: origin(base_url),
        created_at: epoch_now(),
        cookies,
        devices,
    };
    save_json(path, &stored, "session")
}

pub fn origin(url: &Url) -> String {
    format!(
        "{}://{}:{}",
        url.scheme(),
        url.host_str().unwrap_or_default(),
        url.port_or_known_default().unwrap_or(0)
    )
}

/// Loopback test servers may move between ports; real origins must match.
fn origin_matches(stored: &str, current: &Url) -> bool {
    stored == origin(current)
        || Url::parse(stored).is_ok_and(|url| is_http_loopback(&url) && is_http_loopback(current))
}

// ---- remembered login ----

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Identity {
    pub version: u32,
    pub username: String,
    pub method: LoginMethod,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub second_factor: Option<SecondFactor>,
    /// Whether the password is in the macOS keychain.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub password_saved: bool,
}

impl Identity {
    pub fn new(username: &str, method: LoginMethod, factor: Option<SecondFactor>) -> Self {
        Self {
            version: VERSION,
            username: username.to_owned(),
            method,
            second_factor: factor,
            password_saved: false,
        }
    }
}

/// Reject identifiers that could not be a KAIST login and could corrupt
/// keychain command lines.
pub fn validate_username(username: &str) -> Result<(), AppError> {
    if username.trim().is_empty()
        || username != username.trim()
        || username.len() > 254
        || username.chars().any(char::is_control)
    {
        return Err(AppError::usage(
            "login identifier must be a non-empty KAIST ID or email without control characters",
        ));
    }
    Ok(())
}

pub fn load_identity(path: &Path) -> Result<Option<Identity>, AppError> {
    let Some(bytes) = read_file(path, "remembered login")? else {
        return Ok(None);
    };
    let invalid = |detail: String| {
        AppError::config(format!(
            "invalid remembered login {}: {detail}",
            path.display()
        ))
        .with_hint("Run `kaist-mail auth forget` to discard it, then sign in again.")
    };
    let identity: Identity =
        serde_json::from_slice(&bytes).map_err(|error| invalid(error.to_string()))?;
    if identity.version != VERSION {
        return Err(invalid(format!("unsupported version {}", identity.version)));
    }
    validate_username(&identity.username).map_err(|error| invalid(error.message))?;
    Ok(Some(identity))
}

// ---- pending second-factor login ----

/// What survives between "KAIST sent the code" and "the code was typed": the
/// cookie jar (the code is bound to the SSO session cookie and the SAML
/// request to the Dooray one), the trusted devices known so far, the last
/// document URL (for `Referer` and `Origin`) and who is signing in. Never a
/// password; expires after five minutes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingLogin {
    pub version: u32,
    pub dooray_origin: String,
    pub username: String,
    pub second_factor: SecondFactor,
    pub expires_at: u64,
    pub document_url: Option<String>,
    pub previous_devices: Vec<String>,
    pub jar: Jar,
}

impl PendingLogin {
    pub fn new(
        dooray: &Url,
        username: &str,
        second_factor: SecondFactor,
        document_url: Option<&Url>,
        previous_devices: &[String],
        jar: &Jar,
    ) -> Self {
        Self {
            version: VERSION,
            dooray_origin: origin(dooray),
            username: username.to_owned(),
            second_factor,
            expires_at: epoch_now() + PENDING_TTL_SECS,
            document_url: document_url.map(Url::to_string),
            previous_devices: previous_devices.to_vec(),
            jar: jar.clone(),
        }
    }
}

/// Read a pending login that is still valid for `dooray`. A missing, expired,
/// unreadable or foreign file is an error; all but "missing" also delete it
/// so it cannot be retried.
pub fn load_pending(path: &Path, dooray: &Url, now: u64) -> Result<PendingLogin, AppError> {
    let Some(bytes) = read_file(path, "pending login")? else {
        return Err(AppError::code_expired(
            "no login is waiting for a verification code",
        ));
    };
    let discard = |message: &str| {
        let mut warnings = Vec::new();
        remove_owned(path, "pending login", &mut warnings);
        with_cleanup_warnings(AppError::code_expired(message.to_owned()), &warnings)
    };
    let pending: PendingLogin = serde_json::from_slice(&bytes)
        .map_err(|_| discard("the pending login file is unreadable"))?;
    if pending.version != VERSION {
        return Err(discard(
            "the pending login file is from another kaist-mail version",
        ));
    }
    if now >= pending.expires_at {
        return Err(discard("the pending login expired"));
    }
    if !origin_matches(&pending.dooray_origin, dooray) {
        return Err(discard(
            "the pending login belongs to a different Dooray origin",
        ));
    }
    Ok(pending)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dooray() -> Url {
        Url::parse("https://kaist.gov-dooray.com/").unwrap()
    }

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    fn cookie(name: &str, value: &str, expires_at: Option<u64>) -> StoredCookie {
        StoredCookie {
            name: name.into(),
            value: value.into(),
            expires_at,
        }
    }

    #[test]
    fn sessions_are_private_reject_unsafe_cookies_and_drop_expired_ones() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kaist-mail/session.json");
        let cookies = vec![
            cookie("SESSION", "abc", None),
            cookie("old", "x", Some(100)),
            cookie("fresh", "y", Some(200)),
        ];
        save_session(&path, &dooray(), cookies, vec![]).unwrap();
        assert_eq!((mode(&path), mode(path.parent().unwrap())), (0o600, 0o700));
        let session = load_session(&path, &dooray(), 100).unwrap();
        assert_eq!(
            session.cookie_header.as_deref(),
            Some("SESSION=abc; fresh=y")
        );
        let expired = session.status.cookies.iter().map(|c| c.expired);
        assert_eq!(expired.collect::<Vec<_>>(), [false, true, false]);

        for (name, value) in [
            ("n", "a;b"),
            ("n", ""),
            ("n", "a\r\nX: y"),
            ("bad\r\n", "x"),
        ] {
            let result = save_session(&path, &dooray(), vec![cookie(name, value, None)], vec![]);
            assert_eq!(result.unwrap_err().code, "CONFIG_ERROR", "{value:?}");
        }
        for value in ["", "a;b", r"a\tb"] {
            let body = format!(
                r#"{{"version":1,"origin":"https://kaist.gov-dooray.com:443","created_at":1,"cookies":[{{"name":"n","value":"{value}"}}]}}"#
            );
            fs::write(&path, body).unwrap();
            let error = load_session(&path, &dooray(), 0).unwrap_err();
            assert_eq!(error.code, "CONFIG_ERROR");
        }
    }

    #[test]
    fn identity_round_trips_and_corrupt_files_point_to_forget() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kaist-mail/login.json");
        assert_eq!(load_identity(&path).unwrap(), None);
        let identity = Identity::new("student", LoginMethod::Password, Some(SecondFactor::Sms));
        save_json(&path, &identity, "remembered login").unwrap();
        assert_eq!(load_identity(&path).unwrap(), Some(identity));
        assert_eq!(mode(&path), 0o600);
        for body in [
            "not json",
            r#"{"version":9,"username":"a","method":"easy"}"#,
            r#"{"version":1,"username":"","method":"easy"}"#,
            r#"{"version":1,"username":"a","method":"magic"}"#,
        ] {
            fs::write(&path, body).unwrap();
            let error = load_identity(&path).unwrap_err();
            assert_eq!(error.code, "CONFIG_ERROR");
            assert!(error.hint.unwrap().contains("auth forget"));
        }
    }

    #[test]
    fn pending_logins_expire_and_foreign_or_corrupt_files_are_discarded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kaist-mail/pending-login.json");
        let missing = load_pending(&path, &dooray(), 0).unwrap_err();
        assert_eq!((missing.code, missing.exit_code()), ("CODE_EXPIRED", 10));

        let pending = PendingLogin::new(
            &dooray(),
            "s",
            SecondFactor::Email,
            None,
            &[],
            &Jar::default(),
        );
        let other = Url::parse("https://other.gov-dooray.com/").unwrap();
        let now = epoch_now();
        for (url, now, message, garbage) in [
            (dooray(), pending.expires_at, "expired", false),
            (other, now, "different", false),
            (dooray(), now, "unreadable", true),
        ] {
            save_json(&path, &pending, "pending login").unwrap();
            if garbage {
                fs::write(&path, "garbage").unwrap();
            }
            let error = load_pending(&path, &url, now).unwrap_err();
            assert!(error.message.contains(message), "{}", error.message);
            assert!(!path.exists(), "{message}: state is deleted");
        }
        save_json(&path, &pending, "pending login").unwrap();
        let loaded = load_pending(&path, &dooray(), pending.expires_at - 1).unwrap();
        assert_eq!(loaded, pending);
    }
}
