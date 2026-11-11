//! The Dooray web API client: one exact origin, the saved session cookies,
//! bounded bodies, and wapi `header` results turned into errors.

use std::time::Duration;

use serde::{
    Deserialize,
    de::{DeserializeOwned, IgnoredAny},
};
use serde_json::json;
use ureq::Agent;

use crate::{
    auth,
    error::AppError,
    http::{self, Failure, Follow, Method, Response},
    output,
    url::{Url, is_http_loopback},
};

mod transfer;

pub use transfer::{Limits, Size};

pub const PRODUCTION: &str = "https://kaist.gov-dooray.com/";
/// The system folders; small, and also the login's check that a new session
/// is signed in.
pub const SYSTEM_FOLDERS: &str = "/v2/wapi/mail-folders?type=system&size=10000&page=0";
pub const USER_FOLDERS: &str = "/v2/wapi/mail-folders?type=user&size=10000&page=0";
/// wapi answers are buffered whole; files stream through [`Client::download`].
const MAX_BODY: u64 = 8 * 1024 * 1024;

pub struct Client {
    agent: Agent,
    base: Url,
    cookie: String,
}

/// A wapi answer: `{"header": {...}, "result": ...}`.
#[derive(Deserialize)]
struct Envelope<H, T> {
    header: H,
    result: Option<T>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Header {
    is_successful: bool,
    #[serde(default)]
    result_code: i64,
    #[serde(default)]
    result_message: String,
}

/// Accept only the production origin or a loopback fixture.
pub fn validate_base_url(raw: &str) -> Result<Url, AppError> {
    // The rejected value is never echoed: it may carry credentials.
    let url = Url::parse(raw).map_err(|_| AppError::usage("--base-url is not a valid URL"))?;
    let production = url.origin() == Url::parse(PRODUCTION).expect("valid URL").origin();
    if crate::url::has_userinfo(&url) || !(production || is_http_loopback(&url)) {
        return Err(AppError::usage(
            "--base-url must be https://kaist.gov-dooray.com or a loopback http test server",
        ));
    }
    Ok(url)
}

impl Client {
    pub fn new(base: Url, timeout: u64) -> Result<Self, AppError> {
        let session = auth::load(&base)?;
        let cookie = match (session.cookie_header, session.status.configured) {
            (Some(cookie), _) => cookie,
            (None, true) => {
                return Err(AppError::auth_expired(
                    "the saved Dooray session has expired",
                ));
            }
            (None, false) => {
                return Err(AppError::auth_required("not signed in to Dooray"));
            }
        };
        Ok(Self::with_cookie(base, cookie, timeout))
    }

    /// A client for a `Cookie` header that is not saved yet, such as the one
    /// a login is about to save.
    pub fn with_cookie(base: Url, cookie: String, timeout: u64) -> Self {
        Self {
            agent: http::agent(Duration::from_secs(timeout), Some(Duration::from_secs(8))),
            base,
            cookie,
        }
    }

    /// GET a wapi path and return its `result`, or the error its `header` reports.
    pub fn wapi<T: DeserializeOwned>(&self, path: &str) -> Result<T, AppError> {
        let url = self
            .base
            .join(path)
            .map_err(|_| AppError::internal("invalid Dooray API path"))?;
        let mut policy = Policy {
            base: &self.base,
            cookie: &self.cookie,
        };
        let request = Follow {
            method: Method::GET,
            url,
            payload: None,
            max_redirects: 3,
            strict: true,
        };
        let response = http::follow(&self.agent, request, &mut policy).map_err(failure)?;
        let bytes = read_body(response)?;
        // The header decides the outcome before the result's type is checked.
        check_header(path, &bytes)?;
        let envelope: Envelope<IgnoredAny, T> =
            serde_json::from_slice(&bytes).map_err(|error| decode_error(path, &error))?;
        envelope
            .result
            .ok_or_else(|| shape_error(path, "success without a result"))
    }
}

fn shape_error(path: &str, detail: &str) -> AppError {
    AppError::shape(format!("Dooray {path} answered {detail}"))
}

fn decode_error(path: &str, error: &serde_json::Error) -> AppError {
    shape_error(path, &crate::error::json_problem(error))
}

/// The error a wapi envelope's `header` reports, if any.
fn check_header(path: &str, bytes: &[u8]) -> Result<(), AppError> {
    let envelope: Envelope<Header, IgnoredAny> =
        serde_json::from_slice(bytes).map_err(|error| decode_error(path, &error))?;
    let Header {
        is_successful,
        result_code,
        result_message,
    } = envelope.header;
    if is_successful {
        return Ok(());
    }
    // Logic keys on resultCode. resultMessage is Dooray's localized reason
    // for the user, kept only in details, bounded and stripped of control
    // characters because it is untrusted server text.
    let reason: String = output::sanitize_terminal(&result_message)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(200)
        .collect();
    Err(
        AppError::upstream(format!("Dooray reported error {result_code} for {path}"))
            .with_details(json!({"result_code": result_code, "result_message": reason})),
    )
}

fn read_body(response: Response) -> Result<Vec<u8>, AppError> {
    let too_big = || AppError::limit("Dooray response exceeded 8 MiB");
    if response.content_length().is_some_and(|len| len > MAX_BODY) {
        return Err(too_big());
    }
    let bytes = http::read_prefix(response, MAX_BODY)
        .map_err(|error| AppError::network(format!("failed to read Dooray response: {error}")))?;
    if bytes.len() as u64 > MAX_BODY {
        return Err(too_big());
    }
    Ok(bytes)
}

fn failure(failure: Failure) -> AppError {
    match failure {
        Failure::Transport(message) => {
            AppError::network(format!("Dooray request failed: {message}"))
        }
        Failure::Refused(error) => error,
        Failure::MissingLocation | Failure::InvalidLocation => {
            AppError::shape("Dooray returned an invalid redirect")
        }
        Failure::TooManyRedirects => AppError::shape("Dooray exceeded the redirect limit"),
    }
}

struct Policy<'a> {
    base: &'a Url,
    cookie: &'a str,
}

impl http::Policy for Policy<'_> {
    fn headers(&mut self, _method: &Method, _url: &Url) -> Vec<(&'static str, String)> {
        // What Dooray's web app sends with every wapi call.
        vec![
            ("cookie", self.cookie.to_owned()),
            ("accept", "application/json, text/plain, */*".to_owned()),
            ("dooray-caller", "WEB".to_owned()),
            ("dooray-api-version", "1.1".to_owned()),
            ("dooray-mail-api-version", "1.2".to_owned()),
        ]
    }

    /// Dooray sends a signed-out browser to its sign-in entry; any other
    /// origin is never contacted with the session cookies.
    fn allow(&mut self, url: &Url) -> Result<(), AppError> {
        if url.origin() != self.base.origin() || crate::url::has_userinfo(url) {
            return Err(AppError::shape("Dooray redirected to another origin"));
        }
        if auth::is_signin_path(url.path()) {
            return Err(AppError::auth_expired(
                "Dooray redirected to sign-in; the saved session is no longer valid",
            ));
        }
        Ok(())
    }

    fn inspect(&mut self, response: &Response) -> Result<(), AppError> {
        match response.status() {
            200..400 => Ok(()),
            status => Err(AppError::http(status, response.url().path())),
        }
    }
}
