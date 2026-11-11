//! The Dooray web API client: one exact origin, the saved session cookies,
//! bounded bodies, and wapi `header` results turned into errors.

use std::time::Duration;

use serde::{Deserialize, de::DeserializeOwned};
use serde_json::json;
use ureq::Agent;

use crate::{
    auth,
    error::AppError,
    http::{self, Failure, Follow, Method, Response},
    url::{Url, is_http_loopback},
};

pub const PRODUCTION: &str = "https://kaist.gov-dooray.com/";
/// shortcut: whole bodies are buffered; stream once attachment downloads land.
const MAX_BODY: u64 = 8 * 1024 * 1024;

pub struct Client {
    agent: Agent,
    base: Url,
    cookie: String,
}

/// A wapi answer: `{"header": {...}, "result": ...}`.
#[derive(Deserialize)]
struct Envelope<T> {
    header: Header,
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
    let url =
        Url::parse(raw).map_err(|_| AppError::usage(format!("invalid --base-url {raw:?}")))?;
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
        Ok(Self {
            agent: http::agent(Duration::from_secs(timeout), Some(Duration::from_secs(8))),
            base,
            cookie,
        })
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
        let shape = |detail: String| AppError::shape(format!("Dooray {path} answered {detail}"));
        let envelope: Envelope<T> = serde_json::from_slice(&bytes)
            .map_err(|error| shape(format!("an unexpected document: {error}")))?;
        let Header {
            is_successful,
            result_code,
            result_message,
        } = envelope.header;
        if !is_successful {
            // Dooray localizes resultMessage; logic keys on resultCode only.
            return Err(AppError::upstream(format!(
                "Dooray reported error {result_code} for {path}: {result_message}"
            ))
            .with_details(json!({"result_code": result_code, "result_message": result_message})));
        }
        envelope
            .result
            .ok_or_else(|| shape("success without a result".into()))
    }
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
        vec![
            ("cookie", self.cookie.to_owned()),
            ("accept", "application/json".to_owned()),
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
