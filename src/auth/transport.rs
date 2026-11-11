//! The HTTP side of a login: only the Dooray and SSO origins are contacted,
//! redirects are followed by hand, and cookies live in a per-login jar.

use std::time::Duration;

use serde_json::Value;
use ureq::Agent;

use crate::{
    error::AppError,
    http::{self, Failure, Follow, Method, Payload, Response},
    url::{Url, is_http_loopback},
};

use super::cookies::Jar;

const MAX_BODY: usize = 1024 * 1024;

pub struct SsoTransport {
    client: Agent,
    pub cookies: Jar,
    dooray: Url,
    sso: Url,
    document_url: Option<Url>,
}

impl SsoTransport {
    pub fn new(dooray: Url, sso: Url, timeout: u64) -> Result<Self, AppError> {
        let production = dooray.scheme() == "https"
            && dooray.host_str() == Some("kaist.gov-dooray.com")
            && sso.scheme() == "https"
            && sso.host_str() == Some("sso.kaist.ac.kr");
        let loopback = is_http_loopback(&dooray) && is_http_loopback(&sso);
        if !production && !loopback {
            return Err(AppError::config(
                "native login permits only KAIST production origins or loopback test origins",
            ));
        }
        Ok(Self {
            client: http::agent(Duration::from_secs(timeout), Some(Duration::from_secs(8))),
            cookies: Jar::default(),
            dooray,
            sso,
            document_url: None,
        })
    }

    pub fn dooray(&self) -> &Url {
        &self.dooray
    }

    pub fn document_url(&self) -> Option<&Url> {
        self.document_url.as_ref()
    }

    pub fn set_document_url(&mut self, url: Url) -> Result<(), AppError> {
        ensure_allowed(&self.dooray, Some(&self.sso), &url)?;
        self.document_url = Some(url);
        Ok(())
    }

    pub fn is_dooray_origin(&self, url: &Url) -> bool {
        url.origin() == self.dooray.origin()
    }

    /// Resolve `reference` against the SSO origin; only trusted origins pass,
    /// so Dooray steps pass absolute URLs.
    pub fn url(&self, reference: &str) -> Result<Url, AppError> {
        let url = self
            .sso
            .join(reference)
            .map_err(|_| AppError::internal("invalid SSO URL"))?;
        ensure_allowed(&self.dooray, Some(&self.sso), &url)?;
        Ok(url)
    }

    pub fn get(&mut self, reference: &str) -> Result<(Url, String), AppError> {
        self.fetch(Method::GET, reference, None, Mode::Page)
    }

    pub fn post(
        &mut self,
        reference: &str,
        form: &[(&str, &str)],
    ) -> Result<(Url, String), AppError> {
        self.fetch(Method::POST, reference, Some(form), Mode::Page)
    }

    /// POST the SAML assertion to Dooray; this request and its redirects
    /// may reach only the Dooray origin.
    pub fn submit_assertion(
        &mut self,
        action: &Url,
        form: &[(&str, &str)],
    ) -> Result<Url, AppError> {
        if !self.is_dooray_origin(action) {
            return Err(AppError::auth_protocol(
                "the SAML assertion may be sent only to Dooray",
            ));
        }
        let mode = Mode::DoorayOnly;
        Ok(self
            .fetch(Method::POST, action.as_str(), Some(form), mode)?
            .0)
    }

    /// An AJAX form POST answered with JSON; its redirects are not followed.
    pub fn ajax(&mut self, reference: &str, form: &[(&str, &str)]) -> Result<Value, AppError> {
        let (_, body) = self.fetch(Method::POST, reference, Some(form), Mode::Ajax)?;
        serde_json::from_str(&body)
            .map_err(|_| AppError::auth_protocol("KAIST SSO returned invalid JSON"))
    }

    fn fetch(
        &mut self,
        method: Method,
        reference: &str,
        form: Option<&[(&str, &str)]>,
        mode: Mode,
    ) -> Result<(Url, String), AppError> {
        let url = self.url(reference)?;
        let payload = form.map(|form| Payload::form(form.iter().copied()));
        let ajax = mode == Mode::Ajax;
        let mut policy = SsoPolicy {
            cookies: &mut self.cookies,
            document_url: self.document_url.as_ref(),
            dooray: &self.dooray,
            sso: (mode != Mode::DoorayOnly).then_some(&self.sso),
            ajax,
        };
        // AJAX answers are never redirected: any redirect is a protocol error.
        let request = Follow {
            method,
            url,
            payload,
            max_redirects: if ajax { 0 } else { 8 },
            strict: !ajax,
        };
        let response = http::follow(&self.client, request, &mut policy).map_err(failure)?;
        if !ajax {
            self.document_url = Some(response.url().clone());
        }
        text(response)
    }
}

fn failure(failure: Failure) -> AppError {
    match failure {
        Failure::Transport(message) => {
            AppError::network(format!("sign-in request failed: {message}"))
        }
        Failure::Refused(error) => error,
        Failure::MissingLocation => {
            AppError::auth_protocol("sign-in returned a redirect without Location")
        }
        Failure::InvalidLocation => AppError::auth_protocol("sign-in returned an invalid redirect"),
        Failure::TooManyRedirects => AppError::auth_protocol("sign-in exceeded the redirect limit"),
    }
}

/// The response URL and its body, capped at 1 MiB.
fn text(response: Response) -> Result<(Url, String), AppError> {
    let too_big = || AppError::limit("sign-in response exceeded 1 MiB");
    if response
        .content_length()
        .is_some_and(|len| len > MAX_BODY as u64)
    {
        return Err(too_big());
    }
    let url = response.url().clone();
    let bytes = http::read_prefix(response, MAX_BODY as u64)
        .map_err(|error| AppError::network(format!("failed to read sign-in response: {error}")))?;
    if bytes.len() > MAX_BODY {
        return Err(too_big());
    }
    Ok((url, String::from_utf8_lossy(&bytes).into_owned()))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// A page load: redirects within Dooray and SSO are followed.
    Page,
    /// An AJAX call: redirects are protocol errors.
    Ajax,
    /// The SAML assertion: redirects are followed within Dooray only.
    DoorayOnly,
}

/// `sso` is `None` where only Dooray may be reached.
fn ensure_allowed(dooray: &Url, sso: Option<&Url>, url: &Url) -> Result<(), AppError> {
    if url.origin() != dooray.origin() && sso.is_none_or(|sso| url.origin() != sso.origin()) {
        return Err(AppError::auth_protocol(
            "sign-in attempted to reach an untrusted origin",
        ));
    }
    if crate::url::has_userinfo(url) {
        return Err(AppError::auth_protocol("sign-in URL contained userinfo"));
    }
    Ok(())
}

/// Per-hop sign-in rules: trusted origins only, Referer/Origin from the current
/// document, cookies recomputed per URL and captured from every response.
struct SsoPolicy<'a> {
    cookies: &'a mut Jar,
    document_url: Option<&'a Url>,
    dooray: &'a Url,
    sso: Option<&'a Url>,
    ajax: bool,
}

impl http::Policy for SsoPolicy<'_> {
    fn headers(&mut self, method: &Method, url: &Url) -> Vec<(&'static str, String)> {
        let mut headers = Vec::new();
        if let Some(referer) = self.document_url {
            headers.push(("referer", referer.as_str().to_owned()));
        }
        if *method == Method::POST {
            let origin = self.document_url.unwrap_or(url).origin();
            headers.push(("origin", origin.ascii_serialization()));
        }
        if let Some(cookie) = self.cookies.header(url) {
            headers.push(("cookie", cookie));
        }
        if self.ajax {
            headers.push(("x-requested-with", "XMLHttpRequest".to_owned()));
        }
        headers
    }

    fn allow(&mut self, url: &Url) -> Result<(), AppError> {
        ensure_allowed(self.dooray, self.sso, url)
    }

    fn inspect(&mut self, response: &Response) -> Result<(), AppError> {
        self.cookies.capture(response.url(), response.headers())?;
        let status = response.status();
        if !(200..400).contains(&status) {
            let url = response.url();
            let message = format!(
                "sign-in returned HTTP {status} from {}{}",
                url.host_str().unwrap_or_default(),
                url.path()
            );
            return Err(match status {
                429 | 500.. => AppError::network(message),
                _ => AppError::auth_protocol(message),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture_server::{Response, Server};

    #[test]
    fn bounds_a_response_without_content_length_before_eof() {
        // The body is never terminated: an unbounded reader would wait for EOF
        // and fail with a timeout instead of the size limit.
        let server = Server::new(|_| Response::open_ended(vec![b'x'; MAX_BODY + 1]));
        let url = Url::parse(&server.url()).unwrap();
        let mut transport = SsoTransport::new(url.clone(), url.clone(), 2).unwrap();
        let error = transport.get(url.as_str()).unwrap_err();
        assert_eq!(error.code, "LIMIT_EXCEEDED");
    }
}
