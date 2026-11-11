//! The one blocking HTTP transport. The library never follows redirects:
//! every caller supplies its own origin policy to [`follow`].
use std::{
    io::{self, Read},
    sync::Arc,
    time::{Duration, Instant},
};

use crate::url::{Url, is_loopback};
use ureq::{
    Agent, BodyReader, Proxy,
    config::Config,
    http::{self},
    tls::{RootCerts, TlsConfig},
};

use crate::error::AppError;

pub use ureq::http::{HeaderMap, Method, header::SET_COOKIE};

pub const USER_AGENT: &str = concat!("kaist-mail/", env!("CARGO_PKG_VERSION"));

/// Builds an agent that reports every HTTP status as a normal response and
/// leaves redirects to the caller. Each request picks its own proxy (see
/// [`proxy_for`]); trust roots come from the platform store.
pub fn agent(timeout: Duration, connect_timeout: Option<Duration>) -> Agent {
    let tls = TlsConfig::builder()
        .unversioned_rustls_crypto_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .root_certs(RootCerts::PlatformVerifier)
        .build();
    let config: Config = Agent::config_builder()
        .timeout_global(Some(timeout))
        .timeout_connect(connect_timeout)
        .user_agent(USER_AGENT)
        .max_redirects(0)
        .max_redirects_will_error(false)
        .http_status_as_error(false)
        .proxy(None)
        .tls_config(tls)
        .build();
    Agent::new_with_config(config)
}

/// A response whose body is read on demand through [`io::Read`].
pub struct Response {
    url: Url,
    status: u16,
    headers: HeaderMap,
    reader: BodyReader<'static>,
}

impl Response {
    pub fn url(&self) -> &Url {
        &self.url
    }

    pub fn status(&self) -> u16 {
        self.status
    }

    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// The header as text. Raw UTF-8 is accepted (servers send it in
    /// `Location`), unlike `HeaderValue::to_str`, which allows only ASCII.
    pub fn header(&self, name: &str) -> Option<&str> {
        let value = self.headers.get(name)?;
        std::str::from_utf8(value.as_bytes()).ok()
    }

    pub fn content_length(&self) -> Option<u64> {
        self.header("content-length")
            .and_then(|value| value.parse().ok())
    }
}

impl io::Read for Response {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.reader.read(buf)
    }
}

pub struct Payload {
    pub content_type: &'static str,
    pub bytes: Vec<u8>,
}

impl Payload {
    pub(crate) fn form<'a>(pairs: impl IntoIterator<Item = (&'a str, &'a str)>) -> Self {
        Self {
            content_type: "application/x-www-form-urlencoded",
            bytes: crate::url::form_urlencode(pairs).into_bytes(),
        }
    }
}

/// Read at most `limit + 1` bytes, so callers can detect overflow or truncate.
pub(crate) fn read_prefix(reader: impl io::Read, limit: u64) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(limit.min(64 * 1024) as usize);
    reader
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

#[derive(Debug)]
pub enum Failure {
    /// Connection, TLS, timeout or malformed-request failure (URL redacted).
    Transport(String),
    MissingLocation,
    InvalidLocation,
    TooManyRedirects,
    /// The caller's policy rejected a redirect target or a hop's response.
    Refused(AppError),
}

/// The proxy URL for a request to `url`, read through `env` like curl does:
/// `https_proxy`/`HTTPS_PROXY` for https and `http_proxy`/`HTTP_PROXY` for
/// http, then `all_proxy`/`ALL_PROXY`. `no_proxy`/`NO_PROXY` lists `*` or
/// hosts that are bypassed along with their subdomains (a leading dot is
/// optional, IPv6 brackets too). Loopback targets are never proxied.
fn proxy_for(url: &Url, env: impl Fn(&str) -> Option<String>) -> Option<String> {
    let unbracket = |host: &str| {
        let host = host.trim().trim_start_matches('.');
        let inner = host.strip_prefix('[').and_then(|h| h.strip_suffix(']'));
        inner.unwrap_or(host).to_ascii_lowercase()
    };
    let host = unbracket(url.host_str()?);
    if is_loopback(url) {
        return None;
    }
    let first = |names: &[&str]| {
        let mut values = names.iter().filter_map(|name| env(name));
        values.find(|value| !value.trim().is_empty())
    };
    let proxy = match url.scheme() {
        "https" => first(&["https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"]),
        _ => first(&["http_proxy", "HTTP_PROXY", "all_proxy", "ALL_PROXY"]),
    }?;
    let bypass = first(&["no_proxy", "NO_PROXY"]).unwrap_or_default();
    let bypassed = bypass.split(',').map(unbracket).any(|entry| {
        entry == "*" || !entry.is_empty() && (host == entry || host.ends_with(&format!(".{entry}")))
    });
    (!bypassed).then_some(proxy)
}

fn run<B: ureq::AsSendBody>(
    agent: &Agent,
    request: http::Request<B>,
    remaining: Option<Duration>,
    proxy: Option<Proxy>,
) -> Result<http::Response<ureq::Body>, ureq::Error> {
    agent.run(
        agent
            .configure_request(request)
            .timeout_global(remaining)
            .proxy(proxy)
            .build(),
    )
}

/// One request without redirect handling, bounded by `deadline` (when there
/// is one) so a redirect chain shares one overall time budget. The status may be any HTTP status.
fn send_until(
    agent: &Agent,
    method: Method,
    url: &Url,
    headers: &[(&'static str, String)],
    payload: Option<&Payload>,
    deadline: Option<Instant>,
) -> Result<Response, Failure> {
    let transport = |message: String| Failure::Transport(message.replace(url.as_str(), "<url>"));
    let remaining = match deadline {
        Some(deadline) => Some(
            deadline
                .checked_duration_since(Instant::now())
                .filter(|left| !left.is_zero())
                .ok_or_else(|| transport("timeout: request deadline elapsed".into()))?,
        ),
        None => None,
    };
    let proxy = match proxy_for(url, |name| std::env::var(name).ok()) {
        Some(proxy) => Some(
            Proxy::new(&proxy)
                .map_err(|_| Failure::Transport("invalid proxy URL in the environment".into()))?,
        ),
        None => None,
    };
    let mut builder = http::Request::builder().method(method).uri(url.as_str());
    for (name, value) in headers {
        builder = builder.header(*name, value.as_str());
    }
    let result = match payload {
        Some(payload) => builder
            .header("content-type", payload.content_type)
            .body(payload.bytes.clone())
            .map(|request| run(agent, request, remaining, proxy)),
        None => builder
            .body(())
            .map(|request| run(agent, request, remaining, proxy)),
    };
    let response = result
        .map_err(|error| transport(error.to_string()))?
        .map_err(|error| transport(error.to_string()))?;
    let (parts, body) = response.into_parts();
    Ok(Response {
        url: url.clone(),
        status: parts.status.as_u16(),
        headers: parts.headers,
        reader: body.into_reader(),
    })
}

/// Per-hop behavior supplied by the caller of [`follow`].
pub trait Policy {
    /// Extra headers for one hop, computed from that hop's method and URL.
    fn headers(&mut self, _method: &Method, _url: &Url) -> Vec<(&'static str, String)> {
        Vec::new()
    }
    /// Origin policy applied to every redirect target before it is requested.
    fn allow(&mut self, url: &Url) -> Result<(), AppError>;
    /// Observes every hop's response, redirects included.
    fn inspect(&mut self, _response: &Response) -> Result<(), AppError> {
        Ok(())
    }
}

pub struct Follow {
    pub method: Method,
    pub url: Url,
    pub payload: Option<Payload>,
    /// Redirects followed before [`Failure::TooManyRedirects`].
    pub max_redirects: usize,
    /// Treat any 3xx as a redirect (and require `Location`) instead of only
    /// 301/302/303/307/308 responses that carry one.
    pub strict: bool,
}

/// Sends the request and follows redirects by hand. 307/308 keep the method
/// and body; any other redirect drops the body and turns every method except
/// HEAD into GET. The agent's global timeout bounds the whole chain, not each
/// hop.
pub fn follow(
    agent: &Agent,
    request: Follow,
    policy: &mut dyn Policy,
) -> Result<Response, Failure> {
    let Follow {
        mut method,
        mut url,
        mut payload,
        max_redirects,
        strict,
    } = request;
    let deadline = (agent.config().timeouts().global).map(|limit| Instant::now() + limit);
    let mut redirects = 0;
    loop {
        let extra = policy.headers(&method, &url);
        let response = send_until(
            agent,
            method.clone(),
            &url,
            &extra,
            payload.as_ref(),
            deadline,
        )?;
        policy.inspect(&response).map_err(Failure::Refused)?;
        let status = response.status();
        let redirect = if strict {
            (300..400).contains(&status)
        } else {
            matches!(status, 301 | 302 | 303 | 307 | 308)
        };
        if !redirect {
            return Ok(response);
        }
        let Some(location) = response.header("location").map(str::to_owned) else {
            if strict {
                return Err(Failure::MissingLocation);
            }
            return Ok(response);
        };
        if redirects >= max_redirects {
            return Err(Failure::TooManyRedirects);
        }
        redirects += 1;
        let next = url.join(&location).map_err(|_| Failure::InvalidLocation)?;
        policy.allow(&next).map_err(Failure::Refused)?;
        if !matches!(status, 307 | 308) {
            if method != Method::HEAD {
                method = Method::GET;
            }
            payload = None;
        }
        url = next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture_server::{Response as Served, Server};

    struct AllowAll;

    impl Policy for AllowAll {
        fn allow(&mut self, _url: &Url) -> Result<(), AppError> {
            Ok(())
        }
    }

    /// The request lines and bodies seen when `method` meets `status` with a
    /// `Location` of `/next`.
    fn redirected(method: Method, status: &'static str, strict: bool) -> Vec<(String, String)> {
        let server = Server::new(move |request| {
            if request.target == "/start" {
                Served::bytes("text/plain", "")
                    .status(status)
                    .header("Location", "/next")
            } else {
                Served::bytes("text/plain", "done")
            }
        });
        let payload = (method == Method::POST).then(|| Payload {
            content_type: "application/x-www-form-urlencoded",
            bytes: b"a=1".to_vec(),
        });
        let request = Follow {
            method,
            url: Url::parse(&format!("{}/start", server.url())).unwrap(),
            payload,
            max_redirects: 5,
            strict,
        };
        follow(&agent(Duration::from_secs(5), None), request, &mut AllowAll).unwrap();
        let recorded = server.recorded().into_iter();
        recorded.map(|r| (r.line, r.body)).collect()
    }

    fn hop(line: &str, body: &str) -> (String, String) {
        (format!("{line} HTTP/1.1"), body.to_owned())
    }

    #[test]
    fn head_stays_head_and_post_keeps_its_body_only_through_307_and_308() {
        for strict in [false, true] {
            for status in [
                "301 Moved Permanently",
                "302 Found",
                "303 See Other",
                "307 Temporary Redirect",
                "308 Permanent Redirect",
            ] {
                assert_eq!(
                    redirected(Method::HEAD, status, strict),
                    [hop("HEAD /start", ""), hop("HEAD /next", "")],
                    "HEAD through {status}, strict={strict}"
                );
                let kept = matches!(&status[..3], "307" | "308");
                let next = if kept {
                    hop("POST /next", "a=1")
                } else {
                    hop("GET /next", "")
                };
                assert_eq!(
                    redirected(Method::POST, status, strict),
                    [hop("POST /start", "a=1"), next],
                    "POST through {status}, strict={strict}"
                );
            }
        }
        // Strict mode follows every 3xx; the unusual ones never resend a POST.
        for status in [
            "300 Multiple Choices",
            "304 Not Modified",
            "305 Use Proxy",
            "306 Switch Proxy",
        ] {
            assert_eq!(
                redirected(Method::POST, status, true),
                [hop("POST /start", "a=1"), hop("GET /next", "")],
                "POST through {status}, strict"
            );
            assert_eq!(
                redirected(Method::POST, status, false),
                [hop("POST /start", "a=1")],
                "POST through {status}, not strict"
            );
        }
    }

    #[test]
    fn follows_a_raw_utf8_location_with_the_path_percent_encoded() {
        let server = Server::new(|request| {
            if request.target == "/start" {
                Served::bytes("text/plain", "")
                    .status("302 Found")
                    .header("Location", "/files/한.pdf")
            } else {
                Served::bytes("application/pdf", "%PDF")
            }
        });
        let request = Follow {
            method: Method::GET,
            url: Url::parse(&format!("{}/start", server.url())).unwrap(),
            payload: None,
            max_redirects: 5,
            strict: false,
        };
        let agent = agent(Duration::from_secs(5), None);
        let response = follow(&agent, request, &mut AllowAll).unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.url().path(), "/files/%ED%95%9C.pdf");
        assert_eq!(
            server.requests(),
            ["GET /start HTTP/1.1", "GET /files/%ED%95%9C.pdf HTTP/1.1"]
        );
    }

    #[test]
    fn proxy_is_chosen_per_scheme_and_bypassed_for_no_proxy_and_loopback() {
        let pick = |url: &str, vars: &[(&str, &str)]| {
            let url = Url::parse(url).unwrap();
            proxy_for(&url, |name| {
                let found = vars.iter().find(|(key, _)| *key == name);
                found.map(|(_, value)| value.to_string())
            })
        };
        let dooray = "https://kaist.gov-dooray.com/mail/";
        let both = [("HTTPS_PROXY", "http://s:1"), ("HTTP_PROXY", "http://p:1")];
        assert_eq!(pick(dooray, &both).as_deref(), Some("http://s:1"));
        assert_eq!(
            pick("http://example.com/", &both).as_deref(),
            Some("http://p:1")
        );
        assert_eq!(pick(dooray, &[("HTTP_PROXY", "http://p:1")]), None);
        let all = [("ALL_PROXY", "http://a:1"), ("https_proxy", "")];
        assert_eq!(pick(dooray, &all).as_deref(), Some("http://a:1"));
        let lower = [("https_proxy", "http://l:1"), ("HTTPS_PROXY", "http://u:1")];
        assert_eq!(pick(dooray, &lower).as_deref(), Some("http://l:1"));

        let proxied = |url: &str, no_proxy: &str| {
            let vars = [("ALL_PROXY", "http://a:1"), ("NO_PROXY", no_proxy)];
            pick(url, &vars).is_some()
        };
        for no_proxy in [
            "gov-dooray.com",
            ".gov-dooray.com",
            "x, GOV-dooray.com",
            "*",
        ] {
            assert!(!proxied(dooray, no_proxy), "{no_proxy}");
            assert!(!proxied("https://gov-dooray.com/", no_proxy), "{no_proxy}");
        }
        assert!(proxied("https://notgov-dooray.com/", "gov-dooray.com"));
        assert!(proxied(dooray, "sso.kaist.ac.kr"));
        assert!(proxied(dooray, ""));
        for no_proxy in ["2001:db8::1", "[2001:db8::1]"] {
            assert!(!proxied("https://[2001:db8::1]/", no_proxy), "{no_proxy}");
        }
        for loopback in [
            "http://127.0.0.1:9/",
            "http://127.1:9/",
            "http://0177.0.0.1:9/",
            "http://0x7f000001:9/",
            "http://2130706433:9/",
            "http://localhost:9/",
            "http://[::1]:9/",
            "http://[0:0:0:0:0:0:0:1]:9/",
        ] {
            assert!(!proxied(loopback, "example.com"), "{loopback}");
        }
    }
}
