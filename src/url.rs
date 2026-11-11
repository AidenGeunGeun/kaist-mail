//! Standard URL parsing, with shared origin helpers.
pub use ::url::Url;
use ::url::{Host, form_urlencoded};

pub fn has_userinfo(url: &Url) -> bool {
    !url.username().is_empty() || url.password().is_some()
}

/// Loopback hosts never use the environment's proxy.
pub fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Domain("localhost")) => true,
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        _ => false,
    }
}

/// Plain HTTP is accepted only for local fixture servers.
pub fn is_http_loopback(url: &Url) -> bool {
    url.scheme() == "http" && is_loopback(url)
}

/// `application/x-www-form-urlencoded` body from key/value pairs.
pub fn form_urlencode<'a>(pairs: impl IntoIterator<Item = (&'a str, &'a str)>) -> String {
    form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish()
}
