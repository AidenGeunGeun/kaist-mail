//! The transient sign-in cookie jar and the single cookie-acceptance
//! predicate shared by capture and storage.

use serde::{Deserialize, Serialize};

use crate::{
    error::AppError,
    http::{HeaderMap, SET_COOKIE},
    url::Url,
};

use super::store::{StoredCookie, epoch_now};

/// Whether `name` is an RFC 6265 cookie name (an RFC 2616 token).
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| (0x21..0x7f).contains(&byte) && !b"()<>@,;:\\\"/[]?={}".contains(&byte))
}

/// A cookie is storable when its name is a token and its value is 1..=4096
/// printable ASCII bytes other than `;`: nothing that could break out of a
/// `Cookie` header. An empty value never passes: servers send one to delete a cookie.
pub fn valid_cookie(name: &str, value: &str) -> bool {
    valid_name(name)
        && !value.is_empty()
        && value.len() <= 4096
        && value
            .bytes()
            .all(|byte| (0x20..0x7f).contains(&byte) && byte != b';')
}

/// Whether a cookie with this expiry may still be sent at `now`; the one rule
/// for the login jar and the saved session.
pub fn live(expires_at: Option<u64>, now: u64) -> bool {
    expires_at.is_none_or(|at| at > now)
}

/// Trusted-device identifiers follow the cookie-value rule: whatever KAIST
/// sends is kept as long as it cannot break out of a header.
fn valid_device(value: &str) -> bool {
    valid_cookie("device", value)
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Cookie {
    name: String,
    value: String,
    domain: String,
    path: String,
    secure: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expires_at: Option<u64>,
    /// Serialized origin of the response that set it.
    source_origin: String,
}

/// Cookies set during one login, plus trusted-device identifiers. It is also
/// the on-disk form inside a pending login and of the saved KAIST SSO session
/// (re-checked by [`Jar::checked`]).
#[derive(Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jar {
    cookies: Vec<Cookie>,
    devices: Vec<String>,
}

fn in_domain(host: &str, domain: &str) -> bool {
    host == domain || host.ends_with(&format!(".{domain}"))
}

impl Jar {
    pub fn capture(&mut self, url: &Url, headers: &HeaderMap) -> Result<(), AppError> {
        for value in headers.get_all(SET_COOKIE) {
            let value = value
                .to_str()
                .map_err(|_| AppError::auth_protocol("sign-in returned a non-text cookie"))?;
            self.capture_one(url, value)?;
        }
        Ok(())
    }

    fn capture_one(&mut self, url: &Url, header: &str) -> Result<(), AppError> {
        let host = url
            .host_str()
            .ok_or_else(|| AppError::auth_protocol("sign-in response URL has no host"))?;
        let mut parts = header.split(';');
        let (name, value) = parts
            .next()
            .unwrap_or_default()
            .split_once('=')
            .ok_or_else(|| AppError::auth_protocol("sign-in returned a malformed cookie"))?;
        // An empty value is how a server deletes a cookie; it is never stored.
        let mut remove = value.is_empty();
        if !(if remove {
            valid_name(name)
        } else {
            valid_cookie(name, value)
        }) {
            return Err(AppError::auth_protocol("sign-in returned an unsafe cookie"));
        }
        let mut domain = host.to_ascii_lowercase();
        let mut path = match url.path().rfind('/') {
            Some(index) if index > 0 => url.path()[..index].to_owned(),
            _ => "/".into(),
        };
        let mut secure = false;
        let (mut max_age, mut expires) = (None, None);
        for attribute in parts {
            let attribute = attribute.trim();
            let (key, attr) = attribute.split_once('=').unwrap_or((attribute, ""));
            match key.to_ascii_lowercase().as_str() {
                "domain" => {
                    let candidate = attr.trim_start_matches('.').to_ascii_lowercase();
                    if candidate.is_empty() || !in_domain(host, &candidate) {
                        return Err(AppError::auth_protocol(
                            "sign-in attempted to set a cookie for an unrelated domain",
                        ));
                    }
                    domain = candidate;
                }
                "path" if attr.starts_with('/') => path = attr.to_owned(),
                "secure" => secure = true,
                "max-age" => max_age = attr.parse::<i64>().ok(),
                "expires" => expires = http_date(attr),
                _ => {}
            }
        }
        let now = epoch_now();
        // Max-Age wins over Expires (RFC 6265 section 5.3).
        let expires_at = match max_age {
            Some(age) => Some(now.saturating_add_signed(age)),
            None => expires,
        };
        remove |= !live(expires_at, now);
        self.cookies.retain(|cookie| {
            !(cookie.name == name && cookie.domain == domain && cookie.path == path)
        });
        if !remove {
            self.cookies.push(Cookie {
                name: name.into(),
                value: value.into(),
                domain,
                path,
                secure,
                expires_at,
                source_origin: url.origin().ascii_serialization(),
            });
        }
        Ok(())
    }

    /// Re-check a jar read from disk, which is untrusted input, and drop the
    /// cookies that expired while it was stored.
    pub fn checked(mut self) -> Result<Self, AppError> {
        let sound = self.cookies.iter().all(|saved| {
            valid_cookie(&saved.name, &saved.value)
                && !saved.domain.is_empty()
                && saved.path.starts_with('/')
                && !saved
                    .domain
                    .contains(|c: char| c.is_whitespace() || c == ';')
                && Url::parse(&saved.source_origin).is_ok()
        }) && self.devices.iter().all(|device| valid_device(device));
        if sound {
            let now = epoch_now();
            self.cookies.retain(|cookie| live(cookie.expires_at, now));
            Ok(self)
        } else {
            Err(AppError::config(
                "saved login state contains an invalid cookie",
            ))
        }
    }

    /// The `Cookie` header for a request to `url`.
    pub fn header(&self, url: &Url) -> Option<String> {
        let host = url.host_str()?;
        let now = epoch_now();
        let values = self
            .cookies
            .iter()
            .filter(|cookie| {
                let path = url.path();
                live(cookie.expires_at, now)
                    && in_domain(host, &cookie.domain)
                    && (path == cookie.path
                        || path.starts_with(&format!("{}/", cookie.path.trim_end_matches('/'))))
                    && (!cookie.secure || url.scheme() == "https")
            })
            .map(|cookie| format!("{}={}", cookie.name, cookie.value))
            .collect::<Vec<_>>();
        (!values.is_empty()).then(|| values.join("; "))
    }

    /// The site-wide `SESSION` cookie Dooray itself issued: the only one
    /// persisted. Dooray authenticates by it alone (`JSESSIONID` and the
    /// monitoring cookies get 401 on their own).
    /// An expired one is left out, so it is neither verified nor saved.
    pub fn dooray_cookies(&self, dooray: &Url) -> Vec<StoredCookie> {
        let origin = dooray.origin().ascii_serialization();
        let now = epoch_now();
        let mut result = self
            .cookies
            .iter()
            .filter(|cookie| {
                cookie.name == "SESSION"
                    && live(cookie.expires_at, now)
                    && cookie.source_origin == origin
                    && cookie.path == "/"
                    && (!cookie.secure || dooray.scheme() == "https")
            })
            .map(|cookie| StoredCookie {
                name: cookie.name.clone(),
                value: cookie.value.clone(),
                expires_at: cookie.expires_at,
            })
            .collect::<Vec<_>>();
        result.sort_by(|a, b| a.name.cmp(&b.name));
        result.dedup_by(|a, b| a.name == b.name);
        result
    }

    /// The cookies KAIST SSO itself set, its login session among them: kept
    /// so a later SAML request is answered without credentials. Only the
    /// sign-in transport sends them, and it reaches no other host in their domain.
    pub fn sso_session(&self, sso: &Url) -> Jar {
        let origin = sso.origin().ascii_serialization();
        Jar {
            cookies: (self.cookies.iter())
                .filter(|cookie| cookie.source_origin == origin)
                .cloned()
                .collect(),
            devices: Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.cookies.is_empty()
    }

    pub fn device_values(&self) -> Vec<String> {
        let mut values = self
            .cookies
            .iter()
            .filter(|cookie| cookie.name.starts_with("sso.cookie.device."))
            .map(|cookie| cookie.value.clone())
            .chain(self.devices.iter().cloned())
            .collect::<Vec<_>>();
        values.sort();
        values.dedup();
        values
    }

    pub fn remember_device(&mut self, value: &str) -> Result<(), AppError> {
        if !valid_device(value) {
            return Err(AppError::auth_protocol(
                "KAIST returned an invalid trusted-device identifier",
            ));
        }
        self.devices.push(value.to_owned());
        Ok(())
    }
}

/// Unix seconds of a cookie `Expires` date such as `Sun, 06 Nov 1994
/// 08:49:37 GMT`, also in the `06-Nov-1994` form some servers still send.
fn http_date(text: &str) -> Option<u64> {
    let (_, rest) = text.split_once(',')?;
    let fields = rest
        .split([' ', '-', ':'])
        .filter(|field| !field.is_empty())
        .collect::<Vec<_>>();
    let [day, month, year, hour, minute, second, "GMT"] = fields[..] else {
        return None;
    };
    let month = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ]
    .iter()
    .position(|name| name.eq_ignore_ascii_case(month))? as i64
        + 1;
    let number = |field: &str| field.parse::<i64>().ok();
    let (year, day) = (number(year)?, number(day)?);
    // Days since 1970-01-01 in the proleptic Gregorian calendar (Hinnant's days_from_civil).
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let seconds = days * 86_400 + number(hour)? * 3_600 + number(minute)? * 60 + number(second)?;
    u64::try_from(seconds).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ureq::http::HeaderValue;

    const SSO: &str = "https://sso.kaist.ac.kr/";
    const DOORAY: &str = "https://kaist.gov-dooray.com/";

    fn capture(jar: &mut Jar, url: &str, set_cookie: &str) -> Result<(), AppError> {
        let mut headers = HeaderMap::new();
        headers.append(SET_COOKIE, HeaderValue::from_str(set_cookie).unwrap());
        jar.capture(&Url::parse(url).unwrap(), &headers)
    }

    fn dooray(jar: &Jar) -> Vec<StoredCookie> {
        jar.dooray_cookies(&Url::parse(DOORAY).unwrap())
    }

    #[test]
    fn predicates_never_let_a_value_break_the_header() {
        for good in ["SESSION", "sso.cookie.device.1"] {
            assert!(valid_name(good), "{good:?}");
        }
        for bad in [
            "",
            "a b",
            "a;b",
            "a=b",
            "a\r\n",
            "na\u{e9}me",
            "a\"b",
            "a,b",
        ] {
            assert!(!valid_name(bad), "{bad:?}");
        }
        for good in ["abc123", "a=b", "\"quoted\"", "a b", "a,b", "a\\b"] {
            assert!(valid_cookie("n", good), "{good:?}");
        }
        for bad in ["", "a;b", "a\r\nX: y", "a\tb", "caf\u{e9}"] {
            assert!(!valid_cookie("n", bad), "{bad:?}");
        }
        assert!(valid_cookie("n", &"a".repeat(4096)) && !valid_cookie("n", &"a".repeat(4097)));
    }

    #[test]
    fn only_the_dooray_session_cookie_persists_even_with_a_parent_domain() {
        let mut jar = Jar::default();
        for bad in ["a b=c", "novalue", "a=caf\u{e9}", "x=1; Domain=example.com"] {
            let error = capture(&mut jar, SSO, bad).unwrap_err();
            assert_eq!(error.code, "AUTH_PROTOCOL_CHANGED", "{bad:?}");
        }
        capture(&mut jar, SSO, "JSESSIONID=sso; Path=/auth; Secure").unwrap();
        capture(
            &mut jar,
            DOORAY,
            "SESSION=owned; Domain=gov-dooray.com; Path=/; Secure",
        )
        .unwrap();
        capture(&mut jar, DOORAY, "scoped=1; Path=/idp").unwrap();
        capture(&mut jar, DOORAY, "JSESSIONID=host; Path=/; Secure").unwrap();
        capture(&mut jar, DOORAY, "SCOUTER=apm; Path=/; Max-Age=60").unwrap();
        let owned = StoredCookie {
            name: "SESSION".into(),
            value: "owned".into(),
            expires_at: None,
        };
        assert!(dooray(&jar) == vec![owned]);
        let header = jar.header(&Url::parse(DOORAY).unwrap()).unwrap();
        assert!(
            header.split("; ").any(|pair| pair == "SESSION=owned"),
            "{header}"
        );
    }

    #[test]
    fn expiry_comes_from_max_age_then_expires_and_past_dates_delete() {
        let mut jar = Jar::default();
        let both = "a=1; Path=/; Max-Age=3600; Expires=Thu, 01 Jan 2099 00:00:00 GMT";
        capture(&mut jar, DOORAY, both).unwrap();
        capture(
            &mut jar,
            DOORAY,
            "b=2; Path=/; Expires=Thu, 01 Jan 2099 00:00:00 GMT",
        )
        .unwrap();
        capture(
            &mut jar,
            DOORAY,
            "c=3; Path=/; expires=Thu, 28-Feb-2030 23:59:59 GMT",
        )
        .unwrap();
        let expiry = jar
            .cookies
            .iter()
            .map(|cookie| cookie.expires_at.unwrap())
            .collect::<Vec<_>>();
        assert!((3600..=3610).contains(&(expiry[0] - epoch_now())));
        assert_eq!(expiry[1..], [4_070_908_800, 1_898_553_599]);

        for deletion in [
            "a=; Path=/",
            "a=x; Path=/; Max-Age=0",
            "a=x; Path=/; Expires=Thu, 01 Jan 1970 00:00:10 GMT",
        ] {
            let mut jar = Jar::default();
            capture(&mut jar, DOORAY, "a=1; Path=/").unwrap();
            capture(&mut jar, DOORAY, deletion).unwrap();
            assert!(jar.cookies.is_empty(), "{deletion}");
        }
    }

    #[test]
    fn expired_cookies_are_never_sent_even_from_a_restored_jar() {
        let cookie = |name: &str, expires_at: u64| {
            serde_json::json!({"name": name, "value": "v", "domain": "kaist.gov-dooray.com",
                "path": "/", "secure": false, "expires_at": expires_at,
                "source_origin": "https://kaist.gov-dooray.com"})
        };
        let later = epoch_now() + 3_600;
        let saved = serde_json::json!({"cookies": [cookie("JSESSIONID", 1), cookie("SESSION", later)], "devices": []});
        let restored: Jar = serde_json::from_value(saved).unwrap();
        let url = Url::parse(DOORAY).unwrap();
        assert_eq!(restored.header(&url).as_deref(), Some("SESSION=v"));
        let checked = restored.checked().unwrap();
        assert_eq!(checked.header(&url).as_deref(), Some("SESSION=v"));
        assert_eq!(
            checked.cookies.len(),
            1,
            "restoration drops the expired cookie"
        );

        let expired = serde_json::json!({"cookies": [cookie("SESSION", 1)], "devices": []});
        let expired: Jar = serde_json::from_value(expired).unwrap();
        assert!(
            expired.dooray_cookies(&url).is_empty(),
            "an expired session is never verified or saved"
        );
    }

    #[test]
    fn snapshot_round_trips_and_rejects_tampering() {
        let mut jar = Jar::default();
        let scoped = "s=1; Domain=kaist.ac.kr; Path=/auth; Secure";
        capture(&mut jar, "https://sso.kaist.ac.kr/auth/x", scoped).unwrap();
        capture(&mut jar, DOORAY, "SESSION=owned; Path=/; Max-Age=60").unwrap();
        jar.remember_device("dev").unwrap();
        let back: Jar = serde_json::from_str(&serde_json::to_string(&jar).unwrap()).unwrap();
        assert!(back.clone().checked().unwrap() == jar);
        let mut evil = jar.clone();
        evil.cookies[0].value = "x; injected=y".into();
        assert!(evil.checked().is_err());
        let mut evil = jar;
        evil.devices.push("bad;device".into());
        assert!(evil.checked().is_err());
    }
}
