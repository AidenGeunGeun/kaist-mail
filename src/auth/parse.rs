//! What the login reads from Dooray and KAIST SSO pages: structure only,
//! never visible text, so either page language parses the same.

use scraper::{Html, Selector};
use serde_json::Value;

use crate::{error::AppError, url::Url};

const SAML_LOGIN: &str = "/idp/login/saml";

fn sel(selector: &str) -> Selector {
    Selector::parse(selector).expect("static selector")
}

/// The sign-in URL of the KAIST SAML button on Dooray's `/idp/multi` page,
/// found anywhere in the page's Next.js data.
pub fn saml_button(html: &str) -> Option<String> {
    fn find(value: &Value) -> Option<&str> {
        match value {
            Value::String(text) => text.starts_with(SAML_LOGIN).then_some(text),
            Value::Array(items) => items.iter().find_map(find),
            Value::Object(fields) => fields.values().find_map(find),
            _ => None,
        }
    }
    let document = Html::parse_document(html);
    let script = document.select(&sel("script#__NEXT_DATA__")).next()?;
    let data: Value = serde_json::from_str(&script.text().collect::<String>()).ok()?;
    find(&data).map(str::to_owned)
}

/// The agent id the SSO login page was rendered for (`kaist-prod-dooray`
/// after a SAML request from Dooray).
pub fn agent_id(html: &str) -> Option<String> {
    let document = Html::parse_document(html);
    let input = document.select(&sel("input#agt_id")).next()?;
    input.value().attr("value").map(str::to_owned)
}

pub struct HandoffForm {
    pub action: Url,
    pub fields: Vec<(String, String)>,
}

/// Dooray's SAML assertion consumer, the only place an assertion may go.
pub const ACS_PATH: &str = "/idp/login/saml/process";

/// The auto-submitting form that carries the `SAMLResponse` back to Dooray:
/// a POST to exactly the ACS on the Dooray origin with a nonempty
/// `SAMLResponse`. Any other form is ignored.
pub fn handoff_form(html: &str, document_url: &Url, dooray: &Url) -> Result<HandoffForm, AppError> {
    let document = Html::parse_document(html);
    let inputs = sel("input[name]");
    for form in document.select(&sel("form[action]")) {
        let post = form
            .value()
            .attr("method")
            .is_some_and(|method| method.eq_ignore_ascii_case("post"));
        let Some(action) = form
            .value()
            .attr("action")
            .and_then(|action| document_url.join(action).ok())
            .filter(|action| {
                post && action.origin() == dooray.origin() && action.path() == ACS_PATH
            })
        else {
            continue;
        };
        let fields: Vec<_> = form
            .select(&inputs)
            .filter_map(|input| {
                let name = input.value().attr("name")?;
                let value = input.value().attr("value").unwrap_or_default();
                (valid_field_name(name) && value.len() <= 64 * 1024)
                    .then(|| (name.to_owned(), value.to_owned()))
            })
            .take(32)
            .collect();
        if fields
            .iter()
            .any(|(name, value)| name == "SAMLResponse" && !value.is_empty())
        {
            return Ok(HandoffForm { action, fields });
        }
    }
    Err(AppError::auth_protocol(
        "KAIST SSO did not return a SAML assertion form for Dooray",
    ))
}

fn valid_field_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

/// The `/auth/...` paths a device-trust page can act on, for error details.
pub fn auth_policy_shape(html: &str) -> Vec<String> {
    let document = Html::parse_document(html);
    let mut actions: Vec<String> = document
        .select(&sel("button[onclick], a[href]"))
        .flat_map(|element| {
            ["onclick", "href"]
                .into_iter()
                .filter_map(|attr| element.value().attr(attr))
                .filter_map(|value| auth_paths(value).into_iter().next())
                .collect::<Vec<_>>()
        })
        .collect();
    for script in document.select(&sel("script:not([src])")) {
        actions.extend(auth_paths(&script.text().collect::<String>()));
    }
    actions.sort();
    actions.dedup();
    actions
}

pub fn easy_login_code(html: &str) -> Option<String> {
    let document = Html::parse_document(html);
    document
        .select(&sel(".auth_number .sr-only"))
        .map(|element| element.text().collect::<String>())
        .find_map(digits_only)
        .or_else(|| {
            let visible: String = document
                .select(&sel(".auth_number .nember_wrap span"))
                .flat_map(|element| element.text())
                .collect();
            digits_only(visible)
        })
}

fn digits_only(value: impl AsRef<str>) -> Option<String> {
    let digits: String = value
        .as_ref()
        .chars()
        .filter(char::is_ascii_digit)
        .collect();
    (!digits.is_empty() && digits.len() <= 8).then_some(digits)
}

fn auth_paths(text: &str) -> Vec<String> {
    let mut paths = Vec::new();
    let mut rest = text;
    while let Some(index) = rest.find("/auth/") {
        rest = &rest[index..];
        // Plain path characters only: these land in error details.
        let end = rest
            .find(|c: char| !(c.is_ascii_alphanumeric() || "/_.-".contains(c)))
            .unwrap_or(rest.len());
        paths.push(rest[..end].to_owned());
        rest = &rest[end..];
    }
    paths
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_saml_button_in_next_data_whatever_the_labels_say() {
        for label in ["학생/교직원", "Students and staff"] {
            let html = format!(
                r#"<script id="__NEXT_DATA__" type="application/json">{{"props":{{"pageProps":{{"buttons":[{{"name":"guest","url":"/idp/login?x=1"}},{{"name":"{label}","url":"/idp/login/saml?redirectUrl=%2F"}}]}}}}}}</script>"#
            );
            assert_eq!(
                saml_button(&html).as_deref(),
                Some("/idp/login/saml?redirectUrl=%2F")
            );
        }
        assert_eq!(saml_button("<html></html>"), None);
    }

    #[test]
    fn extracts_accessible_easy_login_code() {
        let html = r#"<div class="auth_number"><div class="nember_wrap"><span>8</span><span>0</span></div><div class="sr-only">80</div></div>"#;
        assert_eq!(easy_login_code(html).as_deref(), Some("80"));
    }

    #[test]
    fn accepts_only_handoff_forms_targeting_dooray() {
        let document =
            Url::parse("https://sso.kaist.ac.kr/auth/kaist/user/saml/login/link/redirect").unwrap();
        let dooray = Url::parse("https://kaist.gov-dooray.com/").unwrap();
        let response = "P".repeat(40 * 1024);
        let html = format!(
            r#"<form action="https://evil.example/steal"><input name="SAMLResponse" value="bad"></form><form method="post" action="https://kaist.gov-dooray.com/idp/login/saml/process"><input type="hidden" name="SAMLResponse" value="{response}"></form>"#
        );
        let form = handoff_form(&html, &document, &dooray).unwrap();
        assert_eq!(form.action.path(), "/idp/login/saml/process");
        assert_eq!(form.fields, [("SAMLResponse".into(), response)]);

        let acs = "https://kaist.gov-dooray.com/idp/login/saml/process";
        for bad in [
            format!(r#"<form action="{acs}"><input name="SAMLResponse" value="x"></form>"#),
            r#"<form method="post" action="/auth/signin/finalize"><input name="SAMLResponse" value="x"></form>"#.into(),
            format!(r#"<form method="post" action="{acs}"><input name="SAMLResponse" value=""><input name="RelayState" value="r"></form>"#),
        ] {
            assert!(handoff_form(&bad, &document, &dooray).is_err(), "{bad}");
        }
    }
}
