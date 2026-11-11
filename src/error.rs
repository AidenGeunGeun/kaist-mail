use std::fmt;

use serde::Serialize;
use serde_json::{Value, json};

const LOGIN_HINT: &str = "Run `kaist-mail auth login` to sign in again.";

#[derive(Debug, Clone, Serialize)]
pub struct AppError {
    pub code: &'static str,
    pub message: String,
    pub hint: Option<String>,
    pub retryable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
    #[serde(skip)]
    exit_code: u8,
}

macro_rules! constructors {
    ($($name:ident $code:literal $exit:literal $hint:expr;)*) => {
        $(pub fn $name(message: impl Into<String>) -> Self {
            Self::new($code, message, $hint, $exit)
        })*
    };
}

impl AppError {
    constructors! {
        usage "USAGE" 2 None;
        auth_required "AUTH_REQUIRED" 10 Some(LOGIN_HINT);
        auth_expired "AUTH_EXPIRED" 10 Some(LOGIN_HINT);
        code_expired "CODE_EXPIRED" 10 Some("Run `kaist-mail auth login` to request a new verification code.");
        code_incorrect "CODE_INCORRECT" 10 Some("Run `kaist-mail auth login` and enter the newest six-digit code.");
        credentials_rejected "CREDENTIALS_REJECTED" 10 Some("Check the credentials and retry `kaist-mail auth login --method password`.");
        auth_protocol "AUTH_PROTOCOL_CHANGED" 11 Some("KAIST SSO or Dooray sign-in may have changed; update kaist-mail and retry.");
        network "NETWORK_ERROR" 20 None;
        shape "UPSTREAM_SHAPE_CHANGED" 30 Some("Dooray may have changed its API; update kaist-mail and retry.");
        upstream "UPSTREAM_ERROR" 31 None;
        config "CONFIG_ERROR" 40 None;
        limit "LIMIT_EXCEEDED" 41 None;
        not_found "NOT_FOUND" 44 None;
        internal "INTERNAL_ERROR" 50 None;
    }

    pub fn auth(message: impl Into<String>, hint: impl Into<String>) -> Self {
        Self::auth_required(message).with_hint(hint)
    }

    pub fn code_required(channel: &str, expires_at: u64) -> Self {
        let resume = "kaist-mail auth login --code CODE";
        Self::new(
            "CODE_REQUIRED",
            format!("KAIST sent a verification code by {channel}; enter it to finish signing in"),
            Some("Run `kaist-mail auth login --code CODE` with the six-digit code before the pending login expires."),
            12,
        )
        .with_details(json!({"channel": channel, "expires_at": expires_at, "resume": resume}))
    }

    pub fn http(status: u16, path: &str) -> Self {
        let message = format!("Dooray returned HTTP {status} for {path}");
        match status {
            401 => Self::auth_expired(format!("Dooray rejected the saved session for {path}")),
            403 => Self::new(
                "PERMISSION_DENIED",
                format!("Dooray denied access to {path}"),
                Some("Confirm that this resource belongs to your account and is still available."),
                13,
            ),
            404 => Self::not_found(format!("Dooray resource was not found: {path}")),
            408 | 425 | 429 | 500..=599 => Self::network(message),
            _ => Self::new("HTTP_ERROR", message, None, 21),
        }
    }

    fn new(code: &'static str, message: impl Into<String>, hint: Option<&str>, exit: u8) -> Self {
        Self {
            code,
            message: message.into(),
            hint: hint.map(Into::into),
            retryable: code == "NETWORK_ERROR",
            details: None,
            exit_code: exit,
        }
    }

    pub fn with_details(mut self, details: Value) -> Self {
        self.details = Some(details);
        self
    }

    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    pub fn exit_code(&self) -> u8 {
        self.exit_code
    }
}

/// A JSON decoding failure by kind and position only: serde's own message can
/// quote the input, which may be mail data or a secret.
pub fn json_problem(error: &serde_json::Error) -> String {
    use serde_json::error::Category;
    let kind = match error.classify() {
        Category::Io => "an unreadable document",
        Category::Syntax => "malformed JSON",
        Category::Eof => "truncated JSON",
        Category::Data => "an unexpected field, type or value",
    };
    format!("{kind} at line {} column {}", error.line(), error.column())
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for AppError {}
