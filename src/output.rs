use serde::Serialize;
use serde_json::Value;

use crate::error::AppError;

pub const SCHEMA_VERSION: &str = "1";

#[derive(Debug, Clone, Serialize)]
pub struct ListMeta {
    pub returned: usize,
    /// What Dooray reports as the full count; `None` when it does not say.
    pub total: Option<u64>,
}

#[derive(Debug)]
pub struct CommandResult {
    pub command: &'static str,
    pub data: Value,
    pub human: String,
    pub warnings: Vec<String>,
    pub meta: Option<ListMeta>,
}

#[derive(Serialize)]
#[serde(untagged)]
enum Envelope<'a> {
    Success {
        schema_version: &'static str,
        ok: bool,
        command: &'a str,
        data: &'a Value,
        warnings: &'a [String],
        #[serde(skip_serializing_if = "Option::is_none")]
        meta: &'a Option<ListMeta>,
    },
    Failure {
        schema_version: &'static str,
        ok: bool,
        error: &'a AppError,
    },
}

pub fn result<T: Serialize>(
    command: &'static str,
    data: &T,
    human: String,
) -> Result<CommandResult, AppError> {
    Ok(CommandResult {
        command,
        data: serde_json::to_value(data)
            .map_err(|error| AppError::internal(format!("failed to encode output: {error}")))?,
        human,
        warnings: Vec::new(),
        meta: None,
    })
}

pub fn print_success(result: &CommandResult, json: bool) {
    if json {
        let envelope = Envelope::Success {
            schema_version: SCHEMA_VERSION,
            ok: true,
            command: result.command,
            data: &result.data,
            warnings: &result.warnings,
            meta: &result.meta,
        };
        println!(
            "{}",
            serde_json::to_string(&envelope).expect("serializable envelope")
        );
    } else {
        println!("{}", sanitize_terminal(&result.human));
        for warning in &result.warnings {
            eprintln!("warning: {}", sanitize_terminal(warning));
        }
    }
}

pub fn print_error(error: &AppError, json: bool) {
    if json {
        let envelope = Envelope::Failure {
            schema_version: SCHEMA_VERSION,
            ok: false,
            error,
        };
        eprintln!(
            "{}",
            serde_json::to_string(&envelope).expect("serializable envelope")
        );
    } else {
        eprintln!(
            "error [{}]: {}",
            error.code,
            sanitize_terminal(&error.message)
        );
        if let Some(hint) = &error.hint {
            eprintln!("hint: {}", sanitize_terminal(hint));
        }
    }
}

/// Drops control and bidirectional-override characters that server text could
/// use to rewrite the terminal; every other character, Hangul included, stays.
pub fn sanitize_terminal(value: &str) -> String {
    value
        .chars()
        .filter(|character| {
            (!character.is_control() || matches!(character, '\n' | '\t'))
                && !matches!(
                    character,
                    '\u{061c}'
                        | '\u{200e}'
                        | '\u{200f}'
                        | '\u{202a}'..='\u{202e}'
                        | '\u{2066}'..='\u{2069}'
                )
        })
        .collect()
}
