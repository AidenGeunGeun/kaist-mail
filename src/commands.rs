use serde::{Deserialize, Deserializer, Serialize};

use crate::{
    auth::{self, AuthStatus, LoginOptions},
    cli::{AuthCommand, Cli, Command},
    client::{Client, validate_base_url},
    error::AppError,
    output::{self, CommandResult, ListMeta},
};

pub fn run(cli: &Cli) -> Result<CommandResult, AppError> {
    let base = validate_base_url(&cli.base_url)?;
    match &cli.command {
        Command::Auth(AuthCommand::Login(args)) => {
            let options = LoginOptions {
                user: args.user.clone(),
                method: args.method,
                factor: args.second_factor,
                remember_password: args.remember_password,
                code: args.code.clone(),
            };
            auth::login(&base, cli.timeout, &options, cli.json)
        }
        Command::Auth(AuthCommand::Logout) => auth::logout(),
        Command::Auth(AuthCommand::Forget) => auth::forget(),
        Command::Auth(AuthCommand::Status) => {
            let status = auth::load(&base)?.status;
            let human = status_text(&status);
            output::result("auth.status", &status, human)
        }
        Command::Folders => folders(&Client::new(base, cli.timeout)?),
    }
}

fn status_text(status: &AuthStatus) -> String {
    let mut lines = vec![match status.configured {
        true => format!("Session: {}", status.path),
        false => format!("Not signed in (no session at {})", status.path),
    }];
    let now = crate::auth::epoch_now();
    if let Some(created) = status.created_at {
        lines.push(format!(
            "Saved: {} ago",
            duration(now.saturating_sub(created))
        ));
    }
    for cookie in &status.cookies {
        let expiry = match cookie.expires_at {
            None => "until Dooray ends the session".to_owned(),
            Some(_) if cookie.expired => "expired".to_owned(),
            Some(at) => format!("expires in {}", duration(at - now)),
        };
        lines.push(format!("Cookie {}: {expiry}", cookie.name));
    }
    match (&status.remembered, &status.remembered_error) {
        (Some(found), _) => lines.push(format!(
            "Remembered login: {} ({}{}){}",
            found.username,
            found.method,
            found
                .second_factor
                .as_ref()
                .map(|factor| format!(", code by {factor}"))
                .unwrap_or_default(),
            if found.password_saved {
                ", password in keychain"
            } else {
                ""
            }
        )),
        (None, Some(error)) => lines.push(format!("Remembered login unreadable: {error}")),
        (None, None) => {}
    }
    lines.join("\n")
}

fn duration(seconds: u64) -> String {
    match seconds {
        0..120 => format!("{seconds}s"),
        120..7_200 => format!("{}m", seconds / 60),
        7_200..172_800 => format!("{}h", seconds / 3_600),
        _ => format!("{}d", seconds / 86_400),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FolderPage {
    total_count: Option<u64>,
    contents: Vec<Folder>,
}

#[derive(Deserialize, Serialize)]
struct Folder {
    #[serde(deserialize_with = "id_text")]
    id: String,
    name: String,
}

/// Dooray ids are large integers; accept them as JSON strings or numbers.
fn id_text<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Id {
        Text(String),
        Number(u64),
    }
    Ok(match Id::deserialize(deserializer)? {
        Id::Text(text) => text,
        Id::Number(number) => number.to_string(),
    })
}

fn folders(client: &Client) -> Result<CommandResult, AppError> {
    let page: FolderPage = client.wapi("/v2/wapi/mail-folders")?;
    let human = match page.contents.is_empty() {
        true => "No folders found.".to_owned(),
        false => std::iter::once("ID\tNAME".to_owned())
            .chain(
                page.contents
                    .iter()
                    .map(|folder| format!("{}\t{}", folder.id, folder.name)),
            )
            .collect::<Vec<_>>()
            .join("\n"),
    };
    let mut result = output::result("folders", &page.contents, human)?;
    result.meta = Some(ListMeta {
        returned: page.contents.len(),
        total: page.total_count,
    });
    Ok(result)
}
