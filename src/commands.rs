use serde::{Deserialize, Serialize};

use crate::{
    auth::{self, AuthStatus, LoginOptions},
    cli::{AuthCommand, Cli, Command},
    client::{Client, SYSTEM_FOLDERS, USER_FOLDERS, validate_base_url},
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
        Command::List(args) => crate::query::list(&Client::new(base, cli.timeout)?, args),
        Command::Search(args) => crate::query::search(&Client::new(base, cli.timeout)?, args),
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
    total_count: u64,
    contents: Vec<Folder>,
}

/// A folder as agents see it. `name` is the stable identifier for system
/// folders (`inbox`, `sent`, `draft`, `archive`, `spam`, `trash`) and the
/// user's own label, in any language, for user folders.
#[derive(Deserialize, Serialize)]
struct Folder {
    id: String,
    name: String,
    #[serde(rename = "type")]
    kind: String,
    #[serde(rename(deserialize = "totalCount"))]
    total: u64,
    #[serde(rename(deserialize = "unreadCount"))]
    unread: u64,
    #[serde(
        default,
        rename(deserialize = "parentFolderId"),
        skip_serializing_if = "Option::is_none"
    )]
    parent: Option<String>,
}

fn folders(client: &Client) -> Result<CommandResult, AppError> {
    let mut folders = Vec::new();
    let mut total = 0;
    for path in [SYSTEM_FOLDERS, USER_FOLDERS] {
        let page: FolderPage = client.wapi(path)?;
        total += page.total_count;
        folders.extend(page.contents);
    }
    let human = match folders.is_empty() {
        true => "No folders found.".to_owned(),
        false => std::iter::once("ID\tUNREAD\tTOTAL\tNAME".to_owned())
            .chain(folders.iter().map(|folder| {
                format!(
                    "{}\t{}\t{}\t{}",
                    folder.id, folder.unread, folder.total, folder.name
                )
            }))
            .collect::<Vec<_>>()
            .join("\n"),
    };
    let mut result = output::result("folders", &folders, human)?;
    result.meta = Some(ListMeta {
        returned: folders.len(),
        total: Some(total),
        ..ListMeta::default()
    });
    Ok(result)
}
