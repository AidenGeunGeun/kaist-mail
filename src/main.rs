mod auth;
mod cli;
mod client;
mod commands;
mod download;
mod error;
#[cfg(test)]
#[allow(dead_code)]
#[path = "../tests/fixture/server.rs"]
mod fixture_server;
mod html_text;
mod http;
mod mail;
mod output;
mod private_fs;
mod url;

use std::process::ExitCode;

use clap::{Parser, error::ErrorKind};

use crate::{cli::Cli, error::AppError};

fn report_parse_error(error: clap::Error, json: bool) -> ExitCode {
    let informational = matches!(
        error.kind(),
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
    );
    match (json, informational) {
        (true, true) => {
            let (command, data) = match error.kind() {
                ErrorKind::DisplayVersion => (
                    "version",
                    serde_json::json!({"name": "kaist-mail", "version": env!("CARGO_PKG_VERSION")}),
                ),
                _ => ("help", serde_json::json!({"text": error.to_string()})),
            };
            let result = output::result(command, &data, error.to_string())
                .expect("informational output is serializable");
            output::print_success(&result, true);
            ExitCode::SUCCESS
        }
        (true, false) => {
            let app_error = AppError::usage(error.to_string());
            output::print_error(&app_error, true);
            ExitCode::from(app_error.exit_code())
        }
        _ => {
            let _ = error.print();
            ExitCode::from(if error.use_stderr() { 2 } else { 0 })
        }
    }
}

fn main() -> ExitCode {
    let json = std::env::args_os()
        .take_while(|arg| arg != "--")
        .any(|arg| arg == "--json");
    // A panic message can quote the data being processed, such as mail.
    std::panic::set_hook(Box::new(move |panic| {
        let mut error = AppError::internal(
            "kaist-mail hit a bug; its details are withheld because they may quote mail",
        );
        if let Some(at) = panic.location() {
            error = error
                .with_details(serde_json::json!({"at": format!("{}:{}", at.file(), at.line())}));
        }
        output::print_error(&error, json);
        std::process::exit(error.exit_code().into());
    }));
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => return report_parse_error(error, json),
    };
    match commands::run(&cli) {
        Ok(result) => {
            output::print_success(&result, cli.json);
            ExitCode::SUCCESS
        }
        Err(error) => {
            output::print_error(&error, cli.json);
            ExitCode::from(error.exit_code())
        }
    }
}
