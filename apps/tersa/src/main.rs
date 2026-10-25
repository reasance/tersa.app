// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! `tersa`: a privacy-first Gmail client for the terminal.

#![forbid(unsafe_code)]

mod cli;
mod commands;
mod config;
mod dates;
mod prompt;
mod tui;

use std::process::ExitCode;

use cli::Command;
use commands::Context;
use config::{Config, Paths};

fn main() -> ExitCode {
    let command = match cli::parse(std::env::args_os().skip(1)) {
        Ok(command) => command,
        Err(message) => {
            eprintln!("tersa: {message}");
            return ExitCode::from(2);
        }
    };
    match run(command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("tersa: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run(command: Command) -> Result<(), String> {
    match command {
        Command::Help => {
            println!("{}", cli::USAGE);
            return Ok(());
        }
        Command::Version => {
            println!("tersa {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        _ => {}
    }
    let paths = Paths::discover()?;
    let config = Config::load(&paths.config_file())?;
    let context = Context { paths, config };
    match command {
        Command::Help | Command::Version => Ok(()),
        Command::Tui => commands::tui(&context),
        Command::AccountAdd => commands::account_add(&context),
        Command::AccountList => commands::account_list(&context),
        Command::AccountRemove(account) => commands::account_remove(&context, &account),
        Command::Sync(account) => commands::sync(&context, account.as_deref()),
        Command::Inbox { account, limit } => commands::inbox(&context, account.as_deref(), limit),
        Command::Doctor => {
            commands::doctor(&context);
            Ok(())
        }
    }
}
