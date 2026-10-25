// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Command-line parsing.

use std::ffi::OsString;

/// Default number of messages `inbox` prints.
pub const DEFAULT_INBOX_LIMIT: u16 = 25;

pub const USAGE: &str = "\
tersa — a privacy-first Gmail client for the terminal

Usage:
  tersa                           Open the full-screen interface
  tersa account add               Sign in with Google and add an account
  tersa account list              List added accounts
  tersa account remove <account>  Revoke access and delete local data
  tersa sync [<account>]          Fetch recent mail (all accounts by default)
  tersa inbox [<account>] [--limit <n>]
                                  Print cached recent mail
  tersa doctor                    Check configuration and storage
  tersa help | --version";

#[derive(Debug, Eq, PartialEq)]
pub enum Command {
    Tui,
    Help,
    Version,
    AccountAdd,
    AccountList,
    AccountRemove(String),
    Sync(Option<String>),
    Inbox { account: Option<String>, limit: u16 },
    Doctor,
}

/// Parses the arguments after the program name.
pub fn parse<I: IntoIterator<Item = OsString>>(arguments: I) -> Result<Command, String> {
    let arguments = arguments
        .into_iter()
        .map(|argument| {
            argument
                .into_string()
                .map_err(|_invalid| "arguments must be valid UTF-8".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let words: Vec<&str> = arguments.iter().map(String::as_str).collect();
    match words.as_slice() {
        [] => Ok(Command::Tui),
        ["help" | "-h" | "--help"] => Ok(Command::Help),
        ["--version" | "-V" | "version"] => Ok(Command::Version),
        ["account", "add"] => Ok(Command::AccountAdd),
        ["account", "list"] => Ok(Command::AccountList),
        ["account", "remove", account] => Ok(Command::AccountRemove((*account).to_owned())),
        ["sync"] => Ok(Command::Sync(None)),
        ["sync", account] => Ok(Command::Sync(Some((*account).to_owned()))),
        ["inbox", rest @ ..] => parse_inbox(rest),
        ["doctor"] => Ok(Command::Doctor),
        _ => Err("unrecognized command; run `tersa help`".to_owned()),
    }
}

fn parse_inbox(rest: &[&str]) -> Result<Command, String> {
    let mut account = None;
    let mut limit = DEFAULT_INBOX_LIMIT;
    let mut iterator = rest.iter();
    while let Some(word) = iterator.next() {
        if *word == "--limit" {
            let value = iterator
                .next()
                .ok_or_else(|| "--limit needs a number".to_owned())?;
            limit = value
                .parse()
                .ok()
                .filter(|limit| (1..=500).contains(limit))
                .ok_or_else(|| "--limit must be between 1 and 500".to_owned())?;
        } else if account.is_none() && !word.starts_with('-') {
            account = Some((*word).to_owned());
        } else {
            return Err(format!("unexpected argument `{word}`"));
        }
    }
    Ok(Command::Inbox { account, limit })
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::{Command, DEFAULT_INBOX_LIMIT, parse};

    fn run(words: &[&str]) -> Result<Command, String> {
        parse(words.iter().map(OsString::from))
    }

    #[test]
    fn parses_every_command() {
        assert_eq!(run(&[]), Ok(Command::Tui));
        assert_eq!(run(&["help"]), Ok(Command::Help));
        assert_eq!(run(&["--version"]), Ok(Command::Version));
        assert_eq!(run(&["account", "add"]), Ok(Command::AccountAdd));
        assert_eq!(run(&["account", "list"]), Ok(Command::AccountList));
        assert_eq!(
            run(&["account", "remove", "acct_1"]),
            Ok(Command::AccountRemove("acct_1".to_owned()))
        );
        assert_eq!(run(&["sync"]), Ok(Command::Sync(None)));
        assert_eq!(
            run(&["sync", "acct_1"]),
            Ok(Command::Sync(Some("acct_1".to_owned())))
        );
        assert_eq!(
            run(&["inbox"]),
            Ok(Command::Inbox {
                account: None,
                limit: DEFAULT_INBOX_LIMIT
            })
        );
        assert_eq!(
            run(&["inbox", "acct_1", "--limit", "10"]),
            Ok(Command::Inbox {
                account: Some("acct_1".to_owned()),
                limit: 10
            })
        );
        assert_eq!(run(&["doctor"]), Ok(Command::Doctor));
    }

    #[test]
    fn rejects_bad_input() {
        assert!(run(&["account"]).is_err());
        assert!(run(&["inbox", "--limit", "0"]).is_err());
        assert!(run(&["inbox", "--limit"]).is_err());
        assert!(run(&["inbox", "a", "b"]).is_err());
        assert!(run(&["frobnicate"]).is_err());
    }
}
