// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Explicitly confirmed, existing-only account cache reset.

use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::sync::Arc;

use tersa_application::mailbox::{AccountEmail, AccountId};
use tersa_keys::RootKey;
use tersa_presentation::terminal::SafeText;
use tersa_sync_runtime::{CacheResetOutcome, Installation, InstallationLock, OAuthClient, Runtime};
use tersa_vault::VaultState;

use super::{Context, Locked, executor, open_vault, unlock_with_passphrase};

const CONFIRMATION_LIMIT: u64 = 256;

enum Completion {
    Resynced { messages: u16, bodies: u16 },
    ResyncFailed(SafeText),
}

pub fn account_reset(context: &Context, raw: &str, yes: bool) -> Result<(), String> {
    let input = io::stdin();
    reset_using(
        context,
        raw,
        yes,
        input.is_terminal(),
        &mut input.lock(),
        &mut io::stderr().lock(),
        |context| open_preview_using(context, unlock_existing_root),
        execute_reset,
    )
}

/// Lock before reading the vault; never mint a root or reopen a writable registry.
fn open_preview_using(
    context: &Context,
    unlock_root: impl FnOnce(&Context) -> Result<RootKey, String>,
) -> Result<Locked, String> {
    let held = InstallationLock::acquire_existing(&context.paths.data_dir)
        .map_err(|error| error.to_string())?;
    let root = unlock_root(context)?;
    let installation = Installation::open_existing(&context.paths.data_dir, root)
        .map_err(|error| error.to_string())?;
    Ok(Locked {
        installation: Arc::new(installation),
        _lock: held,
    })
}

fn unlock_existing_root(context: &Context) -> Result<RootKey, String> {
    let vault = open_vault(context)?;
    match vault.state().map_err(|error| error.to_string())? {
        VaultState::Empty => Err(
            "no existing installation key is available; account reset cannot create a key"
                .to_owned(),
        ),
        VaultState::Unprotected => vault.unlock(None).map_err(|error| error.to_string()),
        VaultState::PassphraseProtected => unlock_with_passphrase(&vault),
    }
}

// The seams substitute only unlocked fixture roots and network outcomes in tests.
// Production always uses the existing-only opener and Runtime::reset_cache.
#[expect(
    clippy::too_many_arguments,
    reason = "explicit command I/O and two bounded test seams"
)]
fn reset_using(
    context: &Context,
    raw: &str,
    yes: bool,
    interactive: bool,
    input: &mut impl BufRead,
    output: &mut impl Write,
    open: impl FnOnce(&Context) -> Result<Locked, String>,
    run: impl FnOnce(Arc<Installation>, OAuthClient, &AccountId) -> Result<Completion, String>,
) -> Result<(), String> {
    validate_request(raw, yes, interactive)?;
    // Validate configuration before unlocking, prompting or any destructive work.
    let client = context
        .config
        .oauth_client(&context.paths.config_file())
        .map_err(|message| safe_error(&message))?;
    let locked = open(context).map_err(|message| safe_error(&message))?;
    let account =
        resolve_existing(&locked.installation, raw).map_err(|message| safe_error(&message))?;
    // Even an exact ID and --yes must authenticate the selected profile.
    let email = locked
        .installation
        .account_email_existing(&account)
        .map_err(|error| safe_error(&error.to_string()))?;
    if !yes {
        write_confirmation(output, &account, email.as_ref())?;
        if !read_confirmation(input)? {
            writeln!(output, "Reset cancelled; local cache was not cleared.")
                .map_err(|_error| "reset cancelled; local cache was not cleared".to_owned())?;
            return Ok(());
        }
    }
    // locked outlives Runtime and its sync; its Arc and lock are never replaced.
    let result = run(Arc::clone(&locked.installation), client, &account);
    finish(output, &account, result)
}

fn validate_request(raw: &str, yes: bool, interactive: bool) -> Result<(), String> {
    if raw.trim().is_empty() {
        return Err(
            "an account is required; empty account input cannot select an account".to_owned(),
        );
    }
    if !yes && !interactive {
        return Err("account reset requires interactive input or explicit --yes; local cache was not cleared".to_owned());
    }
    Ok(())
}

fn resolve_existing(installation: &Installation, raw: &str) -> Result<AccountId, String> {
    let accounts = installation.accounts().map_err(|error| error.to_string())?;
    resolve_with(&accounts, raw, |account| {
        installation
            .account_email_existing(account)
            .map_err(|error| error.to_string())
    })
}

fn resolve_with(
    accounts: &[AccountId],
    raw: &str,
    mut email: impl FnMut(&AccountId) -> Result<Option<AccountEmail>, String>,
) -> Result<AccountId, String> {
    if raw.trim().is_empty() {
        return Err("an account is required".to_owned());
    }
    if let Some(account) = accounts.iter().find(|account| account.as_str() == raw) {
        return Ok(account.clone());
    }
    let prefixes: Vec<_> = accounts
        .iter()
        .filter(|account| account.as_str().starts_with(raw))
        .collect();
    match prefixes.as_slice() {
        [account] => return Ok((*account).clone()),
        [] => {}
        _ => return Err(format!("`{raw}` matches more than one account")),
    }
    if raw.contains('@') {
        let mut matches = Vec::new();
        for account in accounts {
            // Do not skip an unreadable peer or stop at the first match.
            if email(account)?.is_some_and(|email| email.as_str().eq_ignore_ascii_case(raw)) {
                matches.push(account);
            }
        }
        match matches.as_slice() {
            [account] => return Ok((*account).clone()),
            [] => {}
            _ => return Err(format!("`{raw}` matches more than one account")),
        }
    }
    Err(format!(
        "no account matches `{raw}`; see `tersa account list`"
    ))
}

fn write_confirmation(
    output: &mut impl Write,
    account: &AccountId,
    email: Option<&AccountEmail>,
) -> Result<(), String> {
    let id = SafeText::single_line(account.as_str());
    let label = email.map_or_else(
        || id.to_string(),
        |email| format!("{} ({id})", SafeText::single_line(email.as_str())),
    );
    writeln!(output, "Reset local cache for {label}?\nThis deletes local downloaded mail, then downloads recent mail using the normal bounded limit.\nType yes to continue:")
        .and_then(|()| output.flush())
        .map_err(|_error| "could not display confirmation; local cache was not cleared".to_owned())
}

fn read_confirmation(input: &mut impl BufRead) -> Result<bool, String> {
    let mut line = Vec::new();
    input
        .take(CONFIRMATION_LIMIT + 1)
        .read_until(b'\n', &mut line)
        .map_err(|_error| "could not read confirmation; local cache was not cleared".to_owned())?;
    Ok(
        u64::try_from(line.len()).is_ok_and(|len| len <= CONFIRMATION_LIMIT)
            && line.last() == Some(&b'\n')
            && std::str::from_utf8(&line).is_ok_and(|line| line.trim().eq_ignore_ascii_case("yes")),
    )
}

fn execute_reset(
    installation: Arc<Installation>,
    client: OAuthClient,
    account: &AccountId,
) -> Result<Completion, String> {
    let mut runtime = Runtime::new(installation, client).map_err(|error| error.to_string())?;
    let outcome = executor()?
        .block_on(runtime.reset_cache(account))
        .map_err(|error| error.to_string())?;
    Ok(match outcome {
        CacheResetOutcome::Resynced(report) => Completion::Resynced {
            messages: report.progress().envelopes,
            bodies: report.progress().bodies_cached,
        },
        CacheResetOutcome::ResyncFailed(error) => {
            Completion::ResyncFailed(SafeText::single_line(&error.to_string()))
        }
    })
}

fn finish(
    output: &mut impl Write,
    account: &AccountId,
    result: Result<Completion, String>,
) -> Result<(), String> {
    let id = SafeText::single_line(account.as_str());
    match result {
        Err(error) => Err(format!("Cache reset refused before clearing local mail: {}", SafeText::single_line(&error))),
        Ok(Completion::Resynced { messages, bodies }) => {
            writeln!(output, "Cleared local cache for {id}. Recent-mail sync completed: {messages} messages, {bodies} bodies cached (normal bounded limit). The account remains registered.")
                .map_err(|_error| "local cache clear and sync completed, but the result could not be written".to_owned())
        }
        Ok(Completion::ResyncFailed(error)) => Err(format!(
            "Local cache clear committed for {id}, but sync failed: {error}. Partial new cache data may exist; the account remains registered. Run `tersa sync {id}` to retry. If sign-in is required, run `tersa account add`."
        )),
    }
}

fn safe_error(message: &str) -> String {
    SafeText::single_line(message).to_string()
}

#[cfg(test)]
mod tests;
