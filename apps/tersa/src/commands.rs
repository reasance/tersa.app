// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Command implementations.

use std::process::{Command as Process, Stdio};
use std::sync::Arc;

use tersa_application::mailbox::{
    AccountId, EnvelopeCursor, MailboxReader, MessageEnvelope, MessageId, StoreLimit,
    UnixTimestampMillis,
};
use tersa_application::sync::SyncReport;
use tersa_keys::RootKey;
use tersa_presentation::terminal::SafeText;
use tersa_store_sqlcipher::SqlCipherMailboxStore;
use tersa_sync_runtime::{
    FlowError, Installation, InstallationLock, Revocation, Runtime, has_local_data,
};
use tersa_vault::{SlotKind, Vault, VaultError, VaultState};

use crate::config::{Config, Paths};
use crate::prompt;

const PASSPHRASE_ATTEMPTS: usize = 3;

pub struct Context {
    pub paths: Paths,
    pub config: Config,
}

/// Whether unlocking may create the vault.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Create {
    Allowed,
    Forbidden,
}

fn open_vault(context: &Context) -> Result<Vault, String> {
    Vault::open(&context.paths.data_dir, context.config.backend).map_err(|error| match error {
        VaultError::KeyringUnavailable => "no system keyring is reachable; set \
             `[vault] backend = \"file\"` to use a passphrase-protected key file instead"
            .to_owned(),
        other => other.to_string(),
    })
}

/// Takes the exclusive installation lock for the rest of the command.
fn lock(context: &Context) -> Result<InstallationLock, String> {
    InstallationLock::acquire(&context.paths.data_dir).map_err(|error| error.to_string())
}

/// Takes the lock for a command that cannot create an installation, or
/// returns `None` when the data directory does not exist. Callers then stop
/// before reading the vault: the keyring entry is shared by every data
/// directory, so a key may exist although this directory does not, and
/// opening it here would create an installation without the lock. Any other
/// error goes through [`lock`] and fails closed.
fn lock_existing(context: &Context) -> Result<Option<InstallationLock>, String> {
    match std::fs::symlink_metadata(&context.paths.data_dir) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        _ => lock(context).map(Some),
    }
}

const NO_ACCOUNTS: &str = "no accounts yet; run `tersa account add`";

fn missing_key_message(context: &Context, vault: &Vault) -> String {
    let location = match vault.kind() {
        SlotKind::Keyring => "the system keyring",
        SlotKind::File => "the passphrase-protected key file",
    };
    format!(
        "encrypted data exists in {dir}, but its key is not in {location}.\n\
         - If the system keyring is temporarily unavailable (for example over SSH \
         without a Secret Service session), make it available and retry; set \
         `[vault] backend = \"keyring\"` to stop falling back to a key file.\n\
         - If the key was created in a passphrase-protected key file (for example \
         on a host without a keyring), set `[vault] backend = \"file\"`.\n\
         - If the key was deleted, this data cannot be decrypted: move {dir} \
         aside and run `tersa account add` again.",
        dir = context.paths.data_dir.display()
    )
}

/// What to do with the vault before opening the installation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UnlockPlan {
    /// The key is gone but encrypted data remains: stop, never mint a key.
    RefuseMissingKey,
    /// Nothing exists and this command may not create anything.
    NothingYet,
    /// First run: create a new root key.
    CreateKey,
    /// Open the existing key without a passphrase.
    Unlock,
    /// Open the existing key with a passphrase.
    UnlockWithPassphrase,
}

/// Decides how to unlock. A new root key is minted only when the vault is
/// empty, no encrypted data exists, and the command may create.
fn plan_unlock(state: VaultState, has_local_data: bool, create: Create) -> UnlockPlan {
    match state {
        VaultState::Empty if has_local_data => UnlockPlan::RefuseMissingKey,
        VaultState::Empty if create == Create::Forbidden => UnlockPlan::NothingYet,
        VaultState::Empty => UnlockPlan::CreateKey,
        VaultState::Unprotected => UnlockPlan::Unlock,
        VaultState::PassphraseProtected => UnlockPlan::UnlockWithPassphrase,
    }
}

/// Unlocks the vault and opens the installation. The lock parameter is
/// unused at run time: requiring it makes "unlock only while holding the
/// installation lock" a compile-time rule, since only
/// [`InstallationLock::acquire`] can produce one.
fn unlock(
    context: &Context,
    _held: &InstallationLock,
    create: Create,
) -> Result<Option<Arc<Installation>>, String> {
    let vault = open_vault(context)?;
    let state = vault.state().map_err(|error| error.to_string())?;
    let root = match plan_unlock(state, has_local_data(&context.paths.data_dir), create) {
        UnlockPlan::RefuseMissingKey => return Err(missing_key_message(context, &vault)),
        UnlockPlan::NothingYet => return Ok(None),
        UnlockPlan::CreateKey => {
            let passphrase = if vault.kind() == SlotKind::File || context.config.passphrase {
                if vault.kind() == SlotKind::File {
                    eprintln!(
                        "No system keyring is available, so tersa protects its key with a \
                         passphrase you will enter each time."
                    );
                }
                Some(prompt::new_passphrase().map_err(|error| error.to_string())?)
            } else {
                None
            };
            vault
                .create(passphrase.as_ref().map(|value| value.as_bytes()))
                .map_err(|error| error.to_string())?
        }
        UnlockPlan::Unlock => vault.unlock(None).map_err(|error| error.to_string())?,
        UnlockPlan::UnlockWithPassphrase => unlock_with_passphrase(&vault)?,
    };
    let installation =
        Installation::open(&context.paths.data_dir, root).map_err(|error| error.to_string())?;
    Ok(Some(Arc::new(installation)))
}

fn unlock_with_passphrase(vault: &Vault) -> Result<RootKey, String> {
    for _ in 0..PASSPHRASE_ATTEMPTS {
        let passphrase = prompt::passphrase("Passphrase: ").map_err(|error| error.to_string())?;
        match vault.unlock(Some(passphrase.as_bytes())) {
            Ok(root) => return Ok(root),
            Err(VaultError::WrongPassphrase) => eprintln!("Wrong passphrase."),
            Err(other) => return Err(other.to_string()),
        }
    }
    Err("too many wrong passphrases".to_owned())
}

/// Opens an existing installation under its lock, for commands that may not
/// mint a root key. It returns `None` when there is no data directory or no
/// key and no encrypted data yet.
fn open_existing(context: &Context) -> Result<Option<Locked>, String> {
    let Some(lock) = lock_existing(context)? else {
        return Ok(None);
    };
    Ok(
        unlock(context, &lock, Create::Forbidden)?.map(|installation| Locked {
            installation,
            _lock: lock,
        }),
    )
}

/// An open installation and the lock that guards it. Fields drop in
/// declaration order, so the lock is released last.
struct Locked {
    installation: Arc<Installation>,
    _lock: InstallationLock,
}

fn require_installation(context: &Context) -> Result<Locked, String> {
    open_existing(context)?.ok_or_else(|| NO_ACCOUNTS.to_owned())
}

fn runtime(context: &Context, installation: Arc<Installation>) -> Result<Runtime, String> {
    let client = context.config.oauth_client(&context.paths.config_file())?;
    Runtime::new(installation, client).map_err(|error| error.to_string())
}

fn executor() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("could not start the async runtime: {error}"))
}

fn resolve_account(installation: &Installation, raw: &str) -> Result<AccountId, String> {
    let accounts = installation.accounts().map_err(|error| error.to_string())?;
    // An id, or a prefix of one, resolves without opening any store. Only an
    // `@` argument pays for the per-account stored-address reads, and a read
    // that fails is reported rather than silently becoming "no account
    // matches".
    let mut id_matches = accounts
        .iter()
        .filter(|account| account.as_str() == raw || account.as_str().starts_with(raw));
    match (id_matches.next(), id_matches.next()) {
        (Some(account), None) => return Ok(account.clone()),
        (Some(_), Some(_)) => return Err(format!("`{raw}` matches more than one account")),
        (None, _) => {}
    }
    if !raw.contains('@') {
        return Err(format!(
            "no account matches `{raw}`; see `tersa account list`"
        ));
    }
    let raw_lowercase = raw.to_ascii_lowercase();
    let mut address_matches = Vec::new();
    for account in &accounts {
        match installation.account_email(account) {
            Ok(Some(email)) if email.as_str().eq_ignore_ascii_case(&raw_lowercase) => {
                address_matches.push(account.clone());
            }
            Ok(_) => {}
            Err(error) => return Err(error.to_string()),
        }
    }
    match (address_matches.first(), address_matches.get(1)) {
        (Some(account), None) => Ok(account.clone()),
        (Some(_), Some(_)) => Err(format!("`{raw}` matches more than one account")),
        (None, _) => Err(format!(
            "no account matches `{raw}`; see `tersa account list`"
        )),
    }
}

fn describe_report(report: SyncReport) -> String {
    let progress = report.progress();
    format!(
        "{} messages, {} bodies cached",
        progress.envelopes, progress.bodies_cached
    )
}

fn open_browser(url: &str) {
    eprintln!(
        "Opening your browser to sign in with Google. If it does not open, visit:\n\n{url}\n"
    );
    let opener = if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    // Arguments are passed as a vector, never through a shell.
    let _ = Process::new(opener)
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

pub fn account_add(context: &Context) -> Result<(), String> {
    // Fail on a missing OAuth client before creating any key material.
    context.config.oauth_client(&context.paths.config_file())?;
    let lock = lock(context)?;
    let installation = unlock(context, &lock, Create::Allowed)?
        .ok_or_else(|| "could not initialize local storage".to_owned())?;
    let runtime = runtime(context, installation)?;
    let added = executor()?
        .block_on(runtime.add_account(open_browser))
        .map_err(|error| error.to_string())?;
    if added.already_present {
        println!(
            "Account {} was already added; its access was renewed.",
            added.account.as_str()
        );
    } else {
        println!("Added account {}.", added.account.as_str());
    }
    match added.first_sync {
        Ok(report) => println!("First sync: {}.", describe_report(report)),
        Err(error) => eprintln!("The first sync failed: {error}. Run `tersa sync` to retry."),
    }
    Ok(())
}

pub fn account_list(context: &Context) -> Result<(), String> {
    let Some(locked) = open_existing(context)? else {
        println!("No accounts yet. Run `tersa account add`.");
        return Ok(());
    };
    let accounts = locked
        .installation
        .accounts()
        .map_err(|error| error.to_string())?;
    if accounts.is_empty() {
        println!("No accounts yet. Run `tersa account add`.");
    }
    for account in accounts {
        match locked
            .installation
            .account_email(&account)
            .ok()
            .flatten()
            .map(|email| SafeText::single_line(email.as_str()))
        {
            Some(email) => println!("{}  {}", email.as_str(), account.as_str()),
            None => println!("{}", account.as_str()),
        }
    }
    Ok(())
}

pub fn account_remove(context: &Context, raw: &str) -> Result<(), String> {
    let locked = require_installation(context)?;
    let installation = Arc::clone(&locked.installation);
    let account = resolve_account(&installation, raw)?;
    let runtime = runtime(context, installation)?;
    let revocation = executor()?
        .block_on(runtime.remove_account(&account))
        .map_err(|error| error.to_string())?;
    println!("Removed account {} and its local data.", account.as_str());
    if revocation == Revocation::Unconfirmed {
        eprintln!(
            "Google did not confirm revoking access. You can revoke it at \
             https://myaccount.google.com/permissions"
        );
    }
    Ok(())
}

pub fn sync(context: &Context, raw: Option<&str>) -> Result<(), String> {
    let locked = require_installation(context)?;
    let installation = Arc::clone(&locked.installation);
    let accounts = match raw {
        Some(raw) => vec![resolve_account(&installation, raw)?],
        None => installation.accounts().map_err(|error| error.to_string())?,
    };
    if accounts.is_empty() {
        println!("No accounts yet. Run `tersa account add`.");
        return Ok(());
    }
    let runtime = runtime(context, installation)?;
    let executor = executor()?;
    let mut failures = 0_usize;
    for account in &accounts {
        match executor.block_on(runtime.sync_account(account)) {
            Ok(report) => println!("{}: {}", account.as_str(), describe_report(report)),
            Err(error) => {
                failures += 1;
                eprintln!("{}: {error}", account.as_str());
            }
        }
    }
    if failures == 0 {
        Ok(())
    } else {
        Err(format!(
            "{failures} of {} accounts failed to sync",
            accounts.len()
        ))
    }
}

/// Prints the cached mail of one account, or of every account in one merged
/// list when no account is named. The merge and its order are the
/// interface's, so both surfaces read the cache alike.
///
/// # Errors
///
/// Returns a message when the installation cannot be opened, no account
/// matches `raw`, a store cannot be opened or read, or `limit` is invalid.
pub fn inbox(context: &Context, raw: Option<&str>, limit: u16) -> Result<(), String> {
    let locked = require_installation(context)?;
    let installation = Arc::clone(&locked.installation);
    let accounts = match raw {
        Some(raw) => vec![resolve_account(&installation, raw)?],
        None => installation.accounts().map_err(|error| error.to_string())?,
    };
    if accounts.is_empty() {
        return Err(NO_ACCOUNTS.to_owned());
    }
    let stores = accounts
        .into_iter()
        .map(|account| {
            installation
                .open_store(&account)
                .map(|store| (account, store))
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    let source = StoreSource {
        stores,
        executor: executor()?,
    };
    let limit = StoreLimit::new(limit).map_err(|_error| "invalid limit".to_owned())?;
    let envelopes = source
        .envelope_page(&[], limit)
        .map_err(|_error| "could not read the local mailbox".to_owned())?;
    if envelopes.is_empty() {
        println!("No cached mail. Run `tersa sync`.");
    }
    let labels = crate::tui::MailSource::account_labels(&source);
    let tagged = source.stores.len() > 1;
    for (account, envelope) in envelopes {
        let marker = if envelope.is_unread() { '*' } else { ' ' };
        let from = truncate(&SafeText::single_line(envelope.from().as_str()), 28);
        let subject = SafeText::single_line(envelope.subject().as_str());
        let date = crate::dates::format_local(envelope.received_at().as_millis());
        if tagged {
            // One tag column when several accounts share the list, like the
            // interface's rows.
            let label = labels
                .iter()
                .find(|(id, _)| *id == account)
                .map_or("", |(_, label)| label.as_str());
            let tag = truncate(&SafeText::single_line(crate::tui::account_tag(label)), 12);
            println!("{marker} {date}  {tag:<12}  {from:<28}  {subject}");
        } else {
            println!("{marker} {date}  {from:<28}  {subject}");
        }
    }
    Ok(())
}

/// Opens the full-screen interface over every account's cached mail in one
/// merged list. The installation lock is held for the whole session.
///
/// # Errors
///
/// Returns a message when there is no installation, no account, or none of
/// the stores can be opened.
pub fn tui(context: &Context) -> Result<(), String> {
    crate::tui::require_terminal()?;
    let locked = require_installation(context)?;
    let installation = Arc::clone(&locked.installation);
    let accounts = installation.accounts().map_err(|error| error.to_string())?;
    if accounts.is_empty() {
        return Err(NO_ACCOUNTS.to_owned());
    }
    let mut stores = Vec::new();
    let mut unreadable = 0_usize;
    // The first open failure is the one reported when no store opens at all.
    let mut first_failure: Option<String> = None;
    for account in accounts {
        // The first frame does not wait for the integrity scan; the start-up
        // sync's first open runs it. A store that cannot open contributes no
        // rows; the interface starts with a line about it.
        match installation.open_store_for_display(&account) {
            Ok(store) => stores.push((account, store)),
            Err(error) => {
                unreadable += 1;
                first_failure.get_or_insert(error.to_string());
            }
        }
    }
    if stores.is_empty() {
        return Err(first_failure.unwrap_or_else(|| "could not read the local mailbox".to_owned()));
    }
    let source = StoreSource {
        stores,
        executor: executor()?,
    };
    // Network work needs the OAuth client; without it the interface still
    // reads the cache.
    let remote = runtime(context, Arc::clone(&locked.installation))
        .ok()
        .map(|runtime| {
            Box::new(Network {
                runtime,
                accounts: source
                    .stores
                    .iter()
                    .map(|(account, _)| account.clone())
                    .collect(),
            }) as Box<dyn crate::tui::Remote>
        });
    crate::tui::run(unreadable, &source, remote)
}

/// The message when some accounts' syncs fail: how many, and the first
/// failure's reason.
fn sync_failure(failed: usize, total: usize, first: &str) -> String {
    format!("{failed} of {total} accounts failed to sync: {first}")
}

/// Downloads and syncs for the interface, through the identity gate.
struct Network {
    runtime: Runtime,
    accounts: Vec<AccountId>,
}

impl crate::tui::Remote for Network {
    fn fetch<'a>(
        &'a self,
        account: &'a AccountId,
        id: &'a MessageId,
    ) -> crate::tui::Pending<'a, Vec<u8>> {
        Box::pin(async move {
            self.runtime
                .fetch_message(account, id)
                .await
                .map_err(|error| error.to_string())
        })
    }

    fn sync(&self) -> crate::tui::Pending<'_, ()> {
        Box::pin(async move {
            let mut failed = 0_usize;
            let mut first: Option<String> = None;
            for account in &self.accounts {
                if let Err(error) = self.runtime.sync_account(account).await {
                    failed += 1;
                    // The status line already says the sync failed; one
                    // account's short reason stands for the first failure.
                    first.get_or_insert(match error {
                        FlowError::Sync(error) => error.reason().to_owned(),
                        other => other.to_string(),
                    });
                }
            }
            match first {
                Some(first) => Err(sync_failure(failed, self.accounts.len(), &first)),
                None => Ok(()),
            }
        })
    }
}

/// Reads cached mail for the interface from every account's store, one
/// `(account, store)` pair each.
pub(crate) struct StoreSource {
    pub(crate) stores: Vec<(AccountId, SqlCipherMailboxStore)>,
    pub(crate) executor: tokio::runtime::Runtime,
}

impl StoreSource {
    /// Each account's keyset cursor for its next page: where its own last
    /// loaded row sits, found by scanning `loaded` from the end and stopping
    /// once every account is found.
    ///
    /// # Errors
    ///
    /// Returns `Err(())` when a loaded row's time is out of range.
    fn cursors(&self, loaded: &[crate::tui::Row]) -> Result<Vec<Option<EnvelopeCursor>>, ()> {
        let mut cursors: Vec<Option<EnvelopeCursor>> = vec![None; self.stores.len()];
        let mut found = 0_usize;
        for row in loaded.iter().rev() {
            if found == self.stores.len() {
                break;
            }
            let Some(index) = self
                .stores
                .iter()
                .position(|(account, _)| *account == row.account)
            else {
                continue;
            };
            if cursors[index].is_some() {
                continue;
            }
            let at = UnixTimestampMillis::new(row.received_at_millis).map_err(|_error| ())?;
            cursors[index] = Some(EnvelopeCursor::new(at, row.id.clone()));
            found += 1;
        }
        Ok(cursors)
    }

    /// Up to `limit` envelopes past `loaded` per account, read from each
    /// store, then merged into the unified order: received time descending,
    /// then account and message identifier ascending.
    ///
    /// # Errors
    ///
    /// Returns `Err(())` when any account's store cannot be read. The page
    /// fails rather than silently missing one account's rows.
    fn envelope_page(
        &self,
        loaded: &[crate::tui::Row],
        limit: StoreLimit,
    ) -> Result<Vec<(AccountId, MessageEnvelope)>, ()> {
        let cursors = self.cursors(loaded)?;
        let mut merged: Vec<(AccountId, MessageEnvelope)> = Vec::new();
        for ((account, store), cursor) in self.stores.iter().zip(cursors) {
            let envelopes = self
                .executor
                .block_on(store.list_envelopes_after(account, cursor.as_ref(), limit))
                .map_err(|_error| ())?;
            merged.extend(
                envelopes
                    .into_iter()
                    .map(|envelope| (account.clone(), envelope)),
            );
        }
        merged.sort_unstable_by(|(left_account, left), (right_account, right)| {
            right
                .received_at()
                .cmp(&left.received_at())
                .then_with(|| left_account.as_str().cmp(right_account.as_str()))
                .then_with(|| left.message_id().as_str().cmp(right.message_id().as_str()))
        });
        merged.truncate(usize::from(limit.get()));
        Ok(merged)
    }
}

impl crate::tui::MailSource for StoreSource {
    fn page(&self, loaded: &[crate::tui::Row], limit: u16) -> Result<Vec<crate::tui::Row>, ()> {
        let limit = StoreLimit::new(limit).map_err(|_error| ())?;
        Ok(self
            .envelope_page(loaded, limit)?
            .into_iter()
            .map(|(account, envelope)| crate::tui::Row::from_envelope(&envelope, &account))
            .collect())
    }

    fn message(&self, account: &AccountId, id: &MessageId) -> Result<Option<Vec<u8>>, ()> {
        let Some((_, store)) = self.stores.iter().find(|(known, _)| known == account) else {
            return Err(());
        };
        self.executor
            .block_on(store.get_message(account, id))
            .map(|message| message.map(|message| message.content().as_bytes().to_vec()))
            .map_err(|_error| ())
    }

    fn account_labels(&self) -> Vec<(AccountId, SafeText)> {
        self.stores
            .iter()
            .map(|(account, store)| {
                // A failed read falls back to the id, like a store with no
                // address yet.
                let label = store
                    .load_email_address(account)
                    .ok()
                    .flatten()
                    .map_or_else(
                        || SafeText::single_line(account.as_str()),
                        |email| SafeText::single_line(email.as_str()),
                    );
                (account.clone(), label)
            })
            .collect()
    }
}

fn truncate(text: &SafeText, width: usize) -> String {
    let mut characters = text.as_str().chars();
    let head: String = characters.by_ref().take(width).collect();
    if characters.next().is_some() {
        let mut shortened: String = head.chars().take(width.saturating_sub(1)).collect();
        shortened.push('…');
        shortened
    } else {
        head
    }
}

pub fn doctor(context: &Context) {
    let config_file = context.paths.config_file();
    println!("config file:   {}", config_file.display());
    println!(
        "               {}",
        if context.config.file_found {
            "found"
        } else {
            "not found"
        }
    );
    println!("data dir:      {}", context.paths.data_dir.display());
    let client = match (
        &context.config.client_id,
        context.config.has_client_secret(),
    ) {
        (Some(_), true) => "configured (client id and secret)",
        (Some(_), false) => "client id only (Google desktop clients usually need the secret)",
        (None, _) => "missing — see `tersa account add` for setup",
    };
    println!("oauth client:  {client}");
    match open_vault(context) {
        Ok(vault) => {
            let backend = match vault.kind() {
                SlotKind::Keyring => "system keyring",
                SlotKind::File => "passphrase-protected key file",
            };
            let state = match vault.state() {
                Ok(VaultState::Empty) if has_local_data(&context.paths.data_dir) => {
                    "key missing, but encrypted data exists; run `tersa account list` \
                     for recovery steps"
                        .to_owned()
                }
                Ok(VaultState::Empty) => "no key yet".to_owned(),
                Ok(VaultState::Unprotected) => "key present".to_owned(),
                Ok(VaultState::PassphraseProtected) => {
                    "key present, passphrase required".to_owned()
                }
                Err(error) => format!("error: {error}"),
            };
            println!("key storage:   {backend} ({state})");
        }
        Err(error) => println!("key storage:   unavailable ({error})"),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use tersa_application::mailbox::{
        AccountId, HeaderText, MailboxStore, MessageEnvelope, MessageId, ThreadId,
        UnixTimestampMillis,
    };
    use tersa_store_sqlcipher::{DatabaseKey, SqlCipherMailboxStore};
    use tersa_sync_runtime::InstallationLock;
    use tersa_vault::{BackendChoice, VaultState};

    use super::{
        Context, Create, NO_ACCOUNTS, StoreSource, UnlockPlan, account_list, account_remove, inbox,
        plan_unlock, sync, sync_failure,
    };
    use crate::config::{Config, Paths};
    use crate::tui::MailSource as _;

    #[test]
    fn a_key_is_minted_only_on_a_truly_fresh_installation() {
        for state in [
            VaultState::Empty,
            VaultState::Unprotected,
            VaultState::PassphraseProtected,
        ] {
            for data in [false, true] {
                for create in [Create::Allowed, Create::Forbidden] {
                    let expected = match state {
                        VaultState::Empty if data => UnlockPlan::RefuseMissingKey,
                        VaultState::Empty if create == Create::Forbidden => UnlockPlan::NothingYet,
                        VaultState::Empty => UnlockPlan::CreateKey,
                        VaultState::Unprotected => UnlockPlan::Unlock,
                        VaultState::PassphraseProtected => UnlockPlan::UnlockWithPassphrase,
                    };
                    let plan = plan_unlock(state, data, create);
                    assert_eq!(plan, expected);
                    assert_eq!(
                        plan == UnlockPlan::CreateKey,
                        state == VaultState::Empty && !data && create == Create::Allowed
                    );
                }
            }
        }
    }

    #[test]
    fn commands_that_cannot_create_leave_a_missing_data_dir_absent() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("tersa-absent-{}-{nanos}", std::process::id()));
        let data_dir: PathBuf = root.join("data");
        let mut config = Config::load(&root.join("config.toml")).expect("config");
        config.backend = BackendChoice::File;
        let context = Context {
            paths: Paths {
                config_dir: root.clone(),
                data_dir: data_dir.clone(),
            },
            config,
        };

        assert_eq!(account_list(&context), Ok(()));
        let refused = Err(NO_ACCOUNTS.to_owned());
        assert_eq!(account_remove(&context, "acct_"), refused);
        assert_eq!(sync(&context, None), refused);
        assert_eq!(inbox(&context, None, 10), refused);
        assert!(std::fs::symlink_metadata(&root).is_err());
    }

    #[test]
    fn commands_refuse_while_another_process_holds_the_lock() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("tersa-busy-{}-{nanos}", std::process::id()));
        let data_dir = root.join("data");
        let held = InstallationLock::acquire(&data_dir).expect("lock");
        let mut config = Config::load(&root.join("config.toml")).expect("config");
        config.backend = BackendChoice::File;
        let context = Context {
            paths: Paths {
                config_dir: root.clone(),
                data_dir,
            },
            config,
        };

        let busy = Err("another tersa process is using this data directory".to_owned());
        assert_eq!(account_list(&context), busy);
        assert_eq!(account_remove(&context, "acct_"), busy);
        assert_eq!(sync(&context, None), busy);
        assert_eq!(inbox(&context, None, 10), busy);
        drop(held);
        std::fs::remove_dir_all(&root).expect("cleanup");
    }

    fn block_on<F: Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime")
            .block_on(future)
    }

    fn envelope(id: &str, at_millis: i64) -> MessageEnvelope {
        MessageEnvelope::new(
            MessageId::new(id).expect("id"),
            ThreadId::new("t").expect("thread"),
            HeaderText::new("Ann <ann@example.com>").expect("from"),
            HeaderText::new(format!("Subject {id}")).expect("subject"),
            HeaderText::new("the preview").expect("preview"),
            UnixTimestampMillis::new(at_millis).expect("time"),
            true,
        )
    }

    fn seed(account: &AccountId, store: &SqlCipherMailboxStore, envelopes: &[MessageEnvelope]) {
        block_on(store.upsert_envelopes(account, envelopes)).expect("seed");
    }

    /// The rows a merge returned as `account/id` pairs, its unified order.
    fn named(rows: &[crate::tui::Row]) -> Vec<String> {
        rows.iter()
            .map(|row| format!("{}/{}", row.account.as_str(), row.id.as_str()))
            .collect()
    }

    /// Removes its directory when dropped, failed assertions included.
    struct Directory(PathBuf);

    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Fresh stores in a temporary directory, removed when dropped.
    struct Stores {
        _directory: Directory,
        pairs: Vec<(AccountId, SqlCipherMailboxStore)>,
    }

    impl Stores {
        /// One store per named account, in a new temporary directory.
        fn open(names: &[&str]) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos();
            let root =
                std::env::temp_dir().join(format!("tersa-inbox-{}-{nanos}", std::process::id()));
            std::fs::create_dir_all(&root).expect("temp dir");
            let pairs = names
                .iter()
                .map(|name| {
                    let account = AccountId::new(*name).expect("account");
                    let store = SqlCipherMailboxStore::open(
                        account.clone(),
                        root.join(format!("{name}.sqlite3")),
                        DatabaseKey::new([9; 32]),
                    )
                    .expect("store");
                    (account, store)
                })
                .collect();
            Self {
                _directory: Directory(root),
                pairs,
            }
        }

        fn account(&self, name: &str) -> &AccountId {
            &self
                .pairs
                .iter()
                .find(|(account, _)| account.as_str() == name)
                .expect("account")
                .0
        }

        fn store(&self, name: &str) -> &SqlCipherMailboxStore {
            &self
                .pairs
                .iter()
                .find(|(account, _)| account.as_str() == name)
                .expect("store")
                .1
        }
    }

    #[test]
    fn the_merge_interleaves_accounts_and_pages_without_loss() {
        let stores = Stores::open(&["acct_a", "acct_b", "acct_c"]);
        // Timestamps interleave across accounts.
        let seeded = [
            ("acct_a", vec![("a1", 30), ("a2", 10), ("a3", 10)]),
            ("acct_b", vec![("z9", 40), ("b1", 20), ("b2", 10)]),
            ("acct_c", vec![("c1", 30), ("c2", 20)]),
        ];
        for (name, rows) in seeded {
            let envelopes = rows
                .iter()
                .map(|(id, at)| envelope(id, *at))
                .collect::<Vec<_>>();
            seed(stores.account(name), stores.store(name), &envelopes);
        }
        let source = StoreSource {
            stores: stores.pairs,
            executor: tokio::runtime::Builder::new_current_thread()
                .build()
                .expect("runtime"),
        };

        // The newest rows of every account, in the unified order.
        let first = source.page(&[], 4).expect("page");
        assert_eq!(
            named(&first),
            ["acct_b/z9", "acct_a/a1", "acct_c/c1", "acct_b/b1"]
        );

        // Paging through the whole cache returns every row exactly once, in
        // the unified order.
        let mut loaded = first;
        loop {
            let rows = source.page(&loaded, 4).expect("page");
            if rows.is_empty() {
                break;
            }
            loaded.extend(rows);
        }
        assert_eq!(
            named(&loaded),
            [
                "acct_b/z9",
                "acct_a/a1",
                "acct_c/c1",
                "acct_b/b1",
                "acct_c/c2",
                "acct_a/a2",
                "acct_a/a3",
                "acct_b/b2",
            ]
        );
    }

    #[test]
    fn equal_timestamps_take_account_then_message_order() {
        let stores = Stores::open(&["acct_a", "acct_b"]);
        for (name, ids) in [("acct_a", vec!["m1", "m2"]), ("acct_b", vec!["m1"])] {
            let envelopes = ids.iter().map(|id| envelope(id, 100)).collect::<Vec<_>>();
            seed(stores.account(name), stores.store(name), &envelopes);
        }
        let source = StoreSource {
            stores: stores.pairs,
            executor: tokio::runtime::Builder::new_current_thread()
                .build()
                .expect("runtime"),
        };
        let rows = source.page(&[], 10).expect("page");
        assert_eq!(named(&rows), ["acct_a/m1", "acct_a/m2", "acct_b/m1"]);
    }

    #[test]
    fn an_account_without_rows_contributes_none() {
        let stores = Stores::open(&["acct_empty", "acct_full"]);
        let envelopes = [("f1", 10), ("f2", 5)]
            .iter()
            .map(|(id, at)| envelope(id, *at))
            .collect::<Vec<_>>();
        seed(
            stores.account("acct_full"),
            stores.store("acct_full"),
            &envelopes,
        );
        let source = StoreSource {
            stores: stores.pairs,
            executor: tokio::runtime::Builder::new_current_thread()
                .build()
                .expect("runtime"),
        };
        let rows = source.page(&[], 10).expect("page");
        assert_eq!(named(&rows), ["acct_full/f1", "acct_full/f2"]);
        let rows = source.page(&rows, 10).expect("page");
        assert!(rows.is_empty(), "paging past the end stops");
    }

    #[test]
    fn a_failed_read_fails_the_page() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("tersa-inbox-fail-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&root).expect("temp dir");
        let directory = Directory(root);
        let account_a = AccountId::new("acct_a").expect("account");
        let account_b = AccountId::new("acct_b").expect("account");
        let store_b = SqlCipherMailboxStore::open(
            account_b.clone(),
            directory.0.join("b.sqlite3"),
            DatabaseKey::new([9; 32]),
        )
        .expect("store");
        seed(&account_b, &store_b, &[envelope("m1", 10)]);
        // The store is bound to acct_b but listed under acct_a, so its own
        // account guard refuses every read. That stands in for any local
        // read failure: the page fails instead of silently missing rows.
        let source = StoreSource {
            stores: vec![(account_a, store_b)],
            executor: tokio::runtime::Builder::new_current_thread()
                .build()
                .expect("runtime"),
        };
        assert!(source.page(&[], 10).is_err());
    }

    #[test]
    fn the_sync_failure_names_the_count_and_the_first_reason() {
        assert_eq!(
            sync_failure(2, 5, "offline"),
            "2 of 5 accounts failed to sync: offline"
        );
        assert_eq!(
            sync_failure(1, 1, "no network"),
            "1 of 1 accounts failed to sync: no network"
        );
    }
}
