// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Command implementations.

use std::process::{Command as Process, Stdio};
use std::sync::Arc;

use tersa_application::mailbox::{AccountId, MailboxReader, MessageId, StoreLimit};
use tersa_application::sync::SyncReport;
use tersa_keys::RootKey;
use tersa_presentation::terminal::SafeText;
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
    let mut matches = accounts
        .into_iter()
        .filter(|account| account.as_str() == raw || account.as_str().starts_with(raw));
    match (matches.next(), matches.next()) {
        (Some(account), None) => Ok(account),
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
        println!("{}", account.as_str());
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

pub fn inbox(context: &Context, raw: Option<&str>, limit: u16) -> Result<(), String> {
    let locked = require_installation(context)?;
    let installation = Arc::clone(&locked.installation);
    let account = match raw {
        Some(raw) => resolve_account(&installation, raw)?,
        None => installation
            .accounts()
            .map_err(|error| error.to_string())?
            .into_iter()
            .next()
            .ok_or_else(|| NO_ACCOUNTS.to_owned())?,
    };
    let store = installation
        .open_store(&account)
        .map_err(|error| error.to_string())?;
    let limit = StoreLimit::new(limit).map_err(|_error| "invalid limit".to_owned())?;
    let envelopes = executor()?
        .block_on(store.list_envelopes(&account, limit))
        .map_err(|_error| "could not read the local mailbox".to_owned())?;
    if envelopes.is_empty() {
        println!("No cached mail. Run `tersa sync`.");
    }
    for envelope in envelopes {
        let marker = if envelope.is_unread() { '*' } else { ' ' };
        println!(
            "{marker} {}  {:<28}  {}",
            crate::dates::format_local(envelope.received_at().as_millis()),
            truncate(&SafeText::single_line(envelope.from().as_str()), 28),
            SafeText::single_line(envelope.subject().as_str()),
        );
    }
    Ok(())
}

/// The most messages the interface loads; paging arrives with T2d.
const TUI_MESSAGES: u16 = 500;

/// Opens the full-screen interface on the first account's cached mail. The
/// installation lock is held for the whole session.
pub fn tui(context: &Context) -> Result<(), String> {
    crate::tui::require_terminal()?;
    let locked = require_installation(context)?;
    let account = locked
        .installation
        .accounts()
        .map_err(|error| error.to_string())?
        .into_iter()
        .next()
        .ok_or_else(|| NO_ACCOUNTS.to_owned())?;
    // The first frame does not wait for the integrity scan; the start-up
    // sync's first open runs it.
    let store = locked
        .installation
        .open_store_for_display(&account)
        .map_err(|error| error.to_string())?;
    let source = StoreSource {
        store,
        account: account.clone(),
        executor: executor()?,
        limit: StoreLimit::new(TUI_MESSAGES).map_err(|_error| "invalid limit".to_owned())?,
    };
    // Network work needs the OAuth client; without it the interface still
    // reads the cache.
    let remote = runtime(context, Arc::clone(&locked.installation))
        .ok()
        .map(|runtime| {
            Box::new(Network {
                runtime,
                account: account.clone(),
            }) as Box<dyn crate::tui::Remote>
        });
    crate::tui::run(SafeText::single_line(account.as_str()), &source, remote)
}

/// Downloads and syncs for the interface, through the identity gate.
struct Network {
    runtime: Runtime,
    account: AccountId,
}

impl crate::tui::Remote for Network {
    fn fetch<'a>(&'a self, id: &'a MessageId) -> crate::tui::Pending<'a, Vec<u8>> {
        Box::pin(async move {
            self.runtime
                .fetch_message(&self.account, id)
                .await
                .map_err(|error| error.to_string())
        })
    }

    fn sync(&self) -> crate::tui::Pending<'_, ()> {
        Box::pin(async move {
            self.runtime
                .sync_account(&self.account)
                .await
                .map(|_report| ())
                // The status line already says the sync failed.
                .map_err(|error| match error {
                    FlowError::Sync(error) => error.reason().to_owned(),
                    other => other.to_string(),
                })
        })
    }
}

/// Reads cached mail for the interface from one account's store.
struct StoreSource<S> {
    store: S,
    account: AccountId,
    executor: tokio::runtime::Runtime,
    limit: StoreLimit,
}

impl<S: MailboxReader> crate::tui::MailSource for StoreSource<S> {
    fn rows(&self) -> Result<Vec<crate::tui::Row>, ()> {
        self.executor
            .block_on(self.store.list_envelopes(&self.account, self.limit))
            .map(|envelopes| {
                envelopes
                    .iter()
                    .map(crate::tui::Row::from_envelope)
                    .collect()
            })
            .map_err(|_error| ())
    }

    fn message(&self, id: &MessageId) -> Result<Option<Vec<u8>>, ()> {
        self.executor
            .block_on(self.store.get_message(&self.account, id))
            .map(|message| message.map(|message| message.content().as_bytes().to_vec()))
            .map_err(|_error| ())
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

    use tersa_sync_runtime::InstallationLock;
    use tersa_vault::{BackendChoice, VaultState};

    use super::{
        Context, Create, NO_ACCOUNTS, UnlockPlan, account_list, account_remove, inbox, plan_unlock,
        sync,
    };
    use crate::config::{Config, Paths};

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
}
