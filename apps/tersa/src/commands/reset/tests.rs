// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::fs;
use std::io::{Cursor, Error, ErrorKind};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use tersa_application::mailbox::{
    HeaderText, MailboxStore, MessageEnvelope, MessageId, ThreadId, UnixTimestampMillis,
};
use tersa_keys::{InstallationKeyPurpose, derive_installation_key, registry_dedup_tag};
use tersa_store_sqlcipher::registry::SqlCipherRegistry;
use zeroize::Zeroizing;

use super::*;
use crate::config::{Config, Paths};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "tersa-reset-cli-unit-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .expect("fixture directory");
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn root() -> RootKey {
    RootKey::from_bytes(Zeroizing::new([7; 32]))
}
struct Fixture {
    context: Context,
    accounts: [AccountId; 2],
    stores: [PathBuf; 2],
    _directory: Directory,
}
impl Fixture {
    fn new() -> Self {
        let directory = Directory::new();
        let context = Context {
            paths: Paths {
                config_dir: directory.0.join("config"),
                data_dir: directory.0.join("data"),
            },
            config: Config::for_test(Some("synthetic-client")),
        };
        drop(Installation::open(&context.paths.data_dir, root()).expect("bootstrap fixture"));
        let accounts = [
            "acct_00000000000000000000000000000001",
            "acct_00000000000000000000000000000002",
        ]
        .map(|id| AccountId::new(id).expect("ID"));
        let key = derive_installation_key(&root(), InstallationKeyPurpose::RegistryDatabaseV1)
            .expect("fixture key")
            .into_bytes();
        let registry =
            SqlCipherRegistry::open(&context.paths.data_dir.join("registry.sqlite3"), &key)
                .expect("fixture registry");
        for (index, account) in accounts.iter().enumerate() {
            registry
                .register(
                    account,
                    &registry_dedup_tag(&root(), format!("synthetic-subject-{index}").as_bytes())
                        .expect("tag"),
                )
                .expect("registration");
        }
        drop(registry);
        let installation =
            Installation::open(&context.paths.data_dir, root()).expect("fixture installation");
        let mut stores = Vec::new();
        for (index, account) in accounts.iter().enumerate() {
            let account_dirs = context.paths.data_dir.join("accounts");
            let before: Vec<_> = fs::read_dir(&account_dirs)
                .expect("fixture directories")
                .map(|entry| entry.expect("entry").path())
                .collect();
            let store = installation.open_store(account).expect("fixture account");
            let created = fs::read_dir(account_dirs)
                .expect("fixture directories")
                .map(|entry| entry.expect("entry").path())
                .find(|path| !before.contains(path))
                .expect("new fixture account directory");
            stores.push(created.join("mail.sqlite3"));
            store
                .store_broker_subject(account, &format!("synthetic-subject-{index}"))
                .expect("subject");
            store
                .store_refresh_token(account, "synthetic-private-token")
                .expect("token");
            store
                .store_email_address(
                    account,
                    &AccountEmail::new(format!("person{index}@example.test")).expect("email"),
                )
                .expect("email");
            let envelope = MessageEnvelope::new(
                MessageId::new("cached").expect("message"),
                ThreadId::new("thread").expect("thread"),
                HeaderText::new("Sender").expect("sender"),
                HeaderText::new("Subject").expect("subject"),
                HeaderText::new("Preview").expect("preview"),
                UnixTimestampMillis::new(10).expect("time"),
                false,
            );
            executor()
                .expect("executor")
                .block_on(store.upsert_envelopes(account, &[envelope]))
                .expect("cached row");
        }
        drop(installation);
        Self {
            context,
            accounts,
            stores: stores.try_into().expect("two fixture stores"),
            _directory: directory,
        }
    }
    fn open(&self) -> Locked {
        open_preview_using(&self.context, |_| Ok(root())).expect("existing preview")
    }
    fn store_path(&self, account: &AccountId) -> PathBuf {
        self.stores[self
            .accounts
            .iter()
            .position(|id| id == account)
            .expect("fixture account")]
        .clone()
    }
}
fn durable_files(path: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut out = BTreeMap::new();
    for entry in fs::read_dir(path).expect("fixture directory") {
        let path = entry.expect("entry").path();
        if path.is_dir() {
            out.extend(durable_files(&path));
        } else if path.file_name().expect("name") != ".lock"
            && !path.to_string_lossy().ends_with("-shm")
        {
            out.insert(path.clone(), fs::read(path).expect("fixture bytes"));
        }
    }
    out
}
fn invoke(
    fixture: &Fixture,
    raw: &str,
    yes: bool,
    interactive: bool,
    answer: &[u8],
    run: impl FnOnce(Arc<Installation>, OAuthClient, &AccountId) -> Result<Completion, String>,
) -> (Result<(), String>, String) {
    let mut output = Vec::new();
    let result = reset_using(
        &fixture.context,
        raw,
        yes,
        interactive,
        &mut Cursor::new(answer),
        &mut output,
        |_| Ok(fixture.open()),
        run,
    );
    (result, String::from_utf8(output).expect("output"))
}

#[test]
fn confirmation_accepts_only_a_complete_bounded_yes_line() {
    for answer in [b"yes\n".as_slice(), b" YES \r\n", b"\tYeS\n"] {
        assert!(read_confirmation(&mut Cursor::new(answer)).expect("read"));
    }
    for answer in [
        b"".as_slice(),
        b"yes",
        b"no\n",
        b"\n",
        b"y\n",
        b"yes please\n",
        b"yEs!\n",
        b"\xffyes\n",
        "ｙｅｓ\n".as_bytes(),
    ] {
        assert!(!read_confirmation(&mut Cursor::new(answer)).expect("read"));
    }
    let oversized = format!("{}yes\n", " ".repeat(256));
    assert!(!read_confirmation(&mut Cursor::new(oversized)).expect("bounded read"));
}

#[test]
fn empty_and_non_tty_requests_stop_before_opening_or_resetting() {
    let fixture = Fixture::new();
    for (raw, yes, interactive) in [
        ("", true, false),
        (" \t\n", true, true),
        ("acct", false, false),
    ] {
        assert!(
            reset_using(
                &fixture.context,
                raw,
                yes,
                interactive,
                &mut Cursor::new(b"yes\n"),
                &mut Vec::new(),
                |_| panic!("must not open"),
                |_, _, _| panic!("must not reset")
            )
            .is_err()
        );
    }
    let mut context = fixture.context;
    context.config = Config::for_test(None);
    assert!(
        reset_using(
            &context,
            "acct",
            true,
            false,
            &mut Cursor::new(b""),
            &mut Vec::new(),
            |_| panic!("missing config must not open"),
            |_, _, _| panic!("must not reset")
        )
        .is_err()
    );
}

#[test]
fn refusal_answers_never_invoke_reset_or_change_encrypted_data() {
    let fixture = Fixture::new();
    let before = durable_files(&fixture.context.paths.data_dir);
    let oversized = format!("{}yes\n", " ".repeat(256));
    for answer in [b"".as_slice(), b"yes", b"no\n", b"\n", oversized.as_bytes()] {
        let (result, output) = invoke(
            &fixture,
            fixture.accounts[0].as_str(),
            false,
            true,
            answer,
            |_, _, _| panic!("not confirmed"),
        );
        assert!(result.is_ok());
        assert!(output.contains("cancelled"));
        assert!(output.contains("person0@example.test"));
        assert!(output.contains(fixture.accounts[0].as_str()));
        assert!(output.contains("normal bounded limit"));
        assert_eq!(durable_files(&fixture.context.paths.data_dir), before);
    }
}

#[test]
fn confirmed_requests_keep_the_same_arc_and_lock_and_dispatch_exactly_once() {
    let fixture = Fixture::new();
    for (yes, interactive, answer) in [
        (false, true, b" Yes \r\n".as_slice()),
        (true, false, b"".as_slice()),
    ] {
        let preview = RefCell::new(None::<Arc<Installation>>);
        let calls = Cell::new(0);
        let mut output = Vec::new();
        let result = reset_using(
            &fixture.context,
            fixture.accounts[1].as_str(),
            yes,
            interactive,
            &mut Cursor::new(answer),
            &mut output,
            |_| {
                let locked = fixture.open();
                *preview.borrow_mut() = Some(Arc::clone(&locked.installation));
                Ok(locked)
            },
            |installation, client, account| {
                assert!(Arc::ptr_eq(
                    &installation,
                    preview.borrow().as_ref().expect("preview")
                ));
                assert_eq!(account, &fixture.accounts[1]);
                assert_eq!(client.client_id, "synthetic-client");
                assert!(
                    InstallationLock::acquire_existing(&fixture.context.paths.data_dir).is_err()
                );
                calls.set(calls.get() + 1);
                Ok(Completion::Resynced {
                    messages: 100,
                    bodies: 25,
                })
            },
        );
        assert!(result.is_ok());
        assert_eq!(calls.get(), 1);
        let output = String::from_utf8(output).expect("text");
        assert!(output.contains("Recent-mail sync completed: 100 messages, 25 bodies cached"));
        assert!(!output.contains("synthetic-private-token"));
        assert!(!output.contains("synthetic-subject"));
        InstallationLock::acquire_existing(&fixture.context.paths.data_dir)
            .expect("released after command");
    }
}

#[test]
fn exact_prefix_and_case_insensitive_address_resolution_fail_closed() {
    let fixture = Fixture::new();
    let preview = fixture.open();
    assert_eq!(
        resolve_existing(&preview.installation, fixture.accounts[0].as_str()).expect("exact"),
        fixture.accounts[0]
    );
    assert_eq!(
        resolve_existing(&preview.installation, "PERSON1@example.test").expect("address"),
        fixture.accounts[1]
    );
    for raw in ["", " ", "acct_", "unknown", "absent@example.test"] {
        assert!(
            resolve_existing(&preview.installation, raw).is_err(),
            "{raw}"
        );
    }
    let accounts = [
        AccountId::new("acct_a").expect("id"),
        AccountId::new("acct_ab").expect("id"),
    ];
    assert_eq!(
        resolve_with(&accounts, "acct_a", |_| panic!("ID must not read stores"))
            .expect("exact wins"),
        accounts[0]
    );
    assert_eq!(
        resolve_with(&accounts, "acct_ab", |_| panic!("ID must not read stores")).expect("ID"),
        accounts[1]
    );
    let single = [AccountId::new("acct_only").expect("id")];
    assert_eq!(
        resolve_with(&single, "acct_o", |_| panic!("prefix must not read stores")).expect("prefix"),
        single[0]
    );
    assert!(
        resolve_with(&accounts, "same@example.test", |_| Ok(Some(
            AccountEmail::new("same@example.test").expect("email")
        )))
        .is_err()
    );
    assert!(
        resolve_with(&accounts, "same@example.test", |account| {
            if account == &accounts[0] {
                Ok(Some(AccountEmail::new("same@example.test").expect("email")))
            } else {
                Err("unreadable peer".to_owned())
            }
        })
        .is_err()
    );
    assert!(resolve_with(&accounts, "same@example.test", |_| Ok(None)).is_err());
}

#[test]
fn unknown_ambiguous_and_unreadable_targets_never_dispatch_even_with_yes() {
    let fixture = Fixture::new();
    for raw in ["unknown", "acct_", "unknown@example.test"] {
        assert!(
            invoke(&fixture, raw, true, false, b"", |_, _, _| panic!(
                "no fallback"
            ))
            .0
            .is_err()
        );
    }
    let path = fixture.store_path(&fixture.accounts[1]);
    fs::remove_file(&path).expect("missing peer fixture");
    let before = durable_files(&fixture.context.paths.data_dir);
    for raw in [fixture.accounts[1].as_str(), "person0@example.test"] {
        assert!(
            invoke(&fixture, raw, true, false, b"", |_, _, _| panic!(
                "unreadable peer must not be skipped"
            ))
            .0
            .is_err()
        );
    }
    assert_eq!(durable_files(&fixture.context.paths.data_dir), before);
    assert!(!path.exists());
}

#[test]
fn existing_preview_never_bootstraps_missing_insecure_or_unclaimed_state() {
    let directory = Directory::new();
    let context = Context {
        paths: Paths {
            config_dir: directory.0.join("config"),
            data_dir: directory.0.join("absent"),
        },
        config: Config::for_test(Some("synthetic")),
    };
    assert!(open_preview_using(&context, |_| panic!("missing directory must not unlock")).is_err());
    assert!(!context.paths.data_dir.exists());
    fs::create_dir(&context.paths.data_dir).expect("directory");
    fs::set_permissions(&context.paths.data_dir, fs::Permissions::from_mode(0o755)).expect("mode");
    assert!(open_preview_using(&context, |_| panic!("unsafe directory must not unlock")).is_err());
    assert_eq!(
        fs::metadata(&context.paths.data_dir)
            .expect("mode")
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
    fs::set_permissions(&context.paths.data_dir, fs::Permissions::from_mode(0o700))
        .expect("fixture mode");
    assert!(open_preview_using(&context, |_| Ok(root())).is_err());
    assert!(!context.paths.data_dir.join("accounts").exists());
    fs::DirBuilder::new()
        .mode(0o700)
        .create(context.paths.data_dir.join("accounts"))
        .expect("accounts directory");
    for bytes in [Vec::new(), vec![0; 8192]] {
        let registry = context.paths.data_dir.join("registry.sqlite3");
        fs::write(&registry, &bytes).expect("unclaimed registry");
        fs::set_permissions(&registry, fs::Permissions::from_mode(0o600)).expect("mode");
        assert!(open_preview_using(&context, |_| Ok(root())).is_err());
        assert_eq!(fs::read(registry).expect("unchanged"), bytes);
    }
    assert!(!context.paths.data_dir.join("root-key.wrapped").exists());
    fs::remove_file(context.paths.data_dir.join(".lock")).expect("remove coordination fixture");
    symlink("registry.sqlite3", context.paths.data_dir.join(".lock")).expect("unsafe lock");
    assert!(open_preview_using(&context, |_| panic!("unsafe lock must not unlock")).is_err());
}

struct BrokenInput;
impl Read for BrokenInput {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(Error::from(ErrorKind::Other))
    }
}
impl BufRead for BrokenInput {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        Err(Error::from(ErrorKind::Other))
    }
    fn consume(&mut self, _: usize) {}
}
#[test]
fn input_failure_does_not_reset_and_yes_does_not_read_confirmation() {
    let fixture = Fixture::new();
    assert!(
        reset_using(
            &fixture.context,
            fixture.accounts[0].as_str(),
            false,
            true,
            &mut BrokenInput,
            &mut Vec::new(),
            |_| Ok(fixture.open()),
            |_, _, _| panic!("read failed")
        )
        .is_err()
    );
    assert!(
        reset_using(
            &fixture.context,
            fixture.accounts[0].as_str(),
            true,
            false,
            &mut BrokenInput,
            &mut Vec::new(),
            |_| Ok(fixture.open()),
            |_, _, _| Ok(Completion::Resynced {
                messages: 0,
                bodies: 0
            })
        )
        .is_ok()
    );
}

#[test]
fn production_runtime_preclear_refusal_leaves_the_real_cache_intact() {
    let fixture = Fixture::new();
    // Identity was deliberately not recorded: the real reset must reject
    // before any sync/provider call. Only the root unlock is substituted.
    let before = durable_files(&fixture.context.paths.data_dir);
    let (result, _) = invoke(
        &fixture,
        fixture.accounts[0].as_str(),
        true,
        false,
        b"",
        execute_reset,
    );
    let error = result.expect_err("missing current identity");
    assert!(error.contains("refused before clearing"));
    assert_eq!(durable_files(&fixture.context.paths.data_dir), before);
}

#[test]
fn all_three_phase_messages_and_hostile_text_are_truthful_and_terminal_safe() {
    let account = AccountId::new("acct_safe").expect("id");
    let mut output = Vec::new();
    let error = finish(
        &mut output,
        &account,
        Err("hostile\x1b[2J\u{202e}failure".to_owned()),
    )
    .expect_err("preclear nonzero");
    assert!(error.contains("refused before clearing"));
    assert!(!error.contains('\x1b') && !error.contains('\u{202e}'));
    assert!(output.is_empty());
    let error = finish(
        &mut output,
        &account,
        Ok(Completion::ResyncFailed(SafeText::single_line(
            "revoked\x1b]52;x\x07\u{202e}",
        ))),
    )
    .expect_err("postclear nonzero");
    assert!(error.contains("cache clear committed"));
    assert!(error.contains("Partial new cache"));
    assert!(error.contains("remains registered"));
    assert!(error.contains("tersa sync acct_safe"));
    assert!(error.contains("tersa account add"));
    assert!(!error.contains('\x1b') && !error.contains('\u{202e}'));
    assert!(!error.contains("grant remains"));
    let hostile_email = AccountEmail::new("hostile\u{202e}@example.test").expect("provider label");
    write_confirmation(&mut output, &account, Some(&hostile_email)).expect("safe prompt");
    assert!(
        !String::from_utf8(output)
            .expect("text")
            .contains('\u{202e}')
    );
}

struct BrokenOutput;
impl Write for BrokenOutput {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(Error::from(ErrorKind::BrokenPipe))
    }
    fn flush(&mut self) -> io::Result<()> {
        Err(Error::from(ErrorKind::BrokenPipe))
    }
}
#[test]
fn failed_confirmation_output_never_dispatches_and_result_output_keeps_its_phase() {
    let fixture = Fixture::new();
    assert!(
        reset_using(
            &fixture.context,
            fixture.accounts[0].as_str(),
            false,
            true,
            &mut Cursor::new(b"yes\n"),
            &mut BrokenOutput,
            |_| Ok(fixture.open()),
            |_, _, _| panic!("prompt was not displayed")
        )
        .is_err()
    );
    let error = finish(
        &mut BrokenOutput,
        &fixture.accounts[0],
        Ok(Completion::Resynced {
            messages: 1,
            bodies: 1,
        }),
    )
    .expect_err("output failed after completion");
    assert!(error.contains("clear and sync completed"));
    assert!(!error.contains("refused before clearing"));
}

#[test]
fn real_encrypted_duplicate_addresses_cannot_select_a_fallback_account() {
    let fixture = Fixture::new();
    let setup =
        Installation::open(&fixture.context.paths.data_dir, root()).expect("fixture update");
    setup
        .open_store(&fixture.accounts[1])
        .expect("second account")
        .store_email_address(
            &fixture.accounts[1],
            &AccountEmail::new("person0@example.test").expect("duplicate address"),
        )
        .expect("fixture duplicate");
    drop(setup);
    let before = durable_files(&fixture.context.paths.data_dir);
    let error = invoke(
        &fixture,
        "person0@example.test",
        true,
        false,
        b"",
        |_, _, _| panic!("duplicate is not a selection"),
    )
    .0
    .expect_err("ambiguous");
    assert!(error.contains("matches more than one account"));
    assert_eq!(durable_files(&fixture.context.paths.data_dir), before);
}
