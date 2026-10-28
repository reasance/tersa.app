// This Source Code Form is subject to the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Exclusive cache maintenance: commit and close, then normal same-account sync.

use core::fmt;

use tersa_application::mailbox::AccountId;
use tersa_application::sync::SyncReport;
use tersa_store_sqlcipher::CacheResetError;

use crate::{FlowError, Runtime};

/// A reset refused before the clear committed; the old cache remains intact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CacheResetPreconditionError {
    /// The exact opaque account is not registered; no fallback is attempted.
    UnknownAccount,
    /// The existing installation, private directory, registry or key is unusable.
    Installation,
    /// Existing-only open or transactional eligibility/clear failed.
    Store(CacheResetError),
}

impl fmt::Display for CacheResetPreconditionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownAccount => formatter.write_str("the requested account is not registered"),
            Self::Installation => {
                formatter.write_str("the installation cannot prepare a cache reset")
            }
            Self::Store(error) => write!(formatter, "{error}"),
        }
    }
}
impl std::error::Error for CacheResetPreconditionError {}

/// Both variants mean the cache clear committed; neither restores old mail.
#[must_use = "inspect whether resync succeeded after the committed clear"]
pub enum CacheResetOutcome {
    /// The normal bounded sync finished, possibly repopulating recent mail.
    Resynced(SyncReport),
    /// Clear committed, but sync failed; partial NEW cache data may exist.
    ResyncFailed(FlowError),
}

impl fmt::Debug for CacheResetOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Resynced(_) => "CacheResetOutcome::Resynced([REDACTED])",
            Self::ResyncFailed(_) => "CacheResetOutcome::ResyncFailed([REDACTED])",
        })
    }
}

// The sole test seam is the sync delegate. Production always supplies the
// unchanged sync_account; real installation/open/clear/drop work is shared.
pub(crate) async fn reset_cache_using<'a, F, Fut>(
    runtime: &'a mut Runtime,
    account: &'a AccountId,
    sync: F,
) -> Result<CacheResetOutcome, CacheResetPreconditionError>
where
    F: FnOnce(&'a Runtime, &'a AccountId) -> Fut,
    Fut: Future<Output = Result<SyncReport, FlowError>>,
{
    runtime.installation().clear_cache_for_reset(account)?;
    Ok(match sync(runtime, account).await {
        Ok(report) => CacheResetOutcome::Resynced(report),
        Err(error) => CacheResetOutcome::ResyncFailed(error),
    })
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::{Path, PathBuf};
    use std::pin::pin;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll, Waker};

    use tersa_application::identity::{
        AccountIdentityHasher, AccountIdentityStore, AccountProfile, IdentityHash,
        IdentityReconcile, normalize_subject,
    };
    use tersa_application::lifecycle::{
        AccountLifecycleMetadata, AccountLifecycleStore, DisconnectRecoveryState,
    };
    use tersa_application::mailbox::{
        AccountEmail, BoxFuture, HeaderText, MailboxReader, MailboxStore, Message, MessageContent,
        MessageEnvelope, MessageId, Page, PageSize, PageToken, RemoteMailbox, RemoteMailboxError,
        StoreLimit, ThreadId, UnixTimestampMillis,
    };
    use tersa_application::token::AccountSubject;
    use tersa_keys::{AccountKeyPurpose, RootKey, derive_account_key};
    use tersa_store_sqlcipher::{DatabaseKey, SqlCipherMailboxStore};
    use tersa_token_broker_core::{BrokerError, RefreshTokenStore, ValidatedSubject};
    use zeroize::Zeroizing;

    use super::*;
    use crate::{
        Installation, InstallationHasher, InstallationLock, InstallationTokens, OAuthClient,
        default_sync_policy, gated_sync,
    };

    struct Directory(PathBuf);
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    struct Fixture {
        runtime: Runtime,
        accounts: [AccountId; 2],
        _lock: InstallationLock,
        _directory: Directory,
    }
    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let directory = Directory(std::env::temp_dir().join(format!(
                "tersa-reset-runtime-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            )));
            let lock = InstallationLock::acquire(&directory.0).expect("lock");
            let installation = Arc::new(
                Installation::open(&directory.0, RootKey::from_bytes(Zeroizing::new([7; 32])))
                    .expect("installation"),
            );
            let tokens = InstallationTokens(Arc::clone(&installation));
            let accounts = ["private-sub-a", "private-sub-b"].map(|name| {
                tokens
                    .store(
                        &subject(name),
                        &Zeroizing::new(format!("private-token-{name}")),
                    )
                    .expect("fixture registration");
                let account = installation
                    .account_for_subject(name)
                    .expect("lookup")
                    .expect("registered");
                let store = installation.open_store(&account).expect("fixture store");
                let hash = InstallationHasher(Arc::clone(&installation))
                    .hash(&account, &normalize_subject(&profile_subject(name)))
                    .expect("hash");
                drive(store.reconcile_identity(
                    &account,
                    &hash,
                    IdentityReconcile::RecordOnly,
                    None,
                ))
                .expect("identity");
                store
                    .store_email_address(
                        &account,
                        &AccountEmail::new(format!("{name}@example.test")).expect("email"),
                    )
                    .expect("email stored");
                drive(store.put_message(&account, &message("old-body", 20))).expect("body");
                drive(store.upsert_envelopes(&account, &[envelope("old-envelope", 10)]))
                    .expect("envelope");
                drive(store.record_successful_sync(&account, 12345)).expect("freshness");
                account
            });
            let runtime = Runtime::new(
                installation,
                OAuthClient {
                    client_id: "test-client".to_owned(),
                    client_secret: None,
                },
            )
            .expect("configured runtime, no network");
            Self {
                runtime,
                accounts,
                _lock: lock,
                _directory: directory,
            }
        }
    }
    fn replace_fixture_store(
        installation: &Installation,
        account: &AccountId,
        wrong_key: bool,
    ) -> SqlCipherMailboxStore {
        let path = installation.cache_path_for_test(account);
        for suffix in ["", "-wal", "-shm"] {
            let _ = fs::remove_file(PathBuf::from(format!("{}{suffix}", path.display())));
        }
        let key = if wrong_key {
            DatabaseKey::new([99; 32])
        } else {
            let key = derive_account_key(
                &RootKey::from_bytes(Zeroizing::new([7; 32])),
                account,
                AccountKeyPurpose::SqlCipherDatabaseV1,
            )
            .expect("fixture key");
            DatabaseKey::from_zeroizing(key.into_bytes())
        };
        let store = SqlCipherMailboxStore::open(account.clone(), path, key)
            .expect("replacement fixture store");
        let hash = tersa_keys::account_identity_hash(
            &RootKey::from_bytes(Zeroizing::new([7; 32])),
            account,
            b"private-sub-a",
        )
        .expect("fixture identity");
        let hash = IdentityHash::from_bytes(hash);
        drive(store.reconcile_identity(account, &hash, IdentityReconcile::RecordOnly, None))
            .expect("identity");
        store
            .store_refresh_token(account, "private-fixture-token")
            .expect("token");
        store
            .store_email_address(
                account,
                &AccountEmail::new("fixture@example.test").expect("email"),
            )
            .expect("email stored");
        drive(store.record_successful_sync(account, 12345)).expect("freshness");
        drive(store.put_message(account, &message("old-body", 20))).expect("body");
        store
    }

    fn subject(value: &str) -> ValidatedSubject {
        ValidatedSubject::new(value).expect("subject")
    }
    fn profile_subject(value: &str) -> AccountSubject {
        AccountSubject::from_raw_for_test(Zeroizing::new(value.to_owned()))
    }
    fn envelope(id: &str, at: i64) -> MessageEnvelope {
        MessageEnvelope::new(
            MessageId::new(id).expect("id"),
            ThreadId::new("thread").expect("thread"),
            HeaderText::new("Sender").expect("sender"),
            HeaderText::new("Subject").expect("subject"),
            HeaderText::new("Preview").expect("preview"),
            UnixTimestampMillis::new(at).expect("timestamp"),
            false,
        )
    }
    fn message(id: &str, at: i64) -> Message {
        Message::new(
            envelope(id, at),
            MessageContent::new(b"Subject: fixture\r\n\r\nfixture body".to_vec()).expect("body"),
        )
    }
    fn drive<T>(future: impl Future<Output = T>) -> T {
        let mut future = pin!(future);
        match future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("local fixture must finish synchronously"),
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    struct Protected {
        identity: Option<IdentityHash>,
        subject: Option<String>,
        token: Option<String>,
        email: Option<AccountEmail>,
        recovery: Option<DisconnectRecoveryState>,
    }
    #[derive(Debug, Eq, PartialEq)]
    struct Snapshot {
        protected: Protected,
        lifecycle: AccountLifecycleMetadata,
        envelopes: Vec<MessageEnvelope>,
        bodies: Vec<Option<Vec<u8>>>,
    }
    fn snapshot(installation: &Installation, account: &AccountId) -> Snapshot {
        let store = installation
            .open_store(account)
            .expect("existing fixture store");
        let lifecycle = drive(store.lifecycle_metadata(account)).expect("lifecycle");
        let envelopes =
            drive(store.list_envelopes(account, StoreLimit::new(10_000).expect("limit")))
                .expect("envelopes");
        let bodies = envelopes
            .iter()
            .map(|row| {
                drive(store.get_message(account, row.message_id()))
                    .expect("body read")
                    .map(|body| body.content().as_bytes().to_vec())
            })
            .collect();
        Snapshot {
            protected: Protected {
                identity: drive(store.load_identity(account)).expect("identity"),
                subject: store
                    .load_broker_subject(account)
                    .expect("subject")
                    .map(|value| value.to_string()),
                token: store
                    .load_refresh_token(account)
                    .expect("token")
                    .map(|value| value.to_string()),
                email: store.load_email_address(account).expect("email"),
                recovery: lifecycle.recovery(),
            },
            lifecycle,
            envelopes,
            bodies,
        }
    }
    fn files(path: &Path) -> Vec<(PathBuf, Vec<u8>)> {
        let mut entries: Vec<_> = fs::read_dir(path)
            .expect("fixture directory")
            .map(|entry| entry.expect("entry").path())
            .filter(|path| path.is_file())
            .map(|path| {
                let bytes = fs::read(&path).expect("fixture file");
                (path, bytes)
            })
            .collect();
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        entries
    }

    struct LocalSession {
        account: AccountId,
        subject: AccountSubject,
        reads: Arc<Mutex<Vec<(AccountId, u16)>>>,
        bodies: Arc<Mutex<Vec<(AccountId, MessageId)>>>,
        fail_body: bool,
    }
    impl AccountProfile for LocalSession {
        fn subject(&self) -> &AccountSubject {
            &self.subject
        }
    }
    impl RemoteMailbox for LocalSession {
        fn list_recent_envelopes<'a>(
            &'a self,
            account: &'a AccountId,
            size: PageSize,
            after: Option<&'a PageToken>,
        ) -> BoxFuture<'a, Result<Page<MessageEnvelope>, RemoteMailboxError>> {
            Box::pin(async move {
                assert_eq!(account, &self.account);
                assert_eq!(size.get(), 25);
                self.reads
                    .lock()
                    .expect("reads")
                    .push((account.clone(), size.get()));
                let start: usize =
                    after.map_or(0, |token| token.as_str().parse().expect("local cursor"));
                let end = (start + usize::from(size.get())).min(120);
                let rows = (start..end)
                    .map(|index| {
                        envelope(
                            &format!("new-{index:03}"),
                            1000 - i64::try_from(index).expect("small"),
                        )
                    })
                    .collect();
                Ok(Page::new(
                    rows,
                    (end < 120).then(|| PageToken::new(end.to_string()).expect("cursor")),
                ))
            })
        }
        fn fetch_message<'a>(
            &'a self,
            account: &'a AccountId,
            id: &'a MessageId,
        ) -> BoxFuture<'a, Result<Message, RemoteMailboxError>> {
            Box::pin(async move {
                assert_eq!(account, &self.account);
                if self.fail_body {
                    return Err(RemoteMailboxError::Transport);
                }
                self.bodies
                    .lock()
                    .expect("bodies")
                    .push((account.clone(), id.clone()));
                let index: i64 = id
                    .as_str()
                    .strip_prefix("new-")
                    .expect("new id")
                    .parse()
                    .expect("index");
                Ok(message(id.as_str(), 1000 - index))
            })
        }
    }

    #[test]
    fn commits_and_closes_before_real_gated_bounded_sync_for_the_same_account() {
        let mut fixture = Fixture::new();
        let [a, b] = fixture.accounts.clone();
        let installation = Arc::clone(fixture.runtime.installation());
        let before_a = snapshot(&installation, &a);
        let before_b = snapshot(&installation, &b);
        let registry = installation.accounts().expect("registry");
        let reads = Arc::new(Mutex::new(Vec::new()));
        let bodies = Arc::new(Mutex::new(Vec::new()));
        let read_log = Arc::clone(&reads);
        let body_log = Arc::clone(&bodies);
        let expected = a.clone();
        let outcome = drive(reset_cache_using(
            &mut fixture.runtime,
            &a,
            |runtime, account| async move {
                assert_eq!(account, &expected);
                let empty = snapshot(runtime.installation(), account);
                assert!(empty.envelopes.is_empty());
                assert!(empty.lifecycle.last_successful_sync_unix_millis().is_none());
                assert_eq!(
                    empty.protected, before_a.protected,
                    "clear preserves metadata before sync"
                );
                // Fresh independent store writes prove the clear transaction ended.
                // The production helper also explicitly drops its owning connection
                // before this callback; this is not an FD/connection census.
                let store = runtime
                    .installation()
                    .open_store(account)
                    .expect("sync store");
                let session = LocalSession {
                    account: account.clone(),
                    subject: profile_subject("private-sub-a"),
                    reads: read_log,
                    bodies: body_log,
                    fail_body: false,
                };
                gated_sync(
                    account,
                    session,
                    &InstallationHasher(Arc::clone(runtime.installation())),
                    store,
                    default_sync_policy(),
                )
                .await
                .map_err(FlowError::Sync)
            },
        ))
        .expect("clear committed");
        let CacheResetOutcome::Resynced(report) = outcome else {
            panic!("sync succeeds");
        };
        assert_eq!(report.progress().envelopes, 100);
        assert_eq!(report.progress().bodies_cached, 25);
        assert_eq!(
            reads.lock().expect("reads").as_slice(),
            vec![(a.clone(), 25); 4]
        );
        assert_eq!(bodies.lock().expect("bodies").len(), 25);
        assert!(
            bodies
                .lock()
                .expect("bodies")
                .iter()
                .all(|(account, _)| account == &a)
        );
        let after = snapshot(&installation, &a);
        assert_eq!(after.envelopes.len(), 100);
        assert!(
            after
                .envelopes
                .iter()
                .all(|row| row.message_id().as_str().starts_with("new-"))
        );
        assert_eq!(
            after.bodies.iter().filter(|body| body.is_some()).count(),
            25
        );
        assert_eq!(snapshot(&installation, &b), before_b);
        assert_eq!(installation.accounts().expect("registry"), registry);
    }

    #[test]
    fn post_commit_sync_failure_is_not_a_preclear_error_and_does_not_restore_mail() {
        let mut fixture = Fixture::new();
        let [a, b] = fixture.accounts.clone();
        let installation = Arc::clone(fixture.runtime.installation());
        let protected = snapshot(&installation, &a).protected;
        let before_b = snapshot(&installation, &b);
        let registry = installation.accounts().expect("registry");
        let outcome = drive(reset_cache_using(&mut fixture.runtime, &a, |_, _| async {
            Err(FlowError::Token(BrokerError::Transport))
        }))
        .expect("clear committed");
        assert!(matches!(outcome, CacheResetOutcome::ResyncFailed(_)));
        let after = snapshot(&installation, &a);
        assert!(after.envelopes.is_empty());
        assert_eq!(after.protected, protected);
        assert!(after.lifecycle.last_successful_sync_unix_millis().is_none());
        assert_eq!(snapshot(&installation, &b), before_b);
        assert_eq!(installation.accounts().expect("registry"), registry);
    }

    #[test]
    fn normal_revoked_token_behavior_is_not_undone_or_mislabeled_as_preclear_failure() {
        let mut fixture = Fixture::new();
        let a = fixture.accounts[0].clone();
        let installation = Arc::clone(fixture.runtime.installation());
        let before = snapshot(&installation, &a);
        let expected = a.clone();
        let outcome = drive(reset_cache_using(
            &mut fixture.runtime,
            &a,
            |runtime, account| async move {
                assert_eq!(account, &expected);
                InstallationTokens(Arc::clone(runtime.installation()))
                    .delete(&subject("private-sub-a"))
                    .expect("normal broker delete on revoked grant");
                Err(FlowError::Token(BrokerError::ConsentRevoked))
            },
        ))
        .expect("clear committed");
        assert!(matches!(
            outcome,
            CacheResetOutcome::ResyncFailed(FlowError::Token(BrokerError::ConsentRevoked))
        ));
        let after = snapshot(&installation, &a);
        assert!(after.envelopes.is_empty());
        assert!(after.protected.token.is_none());
        assert_eq!(after.protected.subject, before.protected.subject);
        assert_eq!(after.protected.identity, before.protected.identity);
        assert_eq!(after.protected.email, before.protected.email);
        assert_eq!(after.protected.recovery, before.protected.recovery);
    }

    #[test]
    fn known_metadata_preconditions_reject_without_sync_or_cache_deletion() {
        for condition in 0..5 {
            let mut fixture = Fixture::new();
            let a = fixture.accounts[0].clone();
            let installation = Arc::clone(fixture.runtime.installation());
            let store = if condition == 1 {
                replace_fixture_store(&installation, &a, false)
            } else {
                installation.open_store(&a).expect("store")
            };
            match condition {
                0 => store.clear_refresh_token(&a).expect("missing token"),
                1 => {} // Replacement fixture deliberately has no subject.

                2 => drive(store.mark_disconnect_started(&a)).expect("pending teardown"),
                3 => drive(store.mark_revoke_unconfirmed(&a)).expect("unconfirmed revoke"),
                _ => store
                    .store_broker_subject(&a, "private-sub-b")
                    .expect("mismatched binding"),
            }
            drop(store);
            let before = snapshot(&installation, &a);
            let called = Cell::new(false);
            let result = drive(reset_cache_using(&mut fixture.runtime, &a, |_, _| {
                called.set(true);
                async {
                    panic!("sync must not run");
                }
            }));
            assert!(result.is_err());
            assert!(!called.get());
            assert_eq!(snapshot(&installation, &a), before);
        }
    }

    #[test]
    fn unknown_account_and_bad_runtime_configuration_cannot_clear_a_cache() {
        let mut fixture = Fixture::new();
        let installation = Arc::clone(fixture.runtime.installation());
        let before = snapshot(&installation, &fixture.accounts[0]);
        assert!(
            Runtime::new(
                Arc::clone(&installation),
                OAuthClient {
                    client_id: String::new(),
                    client_secret: None
                }
            )
            .is_err()
        );
        let unknown = AccountId::new("acct_unknown").expect("id");
        assert!(matches!(
            drive(fixture.runtime.reset_cache(&unknown)),
            Err(CacheResetPreconditionError::UnknownAccount)
        ));
        assert_eq!(snapshot(&installation, &fixture.accounts[0]), before);
        assert_eq!(installation.accounts().expect("registry").len(), 2);
    }

    #[test]
    fn absent_unclaimed_and_corrupt_stores_are_never_created_claimed_or_repaired() {
        for condition in 0..4 {
            let mut fixture = Fixture::new();
            let a = fixture.accounts[0].clone();
            let installation = Arc::clone(fixture.runtime.installation());
            let path = installation.cache_path_for_test(&a);
            let directory = path.parent().expect("parent").to_path_buf();
            if condition == 0 {
                fs::remove_file(&path).expect("missing DB");
            } else if condition == 1 {
                fs::remove_dir_all(&directory).expect("missing account directory");
            } else {
                for suffix in ["", "-wal", "-shm"] {
                    let _ = fs::remove_file(PathBuf::from(format!("{}{suffix}", path.display())));
                }
                fs::write(
                    &path,
                    if condition == 2 {
                        b"".as_slice()
                    } else {
                        b"not SQLCipher".as_slice()
                    },
                )
                .expect("invalid store");
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");
            }
            let before = directory.exists().then(|| files(&directory));
            let called = Cell::new(false);
            assert!(
                drive(reset_cache_using(&mut fixture.runtime, &a, |_, _| {
                    called.set(true);
                    async {
                        panic!("sync must not run");
                    }
                }))
                .is_err()
            );
            assert!(!called.get());
            assert_eq!(directory.exists().then(|| files(&directory)), before);
            if condition <= 1 {
                assert!(!path.exists());
            }
            assert_eq!(installation.accounts().expect("registry").len(), 2);
        }
    }

    #[test]
    fn invalid_account_directory_is_refused_without_permission_repair_or_cross_account_fallback() {
        for use_symlink in [false, true] {
            let mut fixture = Fixture::new();
            let [a, b] = fixture.accounts.clone();
            let installation = Arc::clone(fixture.runtime.installation());
            let b_before = snapshot(&installation, &b);
            let path = installation.cache_path_for_test(&a);
            let directory = path.parent().expect("directory");
            if use_symlink {
                fs::remove_dir_all(directory).expect("remove fixture A");
                symlink(
                    installation
                        .cache_path_for_test(&b)
                        .parent()
                        .expect("B directory"),
                    directory,
                )
                .expect("symlink");
            } else {
                fs::set_permissions(directory, fs::Permissions::from_mode(0o755))
                    .expect("insecure mode");
            }
            assert!(matches!(
                drive(reset_cache_using(&mut fixture.runtime, &a, |_, _| async {
                    panic!("sync must not run");
                })),
                Err(CacheResetPreconditionError::Installation)
            ));
            assert_eq!(snapshot(&installation, &b), b_before);
            if use_symlink {
                assert!(
                    fs::symlink_metadata(directory)
                        .expect("symlink remains")
                        .is_symlink()
                );
            } else {
                assert_eq!(
                    fs::metadata(directory)
                        .expect("directory")
                        .permissions()
                        .mode()
                        & 0o777,
                    0o755
                );
            }
        }
    }

    #[test]
    fn unpolled_and_postcommit_cancelled_futures_have_distinct_durable_effects() {
        struct Dropped(Arc<AtomicBool>);
        impl Drop for Dropped {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let mut fixture = Fixture::new();
        let [a, b] = fixture.accounts.clone();
        let installation = Arc::clone(fixture.runtime.installation());
        let before = snapshot(&installation, &a);
        let before_b = snapshot(&installation, &b);
        let called = Cell::new(false);
        let future = reset_cache_using(&mut fixture.runtime, &a, |_, _| {
            called.set(true);
            async {
                panic!("unpolled");
            }
        });
        drop(future);
        assert!(!called.get());
        assert_eq!(snapshot(&installation, &a), before);
        let dropped = Arc::new(AtomicBool::new(false));
        let probe = Arc::clone(&dropped);
        let mut future = Box::pin(reset_cache_using(
            &mut fixture.runtime,
            &a,
            |_, _| async move {
                let _guard = Dropped(probe);
                std::future::pending().await
            },
        ));
        assert!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        let cleared = snapshot(&installation, &a);
        assert!(cleared.envelopes.is_empty());
        assert_eq!(cleared.protected, before.protected);
        assert!(
            cleared
                .lifecycle
                .last_successful_sync_unix_millis()
                .is_none()
        );
        drop(future);
        assert!(dropped.load(Ordering::SeqCst));
        assert_eq!(snapshot(&installation, &a), cleared);
        assert_eq!(snapshot(&installation, &b), before_b);
    }

    #[test]
    fn public_debug_and_errors_do_not_echo_private_metadata() {
        let text = format!(
            "{:?} {:?} {:?} {} {} {:?}",
            CacheResetPreconditionError::UnknownAccount,
            CacheResetPreconditionError::Installation,
            CacheResetPreconditionError::Store(CacheResetError::Ineligible),
            CacheResetPreconditionError::Installation,
            CacheResetPreconditionError::Store(CacheResetError::Corrupted),
            CacheResetOutcome::ResyncFailed(FlowError::Token(BrokerError::ConsentRevoked))
        );
        for private in ["private-sub-a", "private-token", "example.test"] {
            assert!(!text.contains(private));
        }
    }

    #[test]
    fn wrong_account_key_is_refused_without_sync_or_ciphertext_changes() {
        let mut fixture = Fixture::new();
        let a = fixture.accounts[0].clone();
        let installation = Arc::clone(fixture.runtime.installation());
        let store = replace_fixture_store(&installation, &a, true);
        drop(store);
        let path = installation.cache_path_for_test(&a);
        let directory = path.parent().expect("directory");
        let before = files(directory);
        let called = Cell::new(false);
        assert!(matches!(
            drive(reset_cache_using(&mut fixture.runtime, &a, |_, _| {
                called.set(true);
                async {
                    panic!("no sync");
                }
            })),
            Err(CacheResetPreconditionError::Store(
                CacheResetError::Corrupted
            ))
        ));
        assert!(!called.get());
        assert_eq!(files(directory), before);
        let original = SqlCipherMailboxStore::open(a.clone(), &path, DatabaseKey::new([99; 32]))
            .expect("fixture original key");
        assert_eq!(
            drive(original.list_envelopes(&a, StoreLimit::new(10).expect("limit")))
                .expect("intact cache")
                .len(),
            1
        );
    }

    #[test]
    fn failed_bounded_body_sync_can_leave_new_headers_but_never_restore_old_mail() {
        let mut fixture = Fixture::new();
        let a = fixture.accounts[0].clone();
        let installation = Arc::clone(fixture.runtime.installation());
        let protected = snapshot(&installation, &a).protected;
        let outcome = drive(reset_cache_using(
            &mut fixture.runtime,
            &a,
            |runtime, account| async move {
                let store = runtime
                    .installation()
                    .open_store(account)
                    .expect("normal sync store");
                let session = LocalSession {
                    account: account.clone(),
                    subject: profile_subject("private-sub-a"),
                    reads: Arc::new(Mutex::new(Vec::new())),
                    bodies: Arc::new(Mutex::new(Vec::new())),
                    fail_body: true,
                };
                gated_sync(
                    account,
                    session,
                    &InstallationHasher(Arc::clone(runtime.installation())),
                    store,
                    default_sync_policy(),
                )
                .await
                .map_err(FlowError::Sync)
            },
        ))
        .expect("clear committed");
        assert!(matches!(
            outcome,
            CacheResetOutcome::ResyncFailed(FlowError::Sync(_))
        ));
        let after = snapshot(&installation, &a);
        assert_eq!(after.envelopes.len(), 100);
        assert!(
            after
                .envelopes
                .iter()
                .all(|row| row.message_id().as_str().starts_with("new-"))
        );
        assert!(after.bodies.iter().all(Option::is_none));
        assert_eq!(after.protected, protected);
        assert!(after.lifecycle.last_successful_sync_unix_millis().is_none());
    }
}
