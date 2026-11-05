// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Offline composition evidence with actual encrypted stores and controlled broker transport.

use super::*;
use crate::grants::OperationGrants;
use crate::{InstallationLock, InstallationTokens};
use std::collections::VecDeque;
use std::fs;
use std::path::PathBuf;
use std::sync::{
    Mutex,
    atomic::{AtomicU64, AtomicUsize, Ordering},
};
use std::time::{SystemTime, UNIX_EPOCH};
use tersa_application::{
    identity::{AccountIdentityStore, IdentityHash, IdentityReconcile},
    mailbox::BoxFuture,
    scope::{GMAIL_READONLY_SCOPE, ScopeEvidence},
    token::{
        ExchangeRequest, IdTokenClaims, RefreshRequest, TokenResponse, TokenTransport,
        TokenTransportError,
    },
};
use tersa_keys::RootKey;
use tersa_store_sqlcipher::{CredentialSnapshot, StoreCredential};
use tersa_token_broker_core::{
    CapabilityGrantStore, CapabilityGrantStoreError, GrantCredential, RefreshTokenStore,
    ValidatedSubject,
};

const SUBJECT: &str = "synthetic-subject-a";
const REDIRECT: &str = "http://127.0.0.1:18532/";
const CLIENT: &str = "synthetic-client.apps.googleusercontent.com";
fn secret(value: &str) -> Zeroizing<String> {
    Zeroizing::new(value.to_owned())
}
fn subject() -> ValidatedSubject {
    ValidatedSubject::new(SUBJECT).expect("synthetic fixture or controlled operation")
}
fn drive<F: Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("synthetic fixture or controlled operation")
        .block_on(future)
}

#[derive(Debug)]
struct Transport {
    replies: Mutex<VecDeque<Result<TokenResponse, TokenTransportError>>>,
    exchanges: AtomicUsize,
    refreshes: AtomicUsize,
    revokes: AtomicUsize,
    revoke_wait: Mutex<Option<Arc<tokio::sync::Notify>>>,
}
impl Transport {
    fn new(replies: Vec<Result<TokenResponse, TokenTransportError>>) -> Arc<Self> {
        Arc::new(Self {
            replies: Mutex::new(replies.into()),
            exchanges: AtomicUsize::new(0),
            refreshes: AtomicUsize::new(0),
            revokes: AtomicUsize::new(0),
            revoke_wait: Mutex::new(None),
        })
    }
    fn reply(&self) -> Result<TokenResponse, TokenTransportError> {
        self.replies
            .lock()
            .expect("synthetic fixture or controlled operation")
            .pop_front()
            .expect("unexpected provider request")
    }
}
// This wrapper is a real TokenTransport port, not a configurable provider URL.
#[derive(Debug)]
struct Port(Arc<Transport>);
impl TokenTransport for Port {
    fn exchange(
        &self,
        _request: ExchangeRequest,
    ) -> BoxFuture<'_, Result<TokenResponse, TokenTransportError>> {
        self.0.exchanges.fetch_add(1, Ordering::SeqCst);
        Box::pin(std::future::ready(self.0.reply()))
    }
    fn refresh(
        &self,
        _request: RefreshRequest,
    ) -> BoxFuture<'_, Result<TokenResponse, TokenTransportError>> {
        self.0.refreshes.fetch_add(1, Ordering::SeqCst);
        Box::pin(std::future::ready(self.0.reply()))
    }
    fn revoke<'a>(
        &'a self,
        _token: &'a Zeroizing<String>,
    ) -> BoxFuture<'a, Result<(), TokenTransportError>> {
        self.0.revokes.fetch_add(1, Ordering::SeqCst);
        let wait = self.0.revoke_wait.lock().expect("revoke control").clone();
        Box::pin(async move {
            if let Some(wait) = wait {
                wait.notified().await;
            }
            Ok(())
        })
    }
}
fn response(subject: &str, scope: ScopeEvidence, refresh: Option<&str>) -> TokenResponse {
    response_access(subject, scope, refresh, "synthetic-access")
}
fn response_access(
    subject: &str,
    scope: ScopeEvidence,
    refresh: Option<&str>,
    access: &str,
) -> TokenResponse {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("synthetic fixture or controlled operation")
        .as_secs();
    TokenResponse::with_scope_evidence(
        secret(access),
        Duration::from_secs(3600),
        refresh.map(secret),
        Some(IdTokenClaims::new(
            secret(subject),
            vec![CLIENT.to_owned()],
            "https://accounts.google.com".to_owned(),
            None,
            now,
            now + 3600,
        )),
        scope,
    )
}
struct Fixture {
    runtime: Runtime,
    account: AccountId,
    port: Arc<Transport>,
    _lock: InstallationLock,
    directory: PathBuf,
}
impl Fixture {
    fn new(
        capability: AccountCapability,
        replies: Vec<Result<TokenResponse, TokenTransportError>>,
    ) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "tersa-p7a-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let lock = InstallationLock::acquire(&directory)
            .expect("synthetic fixture or controlled operation");
        let installation = Arc::new(
            Installation::open(&directory, RootKey::from_bytes(Zeroizing::new([9; 32])))
                .expect("synthetic fixture or controlled operation"),
        );
        let account = OperationGrants::new(Arc::clone(&installation))
            .connect_new(&subject(), &secret("old-refresh"), capability)
            .expect("synthetic fixture or controlled operation");
        let port = Transport::new(replies);
        let mut runtime = Runtime::local(installation);
        runtime.online = Some(Online::new(
            OAuthClient {
                client_id: CLIENT.to_owned(),
                client_secret: None,
            },
            Port(Arc::clone(&port)),
        ));
        Self {
            runtime,
            account,
            port,
            _lock: lock,
            directory,
        }
    }
    fn snapshot(&self) -> CredentialSnapshot {
        self.runtime
            .installation
            .open_store(&self.account)
            .expect("synthetic fixture or controlled operation")
            .load_credential_snapshot(&self.account)
            .expect("synthetic fixture or controlled operation")
    }
    fn begin(
        &self,
        broker: &Broker,
        requested: Option<AccountCapability>,
    ) -> (u64, tersa_token_broker_core::PendingAuthorization) {
        self.runtime
            .prepare_existing(broker, &self.account, requested, REDIRECT)
            .expect("synthetic fixture or controlled operation")
    }
    async fn seed_session(&self) -> SharedSession {
        self.runtime
            .session(&self.account)
            .await
            .expect("synthetic fixture or controlled operation")
            .0
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}
fn callback(pending: &tersa_token_broker_core::PendingAuthorization, denied: bool) -> String {
    let state = pending
        .authorization_url()
        .query_pairs()
        .find(|(k, _)| k == "state")
        .expect("synthetic fixture or controlled operation")
        .1
        .into_owned();
    let mut callback =
        url::Url::parse(REDIRECT).expect("synthetic fixture or controlled operation");
    callback
        .query_pairs_mut()
        .append_pair("state", &state)
        .append_pair(
            if denied { "error" } else { "code" },
            if denied {
                "access_denied"
            } else {
                "synthetic-code"
            },
        );
    callback.into()
}

// Distinct runtime/store boundary: old opaque identity must survive broker projection.
#[test]
fn bridge_cas_retains_original_identity_and_rejects_stale_grant_or_owner() {
    let f = Fixture::new(AccountCapability::ReadOnly, vec![]);
    let bridge = OperationGrants::new(Arc::clone(&f.runtime.installation));
    let expected = bridge
        .load_grant(&subject())
        .expect("synthetic fixture or controlled operation")
        .expect("synthetic fixture or controlled operation");
    let store = f
        .runtime
        .installation
        .open_store(&f.account)
        .expect("synthetic fixture or controlled operation");
    drive(store.reconcile_identity(
        &f.account,
        &IdentityHash::from_bytes([1; 32]),
        IdentityReconcile::RecordOnly,
        None,
    ))
    .expect("synthetic fixture or controlled operation");
    assert_eq!(
        bridge.replace_existing(&expected, &secret("new"), AccountCapability::Modify),
        Err(CapabilityGrantStoreError::Conflict)
    );
    assert_eq!(
        bridge.load_grant(&subject()),
        Err(CapabilityGrantStoreError::Conflict)
    );
    assert_eq!(f.snapshot().capability(), AccountCapability::ReadOnly);
    let fresh = OperationGrants::new(Arc::clone(&f.runtime.installation));
    let expected = fresh
        .load_grant(&subject())
        .expect("synthetic fixture or controlled operation")
        .expect("synthetic fixture or controlled operation");
    fresh
        .replace_existing(&expected, &secret("new"), AccountCapability::Modify)
        .expect("synthetic fixture or controlled operation");
    assert_eq!(
        fresh.delete_existing(&expected),
        Err(CapabilityGrantStoreError::Conflict)
    );
    let actual = f.snapshot();
    assert_eq!(actual.capability(), AccountCapability::Modify);
    assert!(
        matches!(actual.credential(), StoreCredential::Active(token) if token.as_str() == "new")
    );
    let wrong = tersa_token_broker_core::StoredCapabilityGrant::new(
        AccountId::new("other").expect("synthetic fixture or controlled operation"),
        subject(),
        AccountCapability::ReadOnly,
        GrantCredential::Missing,
    )
    .expect("synthetic fixture or controlled operation");
    assert_eq!(
        fresh.replace_existing(&wrong, &secret("bad"), AccountCapability::Modify),
        Err(CapabilityGrantStoreError::UnknownAccount)
    );
    assert_eq!(f.snapshot(), actual);
}

#[test]
fn known_missing_and_duplicate_connect_never_overwrite_or_disappear() {
    let f = Fixture::new(AccountCapability::Modify, vec![]);
    let store = f
        .runtime
        .installation
        .open_store(&f.account)
        .expect("synthetic fixture or controlled operation");
    store
        .delete_credential_snapshot(&f.snapshot())
        .expect("synthetic fixture or controlled operation");
    let missing = f.snapshot();
    let bridge = OperationGrants::new(Arc::clone(&f.runtime.installation));
    assert!(matches!(
        bridge
            .load_grant(&subject())
            .expect("synthetic fixture or controlled operation")
            .expect("synthetic fixture or controlled operation")
            .credential(),
        GrantCredential::Missing
    ));
    assert_eq!(
        bridge.connect_new(
            &subject(),
            &secret("duplicate"),
            AccountCapability::ReadOnly
        ),
        Err(CapabilityGrantStoreError::AlreadyConnected)
    );
    assert_eq!(f.snapshot(), missing);
    // A controlled registered tokenless binding remains eligible for explicit reconnect.
    let expected = bridge
        .load_grant(&subject())
        .expect("synthetic fixture or controlled operation")
        .expect("synthetic fixture or controlled operation");
    bridge
        .replace_existing(&expected, &secret("reconnected"), AccountCapability::Modify)
        .expect("synthetic fixture or controlled operation");
    assert_eq!(f.snapshot().capability(), AccountCapability::Modify);
    assert!(
        InstallationTokens(Arc::clone(&f.runtime.installation))
            .load(&subject())
            .is_err()
    );
}

#[test]
fn selected_upgrade_commits_same_account_and_invalidates_only_after_success() {
    drive(async {
        let f = Fixture::new(
            AccountCapability::ReadOnly,
            vec![
                Ok(response(SUBJECT, ScopeEvidence::Absent, None)),
                Ok(response(SUBJECT, ScopeEvidence::Absent, Some("upgraded"))),
            ],
        );
        let session = f.seed_session().await;
        let before = f
            .runtime
            .operations
            .get(&f.account)
            .expect("synthetic fixture or controlled operation")
            .generation();
        let broker = f
            .runtime
            .broker()
            .expect("synthetic fixture or controlled operation");
        let (generation, pending) = f.begin(&broker, Some(AccountCapability::Modify));
        assert!(pending.authorization_url().query_pairs().any(|(k,v)| k=="scope" && v==tersa_application::scope::MODIFY_REQUESTED_SCOPE));
        let token = f
            .runtime
            .complete_existing(
                &broker,
                &f.account,
                generation,
                pending.session_handle(),
                &callback(&pending, false),
            )
            .await
            .expect("synthetic fixture or controlled operation");
        assert_eq!(token.account_id(), &f.account);
        assert_eq!(token.capability(), AccountCapability::Modify);
        assert_eq!(token.accepted_scope().evidence(), ScopeEvidence::Absent);
        assert!(
            f.runtime
                .operations
                .get(&f.account)
                .expect("synthetic fixture or controlled operation")
                .generation()
                > before
        );
        assert!(
            !f.runtime
                .session_is_current(&f.account, &session)
                .expect("synthetic fixture or controlled operation")
        );
        assert_eq!(f.snapshot().capability(), AccountCapability::Modify);
        assert!(
            matches!(f.snapshot().credential(), StoreCredential::Active(t) if t.as_str()=="upgraded")
        );
    });
}

#[test]
fn wrong_subject_denial_cancellation_and_exchange_failure_preserve_cached_session_and_grant() {
    for failure in 0..5 {
        drive(async {
            let second = if failure == 3 {
                Err(TokenTransportError::Transport)
            } else if failure == 4 {
                Ok(response(
                    SUBJECT,
                    ScopeEvidence::LegacyReadOnly { granted: true },
                    Some("legacy"),
                ))
            } else {
                Ok(response(
                    "different-subject",
                    ScopeEvidence::Absent,
                    Some("wrong"),
                ))
            };
            let f = Fixture::new(
                AccountCapability::ReadOnly,
                vec![Ok(response(SUBJECT, ScopeEvidence::Absent, None)), second],
            );
            let session = f.seed_session().await;
            let original = f.snapshot();
            let broker = f
                .runtime
                .broker()
                .expect("synthetic fixture or controlled operation");
            let (generation, pending) = f.begin(&broker, Some(AccountCapability::Modify));
            if failure != 2 {
                let result = f
                    .runtime
                    .complete_existing(
                        &broker,
                        &f.account,
                        generation,
                        pending.session_handle(),
                        &callback(&pending, failure == 1),
                    )
                    .await;
                let expected = match failure {
                    0 => BrokerError::IdentityMismatch,
                    1 => BrokerError::ProviderRejected,
                    3 => BrokerError::Transport,
                    4 => BrokerError::ScopeEvidenceUnavailable,
                    _ => unreachable!("cancellation does not complete"),
                };
                assert!(matches!(result, Err(FlowError::Token(error)) if error == expected));
            }
            drop(broker); // cancellation drops the one-shot/TTL registry and its original snapshot
            assert_eq!(f.snapshot(), original);
            assert_eq!(
                f.runtime
                    .operations
                    .get(&f.account)
                    .expect("synthetic fixture or controlled operation")
                    .generation(),
                generation
            );
            assert!(
                f.runtime
                    .session(&f.account)
                    .await
                    .expect("synthetic fixture or controlled operation")
                    .0
                    .is(&session)
            );
            assert_eq!(f.port.revokes.load(Ordering::SeqCst), 0);
        });
    }
}

#[test]
fn reconnect_preserves_modify_and_omitted_refresh_scope_never_downgrades() {
    drive(async {
        let f = Fixture::new(
            AccountCapability::Modify,
            vec![
                Ok(response(
                    SUBJECT,
                    ScopeEvidence::Absent,
                    Some("reconnected"),
                )),
                Ok(response(SUBJECT, ScopeEvidence::Absent, None)),
            ],
        );
        let broker = f
            .runtime
            .broker()
            .expect("synthetic fixture or controlled operation");
        let (generation, pending) = f.begin(&broker, None);
        let token = f
            .runtime
            .complete_existing(
                &broker,
                &f.account,
                generation,
                pending.session_handle(),
                &callback(&pending, false),
            )
            .await
            .expect("synthetic fixture or controlled operation");
        assert_eq!(token.capability(), AccountCapability::Modify);
        let session = f.seed_session().await;
        assert_eq!(session.capability(), AccountCapability::Modify);
        assert_eq!(
            session
                .accepted_scope()
                .expect("synthetic fixture or controlled operation")
                .evidence(),
            ScopeEvidence::Absent
        );
        assert_eq!(f.snapshot().capability(), AccountCapability::Modify);
    });
}

#[test]
fn reduced_refresh_rotation_is_revocation_only_and_never_enters_legacy_refresh() {
    drive(async {
        let reduced = ScopeEvidence::from_scope_field(Some(GMAIL_READONLY_SCOPE))
            .expect("synthetic fixture or controlled operation");
        let f = Fixture::new(
            AccountCapability::Modify,
            vec![Ok(response(SUBJECT, reduced, Some("revocation-handle")))],
        );
        assert!(f.runtime.session(&f.account).await.is_err());
        assert!(
            matches!(f.snapshot().credential(), StoreCredential::RevocationOnly(t) if t.as_str()=="revocation-handle")
        );
        assert!(f.runtime.session(&f.account).await.is_err());
        assert_eq!(f.port.refreshes.load(Ordering::SeqCst), 1);
        assert!(
            InstallationTokens(Arc::clone(&f.runtime.installation))
                .load(&subject())
                .is_err()
        );
        assert_eq!(
            f.runtime
                .remove_account(&f.account)
                .await
                .expect("synthetic fixture or controlled operation"),
            Revocation::Confirmed
        );
        assert_eq!(f.port.revokes.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn consent_completion_cannot_overwrite_a_new_generation_or_identity_binding() {
    for change_identity in [false, true] {
        drive(async {
            let f = Fixture::new(
                AccountCapability::ReadOnly,
                vec![Ok(response(SUBJECT, ScopeEvidence::Absent, Some("late")))],
            );
            let original = f.snapshot();
            let broker = f
                .runtime
                .broker()
                .expect("synthetic fixture or controlled operation");
            let (generation, pending) = f.begin(&broker, Some(AccountCapability::Modify));
            if change_identity {
                let store = f
                    .runtime
                    .installation
                    .open_store(&f.account)
                    .expect("synthetic fixture or controlled operation");
                store
                    .reconcile_identity(
                        &f.account,
                        &IdentityHash::from_bytes([2; 32]),
                        IdentityReconcile::RecordOnly,
                        None,
                    )
                    .await
                    .expect("synthetic fixture or controlled operation");
            } else {
                f.runtime
                    .invalidate(&f.account)
                    .expect("synthetic fixture or controlled operation");
            }
            let result = f
                .runtime
                .complete_existing(
                    &broker,
                    &f.account,
                    generation,
                    pending.session_handle(),
                    &callback(&pending, false),
                )
                .await;
            assert!(matches!(
                result,
                Err(FlowError::Token(BrokerError::GrantChanged))
            ));
            assert_eq!(f.snapshot().credential(), original.credential());
            assert_eq!(f.snapshot().capability(), AccountCapability::ReadOnly);
            assert_eq!(f.port.exchanges.load(Ordering::SeqCst), 0);
            assert_eq!(f.port.revokes.load(Ordering::SeqCst), 0);
        });
    }
}

#[test]
fn occupied_missing_unclaimed_and_corrupt_stores_never_provision_or_license_connect_cleanup() {
    for damage in 0..3 {
        drive(async {
            let f = Fixture::new(
                AccountCapability::ReadOnly,
                vec![Ok(response(SUBJECT, ScopeEvidence::Absent, Some("new")))],
            );
            let path = f.runtime.installation.cache_path_for_test(&f.account);
            match damage {
                0 => fs::remove_file(&path).expect("synthetic fixture or controlled operation"),
                1 => {
                    fs::write(&path, []).expect("synthetic fixture or controlled operation");
                }
                _ => {
                    fs::write(&path, b"corrupt synthetic occupied store")
                        .expect("synthetic fixture or controlled operation");
                }
            }
            let before = fs::read(&path).ok();
            let bridge = OperationGrants::new(Arc::clone(&f.runtime.installation));
            assert!(bridge.load_grant(&subject()).is_err());
            assert!(
                InstallationTokens(Arc::clone(&f.runtime.installation))
                    .load(&subject())
                    .is_err()
            );
            assert!(f.runtime.installation.open_store(&f.account).is_err());
            let broker = f
                .runtime
                .broker()
                .expect("synthetic fixture or controlled operation");
            let pending = broker
                .begin_capability_authorization(
                    REDIRECT,
                    AccountCapability::ReadOnly,
                    AuthorizationIntent::Connect,
                )
                .expect("synthetic fixture or controlled operation");
            assert!(matches!(
                broker
                    .complete_capability_authorization(
                        pending.session_handle(),
                        &callback(&pending, false)
                    )
                    .await,
                Err(BrokerError::PersistenceFailed)
            ));
            assert_eq!(f.port.revokes.load(Ordering::SeqCst), 0);
            assert_eq!(fs::read(&path).ok(), before);
            assert_eq!(
                f.runtime
                    .installation
                    .accounts()
                    .expect("synthetic fixture or controlled operation"),
                vec![f.account.clone()]
            );
        });
    }
}

#[test]
fn removal_refuses_a_durable_queued_command_before_provider_revocation() {
    use tersa_application::{
        command::{CommandAdmission, MailboxCommandStore},
        profile::AccountFence,
    };
    use tersa_domain::{
        command::{MailboxCommand, MailboxCommandId},
        label::LabelName,
    };
    drive(async {
        let f = Fixture::new(AccountCapability::Modify, vec![]);
        let store = f
            .runtime
            .installation
            .open_store(&f.account)
            .expect("synthetic fixture or controlled operation");
        let identity = IdentityHash::from_bytes([4; 32]);
        store
            .reconcile_identity(&f.account, &identity, IdentityReconcile::RecordOnly, None)
            .await
            .expect("synthetic fixture or controlled operation");
        let command = MailboxCommand::create_label(
            AccountCapability::Modify,
            MailboxCommandId::new("queued").expect("synthetic fixture or controlled operation"),
            f.account.clone(),
            LabelName::new("local queued label")
                .expect("synthetic fixture or controlled operation"),
        )
        .expect("synthetic fixture or controlled operation");
        store
            .admit(
                &CommandAdmission::new(AccountFence::new(f.account.clone(), identity), command)
                    .expect("synthetic fixture or controlled operation"),
            )
            .await
            .expect("synthetic fixture or controlled operation");
        let before = f.snapshot();
        assert!(f.runtime.remove_account(&f.account).await.is_err());
        assert_eq!(f.port.revokes.load(Ordering::SeqCst), 0);
        assert_eq!(f.snapshot(), before);
        assert!(
            store
                .lifecycle_metadata(&f.account)
                .await
                .expect("synthetic fixture or controlled operation")
                .recovery()
                .is_none()
        );
        assert!(
            f.runtime
                .installation
                .accounts()
                .expect("synthetic fixture or controlled operation")
                .contains(&f.account)
        );
    });
}

// This probes real public operations while another owning account permit is held.
// A missing permit would perform a token request/removal or return an immediate error.
#[test]
fn existing_operations_serialize_per_account_without_blocking_other_accounts_or_cached_reads() {
    use std::pin::pin;
    use std::task::{Context, Poll, Waker};
    use tersa_application::mailbox::MailboxReader;
    drive(async {
        let f = Fixture::new(AccountCapability::ReadOnly, vec![]);
        let other_subject = ValidatedSubject::new("synthetic-subject-b")
            .expect("synthetic fixture or controlled operation");
        let other = OperationGrants::new(Arc::clone(&f.runtime.installation))
            .connect_new(
                &other_subject,
                &secret("other-refresh"),
                AccountCapability::ReadOnly,
            )
            .expect("synthetic fixture or controlled operation");
        let operation = f
            .runtime
            .operations
            .get(&f.account)
            .expect("synthetic fixture or controlled operation");
        let permit = operation.permit.lock().await;
        {
            let mut cx = Context::from_waker(Waker::noop());
            let mut sync = pin!(f.runtime.sync_account(&f.account));
            let message =
                MessageId::new("message").expect("synthetic fixture or controlled operation");
            let mut fetch = pin!(f.runtime.fetch_message(&f.account, &message));
            let mut remove = pin!(f.runtime.remove_account(&f.account));
            let mut reset = pin!(f.runtime.reset_account_cache(&f.account));
            for pending in [
                sync.as_mut().poll(&mut cx).map(|_| ()),
                fetch.as_mut().poll(&mut cx).map(|_| ()),
                remove.as_mut().poll(&mut cx).map(|_| ()),
                reset.as_mut().poll(&mut cx).map(|_| ()),
            ] {
                assert!(matches!(pending, Poll::Pending));
            }
            // Cached SQL reads remain available even for the held account.
            let store = f
                .runtime
                .installation
                .open_store_for_display(&f.account)
                .expect("synthetic fixture or controlled operation");
            assert!(
                store
                    .list_envelopes(
                        &f.account,
                        StoreLimit::new(1).expect("synthetic fixture or controlled operation")
                    )
                    .await
                    .expect("synthetic fixture or controlled operation")
                    .is_empty()
            );
            let other_operation = f
                .runtime
                .operations
                .get(&other)
                .expect("synthetic fixture or controlled operation");
            assert!(other_operation.permit.try_lock().is_ok());
            assert_eq!(f.port.refreshes.load(Ordering::SeqCst), 0);
            assert_eq!(f.port.revokes.load(Ordering::SeqCst), 0);
        }
        drop(permit);
        // Cancelled waiters do not retain a permit or advance the credential generation.
        assert!(operation.permit.try_lock().is_ok());
        assert_eq!(operation.generation(), 0);
    });
}

#[test]
fn offline_runtime_resets_locally_then_reports_sync_configuration_failure_after_commit() {
    drive(async {
        let mut f = Fixture::new(AccountCapability::ReadOnly, vec![]);
        let store = f
            .runtime
            .installation
            .open_store(&f.account)
            .expect("synthetic fixture or controlled operation");
        store
            .reconcile_identity(
                &f.account,
                &IdentityHash::from_bytes([5; 32]),
                IdentityReconcile::RecordOnly,
                None,
            )
            .await
            .expect("synthetic fixture or controlled operation");
        store
            .record_successful_sync(&f.account, 123)
            .await
            .expect("synthetic fixture or controlled operation");
        let original = f.snapshot();
        f.runtime.online = None;
        assert!(
            matches!(f.runtime.reset_account_cache(&f.account).await.expect("synthetic fixture or controlled operation"), CacheResetOutcome::ResyncFailed(FlowError::Refresh(error)) if matches!(*error, FlowError::Configuration))
        );
        assert_eq!(f.snapshot(), original);
        assert!(
            store
                .lifecycle_metadata(&f.account)
                .await
                .expect("synthetic fixture or controlled operation")
                .last_successful_sync_unix_millis()
                .is_none()
        );
        assert_eq!(
            f.runtime
                .operations
                .get(&f.account)
                .expect("synthetic fixture or controlled operation")
                .generation(),
            1
        );
        assert_eq!(f.port.refreshes.load(Ordering::SeqCst), 0);
    });
}

#[test]
fn bounded_authorization_admission_refuses_before_browser_or_loopback_work() {
    drive(async {
        let f = Fixture::new(AccountCapability::ReadOnly, vec![]);
        let original = f.snapshot();
        let _all_slots = f
            .runtime
            .authorizations
            .try_acquire_many(8)
            .expect("eight admission slots");
        assert!(matches!(
            f.runtime
                .add_account(|_| panic!("must not open browser"))
                .await,
            Err(FlowError::Token(BrokerError::Busy))
        ));
        assert!(matches!(
            f.runtime
                .upgrade_account(&f.account, |_| panic!("must not open browser"))
                .await,
            Err(FlowError::Token(BrokerError::Busy))
        ));
        assert_eq!(f.snapshot(), original);
        assert_eq!(f.port.exchanges.load(Ordering::SeqCst), 0);
    });
}

#[test]
fn partial_legacy_registration_remains_a_known_tokenless_readonly_binding() {
    let f = Fixture::new(AccountCapability::ReadOnly, vec![]);
    let subject = ValidatedSubject::new("partial-subject").expect("subject");
    let legacy = InstallationTokens(Arc::clone(&f.runtime.installation));
    // The legacy sequence registers before validating its token write. Preserve
    // that real partial state, rather than fabricating a final store payload.
    assert!(legacy.store(&subject, &secret("")).is_err());
    let bridge = OperationGrants::new(Arc::clone(&f.runtime.installation));
    let grant = bridge
        .load_grant(&subject)
        .expect("known binding")
        .expect("not unknown");
    assert_eq!(grant.capability(), AccountCapability::ReadOnly);
    assert!(matches!(grant.credential(), GrantCredential::Missing));
    assert_eq!(
        bridge.connect_new(&subject, &secret("new"), AccountCapability::Modify),
        Err(CapabilityGrantStoreError::AlreadyConnected)
    );
    bridge
        .replace_existing(
            &grant,
            &secret("explicit-reconnect"),
            AccountCapability::ReadOnly,
        )
        .expect("selected recovery");
    assert!(
        legacy
            .load(&subject)
            .expect("usable readonly token")
            .is_some()
    );
}

#[test]
fn committed_upgrade_reports_session_construction_failure_separately_from_grant_success() {
    drive(async {
        // The broker's bounded nonempty access value is accepted; the Gmail
        // constructor rejects its control character before constructing a client.
        let f = Fixture::new(
            AccountCapability::ReadOnly,
            vec![Ok(response_access(
                SUBJECT,
                ScopeEvidence::Absent,
                Some("committed-upgrade"),
                "invalid\naccess",
            ))],
        );
        let broker = f.runtime.broker().expect("broker");
        let (generation, pending) = f.begin(&broker, Some(AccountCapability::Modify));
        let token = f
            .runtime
            .complete_existing(
                &broker,
                &f.account,
                generation,
                pending.session_handle(),
                &callback(&pending, false),
            )
            .await
            .expect("grant committed");
        let result = f.runtime.connected_account(token, true).await;
        assert_eq!(result.account, f.account);
        assert!(result.already_present);
        assert!(matches!(
            result.first_sync,
            Err(FlowError::Session(GmailSessionError::Mailbox(
                RemoteMailboxError::AuthorizationRequired
            )))
        ));
        assert_eq!(f.snapshot().capability(), AccountCapability::Modify);
        assert!(
            matches!(f.snapshot().credential(), StoreCredential::Active(value) if value.as_str()=="committed-upgrade")
        );
        assert_eq!(f.port.revokes.load(Ordering::SeqCst), 0);
        assert_eq!(f.port.refreshes.load(Ordering::SeqCst), 0);
    });
}

#[test]
fn new_connect_completion_cannot_register_during_another_empty_snapshot_cleanup() {
    use std::pin::pin;
    use std::task::{Context, Poll, Waker};
    drive(async {
        let expired = TokenResponse::with_scope_evidence(
            secret("synthetic-access"),
            Duration::from_secs(3600),
            Some(secret("expired-grant")),
            Some(IdTokenClaims::new(
                secret("new-subject"),
                vec![CLIENT.to_owned()],
                "https://accounts.google.com".to_owned(),
                None,
                1,
                2,
            )),
            ScopeEvidence::Absent,
        );
        let f = Fixture::new(
            AccountCapability::ReadOnly,
            vec![
                Ok(expired),
                Ok(response(
                    "new-subject",
                    ScopeEvidence::Absent,
                    Some("valid-new-grant"),
                )),
            ],
        );
        let release = Arc::new(tokio::sync::Notify::new());
        *f.port.revoke_wait.lock().expect("revoke control") = Some(Arc::clone(&release));
        let first_broker = f.runtime.broker().expect("first broker");
        let second_broker = f.runtime.broker().expect("second broker");
        let first = first_broker
            .begin_capability_authorization(
                REDIRECT,
                AccountCapability::ReadOnly,
                AuthorizationIntent::Connect,
            )
            .expect("first Connect");
        let second = second_broker
            .begin_capability_authorization(
                REDIRECT,
                AccountCapability::ReadOnly,
                AuthorizationIntent::Connect,
            )
            .expect("second Connect");
        let first_callback = callback(&first, false);
        let second_callback = callback(&second, false);
        let mut first_completion = pin!(f.runtime.complete_new(
            &first_broker,
            first.session_handle(),
            &first_callback
        ));
        let mut second_completion = pin!(f.runtime.complete_new(
            &second_broker,
            second.session_handle(),
            &second_callback
        ));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(
            first_completion.as_mut().poll(&mut cx),
            Poll::Pending
        ));
        assert_eq!(f.port.revokes.load(Ordering::SeqCst), 1);
        assert!(matches!(
            second_completion.as_mut().poll(&mut cx),
            Poll::Pending
        ));
        assert_eq!(f.port.exchanges.load(Ordering::SeqCst), 1);
        assert!(
            f.runtime
                .installation
                .account_for_subject("new-subject")
                .expect("lookup")
                .is_none()
        );
        release.notify_one();
        assert!(matches!(
            first_completion.await,
            Err(FlowError::Token(BrokerError::IdentityUnverified))
        ));
        let connected = second_completion
            .await
            .expect("second Connect admitted after cleanup");
        let snapshot = f
            .runtime
            .installation
            .open_store(connected.account_id())
            .expect("new store")
            .load_credential_snapshot(connected.account_id())
            .expect("new grant");
        assert!(
            matches!(snapshot.credential(), StoreCredential::Active(value) if value.as_str()=="valid-new-grant")
        );
        assert_eq!(f.port.revokes.load(Ordering::SeqCst), 1);
    });
}

#[path = "composition_tests.rs"]
mod composition_tests;
