// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Broker-effect tests over controlled ports, not SQL/provider atomicity evidence.

use super::*;
use crate::{
    AuthorizationIntent, CapabilityGrantStore, CapabilityGrantStoreError, GrantCredential,
    StoredCapabilityGrant,
};
use tersa_application::{
    AccountCapability,
    mailbox::AccountId,
    profile::UpgradeBinding,
    scope::ScopeEvidence,
    token::{AccountSubject, RefreshRevocationHandle},
};

#[derive(Clone)]
struct GrantStore {
    legacy: FakeStore,
    rows: Arc<Mutex<HashMap<String, StoredCapabilityGrant>>>,
    fail_reads: Arc<AtomicBool>,
    fail_writes: Arc<AtomicBool>,
    fail_deletes: Arc<AtomicBool>,
    incomplete_connect: bool,
    read_delay: Option<(TestClock, u64)>,
}
impl fmt::Debug for GrantStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GrantStore([REDACTED])")
    }
}
fn account(value: &str) -> AccountId {
    AccountId::new(value).unwrap()
}
fn row(capability: AccountCapability, credential: GrantCredential) -> StoredCapabilityGrant {
    StoredCapabilityGrant::new(
        account("selected-account"),
        ValidatedSubject::new(SUBJECT).unwrap(),
        capability,
        credential,
    )
    .unwrap()
}
impl GrantStore {
    fn new(shared: &SharedEvents, stored: Option<StoredCapabilityGrant>) -> Self {
        let rows = stored
            .into_iter()
            .map(|row| (row.subject().as_str().to_owned(), row))
            .collect();
        Self {
            legacy: FakeStore::new(shared),
            rows: Arc::new(Mutex::new(rows)),
            fail_reads: Arc::new(AtomicBool::new(false)),
            fail_writes: Arc::new(AtomicBool::new(false)),
            fail_deletes: Arc::new(AtomicBool::new(false)),
            incomplete_connect: false,
            read_delay: None,
        }
    }
    fn current(&self) -> Option<StoredCapabilityGrant> {
        self.rows.lock().unwrap().get(SUBJECT).cloned()
    }
    fn replace(
        &self,
        expected: &StoredCapabilityGrant,
        token: GrantCredential,
        capability: AccountCapability,
    ) -> Result<(), CapabilityGrantStoreError> {
        let mut rows = self.rows.lock().unwrap();
        let actual = rows
            .get(expected.subject().as_str())
            .ok_or(CapabilityGrantStoreError::UnknownAccount)?;
        if actual != expected {
            return Err(CapabilityGrantStoreError::Conflict);
        }
        if self.fail_writes.load(Ordering::Relaxed) {
            return Err(CapabilityGrantStoreError::Unavailable);
        }
        rows.insert(
            expected.subject().as_str().to_owned(),
            StoredCapabilityGrant::new(
                expected.account_id().clone(),
                expected.subject().clone(),
                capability,
                token,
            )?,
        );
        Ok(())
    }
}
impl RefreshTokenStore for GrantStore {
    fn load(
        &self,
        subject: &ValidatedSubject,
    ) -> Result<Option<Zeroizing<String>>, RefreshTokenStoreError> {
        self.legacy.load(subject)
    }
    fn store(
        &self,
        subject: &ValidatedSubject,
        token: &Zeroizing<String>,
    ) -> Result<(), RefreshTokenStoreError> {
        self.legacy.store(subject, token)
    }
    fn delete(&self, subject: &ValidatedSubject) -> Result<(), RefreshTokenStoreError> {
        self.legacy.delete(subject)
    }
}
impl CapabilityGrantStore for GrantStore {
    fn load_grant(
        &self,
        subject: &ValidatedSubject,
    ) -> Result<Option<StoredCapabilityGrant>, CapabilityGrantStoreError> {
        if let Some((clock, seconds)) = &self.read_delay {
            clock.advance(*seconds);
        }
        if self.fail_reads.load(Ordering::Relaxed) {
            return Err(CapabilityGrantStoreError::Unavailable);
        }
        Ok(self.rows.lock().unwrap().get(subject.as_str()).cloned())
    }
    fn connect_new(
        &self,
        subject: &ValidatedSubject,
        token: &Zeroizing<String>,
        capability: AccountCapability,
    ) -> Result<AccountId, CapabilityGrantStoreError> {
        let mut rows = self.rows.lock().unwrap();
        if rows.contains_key(subject.as_str()) {
            return Err(CapabilityGrantStoreError::AlreadyConnected);
        }
        if self.fail_writes.load(Ordering::Relaxed) {
            if self.incomplete_connect {
                rows.insert(
                    subject.as_str().to_owned(),
                    StoredCapabilityGrant::new(
                        account("selected-account"),
                        subject.clone(),
                        AccountCapability::ReadOnly,
                        GrantCredential::Missing,
                    )?,
                );
            }
            return Err(CapabilityGrantStoreError::Unavailable);
        }
        rows.insert(
            subject.as_str().to_owned(),
            StoredCapabilityGrant::new(
                account("selected-account"),
                subject.clone(),
                capability,
                GrantCredential::Active(token.clone()),
            )?,
        );
        Ok(account("selected-account"))
    }
    fn replace_existing(
        &self,
        expected: &StoredCapabilityGrant,
        token: &Zeroizing<String>,
        capability: AccountCapability,
    ) -> Result<(), CapabilityGrantStoreError> {
        self.replace(expected, GrantCredential::Active(token.clone()), capability)
    }
    fn rotate_existing(
        &self,
        expected: &StoredCapabilityGrant,
        token: &Zeroizing<String>,
    ) -> Result<(), CapabilityGrantStoreError> {
        if !matches!(expected.credential(), GrantCredential::Active(_)) {
            return Err(CapabilityGrantStoreError::Invalid);
        }
        self.replace(
            expected,
            GrantCredential::Active(token.clone()),
            expected.capability(),
        )
    }
    fn retain_revocation_rotation(
        &self,
        expected: &StoredCapabilityGrant,
        token: &RefreshRevocationHandle,
    ) -> Result<(), CapabilityGrantStoreError> {
        if !matches!(expected.credential(), GrantCredential::Active(_)) {
            return Err(CapabilityGrantStoreError::Invalid);
        }
        self.replace(
            expected,
            GrantCredential::RevocationOnly(token.secret_for_revocation().clone()),
            expected.capability(),
        )
    }
    fn delete_existing(
        &self,
        expected: &StoredCapabilityGrant,
    ) -> Result<(), CapabilityGrantStoreError> {
        if self.fail_deletes.load(Ordering::Relaxed) {
            return Err(CapabilityGrantStoreError::Unavailable);
        }
        self.replace(expected, GrantCredential::Missing, expected.capability())
    }
}
type CapabilityBroker =
    BrokerCore<FakeTransport, GrantStore, TestClock, TestWallClock, CounterEntropy>;
fn broker(transport: &FakeTransport, store: &GrantStore) -> CapabilityBroker {
    BrokerCore::new(
        CLIENT_ID.to_owned(),
        None,
        Duration::from_secs(600),
        (
            transport.clone(),
            store.clone(),
            store
                .read_delay
                .as_ref()
                .map_or_else(TestClock::default, |(clock, _)| clock.clone()),
            TestWallClock(NOW),
            CounterEntropy::default(),
        ),
    )
    .unwrap()
}
fn binding() -> UpgradeBinding {
    UpgradeBinding::new(
        account("selected-account"),
        AccountSubject::from_broker_validated(Zeroizing::new(SUBJECT.to_owned())).unwrap(),
    )
}
fn modern(shared: &SharedEvents) -> FakeTransport {
    let mut transport = FakeTransport::success(shared, Some(ROTATED_REFRESH_TOKEN));
    transport.scope_evidence = Some(ScopeEvidence::Absent);
    transport
}
fn complete(
    broker: &CapabilityBroker,
    intent: AuthorizationIntent,
    capability: AccountCapability,
) -> Result<crate::CapabilityBrokerToken, BrokerError> {
    let pending = broker.begin_capability_authorization(REDIRECT, capability, intent)?;
    ready(broker.complete_capability_authorization(
        pending.session_handle(),
        callback_for(&pending, AUTH_CODE).as_str(),
    ))
}

// Contract: capability/Connect intent stays bound and durable pair admission precedes returned access.
// Regression: a lossy boolean authorizes Modify, or duplicate Connect overwrites a known grant.
#[test]
fn connect_binds_both_capabilities_and_refuses_duplicate_without_downgrade() {
    for capability in [AccountCapability::ReadOnly, AccountCapability::Modify] {
        let shared = events();
        let transport = modern(&shared);
        let store = GrantStore::new(&shared, None);
        let broker = broker(&transport, &store);
        let pending = broker
            .begin_capability_authorization(REDIRECT, capability, AuthorizationIntent::Connect)
            .unwrap();
        assert_eq!(
            query_value(pending.authorization_url(), "scope"),
            match capability {
                AccountCapability::ReadOnly =>
                    "openid https://www.googleapis.com/auth/gmail.readonly",
                AccountCapability::Modify => "openid https://www.googleapis.com/auth/gmail.modify",
            }
        );
        let callback = callback_for(&pending, AUTH_CODE);
        let accepted = ready(
            broker.complete_capability_authorization(pending.session_handle(), callback.as_str()),
        )
        .unwrap();
        assert_eq!(accepted.capability(), capability);
        assert_eq!(accepted.accepted_scope().evidence(), ScopeEvidence::Absent);
        assert_eq!(accepted.account_id().as_str(), "selected-account");
        assert_eq!(accepted.token().access_token().as_str(), ACCESS_TOKEN);
        assert_eq!(store.current().unwrap().capability(), capability);
        assert!(
            matches!(store.current().unwrap().credential(),GrantCredential::Active(token) if token.as_str()==ROTATED_REFRESH_TOKEN)
        );
        assert!(matches!(
            ready(
                broker
                    .complete_capability_authorization(pending.session_handle(), callback.as_str())
            ),
            Err(BrokerError::SessionUnknown)
        ));
        let before = store.current();
        assert!(matches!(
            complete(
                &broker,
                AuthorizationIntent::Connect,
                AccountCapability::ReadOnly
            ),
            Err(BrokerError::AccountAlreadyConnected)
        ));
        assert_eq!(store.current(), before);
        assert!(transport.revoked_handles().is_empty());
        assert!(store.legacy.is_empty());
        let debug = format!("{accepted:?}");
        for sentinel in [
            SUBJECT,
            ACCESS_TOKEN,
            ROTATED_REFRESH_TOKEN,
            "selected-account",
        ] {
            assert!(!debug.contains(sentinel));
        }
    }
}

// Contract: selected replacement writes token+capability through the new port, never token-only fallback.
// Regression: a failed atomic port first overwrites the legacy token or routes a different account.
#[test]
fn upgrade_replaces_only_selected_same_subject_and_preserves_on_atomic_failure() {
    for (write_failed, read_failed) in [(false, false), (true, false), (false, true)] {
        let shared = events();
        let transport = modern(&shared);
        let initial = row(
            AccountCapability::ReadOnly,
            GrantCredential::Active(Zeroizing::new(REFRESH_TOKEN.to_owned())),
        );
        let store = GrantStore::new(&shared, Some(initial.clone()));
        let store = GrantStore {
            legacy: store
                .legacy
                .clone()
                .with_stored_token(SUBJECT, REFRESH_TOKEN),
            ..store
        };
        let broker = broker(&transport, &store);
        let pending = broker
            .begin_capability_authorization(
                REDIRECT,
                AccountCapability::Modify,
                AuthorizationIntent::Upgrade(binding()),
            )
            .unwrap();
        store.fail_writes.store(write_failed, Ordering::Relaxed);
        store.fail_reads.store(read_failed, Ordering::Relaxed);
        let result = ready(broker.complete_capability_authorization(
            pending.session_handle(),
            callback_for(&pending, AUTH_CODE).as_str(),
        ));
        if write_failed || read_failed {
            assert!(matches!(result, Err(BrokerError::PersistenceFailed)));
            assert_eq!(store.current(), Some(initial));
        } else {
            assert_eq!(result.unwrap().capability(), AccountCapability::Modify);
            assert_eq!(
                store.current().unwrap().capability(),
                AccountCapability::Modify
            );
            assert!(
                matches!(store.current().unwrap().credential(),GrantCredential::Active(token) if token.as_str()==ROTATED_REFRESH_TOKEN)
            );
        }
        assert_eq!(
            store.legacy.stored_token(SUBJECT).as_deref(),
            Some(REFRESH_TOKEN)
        );
        assert!(transport.revoked_handles().is_empty());
        assert_eq!(store.rows.lock().unwrap().len(), 1);
    }
}

// Contract: rejected/invalid completions cannot register, replace, revoke or expose old-account access.
// Regression: scope/identity/shape failures fall through to registration or grant-wide cleanup.
#[test]
fn upgrade_failures_preserve_the_old_grant_without_registration_or_revoke() {
    let shared = events();
    let mut legacy = modern(&shared);
    legacy.scope_evidence = None;
    let mut under = modern(&shared);
    under.scope_evidence = Some(ScopeEvidence::from_scope_field(Some("openid")).unwrap());
    under.id_token_claims = None;
    let mut malformed = modern(&shared);
    malformed.rotated_refresh_token = Some(Zeroizing::new("r".repeat(1_025)));
    let cases = [
        (
            modern(&shared).with_claims(Some(claims_for(OTHER_SUBJECT, NOW - 10, NOW + 3_600))),
            BrokerError::IdentityMismatch,
        ),
        (
            modern(&shared).with_claims(None),
            BrokerError::IdentityUnverified,
        ),
        (under, BrokerError::InsufficientScope),
        (legacy, BrokerError::ScopeEvidenceUnavailable),
        (malformed, BrokerError::MalformedResponse),
        (
            modern(&shared).with_access_token_and_expiry("", Duration::from_secs(3_600)),
            BrokerError::MalformedResponse,
        ),
        (
            modern(&shared).with_exchange_error(TokenTransportError::InvalidGrant),
            BrokerError::AuthorizationCodeRejected,
        ),
    ];
    for (transport, expected) in cases {
        for upgrade in [false, true] {
            if !upgrade && expected == BrokerError::IdentityMismatch {
                continue;
            }
            let initial = upgrade.then(|| {
                row(
                    AccountCapability::ReadOnly,
                    GrantCredential::Active(Zeroizing::new(REFRESH_TOKEN.to_owned())),
                )
            });
            let store = GrantStore::new(&shared, initial.clone());
            let broker = broker(&transport, &store);
            let intent = if upgrade {
                AuthorizationIntent::Upgrade(binding())
            } else {
                AuthorizationIntent::Connect
            };
            assert!(
                matches!(complete(&broker, intent, AccountCapability::Modify), Err(error) if error == expected)
            );
            assert_eq!(store.current(), initial);
            assert_eq!(store.rows.lock().unwrap().len(), usize::from(upgrade));
            assert!(transport.revoked_handles().is_empty());
            assert!(store.legacy.is_empty());
        }
    }
    let transport = modern(&shared);
    let initial = row(AccountCapability::ReadOnly, GrantCredential::Missing);
    let store = GrantStore::new(&shared, Some(initial.clone()));
    let broker = broker(&transport, &store);
    let pending = broker
        .begin_capability_authorization(
            REDIRECT,
            AccountCapability::Modify,
            AuthorizationIntent::Upgrade(binding()),
        )
        .unwrap();
    let mut denied = Url::parse(REDIRECT).unwrap();
    denied
        .query_pairs_mut()
        .append_pair("state", &query_value(pending.authorization_url(), "state"))
        .append_pair("error", "access_denied");
    assert!(matches!(
        ready(broker.complete_capability_authorization(pending.session_handle(), denied.as_str())),
        Err(BrokerError::ProviderRejected)
    ));
    assert_eq!(store.current(), Some(initial));
    assert!(transport.revoked_handles().is_empty());
}

// Contract: known NULL-token and controlled incomplete first-connect bindings remain reconnectable.
// Regression: missing token means unknown, duplicate Connect overwrites, or a failed first admission wedges forever.
#[test]
fn known_missing_and_incomplete_bindings_reconnect_without_registering_again() {
    let shared = events();
    let transport = modern(&shared);
    let mut store = GrantStore::new(&shared, None);
    store.incomplete_connect = true;
    store.fail_writes.store(true, Ordering::Relaxed);
    let broker = broker(&transport, &store);
    assert!(matches!(
        complete(
            &broker,
            AuthorizationIntent::Connect,
            AccountCapability::Modify
        ),
        Err(BrokerError::PersistenceFailed)
    ));
    assert!(matches!(
        store.current().unwrap().credential(),
        GrantCredential::Missing
    ));
    assert_eq!(
        store.current().unwrap().capability(),
        AccountCapability::ReadOnly
    );
    assert!(transport.revoked_handles().is_empty());
    store.fail_writes.store(false, Ordering::Relaxed);
    assert!(matches!(
        complete(
            &broker,
            AuthorizationIntent::Connect,
            AccountCapability::Modify
        ),
        Err(BrokerError::AccountAlreadyConnected)
    ));
    assert!(matches!(
        ready(broker.refresh_capability_grant(&account("selected-account"), SUBJECT)),
        Err(BrokerError::MissingRefreshToken)
    ));
    let accepted = complete(
        &broker,
        AuthorizationIntent::Upgrade(binding()),
        AccountCapability::Modify,
    )
    .unwrap();
    assert_eq!(accepted.account_id().as_str(), "selected-account");
    assert_eq!(store.rows.lock().unwrap().len(), 1);
    assert_eq!(
        store.current().unwrap().capability(),
        AccountCapability::Modify
    );
}

// Contract: refresh preserves stored capability/subject and rejected rotation is revocation-only.
// Regression: broader response promotes, mismatch rotates, or rejected handles become usable access.
#[test]
fn refresh_binds_snapshot_capability_and_retains_rejected_rotation_only_for_revocation() {
    for capability in [AccountCapability::ReadOnly, AccountCapability::Modify] {
        let shared = events();
        let transport = modern(&shared);
        let store = GrantStore::new(
            &shared,
            Some(row(
                capability,
                GrantCredential::Active(Zeroizing::new(REFRESH_TOKEN.to_owned())),
            )),
        );
        let broker = broker(&transport, &store);
        let accepted =
            ready(broker.refresh_capability_grant(&account("selected-account"), SUBJECT)).unwrap();
        assert_eq!(accepted.capability(), capability);
        assert_eq!(store.current().unwrap().capability(), capability);
        assert!(
            matches!(store.current().unwrap().credential(),GrantCredential::Active(token) if token.as_str()==ROTATED_REFRESH_TOKEN)
        );
    }
    let shared = events();
    let mut transport = modern(&shared);
    transport.scope_evidence = Some(
        ScopeEvidence::from_scope_field(Some("https://www.googleapis.com/auth/gmail.modify"))
            .unwrap(),
    );
    transport.id_token_claims = None;
    let store = GrantStore::new(
        &shared,
        Some(row(
            AccountCapability::ReadOnly,
            GrantCredential::Active(Zeroizing::new(REFRESH_TOKEN.to_owned())),
        )),
    );
    let broker = broker(&transport, &store);
    assert!(matches!(
        ready(broker.refresh_capability_grant(&account("selected-account"), SUBJECT)),
        Err(BrokerError::InsufficientScope)
    ));
    assert_eq!(
        store.current().unwrap().capability(),
        AccountCapability::ReadOnly
    );
    assert!(
        matches!(store.current().unwrap().credential(),GrantCredential::RevocationOnly(token) if token.as_str()==ROTATED_REFRESH_TOKEN)
    );
    let refreshes = shared
        .lock()
        .unwrap()
        .iter()
        .filter(|event| matches!(event, Event::Refresh))
        .count();
    assert!(matches!(
        ready(broker.refresh_capability_grant(&account("selected-account"), SUBJECT)),
        Err(BrokerError::InsufficientScope)
    ));
    assert_eq!(
        shared
            .lock()
            .unwrap()
            .iter()
            .filter(|event| matches!(event, Event::Refresh))
            .count(),
        refreshes
    );
    ready(broker.revoke_capability_grant(&account("selected-account"), SUBJECT)).unwrap();
    assert_eq!(transport.revoked_handles(), [ROTATED_REFRESH_TOKEN]);
    assert!(matches!(
        store.current().unwrap().credential(),
        GrantCredential::RevocationOnly(_)
    ));
    broker
        .delete_capability_grant(&account("selected-account"), SUBJECT)
        .unwrap();
    assert!(matches!(
        store.current().unwrap().credential(),
        GrantCredential::Missing
    ));
}

// Contract: invalid_grant asserts deletion only after confirmation; identity/read failures preserve state.
// Regression: unknown means Missing, a failed delete reports reconnect, or a mismatched subject rotates.
#[test]
fn refresh_failures_and_unknown_binding_have_distinct_non_destructive_outcomes() {
    let shared = events();
    for (transport, delete_failure, expected) in [
        (
            modern(&shared).with_claims(Some(claims_for(OTHER_SUBJECT, NOW - 10, NOW + 3_600))),
            false,
            BrokerError::IdentityMismatch,
        ),
        (
            modern(&shared).with_refresh_error(TokenTransportError::InvalidGrant),
            true,
            BrokerError::PersistenceFailed,
        ),
        (
            modern(&shared).with_refresh_error(TokenTransportError::InvalidGrant),
            false,
            BrokerError::ConsentRevoked,
        ),
    ] {
        let initial = row(
            AccountCapability::Modify,
            GrantCredential::Active(Zeroizing::new(REFRESH_TOKEN.to_owned())),
        );
        let store = GrantStore::new(&shared, Some(initial.clone()));
        store.fail_deletes.store(delete_failure, Ordering::Relaxed);
        let broker = broker(&transport, &store);
        assert!(
            matches!(ready(broker.refresh_capability_grant(&account("selected-account"),SUBJECT)),Err(error) if error==expected)
        );
        if expected == BrokerError::ConsentRevoked {
            assert!(matches!(
                store.current().unwrap().credential(),
                GrantCredential::Missing
            ));
        } else {
            assert_eq!(store.current(), Some(initial));
        }
        assert!(transport.revoked_handles().is_empty());
    }
    let transport = modern(&shared);
    let store = GrantStore::new(&shared, None);
    let broker = broker(&transport, &store);
    assert!(matches!(
        ready(broker.refresh_capability_grant(&account("selected-account"), SUBJECT)),
        Err(BrokerError::AccountUnknown)
    ));
    assert!(matches!(
        broker.begin_capability_authorization(
            REDIRECT,
            AccountCapability::Modify,
            AuthorizationIntent::Upgrade(binding())
        ),
        Err(BrokerError::AccountUnknown)
    ));
    store.fail_reads.store(true, Ordering::Relaxed);
    assert!(matches!(
        ready(broker.refresh_capability_grant(&account("selected-account"), SUBJECT)),
        Err(BrokerError::PersistenceFailed)
    ));
    assert!(store.rows.lock().unwrap().is_empty());
}

// Contract: wrong completion routing consumes privileged/legacy handles instead of falling back.
// Regression: a capability handle reaches token-only persistence or remains reusable after rejection.
#[test]
fn completion_method_routing_is_one_shot_in_both_directions() {
    let shared = events();
    let transport = modern(&shared);
    let initial = row(AccountCapability::ReadOnly, GrantCredential::Missing);
    let store = GrantStore::new(&shared, Some(initial.clone()));
    let broker = broker(&transport, &store);
    for (intent, capability) in [
        (AuthorizationIntent::Connect, AccountCapability::ReadOnly),
        (AuthorizationIntent::Connect, AccountCapability::Modify),
        (
            AuthorizationIntent::Upgrade(binding()),
            AccountCapability::Modify,
        ),
    ] {
        let pending = broker
            .begin_capability_authorization(REDIRECT, capability, intent)
            .unwrap();
        let callback = callback_for(&pending, AUTH_CODE);
        assert!(matches!(
            ready(broker.complete_authorization(pending.session_handle(), callback.as_str())),
            Err(BrokerError::InvalidInput)
        ));
        assert!(matches!(
            ready(
                broker
                    .complete_capability_authorization(pending.session_handle(), callback.as_str())
            ),
            Err(BrokerError::SessionUnknown)
        ));
    }
    let legacy = broker.begin_authorization(REDIRECT).unwrap();
    let callback = callback_for(&legacy, AUTH_CODE);
    assert!(matches!(
        ready(broker.complete_capability_authorization(legacy.session_handle(), callback.as_str())),
        Err(BrokerError::InvalidInput)
    ));
    assert!(matches!(
        ready(broker.complete_authorization(legacy.session_handle(), callback.as_str())),
        Err(BrokerError::SessionUnknown)
    ));
    assert_eq!(store.current(), Some(initial));
    assert!(store.legacy.is_empty());
    assert!(transport.recorded.lock().unwrap().is_empty());
}

// Contract: captured Upgrade intent and subject permit survive a pending exchange and release on cancellation.
// Regression: a second mutation overlaps the account, or a cancelled handle/permit remains reusable/held.
#[test]
fn upgrade_exchange_holds_permit_and_cancellation_releases_it_without_replaying_handle() {
    let shared = events();
    let gate = Arc::new(AtomicBool::new(false));
    let mut transport = modern(&shared);
    transport.exchange_gate = Some(Arc::clone(&gate));
    let initial = row(
        AccountCapability::ReadOnly,
        GrantCredential::Active(Zeroizing::new(REFRESH_TOKEN.to_owned())),
    );
    let store = GrantStore::new(&shared, Some(initial.clone()));
    let broker = broker(&transport, &store);
    let pending = broker
        .begin_capability_authorization(
            REDIRECT,
            AccountCapability::Modify,
            AuthorizationIntent::Upgrade(binding()),
        )
        .unwrap();
    let callback = callback_for(&pending, AUTH_CODE);
    let mut future = Box::pin(
        broker.complete_capability_authorization(pending.session_handle(), callback.as_str()),
    );
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
    assert!(matches!(
        ready(broker.refresh_capability_grant(&account("selected-account"), SUBJECT)),
        Err(BrokerError::Busy)
    ));
    assert_eq!(broker.delete_stored_tokens(SUBJECT), Err(BrokerError::Busy));
    assert_eq!(store.current(), Some(initial));
    drop(future);
    assert_eq!(
        ready(broker.refresh_capability_grant(&account("selected-account"), SUBJECT))
            .unwrap()
            .capability(),
        AccountCapability::ReadOnly
    );
    assert!(matches!(
        ready(
            broker.complete_capability_authorization(pending.session_handle(), callback.as_str())
        ),
        Err(BrokerError::SessionUnknown)
    ));
}

// Contract: optimistic snapshot replacement cannot overwrite a newer same-subject grant.
// Regression: the broker loses the captured snapshot and falls back to unconditional token writes.
#[test]
fn upgrade_stale_snapshot_preserves_a_newer_grant() {
    let shared = events();
    let gate = Arc::new(AtomicBool::new(false));
    let mut transport = modern(&shared);
    transport.exchange_gate = Some(Arc::clone(&gate));
    let store = GrantStore::new(
        &shared,
        Some(row(
            AccountCapability::ReadOnly,
            GrantCredential::Active(Zeroizing::new(REFRESH_TOKEN.to_owned())),
        )),
    );
    let broker = broker(&transport, &store);
    let pending = broker
        .begin_capability_authorization(
            REDIRECT,
            AccountCapability::Modify,
            AuthorizationIntent::Upgrade(binding()),
        )
        .unwrap();
    let callback = callback_for(&pending, AUTH_CODE);
    let mut future = Box::pin(
        broker.complete_capability_authorization(pending.session_handle(), callback.as_str()),
    );
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
    let newer = row(
        AccountCapability::ReadOnly,
        GrantCredential::Active(Zeroizing::new("external-rotation-sentinel".to_owned())),
    );
    store
        .rows
        .lock()
        .unwrap()
        .insert(SUBJECT.to_owned(), newer.clone());
    gate.store(true, Ordering::Relaxed);
    assert!(matches!(ready(future), Err(BrokerError::GrantChanged)));
    assert_eq!(store.current(), Some(newer));
    assert!(store.legacy.is_empty());
    assert!(transport.revoked_handles().is_empty());
}

// Contract: both matched and scope-rejected rotation port failures withhold access and preserve the grant.
// Regression: refresh reports success before persistence or routes a rejected rotation through legacy store.
#[test]
fn refresh_rotation_failures_do_not_fall_back_or_expose_access() {
    for rejected in [false, true] {
        let shared = events();
        let mut transport = modern(&shared);
        if rejected {
            transport.scope_evidence =
                Some(ScopeEvidence::from_scope_field(Some("openid")).unwrap());
            transport.id_token_claims = None;
        }
        let initial = row(
            AccountCapability::Modify,
            GrantCredential::Active(Zeroizing::new(REFRESH_TOKEN.to_owned())),
        );
        let mut store = GrantStore::new(&shared, Some(initial.clone()));
        store.legacy = store
            .legacy
            .clone()
            .with_stored_token(SUBJECT, REFRESH_TOKEN);
        store.fail_writes.store(true, Ordering::Relaxed);
        let broker = broker(&transport, &store);
        assert!(matches!(
            ready(broker.refresh_capability_grant(&account("selected-account"), SUBJECT)),
            Err(BrokerError::PersistenceFailed)
        ));
        assert_eq!(store.current(), Some(initial));
        assert_eq!(
            store.legacy.stored_token(SUBJECT).as_deref(),
            Some(REFRESH_TOKEN)
        );
        assert!(transport.revoked_handles().is_empty());
    }
}

// Contract: selected reconnect needs a fresh bounded refresh token, but known duplicate Connect remains distinct.
// Regression: a missing rotation silently promotes the old token or hides known-account routing.
#[test]
fn missing_completion_token_and_expired_context_preserve_existing_binding() {
    let shared = events();
    let mut transport = modern(&shared);
    transport.rotated_refresh_token = None;
    let initial = row(
        AccountCapability::ReadOnly,
        GrantCredential::Active(Zeroizing::new(REFRESH_TOKEN.to_owned())),
    );
    let store = GrantStore::new(&shared, Some(initial.clone()));
    let broker = broker(&transport, &store);
    assert!(matches!(
        complete(
            &broker,
            AuthorizationIntent::Upgrade(binding()),
            AccountCapability::Modify
        ),
        Err(BrokerError::MissingRefreshToken)
    ));
    assert!(matches!(
        complete(
            &broker,
            AuthorizationIntent::Connect,
            AccountCapability::Modify
        ),
        Err(BrokerError::AccountAlreadyConnected)
    ));
    assert_eq!(store.current(), Some(initial.clone()));
    assert!(transport.revoked_handles().is_empty());
    let pending = broker
        .begin_capability_authorization(
            REDIRECT,
            AccountCapability::Modify,
            AuthorizationIntent::Upgrade(binding()),
        )
        .unwrap();
    let callback = callback_for(&pending, AUTH_CODE);
    broker.clock.advance(600);
    assert!(matches!(
        ready(
            broker.complete_capability_authorization(pending.session_handle(), callback.as_str())
        ),
        Err(BrokerError::SessionUnknown)
    ));
    assert_eq!(store.current(), Some(initial));
}

// These responses reach TokenSuccess; read_delay expires access only after the
// application's deadline was minted, exercising the broker's later access gate.
fn post_success_failures(
    shared: &SharedEvents,
) -> Vec<(FakeTransport, BrokerError, &'static str, bool)> {
    let mut no_refresh = modern(shared);
    no_refresh.rotated_refresh_token = None;
    vec![
        (
            modern(shared).with_claims(Some(claims_for(SUBJECT, NOW - 1_000, NOW - 121))),
            BrokerError::IdentityUnverified,
            ROTATED_REFRESH_TOKEN,
            false,
        ),
        (
            modern(shared).with_claims(Some(claims_for(SUBJECT, NOW + 121, NOW + 3_600))),
            BrokerError::IdentityUnverified,
            ROTATED_REFRESH_TOKEN,
            false,
        ),
        (
            no_refresh,
            BrokerError::MissingRefreshToken,
            ACCESS_TOKEN,
            false,
        ),
        (
            modern(shared),
            BrokerError::MalformedResponse,
            ROTATED_REFRESH_TOKEN,
            true,
        ),
    ]
}

// Contract: only a definitive empty Connect snapshot licenses stranded-grant cleanup.
// Regression: freshness/missing-refresh/access failures run before custody lookup or drop safe cleanup handles.
#[test]
fn connect_post_success_failures_cleanup_only_under_definitive_empty_snapshot() {
    let shared = events();
    for (transport, empty_error, handle, expire_access) in post_success_failures(&shared) {
        // Cleanup failure must not mask the original terminal or start a revoke retry.
        let transport = transport.with_revoke_error(TokenTransportError::Transport);
        for (credential, unreadable) in [
            (None, false),
            (
                Some(GrantCredential::Active(Zeroizing::new(
                    REFRESH_TOKEN.to_owned(),
                ))),
                false,
            ),
            (Some(GrantCredential::Missing), false),
            (
                Some(GrantCredential::RevocationOnly(Zeroizing::new(
                    REFRESH_TOKEN.to_owned(),
                ))),
                false,
            ),
            (
                Some(GrantCredential::Active(Zeroizing::new(
                    REFRESH_TOKEN.to_owned(),
                ))),
                true,
            ),
        ] {
            let initial = credential.map(|credential| row(AccountCapability::ReadOnly, credential));
            let mut store = GrantStore::new(&shared, initial.clone());
            store.fail_reads.store(unreadable, Ordering::Relaxed);
            if expire_access {
                store.read_delay = Some((TestClock::default(), 3_600));
            }
            let broker = broker(&transport, &store);
            let prior_revokes = transport.revoked_handles().len();
            let expected = if unreadable {
                BrokerError::PersistenceFailed
            } else if initial.is_some() {
                BrokerError::AccountAlreadyConnected
            } else {
                empty_error
            };
            assert!(
                matches!(complete(&broker, AuthorizationIntent::Connect, AccountCapability::Modify), Err(error) if error == expected)
            );
            let revoked = transport.revoked_handles();
            let expected_handles = if !unreadable && initial.is_none() {
                vec![handle]
            } else {
                vec![]
            };
            assert_eq!(revoked[prior_revokes..], expected_handles);
            assert_eq!(store.current(), initial);
            assert!(store.legacy.is_empty());
        }
    }
}

// Contract: selected Upgrade never revokes a working/known grant on post-success rejection.
// Regression: Connect's empty-snapshot cleanup is applied to an Upgrade binding.
#[test]
fn upgrade_post_success_rejections_remain_non_revoking() {
    let shared = events();
    for (transport, expected, _, expire_access) in post_success_failures(&shared) {
        if expire_access {
            continue;
        } // This fixture expires access at Connect's post-exchange read.
        let initial = row(
            AccountCapability::ReadOnly,
            GrantCredential::Active(Zeroizing::new(REFRESH_TOKEN.to_owned())),
        );
        let store = GrantStore::new(&shared, Some(initial.clone()));
        let broker = broker(&transport, &store);
        assert!(
            matches!(complete(&broker, AuthorizationIntent::Upgrade(binding()), AccountCapability::Modify), Err(error) if error == expected)
        );
        assert_eq!(store.current(), Some(initial));
        assert!(transport.revoked_handles().is_empty());
        assert!(store.legacy.is_empty());
    }
}

// Contract: a pending empty-Connect cleanup holds the subject permit and cancellation releases it.
// Regression: concurrent mutation races grant-wide cleanup or a cancelled completion keeps its permit/handle.
#[test]
fn connect_cleanup_holds_permit_until_cancelled_and_handle_stays_consumed() {
    let shared = events();
    let gate = Arc::new(AtomicBool::new(false));
    let transport = modern(&shared)
        .with_claims(Some(claims_for(SUBJECT, NOW - 1_000, NOW - 121)))
        .with_gated_revoke(&gate);
    let store = GrantStore::new(&shared, None);
    let broker = broker(&transport, &store);
    let pending = broker
        .begin_capability_authorization(
            REDIRECT,
            AccountCapability::Modify,
            AuthorizationIntent::Connect,
        )
        .unwrap();
    let callback = callback_for(&pending, AUTH_CODE);
    let mut future = Box::pin(
        broker.complete_capability_authorization(pending.session_handle(), callback.as_str()),
    );
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
    assert!(matches!(
        ready(broker.refresh_capability_grant(&account("selected-account"), SUBJECT)),
        Err(BrokerError::Busy)
    ));
    assert_eq!(broker.delete_stored_tokens(SUBJECT), Err(BrokerError::Busy));
    drop(future);
    assert!(matches!(
        ready(broker.refresh_capability_grant(&account("selected-account"), SUBJECT)),
        Err(BrokerError::AccountUnknown)
    ));
    assert!(matches!(
        ready(
            broker.complete_capability_authorization(pending.session_handle(), callback.as_str())
        ),
        Err(BrokerError::SessionUnknown)
    ));
    assert!(store.current().is_none());
    assert!(store.legacy.is_empty());
}
