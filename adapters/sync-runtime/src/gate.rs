// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The account-identity gate and the gated bounded sync.
//!
//! Moved unchanged from the retired macOS sync composition: the gate hashes
//! the session's validated subject, compares it with the recorded identity,
//! and records it, preserves the mailbox, or clears it before any sync write.

use core::fmt;

use tersa_application::identity::{
    AccountIdentityHasher, AccountIdentityStore, AccountProfile, GateError, IdentityDecision,
    IdentityHash, IdentityReconcile, decide, normalize_subject,
};
use tersa_application::mailbox::{
    AccountId, MailboxStore, MailboxStoreError, Message, MessageId, RemoteMailbox,
    RemoteMailboxError,
};
use tersa_application::sync::{
    SyncCoordinator, SyncFailure, SyncFailureSource, SyncPolicy, SyncReport,
};

/// Reports why a gated sync stopped before or during the bounded sync.
#[derive(Debug)]
#[non_exhaustive]
pub enum GatedSyncError {
    /// The account-identity gate blocked the sync; no envelope was ever written.
    Gate(GateError),
    /// The gate passed but the bounded sync itself failed.
    Sync(SyncFailure),
}

impl GatedSyncError {
    /// Why the sync failed, without the "sync failed" framing, for a status
    /// line that already says so.
    #[must_use]
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Gate(_) => "the account identity could not be checked",
            Self::Sync(failure) => sync_cause(*failure),
        }
    }
}

impl fmt::Display for GatedSyncError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Gate(_) => formatter.write_str("the account-identity gate blocked the sync"),
            Self::Sync(failure) => write!(formatter, "the sync failed: {}", sync_cause(*failure)),
        }
    }
}

/// A content-free reason a reader can act on.
fn sync_cause(failure: SyncFailure) -> &'static str {
    match failure.category() {
        SyncFailureSource::Remote(RemoteMailboxError::AuthorizationRequired) => {
            "Gmail asks to sign in again"
        }
        SyncFailureSource::Remote(RemoteMailboxError::RateLimited) => {
            "Gmail's rate limit was reached; it retries later"
        }
        SyncFailureSource::Remote(RemoteMailboxError::Transport) => "Gmail could not be reached",
        SyncFailureSource::Remote(_) | SyncFailureSource::Protocol(_) => {
            "Gmail's mailbox changed during the sync, or its reply was invalid"
        }
        SyncFailureSource::Store(_) => "the local cache could not be written",
        SyncFailureSource::SingleFlight => "another sync is running",
        SyncFailureSource::IdentityFenced => "the account identity changed",
    }
}

impl std::error::Error for GatedSyncError {}

/// Reports why a gated single-message fetch failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum GatedFetchError {
    /// The account-identity gate could not run; nothing was written.
    Gate(GateError),
    /// The connected account is not the one the cache recorded, or none is
    /// recorded yet; only a sync may record or clear an identity, so nothing
    /// was written.
    Unverified,
    /// Gmail did not return the message.
    Remote(RemoteMailboxError),
    /// Caching the fetched message failed.
    Store(MailboxStoreError),
}

impl fmt::Display for GatedFetchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Gate(_) => formatter.write_str("the account-identity gate blocked the download"),
            Self::Unverified => {
                formatter.write_str("the account is not verified for this cache yet; sync first")
            }
            Self::Remote(error) => write!(formatter, "Gmail did not return the message ({error})"),
            Self::Store(_) => formatter.write_str("the downloaded message could not be cached"),
        }
    }
}

impl std::error::Error for GatedFetchError {}

/// Resolves the account-identity gate before any sync write.
///
/// Hashes the connected account's validated subject against the
/// installation-derived salt, compares it with the recorded hash for the fixed
/// account slot, and either records it (first connect), preserves the cached
/// mailbox (same account), or clears the cached mailbox and records the new hash
/// in one transaction (different account).
///
/// Fails closed: a hasher or store-read failure returns a [`GateError`] and the
/// caller must not proceed to any sync write. A read failure is never mistaken
/// for a first connect, so an unavailable identity can never re-baseline the
/// store to whoever happens to be connected. The subject itself is in-hand and
/// already validated (by the session at construction), so obtaining it is
/// infallible.
/// The most gate read-decide-record attempts before failing closed. Each lost
/// race means a concurrent cycle committed its own identity, which happens at most
/// once per racer, so a small bound converges in practice; exhaustion is a fault
/// (a livelock or tamper), never a reason to sync under an uncommitted identity.
const MAX_GATE_ATTEMPTS: u8 = 4;

async fn run_identity_gate<P, H, St>(
    account: &AccountId,
    profile: &P,
    hasher: &H,
    store: &St,
) -> Result<IdentityHash, GateError>
where
    P: AccountProfile,
    H: AccountIdentityHasher,
    St: AccountIdentityStore,
{
    let normalized = normalize_subject(profile.subject());
    let fresh = hasher
        .hash(account, &normalized)
        .map_err(GateError::Hasher)?;
    drop(normalized);
    // Read → decide → compare-and-set record, retried on a lost race. A concurrent
    // cycle (cross-process, or an undisciplined caller without the whole-cycle
    // permit) can change the recorded identity between our read and our record; the
    // store's CAS aborts that stale decision with `IdentityRaced`, and we re-read
    // and re-decide against the new state. It converges because a racer commits its
    // identity exactly once, so a bounded number of attempts always reaches a settled
    // state; exhaustion fails closed rather than syncing under an unknown one.
    for _ in 0..MAX_GATE_ATTEMPTS {
        let stored = store
            .load_identity(account)
            .await
            .map_err(GateError::Store)?;
        let action = match decide(stored.as_ref(), &fresh) {
            // The same account: preserve the cached mailbox, write nothing.
            IdentityDecision::Match => return Ok(fresh),
            IdentityDecision::FirstRecord => IdentityReconcile::RecordOnly,
            IdentityDecision::ClearAndRecord => IdentityReconcile::ClearMailboxAndRecord,
        };
        match store
            .reconcile_identity(account, &fresh, action, stored.as_ref())
            .await
        {
            // The gate returns the committed hash as the fence for the sync: every
            // subsequent mailbox write re-checks the recorded identity equals it.
            Ok(()) => return Ok(fresh),
            // A racing cycle recorded a different identity under us — fall through to
            // the next attempt, which re-reads and re-decides against the new state
            // (it may now be Match, or a clear).
            Err(MailboxStoreError::IdentityRaced) => {}
            Err(other) => return Err(GateError::Store(other)),
        }
    }
    // Persistently lost the race: never sync under an identity we could not commit.
    Err(GateError::Store(MailboxStoreError::IdentityRaced))
}

/// Runs the account-identity gate, then the bounded recent sync — over one
/// account session.
///
/// `session` exposes BOTH the profile-fetch surface (`AccountProfile`) and the
/// mailbox-read surface (`RemoteMailbox`), so a single credential necessarily
/// backs the identity check and the sync it guards. This makes the gate's core
/// invariant — the account whose identity is checked is the account whose mail is
/// written — a type-level guarantee, not a caller contract: a caller cannot check
/// one Google user's identity and then sync a different user's mail, because there
/// is only one session (hence one access token) to build both surfaces from. The
/// concrete [`GmailSession`](crate::GmailSession) holds a single access token and
/// derives both surfaces from it.
///
/// The gate borrows the session and completes first; only then is the session
/// moved into a [`SyncCoordinator`] as the remote and the sync driven. Because
/// the gate runs to a successful completion before the coordinator exists, a
/// blocked gate means `sync_recent` — and therefore every mailbox write — never
/// runs.
///
/// The identity hash is recorded (or the mailbox cleared and the hash recorded)
/// inside the gate, committed BEFORE any message is synced. So a "messages present
/// but identity absent" state — which the missing-row-is-first-connect branch
/// would misread — is unreachable without tampering with the encrypted store
/// itself, which already requires the database key.
///
/// # Concurrency
///
/// This function requires external per-account serialization across the WHOLE
/// gate-to-write cycle and MUST NOT be called concurrently for the same account
/// slot. The gate's load/decide/record and the sync it guards are distinct steps
/// (each call builds its own [`SyncCoordinator`], whose single-flight set is
/// per-call, not shared), so two overlapping cycles could interleave a stale
/// record over a committed one and let two accounts' mail coexist. Enforcement is
/// NOT provided here: it belongs to the caller (the app holds an exclusive
/// [`InstallationLock`](crate::InstallationLock) for the whole command and runs
/// one flow at a time; a future in-process concurrent caller must add a
/// per-account cycle lock) plus an
/// in-transaction identity fence that re-checks the recorded hash inside every
/// mailbox-write transaction. Callers without that discipline break the invariant.
///
/// # Errors
///
/// Returns [`GatedSyncError::Gate`] when the identity gate blocks the sync (no
/// write occurred) and [`GatedSyncError::Sync`] when the bounded sync fails.
pub async fn gated_sync<S, St, H>(
    account: &AccountId,
    session: S,
    hasher: &H,
    store: St,
    policy: SyncPolicy,
) -> Result<SyncReport, GatedSyncError>
where
    S: AccountProfile + RemoteMailbox,
    St: MailboxStore + AccountIdentityStore,
    H: AccountIdentityHasher,
{
    let fence = run_identity_gate(account, &session, hasher, &store)
        .await
        .map_err(GatedSyncError::Gate)?;
    let coordinator = SyncCoordinator::new(session, store);
    coordinator
        .sync_recent(account, policy, &fence)
        .await
        .map_err(GatedSyncError::Sync)
}

/// Downloads one complete message after a read-only identity check, and
/// caches it.
///
/// Unlike [`gated_sync`], this gate never records or clears an identity: it
/// proceeds only when the connected account's hash already equals the
/// recorded one, and otherwise returns [`GatedFetchError::Unverified`] before
/// any download. The matched hash fences the cache write, which re-checks the
/// recorded identity inside its transaction, so a message can never be stored
/// under a different account. The message is cached only when its envelope
/// row still exists; it is returned either way.
///
/// # Concurrency
///
/// Because its gate only reads and its single write is fenced, this function
/// may run concurrently with other fetches and with one [`gated_sync`] cycle
/// for the same account: if that cycle clears and re-records the identity,
/// the fenced write aborts instead of caching under the new identity.
///
/// # Errors
///
/// Returns [`GatedFetchError::Gate`] when the identity cannot be read or
/// hashed and [`GatedFetchError::Unverified`] when it does not match (no
/// write occurred in either case), [`GatedFetchError::Remote`] when Gmail
/// fails, and [`GatedFetchError::Store`] when caching fails.
pub async fn gated_fetch<S, St, H>(
    account: &AccountId,
    session: S,
    hasher: &H,
    store: St,
    message_id: &MessageId,
) -> Result<Message, GatedFetchError>
where
    S: AccountProfile + RemoteMailbox,
    St: MailboxStore + AccountIdentityStore,
    H: AccountIdentityHasher,
{
    let normalized = normalize_subject(session.subject());
    let fresh = hasher
        .hash(account, &normalized)
        .map_err(|error| GatedFetchError::Gate(GateError::Hasher(error)))?;
    drop(normalized);
    let stored = store
        .load_identity(account)
        .await
        .map_err(|error| GatedFetchError::Gate(GateError::Store(error)))?;
    if decide(stored.as_ref(), &fresh) != IdentityDecision::Match {
        return Err(GatedFetchError::Unverified);
    }
    let message = session
        .fetch_message(account, message_id)
        .await
        .map_err(GatedFetchError::Remote)?;
    store
        .cache_message_if_present(account, &message, &fresh)
        .await
        .map_err(GatedFetchError::Store)?;
    Ok(message)
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "tests construct valid fixtures")]

    use std::pin::pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll, Waker};

    use tersa_application::identity::{
        AccountIdentityHasher, AccountIdentityStore, AccountProfile, GateError, HasherError,
        IdentityHash, IdentityReconcile,
    };
    use tersa_application::mailbox::{
        AccountId, BoxFuture, MailboxReader, MailboxStore, MailboxStoreError, Message,
        MessageEnvelope, MessageId, Page, PageSize, PageToken, RemoteMailbox, RemoteMailboxError,
        StoreLimit, ThreadId,
    };
    use tersa_application::sync::SyncPolicy;
    use tersa_application::token::AccountSubject;
    use zeroize::Zeroizing;

    use super::{GatedFetchError, GatedSyncError, gated_fetch, gated_sync, run_identity_gate};

    fn subject(value: &str) -> AccountSubject {
        AccountSubject::from_raw_for_test(Zeroizing::new(value.to_owned()))
    }

    fn account() -> AccountId {
        AccountId::new("account-a").unwrap()
    }

    fn drive<T>(future: impl Future<Output = T>) -> T {
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        let mut future = pin!(future);
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("composition future must complete synchronously"),
        }
    }

    struct FakeProfile(AccountSubject);

    impl AccountProfile for FakeProfile {
        fn subject(&self) -> &AccountSubject {
            &self.0
        }
    }

    struct FakeHasher {
        output: Result<[u8; 32], HasherError>,
        seen: Mutex<Vec<String>>,
    }

    impl FakeHasher {
        fn ok(bytes: [u8; 32]) -> Self {
            Self {
                output: Ok(bytes),
                seen: Mutex::new(Vec::new()),
            }
        }
        fn failing() -> Self {
            Self {
                output: Err(HasherError::Unavailable),
                seen: Mutex::new(Vec::new()),
            }
        }
    }

    impl AccountIdentityHasher for FakeHasher {
        fn hash(
            &self,
            _account: &AccountId,
            normalized: &Zeroizing<String>,
        ) -> Result<IdentityHash, HasherError> {
            self.seen
                .lock()
                .unwrap()
                .push(normalized.as_str().to_owned());
            self.output.map(IdentityHash::from_bytes)
        }
    }

    /// Shared log of the identity-record actions a gate applied, readable after the
    /// store is moved into `gated_sync`.
    type IdentityReconcileLog = Arc<Mutex<Vec<([u8; 32], IdentityReconcile)>>>;

    #[derive(Default)]
    struct FakeStore {
        stored: Mutex<Option<[u8; 32]>>,
        load_error: bool,
        reconcile_error: bool,
        identity_reconciles: IdentityReconcileLog,
        sync_reconciles: Arc<AtomicUsize>,
        sync_fences: Arc<Mutex<Vec<[u8; 32]>>>,
        // When set, the next `reconcile_identity` simulates a concurrent cycle
        // having recorded this identity first (then unsets), so the caller's
        // compare-and-set loses the race once and must re-read and re-decide.
        race_next: Mutex<Option<[u8; 32]>>,
    }

    impl FakeStore {
        fn with_stored(bytes: [u8; 32]) -> Self {
            Self {
                stored: Mutex::new(Some(bytes)),
                ..Self::default()
            }
        }
        /// A store whose first `reconcile_identity` loses the compare-and-set to a
        /// concurrent cycle that recorded `bytes`, exercising the gate's retry.
        fn racing_first_write_to(bytes: [u8; 32]) -> Self {
            Self {
                race_next: Mutex::new(Some(bytes)),
                ..Self::default()
            }
        }
        fn identity_reconciles(&self) -> Vec<([u8; 32], IdentityReconcile)> {
            self.identity_reconciles.lock().unwrap().clone()
        }
        /// A shared handle to the recorded reconcile actions, kept after the store
        /// is moved into `gated_sync`, so a test can prove a retried gate re-decided.
        fn identity_reconciles_probe(&self) -> IdentityReconcileLog {
            Arc::clone(&self.identity_reconciles)
        }
        /// A shared handle to the sync-write counter, kept after the store is
        /// moved into `gated_sync`, so a test can prove the write did or did not run.
        fn sync_probe(&self) -> Arc<AtomicUsize> {
            Arc::clone(&self.sync_reconciles)
        }
        /// A shared handle to the fences threaded into the sync writes, so a test
        /// can prove the gate handed the freshly-committed identity hash to the
        /// coordinator rather than a stale, constant, or unrelated value.
        fn fence_probe(&self) -> Arc<Mutex<Vec<[u8; 32]>>> {
            Arc::clone(&self.sync_fences)
        }
    }

    impl AccountIdentityStore for FakeStore {
        fn load_identity<'a>(
            &'a self,
            _account: &'a AccountId,
        ) -> BoxFuture<'a, Result<Option<IdentityHash>, MailboxStoreError>> {
            Box::pin(async move {
                if self.load_error {
                    return Err(MailboxStoreError::Storage);
                }
                Ok(self.stored.lock().unwrap().map(IdentityHash::from_bytes))
            })
        }

        fn reconcile_identity<'a>(
            &'a self,
            _account: &'a AccountId,
            fresh: &'a IdentityHash,
            action: IdentityReconcile,
            expected: Option<&'a IdentityHash>,
        ) -> BoxFuture<'a, Result<(), MailboxStoreError>> {
            let expected = expected.map(|hash| *hash.as_bytes());
            Box::pin(async move {
                // A concurrent cycle records its identity just before our read, once.
                if let Some(winner) = self.race_next.lock().unwrap().take() {
                    *self.stored.lock().unwrap() = Some(winner);
                }
                // Compare-and-set against the identity the gate observed.
                if *self.stored.lock().unwrap() != expected {
                    return Err(MailboxStoreError::IdentityRaced);
                }
                self.identity_reconciles
                    .lock()
                    .unwrap()
                    .push((*fresh.as_bytes(), action));
                if self.reconcile_error {
                    return Err(MailboxStoreError::Storage);
                }
                *self.stored.lock().unwrap() = Some(*fresh.as_bytes());
                Ok(())
            })
        }
    }

    impl MailboxReader for FakeStore {
        fn list_envelopes<'a>(
            &'a self,
            _account: &'a AccountId,
            _limit: StoreLimit,
        ) -> BoxFuture<'a, Result<Vec<MessageEnvelope>, MailboxStoreError>> {
            Box::pin(async { Ok(Vec::new()) })
        }
        fn thread_envelopes<'a>(
            &'a self,
            _account: &'a AccountId,
            _thread_id: &'a ThreadId,
            _limit: StoreLimit,
        ) -> BoxFuture<'a, Result<Vec<MessageEnvelope>, MailboxStoreError>> {
            Box::pin(async { Ok(Vec::new()) })
        }
        fn get_message<'a>(
            &'a self,
            _account: &'a AccountId,
            _message_id: &'a MessageId,
        ) -> BoxFuture<'a, Result<Option<Message>, MailboxStoreError>> {
            Box::pin(async { Ok(None) })
        }
    }

    impl MailboxStore for FakeStore {
        fn mark_message_read<'a>(
            &'a self,
            _account: &'a AccountId,
            _message_id: &'a MessageId,
        ) -> BoxFuture<'a, Result<(), MailboxStoreError>> {
            Box::pin(async { Ok(()) })
        }
        fn mark_thread_read<'a>(
            &'a self,
            _account: &'a AccountId,
            _thread_id: &'a ThreadId,
        ) -> BoxFuture<'a, Result<(), MailboxStoreError>> {
            Box::pin(async { Ok(()) })
        }
        fn upsert_envelopes<'a>(
            &'a self,
            _account: &'a AccountId,
            _envelopes: &'a [MessageEnvelope],
        ) -> BoxFuture<'a, Result<(), MailboxStoreError>> {
            Box::pin(async { Ok(()) })
        }
        fn put_message<'a>(
            &'a self,
            _account: &'a AccountId,
            _message: &'a Message,
        ) -> BoxFuture<'a, Result<(), MailboxStoreError>> {
            Box::pin(async { Ok(()) })
        }
        fn reconcile_recent_envelopes<'a>(
            &'a self,
            _account: &'a AccountId,
            _envelopes: &'a [MessageEnvelope],
            _keep_limit: StoreLimit,
            fence: &'a IdentityHash,
        ) -> BoxFuture<'a, Result<Vec<MessageId>, MailboxStoreError>> {
            self.sync_reconciles.fetch_add(1, Ordering::SeqCst);
            self.sync_fences.lock().unwrap().push(*fence.as_bytes());
            Box::pin(async { Ok(Vec::new()) })
        }
        fn cache_message_if_present<'a>(
            &'a self,
            _account: &'a AccountId,
            _message: &'a Message,
            fence: &'a IdentityHash,
        ) -> BoxFuture<'a, Result<bool, MailboxStoreError>> {
            self.sync_fences.lock().unwrap().push(*fence.as_bytes());
            Box::pin(async { Ok(true) })
        }
        fn message<'a>(
            &'a self,
            _account: &'a AccountId,
            _message_id: &'a MessageId,
        ) -> BoxFuture<'a, Result<Option<Message>, MailboxStoreError>> {
            Box::pin(async { Ok(None) })
        }
    }

    // One session object exposes both the profile and the mailbox surface, so a
    // test cannot accidentally pair one account's profile with another's mail —
    // the same constraint `gated_sync` now imposes on production callers.
    impl RemoteMailbox for FakeProfile {
        fn list_recent_envelopes<'a>(
            &'a self,
            _account: &'a AccountId,
            _size: PageSize,
            _page_token: Option<&'a PageToken>,
        ) -> BoxFuture<'a, Result<Page<MessageEnvelope>, RemoteMailboxError>> {
            Box::pin(async { Ok(Page::new(Vec::new(), None)) })
        }
        fn fetch_message<'a>(
            &'a self,
            _account: &'a AccountId,
            _message_id: &'a MessageId,
        ) -> BoxFuture<'a, Result<Message, RemoteMailboxError>> {
            Box::pin(async { Err(RemoteMailboxError::NotFound) })
        }
    }

    fn run_gate(
        profile: &FakeProfile,
        hasher: &FakeHasher,
        store: &FakeStore,
    ) -> Result<(), GateError> {
        // Existing gate tests assert only the reconcile side effects, not the
        // returned fence, so collapse the fence to `()` for them; the fence path
        // itself is exercised where `gated_sync` threads it into the writers.
        drive(run_identity_gate(&account(), profile, hasher, store)).map(|_fence| ())
    }

    #[test]
    fn first_connect_records_only() {
        let store = FakeStore::default();
        run_gate(
            &FakeProfile(subject("user-sub")),
            &FakeHasher::ok([5; 32]),
            &store,
        )
        .unwrap();
        assert_eq!(
            store.identity_reconciles(),
            vec![([5; 32], IdentityReconcile::RecordOnly)]
        );
    }

    #[test]
    fn same_account_preserves_the_store() {
        let store = FakeStore::with_stored([5; 32]);
        run_gate(
            &FakeProfile(subject("user-sub")),
            &FakeHasher::ok([5; 32]),
            &store,
        )
        .unwrap();
        // A match writes nothing.
        assert!(store.identity_reconciles().is_empty());
    }

    #[test]
    fn different_account_clears_and_records() {
        let store = FakeStore::with_stored([5; 32]);
        run_gate(
            &FakeProfile(subject("other-sub")),
            &FakeHasher::ok([9; 32]),
            &store,
        )
        .unwrap();
        assert_eq!(
            store.identity_reconciles(),
            vec![([9; 32], IdentityReconcile::ClearMailboxAndRecord)]
        );
    }

    #[test]
    fn a_lost_first_record_race_re_decides_and_clears_instead_of_re_recording() {
        // A concurrent cycle records a DIFFERENT account's identity ([1;32]) between
        // this gate's read and its compare-and-set. The gate must not blindly retry
        // its stale first-record (which would leave the other account's cached mail
        // in place under the new identity); it re-reads, re-decides ClearAndRecord,
        // and only then records — the cross-process backstop the permit cannot give.
        let store = FakeStore::racing_first_write_to([1; 32]);
        let reconciles = store.identity_reconciles_probe();
        let report = drive(gated_sync(
            &account(),
            FakeProfile(subject("user-sub")),
            &FakeHasher::ok([9; 32]),
            store,
            policy(),
        ));
        assert!(report.is_ok());
        // The raced RecordOnly recorded nothing; only the re-decided clear did.
        assert_eq!(
            *reconciles.lock().unwrap(),
            vec![([9; 32], IdentityReconcile::ClearMailboxAndRecord)]
        );
    }

    #[test]
    fn a_persistently_lost_race_fails_closed_without_syncing() {
        // If every attempt loses the race, the gate exhausts its bounded retries and
        // fails closed rather than syncing under an identity it could not commit.
        struct AlwaysRacingStore;
        impl AccountIdentityStore for AlwaysRacingStore {
            fn load_identity<'a>(
                &'a self,
                _account: &'a AccountId,
            ) -> BoxFuture<'a, Result<Option<IdentityHash>, MailboxStoreError>> {
                Box::pin(async { Ok(None) })
            }
            fn reconcile_identity<'a>(
                &'a self,
                _account: &'a AccountId,
                _fresh: &'a IdentityHash,
                _action: IdentityReconcile,
                _expected: Option<&'a IdentityHash>,
            ) -> BoxFuture<'a, Result<(), MailboxStoreError>> {
                Box::pin(async { Err(MailboxStoreError::IdentityRaced) })
            }
        }
        let hasher = FakeHasher::ok([9; 32]);
        let error = drive(run_identity_gate(
            &account(),
            &FakeProfile(subject("user-sub")),
            &hasher,
            &AlwaysRacingStore,
        ))
        .unwrap_err();
        assert!(matches!(
            error,
            GateError::Store(MailboxStoreError::IdentityRaced)
        ));
    }

    #[test]
    fn subject_is_normalized_before_hashing() {
        let store = FakeStore::default();
        let hasher = FakeHasher::ok([5; 32]);
        drive(run_identity_gate(
            &account(),
            &FakeProfile(subject("  Sub-XYZ-123  ")),
            &hasher,
            &store,
        ))
        .unwrap();
        // Trim only — a `sub` is case-sensitive, so casing must be preserved.
        assert_eq!(hasher.seen.lock().unwrap().as_slice(), ["Sub-XYZ-123"]);
    }

    #[test]
    fn a_hasher_failure_fails_closed() {
        let store = FakeStore::with_stored([5; 32]);
        let result = run_gate(
            &FakeProfile(subject("user-sub")),
            &FakeHasher::failing(),
            &store,
        );
        assert_eq!(result, Err(GateError::Hasher(HasherError::Unavailable)));
        assert!(store.identity_reconciles().is_empty());
    }

    #[test]
    fn a_load_failure_fails_closed_and_never_rebaselines() {
        let store = FakeStore {
            stored: Mutex::new(Some([5; 32])),
            load_error: true,
            ..FakeStore::default()
        };
        let result = run_gate(
            &FakeProfile(subject("user-sub")),
            &FakeHasher::ok([9; 32]),
            &store,
        );
        assert_eq!(result, Err(GateError::Store(MailboxStoreError::Storage)));
        // An unreadable identity must never be treated as a first connect.
        assert!(store.identity_reconciles().is_empty());
    }

    #[test]
    fn a_reconcile_failure_surfaces_as_a_store_error() {
        let store = FakeStore {
            reconcile_error: true,
            ..FakeStore::default()
        };
        let result = run_gate(
            &FakeProfile(subject("user-sub")),
            &FakeHasher::ok([9; 32]),
            &store,
        );
        assert_eq!(result, Err(GateError::Store(MailboxStoreError::Storage)));
    }

    fn policy() -> SyncPolicy {
        SyncPolicy::new(
            PageSize::new(10).unwrap(),
            1,
            StoreLimit::new(10).unwrap(),
            StoreLimit::new(1).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn a_blocked_gate_never_reaches_the_sync_write() {
        let store = FakeStore::with_stored([5; 32]);
        let sync_writes = store.sync_probe();
        let error = drive(gated_sync(
            &account(),
            FakeProfile(subject("user-sub")),
            &FakeHasher::failing(),
            store,
            policy(),
        ))
        .unwrap_err();
        assert!(matches!(
            error,
            GatedSyncError::Gate(GateError::Hasher(HasherError::Unavailable))
        ));
        // The gate blocked before the coordinator existed: no sync write ran.
        assert_eq!(sync_writes.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_passing_gate_runs_the_bounded_sync() {
        let store = FakeStore::default();
        let sync_writes = store.sync_probe();
        let sync_fences = store.fence_probe();
        let report = drive(gated_sync(
            &account(),
            FakeProfile(subject("user-sub")),
            &FakeHasher::ok([5; 32]),
            store,
            policy(),
        ));
        assert!(report.is_ok());
        // The gate passed, so the bounded sync ran exactly once.
        assert_eq!(sync_writes.load(Ordering::SeqCst), 1);
        // ...and it received the freshly-committed identity hash as its fence, so
        // the handoff is behaviorally verified — not merely that a write happened.
        // First connect: the fence is the hasher output the gate just recorded.
        assert_eq!(*sync_fences.lock().unwrap(), vec![[5; 32]]);
    }

    #[test]
    fn a_matching_gate_threads_the_verified_hash_as_the_fence() {
        // Same account: the gate writes nothing, but the sync still runs and its
        // fence is the verified identity hash the store already held.
        let store = FakeStore::with_stored([5; 32]);
        let sync_fences = store.fence_probe();
        let report = drive(gated_sync(
            &account(),
            FakeProfile(subject("user-sub")),
            &FakeHasher::ok([5; 32]),
            store,
            policy(),
        ));
        assert!(report.is_ok());
        assert_eq!(*sync_fences.lock().unwrap(), vec![[5; 32]]);
    }

    #[test]
    fn a_changed_account_threads_the_newly_committed_hash_as_the_fence() {
        // A different account connects: the gate clears and records the NEW hash,
        // and the fence handed to the sync must be that new hash, never the prior
        // one — otherwise a stale fence could match the wrong recorded identity.
        let store = FakeStore::with_stored([1; 32]);
        let sync_fences = store.fence_probe();
        let report = drive(gated_sync(
            &account(),
            FakeProfile(subject("other-sub")),
            &FakeHasher::ok([9; 32]),
            store,
            policy(),
        ));
        assert!(report.is_ok());
        assert_eq!(*sync_fences.lock().unwrap(), vec![[9; 32]]);
    }

    /// A session whose mailbox returns one fixed message and counts
    /// downloads.
    struct FetchingProfile(AccountSubject, Arc<AtomicUsize>);

    fn fetching(value: &str) -> (FetchingProfile, Arc<AtomicUsize>) {
        let downloads = Arc::new(AtomicUsize::new(0));
        (
            FetchingProfile(subject(value), Arc::clone(&downloads)),
            downloads,
        )
    }

    impl AccountProfile for FetchingProfile {
        fn subject(&self) -> &AccountSubject {
            &self.0
        }
    }

    impl RemoteMailbox for FetchingProfile {
        fn list_recent_envelopes<'a>(
            &'a self,
            _account: &'a AccountId,
            _size: PageSize,
            _page_token: Option<&'a PageToken>,
        ) -> BoxFuture<'a, Result<Page<MessageEnvelope>, RemoteMailboxError>> {
            Box::pin(async { Ok(Page::new(Vec::new(), None)) })
        }
        fn fetch_message<'a>(
            &'a self,
            _account: &'a AccountId,
            message_id: &'a MessageId,
        ) -> BoxFuture<'a, Result<Message, RemoteMailboxError>> {
            self.1.fetch_add(1, Ordering::SeqCst);
            let envelope = MessageEnvelope::new(
                message_id.clone(),
                ThreadId::new("thread").unwrap(),
                tersa_application::mailbox::HeaderText::new("from").unwrap(),
                tersa_application::mailbox::HeaderText::new("subject").unwrap(),
                tersa_application::mailbox::HeaderText::new("preview").unwrap(),
                tersa_application::mailbox::UnixTimestampMillis::new(1).unwrap(),
                true,
            );
            let content =
                tersa_domain::mailbox::MessageContent::new(b"Subject: s\r\n\r\nbody".to_vec())
                    .unwrap();
            Box::pin(async move { Ok(Message::new(envelope, content)) })
        }
    }

    #[test]
    fn a_failing_gate_never_downloads_or_caches() {
        let store = FakeStore::with_stored([5; 32]);
        let cache_fences = store.fence_probe();
        let (profile, downloads) = fetching("user-sub");
        let error = drive(gated_fetch(
            &account(),
            profile,
            &FakeHasher::failing(),
            store,
            &MessageId::new("m1").unwrap(),
        ))
        .unwrap_err();
        assert!(matches!(error, GatedFetchError::Gate(_)));
        assert_eq!(downloads.load(Ordering::SeqCst), 0);
        assert!(cache_fences.lock().unwrap().is_empty());
    }

    #[test]
    fn an_unverified_account_never_downloads_records_or_clears() {
        for store in [FakeStore::default(), FakeStore::with_stored([1; 32])] {
            let reconciles = store.identity_reconciles_probe();
            let cache_fences = store.fence_probe();
            let (profile, downloads) = fetching("other-sub");
            let error = drive(gated_fetch(
                &account(),
                profile,
                &FakeHasher::ok([9; 32]),
                store,
                &MessageId::new("m1").unwrap(),
            ))
            .unwrap_err();
            assert!(matches!(error, GatedFetchError::Unverified));
            assert_eq!(downloads.load(Ordering::SeqCst), 0);
            assert!(reconciles.lock().unwrap().is_empty(), "no identity write");
            assert!(cache_fences.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn a_matching_account_downloads_and_caches_under_its_fence() {
        let store = FakeStore::with_stored([5; 32]);
        let cache_fences = store.fence_probe();
        let (profile, downloads) = fetching("user-sub");
        let message = drive(gated_fetch(
            &account(),
            profile,
            &FakeHasher::ok([5; 32]),
            store,
            &MessageId::new("m1").unwrap(),
        ))
        .unwrap();
        assert_eq!(message.content().as_bytes(), b"Subject: s\r\n\r\nbody");
        assert_eq!(downloads.load(Ordering::SeqCst), 1);
        assert_eq!(*cache_fences.lock().unwrap(), vec![[5; 32]]);
    }

    #[test]
    fn a_remote_failure_is_reported_after_the_gate() {
        let error = drive(gated_fetch(
            &account(),
            FakeProfile(subject("user-sub")),
            &FakeHasher::ok([5; 32]),
            FakeStore::with_stored([5; 32]),
            &MessageId::new("m1").unwrap(),
        ))
        .unwrap_err();
        assert!(matches!(
            error,
            GatedFetchError::Remote(RemoteMailboxError::NotFound)
        ));
    }

    #[test]
    fn an_unreadable_identity_blocks_the_download() {
        let store = FakeStore {
            load_error: true,
            ..FakeStore::with_stored([5; 32])
        };
        let (profile, downloads) = fetching("user-sub");
        let error = drive(gated_fetch(
            &account(),
            profile,
            &FakeHasher::ok([5; 32]),
            store,
            &MessageId::new("m1").unwrap(),
        ))
        .unwrap_err();
        assert!(matches!(error, GatedFetchError::Gate(GateError::Store(_))));
        assert_eq!(downloads.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn sync_errors_name_a_content_free_cause() {
        use tersa_application::sync::{SyncFailure, SyncFailureSource, SyncProtocolError};

        let message =
            |source| GatedSyncError::Sync(SyncFailure::from_source_for_test(source)).to_string();
        assert_eq!(
            message(SyncFailureSource::Remote(RemoteMailboxError::Transport)),
            "the sync failed: Gmail could not be reached"
        );
        assert_eq!(
            message(SyncFailureSource::Protocol(
                SyncProtocolError::ConflictingDuplicate
            )),
            "the sync failed: Gmail's mailbox changed during the sync, or its reply was invalid"
        );
        assert_eq!(
            message(SyncFailureSource::IdentityFenced),
            "the sync failed: the account identity changed"
        );
    }
}
