// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Bounded recent-snapshot synchronization without a runtime or background work.
// Rust guideline compliant 1.0.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Mutex;

use tersa_domain::mailbox::AccountId;

use crate::identity::IdentityHash;
#[cfg(test)]
use crate::mailbox::MailboxReader;
use crate::mailbox::{
    BoxFuture, MailboxStore, MailboxStoreError, MessageId, PageSize, RemoteMailbox,
    RemoteMailboxError, StoreLimit,
};

/// The largest accepted number of remote pages in one recent snapshot.
pub const MAX_SNAPSHOT_PAGES: u16 = 1_000;

/// Reports an invalid content-free sync policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncPolicyError {
    /// No page would be requested.
    ZeroPageLimit,
    /// The requested page count exceeds the fixed defensive cap.
    PageLimitTooLarge,
    /// The full-message limit exceeds the envelope keep limit.
    BodyLimitExceedsKeepLimit,
}

impl fmt::Display for SyncPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ZeroPageLimit => "the snapshot page limit must be non-zero",
            Self::PageLimitTooLarge => "the snapshot page limit exceeds its maximum",
            Self::BodyLimitExceedsKeepLimit => {
                "the full-message limit must not exceed the envelope keep limit"
            }
        })
    }
}
impl std::error::Error for SyncPolicyError {}

/// Holds validated, bounded recent-snapshot and body-cache limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyncPolicy {
    page_size: PageSize,
    max_pages: u16,
    keep_limit: StoreLimit,
    full_body_limit: StoreLimit,
}

impl SyncPolicy {
    /// Creates a bounded sync policy.
    ///
    /// # Errors
    ///
    /// Returns [`SyncPolicyError`] when page or body limits are inconsistent.
    pub fn new(
        page_size: PageSize,
        max_pages: u16,
        keep_limit: StoreLimit,
        full_body_limit: StoreLimit,
    ) -> Result<Self, SyncPolicyError> {
        if max_pages == 0 {
            return Err(SyncPolicyError::ZeroPageLimit);
        }
        if max_pages > MAX_SNAPSHOT_PAGES {
            return Err(SyncPolicyError::PageLimitTooLarge);
        }
        if full_body_limit.get() > keep_limit.get() {
            return Err(SyncPolicyError::BodyLimitExceedsKeepLimit);
        }
        Ok(Self {
            page_size,
            max_pages,
            keep_limit,
            full_body_limit,
        })
    }
    /// Returns the provider request size.
    #[must_use]
    pub fn page_size(self) -> PageSize {
        self.page_size
    }
    /// Returns the finite remote page cap.
    #[must_use]
    pub fn max_pages(self) -> u16 {
        self.max_pages
    }
    /// Returns the deterministic local envelope keep limit.
    #[must_use]
    pub fn keep_limit(self) -> StoreLimit {
        self.keep_limit
    }
    /// Returns the maximum number of survivor bodies to cache.
    #[must_use]
    pub fn full_body_limit(self) -> StoreLimit {
        self.full_body_limit
    }
}

/// Categorizes a sync failure without exposing mailbox content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncFailureSource {
    /// The remote mailbox operation failed.
    Remote(RemoteMailboxError),
    /// The local mailbox store operation failed.
    Store(MailboxStoreError),
    /// A remote response violated this bounded protocol.
    Protocol(SyncProtocolError),
    /// Another sync is already active for this account.
    SingleFlight,
    /// The in-transaction identity fence aborted a write: the recorded account
    /// identity changed (or vanished) between the gate and this write, so a stale
    /// cycle's envelopes or bodies were rolled back rather than persisted under a
    /// different account.
    IdentityFenced,
}

/// Names a content-free bounded-sync protocol violation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncProtocolError {
    /// A provider returned more items than requested.
    OversizedPage,
    /// A continuation token repeated during the snapshot.
    RepeatedContinuation,
    /// The same message identifier had conflicting envelopes.
    ConflictingDuplicate,
    /// A fetched full message did not match the requested survivor.
    MismatchedFetchedMessage,
}

/// Records bounded sync progress using counts only.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SyncProgress {
    /// Number of list requests completed.
    pub pages: u16,
    /// Number of unique snapshot envelopes collected.
    pub envelopes: u16,
    /// Number of survivor body fetch attempts completed.
    pub body_requests: u16,
    /// Number of full messages cached.
    pub bodies_cached: u16,
    /// Number of missing or displaced survivor bodies skipped.
    pub bodies_skipped: u16,
    /// Whether collection stopped at the recent-snapshot keep limit.
    pub snapshot_truncated: bool,
}

/// Returns a structured failure with no mailbox identifiers or content.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct SyncFailure {
    source: SyncFailureSource,
    progress: SyncProgress,
}
impl SyncFailure {
    /// Returns the failure category.
    #[must_use]
    pub fn category(self) -> SyncFailureSource {
        self.source
    }
    /// Returns progress completed before the failure.
    #[must_use]
    pub fn progress(self) -> SyncProgress {
        self.progress
    }
    /// Constructs a failure from a source for cross-crate tests (e.g. the sync
    /// worker's status mapping), which cannot otherwise build a `SyncFailure`
    /// because its fields are private. Never compiled into production.
    #[cfg(any(test, feature = "test-util"))]
    #[must_use]
    pub fn from_source_for_test(source: SyncFailureSource) -> Self {
        Self {
            source,
            progress: SyncProgress::default(),
        }
    }
}
impl fmt::Debug for SyncFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SyncFailure")
            .field("source", &self.source)
            .field("progress", &self.progress)
            .finish()
    }
}
impl fmt::Display for SyncFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded mailbox synchronization failed")
    }
}
impl std::error::Error for SyncFailure {}

/// Reports a completed bounded sync using counts only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyncReport {
    progress: SyncProgress,
}
impl SyncReport {
    /// Returns the final bounded progress counters.
    #[must_use]
    pub fn progress(self) -> SyncProgress {
        self.progress
    }
}

/// Coordinates lazy, bounded recent-snapshot cache refreshes.
pub struct SyncCoordinator<R, S> {
    remote: R,
    store: S,
    active_accounts: Mutex<HashSet<AccountId>>,
}

impl<R, S> fmt::Debug for SyncCoordinator<R, S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let active_accounts = self
            .active_accounts
            .lock()
            .map(|accounts| accounts.len())
            .unwrap_or(0);
        formatter
            .debug_struct("SyncCoordinator")
            .field("active_account_count", &active_accounts)
            .finish_non_exhaustive()
    }
}

impl<R, S> SyncCoordinator<R, S>
where
    R: RemoteMailbox,
    S: MailboxStore,
{
    /// Creates a coordinator over inward remote and store ports.
    #[must_use]
    pub fn new(remote: R, store: S) -> Self {
        Self {
            remote,
            store,
            active_accounts: Mutex::new(HashSet::new()),
        }
    }

    /// Lazily synchronizes one bounded recent snapshot for `account`.
    ///
    /// Dropping the returned future stops subsequent work and releases the
    /// account's single-flight claim. This method performs no detached work.
    pub fn sync_recent<'a>(
        &'a self,
        account: &'a AccountId,
        policy: SyncPolicy,
        fence: &'a IdentityHash,
    ) -> BoxFuture<'a, Result<SyncReport, SyncFailure>> {
        Box::pin(async move {
            let flight = self.acquire(account)?;
            let result = self.sync_with_flight(account, policy, fence).await;
            drop(flight);
            result
        })
    }

    fn acquire(&self, account: &AccountId) -> Result<SyncFlight<'_, R, S>, SyncFailure> {
        let mut active = self.active_accounts.lock().map_err(|_poison| SyncFailure {
            source: SyncFailureSource::SingleFlight,
            progress: SyncProgress::default(),
        })?;
        if !active.insert(account.clone()) {
            return Err(SyncFailure {
                source: SyncFailureSource::SingleFlight,
                progress: SyncProgress::default(),
            });
        }
        Ok(SyncFlight {
            coordinator: self,
            account: account.clone(),
        })
    }

    async fn sync_with_flight(
        &self,
        account: &AccountId,
        policy: SyncPolicy,
        fence: &IdentityHash,
    ) -> Result<SyncReport, SyncFailure> {
        let mut progress = SyncProgress::default();
        let capacity = usize::from(policy.keep_limit.get());
        let page_capacity = usize::from(policy.page_size.get());
        let mut envelopes = Vec::with_capacity(capacity.saturating_add(page_capacity));
        let mut envelope_positions = HashMap::with_capacity(capacity.saturating_add(page_capacity));
        let mut tokens = Vec::with_capacity(usize::from(policy.max_pages));
        let mut next_token = None;

        for _ in 0..policy.max_pages {
            let page = self
                .remote
                .list_recent_envelopes(account, policy.page_size, next_token.as_ref())
                .await
                .map_err(|error| failure(SyncFailureSource::Remote(error), progress))?;
            progress.pages += 1;
            let (items, continuation) = page.into_parts();
            if items.len() > usize::from(policy.page_size.get()) {
                return Err(failure(
                    SyncFailureSource::Protocol(SyncProtocolError::OversizedPage),
                    progress,
                ));
            }
            for envelope in items {
                if let Some(position) = envelope_positions.get(envelope.message_id()) {
                    if envelopes[*position] != envelope {
                        return Err(failure(
                            SyncFailureSource::Protocol(SyncProtocolError::ConflictingDuplicate),
                            progress,
                        ));
                    }
                    continue;
                }
                envelope_positions.insert(envelope.message_id().clone(), envelopes.len());
                envelopes.push(envelope);
                if envelopes.len() <= capacity {
                    progress.envelopes += 1;
                }
            }
            let reached_keep_limit = envelopes.len() >= capacity;
            if envelopes.len() > capacity {
                envelopes.truncate(capacity);
            }
            if let Some(token) = continuation.as_ref()
                && tokens.iter().any(|seen| seen == token)
            {
                return Err(failure(
                    SyncFailureSource::Protocol(SyncProtocolError::RepeatedContinuation),
                    progress,
                ));
            }
            if reached_keep_limit {
                progress.snapshot_truncated = true;
                break;
            }
            let Some(token) = continuation else {
                break;
            };
            tokens.push(token.clone());
            if progress.pages == policy.max_pages {
                progress.snapshot_truncated = true;
                break;
            }
            next_token = Some(token);
        }

        let survivors = self
            .store
            .reconcile_recent_envelopes(account, &envelopes, policy.keep_limit, fence)
            .await
            .map_err(|error| failure(store_failure_source(error), progress))?;
        let body_limit = usize::from(policy.full_body_limit.get());
        let newest: Vec<_> = survivors.into_iter().take(body_limit).collect();
        self.cache_bodies(account, &newest, fence, &mut progress)
            .await?;
        Ok(SyncReport { progress })
    }

    /// Downloads and caches the bodies of `newest` that the store lacks.
    async fn cache_bodies(
        &self,
        account: &AccountId,
        newest: &[MessageId],
        fence: &IdentityHash,
        progress: &mut SyncProgress,
    ) -> Result<(), SyncFailure> {
        // Gmail messages never change, so a cached body is never fetched again.
        let missing = self
            .store
            .uncached_message_ids(account, newest)
            .await
            .map_err(|error| failure(store_failure_source(error), *progress))?;
        for id in missing {
            progress.body_requests += 1;
            match self.remote.fetch_message(account, &id).await {
                Ok(message) => {
                    if message.envelope().message_id() != &id {
                        return Err(failure(
                            SyncFailureSource::Protocol(
                                SyncProtocolError::MismatchedFetchedMessage,
                            ),
                            *progress,
                        ));
                    }
                    if self
                        .store
                        .cache_message_if_present(account, &message, fence)
                        .await
                        .map_err(|error| failure(store_failure_source(error), *progress))?
                    {
                        progress.bodies_cached += 1;
                    } else {
                        progress.bodies_skipped += 1;
                    }
                }
                Err(RemoteMailboxError::NotFound) => progress.bodies_skipped += 1,
                Err(error) => return Err(failure(SyncFailureSource::Remote(error), *progress)),
            }
        }
        Ok(())
    }
}

fn failure(source: SyncFailureSource, progress: SyncProgress) -> SyncFailure {
    SyncFailure { source, progress }
}

/// Maps a store error to a sync-failure source, surfacing the in-transaction
/// identity fence as its own category rather than a generic store failure.
fn store_failure_source(error: MailboxStoreError) -> SyncFailureSource {
    match error {
        MailboxStoreError::IdentityChanged => SyncFailureSource::IdentityFenced,
        other => SyncFailureSource::Store(other),
    }
}

struct SyncFlight<'a, R, S> {
    coordinator: &'a SyncCoordinator<R, S>,
    account: AccountId,
}
impl<R, S> Drop for SyncFlight<'_, R, S> {
    fn drop(&mut self) {
        if let Ok(mut active) = self.coordinator.active_accounts.lock() {
            active.remove(&self.account);
        }
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "tests construct valid fixtures")]

    use std::future::ready;
    use std::pin::pin;
    use std::task::{Context, Poll, Waker};

    use tersa_domain::mailbox::{
        HeaderText, Message, MessageEnvelope, ThreadId, UnixTimestampMillis,
    };

    use super::*;
    use crate::mailbox::Page;

    struct TestRemote {
        pages: Mutex<Vec<Result<Page<MessageEnvelope>, RemoteMailboxError>>>,
        list_calls: Mutex<u16>,
        fetch_results: Mutex<Vec<Result<Message, RemoteMailboxError>>>,
        fetched_ids: Mutex<Vec<MessageId>>,
    }
    impl TestRemote {
        fn new(pages: Vec<Result<Page<MessageEnvelope>, RemoteMailboxError>>) -> Self {
            Self {
                pages: Mutex::new(pages),
                list_calls: Mutex::new(0),
                fetch_results: Mutex::new(Vec::new()),
                fetched_ids: Mutex::new(Vec::new()),
            }
        }

        fn with_fetch_results(mut self, results: Vec<Result<Message, RemoteMailboxError>>) -> Self {
            self.fetch_results = Mutex::new(results);
            self
        }
    }
    impl RemoteMailbox for TestRemote {
        fn list_recent_envelopes<'a>(
            &'a self,
            _: &'a AccountId,
            _: PageSize,
            _: Option<&'a crate::mailbox::PageToken>,
        ) -> BoxFuture<'a, Result<Page<MessageEnvelope>, RemoteMailboxError>> {
            *self.list_calls.lock().unwrap() += 1;
            Box::pin(ready(self.pages.lock().unwrap().remove(0)))
        }
        fn fetch_message<'a>(
            &'a self,
            _: &'a AccountId,
            id: &'a MessageId,
        ) -> BoxFuture<'a, Result<Message, RemoteMailboxError>> {
            self.fetched_ids.lock().unwrap().push(id.clone());
            let result = if self.fetch_results.lock().unwrap().is_empty() {
                Err(RemoteMailboxError::NotFound)
            } else {
                self.fetch_results.lock().unwrap().remove(0)
            };
            Box::pin(ready(result))
        }
    }
    #[derive(Default)]
    struct TestStore {
        reconciles: Mutex<u16>,
        survivors: Mutex<Option<Vec<MessageId>>>,
        reconcile_error: Mutex<Option<MailboxStoreError>>,
        cache_results: Mutex<Vec<Result<bool, MailboxStoreError>>>,
        cached_ids: Mutex<Vec<MessageId>>,
        put_calls: Mutex<u16>,
        /// Messages whose body the store already holds.
        bodies: Mutex<Vec<MessageId>>,
    }
    impl MailboxStore for TestStore {
        fn mark_message_read<'a>(
            &'a self,
            _: &'a AccountId,
            _: &'a MessageId,
        ) -> BoxFuture<'a, Result<(), MailboxStoreError>> {
            Box::pin(ready(Ok(())))
        }
        fn mark_thread_read<'a>(
            &'a self,
            _: &'a AccountId,
            _: &'a ThreadId,
        ) -> BoxFuture<'a, Result<(), MailboxStoreError>> {
            Box::pin(ready(Ok(())))
        }
        fn upsert_envelopes<'a>(
            &'a self,
            _: &'a AccountId,
            _: &'a [MessageEnvelope],
        ) -> BoxFuture<'a, Result<(), MailboxStoreError>> {
            Box::pin(ready(Ok(())))
        }
        fn put_message<'a>(
            &'a self,
            _: &'a AccountId,
            _: &'a Message,
        ) -> BoxFuture<'a, Result<(), MailboxStoreError>> {
            *self.put_calls.lock().unwrap() += 1;
            Box::pin(ready(Ok(())))
        }
        fn reconcile_recent_envelopes<'a>(
            &'a self,
            _: &'a AccountId,
            values: &'a [MessageEnvelope],
            _: StoreLimit,
            _: &'a IdentityHash,
        ) -> BoxFuture<'a, Result<Vec<MessageId>, MailboxStoreError>> {
            *self.reconciles.lock().unwrap() += 1;
            if let Some(error) = self.reconcile_error.lock().unwrap().take() {
                return Box::pin(ready(Err(error)));
            }
            let configured = self.survivors.lock().unwrap().clone();
            Box::pin(ready(Ok(configured.unwrap_or_else(|| {
                values
                    .iter()
                    .map(|item| item.message_id().clone())
                    .collect()
            }))))
        }
        fn cache_message_if_present<'a>(
            &'a self,
            _: &'a AccountId,
            message: &'a Message,
            _: &'a IdentityHash,
        ) -> BoxFuture<'a, Result<bool, MailboxStoreError>> {
            self.cached_ids
                .lock()
                .unwrap()
                .push(message.envelope().message_id().clone());
            let result = if self.cache_results.lock().unwrap().is_empty() {
                Ok(false)
            } else {
                self.cache_results.lock().unwrap().remove(0)
            };
            Box::pin(ready(result))
        }
        fn message<'a>(
            &'a self,
            _: &'a AccountId,
            _: &'a MessageId,
        ) -> BoxFuture<'a, Result<Option<Message>, MailboxStoreError>> {
            Box::pin(ready(Ok(None)))
        }
    }
    impl MailboxReader for TestStore {
        fn list_envelopes<'a>(
            &'a self,
            _: &'a AccountId,
            _: StoreLimit,
        ) -> BoxFuture<'a, Result<Vec<MessageEnvelope>, MailboxStoreError>> {
            Box::pin(ready(Ok(Vec::new())))
        }
        fn thread_envelopes<'a>(
            &'a self,
            _: &'a AccountId,
            _: &'a ThreadId,
            _: StoreLimit,
        ) -> BoxFuture<'a, Result<Vec<MessageEnvelope>, MailboxStoreError>> {
            Box::pin(ready(Ok(Vec::new())))
        }
        fn get_message<'a>(
            &'a self,
            _: &'a AccountId,
            id: &'a MessageId,
        ) -> BoxFuture<'a, Result<Option<Message>, MailboxStoreError>> {
            let held = self.bodies.lock().unwrap().contains(id);
            Box::pin(ready(Ok(held.then(|| message(id.as_str(), 1)))))
        }
    }
    fn account() -> AccountId {
        AccountId::new("sync-account").unwrap()
    }
    fn envelope(id: &str, received_at: i64) -> MessageEnvelope {
        MessageEnvelope::new(
            MessageId::new(id).unwrap(),
            ThreadId::new("thread").unwrap(),
            HeaderText::new("from").unwrap(),
            HeaderText::new("subject").unwrap(),
            HeaderText::new("preview").unwrap(),
            UnixTimestampMillis::new(received_at).unwrap(),
            false,
        )
    }
    fn message(id: &str, received_at: i64) -> Message {
        Message::new(
            envelope(id, received_at),
            tersa_domain::mailbox::MessageContent::new(format!("body-{id}").into_bytes()).unwrap(),
        )
    }
    fn policy() -> SyncPolicy {
        SyncPolicy::new(
            PageSize::new(2).unwrap(),
            3,
            StoreLimit::new(3).unwrap(),
            StoreLimit::new(3).unwrap(),
        )
        .unwrap()
    }
    fn fence() -> IdentityHash {
        IdentityHash::from_bytes([0; 32])
    }
    fn run<T>(future: impl Future<Output = T>) -> T {
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        let mut future = pin!(future);
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("test operation must be ready"),
        }
    }

    #[test]
    fn zero_item_page_with_fresh_token_continues_and_reconciles_once() {
        let token = crate::mailbox::PageToken::new("next").unwrap();
        let coordinator = SyncCoordinator::new(
            TestRemote::new(vec![
                Ok(Page::new(Vec::new(), Some(token))),
                Ok(Page::new(vec![envelope("one", 1)], None)),
            ]),
            TestStore::default(),
        );
        let report = run(coordinator.sync_recent(&account(), policy(), &fence())).unwrap();
        assert_eq!(report.progress().pages, 2);
        assert_eq!(report.progress().envelopes, 1);
        assert_eq!(*coordinator.store.reconciles.lock().unwrap(), 1);
    }

    #[test]
    fn repeated_token_fails_before_store_mutation() {
        let token = crate::mailbox::PageToken::new("loop").unwrap();
        let coordinator = SyncCoordinator::new(
            TestRemote::new(vec![
                Ok(Page::new(Vec::new(), Some(token.clone()))),
                Ok(Page::new(Vec::new(), Some(token))),
            ]),
            TestStore::default(),
        );
        let error = run(coordinator.sync_recent(&account(), policy(), &fence())).unwrap_err();
        assert_eq!(
            error.category(),
            SyncFailureSource::Protocol(SyncProtocolError::RepeatedContinuation)
        );
        assert_eq!(*coordinator.store.reconciles.lock().unwrap(), 0);
    }

    #[test]
    fn fresh_tokens_stop_at_the_page_cap_and_report_truncation() {
        let coordinator = SyncCoordinator::new(
            TestRemote::new(vec![
                Ok(Page::new(
                    Vec::new(),
                    Some(crate::mailbox::PageToken::new("first").unwrap()),
                )),
                Ok(Page::new(
                    Vec::new(),
                    Some(crate::mailbox::PageToken::new("second").unwrap()),
                )),
            ]),
            TestStore::default(),
        );
        let two_pages = SyncPolicy::new(
            PageSize::new(1).unwrap(),
            2,
            StoreLimit::new(1).unwrap(),
            StoreLimit::new(1).unwrap(),
        )
        .unwrap();

        let report = run(coordinator.sync_recent(&account(), two_pages, &fence())).unwrap();

        assert_eq!(report.progress().pages, 2);
        assert!(report.progress().snapshot_truncated);
        assert_eq!(*coordinator.store.reconciles.lock().unwrap(), 1);
    }

    #[test]
    fn conflicting_duplicates_fail_before_store_mutation() {
        let coordinator = SyncCoordinator::new(
            TestRemote::new(vec![Ok(Page::new(
                vec![envelope("same", 1), envelope("same", 2)],
                None,
            ))]),
            TestStore::default(),
        );
        let error = run(coordinator.sync_recent(&account(), policy(), &fence())).unwrap_err();
        assert_eq!(
            error.category(),
            SyncFailureSource::Protocol(SyncProtocolError::ConflictingDuplicate)
        );
        assert_eq!(*coordinator.store.reconciles.lock().unwrap(), 0);
    }

    #[test]
    fn keep_limit_does_not_bypass_validation_of_the_rest_of_the_page() {
        let coordinator = SyncCoordinator::new(
            TestRemote::new(vec![Ok(Page::new(
                vec![envelope("same", 1), envelope("same", 2)],
                None,
            ))]),
            TestStore::default(),
        );
        let keep_one = SyncPolicy::new(
            PageSize::new(2).unwrap(),
            1,
            StoreLimit::new(1).unwrap(),
            StoreLimit::new(1).unwrap(),
        )
        .unwrap();

        let error = run(coordinator.sync_recent(&account(), keep_one, &fence())).unwrap_err();

        assert_eq!(
            error.category(),
            SyncFailureSource::Protocol(SyncProtocolError::ConflictingDuplicate)
        );
        assert_eq!(*coordinator.store.reconciles.lock().unwrap(), 0);
    }

    #[test]
    fn keep_limit_does_not_bypass_repeated_continuation_validation() {
        let repeated = crate::mailbox::PageToken::new("repeat-at-limit").unwrap();
        let coordinator = SyncCoordinator::new(
            TestRemote::new(vec![
                Ok(Page::new(Vec::new(), Some(repeated.clone()))),
                Ok(Page::new(vec![envelope("fills-limit", 1)], Some(repeated))),
            ]),
            TestStore::default(),
        );
        let keep_one = SyncPolicy::new(
            PageSize::new(1).unwrap(),
            2,
            StoreLimit::new(1).unwrap(),
            StoreLimit::new(1).unwrap(),
        )
        .unwrap();

        let error = run(coordinator.sync_recent(&account(), keep_one, &fence())).unwrap_err();

        assert_eq!(
            error.category(),
            SyncFailureSource::Protocol(SyncProtocolError::RepeatedContinuation)
        );
        assert_eq!(*coordinator.store.reconciles.lock().unwrap(), 0);
    }

    #[test]
    fn policy_rejects_unbounded_or_inconsistent_values() {
        assert_eq!(
            SyncPolicy::new(
                PageSize::new(1).unwrap(),
                0,
                StoreLimit::new(1).unwrap(),
                StoreLimit::new(1).unwrap()
            ),
            Err(SyncPolicyError::ZeroPageLimit)
        );
        assert_eq!(
            SyncPolicy::new(
                PageSize::new(1).unwrap(),
                MAX_SNAPSHOT_PAGES + 1,
                StoreLimit::new(1).unwrap(),
                StoreLimit::new(1).unwrap()
            ),
            Err(SyncPolicyError::PageLimitTooLarge)
        );
        assert_eq!(
            SyncPolicy::new(
                PageSize::new(1).unwrap(),
                1,
                StoreLimit::new(1).unwrap(),
                StoreLimit::new(2).unwrap()
            ),
            Err(SyncPolicyError::BodyLimitExceedsKeepLimit)
        );
    }

    #[test]
    fn oversized_pages_fail_before_store_mutation() {
        let coordinator = SyncCoordinator::new(
            TestRemote::new(vec![Ok(Page::new(
                vec![envelope("one", 1), envelope("two", 2)],
                None,
            ))]),
            TestStore::default(),
        );
        let one_item_pages = SyncPolicy::new(
            PageSize::new(1).unwrap(),
            1,
            StoreLimit::new(3).unwrap(),
            StoreLimit::new(1).unwrap(),
        )
        .unwrap();
        let error = run(coordinator.sync_recent(&account(), one_item_pages, &fence())).unwrap_err();
        assert_eq!(
            error.category(),
            SyncFailureSource::Protocol(SyncProtocolError::OversizedPage)
        );
        assert_eq!(*coordinator.store.reconciles.lock().unwrap(), 0);
    }

    #[test]
    fn exact_duplicates_deduplicate_in_encounter_order() {
        let duplicate = envelope("same", 2);
        let coordinator = SyncCoordinator::new(
            TestRemote::new(vec![Ok(Page::new(
                vec![duplicate.clone(), duplicate, envelope("later", 1)],
                None,
            ))]),
            TestStore::default(),
        );
        let three_item_pages = SyncPolicy::new(
            PageSize::new(3).unwrap(),
            1,
            StoreLimit::new(3).unwrap(),
            StoreLimit::new(1).unwrap(),
        )
        .unwrap();
        let report = run(coordinator.sync_recent(&account(), three_item_pages, &fence())).unwrap();
        assert_eq!(report.progress().envelopes, 2);
        assert_eq!(*coordinator.store.reconciles.lock().unwrap(), 1);
    }

    #[test]
    fn fetches_only_store_survivors_and_skips_a_disappeared_row_without_put() {
        let retained = message("retained", 20);
        let remote = TestRemote::new(vec![Ok(Page::new(
            vec![envelope("displaced", 10), retained.envelope().clone()],
            None,
        ))])
        .with_fetch_results(vec![Ok(retained)]);
        let store = TestStore::default();
        *store.survivors.lock().unwrap() = Some(vec![MessageId::new("retained").unwrap()]);
        *store.cache_results.lock().unwrap() = vec![Ok(false)];
        let coordinator = SyncCoordinator::new(remote, store);

        let report = run(coordinator.sync_recent(&account(), policy(), &fence())).unwrap();

        assert_eq!(report.progress().body_requests, 1);
        assert_eq!(report.progress().bodies_cached, 0);
        assert_eq!(report.progress().bodies_skipped, 1);
        assert_eq!(
            coordinator
                .remote
                .fetched_ids
                .lock()
                .unwrap()
                .iter()
                .map(MessageId::as_str)
                .collect::<Vec<_>>(),
            ["retained"]
        );
        assert_eq!(*coordinator.store.put_calls.lock().unwrap(), 0);
    }

    #[test]
    fn a_fenced_reconcile_surfaces_as_identity_fenced_not_a_generic_store_failure() {
        // The in-transaction identity fence aborts a stale cycle's envelope write
        // with `IdentityChanged`; the coordinator must map it to its own
        // `IdentityFenced` category so a caller can tell "the account changed
        // underneath me" apart from an ordinary storage fault.
        let remote = TestRemote::new(vec![Ok(Page::new(vec![envelope("one", 1)], None))]);
        let store = TestStore::default();
        *store.reconcile_error.lock().unwrap() = Some(MailboxStoreError::IdentityChanged);
        let coordinator = SyncCoordinator::new(remote, store);

        let error = run(coordinator.sync_recent(&account(), policy(), &fence())).unwrap_err();

        assert_eq!(error.category(), SyncFailureSource::IdentityFenced);
        // The abort happens at the reconcile write, before any body fetch.
        assert_eq!(error.progress().body_requests, 0);
    }

    #[test]
    fn a_fenced_body_cache_surfaces_as_identity_fenced_not_a_generic_store_failure() {
        // The body write is fenced too (message IDs are not distinct across
        // accounts), so a fence abort there must also map to `IdentityFenced`.
        let retained = message("retained", 20);
        let remote = TestRemote::new(vec![Ok(Page::new(vec![retained.envelope().clone()], None))])
            .with_fetch_results(vec![Ok(retained)]);
        let store = TestStore::default();
        *store.survivors.lock().unwrap() = Some(vec![MessageId::new("retained").unwrap()]);
        *store.cache_results.lock().unwrap() = vec![Err(MailboxStoreError::IdentityChanged)];
        let coordinator = SyncCoordinator::new(remote, store);

        let error = run(coordinator.sync_recent(&account(), policy(), &fence())).unwrap_err();

        assert_eq!(error.category(), SyncFailureSource::IdentityFenced);
        assert_eq!(error.progress().body_requests, 1);
    }

    #[test]
    fn bodies_already_cached_are_not_fetched_again() {
        let remote = TestRemote::new(vec![Ok(Page::new(
            vec![
                envelope("new", 30),
                envelope("held", 20),
                envelope("older", 10),
            ],
            None,
        ))])
        .with_fetch_results(vec![Ok(message("new", 30))]);
        let store = TestStore::default();
        *store.bodies.lock().unwrap() = vec![MessageId::new("held").unwrap()];
        *store.cache_results.lock().unwrap() = vec![Ok(true)];
        let coordinator = SyncCoordinator::new(remote, store);
        let two_bodies = SyncPolicy::new(
            PageSize::new(3).unwrap(),
            1,
            StoreLimit::new(3).unwrap(),
            StoreLimit::new(2).unwrap(),
        )
        .unwrap();

        let report = run(coordinator.sync_recent(&account(), two_bodies, &fence())).unwrap();

        // "held" is among the two newest but cached; "older" is past the limit.
        assert_eq!(report.progress().body_requests, 1);
        assert_eq!(report.progress().bodies_cached, 1);
        assert_eq!(
            coordinator
                .remote
                .fetched_ids
                .lock()
                .unwrap()
                .iter()
                .map(MessageId::as_str)
                .collect::<Vec<_>>(),
            ["new"]
        );
    }

    #[test]
    fn body_limit_is_sequential_and_not_found_does_not_stop_later_survivors() {
        let remote = TestRemote::new(vec![Ok(Page::new(
            vec![
                envelope("missing", 30),
                envelope("cached", 20),
                envelope("unrequested", 10),
            ],
            None,
        ))])
        .with_fetch_results(vec![
            Err(RemoteMailboxError::NotFound),
            Ok(message("cached", 20)),
        ]);
        let store = TestStore::default();
        *store.cache_results.lock().unwrap() = vec![Ok(true)];
        let coordinator = SyncCoordinator::new(remote, store);
        let two_bodies = SyncPolicy::new(
            PageSize::new(3).unwrap(),
            1,
            StoreLimit::new(3).unwrap(),
            StoreLimit::new(2).unwrap(),
        )
        .unwrap();

        let report = run(coordinator.sync_recent(&account(), two_bodies, &fence())).unwrap();

        assert_eq!(report.progress().body_requests, 2);
        assert_eq!(report.progress().bodies_cached, 1);
        assert_eq!(report.progress().bodies_skipped, 1);
        assert_eq!(
            coordinator
                .remote
                .fetched_ids
                .lock()
                .unwrap()
                .iter()
                .map(MessageId::as_str)
                .collect::<Vec<_>>(),
            ["missing", "cached"]
        );
    }

    #[derive(Default)]
    struct PendingRemote {
        list_calls: Mutex<Vec<AccountId>>,
    }

    struct BodyPendingRemote {
        value: MessageEnvelope,
        fetch_calls: Mutex<u16>,
    }
    impl RemoteMailbox for BodyPendingRemote {
        fn list_recent_envelopes<'a>(
            &'a self,
            _: &'a AccountId,
            _: PageSize,
            _: Option<&'a crate::mailbox::PageToken>,
        ) -> BoxFuture<'a, Result<Page<MessageEnvelope>, RemoteMailboxError>> {
            Box::pin(ready(Ok(Page::new(vec![self.value.clone()], None))))
        }
        fn fetch_message<'a>(
            &'a self,
            _: &'a AccountId,
            _: &'a MessageId,
        ) -> BoxFuture<'a, Result<Message, RemoteMailboxError>> {
            *self.fetch_calls.lock().unwrap() += 1;
            Box::pin(std::future::pending())
        }
    }
    impl RemoteMailbox for PendingRemote {
        fn list_recent_envelopes<'a>(
            &'a self,
            account: &'a AccountId,
            _: PageSize,
            _: Option<&'a crate::mailbox::PageToken>,
        ) -> BoxFuture<'a, Result<Page<MessageEnvelope>, RemoteMailboxError>> {
            self.list_calls.lock().unwrap().push(account.clone());
            Box::pin(std::future::pending())
        }
        fn fetch_message<'a>(
            &'a self,
            _: &'a AccountId,
            _: &'a MessageId,
        ) -> BoxFuture<'a, Result<Message, RemoteMailboxError>> {
            Box::pin(std::future::pending())
        }
    }

    #[test]
    fn sync_is_lazy_single_flight_per_account_and_releases_claim_on_drop() {
        let coordinator = SyncCoordinator::new(PendingRemote::default(), TestStore::default());
        let first_account = account();
        let second_account = AccountId::new("other-account").unwrap();
        let held_fence = fence();

        let unpolled = coordinator.sync_recent(&first_account, policy(), &held_fence);
        assert!(coordinator.active_accounts.lock().unwrap().is_empty());
        assert!(coordinator.remote.list_calls.lock().unwrap().is_empty());
        drop(unpolled);

        let mut first = Box::pin(coordinator.sync_recent(&first_account, policy(), &held_fence));
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        assert!(matches!(first.as_mut().poll(&mut context), Poll::Pending));
        assert_eq!(coordinator.active_accounts.lock().unwrap().len(), 1);

        let duplicate =
            run(coordinator.sync_recent(&first_account, policy(), &held_fence)).unwrap_err();
        assert_eq!(duplicate.category(), SyncFailureSource::SingleFlight);

        let mut other = Box::pin(coordinator.sync_recent(&second_account, policy(), &held_fence));
        assert!(matches!(other.as_mut().poll(&mut context), Poll::Pending));
        assert_eq!(coordinator.active_accounts.lock().unwrap().len(), 2);
        drop(other);
        assert_eq!(coordinator.active_accounts.lock().unwrap().len(), 1);
        drop(first);
        assert!(coordinator.active_accounts.lock().unwrap().is_empty());
    }

    #[test]
    fn cancellation_during_body_fetch_releases_claim_without_cache_mutation() {
        let coordinator = SyncCoordinator::new(
            BodyPendingRemote {
                value: envelope("pending-body", 1),
                fetch_calls: Mutex::new(0),
            },
            TestStore::default(),
        );
        let local_account = account();
        let held_fence = fence();
        let mut operation =
            Box::pin(coordinator.sync_recent(&local_account, policy(), &held_fence));
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);

        assert!(matches!(
            operation.as_mut().poll(&mut context),
            Poll::Pending
        ));
        assert_eq!(*coordinator.remote.fetch_calls.lock().unwrap(), 1);
        assert_eq!(*coordinator.store.reconciles.lock().unwrap(), 1);
        assert!(coordinator.store.cached_ids.lock().unwrap().is_empty());
        assert_eq!(coordinator.active_accounts.lock().unwrap().len(), 1);

        drop(operation);
        assert!(coordinator.active_accounts.lock().unwrap().is_empty());
        assert!(coordinator.store.cached_ids.lock().unwrap().is_empty());
    }

    #[test]
    fn failures_and_reports_do_not_format_mailbox_content() {
        let failure = failure(
            SyncFailureSource::Protocol(SyncProtocolError::ConflictingDuplicate),
            SyncProgress {
                pages: 1,
                envelopes: 2,
                ..SyncProgress::default()
            },
        );
        let report = SyncReport {
            progress: failure.progress(),
        };
        assert_eq!(
            format!("{failure:?}"),
            "SyncFailure { source: Protocol(ConflictingDuplicate), progress: SyncProgress { pages: 1, envelopes: 2, body_requests: 0, bodies_cached: 0, bodies_skipped: 0, snapshot_truncated: false } }"
        );
        assert_eq!(
            failure.to_string(),
            "bounded mailbox synchronization failed"
        );
        assert_eq!(
            format!("{report:?}"),
            "SyncReport { progress: SyncProgress { pages: 1, envelopes: 2, body_requests: 0, bodies_cached: 0, bodies_skipped: 0, snapshot_truncated: false } }"
        );
    }
}
