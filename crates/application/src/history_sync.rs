// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Coordinates bounded metadata synchronization over the approved History ports.
//!
//! The runtime must serialize this cycle with other operations for the account
//! and supply its trusted identity fence. Store transactions remain the authority
//! for identity, cursor CAS, pins and atomicity. This module neither rebinds an
//! account nor settles commands. A snapshot is recent coverage, never absence
//! evidence for an omitted target.
//!
//! Every outcome retains the last validated store checkpoint, including a prefix
//! committed before a later failure. Dropping the future starts no further work;
//! cancellation during a port call requires rereading the durable checkpoint on
//! the next invocation, not inferring whether an interrupted commit completed.
//!
//! Bodies are a separate runtime phase described by
//! [`HistoryBodyPlan`](crate::history_sync::HistoryBodyPlan). The
//! runtime must execute that plan to preserve established body availability;
//! metadata success alone does not mean bodies were downloaded.
//!
//! History acquisition uses at most four pages/2,000 records. Fallback collection
//! has its separate four-page recent-list cap. The shared metadata budget includes
//! a conservative reservation of 100 lookups before fallback, because snapshot
//! hydration happens inside the feed port. Late cursor expiry can therefore stop
//! at a committed prefix and defer fallback until an explicit later invocation.
//!
//! ```
//! use tersa_application::{
//!     history::{GmailHistoryFeed, HistoryCursorStore},
//!     history_sync::{HistorySync, HistorySyncStop},
//!     profile::AccountFence,
//! };
//! # async fn example<R: GmailHistoryFeed, S: HistoryCursorStore>(
//! #     remote: &R, store: &S, fence: &AccountFence,
//! # ) {
//! let report = HistorySync::new(remote, store).sync(fence).await;
//! if let HistorySyncStop::RecoveryRequired(reason) = report.stop() {
//!     // Present the closed reason alongside report.checkpoint() and progress().
//!     // The runtime schedules no automatic reset or retry here.
//!     let _ = reason;
//! }
//! # }
//! ```
// Rust guideline compliant 1.0.

use crate::{
    history::{
        DecidedHistoryRecord, GmailHistoryFeed, HistoryCheckpoint, HistoryCursorStore,
        HistoryDecision, HistoryEventKind, HistoryFeedError, HistoryPage, HistoryPageProgress,
        HistoryQuery, LocalHistoryPresence, LocalHistoryStop, MAX_BODY_HYDRATIONS,
        MAX_CYCLE_RECORDS, MAX_HISTORY_PAGES, MAX_HISTORY_RECORDS, MAX_METADATA_LOOKUPS,
        MAX_RECENT_SNAPSHOT_PAGES, MAX_SNAPSHOT_MESSAGES, ProviderContinuation, SnapshotCommit,
        SnapshotCoverage, SnapshotFallbackReason, TerminalHistoryCheckpoint,
    },
    mailbox::{BoxFuture, PageSize},
    mailbox_state::{
        ContractError, MessageObservation, MetadataObservation, MetadataReadError,
        RemoteMessageState, TriageStoreError,
    },
    profile::AccountFence,
};
use std::fmt;
use tersa_domain::history::HistoryCursor;

/// Counts attempted reads and confirmed commits within one bounded invocation.
///
/// `metadata_requests + 25 * snapshot_requests` bounds metadata GETs, including
/// failed attempts, and never exceeds 1,000. Snapshot internals do not expose an
/// exact hydration count, so neither this report nor the body plan invents one.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HistorySyncProgress {
    /// History page requests started, including a failed final request.
    pub history_requests: usize,
    /// History per-message metadata requests started, including failures.
    pub metadata_requests: usize,
    /// Snapshot page requests started; each port call includes bounded metadata hydration.
    pub snapshot_requests: usize,
    /// Whole records whose returned durable checkpoints were validated.
    pub records_committed: usize,
    /// Snapshot metadata items in a confirmed atomic snapshot commit.
    pub snapshot_messages_committed: usize,
}

/// Identifies a local bound that stopped a cycle with a committed record prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HistorySyncBudget {
    /// Four pages or 2,000 records were processed before provider chain end.
    PagesOrRecords,
    /// The next whole record or fallback collection exceeds the remaining metadata allowance.
    Metadata,
    /// The decoder exposed only a whole-record reference-budget prefix.
    References,
}

/// Explains why explicit recovery is needed, without provider text or credentials.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HistoryRecoveryReason {
    /// An owning-store operation failed; never bootstrap, rebind or fallback.
    Store(TriageStoreError),
    /// A History request failed outside the sole typed cursor-expiry fallback.
    Feed(HistoryFeedError),
    /// Baseline, snapshot or exact-key metadata retrieval failed.
    Read(MetadataReadError),
    /// A returned document did not match the exact requested context.
    Contract(ContractError),
    /// The next provider record could not be fully decided.
    UndecidableRecord,
    /// The bounded chain made no record progress before exhausting its allowance.
    NoProgress,
}

impl From<TriageStoreError> for HistoryRecoveryReason {
    fn from(error: TriageStoreError) -> Self {
        Self::Store(error)
    }
}
impl From<MetadataReadError> for HistoryRecoveryReason {
    fn from(error: MetadataReadError) -> Self {
        Self::Read(error)
    }
}
impl From<ContractError> for HistoryRecoveryReason {
    fn from(error: ContractError) -> Self {
        Self::Contract(error)
    }
}

/// Distinguishes real chain completion, recent snapshot coverage and local stops.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HistorySyncStop {
    /// Every exposed record in a real terminal chain and its head were committed.
    CaughtUp,
    /// A baseline-first bounded recent snapshot was committed; replay is still needed.
    SnapshotCommitted(SnapshotCoverage),
    /// A whole-record prefix was committed; resume later from its durable cursor.
    Bounded(HistorySyncBudget),
    /// No automatic retry/reset is scheduled; retain pending evidence for explicit recovery.
    RecoveryRequired(HistoryRecoveryReason),
}

/// Requests a separate bounded body phase after confirmed metadata/cursor progress.
///
/// P7 must read the current recent survivors from the owning store in its usual
/// deterministic order, select at most [`Self::limit`] (25), filter already cached
/// bodies through the existing mailbox-store port, and fetch/cache only missing
/// survivors using the existing exact-message checks and identity-fenced
/// `cache_message_if_present` path. Do not select merely the changed keys: unchanged
/// recent survivors may also lack bodies. Recheck presence at cache time. Body
/// failures have their own report and must not roll back or hide metadata progress.
/// Never execute this plan under a different identity; serialize it with account
/// operations and honor any identity-related recovery from the metadata phase.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoryBodyPlan {
    fence: AccountFence,
}
impl HistoryBodyPlan {
    /// Returns the identity fence required by every body cache write.
    #[must_use]
    pub fn fence(&self) -> &AccountFence {
        &self.fence
    }
    /// Returns the maximum selected survivors and body fetches in this phase.
    #[must_use]
    pub const fn limit(&self) -> usize {
        MAX_BODY_HYDRATIONS
    }
}

/// Retains honest confirmed progress even when a later operation fails.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistorySyncReport {
    stop: HistorySyncStop,
    progress: HistorySyncProgress,
    checkpoint: Option<HistoryCheckpoint>,
    body_plan: Option<HistoryBodyPlan>,
}
impl HistorySyncReport {
    /// Returns the closed completion or stopping fact.
    #[must_use]
    pub fn stop(&self) -> HistorySyncStop {
        self.stop
    }
    /// Returns bounded attempted reads and confirmed commit counts, never body downloads.
    #[must_use]
    pub fn progress(&self) -> HistorySyncProgress {
        self.progress
    }
    /// Returns the last validated durable checkpoint; None means even the read failed validation.
    ///
    /// This is confirmed historical progress, not authority to write after a
    /// concurrent identity change or conflict. The next cycle rereads the store.
    #[must_use]
    pub fn checkpoint(&self) -> Option<&HistoryCheckpoint> {
        self.checkpoint.as_ref()
    }
    /// Returns deferred body work only after at least one confirmed metadata/cursor commit.
    #[must_use]
    pub fn body_plan(&self) -> Option<&HistoryBodyPlan> {
        self.body_plan.as_ref()
    }
}

/// Orchestrates one lazy bounded cycle using borrowed remote and store ports.
pub struct HistorySync<'a, R: ?Sized, S: ?Sized> {
    remote: &'a R,
    store: &'a S,
}
impl<R: ?Sized, S: ?Sized> fmt::Debug for HistorySync<'_, R, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HistorySync").finish_non_exhaustive()
    }
}
impl<R: ?Sized, S: ?Sized> Clone for HistorySync<'_, R, S> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<R: ?Sized, S: ?Sized> Copy for HistorySync<'_, R, S> {}

impl<'ports, R: GmailHistoryFeed + ?Sized, S: HistoryCursorStore + ?Sized>
    HistorySync<'ports, R, S>
{
    /// Borrows approved ports without starting any work or acquiring runtime authority.
    #[must_use]
    pub fn new(remote: &'ports R, store: &'ports S) -> Self {
        Self { remote, store }
    }

    /// Runs one metadata-only cycle, preserving earlier commits on every later failure.
    ///
    /// The caller owns account serialization and identity admission. Recovery and
    /// budget stops never start detached work, automatically retry, or reset state.
    #[must_use]
    pub fn sync<'a>(&'a self, fence: &'a AccountFence) -> BoxFuture<'a, HistorySyncReport> {
        Box::pin(async move {
            let mut cycle = Cycle::default();
            let stop = self
                .run(fence, &mut cycle)
                .await
                .unwrap_or_else(HistorySyncStop::RecoveryRequired);
            HistorySyncReport {
                stop,
                progress: cycle.progress,
                checkpoint: cycle.checkpoint,
                body_plan: cycle.body_plan,
            }
        })
    }

    async fn run(
        &self,
        fence: &AccountFence,
        cycle: &mut Cycle,
    ) -> Result<HistorySyncStop, HistoryRecoveryReason> {
        let checkpoint = self.store.checkpoint(fence).await?;
        validate_checkpoint(&checkpoint, fence, checkpoint.cursor())?;
        cycle.checkpoint = Some(checkpoint.clone());
        let Some(start) = checkpoint.cursor() else {
            return self
                .snapshot(cycle, checkpoint, SnapshotFallbackReason::NoCursor)
                .await;
        };
        let size = PageSize::new(u16::try_from(MAX_HISTORY_RECORDS).expect("fixed page size"))
            .expect("fixed History page size fits mailbox port");
        let mut query = HistoryQuery::new(fence.account_id().clone(), start.clone(), size);
        loop {
            cycle.progress.history_requests += 1;
            let page = match self.remote.history_page(&query).await {
                Ok(page) => page,
                Err(HistoryFeedError::CursorExpired) => {
                    let expected = cycle.checkpoint.clone().expect("checkpoint read above");
                    return self
                        .snapshot(
                            cycle,
                            expected,
                            SnapshotFallbackReason::HistoryCursorExpired,
                        )
                        .await;
                }
                Err(error) => return Err(HistoryRecoveryReason::Feed(error)),
            };
            if page.query() != &query {
                return Err(ContractError::Continuation.into());
            }
            for (index, record) in page.records().iter().enumerate() {
                if cycle.progress.records_committed == MAX_CYCLE_RECORDS {
                    return cycle.bounded(HistorySyncBudget::PagesOrRecords);
                }
                let Some(request) = self.decide(fence, &page, index, cycle).await? else {
                    return cycle.bounded(HistorySyncBudget::Metadata);
                };
                let committed = self.store.apply_record(&request).await?;
                validate_checkpoint(&committed, fence, Some(record.id()))?;
                cycle.confirm(committed);
                cycle.progress.records_committed += 1;
            }
            match page.progress() {
                HistoryPageProgress::LocalPrefix {
                    reason: LocalHistoryStop::RecoveryRequired,
                    ..
                } => return Err(HistoryRecoveryReason::UndecidableRecord),
                HistoryPageProgress::LocalPrefix {
                    reason: LocalHistoryStop::ReferenceBudget,
                    ..
                } => return cycle.bounded(HistorySyncBudget::References),
                HistoryPageProgress::Complete(ProviderContinuation::End) => {
                    let request = TerminalHistoryCheckpoint::new(fence.clone(), &page)?;
                    let committed = self.store.checkpoint_chain_end(&request).await?;
                    validate_checkpoint(&committed, fence, Some(request.cursor()))?;
                    cycle.confirm(committed);
                    return Ok(HistorySyncStop::CaughtUp);
                }
                HistoryPageProgress::Complete(ProviderContinuation::Next(_)) => {
                    if cycle.progress.history_requests == MAX_HISTORY_PAGES {
                        return cycle.bounded(HistorySyncBudget::PagesOrRecords);
                    }
                    query = HistoryQuery::continue_after(
                        &page,
                        cycle.checkpoint.as_ref().expect("checkpoint read above"),
                    )?;
                }
            }
        }
    }

    async fn decide(
        &self,
        fence: &AccountFence,
        page: &HistoryPage,
        index: usize,
        cycle: &mut Cycle,
    ) -> Result<Option<DecidedHistoryRecord>, HistoryRecoveryReason> {
        let record = &page.records()[index];
        let local = self.store.classify_record(fence, record).await?;
        if local.record() != record {
            return Err(ContractError::Coverage.into());
        }
        // Classify the complete affected set before reserving any metadata reads.
        let required: Vec<_> = local
            .states()
            .iter()
            .map(|(key, presence)| {
                *presence != LocalHistoryPresence::OutsideCache
                    || record.events().iter().any(|event| {
                        event.key() == key && matches!(event.kind(), HistoryEventKind::Added)
                    })
            })
            .collect();
        if required.iter().filter(|needed| **needed).count()
            > MAX_METADATA_LOOKUPS - cycle.progress.metadata_requests
        {
            return Ok(None);
        }
        let mut decisions = Vec::with_capacity(record.affected().len());
        for ((key, _), needed) in local.states().iter().zip(required) {
            if !needed {
                decisions.push(HistoryDecision::Irrelevant(key.clone()));
                continue;
            }
            cycle.progress.metadata_requests += 1;
            let metadata = self.remote.message_metadata(key).await?;
            if metadata.key() != key {
                return Err(ContractError::WrongTarget.into());
            }
            decisions.push(match metadata {
                MetadataObservation::Known(metadata) => HistoryDecision::Metadata(metadata),
                MetadataObservation::Missing(key) => HistoryDecision::Observe(
                    MessageObservation::new(key, RemoteMessageState::Missing)?,
                ),
            });
        }
        Ok(Some(DecidedHistoryRecord::new(
            fence.clone(),
            page,
            index,
            decisions,
        )?))
    }

    async fn snapshot(
        &self,
        cycle: &mut Cycle,
        expected: HistoryCheckpoint,
        reason: SnapshotFallbackReason,
    ) -> Result<HistorySyncStop, HistoryRecoveryReason> {
        // Snapshot hydration is internal to its port. Reserve its whole bounded
        // collection (at most 100 GETs), rather than silently exceeding the
        // shared metadata allowance after a late History-cursor expiry.
        if MAX_SNAPSHOT_MESSAGES > MAX_METADATA_LOOKUPS - cycle.progress.metadata_requests {
            return cycle.bounded(HistorySyncBudget::Metadata);
        }
        let fence = expected.fence();
        let baseline = self.remote.capture_baseline(fence.account_id()).await?;
        if baseline.account_id() != fence.account_id() {
            return Err(ContractError::WrongAccount.into());
        }
        if expected
            .cursor()
            .is_some_and(|cursor| baseline.cursor() < cursor)
        {
            return Err(ContractError::Order.into());
        }
        let mut metadata = Vec::new();
        let mut tokens = Vec::new();
        let mut continuation = None;
        let mut coverage = SnapshotCoverage::RecentTruncated;
        for _ in 0..MAX_RECENT_SNAPSHOT_PAGES {
            cycle.progress.snapshot_requests += 1;
            let page = self
                .remote
                .snapshot_page(&baseline, continuation.as_ref())
                .await?;
            if page.baseline() != &baseline {
                return Err(ContractError::State.into());
            }
            // Validate pagination even at the cap, before permitting a commit.
            match page.continuation() {
                ProviderContinuation::Next(token) => {
                    if tokens.contains(token) {
                        return Err(ContractError::Continuation.into());
                    }
                    tokens.push(token.clone());
                    continuation = Some(token.clone());
                }
                ProviderContinuation::End => {
                    coverage = SnapshotCoverage::RecentChainEnded;
                }
            }
            metadata.extend_from_slice(page.items());
            if coverage == SnapshotCoverage::RecentChainEnded {
                break;
            }
        }
        // The constructor owns exact bounded metadata coverage and duplicate checks.
        let request = SnapshotCommit::new(expected, baseline, metadata, coverage, reason)?;
        let committed = self.store.commit_snapshot(&request).await?;
        validate_checkpoint(
            &committed,
            request.expected().fence(),
            Some(request.baseline().cursor()),
        )?;
        cycle.confirm(committed);
        cycle.progress.snapshot_messages_committed = request.metadata().len();
        Ok(HistorySyncStop::SnapshotCommitted(coverage))
    }
}

fn validate_checkpoint(
    checkpoint: &HistoryCheckpoint,
    fence: &AccountFence,
    cursor: Option<&HistoryCursor>,
) -> Result<(), ContractError> {
    if checkpoint.fence().account_id() != fence.account_id() {
        return Err(ContractError::WrongAccount);
    }
    if checkpoint.fence() != fence || checkpoint.cursor() != cursor {
        return Err(ContractError::State);
    }
    Ok(())
}

#[derive(Default)]
struct Cycle {
    progress: HistorySyncProgress,
    checkpoint: Option<HistoryCheckpoint>,
    body_plan: Option<HistoryBodyPlan>,
}
impl Cycle {
    fn confirm(&mut self, checkpoint: HistoryCheckpoint) {
        self.body_plan = Some(HistoryBodyPlan {
            fence: checkpoint.fence().clone(),
        });
        self.checkpoint = Some(checkpoint);
    }

    fn bounded(&self, budget: HistorySyncBudget) -> Result<HistorySyncStop, HistoryRecoveryReason> {
        if self.progress.records_committed == 0 {
            Err(HistoryRecoveryReason::NoProgress)
        } else {
            Ok(HistorySyncStop::Bounded(budget))
        }
    }
}

#[cfg(test)]
mod tests;
