// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Defines bounded History reads and record-atomic transaction contracts, without orchestration.
//!
//! A page is a complete validated envelope or an explicitly stopped whole-record
//! prefix. Provider continuation never substitutes for omitted local records.
//! Decided-record requests cover every affected message and carry predecessor
//! CAS evidence. Constructors do not prove SQL atomicity, network provenance or
//! whole-chain acquisition: the named producer/store contracts remain mandatory.

use crate::{
    mailbox::{AccountId, BoxFuture, PageSize, PageToken},
    mailbox_state::{
        ContractError, MessageKey, MessageMetadata, MessageObservation, MetadataObservation,
        MetadataReadError, TriageStoreError,
    },
    profile::AccountFence,
};
use std::fmt;
use tersa_domain::{history::HistoryCursor, label::LabelId};

/// Maximum provider History records per page.
pub const MAX_HISTORY_RECORDS: usize = 500;
/// Maximum unique affected messages in one record; also the metadata cycle budget.
pub const MAX_RECORD_MESSAGES: usize = 1_000;
/// Maximum decoded affected references in an exposed whole-record page prefix.
pub const MAX_PAGE_REFERENCES: usize = 10_000;
/// Maximum metadata lookups per cycle; reserve a whole next record before fetching.
pub const MAX_METADATA_LOOKUPS: usize = 1_000;
/// Maximum pages per foreground History cycle.
pub const MAX_HISTORY_PAGES: usize = 4;
/// Maximum records per foreground History cycle.
pub const MAX_CYCLE_RECORDS: usize = 2_000;
/// Maximum optional bodies after metadata/cursor commit.
pub const MAX_BODY_HYDRATIONS: usize = 25;
/// Maximum pages in the baseline-first recent snapshot collector.
pub const MAX_RECENT_SNAPSHOT_PAGES: usize = 4;
/// Maximum metadata items in each fixed recent snapshot page.
pub const SNAPSHOT_PAGE_SIZE: usize = 25;
/// Maximum recent snapshot messages; nonterminal/undo pins remain separately protected.
pub const MAX_SNAPSHOT_MESSAGES: usize = 100;

/// Describes one normalized specific event or an otherwise-uncovered generic reference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HistoryEventKind {
    /// A new message is a bounded recent-cache candidate requiring metadata.
    Added,
    /// A provider deletion concerns this exact message.
    Deleted,
    /// Only these labels were added; this is not full observed membership.
    LabelsAdded(Vec<LabelId>),
    /// Only these labels were removed; this is not full observed membership.
    LabelsRemoved(Vec<LabelId>),
    /// A generic changed reference not already covered by specific events.
    Changed,
}
impl HistoryEventKind {
    fn tag(&self) -> u8 {
        match self {
            Self::Added => 0,
            Self::Deleted => 1,
            Self::LabelsAdded(_) => 2,
            Self::LabelsRemoved(_) => 3,
            Self::Changed => 4,
        }
    }
}

/// Binds one bounded normalized History event to account and message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoryEvent {
    key: MessageKey,
    kind: HistoryEventKind,
}
impl HistoryEvent {
    /// Validates delta label sets without pretending they are complete membership.
    ///
    /// # Errors
    /// Rejects empty, duplicate or over-512-ID delta sets. Decoders must coalesce
    /// repeated specific entries per message/kind before constructing records.
    pub fn new(key: MessageKey, mut kind: HistoryEventKind) -> Result<Self, ContractError> {
        if let HistoryEventKind::LabelsAdded(labels) | HistoryEventKind::LabelsRemoved(labels) =
            &mut kind
        {
            if labels.is_empty() {
                return Err(ContractError::Coverage);
            }
            if labels.len() > 512 {
                return Err(ContractError::TooMany);
            }
            labels.sort_unstable();
            if labels.windows(2).any(|p| p[0] == p[1]) {
                return Err(ContractError::Duplicate);
            }
        }
        Ok(Self { key, kind })
    }
    /// Returns the affected account and message.
    #[must_use]
    pub fn key(&self) -> &MessageKey {
        &self.key
    }
    /// Returns the normalized event, never a full membership inferred from a delta.
    #[must_use]
    pub fn kind(&self) -> &HistoryEventKind {
        &self.kind
    }
}

/// Holds a complete, normalized record with all affected message identities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoryRecord {
    account: AccountId,
    id: HistoryCursor,
    events: Vec<HistoryEvent>,
    affected: Vec<MessageKey>,
    references: usize,
}
impl HistoryRecord {
    /// Validates complete record identity, coverage and decoded-reference accounting.
    ///
    /// `references` includes decoded generic/specific duplicates removed during
    /// normalization; trusted decoding supplies that count. Generic references
    /// covered by specific events must be omitted, never applied twice.
    ///
    /// # Errors
    /// Rejects foreign accounts, duplicate message/kind entries, generic/specific
    /// overlap, over-1,000 affected IDs, or inconsistent/over-10,000 references.
    pub fn new(
        account: AccountId,
        id: HistoryCursor,
        mut events: Vec<HistoryEvent>,
        references: usize,
    ) -> Result<Self, ContractError> {
        if events.len() > 4 * MAX_RECORD_MESSAGES || references > MAX_PAGE_REFERENCES {
            return Err(ContractError::TooMany);
        }
        if references < events.len() {
            return Err(ContractError::Coverage);
        }
        if events.iter().any(|e| e.key.account_id() != &account) {
            return Err(ContractError::WrongAccount);
        }
        events.sort_unstable_by(|a, b| {
            a.key
                .message_id()
                .as_str()
                .cmp(b.key.message_id().as_str())
                .then(a.kind.tag().cmp(&b.kind.tag()))
        });
        let mut affected = Vec::new();
        for group in events.chunk_by(|a, b| a.key == b.key) {
            if group.windows(2).any(|p| p[0].kind.tag() == p[1].kind.tag()) {
                return Err(ContractError::Duplicate);
            }
            if group.len() > 1
                && group
                    .iter()
                    .any(|e| matches!(e.kind, HistoryEventKind::Changed))
            {
                return Err(ContractError::Coverage);
            }
            affected.push(group[0].key.clone());
        }
        if affected.len() > MAX_RECORD_MESSAGES {
            return Err(ContractError::TooMany);
        }
        Ok(Self {
            account,
            id,
            events,
            affected,
            references,
        })
    }
    /// Returns the record's owning account.
    #[must_use]
    pub fn account_id(&self) -> &AccountId {
        &self.account
    }
    /// Returns the canonical record ID, not the response-head cursor.
    #[must_use]
    pub fn id(&self) -> &HistoryCursor {
        &self.id
    }
    /// Returns specific events once and uncovered generic references in canonical order.
    #[must_use]
    pub fn events(&self) -> &[HistoryEvent] {
        &self.events
    }
    /// Returns every unique affected account/message key in canonical order.
    #[must_use]
    pub fn affected(&self) -> &[MessageKey] {
        &self.affected
    }
    /// Returns decoded references charged to the local page budget.
    #[must_use]
    pub fn decoded_references(&self) -> usize {
        self.references
    }
}

/// Binds a page request to provider chain start and locally committed predecessor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoryQuery {
    account: AccountId,
    start: HistoryCursor,
    predecessor: HistoryCursor,
    continuation: Option<PageToken>,
    visited_tokens: Vec<PageToken>,
    size: PageSize,
}
impl HistoryQuery {
    /// Starts a new chain at the actual durable cursor, with no provider token.
    #[must_use]
    pub fn new(account: AccountId, start: HistoryCursor, size: PageSize) -> Self {
        Self {
            account,
            predecessor: start.clone(),
            start,
            continuation: None,
            visited_tokens: Vec::new(),
            size,
        }
    }
    /// Continues only after the preceding complete page's records were committed.
    ///
    /// The checkpoint must come from the owning store. Retain the original
    /// provider chain start while binding the next page to its actual committed
    /// predecessor; local prefixes must restart from their durable record cursor.
    ///
    /// # Errors
    /// Rejects wrong accounts/predecessors, local prefixes, chain end, repeated
    /// tokens and continuation past the four-page cycle budget.
    pub fn continue_after(
        page: &HistoryPage,
        committed: &HistoryCheckpoint,
    ) -> Result<Self, ContractError> {
        if committed.fence.account_id() != page.query.account_id() {
            return Err(ContractError::WrongAccount);
        }
        let last = page
            .records
            .last()
            .map_or(&page.query.predecessor, HistoryRecord::id);
        if committed.cursor() != Some(last) {
            return Err(ContractError::Order);
        }
        let HistoryPageProgress::Complete(ProviderContinuation::Next(token)) = &page.progress
        else {
            return Err(ContractError::Continuation);
        };
        if page.query.visited_tokens.contains(token) {
            return Err(ContractError::Continuation);
        }
        if page.query.visited_tokens.len() + 1 >= MAX_HISTORY_PAGES {
            return Err(ContractError::TooMany);
        }
        let mut visited_tokens = page.query.visited_tokens.clone();
        visited_tokens.push(token.clone());
        Ok(Self {
            account: page.query.account.clone(),
            start: page.query.start.clone(),
            predecessor: last.clone(),
            continuation: Some(token.clone()),
            visited_tokens,
            size: page.query.size,
        })
    }
    /// Returns the owning account.
    #[must_use]
    pub fn account_id(&self) -> &AccountId {
        &self.account
    }
    /// Returns the original provider chain start cursor.
    #[must_use]
    pub fn start(&self) -> &HistoryCursor {
        &self.start
    }
    /// Returns the local committed predecessor expected before this page.
    #[must_use]
    pub fn predecessor(&self) -> &HistoryCursor {
        &self.predecessor
    }
    /// Returns only the actual provider continuation token supplied to this request.
    #[must_use]
    pub fn continuation(&self) -> Option<&PageToken> {
        self.continuation.as_ref()
    }
    /// Returns the validated provider page size.
    #[must_use]
    pub fn page_size(&self) -> PageSize {
        self.size
    }
}

/// Distinguishes an actual provider next page from an actual provider chain end.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderContinuation {
    /// The provider supplied this exact token.
    Next(PageToken),
    /// The provider supplied no next token.
    End,
}
/// Explains why a whole-record local prefix stopped before the next record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalHistoryStop {
    /// The next entire record cannot fit the remaining reference budget.
    ReferenceBudget,
    /// The next record is malformed, over-limit or otherwise undecidable.
    RecoveryRequired,
}
/// Keeps local truncation separate even when the provider reports chain end.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HistoryPageProgress {
    /// Every record in the provider envelope is exposed and validated.
    Complete(ProviderContinuation),
    /// Only a whole-record prefix is exposed; do not follow its provider token or checkpoint head.
    LocalPrefix {
        /// The provider's actual pagination fact, not usable to skip omitted records.
        provider: ProviderContinuation,
        /// The explicit local stopping reason.
        reason: LocalHistoryStop,
    },
}

/// Holds a validated provider envelope or an explicit bounded whole-record prefix.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoryPage {
    query: HistoryQuery,
    response_cursor: HistoryCursor,
    records: Vec<HistoryRecord>,
    progress: HistoryPageProgress,
}
impl HistoryPage {
    /// Validates envelope order before any record is offered for application.
    ///
    /// `provider_record_count` is the actual bounded envelope count, including
    /// omitted records. The decoder validates the whole protocol envelope first,
    /// then exposes only fully decoded records that fit, never partial records.
    /// The transport separately enforces the existing 2 MiB JSON cap.
    ///
    /// # Errors
    /// Rejects foreign accounts, nonincreasing/regressing cursors, over-500-record
    /// envelopes, over-10,000-reference prefixes or inconsistent local truncation.
    pub fn new(
        query: HistoryQuery,
        response_cursor: HistoryCursor,
        records: Vec<HistoryRecord>,
        provider: ProviderContinuation,
        local_stop: Option<LocalHistoryStop>,
        provider_record_count: usize,
    ) -> Result<Self, ContractError> {
        if matches!(&provider, ProviderContinuation::Next(token) if query.visited_tokens.contains(token))
        {
            return Err(ContractError::Continuation);
        }
        if provider_record_count > MAX_HISTORY_RECORDS || records.len() > provider_record_count {
            return Err(ContractError::TooMany);
        }
        if records.iter().any(|r| r.account_id() != query.account_id()) {
            return Err(ContractError::WrongAccount);
        }
        if response_cursor < query.predecessor
            || records
                .first()
                .is_some_and(|r| r.id() <= &query.predecessor)
            || records.windows(2).any(|p| p[0].id() >= p[1].id())
            || records.last().is_some_and(|r| r.id() > &response_cursor)
        {
            return Err(ContractError::Order);
        }
        if records
            .iter()
            .map(HistoryRecord::decoded_references)
            .sum::<usize>()
            > MAX_PAGE_REFERENCES
        {
            return Err(ContractError::TooMany);
        }
        let progress = match local_stop {
            None if records.len() == provider_record_count => {
                HistoryPageProgress::Complete(provider)
            }
            Some(reason) if records.len() < provider_record_count => {
                HistoryPageProgress::LocalPrefix { provider, reason }
            }
            _ => return Err(ContractError::Continuation),
        };
        Ok(Self {
            query,
            response_cursor,
            records,
            progress,
        })
    }
    /// Returns the exact request and local predecessor context.
    #[must_use]
    pub fn query(&self) -> &HistoryQuery {
        &self.query
    }
    /// Returns the provider head; only a completed chain can checkpoint it.
    #[must_use]
    pub fn response_cursor(&self) -> &HistoryCursor {
        &self.response_cursor
    }
    /// Returns the complete exposed records, in strict cursor order.
    #[must_use]
    pub fn records(&self) -> &[HistoryRecord] {
        &self.records
    }
    /// Returns provider completion or explicit local prefix truncation.
    #[must_use]
    pub fn progress(&self) -> &HistoryPageProgress {
        &self.progress
    }
}

/// Binds a durable cursor (possibly absent) to the expected account identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoryCheckpoint {
    fence: AccountFence,
    cursor: Option<HistoryCursor>,
}
impl HistoryCheckpoint {
    /// Rehydrates owning-store cursor state without granting write authority.
    #[must_use]
    pub fn new(fence: AccountFence, cursor: Option<HistoryCursor>) -> Self {
        Self { fence, cursor }
    }
    /// Returns the account and expected identity.
    #[must_use]
    pub fn fence(&self) -> &AccountFence {
        &self.fence
    }
    /// Returns the durable cursor, or absence requiring baseline-first collection.
    #[must_use]
    pub fn cursor(&self) -> Option<&HistoryCursor> {
        self.cursor.as_ref()
    }
}
/// Describes one fully decided message within a History record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HistoryDecision {
    /// Apply actual message-bound membership or missing-target evidence.
    Observe(MessageObservation),
    /// Reconcile a new recent candidate or existing envelope with complete membership.
    Metadata(MessageMetadata),
    /// Ignore an irrelevant outside-cache, unpinned, non-addition change.
    /// The store must recheck cache/pins in the same cursor transaction.
    Irrelevant(MessageKey),
}
impl HistoryDecision {
    fn key(&self) -> &MessageKey {
        match self {
            Self::Observe(o) => o.key(),
            Self::Metadata(m) => m.observation().key(),
            Self::Irrelevant(k) => k,
        }
    }
}
/// Requests all record data plus its cursor in exactly one guarded transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecidedHistoryRecord {
    expected: HistoryCheckpoint,
    record: HistoryRecord,
    decisions: Vec<HistoryDecision>,
}
impl DecidedHistoryRecord {
    /// Binds exact decision coverage to the page's immediate record predecessor.
    ///
    /// # Errors
    /// Rejects foreign identity context, invalid index, incomplete/duplicate target
    /// decisions, or treating a newly added message as an irrelevant no-op.
    pub fn new(
        fence: AccountFence,
        page: &HistoryPage,
        index: usize,
        mut decisions: Vec<HistoryDecision>,
    ) -> Result<Self, ContractError> {
        if fence.account_id() != page.query.account_id() {
            return Err(ContractError::WrongAccount);
        }
        let record = page
            .records
            .get(index)
            .ok_or(ContractError::Coverage)?
            .clone();
        let predecessor = if index == 0 {
            &page.query.predecessor
        } else {
            page.records[index - 1].id()
        };
        if decisions.len() != record.affected.len() {
            return Err(ContractError::Coverage);
        }
        decisions.sort_unstable_by(|a, b| {
            a.key()
                .message_id()
                .as_str()
                .cmp(b.key().message_id().as_str())
        });
        if !decisions
            .iter()
            .map(HistoryDecision::key)
            .eq(&record.affected)
        {
            return Err(ContractError::Coverage);
        }
        for decision in &decisions {
            if record.events.iter().any(|event| {
                event.key == *decision.key() && matches!(event.kind, HistoryEventKind::Added)
            }) {
                // A present addition needs an envelope to compete for the recent cache.
                let complete = match decision {
                    HistoryDecision::Metadata(_) => true,
                    HistoryDecision::Observe(observation) => matches!(
                        observation.state(),
                        crate::mailbox_state::RemoteMessageState::Missing
                    ),
                    HistoryDecision::Irrelevant(_) => false,
                };
                if !complete {
                    return Err(ContractError::State);
                }
            }
        }
        Ok(Self {
            expected: HistoryCheckpoint::new(fence, Some(predecessor.clone())),
            record,
            decisions,
        })
    }
    /// Returns the exact account/identity/cursor compare-and-set precondition.
    #[must_use]
    pub fn expected(&self) -> &HistoryCheckpoint {
        &self.expected
    }
    /// Returns the complete decided record whose ID is committed, never response head.
    #[must_use]
    pub fn record(&self) -> &HistoryRecord {
        &self.record
    }
    /// Returns exactly one decision per unique affected message.
    #[must_use]
    pub fn decisions(&self) -> &[HistoryDecision] {
        &self.decisions
    }
}

/// Requests a nonregressing response-head checkpoint only at a real completed chain end.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminalHistoryCheckpoint {
    expected: HistoryCheckpoint,
    cursor: HistoryCursor,
}
impl TerminalHistoryCheckpoint {
    /// Constructs final-page CAS evidence after every prior chain record was decided.
    ///
    /// # Errors
    /// Rejects foreign accounts, provider continuation and every local prefix.
    /// The trusted coordinator must establish complete prior-chain processing;
    /// the store CAS requires the final page's last record already committed.
    pub fn new(fence: AccountFence, page: &HistoryPage) -> Result<Self, ContractError> {
        if fence.account_id() != page.query.account_id() {
            return Err(ContractError::WrongAccount);
        }
        if !matches!(
            page.progress,
            HistoryPageProgress::Complete(ProviderContinuation::End)
        ) {
            return Err(ContractError::Continuation);
        }
        let predecessor = page
            .records
            .last()
            .map_or(&page.query.predecessor, HistoryRecord::id);
        Ok(Self {
            expected: HistoryCheckpoint::new(fence, Some(predecessor.clone())),
            cursor: page.response_cursor.clone(),
        })
    }
    /// Returns the exact fully applied cursor/identity required by the transaction.
    #[must_use]
    pub fn expected(&self) -> &HistoryCheckpoint {
        &self.expected
    }
    /// Returns the final nonregressing provider head to checkpoint.
    #[must_use]
    pub fn cursor(&self) -> &HistoryCursor {
        &self.cursor
    }
}

/// Captures the profile baseline before snapshot metadata collection begins.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapturedBaseline {
    account: AccountId,
    cursor: HistoryCursor,
}
impl CapturedBaseline {
    /// Wraps an actual profile-baseline read, without inferring it from a snapshot.
    #[must_use]
    pub fn new(account: AccountId, cursor: HistoryCursor) -> Self {
        Self { account, cursor }
    }
    /// Returns the baseline's owning account.
    #[must_use]
    pub fn account_id(&self) -> &AccountId {
        &self.account
    }
    /// Returns the cursor captured before collection.
    #[must_use]
    pub fn cursor(&self) -> &HistoryCursor {
        &self.cursor
    }
}
/// Holds a snapshot page of at most 25 complete metadata items, without bodies.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotPage {
    baseline: CapturedBaseline,
    items: Vec<MessageMetadata>,
    continuation: ProviderContinuation,
}
impl SnapshotPage {
    /// Validates a same-account metadata page against its pre-collected baseline.
    ///
    /// # Errors
    /// Rejects foreign or duplicate message metadata and more than 25 items.
    pub fn new(
        baseline: CapturedBaseline,
        items: Vec<MessageMetadata>,
        continuation: ProviderContinuation,
    ) -> Result<Self, ContractError> {
        validate_metadata(&baseline, &items, SNAPSHOT_PAGE_SIZE)?;
        Ok(Self {
            baseline,
            items,
            continuation,
        })
    }
    /// Returns the baseline retained before page acquisition.
    #[must_use]
    pub fn baseline(&self) -> &CapturedBaseline {
        &self.baseline
    }
    /// Returns metadata in provider order, without raw bodies.
    #[must_use]
    pub fn items(&self) -> &[MessageMetadata] {
        &self.items
    }
    /// Returns actual provider pagination, never a locally fabricated token.
    #[must_use]
    pub fn continuation(&self) -> &ProviderContinuation {
        &self.continuation
    }
}
/// Records bounded recent snapshot coverage, never full-mailbox absence evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SnapshotCoverage {
    /// The requested recent-list chain ended within the four-page budget.
    RecentChainEnded,
    /// The four-page/keep-100 budget ended collection before provider chain end.
    RecentTruncated,
}
/// Restricts baseline/snapshot fallback to the two approved triggers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SnapshotFallbackReason {
    /// No durable cursor exists yet.
    NoCursor,
    /// The exact History start cursor read returned `CursorExpired`.
    HistoryCursorExpired,
}
/// Requests one snapshot metadata/baseline transaction, with no body writes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotCommit {
    expected: HistoryCheckpoint,
    baseline: CapturedBaseline,
    metadata: Vec<MessageMetadata>,
    coverage: SnapshotCoverage,
    reason: SnapshotFallbackReason,
}
impl SnapshotCommit {
    /// Validates bounded metadata against the retained pre-collection baseline.
    ///
    /// # Errors
    /// Rejects foreign accounts, duplicate IDs and more than 100 metadata items.
    /// Coverage is supplied by the trusted bounded collector, not guessed locally.
    pub fn new(
        expected: HistoryCheckpoint,
        baseline: CapturedBaseline,
        metadata: Vec<MessageMetadata>,
        coverage: SnapshotCoverage,
        reason: SnapshotFallbackReason,
    ) -> Result<Self, ContractError> {
        if expected.fence.account_id() != baseline.account_id() {
            return Err(ContractError::WrongAccount);
        }
        validate_metadata(&baseline, &metadata, MAX_SNAPSHOT_MESSAGES)?;
        if matches!(
            (expected.cursor(), reason),
            (None, SnapshotFallbackReason::HistoryCursorExpired)
                | (Some(_), SnapshotFallbackReason::NoCursor)
        ) {
            return Err(ContractError::State);
        }
        Ok(Self {
            expected,
            baseline,
            metadata,
            coverage,
            reason,
        })
    }
    /// Returns the identity/cursor compare-and-set precondition.
    #[must_use]
    pub fn expected(&self) -> &HistoryCheckpoint {
        &self.expected
    }
    /// Returns the baseline captured before metadata acquisition.
    #[must_use]
    pub fn baseline(&self) -> &CapturedBaseline {
        &self.baseline
    }
    /// Returns metadata committed atomically with the baseline, never bodies.
    #[must_use]
    pub fn metadata(&self) -> &[MessageMetadata] {
        &self.metadata
    }
    /// Returns bounded recent coverage; omissions cannot settle commands.
    #[must_use]
    pub fn coverage(&self) -> SnapshotCoverage {
        self.coverage
    }
    /// Returns the specific permitted fallback trigger, never a generic read failure.
    #[must_use]
    pub fn reason(&self) -> SnapshotFallbackReason {
        self.reason
    }
}
fn validate_metadata(
    baseline: &CapturedBaseline,
    items: &[MessageMetadata],
    max: usize,
) -> Result<(), ContractError> {
    if items.len() > max {
        return Err(ContractError::TooMany);
    }
    let mut ids = std::collections::HashSet::new();
    for item in items {
        if item.observation().key().account_id() != baseline.account_id() {
            return Err(ContractError::WrongAccount);
        }
        if !ids.insert(item.observation().key().message_id()) {
            return Err(ContractError::Duplicate);
        }
    }
    Ok(())
}

/// Distinguishes History-cursor expiry from all other read failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HistoryFeedError {
    /// Only a History request's start-cursor 404 permits baseline/snapshot fallback.
    CursorExpired,
    /// Invalid, repeated or protocol-inconsistent provider pagination; never reset automatically.
    InvalidContinuation,
    /// A metadata/profile/transport failure, never a generic 404 fallback.
    Read(MetadataReadError),
}
impl fmt::Display for HistoryFeedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("History feed failed")
    }
}
impl std::error::Error for HistoryFeedError {}

/// Classifies one affected key without loading cached message bodies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalHistoryPresence {
    /// The message is in the bounded recent cache.
    Cached,
    /// Pending/undo evidence pins this message outside the recent cache.
    Pinned,
    /// The message is both cached and pinned.
    CachedAndPinned,
    /// Neither cache nor pins retain this key; transaction must recheck before ignoring.
    OutsideCache,
}
/// Holds exact local cache/pin classification for every affected message in one record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordLocalState {
    record: HistoryRecord,
    states: Vec<(MessageKey, LocalHistoryPresence)>,
}
impl RecordLocalState {
    /// Validates exact key coverage for a bounded record without claiming a provider observation.
    ///
    /// # Errors
    /// Rejects foreign, duplicate, extra or omitted account/message keys.
    pub fn new(
        record: HistoryRecord,
        mut states: Vec<(MessageKey, LocalHistoryPresence)>,
    ) -> Result<Self, ContractError> {
        if states.len() != record.affected.len() {
            return Err(ContractError::Coverage);
        }
        states.sort_unstable_by(|a, b| a.0.message_id().as_str().cmp(b.0.message_id().as_str()));
        if !states.iter().map(|(key, _)| key).eq(record.affected()) {
            return Err(ContractError::Coverage);
        }
        Ok(Self { record, states })
    }
    /// Returns the exact classified record, preserving account and cursor identity.
    #[must_use]
    pub fn record(&self) -> &HistoryRecord {
        &self.record
    }
    /// Returns bounded canonical cache/pin state, never desired-state success evidence.
    #[must_use]
    pub fn states(&self) -> &[(MessageKey, LocalHistoryPresence)] {
        &self.states
    }
}

/// Extends readonly remote reads without modifying the legacy mailbox port.
pub trait GmailHistoryFeed: Send + Sync {
    /// Reads a validated envelope/prefix; invalid envelopes fail before application.
    ///
    /// # Errors
    /// Resolves to a closed failure without provider or backend data; no partial success.
    fn history_page<'a>(
        &'a self,
        query: &'a HistoryQuery,
    ) -> BoxFuture<'a, Result<HistoryPage, HistoryFeedError>>;
    /// Captures profile History baseline before snapshot collection; profile 404 is not expiry.
    ///
    /// # Errors
    /// Resolves to a closed failure without provider or backend data; no partial success.
    fn capture_baseline<'a>(
        &'a self,
        account: &'a AccountId,
    ) -> BoxFuture<'a, Result<CapturedBaseline, MetadataReadError>>;
    /// Lists at most 25 metadata items after the supplied baseline was captured.
    ///
    /// # Errors
    /// Resolves to a closed failure without provider or backend data; no partial success.
    fn snapshot_page<'a>(
        &'a self,
        baseline: &'a CapturedBaseline,
        continuation: Option<&'a PageToken>,
    ) -> BoxFuture<'a, Result<SnapshotPage, MetadataReadError>>;
    /// Reads complete membership for the exact key, or explicit observed Missing.
    ///
    /// # Errors
    /// Resolves to a closed failure without provider or backend data; no partial success.
    fn observe_message<'a>(
        &'a self,
        key: &'a MessageKey,
    ) -> BoxFuture<'a, Result<MessageObservation, MetadataReadError>>;
    /// Reads complete body-free metadata or explicit exact-key Missing, never list omission.
    ///
    /// # Errors
    /// Resolves to a closed failure without provider or backend data; no partial success.
    fn message_metadata<'a>(
        &'a self,
        key: &'a MessageKey,
    ) -> BoxFuture<'a, Result<MetadataObservation, MetadataReadError>>;
}

/// Owns the indivisible data/cursor transactions; no sequential-write defaults exist.
///
/// Every operation verifies the existing account and actual stored identity in
/// its transaction. Unknown accounts never bootstrap. Record and snapshot pruning
/// preserve all nonterminal and undo pins, provider membership remains separate
/// from local-read overlays, and any failure rolls back the entire operation.
pub trait HistoryCursorStore: Send + Sync {
    /// Reads cursor for an existing identity-bound account, without provisioning.
    ///
    /// # Errors
    /// Resolves to a closed failure without provider or backend data; no partial success.
    fn checkpoint<'a>(
        &'a self,
        fence: &'a AccountFence,
    ) -> BoxFuture<'a, Result<HistoryCheckpoint, TriageStoreError>>;
    /// Reads exact cache/pin classification without bodies for bounded record planning.
    /// Recheck classification during apply; stale reads never authorize Irrelevant no-ops.
    ///
    /// # Errors
    /// Resolves to a closed failure without provider or backend data; no partial success.
    fn classify_record<'a>(
        &'a self,
        fence: &'a AccountFence,
        record: &'a HistoryRecord,
    ) -> BoxFuture<'a, Result<RecordLocalState, TriageStoreError>>;
    /// Applies every decision and exactly this record ID atomically against its predecessor.
    ///
    /// Recheck Irrelevant decisions against actual cache/pins. New additions compete
    /// deterministically for keep-100; deletes/updates include cached and pinned IDs.
    /// A stale predecessor rejects without skipping or partially applying a record.
    ///
    /// # Errors
    /// Resolves to a closed failure without provider or backend data; no partial success.
    fn apply_record<'a>(
        &'a self,
        request: &'a DecidedHistoryRecord,
    ) -> BoxFuture<'a, Result<HistoryCheckpoint, TriageStoreError>>;
    /// Checkpoints a real terminal response head only after all chain records were decided.
    ///
    /// # Errors
    /// Resolves to a closed failure without provider or backend data; no partial success.
    fn checkpoint_chain_end<'a>(
        &'a self,
        request: &'a TerminalHistoryCheckpoint,
    ) -> BoxFuture<'a, Result<HistoryCheckpoint, TriageStoreError>>;
    /// Atomically commits snapshot metadata and the previously captured baseline.
    ///
    /// Preserve pending commands, pinned rows and the previous state on any failure.
    /// Snapshot absence never settles command items; optional bodies follow commit.
    ///
    /// # Errors
    /// Resolves to a closed failure without provider or backend data; no partial success.
    fn commit_snapshot<'a>(
        &'a self,
        request: &'a SnapshotCommit,
    ) -> BoxFuture<'a, Result<HistoryCheckpoint, TriageStoreError>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        identity::IdentityHash,
        mailbox::{HeaderText, MessageId, ThreadId, UnixTimestampMillis},
        mailbox_state::RemoteMessageState,
    };
    use tersa_domain::label::LabelMembership;
    fn account(value: &str) -> AccountId {
        AccountId::new(value).expect("account")
    }
    fn cursor(value: &str) -> HistoryCursor {
        HistoryCursor::new(value).expect("cursor")
    }
    fn key(owner: &str, id: &str) -> MessageKey {
        MessageKey::new(account(owner), MessageId::new(id).expect("ID"))
    }
    fn fence(owner: &str) -> AccountFence {
        AccountFence::new(account(owner), IdentityHash::from_bytes([7; 32]))
    }
    fn event(id: &str, kind: HistoryEventKind) -> HistoryEvent {
        HistoryEvent::new(key("owner", id), kind).expect("event")
    }
    fn record(id: &str) -> HistoryRecord {
        HistoryRecord::new(
            account("owner"),
            cursor(id),
            vec![event("m", HistoryEventKind::Changed)],
            1,
        )
        .expect("record")
    }
    fn query() -> HistoryQuery {
        HistoryQuery::new(
            account("owner"),
            cursor("9"),
            PageSize::new(500).expect("size"),
        )
    }
    fn metadata(owner: &str, id: &str) -> MessageMetadata {
        let header = || HeaderText::new("synthetic").expect("header");
        let envelope = crate::mailbox::MessageEnvelope::new(
            MessageId::new(id).expect("ID"),
            ThreadId::new("t").expect("thread"),
            header(),
            header(),
            header(),
            UnixTimestampMillis::new(0).expect("time"),
            false,
        );
        MessageMetadata::new(
            key(owner, id),
            envelope,
            LabelMembership::new(account(owner), vec![]).expect("full membership"),
        )
        .expect("metadata")
    }

    // Contract: normalized references apply specific events once, under record-wide bounds.
    // Regression: generic overlap doubles work or a supported 1,000-target record cannot fit.
    #[test]
    fn records_validate_identity_normalization_and_whole_record_budget() {
        let generic = event("m", HistoryEventKind::Changed);
        let added = event("m", HistoryEventKind::Added);
        assert_eq!(
            HistoryRecord::new(
                account("owner"),
                cursor("10"),
                vec![generic.clone(), added],
                2
            ),
            Err(ContractError::Coverage)
        );
        assert_eq!(
            HistoryRecord::new(
                account("owner"),
                cursor("10"),
                vec![generic.clone(), generic.clone()],
                2
            ),
            Err(ContractError::Duplicate)
        );
        assert_eq!(
            HistoryRecord::new(account("other"), cursor("10"), vec![generic], 1),
            Err(ContractError::WrongAccount)
        );
        let events: Vec<_> = (0..1_000)
            .map(|i| event(&format!("m-{i}"), HistoryEventKind::Added))
            .collect();
        let full = HistoryRecord::new(account("owner"), cursor("10"), events.clone(), 1_000)
            .expect("full maximum record");
        assert_eq!(full.affected().len(), 1_000);
        assert!(MAX_METADATA_LOOKUPS >= full.affected().len());
        let mut overflow = events;
        overflow.push(event("extra", HistoryEventKind::Added));
        assert_eq!(
            HistoryRecord::new(account("owner"), cursor("10"), overflow, 1_001),
            Err(ContractError::TooMany)
        );
    }

    // Contract: order and local-vs-provider continuation control which cursor can be committed.
    // Regression: response head skips undecided records or a local prefix looks like chain end.
    #[test]
    fn pages_and_record_requests_bind_exact_predecessors_without_skipping() {
        let page = HistoryPage::new(
            query(),
            cursor("20"),
            vec![record("10"), record("11")],
            ProviderContinuation::End,
            None,
            2,
        )
        .expect("complete envelope");
        let decision = HistoryDecision::Observe(
            MessageObservation::new(key("owner", "m"), RemoteMessageState::Missing)
                .expect("missing"),
        );
        let second = DecidedHistoryRecord::new(fence("owner"), &page, 1, vec![decision])
            .expect("decided second record");
        assert_eq!(
            second.expected().cursor().expect("predecessor").as_str(),
            "10"
        );
        assert_eq!(second.record().id().as_str(), "11");
        assert_eq!(
            TerminalHistoryCheckpoint::new(fence("owner"), &page)
                .expect("end")
                .expected()
                .cursor()
                .expect("last applied")
                .as_str(),
            "11"
        );
        for records in [
            vec![record("11"), record("10")],
            vec![record("10"), record("10")],
            vec![record("9")],
        ] {
            let count = records.len();
            assert_eq!(
                HistoryPage::new(
                    query(),
                    cursor("20"),
                    records,
                    ProviderContinuation::End,
                    None,
                    count
                ),
                Err(ContractError::Order)
            );
        }
        let prefix = HistoryPage::new(
            query(),
            cursor("20"),
            vec![record("10")],
            ProviderContinuation::End,
            Some(LocalHistoryStop::RecoveryRequired),
            2,
        )
        .expect("whole-record prefix");
        assert!(matches!(
            prefix.progress(),
            HistoryPageProgress::LocalPrefix {
                provider: ProviderContinuation::End,
                ..
            }
        ));
        assert_eq!(
            TerminalHistoryCheckpoint::new(fence("owner"), &prefix),
            Err(ContractError::Continuation)
        );
        let continued = HistoryPage::new(
            query(),
            cursor("20"),
            vec![],
            ProviderContinuation::Next(PageToken::new("actual-provider-token").expect("token")),
            None,
            0,
        )
        .expect("empty intermediate page");
        assert_eq!(
            TerminalHistoryCheckpoint::new(fence("owner"), &continued),
            Err(ContractError::Continuation)
        );
        let empty_end = HistoryPage::new(
            query(),
            cursor("20"),
            vec![],
            ProviderContinuation::End,
            None,
            0,
        )
        .expect("empty final page");
        let terminal = TerminalHistoryCheckpoint::new(fence("owner"), &empty_end)
            .expect("valid final checkpoint");
        assert_eq!(
            terminal
                .expected()
                .cursor()
                .expect("unchanged predecessor")
                .as_str(),
            "9"
        );
        assert_eq!(terminal.cursor().as_str(), "20");
    }

    // Contract: empty intermediate pages continue from unchanged durable state, not an invented record.
    // Regression: valid empty pages fail, or stale/foreign/local-prefix state skips undecided records.
    #[test]
    fn continuation_accepts_empty_pages_only_with_matching_checkpoint_and_fresh_token() {
        let token = PageToken::new("fresh-provider-token").expect("token");
        let empty = HistoryPage::new(
            query(),
            cursor("20"),
            vec![],
            ProviderContinuation::Next(token),
            None,
            0,
        )
        .expect("valid empty intermediate page");
        let unchanged = HistoryCheckpoint::new(fence("owner"), Some(cursor("9")));
        let continued = HistoryQuery::continue_after(&empty, &unchanged)
            .expect("no nonexistent record commit required");
        assert_eq!(continued.predecessor().as_str(), "9");
        assert_eq!(continued.start().as_str(), "9");
        assert_eq!(
            continued.continuation().expect("actual token").as_str(),
            "fresh-provider-token"
        );
        for checkpoint in [
            HistoryCheckpoint::new(fence("owner"), None),
            HistoryCheckpoint::new(fence("owner"), Some(cursor("8"))),
        ] {
            assert_eq!(
                HistoryQuery::continue_after(&empty, &checkpoint),
                Err(ContractError::Order)
            );
        }
        assert_eq!(
            HistoryQuery::continue_after(
                &empty,
                &HistoryCheckpoint::new(fence("other"), Some(cursor("9")))
            ),
            Err(ContractError::WrongAccount)
        );
        let prefix = HistoryPage::new(
            query(),
            cursor("20"),
            vec![],
            ProviderContinuation::Next(PageToken::new("unusable-prefix-token").expect("token")),
            Some(LocalHistoryStop::RecoveryRequired),
            1,
        )
        .expect("locally blocked first record");
        assert_eq!(
            HistoryQuery::continue_after(&prefix, &unchanged),
            Err(ContractError::Continuation)
        );
        let incomplete = HistoryPage::new(
            query(),
            cursor("20"),
            vec![record("10")],
            ProviderContinuation::Next(PageToken::new("next-page").expect("token")),
            None,
            1,
        )
        .expect("nonempty page");
        assert_eq!(
            HistoryQuery::continue_after(&incomplete, &unchanged),
            Err(ContractError::Order)
        );
        // Four empty pages with distinct tokens fit; creating a fifth request does not.
        let mut next = continued;
        for token in ["second-token", "third-token"] {
            let page = HistoryPage::new(
                next,
                cursor("20"),
                vec![],
                ProviderContinuation::Next(PageToken::new(token).expect("token")),
                None,
                0,
            )
            .expect("fresh empty page");
            next = HistoryQuery::continue_after(&page, &unchanged).expect("within cycle budget");
        }
        let fourth = HistoryPage::new(
            next,
            cursor("20"),
            vec![],
            ProviderContinuation::Next(PageToken::new("fourth-token").expect("token")),
            None,
            0,
        )
        .expect("fourth page");
        assert_eq!(
            HistoryQuery::continue_after(&fourth, &unchanged),
            Err(ContractError::TooMany)
        );
    }

    // Contract: valid oversized pages expose a whole-record prefix instead of fabricated tokens.
    // Regression: decoder rejects every oversized page or marks a truncated prefix complete.
    #[test]
    fn local_reference_budget_is_expressible_at_whole_record_boundaries() {
        let events: Vec<_> = (0..1_000)
            .map(|i| event(&format!("m-{i}"), HistoryEventKind::Changed))
            .collect();
        let records: Vec<_> = (10..21)
            .map(|i| {
                HistoryRecord::new(
                    account("owner"),
                    cursor(&i.to_string()),
                    events.clone(),
                    1_000,
                )
                .expect("record")
            })
            .collect();
        assert_eq!(
            HistoryPage::new(
                query(),
                cursor("30"),
                records.clone(),
                ProviderContinuation::End,
                None,
                11
            ),
            Err(ContractError::TooMany)
        );
        let prefix = HistoryPage::new(
            query(),
            cursor("30"),
            records[..10].to_vec(),
            ProviderContinuation::End,
            Some(LocalHistoryStop::ReferenceBudget),
            11,
        )
        .expect("10,000-reference prefix");
        assert_eq!(prefix.records().len(), 10);
        assert_eq!(
            prefix.records().last().expect("prefix end").id().as_str(),
            "19"
        );
        assert_eq!(
            TerminalHistoryCheckpoint::new(fence("owner"), &prefix),
            Err(ContractError::Continuation)
        );
        assert_eq!(
            HistoryPage::new(
                query(),
                cursor("30"),
                vec![],
                ProviderContinuation::End,
                Some(LocalHistoryStop::ReferenceBudget),
                501
            ),
            Err(ContractError::TooMany)
        );
        let token = PageToken::new("provider-token").expect("token");
        let preceding = HistoryPage::new(
            query(),
            cursor("30"),
            vec![record("10")],
            ProviderContinuation::Next(token.clone()),
            None,
            1,
        )
        .expect("preceding page");
        let committed = HistoryCheckpoint::new(fence("owner"), Some(cursor("10")));
        let continued =
            HistoryQuery::continue_after(&preceding, &committed).expect("committed prior page");
        assert_eq!(
            HistoryPage::new(
                continued,
                cursor("30"),
                vec![],
                ProviderContinuation::Next(token),
                None,
                0
            ),
            Err(ContractError::Continuation)
        );
    }

    // Contract: every added target needs full metadata or explicit observed absence before cursor apply.
    // Regression: incomplete/no-op decisions advance the cursor over an undecided addition.
    #[test]
    fn decisions_and_local_context_require_full_exact_target_coverage() {
        let added = HistoryRecord::new(
            account("owner"),
            cursor("10"),
            vec![event("m", HistoryEventKind::Added)],
            1,
        )
        .expect("addition");
        let page = HistoryPage::new(
            query(),
            cursor("20"),
            vec![added.clone()],
            ProviderContinuation::End,
            None,
            1,
        )
        .expect("page");
        assert_eq!(
            DecidedHistoryRecord::new(fence("owner"), &page, 0, vec![]),
            Err(ContractError::Coverage)
        );
        assert_eq!(
            DecidedHistoryRecord::new(
                fence("owner"),
                &page,
                0,
                vec![HistoryDecision::Irrelevant(key("owner", "m"))]
            ),
            Err(ContractError::State)
        );
        assert_eq!(
            DecidedHistoryRecord::new(
                fence("owner"),
                &page,
                0,
                vec![HistoryDecision::Metadata(metadata("other", "m"))]
            ),
            Err(ContractError::Coverage)
        );
        let labels_only = MessageObservation::new(
            key("owner", "m"),
            RemoteMessageState::Known(
                LabelMembership::new(account("owner"), vec![]).expect("complete labels"),
            ),
        )
        .expect("observation");
        assert_eq!(
            DecidedHistoryRecord::new(
                fence("owner"),
                &page,
                0,
                vec![HistoryDecision::Observe(labels_only)]
            ),
            Err(ContractError::State)
        );
        let valid = DecidedHistoryRecord::new(
            fence("owner"),
            &page,
            0,
            vec![HistoryDecision::Metadata(metadata("owner", "m"))],
        )
        .expect("full metadata decision");
        assert_eq!(valid.decisions().len(), 1);
        assert_eq!(
            RecordLocalState::new(added.clone(), vec![]),
            Err(ContractError::Coverage)
        );
        assert!(
            RecordLocalState::new(
                added,
                vec![(key("owner", "m"), LocalHistoryPresence::Pinned)]
            )
            .is_ok()
        );
    }

    // Contract: snapshot commit retains an account-bound baseline and only approved fallback causes.
    // Regression: a generic missing read triggers fallback or metadata swaps the retained baseline.
    #[test]
    fn snapshot_contract_retains_baseline_and_rejects_foreign_or_duplicate_metadata() {
        let baseline = CapturedBaseline::new(account("owner"), cursor("5"));
        let expected = HistoryCheckpoint::new(fence("owner"), None);
        let snapshot = SnapshotCommit::new(
            expected.clone(),
            baseline.clone(),
            vec![metadata("owner", "m")],
            SnapshotCoverage::RecentTruncated,
            SnapshotFallbackReason::NoCursor,
        )
        .expect("bounded snapshot");
        assert_eq!(snapshot.baseline().cursor().as_str(), "5");
        assert_eq!(snapshot.metadata().len(), 1);
        assert_eq!(snapshot.coverage(), SnapshotCoverage::RecentTruncated);
        assert_eq!(
            SnapshotCommit::new(
                expected.clone(),
                baseline.clone(),
                vec![],
                SnapshotCoverage::RecentChainEnded,
                SnapshotFallbackReason::HistoryCursorExpired
            ),
            Err(ContractError::State)
        );
        assert_eq!(
            SnapshotPage::new(
                baseline.clone(),
                vec![metadata("other", "m")],
                ProviderContinuation::End
            ),
            Err(ContractError::WrongAccount)
        );
        assert_eq!(
            SnapshotPage::new(
                baseline,
                vec![metadata("owner", "m"), metadata("owner", "m")],
                ProviderContinuation::End
            ),
            Err(ContractError::Duplicate)
        );
    }
}
