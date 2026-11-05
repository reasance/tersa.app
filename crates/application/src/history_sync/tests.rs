// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Controlled-port protocol tests; SQL transaction guarantees belong to P5b.
// Rust guideline compliant 1.0.

#![expect(
    clippy::unwrap_used,
    reason = "controlled tests use valid synthetic values"
)]

use super::*;
use crate::{
    history::{CapturedBaseline, HistoryEvent, HistoryRecord, RecordLocalState, SnapshotPage},
    identity::IdentityHash,
    mailbox::{
        AccountId, HeaderText, MessageEnvelope, MessageId, PageToken, ThreadId, UnixTimestampMillis,
    },
    mailbox_state::{MessageKey, MessageMetadata},
};
use std::{
    collections::VecDeque,
    future::poll_fn,
    pin::pin,
    sync::Mutex,
    task::{Context, Poll, Waker},
};
use tersa_domain::label::{LabelId, LabelMembership};

fn account() -> AccountId {
    AccountId::new("owner").unwrap()
}
fn fence() -> AccountFence {
    AccountFence::new(account(), IdentityHash::from_bytes([7; 32]))
}
fn cursor(value: &str) -> HistoryCursor {
    HistoryCursor::new(value).unwrap()
}
fn token(value: &str) -> PageToken {
    PageToken::new(value).unwrap()
}
fn key(id: &str) -> MessageKey {
    MessageKey::new(account(), MessageId::new(id).unwrap())
}
fn metadata(id: &str) -> MessageMetadata {
    MessageMetadata::new(
        key(id),
        MessageEnvelope::new(
            MessageId::new(id).unwrap(),
            ThreadId::new("thread").unwrap(),
            HeaderText::new("sender").unwrap(),
            HeaderText::new("subject").unwrap(),
            HeaderText::new("preview").unwrap(),
            UnixTimestampMillis::new(10).unwrap(),
            true,
        ),
        LabelMembership::new(account(), vec![LabelId::new("INBOX").unwrap()]).unwrap(),
    )
    .unwrap()
}
fn record(id: &str, ids: &[&str], kind: &HistoryEventKind) -> HistoryRecord {
    HistoryRecord::new(
        account(),
        cursor(id),
        ids.iter()
            .map(|id| HistoryEvent::new(key(id), kind.clone()).unwrap())
            .collect(),
        ids.len(),
    )
    .unwrap()
}
fn added(id: &str, ids: &[&str]) -> HistoryRecord {
    record(id, ids, &HistoryEventKind::Added)
}
fn thousand(id: &str) -> HistoryRecord {
    let ids: Vec<_> = (0..1_000).map(|i| format!("large-{i}")).collect();
    added(id, &ids.iter().map(String::as_str).collect::<Vec<_>>())
}
fn run<T>(future: impl Future<Output = T>) -> T {
    let mut future = pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("unexpected gated operation"),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Call {
    Checkpoint,
    History(HistoryQuery),
    Baseline,
    Snapshot(Option<PageToken>),
    Classify(HistoryCursor),
    Metadata(MessageKey),
    Apply(HistoryCursor),
    Terminal,
    SnapshotCommit,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Stage {
    Baseline,
    Snapshot(usize),
    Metadata(usize),
    Apply(usize),
    SnapshotCommit,
}

#[derive(Default)]
struct Control {
    calls: Mutex<Vec<Call>>,
    gate: Mutex<Option<Stage>>,
}
impl Control {
    fn call(&self, call: Call) {
        self.calls.lock().unwrap().push(call);
    }
    async fn wait(&self, stage: Stage) {
        poll_fn(|_cx| {
            if *self.gate.lock().unwrap() == Some(stage) {
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        })
        .await;
    }
}

struct PageSpec {
    records: Vec<HistoryRecord>,
    next: ProviderContinuation,
    local: Option<LocalHistoryStop>,
    wrong_query: bool,
}
impl PageSpec {
    fn end(records: Vec<HistoryRecord>) -> Self {
        Self {
            records,
            next: ProviderContinuation::End,
            local: None,
            wrong_query: false,
        }
    }
    fn next(records: Vec<HistoryRecord>, value: &str) -> Self {
        Self {
            next: ProviderContinuation::Next(token(value)),
            ..Self::end(records)
        }
    }
}

struct SnapshotSpec {
    items: Vec<MessageMetadata>,
    next: ProviderContinuation,
    wrong_baseline: bool,
}
impl SnapshotSpec {
    fn new(ids: &[&str], next: ProviderContinuation) -> Self {
        Self {
            items: ids.iter().map(|id| metadata(id)).collect(),
            next,
            wrong_baseline: false,
        }
    }
}

struct Remote<'a> {
    control: &'a Control,
    pages: Mutex<VecDeque<Result<PageSpec, HistoryFeedError>>>,
    snapshots: Mutex<VecDeque<Result<SnapshotSpec, MetadataReadError>>>,
    baseline: Result<CapturedBaseline, MetadataReadError>,
    metadata_failure: Option<(usize, MetadataReadError)>,
    metadata_reply: Option<(usize, MetadataObservation)>,
    metadata_calls: Mutex<usize>,
    snapshot_calls: Mutex<usize>,
}
impl<'a> Remote<'a> {
    fn new(control: &'a Control, pages: Vec<PageSpec>) -> Self {
        Self {
            control,
            pages: Mutex::new(pages.into_iter().map(Ok).collect()),
            snapshots: Mutex::default(),
            baseline: Ok(CapturedBaseline::new(account(), cursor("9000"))),
            metadata_failure: None,
            metadata_reply: None,
            metadata_calls: Mutex::new(0),
            snapshot_calls: Mutex::new(0),
        }
    }
}
impl GmailHistoryFeed for Remote<'_> {
    fn history_page<'a>(
        &'a self,
        query: &'a HistoryQuery,
    ) -> BoxFuture<'a, Result<HistoryPage, HistoryFeedError>> {
        Box::pin(async move {
            self.control.call(Call::History(query.clone()));
            let spec = self
                .pages
                .lock()
                .unwrap()
                .pop_front()
                .expect("scripted page")?;
            let query = if spec.wrong_query {
                HistoryQuery::new(account(), cursor("1"), query.page_size())
            } else {
                query.clone()
            };
            let count = spec.records.len() + usize::from(spec.local.is_some());
            HistoryPage::new(
                query,
                cursor("8000"),
                spec.records,
                spec.next,
                spec.local,
                count,
            )
            .map_err(|error| match error {
                ContractError::Continuation => HistoryFeedError::InvalidContinuation,
                _ => HistoryFeedError::Read(MetadataReadError::InvalidResponse),
            })
        })
    }
    fn capture_baseline<'a>(
        &'a self,
        owner: &'a AccountId,
    ) -> BoxFuture<'a, Result<CapturedBaseline, MetadataReadError>> {
        Box::pin(async move {
            assert_eq!(owner, &account());
            self.control.call(Call::Baseline);
            self.control.wait(Stage::Baseline).await;
            self.baseline.clone()
        })
    }
    fn snapshot_page<'a>(
        &'a self,
        baseline: &'a CapturedBaseline,
        continuation: Option<&'a PageToken>,
    ) -> BoxFuture<'a, Result<SnapshotPage, MetadataReadError>> {
        Box::pin(async move {
            self.control.call(Call::Snapshot(continuation.cloned()));
            let count = {
                let mut count = self.snapshot_calls.lock().unwrap();
                *count += 1;
                *count
            };
            self.control.wait(Stage::Snapshot(count)).await;
            let spec = self
                .snapshots
                .lock()
                .unwrap()
                .pop_front()
                .expect("snapshot page")?;
            let baseline = if spec.wrong_baseline {
                CapturedBaseline::new(account(), cursor("9001"))
            } else {
                baseline.clone()
            };
            SnapshotPage::new(baseline, spec.items, spec.next)
                .map_err(|_error| MetadataReadError::InvalidResponse)
        })
    }
    fn observe_message<'a>(
        &'a self,
        _key: &'a MessageKey,
    ) -> BoxFuture<'a, Result<MessageObservation, MetadataReadError>> {
        Box::pin(async { panic!("membership-only fetch would lose legacy envelope updates") })
    }
    fn message_metadata<'a>(
        &'a self,
        requested: &'a MessageKey,
    ) -> BoxFuture<'a, Result<MetadataObservation, MetadataReadError>> {
        Box::pin(async move {
            self.control.call(Call::Metadata(requested.clone()));
            let count = {
                let mut count = self.metadata_calls.lock().unwrap();
                *count += 1;
                *count
            };
            self.control.wait(Stage::Metadata(count)).await;
            if let Some((at, error)) = self.metadata_failure
                && count == at
            {
                return Err(error);
            }
            if let Some((at, reply)) = &self.metadata_reply
                && count == *at
            {
                return Ok(reply.clone());
            }
            Ok(MetadataObservation::Known(metadata(
                requested.message_id().as_str(),
            )))
        })
    }
}

struct Stored {
    checkpoint: HistoryCheckpoint,
    records: Vec<DecidedHistoryRecord>,
    snapshots: Vec<SnapshotCommit>,
    terminal_commits: usize,
}
struct Store<'a> {
    control: &'a Control,
    state: Mutex<Stored>,
    checkpoint_error: Option<TriageStoreError>,
    checkpoint_reply: Option<HistoryCheckpoint>,
    classify_wrong: bool,
    presence: Vec<(MessageKey, LocalHistoryPresence)>,
    apply_failure: Option<(usize, TriageStoreError)>,
    apply_reply: Option<HistoryCheckpoint>,
    terminal_error: Option<TriageStoreError>,
    snapshot_error: Option<TriageStoreError>,
}
impl<'a> Store<'a> {
    fn new(control: &'a Control, start: Option<&str>) -> Self {
        Self {
            control,
            state: Mutex::new(Stored {
                checkpoint: HistoryCheckpoint::new(fence(), start.map(cursor)),
                records: Vec::new(),
                snapshots: Vec::new(),
                terminal_commits: 0,
            }),
            checkpoint_error: None,
            checkpoint_reply: None,
            classify_wrong: false,
            presence: Vec::new(),
            apply_failure: None,
            apply_reply: None,
            terminal_error: None,
            snapshot_error: None,
        }
    }
    fn cas(state: &Stored, expected: &HistoryCheckpoint) -> Result<(), TriageStoreError> {
        if state.checkpoint.fence() != expected.fence() {
            return Err(TriageStoreError::IdentityChanged);
        }
        if &state.checkpoint != expected {
            return Err(TriageStoreError::Conflict);
        }
        Ok(())
    }
}
impl HistoryCursorStore for Store<'_> {
    fn checkpoint<'a>(
        &'a self,
        requested: &'a AccountFence,
    ) -> BoxFuture<'a, Result<HistoryCheckpoint, TriageStoreError>> {
        Box::pin(async move {
            assert_eq!(requested, &fence());
            self.control.call(Call::Checkpoint);
            if let Some(error) = self.checkpoint_error {
                return Err(error);
            }
            Ok(self
                .checkpoint_reply
                .clone()
                .unwrap_or_else(|| self.state.lock().unwrap().checkpoint.clone()))
        })
    }
    fn classify_record<'a>(
        &'a self,
        _fence: &'a AccountFence,
        requested: &'a HistoryRecord,
    ) -> BoxFuture<'a, Result<RecordLocalState, TriageStoreError>> {
        Box::pin(async move {
            self.control.call(Call::Classify(requested.id().clone()));
            let record = if self.classify_wrong {
                added("7000", &["foreign-record"])
            } else {
                requested.clone()
            };
            let states = record
                .affected()
                .iter()
                .map(|key| {
                    let presence = self
                        .presence
                        .iter()
                        .find(|(k, _)| k == key)
                        .map_or(LocalHistoryPresence::Cached, |(_, presence)| *presence);
                    (key.clone(), presence)
                })
                .collect();
            Ok(RecordLocalState::new(record, states).unwrap())
        })
    }
    fn apply_record<'a>(
        &'a self,
        request: &'a DecidedHistoryRecord,
    ) -> BoxFuture<'a, Result<HistoryCheckpoint, TriageStoreError>> {
        Box::pin(async move {
            self.control
                .call(Call::Apply(request.record().id().clone()));
            let count = self.state.lock().unwrap().records.len() + 1;
            self.control.wait(Stage::Apply(count)).await;
            if let Some((at, error)) = self.apply_failure
                && count == at
            {
                return Err(error);
            }
            let mut state = self.state.lock().unwrap();
            Self::cas(&state, request.expected())?;
            state.checkpoint = HistoryCheckpoint::new(
                request.expected().fence().clone(),
                Some(request.record().id().clone()),
            );
            state.records.push(request.clone());
            Ok(self
                .apply_reply
                .clone()
                .unwrap_or_else(|| state.checkpoint.clone()))
        })
    }
    fn checkpoint_chain_end<'a>(
        &'a self,
        request: &'a TerminalHistoryCheckpoint,
    ) -> BoxFuture<'a, Result<HistoryCheckpoint, TriageStoreError>> {
        Box::pin(async move {
            self.control.call(Call::Terminal);
            if let Some(error) = self.terminal_error {
                return Err(error);
            }
            let mut state = self.state.lock().unwrap();
            Self::cas(&state, request.expected())?;
            state.checkpoint = HistoryCheckpoint::new(
                request.expected().fence().clone(),
                Some(request.cursor().clone()),
            );
            state.terminal_commits += 1;
            Ok(state.checkpoint.clone())
        })
    }
    fn commit_snapshot<'a>(
        &'a self,
        request: &'a SnapshotCommit,
    ) -> BoxFuture<'a, Result<HistoryCheckpoint, TriageStoreError>> {
        Box::pin(async move {
            self.control.call(Call::SnapshotCommit);
            self.control.wait(Stage::SnapshotCommit).await;
            if let Some(error) = self.snapshot_error {
                return Err(error);
            }
            let mut state = self.state.lock().unwrap();
            Self::cas(&state, request.expected())?;
            state.checkpoint = HistoryCheckpoint::new(
                request.expected().fence().clone(),
                Some(request.baseline().cursor().clone()),
            );
            state.snapshots.push(request.clone());
            Ok(state.checkpoint.clone())
        })
    }
}

fn confirmed(report: &HistorySyncReport) -> Option<&str> {
    report
        .checkpoint()
        .and_then(HistoryCheckpoint::cursor)
        .map(HistoryCursor::as_str)
}
fn recovery(reason: HistoryRecoveryReason) -> HistorySyncStop {
    HistorySyncStop::RecoveryRequired(reason)
}

// Contract: page tokens are followed only after complete records commit; real
// empty intermediate and terminal pages are valid. A response-head shortcut or
// reordering fails the independent cursor CAS and exact request trace.
#[test]
fn multiple_pages_empty_intermediate_and_terminal_checkpoint_follow_durable_prefix() {
    let control = Control::default();
    let remote = Remote::new(
        &control,
        vec![
            PageSpec::next(vec![added("10", &["a"]), added("12", &["b"])], "one"),
            PageSpec::next(vec![], "two"),
            PageSpec::next(vec![added("20", &["c"])], "three"),
            PageSpec::end(vec![]),
        ],
    );
    let store = Store::new(&control, Some("9"));
    let report = run(HistorySync::new(&remote, &store).sync(&fence()));
    assert_eq!(report.stop(), HistorySyncStop::CaughtUp);
    assert_eq!(confirmed(&report), Some("8000"));
    assert_eq!(report.progress().history_requests, 4);
    assert_eq!(report.progress().records_committed, 3);
    let state = store.state.lock().unwrap();
    assert_eq!(
        state
            .records
            .iter()
            .map(|r| r.record().id().as_str())
            .collect::<Vec<_>>(),
        ["10", "12", "20"]
    );
    assert_eq!(state.terminal_commits, 1);
    let calls = control.calls.lock().unwrap();
    let queries: Vec<_> = calls
        .iter()
        .filter_map(|call| match call {
            Call::History(query) => Some(query),
            _ => None,
        })
        .collect();
    assert!(queries.iter().all(|q| q.start().as_str() == "9"));
    assert_eq!(
        queries
            .iter()
            .map(|q| q.predecessor().as_str())
            .collect::<Vec<_>>(),
        ["9", "12", "12", "20"]
    );
    assert_eq!(
        queries
            .iter()
            .map(|q| q.continuation().map(PageToken::as_str))
            .collect::<Vec<_>>(),
        [None, Some("one"), Some("two"), Some("three")]
    );
    assert_eq!(calls.last(), Some(&Call::Terminal));
    assert_eq!(report.body_plan().unwrap().limit(), 25);
    assert_eq!(report.body_plan().unwrap().fence(), &fence());
}

// Contract: complete membership and envelope metadata replace deltas for relevant
// keys; additions cannot be ignored outside cache. No existing constructor test
// proves that the coordinator chooses these fetches and forwards their results.
#[test]
fn classifies_every_target_and_fetches_metadata_for_cached_pinned_and_added_keys() {
    let control = Control::default();
    let events = [
        (
            "cached",
            HistoryEventKind::LabelsRemoved(vec![LabelId::new("UNREAD").unwrap()]),
        ),
        ("pinned", HistoryEventKind::Deleted),
        ("outside", HistoryEventKind::Changed),
        ("new", HistoryEventKind::Added),
    ]
    .into_iter()
    .map(|(id, kind)| HistoryEvent::new(key(id), kind).unwrap())
    .collect();
    let record = HistoryRecord::new(account(), cursor("10"), events, 4).unwrap();
    let mut remote = Remote::new(&control, vec![PageSpec::end(vec![record])]);
    // Canonical order is cached, new, outside, pinned.
    remote.metadata_reply = Some((3, MetadataObservation::Missing(key("pinned"))));
    let mut store = Store::new(&control, Some("9"));
    store.presence = vec![
        (key("pinned"), LocalHistoryPresence::Pinned),
        (key("outside"), LocalHistoryPresence::OutsideCache),
        (key("new"), LocalHistoryPresence::OutsideCache),
    ];
    let report = run(HistorySync::new(&remote, &store).sync(&fence()));
    assert_eq!(report.stop(), HistorySyncStop::CaughtUp);
    assert_eq!(report.progress().metadata_requests, 3);
    let state = store.state.lock().unwrap();
    let decisions = state.records[0].decisions();
    assert_eq!(
        decisions,
        &[
            HistoryDecision::Metadata(metadata("cached")),
            HistoryDecision::Metadata(metadata("new")),
            HistoryDecision::Irrelevant(key("outside")),
            HistoryDecision::Observe(
                MessageObservation::new(key("pinned"), RemoteMessageState::Missing).unwrap()
            ),
        ]
    );
    let calls = control.calls.lock().unwrap();
    assert!(matches!(calls[2], Call::Classify(_)));
    assert!(matches!(calls[3], Call::Metadata(_)));
}

// Contract: reserve the entire next record before spending any of its lookups.
// A regression that spends 999 lookups then truncates a 1,000-target record would
// fail both the request count and next-cycle successful record commit.
#[test]
fn reserves_whole_next_record_and_thousand_targets_fit_a_fresh_cycle() {
    let control = Control::default();
    let remote = Remote::new(
        &control,
        vec![
            PageSpec::end(vec![added("10", &["small"]), thousand("11")]),
            PageSpec::end(vec![thousand("11")]),
        ],
    );
    let store = Store::new(&control, Some("9"));
    let sync = HistorySync::new(&remote, &store);
    let report = run(sync.sync(&fence()));
    assert_eq!(
        report.stop(),
        HistorySyncStop::Bounded(HistorySyncBudget::Metadata)
    );
    assert_eq!(confirmed(&report), Some("10"));
    assert_eq!(report.progress().metadata_requests, 1);
    assert_eq!(store.state.lock().unwrap().terminal_commits, 0);
    let resumed = run(sync.sync(&fence()));
    assert_eq!(resumed.stop(), HistorySyncStop::CaughtUp);
    assert_eq!(resumed.progress().metadata_requests, 1_000);
    let state = store.state.lock().unwrap();
    assert_eq!(state.records.len(), 2);
    assert_eq!(state.records[1].decisions().len(), 1_000);
    let calls = control.calls.lock().unwrap();
    let queries: Vec<_> = calls
        .iter()
        .filter_map(|call| match call {
            Call::History(query) => Some(query),
            _ => None,
        })
        .collect();
    assert_eq!(queries[1].start(), &cursor("10"));
    assert!(queries[1].continuation().is_none());
}

// Contract: exposed local prefixes never checkpoint head or follow a provider
// token past omitted records, including when the provider says End.
#[test]
fn local_prefixes_keep_known_cursor_and_report_bound_or_undecidable() {
    for provider in [
        ProviderContinuation::End,
        ProviderContinuation::Next(token("skip")),
    ] {
        for (reason, progressing) in [
            (LocalHistoryStop::ReferenceBudget, true),
            (LocalHistoryStop::RecoveryRequired, true),
            (LocalHistoryStop::ReferenceBudget, false),
            (LocalHistoryStop::RecoveryRequired, false),
        ] {
            let control = Control::default();
            let spec = PageSpec {
                next: provider.clone(),
                local: Some(reason),
                ..PageSpec::end(if progressing {
                    vec![added("10", &["a"])]
                } else {
                    vec![]
                })
            };
            let remote = Remote::new(&control, vec![spec]);
            let store = Store::new(&control, Some("9"));
            let report = run(HistorySync::new(&remote, &store).sync(&fence()));
            assert_eq!(
                confirmed(&report),
                Some(if progressing { "10" } else { "9" })
            );
            assert_eq!(
                report.stop(),
                match reason {
                    LocalHistoryStop::ReferenceBudget if progressing =>
                        HistorySyncStop::Bounded(HistorySyncBudget::References),
                    LocalHistoryStop::ReferenceBudget =>
                        recovery(HistoryRecoveryReason::NoProgress),
                    LocalHistoryStop::RecoveryRequired =>
                        recovery(HistoryRecoveryReason::UndecidableRecord),
                }
            );
            assert_eq!(store.state.lock().unwrap().terminal_commits, 0);
            assert_eq!(report.progress().history_requests, 1);
        }
    }
}

// Contract: late expiry shares the metadata bound with snapshot hydration. At
// 900 History lookups a full 100-message snapshot fits; above it, preserve the
// prefix and defer the whole fallback collection until a fresh explicit cycle.
#[test]
fn late_expiry_reserves_the_whole_snapshot_within_the_shared_lookup_budget() {
    for count in [900, 901, 1_000] {
        let control = Control::default();
        let ids: Vec<_> = (0..count).map(|i| format!("history-{i}")).collect();
        let record = added("10", &ids.iter().map(String::as_str).collect::<Vec<_>>());
        let remote = Remote::new(&control, vec![PageSpec::next(vec![record], "next")]);
        remote.pages.lock().unwrap().extend([
            Err(HistoryFeedError::CursorExpired),
            Err(HistoryFeedError::CursorExpired),
        ]);
        for page in 0..4 {
            remote.snapshots.lock().unwrap().push_back(Ok(SnapshotSpec {
                items: (0..25)
                    .map(|i| metadata(&format!("snapshot-{}", page * 25 + i)))
                    .collect(),
                next: ProviderContinuation::Next(token(&format!("snapshot-next-{page}"))),
                wrong_baseline: false,
            }));
        }
        let store = Store::new(&control, Some("9"));
        let sync = HistorySync::new(&remote, &store);
        let report = run(sync.sync(&fence()));
        assert_eq!(report.progress().records_committed, 1);
        let progress = report.progress();
        assert!(progress.metadata_requests + 25 * progress.snapshot_requests <= 1_000);
        if count == 900 {
            assert_eq!(
                report.stop(),
                HistorySyncStop::SnapshotCommitted(SnapshotCoverage::RecentTruncated)
            );
            assert_eq!(confirmed(&report), Some("9000"));
            assert_eq!(progress.snapshot_messages_committed, 100);
        } else {
            assert_eq!(
                report.stop(),
                HistorySyncStop::Bounded(HistorySyncBudget::Metadata)
            );
            assert_eq!(confirmed(&report), Some("10"));
            assert!(!control.calls.lock().unwrap().contains(&Call::Baseline));
            let resumed = run(sync.sync(&fence()));
            assert_eq!(
                resumed.stop(),
                HistorySyncStop::SnapshotCommitted(SnapshotCoverage::RecentTruncated)
            );
            let state = store.state.lock().unwrap();
            assert_eq!(state.snapshots[0].expected().cursor(), Some(&cursor("10")));
        }
    }
}

// Contract: expiry permits collection but a subsequent snapshot failure still
// retains records already committed in this invocation and their body plan.
#[test]
fn failed_fallback_after_a_history_prefix_retains_confirmed_progress() {
    let control = Control::default();
    let remote = Remote::new(
        &control,
        vec![PageSpec::next(vec![added("10", &["a"])], "next")],
    );
    remote
        .pages
        .lock()
        .unwrap()
        .push_back(Err(HistoryFeedError::CursorExpired));
    remote.snapshots.lock().unwrap().extend([
        Ok(SnapshotSpec::new(
            &["b"],
            ProviderContinuation::Next(token("snapshot-next")),
        )),
        Err(MetadataReadError::Transport),
    ]);
    let store = Store::new(&control, Some("9"));
    let report = run(HistorySync::new(&remote, &store).sync(&fence()));
    assert_eq!(
        report.stop(),
        recovery(HistoryRecoveryReason::Read(MetadataReadError::Transport))
    );
    assert_eq!(confirmed(&report), Some("10"));
    assert_eq!(report.progress().records_committed, 1);
    assert_eq!(report.progress().snapshot_messages_committed, 0);
    assert!(report.body_plan().is_some());
    assert!(
        !control
            .calls
            .lock()
            .unwrap()
            .contains(&Call::SnapshotCommit)
    );
}

// Contract: bounded empty chains require recovery; finite progressing chains
// stop at four pages/2,000 complete records without claiming the provider head.
#[test]
fn page_and_record_limits_distinguish_progress_from_no_progress() {
    for progressing in [false, true] {
        let control = Control::default();
        let pages = (0..4)
            .map(|page| {
                let records = if progressing {
                    (0..500)
                        .map(|offset| {
                            record(
                                &(10 + page * 500 + offset).to_string(),
                                &[],
                                &HistoryEventKind::Changed,
                            )
                        })
                        .collect()
                } else {
                    vec![]
                };
                PageSpec::next(records, &format!("page-{page}"))
            })
            .collect();
        let remote = Remote::new(&control, pages);
        let store = Store::new(&control, Some("9"));
        let report = run(HistorySync::new(&remote, &store).sync(&fence()));
        assert_eq!(report.progress().history_requests, 4);
        assert_eq!(
            report.stop(),
            if progressing {
                HistorySyncStop::Bounded(HistorySyncBudget::PagesOrRecords)
            } else {
                recovery(HistoryRecoveryReason::NoProgress)
            }
        );
        assert_eq!(
            confirmed(&report),
            Some(if progressing { "2009" } else { "9" })
        );
        assert_eq!(
            report.progress().records_committed,
            if progressing { 2_000 } else { 0 }
        );
        assert_eq!(store.state.lock().unwrap().terminal_commits, 0);
    }
}

// Contract: later remote/store/terminal failures retain the earlier confirmed
// durable prefix, never claim caught-up and never cause destructive fallback.
#[test]
fn later_failures_retain_prefix_and_do_not_fallback() {
    for failure in 0..5 {
        let control = Control::default();
        let mut remote = Remote::new(
            &control,
            vec![PageSpec::end(vec![
                added("10", &["a"]),
                added("11", &["b"]),
            ])],
        );
        let mut store = Store::new(&control, Some("9"));
        let expected = match failure {
            0 => {
                remote.metadata_failure = Some((2, MetadataReadError::Transport));
                HistoryRecoveryReason::Read(MetadataReadError::Transport)
            }
            1 => {
                store.apply_failure = Some((2, TriageStoreError::Storage));
                HistoryRecoveryReason::Store(TriageStoreError::Storage)
            }
            2 => {
                store.apply_failure = Some((2, TriageStoreError::Conflict));
                HistoryRecoveryReason::Store(TriageStoreError::Conflict)
            }
            3 => {
                store.apply_failure = Some((2, TriageStoreError::IdentityChanged));
                HistoryRecoveryReason::Store(TriageStoreError::IdentityChanged)
            }
            _ => {
                store.terminal_error = Some(TriageStoreError::Storage);
                HistoryRecoveryReason::Store(TriageStoreError::Storage)
            }
        };
        let report = run(HistorySync::new(&remote, &store).sync(&fence()));
        assert_eq!(report.stop(), recovery(expected));
        assert_eq!(
            confirmed(&report),
            Some(if failure == 4 { "11" } else { "10" })
        );
        assert_eq!(
            report.progress().records_committed,
            if failure == 4 { 2 } else { 1 }
        );
        assert!(report.body_plan().is_some());
        assert!(!control.calls.lock().unwrap().contains(&Call::Baseline));
    }
}

// Contract: a later page failure cannot erase prior page progress. The table
// covers errors that must not be confused with the typed History-cursor expiry.
#[test]
fn nonexpiry_history_failures_never_trigger_snapshot() {
    for error in [
        HistoryFeedError::InvalidContinuation,
        HistoryFeedError::Read(MetadataReadError::ProfileMissing),
        HistoryFeedError::Read(MetadataReadError::Transport),
        HistoryFeedError::Read(MetadataReadError::AuthorizationRequired),
        HistoryFeedError::Read(MetadataReadError::RateLimited),
        HistoryFeedError::Read(MetadataReadError::InvalidResponse),
    ] {
        let control = Control::default();
        let remote = Remote::new(
            &control,
            vec![PageSpec::next(vec![added("10", &["a"])], "next")],
        );
        remote.pages.lock().unwrap().push_back(Err(error));
        let store = Store::new(&control, Some("9"));
        let report = run(HistorySync::new(&remote, &store).sync(&fence()));
        assert_eq!(report.stop(), recovery(HistoryRecoveryReason::Feed(error)));
        assert_eq!(confirmed(&report), Some("10"));
        assert_eq!(report.progress().records_committed, 1);
        assert!(!control.calls.lock().unwrap().contains(&Call::Baseline));
    }
}

// Contract: repeated/invalid continuations fail closed at acquisition, never
// follow a loop or commit records from a rejected page envelope.
#[test]
fn repeated_token_is_recovery_without_applying_the_rejected_page() {
    let control = Control::default();
    let remote = Remote::new(
        &control,
        vec![
            PageSpec::next(vec![added("10", &["a"])], "repeat"),
            PageSpec::next(vec![added("11", &["b"])], "repeat"),
        ],
    );
    let store = Store::new(&control, Some("9"));
    let report = run(HistorySync::new(&remote, &store).sync(&fence()));
    assert_eq!(
        report.stop(),
        recovery(HistoryRecoveryReason::Feed(
            HistoryFeedError::InvalidContinuation
        ))
    );
    assert_eq!(confirmed(&report), Some("10"));
    assert_eq!(report.progress().metadata_requests, 1);
    assert_eq!(report.progress().history_requests, 2);
}

// Contract: a structurally valid response for a different query/key/account or
// classification record cannot be rebound to the requested operation.
#[test]
fn mismatched_documents_stop_before_record_apply() {
    for mismatch in 0..5 {
        let control = Control::default();
        let mut spec = PageSpec::end(vec![added("10", &["a"])]);
        spec.wrong_query = mismatch == 0;
        let mut remote = Remote::new(&control, vec![spec]);
        let mut store = Store::new(&control, Some("9"));
        match mismatch {
            1 => {
                remote.metadata_reply =
                    Some((1, MetadataObservation::Known(metadata("wrong-key"))));
            }
            2 => {
                remote.metadata_reply = Some((
                    1,
                    MetadataObservation::Missing(MessageKey::new(
                        AccountId::new("foreign").unwrap(),
                        MessageId::new("a").unwrap(),
                    )),
                ));
            }
            3 => store.classify_wrong = true,
            4 => {
                store.checkpoint_reply = Some(HistoryCheckpoint::new(
                    AccountFence::new(account(), IdentityHash::from_bytes([8; 32])),
                    Some(cursor("9")),
                ));
            }
            _ => {}
        }
        let report = run(HistorySync::new(&remote, &store).sync(&fence()));
        assert!(matches!(
            report.stop(),
            HistorySyncStop::RecoveryRequired(HistoryRecoveryReason::Contract(_))
        ));
        assert!(store.state.lock().unwrap().records.is_empty());
        assert!(report.body_plan().is_none());
        assert!(!control.calls.lock().unwrap().contains(&Call::Baseline));
    }
}

// Contract: an invalid commit receipt does not turn an unknown store outcome into
// confirmed progress. A new cycle must reread actual state before resuming.
#[test]
fn invalid_store_receipt_keeps_the_last_confirmed_checkpoint() {
    let control = Control::default();
    let remote = Remote::new(&control, vec![PageSpec::end(vec![added("10", &["a"])])]);
    let mut store = Store::new(&control, Some("9"));
    store.apply_reply = Some(HistoryCheckpoint::new(fence(), Some(cursor("11"))));
    let report = run(HistorySync::new(&remote, &store).sync(&fence()));
    assert_eq!(
        report.stop(),
        recovery(HistoryRecoveryReason::Contract(ContractError::State))
    );
    assert_eq!(confirmed(&report), Some("9"));
    assert_eq!(report.progress().records_committed, 0);
    assert!(report.body_plan().is_none());
    assert_eq!(
        store.state.lock().unwrap().checkpoint.cursor(),
        Some(&cursor("10"))
    );
}

// Contract: only absence of a stored cursor or typed expiry invokes fallback;
// the snapshot commit carries the original pre-collection baseline and reason.
#[test]
fn baseline_first_snapshot_commit_is_last_for_both_approved_triggers() {
    for start in [None, Some("9")] {
        let control = Control::default();
        let remote = Remote::new(&control, vec![]);
        if start.is_some() {
            remote
                .pages
                .lock()
                .unwrap()
                .push_back(Err(HistoryFeedError::CursorExpired));
        }
        remote.snapshots.lock().unwrap().extend([
            Ok(SnapshotSpec::new(
                &["a"],
                ProviderContinuation::Next(token("more")),
            )),
            Ok(SnapshotSpec::new(&["b"], ProviderContinuation::End)),
        ]);
        let store = Store::new(&control, start);
        let report = run(HistorySync::new(&remote, &store).sync(&fence()));
        assert_eq!(
            report.stop(),
            HistorySyncStop::SnapshotCommitted(SnapshotCoverage::RecentChainEnded)
        );
        assert_eq!(confirmed(&report), Some("9000"));
        assert_eq!(report.progress().snapshot_messages_committed, 2);
        let state = store.state.lock().unwrap();
        let request = &state.snapshots[0];
        assert_eq!(request.baseline().cursor(), &cursor("9000"));
        assert_eq!(request.expected().cursor(), start.map(cursor).as_ref());
        assert_eq!(
            request.reason(),
            if start.is_some() {
                SnapshotFallbackReason::HistoryCursorExpired
            } else {
                SnapshotFallbackReason::NoCursor
            }
        );
        assert_eq!(request.metadata(), &[metadata("a"), metadata("b")]);
        // The coordinator submits only actual collected metadata, not invented
        // Missing observations for omitted pinned/command targets. SQL preservation
        // and command settlement are independently owned by P5b/P6b.
        assert_eq!(state.records.len(), 0);
        let calls = control.calls.lock().unwrap();
        let offset = usize::from(start.is_some());
        assert_eq!(
            calls[1 + offset..],
            [
                Call::Baseline,
                Call::Snapshot(None),
                Call::Snapshot(Some(token("more"))),
                Call::SnapshotCommit
            ]
        );
        assert!(report.body_plan().is_some());
    }
}

// Contract: the configured four-page/100-message cap is successful bounded
// recent coverage, distinct from caught-up or collection failure.
#[test]
fn snapshot_cap_commits_exactly_four_pages_and_one_hundred_metadata_items() {
    let control = Control::default();
    let remote = Remote::new(&control, vec![]);
    for page in 0..4 {
        remote.snapshots.lock().unwrap().push_back(Ok(SnapshotSpec {
            items: (0..25)
                .map(|i| metadata(&format!("snapshot-{}", page * 25 + i)))
                .collect(),
            next: ProviderContinuation::Next(token(&format!("next-{page}"))),
            wrong_baseline: false,
        }));
    }
    let store = Store::new(&control, None);
    let report = run(HistorySync::new(&remote, &store).sync(&fence()));
    assert_eq!(
        report.stop(),
        HistorySyncStop::SnapshotCommitted(SnapshotCoverage::RecentTruncated)
    );
    assert_eq!(report.progress().snapshot_requests, 4);
    assert_eq!(report.progress().snapshot_messages_committed, 100);
    assert_eq!(
        store.state.lock().unwrap().snapshots[0].metadata().len(),
        100
    );
}

// Contract: collection errors, bad pagination/context, duplicate metadata and
// failed commit preserve the old checkpoint and never submit a partial snapshot.
#[test]
fn snapshot_failures_preserve_prior_state_and_do_not_commit_partial_collection() {
    for failure in 0..8 {
        let control = Control::default();
        let mut remote = Remote::new(&control, vec![]);
        remote
            .pages
            .lock()
            .unwrap()
            .push_back(Err(HistoryFeedError::CursorExpired));
        let mut store = Store::new(&control, Some("9"));
        let first = SnapshotSpec::new(&["a"], ProviderContinuation::Next(token("next")));
        let mut second = SnapshotSpec::new(&["b"], ProviderContinuation::End);
        let second = match failure {
            0 => Err(MetadataReadError::Transport),
            1 => {
                second.next = ProviderContinuation::Next(token("next"));
                Ok(second)
            }
            2 => {
                second.wrong_baseline = true;
                Ok(second)
            }
            3 => Ok(SnapshotSpec::new(&["a"], ProviderContinuation::End)),
            4 => {
                remote.baseline = Err(MetadataReadError::ProfileMissing);
                Ok(second)
            }
            5 => {
                store.snapshot_error = Some(TriageStoreError::Conflict);
                Ok(second)
            }
            6 => {
                remote.baseline = Ok(CapturedBaseline::new(
                    AccountId::new("foreign").unwrap(),
                    cursor("9000"),
                ));
                Ok(second)
            }
            _ => {
                remote.baseline = Ok(CapturedBaseline::new(account(), cursor("8")));
                Ok(second)
            }
        };
        remote.snapshots.lock().unwrap().extend([Ok(first), second]);
        let report = run(HistorySync::new(&remote, &store).sync(&fence()));
        let expected = match failure {
            0 => HistoryRecoveryReason::Read(MetadataReadError::Transport),
            1 => HistoryRecoveryReason::Contract(ContractError::Continuation),
            2 => HistoryRecoveryReason::Contract(ContractError::State),
            3 => HistoryRecoveryReason::Contract(ContractError::Duplicate),
            4 => HistoryRecoveryReason::Read(MetadataReadError::ProfileMissing),
            5 => HistoryRecoveryReason::Store(TriageStoreError::Conflict),
            6 => HistoryRecoveryReason::Contract(ContractError::WrongAccount),
            _ => HistoryRecoveryReason::Contract(ContractError::Order),
        };
        assert_eq!(report.stop(), recovery(expected));
        assert_eq!(confirmed(&report), Some("9"));
        assert_eq!(report.progress().snapshot_messages_committed, 0);
        assert!(report.body_plan().is_none());
        assert!(store.state.lock().unwrap().snapshots.is_empty());
        let calls = control.calls.lock().unwrap();
        assert_eq!(calls.contains(&Call::SnapshotCommit), failure == 5);
    }
}

// Contract: unavailable/corrupt/changed identity cannot be treated as no cursor.
#[test]
fn failed_checkpoint_read_has_no_fallback_or_invented_progress() {
    for error in [
        TriageStoreError::UnknownAccount,
        TriageStoreError::Corrupt,
        TriageStoreError::IdentityChanged,
        TriageStoreError::Storage,
    ] {
        let control = Control::default();
        let remote = Remote::new(&control, vec![]);
        let mut store = Store::new(&control, None);
        store.checkpoint_error = Some(error);
        let report = run(HistorySync::new(&remote, &store).sync(&fence()));
        assert_eq!(report.stop(), recovery(HistoryRecoveryReason::Store(error)));
        assert!(report.checkpoint().is_none());
        assert_eq!(*control.calls.lock().unwrap(), [Call::Checkpoint]);
    }
}

// Contract: no record apply until its complete metadata has arrived; cancellation
// preserves earlier record commits and starts no remaining reads or terminal work.
#[test]
fn cancellation_during_next_record_metadata_keeps_only_the_previous_record() {
    let control = Control::default();
    *control.gate.lock().unwrap() = Some(Stage::Metadata(3));
    let remote = Remote::new(
        &control,
        vec![PageSpec::end(vec![
            added("10", &["a"]),
            added("11", &["b", "c"]),
        ])],
    );
    let store = Store::new(&control, Some("9"));
    let sync = HistorySync::new(&remote, &store);
    let bound = fence();
    let mut future = sync.sync(&bound);
    assert!(
        future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    assert_eq!(store.state.lock().unwrap().records.len(), 1);
    assert_eq!(
        store.state.lock().unwrap().checkpoint.cursor(),
        Some(&cursor("10"))
    );
    assert!(
        !control
            .calls
            .lock()
            .unwrap()
            .contains(&Call::Apply(cursor("11")))
    );
    drop(future);
    *control.gate.lock().unwrap() = None;
    assert_eq!(*remote.metadata_calls.lock().unwrap(), 3);
    assert_eq!(store.state.lock().unwrap().terminal_commits, 0);
}

// Contract: baseline completion precedes any snapshot request; all pages precede
// commit; dropping collection or an uncompleted commit submits no later work.
#[test]
fn async_snapshot_gates_prove_baseline_first_collection_then_commit() {
    for stage in [Stage::Baseline, Stage::Snapshot(2), Stage::SnapshotCommit] {
        let control = Control::default();
        *control.gate.lock().unwrap() = Some(stage);
        let remote = Remote::new(&control, vec![]);
        remote.snapshots.lock().unwrap().extend([
            Ok(SnapshotSpec::new(
                &["a"],
                ProviderContinuation::Next(token("next")),
            )),
            Ok(SnapshotSpec::new(&["b"], ProviderContinuation::End)),
        ]);
        let store = Store::new(&control, None);
        let sync = HistorySync::new(&remote, &store);
        let bound = fence();
        let mut future = sync.sync(&bound);
        assert!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        assert!(store.state.lock().unwrap().checkpoint.cursor().is_none());
        assert!(store.state.lock().unwrap().snapshots.is_empty());
        let calls = control.calls.lock().unwrap().clone();
        if stage == Stage::Baseline {
            assert_eq!(calls, [Call::Checkpoint, Call::Baseline]);
            // Positive control: releasing the baseline lets the exact same future
            // collect and commit, proving the gate is on the real awaited boundary.
            *control.gate.lock().unwrap() = None;
            let report = run(future);
            assert!(matches!(
                report.stop(),
                HistorySyncStop::SnapshotCommitted(_)
            ));
        } else {
            assert_eq!(
                calls.last(),
                Some(&if stage == Stage::SnapshotCommit {
                    Call::SnapshotCommit
                } else {
                    Call::Snapshot(Some(token("next")))
                })
            );
            drop(future);
            *control.gate.lock().unwrap() = None;
            assert_eq!(*control.calls.lock().unwrap(), calls);
            assert!(store.state.lock().unwrap().checkpoint.cursor().is_none());
        }
    }
}
