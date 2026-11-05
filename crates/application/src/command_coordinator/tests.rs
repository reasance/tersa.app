// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Stateful protocol evidence, not SQL atomicity or live-provider proof.
// Rust guideline compliant 1.0.
#![expect(
    clippy::unwrap_used,
    reason = "tests use controlled synthetic contracts"
)]

use super::*;
use crate::{
    command::{
        CommandItemProgress, CommandRejection, LabelItemProgress, UserLabelObservation,
        WriteAcknowledgement,
    },
    history::{CapturedBaseline, HistoryFeedError, HistoryPage, HistoryQuery, SnapshotPage},
    identity::IdentityHash,
    mailbox::{AccountId, MessageId, PageToken},
    mailbox_state::{MessageKey, MessageObservation, MetadataObservation},
};
use std::{
    future::poll_fn,
    pin::pin,
    sync::Mutex,
    task::{Context, Poll, Waker},
};
use tersa_domain::{
    account::AccountCapability,
    command::{
        CommandItemOutcome, CompensationBatch, ConditionalCompensation, DesiredMailboxState,
        MailboxCommandId, MessageAction, MessageCompensation,
    },
    label::{
        LabelCatalog, LabelDefinition, LabelId, LabelKind, LabelMembership, LabelName, UserLabel,
    },
};

fn account() -> AccountId {
    AccountId::new("owner").unwrap()
}
fn fence() -> AccountFence {
    AccountFence::new(account(), IdentityHash::from_bytes([7; 32]))
}
fn id(value: &str) -> MessageId {
    MessageId::new(value).unwrap()
}
fn key(value: &str) -> MessageKey {
    MessageKey::new(account(), id(value))
}
fn command_id(value: &str) -> MailboxCommandId {
    MailboxCommandId::new(value).unwrap()
}
fn command(ids: &[&str]) -> MailboxCommand {
    MailboxCommand::message_state(
        AccountCapability::Modify,
        command_id("command"),
        MessageTargets::new(account(), ids.iter().map(|v| id(v)).collect()).unwrap(),
        &MessageAction::Read,
    )
    .unwrap()
}
fn create() -> MailboxCommand {
    MailboxCommand::create_label(
        AccountCapability::Modify,
        command_id("create"),
        account(),
        LabelName::new("Target").unwrap(),
    )
    .unwrap()
}
fn label(value: &str, name: &str) -> LabelDefinition {
    LabelDefinition::new(
        account(),
        LabelId::new(value).unwrap(),
        LabelName::new(name).unwrap(),
        LabelKind::User,
    )
    .unwrap()
}
fn user() -> UserLabel {
    label("Label_1", "Known").user_label().unwrap()
}
fn observation(value: &str, labels: &[&str]) -> MessageObservation {
    MessageObservation::new(
        key(value),
        RemoteMessageState::Known(
            LabelMembership::new(
                account(),
                labels.iter().map(|v| LabelId::new(*v).unwrap()).collect(),
            )
            .unwrap(),
        ),
    )
    .unwrap()
}
fn missing(value: &str) -> MessageObservation {
    MessageObservation::new(key(value), RemoteMessageState::Missing).unwrap()
}
fn initial(command: MailboxCommand) -> CommandSnapshot {
    let ids = match command.kind() {
        MailboxCommandKind::MessageState { targets, .. } => targets.ids().to_vec(),
        MailboxCommandKind::Compensate(batch) => batch
            .items()
            .iter()
            .map(|v| v.message_id().clone())
            .collect(),
        _ => vec![],
    };
    let progress = if ids.is_empty() {
        CommandProgress::Label(LabelItemProgress::Pending)
    } else {
        CommandProgress::Messages(
            ids.into_iter()
                .map(|id| CommandItemProgress::new(MessageKey::new(account(), id), None))
                .collect(),
        )
    };
    let stamp = CommandStamp::new(
        CommandKey::new(command.account_id().clone(), command.id().clone()),
        1,
    );
    CommandSnapshot::new(
        command,
        stamp,
        MailboxCommandStatus::Queued,
        0,
        progress,
        None,
    )
    .unwrap()
}
fn changed(
    snapshot: &CommandSnapshot,
    status: MailboxCommandStatus,
    progress: CommandProgress,
    attempts: u8,
    ticket: bool,
) -> CommandSnapshot {
    let stamp = CommandStamp::new(
        snapshot.stamp().key().clone(),
        snapshot.stamp().revision() + 1,
    );
    CommandSnapshot::new(
        snapshot.command().clone(),
        stamp.clone(),
        status,
        attempts,
        progress,
        ticket.then(|| RetryAuthorization::from_store(stamp)),
    )
    .unwrap()
}
fn run<T>(future: impl Future<Output = T>) -> T {
    let mut future = pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("unexpected gate"),
    }
}
fn current_pre(store: &Store<'_>) -> CommandPrecondition {
    CommandPrecondition::new(
        fence(),
        store.state.lock().unwrap().rows[0].snapshot.stamp().clone(),
    )
    .unwrap()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stage {
    Admit,
    Undo,
    Lookup,
    Candidate,
    Cancel,
    Retry,
    Abandon,
    Summaries,
    Oldest,
    Recover,
    Message(usize),
    Catalog,
    UserLabel,
    Reconcile,
    ReadFailure,
    Prepare,
    Dispatch,
    Record,
    OutcomeShape,
}
#[derive(Default)]
struct Control {
    calls: Mutex<Vec<Stage>>,
    gate: Mutex<Option<Stage>>,
    failures: Mutex<Vec<Stage>>,
    invalid: Mutex<Option<Stage>>,
}
impl Control {
    async fn step(&self, stage: Stage) -> bool {
        self.calls.lock().unwrap().push(stage);
        poll_fn(|_cx| {
            if *self.gate.lock().unwrap() == Some(stage) {
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        })
        .await;
        self.failures.lock().unwrap().contains(&stage)
    }
    fn calls(&self) -> Vec<Stage> {
        self.calls.lock().unwrap().clone()
    }
}
struct Row {
    snapshot: CommandSnapshot,
    dispatched: bool,
    compensation_guard: bool,
    selected: Option<MessageTargets>,
    fact: Option<DispatchFact>,
}
struct State {
    rows: Vec<Row>,
    reconciliations: Vec<CommandReconciliation>,
    preparations: Vec<DispatchPreparation>,
    records: Vec<RemoteCommandOutcome>,
    undo: Option<UndoCandidate>,
    latest_evidence: Option<CommandEvidence>,
    modify: bool,
}
struct Store<'a> {
    control: &'a Control,
    state: Mutex<State>,
}
impl<'a> Store<'a> {
    fn new(control: &'a Control, command: Option<MailboxCommand>) -> Self {
        Self {
            control,
            state: Mutex::new(State {
                rows: command
                    .into_iter()
                    .map(|command| Row {
                        snapshot: initial(command),
                        dispatched: false,
                        compensation_guard: false,
                        selected: None,
                        fact: None,
                    })
                    .collect(),
                reconciliations: vec![],
                preparations: vec![],
                records: vec![],
                undo: None,
                latest_evidence: None,
                modify: true,
            }),
        }
    }
    fn cas(
        state: &State,
        expected: &CommandPrecondition,
        fifo: bool,
    ) -> Result<usize, TriageStoreError> {
        if expected.fence() != &fence() {
            return Err(TriageStoreError::IdentityChanged);
        }
        let index = state
            .rows
            .iter()
            .position(|r| r.snapshot.stamp().key() == expected.stamp().key())
            .ok_or(TriageStoreError::NotEligible)?;
        if state.rows[index].snapshot.stamp() != expected.stamp() {
            return Err(TriageStoreError::Conflict);
        }
        if fifo
            && state.rows[..index]
                .iter()
                .any(|r| !r.snapshot.status().is_terminal())
        {
            return Err(TriageStoreError::Conflict);
        }
        Ok(index)
    }
    fn add(
        state: &mut State,
        command: &MailboxCommand,
    ) -> Result<CommandAdmissionOutcome, TriageStoreError> {
        if let Some(row) = state
            .rows
            .iter()
            .find(|r| r.snapshot.command().id() == command.id())
        {
            return Ok(CommandAdmissionOutcome::Retained(RetainedCommand::Full(
                Box::new(row.snapshot.clone()),
            )));
        }
        if !state.modify {
            return Err(TriageStoreError::ReadOnly);
        }
        let snapshot = initial(command.clone());
        state.rows.push(Row {
            snapshot: snapshot.clone(),
            dispatched: false,
            compensation_guard: false,
            selected: None,
            fact: None,
        });
        Ok(CommandAdmissionOutcome::Admitted(Box::new(snapshot)))
    }
}
fn desired<'a>(command: &'a MailboxCommand, key: &MessageKey) -> &'a DesiredMailboxState {
    match command.kind() {
        MailboxCommandKind::MessageState { desired, .. } => desired,
        MailboxCommandKind::Compensate(batch) => batch
            .items()
            .iter()
            .find(|i| i.message_id() == key.message_id())
            .unwrap()
            .condition()
            .restore_state(),
        _ => panic!("message command"),
    }
}
fn undo_condition(row: &Row, evidence: &CommandEvidence) -> bool {
    let MailboxCommandKind::Compensate(batch) = row.snapshot.command().kind() else {
        return true;
    };
    if row.compensation_guard {
        return true;
    }
    let CommandEvidence::Messages {
        observations,
        user_label,
    } = evidence
    else {
        panic!("message evidence");
    };
    user_label.as_ref().is_none_or(|l| l.definition().is_some()) && batch.items().iter().zip(observations.observations()).all(|(item, observed)| {
        matches!(observed.state(), RemoteMessageState::Known(labels) if item.condition().expected_post_state().is_observed_in(&ObservedMembership::Observed(labels.clone())))
    })
}

fn observed_progress(row: &Row, evidence: &CommandReconciliation) -> CommandProgress {
    match (row.snapshot.progress(), evidence.evidence()) {
        (
            CommandProgress::Messages(items),
            CommandEvidence::Messages {
                observations,
                user_label,
            },
        ) => {
            let values = items
                .iter()
                .zip(observations.observations())
                .map(|(item, observed)| {
                    let outcome = item.outcome().or_else(|| match observed.state() {
                        RemoteMessageState::Missing => Some(CommandItemOutcome::TargetMissing),
                        RemoteMessageState::Known(labels)
                            if desired(row.snapshot.command(), item.key())
                                .is_observed_in(&ObservedMembership::Observed(labels.clone())) =>
                        {
                            Some(CommandItemOutcome::DesiredStateObserved)
                        }
                        _ if user_label
                            .as_ref()
                            .is_some_and(|label| label.definition().is_none()) =>
                        {
                            Some(CommandItemOutcome::Failed)
                        }
                        RemoteMessageState::Known(_) => None,
                    });
                    CommandItemProgress::new(item.key().clone(), outcome)
                })
                .collect();
            CommandProgress::Messages(values)
        }
        (CommandProgress::Label(_), CommandEvidence::CreateCatalog(_)) => CommandProgress::Label(
            if matches!(evidence.create_matches(), Some(LabelCreateMatches::One(_))) {
                LabelItemProgress::Complete
            } else {
                LabelItemProgress::Pending
            },
        ),
        (CommandProgress::Label(_), CommandEvidence::UserLabel(observed)) => {
            let result = match (row.snapshot.command().kind(), observed.definition()) {
                (MailboxCommandKind::DeleteLabel(_), None) => LabelItemProgress::Complete,
                (MailboxCommandKind::RenameLabel { name, .. }, Some(d)) if d.name() == name => {
                    LabelItemProgress::Complete
                }
                (MailboxCommandKind::RenameLabel { .. }, None) => LabelItemProgress::Failed,
                _ => LabelItemProgress::Pending,
            };
            CommandProgress::Label(result)
        }
        _ => panic!("validated evidence"),
    }
}

impl MailboxCommandStore for Store<'_> {
    fn admit<'a>(
        &'a self,
        request: &'a CommandAdmission,
    ) -> BoxFuture<'a, Result<CommandAdmissionOutcome, TriageStoreError>> {
        Box::pin(async move {
            assert!(!self.control.step(Stage::Admit).await);
            assert_eq!(request.fence(), &fence());
            assert!(!matches!(
                request.command().kind(),
                MailboxCommandKind::Compensate(_)
            ));
            Self::add(&mut self.state.lock().unwrap(), request.command())
        })
    }
    fn admit_undo<'a>(
        &'a self,
        request: &'a UndoAdmission,
    ) -> BoxFuture<'a, Result<CommandAdmissionOutcome, TriageStoreError>> {
        Box::pin(async move {
            assert!(!self.control.step(Stage::Undo).await);
            assert_eq!(request.fence(), &fence());
            let mut state = self.state.lock().unwrap();
            if state.undo.as_ref() != Some(request.candidate())
                || state
                    .rows
                    .iter()
                    .any(|r| !r.snapshot.status().is_terminal())
            {
                return Err(TriageStoreError::NotEligible);
            }
            Self::add(&mut state, request.command())
        })
    }
    fn lookup<'a>(
        &'a self,
        bound: &'a AccountFence,
        requested: &'a CommandKey,
    ) -> BoxFuture<'a, Result<Option<RetainedCommand>, TriageStoreError>> {
        Box::pin(async move {
            assert!(!self.control.step(Stage::Lookup).await);
            assert_eq!(bound, &fence());
            Ok(self
                .state
                .lock()
                .unwrap()
                .rows
                .iter()
                .find(|r| r.snapshot.stamp().key() == requested)
                .map(|r| RetainedCommand::Full(Box::new(r.snapshot.clone()))))
        })
    }
    fn undo_candidate<'a>(
        &'a self,
        bound: &'a AccountFence,
    ) -> BoxFuture<'a, Result<Option<UndoCandidate>, TriageStoreError>> {
        Box::pin(async move {
            assert!(!self.control.step(Stage::Candidate).await);
            assert_eq!(bound, &fence());
            Ok(self.state.lock().unwrap().undo.clone())
        })
    }
    fn terminal_summaries<'a>(
        &'a self,
        bound: &'a AccountFence,
    ) -> BoxFuture<'a, Result<TerminalSummaries, TriageStoreError>> {
        Box::pin(async move {
            assert!(!self.control.step(Stage::Summaries).await);
            assert_eq!(bound, &fence());
            Ok(TerminalSummaries::new(
                account(),
                self.state
                    .lock()
                    .unwrap()
                    .rows
                    .iter()
                    .filter(|r| r.snapshot.status().is_terminal())
                    .map(|r| TerminalCommandSummary::from_snapshot(&r.snapshot).unwrap())
                    .collect(),
            )
            .unwrap())
        })
    }
    fn oldest_pending<'a>(
        &'a self,
        bound: &'a AccountFence,
    ) -> BoxFuture<'a, Result<Option<CommandSnapshot>, TriageStoreError>> {
        Box::pin(async move {
            if self.control.step(Stage::Oldest).await {
                return Err(TriageStoreError::Storage);
            }
            assert_eq!(bound, &fence());
            let mut result = self
                .state
                .lock()
                .unwrap()
                .rows
                .iter()
                .find(|r| !r.snapshot.status().is_terminal())
                .map(|r| r.snapshot.clone());
            if *self.control.invalid.lock().unwrap() == Some(Stage::Oldest) {
                result = Some(initial(
                    MailboxCommand::create_label(
                        AccountCapability::Modify,
                        command_id("other"),
                        AccountId::new("foreign").unwrap(),
                        LabelName::new("Target").unwrap(),
                    )
                    .unwrap(),
                ));
            }
            Ok(result)
        })
    }
    fn recover_dispatching<'a>(
        &'a self,
        expected: &'a CommandPrecondition,
    ) -> BoxFuture<'a, Result<CommandSnapshot, TriageStoreError>> {
        Box::pin(async move {
            if self.control.step(Stage::Recover).await {
                return Err(TriageStoreError::Storage);
            }
            let mut state = self.state.lock().unwrap();
            let index = Self::cas(&state, expected, true)?;
            let row = &mut state.rows[index];
            assert_eq!(row.snapshot.status(), MailboxCommandStatus::Dispatching);
            row.snapshot = changed(
                &row.snapshot,
                MailboxCommandStatus::Ambiguous,
                row.snapshot.progress().clone(),
                row.snapshot.automatic_attempts(),
                false,
            );
            Ok(row.snapshot.clone())
        })
    }
    fn reconcile<'a>(
        &'a self,
        expected: &'a CommandPrecondition,
        evidence: &'a CommandReconciliation,
    ) -> BoxFuture<'a, Result<CommandSnapshot, TriageStoreError>> {
        Box::pin(async move {
            if self.control.step(Stage::Reconcile).await {
                return Err(TriageStoreError::Storage);
            }
            let mut state = self.state.lock().unwrap();
            let index = Self::cas(&state, expected, true)?;
            assert_eq!(&state.rows[index].snapshot, evidence.snapshot());
            state.reconciliations.push(evidence.clone());
            state.latest_evidence = Some(evidence.evidence().clone());
            let row = &mut state.rows[index];
            if !undo_condition(row, evidence.evidence()) {
                row.snapshot = changed(
                    &row.snapshot,
                    MailboxCommandStatus::NeedsAttention,
                    row.snapshot.progress().clone(),
                    row.snapshot.automatic_attempts(),
                    false,
                );
                return Ok(row.snapshot.clone());
            }
            let (status, progress, ticket) = {
                let progress = observed_progress(row, evidence);
                let outcomes: Vec<_> = match &progress {
                    CommandProgress::Messages(items) => {
                        items.iter().map(CommandItemProgress::outcome).collect()
                    }
                    CommandProgress::Label(value) => vec![match value {
                        LabelItemProgress::Complete => {
                            Some(CommandItemOutcome::DesiredStateObserved)
                        }
                        LabelItemProgress::Failed => Some(CommandItemOutcome::Failed),
                        LabelItemProgress::Pending => None,
                    }],
                };
                let terminal = outcomes.iter().all(Option::is_some);
                let status = if terminal {
                    if outcomes
                        .iter()
                        .all(|v| *v == Some(CommandItemOutcome::DesiredStateObserved))
                    {
                        MailboxCommandStatus::Complete
                    } else {
                        MailboxCommandStatus::Partial
                    }
                } else if row.snapshot.retry_authorization().is_some()
                    || row.snapshot.automatic_attempts() >= 3
                    || (matches!(
                        row.snapshot.command().kind(),
                        MailboxCommandKind::CreateLabel(_)
                    ) && row.dispatched)
                {
                    MailboxCommandStatus::NeedsAttention
                } else if row.dispatched {
                    MailboxCommandStatus::Ambiguous
                } else {
                    row.snapshot.status()
                };
                (
                    status,
                    progress,
                    !terminal && row.snapshot.retry_authorization().is_some(),
                )
            };
            row.snapshot = changed(
                &row.snapshot,
                status,
                progress,
                row.snapshot.automatic_attempts(),
                ticket,
            );
            Ok(row.snapshot.clone())
        })
    }
    fn prepare_dispatch<'a>(
        &'a self,
        request: &'a DispatchPreparation,
    ) -> BoxFuture<'a, Result<DispatchReceipt, TriageStoreError>> {
        Box::pin(async move {
            if self.control.step(Stage::Prepare).await {
                return Err(TriageStoreError::Storage);
            }
            let mut state = self.state.lock().unwrap();
            let index = Self::cas(&state, request.precondition(), true)?;
            assert_eq!(
                &state.rows[index].snapshot,
                request.reconciliation().snapshot()
            );
            assert_eq!(
                state.latest_evidence.as_ref(),
                Some(request.reconciliation().evidence())
            );
            state.preparations.push(request.clone());
            if !state.modify {
                return Err(TriageStoreError::ReadOnly);
            }
            let row = &mut state.rows[index];
            if !undo_condition(row, request.reconciliation().evidence()) {
                return Err(TriageStoreError::NotEligible);
            }
            let automatic = matches!(request.authorization(), DispatchAuthorization::Automatic);
            if automatic
                && (row.snapshot.automatic_attempts() >= 3
                    || row.snapshot.retry_authorization().is_some()
                    || (matches!(
                        row.snapshot.command().kind(),
                        MailboxCommandKind::CreateLabel(_)
                    ) && row.dispatched))
            {
                return Err(TriageStoreError::NotEligible);
            }
            if let DispatchAuthorization::Explicit(ticket) = request.authorization() {
                if row.snapshot.retry_authorization() != Some(ticket) {
                    return Err(TriageStoreError::Conflict);
                }
                if matches!(
                    row.snapshot.command().kind(),
                    MailboxCommandKind::CreateLabel(_)
                ) && row.dispatched
                    && request.duplicate_risk() != DuplicateRiskConfirmation::Confirmed
                {
                    return Err(TriageStoreError::NotEligible);
                }
            }
            if let CommandEvidence::Messages { observations, .. } =
                request.reconciliation().evidence()
            {
                let CommandProgress::Messages(items) = row.snapshot.progress() else {
                    panic!("message progress");
                };
                let unmet: Vec<_> = items.iter().zip(observations.observations())
                    .filter(|(item, o)| item.outcome().is_none() && matches!(o.state(), RemoteMessageState::Known(labels)
                        if !desired(row.snapshot.command(), item.key()).is_observed_in(&ObservedMembership::Observed(labels.clone()))))
                    .map(|(item, _)| item.key().message_id().clone()).collect();
                assert_eq!(request.targets().unwrap().ids(), unmet);
            } else if matches!(
                row.snapshot.command().kind(),
                MailboxCommandKind::CreateLabel(_)
            ) {
                assert_eq!(
                    request.reconciliation().create_matches(),
                    Some(LabelCreateMatches::Zero)
                );
            }
            row.snapshot = changed(
                &row.snapshot,
                MailboxCommandStatus::Dispatching,
                row.snapshot.progress().clone(),
                row.snapshot.automatic_attempts() + u8::from(automatic),
                false,
            );
            row.dispatched = true;
            row.compensation_guard = true;
            row.selected = request.targets().cloned();
            let mut snapshot = row.snapshot.clone();
            if *self.control.invalid.lock().unwrap() == Some(Stage::Prepare) {
                snapshot = changed(
                    &initial(command(&["foreign-receipt-target"])),
                    MailboxCommandStatus::Dispatching,
                    initial(command(&["foreign-receipt-target"]))
                        .progress()
                        .clone(),
                    1,
                    false,
                );
            }
            let targets = if snapshot.command() == row.snapshot.command() {
                request.targets().cloned()
            } else {
                Some(MessageTargets::new(account(), vec![id("foreign-receipt-target")]).unwrap())
            };
            Ok(DispatchReceipt::from_committed(snapshot, targets).unwrap())
        })
    }
    fn record_dispatch<'a>(
        &'a self,
        expected: &'a CommandPrecondition,
        outcome: &'a RemoteCommandOutcome,
    ) -> BoxFuture<'a, Result<CommandSnapshot, TriageStoreError>> {
        Box::pin(async move {
            if self.control.step(Stage::Record).await {
                return Err(TriageStoreError::Storage);
            }
            let mut state = self.state.lock().unwrap();
            let index = Self::cas(&state, expected, true)?;
            assert_eq!(outcome.stamp(), expected.stamp());
            state.records.push(outcome.clone());
            let row = &mut state.rows[index];
            assert_eq!(row.snapshot.status(), MailboxCommandStatus::Dispatching);
            row.fact = Some(outcome.fact().clone());
            row.snapshot = changed(
                &row.snapshot,
                if matches!(outcome.fact(), DispatchFact::Rejected(_)) {
                    MailboxCommandStatus::NeedsAttention
                } else {
                    MailboxCommandStatus::Ambiguous
                },
                row.snapshot.progress().clone(),
                row.snapshot.automatic_attempts(),
                false,
            );
            Ok(row.snapshot.clone())
        })
    }
    fn reconciliation_failed<'a>(
        &'a self,
        expected: &'a CommandPrecondition,
        failure: ReconciliationFailure,
    ) -> BoxFuture<'a, Result<CommandSnapshot, TriageStoreError>> {
        Box::pin(async move {
            if self.control.step(Stage::ReadFailure).await {
                return Err(TriageStoreError::Storage);
            }
            assert!(matches!(
                failure,
                ReconciliationFailure::ReadUnavailable | ReconciliationFailure::InvalidEvidence
            ));
            let mut state = self.state.lock().unwrap();
            let index = Self::cas(&state, expected, true)?;
            let row = &mut state.rows[index];
            row.snapshot = changed(
                &row.snapshot,
                MailboxCommandStatus::NeedsAttention,
                row.snapshot.progress().clone(),
                row.snapshot.automatic_attempts(),
                false,
            );
            Ok(row.snapshot.clone())
        })
    }
    fn authorize_retry<'a>(
        &'a self,
        expected: &'a CommandPrecondition,
    ) -> BoxFuture<'a, Result<RetryAuthorization, TriageStoreError>> {
        Box::pin(async move {
            assert!(!self.control.step(Stage::Retry).await);
            let mut state = self.state.lock().unwrap();
            let index = Self::cas(&state, expected, true)?;
            let row = &mut state.rows[index];
            if !matches!(
                row.snapshot.status(),
                MailboxCommandStatus::Ambiguous | MailboxCommandStatus::NeedsAttention
            ) || row.snapshot.retry_authorization().is_some()
            {
                return Err(TriageStoreError::NotEligible);
            }
            row.snapshot = changed(
                &row.snapshot,
                row.snapshot.status(),
                row.snapshot.progress().clone(),
                row.snapshot.automatic_attempts(),
                true,
            );
            Ok(row.snapshot.retry_authorization().unwrap().clone())
        })
    }
    fn cancel_queued<'a>(
        &'a self,
        expected: &'a CommandPrecondition,
    ) -> BoxFuture<'a, Result<TerminalCommandSummary, TriageStoreError>> {
        Box::pin(async move {
            assert!(!self.control.step(Stage::Cancel).await);
            let mut state = self.state.lock().unwrap();
            let index = Self::cas(&state, expected, false)?;
            let row = &mut state.rows[index];
            if row.snapshot.status() != MailboxCommandStatus::Queued || row.dispatched {
                return Err(TriageStoreError::NotEligible);
            }
            row.snapshot = changed(
                &row.snapshot,
                MailboxCommandStatus::Cancelled,
                row.snapshot.progress().clone(),
                0,
                false,
            );
            Ok(TerminalCommandSummary::from_snapshot(&row.snapshot).unwrap())
        })
    }
    fn abandon<'a>(
        &'a self,
        expected: &'a CommandPrecondition,
        confirmation: AbandonConfirmation,
    ) -> BoxFuture<'a, Result<TerminalCommandSummary, TriageStoreError>> {
        Box::pin(async move {
            assert!(!self.control.step(Stage::Abandon).await);
            assert_eq!(
                confirmation,
                AbandonConfirmation::ProviderMayAlreadyHaveApplied
            );
            let mut state = self.state.lock().unwrap();
            let index = Self::cas(&state, expected, false)?;
            let row = &mut state.rows[index];
            row.snapshot = changed(
                &row.snapshot,
                MailboxCommandStatus::Abandoned,
                row.snapshot.progress().clone(),
                row.snapshot.automatic_attempts(),
                false,
            );
            Ok(TerminalCommandSummary::from_snapshot(&row.snapshot).unwrap())
        })
    }
}

struct Remote<'a> {
    control: &'a Control,
    store: &'a Store<'a>,
    messages: Mutex<Vec<MessageObservation>>,
    definitions: Mutex<Vec<LabelDefinition>>,
    reads: Mutex<usize>,
    sent: Mutex<Vec<DispatchReceipt>>,
    denial: Option<CommandDispatchError>,
    fact: Option<DispatchFact>,
}
impl<'a> Remote<'a> {
    fn new(control: &'a Control, store: &'a Store<'a>, messages: Vec<MessageObservation>) -> Self {
        Self {
            control,
            store,
            messages: Mutex::new(messages),
            definitions: Mutex::new(vec![label("Label_1", "Known")]),
            reads: Mutex::new(0),
            sent: Mutex::new(vec![]),
            denial: None,
            fact: None,
        }
    }
    async fn catalog(&self, owner: &AccountId) -> Result<LabelCatalog, MetadataReadError> {
        assert_eq!(owner, &account());
        if self.control.step(Stage::Catalog).await {
            return Err(MetadataReadError::Transport);
        }
        let owner = if *self.control.invalid.lock().unwrap() == Some(Stage::Catalog) {
            AccountId::new("foreign").unwrap()
        } else {
            owner.clone()
        };
        let definitions = if owner == account() {
            self.definitions.lock().unwrap().clone()
        } else {
            vec![]
        };
        Ok(LabelCatalog::new(owner, definitions).unwrap())
    }
    async fn user_label(
        &self,
        target: &UserLabel,
    ) -> Result<UserLabelObservation, MetadataReadError> {
        assert_eq!(target, &user());
        if self.control.step(Stage::UserLabel).await {
            return Err(MetadataReadError::Transport);
        }
        let target = if *self.control.invalid.lock().unwrap() == Some(Stage::UserLabel) {
            label("Label_wrong", "Wrong").user_label().unwrap()
        } else {
            target.clone()
        };
        Ok(UserLabelObservation::new(
            target.clone(),
            self.definitions
                .lock()
                .unwrap()
                .iter()
                .find(|d| d.id() == target.id())
                .cloned(),
        )
        .unwrap())
    }
}
impl GmailHistoryFeed for Remote<'_> {
    fn observe_message<'a>(
        &'a self,
        requested: &'a MessageKey,
    ) -> BoxFuture<'a, Result<MessageObservation, MetadataReadError>> {
        Box::pin(async move {
            let count = {
                let mut count = self.reads.lock().unwrap();
                *count += 1;
                *count
            };
            if self.control.step(Stage::Message(count)).await {
                return Err(MetadataReadError::Transport);
            }
            if *self.control.invalid.lock().unwrap() == Some(Stage::Message(count)) {
                return Ok(observation("wrong-key", &[]));
            }
            self.messages
                .lock()
                .unwrap()
                .iter()
                .find(|m| m.key() == requested)
                .cloned()
                .ok_or(MetadataReadError::InvalidResponse)
        })
    }
    fn history_page<'a>(
        &'a self,
        _q: &'a HistoryQuery,
    ) -> BoxFuture<'a, Result<HistoryPage, HistoryFeedError>> {
        Box::pin(async { panic!("History is not per-target freshness authority") })
    }
    fn capture_baseline<'a>(
        &'a self,
        _a: &'a AccountId,
    ) -> BoxFuture<'a, Result<CapturedBaseline, MetadataReadError>> {
        Box::pin(async { panic!("no snapshot fallback") })
    }
    fn snapshot_page<'a>(
        &'a self,
        _b: &'a CapturedBaseline,
        _t: Option<&'a PageToken>,
    ) -> BoxFuture<'a, Result<SnapshotPage, MetadataReadError>> {
        Box::pin(async { panic!("snapshot omissions cannot settle commands") })
    }
    fn message_metadata<'a>(
        &'a self,
        _k: &'a MessageKey,
    ) -> BoxFuture<'a, Result<MetadataObservation, MetadataReadError>> {
        Box::pin(async { panic!("command reads are body/envelope free") })
    }
}
impl RemoteMailboxCommands for Remote<'_> {
    fn dispatch<'a>(
        &'a self,
        receipt: &'a DispatchReceipt,
    ) -> BoxFuture<'a, Result<RemoteCommandOutcome, CommandDispatchError>> {
        Box::pin(async move {
            // This check is before the gate: durable Dispatching must already exist
            // when the writer is invoked, not merely when the response completes.
            {
                let state = self.store.state.lock().unwrap();
                let row = state
                    .rows
                    .iter()
                    .find(|r| r.snapshot.stamp() == receipt.snapshot().stamp())
                    .unwrap();
                assert_eq!(&row.snapshot, receipt.snapshot());
                assert_eq!(row.selected.as_ref(), receipt.targets());
                assert_eq!(row.snapshot.status(), MailboxCommandStatus::Dispatching);
            }
            self.sent.lock().unwrap().push(receipt.clone());
            if self.control.step(Stage::Dispatch).await {
                return Err(CommandDispatchError::InvalidRequest);
            }
            if let Some(denial) = self.denial {
                return Err(denial);
            }
            let fact =
                self.fact
                    .clone()
                    .unwrap_or_else(|| match receipt.snapshot().command().kind() {
                        MailboxCommandKind::CreateLabel(_) => DispatchFact::Acknowledged(
                            WriteAcknowledgement::LabelCreated(label("Label_new", "Target")),
                        ),
                        MailboxCommandKind::RenameLabel { .. }
                        | MailboxCommandKind::DeleteLabel(_) => DispatchFact::Acknowledged(
                            WriteAcknowledgement::LabelDefinitionAccepted,
                        ),
                        _ => DispatchFact::Acknowledged(WriteAcknowledgement::MessageBatchAccepted),
                    });
            if *self.control.invalid.lock().unwrap() == Some(Stage::Dispatch) {
                let other = changed(
                    receipt.snapshot(),
                    MailboxCommandStatus::Dispatching,
                    receipt.snapshot().progress().clone(),
                    receipt.snapshot().automatic_attempts(),
                    false,
                );
                return Ok(RemoteCommandOutcome::new(
                    &DispatchReceipt::from_committed(other, receipt.targets().cloned()).unwrap(),
                    fact,
                )
                .unwrap());
            }
            if *self.control.invalid.lock().unwrap() == Some(Stage::OutcomeShape) {
                let intent = MailboxCommand::create_label(
                    AccountCapability::Modify,
                    receipt.snapshot().command().id().clone(),
                    account(),
                    LabelName::new("Target").unwrap(),
                )
                .unwrap();
                let other = CommandSnapshot::new(
                    intent,
                    receipt.snapshot().stamp().clone(),
                    MailboxCommandStatus::Dispatching,
                    receipt.snapshot().automatic_attempts(),
                    CommandProgress::Label(LabelItemProgress::Pending),
                    None,
                )
                .unwrap();
                return Ok(RemoteCommandOutcome::new(
                    &DispatchReceipt::from_committed(other, None).unwrap(),
                    DispatchFact::Acknowledged(WriteAcknowledgement::LabelCreated(label(
                        "Label_new",
                        "Target",
                    ))),
                )
                .unwrap());
            }
            Ok(RemoteCommandOutcome::new(receipt, fact).unwrap())
        })
    }
    fn label_catalog<'a>(
        &'a self,
        owner: &'a AccountId,
    ) -> BoxFuture<'a, Result<LabelCatalog, MetadataReadError>> {
        Box::pin(self.catalog(owner))
    }
    fn observe_user_label<'a>(
        &'a self,
        target: &'a UserLabel,
    ) -> BoxFuture<'a, Result<UserLabelObservation, MetadataReadError>> {
        Box::pin(self.user_label(target))
    }
}

// This facet exposes no dispatch port. Observation accepts it without a writer
// bound; the combined provider harness supplies its controlled read data.
struct ReadLabels<'a, 'b>(&'a Remote<'b>);
impl CommandLabelReader for ReadLabels<'_, '_> {
    fn read_label_catalog<'a>(
        &'a self,
        owner: &'a AccountId,
    ) -> BoxFuture<'a, Result<LabelCatalog, MetadataReadError>> {
        Box::pin(self.0.catalog(owner))
    }
    fn read_user_label<'a>(
        &'a self,
        target: &'a UserLabel,
    ) -> BoxFuture<'a, Result<UserLabelObservation, MetadataReadError>> {
        Box::pin(self.0.user_label(target))
    }
}

fn automatic<S: MailboxCommandStore>(
    coordinator: MailboxCommandCoordinator<'_, S>,
    remote: &Remote<'_>,
) -> CommandDriveReport {
    run(coordinator.drive(&fence(), remote, remote, &CommandWritePolicy::Automatic))
}

// Contract: local intent/replay/recovery needs only storage. Unknown replay is
// None, and terminal replay never re-enqueues or dispatches. No remote is built.
#[test]
fn local_actions_and_unknown_terminal_replay_work_without_any_remote_client() {
    let control = Control::default();
    let store = Store::new(&control, None);
    let coordinator = MailboxCommandCoordinator::new(&store);
    let request = CommandAdmission::new(fence(), command(&["a"])).unwrap();
    let admitted = run(coordinator.admit(&request)).unwrap();
    assert!(matches!(admitted, CommandAdmissionOutcome::Admitted(_)));
    let saved_key = CommandKey::new(account(), command_id("command"));
    assert!(
        run(coordinator.lookup(&fence(), &saved_key))
            .unwrap()
            .is_some()
    );
    assert!(
        run(coordinator.lookup(&fence(), &CommandKey::new(account(), command_id("expired"))))
            .unwrap()
            .is_none()
    );
    assert!(run(coordinator.undo_candidate(&fence())).unwrap().is_none());
    let cancelled = run(coordinator.cancel_queued(&current_pre(&store))).unwrap();
    assert_eq!(cancelled.status(), MailboxCommandStatus::Cancelled);
    assert!(
        matches!(run(coordinator.lookup(&fence(),&saved_key)).unwrap(),Some(RetainedCommand::Full(s)) if s.status()==MailboxCommandStatus::Cancelled)
    );
    assert!(matches!(
        run(coordinator.admit(&request)).unwrap(),
        CommandAdmissionOutcome::Retained(_)
    ));
    run(coordinator.admit(&CommandAdmission::new(fence(), create()).unwrap())).unwrap();
    {
        let mut state = store.state.lock().unwrap();
        let row = &mut state.rows[1];
        row.snapshot = changed(
            &row.snapshot,
            MailboxCommandStatus::NeedsAttention,
            row.snapshot.progress().clone(),
            0,
            false,
        );
    }
    let expected = CommandPrecondition::new(
        fence(),
        store.state.lock().unwrap().rows[1].snapshot.stamp().clone(),
    )
    .unwrap();
    let ticket = run(coordinator.authorize_retry(&expected)).unwrap();
    assert!(ticket.stamp().revision() > expected.stamp().revision());
    let expected = CommandPrecondition::new(fence(), ticket.stamp().clone()).unwrap();
    let abandoned = run(coordinator.abandon(
        &expected,
        AbandonConfirmation::ProviderMayAlreadyHaveApplied,
    ))
    .unwrap();
    assert_eq!(abandoned.status(), MailboxCommandStatus::Abandoned);
    assert_eq!(
        run(coordinator.terminal_summaries(&fence()))
            .unwrap()
            .summaries()
            .len(),
        2
    );
    assert_eq!(
        control.calls(),
        [
            Stage::Admit,
            Stage::Lookup,
            Stage::Lookup,
            Stage::Candidate,
            Stage::Cancel,
            Stage::Lookup,
            Stage::Admit,
            Stage::Admit,
            Stage::Retry,
            Stage::Abandon,
            Stage::Summaries
        ]
    );
    assert_eq!(store.state.lock().unwrap().rows.len(), 2);
}

fn candidate(ids: &[&str]) -> UndoCandidate {
    let source = initial(command(ids));
    let progress = CommandProgress::Messages(
        ids.iter()
            .map(|v| {
                CommandItemProgress::new(key(v), Some(CommandItemOutcome::DesiredStateObserved))
            })
            .collect(),
    );
    let complete = changed(&source, MailboxCommandStatus::Complete, progress, 1, false);
    let batch = CompensationBatch::new(
        account(),
        ids.iter()
            .map(|v| {
                MessageCompensation::new(
                    id(v),
                    ConditionalCompensation::new(
                        DesiredMailboxState::for_action(account(), &MessageAction::Read).unwrap(),
                        DesiredMailboxState::for_action(account(), &MessageAction::Unread).unwrap(),
                    )
                    .unwrap(),
                )
            })
            .collect(),
    )
    .unwrap();
    UndoCandidate::new(&complete, batch).unwrap()
}
fn undo_request(ids: &[&str]) -> UndoAdmission {
    let candidate = candidate(ids);
    let command = MailboxCommand::compensate(
        AccountCapability::Modify,
        command_id("undo"),
        candidate.compensation().clone(),
    )
    .unwrap();
    UndoAdmission::new(fence(), candidate, command).unwrap()
}

// Contract: offline undo is conditional admission, not generic admission or an
// eligibility claim. The admission-only gate runs once; later queued work must
// neither deadlock the undo nor cause it to rerun that gate during dispatch.
#[test]
fn offline_undo_admission_uses_its_own_gate_and_later_queue_does_not_block_dispatch() {
    let control = Control::default();
    let store = Store::new(&control, None);
    let coordinator = MailboxCommandCoordinator::new(&store);
    let request = undo_request(&["a", "b"]);
    store.state.lock().unwrap().undo = Some(request.candidate().clone());
    assert_eq!(
        run(coordinator.undo_candidate(&fence())).unwrap(),
        Some(request.candidate().clone())
    );
    assert!(matches!(
        run(coordinator.admit_undo(&request)).unwrap(),
        CommandAdmissionOutcome::Admitted(_)
    ));
    assert_eq!(control.calls(), [Stage::Candidate, Stage::Undo]);
    run(coordinator.admit(&CommandAdmission::new(fence(), create()).unwrap())).unwrap();
    let remote = Remote::new(
        &control,
        &store,
        vec![observation("a", &[]), observation("b", &[])],
    );
    let report = automatic(coordinator, &remote);
    assert_eq!(report.stop(), CommandDriveStop::AwaitingObservation);
    let sent = remote.sent.lock().unwrap();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].snapshot().command(), request.command());
    assert_eq!(
        control
            .calls()
            .iter()
            .filter(|s| **s == Stage::Undo)
            .count(),
        1
    );
    assert_eq!(
        store.state.lock().unwrap().rows[1].snapshot.status(),
        MailboxCommandStatus::Queued
    );
}

// Contract: reads settle already-desired targets before selecting only unmet
// unsettled targets. A fresh next pass, rather than ACK, proves completion.
#[test]
fn whole_fresh_evidence_latest_revision_unmet_subset_and_ack_then_observation() {
    let control = Control::default();
    let store = Store::new(&control, Some(command(&["a", "b"])));
    let coordinator = MailboxCommandCoordinator::new(&store);
    let remote = Remote::new(
        &control,
        &store,
        vec![observation("a", &[]), observation("b", &["UNREAD"])],
    );
    let report = automatic(coordinator, &remote);
    assert_eq!(report.stop(), CommandDriveStop::AwaitingObservation);
    assert_eq!(
        report.snapshot().unwrap().status(),
        MailboxCommandStatus::Ambiguous
    );
    assert_eq!(report.snapshot().unwrap().counts().satisfied(), 1);
    assert_eq!(report.snapshot().unwrap().counts().pending(), 1);
    assert_eq!(report.message_reads(), 2);
    assert_eq!(report.label_reads(), 0);
    assert!(report.dispatch_invoked());
    assert_eq!(
        control.calls(),
        [
            Stage::Oldest,
            Stage::Message(1),
            Stage::Message(2),
            Stage::Reconcile,
            Stage::Prepare,
            Stage::Dispatch,
            Stage::Record
        ]
    );
    let state = store.state.lock().unwrap();
    let preparation = &state.preparations[0];
    assert_eq!(preparation.precondition().stamp().revision(), 2);
    assert_eq!(preparation.targets().unwrap().ids(), [id("b")]);
    drop(state);
    *remote.messages.lock().unwrap() = vec![observation("a", &[]), observation("b", &[])];
    let settled = automatic(coordinator, &remote);
    assert_eq!(settled.stop(), CommandDriveStop::Terminal);
    assert_eq!(
        settled.snapshot().unwrap().status(),
        MailboxCommandStatus::Complete
    );
    assert_eq!(remote.sent.lock().unwrap().len(), 1);
    assert!(!settled.dispatch_invoked());
}

// Contract: full desired-state and all-missing evidence terminate without write;
// zero successes/all missing is Partial rather than Complete or unresolved.
#[test]
fn initial_satisfied_or_all_missing_targets_settle_without_dispatch() {
    for absent in [false, true] {
        let control = Control::default();
        let store = Store::new(&control, Some(command(&["a", "b"])));
        let coordinator = MailboxCommandCoordinator::new(&store);
        let messages = if absent {
            vec![missing("a"), missing("b")]
        } else {
            vec![observation("a", &[]), observation("b", &[])]
        };
        let remote = Remote::new(&control, &store, messages);
        let report = automatic(coordinator, &remote);
        assert_eq!(report.stop(), CommandDriveStop::Terminal);
        assert_eq!(
            report.snapshot().unwrap().status(),
            if absent {
                MailboxCommandStatus::Partial
            } else {
                MailboxCommandStatus::Complete
            }
        );
        assert_eq!(
            report.snapshot().unwrap().counts().target_missing(),
            if absent { 2 } else { 0 }
        );
        assert_eq!(
            report.snapshot().unwrap().counts().satisfied(),
            if absent { 0 } else { 2 }
        );
        assert!(remote.sent.lock().unwrap().is_empty());
        assert!(store.state.lock().unwrap().preparations.is_empty());
    }
}

// Contract: total automatic attempts are three; one explicit ticket survives
// reconciliation at its new revision, authorizes one extra and never resets the
// counter. A stale pre-reconciliation ticket would fail the fake store CAS.
#[test]
fn automatic_exhaustion_and_explicit_retry_use_latest_ticket_for_one_extra_attempt() {
    let control = Control::default();
    let store = Store::new(&control, Some(command(&["a"])));
    let coordinator = MailboxCommandCoordinator::new(&store);
    let remote = Remote::new(&control, &store, vec![observation("a", &["UNREAD"])]);
    for count in 1..=3 {
        let report = automatic(coordinator, &remote);
        assert_eq!(report.stop(), CommandDriveStop::AwaitingObservation);
        assert_eq!(report.snapshot().unwrap().automatic_attempts(), count);
        assert_eq!(remote.sent.lock().unwrap().len(), usize::from(count));
    }
    let exhausted = automatic(coordinator, &remote);
    assert_eq!(
        exhausted.stop(),
        CommandDriveStop::Attention(CommandAttention::AutomaticBudgetExhausted)
    );
    let old_ticket = run(coordinator.authorize_retry(&current_pre(&store))).unwrap();
    let policy = CommandWritePolicy::ExplicitRetry {
        key: old_ticket.stamp().key().clone(),
        duplicate_risk: DuplicateRiskConfirmation::NotConfirmed,
    };
    let report = run(coordinator.drive(&fence(), &remote, &remote, &policy));
    assert_eq!(report.stop(), CommandDriveStop::AwaitingObservation);
    assert_eq!(report.snapshot().unwrap().automatic_attempts(), 3);
    assert_eq!(remote.sent.lock().unwrap().len(), 4);
    let state = store.state.lock().unwrap();
    let last = state.preparations.last().unwrap();
    let DispatchAuthorization::Explicit(used) = last.authorization() else {
        panic!("explicit ticket");
    };
    assert_ne!(used, &old_ticket);
    assert_eq!(
        Some(used),
        last.reconciliation().snapshot().retry_authorization()
    );
    drop(state);
    let repeated = run(coordinator.drive(&fence(), &remote, &remote, &policy));
    assert_eq!(
        repeated.stop(),
        CommandDriveStop::Attention(CommandAttention::RetryAuthorizationRequired)
    );
    assert_eq!(remote.sent.lock().unwrap().len(), 4);
}

// Contract: automatic_attempts == 0 does not mean a create was never dispatched.
// A possible explicit-only create needs fresh Zero + a latest ticket + explicit
// duplicate-risk confirmation. One adopts, Multiple stays unresolved.
#[test]
fn create_recovery_never_automatically_resends_and_confirmed_zero_retry_is_single_use() {
    for matches in 0..=2 {
        let control = Control::default();
        let store = Store::new(&control, Some(create()));
        let coordinator = MailboxCommandCoordinator::new(&store);
        {
            let mut state = store.state.lock().unwrap();
            let row = &mut state.rows[0];
            row.snapshot = changed(
                &row.snapshot,
                MailboxCommandStatus::Ambiguous,
                row.snapshot.progress().clone(),
                0,
                false,
            );
            row.dispatched = true;
        }
        let remote = Remote::new(&control, &store, vec![]);
        *remote.definitions.lock().unwrap() = (0..matches)
            .map(|i| label(&format!("Label_match_{i}"), "Target"))
            .collect();
        let report = automatic(coordinator, &remote);
        assert_eq!(
            report.stop(),
            match matches {
                0 => CommandDriveStop::Attention(CommandAttention::Unresolved),
                1 => CommandDriveStop::Terminal,
                _ => CommandDriveStop::Attention(CommandAttention::MultipleCreateMatches),
            }
        );
        assert!(remote.sent.lock().unwrap().is_empty());
        assert_eq!(report.snapshot().unwrap().automatic_attempts(), 0);
        if matches == 0 {
            let ticket = run(coordinator.authorize_retry(&current_pre(&store))).unwrap();
            let mut policy = CommandWritePolicy::ExplicitRetry {
                key: ticket.stamp().key().clone(),
                duplicate_risk: DuplicateRiskConfirmation::NotConfirmed,
            };
            let refused = run(coordinator.drive(&fence(), &remote, &remote, &policy));
            assert_eq!(
                refused.stop(),
                CommandDriveStop::Attention(CommandAttention::DuplicateRiskConfirmationRequired)
            );
            assert!(!refused.dispatch_invoked());
            policy = CommandWritePolicy::ExplicitRetry {
                key: ticket.stamp().key().clone(),
                duplicate_risk: DuplicateRiskConfirmation::Confirmed,
            };
            let written = run(coordinator.drive(&fence(), &remote, &remote, &policy));
            assert_eq!(written.stop(), CommandDriveStop::AwaitingObservation);
            assert_eq!(written.snapshot().unwrap().automatic_attempts(), 0);
            let no_resend = automatic(coordinator, &remote);
            assert_eq!(
                no_resend.stop(),
                CommandDriveStop::Attention(CommandAttention::Unresolved)
            );
            assert_eq!(remote.sent.lock().unwrap().len(), 1);
        }
    }
}

// Contract: readonly reconciliation requires neither Modify capability nor a
// writer dependency. Grant loss still blocks preparation on an explicit drive.
#[test]
fn observation_only_works_after_modify_loss_including_known_label_reads() {
    for satisfied in [false, true] {
        let control = Control::default();
        let store = Store::new(&control, Some(command(&["a"])));
        store.state.lock().unwrap().modify = false;
        let coordinator = MailboxCommandCoordinator::new(&store);
        let remote = Remote::new(
            &control,
            &store,
            vec![observation("a", if satisfied { &[] } else { &["UNREAD"] })],
        );
        let report = run(coordinator.observe(&fence(), &remote, &ReadLabels(&remote)));
        assert_eq!(
            report.stop(),
            if satisfied {
                CommandDriveStop::Terminal
            } else {
                CommandDriveStop::ObservationOnly
            }
        );
        assert!(!report.dispatch_invoked());
        assert!(!control.calls().contains(&Stage::Prepare));
        if !satisfied {
            let denied = automatic(coordinator, &remote);
            assert_eq!(
                denied.stop(),
                CommandDriveStop::RecoveryRequired(CommandFailure::new(
                    CommandPhase::Prepare,
                    TriageStoreError::ReadOnly
                ))
            );
            assert!(remote.sent.lock().unwrap().is_empty());
        }
    }
    let control = Control::default();
    let rename = MailboxCommand::rename_label(
        AccountCapability::Modify,
        command_id("rename"),
        user(),
        LabelName::new("Known").unwrap(),
    )
    .unwrap();
    let store = Store::new(&control, Some(rename));
    store.state.lock().unwrap().modify = false;
    let remote = Remote::new(&control, &store, vec![]);
    let report = run(MailboxCommandCoordinator::new(&store).observe(
        &fence(),
        &remote,
        &ReadLabels(&remote),
    ));
    assert_eq!(report.stop(), CommandDriveStop::Terminal);
    assert_eq!(report.label_reads(), 1);
    assert_eq!(report.message_reads(), 0);
    assert_eq!(
        control.calls(),
        [Stage::Oldest, Stage::UserLabel, Stage::Reconcile]
    );
}

// Contract: the first undo guard covers ALL targets before any generic already-
// desired settlement. A changed/already-restored or missing target refuses all
// writes; after a guarded possible partial write, durable markers permit recovery.
#[test]
fn undo_whole_set_mismatch_never_settles_or_sends_but_guarded_partial_recovery_can_continue() {
    for messages in [
        vec![observation("a", &["UNREAD"]), observation("b", &[])],
        vec![missing("a"), observation("b", &[])],
        vec![observation("a", &["UNREAD"]), observation("b", &["UNREAD"])],
    ] {
        let control = Control::default();
        let request = undo_request(&["a", "b"]);
        let store = Store::new(&control, Some(request.command().clone()));
        let coordinator = MailboxCommandCoordinator::new(&store);
        let remote = Remote::new(&control, &store, messages);
        let report = automatic(coordinator, &remote);
        assert!(matches!(report.stop(), CommandDriveStop::Attention(_)));
        assert_eq!(
            report.snapshot().unwrap().status(),
            MailboxCommandStatus::NeedsAttention
        );
        assert_eq!(report.snapshot().unwrap().counts().satisfied(), 0);
        assert!(remote.sent.lock().unwrap().is_empty());
    }
    let control = Control::default();
    let request = undo_request(&["a", "b"]);
    let store = Store::new(&control, Some(request.command().clone()));
    let coordinator = MailboxCommandCoordinator::new(&store);
    let mut remote = Remote::new(
        &control,
        &store,
        vec![observation("a", &[]), observation("b", &[])],
    );
    remote.fact = Some(DispatchFact::Ambiguous);
    assert_eq!(
        automatic(coordinator, &remote).stop(),
        CommandDriveStop::AwaitingObservation
    );
    *remote.messages.lock().unwrap() = vec![observation("a", &["UNREAD"]), observation("b", &[])];
    let recovered = automatic(coordinator, &remote);
    assert_eq!(recovered.stop(), CommandDriveStop::AwaitingObservation);
    assert_eq!(
        remote
            .sent
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .targets()
            .unwrap()
            .ids(),
        [id("b")]
    );
    *remote.messages.lock().unwrap() =
        vec![observation("a", &["UNREAD"]), observation("b", &["UNREAD"])];
    let complete = automatic(coordinator, &remote);
    assert_eq!(complete.stop(), CommandDriveStop::Terminal);
    assert_eq!(
        complete.snapshot().unwrap().status(),
        MailboxCommandStatus::Complete
    );
    assert_eq!(remote.sent.lock().unwrap().len(), 2);
}

// Contract: failed/incomplete reads invalidate retry authority via the semantic
// attention operation, preserve earlier state if that also fails, and never send.
#[test]
fn read_failures_record_attention_without_writes_and_report_secondary_failure() {
    for secondary in [false, true] {
        let control = Control::default();
        let store = Store::new(&control, Some(command(&["a", "b"])));
        let coordinator = MailboxCommandCoordinator::new(&store);
        {
            let mut state = store.state.lock().unwrap();
            let row = &mut state.rows[0];
            row.snapshot = changed(
                &row.snapshot,
                MailboxCommandStatus::NeedsAttention,
                row.snapshot.progress().clone(),
                3,
                true,
            );
        }
        let before = store.state.lock().unwrap().rows[0].snapshot.clone();
        control.failures.lock().unwrap().push(Stage::Message(2));
        if secondary {
            control.failures.lock().unwrap().push(Stage::ReadFailure);
        }
        let remote = Remote::new(
            &control,
            &store,
            vec![observation("a", &[]), observation("b", &["UNREAD"])],
        );
        let policy = CommandWritePolicy::ExplicitRetry {
            key: before.stamp().key().clone(),
            duplicate_risk: DuplicateRiskConfirmation::NotConfirmed,
        };
        let report = run(coordinator.drive(&fence(), &remote, &remote, &policy));
        assert_eq!(
            report.stop(),
            CommandDriveStop::RecoveryRequired(CommandFailure::new(
                CommandPhase::ReadEvidence,
                MetadataReadError::Transport
            ))
        );
        assert_eq!(report.message_reads(), 2);
        assert!(!report.dispatch_invoked());
        assert!(!control.calls().contains(&Stage::Reconcile));
        if secondary {
            assert_eq!(report.snapshot(), Some(&before));
            assert_eq!(
                report.attention_failure(),
                Some(CommandFailure::new(
                    CommandPhase::RecordReadFailure,
                    TriageStoreError::Storage
                ))
            );
        } else {
            assert_eq!(
                report.snapshot().unwrap().status(),
                MailboxCommandStatus::NeedsAttention
            );
            assert!(report.snapshot().unwrap().retry_authorization().is_none());
            assert_eq!(report.snapshot().unwrap().automatic_attempts(), 3);
        }
    }
}

// Contract: deny wrong account/key/evidence/receipt/outcome at its actual phase.
// No invalid receipt reaches the writer; invalid post-send facts never reach
// record_dispatch and preserve confirmed Dispatching for durable recovery.
#[test]
fn mismatched_port_results_fail_closed_at_the_correct_boundary() {
    for invalid in [
        Stage::Oldest,
        Stage::Message(1),
        Stage::Catalog,
        Stage::UserLabel,
        Stage::Prepare,
        Stage::Dispatch,
        Stage::OutcomeShape,
    ] {
        let control = Control::default();
        *control.invalid.lock().unwrap() = Some(invalid);
        let intent = match invalid {
            Stage::Catalog => create(),
            Stage::UserLabel => MailboxCommand::delete_label(
                AccountCapability::Modify,
                command_id("delete"),
                user(),
            )
            .unwrap(),
            _ => command(&["a"]),
        };
        let store = Store::new(&control, Some(intent));
        let coordinator = MailboxCommandCoordinator::new(&store);
        let remote = Remote::new(&control, &store, vec![observation("a", &["UNREAD"])]);
        let report = automatic(coordinator, &remote);
        let phase = match invalid {
            Stage::Oldest => CommandPhase::Oldest,
            Stage::Prepare => CommandPhase::Prepare,
            Stage::Dispatch | Stage::OutcomeShape => CommandPhase::ValidateOutcome,
            _ => CommandPhase::ReadEvidence,
        };
        assert!(
            matches!(report.stop(),CommandDriveStop::RecoveryRequired(CommandFailure{phase:p,error:CommandCoordinatorError::Contract(_)} ) if p==phase)
        );
        let invoked = matches!(invalid, Stage::Dispatch | Stage::OutcomeShape);
        assert_eq!(report.dispatch_invoked(), invoked);
        assert_eq!(remote.sent.lock().unwrap().len(), usize::from(invoked));
        assert!(store.state.lock().unwrap().records.is_empty());
        if invoked {
            assert_eq!(
                report.snapshot().unwrap().status(),
                MailboxCommandStatus::Dispatching
            );
        }
    }
}

// Contract: preparation/recording failures and broad pre-dispatch session denial
// preserve the right durable phase; none fabricates per-item terminal failure.
#[test]
fn store_and_writer_failures_preserve_last_confirmed_state_and_phase() {
    for stage in [
        Stage::Oldest,
        Stage::Recover,
        Stage::Reconcile,
        Stage::Prepare,
        Stage::Dispatch,
        Stage::Record,
    ] {
        let control = Control::default();
        control.failures.lock().unwrap().push(stage);
        let store = Store::new(&control, Some(command(&["a"])));

        if stage == Stage::Recover {
            let mut state = store.state.lock().unwrap();
            let row = &mut state.rows[0];
            row.snapshot = changed(
                &row.snapshot,
                MailboxCommandStatus::Dispatching,
                row.snapshot.progress().clone(),
                1,
                false,
            );
            row.dispatched = true;
        }
        let coordinator = MailboxCommandCoordinator::new(&store);
        let remote = Remote::new(&control, &store, vec![observation("a", &["UNREAD"])]);
        let report = automatic(coordinator, &remote);
        let phase = match stage {
            Stage::Oldest => CommandPhase::Oldest,
            Stage::Recover => CommandPhase::RecoverDispatching,
            Stage::Reconcile => CommandPhase::Reconcile,
            Stage::Prepare => CommandPhase::Prepare,
            Stage::Dispatch => CommandPhase::Dispatch,
            _ => CommandPhase::RecordDispatch,
        };
        let error = if stage == Stage::Dispatch {
            CommandCoordinatorError::DispatchDenied(CommandDispatchError::InvalidRequest)
        } else {
            CommandCoordinatorError::Store(TriageStoreError::Storage)
        };
        assert_eq!(
            report.stop(),
            CommandDriveStop::RecoveryRequired(CommandFailure { phase, error })
        );
        if stage == Stage::Oldest {
            assert!(report.snapshot().is_none());
        } else {
            assert!(!report.snapshot().unwrap().status().is_terminal());
        }
        if matches!(stage, Stage::Dispatch | Stage::Record) {
            assert_eq!(
                report.snapshot().unwrap().status(),
                MailboxCommandStatus::Dispatching
            );
            assert!(report.dispatch_invoked());
        } else {
            assert!(!report.dispatch_invoked());
        }
    }
}

// Contract: interruption never spawns detached sends. Each meaningful awaited
// boundary stays pending, and no later phase runs until it resolves. Releasing
// Prepare is the positive control for commit-before-writer sequencing.
#[test]
fn cancellation_at_each_online_boundary_starts_no_detached_work() {
    for stage in [
        Stage::Oldest,
        Stage::Recover,
        Stage::Message(1),
        Stage::Catalog,
        Stage::UserLabel,
        Stage::ReadFailure,
        Stage::Reconcile,
        Stage::Prepare,
        Stage::Dispatch,
        Stage::Record,
    ] {
        let control = Control::default();
        *control.gate.lock().unwrap() = Some(stage);
        let intent = match stage {
            Stage::Catalog => create(),
            Stage::UserLabel => MailboxCommand::delete_label(
                AccountCapability::Modify,
                command_id("delete"),
                user(),
            )
            .unwrap(),
            _ => command(&["a"]),
        };
        let store = Store::new(&control, Some(intent));
        if stage == Stage::ReadFailure {
            control.failures.lock().unwrap().push(Stage::Message(1));
        }

        if stage == Stage::Recover {
            let mut state = store.state.lock().unwrap();
            let row = &mut state.rows[0];
            row.snapshot = changed(
                &row.snapshot,
                MailboxCommandStatus::Dispatching,
                row.snapshot.progress().clone(),
                1,
                false,
            );
            row.dispatched = true;
        }
        let coordinator = MailboxCommandCoordinator::new(&store);
        let remote = Remote::new(&control, &store, vec![observation("a", &["UNREAD"])]);
        let bound = fence();
        let policy = CommandWritePolicy::Automatic;
        let mut future = coordinator.drive(&bound, &remote, &remote, &policy);
        assert!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        assert_eq!(control.calls().last(), Some(&stage));
        assert_eq!(
            remote.sent.lock().unwrap().len(),
            usize::from(matches!(stage, Stage::Dispatch | Stage::Record))
        );
        if stage == Stage::Prepare {
            assert_ne!(
                store.state.lock().unwrap().rows[0].snapshot.status(),
                MailboxCommandStatus::Dispatching
            );
            *control.gate.lock().unwrap() = None;
            let report = run(future);
            assert_eq!(report.stop(), CommandDriveStop::AwaitingObservation);
            assert_eq!(remote.sent.lock().unwrap().len(), 1);
        } else {
            let calls = control.calls();
            drop(future);
            *control.gate.lock().unwrap() = None;
            assert_eq!(control.calls(), calls);
            if matches!(stage, Stage::Dispatch | Stage::Record) {
                assert_eq!(
                    store.state.lock().unwrap().rows[0].snapshot.status(),
                    MailboxCommandStatus::Dispatching
                );
            }
        }
    }
}

// Contract: a persisted Dispatching marker is recovered before any ordinary read
// or settlement. After a cancelled send, a fresh pass reconciles first, not resend.
#[test]
fn interrupted_dispatch_recovers_ambiguous_before_fresh_observation() {
    let control = Control::default();
    *control.gate.lock().unwrap() = Some(Stage::Dispatch);
    let store = Store::new(&control, Some(command(&["a"])));
    let coordinator = MailboxCommandCoordinator::new(&store);
    let remote = Remote::new(&control, &store, vec![observation("a", &["UNREAD"])]);
    let bound = fence();
    let policy = CommandWritePolicy::Automatic;
    let mut pending = coordinator.drive(&bound, &remote, &remote, &policy);
    assert!(
        pending
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    drop(pending);
    *control.gate.lock().unwrap() = None;
    *remote.messages.lock().unwrap() = vec![observation("a", &[])];
    let before = control.calls().len();
    let report = automatic(coordinator, &remote);
    assert_eq!(report.stop(), CommandDriveStop::Terminal);
    assert_eq!(
        &control.calls()[before..],
        [
            Stage::Oldest,
            Stage::Recover,
            Stage::Message(2),
            Stage::Reconcile
        ]
    );
    assert_eq!(remote.sent.lock().unwrap().len(), 1);
}

// Contract: the 1,000-target bound is a real finite reconciliation pass, not
// per-target retries or cached settlement; one further command is not driven.
#[test]
fn a_thousand_exact_target_reads_select_one_attempt_and_leave_later_work_queued() {
    let control = Control::default();
    let values: Vec<_> = (0..1_000).map(|i| format!("target-{i}")).collect();
    let refs: Vec<_> = values.iter().map(String::as_str).collect();
    let store = Store::new(&control, Some(command(&refs)));
    let coordinator = MailboxCommandCoordinator::new(&store);
    run(coordinator.admit(&CommandAdmission::new(fence(), create()).unwrap())).unwrap();
    let remote = Remote::new(
        &control,
        &store,
        values
            .iter()
            .map(|id| observation(id, &["UNREAD"]))
            .collect(),
    );
    let report = automatic(coordinator, &remote);
    assert_eq!(report.stop(), CommandDriveStop::AwaitingObservation);
    assert_eq!(report.message_reads(), 1_000);
    assert_eq!(report.label_reads(), 0);
    assert_eq!(remote.sent.lock().unwrap().len(), 1);
    assert_eq!(
        remote.sent.lock().unwrap()[0]
            .targets()
            .unwrap()
            .ids()
            .len(),
        1_000
    );
    assert_eq!(
        store.state.lock().unwrap().rows[1].snapshot.status(),
        MailboxCommandStatus::Queued
    );
}

// Contract: message-label writes need exact User-ID verification in addition to
// complete membership; definition-only rename/delete settle from known-ID reads.
// A read error must not masquerade as absence or permit dispatch.
#[test]
fn required_label_reads_and_known_id_definition_operations_use_fresh_evidence() {
    for action in [
        MessageAction::ApplyLabel(user()),
        MessageAction::RemoveLabel(user()),
    ] {
        let control = Control::default();
        let intent = MailboxCommand::message_state(
            AccountCapability::Modify,
            command_id("membership"),
            MessageTargets::new(account(), vec![id("a")]).unwrap(),
            &action,
        )
        .unwrap();
        let store = Store::new(&control, Some(intent));
        let coordinator = MailboxCommandCoordinator::new(&store);
        let labels = if matches!(action, MessageAction::ApplyLabel(_)) {
            vec![]
        } else {
            vec!["Label_1"]
        };
        let remote = Remote::new(&control, &store, vec![observation("a", &labels)]);
        let report = automatic(coordinator, &remote);
        assert_eq!(report.stop(), CommandDriveStop::AwaitingObservation);
        assert_eq!(report.label_reads(), 1);
        assert_eq!(
            control.calls(),
            [
                Stage::Oldest,
                Stage::Message(1),
                Stage::UserLabel,
                Stage::Reconcile,
                Stage::Prepare,
                Stage::Dispatch,
                Stage::Record
            ]
        );
        let state = store.state.lock().unwrap();
        assert!(
            matches!(state.preparations[0].reconciliation().evidence(),CommandEvidence::Messages{user_label:Some(observed),..} if observed.target()==&user() && observed.definition().is_some())
        );
    }
    for (delete, present) in [(false, true), (false, false), (true, true), (true, false)] {
        let control = Control::default();
        let intent = if delete {
            MailboxCommand::delete_label(
                AccountCapability::Modify,
                command_id("definition"),
                user(),
            )
            .unwrap()
        } else {
            MailboxCommand::rename_label(
                AccountCapability::Modify,
                command_id("definition"),
                user(),
                LabelName::new("New").unwrap(),
            )
            .unwrap()
        };
        let store = Store::new(&control, Some(intent));
        let coordinator = MailboxCommandCoordinator::new(&store);
        let remote = Remote::new(&control, &store, vec![]);
        if !present {
            remote.definitions.lock().unwrap().clear();
        }
        let report = automatic(coordinator, &remote);
        assert_eq!(
            report.stop(),
            if present {
                CommandDriveStop::AwaitingObservation
            } else {
                CommandDriveStop::Terminal
            }
        );
        assert_eq!(report.message_reads(), 0);
        assert_eq!(report.label_reads(), 1);
        assert_eq!(remote.sent.lock().unwrap().len(), usize::from(present));
        if !present {
            assert_eq!(
                report.snapshot().unwrap().status(),
                if delete {
                    MailboxCommandStatus::Complete
                } else {
                    MailboxCommandStatus::Partial
                }
            );
        }
    }
}

// Contract: label reads are real awaited acquisition boundaries. Their failure
// retains attention, invalidates an unused retry, and never sends a create/CRUD.
#[test]
fn failed_catalog_or_known_label_read_is_not_absence_or_permission_to_write() {
    for stage in [Stage::Catalog, Stage::UserLabel] {
        let control = Control::default();
        control.failures.lock().unwrap().push(stage);
        let intent = if stage == Stage::Catalog {
            create()
        } else {
            MailboxCommand::delete_label(AccountCapability::Modify, command_id("delete"), user())
                .unwrap()
        };
        let store = Store::new(&control, Some(intent));
        let coordinator = MailboxCommandCoordinator::new(&store);
        let remote = Remote::new(&control, &store, vec![]);
        let report = automatic(coordinator, &remote);
        assert_eq!(
            report.stop(),
            CommandDriveStop::RecoveryRequired(CommandFailure::new(
                CommandPhase::ReadEvidence,
                MetadataReadError::Transport
            ))
        );
        assert_eq!(
            report.snapshot().unwrap().status(),
            MailboxCommandStatus::NeedsAttention
        );
        assert_eq!(report.snapshot().unwrap().counts().pending(), 1);
        assert_eq!(control.calls(), [Stage::Oldest, stage, Stage::ReadFailure]);
        assert!(remote.sent.lock().unwrap().is_empty());
    }
}

// Contract: an absent required User definition refuses first undo as a whole,
// even when the message memberships themselves still match the expected post-state.
#[test]
fn conditional_undo_requires_the_known_user_definition_before_any_restore() {
    let control = Control::default();
    let condition = ConditionalCompensation::new(
        DesiredMailboxState::for_action(account(), &MessageAction::ApplyLabel(user())).unwrap(),
        DesiredMailboxState::for_action(account(), &MessageAction::RemoveLabel(user())).unwrap(),
    )
    .unwrap();
    let batch = CompensationBatch::new(
        account(),
        vec![MessageCompensation::new(id("a"), condition)],
    )
    .unwrap();
    let intent =
        MailboxCommand::compensate(AccountCapability::Modify, command_id("undo-label"), batch)
            .unwrap();
    let store = Store::new(&control, Some(intent));
    let coordinator = MailboxCommandCoordinator::new(&store);
    let remote = Remote::new(&control, &store, vec![observation("a", &["Label_1"])]);
    remote.definitions.lock().unwrap().clear();
    let report = automatic(coordinator, &remote);
    assert_eq!(
        report.stop(),
        CommandDriveStop::Attention(CommandAttention::Unresolved)
    );
    assert_eq!(
        report.snapshot().unwrap().status(),
        MailboxCommandStatus::NeedsAttention
    );
    assert_eq!(report.label_reads(), 1);
    assert!(store.state.lock().unwrap().preparations.is_empty());
    assert!(remote.sent.lock().unwrap().is_empty());
}

// Contract: a retry selected for a different command cannot authorize the oldest
// command, and even a valid retained ticket is not consumed by Automatic mode.
#[test]
fn retry_policy_is_bound_to_the_selected_command_and_does_not_leak_into_automatic_mode() {
    let control = Control::default();
    let store = Store::new(&control, Some(command(&["a"])));
    let coordinator = MailboxCommandCoordinator::new(&store);
    let remote = Remote::new(&control, &store, vec![observation("a", &["UNREAD"])]);
    let wrong = CommandWritePolicy::ExplicitRetry {
        key: CommandKey::new(account(), command_id("different")),
        duplicate_risk: DuplicateRiskConfirmation::Confirmed,
    };
    let wrong_result = run(coordinator.drive(&fence(), &remote, &remote, &wrong));
    assert_eq!(
        wrong_result.stop(),
        CommandDriveStop::RecoveryRequired(CommandFailure::new(
            CommandPhase::Oldest,
            ContractError::WrongTarget
        ))
    );
    assert_eq!(control.calls(), [Stage::Oldest]);
    automatic(coordinator, &remote);
    run(coordinator.authorize_retry(&current_pre(&store))).unwrap();
    let report = automatic(coordinator, &remote);
    assert_eq!(
        report.stop(),
        CommandDriveStop::Attention(CommandAttention::RetryAuthorizationRequired)
    );
    assert!(report.snapshot().unwrap().retry_authorization().is_some());
    assert_eq!(remote.sent.lock().unwrap().len(), 1);
}

// Contract: actual provider rejections are recorded as bound transport facts,
// leaving item settlement to fresh observation. Session denial (an Err) has a
// different recovery path and must never be fabricated into one of these facts.
#[test]
fn provider_rejections_are_recorded_without_fabricated_terminal_item_failure() {
    for rejection in [
        CommandRejection::AuthorizationRequired,
        CommandRejection::RateLimited,
        CommandRejection::Rejected,
    ] {
        let control = Control::default();
        let store = Store::new(&control, Some(command(&["a"])));
        let coordinator = MailboxCommandCoordinator::new(&store);
        let mut remote = Remote::new(&control, &store, vec![observation("a", &["UNREAD"])]);
        remote.fact = Some(DispatchFact::Rejected(rejection));
        let report = automatic(coordinator, &remote);
        assert_eq!(report.stop(), CommandDriveStop::AwaitingObservation);
        assert_eq!(
            report.snapshot().unwrap().status(),
            MailboxCommandStatus::NeedsAttention
        );
        assert_eq!(report.snapshot().unwrap().counts().pending(), 1);
        assert_eq!(report.snapshot().unwrap().counts().failed(), 0);
        let state = store.state.lock().unwrap();
        assert_eq!(state.records.len(), 1);
        assert_eq!(state.records[0].fact(), &DispatchFact::Rejected(rejection));
        assert_eq!(remote.sent.lock().unwrap().len(), 1);
    }
}
