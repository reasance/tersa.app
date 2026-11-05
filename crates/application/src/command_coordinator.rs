// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Coordinates offline command intent and one bounded online FIFO operation.
//!
//! Local methods borrow only the store. They never construct a remote client,
//! obtain credentials or send a mutation. Callers generate fresh IDs; replay is
//! lookup only, including unknown/expired IDs. Compensation uses UndoAdmission,
//! never ordinary admission. Store transactions remain authoritative for identity,
//! persisted capability, FIFO, quotas, revisions and conditional undo markers.
//!
//! P7 supplies account serialization and trusted identity/session admission. It
//! chooses `observe` for readonly settlement, or `drive` with an accepted Modify
//! writer for one attempt. Observation needs only GmailHistoryFeed and the
//! readonly CommandLabelReader facet; a readonly Gmail bridge belongs to P7.
//! Each pass acquires at most 1,000 exact-message minimal GETs and one required
//! label read or complete bounded catalog. HistorySync/cached state is not fresh
//! command evidence. This conservative whole-target pass also permits the store
//! to check first-dispatch undo conditions before generic desired-state settlement.
//! Guarded partial compensation recovery is decided by durable store markers;
//! neither automatic-attempt counts nor current memberships reveal those markers.
//! Provider changes after comparison remain a no-CAS residual.
//!
//! Every write awaits store preparation and validates its receipt first. At most
//! one remote dispatch is invoked; no retry or next-command loop is hidden here.
//! ACK remains awaiting observation. Errors retain the last validated durable
//! snapshot and name the failed phase. A pre-dispatch denial cannot be represented
//! by record_dispatch without inventing a transport fact: leave Dispatching intact
//! and report the denial. A later invocation conservatively recovers that marker
//! as Ambiguous. Invalid receipts/outcomes likewise never fabricate rollback or
//! terminal item failure. Dropping any future starts no detached work; interruption
//! of a mutator requires rereading durable state, including possible Dispatching.
//!
//! ```
//! use tersa_application::{
//!     command::{CommandKey, MailboxCommandStore},
//!     command_coordinator::MailboxCommandCoordinator,
//!     profile::AccountFence,
//! };
//! # async fn offline<S: MailboxCommandStore>(store: &S, fence: &AccountFence, key: &CommandKey) {
//! // No remote client or access token is needed, and None never admits new work.
//! let saved = MailboxCommandCoordinator::new(store).lookup(fence, key).await;
//! # let _ = saved;
//! # }
//! ```
// Rust guideline compliant 1.0.

use crate::{
    command::{
        AbandonConfirmation, CommandAdmission, CommandAdmissionOutcome, CommandDispatchError,
        CommandEvidence, CommandKey, CommandLabelReader, CommandPrecondition, CommandProgress,
        CommandReconciliation, CommandSnapshot, CommandStamp, DispatchAuthorization, DispatchFact,
        DispatchPreparation, DispatchReceipt, DuplicateRiskConfirmation, LabelCreateMatches,
        MAX_AUTOMATIC_ATTEMPTS, MailboxCommandStore, ReconciliationFailure, RemoteCommandOutcome,
        RemoteMailboxCommands, RetainedCommand, RetryAuthorization, TerminalCommandSummary,
        TerminalSummaries, UndoAdmission, UndoCandidate, required_user_label,
    },
    history::GmailHistoryFeed,
    mailbox::BoxFuture,
    mailbox_state::{
        ContractError, MessageObservations, MetadataReadError, RemoteMessageState, TriageStoreError,
    },
    profile::AccountFence,
};
use std::fmt;
use tersa_domain::{
    command::{MailboxCommand, MailboxCommandKind, MailboxCommandStatus, MessageTargets},
    label::ObservedMembership,
};

/// Reports a closed port failure without provider strings or credential material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandCoordinatorError {
    /// An owning-store operation failed; no rebind, reset or implicit readmission.
    Store(TriageStoreError),
    /// A required fresh read failed; absence was not established.
    Read(MetadataReadError),
    /// A returned document was not bound to the intended command/context.
    Contract(ContractError),
    /// The writer denied the attempt before any provider mutation was attempted.
    DispatchDenied(CommandDispatchError),
}
impl fmt::Display for CommandCoordinatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("mailbox command coordination failed")
    }
}
impl std::error::Error for CommandCoordinatorError {}
impl From<TriageStoreError> for CommandCoordinatorError {
    fn from(error: TriageStoreError) -> Self {
        Self::Store(error)
    }
}
impl From<ContractError> for CommandCoordinatorError {
    fn from(error: ContractError) -> Self {
        Self::Contract(error)
    }
}
impl From<MetadataReadError> for CommandCoordinatorError {
    fn from(error: MetadataReadError) -> Self {
        Self::Read(error)
    }
}

/// Names the awaited/validation boundary that failed in an online invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandPhase {
    /// Reading the oldest durable command.
    Oldest,
    /// Recovering a previous interrupted Dispatching marker.
    RecoverDispatching,
    /// Acquiring/validating whole-target fresh observations.
    ReadEvidence,
    /// Committing derived observation outcomes.
    Reconcile,
    /// Retaining `NeedsAttention` after failed fresh acquisition.
    RecordReadFailure,
    /// Committing/validating Dispatching before any remote write.
    Prepare,
    /// Invoking the single remote write, including a pre-dispatch denial.
    Dispatch,
    /// Validating the returned remote outcome after possible application.
    ValidateOutcome,
    /// Recording the correctly bound transport fact.
    RecordDispatch,
}

/// Preserves the failed phase and its closed error category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommandFailure {
    /// Failed operation or response validation boundary.
    pub phase: CommandPhase,
    /// Closed failure; does not imply provider rollback.
    pub error: CommandCoordinatorError,
}
impl CommandFailure {
    fn new<E: Into<CommandCoordinatorError>>(phase: CommandPhase, error: E) -> Self {
        Self {
            phase,
            error: error.into(),
        }
    }
}

/// Chooses one permitted write mode; neither mode creates a retry authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandWritePolicy {
    /// Use only remaining automatic budget; do not consume a pending explicit ticket.
    Automatic,
    /// Consume at most one existing ticket after fresh reconciliation of this exact command.
    /// The latest returned snapshot supplies the ticket, never a pre-reconciliation copy.
    ExplicitRetry {
        /// Bind the user-selected retry and duplicate-risk confirmation to this command.
        key: CommandKey,
        /// Required for an explicit create attempt; never inferred from zero matches.
        duplicate_risk: DuplicateRiskConfirmation,
    },
}

/// Reports a safe stop without guessing undisclosed durable dispatch history.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandAttention {
    /// Store snapshot/evidence does not expose enough eligibility detail to claim more.
    Unresolved,
    /// The known total automatic budget has been consumed.
    AutomaticBudgetExhausted,
    /// The selected mode cannot consume the current persisted ticket state.
    RetryAuthorizationRequired,
    /// The user has not confirmed duplicate risk for this explicit create attempt.
    DuplicateRiskConfirmationRequired,
    /// A complete fresh catalog has multiple exact User-name matches.
    MultipleCreateMatches,
    /// The authoritative store refused preparation; do not infer its hidden marker state.
    StoreNotEligible,
}

/// Distinguishes observation/terminal disposition from a possible provider write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandDriveStop {
    /// The queue had no oldest nonterminal command.
    Idle,
    /// Actual store reconciliation committed terminal disposition; inspect its status/counts.
    Terminal,
    /// Readonly reconciliation completed; no preparation or dispatch was attempted.
    ObservationOnly,
    /// No dispatch was invoked; explicit attention or a later guarded pass is needed.
    Attention(CommandAttention),
    /// One correctly bound transport fact was committed; ACK is not completion.
    AwaitingObservation,
    /// Failed work retains the last confirmed snapshot, including possible Dispatching.
    RecoveryRequired(CommandFailure),
}

/// Returns bounded online progress and the last validated durable command state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandDriveReport {
    stop: CommandDriveStop,
    snapshot: Option<CommandSnapshot>,
    message_reads: usize,
    label_reads: usize,
    dispatch_invoked: bool,
    attention_failure: Option<CommandFailure>,
}
impl CommandDriveReport {
    /// Returns the completion, attention or failed-phase fact.
    #[must_use]
    pub fn stop(&self) -> CommandDriveStop {
        self.stop
    }
    /// Returns the last validated durable state, not renewed write authority after failure.
    #[must_use]
    pub fn snapshot(&self) -> Option<&CommandSnapshot> {
        self.snapshot.as_ref()
    }
    /// Returns exact-message GETs started, including a failed final read; at most 1,000.
    #[must_use]
    pub fn message_reads(&self) -> usize {
        self.message_reads
    }
    /// Returns required-label/catalog reads started; at most one per invocation.
    #[must_use]
    pub fn label_reads(&self) -> usize {
        self.label_reads
    }
    /// Returns whether the writer was invoked once; does not prove provider application.
    #[must_use]
    pub fn dispatch_invoked(&self) -> bool {
        self.dispatch_invoked
    }
    /// Returns a secondary failure retaining `NeedsAttention` after failed fresh reads.
    #[must_use]
    pub fn attention_failure(&self) -> Option<CommandFailure> {
        self.attention_failure
    }
}

/// Borrows only the store so local recovery remains usable offline.
pub struct MailboxCommandCoordinator<'a, S: ?Sized> {
    store: &'a S,
}
impl<S: ?Sized> fmt::Debug for MailboxCommandCoordinator<'_, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MailboxCommandCoordinator")
            .finish_non_exhaustive()
    }
}
impl<S: ?Sized> Clone for MailboxCommandCoordinator<'_, S> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<S: ?Sized> Copy for MailboxCommandCoordinator<'_, S> {}

impl<'store, S: MailboxCommandStore + ?Sized> MailboxCommandCoordinator<'store, S> {
    /// Borrows the store; no remote client, account access or work is started.
    #[must_use]
    pub fn new(store: &'store S) -> Self {
        Self { store }
    }

    /// Admits genuinely fresh ordinary intent, never unknown/expired replay or compensation.
    ///
    /// # Errors
    /// Returns store denial or a mismatched store result. Caller supplies a fresh ID.
    pub async fn admit(
        &self,
        request: &CommandAdmission,
    ) -> Result<CommandAdmissionOutcome, CommandCoordinatorError> {
        let result = self.store.admit(request).await?;
        validate_admission(&result, request.command())?;
        Ok(result)
    }
    /// Admits offline conditional undo through the separate store-owned admission gate.
    ///
    /// # Errors
    /// Returns failed source/queue/identity/quota guards or a mismatched result.
    pub async fn admit_undo(
        &self,
        request: &UndoAdmission,
    ) -> Result<CommandAdmissionOutcome, CommandCoordinatorError> {
        let result = self.store.admit_undo(request).await?;
        validate_admission(&result, request.command())?;
        Ok(result)
    }
    /// Reads saved status only; unknown/expired IDs return None without admission or dispatch.
    ///
    /// # Errors
    /// Returns store failure or account/command context mismatch.
    pub async fn lookup(
        &self,
        fence: &AccountFence,
        key: &CommandKey,
    ) -> Result<Option<RetainedCommand>, CommandCoordinatorError> {
        validate_key(fence, key)?;
        let result = self.store.lookup(fence, key).await?;
        if let Some(saved) = &result {
            validate_retained(saved, key)?;
        }
        Ok(result)
    }
    /// Reads the one conditional undo candidate without claiming current online eligibility.
    ///
    /// # Errors
    /// Returns store failure or an account mismatch.
    pub async fn undo_candidate(
        &self,
        fence: &AccountFence,
    ) -> Result<Option<UndoCandidate>, CommandCoordinatorError> {
        let result = self.store.undo_candidate(fence).await?;
        if let Some(candidate) = &result {
            validate_key(fence, candidate.source().key())?;
        }
        Ok(result)
    }
    /// Cancels only unsent Queued intent through the store; no remote cancellation exists.
    ///
    /// # Errors
    /// Returns failed durable guards or invalid cancellation result.
    pub async fn cancel_queued(
        &self,
        expected: &CommandPrecondition,
    ) -> Result<TerminalCommandSummary, CommandCoordinatorError> {
        let result = self.store.cancel_queued(expected).await?;
        validate_summary(&result, expected, MailboxCommandStatus::Cancelled)?;
        Ok(result)
    }
    /// Commits warned Abandon locally, claiming neither success nor provider rollback.
    ///
    /// # Errors
    /// Returns failed durable guards or invalid abandonment result.
    pub async fn abandon(
        &self,
        expected: &CommandPrecondition,
        confirmation: AbandonConfirmation,
    ) -> Result<TerminalCommandSummary, CommandCoordinatorError> {
        let result = self.store.abandon(expected, confirmation).await?;
        validate_summary(&result, expected, MailboxCommandStatus::Abandoned)?;
        Ok(result)
    }
    /// Authorizes one explicit retry locally; does not reconcile or send anything.
    ///
    /// # Errors
    /// Returns failed state/FIFO guards or an invalid ticket. A later drive uses
    /// the latest reconciled snapshot's ticket, not this possibly stale revision.
    pub async fn authorize_retry(
        &self,
        expected: &CommandPrecondition,
    ) -> Result<RetryAuthorization, CommandCoordinatorError> {
        let ticket = self.store.authorize_retry(expected).await?;
        validate_new_stamp(ticket.stamp(), expected.stamp())?;
        Ok(ticket)
    }
    /// Reads bounded retained terminal facts without fabricating active commands.
    ///
    /// # Errors
    /// Returns a store failure or mismatched account.
    pub async fn terminal_summaries(
        &self,
        fence: &AccountFence,
    ) -> Result<TerminalSummaries, CommandCoordinatorError> {
        let result = self.store.terminal_summaries(fence).await?;
        if result.account_id() != fence.account_id() {
            return Err(ContractError::WrongAccount.into());
        }
        Ok(result)
    }

    /// Reconciles one oldest command using readonly ports; never prepares or invokes a writer.
    #[must_use]
    pub fn observe<'a, R: GmailHistoryFeed + ?Sized, L: CommandLabelReader + ?Sized>(
        &'a self,
        fence: &'a AccountFence,
        feed: &'a R,
        labels: &'a L,
    ) -> BoxFuture<'a, CommandDriveReport> {
        Box::pin(async move { self.online(fence, feed, labels, None).await })
    }

    /// Reconciles one oldest command and attempts at most one prepared write.
    ///
    /// P7 supplies an accepted same-account Modify writer and serialization.
    /// `ExplicitRetry` consumes an existing latest ticket; it never authorizes one.
    #[must_use]
    pub fn drive<'a, R: GmailHistoryFeed + ?Sized>(
        &'a self,
        fence: &'a AccountFence,
        feed: &'a R,
        writer: &'a dyn RemoteMailboxCommands,
        policy: &'a CommandWritePolicy,
    ) -> BoxFuture<'a, CommandDriveReport> {
        Box::pin(async move {
            self.online(fence, feed, writer, Some((writer, policy)))
                .await
        })
    }

    async fn online<R: GmailHistoryFeed + ?Sized, L: CommandLabelReader + ?Sized>(
        &self,
        fence: &AccountFence,
        feed: &R,
        labels: &L,
        write: Option<(&dyn RemoteMailboxCommands, &CommandWritePolicy)>,
    ) -> CommandDriveReport {
        let mut report = CommandDriveReport {
            stop: CommandDriveStop::Idle,
            snapshot: None,
            message_reads: 0,
            label_reads: 0,
            dispatch_invoked: false,
            attention_failure: None,
        };
        let result = self.run(fence, feed, labels, write, &mut report).await;
        report.stop = result.unwrap_or_else(CommandDriveStop::RecoveryRequired);
        report
    }

    async fn run<R: GmailHistoryFeed + ?Sized, L: CommandLabelReader + ?Sized>(
        &self,
        fence: &AccountFence,
        feed: &R,
        labels: &L,
        write: Option<(&dyn RemoteMailboxCommands, &CommandWritePolicy)>,
        report: &mut CommandDriveReport,
    ) -> Result<CommandDriveStop, CommandFailure> {
        let phase = CommandPhase::Oldest;
        let Some(mut snapshot) = self
            .store
            .oldest_pending(fence)
            .await
            .map_err(|e| CommandFailure::new(phase, e))?
        else {
            return Ok(CommandDriveStop::Idle);
        };
        validate_key(fence, snapshot.stamp().key()).map_err(|e| CommandFailure::new(phase, e))?;
        if snapshot.status().is_terminal() {
            return Err(CommandFailure::new(phase, ContractError::State));
        }
        report.snapshot = Some(snapshot.clone());
        if let Some((_, CommandWritePolicy::ExplicitRetry { key, .. })) = write
            && snapshot.stamp().key() != key
        {
            return Err(CommandFailure::new(phase, ContractError::WrongTarget));
        }
        if snapshot.status() == MailboxCommandStatus::Dispatching {
            let phase = CommandPhase::RecoverDispatching;
            let expected = precondition(fence, &snapshot);
            let recovered = self
                .store
                .recover_dispatching(&expected)
                .await
                .map_err(|e| CommandFailure::new(phase, e))?;
            validate_update(&snapshot, &recovered, snapshot.automatic_attempts())
                .map_err(|e| CommandFailure::new(phase, e))?;
            if recovered.status() != MailboxCommandStatus::Ambiguous
                || recovered.progress() != snapshot.progress()
            {
                return Err(CommandFailure::new(phase, ContractError::State));
            }
            report.snapshot = Some(recovered.clone());
            snapshot = recovered;
        }
        let evidence = match acquire_evidence(feed, labels, &snapshot, report).await {
            Ok(evidence) => evidence,
            Err(error) => {
                self.read_failed(fence, &snapshot, error, report).await;
                return Err(CommandFailure::new(CommandPhase::ReadEvidence, error));
            }
        };
        let reconciliation = CommandReconciliation::new(snapshot.clone(), evidence.clone())
            .map_err(|e| CommandFailure::new(CommandPhase::ReadEvidence, e))?;
        let phase = CommandPhase::Reconcile;
        let latest = self
            .store
            .reconcile(&precondition(fence, &snapshot), &reconciliation)
            .await
            .map_err(|e| CommandFailure::new(phase, e))?;
        validate_update(&snapshot, &latest, snapshot.automatic_attempts())
            .map_err(|e| CommandFailure::new(phase, e))?;
        if matches!(
            latest.status(),
            MailboxCommandStatus::Dispatching
                | MailboxCommandStatus::Cancelled
                | MailboxCommandStatus::Abandoned
        ) {
            return Err(CommandFailure::new(phase, ContractError::State));
        }
        report.snapshot = Some(latest.clone());
        if latest.status().is_terminal() {
            return Ok(CommandDriveStop::Terminal);
        }
        let Some((writer, policy)) = write else {
            return Ok(CommandDriveStop::ObservationOnly);
        };
        let reconciliation = CommandReconciliation::new(latest, evidence)
            .map_err(|e| CommandFailure::new(phase, e))?;
        self.send(fence, writer, policy, reconciliation, report)
            .await
    }

    async fn send(
        &self,
        fence: &AccountFence,
        writer: &dyn RemoteMailboxCommands,
        policy: &CommandWritePolicy,
        reconciliation: CommandReconciliation,
        report: &mut CommandDriveReport,
    ) -> Result<CommandDriveStop, CommandFailure> {
        let latest = reconciliation.snapshot().clone();
        let authorization = match authorization(&latest, policy, &reconciliation) {
            Ok(authorization) => authorization,
            Err(attention) => return Ok(CommandDriveStop::Attention(attention)),
        };
        if !label_evidence_permits_write(&reconciliation) {
            return Ok(CommandDriveStop::Attention(CommandAttention::Unresolved));
        }
        let targets = select_targets(&reconciliation)
            .map_err(|e| CommandFailure::new(CommandPhase::Prepare, e))?;
        if matches!(latest.progress(), CommandProgress::Messages(_)) && targets.is_none() {
            return Ok(CommandDriveStop::Attention(CommandAttention::Unresolved));
        }
        let duplicate_risk = match policy {
            CommandWritePolicy::Automatic => DuplicateRiskConfirmation::NotConfirmed,
            CommandWritePolicy::ExplicitRetry { duplicate_risk, .. } => *duplicate_risk,
        };
        let request = DispatchPreparation::new(
            precondition(fence, &latest),
            reconciliation,
            targets,
            authorization,
            duplicate_risk,
        )
        .map_err(|e| CommandFailure::new(CommandPhase::Prepare, e))?;
        let receipt = match self.store.prepare_dispatch(&request).await {
            Ok(receipt) => receipt,
            Err(TriageStoreError::NotEligible) => {
                return Ok(CommandDriveStop::Attention(
                    CommandAttention::StoreNotEligible,
                ));
            }
            Err(error) => return Err(CommandFailure::new(CommandPhase::Prepare, error)),
        };
        validate_receipt(&request, &receipt)
            .map_err(|e| CommandFailure::new(CommandPhase::Prepare, e))?;
        report.snapshot = Some(receipt.snapshot().clone());
        report.dispatch_invoked = true;
        let outcome = writer.dispatch(&receipt).await.map_err(|e| {
            CommandFailure::new(
                CommandPhase::Dispatch,
                CommandCoordinatorError::DispatchDenied(e),
            )
        })?;
        if outcome.stamp() != receipt.snapshot().stamp() {
            return Err(CommandFailure::new(
                CommandPhase::ValidateOutcome,
                ContractError::WrongTarget,
            ));
        }
        RemoteCommandOutcome::new(&receipt, outcome.fact().clone())
            .map_err(|e| CommandFailure::new(CommandPhase::ValidateOutcome, e))?;
        let phase = CommandPhase::RecordDispatch;
        let recorded = self
            .store
            .record_dispatch(&precondition(fence, receipt.snapshot()), &outcome)
            .await
            .map_err(|e| CommandFailure::new(phase, e))?;
        validate_update(
            receipt.snapshot(),
            &recorded,
            receipt.snapshot().automatic_attempts(),
        )
        .map_err(|e| CommandFailure::new(phase, e))?;
        let status = if matches!(outcome.fact(), DispatchFact::Rejected(_)) {
            MailboxCommandStatus::NeedsAttention
        } else {
            MailboxCommandStatus::Ambiguous
        };
        if recorded.status() != status
            || recorded.progress() != receipt.snapshot().progress()
            || recorded.retry_authorization().is_some()
        {
            return Err(CommandFailure::new(phase, ContractError::State));
        }
        report.snapshot = Some(recorded);
        Ok(CommandDriveStop::AwaitingObservation)
    }

    async fn read_failed(
        &self,
        fence: &AccountFence,
        snapshot: &CommandSnapshot,
        error: CommandCoordinatorError,
        report: &mut CommandDriveReport,
    ) {
        let failure = if matches!(error, CommandCoordinatorError::Read(_)) {
            ReconciliationFailure::ReadUnavailable
        } else {
            ReconciliationFailure::InvalidEvidence
        };
        let phase = CommandPhase::RecordReadFailure;
        let result = self
            .store
            .reconciliation_failed(&precondition(fence, snapshot), failure)
            .await
            .map_err(CommandCoordinatorError::from)
            .and_then(|updated| {
                validate_update(snapshot, &updated, snapshot.automatic_attempts())?;
                if updated.status() != MailboxCommandStatus::NeedsAttention
                    || updated.progress() != snapshot.progress()
                    || updated.retry_authorization().is_some()
                {
                    return Err(ContractError::State.into());
                }
                Ok(updated)
            });
        match result {
            Ok(updated) => report.snapshot = Some(updated),
            Err(error) => report.attention_failure = Some(CommandFailure::new(phase, error)),
        }
    }
}

fn precondition(fence: &AccountFence, snapshot: &CommandSnapshot) -> CommandPrecondition {
    CommandPrecondition::new(fence.clone(), snapshot.stamp().clone())
        .expect("validated account binding")
}
fn validate_key(fence: &AccountFence, key: &CommandKey) -> Result<(), ContractError> {
    if fence.account_id() != key.account_id() {
        return Err(ContractError::WrongAccount);
    }
    Ok(())
}
fn validate_new_stamp(stamp: &CommandStamp, previous: &CommandStamp) -> Result<(), ContractError> {
    if stamp.key() != previous.key() {
        return Err(ContractError::WrongTarget);
    }
    if stamp.revision() <= previous.revision() {
        return Err(ContractError::Order);
    }
    Ok(())
}
fn validate_update(
    before: &CommandSnapshot,
    after: &CommandSnapshot,
    attempts: u8,
) -> Result<(), ContractError> {
    validate_new_stamp(after.stamp(), before.stamp())?;
    if after.command() != before.command()
        || after.automatic_attempts() != attempts
        || (before.retry_authorization().is_none() && after.retry_authorization().is_some())
    {
        return Err(ContractError::State);
    }
    if let (CommandProgress::Messages(old), CommandProgress::Messages(new)) =
        (before.progress(), after.progress())
        && old
            .iter()
            .zip(new)
            .any(|(a, b)| a.outcome().is_some() && a.outcome() != b.outcome())
    {
        return Err(ContractError::State);
    }
    Ok(())
}
fn validate_retained(saved: &RetainedCommand, key: &CommandKey) -> Result<(), ContractError> {
    let stamp = match saved {
        RetainedCommand::Full(s) => s.stamp(),
        RetainedCommand::Terminal(s) => s.stamp(),
    };
    if stamp.key() != key {
        return Err(ContractError::WrongTarget);
    }
    Ok(())
}
fn validate_admission(
    result: &CommandAdmissionOutcome,
    command: &MailboxCommand,
) -> Result<(), ContractError> {
    let key = CommandKey::new(command.account_id().clone(), command.id().clone());
    match result {
        CommandAdmissionOutcome::Retained(saved) => validate_retained(saved, &key),
        CommandAdmissionOutcome::Admitted(s) => {
            if s.command() != command
                || s.status() != MailboxCommandStatus::Queued
                || s.counts().pending() != s.counts().total()
            {
                return Err(ContractError::State);
            }
            Ok(())
        }
    }
}
fn validate_summary(
    summary: &TerminalCommandSummary,
    expected: &CommandPrecondition,
    status: MailboxCommandStatus,
) -> Result<(), ContractError> {
    validate_new_stamp(summary.stamp(), expected.stamp())?;
    if summary.status() != status {
        return Err(ContractError::State);
    }
    Ok(())
}
fn validate_receipt(
    request: &DispatchPreparation,
    receipt: &DispatchReceipt,
) -> Result<(), ContractError> {
    let before = request.reconciliation().snapshot();
    let attempts = before.automatic_attempts()
        + u8::from(matches!(
            request.authorization(),
            DispatchAuthorization::Automatic
        ));
    validate_update(before, receipt.snapshot(), attempts)?;
    if receipt.targets() != request.targets()
        || receipt.snapshot().progress() != before.progress()
        || receipt.snapshot().retry_authorization().is_some()
    {
        return Err(ContractError::Coverage);
    }
    Ok(())
}

fn authorization(
    snapshot: &CommandSnapshot,
    policy: &CommandWritePolicy,
    reconciliation: &CommandReconciliation,
) -> Result<DispatchAuthorization, CommandAttention> {
    if reconciliation.create_matches() == Some(LabelCreateMatches::Multiple) {
        return Err(CommandAttention::MultipleCreateMatches);
    }
    match policy {
        CommandWritePolicy::Automatic => {
            if snapshot.retry_authorization().is_some() {
                return Err(CommandAttention::RetryAuthorizationRequired);
            }
            if snapshot.automatic_attempts() >= MAX_AUTOMATIC_ATTEMPTS {
                return Err(CommandAttention::AutomaticBudgetExhausted);
            }
            // Queued means unsent. Other states do not reveal whether a zero-count
            // create was explicitly sent. Pause automatic work; an explicit
            // ticket and confirmation let the store decide retry eligibility.
            if matches!(
                snapshot.command().kind(),
                MailboxCommandKind::CreateLabel(_)
            ) && snapshot.status() != MailboxCommandStatus::Queued
            {
                return Err(CommandAttention::Unresolved);
            }
            Ok(DispatchAuthorization::Automatic)
        }
        CommandWritePolicy::ExplicitRetry { duplicate_risk, .. } => {
            let ticket = snapshot
                .retry_authorization()
                .ok_or(CommandAttention::RetryAuthorizationRequired)?;
            if matches!(
                snapshot.command().kind(),
                MailboxCommandKind::CreateLabel(_)
            ) && *duplicate_risk != DuplicateRiskConfirmation::Confirmed
            {
                return Err(CommandAttention::DuplicateRiskConfirmationRequired);
            }
            Ok(DispatchAuthorization::Explicit(ticket.clone()))
        }
    }
}

fn label_evidence_permits_write(reconciliation: &CommandReconciliation) -> bool {
    match reconciliation.evidence() {
        CommandEvidence::Messages { user_label, .. } => user_label
            .as_ref()
            .is_none_or(|label| label.definition().is_some()),
        CommandEvidence::CreateCatalog(_) => {
            reconciliation.create_matches() == Some(LabelCreateMatches::Zero)
        }
        CommandEvidence::UserLabel(observed) => {
            let Some(definition) = observed.definition() else {
                return false;
            };
            match reconciliation.snapshot().command().kind() {
                MailboxCommandKind::RenameLabel { name, .. } => definition.name() != name,
                MailboxCommandKind::DeleteLabel(_) => true,
                _ => false,
            }
        }
    }
}

async fn acquire_evidence<R: GmailHistoryFeed + ?Sized, L: CommandLabelReader + ?Sized>(
    feed: &R,
    labels: &L,
    snapshot: &CommandSnapshot,
    report: &mut CommandDriveReport,
) -> Result<CommandEvidence, CommandCoordinatorError> {
    let command = snapshot.command();
    let evidence = match command.kind() {
        MailboxCommandKind::CreateLabel(_) => {
            report.label_reads += 1;
            CommandEvidence::CreateCatalog(labels.read_label_catalog(command.account_id()).await?)
        }
        MailboxCommandKind::RenameLabel { label, .. } | MailboxCommandKind::DeleteLabel(label) => {
            report.label_reads += 1;
            let observed = labels.read_user_label(label).await?;
            if observed.target() != label {
                return Err(ContractError::WrongTarget.into());
            }
            CommandEvidence::UserLabel(observed)
        }
        MailboxCommandKind::MessageState { .. } | MailboxCommandKind::Compensate(_) => {
            let CommandProgress::Messages(items) = snapshot.progress() else {
                return Err(ContractError::Coverage.into());
            };
            let targets = MessageTargets::new(
                command.account_id().clone(),
                items.iter().map(|i| i.key().message_id().clone()).collect(),
            )
            .map_err(|_e| ContractError::Coverage)?;
            let mut observations = Vec::with_capacity(items.len());
            for item in items {
                report.message_reads += 1;
                let observed = feed.observe_message(item.key()).await?;
                if observed.key() != item.key() {
                    return Err(ContractError::WrongTarget.into());
                }
                observations.push(observed);
            }
            let user_label = if let Some(label) = required_user_label(command) {
                report.label_reads += 1;
                let observed = labels.read_user_label(label).await?;
                if observed.target() != label {
                    return Err(ContractError::WrongTarget.into());
                }
                Some(observed)
            } else {
                None
            };
            CommandEvidence::Messages {
                observations: MessageObservations::new(targets, observations)?,
                user_label,
            }
        }
    };
    // Delegate shape/account/coverage truth tables to the existing constructor.
    CommandReconciliation::new(snapshot.clone(), evidence.clone())?;
    Ok(evidence)
}

fn select_targets(
    reconciliation: &CommandReconciliation,
) -> Result<Option<MessageTargets>, ContractError> {
    let snapshot = reconciliation.snapshot();
    let CommandEvidence::Messages { observations, .. } = reconciliation.evidence() else {
        return Ok(None);
    };
    let CommandProgress::Messages(progress) = snapshot.progress() else {
        return Err(ContractError::Coverage);
    };
    let mut selected = Vec::new();
    for (item, observed) in progress.iter().zip(observations.observations()) {
        if item.outcome().is_some() {
            continue;
        }
        let desired = match snapshot.command().kind() {
            MailboxCommandKind::MessageState { desired, .. } => desired,
            MailboxCommandKind::Compensate(batch) => batch
                .items()
                .iter()
                .find(|c| c.message_id() == item.key().message_id())
                .ok_or(ContractError::Coverage)?
                .condition()
                .restore_state(),
            _ => return Err(ContractError::Coverage),
        };
        if let RemoteMessageState::Known(labels) = observed.state()
            && !desired.is_observed_in(&ObservedMembership::Observed(labels.clone()))
        {
            selected.push(item.key().message_id().clone());
        }
    }
    if selected.is_empty() {
        return Ok(None);
    }
    MessageTargets::new(snapshot.command().account_id().clone(), selected)
        .map(Some)
        .map_err(|_e| ContractError::Coverage)
}

#[cfg(test)]
mod tests;
