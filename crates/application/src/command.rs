// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Defines closed command transport and semantic durable-queue transaction contracts.
//!
//! Values validate identity, coverage and closed states, not actual SQL commits
//! or live authority. Store-produced revisions are CAS evidence, not credential
//! generations. Every transaction must recheck actual identity/capability, FIFO,
//! pins and persisted state; no defaults emulate transactions with separate writes.
//! Rehydrate touched states/User IDs through the domain constructors, never a
//! fabricated full membership or label name. No queue/retry coordinator lives here.

use crate::{
    mailbox::{AccountId, BoxFuture},
    mailbox_state::{
        ContractError, MessageKey, MessageObservations, MetadataReadError, TriageStoreError,
    },
    profile::AccountFence,
};
use std::fmt;
use tersa_domain::{
    command::{
        CommandItemOutcome, CompensationBatch, MailboxCommand, MailboxCommandId,
        MailboxCommandKind, MailboxCommandStatus, MailboxField, MessageTargets,
    },
    label::{LabelCatalog, LabelDefinition, UserLabel},
    mailbox::MessageId,
};

/// Maximum nonterminal commands per account, including label-only commands.
pub const MAX_PENDING_COMMANDS: usize = 32;
/// Maximum total nonterminal message-target references per account.
pub const MAX_PENDING_TARGET_REFERENCES: usize = 4_096;
/// Maximum retained terminal aggregate summaries, separate from the one undo candidate.
pub const MAX_TERMINAL_SUMMARIES: usize = 128;
/// Maximum automatic dispatch attempts including the initial attempt; explicit Retry never resets this.
pub const MAX_AUTOMATIC_ATTEMPTS: u8 = 3;

/// Identifies one command within exactly one account.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandKey {
    account: AccountId,
    command: MailboxCommandId,
}
impl CommandKey {
    /// Binds a local command identity to its owning account.
    #[must_use]
    pub fn new(account: AccountId, command: MailboxCommandId) -> Self {
        Self { account, command }
    }
    /// Returns the owning account.
    #[must_use]
    pub fn account_id(&self) -> &AccountId {
        &self.account
    }
    /// Returns the account-local command ID.
    #[must_use]
    pub fn command_id(&self) -> &MailboxCommandId {
        &self.command
    }
}
/// Identifies an exact durable command revision, not a process-local credential generation.
#[derive(Clone, Eq, PartialEq)]
pub struct CommandStamp {
    key: CommandKey,
    revision: u64,
}
impl CommandStamp {
    /// Rehydrates a store-issued row revision for exact compare-and-set operations.
    #[must_use]
    pub fn new(key: CommandKey, revision: u64) -> Self {
        Self { key, revision }
    }
    /// Returns the account-bound command identity.
    #[must_use]
    pub fn key(&self) -> &CommandKey {
        &self.key
    }
    /// Returns the persisted command revision, never a credential generation.
    #[must_use]
    pub fn revision(&self) -> u64 {
        self.revision
    }
}
impl fmt::Debug for CommandStamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CommandStamp([REDACTED])")
    }
}
/// Retains one item's durable resolved outcome or explicit pending state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandItemProgress {
    key: MessageKey,
    outcome: Option<CommandItemOutcome>,
}
impl CommandItemProgress {
    /// Rehydrates item state from trusted storage, not from an acknowledgement/count.
    #[must_use]
    pub fn new(key: MessageKey, outcome: Option<CommandItemOutcome>) -> Self {
        Self { key, outcome }
    }
    /// Returns account and message identity for this item.
    #[must_use]
    pub fn key(&self) -> &MessageKey {
        &self.key
    }
    /// Returns terminal item evidence or None when still pending.
    #[must_use]
    pub fn outcome(&self) -> Option<CommandItemOutcome> {
        self.outcome
    }
}
/// Separates label-definition reconciliation from per-message membership outcomes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LabelItemProgress {
    /// Definition outcome is not yet proven.
    Pending,
    /// Known ID/name or absence evidence proved the definition operation.
    Complete,
    /// A known terminal definition failure, not uncertainty.
    Failed,
}
/// Carries per-message durable state or one label-definition outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandProgress {
    /// Exact one-per-target item coverage, validated by `CommandSnapshot`.
    Messages(Vec<CommandItemProgress>),
    /// One definition outcome; label CRUD consumes no message-target quota.
    Label(LabelItemProgress),
}
/// Contains bounded aggregate counts, never sufficient evidence for settlement by itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommandCounts {
    total: u16,
    satisfied: u16,
    missing: u16,
    failed: u16,
}
impl CommandCounts {
    /// Rehydrates bounded terminal summary counts, never item settlement evidence.
    ///
    /// # Errors
    /// Rejects zero/over-1,000 total items or resolved counts exceeding total.
    pub fn from_retained(
        total: u16,
        satisfied: u16,
        missing: u16,
        failed: u16,
    ) -> Result<Self, ContractError> {
        if total == 0
            || usize::from(total) > MessageTargets::MAX_TARGETS
            || u32::from(satisfied) + u32::from(missing) + u32::from(failed) > u32::from(total)
        {
            return Err(ContractError::Coverage);
        }
        Ok(Self {
            total,
            satisfied,
            missing,
            failed,
        })
    }
    /// Returns logical items, counting a label definition as one.
    #[must_use]
    pub fn total(self) -> u16 {
        self.total
    }
    /// Returns resolved desired-state observations.
    #[must_use]
    pub fn satisfied(self) -> u16 {
        self.satisfied
    }
    /// Returns terminal observed target absences.
    #[must_use]
    pub fn target_missing(self) -> u16 {
        self.missing
    }
    /// Returns known terminal failures other than missing targets.
    #[must_use]
    pub fn failed(self) -> u16 {
        self.failed
    }
    /// Returns unresolved items, never silently counted as success.
    #[must_use]
    pub fn pending(self) -> u16 {
        self.total - self.satisfied - self.missing - self.failed
    }
}
/// Holds a structurally validated retained command and its actual durable revision/state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandSnapshot {
    command: MailboxCommand,
    stamp: CommandStamp,
    status: MailboxCommandStatus,
    automatic_attempts: u8,
    progress: CommandProgress,
    counts: CommandCounts,
    retry_authorization: Option<RetryAuthorization>,
}
impl CommandSnapshot {
    /// Validates command identity, bounded attempts, complete item coverage and terminal semantics.
    ///
    /// # Errors
    /// Rejects wrong stamp/account/target coverage, excessive attempts, Queued
    /// with prior automatic attempts, and Complete/Partial with unresolved or
    /// inconsistent outcomes. Trusted storage supplies actual outcomes/revision.
    pub fn new(
        command: MailboxCommand,
        stamp: CommandStamp,
        status: MailboxCommandStatus,
        automatic_attempts: u8,
        mut progress: CommandProgress,
        retry_authorization: Option<RetryAuthorization>,
    ) -> Result<Self, ContractError> {
        if command.account_id() != stamp.key.account_id() {
            return Err(ContractError::WrongAccount);
        }
        if command.id() != stamp.key.command_id() {
            return Err(ContractError::WrongTarget);
        }
        if retry_authorization.as_ref().is_some_and(|ticket| {
            ticket.stamp() != &stamp
                || !matches!(
                    status,
                    MailboxCommandStatus::Ambiguous | MailboxCommandStatus::NeedsAttention
                )
        }) {
            return Err(ContractError::State);
        }
        if let MailboxCommandKind::Compensate(batch) = command.kind() {
            let first = batch.items()[0].condition().expected_post_state();
            if batch
                .items()
                .iter()
                .any(|item| !same_touched_mask(item.condition().expected_post_state(), first))
            {
                return Err(ContractError::Coverage);
            }
        }
        if automatic_attempts > MAX_AUTOMATIC_ATTEMPTS
            || (status == MailboxCommandStatus::Queued && automatic_attempts != 0)
        {
            return Err(ContractError::State);
        }
        let expected = command_message_ids(&command);
        let counts = match &mut progress {
            CommandProgress::Messages(items) if !expected.is_empty() => {
                if items.len() != expected.len() {
                    return Err(ContractError::Coverage);
                }
                items.sort_unstable_by(|a, b| {
                    a.key.message_id().as_str().cmp(b.key.message_id().as_str())
                });
                if items
                    .iter()
                    .any(|i| i.key.account_id() != command.account_id())
                {
                    return Err(ContractError::WrongAccount);
                }
                if !items.iter().map(|i| i.key.message_id()).eq(expected) {
                    return Err(ContractError::Coverage);
                }
                let mut counts = CommandCounts {
                    total: u16::try_from(items.len()).map_err(|_e| ContractError::TooMany)?,
                    satisfied: 0,
                    missing: 0,
                    failed: 0,
                };
                for item in items {
                    match item.outcome {
                        Some(CommandItemOutcome::DesiredStateObserved) => counts.satisfied += 1,
                        Some(CommandItemOutcome::TargetMissing) => counts.missing += 1,
                        Some(CommandItemOutcome::Failed) => counts.failed += 1,
                        None => {}
                    }
                }
                counts
            }
            CommandProgress::Label(label) if expected.is_empty() => CommandCounts {
                total: 1,
                satisfied: u16::from(*label == LabelItemProgress::Complete),
                missing: 0,
                failed: u16::from(*label == LabelItemProgress::Failed),
            },
            _ => return Err(ContractError::Coverage),
        };
        if !status.is_terminal() && counts.pending() == 0 {
            return Err(ContractError::State);
        }
        if (status == MailboxCommandStatus::Complete
            && (counts.pending() != 0 || counts.satisfied != counts.total))
            || (status == MailboxCommandStatus::Partial
                && (counts.pending() != 0 || counts.missing + counts.failed == 0))
        {
            return Err(ContractError::State);
        }
        Ok(Self {
            command,
            stamp,
            status,
            automatic_attempts,
            progress,
            counts,
            retry_authorization,
        })
    }
    /// Returns immutable intent, not proof of current Modify authority.
    #[must_use]
    pub fn command(&self) -> &MailboxCommand {
        &self.command
    }
    /// Returns exact revision evidence for any transaction.
    #[must_use]
    pub fn stamp(&self) -> &CommandStamp {
        &self.stamp
    }
    /// Returns the closed aggregate state.
    #[must_use]
    pub fn status(&self) -> MailboxCommandStatus {
        self.status
    }
    /// Returns total automatic attempts already consumed, never reset by Retry.
    #[must_use]
    pub fn automatic_attempts(&self) -> u8 {
        self.automatic_attempts
    }
    /// Returns actual per-item/definition state for restart reconciliation.
    #[must_use]
    pub fn progress(&self) -> &CommandProgress {
        &self.progress
    }
    /// Returns validated aggregate counts, separate from item evidence.
    #[must_use]
    pub fn counts(&self) -> CommandCounts {
        self.counts
    }
    /// Returns a persisted unused explicit-Retry authorization for restart recovery.
    #[must_use]
    pub fn retry_authorization(&self) -> Option<&RetryAuthorization> {
        self.retry_authorization.as_ref()
    }
}
fn command_message_ids(command: &MailboxCommand) -> Vec<&MessageId> {
    match command.kind() {
        MailboxCommandKind::MessageState { targets, .. } => targets.ids().iter().collect(),
        MailboxCommandKind::Compensate(batch) => batch
            .items()
            .iter()
            .map(tersa_domain::command::MessageCompensation::message_id)
            .collect(),
        _ => Vec::new(),
    }
}
fn same_touched_mask(
    a: &tersa_domain::command::DesiredMailboxState,
    b: &tersa_domain::command::DesiredMailboxState,
) -> bool {
    a.account_id() == b.account_id()
        && a.memberships()
            .iter()
            .map(tersa_domain::command::DesiredMembership::field)
            .eq(b
                .memberships()
                .iter()
                .map(tersa_domain::command::DesiredMembership::field))
}

/// Represents fresh known-ID verification of a previously classified User label.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserLabelObservation {
    target: UserLabel,
    definition: Option<LabelDefinition>,
}
impl UserLabelObservation {
    /// Validates a same-account, same-ID User definition, or exact known-ID absence.
    ///
    /// # Errors
    /// Rejects foreign accounts, mismatched IDs or a System definition. None must
    /// mean an actual target read established absence, never a failed catalog/read.
    pub fn new(
        target: UserLabel,
        definition: Option<LabelDefinition>,
    ) -> Result<Self, ContractError> {
        if let Some(value) = &definition {
            if value.account_id() != target.account_id() {
                return Err(ContractError::WrongAccount);
            }
            if value.id() != target.id() {
                return Err(ContractError::WrongTarget);
            }
            if value.user_label().is_err() {
                return Err(ContractError::State);
            }
        }
        Ok(Self { target, definition })
    }
    /// Returns the exact account-bound known User ID that was requested.
    #[must_use]
    pub fn target(&self) -> &UserLabel {
        &self.target
    }
    /// Returns a freshly observed definition or explicit known-ID absence.
    #[must_use]
    pub fn definition(&self) -> Option<&LabelDefinition> {
        self.definition.as_ref()
    }
}
/// Keeps exact catalog name matches distinct, without permission to recreate a label.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LabelCreateMatches {
    /// No exact User-name match in a complete bounded catalog; no automatic recreate.
    Zero,
    /// One exact observed User ID may be adopted.
    One(UserLabel),
    /// More than one exact User-name match; never create another.
    Multiple,
}
/// Supplies actual full observations for message commands or label-definition commands.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandEvidence {
    /// Whole message set and, when required, fresh verification of the touched User ID.
    Messages {
        /// Exactly one complete known/missing observation per command target.
        observations: MessageObservations,
        /// The exact touched User-label definition, when the command needs one.
        user_label: Option<UserLabelObservation>,
    },
    /// A full bounded catalog, never a partial list or guessed name match count.
    CreateCatalog(LabelCatalog),
    /// A known User-label ID read for rename/delete.
    UserLabel(UserLabelObservation),
}
/// Binds fresh reconciliation evidence to one nonterminal durable command revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandReconciliation {
    snapshot: CommandSnapshot,
    evidence: CommandEvidence,
}
impl CommandReconciliation {
    /// Validates exact account, target and required-label coverage without settling anything.
    ///
    /// # Errors
    /// Rejects terminal commands, mismatched evidence shapes/accounts/IDs, partial
    /// message coverage and absent/extraneous User-label verification.
    pub fn new(
        snapshot: CommandSnapshot,
        evidence: CommandEvidence,
    ) -> Result<Self, ContractError> {
        if snapshot.status.is_terminal() {
            return Err(ContractError::State);
        }
        let command = snapshot.command();
        match (command.kind(), &evidence) {
            (MailboxCommandKind::CreateLabel(_), CommandEvidence::CreateCatalog(catalog)) => {
                if catalog.account_id() != command.account_id() {
                    return Err(ContractError::WrongAccount);
                }
            }
            (
                MailboxCommandKind::RenameLabel { label, .. }
                | MailboxCommandKind::DeleteLabel(label),
                CommandEvidence::UserLabel(observed),
            ) => {
                if observed.target() != label {
                    return Err(ContractError::WrongTarget);
                }
            }
            (
                MailboxCommandKind::MessageState { .. } | MailboxCommandKind::Compensate(_),
                CommandEvidence::Messages {
                    observations,
                    user_label,
                },
            ) => {
                if observations.targets().account_id() != command.account_id() {
                    return Err(ContractError::WrongAccount);
                }
                if !observations
                    .targets()
                    .ids()
                    .iter()
                    .eq(command_message_ids(command))
                {
                    return Err(ContractError::Coverage);
                }
                let required = required_user_label(command);
                if user_label.as_ref().map(UserLabelObservation::target) != required {
                    return Err(ContractError::Coverage);
                }
            }
            _ => return Err(ContractError::Coverage),
        }
        Ok(Self { snapshot, evidence })
    }
    /// Returns the exact durable revision that this evidence was acquired to reconcile.
    #[must_use]
    pub fn snapshot(&self) -> &CommandSnapshot {
        &self.snapshot
    }
    /// Returns complete provider evidence, never cached Unknown values.
    #[must_use]
    pub fn evidence(&self) -> &CommandEvidence {
        &self.evidence
    }
    /// Reports zero/one/multiple exact User matches only from a complete create catalog.
    #[must_use]
    pub fn create_matches(&self) -> Option<LabelCreateMatches> {
        let (MailboxCommandKind::CreateLabel(name), CommandEvidence::CreateCatalog(catalog)) =
            (self.snapshot.command.kind(), &self.evidence)
        else {
            return None;
        };
        let mut matching = catalog
            .definitions()
            .iter()
            .filter(|d| d.name() == name)
            .filter_map(|d| d.user_label().ok());
        Some(match (matching.next(), matching.next()) {
            (None, _) => LabelCreateMatches::Zero,
            (Some(one), None) => LabelCreateMatches::One(one),
            (Some(_), Some(_)) => LabelCreateMatches::Multiple,
        })
    }
}
fn required_user_label(command: &MailboxCommand) -> Option<&UserLabel> {
    let desired = match command.kind() {
        MailboxCommandKind::MessageState { desired, .. } => desired,
        MailboxCommandKind::Compensate(batch) => {
            batch.items().first()?.condition().expected_post_state()
        }
        _ => return None,
    };
    desired.memberships().iter().find_map(|m| {
        if let MailboxField::UserLabel(label) = m.field() {
            Some(label)
        } else {
            None
        }
    })
}

/// Captures fresh admission separately from replay lookup and offline undo admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandAdmission {
    fence: AccountFence,
    command: MailboxCommand,
}
impl CommandAdmission {
    /// Validates account-local fresh intent, excluding compensation's separate admission gate.
    ///
    /// # Errors
    /// Rejects a foreign account or compensation bypassing undo admission. The
    /// caller must generate a fresh ID for a new user intent, never replay an expired ID.
    pub fn new(fence: AccountFence, command: MailboxCommand) -> Result<Self, ContractError> {
        if fence.account_id() != command.account_id() {
            return Err(ContractError::WrongAccount);
        }
        if matches!(command.kind(), MailboxCommandKind::Compensate(_)) {
            return Err(ContractError::State);
        }
        Ok(Self { fence, command })
    }
    /// Returns the existing-account identity precondition.
    #[must_use]
    pub fn fence(&self) -> &AccountFence {
        &self.fence
    }
    /// Returns the full immutable bounded intent for atomic admission.
    #[must_use]
    pub fn command(&self) -> &MailboxCommand {
        &self.command
    }
}
/// Represents the one last-Complete message command's conditional compensation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UndoCandidate {
    source: CommandStamp,
    compensation: CompensationBatch,
}
impl UndoCandidate {
    /// Rehydrates the retained message-only undo record without fabricating compacted item rows.
    ///
    /// # Errors
    /// Rejects non-Complete/non-message source summaries, foreign accounts,
    /// wrong target counts or differing expected-post patches. Trusted storage
    /// supplies the retained source/targets and actual touched pre-state.
    pub fn from_retained(
        source: &TerminalCommandSummary,
        compensation: CompensationBatch,
    ) -> Result<Self, ContractError> {
        if source.status != MailboxCommandStatus::Complete
            || source.category == CommandCategory::LabelDefinition
        {
            return Err(ContractError::State);
        }
        if source.stamp.key.account_id() != compensation.account_id() {
            return Err(ContractError::WrongAccount);
        }
        if usize::from(source.counts.total) != compensation.items().len()
            || compensation.items().iter().any(|item| {
                !same_touched_mask(
                    item.condition().expected_post_state(),
                    compensation.items()[0].condition().expected_post_state(),
                )
            })
        {
            return Err(ContractError::Coverage);
        }
        Ok(Self {
            source: source.stamp.clone(),
            compensation,
        })
    }
    /// Validates Complete message-only ancestry and exact expected-post/target coverage.
    ///
    /// # Errors
    /// Rejects label CRUD, non-Complete source, foreign accounts, changed targets
    /// or post-state mismatch. Trusted storage must supply recorded actual pre-state.
    pub fn new(
        source: &CommandSnapshot,
        compensation: CompensationBatch,
    ) -> Result<Self, ContractError> {
        if source.status != MailboxCommandStatus::Complete {
            return Err(ContractError::State);
        }
        if compensation.account_id() != source.command.account_id() {
            return Err(ContractError::WrongAccount);
        }
        if !compensation
            .items()
            .iter()
            .map(tersa_domain::command::MessageCompensation::message_id)
            .eq(command_message_ids(source.command()))
        {
            return Err(ContractError::Coverage);
        }
        for item in compensation.items() {
            let expected = match source.command.kind() {
                MailboxCommandKind::MessageState { desired, .. } => desired,
                MailboxCommandKind::Compensate(batch) => batch
                    .items()
                    .iter()
                    .find(|old| old.message_id() == item.message_id())
                    .ok_or(ContractError::Coverage)?
                    .condition()
                    .restore_state(),
                _ => return Err(ContractError::State),
            };
            if item.condition().expected_post_state() != expected {
                return Err(ContractError::Coverage);
            }
        }
        Self::from_retained(
            &TerminalCommandSummary::from_snapshot(source)?,
            compensation,
        )
    }
    /// Returns the exact source command/revision whose undo slot is retained.
    #[must_use]
    pub fn source(&self) -> &CommandStamp {
        &self.source
    }
    /// Returns per-target touched pre-state and expected post-state, without observations fabricated.
    #[must_use]
    pub fn compensation(&self) -> &CompensationBatch {
        &self.compensation
    }
}
/// Requests offline conditional compensation through the separate undo admission gate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UndoAdmission {
    fence: AccountFence,
    candidate: UndoCandidate,
    command: MailboxCommand,
}
impl UndoAdmission {
    /// Binds a fresh command to the retained conditional compensation and owning identity.
    ///
    /// # Errors
    /// Rejects foreign accounts or reusing the source command ID. This claims no
    /// current undo eligibility, provider write or successful whole-set comparison.
    pub fn new(
        fence: AccountFence,
        candidate: UndoCandidate,
        command: MailboxCommand,
    ) -> Result<Self, ContractError> {
        if fence.account_id() != candidate.source.key.account_id()
            || command.account_id() != fence.account_id()
        {
            return Err(ContractError::WrongAccount);
        }
        if command.id() == candidate.source.key.command_id()
            || !matches!(command.kind(), MailboxCommandKind::Compensate(batch) if batch == &candidate.compensation)
        {
            return Err(ContractError::State);
        }
        Ok(Self {
            fence,
            candidate,
            command,
        })
    }
    /// Returns the account identity precondition.
    #[must_use]
    pub fn fence(&self) -> &AccountFence {
        &self.fence
    }
    /// Returns the exact retained undo candidate to compare atomically.
    #[must_use]
    pub fn candidate(&self) -> &UndoCandidate {
        &self.candidate
    }
    /// Returns Queued compensation intent, not a live eligibility claim.
    #[must_use]
    pub fn command(&self) -> &MailboxCommand {
        &self.command
    }
}
/// Binds a semantic mutation to exact command revision and actual account identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandPrecondition {
    fence: AccountFence,
    stamp: CommandStamp,
}
impl CommandPrecondition {
    /// Validates account agreement for a compare-and-set transition.
    ///
    /// # Errors
    /// Rejects a command belonging to another account.
    pub fn new(fence: AccountFence, stamp: CommandStamp) -> Result<Self, ContractError> {
        if fence.account_id() != stamp.key.account_id() {
            return Err(ContractError::WrongAccount);
        }
        Ok(Self { fence, stamp })
    }
    /// Returns the actual-identity comparison input.
    #[must_use]
    pub fn fence(&self) -> &AccountFence {
        &self.fence
    }
    /// Returns the exact expected command revision.
    #[must_use]
    pub fn stamp(&self) -> &CommandStamp {
        &self.stamp
    }
}
/// Identifies one durable explicit-Retry authorization, consumed once by dispatch preparation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetryAuthorization(CommandStamp);
impl RetryAuthorization {
    /// Rehydrates the revision returned by atomic retry authorization, not a new permission.
    #[must_use]
    pub fn from_store(stamp: CommandStamp) -> Self {
        Self(stamp)
    }
    /// Returns the revision whose persisted unused authorization must be consumed atomically.
    #[must_use]
    pub fn stamp(&self) -> &CommandStamp {
        &self.0
    }
}
/// Distinguishes automatic budget from a single explicit retry permission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DispatchAuthorization {
    /// Initial or guarded automatic idempotent attempt within the three-attempt budget.
    Automatic,
    /// One authorized retry, never a reset of the automatic attempt counter.
    Explicit(RetryAuthorization),
}
/// Records explicit acknowledgement of possible duplicate-label creation risk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DuplicateRiskConfirmation {
    /// No duplicate-risk confirmation was supplied.
    NotConfirmed,
    /// The user explicitly accepted possible duplicate-label creation for one retry.
    Confirmed,
}
/// Records explicit acknowledgement that abandoning may leave provider changes applied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AbandonConfirmation {
    /// The user acknowledged possible prior provider application and stopped recovery.
    ProviderMayAlreadyHaveApplied,
}
/// Describes a fresh reconciliation stop, without pretending an unread target is absent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconciliationFailure {
    /// A fresh provider read could not be completed.
    ReadUnavailable,
    /// The returned metadata was incomplete, invalid or over-limit.
    InvalidEvidence,
    /// Fresh compensation expected-post/target/label preconditions failed as a whole.
    CompensationRefused,
}

/// Requests guarded durable Dispatching/pre-state before any HTTP mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DispatchPreparation {
    precondition: CommandPrecondition,
    reconciliation: CommandReconciliation,
    targets: Option<MessageTargets>,
    authorization: DispatchAuthorization,
    duplicate_risk: DuplicateRiskConfirmation,
}
impl DispatchPreparation {
    /// Validates identity, exact revision, selected unsettled subset and explicit ticket binding.
    ///
    /// # Errors
    /// Rejects mismatched preconditions/tickets, empty/foreign/extraneous/settled
    /// selected targets, or message/label selection shape mismatch. Full fresh
    /// evidence is retained even when only an unmet subset will be dispatched.
    pub fn new(
        precondition: CommandPrecondition,
        reconciliation: CommandReconciliation,
        targets: Option<MessageTargets>,
        authorization: DispatchAuthorization,
        duplicate_risk: DuplicateRiskConfirmation,
    ) -> Result<Self, ContractError> {
        if precondition.stamp != reconciliation.snapshot.stamp {
            return Err(ContractError::State);
        }
        if matches!(&authorization, DispatchAuthorization::Explicit(ticket) if ticket.stamp() != &precondition.stamp || reconciliation.snapshot.retry_authorization() != Some(ticket))
        {
            return Err(ContractError::State);
        }
        validate_selection(&reconciliation.snapshot, targets.as_ref())?;
        Ok(Self {
            precondition,
            reconciliation,
            targets,
            authorization,
            duplicate_risk,
        })
    }
    /// Returns identity and exact revision to compare inside the transaction.
    #[must_use]
    pub fn precondition(&self) -> &CommandPrecondition {
        &self.precondition
    }
    /// Returns whole-set fresh provider evidence for all guards and touched pre-state.
    #[must_use]
    pub fn reconciliation(&self) -> &CommandReconciliation {
        &self.reconciliation
    }
    /// Returns the selected unsettled message subset, or None for definition CRUD.
    #[must_use]
    pub fn targets(&self) -> Option<&MessageTargets> {
        self.targets.as_ref()
    }
    /// Returns automatic or single-use explicit retry authorization.
    #[must_use]
    pub fn authorization(&self) -> &DispatchAuthorization {
        &self.authorization
    }
    /// Returns explicit duplicate-risk confirmation, never inferred from catalog absence.
    #[must_use]
    pub fn duplicate_risk(&self) -> DuplicateRiskConfirmation {
        self.duplicate_risk
    }
}
fn validate_selection(
    snapshot: &CommandSnapshot,
    targets: Option<&MessageTargets>,
) -> Result<(), ContractError> {
    match (&snapshot.progress, targets) {
        (CommandProgress::Label(_), None) => Ok(()),
        (CommandProgress::Messages(items), Some(targets)) => {
            if targets.account_id() != snapshot.command.account_id() {
                return Err(ContractError::WrongAccount);
            }
            if targets.ids().iter().any(|id| {
                !items
                    .iter()
                    .any(|item| item.key.message_id() == id && item.outcome.is_none())
            }) {
                return Err(ContractError::Coverage);
            }
            Ok(())
        }
        _ => Err(ContractError::Coverage),
    }
}
/// Carries store-produced durable pre-dispatch state to the closed remote port.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DispatchReceipt {
    snapshot: CommandSnapshot,
    targets: Option<MessageTargets>,
}
impl DispatchReceipt {
    /// Rehydrates a trusted committed Dispatching receipt, never emulating persistence.
    ///
    /// # Errors
    /// Rejects non-Dispatching state and invalid/settled target selection. The
    /// producer must have atomically persisted pre-state, guards and budget/ticket
    /// consumption first; constructing a receipt alone proves none of those writes.
    pub fn from_committed(
        snapshot: CommandSnapshot,
        targets: Option<MessageTargets>,
    ) -> Result<Self, ContractError> {
        if snapshot.status != MailboxCommandStatus::Dispatching {
            return Err(ContractError::State);
        }
        validate_selection(&snapshot, targets.as_ref())?;
        Ok(Self { snapshot, targets })
    }
    /// Returns the durable dispatch command/revision, including the closed operation.
    #[must_use]
    pub fn snapshot(&self) -> &CommandSnapshot {
        &self.snapshot
    }
    /// Returns only selected unsettled targets; adapters must not redispatch the rest.
    #[must_use]
    pub fn targets(&self) -> Option<&MessageTargets> {
        self.targets.as_ref()
    }
}
/// Records a provider acknowledgement, never command completion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WriteAcknowledgement {
    /// Successful batchModify with an empty success body is a valid acknowledgement.
    MessageBatchAccepted,
    /// A create response supplied this validated observed User definition.
    LabelCreated(LabelDefinition),
    /// Name-only PATCH or definition DELETE was acknowledged.
    LabelDefinitionAccepted,
}
/// Reports a known provider rejection, without an arbitrary body or identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandRejection {
    /// The provider rejected current authorization.
    AuthorizationRequired,
    /// The provider rejected the request due to rate limits.
    RateLimited,
    /// The provider definitively rejected the attempted operation.
    Rejected,
}
/// Distinguishes acknowledgement, possible application and known provider rejection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DispatchFact {
    /// Provider acknowledgement still requires per-item/definition reconciliation.
    Acknowledged(WriteAcknowledgement),
    /// Timeout/drop/malformed response after possible dispatch; never atomic batch failure.
    Ambiguous,
    /// A known provider rejection, not a fabricated successful empty response.
    Rejected(CommandRejection),
}
/// Binds a remote outcome to exactly the store's durable dispatch receipt revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteCommandOutcome {
    stamp: CommandStamp,
    fact: DispatchFact,
}
impl RemoteCommandOutcome {
    /// Validates acknowledgement shape and returned create identity/name against the command.
    ///
    /// # Errors
    /// Rejects mismatched acknowledgement kinds, foreign create definitions, a
    /// non-User definition or an unexpected exact name. Such post-dispatch parse
    /// failures must be reported as Ambiguous, never as proof of no application.
    pub fn new(receipt: &DispatchReceipt, fact: DispatchFact) -> Result<Self, ContractError> {
        if let DispatchFact::Acknowledged(ack) = &fact {
            match (receipt.snapshot.command.kind(), ack) {
                (
                    MailboxCommandKind::MessageState { .. } | MailboxCommandKind::Compensate(_),
                    WriteAcknowledgement::MessageBatchAccepted,
                )
                | (
                    MailboxCommandKind::RenameLabel { .. } | MailboxCommandKind::DeleteLabel(_),
                    WriteAcknowledgement::LabelDefinitionAccepted,
                ) => {}
                (
                    MailboxCommandKind::CreateLabel(name),
                    WriteAcknowledgement::LabelCreated(label),
                ) => {
                    if label.account_id() != receipt.snapshot.command.account_id() {
                        return Err(ContractError::WrongAccount);
                    }
                    if label.name() != name || label.user_label().is_err() {
                        return Err(ContractError::State);
                    }
                }
                _ => return Err(ContractError::State),
            }
        }
        Ok(Self {
            stamp: receipt.snapshot.stamp.clone(),
            fact,
        })
    }
    /// Returns the exact durable dispatch identity and revision.
    #[must_use]
    pub fn stamp(&self) -> &CommandStamp {
        &self.stamp
    }
    /// Returns a transport fact, never a Complete/Partial aggregate status.
    #[must_use]
    pub fn fact(&self) -> &DispatchFact {
        &self.fact
    }
}
/// Reports a pre-dispatch denial with no mailbox mutation attempted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandDispatchError {
    /// Persisted/current-session Modify authorization is unavailable.
    AuthorizationRequired,
    /// The account/session/generation or closed request is invalid.
    InvalidRequest,
}
impl fmt::Display for CommandDispatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("mailbox command dispatch was denied")
    }
}
impl std::error::Error for CommandDispatchError {}

/// Extends reads with a separate, account-bound, allowlisted Modify component.
///
/// No generic endpoint/system-label mutation is available. Actual transport must
/// verify account/current accepted Modify session and runtime generation. Once
/// HTTP might have applied a write, failures become Ambiguous facts, never a
/// readonly retry helper or a pre-dispatch Err. Dropping a dispatched future
/// leaves durable Dispatching for recovery as Ambiguous; do not spawn retries.
pub trait RemoteMailboxCommands: Send + Sync {
    /// Sends exactly the closed command and selected targets in a durable receipt.
    ///
    /// # Errors
    /// Resolves to a closed failure without provider or backend data; no partial success.
    fn dispatch<'a>(
        &'a self,
        receipt: &'a DispatchReceipt,
    ) -> BoxFuture<'a, Result<RemoteCommandOutcome, CommandDispatchError>>;
    /// Reads a complete bounded catalog; overflow is failure, never partial success.
    ///
    /// # Errors
    /// Resolves to a closed failure without provider or backend data; no partial success.
    fn label_catalog<'a>(
        &'a self,
        account: &'a AccountId,
    ) -> BoxFuture<'a, Result<LabelCatalog, MetadataReadError>>;
    /// Freshly verifies one known User definition by exact account and immutable ID.
    ///
    /// # Errors
    /// Resolves to a closed failure without provider or backend data; no partial success.
    fn observe_user_label<'a>(
        &'a self,
        target: &'a UserLabel,
    ) -> BoxFuture<'a, Result<UserLabelObservation, MetadataReadError>>;
}

/// Retains command family without raw intent or compacted item rows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandCategory {
    /// Original message-state action, potentially eligible for the one undo slot.
    MessageState,
    /// Conditional message-state compensation, separate from label-definition CRUD.
    Compensation,
    /// Label create/rename/delete; cannot replace the message undo slot.
    LabelDefinition,
}
impl CommandCategory {
    fn of(command: &MailboxCommand) -> Self {
        match command.kind() {
            MailboxCommandKind::MessageState { .. } => Self::MessageState,
            MailboxCommandKind::Compensate(_) => Self::Compensation,
            _ => Self::LabelDefinition,
        }
    }
}

/// Retains a terminal aggregate without expanding it back into active command state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminalCommandSummary {
    stamp: CommandStamp,
    status: MailboxCommandStatus,
    counts: CommandCounts,
    category: CommandCategory,
}
impl TerminalCommandSummary {
    /// Rehydrates a compacted terminal summary, without reconstructing deleted item rows.
    ///
    /// # Errors
    /// Rejects nonterminal states, inconsistent Complete/Partial counts and label
    /// summaries with message-style cardinality/`TargetMissing` outcomes. Counts
    /// remain informational; this constructor never grants settlement authority.
    pub fn from_retained(
        stamp: CommandStamp,
        status: MailboxCommandStatus,
        counts: CommandCounts,
        category: CommandCategory,
    ) -> Result<Self, ContractError> {
        if !status.is_terminal()
            || (status == MailboxCommandStatus::Complete && counts.satisfied != counts.total)
            || (status == MailboxCommandStatus::Partial
                && (counts.pending() != 0 || counts.missing + counts.failed == 0))
            || (category == CommandCategory::LabelDefinition
                && (counts.total != 1 || counts.missing != 0))
        {
            return Err(ContractError::State);
        }
        Ok(Self {
            stamp,
            status,
            counts,
            category,
        })
    }
    /// Validates terminal disposition from a structurally consistent retained snapshot.
    ///
    /// # Errors
    /// Rejects every nonterminal state; Abandoned remains terminal uncertainty, not success.
    pub fn from_snapshot(snapshot: &CommandSnapshot) -> Result<Self, ContractError> {
        Self::from_retained(
            snapshot.stamp.clone(),
            snapshot.status,
            snapshot.counts,
            CommandCategory::of(snapshot.command()),
        )
    }
    /// Returns the retained account/command revision identity.
    #[must_use]
    pub fn stamp(&self) -> &CommandStamp {
        &self.stamp
    }
    /// Returns terminal success, failure, cancellation or abandonment.
    #[must_use]
    pub fn status(&self) -> MailboxCommandStatus {
        self.status
    }
    /// Returns bounded retained aggregate counts.
    #[must_use]
    pub fn counts(&self) -> CommandCounts {
        self.counts
    }
    /// Returns the retained family used to reject label-CRUD undo ancestry.
    #[must_use]
    pub fn category(&self) -> CommandCategory {
        self.category
    }
}
/// Holds bounded same-account terminal summaries, separate from the one undo record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminalSummaries {
    account: AccountId,
    summaries: Vec<TerminalCommandSummary>,
}
impl TerminalSummaries {
    /// Validates the retention boundary and unique same-account command identities.
    ///
    /// # Errors
    /// Rejects more than 128 summaries, foreign accounts and duplicate command IDs.
    pub fn new(
        account: AccountId,
        summaries: Vec<TerminalCommandSummary>,
    ) -> Result<Self, ContractError> {
        if summaries.len() > MAX_TERMINAL_SUMMARIES {
            return Err(ContractError::TooMany);
        }
        let mut ids = std::collections::HashSet::new();
        for summary in &summaries {
            if summary.stamp.key.account_id() != &account {
                return Err(ContractError::WrongAccount);
            }
            if !ids.insert(summary.stamp.key.command_id()) {
                return Err(ContractError::Duplicate);
            }
        }
        Ok(Self { account, summaries })
    }
    /// Returns the owning account.
    #[must_use]
    pub fn account_id(&self) -> &AccountId {
        &self.account
    }
    /// Returns bounded terminal summaries in store retention order.
    #[must_use]
    pub fn summaries(&self) -> &[TerminalCommandSummary] {
        &self.summaries
    }
}
/// Distinguishes new durable admission from replay of an already retained ID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandAdmissionOutcome {
    /// New intent was atomically persisted Queued, with quotas and pins reserved.
    Admitted(Box<CommandSnapshot>),
    /// The retained ID already exists; return saved state without enqueue or dispatch.
    Retained(RetainedCommand),
}

/// Supports saved-status replay after terminal item rows have been compacted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RetainedCommand {
    /// Full retained state remains available while item rows exist; terminal state stays terminal.
    Full(Box<CommandSnapshot>),
    /// Terminal summary needs no fabricated full command/items to rehydrate.
    Terminal(TerminalCommandSummary),
}

/// Owns atomic command lifecycle operations, with no generic status setter or default writes.
///
/// Every mutator validates actual stored account identity, expected revision/state
/// and account single-flight/FIFO guards in its transaction. Admission and dispatch
/// additionally require persisted Modify. Local cancellation, observation settlement
/// and warned abandonment remain available without a usable provider grant.
/// Revision changes invalidate old evidence/tickets. Runtime
/// separately checks process-local credential generation; it is not a schema field.
/// Every successful semantic mutation advances the command revision without
/// wrap/reuse, including observation updates and retry/dispatch/terminal changes.
/// Carry any still-unused retry permission into the new snapshot's ticket while
/// invalidating its old revision; dispatch consumes that permission atomically.
/// Never evict nonterminal evidence to meet quotas, and never derive success from
/// counts, snapshot omission or acknowledgement. Terminal outcomes cannot reopen.
pub trait MailboxCommandStore: Send + Sync {
    /// Atomically admits fresh intent as Queued, checking 32 commands/4,096 target references.
    ///
    /// Retained IDs replay saved status without mutations. Unknown/expired REPLAY
    /// lookups must never call admission; only genuinely fresh new user intent does.
    /// Reserve full targets/desired state and pins together; label CRUD uses a slot.
    ///
    /// # Errors
    /// Resolves to a closed failure without provider or backend data; no partial success.
    fn admit<'a>(
        &'a self,
        request: &'a CommandAdmission,
    ) -> BoxFuture<'a, Result<CommandAdmissionOutcome, TriageStoreError>>;
    /// Atomically admits conditional undo only if its retained Complete source is current.
    ///
    /// Refuse pre-existing nonterminal commands only HERE, plus ordinary quotas.
    /// Persist expected-post/actual-pre touched fields as Queued without claiming
    /// online eligibility. Do not reapply the admission-only gate during dispatch.
    ///
    /// # Errors
    /// Resolves to a closed failure without provider or backend data; no partial success.
    fn admit_undo<'a>(
        &'a self,
        request: &'a UndoAdmission,
    ) -> BoxFuture<'a, Result<CommandAdmissionOutcome, TriageStoreError>>;
    /// Reads retained saved status only; None means unknown/expired, never permission to enqueue.
    ///
    /// # Errors
    /// Resolves to a closed failure without provider or backend data; no partial success.
    fn lookup<'a>(
        &'a self,
        fence: &'a AccountFence,
        key: &'a CommandKey,
    ) -> BoxFuture<'a, Result<Option<RetainedCommand>, TriageStoreError>>;
    /// Reads the oldest nonterminal command with complete item coverage for FIFO/restart work.
    ///
    /// No target/account may change during rehydration. An unresolved oldest possible
    /// dispatch blocks later writes, while reads remain available.
    ///
    /// # Errors
    /// Resolves to a closed failure without provider or backend data; no partial success.
    fn oldest_pending<'a>(
        &'a self,
        fence: &'a AccountFence,
    ) -> BoxFuture<'a, Result<Option<CommandSnapshot>, TriageStoreError>>;
    /// Atomically changes interrupted Dispatching to Ambiguous without advancing the queue.
    ///
    /// # Errors
    /// Resolves to a closed failure without provider or backend data; no partial success.
    fn recover_dispatching<'a>(
        &'a self,
        expected: &'a CommandPrecondition,
    ) -> BoxFuture<'a, Result<CommandSnapshot, TriageStoreError>>;
    /// Atomically persists Dispatching, touched pre-state, attempt/ticket use before HTTP.
    ///
    /// Require the oldest eligible revision, fresh unmet evidence for selected
    /// unsettled targets and required known User IDs. Automatic attempts total at
    /// most three; never automatically recreate a previously dispatched create.
    /// Explicit Retry must consume one persisted unused ticket, without resetting
    /// automatic budget. A create retry needs fresh Zero matches plus explicit
    /// duplicate-risk confirmation; One settles/adopts, Multiple never dispatches.
    /// Before first compensation dispatch, freshly validate the WHOLE target set,
    /// required labels and touched expected post-state; any missing/mismatch refuses
    /// ALL writes. Persist that guarded disposition for ordinary ambiguity recovery.
    /// Later queued work and the undo itself do not trigger the admission-only gate.
    ///
    /// # Errors
    /// Resolves to a closed failure without provider or backend data; no partial success.
    fn prepare_dispatch<'a>(
        &'a self,
        request: &'a DispatchPreparation,
    ) -> BoxFuture<'a, Result<DispatchReceipt, TriageStoreError>>;
    /// Atomically records only the matching current dispatch revision's transport fact.
    ///
    /// Acknowledgement never completes a command. Possible application remains
    /// nonterminal until reconciliation; stale results cannot overwrite newer state.
    ///
    /// # Errors
    /// Resolves to a closed failure without provider or backend data; no partial success.
    fn record_dispatch<'a>(
        &'a self,
        expected: &'a CommandPrecondition,
        outcome: &'a RemoteCommandOutcome,
    ) -> BoxFuture<'a, Result<CommandSnapshot, TriageStoreError>>;
    /// Atomically records observations and derives item outcomes against stored desired fields.
    ///
    /// Same-account exact-message Known evidence must match ALL touched fields for
    /// success; Missing is terminal `TargetMissing`. Settled items never redispatch.
    /// Complete requires every item successful; Partial requires every item resolved
    /// and at least one known failure, including zero successes/all `TargetMissing`.
    /// Label create adopts exactly One catalog match, rename verifies known ID/name,
    /// delete verifies known-ID absence. Unknown/failed reads cannot settle anything.
    /// Terminal commit releases FIFO/quota/pins, retains at most 128 summaries and
    /// replaces the one undo slot ONLY for eligible Complete message-state commands.
    ///
    /// # Errors
    /// Resolves to a closed failure without provider or backend data; no partial success.
    fn reconcile<'a>(
        &'a self,
        expected: &'a CommandPrecondition,
        observations: &'a CommandReconciliation,
    ) -> BoxFuture<'a, Result<CommandSnapshot, TriageStoreError>>;
    /// Atomically cancels Queued only, before any mutation attempt, retaining terminal disposition.
    ///
    /// # Errors
    /// Resolves to a closed failure without provider or backend data; no partial success.
    fn cancel_queued<'a>(
        &'a self,
        expected: &'a CommandPrecondition,
    ) -> BoxFuture<'a, Result<TerminalCommandSummary, TriageStoreError>>;
    /// Atomically issues one new-revision unused ticket for Ambiguous/`NeedsAttention` only.
    ///
    /// This permits fresh reconciliation, not immediate dispatch. Failed reads leave
    /// `NeedsAttention` without provider mutation; consumed/stale tickets cannot be replayed.
    ///
    /// # Errors
    /// Resolves to a closed failure without provider or backend data; no partial success.
    fn authorize_retry<'a>(
        &'a self,
        expected: &'a CommandPrecondition,
    ) -> BoxFuture<'a, Result<RetryAuthorization, TriageStoreError>>;
    /// Atomically retains `NeedsAttention` after failed fresh reconciliation, without mailbox writes.
    /// Invalidate the old revision and any unused retry ticket; preserve possible-dispatch
    /// evidence, pins, quota and the unchanged automatic-attempt counter.
    ///
    /// # Errors
    /// Resolves to a closed failure without provider or backend data; no partial success.
    fn reconciliation_failed<'a>(
        &'a self,
        expected: &'a CommandPrecondition,
        failure: ReconciliationFailure,
    ) -> BoxFuture<'a, Result<CommandSnapshot, TriageStoreError>>;
    /// Atomically commits warned Abandoned summary before releasing FIFO, pins and quota.
    ///
    /// This claims neither success nor rollback. Retained abandoned IDs can never
    /// retry/requeue; preserve bounded evidence even when no item succeeded.
    ///
    /// # Errors
    /// Resolves to a closed failure without provider or backend data; no partial success.
    fn abandon<'a>(
        &'a self,
        expected: &'a CommandPrecondition,
        confirmation: AbandonConfirmation,
    ) -> BoxFuture<'a, Result<TerminalCommandSummary, TriageStoreError>>;
    /// Reads the one retained undo slot without claiming current offline/online eligibility.
    ///
    /// # Errors
    /// Resolves to a closed failure without provider or backend data; no partial success.
    fn undo_candidate<'a>(
        &'a self,
        fence: &'a AccountFence,
    ) -> BoxFuture<'a, Result<Option<UndoCandidate>, TriageStoreError>>;
    /// Reads bounded terminal summaries without provisioning an unknown account.
    ///
    /// # Errors
    /// Resolves to a closed failure without provider or backend data; no partial success.
    fn terminal_summaries<'a>(
        &'a self,
        fence: &'a AccountFence,
    ) -> BoxFuture<'a, Result<TerminalSummaries, TriageStoreError>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        identity::IdentityHash,
        mailbox_state::{MessageObservation, RemoteMessageState},
    };
    use tersa_domain::{
        account::AccountCapability,
        command::{
            ConditionalCompensation, DesiredMailboxState, MessageAction, MessageCompensation,
        },
        label::{LabelId, LabelKind, LabelMembership, LabelName},
    };
    fn account(value: &str) -> AccountId {
        AccountId::new(value).expect("account")
    }
    fn id(value: &str) -> MessageId {
        MessageId::new(value).expect("message")
    }
    fn key(owner: &str, value: &str) -> MessageKey {
        MessageKey::new(account(owner), id(value))
    }
    fn targets(values: &[&str]) -> MessageTargets {
        MessageTargets::new(account("owner"), values.iter().map(|v| id(v)).collect())
            .expect("targets")
    }
    fn fence() -> AccountFence {
        AccountFence::new(account("owner"), IdentityHash::from_bytes([7; 32]))
    }
    fn stamp(revision: u64) -> CommandStamp {
        CommandStamp::new(
            CommandKey::new(
                account("owner"),
                MailboxCommandId::new("cmd-sentinel").expect("command"),
            ),
            revision,
        )
    }
    fn command(action: &MessageAction) -> MailboxCommand {
        MailboxCommand::message_state(
            AccountCapability::Modify,
            MailboxCommandId::new("cmd-sentinel").expect("command"),
            targets(&["a", "b"]),
            action,
        )
        .expect("command")
    }
    fn item(value: &str, outcome: Option<CommandItemOutcome>) -> CommandItemProgress {
        CommandItemProgress::new(key("owner", value), outcome)
    }
    fn snapshot(
        status: MailboxCommandStatus,
        revision: u64,
        outcomes: [Option<CommandItemOutcome>; 2],
        retry: bool,
    ) -> CommandSnapshot {
        CommandSnapshot::new(
            command(&MessageAction::Read),
            stamp(revision),
            status,
            1,
            CommandProgress::Messages(vec![item("a", outcomes[0]), item("b", outcomes[1])]),
            retry.then(|| RetryAuthorization::from_store(stamp(revision))),
        )
        .expect("snapshot")
    }
    fn observations(values: &[&str]) -> MessageObservations {
        MessageObservations::new(
            targets(values),
            values
                .iter()
                .map(|value| {
                    MessageObservation::new(
                        key("owner", value),
                        RemoteMessageState::Known(
                            LabelMembership::new(
                                account("owner"),
                                vec![LabelId::new("UNREAD").expect("label")],
                            )
                            .expect("full membership"),
                        ),
                    )
                    .expect("observation")
                })
                .collect(),
        )
        .expect("covered observations")
    }
    fn label(value: &str, name: &str, kind: LabelKind) -> LabelDefinition {
        LabelDefinition::new(
            account("owner"),
            LabelId::new(value).expect("label ID"),
            LabelName::new(name).expect("name"),
            kind,
        )
        .expect("definition")
    }

    // Contract: aggregate Partial includes all TargetMissing/zero successes; unresolved is not terminal.
    // Regression: counts or a partial item list manufacture terminal completion.
    #[test]
    fn retained_progress_and_compacted_summary_preserve_terminal_failure_semantics() {
        let partial = CommandSnapshot::new(
            command(&MessageAction::Read),
            stamp(7),
            MailboxCommandStatus::Partial,
            1,
            CommandProgress::Messages(vec![
                item("b", Some(CommandItemOutcome::TargetMissing)),
                item("a", Some(CommandItemOutcome::TargetMissing)),
            ]),
            None,
        )
        .expect("all resolved failures");
        assert_eq!(partial.counts().satisfied(), 0);
        assert_eq!(partial.counts().target_missing(), 2);
        assert_eq!(partial.counts().pending(), 0);
        let CommandProgress::Messages(items) = partial.progress() else {
            panic!("message progress");
        };
        assert_eq!(
            items
                .iter()
                .map(|i| i.key().message_id().as_str())
                .collect::<Vec<_>>(),
            ["a", "b"]
        );
        for (status, outcomes) in [
            (
                MailboxCommandStatus::Complete,
                [
                    Some(CommandItemOutcome::TargetMissing),
                    Some(CommandItemOutcome::TargetMissing),
                ],
            ),
            (
                MailboxCommandStatus::Partial,
                [Some(CommandItemOutcome::TargetMissing), None],
            ),
        ] {
            assert_eq!(
                CommandSnapshot::new(
                    command(&MessageAction::Read),
                    stamp(7),
                    status,
                    1,
                    CommandProgress::Messages(vec![item("a", outcomes[0]), item("b", outcomes[1])]),
                    None
                ),
                Err(ContractError::State)
            );
        }
        let summary = TerminalCommandSummary::from_retained(
            stamp(7),
            MailboxCommandStatus::Partial,
            CommandCounts::from_retained(2, 0, 2, 0).expect("retained counts"),
            CommandCategory::MessageState,
        )
        .expect("no fabricated item rows");
        assert_eq!(summary.counts().target_missing(), 2);
        assert_eq!(summary.status(), MailboxCommandStatus::Partial);
        assert_eq!(summary.stamp().revision(), 7);
        assert!(!format!("{partial:?} {summary:?}").contains("cmd-sentinel"));
        let foreign = CommandItemProgress::new(key("other", "a"), None);
        assert_eq!(
            CommandSnapshot::new(
                command(&MessageAction::Read),
                stamp(7),
                MailboxCommandStatus::Ambiguous,
                1,
                CommandProgress::Messages(vec![foreign, item("b", None)]),
                None
            ),
            Err(ContractError::WrongAccount)
        );
    }

    // Contract: fresh whole-set evidence, unsettled selection and tickets bind exact revisions.
    // Regression: settled targets resend, stale Retry evidence dispatches, or acknowledgement completes.
    #[test]
    fn dispatch_values_require_exact_coverage_revision_and_unsettled_selection() {
        let current = snapshot(
            MailboxCommandStatus::Ambiguous,
            7,
            [Some(CommandItemOutcome::DesiredStateObserved), None],
            true,
        );
        let incomplete = CommandEvidence::Messages {
            observations: observations(&["a"]),
            user_label: None,
        };
        assert_eq!(
            CommandReconciliation::new(current.clone(), incomplete),
            Err(ContractError::Coverage)
        );
        let reconciled = CommandReconciliation::new(
            current,
            CommandEvidence::Messages {
                observations: observations(&["a", "b"]),
                user_label: None,
            },
        )
        .expect("whole-set evidence");
        let pre = CommandPrecondition::new(fence(), stamp(7)).expect("CAS precondition");
        let ticket = DispatchAuthorization::Explicit(RetryAuthorization::from_store(stamp(7)));
        assert!(
            DispatchPreparation::new(
                pre.clone(),
                reconciled.clone(),
                Some(targets(&["b"])),
                ticket.clone(),
                DuplicateRiskConfirmation::NotConfirmed
            )
            .is_ok()
        );
        assert_eq!(
            DispatchPreparation::new(
                pre.clone(),
                reconciled.clone(),
                Some(targets(&["a"])),
                ticket,
                DuplicateRiskConfirmation::NotConfirmed
            ),
            Err(ContractError::Coverage)
        );
        assert_eq!(
            DispatchPreparation::new(
                pre,
                reconciled,
                Some(targets(&["b"])),
                DispatchAuthorization::Explicit(RetryAuthorization::from_store(stamp(6))),
                DuplicateRiskConfirmation::NotConfirmed
            ),
            Err(ContractError::State)
        );
        let dispatched = snapshot(
            MailboxCommandStatus::Dispatching,
            8,
            [Some(CommandItemOutcome::DesiredStateObserved), None],
            false,
        );
        let receipt = DispatchReceipt::from_committed(dispatched, Some(targets(&["b"])))
            .expect("trusted producer receipt");
        let ack = RemoteCommandOutcome::new(
            &receipt,
            DispatchFact::Acknowledged(WriteAcknowledgement::MessageBatchAccepted),
        )
        .expect("empty success acknowledgement");
        assert_eq!(ack.stamp().revision(), 8);
        assert_eq!(
            ack.fact(),
            &DispatchFact::Acknowledged(WriteAcknowledgement::MessageBatchAccepted)
        );
        assert_eq!(
            RemoteCommandOutcome::new(
                &receipt,
                DispatchFact::Acknowledged(WriteAcknowledgement::LabelDefinitionAccepted)
            ),
            Err(ContractError::State)
        );
        assert_eq!(
            RemoteCommandOutcome::new(&receipt, DispatchFact::Ambiguous)
                .expect("possible dispatch")
                .fact(),
            &DispatchFact::Ambiguous
        );
    }

    // Contract: create adopts only one exact User-name match; known-ID verification cannot swap labels.
    // Regression: system/name guessing, catalog overflow substitution or mismatched known IDs.
    #[test]
    fn create_matching_and_known_label_observations_keep_provider_identity() {
        let name = "exact-name-sentinel";
        let create = MailboxCommand::create_label(
            AccountCapability::Modify,
            MailboxCommandId::new("cmd-sentinel").expect("command"),
            account("owner"),
            LabelName::new(name).expect("name"),
        )
        .expect("create");
        for (labels, expected) in [
            (vec![label("INBOX", name, LabelKind::System)], 0),
            (
                vec![
                    label("Label_a", name, LabelKind::User),
                    label("Label_other", "other", LabelKind::User),
                ],
                1,
            ),
            (
                vec![
                    label("Label_a", name, LabelKind::User),
                    label("Label_b", name, LabelKind::User),
                ],
                2,
            ),
        ] {
            let current = CommandSnapshot::new(
                create.clone(),
                stamp(4),
                MailboxCommandStatus::Ambiguous,
                1,
                CommandProgress::Label(LabelItemProgress::Pending),
                None,
            )
            .expect("create state");
            let recon = CommandReconciliation::new(
                current,
                CommandEvidence::CreateCatalog(
                    LabelCatalog::new(account("owner"), labels).expect("complete catalog"),
                ),
            )
            .expect("catalog evidence");
            match (recon.create_matches().expect("create evidence"), expected) {
                (LabelCreateMatches::Zero, 0) | (LabelCreateMatches::Multiple, 2) => {}
                (LabelCreateMatches::One(target), 1) => assert_eq!(target.id().as_str(), "Label_a"),
                _ => panic!("incorrect exact User match classification"),
            }
        }
        let target =
            UserLabel::from_classified_id(account("owner"), LabelId::new("Label_a").expect("ID"))
                .expect("trusted classification");
        assert_eq!(
            UserLabelObservation::new(
                target.clone(),
                Some(label("Label_b", name, LabelKind::User))
            ),
            Err(ContractError::WrongTarget)
        );
        assert!(
            UserLabelObservation::new(target, None)
                .expect("exact known-ID absence")
                .definition()
                .is_none()
        );
    }

    // Contract: retained touched fields reconstruct offline undo without provider observations or names.
    // Regression: compacted state requires fabricated membership, label CRUD undo or ordinary admission bypass.
    #[test]
    fn offline_undo_rehydrates_from_touched_state_and_uses_its_separate_gate() {
        use tersa_domain::command::MailboxField::{Inbox, Trash};
        let post = DesiredMailboxState::from_touched_fields(
            account("owner"),
            vec![(Trash, true), (Inbox, false)],
        )
        .expect("stored post-state");
        let batch = CompensationBatch::new(
            account("owner"),
            [("a", false), ("b", true)]
                .into_iter()
                .map(|(message, inbox)| {
                    let pre = DesiredMailboxState::from_touched_fields(
                        account("owner"),
                        vec![(Trash, false), (Inbox, inbox)],
                    )
                    .expect("stored actual touched pre-state");
                    MessageCompensation::new(
                        id(message),
                        ConditionalCompensation::new(post.clone(), pre).expect("same footprint"),
                    )
                })
                .collect(),
        )
        .expect("retained per-target compensation");
        let summary = TerminalCommandSummary::from_retained(
            stamp(12),
            MailboxCommandStatus::Complete,
            CommandCounts::from_retained(2, 2, 0, 0).expect("counts"),
            CommandCategory::MessageState,
        )
        .expect("compacted source");
        let candidate =
            UndoCandidate::from_retained(&summary, batch.clone()).expect("retained undo record");
        assert_eq!(candidate.source().revision(), 12);
        assert!(
            !candidate.compensation().items()[0]
                .condition()
                .restore_state()
                .memberships()
                .iter()
                .find(|m| m.field() == &Inbox)
                .expect("Inbox field")
                .is_present()
        );
        assert!(
            candidate.compensation().items()[1]
                .condition()
                .restore_state()
                .memberships()
                .iter()
                .find(|m| m.field() == &Inbox)
                .expect("Inbox field")
                .is_present()
        );
        let undo = MailboxCommand::compensate(
            AccountCapability::Modify,
            MailboxCommandId::new("fresh-undo").expect("ID"),
            batch.clone(),
        )
        .expect("conditional command");
        assert_eq!(
            CommandAdmission::new(fence(), undo.clone()),
            Err(ContractError::State)
        );
        assert!(UndoAdmission::new(fence(), candidate, undo).is_ok());
        let label_source = TerminalCommandSummary::from_retained(
            stamp(12),
            MailboxCommandStatus::Complete,
            CommandCounts::from_retained(1, 1, 0, 0).expect("counts"),
            CommandCategory::LabelDefinition,
        )
        .expect("label summary");
        assert_eq!(
            UndoCandidate::from_retained(&label_source, batch.clone()),
            Err(ContractError::State)
        );
        let partial = TerminalCommandSummary::from_retained(
            stamp(12),
            MailboxCommandStatus::Partial,
            CommandCounts::from_retained(2, 0, 2, 0).expect("counts"),
            CommandCategory::MessageState,
        )
        .expect("Partial summary");
        assert_eq!(
            UndoCandidate::from_retained(&partial, batch),
            Err(ContractError::State)
        );
    }

    // Contract: terminal retention is bounded without evicting nonterminal evidence or inventing rows.
    // Regression: aggregate reload accepts overflow, duplicate identities or impossible terminal counts.
    #[test]
    fn compacted_terminal_values_enforce_bounds_and_closed_counts() {
        assert_eq!(
            CommandCounts::from_retained(2, 2, 1, 0),
            Err(ContractError::Coverage)
        );
        assert_eq!(
            TerminalCommandSummary::from_retained(
                stamp(1),
                MailboxCommandStatus::Complete,
                CommandCounts::from_retained(2, 1, 0, 0).expect("pending count"),
                CommandCategory::MessageState
            ),
            Err(ContractError::State)
        );
        let summaries: Vec<_> = (0..128)
            .map(|i| {
                TerminalCommandSummary::from_retained(
                    CommandStamp::new(
                        CommandKey::new(
                            account("owner"),
                            MailboxCommandId::new(format!("cmd-{i}")).expect("ID"),
                        ),
                        0,
                    ),
                    MailboxCommandStatus::Abandoned,
                    CommandCounts::from_retained(1, 0, 0, 0).expect("unresolved count"),
                    CommandCategory::LabelDefinition,
                )
                .expect("warned terminal uncertainty")
            })
            .collect();
        assert_eq!(
            TerminalSummaries::new(account("owner"), summaries.clone())
                .expect("bounded retention")
                .summaries()
                .len(),
            128
        );
        assert_eq!(
            TerminalSummaries::new(account("other"), summaries.clone()),
            Err(ContractError::WrongAccount)
        );
        assert_eq!(
            TerminalSummaries::new(
                account("owner"),
                vec![summaries[0].clone(), summaries[0].clone()]
            ),
            Err(ContractError::Duplicate)
        );
        let mut overflow = summaries;
        overflow.push(overflow[0].clone());
        assert_eq!(
            TerminalSummaries::new(account("owner"), overflow),
            Err(ContractError::TooMany)
        );
    }
}
