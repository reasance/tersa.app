// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Defines the closed account-local command set and conditional compensation values.
//!
//! Commands are pure intent, not admission, persistence, dispatch or success.
//! Desired patches contain only touched ADR 0027 memberships. Complete provider
//! observations can match them; Unknown and observations of another account
//! cannot. Compensation retains each target's actual touched pre-state and the
//! expected post-state, without asserting current eligibility or atomic rollback.
//! Application owns whole-set freshness, queue, replay, retry and undo policy.

use std::fmt;

use crate::{
    account::AccountCapability,
    label::{LabelMembership, LabelName, ObservedMembership, UserLabel, valid_segment},
    mailbox::{AccountId, MessageId},
};

/// Reports a rejected command value without retaining identifiers or message data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandError {
    /// The local command identifier violates its defensive format.
    InvalidId,
    /// A command requires at least one message target.
    EmptyTargets,
    /// The input exceeds the per-command target bound.
    TooManyTargets,
    /// A message ID occurs more than once.
    DuplicateTarget,
    /// A label, state or target collection belongs to another account.
    WrongAccount,
    /// A readonly capability cannot construct a write intent.
    ReadOnly,
    /// Compensation must restore exactly the same touched fields it guards.
    MismatchedCompensation,
    /// A touched field occurs more than once, even with different presence bits.
    DuplicateField,
    /// The touched fields are empty or not exactly one approved action footprint.
    InvalidFieldMask,
}
impl fmt::Display for CommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidId => "invalid local mailbox command identifier",
            Self::EmptyTargets => "mailbox command requires message targets",
            Self::TooManyTargets => "mailbox command exceeds its target bound",
            Self::DuplicateTarget => "duplicate mailbox command target",
            Self::WrongAccount => "mailbox command values belong to different accounts",
            Self::ReadOnly => "readonly capability cannot construct a mailbox write",
            Self::MismatchedCompensation => "compensation touched fields do not match",
            Self::DuplicateField => "duplicate touched mailbox field",
            Self::InvalidFieldMask => "invalid touched mailbox field mask",
        })
    }
}
impl std::error::Error for CommandError {}

/// Identifies a local command without generating randomness or assuming a UUID format.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct MailboxCommandId(String);
impl MailboxCommandId {
    /// Defensive byte limit consistent with existing opaque identifiers.
    pub const MAX_LEN: usize = 256;
    /// Validates a locally supplied opaque command ID without normalization.
    ///
    /// # Errors
    ///
    /// Rejects empty input, more than 256 bytes, or anything except ASCII
    /// letters, digits, `_` and `-`. Uniqueness/replay protection belongs to storage.
    pub fn new<T: Into<String>>(value: T) -> Result<Self, CommandError> {
        let value = value.into();
        if !valid_segment(&value, Self::MAX_LEN) {
            return Err(CommandError::InvalidId);
        }
        Ok(Self(value))
    }
    /// Returns the exact local ID for trusted persistence.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl fmt::Debug for MailboxCommandId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MailboxCommandId([REDACTED])")
    }
}

/// Holds a nonempty account-local set of distinct message IDs.
///
/// IDs are sorted by their exact bytes. Duplicate input is rejected rather
/// than deduplicated; equality is independent of input order. Existing
/// [`MessageId`] validation remains unchanged and is not decimal validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageTargets {
    account: AccountId,
    ids: Vec<MessageId>,
}
impl MessageTargets {
    /// Maximum message targets per command, per ADR 0027.
    pub const MAX_TARGETS: usize = 1_000;
    /// Validates a complete account-local target set without truncation.
    ///
    /// # Errors
    ///
    /// Rejects empty input, more than 1,000 IDs and duplicate IDs.
    pub fn new(account: AccountId, mut ids: Vec<MessageId>) -> Result<Self, CommandError> {
        validate_target_count(ids.len())?;
        ids.sort_unstable_by(|left, right| left.as_str().cmp(right.as_str()));
        if ids.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(CommandError::DuplicateTarget);
        }
        Ok(Self { account, ids })
    }
    /// Returns the one owning account for every target ID.
    #[must_use]
    pub fn account_id(&self) -> &AccountId {
        &self.account
    }
    /// Returns every target in canonical byte order.
    #[must_use]
    pub fn ids(&self) -> &[MessageId] {
        &self.ids
    }
}
fn validate_target_count(count: usize) -> Result<(), CommandError> {
    if count == 0 {
        return Err(CommandError::EmptyTargets);
    }
    if count > MessageTargets::MAX_TARGETS {
        return Err(CommandError::TooManyTargets);
    }
    Ok(())
}

/// Enumerates only approved message-state actions, excluding arbitrary system labels.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MessageAction {
    /// Remove UNREAD membership.
    Read,
    /// Add UNREAD membership.
    Unread,
    /// Add STARRED membership.
    Star,
    /// Remove STARRED membership.
    Unstar,
    /// Remove INBOX membership.
    Archive,
    /// Add TRASH and remove INBOX membership.
    Trash,
    /// Remove TRASH and add INBOX membership.
    Restore,
    /// Add SPAM and remove INBOX membership.
    Spam,
    /// Remove SPAM and add INBOX membership.
    ClearSpam,
    /// Add one validated account-bound User-label membership.
    ApplyLabel(UserLabel),
    /// Remove one validated account-bound User-label membership.
    RemoveLabel(UserLabel),
}

/// Identifies exactly one approved touched membership, never an arbitrary system label.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MailboxField {
    /// Provider unread membership, separate from legacy local-read state.
    Unread,
    /// Provider starred membership.
    Starred,
    /// Provider Inbox membership.
    Inbox,
    /// Provider Trash membership.
    Trash,
    /// Provider Spam membership.
    Spam,
    /// One validated User-label membership.
    UserLabel(UserLabel),
}
impl MailboxField {
    fn order_key(&self) -> u8 {
        match self {
            Self::Unread => 0,
            Self::Starred => 1,
            Self::Trash => 2,
            Self::Spam => 3,
            Self::Inbox => 4,
            Self::UserLabel(_) => 5,
        }
    }

    fn observed_in(&self, membership: &LabelMembership) -> bool {
        match self {
            Self::Unread => membership.contains_system("UNREAD"),
            Self::Starred => membership.contains_system("STARRED"),
            Self::Inbox => membership.contains_system("INBOX"),
            Self::Trash => membership.contains_system("TRASH"),
            Self::Spam => membership.contains_system("SPAM"),
            Self::UserLabel(label) => membership.contains(label.id()),
        }
    }
}

/// Holds the desired presence of one touched mailbox field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DesiredMembership {
    field: MailboxField,
    present: bool,
}
impl DesiredMembership {
    /// Returns the touched field.
    #[must_use]
    pub fn field(&self) -> &MailboxField {
        &self.field
    }
    /// Returns whether that membership must be present.
    #[must_use]
    pub fn is_present(&self) -> bool {
        self.present
    }
}

/// Holds only the touched fields of one approved action or its recorded inverse.
///
/// The nonempty ordered field list cannot be mutated. Reconstruction accepts
/// exactly one approved action footprint, with independent presence bits for
/// actual pre-state. [`Self::record_pre_state`] retains precisely that field mask.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DesiredMailboxState {
    account: AccountId,
    memberships: Vec<DesiredMembership>,
}
impl DesiredMailboxState {
    /// Reconstructs touched state without inventing a complete provider observation.
    ///
    /// Accepts exactly the footprints `{Unread}`, `{Starred}`, `{Inbox}`,
    /// `{Trash, Inbox}`, `{Spam, Inbox}`, or one account-bound User label.
    /// Presence bits remain independent so recorded pre-state need not equal a
    /// named action's post-state. Fields are ordered canonically as Unread,
    /// Starred, Trash, Spam, Inbox, User label; input order does not affect equality.
    /// Persisted values are not evidence of current provider state or freshness.
    ///
    /// # Errors
    ///
    /// Rejects empty or unapproved masks, duplicate fields regardless of presence,
    /// and any User label belonging to a different account.
    pub fn from_touched_fields(
        account: AccountId,
        mut fields: Vec<(MailboxField, bool)>,
    ) -> Result<Self, CommandError> {
        use MailboxField::{Inbox, Spam, Starred, Trash, Unread, UserLabel};
        if fields.is_empty() || fields.len() > 2 {
            return Err(CommandError::InvalidFieldMask);
        }
        if fields
            .iter()
            .any(|(field, _)| matches!(field, UserLabel(label) if label.account_id() != &account))
        {
            return Err(CommandError::WrongAccount);
        }
        fields.sort_unstable_by_key(|(field, _)| field.order_key());
        if fields.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(CommandError::DuplicateField);
        }
        if !matches!(
            fields.as_slice(),
            [(Unread | Starred | Inbox | UserLabel(_), _)] | [(Trash | Spam, _), (Inbox, _)]
        ) {
            return Err(CommandError::InvalidFieldMask);
        }
        Ok(Self {
            account,
            memberships: fields
                .into_iter()
                .map(|(field, present)| DesiredMembership { field, present })
                .collect(),
        })
    }

    /// Derives the exact ADR 0027 field map for an account-local action.
    ///
    /// # Errors
    ///
    /// Rejects a User label belonging to a different account.
    pub fn for_action(account: AccountId, action: &MessageAction) -> Result<Self, CommandError> {
        use MailboxField::{Inbox, Spam, Starred, Trash, Unread, UserLabel};
        let fields = match action {
            MessageAction::Read => vec![(Unread, false)],
            MessageAction::Unread => vec![(Unread, true)],
            MessageAction::Star => vec![(Starred, true)],
            MessageAction::Unstar => vec![(Starred, false)],
            MessageAction::Archive => vec![(Inbox, false)],
            MessageAction::Trash => vec![(Trash, true), (Inbox, false)],
            MessageAction::Restore => vec![(Trash, false), (Inbox, true)],
            MessageAction::Spam => vec![(Spam, true), (Inbox, false)],
            MessageAction::ClearSpam => vec![(Spam, false), (Inbox, true)],
            MessageAction::ApplyLabel(label) | MessageAction::RemoveLabel(label) => {
                vec![(
                    UserLabel(label.clone()),
                    matches!(action, MessageAction::ApplyLabel(_)),
                )]
            }
        };
        Self::from_touched_fields(account, fields)
    }
    /// Returns the account whose provider state is required.
    #[must_use]
    pub fn account_id(&self) -> &AccountId {
        &self.account
    }
    /// Returns only touched fields, in canonical order independent of construction.
    #[must_use]
    pub fn memberships(&self) -> &[DesiredMembership] {
        &self.memberships
    }
    /// Tests all touched fields against complete same-account provider membership.
    ///
    /// Unknown always returns false, including patches requiring absence only.
    /// This checks a supplied observation, not its freshness or message identity.
    #[must_use]
    pub fn is_observed_in(&self, observed: &ObservedMembership) -> bool {
        let ObservedMembership::Observed(membership) = observed else {
            return false;
        };
        membership.account_id() == &self.account
            && self
                .memberships
                .iter()
                .all(|change| change.field.observed_in(membership) == change.present)
    }
    /// Records actual pre-state for precisely these touched fields.
    ///
    /// Unknown or cross-account observations return `None`, never guessed values.
    /// The caller must bind this supplied observation to the correct message.
    #[must_use]
    pub fn record_pre_state(&self, observed: &ObservedMembership) -> Option<Self> {
        let ObservedMembership::Observed(membership) = observed else {
            return None;
        };
        if membership.account_id() != &self.account {
            return None;
        }
        Some(Self {
            account: self.account.clone(),
            memberships: self
                .memberships
                .iter()
                .map(|change| DesiredMembership {
                    field: change.field.clone(),
                    present: change.field.observed_in(membership),
                })
                .collect(),
        })
    }
}

/// Retains expected post-state and the actual touched pre-state to restore.
///
/// Constructing this value makes no eligibility or provider-write claim. Fresh
/// whole-target-set comparison belongs to the application before any dispatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConditionalCompensation {
    expected: DesiredMailboxState,
    restore: DesiredMailboxState,
}
impl ConditionalCompensation {
    /// Validates matching account and touched fields for conditional compensation.
    ///
    /// # Errors
    ///
    /// Rejects different accounts or different touched field masks.
    pub fn new(
        expected: DesiredMailboxState,
        restore: DesiredMailboxState,
    ) -> Result<Self, CommandError> {
        if expected.account != restore.account {
            return Err(CommandError::WrongAccount);
        }
        if !expected
            .memberships
            .iter()
            .map(|change| &change.field)
            .eq(restore.memberships.iter().map(|change| &change.field))
        {
            return Err(CommandError::MismatchedCompensation);
        }
        Ok(Self { expected, restore })
    }
    /// Returns the touched post-state required before compensation dispatch.
    #[must_use]
    pub fn expected_post_state(&self) -> &DesiredMailboxState {
        &self.expected
    }
    /// Returns the actual recorded touched pre-state to restore.
    #[must_use]
    pub fn restore_state(&self) -> &DesiredMailboxState {
        &self.restore
    }
}

/// Associates one target with its own conditional compensation evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageCompensation {
    message_id: MessageId,
    condition: ConditionalCompensation,
}
impl MessageCompensation {
    /// Associates a message with validated compensation values, without dispatching.
    #[must_use]
    pub fn new(message_id: MessageId, condition: ConditionalCompensation) -> Self {
        Self {
            message_id,
            condition,
        }
    }
    /// Returns the target message ID.
    #[must_use]
    pub fn message_id(&self) -> &MessageId {
        &self.message_id
    }
    /// Returns the expected and restorative touched state for this target.
    #[must_use]
    pub fn condition(&self) -> &ConditionalCompensation {
        &self.condition
    }
}

/// Holds nonempty, unique, same-account per-message compensation values.
///
/// Entries are sorted by message ID. Per-message pre-state may differ; no target
/// is collapsed or truncated. Application must verify the entire set freshly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompensationBatch {
    account: AccountId,
    items: Vec<MessageCompensation>,
}
impl CompensationBatch {
    /// Validates all compensation targets under the ordinary 1,000-target bound.
    ///
    /// # Errors
    ///
    /// Rejects empty/oversized input, cross-account evidence or duplicate targets.
    pub fn new(
        account: AccountId,
        mut items: Vec<MessageCompensation>,
    ) -> Result<Self, CommandError> {
        validate_target_count(items.len())?;
        if items
            .iter()
            .any(|item| item.condition.expected.account_id() != &account)
        {
            return Err(CommandError::WrongAccount);
        }
        items.sort_unstable_by(|left, right| {
            left.message_id.as_str().cmp(right.message_id.as_str())
        });
        if items
            .windows(2)
            .any(|pair| pair[0].message_id == pair[1].message_id)
        {
            return Err(CommandError::DuplicateTarget);
        }
        Ok(Self { account, items })
    }
    /// Returns the one owning account of the whole compensation.
    #[must_use]
    pub fn account_id(&self) -> &AccountId {
        &self.account
    }
    /// Returns every target and condition in canonical message-ID order.
    #[must_use]
    pub fn items(&self) -> &[MessageCompensation] {
        &self.items
    }
}

/// Describes a validated command's closed operation, excluding permanent message deletion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MailboxCommandKind {
    /// One approved message-state action over an account-local batch.
    MessageState {
        /// Complete bounded target set.
        targets: MessageTargets,
        /// Exact touched-field patch.
        desired: DesiredMailboxState,
    },
    /// Conditional restoration of recorded touched message state.
    Compensate(CompensationBatch),
    /// Create a User-label definition using only its name.
    CreateLabel(LabelName),
    /// Rename a known User-label definition using only its name.
    RenameLabel {
        /// Validated account-bound User label.
        label: UserLabel,
        /// Exact new provider name.
        name: LabelName,
    },
    /// Delete a User-label definition and assignments, never messages.
    DeleteLabel(UserLabel),
}

/// Holds validated, bounded, account-local write intent with a local replay identity.
///
/// Construction requires Modify but proves neither stored capability nor a
/// current access session. No mutation, queue admission or replay occurs here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MailboxCommand {
    id: MailboxCommandId,
    account: AccountId,
    kind: MailboxCommandKind,
}
impl MailboxCommand {
    /// Constructs one approved message action over all validated targets.
    ///
    /// # Errors
    ///
    /// Rejects `ReadOnly` capability and cross-account User labels.
    pub fn message_state(
        capability: AccountCapability,
        id: MailboxCommandId,
        targets: MessageTargets,
        action: &MessageAction,
    ) -> Result<Self, CommandError> {
        let account = targets.account_id().clone();
        let desired = DesiredMailboxState::for_action(account.clone(), action)?;
        Self::build(
            capability,
            id,
            account,
            MailboxCommandKind::MessageState { targets, desired },
        )
    }
    /// Constructs conditional compensation without claiming undo eligibility.
    ///
    /// # Errors
    ///
    /// Rejects `ReadOnly` capability.
    pub fn compensate(
        capability: AccountCapability,
        id: MailboxCommandId,
        batch: CompensationBatch,
    ) -> Result<Self, CommandError> {
        Self::build(
            capability,
            id,
            batch.account_id().clone(),
            MailboxCommandKind::Compensate(batch),
        )
    }
    /// Constructs name-only User-label creation intent for one account.
    ///
    /// # Errors
    ///
    /// Rejects `ReadOnly` capability. Provider name policy belongs to transport.
    pub fn create_label(
        capability: AccountCapability,
        id: MailboxCommandId,
        account: AccountId,
        name: LabelName,
    ) -> Result<Self, CommandError> {
        Self::build(
            capability,
            id,
            account,
            MailboxCommandKind::CreateLabel(name),
        )
    }
    /// Constructs name-only rename intent for a validated User label.
    ///
    /// # Errors
    ///
    /// Rejects `ReadOnly` capability. The label determines the owning account.
    pub fn rename_label(
        capability: AccountCapability,
        id: MailboxCommandId,
        label: UserLabel,
        name: LabelName,
    ) -> Result<Self, CommandError> {
        Self::build(
            capability,
            id,
            label.account_id().clone(),
            MailboxCommandKind::RenameLabel { label, name },
        )
    }
    /// Constructs User-label definition deletion, which never deletes messages.
    ///
    /// # Errors
    ///
    /// Rejects `ReadOnly` capability. The label determines the owning account.
    pub fn delete_label(
        capability: AccountCapability,
        id: MailboxCommandId,
        label: UserLabel,
    ) -> Result<Self, CommandError> {
        Self::build(
            capability,
            id,
            label.account_id().clone(),
            MailboxCommandKind::DeleteLabel(label),
        )
    }
    fn build(
        capability: AccountCapability,
        id: MailboxCommandId,
        account: AccountId,
        kind: MailboxCommandKind,
    ) -> Result<Self, CommandError> {
        if capability != AccountCapability::Modify {
            return Err(CommandError::ReadOnly);
        }
        Ok(Self { id, account, kind })
    }
    /// Returns the local command identity, without creating replay authority.
    #[must_use]
    pub fn id(&self) -> &MailboxCommandId {
        &self.id
    }
    /// Returns the command's sole owning account.
    #[must_use]
    pub fn account_id(&self) -> &AccountId {
        &self.account
    }
    /// Returns the validated closed operation.
    #[must_use]
    pub fn kind(&self) -> &MailboxCommandKind {
        &self.kind
    }
}

/// Distinguishes pending evidence from terminal command disposition, without transitions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MailboxCommandStatus {
    /// Durable intent; no mailbox mutation attempted.
    Queued,
    /// Durable pre-dispatch marker; interruption must be treated as ambiguous.
    Dispatching,
    /// Possible provider application remains unresolved and nonterminal.
    Ambiguous,
    /// Unresolved evidence requires attention and remains nonterminal.
    NeedsAttention,
    /// Terminal success after every touched target field was observed.
    Complete,
    /// Terminal aggregate with all items resolved and at least one known failure.
    Partial,
    /// Terminal cancellation before any mailbox mutation attempt.
    Cancelled,
    /// Terminal explicit disposition of uncertainty; never success or rollback.
    Abandoned,
}
impl MailboxCommandStatus {
    /// Reports terminal disposition, including terminal failures and abandonment.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Complete | Self::Partial | Self::Cancelled | Self::Abandoned
        )
    }
    /// Reports only terminal success; abandonment and partial results are not success.
    #[must_use]
    pub fn is_success(self) -> bool {
        self == Self::Complete
    }
}

/// Describes a resolved message item, separate from aggregate command status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandItemOutcome {
    /// All touched fields were observed in the desired state.
    DesiredStateObserved,
    /// The target was observed missing; terminal failure rather than success.
    TargetMissing,
    /// A known terminal item failure, without provider text.
    Failed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::label::{LabelDefinition, LabelId, LabelKind};

    fn account(value: &str) -> AccountId {
        AccountId::new(value).expect("valid synthetic value")
    }
    fn message(value: &str) -> MessageId {
        MessageId::new(value).expect("valid synthetic value")
    }
    fn command_id() -> MailboxCommandId {
        MailboxCommandId::new("command-sentinel").expect("valid synthetic value")
    }
    fn user(owner: &str) -> UserLabel {
        LabelDefinition::new(
            account(owner),
            LabelId::new("Label_sentinel").expect("valid synthetic value"),
            LabelName::new("name-sentinel").expect("valid synthetic value"),
            LabelKind::User,
        )
        .expect("valid synthetic value")
        .user_label()
        .expect("valid synthetic value")
    }
    fn observation(owner: &str, ids: &[&str]) -> ObservedMembership {
        ObservedMembership::Observed(
            LabelMembership::new(
                account(owner),
                ids.iter()
                    .map(|id| LabelId::new(*id).expect("valid synthetic value"))
                    .collect(),
            )
            .expect("valid synthetic value"),
        )
    }
    fn targets() -> MessageTargets {
        MessageTargets::new(
            account("account-sentinel"),
            vec![message("message-sentinel")],
        )
        .expect("valid synthetic value")
    }
    fn condition() -> ConditionalCompensation {
        let expected =
            DesiredMailboxState::for_action(account("account-sentinel"), &MessageAction::Trash)
                .expect("valid synthetic value");
        let restore = expected
            .record_pre_state(&observation("account-sentinel", &[]))
            .expect("valid synthetic value");
        ConditionalCompensation::new(expected, restore).expect("valid synthetic value")
    }

    // Contract: command identity validation and lossless canonical target bounds.
    // Regression: path-like IDs, duplicate collapsing or target truncation.
    #[test]
    fn local_identity_and_target_sets_reject_invalid_boundaries() {
        for invalid in ["", "a/b", "a.b", "a%20b", "a b", "é", "a\n"] {
            assert_eq!(MailboxCommandId::new(invalid), Err(CommandError::InvalidId));
        }
        assert_eq!(command_id().as_str(), "command-sentinel");
        assert!(MailboxCommandId::new("a".repeat(256)).is_ok());
        assert_eq!(
            MailboxCommandId::new("a".repeat(257)),
            Err(CommandError::InvalidId)
        );
        assert_eq!(
            MessageTargets::new(account("owner"), vec![]),
            Err(CommandError::EmptyTargets)
        );
        assert_eq!(
            MessageTargets::new(account("owner"), vec![message("a"), message("a")]),
            Err(CommandError::DuplicateTarget)
        );
        let ordered = MessageTargets::new(account("owner"), vec![message("a"), message("b")])
            .expect("valid synthetic value");
        assert_eq!(
            ordered
                .ids()
                .iter()
                .map(MessageId::as_str)
                .collect::<Vec<_>>(),
            ["a", "b"]
        );
        assert_eq!(
            ordered,
            MessageTargets::new(account("owner"), vec![message("b"), message("a")])
                .expect("valid synthetic value")
        );
        assert_ne!(
            ordered,
            MessageTargets::new(account("other"), vec![message("a"), message("b")])
                .expect("valid synthetic value")
        );
        let ids: Vec<_> = (0..1_000)
            .map(|i| message(&format!("message-{i}")))
            .collect();
        assert_eq!(
            MessageTargets::new(account("owner"), ids.clone())
                .expect("valid synthetic value")
                .ids()
                .len(),
            1_000
        );
        let mut overflow = ids;
        overflow.push(message("extra"));
        assert_eq!(
            MessageTargets::new(account("owner"), overflow),
            Err(CommandError::TooManyTargets)
        );
    }

    // Contract: exact ADR 0027 field masks and values, independently specified here.
    // Regression: touching unrelated fields, incorrect restore or spam semantics.
    #[test]
    fn approved_actions_have_exact_touched_field_maps() {
        use MailboxField::{Inbox, Spam, Starred, Trash, Unread, UserLabel};
        let label = user("owner");
        let cases = [
            (MessageAction::Read, vec![(Unread, false)]),
            (MessageAction::Unread, vec![(Unread, true)]),
            (MessageAction::Star, vec![(Starred, true)]),
            (MessageAction::Unstar, vec![(Starred, false)]),
            (MessageAction::Archive, vec![(Inbox, false)]),
            (MessageAction::Trash, vec![(Trash, true), (Inbox, false)]),
            (MessageAction::Restore, vec![(Trash, false), (Inbox, true)]),
            (MessageAction::Spam, vec![(Spam, true), (Inbox, false)]),
            (MessageAction::ClearSpam, vec![(Spam, false), (Inbox, true)]),
            (
                MessageAction::ApplyLabel(label.clone()),
                vec![(UserLabel(label.clone()), true)],
            ),
            (
                MessageAction::RemoveLabel(label.clone()),
                vec![(UserLabel(label), false)],
            ),
        ];
        for (action, expected) in cases {
            let patch = DesiredMailboxState::for_action(account("owner"), &action)
                .expect("valid synthetic value");
            let actual: Vec<_> = patch
                .memberships()
                .iter()
                .map(|change| (change.field().clone(), change.is_present()))
                .collect();
            assert_eq!(actual, expected);
            let mut persisted = expected;
            persisted.reverse();
            assert_eq!(
                DesiredMailboxState::from_touched_fields(account("owner"), persisted)
                    .expect("valid persisted action footprint"),
                patch
            );
        }
    }

    // Contract: persisted touched fields alone reconstruct guarded post/pre-state.
    // Regression: rehydration needs a fabricated full observation or label name.
    #[test]
    fn persisted_compensation_reconstructs_without_provider_observations() {
        use MailboxField::{Inbox, Trash, UserLabel};
        let expected = DesiredMailboxState::from_touched_fields(
            account("owner"),
            vec![(Inbox, false), (Trash, true)],
        )
        .expect("stored trash post-state");
        let fields = |state: &DesiredMailboxState| {
            state
                .memberships()
                .iter()
                .map(|change| (change.field().clone(), change.is_present()))
                .collect::<Vec<_>>()
        };
        for (persisted, canonical) in [
            (
                vec![(Inbox, false), (Trash, false)],
                vec![(Trash, false), (Inbox, false)],
            ),
            (
                vec![(Inbox, true), (Trash, false)],
                vec![(Trash, false), (Inbox, true)],
            ),
        ] {
            let restore = DesiredMailboxState::from_touched_fields(account("owner"), persisted)
                .expect("stored actual pre-state");
            let condition = ConditionalCompensation::new(expected.clone(), restore)
                .expect("matching stored touched masks");
            assert_eq!(
                fields(condition.expected_post_state()),
                [(Trash, true), (Inbox, false)]
            );
            assert_eq!(fields(condition.restore_state()), canonical);
        }

        let label = crate::label::UserLabel::from_classified_id(
            account("owner"),
            LabelId::new("Label_persisted").expect("stored label ID"),
        )
        .expect("trusted persisted User classification");
        let applied = DesiredMailboxState::from_touched_fields(
            account("owner"),
            vec![(UserLabel(label.clone()), true)],
        )
        .expect("stored apply-label field");
        let removed = DesiredMailboxState::from_touched_fields(
            account("owner"),
            vec![(UserLabel(label), false)],
        )
        .expect("stored absent-label pre-state");
        let condition = ConditionalCompensation::new(applied, removed)
            .expect("matching stored User-label masks");
        let change = &condition.expected_post_state().memberships()[0];
        let UserLabel(target) = change.field() else {
            panic!("expected stored User-label field");
        };
        assert_eq!(target.account_id().as_str(), "owner");
        assert_eq!(target.id().as_str(), "Label_persisted");
        assert!(change.is_present());
        assert!(!condition.restore_state().memberships()[0].is_present());
    }

    // Contract: rehydration cannot admit invalid masks, duplicates or foreign labels.
    // Regression: trusted storage bypasses the action footprint or account boundary.
    #[test]
    fn persisted_touched_fields_reject_invalid_masks_and_ownership() {
        use MailboxField::{Inbox, Spam, Starred, Trash, Unread, UserLabel};
        let foreign = crate::label::UserLabel::from_classified_id(
            account("other"),
            LabelId::new("Label_foreign").expect("stored label ID"),
        )
        .expect("trusted persisted User classification");
        for (fields, error) in [
            (vec![], CommandError::InvalidFieldMask),
            (
                vec![(Inbox, false), (Inbox, true)],
                CommandError::DuplicateField,
            ),
            (vec![(UserLabel(foreign), true)], CommandError::WrongAccount),
            (vec![(Trash, true)], CommandError::InvalidFieldMask),
            (vec![(Spam, false)], CommandError::InvalidFieldMask),
            (
                vec![(Unread, true), (Starred, false)],
                CommandError::InvalidFieldMask,
            ),
            (
                vec![(Trash, true), (Inbox, false), (Starred, true)],
                CommandError::InvalidFieldMask,
            ),
        ] {
            assert_eq!(
                DesiredMailboxState::from_touched_fields(account("owner"), fields),
                Err(error)
            );
        }
    }

    // Contract: all touched fields need same-account complete observation, never Unknown.
    // Regression: unknown treated as absent, checking only one field, local-read substitution.
    #[test]
    fn only_complete_same_account_membership_proves_desired_state() {
        let trash = DesiredMailboxState::for_action(account("owner"), &MessageAction::Trash)
            .expect("valid synthetic value");
        for (observed, matches) in [
            (ObservedMembership::Unknown, false),
            (observation("owner", &[]), false),
            (observation("owner", &["TRASH", "INBOX"]), false),
            (observation("other", &["TRASH"]), false),
            (observation("owner", &["TRASH", "IMPORTANT"]), true),
        ] {
            assert_eq!(trash.is_observed_in(&observed), matches);
        }
        let read = DesiredMailboxState::for_action(account("owner"), &MessageAction::Read)
            .expect("valid synthetic value");
        assert!(!read.is_observed_in(&ObservedMembership::Unknown));
        assert!(read.is_observed_in(&observation("owner", &[])));
        let apply = DesiredMailboxState::for_action(
            account("owner"),
            &MessageAction::ApplyLabel(user("owner")),
        )
        .expect("valid synthetic value");
        assert!(apply.is_observed_in(&observation("owner", &["Label_sentinel"])));
        assert!(!apply.is_observed_in(&observation("owner", &[])));
    }

    // Contract: compensation retains actual touched pre-state and guards the same mask.
    // Regression: undo always returns to Inbox or restores fields never touched.
    #[test]
    fn compensation_retains_conditional_per_target_pre_state() {
        let expected =
            DesiredMailboxState::for_action(account("account-sentinel"), &MessageAction::Trash)
                .expect("valid synthetic value");
        assert!(
            expected
                .record_pre_state(&ObservedMembership::Unknown)
                .is_none()
        );
        assert!(
            expected
                .record_pre_state(&observation("other", &[]))
                .is_none()
        );
        let archived = expected
            .record_pre_state(&observation("account-sentinel", &["STARRED"]))
            .expect("valid synthetic value");
        let inbox = expected
            .record_pre_state(&observation("account-sentinel", &["INBOX"]))
            .expect("valid synthetic value");
        let first = ConditionalCompensation::new(expected.clone(), archived)
            .expect("valid synthetic value");
        let second =
            ConditionalCompensation::new(expected.clone(), inbox).expect("valid synthetic value");
        assert_eq!(
            first
                .restore_state()
                .memberships()
                .iter()
                .map(|change| (change.field().clone(), change.is_present()))
                .collect::<Vec<_>>(),
            [(MailboxField::Trash, false), (MailboxField::Inbox, false)]
        );
        assert!(second.restore_state().memberships()[1].is_present());
        let batch = CompensationBatch::new(
            account("account-sentinel"),
            vec![
                MessageCompensation::new(message("b"), second),
                MessageCompensation::new(message("a"), first),
            ],
        )
        .expect("valid synthetic value");
        assert_eq!(
            batch
                .items()
                .iter()
                .map(|item| item.message_id().as_str())
                .collect::<Vec<_>>(),
            ["a", "b"]
        );
        assert!(
            batch.items()[0]
                .condition()
                .expected_post_state()
                .is_observed_in(&observation("account-sentinel", &["TRASH"]))
        );
        let wrong_mask =
            DesiredMailboxState::for_action(account("account-sentinel"), &MessageAction::Archive)
                .expect("valid synthetic value");
        assert_eq!(
            ConditionalCompensation::new(expected.clone(), wrong_mask),
            Err(CommandError::MismatchedCompensation)
        );
        let wrong_account =
            DesiredMailboxState::for_action(account("other"), &MessageAction::Trash)
                .expect("valid synthetic value");
        assert_eq!(
            ConditionalCompensation::new(expected, wrong_account),
            Err(CommandError::WrongAccount)
        );
    }

    // Contract: compensation collections never bypass ordinary target or account bounds.
    // Regression: per-item evidence mixed across accounts or overflow retained partially.
    #[test]
    fn compensation_batch_rejects_invalid_collections() {
        assert_eq!(
            CompensationBatch::new(account("account-sentinel"), vec![]),
            Err(CommandError::EmptyTargets)
        );
        let item = MessageCompensation::new(message("a"), condition());
        assert_eq!(
            CompensationBatch::new(account("other"), vec![item.clone()]),
            Err(CommandError::WrongAccount)
        );
        assert_eq!(
            CompensationBatch::new(account("account-sentinel"), vec![item.clone(), item]),
            Err(CommandError::DuplicateTarget)
        );
        let items: Vec<_> = (0..1_000)
            .map(|i| MessageCompensation::new(message(&format!("m-{i}")), condition()))
            .collect();
        assert_eq!(
            CompensationBatch::new(account("account-sentinel"), items.clone())
                .expect("valid synthetic value")
                .items()
                .len(),
            1_000
        );
        let mut overflow = items;
        overflow.push(MessageCompensation::new(message("extra"), condition()));
        assert_eq!(
            CompensationBatch::new(account("account-sentinel"), overflow),
            Err(CommandError::TooManyTargets)
        );
    }

    // Contract: every command constructor denies readonly and retains only account-local values.
    // Regression: a label-only or compensation path bypasses the construction guard.
    #[test]
    fn command_construction_enforces_capability_account_and_nested_redaction() {
        for capability in [AccountCapability::ReadOnly, AccountCapability::Modify] {
            let label = user("account-sentinel");
            let name = LabelName::new("name-sentinel").expect("valid synthetic value");
            let batch = CompensationBatch::new(
                account("account-sentinel"),
                vec![MessageCompensation::new(
                    message("message-sentinel"),
                    condition(),
                )],
            )
            .expect("valid synthetic value");
            let commands = [
                MailboxCommand::message_state(
                    capability,
                    command_id(),
                    targets(),
                    &MessageAction::ApplyLabel(label.clone()),
                ),
                MailboxCommand::create_label(
                    capability,
                    command_id(),
                    account("account-sentinel"),
                    name.clone(),
                ),
                MailboxCommand::rename_label(capability, command_id(), label.clone(), name),
                MailboxCommand::delete_label(capability, command_id(), label),
                MailboxCommand::compensate(capability, command_id(), batch),
            ];
            for command in commands {
                if capability == AccountCapability::ReadOnly {
                    assert_eq!(command, Err(CommandError::ReadOnly));
                } else {
                    let command = command.expect("valid synthetic value");
                    assert_eq!(command.id().as_str(), "command-sentinel");
                    assert_eq!(command.account_id().as_str(), "account-sentinel");
                    let output = format!("{command:?}");
                    for sentinel in [
                        "account-sentinel",
                        "command-sentinel",
                        "message-sentinel",
                        "Label_sentinel",
                        "name-sentinel",
                    ] {
                        assert!(!output.contains(sentinel));
                    }
                    assert!(output.contains("[REDACTED]"));
                }
            }
        }
        assert_eq!(
            MailboxCommand::message_state(
                AccountCapability::Modify,
                command_id(),
                targets(),
                &MessageAction::RemoveLabel(user("other"))
            ),
            Err(CommandError::WrongAccount)
        );
        assert_eq!(
            CommandError::WrongAccount.to_string(),
            "mailbox command values belong to different accounts"
        );
    }

    // Contract: Partial and abandonment are terminal without claiming success.
    // Regression: uncertain statuses release evidence or abandonment becomes success.
    #[test]
    fn status_dispositions_distinguish_terminal_from_success() {
        use MailboxCommandStatus::{
            Abandoned, Ambiguous, Cancelled, Complete, Dispatching, NeedsAttention, Partial, Queued,
        };
        for (status, terminal, success) in [
            (Queued, false, false),
            (Dispatching, false, false),
            (Ambiguous, false, false),
            (NeedsAttention, false, false),
            (Complete, true, true),
            (Partial, true, false),
            (Cancelled, true, false),
            (Abandoned, true, false),
        ] {
            assert_eq!(status.is_terminal(), terminal);
            assert_eq!(status.is_success(), success);
        }
    }
}
