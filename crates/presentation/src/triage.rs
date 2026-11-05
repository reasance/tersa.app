// This Source Code Form is subject to the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Bounded triage display documents, separate from routing and command authority.
//!
//! The caller maps actual lower-layer facts into these closed inputs. No input
//! here grants an action, performs a transition or promises Undo/Retry eligibility.
//! Keep original typed account/message/label/command keys alongside documents;
//! sanitized or shortened names and identifiers can collide and MUST NOT route
//! actions. Terminal command intent is never substituted for cached observations.
//!
//! Every output string is single-line [`SafeText`](crate::terminal::SafeText). Documents retain separate
//! fields/rows so the UI chooses layout without accepting raw provider errors.
//! Name/identifier work is bounded before sanitization; list omission is explicit.
//!
//! ```
//! use tersa_presentation::triage::{LabelInput, render_label};
//! let typed_routing_key = 42_u64; // Owned by the caller, independent of display.
//! let document = render_label(LabelInput { name: Some("Follow up"), identifier: "Label_1" });
//! let action_row = (typed_routing_key, document);
//! assert_eq!(action_row.0, 42);
//! assert_eq!(action_row.1.name.as_str(), "Follow up");
//! ```

use crate::terminal::SafeText;
use std::fmt;

/// Maximum raw UTF-8 bytes inspected for each provider-derived display field.
pub const MAX_FIELD_INPUT_BYTES: usize = 4_096;
/// Maximum sanitized name characters, plus a visible ellipsis when shortened.
pub const MAX_NAME_CHARS: usize = 96;
/// Maximum sanitized identifier characters, plus a visible ellipsis when shortened.
pub const MAX_IDENTIFIER_CHARS: usize = 64;
/// Maximum User labels shown in one observed or desired list.
pub const MAX_LABELS_SHOWN: usize = 12;
/// Maximum pending projections shown for one message.
pub const MAX_PENDING_SHOWN: usize = 8;
/// Maximum command rows rendered in one account document; callers may page inputs.
pub const MAX_COMMANDS_SHOWN: usize = 32;

/// Stored capability supplied by the caller, never inferred from a display string.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Capability {
    /// Legacy local-read display; provider mutations require explicit upgrade.
    ReadOnly,
    /// Stored Modify capability, distinct from a currently usable session.
    Modify,
}
/// Current access fact supplied independently of stored capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Authority {
    /// Caller reports a current session; actual action guards still apply.
    Current,
    /// No credential is available for current online access.
    Missing,
    /// The current access session has expired.
    Expired,
    /// Saved credential cannot provide mailbox access.
    RevocationOnly,
    /// Current authority could not be established.
    Unavailable,
}
/// Provider-derived account display text and independently supplied access facts.
#[derive(Clone, Copy)]
pub struct AccountInput<'a> {
    /// Stored address/name for display only.
    pub name: &'a str,
    /// Display copy of the opaque account key; caller retains the actual typed key.
    pub identifier: &'a str,
    /// Actual stored capability.
    pub capability: Capability,
    /// Actual current access state, without raw token/authorization errors.
    pub authority: Authority,
}
impl fmt::Debug for AccountInput<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccountInput")
            .field("capability", &self.capability)
            .field("authority", &self.authority)
            .finish_non_exhaustive()
    }
}
/// Exact label display fields; no routing or name-based identity is retained.
#[derive(Clone, Copy)]
pub struct LabelInput<'a> {
    /// None means the cached definition/name is unavailable, never a guessed name.
    pub name: Option<&'a str>,
    /// Display copy of the immutable label ID; caller retains the typed User label.
    pub identifier: &'a str,
}
impl fmt::Debug for LabelInput<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LabelInput([REDACTED])")
    }
}
/// Bounded sanitized label display, unsuitable for action routing.
#[derive(Clone, Eq, PartialEq)]
pub struct LabelDocument {
    /// Sanitized bounded name or an explicit unavailable-name placeholder.
    pub name: SafeText,
    /// Sanitized bounded identifier, never an action key.
    pub identifier: SafeText,
}
impl fmt::Debug for LabelDocument {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LabelDocument([REDACTED])")
    }
}
/// Account display keeps stored capability separate from current access.
#[derive(Clone, Eq, PartialEq)]
pub struct AccountDocument {
    /// Sanitized bounded account name/address.
    pub name: SafeText,
    /// Sanitized bounded account ID, never an action key.
    pub identifier: SafeText,
    /// Stored capability description.
    pub capability: SafeText,
    /// Current session/access description; no eligibility is derived here.
    pub authority: SafeText,
    /// Readonly limitation or explicit reminder that live guards still apply.
    pub limitation: SafeText,
}
impl fmt::Debug for AccountDocument {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AccountDocument([REDACTED])")
    }
}

/// Complete cached provider folder flags, without an inferred archived category.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Folders {
    /// Actual observed INBOX membership.
    pub inbox: bool,
    /// Actual observed TRASH membership.
    pub trash: bool,
    /// Actual observed SPAM membership.
    pub spam: bool,
}
/// Complete observed provider facts, independently of local-read display.
#[derive(Clone, Copy, Debug)]
pub struct ObservedMessage<'a> {
    /// Actual observed UNREAD membership.
    pub unread: bool,
    /// Actual observed STARRED membership.
    pub starred: bool,
    /// Actual observed folder membership.
    pub folders: Folders,
    /// Observed User-label display copies, possibly with unavailable definitions.
    pub labels: &'a [LabelInput<'a>],
}
/// Cached knowledge supplied by the caller; Unknown never means observed empty.
#[derive(Clone, Copy, Debug)]
pub enum ObservedState<'a> {
    /// No complete provider observation is available.
    Unknown,
    /// An exact provider observation established absence.
    Missing,
    /// Complete known membership, including a known empty set.
    Known(ObservedMessage<'a>),
}
/// Only touched desired fields; these are pending intent, never provider truth.
#[derive(Clone, Copy, Debug, Default)]
pub struct DesiredMessage<'a> {
    /// Pending desired UNREAD value, or untouched.
    pub unread: Option<bool>,
    /// Pending desired STARRED value, or untouched.
    pub starred: Option<bool>,
    /// Pending desired INBOX value, or untouched.
    pub inbox: Option<bool>,
    /// Pending desired TRASH value, or untouched.
    pub trash: Option<bool>,
    /// Pending desired SPAM value, or untouched.
    pub spam: Option<bool>,
    /// User labels to apply, not observed memberships.
    pub add_labels: &'a [LabelInput<'a>],
    /// User labels to remove, not observed absences.
    pub remove_labels: &'a [LabelInput<'a>],
}
/// Actual nonterminal status of a pending projection, not a transition request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PendingStatus {
    /// Intent saved locally, unsent.
    Queued,
    /// Durable possible-dispatch marker.
    Dispatching,
    /// Possible provider application remains unresolved.
    Ambiguous,
    /// Explicit recovery attention is needed.
    NeedsAttention,
}
/// One caller-supplied pending projection, without command routing or eligibility.
#[derive(Clone, Copy, Debug)]
pub struct PendingInput<'a> {
    /// Actual persisted nonterminal status.
    pub status: PendingStatus,
    /// Actual touched desired fields.
    pub desired: DesiredMessage<'a>,
}
/// Message display inputs preserve legacy and provider facts separately.
#[derive(Clone, Copy, Debug)]
pub struct MessageStateInput<'a> {
    /// Actual stored capability determines the established display convention.
    pub capability: Capability,
    /// Existing local-read flag, used only by readonly display.
    pub legacy_unread: bool,
    /// Actual cached provider observation.
    pub observed: ObservedState<'a>,
    /// Actual nonterminal projections, in caller-supplied order.
    pub pending: &'a [PendingInput<'a>],
}
/// One visibly pending projection, kept outside observed state.
#[derive(Clone, Eq, PartialEq)]
pub struct PendingDocument {
    /// Nonterminal status with an explicit pending prefix.
    pub status: SafeText,
    /// Bounded touched desired changes, never replacements for observed fields.
    pub changes: Vec<SafeText>,
    /// Count of desired labels omitted across apply/remove lists.
    pub omitted_labels: usize,
}
/// Separate legacy/observed fields and pending intent for one message.
#[derive(Clone, Eq, PartialEq)]
pub struct MessageStateDocument {
    /// Explicit known, unknown or observed-missing provider knowledge.
    pub metadata: SafeText,
    /// Readonly legacy display or Modify's observed/unknown read state.
    pub read: SafeText,
    /// Observed star state or an explicit unknown/unavailable state.
    pub star: SafeText,
    /// Observed folders or an explicit unknown/unavailable state.
    pub folders: SafeText,
    /// Known-empty, observed, unavailable or unknown User-label knowledge.
    pub label_state: SafeText,
    /// Bounded observed User-label names/identifiers.
    pub labels: Vec<LabelDocument>,
    /// Observed User labels omitted from this display.
    pub omitted_labels: usize,
    /// Bounded pending projections; terminal results cannot enter this input facet.
    pub pending: Vec<PendingDocument>,
    /// Pending projections omitted from this display.
    pub omitted_pending: usize,
}

/// Closed command/result fact supplied by the lower-layer caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandStatus {
    /// Durable unsent intent.
    Queued,
    /// Durable possible-dispatch marker, never completion.
    Dispatching,
    /// Transport acknowledgement awaiting fresh reconciliation, not a terminal status.
    Acknowledged,
    /// Unknown possible provider application.
    Ambiguous,
    /// Recovery attention is required.
    NeedsAttention,
    /// Terminal result confirmed by actual observations.
    Complete,
    /// Terminal result containing missing/failed targets.
    Partial,
    /// Local cancellation before dispatch.
    Cancelled,
    /// Warned terminal disposition of uncertainty, not rollback or success.
    Abandoned,
}
/// Command category for display; labels are never converted back into action targets.
#[derive(Clone, Copy, Debug)]
pub enum CommandKind<'a> {
    /// Approved message-state changes.
    MessageChanges,
    /// User-label creation.
    CreateLabel(LabelInput<'a>),
    /// User-label rename.
    RenameLabel(LabelInput<'a>),
    /// User-label definition deletion.
    DeleteLabel(LabelInput<'a>),
    /// Conditional compensation admitted as offline intent.
    ConditionalUndo,
}
/// Bounded numeric outcomes supplied from actual command counts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutcomeCounts {
    total: u16,
    completed: u16,
    missing: u16,
    failed: u16,
}
/// Invalid arithmetic in supplied display counts, without raw backend details.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidOutcomeCounts;
impl fmt::Display for InvalidOutcomeCounts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("command display counts are inconsistent")
    }
}
impl std::error::Error for InvalidOutcomeCounts {}
impl OutcomeCounts {
    /// Copies actual outcome counts without deriving command state or eligibility.
    /// # Errors
    /// Rejects zero total or outcome counts exceeding the total.
    pub fn new(
        total: u16,
        completed: u16,
        missing: u16,
        failed: u16,
    ) -> Result<Self, InvalidOutcomeCounts> {
        if total == 0
            || u32::from(completed) + u32::from(missing) + u32::from(failed) > u32::from(total)
        {
            return Err(InvalidOutcomeCounts);
        }
        Ok(Self {
            total,
            completed,
            missing,
            failed,
        })
    }
}
/// One command's display facts; status/count coherence remains the caller's contract.
#[derive(Clone, Copy)]
pub struct CommandInput<'a> {
    /// Display copy of the command ID, never a replay/action key.
    pub identifier: &'a str,
    /// Closed action category.
    pub kind: CommandKind<'a>,
    /// Actual persisted/result status, never inferred from counts or acknowledgement.
    pub status: CommandStatus,
    /// Actual counts for that status; no status transition is inferred here.
    pub counts: OutcomeCounts,
}
impl fmt::Debug for CommandInput<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CommandInput")
            .field("status", &self.status)
            .field("counts", &self.counts)
            .finish_non_exhaustive()
    }
}
/// A saved command result or pending status, separate from current Gmail observations.
#[derive(Clone, Eq, PartialEq)]
pub struct CommandDocument {
    /// Sanitized bounded command ID, never a routing key.
    pub identifier: SafeText,
    /// Sanitized closed action description.
    pub action: SafeText,
    /// Actual status with truthful uncertainty/all-missing wording.
    pub status: SafeText,
    /// Completed, missing, failed and pending outcome counts.
    pub outcomes: SafeText,
    /// Meaning of this status without granting an action.
    pub notice: SafeText,
}
/// Bounded command rows explicitly scoped to one displayed account.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountCommandsDocument {
    /// Account context; actual typed routing identity stays with the caller.
    pub account: AccountDocument,
    /// Pending and/or terminal rows in caller-provided order, without transitions.
    pub commands: Vec<CommandDocument>,
    /// Rows omitted from this document; callers can supply another page.
    pub omitted: usize,
}

/// Required semantic warnings, selected only for their specific requested actions.
#[derive(Clone, Copy, Debug)]
pub enum ActionWarning<'a> {
    /// Delete this exact User-label definition, not its messages.
    DeleteLabel(LabelInput<'a>),
    /// Stop automatic recovery after possible provider application.
    Abandon,
    /// Another possible label-create attempt requires explicit duplicate-risk consent.
    RetryPossibleLabelCreate,
    /// Queue conditional compensation without claiming current eligibility.
    ConditionalOfflineUndo,
}
/// A specific action warning; ordinary reversible actions have no warning variant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WarningDocument {
    /// Canonical warning title.
    pub title: SafeText,
    /// Intentional single-line explanation; UI owns wrapping, not raw line breaks.
    pub explanation: SafeText,
    /// Sanitized exact-label display context where applicable; never an action key.
    pub label: Option<LabelDocument>,
}
/// Closed recovery facts, never arbitrary backend/SQL/authorization text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryNotice {
    /// Current online access requires reconnect.
    ReconnectRequired,
    /// Current account identity could not safely be verified.
    IdentityUnverified,
    /// Local account data is unavailable.
    AccountUnavailable,
    /// Unresolved commands block destructive maintenance.
    PendingCommandsBlockMaintenance,
    /// Transport acknowledgement/uncertainty still requires observation.
    ObservationRequired,
    /// Fresh recovery observation failed; previous evidence remains.
    ObservationFailed,
    /// Bounded work made no progress; do not claim completion or automatic retry.
    NoProgress,
    /// Provider consent withdrawal was not confirmed.
    RevocationUnconfirmed,
}
/// Actual cache-refresh progress, independent of command settlement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MailboxRefresh {
    /// No cache refresh was attempted.
    NotAttempted,
    /// History caught up for the retained cache, not the whole mailbox.
    CaughtUp,
    /// A bounded recent snapshot was saved; History replay remains.
    RecentSnapshot,
    /// Only a bounded prefix was saved.
    Bounded,
    /// Refresh failed without undoing confirmed command settlement.
    Failed,
}
/// Actual complete-catalog cache refresh fact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatalogRefresh {
    /// No catalog read was attempted.
    NotAttempted,
    /// Complete observed catalog was saved.
    Updated,
    /// Catalog refresh failed; previous cache may be stale.
    Failed,
}
/// Body results remain separate from saved metadata/cursor progress.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BodyRefresh {
    /// No body work ran, including an unsafe/skipped deferred plan.
    NotRun,
    /// Body work finished; count is actual conditional cache writes.
    Finished(u16),
    /// Body work failed after this many confirmed cache writes.
    Failed(u16),
}
/// Separately supplied refresh facts, never inferred from terminal command intent.
#[derive(Clone, Copy, Debug)]
pub struct ConvergenceInput {
    /// Actual mailbox History/snapshot result.
    pub mailbox: MailboxRefresh,
    /// Actual catalog cache result.
    pub catalog: CatalogRefresh,
    /// Actual body cache result.
    pub bodies: BodyRefresh,
    /// True only when a reported post-progress last-sync status update failed.
    pub freshness_update_failed: bool,
}
/// Sanitized independent notices for command-versus-cache convergence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConvergenceDocument {
    /// Actual metadata/cursor coverage, without a full-mailbox claim.
    pub mailbox: SafeText,
    /// Actual catalog progress.
    pub catalog: SafeText,
    /// Actual body progress, independent of metadata.
    pub bodies: SafeText,
    /// A failed last-sync status update, if supplied.
    pub freshness: Option<SafeText>,
    /// Command completion is not current provider-state evidence.
    pub distinction: SafeText,
}

/// Sanitizes and bounds a display copy of an identifier; never use it for routing.
#[must_use]
pub fn render_identifier(value: &str) -> SafeText {
    field(value, MAX_IDENTIFIER_CHARS, "(identifier unavailable)")
}
/// Renders bounded account names and distinct stored/current access descriptions.
#[must_use]
pub fn render_account(input: AccountInput<'_>) -> AccountDocument {
    AccountDocument {
        name: field(input.name, MAX_NAME_CHARS, "(account name unavailable)"),
        identifier: render_identifier(input.identifier),
        capability: line(match input.capability {
            Capability::ReadOnly => "Stored access: Read-only",
            Capability::Modify => "Stored access: Modify",
        }),
        authority: line(match input.authority {
            Authority::Current => "Current session available; action guards still apply.",
            Authority::Missing => "No current access. Reconnect before online mailbox actions.",
            Authority::Expired => "Session expired. Online actions need fresh access.",
            Authority::RevocationOnly => {
                "Reconnect required. The saved credential cannot access the mailbox."
            }
            Authority::Unavailable => "Current online authority is unavailable.",
        }),
        limitation: line(match input.capability {
            Capability::ReadOnly => {
                "Mailbox changes require an explicit upgrade. Existing local-read display is preserved."
            }
            Capability::Modify => "Stored Modify access alone does not authorize a current action.",
        }),
    }
}
/// Renders a sanitized name/ID pair without guessing an unavailable label definition.
#[must_use]
pub fn render_label(input: LabelInput<'_>) -> LabelDocument {
    LabelDocument {
        name: input.name.map_or_else(
            || line("(label name unavailable)"),
            |name| field(name, MAX_NAME_CHARS, "(label name unavailable)"),
        ),
        identifier: render_identifier(input.identifier),
    }
}
/// Renders observed state and distinct pending projections without deriving a toggle.
#[must_use]
pub fn render_message_state(input: MessageStateInput<'_>) -> MessageStateDocument {
    let (metadata, observed_read, star, folders, label_state, labels, omitted_labels) =
        match input.observed {
            ObservedState::Unknown => (
                line("Gmail metadata unknown"),
                line("Gmail read state unknown"),
                line("Gmail star state unknown"),
                line("Gmail folders unknown"),
                line("User-label membership unknown"),
                Vec::new(),
                0,
            ),
            ObservedState::Missing => (
                line("Observed missing from Gmail"),
                line("Gmail read state unavailable"),
                line("Gmail star state unavailable"),
                line("Gmail folders unavailable"),
                line("User-label membership unavailable"),
                Vec::new(),
                0,
            ),
            ObservedState::Known(value) => (
                line("Observed Gmail state"),
                line(if value.unread {
                    "Observed: unread"
                } else {
                    "Observed: read"
                }),
                line(if value.starred {
                    "Observed: starred"
                } else {
                    "Observed: not starred"
                }),
                render_folders(value.folders),
                line(if value.labels.is_empty() {
                    "Observed User labels: none"
                } else {
                    "Observed User labels"
                }),
                value
                    .labels
                    .iter()
                    .take(MAX_LABELS_SHOWN)
                    .copied()
                    .map(render_label)
                    .collect(),
                value.labels.len().saturating_sub(MAX_LABELS_SHOWN),
            ),
        };
    MessageStateDocument {
        metadata,
        read: if input.capability == Capability::ReadOnly {
            line(if input.legacy_unread {
                "Local display: unread"
            } else {
                "Local display: read"
            })
        } else {
            observed_read
        },
        star,
        folders,
        label_state,
        labels,
        omitted_labels,
        pending: input
            .pending
            .iter()
            .take(MAX_PENDING_SHOWN)
            .map(render_pending)
            .collect(),
        omitted_pending: input.pending.len().saturating_sub(MAX_PENDING_SHOWN),
    }
}
/// Renders actual command facts; acknowledgement and counts never promote its status.
#[must_use]
pub fn render_command(input: CommandInput<'_>) -> CommandDocument {
    let counts = input.counts;
    let pending = counts.total - counts.completed - counts.missing - counts.failed;
    let status = match input.status {
        CommandStatus::Queued => "Queued",
        CommandStatus::Dispatching => "Dispatching",
        CommandStatus::Acknowledged => "Acknowledged; awaiting observation",
        CommandStatus::Ambiguous => "Ambiguous; outcome unknown",
        CommandStatus::NeedsAttention => "Needs attention",
        CommandStatus::Complete => "Complete",
        CommandStatus::Partial if counts.missing == counts.total => "Partial: all targets missing",
        CommandStatus::Partial if counts.completed == 0 => "Partial: no targets completed",
        CommandStatus::Partial => "Partial",
        CommandStatus::Cancelled => "Cancelled",
        CommandStatus::Abandoned => "Abandoned",
    };
    let notice = match input.status {
        CommandStatus::Queued if matches!(input.kind, CommandKind::ConditionalUndo) => {
            "Conditional Undo is queued intent. Eligibility will be freshly checked after reconnect."
        }
        CommandStatus::Queued => {
            "Intent saved locally; this queued command has not been dispatched."
        }
        CommandStatus::Dispatching => {
            "This command may have reached Gmail. Completion is not confirmed."
        }
        CommandStatus::Acknowledged => {
            "Acknowledgement is not completion. Fresh observation is still required."
        }
        CommandStatus::Ambiguous => {
            "Gmail may already have applied this command. Fresh observation is required."
        }
        CommandStatus::NeedsAttention => {
            "Recovery needs explicit attention; completion is not confirmed."
        }
        CommandStatus::Partial if counts.missing == counts.total => {
            "No targets completed. Every target was observed missing."
        }
        CommandStatus::Complete | CommandStatus::Partial => {
            "Saved command result only; current Gmail state comes from observed metadata."
        }
        CommandStatus::Cancelled => "Local queued intent was cancelled before dispatch.",
        CommandStatus::Abandoned => {
            "Automatic recovery stopped. Gmail may already have applied the command. This is not rollback or success."
        }
    };
    CommandDocument {
        identifier: render_identifier(input.identifier),
        action: render_kind(input.kind),
        status: line(status),
        notice: line(notice),
        outcomes: line(&format!(
            "{} completed; {} missing; {} failed; {pending} pending ({} total)",
            counts.completed, counts.missing, counts.failed, counts.total
        )),
    }
}
/// Renders one bounded account-scoped page without sorting or changing command states.
#[must_use]
pub fn render_account_commands(
    account: AccountInput<'_>,
    commands: &[CommandInput<'_>],
) -> AccountCommandsDocument {
    AccountCommandsDocument {
        account: render_account(account),
        commands: commands
            .iter()
            .take(MAX_COMMANDS_SHOWN)
            .copied()
            .map(render_command)
            .collect(),
        omitted: commands.len().saturating_sub(MAX_COMMANDS_SHOWN),
    }
}
/// Renders a specific required warning; it never confirms or admits an action.
#[must_use]
pub fn render_warning(warning: ActionWarning<'_>) -> WarningDocument {
    let (title, explanation, label) = match warning {
        ActionWarning::DeleteLabel(label) => (
            "Delete this User label?",
            "Deleting this label removes its definition and membership from messages. Messages themselves are not deleted. Label deletion has no command Undo.",
            Some(render_label(label)),
        ),
        ActionWarning::Abandon => (
            "Abandon automatic recovery?",
            "Gmail may already have applied this command. Automatic recovery stops after Abandon is saved. Abandon is not rollback and is not success.",
            None,
        ),
        ActionWarning::RetryPossibleLabelCreate => (
            "Retry a possibly applied label create?",
            "An earlier create may already have reached Gmail. A new attempt can create a duplicate label. Fresh catalog reconciliation and explicit duplicate-risk confirmation are required before another attempt.",
            None,
        ),
        ActionWarning::ConditionalOfflineUndo => (
            "Queue conditional Undo?",
            "Undo is saved as queued conditional intent. After reconnect, fresh observations must confirm every target, required label and expected post-state before compensation. Any mismatch refuses the whole compensation without dispatch. Queuing Undo does not confirm current eligibility or completion.",
            None,
        ),
    };
    WarningDocument {
        title: line(title),
        explanation: line(explanation),
        label,
    }
}
/// Formats only closed recovery facts, never raw provider/backend error text.
#[must_use]
pub fn render_recovery(notice: RecoveryNotice) -> SafeText {
    line(match notice {
        RecoveryNotice::ReconnectRequired => {
            "Reconnect this account before online mailbox actions; stored recovery remains available."
        }
        RecoveryNotice::IdentityUnverified => {
            "Account identity could not be verified. Stop mailbox work and reload this account's state."
        }
        RecoveryNotice::AccountUnavailable => {
            "This account's cached data is unavailable. No account fallback was selected."
        }
        RecoveryNotice::PendingCommandsBlockMaintenance => {
            "Pending commands block cache reset and removal. Cancel unsent intent, settle work or explicitly Abandon unresolved commands first."
        }
        RecoveryNotice::ObservationRequired => {
            "Fresh observation is required before completion can be confirmed."
        }
        RecoveryNotice::ObservationFailed => {
            "Fresh observation failed. Previous command evidence is retained; success is not confirmed."
        }
        RecoveryNotice::NoProgress => {
            "No progress was confirmed. Work stopped without an automatic retry loop."
        }
        RecoveryNotice::RevocationUnconfirmed => {
            "Provider consent withdrawal could not be confirmed. Local cleanup is not proof that access was revoked."
        }
    })
}
/// Formats independent cache/body/catalog results without altering command settlement.
#[must_use]
pub fn render_convergence(input: ConvergenceInput) -> ConvergenceDocument {
    let mailbox = match input.mailbox {
        MailboxRefresh::NotAttempted => {
            "Cached view refresh has not run; command intent is not current Gmail state."
        }
        MailboxRefresh::CaughtUp => {
            "History caught up for the retained cache; this is not full-mailbox coverage."
        }
        MailboxRefresh::RecentSnapshot => {
            "Recent snapshot saved; History replay is still required."
        }
        MailboxRefresh::Bounded => {
            "Bounded History progress saved; cached views may still be stale."
        }
        MailboxRefresh::Failed => {
            "Cached view refresh failed; confirmed command results remain saved."
        }
    };
    let catalog = match input.catalog {
        CatalogRefresh::NotAttempted => "Label catalog refresh has not run.",
        CatalogRefresh::Updated => "Observed label catalog refreshed.",
        CatalogRefresh::Failed => "Label catalog refresh failed; cached labels may be stale.",
    };
    let bodies = match input.bodies {
        BodyRefresh::NotRun => line("No message-body caching was performed."),
        BodyRefresh::Finished(count) => line(&format!("Cached {count} message bodies.")),
        BodyRefresh::Failed(count) => line(&format!(
            "Cached {count} message bodies before body work failed. Saved metadata progress is retained."
        )),
    };
    ConvergenceDocument {
        mailbox: line(mailbox),
        catalog: line(catalog),
        bodies,
        freshness: input
            .freshness_update_failed
            .then(|| line("Last-sync status could not be updated; saved progress remains.")),
        distinction: line(
            "Command results and cached view refresh are separate. Terminal desired intent is not current provider truth.",
        ),
    }
}

fn line(value: &str) -> SafeText {
    SafeText::single_line(value)
}
fn field(value: &str, limit: usize, fallback: &str) -> SafeText {
    let mut end = value.len().min(MAX_FIELD_INPUT_BYTES);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    let sanitized = line(&value[..end]);
    let cut = sanitized
        .as_str()
        .char_indices()
        .nth(limit)
        .map(|(index, _)| index);
    let shortened = end < value.len() || cut.is_some();
    let text = &sanitized.as_str()[..cut.unwrap_or(sanitized.as_str().len())];
    let text = if text.trim().is_empty() {
        fallback
    } else {
        text
    };
    if shortened {
        line(&format!("{text}…"))
    } else {
        line(text)
    }
}
fn render_folders(value: Folders) -> SafeText {
    let mut folders = Vec::with_capacity(3);
    if value.inbox {
        folders.push("Inbox");
    }
    if value.trash {
        folders.push("Trash");
    }
    if value.spam {
        folders.push("Spam");
    }
    if folders.is_empty() {
        line("Observed folders: none of Inbox, Trash, Spam")
    } else {
        line(&format!("Observed folders: {}", folders.join(", ")))
    }
}
fn render_pending(value: &PendingInput<'_>) -> PendingDocument {
    let status = match value.status {
        PendingStatus::Queued => "Pending: queued",
        PendingStatus::Dispatching => "Pending: dispatching; not confirmed",
        PendingStatus::Ambiguous => "Pending: ambiguous outcome",
        PendingStatus::NeedsAttention => "Pending: needs attention",
    };
    let mut changes = Vec::new();
    for (fact, yes, no) in [
        (value.desired.unread, "Mark unread", "Mark read"),
        (value.desired.starred, "Star", "Unstar"),
        (value.desired.inbox, "Add to Inbox", "Remove from Inbox"),
        (value.desired.trash, "Move to Trash", "Remove from Trash"),
        (value.desired.spam, "Move to Spam", "Remove from Spam"),
    ] {
        if let Some(fact) = fact {
            changes.push(line(if fact { yes } else { no }));
        }
    }
    for (labels, verb) in [
        (value.desired.add_labels, "Apply label"),
        (value.desired.remove_labels, "Remove label"),
    ] {
        for label in labels.iter().take(MAX_LABELS_SHOWN) {
            let label = render_label(*label);
            changes.push(line(&format!(
                "{verb}: {} [{}]",
                label.name, label.identifier
            )));
        }
    }
    PendingDocument {
        status: line(status),
        changes,
        omitted_labels: value
            .desired
            .add_labels
            .len()
            .saturating_sub(MAX_LABELS_SHOWN)
            .saturating_add(
                value
                    .desired
                    .remove_labels
                    .len()
                    .saturating_sub(MAX_LABELS_SHOWN),
            ),
    }
}
fn render_kind(kind: CommandKind<'_>) -> SafeText {
    match kind {
        CommandKind::MessageChanges => line("Message changes"),
        CommandKind::ConditionalUndo => line("Conditional Undo"),
        CommandKind::CreateLabel(label) => label_action("Create label", label),
        CommandKind::RenameLabel(label) => label_action("Rename label", label),
        CommandKind::DeleteLabel(label) => label_action("Delete label", label),
    }
}
fn label_action(action: &str, label: LabelInput<'_>) -> SafeText {
    let label = render_label(label);
    line(&format!("{action}: {} [{}]", label.name, label.identifier))
}

#[cfg(test)]
#[path = "triage_tests.rs"]
mod tests;

impl fmt::Debug for PendingDocument {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PendingDocument([REDACTED])")
    }
}

impl fmt::Debug for MessageStateDocument {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MessageStateDocument([REDACTED])")
    }
}

impl fmt::Debug for CommandDocument {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CommandDocument([REDACTED])")
    }
}
