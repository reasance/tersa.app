// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! P8 documents from actual cached facts. No document supplies action identity.
use tersa_application::{
    command::{
        CommandCategory, CommandCounts, CommandSnapshot, MailboxCommandKind, MailboxCommandStatus,
        MailboxField, TerminalCommandSummary,
    },
    mailbox_state::LabelDefinition,
};
use tersa_presentation::{terminal::SafeText, triage as p8};
use tersa_sync_runtime::{AccountCommandStatus, CredentialPurpose};

pub(super) fn label_input(definition: &LabelDefinition) -> p8::LabelInput<'_> {
    p8::LabelInput {
        name: Some(definition.name().as_str()),
        identifier: definition.id().as_str(),
    }
}
pub(super) fn account_lines(state: &AccountCommandStatus) -> Vec<SafeText> {
    let doc = p8::render_account(p8::AccountInput {
        name: state
            .metadata
            .email()
            .map_or(state.metadata.account_id().as_str(), |email| email.as_str()),
        identifier: state.metadata.account_id().as_str(),
        capability: if state.metadata.capability() == tersa_application::AccountCapability::Modify {
            p8::Capability::Modify
        } else {
            p8::Capability::ReadOnly
        },
        authority: match state.credential {
            CredentialPurpose::Active => p8::Authority::Unavailable,
            CredentialPurpose::Missing => p8::Authority::Missing,
            CredentialPurpose::RevocationOnly => p8::Authority::RevocationOnly,
        },
    });
    let mut lines = vec![doc.name, doc.identifier, doc.capability, doc.authority];
    lines.push(doc.limitation);
    if state.lifecycle.recovery().is_some() {
        lines.push(SafeText::single_line(
            "Account lifecycle recovery remains unresolved; online operations may be refused.",
        ));
    }
    lines.push(SafeText::single_line(&format!("{} pending commands; {} retained terminal summaries. Local controls remain available without a token.", state.pending.len(), state.terminal.summaries().len())));
    lines
}
fn status(status: MailboxCommandStatus) -> p8::CommandStatus {
    match status {
        MailboxCommandStatus::Queued => p8::CommandStatus::Queued,
        MailboxCommandStatus::Dispatching => p8::CommandStatus::Dispatching,
        MailboxCommandStatus::Ambiguous => p8::CommandStatus::Ambiguous,
        MailboxCommandStatus::NeedsAttention => p8::CommandStatus::NeedsAttention,
        MailboxCommandStatus::Complete => p8::CommandStatus::Complete,
        MailboxCommandStatus::Partial => p8::CommandStatus::Partial,
        MailboxCommandStatus::Cancelled => p8::CommandStatus::Cancelled,
        MailboxCommandStatus::Abandoned => p8::CommandStatus::Abandoned,
    }
}
fn command_doc(
    id: &str,
    kind: p8::CommandKind<'_>,
    state: MailboxCommandStatus,
    counts: CommandCounts,
) -> p8::CommandDocument {
    // Counts come from a validated store snapshot/summary. Preserve a closed
    // unavailable display if a future producer violates that contract.
    match p8::OutcomeCounts::new(
        counts.total(),
        counts.satisfied(),
        counts.target_missing(),
        counts.failed(),
    ) {
        Ok(counts) => p8::render_command(p8::CommandInput {
            identifier: id,
            kind,
            status: status(state),
            counts,
        }),
        Err(_error) => p8::CommandDocument {
            identifier: p8::render_identifier(id),
            action: SafeText::single_line("Saved command"),
            status: SafeText::single_line("Status unavailable"),
            outcomes: SafeText::single_line("Outcome counts unavailable"),
            notice: SafeText::single_line("Reload account status; no completion is assumed."),
        },
    }
}
fn snapshot_doc(snapshot: &CommandSnapshot) -> p8::CommandDocument {
    match snapshot.command().kind() {
        MailboxCommandKind::CreateLabel(name) => command_doc(
            snapshot.command().id().as_str(),
            p8::CommandKind::CreateLabel(p8::LabelInput {
                name: Some(name.as_str()),
                identifier: "not assigned",
            }),
            snapshot.status(),
            snapshot.counts(),
        ),
        MailboxCommandKind::RenameLabel { label, name } => command_doc(
            snapshot.command().id().as_str(),
            p8::CommandKind::RenameLabel(p8::LabelInput {
                name: Some(name.as_str()),
                identifier: label.id().as_str(),
            }),
            snapshot.status(),
            snapshot.counts(),
        ),
        MailboxCommandKind::DeleteLabel(label) => command_doc(
            snapshot.command().id().as_str(),
            p8::CommandKind::DeleteLabel(p8::LabelInput {
                name: None,
                identifier: label.id().as_str(),
            }),
            snapshot.status(),
            snapshot.counts(),
        ),
        MailboxCommandKind::Compensate(_) => command_doc(
            snapshot.command().id().as_str(),
            p8::CommandKind::ConditionalUndo,
            snapshot.status(),
            snapshot.counts(),
        ),
        MailboxCommandKind::MessageState { .. } => command_doc(
            snapshot.command().id().as_str(),
            p8::CommandKind::MessageChanges,
            snapshot.status(),
            snapshot.counts(),
        ),
    }
}
pub(super) fn command_heading(snapshot: &CommandSnapshot) -> String {
    let doc = snapshot_doc(snapshot);
    format!(
        "{} · {} · {} · {}",
        doc.identifier, doc.action, doc.status, doc.outcomes
    )
}
pub(super) fn command_lines(snapshot: &CommandSnapshot) -> Vec<SafeText> {
    let doc = snapshot_doc(snapshot);
    let mut lines = vec![
        doc.identifier,
        doc.action,
        doc.status,
        doc.outcomes,
        doc.notice,
    ];
    match snapshot.command().kind() {
        MailboxCommandKind::MessageState { targets, desired } => {
            for field in desired.memberships() {
                let value = match field.field() {
                    MailboxField::Unread => if field.is_present() { "Desired: Unread".to_owned() } else { "Desired: Read".to_owned() },
                    MailboxField::Starred => format!("Desired: starred {}", field.is_present()),
                    MailboxField::Inbox => format!("Desired: Inbox membership {}", field.is_present()),
                    MailboxField::Trash => format!("Desired: Trash membership {}", field.is_present()),
                    MailboxField::Spam => format!("Desired: Spam membership {}", field.is_present()),
                    MailboxField::UserLabel(label) => format!("Desired: User label [{}] membership {}", p8::render_identifier(label.id().as_str()), field.is_present()),
                };
                lines.push(SafeText::single_line(&value));
            }
            lines.push(SafeText::single_line(&format!("Exact account: {}. {} captured message targets.", p8::render_identifier(targets.account_id().as_str()), targets.ids().len())));
            lines.extend(targets.ids().iter().map(|id| p8::render_identifier(id.as_str())));
        }
        MailboxCommandKind::Compensate(batch) => lines.push(SafeText::single_line(&format!("{} conditional message targets; whole-set eligibility is checked on fresh reconciliation.", batch.items().len()))),
        _ => {}
    }
    lines
}
pub(super) fn terminal_lines(summary: &TerminalCommandSummary) -> Vec<SafeText> {
    let kind = if summary.category() == CommandCategory::Compensation {
        p8::CommandKind::ConditionalUndo
    } else {
        p8::CommandKind::MessageChanges
    };
    let mut doc = command_doc(
        summary.stamp().key().command_id().as_str(),
        kind,
        summary.status(),
        summary.counts(),
    );
    if summary.category() == CommandCategory::LabelDefinition {
        doc.action = SafeText::single_line("Label definition (target details compacted)");
    }
    vec![SafeText::single_line(&format!(
        "Saved result: {} · {} · {} · {}. {}",
        doc.identifier, doc.action, doc.status, doc.outcomes, doc.notice
    ))]
}
