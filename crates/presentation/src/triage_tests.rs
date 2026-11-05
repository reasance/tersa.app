// This Source Code Form is subject to the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Observable triage documents; the sanitizer's full matrix remains terminal-owned.

use super::*;

fn account(capability: Capability, authority: Authority) -> AccountInput<'static> {
    AccountInput {
        name: "reader@example.test",
        identifier: "acct_1",
        capability,
        authority,
    }
}
fn counts(total: u16, completed: u16, missing: u16, failed: u16) -> OutcomeCounts {
    OutcomeCounts::new(total, completed, missing, failed).expect("valid lower-layer counts")
}
fn command(status: CommandStatus, counts: OutcomeCounts) -> CommandInput<'static> {
    CommandInput {
        identifier: "command_1",
        kind: CommandKind::MessageChanges,
        status,
        counts,
    }
}

// Protects every new provider-text route, including composed action/warning text.
// A formatter bypassing SafeText would expose ESC/bidi/newline bytes at this boundary.
#[test]
fn hostile_account_label_and_command_fields_leave_only_safe_single_line_documents() {
    let hostile = "private\x1b[2J\u{202e}name\nnext\tline";
    let label = LabelInput {
        name: Some(hostile),
        identifier: "Label_\x1b]52;x\x07\n1",
    };
    let context = AccountInput {
        name: hostile,
        identifier: "acct_\u{202e}1\n2",
        capability: Capability::Modify,
        authority: Authority::Expired,
    };
    let cmd = CommandInput {
        identifier: hostile,
        kind: CommandKind::RenameLabel(label),
        status: CommandStatus::Queued,
        counts: counts(1, 0, 0, 0),
    };
    let queue = render_account_commands(context, &[cmd]);
    let warning = render_warning(ActionWarning::DeleteLabel(label));
    let label_document = warning.label.as_ref().expect("label context");
    for value in [
        &queue.account.name,
        &queue.account.identifier,
        &queue.commands[0].identifier,
        &queue.commands[0].action,
        &label_document.name,
        &label_document.identifier,
    ] {
        assert!(!value.as_str().chars().any(char::is_control));
        assert!(!value.as_str().contains('\u{202e}'));
    }
    assert!(queue.account.authority.as_str().contains("expired"));
    assert!(
        queue.commands[0]
            .action
            .as_str()
            .starts_with("Rename label:")
    );
    assert!(
        !format!("{queue:?} {context:?} {cmd:?}").contains("private"),
        "debug output must not log provider names or IDs"
    );

    // Sanitization collisions are legitimate display collisions, never recovered identity.
    let originals = ["Label_\u{202e}1", "Label_1"];
    let displayed = originals.map(|identifier| {
        render_label(LabelInput {
            name: Some("Same name"),
            identifier,
        })
    });
    assert_ne!(originals[0], originals[1]);
    assert_eq!(displayed[0], displayed[1]);
}

#[test]
fn unknown_modify_state_never_uses_local_unread_or_pending_intent_as_observation() {
    let pending = [PendingInput {
        status: PendingStatus::Queued,
        desired: DesiredMessage {
            unread: Some(true),
            starred: Some(true),
            inbox: Some(false),
            ..DesiredMessage::default()
        },
    }];
    let input = MessageStateInput {
        capability: Capability::Modify,
        legacy_unread: true,
        observed: ObservedState::Unknown,
        pending: &pending,
    };
    let unknown = render_message_state(input);
    assert_eq!(unknown.read.as_str(), "Gmail read state unknown");
    assert_eq!(
        unknown.label_state.as_str(),
        "User-label membership unknown"
    );
    assert!(
        unknown.pending[0]
            .changes
            .iter()
            .any(|line| line.as_str() == "Mark unread")
    );
    let legacy = render_message_state(MessageStateInput {
        capability: Capability::ReadOnly,
        ..input
    });
    assert_eq!(legacy.read.as_str(), "Local display: unread");
    assert_eq!(legacy.metadata.as_str(), "Gmail metadata unknown");
    let observed = render_message_state(MessageStateInput {
        observed: ObservedState::Known(ObservedMessage {
            unread: false,
            starred: false,
            folders: Folders {
                inbox: true,
                ..Folders::default()
            },
            labels: &[],
        }),
        ..input
    });
    assert_eq!(observed.read.as_str(), "Observed: read");
    assert_eq!(observed.star.as_str(), "Observed: not starred");
    assert_eq!(observed.folders.as_str(), "Observed folders: Inbox");
    assert_eq!(observed.label_state.as_str(), "Observed User labels: none");
    assert!(observed.pending[0].status.as_str().contains("Pending"));
    assert!(
        observed.pending[0]
            .changes
            .iter()
            .any(|line| line.as_str() == "Mark unread")
    );
    let missing = render_message_state(MessageStateInput {
        observed: ObservedState::Missing,
        ..input
    });
    assert_eq!(missing.metadata.as_str(), "Observed missing from Gmail");
    assert_eq!(missing.read.as_str(), "Gmail read state unavailable");
}

#[test]
fn uncertain_acknowledgement_and_terminal_all_missing_results_do_not_sound_complete() {
    let acknowledged = render_command(command(CommandStatus::Acknowledged, counts(3, 0, 0, 0)));
    assert!(
        acknowledged
            .status
            .as_str()
            .contains("awaiting observation")
    );
    assert!(acknowledged.notice.as_str().contains("not completion"));
    let ambiguous = render_command(command(CommandStatus::Ambiguous, counts(3, 0, 0, 0)));
    assert!(
        ambiguous
            .notice
            .as_str()
            .contains("may already have applied")
    );
    let dispatching = render_command(command(CommandStatus::Dispatching, counts(3, 0, 0, 0)));
    assert!(dispatching.notice.as_str().contains("not confirmed"));
    let attention = render_command(command(CommandStatus::NeedsAttention, counts(3, 0, 0, 0)));
    assert!(attention.notice.as_str().contains("not confirmed"));
    let missing = render_command(command(CommandStatus::Partial, counts(3, 0, 3, 0)));
    assert_eq!(missing.status.as_str(), "Partial: all targets missing");
    assert!(missing.notice.as_str().contains("No targets completed"));
    assert_eq!(
        missing.outcomes.as_str(),
        "0 completed; 3 missing; 0 failed; 0 pending (3 total)"
    );
    let mixed = render_command(command(CommandStatus::Partial, counts(3, 1, 1, 1)));
    assert!(
        mixed
            .outcomes
            .as_str()
            .starts_with("1 completed; 1 missing; 1 failed")
    );
    let complete = render_command(command(CommandStatus::Complete, counts(3, 3, 0, 0)));
    assert_eq!(complete.status.as_str(), "Complete");
    assert!(
        complete
            .notice
            .as_str()
            .contains("Saved command result only")
    );
    assert!(
        OutcomeCounts::new(1, 1, 1, 0).is_err(),
        "inconsistent counts must not wrap pending arithmetic"
    );
}

#[test]
fn required_warnings_preserve_uncertainty_duplicate_risk_and_conditional_undo_semantics() {
    let abandon = render_warning(ActionWarning::Abandon);
    assert!(
        abandon
            .explanation
            .as_str()
            .contains("may already have applied")
    );
    assert!(
        abandon
            .explanation
            .as_str()
            .contains("recovery stops after Abandon is saved")
    );
    assert!(
        abandon
            .explanation
            .as_str()
            .contains("not rollback and is not success")
    );
    let retry = render_warning(ActionWarning::RetryPossibleLabelCreate);
    assert!(
        retry
            .explanation
            .as_str()
            .contains("can create a duplicate label")
    );
    assert!(
        retry
            .explanation
            .as_str()
            .contains("Fresh catalog reconciliation")
    );
    assert!(
        retry
            .explanation
            .as_str()
            .contains("explicit duplicate-risk confirmation")
    );
    let undo = render_warning(ActionWarning::ConditionalOfflineUndo);
    assert!(
        undo.explanation
            .as_str()
            .contains("queued conditional intent")
    );
    assert!(
        undo.explanation
            .as_str()
            .contains("every target, required label and expected post-state")
    );
    assert!(
        undo.explanation
            .as_str()
            .contains("Any mismatch refuses the whole compensation without dispatch")
    );
    assert!(
        undo.explanation
            .as_str()
            .contains("does not confirm current eligibility or completion")
    );
    let queued = render_command(CommandInput {
        kind: CommandKind::ConditionalUndo,
        ..command(CommandStatus::Queued, counts(1, 0, 0, 0))
    });
    assert!(
        queued
            .notice
            .as_str()
            .contains("Eligibility will be freshly checked after reconnect")
    );
    let delete = render_warning(ActionWarning::DeleteLabel(LabelInput {
        name: None,
        identifier: "Label_1",
    }));
    assert!(
        delete
            .explanation
            .as_str()
            .contains("Messages themselves are not deleted")
    );
    assert!(delete.explanation.as_str().contains("no command Undo"));
    assert_eq!(
        delete.label.expect("label").name.as_str(),
        "(label name unavailable)"
    );
}

#[test]
fn cache_refresh_and_body_failures_never_rewrite_saved_command_completion() {
    let complete = render_command(command(CommandStatus::Complete, counts(1, 1, 0, 0)));
    let refresh = render_convergence(ConvergenceInput {
        mailbox: MailboxRefresh::Failed,
        catalog: CatalogRefresh::Failed,
        bodies: BodyRefresh::Failed(2),
        freshness_update_failed: true,
    });
    assert_eq!(complete.status.as_str(), "Complete");
    assert!(
        refresh
            .mailbox
            .as_str()
            .contains("confirmed command results remain saved")
    );
    assert!(
        refresh
            .catalog
            .as_str()
            .contains("cached labels may be stale")
    );
    assert!(refresh.bodies.as_str().contains("Cached 2 message bodies"));
    assert!(
        refresh
            .bodies
            .as_str()
            .contains("metadata progress is retained")
    );
    assert!(
        refresh
            .freshness
            .expect("post-progress failure")
            .as_str()
            .contains("saved progress remains")
    );
    assert!(
        refresh
            .distinction
            .as_str()
            .contains("Terminal desired intent is not current provider truth")
    );
    let bounded = render_convergence(ConvergenceInput {
        mailbox: MailboxRefresh::Bounded,
        catalog: CatalogRefresh::NotAttempted,
        bodies: BodyRefresh::NotRun,
        freshness_update_failed: false,
    });
    assert!(bounded.mailbox.as_str().contains("may still be stale"));
    let readonly = render_account(account(Capability::ReadOnly, Authority::Current));
    assert!(readonly.limitation.as_str().contains("explicit upgrade"));
    let revoked = render_account(account(Capability::Modify, Authority::RevocationOnly));
    assert!(
        revoked
            .authority
            .as_str()
            .contains("cannot access the mailbox")
    );
    assert!(
        render_recovery(RecoveryNotice::PendingCommandsBlockMaintenance)
            .as_str()
            .contains("Pending commands block cache reset and removal")
    );
}

#[test]
fn provider_field_and_list_bounds_are_visible_without_unbounded_output() {
    let long = "界".repeat(MAX_FIELD_INPUT_BYTES);
    let label = LabelInput {
        name: Some(&long),
        identifier: &long,
    };
    let displayed = render_label(label);
    assert_eq!(displayed.name.as_str().chars().count(), MAX_NAME_CHARS + 1);
    assert_eq!(
        displayed.identifier.as_str().chars().count(),
        MAX_IDENTIFIER_CHARS + 1
    );
    assert!(displayed.name.as_str().ends_with('…'));
    let labels = vec![label; MAX_LABELS_SHOWN + 2];
    let pending = vec![
        PendingInput {
            status: PendingStatus::Ambiguous,
            desired: DesiredMessage {
                add_labels: &labels,
                ..DesiredMessage::default()
            }
        };
        MAX_PENDING_SHOWN + 1
    ];
    let state = render_message_state(MessageStateInput {
        capability: Capability::Modify,
        legacy_unread: false,
        observed: ObservedState::Known(ObservedMessage {
            unread: false,
            starred: false,
            folders: Folders::default(),
            labels: &labels,
        }),
        pending: &pending,
    });
    assert_eq!(state.labels.len(), MAX_LABELS_SHOWN);
    assert_eq!(state.omitted_labels, 2);
    assert_eq!(state.pending.len(), MAX_PENDING_SHOWN);
    assert_eq!(state.omitted_pending, 1);
    assert_eq!(state.pending[0].changes.len(), MAX_LABELS_SHOWN);
    assert_eq!(state.pending[0].omitted_labels, 2);
    let commands = vec![command(CommandStatus::Queued, counts(1, 0, 0, 0)); MAX_COMMANDS_SHOWN + 3];
    let queue = render_account_commands(account(Capability::Modify, Authority::Missing), &commands);
    assert_eq!(queue.commands.len(), MAX_COMMANDS_SHOWN);
    assert_eq!(queue.omitted, 3);
}
