// This Source Code Form is subject to the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Bounded ordered account work for P9b callers, without implied durable admission.
//!
//! A submitted request is only in memory. Durable progress is published after the
//! runtime receipt. On shutdown unstarted requests are not admitted, and started
//! requests without a consumed final result require a durable-status reload.
//! Cancellation never means command Cancel/Abandon or provider rollback.

use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
    mpsc::Sender,
};
use tersa_application::{
    command::{
        AbandonConfirmation, CommandAdmissionOutcome, CommandStamp, RetryAuthorization,
        TerminalCommandSummary,
    },
    command_coordinator::CommandWritePolicy,
    mailbox::AccountId,
    mailbox_state::LabelCatalog,
};
use tersa_presentation::terminal::SafeText;
use tersa_sync_runtime::{AccountCommandReport, AccountCommandStatus, CommandIntent};

/// Counts queued, running AND completed-but-unconsumed requests per account.
pub const MAX_CONTROLS: usize = 4;
const MAX_PROGRESS: usize = 2;
const MAX_AUTH_LINK_BYTES: usize = 16 * 1024;

/// Exact work; caller retains typed targets and captured dialog/view epoch.
#[expect(
    dead_code,
    reason = "P9b adds user menu submitters; P9a exhaustively wires these required runtime operations"
)]
#[derive(Clone, Debug)]
pub enum ControlJob {
    Admit {
        intent: CommandIntent,
        resume: bool,
    },
    Undo {
        resume: bool,
    },
    Cancel(CommandStamp),
    Abandon {
        stamp: CommandStamp,
        confirmation: AbandonConfirmation,
    },
    AuthorizeRetry {
        stamp: CommandStamp,
        resume: Option<CommandWritePolicy>,
    },
    Status,
    Catalog {
        refresh: bool,
    },
    Drive(Option<CommandWritePolicy>),
    Upgrade,
    Reconnect,
}
/// Durable receipt is distinct from submission and any later online failure.
#[derive(Clone, Debug)]
pub enum Durable {
    Admitted(CommandStamp),
    Cancelled(TerminalCommandSummary),
    Abandoned(TerminalCommandSummary),
    RetryAuthorized(RetryAuthorization),
    GrantReplaced(AccountId),
}
impl Durable {
    pub fn from_admission(value: &CommandAdmissionOutcome) -> Self {
        let stamp = match value {
            CommandAdmissionOutcome::Admitted(snapshot)
            | CommandAdmissionOutcome::Retained(
                tersa_application::command::RetainedCommand::Full(snapshot),
            ) => snapshot.stamp(),
            CommandAdmissionOutcome::Retained(
                tersa_application::command::RetainedCommand::Terminal(summary),
            ) => summary.stamp(),
        };
        Self::Admitted(stamp.clone())
    }
    fn owner(&self) -> &AccountId {
        match self {
            Self::Admitted(stamp) => stamp.key().account_id(),
            Self::Cancelled(summary) | Self::Abandoned(summary) => {
                summary.stamp().key().account_id()
            }
            Self::RetryAuthorized(ticket) => ticket.stamp().key().account_id(),
            Self::GrantReplaced(account) => account,
        }
    }
    pub fn notice(&self) -> SafeText {
        use tersa_presentation::triage::render_identifier;
        let (kind, id) = match self {
            Self::Admitted(stamp) => ("Intent durably admitted", stamp.key().command_id().as_str()),
            Self::Cancelled(summary) => (
                "Local queued intent cancelled",
                summary.stamp().key().command_id().as_str(),
            ),
            Self::Abandoned(summary) => (
                "Warned Abandon saved; no rollback is claimed",
                summary.stamp().key().command_id().as_str(),
            ),
            Self::RetryAuthorized(ticket) => (
                "Explicit retry authorization saved",
                ticket.stamp().key().command_id().as_str(),
            ),
            Self::GrantReplaced(account) => ("Account grant saved", account.as_str()),
        };
        SafeText::single_line(&format!("{kind}: {}.", render_identifier(id)))
    }
}
/// One final result. A durable receipt is retained even if online work failed.
#[derive(Debug)]
pub enum ControlResult {
    Changed {
        durable: Durable,
        online: Option<Result<AccountCommandReport, SafeText>>,
    },
    Status(AccountCommandStatus),
    Catalog(Option<LabelCatalog>),
    Driven(AccountCommandReport),
    Authorized {
        durable: Durable,
        legacy_sync: Result<SafeText, SafeText>,
        history: Option<Result<SafeText, SafeText>>,
    },
}
/// Immutable request binding; late results cannot retarget another account/view/dialog.
#[derive(Clone, Debug)]
pub struct Binding {
    pub account: AccountId,
    pub request: u64,
    pub epoch: u64,
}
#[derive(Debug)]
pub enum Progress {
    Durable(Durable),
    AuthorizationLink(SafeText),
}
#[derive(Debug)]
pub enum ControlEvent {
    Progress(Binding, Progress),
    Finished(Binding, Result<Box<ControlResult>, SafeText>),
}
impl ControlEvent {
    pub fn valid_owner(&self) -> bool {
        let account = &self.binding().account;
        match self {
            Self::Progress(_, Progress::Durable(receipt)) => receipt.owner() == account,
            Self::Finished(_, Ok(result)) => result.valid_owner(account),
            _ => true,
        }
    }
    pub fn binding(&self) -> &Binding {
        match self {
            Self::Progress(binding, _) | Self::Finished(binding, _) => binding,
        }
    }
}
/// Only the worker can construct a sink; callbacks cannot change its target binding.
#[derive(Clone)]
pub struct ProgressSink {
    pub(super) binding: Binding,
    pub(super) outgoing: Sender<super::worker::Done>,
    pub(super) stopping: Arc<AtomicBool>,
    pub(super) emitted: Arc<AtomicUsize>,
}
impl ProgressSink {
    pub fn stopped(&self) -> bool {
        self.stopping.load(Ordering::SeqCst)
    }
    fn emit(&self, progress: Progress) -> bool {
        if self.stopped() || self.emitted.fetch_add(1, Ordering::SeqCst) >= MAX_PROGRESS {
            return false;
        }
        self.outgoing
            .send(super::worker::Done::Control(ControlEvent::Progress(
                self.binding.clone(),
                progress,
            )))
            .is_ok()
    }
    pub fn durable(&self, receipt: Durable) {
        if receipt.owner() == &self.binding.account {
            let _ = self.emit(Progress::Durable(receipt));
        }
    }
    /// A full bounded trusted authorization URL, never a truncated actionable link.
    pub fn authorization(&self, url: &str) -> bool {
        url.len() <= MAX_AUTH_LINK_BYTES
            && self.emit(Progress::AuthorizationLink(SafeText::single_line(url)))
    }
}

impl ControlResult {
    fn valid_owner(&self, account: &AccountId) -> bool {
        let report_owner = |report: &AccountCommandReport| {
            report
                .command
                .snapshot()
                .is_none_or(|snapshot| snapshot.command().account_id() == account)
        };
        match self {
            Self::Changed { durable, online } => {
                durable.owner() == account
                    && online.as_ref().is_none_or(|value| match value {
                        Ok(report) => report_owner(report),
                        Err(_) => true,
                    })
            }
            Self::Status(status) => status.metadata.account_id() == account,
            Self::Catalog(catalog) => catalog
                .as_ref()
                .is_none_or(|catalog| catalog.account_id() == account),
            Self::Driven(report) => report_owner(report),
            Self::Authorized { durable, .. } => durable.owner() == account,
        }
    }
    pub fn notice(&self) -> SafeText {
        match self {
            Self::Changed { durable, online } => {
                let suffix = match online {
                    None => "No follow-up online attempt was run.".to_owned(),
                    Some(Err(error)) => format!(
                        "Online follow-up failed: {error}. The durable receipt remains saved."
                    ),
                    Some(Ok(report)) => command_notice(report).to_string(),
                };
                SafeText::single_line(&format!("{} {suffix}", durable.notice()))
            }
            Self::Status(status) => {
                use tersa_presentation::triage as p8;
                let capability = if status.metadata.capability()
                    == tersa_application::AccountCapability::Modify
                {
                    p8::Capability::Modify
                } else {
                    p8::Capability::ReadOnly
                };
                let authority = match status.credential {
                    tersa_sync_runtime::CredentialPurpose::Missing => p8::Authority::Missing,
                    tersa_sync_runtime::CredentialPurpose::RevocationOnly => {
                        p8::Authority::RevocationOnly
                    }
                    tersa_sync_runtime::CredentialPurpose::Active => p8::Authority::Unavailable,
                };
                let doc = p8::render_account(p8::AccountInput {
                    name: status
                        .metadata
                        .email()
                        .map_or(status.metadata.account_id().as_str(), |email| {
                            email.as_str()
                        }),
                    identifier: status.metadata.account_id().as_str(),
                    capability,
                    authority,
                });
                SafeText::single_line(&format!(
                    "{}: {}; {} Pending: {}; saved terminal results: {}; conditional Undo source retained: {}. {}",
                    doc.name,
                    doc.capability,
                    doc.authority,
                    status.pending.len(),
                    status.terminal.summaries().len(),
                    status.undo.is_some(),
                    if status.lifecycle.recovery().is_some() {
                        "Account recovery remains unresolved."
                    } else {
                        ""
                    }
                ))
            }
            Self::Catalog(catalog) => SafeText::single_line(&catalog.as_ref().map_or_else(
                || "Label catalog is unknown.".to_owned(),
                |catalog| {
                    format!(
                        "Observed label catalog: {} definitions.",
                        catalog.definitions().len()
                    )
                },
            )),
            Self::Driven(report) => command_notice(report),
            Self::Authorized {
                durable,
                legacy_sync,
                history,
            } => {
                let compatibility = match legacy_sync {
                    Ok(text) | Err(text) => text,
                };
                let history = match history {
                    None => "History follow-up was not run.".to_owned(),
                    Some(Ok(text)) => text.to_string(),
                    Some(Err(text)) => format!("History follow-up failed: {text}"),
                };
                SafeText::single_line(&format!("{} {compatibility} {history}", durable.notice()))
            }
        }
    }
}
fn command_notice(report: &AccountCommandReport) -> SafeText {
    use tersa_application::command::MailboxCommandStatus as Status;
    use tersa_presentation::triage as p8;
    let Some(snapshot) = report.command.snapshot() else {
        return SafeText::single_line("No command snapshot was changed; inspect account status.");
    };
    let status = match snapshot.status() {
        Status::Queued => p8::CommandStatus::Queued,
        Status::Dispatching => p8::CommandStatus::Dispatching,
        Status::Ambiguous => p8::CommandStatus::Ambiguous,
        Status::NeedsAttention => p8::CommandStatus::NeedsAttention,
        Status::Complete => p8::CommandStatus::Complete,
        Status::Partial => p8::CommandStatus::Partial,
        Status::Cancelled => p8::CommandStatus::Cancelled,
        Status::Abandoned => p8::CommandStatus::Abandoned,
    };
    let counts = snapshot.counts();
    let Ok(counts) = p8::OutcomeCounts::new(
        counts.total(),
        counts.satisfied(),
        counts.target_missing(),
        counts.failed(),
    ) else {
        return SafeText::single_line(
            "Command result saved; outcome counts could not be displayed.",
        );
    };
    let doc = p8::render_command(p8::CommandInput {
        identifier: snapshot.command().id().as_str(),
        kind: if matches!(
            snapshot.command().kind(),
            tersa_application::command::MailboxCommandKind::Compensate(_)
        ) {
            p8::CommandKind::ConditionalUndo
        } else {
            p8::CommandKind::MessageChanges
        },
        status,
        counts,
    });
    let convergence = report.convergence.as_ref().map_or("", |result| {
        if result.catalog.is_err() || result.history.as_ref().is_err() {
            " Cached view refresh failed separately."
        } else {
            " Cached History/catalog refresh has a separate bounded result."
        }
    });
    SafeText::single_line(&format!(
        "{}: {}. {} {}{convergence}",
        doc.identifier, doc.status, doc.outcomes, doc.notice
    ))
}
