// This Source Code Form is subject to the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Truthful bounded History reporting and one optional command recovery pass.

use tersa_application::{
    AccountCapability,
    command_coordinator::{CommandDriveStop, CommandWritePolicy},
    history_sync::HistorySyncStop,
    mailbox::AccountId,
};
use tersa_presentation::{
    terminal::SafeText,
    triage::{self as p8, BodyRefresh, CatalogRefresh, ConvergenceInput, MailboxRefresh},
};
use tersa_sync_runtime::{AccountHistoryReport, Runtime};

pub(super) fn describe(report: &AccountHistoryReport) -> SafeText {
    let mailbox = match report.metadata.stop() {
        HistorySyncStop::CaughtUp => MailboxRefresh::CaughtUp,
        HistorySyncStop::SnapshotCommitted(_) => MailboxRefresh::RecentSnapshot,
        HistorySyncStop::Bounded(_) => MailboxRefresh::Bounded,
        HistorySyncStop::RecoveryRequired(_) => MailboxRefresh::Failed,
    };
    let count = u16::try_from(report.bodies.cached).unwrap_or(u16::MAX);
    let bodies = if report.bodies.skipped {
        BodyRefresh::NotRun
    } else if report.bodies.failure.is_some() {
        BodyRefresh::Failed(count)
    } else {
        BodyRefresh::Finished(count)
    };
    let doc = p8::render_convergence(ConvergenceInput {
        mailbox,
        catalog: CatalogRefresh::NotAttempted,
        bodies,
        freshness_update_failed: report.freshness.as_ref().is_some_and(Result::is_err),
    });
    let progress = report.metadata.progress();
    SafeText::single_line(&format!(
        "{} {} {} History records saved: {}; snapshot messages saved: {}.",
        doc.mailbox,
        doc.bodies,
        doc.freshness
            .map_or_else(String::new, |value| value.to_string()),
        progress.records_committed,
        progress.snapshot_messages_committed
    ))
}

pub(super) struct CycleReport {
    pub notice: SafeText,
    pub complete: bool,
}
impl std::fmt::Display for CycleReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.notice.fmt(f)
    }
}

/// One History cycle and at most one coordinator pass; never drains a queue.
pub(super) async fn cycle(runtime: &Runtime, account: &AccountId) -> Result<CycleReport, SafeText> {
    let history = runtime
        .sync_history(account)
        .await
        .map_err(|error| SafeText::single_line(&error.to_string()))?;
    let text = describe(&history);
    if matches!(
        history.metadata.stop(),
        HistorySyncStop::RecoveryRequired(_)
    ) || history.bodies.failure.is_some()
        || history.freshness.as_ref().is_some_and(Result::is_err)
    {
        return Err(text);
    }
    let mut complete = matches!(history.metadata.stop(), HistorySyncStop::CaughtUp);
    let mut suffix = String::new();
    match runtime.command_status(account).await {
        Ok(status) if !status.pending.is_empty() => {
            let policy = CommandWritePolicy::Automatic;
            let write =
                (status.metadata.capability() == AccountCapability::Modify).then_some(&policy);
            match runtime.drive_commands(account, write).await {
                Ok(report) => {
                    complete &= status.pending.len() <= 1
                        && matches!(
                            report.command.stop(),
                            CommandDriveStop::Idle | CommandDriveStop::Terminal
                        );
                    suffix = match report.command.stop() {
                        CommandDriveStop::Idle => "No pending command work.".to_owned(),
                        CommandDriveStop::Terminal => {
                            "One command reached a terminal result; cached refresh is separate."
                                .to_owned()
                        }
                        CommandDriveStop::ObservationOnly => {
                            "One command observed; no write attempted.".to_owned()
                        }
                        CommandDriveStop::AwaitingObservation => {
                            "One command attempt saved; fresh observation remains required."
                                .to_owned()
                        }
                        CommandDriveStop::Attention(_) => {
                            "Command recovery needs attention; automatic work stopped.".to_owned()
                        }
                        CommandDriveStop::RecoveryRequired(_) => {
                            "Command recovery failed; durable evidence is retained.".to_owned()
                        }
                    };
                    if let Some(refresh) = report.convergence {
                        if let Ok(history) = &refresh.history {
                            complete &=
                                matches!(history.metadata.stop(), HistorySyncStop::CaughtUp);
                            suffix.push(' ');
                            suffix.push_str(describe(history).as_str());
                        }
                        if refresh.catalog.is_err()
                            || !refresh.history.as_ref().is_ok_and(|r| {
                                !matches!(r.metadata.stop(), HistorySyncStop::RecoveryRequired(_))
                                    && r.bodies.failure.is_none()
                            })
                        {
                            return Err(SafeText::single_line(&format!(
                                "{text} {suffix} Cached command-result refresh failed or remains incomplete."
                            )));
                        }
                    }
                    if matches!(report.command.stop(), CommandDriveStop::RecoveryRequired(_)) {
                        return Err(SafeText::single_line(&format!("{text} {suffix}")));
                    }
                }
                Err(error) => {
                    return Err(SafeText::single_line(&format!(
                        "{text} Command work stopped: {error}. Existing intent is retained."
                    )));
                }
            }
        }
        Ok(_) => {}
        Err(_) => {
            complete = false;
            suffix.push_str("Command status is unavailable; no command dispatch was started.");
        }
    }
    Ok(CycleReport {
        notice: SafeText::single_line(&format!("{text} {suffix}")),
        complete,
    })
}
