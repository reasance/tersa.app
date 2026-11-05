// This Source Code Form is subject to the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Required production runtime dispatch for the ordered TUI control protocol.

use crate::tui::control::{ControlJob, ControlResult, Durable, ProgressSink};
use std::sync::Arc;
use tersa_application::{command_coordinator::CommandWritePolicy, mailbox::AccountId};
use tersa_presentation::terminal::SafeText;
use tersa_sync_runtime::Runtime;

pub(super) async fn run(
    runtime: &Arc<Runtime>,
    account: &AccountId,
    job: ControlJob,
    progress: &ProgressSink,
) -> Result<ControlResult, String> {
    if progress.stopped() {
        return Err("Work stopped before admission; no durable receipt was published.".to_owned());
    }
    match job {
        ControlJob::Admit { intent, resume } => {
            let outcome = runtime
                .admit_command(account, &intent)
                .await
                .map_err(|error| error.to_string())?;
            changed(
                runtime,
                account,
                Durable::from_admission(&outcome),
                resume.then_some(CommandWritePolicy::Automatic),
                progress,
            )
            .await
        }
        ControlJob::Undo {
            expected_source,
            resume,
        } => {
            let outcome = runtime
                .admit_undo_for(account, &expected_source)
                .await
                .map_err(|error| error.to_string())?;
            changed(
                runtime,
                account,
                Durable::from_admission(&outcome),
                resume.then_some(CommandWritePolicy::Automatic),
                progress,
            )
            .await
        }
        ControlJob::Cancel(stamp) => {
            let receipt = runtime
                .cancel_command(account, &stamp)
                .await
                .map_err(|error| error.to_string())?;
            changed(
                runtime,
                account,
                Durable::Cancelled(receipt),
                None,
                progress,
            )
            .await
        }
        ControlJob::Abandon {
            stamp,
            confirmation,
        } => {
            let receipt = runtime
                .abandon_command(account, &stamp, confirmation)
                .await
                .map_err(|error| error.to_string())?;
            changed(
                runtime,
                account,
                Durable::Abandoned(receipt),
                None,
                progress,
            )
            .await
        }
        ControlJob::AuthorizeRetry { stamp, resume } => {
            let receipt = retry_receipt(runtime, account, &stamp).await?;
            changed(
                runtime,
                account,
                Durable::RetryAuthorized(receipt),
                resume,
                progress,
            )
            .await
        }
        ControlJob::Status => runtime
            .command_status(account)
            .await
            .map(ControlResult::Status)
            .map_err(|error| error.to_string()),
        ControlJob::Catalog { refresh } => catalog(runtime, account, refresh).await,
        ControlJob::Drive(policy) => runtime
            .drive_commands(account, policy.as_ref())
            .await
            .map(ControlResult::Driven)
            .map_err(|error| error.to_string()),
        ControlJob::Upgrade => authorize(runtime, account, true, progress).await,
        ControlJob::Reconnect => authorize(runtime, account, false, progress).await,
    }
}
async fn catalog(
    runtime: &Runtime,
    account: &AccountId,
    refresh: bool,
) -> Result<ControlResult, String> {
    if refresh {
        runtime
            .refresh_label_catalog(account)
            .await
            .map(|catalog| ControlResult::Catalog(Some(catalog)))
            .map_err(|error| error.to_string())
    } else {
        runtime
            .cached_label_catalog(account)
            .map(ControlResult::Catalog)
            .map_err(|error| error.to_string())
    }
}
async fn changed(
    runtime: &Runtime,
    account: &AccountId,
    durable: Durable,
    policy: Option<CommandWritePolicy>,
    progress: &ProgressSink,
) -> Result<ControlResult, String> {
    progress.durable(durable.clone());
    let online = if progress.stopped() {
        None
    } else if let Some(policy) = policy {
        Some(
            runtime
                .drive_commands(account, Some(&policy))
                .await
                .map_err(|error| SafeText::single_line(&error.to_string())),
        )
    } else {
        None
    };
    Ok(ControlResult::Changed { durable, online })
}

async fn authorize(
    runtime: &Runtime,
    account: &AccountId,
    upgrade: bool,
    progress: &ProgressSink,
) -> Result<ControlResult, String> {
    let callback = |url: &str| {
        if progress.authorization(url) && !progress.stopped() {
            let _ = crate::browser::launch(url);
        }
    };
    let result = if upgrade {
        runtime.upgrade_account(account, callback).await
    } else {
        runtime.reconnect_account(account, callback).await
    };
    let added = result.map_err(|error| error.to_string())?;
    let durable = Durable::GrantReplaced(added.account);
    progress.durable(durable.clone());
    let legacy_sync = added
        .first_sync
        .map(|report| {
            SafeText::single_line(&format!(
                "Compatibility snapshot: {}.",
                super::describe_report(report)
            ))
        })
        .map_err(|error| {
            SafeText::single_line(&format!(
                "Grant saved; compatibility snapshot failed: {error}."
            ))
        });
    let history = if legacy_sync.is_ok() && !progress.stopped() {
        Some(
            super::history::cycle(runtime, account)
                .await
                .map(|report| report.notice),
        )
    } else {
        None
    };
    Ok(ControlResult::Authorized {
        durable,
        legacy_sync,
        history,
    })
}

async fn retry_receipt(
    runtime: &Runtime,
    account: &AccountId,
    stamp: &tersa_application::command::CommandStamp,
) -> Result<tersa_application::command::RetryAuthorization, String> {
    // A saved unused ticket can survive an offline follow-up. Reuse
    // only the exact selected store revision, never silently select a
    // newer command or authorize an additional ticket.
    let current = runtime
        .command_lookup(account, stamp.key().command_id())
        .await
        .map_err(|error| error.to_string())?;
    let receipt = match current {
        Some(tersa_application::command::RetainedCommand::Full(snapshot))
            if snapshot.stamp() == stamp =>
        {
            match snapshot.retry_authorization() {
                Some(ticket) => ticket.clone(),
                None => runtime
                    .authorize_command_retry(account, stamp)
                    .await
                    .map_err(|error| error.to_string())?,
            }
        }
        _ => {
            return Err(
                "The selected command changed; reload queue status before retrying.".to_owned(),
            );
        }
    };
    Ok(receipt)
}
