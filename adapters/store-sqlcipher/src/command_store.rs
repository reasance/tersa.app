// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Owns atomic admission, lifecycle and retention for the account-local command queue.

use crate::{
    SqlCipherMailboxStore,
    cached::{check_fence, sql_error},
    command_codec::{self as codec, Body, Header},
    pins,
};
use rusqlite::{Connection, Transaction, TransactionBehavior, params};
use tersa_application::{
    command::{
        AbandonConfirmation, CommandAdmission, CommandAdmissionOutcome, CommandCategory,
        CommandKey, CommandPrecondition, CommandReconciliation, CommandSnapshot, CommandStamp,
        DispatchPreparation, DispatchReceipt, MAX_PENDING_COMMANDS, MAX_PENDING_TARGET_REFERENCES,
        MailboxCommandStore, ReconciliationFailure, RemoteCommandOutcome, RetainedCommand,
        RetryAuthorization, TerminalCommandSummary, TerminalSummaries, UndoAdmission,
        UndoCandidate,
    },
    mailbox::BoxFuture,
    mailbox_state::TriageStoreError as Error,
    profile::AccountFence,
};
use tersa_domain::{
    command::{
        CommandItemOutcome, MailboxCommand, MailboxCommandId, MailboxCommandKind,
        MailboxCommandStatus, MailboxField,
    },
    mailbox::AccountId,
};

mod dispatch;

pub(super) fn write<T>(
    store: &SqlCipherMailboxStore,
    fence: &AccountFence,
    operation: impl FnOnce(&Transaction<'_>) -> Result<T, Error>,
) -> Result<T, Error> {
    if fence.account_id() != &store.account {
        return Err(Error::UnknownAccount);
    }
    let mut connection = store.connection.lock().map_err(|_error| Error::Storage)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sql_error)?;
    check_fence(&transaction, fence)?;
    let value = operation(&transaction)?;
    transaction.commit().map_err(sql_error)?;
    Ok(value)
}
fn read<T>(
    store: &SqlCipherMailboxStore,
    fence: &AccountFence,
    operation: impl FnOnce(&Transaction<'_>) -> Result<T, Error>,
) -> Result<T, Error> {
    if fence.account_id() != &store.account {
        return Err(Error::UnknownAccount);
    }
    store.with_cached_read_transaction(|transaction, _| {
        check_fence(transaction, fence)?;
        operation(transaction)
    })
}
pub(super) fn authority(connection: &Connection) -> Result<(), Error> {
    let (capability, recovery): (i64, Option<i64>) = connection.query_row("SELECT capability,(SELECT disconnect_recovery FROM account_lifecycle WHERE singleton = 1) FROM account_binding WHERE singleton = 1",[],|r| Ok((r.get(0)?,r.get(1)?))).map_err(sql_error)?;
    if capability != 1 {
        return Err(Error::ReadOnly);
    }
    if recovery.is_some() {
        return Err(Error::NotEligible);
    }
    Ok(())
}
pub(super) fn queue(connection: &Connection, account: &AccountId) -> Result<Vec<Header>, Error> {
    pins::read(connection, account)?;
    let headers = codec::headers(connection, account)?;
    let summaries = codec::summaries(connection, account)?;
    let next: i64 = connection
        .query_row(
            "SELECT next_fifo FROM mailbox_checkpoint WHERE singleton = 1",
            [],
            |r| r.get(0),
        )
        .map_err(sql_error)?;
    if next < 1
        || headers.iter().any(|h| h.fifo >= next)
        || summaries.iter().any(|(fifo, _)| *fifo >= next)
    {
        return Err(Error::Corrupt);
    }
    for header in &headers {
        if let Some((fifo, summary)) = summaries
            .iter()
            .find(|(_, s)| s.stamp().key().command_id() == &header.id)
            && (!header.status.is_terminal()
                || *fifo != header.fifo
                || summary.stamp().revision() != header.revision
                || summary.status() != header.status)
        {
            return Err(Error::Corrupt);
        }
        if let Some((_, summary)) = summaries
            .iter()
            .find(|(_, s)| s.stamp().key().command_id() == &header.id)
        {
            let total: i64 = connection
                .query_row(
                    "SELECT count(*) FROM command_items WHERE command_id=?1",
                    [header.id.as_str()],
                    |r| r.get(0),
                )
                .map_err(sql_error)?;
            if summary.category() != CommandCategory::MessageState
                || i64::from(summary.counts().total()) != total
            {
                return Err(Error::Corrupt);
            }
        }
        if summaries
            .iter()
            .any(|(fifo, s)| *fifo == header.fifo && s.stamp().key().command_id() != &header.id)
        {
            return Err(Error::Corrupt);
        }
    }
    Ok(headers)
}
pub(super) fn current(
    connection: &Connection,
    expected: &CommandPrecondition,
    fifo: bool,
) -> Result<Body, Error> {
    let mut headers = queue(connection, expected.fence().account_id())?;
    let index = headers
        .iter()
        .position(|h| &h.id == expected.stamp().key().command_id())
        .ok_or(Error::NotEligible)?;
    let header = headers.remove(index);
    if header.revision != expected.stamp().revision() {
        return Err(Error::Conflict);
    }
    if header.status.is_terminal() {
        return Err(Error::NotEligible);
    }
    if fifo
        && headers
            .iter()
            .any(|h| !h.status.is_terminal() && h.fifo < header.fifo)
    {
        return Err(Error::Conflict);
    }
    codec::body(connection, expected.fence().account_id(), header)
}
pub(super) fn advance(body: &mut Body) -> Result<(), Error> {
    body.header.revision = body
        .header
        .revision
        .checked_add(1)
        .ok_or(Error::NotEligible)?;
    if body.header.retry.is_some() {
        body.header.retry = Some(body.header.revision);
    }
    Ok(())
}
pub(super) fn save(connection: &Connection, body: &Body) -> Result<(), Error> {
    let h = &body.header;
    connection.execute("UPDATE mailbox_commands SET revision=?2,status=?3,automatic_attempts=?4,retry_revision=?5,duplicate_risk=?6,dispatch_started=?7,dispatch_revision=?8,dispatch_authorization=?9,compensation_guard_revision=?10,dispatch_fact=?11,dispatch_label_id=?12,dispatch_label_name=?13,label_observation=?14,reconciliation_failure=?15,label_progress=?16,create_matches=?17,observed_label_id=?18,observed_label_name=?19 WHERE command_id=?1",
        params![h.id.as_str(),h.revision.to_be_bytes(),codec::status_code(h.status),h.attempts,h.retry.map(u64::to_be_bytes),h.duplicate_risk,h.dispatch.is_some(),h.dispatch.map(u64::to_be_bytes),h.authorization,h.guard.map(u64::to_be_bytes),h.fact,h.dispatch_label.as_ref().map(|l| l.id().as_str()),h.dispatch_label.as_ref().map(|l| l.name().as_str()),h.label_observation,h.failure,h.label_progress,h.matches,h.observed_label.as_ref().map(|l| l.id().as_str()),h.observed_label.as_ref().map(|l| l.name().as_str())]).map_err(sql_error)?;
    for item in &body.items {
        let observation = item.observation.as_ref().map(|v| {
            i64::from(matches!(
                v,
                tersa_application::mailbox_state::RemoteMessageState::Known(_)
            ))
        });
        let outcome = item.outcome.map(|o| match o {
            CommandItemOutcome::DesiredStateObserved => 0,
            CommandItemOutcome::TargetMissing => 1,
            CommandItemOutcome::Failed => 2,
        });
        connection.execute("UPDATE command_items SET outcome=?3,observation=?4,dispatch_selected=?5 WHERE command_id=?1 AND message_id=?2",params![h.id.as_str(),item.id.as_str(),outcome,observation,item.selected]).map_err(sql_error)?;
        connection
            .execute(
                "DELETE FROM command_item_memberships WHERE command_id=?1 AND message_id=?2",
                params![h.id.as_str(), item.id.as_str()],
            )
            .map_err(sql_error)?;
        if let Some(tersa_application::mailbox_state::RemoteMessageState::Known(labels)) =
            &item.observation
        {
            for label in labels.ids() {
                connection
                    .execute(
                        "INSERT INTO command_item_memberships VALUES (?1,?2,?3)",
                        params![h.id.as_str(), item.id.as_str(), label.as_str()],
                    )
                    .map_err(sql_error)?;
            }
        }
        for (index, field) in item.desired.memberships().iter().enumerate() {
            connection.execute("UPDATE command_fields SET pre_state=?4,post_state=?5 WHERE command_id=?1 AND message_id=?2 AND field_id=?3",params![h.id.as_str(),item.id.as_str(),codec::field_id(field.field()),item.pre.as_ref().map(|s| s.memberships()[index].is_present()),item.post.as_ref().map(|s| s.memberships()[index].is_present())]).map_err(sql_error)?;
        }
    }
    Ok(())
}
fn retained(
    connection: &Connection,
    account: &AccountId,
    id: &MailboxCommandId,
) -> Result<Option<RetainedCommand>, Error> {
    let headers = queue(connection, account)?;
    if let Some(header) = headers.into_iter().find(|h| &h.id == id) {
        return Ok(Some(RetainedCommand::Full(Box::new(
            codec::body(connection, account, header)?.snapshot(account)?,
        ))));
    }
    codec::no_orphans(connection, id.as_str())?;
    Ok(codec::summaries(connection, account)?
        .into_iter()
        .find(|(_, s)| s.stamp().key().command_id() == id)
        .map(|(_, s)| RetainedCommand::Terminal(s)))
}
fn insert(
    connection: &Connection,
    command: &MailboxCommand,
    source: Option<&CommandStamp>,
) -> Result<CommandSnapshot, Error> {
    if matches!(command.kind(), MailboxCommandKind::Compensate(_)) != source.is_some() {
        return Err(Error::NotEligible);
    }
    let headers = queue(connection, command.account_id())?;
    let count = headers.iter().filter(|h| !h.status.is_terminal()).count();
    let refs: i64 = connection.query_row("SELECT count(*) FROM command_items WHERE command_id IN (SELECT command_id FROM mailbox_commands WHERE status < 4)",[],|r| r.get(0)).map_err(sql_error)?;
    let targets: Vec<_> = match command.kind() {
        MailboxCommandKind::MessageState { targets, desired } => {
            targets.ids().iter().map(|id| (id, desired, None)).collect()
        }
        MailboxCommandKind::Compensate(batch) => batch
            .items()
            .iter()
            .map(|i| {
                (
                    i.message_id(),
                    i.condition().restore_state(),
                    Some(i.condition().expected_post_state()),
                )
            })
            .collect(),
        _ => Vec::new(),
    };
    if count >= MAX_PENDING_COMMANDS
        || usize::try_from(refs)
            .map_err(|_error| Error::Corrupt)?
            .checked_add(targets.len())
            .ok_or(Error::Corrupt)?
            > MAX_PENDING_TARGET_REFERENCES
    {
        return Err(Error::QuotaExceeded);
    }
    let fifo: i64 = connection
        .query_row(
            "SELECT next_fifo FROM mailbox_checkpoint WHERE singleton=1",
            [],
            |r| r.get(0),
        )
        .map_err(sql_error)?;
    let next = fifo.checked_add(1).ok_or(Error::NotEligible)?;
    let (kind, label, name) = match command.kind() {
        MailboxCommandKind::MessageState { .. } => (0, None, None),
        MailboxCommandKind::Compensate(_) => (1, None, None),
        MailboxCommandKind::CreateLabel(name) => (2, None, Some(name.as_str())),
        MailboxCommandKind::RenameLabel { label, name } => {
            (3, Some(label.id().as_str()), Some(name.as_str()))
        }
        MailboxCommandKind::DeleteLabel(label) => (4, Some(label.id().as_str()), None),
    };
    connection.execute("INSERT INTO mailbox_commands (command_id,revision,fifo,kind,status,label_id,label_name,undo_source_id,undo_source_revision) VALUES (?1,?2,?3,?4,0,?5,?6,?7,?8)",params![command.id().as_str(),0u64.to_be_bytes(),fifo,kind,label,name,source.map(|s| s.key().command_id().as_str()),source.map(|s| s.revision().to_be_bytes())]).map_err(sql_error)?;
    for (id, desired, expected) in targets {
        connection
            .execute(
                "INSERT INTO command_items (command_id,message_id) VALUES (?1,?2)",
                params![command.id().as_str(), id.as_str()],
            )
            .map_err(sql_error)?;
        for (index, field) in desired.memberships().iter().enumerate() {
            connection.execute("INSERT INTO command_fields (command_id,message_id,field_id,user_label,desired,expected_post_state) VALUES (?1,?2,?3,?4,?5,?6)",params![command.id().as_str(),id.as_str(),codec::field_id(field.field()),matches!(field.field(),MailboxField::UserLabel(_)),field.is_present(),expected.map(|v| v.memberships()[index].is_present())]).map_err(sql_error)?;
        }
    }
    connection
        .execute(
            "UPDATE mailbox_checkpoint SET next_fifo=?1 WHERE singleton=1",
            [next],
        )
        .map_err(sql_error)?;
    let header = codec::headers(connection, command.account_id())?
        .into_iter()
        .find(|h| &h.id == command.id())
        .ok_or(Error::Corrupt)?;
    codec::body(connection, command.account_id(), header)?.snapshot(command.account_id())
}
pub(super) fn finish(
    transaction: &Transaction<'_>,
    account: &AccountId,
    body: &Body,
) -> Result<TerminalCommandSummary, Error> {
    let snapshot = body.snapshot(account)?;
    let summary =
        TerminalCommandSummary::from_snapshot(&snapshot).map_err(|_error| Error::Corrupt)?;
    codec::summaries(transaction, account)?;
    save(transaction, body)?;
    let counts = summary.counts();
    let category = match summary.category() {
        CommandCategory::MessageState => 0,
        CommandCategory::Compensation => 1,
        CommandCategory::LabelDefinition => 2,
    };
    // The retained terminal disposition and subsequent guard/pin release share this commit.
    transaction
        .execute(
            "INSERT INTO terminal_commands VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![
                body.header.id.as_str(),
                body.header.revision.to_be_bytes(),
                body.header.fifo,
                codec::status_code(body.header.status),
                category,
                counts.total(),
                counts.satisfied(),
                counts.target_missing(),
                counts.failed()
            ],
        )
        .map_err(sql_error)?;
    if body.header.kind == 0 && body.header.status == MailboxCommandStatus::Complete {
        transaction
            .execute("DELETE FROM mailbox_undo", [])
            .map_err(sql_error)?;
        transaction
            .execute(
                "DELETE FROM mailbox_commands WHERE status >= 4 AND command_id != ?1",
                [body.header.id.as_str()],
            )
            .map_err(sql_error)?;
        transaction
            .execute(
                "INSERT INTO mailbox_undo VALUES (1,?1)",
                [body.header.id.as_str()],
            )
            .map_err(sql_error)?;
    } else {
        transaction
            .execute(
                "DELETE FROM mailbox_commands WHERE command_id=?1",
                [body.header.id.as_str()],
            )
            .map_err(sql_error)?;
    }
    transaction.execute("DELETE FROM terminal_commands WHERE command_id NOT IN (SELECT command_id FROM terminal_commands ORDER BY fifo DESC LIMIT 128)",[]).map_err(sql_error)?;
    // Cache lifetime is independent of command bodies; release only after retaining the disposition.
    let pins = pins::read(transaction, account)?;
    crate::history_store::prune_provider(transaction, account, &pins)?;
    Ok(summary)
}
fn candidate(connection: &Connection, account: &AccountId) -> Result<Option<UndoCandidate>, Error> {
    let headers = queue(connection, account)?;
    let Some(header) = headers
        .into_iter()
        .find(|h| h.status == MailboxCommandStatus::Complete)
    else {
        return Ok(None);
    };
    let body = codec::body(connection, account, header)?;
    codec::undo_from_body(account, &body).map(Some)
}

/// Validates bounded command relationships before an actual destructive lifecycle operation.
pub(crate) fn guard_lifecycle(connection: &Connection, account: &AccountId) -> Result<(), Error> {
    crate::store::triage_version(connection, account)?;
    let headers = queue(connection, account)?;
    let orphan: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM command_item_memberships AS m WHERE NOT EXISTS(SELECT 1 FROM command_items AS i WHERE i.command_id=m.command_id AND i.message_id=m.message_id))",[],|r| r.get(0)).map_err(sql_error)?;
    if orphan {
        return Err(Error::Corrupt);
    }
    for header in headers {
        let body = codec::body(connection, account, header)?;
        if !body.header.status.is_terminal() {
            return Err(Error::NotEligible);
        }
    }
    Ok(())
}

impl MailboxCommandStore for SqlCipherMailboxStore {
    fn admit<'a>(
        &'a self,
        request: &'a CommandAdmission,
    ) -> BoxFuture<'a, Result<CommandAdmissionOutcome, Error>> {
        Box::pin(async move {
            write(self, request.fence(), |tx| {
                if let Some(value) = retained(tx, &self.account, request.command().id())? {
                    return Ok(CommandAdmissionOutcome::Retained(value));
                }
                if matches!(request.command().kind(), MailboxCommandKind::Compensate(_)) {
                    return Err(Error::NotEligible);
                }
                authority(tx)?;
                Ok(CommandAdmissionOutcome::Admitted(Box::new(insert(
                    tx,
                    request.command(),
                    None,
                )?)))
            })
        })
    }
    fn admit_undo<'a>(
        &'a self,
        request: &'a UndoAdmission,
    ) -> BoxFuture<'a, Result<CommandAdmissionOutcome, Error>> {
        Box::pin(async move {
            write(self, request.fence(), |tx| {
                if let Some(value) = retained(tx, &self.account, request.command().id())? {
                    return Ok(CommandAdmissionOutcome::Retained(value));
                }
                authority(tx)?;
                if queue(tx, &self.account)?
                    .iter()
                    .any(|h| !h.status.is_terminal())
                    || candidate(tx, &self.account)?.as_ref() != Some(request.candidate())
                {
                    return Err(Error::NotEligible);
                }
                Ok(CommandAdmissionOutcome::Admitted(Box::new(insert(
                    tx,
                    request.command(),
                    Some(request.candidate().source()),
                )?)))
            })
        })
    }
    fn lookup<'a>(
        &'a self,
        fence: &'a AccountFence,
        key: &'a CommandKey,
    ) -> BoxFuture<'a, Result<Option<RetainedCommand>, Error>> {
        Box::pin(async move {
            if key.account_id() != &self.account {
                return Err(Error::UnknownAccount);
            }
            read(self, fence, |tx| {
                retained(tx, &self.account, key.command_id())
            })
        })
    }
    fn oldest_pending<'a>(
        &'a self,
        fence: &'a AccountFence,
    ) -> BoxFuture<'a, Result<Option<CommandSnapshot>, Error>> {
        Box::pin(async move {
            read(self, fence, |tx| {
                queue(tx, &self.account)?
                    .into_iter()
                    .find(|h| !h.status.is_terminal())
                    .map(|h| codec::body(tx, &self.account, h)?.snapshot(&self.account))
                    .transpose()
            })
        })
    }
    fn recover_dispatching<'a>(
        &'a self,
        expected: &'a CommandPrecondition,
    ) -> BoxFuture<'a, Result<CommandSnapshot, Error>> {
        Box::pin(async move {
            write(self, expected.fence(), |tx| {
                let mut body = current(tx, expected, true)?;
                if body.header.status != MailboxCommandStatus::Dispatching {
                    return Err(Error::NotEligible);
                }
                advance(&mut body)?;
                body.header.status = MailboxCommandStatus::Ambiguous;
                save(tx, &body)?;
                body.snapshot(&self.account)
            })
        })
    }
    fn prepare_dispatch<'a>(
        &'a self,
        request: &'a DispatchPreparation,
    ) -> BoxFuture<'a, Result<DispatchReceipt, Error>> {
        Box::pin(async move { dispatch::prepare(self, request) })
    }
    fn record_dispatch<'a>(
        &'a self,
        expected: &'a CommandPrecondition,
        outcome: &'a RemoteCommandOutcome,
    ) -> BoxFuture<'a, Result<CommandSnapshot, Error>> {
        Box::pin(async move { dispatch::record(self, expected, outcome) })
    }
    fn reconcile<'a>(
        &'a self,
        expected: &'a CommandPrecondition,
        observations: &'a CommandReconciliation,
    ) -> BoxFuture<'a, Result<CommandSnapshot, Error>> {
        Box::pin(async move { dispatch::reconcile(self, expected, observations) })
    }
    fn cancel_queued<'a>(
        &'a self,
        expected: &'a CommandPrecondition,
    ) -> BoxFuture<'a, Result<TerminalCommandSummary, Error>> {
        Box::pin(async move {
            write(self, expected.fence(), |tx| {
                let mut body = current(tx, expected, false)?;
                if body.header.status != MailboxCommandStatus::Queued
                    || body.header.dispatch.is_some()
                {
                    return Err(Error::NotEligible);
                }
                advance(&mut body)?;
                body.header.status = MailboxCommandStatus::Cancelled;
                body.header.retry = None;
                finish(tx, &self.account, &body)
            })
        })
    }
    fn authorize_retry<'a>(
        &'a self,
        expected: &'a CommandPrecondition,
    ) -> BoxFuture<'a, Result<RetryAuthorization, Error>> {
        Box::pin(async move {
            write(self, expected.fence(), |tx| {
                let mut body = current(tx, expected, true)?;
                if !matches!(
                    body.header.status,
                    MailboxCommandStatus::Ambiguous | MailboxCommandStatus::NeedsAttention
                ) || body.header.retry.is_some()
                {
                    return Err(Error::NotEligible);
                }
                advance(&mut body)?;
                body.header.retry = Some(body.header.revision);
                save(tx, &body)?;
                Ok(RetryAuthorization::from_store(
                    body.header.stamp(&self.account),
                ))
            })
        })
    }
    fn reconciliation_failed<'a>(
        &'a self,
        expected: &'a CommandPrecondition,
        failure: ReconciliationFailure,
    ) -> BoxFuture<'a, Result<CommandSnapshot, Error>> {
        Box::pin(async move {
            write(self, expected.fence(), |tx| {
                let mut body = current(tx, expected, true)?;
                advance(&mut body)?;
                body.header.status = MailboxCommandStatus::NeedsAttention;
                body.header.retry = None;
                body.header.failure = Some(match failure {
                    ReconciliationFailure::ReadUnavailable => 0,
                    ReconciliationFailure::InvalidEvidence => 1,
                    ReconciliationFailure::CompensationRefused => 2,
                });
                save(tx, &body)?;
                body.snapshot(&self.account)
            })
        })
    }
    fn abandon<'a>(
        &'a self,
        expected: &'a CommandPrecondition,
        _confirmation: AbandonConfirmation,
    ) -> BoxFuture<'a, Result<TerminalCommandSummary, Error>> {
        Box::pin(async move {
            write(self, expected.fence(), |tx| {
                let mut body = current(tx, expected, false)?;
                advance(&mut body)?;
                body.header.status = MailboxCommandStatus::Abandoned;
                body.header.retry = None;
                finish(tx, &self.account, &body)
            })
        })
    }
    fn undo_candidate<'a>(
        &'a self,
        fence: &'a AccountFence,
    ) -> BoxFuture<'a, Result<Option<UndoCandidate>, Error>> {
        Box::pin(async move { read(self, fence, |tx| candidate(tx, &self.account)) })
    }
    fn terminal_summaries<'a>(
        &'a self,
        fence: &'a AccountFence,
    ) -> BoxFuture<'a, Result<TerminalSummaries, Error>> {
        Box::pin(async move {
            read(self, fence, |tx| {
                queue(tx, &self.account)?;
                TerminalSummaries::new(
                    self.account.clone(),
                    codec::summaries(tx, &self.account)?
                        .into_iter()
                        .map(|(_, s)| s)
                        .collect(),
                )
                .map_err(|_error| Error::Corrupt)
            })
        })
    }
}
