// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Implements identity/cursor-fenced, record-atomic History persistence.

use crate::{
    SqlCipherMailboxStore,
    cached::{check_fence, mailbox_error, provider_state, sql_error},
    pins, store,
};
use rusqlite::{Connection, Transaction, TransactionBehavior, params};
use std::collections::HashSet;
use tersa_application::{
    history::{
        DecidedHistoryRecord, HistoryCheckpoint, HistoryCursorStore, HistoryDecision,
        HistoryRecord, LocalHistoryPresence, RecordLocalState, SnapshotCommit,
        TerminalHistoryCheckpoint,
    },
    mailbox::BoxFuture,
    mailbox_state::{
        MessageKey, MessageMetadata, MessageObservation, RemoteMessageState,
        TriageStoreError as Error,
    },
    profile::AccountFence,
};
use tersa_domain::{
    history::HistoryCursor,
    mailbox::{AccountId, MessageId},
};

fn cursor(connection: &Connection) -> Result<Option<HistoryCursor>, Error> {
    let (kind,value): (String,Option<String>) = connection.query_row(
        "SELECT typeof(history_cursor), CASE WHEN typeof(history_cursor) = 'text' AND length(CAST(history_cursor AS BLOB)) BETWEEN 1 AND 32 THEN history_cursor END FROM mailbox_checkpoint WHERE singleton = 1",[],|r| Ok((r.get(0)?,r.get(1)?))
    ).map_err(sql_error)?;
    match kind.as_str() {
        "null" => Ok(None),
        "text" => HistoryCursor::new(value.ok_or(Error::Corrupt)?)
            .map(Some)
            .map_err(|_error| Error::Corrupt),
        _ => Err(Error::Corrupt),
    }
}
fn expected(connection: &Connection, checkpoint: &HistoryCheckpoint) -> Result<(), Error> {
    check_fence(connection, checkpoint.fence())?;
    if cursor(connection)?.as_ref() != checkpoint.cursor() {
        return Err(Error::Conflict);
    }
    Ok(())
}
fn set_cursor(
    connection: &Connection,
    fence: &AccountFence,
    value: &HistoryCursor,
) -> Result<HistoryCheckpoint, Error> {
    let changed = connection
        .execute(
            "UPDATE mailbox_checkpoint SET history_cursor = ?1 WHERE singleton = 1",
            [value.as_str()],
        )
        .map_err(sql_error)?;
    if changed != 1 {
        return Err(Error::Corrupt);
    }
    Ok(HistoryCheckpoint::new(fence.clone(), Some(value.clone())))
}
fn is_cached(connection: &Connection, id: &MessageId) -> Result<bool, Error> {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM messages WHERE message_id = ?1)",
            [id.as_str()],
            |r| r.get(0),
        )
        .map_err(sql_error)
}
fn observe(
    connection: &Connection,
    observation: &MessageObservation,
    pins: &HashSet<MessageId>,
) -> Result<(), Error> {
    let key = observation.key();
    // Validate the accessed old parent/child relationship before replacing or discarding it.
    provider_state(connection, key)?;
    let retained = pins.contains(key.message_id());
    if matches!(observation.state(), RemoteMessageState::Missing) {
        connection
            .execute(
                "DELETE FROM messages WHERE message_id = ?1",
                [key.message_id().as_str()],
            )
            .map_err(sql_error)?;
    }
    let keep = retained || is_cached(connection, key.message_id())?;
    connection
        .execute(
            "DELETE FROM provider_memberships WHERE message_id = ?1",
            [key.message_id().as_str()],
        )
        .map_err(sql_error)?;
    if !keep {
        connection
            .execute(
                "DELETE FROM provider_messages WHERE message_id = ?1",
                [key.message_id().as_str()],
            )
            .map_err(sql_error)?;
        return Ok(());
    }
    let known = matches!(observation.state(), RemoteMessageState::Known(_));
    connection.execute("INSERT INTO provider_messages VALUES (?1,?2) ON CONFLICT(message_id) DO UPDATE SET observation = excluded.observation",params![key.message_id().as_str(),i64::from(known)]).map_err(sql_error)?;
    if let RemoteMessageState::Known(labels) = observation.state() {
        for label in labels.ids() {
            connection
                .execute(
                    "INSERT INTO provider_memberships VALUES (?1,?2)",
                    params![key.message_id().as_str(), label.as_str()],
                )
                .map_err(sql_error)?;
        }
    }
    Ok(())
}
fn metadata(
    transaction: &Transaction<'_>,
    value: &MessageMetadata,
    pins: &HashSet<MessageId>,
) -> Result<(), Error> {
    provider_state(transaction, value.observation().key())?;
    store::write_envelope(transaction, value.envelope(), None).map_err(mailbox_error)?;
    observe(transaction, value.observation(), pins)
}

// Bounds include all 4,096 pending references, 1,000 undo targets, 100 recent
// messages and the largest single 1,000-target record's transient candidates.
const MAX_TRANSIENT_ROWS: usize = 6196;
fn prune(
    transaction: &Transaction<'_>,
    account: &AccountId,
    pins: &HashSet<MessageId>,
) -> Result<(), Error> {
    let mut statement = transaction.prepare("SELECT CASE WHEN typeof(message_id) = 'text' AND length(CAST(message_id AS BLOB)) BETWEEN 1 AND 256 THEN message_id END, CASE WHEN typeof(received_at) = 'integer' AND received_at >= 0 THEN received_at END FROM messages ORDER BY received_at DESC,message_id ASC LIMIT 6197").map_err(sql_error)?;
    let mut rows = statement.query([]).map_err(sql_error)?;
    let mut keep = HashSet::new();
    let mut remove = Vec::new();
    let mut count = 0;
    while let Some(row) = rows.next().map_err(sql_error)? {
        if count == MAX_TRANSIENT_ROWS {
            return Err(Error::Corrupt);
        }
        let id = MessageId::new(row.get::<_, String>(0).map_err(sql_error)?)
            .map_err(|_error| Error::Corrupt)?;
        let _: i64 = row.get(1).map_err(sql_error)?;
        if count < 100 || pins.contains(&id) {
            keep.insert(id);
        } else {
            remove.push(id);
        }
        count += 1;
    }
    drop(rows);
    drop(statement);
    for id in remove {
        transaction
            .execute("DELETE FROM messages WHERE message_id = ?1", [id.as_str()])
            .map_err(sql_error)?;
    }
    let mut statement = transaction.prepare("SELECT CASE WHEN typeof(message_id) = 'text' AND length(CAST(message_id AS BLOB)) BETWEEN 1 AND 256 THEN message_id END FROM provider_messages LIMIT 6197").map_err(sql_error)?;
    let mut rows = statement.query([]).map_err(sql_error)?;
    let mut remove = Vec::new();
    let mut count = 0;
    while let Some(row) = rows.next().map_err(sql_error)? {
        if count == MAX_TRANSIENT_ROWS {
            return Err(Error::Corrupt);
        }
        count += 1;
        let id = MessageId::new(row.get::<_, String>(0).map_err(sql_error)?)
            .map_err(|_error| Error::Corrupt)?;
        if !keep.contains(&id) && !pins.contains(&id) {
            remove.push(id);
        }
    }
    drop(rows);
    drop(statement);
    for id in remove {
        provider_state(transaction, &MessageKey::new(account.clone(), id.clone()))?;
        transaction
            .execute(
                "DELETE FROM provider_messages WHERE message_id = ?1",
                [id.as_str()],
            )
            .map_err(sql_error)?;
    }
    Ok(())
}

fn history_write<T>(
    store: &SqlCipherMailboxStore,
    checkpoint: &HistoryCheckpoint,
    operation: impl FnOnce(&Transaction<'_>) -> Result<T, Error>,
) -> Result<T, Error> {
    if checkpoint.fence().account_id() != &store.account {
        return Err(Error::UnknownAccount);
    }
    let mut connection = store.connection.lock().map_err(|_error| Error::Storage)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sql_error)?;
    expected(&transaction, checkpoint)?;
    let result = operation(&transaction)?;
    transaction.commit().map_err(sql_error)?;
    Ok(result)
}

impl HistoryCursorStore for SqlCipherMailboxStore {
    fn checkpoint<'a>(
        &'a self,
        fence: &'a AccountFence,
    ) -> BoxFuture<'a, Result<HistoryCheckpoint, Error>> {
        Box::pin(async move {
            if fence.account_id() != &self.account {
                return Err(Error::UnknownAccount);
            }
            self.with_cached_read_transaction(|transaction, _version| {
                check_fence(transaction, fence)?;
                Ok(HistoryCheckpoint::new(fence.clone(), cursor(transaction)?))
            })
        })
    }
    fn classify_record<'a>(
        &'a self,
        fence: &'a AccountFence,
        record: &'a HistoryRecord,
    ) -> BoxFuture<'a, Result<RecordLocalState, Error>> {
        Box::pin(async move {
            if fence.account_id() != &self.account || record.account_id() != &self.account {
                return Err(Error::UnknownAccount);
            }
            self.with_cached_read_transaction(|transaction, _version| {
                check_fence(transaction, fence)?;
                let pins = pins::read(transaction, &self.account)?;
                let mut states = Vec::with_capacity(record.affected().len());
                for key in record.affected() {
                    let presence = match (
                        is_cached(transaction, key.message_id())?,
                        pins.contains(key.message_id()),
                    ) {
                        (true, true) => LocalHistoryPresence::CachedAndPinned,
                        (true, false) => LocalHistoryPresence::Cached,
                        (false, true) => LocalHistoryPresence::Pinned,
                        (false, false) => LocalHistoryPresence::OutsideCache,
                    };
                    states.push((key.clone(), presence));
                }
                RecordLocalState::new(record.clone(), states).map_err(|_error| Error::Corrupt)
            })
        })
    }
    fn apply_record<'a>(
        &'a self,
        request: &'a DecidedHistoryRecord,
    ) -> BoxFuture<'a, Result<HistoryCheckpoint, Error>> {
        Box::pin(async move {
            history_write(self, request.expected(), |transaction| {
                let pins = pins::read(transaction, &self.account)?;
                for decision in request.decisions() {
                    match decision {
                        HistoryDecision::Metadata(value) => metadata(transaction, value, &pins)?,
                        HistoryDecision::Observe(value) => observe(transaction, value, &pins)?,
                        HistoryDecision::Irrelevant(key) => {
                            if is_cached(transaction, key.message_id())?
                                || pins.contains(key.message_id())
                            {
                                return Err(Error::Conflict);
                            }
                            // Even an ignored exact key may not hide a dangling membership.
                            provider_state(transaction, key)?;
                        }
                    }
                }
                prune(transaction, &self.account, &pins)?;
                set_cursor(
                    transaction,
                    request.expected().fence(),
                    request.record().id(),
                )
            })
        })
    }
    fn checkpoint_chain_end<'a>(
        &'a self,
        request: &'a TerminalHistoryCheckpoint,
    ) -> BoxFuture<'a, Result<HistoryCheckpoint, Error>> {
        Box::pin(async move {
            history_write(self, request.expected(), |transaction| {
                set_cursor(transaction, request.expected().fence(), request.cursor())
            })
        })
    }
    fn commit_snapshot<'a>(
        &'a self,
        request: &'a SnapshotCommit,
    ) -> BoxFuture<'a, Result<HistoryCheckpoint, Error>> {
        Box::pin(async move {
            history_write(self, request.expected(), |transaction| {
                let pins = pins::read(transaction, &self.account)?;
                for value in request.metadata() {
                    metadata(transaction, value, &pins)?;
                }
                prune(transaction, &self.account, &pins)?;
                set_cursor(
                    transaction,
                    request.expected().fence(),
                    request.baseline().cursor(),
                )
            })
        })
    }
}
