// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Reads bounded observed-filter pages and complete pending queues without recovery mutations.

use crate::{
    SqlCipherMailboxReader, SqlCipherMailboxStore,
    cached::{check_fence, mailbox_error, provider_state, sql_error},
    command_codec, command_store, store,
};
use rusqlite::Connection;
use tersa_application::{
    command::CommandSnapshot,
    mailbox::{AccountId, EnvelopeCursor, MailboxStoreError, MessageEnvelope, StoreLimit},
    mailbox_state::{MessageKey, TriageStoreError},
    profile::AccountFence,
};
use tersa_domain::label::UserLabel;

/// Selects all cached envelopes or an exact observed membership within one account.
///
/// Names and pending command intent never determine membership. A User label retains
/// its classified ID and owning account; no current catalog definition is required.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CachedMailboxFilter {
    /// All cached envelopes, including those with unavailable provider metadata.
    Recent,
    /// Complete observed INBOX membership.
    Inbox,
    /// Complete observed TRASH membership.
    Trash,
    /// Complete observed SPAM membership.
    Spam,
    /// Complete observed membership in this exact account-bound User-label ID.
    UserLabel(UserLabel),
}
impl CachedMailboxFilter {
    fn label_id(&self) -> Option<&str> {
        match self {
            Self::Recent => None,
            Self::Inbox => Some("INBOX"),
            Self::Trash => Some("TRASH"),
            Self::Spam => Some("SPAM"),
            Self::UserLabel(label) => Some(label.id().as_str()),
        }
    }
}

// UnifiedMailboxQuery needs 200 display rows and one continuation probe.
const MAX_FILTERED_PAGE: u16 = 201;
const ENVELOPE_COLUMNS: &str = "CASE WHEN typeof(m.message_id) = 'text' AND length(CAST(m.message_id AS BLOB)) <= 256 THEN m.message_id END,
    CASE WHEN typeof(m.thread_id) = 'text' AND length(CAST(m.thread_id AS BLOB)) <= 256 THEN m.thread_id END,
    CASE WHEN typeof(m.sender) = 'text' AND length(CAST(m.sender AS BLOB)) <= 1024 THEN m.sender END,
    CASE WHEN typeof(m.subject) = 'text' AND length(CAST(m.subject AS BLOB)) <= 1024 THEN m.subject END,
    CASE WHEN typeof(m.preview) = 'text' AND length(CAST(m.preview AS BLOB)) <= 1024 THEN m.preview END,
    CASE WHEN typeof(m.received_at) = 'integer' THEN m.received_at END,
    CASE WHEN typeof(m.unread) = 'integer' THEN m.unread END";
const OBSERVED_FILTER: &str = " AND EXISTS (SELECT 1 FROM provider_messages AS p WHERE p.message_id = m.message_id AND p.observation = 1)
    AND EXISTS (SELECT 1 FROM provider_memberships AS pm WHERE pm.message_id = m.message_id AND pm.label_id = :label)";

fn envelopes(
    connection: &Connection,
    account: &AccountId,
    filter: &CachedMailboxFilter,
    after: Option<&EnvelopeCursor>,
    limit: StoreLimit,
    version: i64,
) -> Result<Vec<MessageEnvelope>, TriageStoreError> {
    // Legacy readonly stores have no observed membership, and never acquire it by inference.
    if version < 3 && filter.label_id().is_some() {
        return Ok(Vec::new());
    }
    let seek = if after.is_some() {
        " WHERE m.received_at <= :at AND (m.received_at < :at OR m.message_id > :id)"
    } else {
        " WHERE 1 = 1"
    };
    let predicate = if filter.label_id().is_some() {
        OBSERVED_FILTER
    } else {
        ""
    };
    let sql = format!(
        "SELECT {ENVELOPE_COLUMNS} FROM messages AS m{seek}{predicate} ORDER BY m.received_at DESC,m.message_id ASC LIMIT :limit"
    );
    let mut statement = connection.prepare(&sql).map_err(sql_error)?;
    statement
        .raw_bind_parameter(
            statement
                .parameter_index(":limit")
                .map_err(sql_error)?
                .ok_or(TriageStoreError::Corrupt)?,
            i64::from(limit.get()),
        )
        .map_err(sql_error)?;
    if let Some(label) = filter.label_id() {
        statement
            .raw_bind_parameter(
                statement
                    .parameter_index(":label")
                    .map_err(sql_error)?
                    .ok_or(TriageStoreError::Corrupt)?,
                label,
            )
            .map_err(sql_error)?;
    }
    if let Some(cursor) = after {
        statement
            .raw_bind_parameter(
                statement
                    .parameter_index(":at")
                    .map_err(sql_error)?
                    .ok_or(TriageStoreError::Corrupt)?,
                cursor.received_at().as_millis(),
            )
            .map_err(sql_error)?;
        statement
            .raw_bind_parameter(
                statement
                    .parameter_index(":id")
                    .map_err(sql_error)?
                    .ok_or(TriageStoreError::Corrupt)?,
                cursor.message_id().as_str(),
            )
            .map_err(sql_error)?;
    }
    let mut rows = statement.raw_query();
    let mut result = Vec::new();
    while let Some(row) = rows.next().map_err(sql_error)? {
        let envelope = store::envelope_from_row(row).map_err(mailbox_error)?;
        if version >= 3 {
            // Validate full bounded evidence for each returned key, including Recent's Unknown/Missing.
            // SQL has already applied membership before LIMIT; unrelated candidates are not materialized.
            provider_state(
                connection,
                &MessageKey::new(account.clone(), envelope.message_id().clone()),
            )?;
        }
        result.push(envelope);
    }
    Ok(result)
}
fn mailbox_failure(error: TriageStoreError) -> MailboxStoreError {
    match error {
        TriageStoreError::Corrupt => MailboxStoreError::Corrupted,
        _ => MailboxStoreError::Storage,
    }
}

macro_rules! triage_reads {
    ($ty:ty) => {
        impl $ty {
            /// Lists an observed-filter keyset page without reading message bodies.
            ///
            /// Membership is filtered in SQL before the page limit. Results retain
            /// `received_at DESC, message_id ASC` order and the existing envelope unread
            /// display value. Pending intent does not change this observed view.
            /// Recent includes Unknown and known-empty metadata; other filters require
            /// complete observed membership. Readonly v1/v2 return empty membership-filter
            /// pages and useful Recent pages, without migration or inferred membership.
            ///
            /// # Errors
            /// Returns `Storage` for a foreign account/User label, a limit above 201 or
            /// backend failure; invalid accessed rows/schema return `Corrupted`.
            pub fn list_filtered_envelopes_after(
                &self,
                account: &AccountId,
                filter: &CachedMailboxFilter,
                after: Option<&EnvelopeCursor>,
                limit: StoreLimit,
            ) -> Result<Vec<MessageEnvelope>, MailboxStoreError> {
                if account != &self.account
                    || matches!(filter, CachedMailboxFilter::UserLabel(label) if label.account_id() != account)
                    || limit.get() > MAX_FILTERED_PAGE
                {
                    return Err(MailboxStoreError::Storage);
                }
                self.with_cached_read_transaction(|transaction, version| {
                    envelopes(transaction, account, filter, after, limit, version)
                }).map_err(mailbox_failure)
            }

            /// Reads every validated nonterminal command in account-local FIFO order.
            ///
            /// One readonly transaction verifies ownership/identity and rehydrates at
            /// most 32 commands with 4,096 full target references. No token is loaded;
            /// persisted Dispatching remains Dispatching, with explicit recovery owned
            /// by the coordinator. Legacy v1/v2 return an empty queue only after the
            /// same actual identity/fence checks, without migration.
            ///
            /// # Errors
            /// Returns closed owner, identity, corruption or storage failures. Invalid
            /// queue rows/overflow fail the entire read, never a truncated or empty success.
            pub fn pending_commands(
                &self,
                fence: &AccountFence,
            ) -> Result<Vec<CommandSnapshot>, TriageStoreError> {
                if fence.account_id() != &self.account {
                    return Err(TriageStoreError::UnknownAccount);
                }
                self.with_cached_read_transaction(|transaction, version| {
                    check_fence(transaction, fence)?;
                    if version < 3 {
                        return Ok(Vec::new());
                    }
                    command_store::queue(transaction, &self.account)?
                        .into_iter()
                        .filter(|header| !header.status.is_terminal())
                        .map(|header| {
                            command_codec::body(transaction, &self.account, header)?
                                .snapshot(&self.account)
                        })
                        .collect()
                })
            }
        }
    };
}
triage_reads!(SqlCipherMailboxStore);
triage_reads!(SqlCipherMailboxReader);
