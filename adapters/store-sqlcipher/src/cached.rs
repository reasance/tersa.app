// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Reads bounded cached observations and profiles without credential or freshness claims.

use crate::{SqlCipherMailboxReader, SqlCipherMailboxStore, store};
use rusqlite::{Connection, ErrorCode, TransactionBehavior, params};
use tersa_application::{
    identity::IdentityHash,
    mailbox::{AccountEmail, AccountId, BoxFuture, MailboxStoreError, MessageId},
    mailbox_state::{MessageKey, TriageStoreError as Error},
    profile::{AccountFence, AccountMetadata, AccountMetadataReader, UpgradeBinding},
    token::AccountSubject,
};
use tersa_domain::{
    account::AccountCapability,
    label::{LabelCatalog, LabelDefinition, LabelId, LabelKind, LabelMembership, LabelName},
};
use zeroize::Zeroizing;

/// Describes cached knowledge, never current command-reconciliation authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CachedProviderState {
    /// No retained complete observation is available.
    Unknown,
    /// An exact-key provider read established absence while this target remained pinned.
    Missing,
    /// Complete observed membership, including a known empty set.
    Known(LabelMembership),
}
/// Pairs cached provider state with its exact account/message identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CachedProviderMessage {
    key: MessageKey,
    state: CachedProviderState,
}
impl CachedProviderMessage {
    /// Returns the owning account and message.
    #[must_use]
    pub fn key(&self) -> &MessageKey {
        &self.key
    }
    /// Returns cached knowledge without a freshness claim.
    #[must_use]
    pub fn state(&self) -> &CachedProviderState {
        &self.state
    }
}

pub(crate) fn sql_error(error: rusqlite::Error) -> Error {
    match error {
        rusqlite::Error::SqliteFailure(code, message) => {
            drop(message);
            if matches!(
                code.code,
                ErrorCode::DatabaseCorrupt | ErrorCode::NotADatabase
            ) {
                Error::Corrupt
            } else {
                Error::Storage
            }
        }
        rusqlite::Error::InvalidColumnType(..)
        | rusqlite::Error::FromSqlConversionFailure(..)
        | rusqlite::Error::QueryReturnedNoRows
        | rusqlite::Error::Utf8Error(..)
        | rusqlite::Error::IntegralValueOutOfRange(..) => Error::Corrupt,
        other => {
            drop(other);
            Error::Storage
        }
    }
}
pub(crate) fn mailbox_error(error: MailboxStoreError) -> Error {
    match error {
        MailboxStoreError::Corrupted => Error::Corrupt,
        _ => Error::Storage,
    }
}
fn recorded_identity(
    connection: &Connection,
    account: &AccountId,
) -> Result<Option<IdentityHash>, Error> {
    let mut statement = connection.prepare("SELECT CASE WHEN typeof(account_id) = 'text' AND length(CAST(account_id AS BLOB)) BETWEEN 1 AND 256 THEN account_id END, CASE WHEN typeof(identity_hash) = 'blob' AND length(identity_hash) = 32 THEN identity_hash END, CASE WHEN typeof(algo_version) = 'integer' AND algo_version = 2 THEN algo_version END FROM account_identity LIMIT 2").map_err(sql_error)?;
    let mut rows = statement.query([]).map_err(sql_error)?;
    let identity = if let Some(row) = rows.next().map_err(sql_error)? {
        let owner: String = row.get(0).map_err(sql_error)?;
        if owner != account.as_str() {
            return Err(Error::Corrupt);
        }
        let bytes: Vec<u8> = row.get(1).map_err(sql_error)?;
        let _: i64 = row.get(2).map_err(sql_error)?;
        Some(IdentityHash::from_bytes(
            bytes.try_into().map_err(|_error| Error::Corrupt)?,
        ))
    } else {
        None
    };
    if rows.next().map_err(sql_error)?.is_some() {
        return Err(Error::Corrupt);
    }
    Ok(identity)
}

pub(crate) fn check_fence(connection: &Connection, fence: &AccountFence) -> Result<(), Error> {
    store::triage_version(connection, fence.account_id())?;
    let foreign_keys: i64 = connection
        .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
        .map_err(sql_error)?;
    if foreign_keys != 1 {
        return Err(Error::Corrupt);
    }
    let actual = recorded_identity(connection, fence.account_id())?;
    if actual.as_ref() != Some(fence.identity()) {
        return Err(Error::IdentityChanged);
    }
    Ok(())
}

pub(crate) fn provider_state(
    connection: &Connection,
    key: &MessageKey,
) -> Result<CachedProviderState, Error> {
    let mut statement = connection.prepare("SELECT CASE WHEN typeof(observation) = 'integer' AND observation IN (0,1) THEN observation END FROM provider_messages WHERE message_id = ?1").map_err(sql_error)?;
    let mut rows = statement
        .query([key.message_id().as_str()])
        .map_err(sql_error)?;
    let observation = rows
        .next()
        .map_err(sql_error)?
        .map(|row| row.get::<_, i64>(0))
        .transpose()
        .map_err(sql_error)?;
    // Query the child even if the parent is absent: a dangling child is corruption, not Unknown.
    let mut statement = connection.prepare("SELECT CASE WHEN typeof(label_id) = 'text' AND length(CAST(label_id AS BLOB)) BETWEEN 1 AND 256 THEN label_id END FROM provider_memberships WHERE message_id = ?1 ORDER BY label_id LIMIT 513").map_err(sql_error)?;
    let mut rows = statement
        .query([key.message_id().as_str()])
        .map_err(sql_error)?;
    let mut labels = Vec::new();
    while let Some(row) = rows.next().map_err(sql_error)? {
        if labels.len() == LabelMembership::MAX_LABELS || observation != Some(1) {
            return Err(Error::Corrupt);
        }
        labels.push(
            LabelId::new(row.get::<_, String>(0).map_err(sql_error)?)
                .map_err(|_error| Error::Corrupt)?,
        );
    }
    match observation {
        None => Ok(CachedProviderState::Unknown),
        Some(0) => Ok(CachedProviderState::Missing),
        Some(1) => LabelMembership::new(key.account_id().clone(), labels)
            .map(CachedProviderState::Known)
            .map_err(|_error| Error::Corrupt),
        _ => Err(Error::Corrupt),
    }
}

fn catalog(
    connection: &Connection,
    account: &AccountId,
    version: i64,
) -> Result<Option<LabelCatalog>, Error> {
    if version < 3 {
        return Ok(None);
    }
    let known: i64 = connection.query_row("SELECT CASE WHEN typeof(catalog_known) = 'integer' AND catalog_known IN (0,1) THEN catalog_known END FROM mailbox_checkpoint WHERE singleton = 1", [], |r| r.get(0)).map_err(sql_error)?;
    let mut statement = connection.prepare("SELECT CASE WHEN typeof(label_id) = 'text' AND length(CAST(label_id AS BLOB)) BETWEEN 1 AND 256 THEN label_id END, CASE WHEN typeof(name) = 'text' AND length(CAST(name AS BLOB)) BETWEEN 1 AND 1024 THEN name END, CASE WHEN typeof(kind) = 'integer' AND kind IN (0,1) THEN kind END FROM provider_labels ORDER BY label_id LIMIT 501").map_err(sql_error)?;
    let mut rows = statement.query([]).map_err(sql_error)?;
    let mut definitions = Vec::new();
    while let Some(row) = rows.next().map_err(sql_error)? {
        if known == 0 || definitions.len() == LabelCatalog::MAX_LABELS {
            return Err(Error::Corrupt);
        }
        definitions.push(
            LabelDefinition::new(
                account.clone(),
                LabelId::new(row.get::<_, String>(0).map_err(sql_error)?)
                    .map_err(|_error| Error::Corrupt)?,
                LabelName::new(row.get::<_, String>(1).map_err(sql_error)?)
                    .map_err(|_error| Error::Corrupt)?,
                if row.get::<_, i64>(2).map_err(sql_error)? == 0 {
                    LabelKind::System
                } else {
                    LabelKind::User
                },
            )
            .map_err(|_error| Error::Corrupt)?,
        );
    }
    if known == 0 {
        Ok(None)
    } else {
        LabelCatalog::new(account.clone(), definitions)
            .map(Some)
            .map_err(|_error| Error::Corrupt)
    }
}
fn metadata(
    connection: &Connection,
    account: &AccountId,
    version: i64,
) -> Result<AccountMetadata, Error> {
    let capability = if version < 3 {
        AccountCapability::ReadOnly
    } else {
        match connection
            .query_row(
                "SELECT capability FROM account_binding WHERE singleton = 1",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map_err(sql_error)?
        {
            0 => AccountCapability::ReadOnly,
            1 => AccountCapability::Modify,
            _ => return Err(Error::Corrupt),
        }
    };
    let email = if version == 1 {
        None
    } else {
        let (kind, value): (String, Option<String>) = connection.query_row("SELECT typeof(email_address), CASE WHEN typeof(email_address) = 'text' AND length(CAST(email_address AS BLOB)) BETWEEN 3 AND 320 THEN email_address END FROM account_binding WHERE singleton = 1", [], |r| Ok((r.get(0)?,r.get(1)?))).map_err(sql_error)?;
        match kind.as_str() {
            "null" => None,
            "text" => Some(
                AccountEmail::new(value.ok_or(Error::Corrupt)?).map_err(|_error| Error::Corrupt)?,
            ),
            _ => return Err(Error::Corrupt),
        }
    };
    Ok(AccountMetadata::new(account.clone(), email, capability))
}
fn upgrade_binding(connection: &Connection, account: &AccountId) -> Result<UpgradeBinding, Error> {
    // Missing identity is a legitimate interrupted registration; incompatible present identity is not.
    recorded_identity(connection, account)?;
    let subject = connection.query_row("SELECT CASE WHEN typeof(broker_subject) = 'text' AND length(CAST(broker_subject AS BLOB)) BETWEEN 1 AND 255 THEN broker_subject END FROM account_binding WHERE singleton = 1", [], |r| r.get::<_,String>(0).map(Zeroizing::new)).map_err(sql_error)?;
    let subject =
        AccountSubject::from_broker_validated(subject).map_err(|_error| Error::Corrupt)?;
    Ok(UpgradeBinding::new(account.clone(), subject))
}

macro_rules! cached_reads {
    ($ty:ty) => {
        impl $ty {
            /// Reads at most 200 exact-key cached states in one readonly transaction.
            ///
            /// Input order is retained; duplicates/foreign owners fail closed.
            /// Legacy schemas return Unknown without migrating. No bodies are read.
            /// # Errors
            /// Returns closed owner/storage/corruption errors, including orphan/overflow membership.
            pub fn cached_provider_states(
                &self,
                account: &AccountId,
                ids: &[MessageId],
            ) -> Result<Vec<CachedProviderMessage>, Error> {
                if account != &self.account {
                    return Err(Error::UnknownAccount);
                }
                if ids.len() > 200 {
                    return Err(Error::QuotaExceeded);
                }
                let mut seen = std::collections::HashSet::new();
                if ids.iter().any(|id| !seen.insert(id)) {
                    return Err(Error::Conflict);
                }
                self.with_cached_read_transaction(|transaction, version| {
                    let mut result = Vec::with_capacity(ids.len());
                    for id in ids {
                        let key = MessageKey::new(account.clone(), id.clone());
                        let state = if version < 3 {
                            CachedProviderState::Unknown
                        } else {
                            provider_state(transaction, &key)?
                        };
                        result.push(CachedProviderMessage { key, state });
                    }
                    Ok(result)
                })
            }
            /// Reads one exact-key cached state, without freshness or provider-access claims.
            /// # Errors
            /// Returns the same closed failures as the bounded batch reader.
            pub fn cached_provider_state(
                &self,
                key: &MessageKey,
            ) -> Result<CachedProviderState, Error> {
                let mut result = self.cached_provider_states(
                    key.account_id(),
                    std::slice::from_ref(key.message_id()),
                )?;
                result.pop().map(|row| row.state).ok_or(Error::Corrupt)
            }
            /// Reads a complete cached catalog, distinguishing Unknown from known empty.
            /// # Errors
            /// Rejects foreign ownership, invalid definitions and over-500 catalogs without truncation.
            pub fn cached_label_catalog(
                &self,
                account: &AccountId,
            ) -> Result<Option<LabelCatalog>, Error> {
                if account != &self.account {
                    return Err(Error::UnknownAccount);
                }
                self.with_cached_read_transaction(|transaction, version| {
                    let result = catalog(transaction, account, version)?;
                    Ok(result)
                })
            }
        }
        impl AccountMetadataReader for $ty {
            fn read_metadata<'a>(
                &'a self,
                account: &'a AccountId,
            ) -> BoxFuture<'a, Result<Option<AccountMetadata>, Error>> {
                Box::pin(async move {
                    if account != &self.account {
                        return Ok(None);
                    }
                    self.with_cached_read_transaction(|transaction, version| {
                        let result = metadata(transaction, account, version)?;
                        Ok(Some(result))
                    })
                })
            }
            fn read_upgrade_binding<'a>(
                &'a self,
                account: &'a AccountId,
            ) -> BoxFuture<'a, Result<Option<UpgradeBinding>, Error>> {
                Box::pin(async move {
                    if account != &self.account {
                        return Ok(None);
                    }
                    self.with_cached_read_transaction(|transaction, _version| {
                        let result = upgrade_binding(transaction, account)?;
                        Ok(Some(result))
                    })
                })
            }
        }
    };
}
cached_reads!(SqlCipherMailboxStore);
cached_reads!(SqlCipherMailboxReader);

pub(crate) fn replace_catalog(
    store: &SqlCipherMailboxStore,
    fence: &AccountFence,
    value: &LabelCatalog,
) -> Result<(), Error> {
    if fence.account_id() != &store.account || value.account_id() != &store.account {
        return Err(Error::UnknownAccount);
    }
    let mut connection = store.connection.lock().map_err(|_error| Error::Storage)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sql_error)?;
    check_fence(&transaction, fence)?;
    catalog(&transaction, &store.account, 3)?;
    transaction
        .execute("DELETE FROM provider_labels", [])
        .map_err(sql_error)?;
    for label in value.definitions() {
        transaction
            .execute(
                "INSERT INTO provider_labels VALUES (?1,?2,?3)",
                params![
                    label.id().as_str(),
                    label.name().as_str(),
                    i64::from(label.kind() == LabelKind::User)
                ],
            )
            .map_err(sql_error)?;
    }
    transaction
        .execute(
            "UPDATE mailbox_checkpoint SET catalog_known = 1 WHERE singleton = 1",
            [],
        )
        .map_err(sql_error)?;
    transaction.commit().map_err(sql_error)
}
