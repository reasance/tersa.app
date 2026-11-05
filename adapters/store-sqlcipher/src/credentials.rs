// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Owns bounded credential snapshots for a later trusted runtime bridge.
//!
//! These types grant no account registration or refresh authority. The store
//! compares the entire snapshot inside an immediate transaction. Runtime must
//! additionally serialize account operations and invalidate process-local access
//! sessions. There is deliberately no dependency on the broker adapter.

use std::fmt;
use tersa_application::identity::IdentityHash;

use rusqlite::{Connection, types::ValueRef};
use tersa_domain::{account::AccountCapability, mailbox::AccountId};
use zeroize::Zeroizing;

/// Separates usable credentials from handles retained only for revocation.
#[derive(Clone, Eq, PartialEq)]
pub enum StoreCredential {
    /// A known binding without a credential, eligible for explicit reconnect.
    Missing,
    /// A bounded credential usable only through capability-aware broker policy.
    Active(Zeroizing<String>),
    /// A bounded handle that must never authorize refresh access.
    RevocationOnly(Zeroizing<String>),
}
impl fmt::Debug for StoreCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Missing => "Missing",
            Self::Active(_) => "Active([REDACTED])",
            Self::RevocationOnly(_) => "RevocationOnly([REDACTED])",
        })
    }
}
impl StoreCredential {
    pub(crate) fn parts(&self) -> Result<(i64, Option<&str>), CredentialStoreError> {
        match self {
            Self::Missing => Ok((0, None)),
            Self::Active(value) | Self::RevocationOnly(value)
                if (1..=1024).contains(&value.len()) =>
            {
                Ok((
                    if matches!(self, Self::Active(_)) {
                        1
                    } else {
                        2
                    },
                    Some(value),
                ))
            }
            _ => Err(CredentialStoreError::Invalid),
        }
    }
}

/// Captures actual account, immutable subject, grant and optional recorded identity.
///
/// Private fields prevent callers from fabricating expected state. Even an
/// absent identity is compared, so delayed bootstrap cannot overwrite a newer
/// binding. Tokens and subjects stay zeroizing and all formatting is redacted.
#[derive(Clone, Eq, PartialEq)]
pub struct CredentialSnapshot {
    pub(crate) account: AccountId,
    pub(crate) subject: Option<Zeroizing<String>>,
    pub(crate) capability: AccountCapability,
    pub(crate) credential: StoreCredential,
    pub(crate) identity: Option<IdentityHash>,
}
impl fmt::Debug for CredentialSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CredentialSnapshot([REDACTED])")
    }
}
impl CredentialSnapshot {
    /// Returns the actual owning account.
    #[must_use]
    pub fn account_id(&self) -> &AccountId {
        &self.account
    }
    /// Returns the immutable routing subject, absent only before account binding.
    #[must_use]
    pub fn subject(&self) -> Option<&str> {
        self.subject.as_deref().map(String::as_str)
    }
    /// Returns persisted capability, independent of access-session authority.
    #[must_use]
    pub fn capability(&self) -> AccountCapability {
        self.capability
    }
    /// Returns explicit purpose and zeroizing credential custody.
    #[must_use]
    pub fn credential(&self) -> &StoreCredential {
        &self.credential
    }
    /// Returns the recorded identity, if the identity gate has established one.
    #[must_use]
    pub fn identity(&self) -> Option<&[u8; 32]> {
        self.identity.as_ref().map(IdentityHash::as_bytes)
    }
}

/// Reports credential failures without SQL, identifiers or secret values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialStoreError {
    /// Backend unavailable; the atomic mutation did not partially commit.
    Storage,
    /// Corrupt or unsupported stored/supplied values, never absence.
    Invalid,
    /// The selected account is not owned by this store; no provisioning occurred.
    UnknownAccount,
    /// Any expected binding, identity, capability, purpose or token has changed.
    Conflict,
}
impl fmt::Display for CredentialStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("credential store operation failed")
    }
}
impl std::error::Error for CredentialStoreError {}

pub(crate) fn capability_code(capability: AccountCapability) -> i64 {
    match capability {
        AccountCapability::ReadOnly => 0,
        AccountCapability::Modify => 1,
    }
}

pub(crate) fn read(
    connection: &Connection,
    account: &AccountId,
    token_limit: usize,
) -> Result<CredentialSnapshot, CredentialStoreError> {
    let mut statement = connection.prepare(
        "SELECT CASE WHEN typeof(account_id) = 'text' AND length(CAST(account_id AS BLOB)) BETWEEN 1 AND 256 THEN account_id END,
         CASE WHEN typeof(broker_subject) = 'text' AND length(CAST(broker_subject AS BLOB)) BETWEEN 1 AND 255 THEN broker_subject END,
         CASE WHEN typeof(capability) = 'integer' THEN capability END,
         CASE WHEN typeof(credential_purpose) = 'integer' THEN credential_purpose END,
         CASE WHEN typeof(refresh_token) = 'text' AND length(CAST(refresh_token AS BLOB)) BETWEEN 1 AND ?1 THEN refresh_token END,
         typeof(broker_subject), typeof(refresh_token)
         FROM account_binding WHERE singleton = 1",
    ).map_err(|_error| CredentialStoreError::Storage)?;
    let mut rows = statement
        .query([i64::try_from(token_limit).map_err(|_error| CredentialStoreError::Invalid)?])
        .map_err(|_error| CredentialStoreError::Storage)?;
    let row = rows
        .next()
        .map_err(|_error| CredentialStoreError::Storage)?
        .ok_or(CredentialStoreError::Invalid)?;
    // ValueRef borrows SQLite memory: bound/type checks precede every allocation.
    let text = |index, max| -> Result<Option<&str>, CredentialStoreError> {
        match row
            .get_ref(index)
            .map_err(|_error| CredentialStoreError::Invalid)?
        {
            ValueRef::Null => Ok(None),
            ValueRef::Text(bytes) if !bytes.is_empty() && bytes.len() <= max => {
                std::str::from_utf8(bytes)
                    .map(Some)
                    .map_err(|_error| CredentialStoreError::Invalid)
            }
            _ => Err(CredentialStoreError::Invalid),
        }
    };
    if text(0, 256)? != Some(account.as_str()) {
        return Err(CredentialStoreError::Invalid);
    }
    let subject = text(1, 255)?;
    let subject_kind: &str = row
        .get_ref(5)
        .map_err(|_error| CredentialStoreError::Invalid)?
        .as_str()
        .map_err(|_error| CredentialStoreError::Invalid)?;
    if (subject.is_none() && subject_kind != "null")
        || (subject.is_some() && subject_kind != "text")
    {
        return Err(CredentialStoreError::Invalid);
    }
    if subject.is_some_and(|s| !s.bytes().all(|b| (0x21..=0x7e).contains(&b))) {
        return Err(CredentialStoreError::Invalid);
    }
    let capability = match row
        .get_ref(2)
        .map_err(|_error| CredentialStoreError::Invalid)?
    {
        ValueRef::Integer(0) => AccountCapability::ReadOnly,
        ValueRef::Integer(1) => AccountCapability::Modify,
        _ => return Err(CredentialStoreError::Invalid),
    };
    let token = text(4, token_limit)?;
    let token_kind: &str = row
        .get_ref(6)
        .map_err(|_error| CredentialStoreError::Invalid)?
        .as_str()
        .map_err(|_error| CredentialStoreError::Invalid)?;
    if (token.is_none() && token_kind != "null") || (token.is_some() && token_kind != "text") {
        return Err(CredentialStoreError::Invalid);
    }
    let credential = match (
        row.get_ref(3)
            .map_err(|_error| CredentialStoreError::Invalid)?,
        token,
    ) {
        (ValueRef::Integer(0), None) => StoreCredential::Missing,
        (ValueRef::Integer(1), Some(value)) => {
            StoreCredential::Active(Zeroizing::new(value.to_owned()))
        }
        (ValueRef::Integer(2), Some(value)) => {
            StoreCredential::RevocationOnly(Zeroizing::new(value.to_owned()))
        }
        _ => return Err(CredentialStoreError::Invalid),
    };
    if subject.is_none()
        && (capability != AccountCapability::ReadOnly
            || matches!(credential, StoreCredential::RevocationOnly(_)))
    {
        return Err(CredentialStoreError::Invalid);
    }
    Ok(CredentialSnapshot {
        account: account.clone(),
        subject: subject.map(|s| Zeroizing::new(s.to_owned())),
        capability,
        credential,
        identity: super::store::read_recorded_identity(connection, account)
            .map_err(|_error| CredentialStoreError::Invalid)?
            .map(IdentityHash::from_bytes),
    })
}
