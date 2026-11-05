// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Defines broker-only atomic credential/capability ports, separate from legacy token writes.
//!
//! These synchronous ports hold no network await. Runtime must hold the selected
//! account operation permit across completion/refresh, store commit and cached
//! session invalidation/generation advancement. Generation stays process-local.
//! Concrete storage owns registration, existing-only routing and transactions;
//! no default substitutes multiple successful writes for atomic grant replacement.

use crate::ValidatedSubject;
use std::fmt;
use tersa_application::{AccountCapability, mailbox::AccountId, token::RefreshRevocationHandle};
use zeroize::Zeroizing;

/// Describes a stored credential's purpose, never implicit from token presence alone.
#[derive(Clone, Eq, PartialEq)]
pub enum GrantCredential {
    /// Known account with no credential, still eligible for selected-account reconnect.
    Missing,
    /// A granted credential eligible for capability-aware refresh.
    Active(Zeroizing<String>),
    /// A rejected refresh rotation retained solely for revocation, never usable refresh access.
    RevocationOnly(Zeroizing<String>),
}
impl fmt::Debug for GrantCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Missing => "Missing",
            Self::Active(_) => "Active([REDACTED])",
            Self::RevocationOnly(_) => "RevocationOnly([REDACTED])",
        })
    }
}

/// Binds one atomic stored snapshot to account, immutable subject, capability and purpose.
///
/// Passing this full snapshot back to a mutator is a compare-and-set precondition,
/// not a persisted credential-generation column. Store implementations must check
/// the entire binding/current credential and capability under the writer transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredCapabilityGrant {
    account: AccountId,
    subject: ValidatedSubject,
    capability: AccountCapability,
    credential: GrantCredential,
}
impl StoredCapabilityGrant {
    /// Rehydrates a bounded owning-store snapshot without accepting a raw UI credential model.
    ///
    /// # Errors
    /// Rejects empty or over-1,024-byte stored credentials as corrupt store input.
    pub fn new(
        account: AccountId,
        subject: ValidatedSubject,
        capability: AccountCapability,
        credential: GrantCredential,
    ) -> Result<Self, CapabilityGrantStoreError> {
        if let GrantCredential::Active(token) | GrantCredential::RevocationOnly(token) = &credential
            && (token.is_empty() || token.len() > 1_024)
        {
            return Err(CapabilityGrantStoreError::Invalid);
        }
        Ok(Self {
            account,
            subject,
            capability,
            credential,
        })
    }
    /// Returns the selected existing account, including when its token is missing.
    #[must_use]
    pub fn account_id(&self) -> &AccountId {
        &self.account
    }
    /// Returns the immutable validated subject binding.
    #[must_use]
    pub fn subject(&self) -> &ValidatedSubject {
        &self.subject
    }
    /// Returns stored capability, never inferred from a refresh response.
    #[must_use]
    pub fn capability(&self) -> AccountCapability {
        self.capability
    }
    /// Returns credential purpose; revocation-only values must not authorize refresh.
    #[must_use]
    pub fn credential(&self) -> &GrantCredential {
        &self.credential
    }
}

/// Reports closed credential-store failures without identifiers, secrets or SQL.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityGrantStoreError {
    /// An owning-store operation failed without a partially replaced token/capability pair.
    Unavailable,
    /// Stored values are corrupt or unsupported, not an absent grant.
    Invalid,
    /// The selected account/subject no longer exists; never register it from replacement.
    UnknownAccount,
    /// Connect found a known subject, even if its current token is missing.
    AlreadyConnected,
    /// The expected account, identity, token, purpose or capability changed since load.
    Conflict,
}
impl fmt::Display for CapabilityGrantStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("capability grant store operation failed")
    }
}
impl std::error::Error for CapabilityGrantStoreError {}

/// Owns atomic capability grant operations without any token-only fallback.
///
/// None from load means UNKNOWN account, never a known account with NULL token.
/// Legacy `RefreshTokenStore` compatibility must be a ReadOnly/Active-only
/// view: never expose revocation-only credentials as usable tokens, mutate
/// capability, or overwrite conflicting/Modify/revocation-only grants through
/// token-only writes. New revocation uses this port's explicit purpose instead.
/// Unsupported occupied legacy reads MUST return an error, never None: hiding
/// them as absent could license legacy grant-wide stranded-grant cleanup.
/// Validate every supplied credential's 1..=1,024-byte bound before persistence.
/// Every mutation rechecks actual account/subject and the full expected snapshot;
/// concurrent changes fail Conflict without overwriting the newer grant.
/// Runtime serialization/session invalidation remains mandatory, including with
/// other account operations; subject permits alone are not that account fence.
pub trait CapabilityGrantStore: fmt::Debug + Send + Sync {
    /// Atomically reads binding, credential purpose/token and capability without provisioning.
    ///
    /// # Errors
    /// Returns Invalid/Unavailable on unreadable state, never a fabricated None.
    fn load_grant(
        &self,
        subject: &ValidatedSubject,
    ) -> Result<Option<StoredCapabilityGrant>, CapabilityGrantStoreError>;
    /// Admits only a new subject and commits token plus capability in one owning-account transaction.
    ///
    /// Existing subjects, including known tokenless bindings, return `AlreadyConnected`
    /// without overwriting/downgrading. A failed registration sequence may leave a
    /// controlled known ReadOnly/tokenless binding; it MUST remain visible to load
    /// and readonly selected-account binding reads, so explicit reconnect can finish
    /// it. Never return success until the complete token/capability pair is durable.
    ///
    /// # Errors
    /// Returns a closed failure; no partial token/capability replacement is permitted.
    fn connect_new(
        &self,
        subject: &ValidatedSubject,
        token: &Zeroizing<String>,
        capability: AccountCapability,
    ) -> Result<AccountId, CapabilityGrantStoreError>;
    /// Replaces token plus requested capability atomically for exactly the selected known binding.
    ///
    /// Missing/revocation-only existing credentials remain reconnectable. Never
    /// register, bootstrap, route to another account or emulate with two writes.
    ///
    /// # Errors
    /// Returns UnknownAccount/Conflict or a storage failure, preserving the old grant.
    fn replace_existing(
        &self,
        expected: &StoredCapabilityGrant,
        token: &Zeroizing<String>,
        capability: AccountCapability,
    ) -> Result<(), CapabilityGrantStoreError>;
    /// Retains a matched granted refresh rotation while preserving actual stored capability.
    ///
    /// # Errors
    /// Rejects non-Active, changed or unknown snapshots; no capability parameter permits promotion.
    fn rotate_existing(
        &self,
        expected: &StoredCapabilityGrant,
        token: &Zeroizing<String>,
    ) -> Result<(), CapabilityGrantStoreError>;
    /// Retains a rejected refresh rotation ONLY as a revocation handle, preserving capability.
    ///
    /// # Errors
    /// Rejects changed/non-Active bindings and failures without exposing usable access.
    fn retain_revocation_rotation(
        &self,
        expected: &StoredCapabilityGrant,
        handle: &RefreshRevocationHandle,
    ) -> Result<(), CapabilityGrantStoreError>;
    /// Clears the credential only for the exact known snapshot, preserving account/capability.
    ///
    /// # Errors
    /// Rejects changed/unknown state or deletion failure; never assert `ConsentRevoked` on failure.
    fn delete_existing(
        &self,
        expected: &StoredCapabilityGrant,
    ) -> Result<(), CapabilityGrantStoreError>;
}
