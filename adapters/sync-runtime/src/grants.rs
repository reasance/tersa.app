// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Operation-scoped credential custody retaining the original store identity fence.

use crate::{Installation, InstallationTokens};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tersa_application::{AccountCapability, mailbox::AccountId, token::RefreshRevocationHandle};
use tersa_store_sqlcipher::{CredentialSnapshot, CredentialStoreError, StoreCredential};
use tersa_token_broker_core::{
    CapabilityGrantStore, CapabilityGrantStoreError as Error, GrantCredential, RefreshTokenStore,
    RefreshTokenStoreError, StoredCapabilityGrant, ValidatedSubject,
};
use zeroize::Zeroizing;

/// A fresh instance belongs to exactly one broker operation (begin/complete count as one).
/// Repeated loads never replace its original expected identity with a newer observation.
/// It is deliberately not shared between unrelated operations, which may legitimately
/// establish identity after a first sync. Subject/account permits are owned by the caller.
pub(crate) struct OperationGrants {
    installation: Arc<Installation>,
    observed: Mutex<HashMap<AccountId, CredentialSnapshot>>,
}
impl std::fmt::Debug for OperationGrants {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OperationGrants([REDACTED])")
    }
}
impl OperationGrants {
    pub(crate) fn new(installation: Arc<Installation>) -> Self {
        Self {
            installation,
            observed: Mutex::new(HashMap::new()),
        }
    }

    fn replace(
        &self,
        expected: &StoredCapabilityGrant,
        capability: AccountCapability,
        credential: &StoreCredential,
    ) -> Result<(), Error> {
        if self
            .installation
            .account_for_subject(expected.subject().as_str())
            .map_err(|_error| Error::Unavailable)?
            .as_ref()
            != Some(expected.account_id())
        {
            return Err(Error::UnknownAccount);
        }
        let snapshot = self
            .observed
            .lock()
            .map_err(|_error| Error::Unavailable)?
            .get(expected.account_id())
            .cloned()
            .ok_or(Error::Conflict)?;
        if grant(&snapshot)? != *expected {
            return Err(Error::Conflict);
        }
        // Pass the ORIGINAL opaque snapshot. Its optional identity is not present
        // in StoredCapabilityGrant and must never be reconstructed from a reload.
        let store = self
            .installation
            .open_store(expected.account_id())
            .map_err(|_error| Error::Unavailable)?;
        store
            .replace_credential_snapshot(&snapshot, capability, credential)
            .map_err(map_store)
    }
}
fn map_store(error: CredentialStoreError) -> Error {
    match error {
        CredentialStoreError::Storage => Error::Unavailable,
        CredentialStoreError::Invalid => Error::Invalid,
        CredentialStoreError::UnknownAccount => Error::UnknownAccount,
        CredentialStoreError::Conflict => Error::Conflict,
    }
}
fn grant(snapshot: &CredentialSnapshot) -> Result<StoredCapabilityGrant, Error> {
    let subject = ValidatedSubject::new(snapshot.subject().ok_or(Error::Invalid)?)
        .map_err(|_error| Error::Invalid)?;
    let credential = match snapshot.credential() {
        StoreCredential::Missing => GrantCredential::Missing,
        StoreCredential::Active(value) => GrantCredential::Active(value.clone()),
        StoreCredential::RevocationOnly(value) => GrantCredential::RevocationOnly(value.clone()),
    };
    StoredCapabilityGrant::new(
        snapshot.account_id().clone(),
        subject,
        snapshot.capability(),
        credential,
    )
}
impl CapabilityGrantStore for OperationGrants {
    fn load_grant(
        &self,
        subject: &ValidatedSubject,
    ) -> Result<Option<StoredCapabilityGrant>, Error> {
        let Some(account) = self
            .installation
            .account_for_subject(subject.as_str())
            .map_err(|_error| Error::Unavailable)?
        else {
            return Ok(None);
        };
        let store = self
            .installation
            .open_store(&account)
            .map_err(|_error| Error::Unavailable)?;
        let snapshot = store
            .load_credential_snapshot(&account)
            .map_err(map_store)?;
        let current = grant(&snapshot)?;
        if current.subject() != subject {
            return Err(Error::Invalid);
        }
        let mut observed = self.observed.lock().map_err(|_error| Error::Unavailable)?;
        match observed.get(&account) {
            Some(original) if original != &snapshot => return Err(Error::Conflict),
            Some(_) => {}
            None => {
                observed.insert(account, snapshot);
            }
        }
        Ok(Some(current))
    }
    fn connect_new(
        &self,
        subject: &ValidatedSubject,
        token: &Zeroizing<String>,
        capability: AccountCapability,
    ) -> Result<AccountId, Error> {
        if token.is_empty() || token.len() > 1024 {
            return Err(Error::Invalid);
        }
        // The installation allocation mutex also excludes legacy registration.
        self.installation
            .connect_capability(subject, token, capability)
    }
    fn replace_existing(
        &self,
        expected: &StoredCapabilityGrant,
        token: &Zeroizing<String>,
        capability: AccountCapability,
    ) -> Result<(), Error> {
        self.replace(
            expected,
            capability,
            &StoreCredential::Active(token.clone()),
        )
    }
    fn rotate_existing(
        &self,
        expected: &StoredCapabilityGrant,
        token: &Zeroizing<String>,
    ) -> Result<(), Error> {
        if !matches!(expected.credential(), GrantCredential::Active(_)) {
            return Err(Error::Invalid);
        }
        self.replace_existing(expected, token, expected.capability())
    }
    fn retain_revocation_rotation(
        &self,
        expected: &StoredCapabilityGrant,
        handle: &RefreshRevocationHandle,
    ) -> Result<(), Error> {
        if !matches!(expected.credential(), GrantCredential::Active(_)) {
            return Err(Error::Invalid);
        }
        self.replace(
            expected,
            expected.capability(),
            &StoreCredential::RevocationOnly(handle.secret_for_revocation().clone()),
        )
    }
    fn delete_existing(&self, expected: &StoredCapabilityGrant) -> Result<(), Error> {
        self.replace(expected, expected.capability(), &StoreCredential::Missing)
    }
}
// Required by BrokerCore's compatibility bound. Legacy access is still restricted
// by the owning store to ReadOnly/Active and is never used for capability operations.
impl RefreshTokenStore for OperationGrants {
    fn store(
        &self,
        subject: &ValidatedSubject,
        token: &Zeroizing<String>,
    ) -> Result<(), RefreshTokenStoreError> {
        InstallationTokens(Arc::clone(&self.installation)).store(subject, token)
    }
    fn load(
        &self,
        subject: &ValidatedSubject,
    ) -> Result<Option<Zeroizing<String>>, RefreshTokenStoreError> {
        InstallationTokens(Arc::clone(&self.installation)).load(subject)
    }
    fn delete(&self, subject: &ValidatedSubject) -> Result<(), RefreshTokenStoreError> {
        InstallationTokens(Arc::clone(&self.installation)).delete(subject)
    }
}
