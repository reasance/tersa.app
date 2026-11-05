// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Defines readonly account metadata and selected-account binding, without credential custody.
//!
//! This profile value does not replace `identity::AccountProfile`. Reads never
//! bootstrap an unknown account. Credential replacement stays in broker/store
//! ports; no capability-only setter or credential is exposed here. Runtime owns
//! process-local credential generation and must fence current sessions separately.

use crate::{
    identity::IdentityHash,
    mailbox::{AccountEmail, AccountId, BoxFuture},
    mailbox_state::TriageStoreError,
    token::AccountSubject,
};
use tersa_domain::account::AccountCapability;

/// Binds an operation to the expected registered account identity.
///
/// Construction is not proof of current authority: owning transactions must
/// compare this identity to actual stored identity before making any writes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountFence {
    account: AccountId,
    identity: IdentityHash,
}
impl AccountFence {
    /// Captures account and identity validated by trusted runtime composition.
    #[must_use]
    pub fn new(account: AccountId, identity: IdentityHash) -> Self {
        Self { account, identity }
    }
    /// Returns the selected account.
    #[must_use]
    pub fn account_id(&self) -> &AccountId {
        &self.account
    }
    /// Returns the identity that the transaction must compare atomically.
    #[must_use]
    pub fn identity(&self) -> &IdentityHash {
        &self.identity
    }
}

/// Contains readonly display metadata and persisted capability, without any credentials.
///
/// An absent stored address is valid for a known account, including readonly
/// legacy stores. It does not mean the account is unknown and must not be replaced
/// with a fabricated provider address.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountMetadata {
    account: AccountId,
    email: Option<AccountEmail>,
    capability: AccountCapability,
}
impl AccountMetadata {
    /// Assembles validated metadata returned by an existing-account reader.
    #[must_use]
    pub fn new(
        account: AccountId,
        email: Option<AccountEmail>,
        capability: AccountCapability,
    ) -> Self {
        Self {
            account,
            email,
            capability,
        }
    }
    /// Returns the registered account ID.
    #[must_use]
    pub fn account_id(&self) -> &AccountId {
        &self.account
    }
    /// Returns the stored address, if present, for sanitized presentation only.
    ///
    /// None means this known account has no stored address, never an unknown account.
    #[must_use]
    pub fn email(&self) -> Option<&AccountEmail> {
        self.email.as_ref()
    }
    /// Returns persisted capability, not current access-session authority.
    #[must_use]
    pub fn capability(&self) -> AccountCapability {
        self.capability
    }
}

/// Captures selected account and expected immutable subject before browser launch.
///
/// This trusted broker-facing binding carries no token. Completion must compare
/// subjects before registration, replacement or revocation; denial/mismatch
/// preserves the old grant. Requested capability remains bound by P2a's session.
#[derive(Debug)]
pub struct UpgradeBinding {
    account: AccountId,
    expected_subject: AccountSubject,
}
impl UpgradeBinding {
    /// Captures a validated stored subject for the explicitly selected account.
    #[must_use]
    pub fn new(account: AccountId, expected_subject: AccountSubject) -> Self {
        Self {
            account,
            expected_subject,
        }
    }
    /// Returns the account selected before authorization began.
    #[must_use]
    pub fn account_id(&self) -> &AccountId {
        &self.account
    }
    /// Returns the immutable stored subject that completion must match.
    #[must_use]
    pub fn expected_subject(&self) -> &AccountSubject {
        &self.expected_subject
    }
}

/// Reads existing-account metadata and trusted Upgrade bindings without provisioning.
pub trait AccountMetadataReader: Send + Sync {
    /// Reads existing metadata; unknown accounts return None with no bootstrap or writes.
    /// Known accounts without a stored address return Some metadata with no email.
    ///
    /// # Errors
    /// Resolves to a closed failure without provider or backend data; no partial success.
    fn read_metadata<'a>(
        &'a self,
        account: &'a AccountId,
    ) -> BoxFuture<'a, Result<Option<AccountMetadata>, TriageStoreError>>;
    /// Captures the existing account/subject binding before browser launch, without writing.
    ///
    /// Unknown accounts return None. Unreadable identity is Corrupt, never absence.
    ///
    /// # Errors
    /// Resolves to a closed failure without provider or backend data; no partial success.
    fn read_upgrade_binding<'a>(
        &'a self,
        account: &'a AccountId,
    ) -> BoxFuture<'a, Result<Option<UpgradeBinding>, TriageStoreError>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    // Contract: new profile/binding/fence composites never render address, subject or local ID.
    // Regression: a future Debug implementation formats raw values instead of redacted types.
    #[test]
    fn metadata_and_upgrade_binding_debug_redact_account_identifiers() {
        let account = AccountId::new("account-sentinel").expect("account");
        let metadata = AccountMetadata::new(
            account.clone(),
            Some(AccountEmail::new("address-sentinel@example.test").expect("email")),
            AccountCapability::ReadOnly,
        );
        let fence = AccountFence::new(account.clone(), IdentityHash::from_bytes([7; 32]));
        let binding = UpgradeBinding::new(
            account,
            AccountSubject::from_broker_validated(Zeroizing::new("subject-sentinel".to_owned()))
                .expect("trusted stored subject"),
        );
        let output = format!("{metadata:?} {fence:?} {binding:?}");
        for sentinel in ["account-sentinel", "address-sentinel", "subject-sentinel"] {
            assert!(!output.contains(sentinel));
        }
        assert!(output.contains("[REDACTED]"));
    }

    // Contract: a known account with no stored address remains distinct from an unknown account.
    // Regression: legacy/NULL addresses erase account metadata or require a fabricated email.
    #[test]
    fn known_account_without_email_preserves_metadata_and_differs_from_unknown() {
        let known = Some(AccountMetadata::new(
            AccountId::new("known-account-sentinel").expect("account"),
            None,
            AccountCapability::Modify,
        ));
        let unknown: Option<AccountMetadata> = None;
        assert_eq!(known.as_ref().map(AccountMetadata::email), Some(None));
        assert_eq!(unknown.as_ref().map(AccountMetadata::email), None);
        let metadata = known.as_ref().expect("known account is retained");
        assert_eq!(metadata.account_id().as_str(), "known-account-sentinel");
        assert_eq!(metadata.capability(), AccountCapability::Modify);
        let debug = format!("{metadata:?}");
        assert!(!debug.contains("known-account-sentinel"));
        assert!(!debug.contains('@'));
    }
}
