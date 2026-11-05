// This Source Code Form is subject to the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Closed composition errors and existing-account identity contexts.

use crate::{FlowError, InstallationError, Runtime};
use tersa_application::{
    command::CommandError,
    command_coordinator::CommandCoordinatorError,
    identity::{AccountIdentityStore, GateError},
    mailbox::{AccountId, MailboxStoreError},
    mailbox_state::{ContractError, MetadataReadError, TriageStoreError},
    profile::AccountFence,
    unified_mailbox::UnifiedMailboxError,
};
use tersa_store_sqlcipher::SqlCipherMailboxStore;

/// Reports runtime composition failure without provider text or credentials.
#[derive(Debug)]
#[non_exhaustive]
pub enum CompositionError {
    /// Existing account routing, authorization or session failed.
    Flow(FlowError),
    /// Local cache access failed.
    Store(MailboxStoreError),
    /// A durable triage guard or read failed.
    Triage(TriageStoreError),
    /// Identity admission failed.
    Gate(GateError),
    /// Command coordination failed before a report was available.
    Command(CommandCoordinatorError),
    /// Closed user intent was invalid.
    Intent(CommandError),
    /// An account, target or saved context did not match.
    Contract(ContractError),
    /// A cached view request or continuation was invalid.
    View(UnifiedMailboxError),
    /// Current session authority, expiry or generation is unavailable.
    Authority,
    /// A readonly provider observation failed.
    Metadata(MetadataReadError),
    /// Current identity no longer matches the admitted work.
    IdentityChanged,
    /// No retained Complete command is available for undo.
    NoUndo,
    /// Secure command identity generation failed.
    Entropy,
}
impl std::fmt::Display for CompositionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("account runtime composition could not complete")
    }
}
impl std::error::Error for CompositionError {}
macro_rules! conversion {
    ($ty:ty, $variant:ident) => {
        impl From<$ty> for CompositionError {
            fn from(value: $ty) -> Self {
                Self::$variant(value)
            }
        }
    };
}
conversion!(FlowError, Flow);
conversion!(MetadataReadError, Metadata);
conversion!(MailboxStoreError, Store);
conversion!(TriageStoreError, Triage);
conversion!(GateError, Gate);
conversion!(CommandCoordinatorError, Command);
conversion!(CommandError, Intent);
conversion!(ContractError, Contract);
conversion!(UnifiedMailboxError, View);
impl From<InstallationError> for CompositionError {
    fn from(value: InstallationError) -> Self {
        Self::Flow(FlowError::Installation(value))
    }
}
impl Runtime {
    pub(crate) async fn local_context(
        &self,
        account: &AccountId,
    ) -> Result<(SqlCipherMailboxStore, AccountFence), CompositionError> {
        let store = self.installation.open_store(account)?;
        let identity = store
            .load_identity(account)
            .await?
            .ok_or(TriageStoreError::NotEligible)?;
        Ok((store, AccountFence::new(account.clone(), identity)))
    }
}
