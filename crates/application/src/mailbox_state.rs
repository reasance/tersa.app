// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Defines message-bound metadata and complete observations for the T4 extension ports.
//!
//! Constructors validate structure and identity, not network freshness or durable
//! authority. Trusted producers must bind actual responses to requested keys.
//! Missing is an observed provider absence, never a transport error or snapshot
//! omission. Cached Unknown membership cannot enter these observation values.

use crate::mailbox::{AccountId, MessageEnvelope, MessageId};
use std::fmt;
use tersa_domain::command::MessageTargets;

/// Shared validated label values and constructor errors used by mailbox extension ports.
///
/// Includes complete membership and its explicit Unknown/Observed distinction,
/// known User-label identity, definitions and bounded complete catalogs.
#[doc(inline)]
pub use tersa_domain::label::{
    LabelCatalog, LabelDefinition, LabelError, LabelId, LabelKind, LabelMembership, LabelName,
    ObservedMembership, UserLabel,
};

/// Reports invalid extension-port values without retaining any rejected input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContractError {
    /// An account does not match its enclosing request.
    WrongAccount,
    /// A message or label ID does not match its requested target.
    WrongTarget,
    /// A bounded collection exceeds its limit.
    TooMany,
    /// Required evidence is absent or does not cover exactly the requested set.
    Coverage,
    /// A collection contains duplicate identities or events.
    Duplicate,
    /// History IDs are unordered, duplicated or regressing.
    Order,
    /// Continuation or prefix metadata is inconsistent.
    Continuation,
    /// A closed state or precondition combination is inconsistent.
    State,
}
impl fmt::Display for ContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid mailbox extension contract value")
    }
}
impl std::error::Error for ContractError {}

/// Reports an owning-store failure without backend data or identifiers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TriageStoreError {
    /// The operation failed and made no partial transaction durable.
    Storage,
    /// Stored values are corrupt or unsupported; never silently repair or reset.
    Corrupt,
    /// The selected account does not exist; never provision it.
    UnknownAccount,
    /// Stored identity no longer equals the supplied fence.
    IdentityChanged,
    /// Persisted capability does not authorize commands.
    ReadOnly,
    /// A cursor, command revision, retry ticket or FIFO precondition is stale.
    Conflict,
    /// Atomic admission would exceed either account quota.
    QuotaExceeded,
    /// The requested semantic transition or undo is ineligible.
    NotEligible,
}
impl fmt::Display for TriageStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("mailbox extension store operation failed")
    }
}
impl std::error::Error for TriageStoreError {}

/// Reports a metadata read failure, distinct from an observed missing message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetadataReadError {
    /// A current accepted access session is required.
    AuthorizationRequired,
    /// The provider rejected work due to a rate limit.
    RateLimited,
    /// Profile/baseline retrieval failed with absence, not History-cursor expiry.
    ProfileMissing,
    /// No valid provider response was received.
    Transport,
    /// The bounded response violated the contract.
    InvalidResponse,
}
impl fmt::Display for MetadataReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("mailbox metadata read failed")
    }
}
impl std::error::Error for MetadataReadError {}

/// Identifies one message within exactly one account.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageKey {
    account: AccountId,
    message: MessageId,
}
impl MessageKey {
    /// Binds an opaque provider message ID to its owning account.
    #[must_use]
    pub fn new(account: AccountId, message: MessageId) -> Self {
        Self { account, message }
    }
    /// Returns the owning account.
    #[must_use]
    pub fn account_id(&self) -> &AccountId {
        &self.account
    }
    /// Returns the account-local message ID.
    #[must_use]
    pub fn message_id(&self) -> &MessageId {
        &self.message
    }
}

/// Represents an actual provider absence or complete observed membership.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RemoteMessageState {
    /// A read of this exact target established absence.
    Missing,
    /// A read established all membership within the domain bound.
    Known(LabelMembership),
}

/// Binds complete provider evidence to both account and message identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageObservation {
    key: MessageKey,
    state: RemoteMessageState,
}
impl MessageObservation {
    /// Validates same-account membership for an exact message target.
    ///
    /// # Errors
    /// Rejects membership belonging to a different account.
    pub fn new(key: MessageKey, state: RemoteMessageState) -> Result<Self, ContractError> {
        if matches!(&state, RemoteMessageState::Known(labels) if labels.account_id() != key.account_id())
        {
            return Err(ContractError::WrongAccount);
        }
        Ok(Self { key, state })
    }
    /// Returns the observed account and message key.
    #[must_use]
    pub fn key(&self) -> &MessageKey {
        &self.key
    }
    /// Returns complete known membership or explicit target absence.
    #[must_use]
    pub fn state(&self) -> &RemoteMessageState {
        &self.state
    }
}

/// Holds an envelope and full membership without fetching a complete message body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageMetadata {
    observation: MessageObservation,
    envelope: MessageEnvelope,
}
impl MessageMetadata {
    /// Validates account, envelope ID and membership before metadata can be applied.
    ///
    /// # Errors
    /// Rejects a foreign membership account or mismatched envelope message ID.
    pub fn new(
        key: MessageKey,
        envelope: MessageEnvelope,
        membership: LabelMembership,
    ) -> Result<Self, ContractError> {
        if key.message_id() != envelope.message_id() {
            return Err(ContractError::WrongTarget);
        }
        let observation = MessageObservation::new(key, RemoteMessageState::Known(membership))?;
        Ok(Self {
            observation,
            envelope,
        })
    }
    /// Returns the complete message-bound observation.
    #[must_use]
    pub fn observation(&self) -> &MessageObservation {
        &self.observation
    }
    /// Returns the envelope, independent of legacy local-read presentation.
    #[must_use]
    pub fn envelope(&self) -> &MessageEnvelope {
        &self.envelope
    }
}

/// Returns body-free metadata or explicit absence bound to the requested account/message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MetadataObservation {
    /// The exact requested message was observed missing, never inferred from list omission.
    Missing(MessageKey),
    /// The exact requested message has complete envelope/membership metadata.
    Known(MessageMetadata),
}
impl MetadataObservation {
    /// Returns account and message identity even when the target is missing.
    #[must_use]
    pub fn key(&self) -> &MessageKey {
        match self {
            Self::Missing(key) => key,
            Self::Known(metadata) => metadata.observation().key(),
        }
    }
}

/// Holds exact full-set observation coverage in canonical message-ID order.
///
/// Unknown rows, duplicate observations, omitted targets and extra targets fail
/// closed. This validates coverage, not freshness; runtime owns fresh acquisition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageObservations {
    targets: MessageTargets,
    observations: Vec<MessageObservation>,
}
impl MessageObservations {
    /// Validates exactly one same-account observation for every requested target.
    ///
    /// # Errors
    /// Rejects foreign accounts, duplicate IDs and missing or extra observations.
    pub fn new(
        targets: MessageTargets,
        mut observations: Vec<MessageObservation>,
    ) -> Result<Self, ContractError> {
        if observations.len() != targets.ids().len() {
            return Err(ContractError::Coverage);
        }
        if observations
            .iter()
            .any(|o| o.key.account_id() != targets.account_id())
        {
            return Err(ContractError::WrongAccount);
        }
        observations
            .sort_unstable_by(|a, b| a.key.message_id().as_str().cmp(b.key.message_id().as_str()));
        if observations.windows(2).any(|p| p[0].key == p[1].key) {
            return Err(ContractError::Duplicate);
        }
        if !observations
            .iter()
            .map(|o| o.key.message_id())
            .eq(targets.ids())
        {
            return Err(ContractError::Coverage);
        }
        Ok(Self {
            targets,
            observations,
        })
    }
    /// Returns the full requested account-local target set.
    #[must_use]
    pub fn targets(&self) -> &MessageTargets {
        &self.targets
    }
    /// Returns all complete observations in canonical message-ID order.
    #[must_use]
    pub fn observations(&self) -> &[MessageObservation] {
        &self.observations
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mailbox::{HeaderText, ThreadId, UnixTimestampMillis};
    fn account(value: &str) -> AccountId {
        AccountId::new(value).expect("synthetic account")
    }
    fn key(owner: &str, id: &str) -> MessageKey {
        MessageKey::new(account(owner), MessageId::new(id).expect("synthetic ID"))
    }
    fn envelope(id: &str) -> MessageEnvelope {
        MessageEnvelope::new(
            MessageId::new(id).expect("ID"),
            ThreadId::new("thread-sentinel").expect("thread"),
            HeaderText::new("sender-sentinel").expect("header"),
            HeaderText::new("subject-sentinel").expect("header"),
            HeaderText::new("preview-sentinel").expect("header"),
            UnixTimestampMillis::new(0).expect("time"),
            false,
        )
    }
    fn missing(owner: &str, id: &str) -> MessageObservation {
        MessageObservation::new(key(owner, id), RemoteMessageState::Missing)
            .expect("missing observation")
    }

    // Contract: membership and envelope identity cannot silently change a requested key.
    // Regression: account-local message collisions or a foreign membership is accepted.
    #[test]
    fn metadata_binds_account_message_and_complete_membership() {
        let labels = LabelMembership::new(account("account-sentinel"), vec![])
            .expect("full empty membership");
        let metadata = MessageMetadata::new(
            key("account-sentinel", "message-sentinel"),
            envelope("message-sentinel"),
            labels.clone(),
        )
        .expect("matching metadata");
        assert_eq!(
            metadata.observation().key().message_id().as_str(),
            "message-sentinel"
        );
        assert!(matches!(
            metadata.observation().state(),
            RemoteMessageState::Known(_)
        ));
        assert_eq!(
            MessageMetadata::new(
                key("account-sentinel", "other"),
                envelope("message-sentinel"),
                labels.clone()
            ),
            Err(ContractError::WrongTarget)
        );
        assert_eq!(
            MessageObservation::new(
                key("other", "message-sentinel"),
                RemoteMessageState::Known(labels)
            ),
            Err(ContractError::WrongAccount)
        );
        let absent = MetadataObservation::Missing(key("account-sentinel", "absent-sentinel"));
        assert_eq!(absent.key().message_id().as_str(), "absent-sentinel");
        let debug = format!("{metadata:?} {absent:?}");
        for sentinel in [
            "account-sentinel",
            "message-sentinel",
            "thread-sentinel",
            "sender-sentinel",
            "subject-sentinel",
            "preview-sentinel",
            "absent-sentinel",
        ] {
            assert!(!debug.contains(sentinel));
        }
    }

    // Contract: fresh whole-set evidence has exact unique account/message coverage.
    // Regression: an omitted target, duplicate or extra key supplies false success coverage.
    #[test]
    fn observation_sets_require_exact_coverage_and_canonical_order() {
        let targets = MessageTargets::new(
            account("owner"),
            vec![key("owner", "a").message, key("owner", "b").message],
        )
        .expect("targets");
        let set = MessageObservations::new(
            targets.clone(),
            vec![missing("owner", "b"), missing("owner", "a")],
        )
        .expect("complete set");
        assert_eq!(
            set.observations()
                .iter()
                .map(|o| o.key().message_id().as_str())
                .collect::<Vec<_>>(),
            ["a", "b"]
        );
        for (input, error) in [
            (vec![missing("owner", "a")], ContractError::Coverage),
            (
                vec![missing("owner", "a"), missing("owner", "a")],
                ContractError::Duplicate,
            ),
            (
                vec![missing("owner", "a"), missing("owner", "c")],
                ContractError::Coverage,
            ),
            (
                vec![missing("other", "a"), missing("owner", "b")],
                ContractError::WrongAccount,
            ),
        ] {
            assert_eq!(MessageObservations::new(targets.clone(), input), Err(error));
        }
    }
}
