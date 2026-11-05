// This Source Code Form is subject to the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Offline bounded views: observed filtering precedes the global display cap.

use crate::{CompositionError, Runtime};
use tersa_application::{
    AccountCapability,
    command::{
        CommandSnapshot, CommandStamp, DesiredMailboxState, MailboxCommandKind,
        MailboxCommandStatus,
    },
    identity::{AccountIdentityStore, IdentityHash},
    mailbox::{
        AccountId, BoxFuture, EnvelopeCursor, MailboxReader, MailboxStoreError, Message,
        MessageEnvelope, MessageId, StoreLimit, ThreadId,
    },
    mailbox_state::{LabelCatalog, TriageStoreError},
    profile::{AccountFence, AccountMetadata, AccountMetadataReader},
    unified_mailbox::{
        UnavailableAccount, UnavailableAccountState, UnifiedMailboxContinuation,
        UnifiedMailboxError, UnifiedMailboxQuery, UnifiedMailboxResult, UnifiedMailboxSource,
    },
};
#[doc(inline)]
pub use tersa_store_sqlcipher::CachedMailboxFilter;
use tersa_store_sqlcipher::{CachedProviderMessage, CachedProviderState, SqlCipherMailboxStore};

/// Explicit account scope for offline cached views.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CachedViewScope {
    /// Every registered applicable account, at most five.
    All,
    /// Exactly this registered account.
    Account(AccountId),
}
/// Opaque keyset progress bound to the same scope, filter and account generations.
///
/// Pages are not mailbox snapshots; restart after sync changes the cache.
#[derive(Clone)]
pub struct CachedViewContinuation {
    scope: CachedViewScope,
    filter: CachedMailboxFilter,
    generations: Vec<(AccountId, u64)>,
    inner: UnifiedMailboxContinuation,
}
impl std::fmt::Debug for CachedViewContinuation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CachedViewContinuation([REDACTED])")
    }
}
/// Pending touched intent, kept separate from complete observed provider state.
#[derive(Clone, Debug)]
pub struct PendingMessageProjection {
    /// Exact durable command/revision.
    pub stamp: CommandStamp,
    /// Actual persisted status, including unrecovered Dispatching.
    pub status: MailboxCommandStatus,
    /// Desired touched fields, never substituted for observed membership.
    pub desired: DesiredMailboxState,
}
/// One raw internal row, requiring sanitization by presentation before terminal output.
#[derive(Debug)]
pub struct CachedViewRow {
    /// Exact owning account for subsequent actions.
    pub account: AccountId,
    /// Cached envelope; its unread bit retains legacy local-read semantics.
    pub envelope: MessageEnvelope,
    /// Stored capability, not proof of usable online authority.
    pub capability: AccountCapability,
    /// Complete cached observation or explicit Unknown/Missing knowledge.
    pub observed: CachedProviderState,
    /// `ReadOnly` uses legacy display; Modify uses observed UNREAD or None when unknown/missing.
    pub display_unread: Option<bool>,
    /// None means identity was not established; Some contains distinct pending intent.
    pub pending: Option<Vec<PendingMessageProjection>>,
}
/// A globally capped cached page with account-local availability and opaque progress.
#[derive(Debug)]
pub struct CachedViewPage {
    /// At most 200 rows, after membership filtering within each account.
    pub rows: Vec<CachedViewRow>,
    /// Accounts whose bounded envelope read was unavailable.
    pub unavailable_accounts: Vec<UnavailableAccount>,
    /// Bound continuation; restart after sync, reset, scope or filter changes.
    pub continuation: Option<CachedViewContinuation>,
}
struct FilteredReader {
    account: AccountId,
    filter: CachedMailboxFilter,
    store: Option<SqlCipherMailboxStore>,
    generation: u64,
    identity: Option<IdentityHash>,
}
impl MailboxReader for FilteredReader {
    fn list_envelopes<'a>(
        &'a self,
        account: &'a AccountId,
        limit: StoreLimit,
    ) -> BoxFuture<'a, Result<Vec<MessageEnvelope>, MailboxStoreError>> {
        self.list_envelopes_after(account, None, limit)
    }
    fn list_envelopes_after<'a>(
        &'a self,
        account: &'a AccountId,
        after: Option<&'a EnvelopeCursor>,
        limit: StoreLimit,
    ) -> BoxFuture<'a, Result<Vec<MessageEnvelope>, MailboxStoreError>> {
        Box::pin(async move {
            self.store
                .as_ref()
                .ok_or(MailboxStoreError::Storage)?
                .list_filtered_envelopes_after(account, &self.filter, after, limit)
        })
    }
    fn thread_envelopes<'a>(
        &'a self,
        account: &'a AccountId,
        thread: &'a ThreadId,
        limit: StoreLimit,
    ) -> BoxFuture<'a, Result<Vec<MessageEnvelope>, MailboxStoreError>> {
        Box::pin(async move {
            self.store
                .as_ref()
                .ok_or(MailboxStoreError::Storage)?
                .thread_envelopes(account, thread, limit)
                .await
        })
    }
    fn get_message<'a>(
        &'a self,
        account: &'a AccountId,
        id: &'a MessageId,
    ) -> BoxFuture<'a, Result<Option<Message>, MailboxStoreError>> {
        Box::pin(async move {
            self.store
                .as_ref()
                .ok_or(MailboxStoreError::Storage)?
                .get_message(account, id)
                .await
        })
    }
}
impl Runtime {
    /// Reads one registered account's cached capability/profile without credentials.
    /// # Errors
    /// Returns existing-only routing or metadata failures.
    pub async fn account_metadata(
        &self,
        account: &AccountId,
    ) -> Result<AccountMetadata, CompositionError> {
        Ok(self
            .installation
            .open_store_for_display(account)?
            .read_metadata(account)
            .await?
            .ok_or(TriageStoreError::UnknownAccount)?)
    }
    /// Reads a complete cached catalog; None is Unknown, not an empty catalog.
    /// # Errors
    /// Returns existing-only routing or cached read failures.
    pub fn cached_label_catalog(
        &self,
        account: &AccountId,
    ) -> Result<Option<LabelCatalog>, CompositionError> {
        Ok(self
            .installation
            .open_store_for_display(account)?
            .cached_label_catalog(account)?)
    }
    /// Reads at most 200 exact-key cached provider states without online authority.
    /// # Errors
    /// Rejects foreign/duplicate/oversized keys, invalid state or unreadable accounts.
    pub fn cached_provider_states(
        &self,
        account: &AccountId,
        ids: &[MessageId],
    ) -> Result<Vec<CachedProviderMessage>, CompositionError> {
        Ok(self
            .installation
            .open_store_for_display(account)?
            .cached_provider_states(account, ids)?)
    }
    /// Reads an offline observed-filter page, capped globally after store filtering.
    ///
    /// No online account permit or token is required. All-scope User-label reads
    /// include only that label's owning account; peers are not failures or matches.
    /// Modify unread display is derived from complete observed membership, while
    /// pending intent remains a separate projection. Source probes may contain 201
    /// rows; provider decoration only receives the final at-most-200 display keys.
    ///
    /// # Errors
    /// Rejects invalid scope/filter/page/continuation, changed account generations
    /// or identity, and failed decoration. Source-open/read failures are account-local.
    pub async fn cached_view(
        &self,
        scope: &CachedViewScope,
        filter: &CachedMailboxFilter,
        page_size: u16,
        continuation: Option<&CachedViewContinuation>,
    ) -> Result<CachedViewPage, CompositionError> {
        if !(1..=200).contains(&page_size) {
            return Err(UnifiedMailboxError::InvalidPageSize.into());
        }
        if continuation.is_some_and(|saved| &saved.scope != scope || &saved.filter != filter) {
            return Err(UnifiedMailboxError::ContinuationMismatch.into());
        }
        let accounts = self.view_accounts(scope, filter)?;
        if accounts.is_empty() {
            if continuation.is_some() {
                return Err(UnifiedMailboxError::ContinuationMismatch.into());
            }
            return Ok(CachedViewPage {
                rows: Vec::new(),
                unavailable_accounts: Vec::new(),
                continuation: None,
            });
        }
        let readers = self.view_readers(&accounts, filter).await?;
        let generations: Vec<_> = readers
            .iter()
            .map(|row| (row.account.clone(), row.generation))
            .collect();
        if continuation.is_some_and(|saved| saved.generations != generations) {
            return Err(UnifiedMailboxError::ContinuationMismatch.into());
        }
        let sources: Vec<_> = readers
            .iter()
            .map(|row| {
                if row.store.is_some() {
                    UnifiedMailboxSource::Ready {
                        account_id: row.account.clone(),
                        reader: row,
                    }
                } else {
                    UnifiedMailboxSource::Unavailable {
                        account_id: row.account.clone(),
                        state: UnavailableAccountState::StoreUnavailable,
                    }
                }
            })
            .collect();
        let UnifiedMailboxResult::Available(document) = UnifiedMailboxQuery::new()
            .execute(
                &sources,
                page_size,
                continuation.map(|value| &value.inner),
                false,
            )
            .await?
        else {
            return Err(CompositionError::Authority);
        };
        let mut rows = Vec::with_capacity(document.rows.len());
        for reader in &readers {
            let selected: Vec<_> = document
                .rows
                .iter()
                .filter(|row| row.account_id == reader.account)
                .collect();
            if !selected.is_empty() {
                self.decorate_view(reader, &selected, &mut rows).await?;
            }
            self.operations
                .get(&reader.account)?
                .validate(reader.generation)?;
            if let Some(store) = &reader.store
                && store.load_identity(&reader.account).await? != reader.identity
            {
                return Err(CompositionError::IdentityChanged);
            }
        }
        // Decoration groups by account; restore the original globally merged order.
        rows.sort_by(|a, b| {
            b.envelope
                .received_at()
                .cmp(&a.envelope.received_at())
                .then_with(|| a.account.as_str().cmp(b.account.as_str()))
                .then_with(|| {
                    a.envelope
                        .message_id()
                        .as_str()
                        .cmp(b.envelope.message_id().as_str())
                })
        });
        Ok(CachedViewPage {
            rows,
            unavailable_accounts: document.unavailable_accounts,
            continuation: document.continuation.map(|inner| CachedViewContinuation {
                scope: scope.clone(),
                filter: filter.clone(),
                generations,
                inner,
            }),
        })
    }
    fn view_accounts(
        &self,
        scope: &CachedViewScope,
        filter: &CachedMailboxFilter,
    ) -> Result<Vec<AccountId>, CompositionError> {
        let registered = self.installation.accounts()?;
        let mut accounts = match scope {
            CachedViewScope::All => registered.clone(),
            CachedViewScope::Account(account) if registered.contains(account) => {
                vec![account.clone()]
            }
            CachedViewScope::Account(_) => return Err(TriageStoreError::UnknownAccount.into()),
        };
        if let CachedMailboxFilter::UserLabel(label) = filter {
            if !accounts.contains(label.account_id()) {
                return Err(TriageStoreError::UnknownAccount.into());
            }
            accounts.retain(|account| account == label.account_id());
        }
        accounts.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        Ok(accounts)
    }
    async fn view_readers(
        &self,
        accounts: &[AccountId],
        filter: &CachedMailboxFilter,
    ) -> Result<Vec<FilteredReader>, CompositionError> {
        let mut readers = Vec::with_capacity(accounts.len());
        for account in accounts {
            let generation = self.operations.get(account)?.generation();
            let store = self.installation.open_store_for_display(account).ok();
            let identity = if let Some(store) = &store {
                store.load_identity(account).await?
            } else {
                None
            };
            readers.push(FilteredReader {
                account: account.clone(),
                filter: filter.clone(),
                store,
                generation,
                identity,
            });
        }
        Ok(readers)
    }
    async fn decorate_view(
        &self,
        reader: &FilteredReader,
        selected: &[&tersa_application::unified_mailbox::UnifiedMailboxRow],
        rows: &mut Vec<CachedViewRow>,
    ) -> Result<(), CompositionError> {
        let store = reader.store.as_ref().ok_or(TriageStoreError::Storage)?;
        let ids: Vec<_> = selected
            .iter()
            .map(|row| row.envelope.message_id().clone())
            .collect();
        let states = store.cached_provider_states(&reader.account, &ids)?;
        let metadata = store
            .read_metadata(&reader.account)
            .await?
            .ok_or(TriageStoreError::UnknownAccount)?;
        let pending = reader
            .identity
            .as_ref()
            .map(|identity| {
                store.pending_commands(&AccountFence::new(reader.account.clone(), identity.clone()))
            })
            .transpose()?;
        for (row, state) in selected.iter().zip(states) {
            let observed = state.state().clone();
            let display_unread = if metadata.capability() == AccountCapability::ReadOnly {
                Some(row.envelope.is_unread())
            } else {
                match &observed {
                    CachedProviderState::Known(labels) => {
                        Some(labels.ids().iter().any(|id| id.as_str() == "UNREAD"))
                    }
                    _ => None,
                }
            };
            rows.push(CachedViewRow {
                account: reader.account.clone(),
                envelope: row.envelope.clone(),
                capability: metadata.capability(),
                observed,
                display_unread,
                pending: pending
                    .as_ref()
                    .map(|commands| projections(commands, row.envelope.message_id())),
            });
        }
        Ok(())
    }
}
fn projections(commands: &[CommandSnapshot], id: &MessageId) -> Vec<PendingMessageProjection> {
    commands
        .iter()
        .filter_map(|snapshot| {
            let desired = match snapshot.command().kind() {
                MailboxCommandKind::MessageState { targets, desired }
                    if targets.ids().contains(id) =>
                {
                    Some(desired.clone())
                }
                MailboxCommandKind::Compensate(batch) => batch
                    .items()
                    .iter()
                    .find(|item| item.message_id() == id)
                    .map(|item| item.condition().restore_state().clone()),
                _ => None,
            }?;
            Some(PendingMessageProjection {
                stamp: snapshot.stamp().clone(),
                status: snapshot.status(),
                desired,
            })
        })
        .collect()
}
