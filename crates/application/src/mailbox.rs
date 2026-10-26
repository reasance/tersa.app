// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Defines runtime-free inward mailbox ports for remote and local adapters.
//!
//! Returned futures are owned by callers. Dropping one is the caller's
//! cancellation request and releases future-owned state. An adapter should stop
//! before dispatch or commit when possible. An already-dispatched or
//! irreversible operation may finish once, but must not start retries or
//! unbounded detached work after drop.
// Rust guideline compliant 1.0.

use std::fmt;
use std::pin::Pin;

use crate::identity::IdentityHash;

#[doc(inline)]
pub use tersa_domain::mailbox::{
    AccountId, HeaderText, Message, MessageContent, MessageEnvelope, MessageId, ThreadId,
    UnixTimestampMillis,
};

/// Owns a `Send` future without selecting an async runtime.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

const MAX_PAGE_TOKEN_LEN: usize = 4_096;
const MAX_ACCOUNT_EMAIL_LEN: usize = 320;

/// Reports rejected application contract values without exposing their content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MailboxContractError {
    /// A page token was empty.
    EmptyPageToken,
    /// A page token was too long.
    PageTokenTooLong { len: usize },
    /// A page token contained a control character.
    InvalidPageToken,
    /// A requested page size was outside 1 through 500.
    InvalidPageSize { value: u16 },
    /// A requested local result limit was outside 1 through 10,000.
    InvalidStoreLimit { value: u16 },
    /// An account email was too short to hold a local part, `@`, and domain.
    AccountEmailTooShort,
    /// An account email was too long.
    AccountEmailTooLong { len: usize },
    /// An account email lacked `@` or contained whitespace or a control
    /// character.
    InvalidAccountEmail,
}

impl fmt::Display for MailboxContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::EmptyPageToken => "the page token must not be empty",
            Self::PageTokenTooLong { .. } => "the page token exceeds its maximum length",
            Self::InvalidPageToken => "the page token contains an invalid character",
            Self::InvalidPageSize { .. } => "the page size must be between 1 and 500",
            Self::InvalidStoreLimit { .. } => "the store limit must be between 1 and 10000",
            Self::AccountEmailTooShort => "the account email is too short",
            Self::AccountEmailTooLong { .. } => "the account email exceeds its maximum length",
            Self::InvalidAccountEmail => "the account email is not a valid address",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for MailboxContractError {}

/// Holds a bounded opaque provider pagination token.
#[derive(Clone, Eq, PartialEq)]
pub struct PageToken(String);

impl PageToken {
    /// The conservative provider-neutral token cap in bytes.
    pub const MAX_LEN: usize = MAX_PAGE_TOKEN_LEN;
    /// Creates a non-empty token without control characters.
    ///
    /// # Errors
    ///
    /// Returns [`MailboxContractError`] if the token is empty, larger than
    /// [`Self::MAX_LEN`], or contains a Unicode control character.
    pub fn new<T: Into<String>>(value: T) -> Result<Self, MailboxContractError> {
        let value = value.into();
        if value.is_empty() {
            return Err(MailboxContractError::EmptyPageToken);
        }
        if value.len() > Self::MAX_LEN {
            return Err(MailboxContractError::PageTokenTooLong { len: value.len() });
        }
        if value.chars().any(char::is_control) {
            return Err(MailboxContractError::InvalidPageToken);
        }
        Ok(Self(value))
    }
    /// Returns the opaque token text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for PageToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PageToken([REDACTED])")
    }
}

/// Holds the Gmail address of one account for display and resolution.
#[derive(Clone, Eq, PartialEq)]
pub struct AccountEmail(String);

impl AccountEmail {
    /// The conservative provider-neutral address cap in bytes.
    pub const MAX_LEN: usize = MAX_ACCOUNT_EMAIL_LEN;
    /// The shortest address that can hold a local part, `@`, and a domain.
    pub const MIN_LEN: usize = 3;
    /// Creates an address with `@`, without whitespace or control characters.
    ///
    /// # Errors
    ///
    /// Returns [`MailboxContractError`] if the address is shorter than
    /// [`Self::MIN_LEN`], larger than [`Self::MAX_LEN`], missing `@`, or
    /// contains whitespace or an ASCII or C1 control character.
    pub fn new<T: Into<String>>(value: T) -> Result<Self, MailboxContractError> {
        let value = value.into();
        if value.len() < Self::MIN_LEN {
            return Err(MailboxContractError::AccountEmailTooShort);
        }
        if value.len() > Self::MAX_LEN {
            return Err(MailboxContractError::AccountEmailTooLong { len: value.len() });
        }
        // `char::is_control` rejects exactly the ASCII controls and the C1
        // range, so this one test covers both.
        if value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
        {
            return Err(MailboxContractError::InvalidAccountEmail);
        }
        if !value.contains('@') {
            return Err(MailboxContractError::InvalidAccountEmail);
        }
        Ok(Self(value))
    }
    /// Returns the validated address text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AccountEmail {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AccountEmail([REDACTED])")
    }
}

/// Limits one remote provider pagination request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PageSize(u16);

impl PageSize {
    /// Creates a remote pagination size from 1 through 500 inclusive.
    ///
    /// # Errors
    ///
    /// Returns [`MailboxContractError::InvalidPageSize`] outside that range.
    pub fn new(value: u16) -> Result<Self, MailboxContractError> {
        if !(1..=500).contains(&value) {
            return Err(MailboxContractError::InvalidPageSize { value });
        }
        Ok(Self(value))
    }
    /// Returns the validated remote pagination size.
    #[must_use]
    pub fn get(self) -> u16 {
        self.0
    }
}

/// Where a keyset page of envelopes resumes: just after the envelope with
/// this received time and identifier, in listing order (received time
/// descending, then identifier ascending).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvelopeCursor {
    received_at: UnixTimestampMillis,
    message_id: MessageId,
}

impl EnvelopeCursor {
    /// The cursor just after `envelope`.
    #[must_use]
    pub fn after(envelope: &MessageEnvelope) -> Self {
        Self::new(envelope.received_at(), envelope.message_id().clone())
    }

    /// The cursor just after the envelope with `received_at` and `message_id`.
    #[must_use]
    pub fn new(received_at: UnixTimestampMillis, message_id: MessageId) -> Self {
        Self {
            received_at,
            message_id,
        }
    }

    /// The received time of the last envelope already listed.
    #[must_use]
    pub fn received_at(&self) -> UnixTimestampMillis {
        self.received_at
    }

    /// The identifier of the last envelope already listed.
    #[must_use]
    pub fn message_id(&self) -> &MessageId {
        &self.message_id
    }

    /// Whether `envelope` comes after this cursor in listing order.
    #[must_use]
    pub fn precedes(&self, envelope: &MessageEnvelope) -> bool {
        let at = envelope.received_at().as_millis();
        let mine = self.received_at.as_millis();
        at < mine || (at == mine && envelope.message_id().as_str() > self.message_id.as_str())
    }
}

/// Limits one local store listing result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoreLimit(u16);

impl StoreLimit {
    /// The defensive maximum number of envelopes returned by one local query.
    pub const MAX: u16 = 10_000;

    /// Creates a local result limit from 1 through 10,000 inclusive.
    ///
    /// # Errors
    ///
    /// Returns [`MailboxContractError::InvalidStoreLimit`] outside that range.
    pub fn new(value: u16) -> Result<Self, MailboxContractError> {
        if !(1..=Self::MAX).contains(&value) {
            return Err(MailboxContractError::InvalidStoreLimit { value });
        }
        Ok(Self(value))
    }

    /// Returns the validated local result limit.
    #[must_use]
    pub fn get(self) -> u16 {
        self.0
    }
}

/// Contains one remote mailbox listing page.
#[derive(Clone, Eq, PartialEq)]
pub struct Page<T> {
    items: Vec<T>,
    next_token: Option<PageToken>,
}

impl<T> fmt::Debug for Page<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Page")
            .field("item_count", &self.items.len())
            .field("has_next_token", &self.next_token.is_some())
            .finish()
    }
}

impl<T> Page<T> {
    /// Creates a page from its items and optional continuation token.
    #[must_use]
    pub fn new(items: Vec<T>, next_token: Option<PageToken>) -> Self {
        Self { items, next_token }
    }
    /// Returns the page items.
    #[must_use]
    pub fn items(&self) -> &[T] {
        &self.items
    }
    /// Returns the optional continuation token.
    #[must_use]
    pub fn next_token(&self) -> Option<&PageToken> {
        self.next_token.as_ref()
    }
    /// Separates page items from the optional continuation token.
    #[must_use]
    pub fn into_parts(self) -> (Vec<T>, Option<PageToken>) {
        (self.items, self.next_token)
    }
}

/// Describes a remote mailbox failure without provider payloads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RemoteMailboxError {
    /// The account needs a new authorization grant.
    AuthorizationRequired,
    /// The provider rejected work because a rate limit was reached.
    RateLimited,
    /// The requested remote mailbox item does not exist.
    NotFound,
    /// The provider transport failed before a valid response was available.
    Transport,
    /// The provider returned a response that violated the adapter contract.
    InvalidResponse,
}
impl fmt::Display for RemoteMailboxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::AuthorizationRequired => "remote mailbox authorization is required",
            Self::RateLimited => "remote mailbox rate limit reached",
            Self::NotFound => "remote mailbox item was not found",
            Self::Transport => "remote mailbox transport failed",
            Self::InvalidResponse => "remote mailbox returned an invalid response",
        })
    }
}
impl std::error::Error for RemoteMailboxError {}

/// Describes a local mailbox storage failure without backend payloads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MailboxStoreError {
    /// The store could not complete the requested operation.
    Storage,
    /// Stored mailbox data failed an integrity or format check.
    Corrupted,
    /// The recorded account identity changed (or vanished) between the gate's
    /// decision and this write — the in-transaction identity fence aborted the
    /// write so a stale cycle can never persist under a different account.
    IdentityChanged,
    /// A concurrent cycle recorded a different account identity between the gate's
    /// read and its compare-and-set record, so this stale decision was aborted.
    /// Unlike [`Self::IdentityChanged`] (which fails a mailbox write), the caller
    /// must re-read and re-decide the gate against the new state, then retry.
    IdentityRaced,
}
impl fmt::Display for MailboxStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Storage => "local mailbox storage failed",
            Self::Corrupted => "local mailbox storage is corrupted",
            Self::IdentityChanged => "the account identity changed during the write",
            Self::IdentityRaced => "the account identity was recorded concurrently",
        })
    }
}
impl std::error::Error for MailboxStoreError {}

/// Retrieves mailbox data from a remote provider.
///
/// A future revision or checkpoint must be acquired atomically with listing,
/// never through a separate post-list getter. This trait adds no sync protocol.
pub trait RemoteMailbox: Send + Sync {
    /// Lists recent envelopes for an account and optional continuation token.
    ///
    /// Future revision acquisition must be atomic with this listing, never a
    /// separate post-list getter. The returned items preserve provider page
    /// order. Global ordering, including equal-time ordering, is provider
    /// defined or unspecified; callers must not treat this as a lossless sync
    /// snapshot.
    fn list_recent_envelopes<'a>(
        &'a self,
        account: &'a AccountId,
        size: PageSize,
        page_token: Option<&'a PageToken>,
    ) -> BoxFuture<'a, Result<Page<MessageEnvelope>, RemoteMailboxError>>;
    /// Fetches one complete message for an account.
    fn fetch_message<'a>(
        &'a self,
        account: &'a AccountId,
        message_id: &'a MessageId,
    ) -> BoxFuture<'a, Result<Message, RemoteMailboxError>>;
}

/// Reads envelope rows and optional cached complete messages from a local store.
///
/// An envelope includes its existing body-derived preview field. Complete
/// cached bodies are available only through [`MailboxReader::get_message`] when
/// the store holds them; narrower output adapters may project away preview and
/// bodies when their contract requires metadata only. This port still excludes
/// every mutation.
pub trait MailboxReader: Send + Sync {
    /// Lists envelopes in a deterministic total order: received time descending,
    /// then message identifier ascending, limited by the local result limit.
    ///
    /// # Errors
    ///
    /// Returns an opaque store error when the account is not authorized, the
    /// store cannot be read, or persisted values violate domain invariants.
    fn list_envelopes<'a>(
        &'a self,
        account: &'a AccountId,
        limit: StoreLimit,
    ) -> BoxFuture<'a, Result<Vec<MessageEnvelope>, MailboxStoreError>>;
    /// Lists one thread's envelopes in a deterministic total order: received
    /// time ascending, then message identifier ascending, limited by the local
    /// result limit.
    ///
    /// # Errors
    ///
    /// Returns an opaque store error when the account is not authorized, the
    /// store cannot be read, or persisted values violate domain invariants.
    fn thread_envelopes<'a>(
        &'a self,
        account: &'a AccountId,
        thread_id: &'a ThreadId,
        limit: StoreLimit,
    ) -> BoxFuture<'a, Result<Vec<MessageEnvelope>, MailboxStoreError>>;
    /// Returns one complete cached message when a body is present for `message_id`.
    ///
    /// Returns `Ok(None)` when the message is absent **or** only an envelope row
    /// exists without a cached body. Callers that need metadata for body-less
    /// rows must use the envelope listing methods.
    ///
    /// # Errors
    ///
    /// Returns an opaque store error when the account is not authorized, the
    /// store cannot be read, or persisted values violate domain invariants.
    fn get_message<'a>(
        &'a self,
        account: &'a AccountId,
        message_id: &'a MessageId,
    ) -> BoxFuture<'a, Result<Option<Message>, MailboxStoreError>>;
    /// Lists up to `limit` envelopes that come after `after` in the order of
    /// [`Self::list_envelopes`], or from the newest when `after` is `None`.
    /// Paging with the last envelope of each page lists every envelope once.
    ///
    /// The default lists the newest [`StoreLimit::MAX`] envelopes and skips,
    /// so it never pages past them; stores should seek.
    ///
    /// # Errors
    ///
    /// Returns an opaque store error when the account is not authorized, the
    /// store cannot be read, or persisted values violate domain invariants.
    fn list_envelopes_after<'a>(
        &'a self,
        account: &'a AccountId,
        after: Option<&'a EnvelopeCursor>,
        limit: StoreLimit,
    ) -> BoxFuture<'a, Result<Vec<MessageEnvelope>, MailboxStoreError>> {
        Box::pin(async move {
            let all = self
                .list_envelopes(account, StoreLimit(StoreLimit::MAX))
                .await?;
            Ok(all
                .into_iter()
                .filter(|envelope| after.is_none_or(|cursor| cursor.precedes(envelope)))
                .take(usize::from(limit.get()))
                .collect())
        })
    }
    /// Returns the identifiers in `message_ids`, in order, for which
    /// [`Self::get_message`] would return `Ok(None)`: no row, or a row without
    /// a cached body. The sync uses it to skip bodies it already holds.
    ///
    /// The default reads each message; stores should answer without loading
    /// bodies.
    ///
    /// # Errors
    ///
    /// Returns an opaque store error when the account is not authorized, the
    /// store cannot be read, or persisted values violate domain invariants.
    fn uncached_message_ids<'a>(
        &'a self,
        account: &'a AccountId,
        message_ids: &'a [MessageId],
    ) -> BoxFuture<'a, Result<Vec<MessageId>, MailboxStoreError>> {
        Box::pin(async move {
            let mut uncached = Vec::new();
            for id in message_ids {
                if self.get_message(account, id).await?.is_none() {
                    uncached.push(id.clone());
                }
            }
            Ok(uncached)
        })
    }
}

impl<T: MailboxReader + ?Sized> MailboxReader for &T {
    fn list_envelopes<'a>(
        &'a self,
        account: &'a AccountId,
        limit: StoreLimit,
    ) -> BoxFuture<'a, Result<Vec<MessageEnvelope>, MailboxStoreError>> {
        (**self).list_envelopes(account, limit)
    }
    fn thread_envelopes<'a>(
        &'a self,
        account: &'a AccountId,
        thread_id: &'a ThreadId,
        limit: StoreLimit,
    ) -> BoxFuture<'a, Result<Vec<MessageEnvelope>, MailboxStoreError>> {
        (**self).thread_envelopes(account, thread_id, limit)
    }
    fn get_message<'a>(
        &'a self,
        account: &'a AccountId,
        message_id: &'a MessageId,
    ) -> BoxFuture<'a, Result<Option<Message>, MailboxStoreError>> {
        (**self).get_message(account, message_id)
    }
    fn uncached_message_ids<'a>(
        &'a self,
        account: &'a AccountId,
        message_ids: &'a [MessageId],
    ) -> BoxFuture<'a, Result<Vec<MessageId>, MailboxStoreError>> {
        (**self).uncached_message_ids(account, message_ids)
    }
    fn list_envelopes_after<'a>(
        &'a self,
        account: &'a AccountId,
        after: Option<&'a EnvelopeCursor>,
        limit: StoreLimit,
    ) -> BoxFuture<'a, Result<Vec<MessageEnvelope>, MailboxStoreError>> {
        (**self).list_envelopes_after(account, after, limit)
    }
}

/// Persists mailbox data in a local store.
///
/// Store mutations must be atomic and all-or-nothing. After dropping a future,
/// the outcome may be unknown, but partial durable state is forbidden; callers
/// may reconcile by re-reading. Each concrete adapter must test its own
/// cancellation and atomicity behavior. Reusable cross-crate test support is
/// deferred.
pub trait MailboxStore: MailboxReader {
    /// Marks one message as locally read without touching remote labels.
    ///
    /// The product holds only `gmail.readonly`, so server-side UNREAD removal is
    /// out of scope. Local read is sticky under later envelope reconciliation:
    /// a subsequent remote UNREAD snapshot must not re-open a message the user
    /// already opened. Absent messages are a successful no-op.
    ///
    /// # Errors
    ///
    /// Returns an opaque store error when the account is not authorized or the
    /// store cannot be written.
    fn mark_message_read<'a>(
        &'a self,
        account: &'a AccountId,
        message_id: &'a MessageId,
    ) -> BoxFuture<'a, Result<(), MailboxStoreError>>;
    /// Marks every message in one thread as locally read.
    ///
    /// Same local-only and sticky rules as [`Self::mark_message_read`].
    ///
    /// # Errors
    ///
    /// Returns an opaque store error when the account is not authorized or the
    /// store cannot be written.
    fn mark_thread_read<'a>(
        &'a self,
        account: &'a AccountId,
        thread_id: &'a ThreadId,
    ) -> BoxFuture<'a, Result<(), MailboxStoreError>>;
    /// Inserts or replaces mailbox envelopes for an account.
    ///
    /// Unlike [`Self::reconcile_recent_envelopes`], this write is **not** identity-
    /// fenced: it must not be wired into the bounded-sync write path, which carries
    /// a `fence` so a stale cycle can never persist under a changed account. Reserve
    /// it for gate/bootstrap contexts where the caller already holds the identity
    /// invariant; the sync coordinator only ever calls the two fenced writers.
    fn upsert_envelopes<'a>(
        &'a self,
        account: &'a AccountId,
        envelopes: &'a [MessageEnvelope],
    ) -> BoxFuture<'a, Result<(), MailboxStoreError>>;
    /// Inserts or replaces one complete message for an account.
    ///
    /// Not identity-fenced — same caveat as [`Self::upsert_envelopes`]. The fenced
    /// body write on the sync path is [`Self::cache_message_if_present`].
    fn put_message<'a>(
        &'a self,
        account: &'a AccountId,
        message: &'a Message,
    ) -> BoxFuture<'a, Result<(), MailboxStoreError>>;
    /// Atomically reconciles a recent envelope snapshot and returns survivors.
    ///
    /// The mutation upserts `envelopes` while preserving existing cached bodies,
    /// then retains only the newest `keep_limit` rows ordered by received time
    /// descending and message identifier ascending. Returned identifiers form a
    /// duplicate-free subsequence of input encounter order and name only input
    /// rows that survived that deterministic pruning.
    /// Implementations reject an input longer than [`StoreLimit::MAX`].
    ///
    /// `fence` is the account-identity hash the sync cycle computed at its gate.
    /// The write commits only if the store's recorded identity for `account` still
    /// equals `fence` inside the same transaction; a changed or missing identity
    /// aborts with [`MailboxStoreError::IdentityChanged`], so a stale cycle can
    /// never persist envelopes under a different account.
    fn reconcile_recent_envelopes<'a>(
        &'a self,
        account: &'a AccountId,
        envelopes: &'a [MessageEnvelope],
        keep_limit: StoreLimit,
        fence: &'a IdentityHash,
    ) -> BoxFuture<'a, Result<Vec<MessageId>, MailboxStoreError>>;
    /// Caches a complete message only if its envelope row is still present.
    ///
    /// This is one atomic conditional mutation. It never inserts a missing row
    /// and reports whether the existing row was updated. It is fenced by the
    /// account-identity hash exactly as [`Self::reconcile_recent_envelopes`] is:
    /// a stale body-fetch cannot land a cache write under a different account,
    /// even on a colliding message identifier.
    fn cache_message_if_present<'a>(
        &'a self,
        account: &'a AccountId,
        message: &'a Message,
        fence: &'a IdentityHash,
    ) -> BoxFuture<'a, Result<bool, MailboxStoreError>>;
    /// Retrieves an optional complete message.
    fn message<'a>(
        &'a self,
        account: &'a AccountId,
        message_id: &'a MessageId,
    ) -> BoxFuture<'a, Result<Option<Message>, MailboxStoreError>>;
}

impl<T: MailboxStore + ?Sized> MailboxStore for &T {
    fn mark_message_read<'a>(
        &'a self,
        account: &'a AccountId,
        message_id: &'a MessageId,
    ) -> BoxFuture<'a, Result<(), MailboxStoreError>> {
        (**self).mark_message_read(account, message_id)
    }
    fn mark_thread_read<'a>(
        &'a self,
        account: &'a AccountId,
        thread_id: &'a ThreadId,
    ) -> BoxFuture<'a, Result<(), MailboxStoreError>> {
        (**self).mark_thread_read(account, thread_id)
    }
    fn upsert_envelopes<'a>(
        &'a self,
        account: &'a AccountId,
        envelopes: &'a [MessageEnvelope],
    ) -> BoxFuture<'a, Result<(), MailboxStoreError>> {
        (**self).upsert_envelopes(account, envelopes)
    }
    fn put_message<'a>(
        &'a self,
        account: &'a AccountId,
        message: &'a Message,
    ) -> BoxFuture<'a, Result<(), MailboxStoreError>> {
        (**self).put_message(account, message)
    }
    fn reconcile_recent_envelopes<'a>(
        &'a self,
        account: &'a AccountId,
        envelopes: &'a [MessageEnvelope],
        keep_limit: StoreLimit,
        fence: &'a IdentityHash,
    ) -> BoxFuture<'a, Result<Vec<MessageId>, MailboxStoreError>> {
        (**self).reconcile_recent_envelopes(account, envelopes, keep_limit, fence)
    }
    fn cache_message_if_present<'a>(
        &'a self,
        account: &'a AccountId,
        message: &'a Message,
        fence: &'a IdentityHash,
    ) -> BoxFuture<'a, Result<bool, MailboxStoreError>> {
        (**self).cache_message_if_present(account, message, fence)
    }
    fn message<'a>(
        &'a self,
        account: &'a AccountId,
        message_id: &'a MessageId,
    ) -> BoxFuture<'a, Result<Option<Message>, MailboxStoreError>> {
        (**self).message(account, message_id)
    }
}

/// Purges one account's local data on disconnect (OAuth consent withdrawal).
///
/// PERMIT-HOLDER-ONLY, DESTRUCTIVE-ONLY: the caller MUST hold the account
/// slot's whole-cycle permit, so no sync or connect cycle can be in flight or
/// begin while the purge runs, and the purge carries no fence or identity hash
/// — it cannot inject or compare state, only destroy it. One call is one
/// atomic transaction: the mailbox rows and the account-identity row die
/// together, so a retried disconnect after a mid-purge crash never finds a
/// half-torn-down account. The store's account binding is NOT part of the
/// purge: the file stays bound to its account for a clean re-connect.
pub trait AccountPurgeStore: Send + Sync {
    /// Clears the account's mailbox rows and deletes its account-identity row
    /// in one transaction. An account with no recorded data purges as a no-op
    /// success.
    ///
    /// # Errors
    ///
    /// Returns an opaque store error when the transaction cannot be applied or
    /// committed; a failed purge applies nothing.
    fn purge_account<'a>(
        &'a self,
        account: &'a AccountId,
    ) -> BoxFuture<'a, Result<(), MailboxStoreError>>;
}

/// Reference forwarding: a shared reference to a purge store is itself a purge
/// store, so a lazily-opened store can be passed by reference into a generic
/// teardown without moving ownership.
impl<T: AccountPurgeStore + ?Sized> AccountPurgeStore for &T {
    fn purge_account<'a>(
        &'a self,
        account: &'a AccountId,
    ) -> BoxFuture<'a, Result<(), MailboxStoreError>> {
        (**self).purge_account(account)
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "tests assert valid fixtures")]
    use super::*;
    use std::collections::HashMap;
    use std::future::ready;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll, Wake, Waker};

    struct NonDebugItem(&'static str);

    fn account() -> AccountId {
        AccountId::new("account").unwrap()
    }
    fn envelope(id: &str, thread: &str, at: i64) -> MessageEnvelope {
        MessageEnvelope::new(
            MessageId::new(id).unwrap(),
            ThreadId::new(thread).unwrap(),
            HeaderText::new("from-sentinel").unwrap(),
            HeaderText::new("subject-sentinel").unwrap(),
            HeaderText::new("preview-sentinel").unwrap(),
            UnixTimestampMillis::new(at).unwrap(),
            false,
        )
    }

    #[test]
    fn pagination_contracts_enforce_bounds_and_redact_tokens() {
        assert!(PageToken::new("é".repeat(2048)).is_ok());
        assert!(matches!(
            PageToken::new("é".repeat(2049)),
            Err(MailboxContractError::PageTokenTooLong { len: 4098 })
        ));
        assert_eq!(
            PageToken::new(""),
            Err(MailboxContractError::EmptyPageToken)
        );
        assert_eq!(
            PageToken::new("bad\nvalue"),
            Err(MailboxContractError::InvalidPageToken)
        );
        let token = PageToken::new("token-sentinel").unwrap();
        assert!(!format!("{token:?}").contains("token-sentinel"));
        assert_eq!(token, PageToken::new("token-sentinel").unwrap());
        assert_eq!(token.as_str(), "token-sentinel");
        assert_eq!(
            PageSize::new(0),
            Err(MailboxContractError::InvalidPageSize { value: 0 })
        );
        assert_eq!(
            PageSize::new(501),
            Err(MailboxContractError::InvalidPageSize { value: 501 })
        );
        assert_eq!(PageSize::new(1).unwrap().get(), 1);
        assert_eq!(PageSize::new(500).unwrap().get(), 500);
        assert_eq!(
            StoreLimit::new(0),
            Err(MailboxContractError::InvalidStoreLimit { value: 0 })
        );
        assert_eq!(
            StoreLimit::new(10_001),
            Err(MailboxContractError::InvalidStoreLimit { value: 10_001 })
        );
        assert_eq!(StoreLimit::new(StoreLimit::MAX).unwrap().get(), 10_000);
        let page = Page::new(vec![NonDebugItem("item-sentinel")], Some(token));
        assert_eq!(page.items().len(), 1);
        assert_eq!(page.items()[0].0, "item-sentinel");
        assert!(page.next_token().is_some());
        let debug = format!("{page:?}");
        assert!(debug.contains("item_count: 1"));
        assert!(debug.contains("has_next_token: true"));
        assert!(!debug.contains("item-sentinel"));
        assert!(!debug.contains("token-sentinel"));
        assert_eq!(page.into_parts().0.len(), 1);
    }

    #[test]
    fn account_email_contracts_enforce_bounds_and_redact_the_address() {
        assert_eq!(
            AccountEmail::new("ab"),
            Err(MailboxContractError::AccountEmailTooShort)
        );
        assert_eq!(AccountEmail::new("a@b").unwrap().as_str(), "a@b");
        let longest = format!("a@{}", "b".repeat(AccountEmail::MAX_LEN - 2));
        assert_eq!(longest.len(), AccountEmail::MAX_LEN);
        assert!(AccountEmail::new(longest.clone()).is_ok());
        let mut over = longest.clone();
        over.push('b');
        assert!(matches!(
            AccountEmail::new(over),
            Err(MailboxContractError::AccountEmailTooLong { len: 321 })
        ));
        assert_eq!(
            AccountEmail::new("missing-at-sign"),
            Err(MailboxContractError::InvalidAccountEmail)
        );
        for rejected in [
            "a b@c",
            "a\tb@c",
            "a\nb@c",
            "a\u{1}b@c",
            "a\u{7f}b@c",
            "a\u{9f}b@c",
        ] {
            assert_eq!(
                AccountEmail::new(rejected),
                Err(MailboxContractError::InvalidAccountEmail)
            );
        }
        let address = AccountEmail::new("address-sentinel@example.invalid").unwrap();
        assert!(!format!("{address:?}").contains("address-sentinel"));
        assert_eq!(
            address,
            AccountEmail::new("address-sentinel@example.invalid").unwrap()
        );
        assert_eq!(address.as_str(), "address-sentinel@example.invalid");
    }

    struct Noop;
    impl Wake for Noop {
        fn wake(self: Arc<Self>) {}
    }
    fn poll_once<T>(future: &mut BoxFuture<'_, T>) -> Poll<T> {
        let waker = Waker::from(Arc::new(Noop));
        let mut context = Context::from_waker(&waker);
        future.as_mut().poll(&mut context)
    }

    struct DropGuard(Arc<AtomicBool>);
    impl Drop for DropGuard {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    struct Pending {
        _guard: DropGuard,
    }
    impl Future for Pending {
        type Output = Result<Page<MessageEnvelope>, RemoteMailboxError>;
        fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
            Poll::Pending
        }
    }
    struct CancellingRemote {
        dropped: Arc<AtomicBool>,
    }
    impl RemoteMailbox for CancellingRemote {
        fn list_recent_envelopes<'a>(
            &'a self,
            _: &'a AccountId,
            _: PageSize,
            _: Option<&'a PageToken>,
        ) -> BoxFuture<'a, Result<Page<MessageEnvelope>, RemoteMailboxError>> {
            Box::pin(Pending {
                _guard: DropGuard(Arc::clone(&self.dropped)),
            })
        }
        fn fetch_message<'a>(
            &'a self,
            _: &'a AccountId,
            _: &'a MessageId,
        ) -> BoxFuture<'a, Result<Message, RemoteMailboxError>> {
            Box::pin(ready(Err(RemoteMailboxError::NotFound)))
        }
    }

    #[test]
    fn ports_are_object_safe_and_dropping_a_pending_future_releases_owned_state() {
        let dropped = Arc::new(AtomicBool::new(false));
        let remote: Box<dyn RemoteMailbox> = Box::new(CancellingRemote {
            dropped: Arc::clone(&dropped),
        });
        let account = account();
        let mut future = remote.list_recent_envelopes(&account, PageSize::new(1).unwrap(), None);
        assert!(matches!(poll_once(&mut future), Poll::Pending));
        drop(future);
        assert!(dropped.load(Ordering::SeqCst));
        let _: Box<dyn MailboxReader> = Box::new(FakeStore::default());
        let _: Box<dyn MailboxStore> = Box::new(FakeStore::default());
    }

    #[derive(Default)]
    struct FakeStore {
        envelopes: Mutex<HashMap<AccountId, Vec<MessageEnvelope>>>,
        messages: Mutex<HashMap<(AccountId, MessageId), Message>>,
    }
    impl MailboxStore for FakeStore {
        fn mark_message_read<'a>(
            &'a self,
            account: &'a AccountId,
            message_id: &'a MessageId,
        ) -> BoxFuture<'a, Result<(), MailboxStoreError>> {
            mark_fake_read(self, account, Some(message_id), None);
            Box::pin(ready(Ok(())))
        }
        fn mark_thread_read<'a>(
            &'a self,
            account: &'a AccountId,
            thread_id: &'a ThreadId,
        ) -> BoxFuture<'a, Result<(), MailboxStoreError>> {
            mark_fake_read(self, account, None, Some(thread_id));
            Box::pin(ready(Ok(())))
        }
        fn upsert_envelopes<'a>(
            &'a self,
            account: &'a AccountId,
            values: &'a [MessageEnvelope],
        ) -> BoxFuture<'a, Result<(), MailboxStoreError>> {
            let mut map = self.envelopes.lock().unwrap();
            let stored = map.entry(account.clone()).or_default();
            for value in values {
                // Sticky local read: once unread is false, a later remote UNREAD
                // snapshot does not reopen the message.
                let next = if let Some(existing) = stored
                    .iter()
                    .find(|existing| existing.message_id() == value.message_id())
                {
                    if !existing.is_unread() && value.is_unread() {
                        MessageEnvelope::new(
                            value.message_id().clone(),
                            value.thread_id().clone(),
                            value.from().clone(),
                            value.subject().clone(),
                            value.preview().clone(),
                            value.received_at(),
                            false,
                        )
                    } else {
                        value.clone()
                    }
                } else {
                    value.clone()
                };
                if let Some(position) = stored
                    .iter()
                    .position(|existing| existing.message_id() == next.message_id())
                {
                    stored[position] = next;
                } else {
                    stored.push(next);
                }
            }
            Box::pin(ready(Ok(())))
        }
        fn put_message<'a>(
            &'a self,
            account: &'a AccountId,
            value: &'a Message,
        ) -> BoxFuture<'a, Result<(), MailboxStoreError>> {
            self.messages.lock().unwrap().insert(
                (account.clone(), value.envelope().message_id().clone()),
                value.clone(),
            );
            Box::pin(ready(Ok(())))
        }
        fn reconcile_recent_envelopes<'a>(
            &'a self,
            account: &'a AccountId,
            values: &'a [MessageEnvelope],
            keep_limit: StoreLimit,
            _fence: &'a IdentityHash,
        ) -> BoxFuture<'a, Result<Vec<MessageId>, MailboxStoreError>> {
            if values.len() > usize::from(StoreLimit::MAX) {
                return Box::pin(ready(Err(MailboxStoreError::Storage)));
            }
            let mut map = self.envelopes.lock().unwrap();
            let stored = map.entry(account.clone()).or_default();
            for value in values {
                if let Some(position) = stored
                    .iter()
                    .position(|existing| existing.message_id() == value.message_id())
                {
                    stored[position] = value.clone();
                } else {
                    stored.push(value.clone());
                }
            }
            stored.sort_by(|left, right| {
                right
                    .received_at()
                    .cmp(&left.received_at())
                    .then_with(|| left.message_id().as_str().cmp(right.message_id().as_str()))
            });
            stored.truncate(usize::from(keep_limit.get()));
            let survivors = values
                .iter()
                .filter(|value| {
                    stored
                        .iter()
                        .any(|stored_value| stored_value.message_id() == value.message_id())
                })
                .fold(Vec::new(), |mut ids, value| {
                    if !ids.iter().any(|id| id == value.message_id()) {
                        ids.push(value.message_id().clone());
                    }
                    ids
                });
            self.messages
                .lock()
                .unwrap()
                .retain(|(stored_account, id), _| {
                    stored_account != account
                        || stored
                            .iter()
                            .any(|stored_value| stored_value.message_id() == id)
                });
            Box::pin(ready(Ok(survivors)))
        }
        fn cache_message_if_present<'a>(
            &'a self,
            account: &'a AccountId,
            value: &'a Message,
            _fence: &'a IdentityHash,
        ) -> BoxFuture<'a, Result<bool, MailboxStoreError>> {
            let exists = self
                .envelopes
                .lock()
                .unwrap()
                .get(account)
                .is_some_and(|values| {
                    values
                        .iter()
                        .any(|stored| stored.message_id() == value.envelope().message_id())
                });
            if exists {
                self.messages.lock().unwrap().insert(
                    (account.clone(), value.envelope().message_id().clone()),
                    value.clone(),
                );
            }
            Box::pin(ready(Ok(exists)))
        }
        fn message<'a>(
            &'a self,
            account: &'a AccountId,
            id: &'a MessageId,
        ) -> BoxFuture<'a, Result<Option<Message>, MailboxStoreError>> {
            Box::pin(ready(Ok(self
                .messages
                .lock()
                .unwrap()
                .get(&(account.clone(), id.clone()))
                .cloned())))
        }
    }
    fn mark_fake_read(
        store: &FakeStore,
        account: &AccountId,
        message_id: Option<&MessageId>,
        thread_id: Option<&ThreadId>,
    ) {
        let mut map = store.envelopes.lock().unwrap();
        let Some(values) = map.get_mut(account) else {
            return;
        };
        for value in values.iter_mut() {
            let matches_message = message_id.is_none_or(|id| value.message_id() == id);
            let matches_thread = thread_id.is_none_or(|id| value.thread_id() == id);
            if matches_message && matches_thread && value.is_unread() {
                *value = MessageEnvelope::new(
                    value.message_id().clone(),
                    value.thread_id().clone(),
                    value.from().clone(),
                    value.subject().clone(),
                    value.preview().clone(),
                    value.received_at(),
                    false,
                );
            }
        }
        let mut messages = store.messages.lock().unwrap();
        for ((stored_account, stored_id), message) in messages.iter_mut() {
            if stored_account != account {
                continue;
            }
            let matches_message = message_id.is_none_or(|id| stored_id == id);
            let matches_thread = thread_id.is_none_or(|id| message.envelope().thread_id() == id);
            if matches_message && matches_thread && message.envelope().is_unread() {
                let envelope = MessageEnvelope::new(
                    message.envelope().message_id().clone(),
                    message.envelope().thread_id().clone(),
                    message.envelope().from().clone(),
                    message.envelope().subject().clone(),
                    message.envelope().preview().clone(),
                    message.envelope().received_at(),
                    false,
                );
                *message = Message::new(envelope, message.content().clone());
            }
        }
    }

    impl MailboxReader for FakeStore {
        fn list_envelopes<'a>(
            &'a self,
            account: &'a AccountId,
            limit: StoreLimit,
        ) -> BoxFuture<'a, Result<Vec<MessageEnvelope>, MailboxStoreError>> {
            let mut values = self
                .envelopes
                .lock()
                .unwrap()
                .get(account)
                .cloned()
                .unwrap_or_default();
            values.sort_by(|left, right| {
                right
                    .received_at()
                    .cmp(&left.received_at())
                    .then_with(|| left.message_id().as_str().cmp(right.message_id().as_str()))
            });
            values.truncate(usize::from(limit.get()));
            Box::pin(ready(Ok(values)))
        }
        fn thread_envelopes<'a>(
            &'a self,
            account: &'a AccountId,
            thread: &'a ThreadId,
            limit: StoreLimit,
        ) -> BoxFuture<'a, Result<Vec<MessageEnvelope>, MailboxStoreError>> {
            let mut values: Vec<_> = self
                .envelopes
                .lock()
                .unwrap()
                .get(account)
                .into_iter()
                .flatten()
                .filter(|value| value.thread_id() == thread)
                .cloned()
                .collect();
            values.sort_by(|left, right| {
                left.received_at()
                    .cmp(&right.received_at())
                    .then_with(|| left.message_id().as_str().cmp(right.message_id().as_str()))
            });
            values.truncate(usize::from(limit.get()));
            Box::pin(ready(Ok(values)))
        }
        fn get_message<'a>(
            &'a self,
            account: &'a AccountId,
            message_id: &'a MessageId,
        ) -> BoxFuture<'a, Result<Option<Message>, MailboxStoreError>> {
            Box::pin(ready(Ok(self
                .messages
                .lock()
                .unwrap()
                .get(&(account.clone(), message_id.clone()))
                .cloned())))
        }
    }

    #[test]
    fn the_default_keyset_listing_resumes_after_the_cursor() {
        let store = FakeStore::default();
        let account = account();
        let values = [
            envelope("old", "thread", 1),
            envelope("thread-b", "thread", 3),
            envelope("thread-a", "thread", 3),
            envelope("middle", "other", 2),
        ];
        let mut stored = store.upsert_envelopes(&account, &values);
        assert_eq!(poll_once(&mut stored), Poll::Ready(Ok(())));
        let mut ids = Vec::new();
        let mut cursor: Option<EnvelopeCursor> = None;
        loop {
            let page = {
                let mut page = store.list_envelopes_after(
                    &account,
                    cursor.as_ref(),
                    StoreLimit::new(1).unwrap(),
                );
                let Poll::Ready(Ok(page)) = poll_once(&mut page) else {
                    panic!("the fake is immediately ready");
                };
                page
            };
            let Some(last) = page.last() else { break };
            cursor = Some(EnvelopeCursor::after(last));
            ids.extend(
                page.iter()
                    .map(|value| value.message_id().as_str().to_owned()),
            );
        }
        assert_eq!(ids, ["thread-a", "thread-b", "middle", "old"]);
    }
}
