// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Merges bounded account-local keyset windows without a runtime or mutations.
//!
//! Each page reads at most one window of `page_size + 1` per ready account.
//! Production readers must override [`MailboxReader::list_envelopes_after`](crate::mailbox::MailboxReader::list_envelopes_after)
//! with a bounded seek: its trait default internally materializes 10,000 rows.
//! Continuations retain only account-local last-consumed cursors, exhaustion,
//! and availability. Failed readers stay unavailable through that continuation
//! chain; a fresh query is required to retry them. There is no mailbox snapshot:
//! callers restart after sync rather than treating continuations as snapshots.
//! Envelopes remain internal, unsanitized application data, never terminal text.
// Rust guideline compliant 1.0.

use std::collections::VecDeque;
use std::fmt;

use crate::mailbox::{
    AccountId, BoxFuture, EnvelopeCursor, MailboxReader, MessageEnvelope, StoreLimit,
};

/// The ADR 0026 beta limit on accounts in one query.
pub const MAX_ACCOUNTS: usize = 5;
/// The ADR 0026 global output cap; one additional row per source probes for more.
pub const MAX_PAGE_SIZE: u16 = 200;

/// Safe, account-local unavailability with no provider error payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnavailableAccountState {
    /// The caller already knows authorization is required.
    AuthorizationRequired,
    /// The caller or a failed read reports an unavailable local store.
    StoreUnavailable,
}

/// One explicitly authorized reader or caller-supplied unavailable account.
#[derive(Clone)]
pub enum UnifiedMailboxSource<'a> {
    /// Reads only the named account through its existing mailbox port.
    Ready {
        /// The opaque account routing key.
        account_id: AccountId,
        /// Must implement a bounded keyset seek in production.
        reader: &'a dyn MailboxReader,
    },
    /// Contributes an availability state without any reader call.
    Unavailable {
        /// The opaque account routing key.
        account_id: AccountId,
        /// Authorization is explicit input, never inferred from a store error.
        state: UnavailableAccountState,
    },
}

impl UnifiedMailboxSource<'_> {
    /// Returns the account's opaque routing key.
    #[must_use]
    pub fn account_id(&self) -> &AccountId {
        match self {
            Self::Ready { account_id, .. } | Self::Unavailable { account_id, .. } => account_id,
        }
    }

    fn disposition(&self) -> Disposition {
        match self {
            Self::Ready { .. } => Disposition::Ready,
            Self::Unavailable { state, .. } => Disposition::Unavailable(*state),
        }
    }
}

impl fmt::Debug for UnifiedMailboxSource<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("UnifiedMailboxSource([REDACTED])")
    }
}

/// One raw envelope and its originating account; message IDs are account-local.
#[derive(Clone, Eq, PartialEq)]
pub struct UnifiedMailboxRow {
    /// The account required for every subsequent message route.
    pub account_id: AccountId,
    /// Internal application data; sanitize before display.
    pub envelope: MessageEnvelope,
}

impl fmt::Debug for UnifiedMailboxRow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("UnifiedMailboxRow([REDACTED])")
    }
}

/// An unavailable account contributes no rows to the document.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnavailableAccount {
    /// The account whose rows are absent.
    pub account_id: AccountId,
    /// A content-free state, distinct from authorization of other accounts.
    pub state: UnavailableAccountState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Disposition {
    Ready,
    Unavailable(UnavailableAccountState),
}

#[derive(Clone, Eq, PartialEq)]
struct AccountContinuation {
    account_id: AccountId,
    disposition: Disposition,
    consumed: Option<EnvelopeCursor>,
    exhausted: bool,
    failure: Option<UnavailableAccountState>,
}

/// Opaque, bounded progress for the same account set and input dispositions.
///
/// Contains at most five entries, sorted by account ID. Cursors advance only
/// for emitted rows, so fetched rows that lose a merge are not skipped. Page
/// size and input order may change between calls. A deleted cursor target is
/// still a valid seek. This value holds no reader, envelope, or credential.
#[derive(Clone, Eq, PartialEq)]
pub struct UnifiedMailboxContinuation {
    accounts: Vec<AccountContinuation>,
}

impl fmt::Debug for UnifiedMailboxContinuation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("UnifiedMailboxContinuation([REDACTED])")
    }
}

/// A bounded page and safe availability states, both in deterministic order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnifiedMailboxDocument {
    /// At most the requested number of rows in global listing order.
    pub rows: Vec<UnifiedMailboxRow>,
    /// Account-local unavailability, ordered by opaque account ID.
    pub unavailable_accounts: Vec<UnavailableAccount>,
    /// Present exactly when this read observed additional available rows.
    pub continuation: Option<UnifiedMailboxContinuation>,
}

/// Locked queries expose only the unit variant, with no account identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UnifiedMailboxResult {
    /// Lock takes precedence over all input validation and performs no reads.
    Locked,
    /// Available rows may coexist with account-local unavailable states.
    Available(UnifiedMailboxDocument),
}

/// Closed input errors that disclose no identifiers, cursors, or message data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnifiedMailboxError {
    /// A query must have between one and five distinct accounts.
    InvalidAccountCount,
    /// The same account was supplied more than once.
    DuplicateAccount,
    /// A page size must be between one and 200 inclusive.
    InvalidPageSize,
    /// The continuation names a different account set or input disposition.
    ContinuationMismatch,
}

impl fmt::Display for UnifiedMailboxError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidAccountCount => "the unified query requires one through five accounts",
            Self::DuplicateAccount => "the unified query requires distinct accounts",
            Self::InvalidPageSize => "the unified page size must be one through 200",
            Self::ContinuationMismatch => "the unified continuation does not match the request",
        })
    }
}
impl std::error::Error for UnifiedMailboxError {}

/// Executes read-only unified pages; the caller owns polling and cancellation.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnifiedMailboxQuery;

impl UnifiedMailboxQuery {
    /// Creates a stateless query without acquiring resources.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Returns one deterministic page, or only `Locked` before any validation.
    ///
    /// Accounts and continuations are validated before all reader calls. Reads
    /// run sequentially; dropping this future drops the active read and never
    /// starts a later one. A ready reader's error or malformed keyset response
    /// becomes `StoreUnavailable` for that account, never an authorization
    /// failure. Failures persist until the caller starts a fresh query.
    ///
    /// # Errors
    ///
    /// Returns [`UnifiedMailboxError`] for invalid account/page bounds,
    /// duplicates, or a continuation with different accounts or dispositions.
    ///
    /// # Panics
    ///
    /// Panics if an internal validated-page or nonempty-window invariant is violated.
    #[must_use]
    pub fn execute<'a>(
        &self,
        sources: &'a [UnifiedMailboxSource<'a>],
        page_size: u16,
        continuation: Option<&'a UnifiedMailboxContinuation>,
        locked: bool,
    ) -> BoxFuture<'a, Result<UnifiedMailboxResult, UnifiedMailboxError>> {
        Box::pin(async move {
            if locked {
                return Ok(UnifiedMailboxResult::Locked);
            }
            let (sources, mut accounts) = validate(sources, page_size, continuation)?;
            // Validation proves this is at most 201, within the existing port.
            let probe = StoreLimit::new(page_size + 1).expect("validated query page size");
            let mut windows = Vec::with_capacity(accounts.len());
            for (source, progress) in sources.iter().zip(&mut accounts) {
                let mut rows = VecDeque::new();
                if let UnifiedMailboxSource::Ready { reader, account_id } = source
                    && !progress.exhausted
                    && progress.failure.is_none()
                {
                    match reader
                        .list_envelopes_after(account_id, progress.consumed.as_ref(), probe)
                        .await
                    {
                        Ok(envelopes)
                            if valid_window(&envelopes, progress.consumed.as_ref(), probe) =>
                        {
                            progress.exhausted = envelopes.len() < usize::from(probe.get());
                            rows = envelopes.into();
                        }
                        _ => progress.failure = Some(UnavailableAccountState::StoreUnavailable),
                    }
                }
                windows.push(rows);
            }
            let mut rows = Vec::with_capacity(usize::from(page_size));
            while rows.len() < usize::from(page_size) {
                let next = windows
                    .iter()
                    .enumerate()
                    .filter_map(|(index, window)| window.front().map(|envelope| (index, envelope)))
                    .min_by(|(left_index, left), (right_index, right)| {
                        right
                            .received_at()
                            .cmp(&left.received_at())
                            .then_with(|| {
                                accounts[*left_index]
                                    .account_id
                                    .as_str()
                                    .cmp(accounts[*right_index].account_id.as_str())
                            })
                            .then_with(|| {
                                left.message_id().as_str().cmp(right.message_id().as_str())
                            })
                    })
                    .map(|(index, _)| index);
                let Some(index) = next else {
                    break;
                };
                let envelope = windows[index]
                    .pop_front()
                    .expect("selected nonempty window");
                accounts[index].consumed = Some(EnvelopeCursor::after(&envelope));
                rows.push(UnifiedMailboxRow {
                    account_id: accounts[index].account_id.clone(),
                    envelope,
                });
            }
            let mut more = false;
            for (progress, window) in accounts.iter_mut().zip(windows) {
                if !window.is_empty() {
                    // A fetched but unconsumed tail is sought again next time.
                    progress.exhausted = false;
                    more = true;
                }
            }
            let unavailable_accounts = accounts
                .iter()
                .filter_map(|progress| {
                    let state = match progress.disposition {
                        Disposition::Unavailable(state) => Some(state),
                        Disposition::Ready => progress.failure,
                    }?;
                    Some(UnavailableAccount {
                        account_id: progress.account_id.clone(),
                        state,
                    })
                })
                .collect();
            Ok(UnifiedMailboxResult::Available(UnifiedMailboxDocument {
                rows,
                unavailable_accounts,
                continuation: more.then_some(UnifiedMailboxContinuation { accounts }),
            }))
        })
    }
}

fn valid_window(
    rows: &[MessageEnvelope],
    after: Option<&EnvelopeCursor>,
    limit: StoreLimit,
) -> bool {
    rows.len() <= usize::from(limit.get())
        && rows
            .iter()
            .all(|row| after.is_none_or(|cursor| cursor.precedes(row)))
        && rows
            .windows(2)
            .all(|pair| EnvelopeCursor::after(&pair[0]).precedes(&pair[1]))
}

type ValidatedSources<'a> = (Vec<&'a UnifiedMailboxSource<'a>>, Vec<AccountContinuation>);

fn validate<'a>(
    sources: &'a [UnifiedMailboxSource<'a>],
    page_size: u16,
    continuation: Option<&UnifiedMailboxContinuation>,
) -> Result<ValidatedSources<'a>, UnifiedMailboxError> {
    if !(1..=MAX_ACCOUNTS).contains(&sources.len()) {
        return Err(UnifiedMailboxError::InvalidAccountCount);
    }
    if !(1..=MAX_PAGE_SIZE).contains(&page_size) {
        return Err(UnifiedMailboxError::InvalidPageSize);
    }
    let mut sorted: Vec<_> = sources.iter().collect();
    sorted.sort_unstable_by(|left, right| {
        left.account_id().as_str().cmp(right.account_id().as_str())
    });
    if sorted
        .windows(2)
        .any(|pair| pair[0].account_id() == pair[1].account_id())
    {
        return Err(UnifiedMailboxError::DuplicateAccount);
    }
    let accounts = if let Some(continuation) = continuation {
        if continuation.accounts.len() != sorted.len()
            || continuation
                .accounts
                .iter()
                .zip(&sorted)
                .any(|(saved, source)| {
                    saved.account_id != *source.account_id()
                        || saved.disposition != source.disposition()
                })
        {
            return Err(UnifiedMailboxError::ContinuationMismatch);
        }
        continuation.accounts.clone()
    } else {
        sorted
            .iter()
            .map(|source| AccountContinuation {
                account_id: source.account_id().clone(),
                disposition: source.disposition(),
                consumed: None,
                exhausted: false,
                failure: None,
            })
            .collect()
    };
    Ok((sorted, accounts))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll, Waker};

    use crate::mailbox::{
        HeaderText, MailboxStoreError, Message, MessageId, ThreadId, UnixTimestampMillis,
    };

    use super::*;

    struct Reader {
        account: AccountId,
        rows: Mutex<Vec<MessageEnvelope>>,
        calls: Mutex<Vec<(Option<EnvelopeCursor>, u16)>>,
        error: Mutex<Option<MailboxStoreError>>,
        malformed: Mutex<Option<Vec<MessageEnvelope>>>,
        pending: bool,
        dropped: Arc<AtomicBool>,
    }

    impl Reader {
        fn new(account: &str, rows: Vec<MessageEnvelope>) -> Self {
            Self {
                account: id(account),
                rows: Mutex::new(rows),
                calls: Mutex::new(Vec::new()),
                error: Mutex::new(None),
                malformed: Mutex::new(None),
                pending: false,
                dropped: Arc::new(AtomicBool::new(false)),
            }
        }

        fn source(&self) -> UnifiedMailboxSource<'_> {
            UnifiedMailboxSource::Ready {
                account_id: self.account.clone(),
                reader: self,
            }
        }

        fn calls(&self) -> Vec<(Option<EnvelopeCursor>, u16)> {
            self.calls.lock().expect("fixture lock").clone()
        }
    }

    struct Dropped(Arc<AtomicBool>);
    impl Drop for Dropped {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    impl MailboxReader for Reader {
        fn list_envelopes<'a>(
            &'a self,
            _: &'a AccountId,
            _: StoreLimit,
        ) -> BoxFuture<'a, Result<Vec<MessageEnvelope>, MailboxStoreError>> {
            panic!("unified reads must not call the 10,000-row fallback")
        }

        fn thread_envelopes<'a>(
            &'a self,
            _: &'a AccountId,
            _: &'a ThreadId,
            _: StoreLimit,
        ) -> BoxFuture<'a, Result<Vec<MessageEnvelope>, MailboxStoreError>> {
            panic!("unified reads must not query threads")
        }

        fn get_message<'a>(
            &'a self,
            _: &'a AccountId,
            _: &'a MessageId,
        ) -> BoxFuture<'a, Result<Option<Message>, MailboxStoreError>> {
            panic!("unified reads must not load message bodies")
        }

        fn list_envelopes_after<'a>(
            &'a self,
            account: &'a AccountId,
            after: Option<&'a EnvelopeCursor>,
            limit: StoreLimit,
        ) -> BoxFuture<'a, Result<Vec<MessageEnvelope>, MailboxStoreError>> {
            Box::pin(async move {
                assert_eq!(
                    account, &self.account,
                    "route must select the exact account"
                );
                assert!(limit.get() <= MAX_PAGE_SIZE + 1);
                self.calls
                    .lock()
                    .expect("fixture lock")
                    .push((after.cloned(), limit.get()));
                if self.pending {
                    let _dropped = Dropped(Arc::clone(&self.dropped));
                    std::future::pending::<()>().await;
                }
                if let Some(error) = *self.error.lock().expect("fixture lock") {
                    return Err(error);
                }
                if let Some(rows) = self.malformed.lock().expect("fixture lock").as_ref() {
                    return Ok(rows.clone());
                }
                Ok(self
                    .rows
                    .lock()
                    .expect("fixture lock")
                    .iter()
                    .filter(|row| after.is_none_or(|cursor| cursor.precedes(row)))
                    .take(usize::from(limit.get()))
                    .cloned()
                    .collect())
            })
        }
    }

    fn id(text: &str) -> AccountId {
        AccountId::new(text).expect("valid account")
    }

    fn envelope(message_id: &str, received_at: i64) -> MessageEnvelope {
        MessageEnvelope::new(
            MessageId::new(message_id).expect("valid message ID"),
            ThreadId::new("private-thread").expect("valid thread"),
            HeaderText::new("private-sender@example.com").expect("valid sender"),
            HeaderText::new("private-subject").expect("valid subject"),
            HeaderText::new("private-preview").expect("valid preview"),
            UnixTimestampMillis::new(received_at).expect("valid timestamp"),
            true,
        )
    }

    fn run<T>(future: impl Future<Output = T>) -> T {
        let mut future = std::pin::pin!(future);
        match future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            Poll::Ready(output) => output,
            Poll::Pending => panic!("fixture should complete without an async runtime"),
        }
    }

    fn page(
        sources: &[UnifiedMailboxSource<'_>],
        size: u16,
        continuation: Option<&UnifiedMailboxContinuation>,
    ) -> UnifiedMailboxDocument {
        match run(UnifiedMailboxQuery::new().execute(sources, size, continuation, false))
            .expect("valid query")
        {
            UnifiedMailboxResult::Available(document) => document,
            UnifiedMailboxResult::Locked => panic!("unlocked request"),
        }
    }

    fn named(rows: &[UnifiedMailboxRow]) -> Vec<(String, String, i64)> {
        rows.iter()
            .map(|row| {
                (
                    row.account_id.as_str().to_owned(),
                    row.envelope.message_id().as_str().to_owned(),
                    row.envelope.received_at().as_millis(),
                )
            })
            .collect()
    }

    #[test]
    fn five_full_accounts_are_read_once_with_a_201_row_ceiling() {
        let readers: Vec<_> = (0..5)
            .map(|account| {
                Reader::new(
                    &format!("acct_{account}"),
                    (0..250)
                        .map(|row| envelope(&format!("m{row}"), 2_000 - row * 5 - account))
                        .collect(),
                )
            })
            .collect();
        let sources: Vec<_> = readers.iter().map(Reader::source).collect();
        let document = page(&sources, 200, None);
        assert_eq!(document.rows.len(), 200);
        assert!(document.continuation.is_some());
        assert!(document.unavailable_accounts.is_empty());
        for (index, row) in document.rows.iter().enumerate() {
            assert_eq!(row.account_id.as_str(), format!("acct_{}", index % 5));
            assert_eq!(
                row.envelope.received_at().as_millis(),
                2_000 - i64::try_from(index).expect("bounded index")
            );
        }
        for reader in &readers {
            assert_eq!(
                reader.calls(),
                [(None, 201)],
                "one bounded read per ready account"
            );
        }
    }

    #[test]
    fn tied_duplicate_ids_walk_once_and_input_order_does_not_change_progress() {
        let a = Reader::new(
            "acct_a",
            vec![envelope("same", 20), envelope("z", 20), envelope("old", 10)],
        );
        let b = Reader::new(
            "acct_b",
            vec![envelope("same", 20), envelope("z", 20), envelope("old", 10)],
        );
        let expected = [
            ("acct_a", "same", 20),
            ("acct_a", "z", 20),
            ("acct_b", "same", 20),
            ("acct_b", "z", 20),
            ("acct_a", "old", 10),
            ("acct_b", "old", 10),
        ];
        for size in [1, 2] {
            let sources = [a.source(), b.source()];
            let reversed = [b.source(), a.source()];
            let mut continuation = None;
            let mut seen = Vec::new();
            for step in 0..6 {
                let document = page(&sources, size, continuation.as_ref());
                let shuffled = page(&reversed, size, continuation.as_ref());
                assert_eq!(
                    document, shuffled,
                    "input order must not affect rows or cursors"
                );
                assert!(document.rows.len() <= usize::from(size));
                if step == 0 {
                    let token = document.continuation.as_ref().expect("more rows");
                    assert!(
                        token.accounts[1].consumed.is_none(),
                        "losing account must not advance"
                    );
                }
                seen.extend(named(&document.rows));
                continuation = document.continuation;
                if continuation.is_none() {
                    break;
                }
            }
            assert!(continuation.is_none(), "finite pagination must finish");
            let wanted: Vec<_> = expected
                .iter()
                .map(|(account, message, at)| ((*account).to_owned(), (*message).to_owned(), *at))
                .collect();
            assert_eq!(seen, wanted);
            assert!(
                a.calls()
                    .iter()
                    .chain(b.calls().iter())
                    .all(|(_, limit)| *limit <= size + 1)
            );
            a.calls.lock().expect("fixture lock").clear();
            b.calls.lock().expect("fixture lock").clear();
        }
    }

    #[test]
    fn losing_account_appears_on_page_two_and_exhausted_account_is_not_reread() {
        let a = Reader::new("acct_a", vec![envelope("same", 30)]);
        let b = Reader::new("acct_b", vec![envelope("same", 20), envelope("older", 10)]);
        let sources = [b.source(), a.source()];
        let first = page(&sources, 1, None);
        assert_eq!(first.rows[0].account_id, id("acct_a"));
        let second = page(&sources, 1, first.continuation.as_ref());
        assert_eq!(second.rows[0].account_id, id("acct_b"));
        let third = page(&sources, 2, second.continuation.as_ref());
        assert_eq!(third.rows.len(), 1);
        assert_eq!(third.rows[0].envelope.message_id().as_str(), "older");
        assert!(
            third.continuation.is_none(),
            "exact end, not an unnecessary next page"
        );
        assert_eq!(
            a.calls().len(),
            1,
            "a known exhausted account needs no later read"
        );
        assert_eq!(b.calls().len(), 3);
    }

    #[test]
    fn explicit_authorization_and_every_reader_error_remain_distinct() {
        for error in [
            MailboxStoreError::Storage,
            MailboxStoreError::Corrupted,
            MailboxStoreError::IdentityChanged,
            MailboxStoreError::IdentityRaced,
        ] {
            let good = Reader::new("acct_good", vec![envelope("same", 20)]);
            let bad = Reader::new("acct_bad", vec![envelope("same", 30)]);
            *bad.error.lock().expect("fixture lock") = Some(error);
            let sources = [
                good.source(),
                UnifiedMailboxSource::Unavailable {
                    account_id: id("acct_auth"),
                    state: UnavailableAccountState::AuthorizationRequired,
                },
                bad.source(),
            ];
            let document = page(&sources, 200, None);
            assert_eq!(document.rows.len(), 1);
            assert_eq!(document.rows[0].account_id, id("acct_good"));
            assert_eq!(
                document.unavailable_accounts,
                [
                    UnavailableAccount {
                        account_id: id("acct_auth"),
                        state: UnavailableAccountState::AuthorizationRequired
                    },
                    UnavailableAccount {
                        account_id: id("acct_bad"),
                        state: UnavailableAccountState::StoreUnavailable
                    },
                ]
            );
            assert!(document.continuation.is_none());
            assert_eq!(good.calls().len(), 1);
            assert_eq!(bad.calls().len(), 1);
        }
    }

    #[test]
    fn failures_persist_until_fresh_query_without_retrying_or_reordering() {
        let a = Reader::new("acct_a", vec![envelope("newer", 40)]);
        let b = Reader::new(
            "acct_b",
            vec![
                envelope("first", 30),
                envelope("second", 20),
                envelope("third", 10),
            ],
        );
        *a.error.lock().expect("fixture lock") = Some(MailboxStoreError::Storage);
        let sources = [a.source(), b.source()];
        let first = page(&sources, 1, None);
        *a.error.lock().expect("fixture lock") = None;
        let second = page(&sources, 1, first.continuation.as_ref());
        assert_eq!(second.rows[0].envelope.message_id().as_str(), "second");
        assert_eq!(second.unavailable_accounts, first.unavailable_accounts);
        assert_eq!(
            a.calls().len(),
            1,
            "a continuation must not implicitly retry"
        );
        let fresh = page(&sources, 1, None);
        assert_eq!(fresh.rows[0].account_id, id("acct_a"));
        assert!(fresh.unavailable_accounts.is_empty());
        assert_eq!(a.calls().len(), 2, "a new query may recover the account");
    }

    #[test]
    fn a_later_page_failure_preserves_consumed_cursor_and_stays_unavailable() {
        let a = Reader::new(
            "acct_a",
            vec![envelope("a", 40), envelope("b", 30), envelope("c", 20)],
        );
        let b = Reader::new("acct_b", vec![envelope("a", 25), envelope("b", 15)]);
        let sources = [a.source(), b.source()];
        let first = page(&sources, 1, None);
        assert_eq!(first.rows[0].account_id, id("acct_a"));
        let consumed = first.continuation.as_ref().expect("more rows").accounts[0]
            .consumed
            .clone();
        *a.error.lock().expect("fixture lock") = Some(MailboxStoreError::Corrupted);
        let second = page(&sources, 1, first.continuation.as_ref());
        assert_eq!(second.rows[0].account_id, id("acct_b"));
        assert_eq!(
            second.continuation.as_ref().expect("more rows").accounts[0].consumed,
            consumed
        );
        assert_eq!(
            second.unavailable_accounts[0].state,
            UnavailableAccountState::StoreUnavailable
        );
        *a.error.lock().expect("fixture lock") = None;
        let third = page(&sources, 1, second.continuation.as_ref());
        assert_eq!(third.rows[0].envelope.received_at().as_millis(), 15);
        assert_eq!(third.unavailable_accounts, second.unavailable_accounts);
        assert!(third.continuation.is_none());
        assert_eq!(
            a.calls().len(),
            2,
            "the recovered reader is not implicitly retried"
        );
    }

    #[test]
    fn all_explicit_unavailable_is_a_successful_empty_document() {
        let sources = [
            UnifiedMailboxSource::Unavailable {
                account_id: id("acct_auth"),
                state: UnavailableAccountState::AuthorizationRequired,
            },
            UnifiedMailboxSource::Unavailable {
                account_id: id("acct_store"),
                state: UnavailableAccountState::StoreUnavailable,
            },
        ];
        let document = page(&sources, 1, None);
        assert!(document.rows.is_empty());
        assert_eq!(document.unavailable_accounts.len(), 2);
        assert!(document.continuation.is_none());
    }

    #[test]
    fn locked_wins_over_every_invalid_input_and_returns_no_identity() {
        let reader = Reader::new("acct_secret", vec![envelope("private-message", 20)]);
        let duplicate = [reader.source(), reader.source()];
        let empty = [];
        let six = vec![reader.source(); 6];
        let valid = [reader.source()];
        for sources in [&duplicate[..], &empty[..], &six[..], &valid[..]] {
            for size in [0, 1, 200, 201] {
                let result = run(UnifiedMailboxQuery.execute(sources, size, None, true))
                    .expect("locked result");
                assert_eq!(result, UnifiedMailboxResult::Locked);
                assert_eq!(format!("{result:?}"), "Locked");
            }
        }
        assert!(reader.calls().is_empty());
    }

    #[test]
    fn invalid_bounds_and_duplicate_accounts_reject_before_any_reads() {
        let reader = Reader::new("acct_a", vec![envelope("m", 20)]);
        let sources = [reader.source()];
        for size in [0, 201, u16::MAX] {
            assert_eq!(
                run(UnifiedMailboxQuery.execute(&sources, size, None, false)),
                Err(UnifiedMailboxError::InvalidPageSize)
            );
        }
        assert_eq!(
            run(UnifiedMailboxQuery.execute(&[], 1, None, false)),
            Err(UnifiedMailboxError::InvalidAccountCount)
        );
        assert_eq!(
            run(UnifiedMailboxQuery.execute(&vec![reader.source(); 6], 1, None, false)),
            Err(UnifiedMailboxError::InvalidAccountCount)
        );
        assert_eq!(
            run(UnifiedMailboxQuery.execute(&[reader.source(), reader.source()], 1, None, false)),
            Err(UnifiedMailboxError::DuplicateAccount)
        );
        assert!(reader.calls().is_empty());
    }

    #[test]
    fn changed_account_sets_and_dispositions_reject_before_any_reads() {
        let a = Reader::new("acct_a", vec![envelope("a", 30), envelope("b", 20)]);
        let b = Reader::new("acct_b", vec![envelope("a", 10)]);
        let c = Reader::new("acct_c", vec![]);
        let first = page(&[a.source(), b.source()], 1, None);
        a.calls.lock().expect("fixture lock").clear();
        b.calls.lock().expect("fixture lock").clear();
        for sources in [
            vec![a.source()],
            vec![a.source(), c.source()],
            vec![a.source(), b.source(), c.source()],
            vec![
                a.source(),
                UnifiedMailboxSource::Unavailable {
                    account_id: id("acct_b"),
                    state: UnavailableAccountState::StoreUnavailable,
                },
            ],
        ] {
            assert_eq!(
                run(UnifiedMailboxQuery.execute(&sources, 1, first.continuation.as_ref(), false)),
                Err(UnifiedMailboxError::ContinuationMismatch)
            );
        }
        let auth = UnifiedMailboxSource::Unavailable {
            account_id: id("acct_b"),
            state: UnavailableAccountState::AuthorizationRequired,
        };
        let first = page(&[a.source(), auth], 1, None);
        a.calls.lock().expect("fixture lock").clear();
        for replacement in [
            b.source(),
            UnifiedMailboxSource::Unavailable {
                account_id: id("acct_b"),
                state: UnavailableAccountState::StoreUnavailable,
            },
        ] {
            assert_eq!(
                run(UnifiedMailboxQuery.execute(
                    &[a.source(), replacement],
                    1,
                    first.continuation.as_ref(),
                    false
                )),
                Err(UnifiedMailboxError::ContinuationMismatch)
            );
        }
        assert!(a.calls().is_empty());
        assert!(b.calls().is_empty());
        assert!(c.calls().is_empty());
    }

    #[test]
    fn deleted_cursor_target_is_still_a_valid_seek() {
        let reader = Reader::new(
            "acct_a",
            vec![envelope("a", 20), envelope("b", 20), envelope("c", 10)],
        );
        let sources = [reader.source()];
        let first = page(&sources, 1, None);
        reader.rows.lock().expect("fixture lock").remove(0);
        let second = page(&sources, 2, first.continuation.as_ref());
        assert_eq!(
            named(&second.rows),
            [
                ("acct_a".to_owned(), "b".to_owned(), 20),
                ("acct_a".to_owned(), "c".to_owned(), 10),
            ]
        );
        assert!(second.continuation.is_none());
    }

    #[test]
    fn dropping_a_pending_query_cancels_active_read_and_never_reads_later_accounts() {
        let mut a = Reader::new("acct_a", vec![]);
        a.pending = true;
        let b = Reader::new("acct_b", vec![]);
        let sources = [b.source(), a.source()];
        let mut future = UnifiedMailboxQuery.execute(&sources, 200, None, false);
        assert!(
            a.calls().is_empty(),
            "constructing the future does not dispatch"
        );
        assert!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        assert_eq!(a.calls(), [(None, 201)]);
        assert!(b.calls().is_empty());
        drop(future);
        assert!(
            a.dropped.load(Ordering::SeqCst),
            "active reader future must be dropped"
        );
        assert!(
            b.calls().is_empty(),
            "no detached work continues after cancellation"
        );
    }

    #[test]
    fn malformed_reader_windows_are_account_local_unavailability() {
        for malformed in [
            vec![envelope("a", 10), envelope("b", 20)], // out of order
            vec![envelope("a", 20), envelope("a", 20)], // duplicate
            vec![envelope("a", 30), envelope("b", 20), envelope("c", 10)], // exceeds probe
        ] {
            let bad = Reader::new("acct_bad", vec![]);
            *bad.malformed.lock().expect("fixture lock") = Some(malformed);
            let good = Reader::new("acct_good", vec![envelope("good", 10)]);
            let document = page(&[bad.source(), good.source()], 1, None);
            assert_eq!(document.rows[0].account_id, id("acct_good"));
            assert_eq!(
                document.unavailable_accounts,
                [UnavailableAccount {
                    account_id: id("acct_bad"),
                    state: UnavailableAccountState::StoreUnavailable,
                }]
            );
        }
        let reader = Reader::new("acct_a", vec![envelope("a", 20), envelope("b", 10)]);
        let sources = [reader.source()];
        let first = page(&sources, 1, None);
        *reader.malformed.lock().expect("fixture lock") = Some(vec![envelope("a", 20)]);
        let second = page(&sources, 1, first.continuation.as_ref());
        assert!(
            second.rows.is_empty(),
            "a response before its cursor must never be emitted"
        );
        assert_eq!(
            second.unavailable_accounts[0].state,
            UnavailableAccountState::StoreUnavailable
        );
    }

    #[test]
    fn debug_and_errors_never_disclose_raw_content_or_identifiers() {
        let reader = Reader::new(
            "acct_private",
            vec![
                envelope("private-message", 20),
                envelope("private-next", 10),
            ],
        );
        let source = reader.source();
        let document = page(std::slice::from_ref(&source), 1, None);
        let printed = format!(
            "{source:?} {document:?} {:?} {:?}",
            document.rows[0], document.continuation
        );
        for private in [
            "acct_private",
            "private-message",
            "private-next",
            "private-thread",
            "private-sender",
            "private-subject",
            "private-preview",
        ] {
            assert!(!printed.contains(private));
        }
        for error in [
            UnifiedMailboxError::InvalidAccountCount,
            UnifiedMailboxError::InvalidPageSize,
            UnifiedMailboxError::DuplicateAccount,
            UnifiedMailboxError::ContinuationMismatch,
        ] {
            assert!(!format!("{error:?} {error}").contains("private"));
        }
    }
}
