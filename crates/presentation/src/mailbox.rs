// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! UI-neutral mailbox view models projected from metadata documents.

use std::fmt;

use tersa_application::mailbox_metadata::{
    MailboxMetadataCommand, MailboxMetadataDocument, MailboxMetadataMessage,
};
use tersa_application::mailbox_search::MailboxSearchDocument;
use tersa_domain::mailbox::ThreadId;

/// Reports a rejected mailbox view-model projection without exposing content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MailboxViewModelError {
    /// The document command did not match the requested view model.
    UnexpectedCommand,
}

impl fmt::Display for MailboxViewModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the document command does not match the requested view model")
    }
}

impl std::error::Error for MailboxViewModelError {}

/// Holds one owned mailbox row with the stable metadata field parity.
///
/// Values are projected verbatim: no date formatting and no output escaping,
/// which remain the output adapter's responsibility. Message bodies are
/// rendered by [`crate::message::render_message`].
#[derive(Clone, Eq, PartialEq)]
pub struct MessageRowViewModel {
    /// The opaque message identifier.
    pub message_id: String,
    /// The opaque thread identifier.
    pub thread_id: String,
    /// The sender header text.
    pub from: String,
    /// The subject header text.
    pub subject: String,
    /// The provider preview/snippet text.
    pub preview: String,
    /// Milliseconds since the Unix epoch.
    pub received_at_millis: i64,
    /// Whether the message is unread.
    pub unread: bool,
}

impl MessageRowViewModel {
    /// Projects one metadata message into an owned view row without a body.
    #[must_use]
    pub fn from_message(message: &MailboxMetadataMessage) -> Self {
        Self {
            message_id: message.message_id().as_str().to_owned(),
            thread_id: message.thread_id().as_str().to_owned(),
            from: message.from().as_str().to_owned(),
            subject: message.subject().as_str().to_owned(),
            preview: message.preview().as_str().to_owned(),
            received_at_millis: message.received_at().as_millis(),
            unread: message.is_unread(),
        }
    }
}

impl fmt::Debug for MessageRowViewModel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MessageRowViewModel")
            .field("message_id", &"[REDACTED]")
            .field("thread_id", &"[REDACTED]")
            .field("from", &"[REDACTED]")
            .field("subject", &"[REDACTED]")
            .field("preview", &"[REDACTED]")
            .field("received_at_millis", &self.received_at_millis)
            .field("unread", &self.unread)
            .finish()
    }
}

/// Holds an owned inbox listing ready for a platform presentation adapter.
#[derive(Clone, Eq, PartialEq)]
pub struct InboxViewModel {
    account_id: String,
    limit: u16,
    rows: Vec<MessageRowViewModel>,
}

impl InboxViewModel {
    /// Projects an inbox metadata document into an owned view model.
    ///
    /// # Errors
    ///
    /// Returns [`MailboxViewModelError::UnexpectedCommand`] if the document
    /// does not represent the inbox command.
    pub fn from_document(
        document: &MailboxMetadataDocument,
    ) -> Result<Self, MailboxViewModelError> {
        if document.command() != MailboxMetadataCommand::Inbox {
            return Err(MailboxViewModelError::UnexpectedCommand);
        }
        Ok(Self {
            account_id: document.account_id().as_str().to_owned(),
            limit: document.limit().get(),
            rows: rows_from_document(document),
        })
    }

    /// Returns the opaque account identifier.
    #[must_use]
    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    /// Returns the validated result limit.
    #[must_use]
    pub const fn limit(&self) -> u16 {
        self.limit
    }

    /// Returns whether the view model has no rows.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Returns the projected rows in document order.
    #[must_use]
    pub fn rows(&self) -> &[MessageRowViewModel] {
        &self.rows
    }
}

impl fmt::Debug for InboxViewModel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InboxViewModel")
            .field("account_id", &"[REDACTED]")
            .field("limit", &self.limit)
            .field("row_count", &self.rows.len())
            .finish()
    }
}

/// Holds an owned thread listing ready for a platform presentation adapter.
#[derive(Clone, Eq, PartialEq)]
pub struct ThreadViewModel {
    account_id: String,
    thread_id: String,
    limit: u16,
    rows: Vec<MessageRowViewModel>,
}

impl ThreadViewModel {
    /// Projects a thread metadata document into an owned view model.
    ///
    /// An empty thread is a valid view model; mapping an absent thread to a
    /// not-found outcome belongs to a later adapter.
    ///
    /// # Errors
    ///
    /// Returns [`MailboxViewModelError::UnexpectedCommand`] if the document
    /// does not represent the thread command.
    pub fn from_document(
        document: &MailboxMetadataDocument,
        thread_id: &ThreadId,
    ) -> Result<Self, MailboxViewModelError> {
        if document.command() != MailboxMetadataCommand::Thread {
            return Err(MailboxViewModelError::UnexpectedCommand);
        }
        Ok(Self {
            account_id: document.account_id().as_str().to_owned(),
            thread_id: thread_id.as_str().to_owned(),
            limit: document.limit().get(),
            rows: rows_from_document(document),
        })
    }

    /// Builds a thread view model from already-projected rows.
    ///
    /// Used by the trusted composition after attaching cached body display text
    /// and applying local mark-as-read.
    #[must_use]
    pub fn from_rows(
        account_id: String,
        thread_id: String,
        limit: u16,
        rows: Vec<MessageRowViewModel>,
    ) -> Self {
        Self {
            account_id,
            thread_id,
            limit,
            rows,
        }
    }

    /// Returns the opaque account identifier.
    #[must_use]
    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    /// Returns the requested opaque thread identifier.
    #[must_use]
    pub fn thread_id(&self) -> &str {
        &self.thread_id
    }

    /// Returns the validated result limit.
    #[must_use]
    pub const fn limit(&self) -> u16 {
        self.limit
    }

    /// Returns whether the view model has no rows.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Returns the projected rows in document order.
    #[must_use]
    pub fn rows(&self) -> &[MessageRowViewModel] {
        &self.rows
    }
}

impl fmt::Debug for ThreadViewModel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ThreadViewModel")
            .field("account_id", &"[REDACTED]")
            .field("thread_id", &"[REDACTED]")
            .field("limit", &self.limit)
            .field("row_count", &self.rows.len())
            .finish()
    }
}

/// Holds an owned search result listing ready for a platform presentation adapter.
#[derive(Clone, Eq, PartialEq)]
pub struct SearchViewModel {
    account_id: String,
    query: String,
    limit: u16,
    rows: Vec<MessageRowViewModel>,
}

impl SearchViewModel {
    /// Projects a metadata search document into an owned view model.
    ///
    /// An empty result is a valid view model; mapping an absent result to a
    /// not-found outcome belongs to a later adapter.
    #[must_use]
    pub fn from_document(document: &MailboxSearchDocument) -> Self {
        Self {
            account_id: document.account_id().as_str().to_owned(),
            query: document.query().as_str().to_owned(),
            limit: document.limit().get(),
            rows: document
                .messages()
                .iter()
                .map(MessageRowViewModel::from_message)
                .collect(),
        }
    }

    /// Returns the opaque account identifier.
    #[must_use]
    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    /// Returns the submitted search query text.
    #[must_use]
    pub fn query(&self) -> &str {
        &self.query
    }

    /// Returns the validated result limit.
    #[must_use]
    pub const fn limit(&self) -> u16 {
        self.limit
    }

    /// Returns whether the view model has no rows.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Returns the projected rows in document order.
    #[must_use]
    pub fn rows(&self) -> &[MessageRowViewModel] {
        &self.rows
    }
}

impl fmt::Debug for SearchViewModel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SearchViewModel")
            .field("account_id", &"[REDACTED]")
            .field("query", &"[REDACTED]")
            .field("limit", &self.limit)
            .field("row_count", &self.rows.len())
            .finish()
    }
}

/// Projects every document message into an owned view row, preserving order.
fn rows_from_document(document: &MailboxMetadataDocument) -> Vec<MessageRowViewModel> {
    document
        .messages()
        .iter()
        .map(MessageRowViewModel::from_message)
        .collect()
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "Test fixtures use valid literals and fail immediately on unexpected results."
)]
mod tests {
    use std::pin::pin;
    use std::task::{Context, Poll, Waker};

    use tersa_application::mailbox::{BoxFuture, MailboxReader, MailboxStoreError, StoreLimit};
    use tersa_application::mailbox_metadata::{inbox_metadata, thread_metadata};
    use tersa_application::mailbox_search::{MailboxSearchQuery, search_metadata};
    use tersa_domain::mailbox::{
        AccountId, HeaderText, Message, MessageEnvelope, MessageId, UnixTimestampMillis,
    };

    use super::*;

    struct FakeReader {
        envelopes: Vec<MessageEnvelope>,
    }

    impl MailboxReader for FakeReader {
        fn list_envelopes<'a>(
            &'a self,
            _account: &'a AccountId,
            _limit: StoreLimit,
        ) -> BoxFuture<'a, Result<Vec<MessageEnvelope>, MailboxStoreError>> {
            let result = Ok(self.envelopes.clone());
            Box::pin(async move { result })
        }

        fn thread_envelopes<'a>(
            &'a self,
            _account: &'a AccountId,
            _thread_id: &'a ThreadId,
            _limit: StoreLimit,
        ) -> BoxFuture<'a, Result<Vec<MessageEnvelope>, MailboxStoreError>> {
            let result = Ok(self.envelopes.clone());
            Box::pin(async move { result })
        }

        fn get_message<'a>(
            &'a self,
            _account: &'a AccountId,
            _message_id: &'a MessageId,
        ) -> BoxFuture<'a, Result<Option<Message>, MailboxStoreError>> {
            Box::pin(async move { Ok(None) })
        }
    }

    fn account() -> AccountId {
        AccountId::new("account-1").unwrap()
    }

    fn thread() -> ThreadId {
        ThreadId::new("thread-1").unwrap()
    }

    fn limit() -> StoreLimit {
        StoreLimit::new(50).unwrap()
    }

    fn envelope(id: &str, timestamp: i64) -> MessageEnvelope {
        MessageEnvelope::new(
            MessageId::new(id).unwrap(),
            thread(),
            HeaderText::new(format!("from-{id}")).unwrap(),
            HeaderText::new(format!("subject-{id}")).unwrap(),
            HeaderText::new(format!("preview-{id}")).unwrap(),
            UnixTimestampMillis::new(timestamp).unwrap(),
            true,
        )
    }

    #[test]
    fn row_projection_carries_preview() {
        let document = inbox_document(vec![envelope("m1", 1)]);
        let message = &document.messages()[0];
        let row = MessageRowViewModel::from_message(message);
        assert_eq!(row.preview, "preview-m1");
    }

    fn run<T>(future: impl Future<Output = T>) -> T {
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        let mut future = pin!(future);
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("application metadata future must complete synchronously"),
        }
    }

    fn inbox_document(envelopes: Vec<MessageEnvelope>) -> MailboxMetadataDocument {
        let reader = FakeReader { envelopes };
        run(inbox_metadata(&reader, &account(), limit())).unwrap()
    }

    fn thread_document(envelopes: Vec<MessageEnvelope>) -> MailboxMetadataDocument {
        let reader = FakeReader { envelopes };
        run(thread_metadata(&reader, &account(), &thread(), limit())).unwrap()
    }

    fn search_document(envelopes: Vec<MessageEnvelope>, query: &str) -> MailboxSearchDocument {
        let reader = FakeReader { envelopes };
        let query = MailboxSearchQuery::new(query).unwrap();
        run(search_metadata(&reader, &account(), &query, limit())).unwrap()
    }

    #[test]
    fn search_view_model_projects_every_document_field() {
        let document = search_document(
            vec![
                MessageEnvelope::new(
                    MessageId::new("hit").unwrap(),
                    thread(),
                    HeaderText::new("alice@example.test").unwrap(),
                    HeaderText::new("weekly status").unwrap(),
                    HeaderText::new("preview-hit").unwrap(),
                    UnixTimestampMillis::new(20).unwrap(),
                    false,
                ),
                envelope("miss", 10),
            ],
            "alice",
        );
        let model = SearchViewModel::from_document(&document);

        assert_eq!(model.account_id(), "account-1");
        assert_eq!(model.query(), "alice");
        assert_eq!(model.limit(), 50);
        assert!(!model.is_empty());
        assert_eq!(model.rows().len(), 1);
        let row = &model.rows()[0];
        assert_eq!(row.message_id, "hit");
        assert_eq!(row.thread_id, "thread-1");
        assert_eq!(row.from, "alice@example.test");
        assert_eq!(row.subject, "weekly status");
        assert_eq!(row.received_at_millis, 20);
        assert!(!row.unread);
    }

    #[test]
    fn empty_search_document_produces_an_empty_view_model() {
        let model = SearchViewModel::from_document(&search_document(Vec::new(), "alice"));
        assert!(model.is_empty());
        assert!(model.rows().is_empty());
        assert_eq!(model.query(), "alice");
        assert_eq!(model.limit(), 50);
    }

    #[test]
    fn search_view_model_debug_redacts_account_query_and_rows() {
        let document = search_document(vec![envelope("msgid-secret", 10)], "msgid-secret");
        let model = SearchViewModel::from_document(&document);
        let debug = format!("{model:?} {:?}", model.rows()[0]);

        assert!(debug.contains("row_count"));
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("account-1"));
        assert!(!debug.contains("query-secret"));
        assert!(!debug.contains("msgid-secret"));
        assert!(!debug.contains("from-msgid-secret"));
        assert!(!debug.contains("subject-msgid-secret"));
    }

    #[test]
    fn inbox_view_model_projects_every_document_field() {
        let document = inbox_document(vec![envelope("newest", 20), envelope("older", 10)]);
        let model = InboxViewModel::from_document(&document).unwrap();

        assert_eq!(model.account_id(), "account-1");
        assert_eq!(model.limit(), 50);
        assert!(!model.is_empty());
        assert_eq!(model.rows().len(), 2);
        let row = &model.rows()[0];
        assert_eq!(row.message_id, "newest");
        assert_eq!(row.thread_id, "thread-1");
        assert_eq!(row.from, "from-newest");
        assert_eq!(row.subject, "subject-newest");
        assert_eq!(row.received_at_millis, 20);
        assert!(row.unread);
        assert_eq!(model.rows()[1].message_id, "older");
    }

    #[test]
    fn thread_view_model_projects_fields_and_threads_the_requested_id() {
        let document = thread_document(vec![envelope("oldest", 10), envelope("newer", 20)]);
        let requested = ThreadId::new("thread-1").unwrap();
        let model = ThreadViewModel::from_document(&document, &requested).unwrap();

        assert_eq!(model.account_id(), "account-1");
        assert_eq!(model.thread_id(), "thread-1");
        assert_eq!(model.limit(), 50);
        assert!(!model.is_empty());
        assert_eq!(model.rows().len(), 2);
        assert_eq!(model.rows()[0].message_id, "oldest");
        assert_eq!(model.rows()[0].thread_id, "thread-1");
        assert_eq!(model.rows()[0].received_at_millis, 10);
    }

    #[test]
    fn view_models_reject_a_mismatched_document_command() {
        let inbox_document = inbox_document(Vec::new());
        assert_eq!(
            ThreadViewModel::from_document(&inbox_document, &thread()),
            Err(MailboxViewModelError::UnexpectedCommand)
        );
        let thread_document = thread_document(Vec::new());
        assert_eq!(
            InboxViewModel::from_document(&thread_document),
            Err(MailboxViewModelError::UnexpectedCommand)
        );
    }

    #[test]
    fn empty_documents_produce_empty_view_models() {
        let inbox = InboxViewModel::from_document(&inbox_document(Vec::new())).unwrap();
        assert!(inbox.is_empty());
        assert!(inbox.rows().is_empty());

        let thread = ThreadViewModel::from_document(&thread_document(Vec::new()), &thread())
            .expect("an empty thread is a valid view model");
        assert!(thread.is_empty());
        assert!(thread.rows().is_empty());
        assert_eq!(thread.thread_id(), "thread-1");
    }

    #[test]
    fn debug_output_is_structural_and_redacted() {
        let account = AccountId::new("acct-secret").unwrap();
        let thread = ThreadId::new("thrd-secret").unwrap();
        let envelopes = vec![MessageEnvelope::new(
            MessageId::new("msgid-secret").unwrap(),
            thread.clone(),
            HeaderText::new("fromtext-secret").unwrap(),
            HeaderText::new("subjtext-secret").unwrap(),
            HeaderText::new("prevtext-secret").unwrap(),
            UnixTimestampMillis::new(10).unwrap(),
            true,
        )];
        let reader = FakeReader { envelopes };
        let inbox_document = run(inbox_metadata(&reader, &account, limit())).unwrap();
        let thread_document = run(thread_metadata(&reader, &account, &thread, limit())).unwrap();
        let inbox = InboxViewModel::from_document(&inbox_document).unwrap();
        let thread = ThreadViewModel::from_document(&thread_document, &thread).unwrap();
        let debug = format!("{inbox:?} {thread:?} {:?}", inbox.rows()[0]);

        assert!(debug.contains("row_count"));
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("acct-secret"));
        assert!(!debug.contains("thrd-secret"));
        assert!(!debug.contains("msgid-secret"));
        assert!(!debug.contains("fromtext-secret"));
        assert!(!debug.contains("subjtext-secret"));
        assert!(!debug.contains("prevtext-secret"));
    }
}
