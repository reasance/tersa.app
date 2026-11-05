// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Account-bound production read/write construction; no configurable provider endpoints.

use crate::session::SessionEmailAddress;
use std::{fmt, sync::Arc};
use tersa_application::{
    AccountCapability,
    command::{
        CommandDispatchError, CommandLabelReader, RemoteMailboxCommands, UserLabelObservation,
    },
    history::{
        CapturedBaseline, GmailHistoryFeed, HistoryFeedError, HistoryPage, HistoryQuery,
        SnapshotPage,
    },
    mailbox::{
        AccountEmail, AccountId, BoxFuture, Message, MessageEnvelope, MessageId, Page, PageSize,
        PageToken, RemoteMailbox, RemoteMailboxError,
    },
    mailbox_state::{
        LabelCatalog, MessageKey, MessageObservation, MetadataObservation, MetadataReadError,
        UserLabel,
    },
    scope::AcceptedScope,
};
use tersa_gmail_rest::{GmailMailbox, GmailModifyMailbox};
use zeroize::Zeroizing;

pub(crate) trait AccountMailbox:
    RemoteMailbox + GmailHistoryFeed + CommandLabelReader + SessionEmailAddress
{
}
impl<T: RemoteMailbox + GmailHistoryFeed + CommandLabelReader + SessionEmailAddress> AccountMailbox
    for T
{
}

pub(crate) trait MailboxFactory: fmt::Debug + Send + Sync {
    fn read(
        &self,
        account: AccountId,
        token: &Zeroizing<String>,
    ) -> Result<Arc<dyn AccountMailbox>, RemoteMailboxError>;
    fn writer(
        &self,
        account: AccountId,
        token: &Zeroizing<String>,
        capability: AccountCapability,
        scope: AcceptedScope,
    ) -> Result<Box<dyn RemoteMailboxCommands>, CommandDispatchError>;
}
#[derive(Debug)]
pub(crate) struct GoogleMailboxes;
impl MailboxFactory for GoogleMailboxes {
    fn read(
        &self,
        account: AccountId,
        token: &Zeroizing<String>,
    ) -> Result<Arc<dyn AccountMailbox>, RemoteMailboxError> {
        Ok(Arc::new(GoogleRead(GmailMailbox::new(
            account,
            token.as_str().to_owned(),
        )?)))
    }
    fn writer(
        &self,
        account: AccountId,
        token: &Zeroizing<String>,
        capability: AccountCapability,
        scope: AcceptedScope,
    ) -> Result<Box<dyn RemoteMailboxCommands>, CommandDispatchError> {
        Ok(Box::new(GmailModifyMailbox::new(
            account,
            token.as_str().to_owned(),
            capability,
            scope,
        )?))
    }
}
struct GoogleRead(GmailMailbox);
impl RemoteMailbox for GoogleRead {
    fn list_recent_envelopes<'a>(
        &'a self,
        account: &'a AccountId,
        size: PageSize,
        page: Option<&'a PageToken>,
    ) -> BoxFuture<'a, Result<Page<MessageEnvelope>, RemoteMailboxError>> {
        self.0.list_recent_envelopes(account, size, page)
    }
    fn fetch_message<'a>(
        &'a self,
        account: &'a AccountId,
        id: &'a MessageId,
    ) -> BoxFuture<'a, Result<Message, RemoteMailboxError>> {
        self.0.fetch_message(account, id)
    }
}
impl SessionEmailAddress for GoogleRead {
    fn email_address(&self) -> BoxFuture<'_, Result<AccountEmail, RemoteMailboxError>> {
        Box::pin(self.0.email_address())
    }
}
// This bridge deliberately uses only GET-only GmailMailbox helpers. Observing a
// command never requires constructing a Modify transport or possessing Modify scope.
impl CommandLabelReader for GoogleRead {
    fn read_label_catalog<'a>(
        &'a self,
        account: &'a AccountId,
    ) -> BoxFuture<'a, Result<LabelCatalog, MetadataReadError>> {
        Box::pin(self.0.label_catalog(account))
    }
    fn read_user_label<'a>(
        &'a self,
        target: &'a UserLabel,
    ) -> BoxFuture<'a, Result<UserLabelObservation, MetadataReadError>> {
        Box::pin(async move {
            let definition = self
                .0
                .label_definition(target.account_id(), target.id())
                .await?;
            UserLabelObservation::new(target.clone(), definition)
                .map_err(|_error| MetadataReadError::InvalidResponse)
        })
    }
}
impl GmailHistoryFeed for GoogleRead {
    fn history_page<'a>(
        &'a self,
        query: &'a HistoryQuery,
    ) -> BoxFuture<'a, Result<HistoryPage, HistoryFeedError>> {
        self.0.history_page(query)
    }
    fn capture_baseline<'a>(
        &'a self,
        account: &'a AccountId,
    ) -> BoxFuture<'a, Result<CapturedBaseline, MetadataReadError>> {
        self.0.capture_baseline(account)
    }
    fn snapshot_page<'a>(
        &'a self,
        baseline: &'a CapturedBaseline,
        page: Option<&'a PageToken>,
    ) -> BoxFuture<'a, Result<SnapshotPage, MetadataReadError>> {
        self.0.snapshot_page(baseline, page)
    }
    fn observe_message<'a>(
        &'a self,
        key: &'a MessageKey,
    ) -> BoxFuture<'a, Result<MessageObservation, MetadataReadError>> {
        self.0.observe_message(key)
    }
    fn message_metadata<'a>(
        &'a self,
        key: &'a MessageKey,
    ) -> BoxFuture<'a, Result<MetadataObservation, MetadataReadError>> {
        self.0.message_metadata(key)
    }
}
