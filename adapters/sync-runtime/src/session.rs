// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! One account's Gmail session: a mailbox surface and the validated OAuth
//! subject, both derived from a single access token.

use core::fmt;
use std::sync::Arc;

use tersa_application::identity::AccountProfile;
use tersa_application::mailbox::{
    AccountEmail, AccountId, BoxFuture, Message, MessageEnvelope, MessageId, Page, PageSize,
    PageToken, RemoteMailbox, RemoteMailboxError,
};
use tersa_application::token::{AccountSubject, BrokerSubjectError};
use tersa_gmail_rest::GmailMailbox;
use zeroize::Zeroizing;

/// Reports why a [`GmailSession`] could not be built.
#[derive(Debug)]
#[non_exhaustive]
pub enum GmailSessionError {
    /// The token service's subject failed re-validation.
    Subject(BrokerSubjectError),
    /// The mailbox surface could not be constructed from the access token.
    Mailbox(RemoteMailboxError),
}

impl fmt::Display for GmailSessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Subject(_) => formatter.write_str("the account subject is unusable"),
            Self::Mailbox(_) => formatter.write_str("the mailbox surface could not be built"),
        }
    }
}

impl std::error::Error for GmailSessionError {}

/// One connected account's mailbox surface plus its validated subject.
///
/// The identity gate hashes the subject and the sync reads the mailbox, both
/// backed by one access token, so the checked identity and the written
/// identity necessarily coincide.
pub struct GmailSession {
    mailbox: GmailMailbox,
    subject: AccountSubject,
}

impl GmailSession {
    /// Builds a session from one token-service reply.
    ///
    /// The access token is copied once into the Gmail adapter, which re-wraps
    /// it in zeroizing storage. Neither value reaches a log or `Debug` sink.
    ///
    /// # Errors
    ///
    /// Returns [`GmailSessionError::Subject`] when the subject fails
    /// re-validation and [`GmailSessionError::Mailbox`] when the access token
    /// cannot construct the mailbox surface.
    pub fn new(
        account: AccountId,
        access_token: &Zeroizing<String>,
        subject: Zeroizing<String>,
    ) -> Result<Self, GmailSessionError> {
        let subject =
            AccountSubject::from_broker_validated(subject).map_err(GmailSessionError::Subject)?;
        let mailbox = GmailMailbox::new(account, access_token.as_str().to_owned())
            .map_err(GmailSessionError::Mailbox)?;
        Ok(Self { mailbox, subject })
    }
}

impl fmt::Debug for GmailSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GmailSession([REDACTED])")
    }
}

impl AccountProfile for GmailSession {
    fn subject(&self) -> &AccountSubject {
        &self.subject
    }
}

impl RemoteMailbox for GmailSession {
    fn list_recent_envelopes<'a>(
        &'a self,
        account: &'a AccountId,
        size: PageSize,
        page_token: Option<&'a PageToken>,
    ) -> BoxFuture<'a, Result<Page<MessageEnvelope>, RemoteMailboxError>> {
        self.mailbox
            .list_recent_envelopes(account, size, page_token)
    }

    fn fetch_message<'a>(
        &'a self,
        account: &'a AccountId,
        message_id: &'a MessageId,
    ) -> BoxFuture<'a, Result<Message, RemoteMailboxError>> {
        self.mailbox.fetch_message(account, message_id)
    }
}

/// A [`GmailSession`] shared by the flows of one runtime until its access
/// token expires, so downloads reuse one token and one HTTPS connection pool.
#[derive(Clone, Debug)]
pub struct SharedSession(Arc<GmailSession>);

impl SharedSession {
    #[must_use]
    pub fn new(session: GmailSession) -> Self {
        Self(Arc::new(session))
    }

    /// Whether both handles share one session, as opposed to two sessions
    /// for the same account.
    #[must_use]
    pub fn is(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl AccountProfile for SharedSession {
    fn subject(&self) -> &AccountSubject {
        self.0.subject()
    }
}

impl RemoteMailbox for SharedSession {
    fn list_recent_envelopes<'a>(
        &'a self,
        account: &'a AccountId,
        size: PageSize,
        page_token: Option<&'a PageToken>,
    ) -> BoxFuture<'a, Result<Page<MessageEnvelope>, RemoteMailboxError>> {
        self.0.list_recent_envelopes(account, size, page_token)
    }

    fn fetch_message<'a>(
        &'a self,
        account: &'a AccountId,
        message_id: &'a MessageId,
    ) -> BoxFuture<'a, Result<Message, RemoteMailboxError>> {
        self.0.fetch_message(account, message_id)
    }
}

/// The account's Gmail address, fetched with the session's own access token.
/// A crate-local surface: the application's [`RemoteMailbox`] port stays
/// unchanged and other mailbox adapters stay free to skip it.
pub trait SessionEmailAddress {
    /// Fetches the Gmail address of the authenticated user behind the token.
    ///
    /// # Errors
    ///
    /// Returns [`RemoteMailboxError`] for a transport failure and for a
    /// missing or invalid profile address.
    fn email_address(&self) -> BoxFuture<'_, Result<AccountEmail, RemoteMailboxError>>;
}

impl SessionEmailAddress for GmailSession {
    fn email_address(&self) -> BoxFuture<'_, Result<AccountEmail, RemoteMailboxError>> {
        Box::pin(self.mailbox.email_address())
    }
}

impl SessionEmailAddress for SharedSession {
    fn email_address(&self) -> BoxFuture<'_, Result<AccountEmail, RemoteMailboxError>> {
        self.0.email_address()
    }
}

#[cfg(test)]
mod tests {
    use tersa_application::identity::AccountProfile;
    use tersa_application::mailbox::AccountId;
    use tersa_application::token::BrokerSubjectError;
    use zeroize::Zeroizing;

    use super::{GmailSession, GmailSessionError};

    fn account() -> AccountId {
        AccountId::new("account-a").expect("account")
    }

    #[test]
    fn session_feeds_the_identity_gate_subject_and_redacts() {
        let session = GmailSession::new(
            account(),
            &Zeroizing::new("ya29.test-access-token".to_owned()),
            Zeroizing::new("112233445566778899001".to_owned()),
        )
        .expect("session");
        assert_eq!(
            AccountProfile::subject(&session).as_str(),
            "112233445566778899001"
        );
        let rendered = format!("{session:?}");
        assert!(!rendered.contains("112233445566778899001"));
        assert!(!rendered.contains("ya29.test-access-token"));
    }

    #[test]
    fn session_rejects_an_invalid_subject_without_echoing_it() {
        let error = GmailSession::new(
            account(),
            &Zeroizing::new("ya29.test-access-token".to_owned()),
            Zeroizing::new("has a space".to_owned()),
        )
        .expect_err("invalid subject");
        assert!(matches!(
            error,
            GmailSessionError::Subject(BrokerSubjectError::InvalidCharacters)
        ));
        assert!(!format!("{error}").contains("has a space"));
    }
}
