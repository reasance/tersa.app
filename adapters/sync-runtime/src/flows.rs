// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Account flows: add (OAuth consent then first sync), sync, and remove.

use core::fmt;
use std::sync::Arc;
use std::time::Duration;

use tersa_application::mailbox::{AccountId, MessageId, PageSize, StoreLimit};
use tersa_application::oauth::{MonotonicClock, SystemMonotonicClock, SystemWallClock};
use tersa_application::sync::{SyncPolicy, SyncReport};
use tersa_gmail_rest::GmailTokenTransport;
use tersa_token_broker_core::{BrokerCore, BrokerError, BrokerToken, GetRandomEntropy};
use zeroize::Zeroizing;

use crate::gate::{GatedFetchError, GatedSyncError, gated_fetch, gated_sync};
use crate::installation::{
    Installation, InstallationError, InstallationHasher, InstallationTokens,
};
use crate::loopback::{Loopback, LoopbackError};
use crate::session::{GmailSession, GmailSessionError};

/// How long the browser sign-in may take.
pub const SIGN_IN_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const SESSION_TTL: Duration = Duration::from_secs(10 * 60);

type Broker = BrokerCore<
    GmailTokenTransport,
    InstallationTokens,
    SharedMonotonicClock,
    SystemWallClock,
    GetRandomEntropy,
>;

/// [`SystemMonotonicClock`] is not `Clone`; the token service clones its
/// clock into each pending session, so share one origin through an `Arc`.
#[derive(Clone, Debug)]
struct SharedMonotonicClock(Arc<SystemMonotonicClock>);

impl MonotonicClock for SharedMonotonicClock {
    fn now(&self) -> Duration {
        self.0.now()
    }
}

/// The user's Google OAuth "Desktop app" client.
pub struct OAuthClient {
    /// The client identifier.
    pub client_id: String,
    /// The client secret, which Google issues to desktop clients but does not
    /// treat as confidential.
    pub client_secret: Option<Zeroizing<String>>,
}

impl fmt::Debug for OAuthClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OAuthClient([REDACTED])")
    }
}

/// Flow failures, each with a user-facing message and no secrets.
#[derive(Debug)]
#[non_exhaustive]
pub enum FlowError {
    /// The OAuth client configuration is unusable.
    Configuration,
    /// No more accounts can be added.
    AccountLimit,
    /// The local sign-in listener failed.
    Loopback(LoopbackError),
    /// The token service failed.
    Token(BrokerError),
    /// The account could not be found.
    UnknownAccount,
    /// Local storage failed.
    Installation(InstallationError),
    /// The Gmail session could not be built.
    Session(GmailSessionError),
    /// The identity gate or the sync failed.
    Sync(GatedSyncError),
    /// The identity gate or a single-message download failed.
    Fetch(GatedFetchError),
}

impl fmt::Display for FlowError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration => formatter.write_str(
                "the Google OAuth client is not configured correctly (see `tersa doctor`)",
            ),
            Self::AccountLimit => formatter.write_str("the maximum number of accounts is reached"),
            Self::Loopback(error) => write!(formatter, "{error}"),
            Self::Token(BrokerError::ConsentRevoked | BrokerError::MissingRefreshToken) => {
                formatter.write_str("access was revoked; remove and add the account again")
            }
            Self::Token(error) => write!(formatter, "{error}"),
            Self::UnknownAccount => formatter.write_str("no such account"),
            Self::Installation(error) => write!(formatter, "{error}"),
            Self::Session(error) => write!(formatter, "{error}"),
            Self::Sync(error) => write!(formatter, "{error}"),
            Self::Fetch(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for FlowError {}

impl From<InstallationError> for FlowError {
    fn from(error: InstallationError) -> Self {
        Self::Installation(error)
    }
}

/// The result of adding an account.
#[derive(Debug)]
pub struct AddedAccount {
    /// The local account identifier.
    pub account: AccountId,
    /// Whether this Google account was already registered (its credential
    /// was replaced).
    pub already_present: bool,
    /// The first sync, which may fail without undoing the add.
    pub first_sync: Result<SyncReport, FlowError>,
}

/// Whether the provider confirmed revocation during removal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Revocation {
    /// Google confirmed the grant is revoked.
    Confirmed,
    /// Revocation could not be confirmed; local data was removed anyway.
    Unconfirmed,
}

/// The account flows over one unlocked installation.
pub struct Runtime {
    installation: Arc<Installation>,
    broker: Broker,
    hasher: InstallationHasher,
}

impl fmt::Debug for Runtime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Runtime([REDACTED])")
    }
}

impl Runtime {
    /// Builds the runtime for `installation` and the user's OAuth `client`.
    ///
    /// # Errors
    ///
    /// Returns [`FlowError::Configuration`] for an unusable client or HTTP
    /// stack.
    pub fn new(installation: Arc<Installation>, client: OAuthClient) -> Result<Self, FlowError> {
        let transport = GmailTokenTransport::new().map_err(|_error| FlowError::Configuration)?;
        let broker = BrokerCore::new(
            client.client_id,
            client.client_secret,
            SESSION_TTL,
            (
                transport,
                InstallationTokens(Arc::clone(&installation)),
                SharedMonotonicClock(Arc::new(SystemMonotonicClock::new())),
                SystemWallClock,
                GetRandomEntropy,
            ),
        )
        .map_err(|_error| FlowError::Configuration)?;
        Ok(Self {
            hasher: InstallationHasher(Arc::clone(&installation)),
            installation,
            broker,
        })
    }

    /// The installation this runtime serves.
    #[must_use]
    pub fn installation(&self) -> &Arc<Installation> {
        &self.installation
    }

    /// Runs browser sign-in, registers the account, and performs a first sync.
    ///
    /// `open_browser` receives the authorization URL; it should try to open
    /// it and always show it to the user.
    ///
    /// # Errors
    ///
    /// Returns a [`FlowError`] when sign-in fails. A failed first sync is
    /// reported in [`AddedAccount::first_sync`] instead.
    pub async fn add_account<F: FnOnce(&str)>(
        &self,
        open_browser: F,
    ) -> Result<AddedAccount, FlowError> {
        if !self.installation.has_capacity()? {
            return Err(FlowError::AccountLimit);
        }
        let before = self.installation.accounts()?;
        let loopback = Loopback::bind().await.map_err(FlowError::Loopback)?;
        let pending = self
            .broker
            .begin_authorization(&loopback.redirect_uri())
            .map_err(FlowError::Token)?;
        let expected_state = pending
            .authorization_url()
            .query_pairs()
            .find(|(name, _value)| name == "state")
            .map(|(_name, value)| value.into_owned())
            .ok_or(FlowError::Configuration)?;
        open_browser(pending.authorization_url().as_str());
        let callback = loopback
            .wait_for_callback(SIGN_IN_TIMEOUT, &expected_state)
            .await
            .map_err(FlowError::Loopback)?;
        let token = self
            .broker
            .complete_authorization(pending.session_handle(), &callback)
            .await
            .map_err(FlowError::Token)?;
        let account = self
            .installation
            .account_for_subject(token.subject())?
            .ok_or(FlowError::UnknownAccount)?;
        let first_sync = self.sync_with_token(&account, &token).await;
        Ok(AddedAccount {
            already_present: before.contains(&account),
            account,
            first_sync,
        })
    }

    /// Refreshes the account's access token and runs a bounded sync.
    ///
    /// # Errors
    ///
    /// Returns a [`FlowError`] for an unknown account, a token failure, or a
    /// gate or sync failure.
    pub async fn sync_account(&self, account: &AccountId) -> Result<SyncReport, FlowError> {
        let subject = self.subject_of(account)?;
        let token = self
            .broker
            .refresh_access_token(&subject)
            .await
            .map_err(FlowError::Token)?;
        self.sync_with_token(account, &token).await
    }

    /// Revokes the grant at Google (best effort), then deletes the account's
    /// credential and local data.
    ///
    /// # Errors
    ///
    /// Returns a [`FlowError`] when the account is unknown or local removal
    /// fails.
    pub async fn remove_account(&self, account: &AccountId) -> Result<Revocation, FlowError> {
        let subject = self.subject_of(account)?;
        let revocation = match self.broker.revoke_provider_grant(&subject).await {
            Ok(()) => Revocation::Confirmed,
            Err(_error) => Revocation::Unconfirmed,
        };
        // Deleting the stored token is part of the local removal; a failure
        // here is superseded by deleting the whole account directory.
        let _ = self.broker.delete_stored_tokens(&subject);
        self.installation.remove_account(account)?;
        Ok(revocation)
    }

    /// Downloads one complete message through the identity gate, caches it,
    /// and returns its raw RFC 5322 bytes.
    ///
    /// # Errors
    ///
    /// Returns a [`FlowError`] for an unknown account, a token failure, or a
    /// gate, download, or cache failure.
    pub async fn fetch_message(
        &self,
        account: &AccountId,
        message_id: &MessageId,
    ) -> Result<Vec<u8>, FlowError> {
        let subject = self.subject_of(account)?;
        let token = self
            .broker
            .refresh_access_token(&subject)
            .await
            .map_err(FlowError::Token)?;
        let session = GmailSession::new(
            account.clone(),
            token.access_token(),
            Zeroizing::new(token.subject().to_owned()),
        )
        .map_err(FlowError::Session)?;
        let store = self.installation.open_store(account)?;
        let message = gated_fetch(account, session, &self.hasher, store, message_id)
            .await
            .map_err(FlowError::Fetch)?;
        Ok(message.content().as_bytes().to_vec())
    }

    fn subject_of(&self, account: &AccountId) -> Result<Zeroizing<String>, FlowError> {
        self.installation
            .open_store(account)
            .map_err(|error| match error {
                InstallationError::UnknownAccount => FlowError::UnknownAccount,
                other => FlowError::Installation(other),
            })?
            .load_broker_subject(account)
            .map_err(|error| FlowError::Installation(InstallationError::Store(error)))?
            .ok_or(FlowError::UnknownAccount)
    }

    async fn sync_with_token(
        &self,
        account: &AccountId,
        token: &BrokerToken,
    ) -> Result<SyncReport, FlowError> {
        let session = GmailSession::new(
            account.clone(),
            token.access_token(),
            Zeroizing::new(token.subject().to_owned()),
        )
        .map_err(FlowError::Session)?;
        let store = self.installation.open_store(account)?;
        gated_sync(account, session, &self.hasher, store, default_sync_policy())
            .await
            .map_err(FlowError::Sync)
    }
}

/// The bounded recent-snapshot policy: 4 pages of 25, keep 100 envelopes,
/// cache 25 full bodies.
///
/// # Panics
///
/// Never: the constants are within the policy bounds, which a unit test pins.
#[must_use]
pub fn default_sync_policy() -> SyncPolicy {
    // The constants are within the policy bounds, so construction cannot fail.
    let page_size = PageSize::new(25).expect("25 is a valid page size");
    let keep = StoreLimit::new(100).expect("100 is a valid store limit");
    let bodies = StoreLimit::new(25).expect("25 is a valid store limit");
    SyncPolicy::new(page_size, 4, keep, bodies).expect("the default sync policy is valid")
}

#[cfg(test)]
mod tests {
    use super::default_sync_policy;

    #[test]
    fn the_default_policy_is_valid() {
        let _policy = default_sync_policy();
    }
}
