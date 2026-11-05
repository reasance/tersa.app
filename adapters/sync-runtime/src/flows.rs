// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Account flows: add (OAuth consent then first sync), sync, and remove.

use core::fmt;
use std::sync::Arc;
use std::time::Duration;

use crate::coordination::Accounts;
use crate::online::{Broker, Online};
use tersa_application::identity::AccountProfile;
use tersa_application::mailbox::{
    AccountId, MessageId, PageSize, RemoteMailbox, RemoteMailboxError, StoreLimit,
};
use tersa_application::oauth::{MonotonicClock, SystemMonotonicClock};
use tersa_application::sync::{SyncFailureSource, SyncPolicy, SyncReport};
use tersa_application::{
    AccountCapability, lifecycle::AccountLifecycleStore, profile::UpgradeBinding,
    token::AccountSubject,
};
use tersa_gmail_rest::GmailTokenTransport;
use tersa_token_broker_core::{AuthorizationIntent, BrokerError, CapabilityBrokerToken};
use zeroize::Zeroizing;

use crate::cache_reset::{CacheResetOutcome, CacheResetPreconditionError, reset_cache_using};
use crate::gate::{GatedFetchError, GatedSyncError, gated_fetch, gated_sync};
use crate::installation::{Installation, InstallationError, InstallationHasher};
use crate::loopback::{Loopback, LoopbackError};
use crate::session::{GmailSession, GmailSessionError, SessionEmailAddress, SharedSession};
use crate::session_cache::{Origin, SessionCache, SystemCacheClock};

/// How long the browser sign-in may take.
pub const SIGN_IN_TIMEOUT: Duration = Duration::from_secs(5 * 60);
/// A cached access token is replaced this long before it expires.
const TOKEN_MARGIN: Duration = Duration::from_secs(60);

/// [`SystemMonotonicClock`] is not `Clone`; the token service clones its
/// clock into each pending session, so share one origin through an `Arc`.
#[derive(Clone, Debug)]
pub(crate) struct SharedMonotonicClock(pub(crate) Arc<SystemMonotonicClock>);

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
    /// The token refresh this call waited for failed, for the given reason.
    Refresh(Arc<FlowError>),
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
                formatter.write_str("access was revoked; reconnect the selected account")
            }
            Self::Token(error) => write!(formatter, "{error}"),
            Self::UnknownAccount => formatter.write_str("no such account"),
            Self::Installation(error) => write!(formatter, "{error}"),
            Self::Session(error) => write!(formatter, "{error}"),
            Self::Sync(error) => write!(formatter, "{error}"),
            Self::Fetch(error) => write!(formatter, "{error}"),
            Self::Refresh(error) => write!(formatter, "{error}"),
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
    /// Whether this Google account was already registered. New Connect now
    /// refuses duplicates; this compatibility field is false on success.
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
    online: Option<Online>,
    // Match the broker's eight pending-session ceiling across isolated brokers.
    authorizations: tokio::sync::Semaphore,
    // Subject is unknown until exchange. Serialize only Connect completion so
    // an empty-snapshot cleanup cannot race another Connect registering it.
    connections: tokio::sync::Mutex<()>,
    pub(crate) operations: Accounts,
    hasher: InstallationHasher,
    /// One Gmail session per account, reused until shortly before its access
    /// token expires.
    sessions: SessionCache<SharedSession, Arc<FlowError>, SystemCacheClock>,
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
        let online = Online::new(client, transport);
        // Validate configuration before exposing an online runtime.
        let _ = online.broker(&installation)?;
        let mut runtime = Self::local(installation);
        runtime.online = Some(online);
        Ok(runtime)
    }

    /// Builds a local runtime without requiring OAuth configuration or usable credentials.
    ///
    /// The caller retains the installation lock. Local operations share the same
    /// account coordination as online work; network operations return Configuration.
    #[must_use]
    pub fn local(installation: Arc<Installation>) -> Self {
        Self {
            hasher: InstallationHasher(Arc::clone(&installation)),
            installation,
            online: None,
            authorizations: tokio::sync::Semaphore::new(8),
            connections: tokio::sync::Mutex::new(()),
            operations: Accounts::default(),
            sessions: SessionCache::new(SystemCacheClock, TOKEN_MARGIN),
        }
    }

    fn broker(&self) -> Result<Broker, FlowError> {
        self.online
            .as_ref()
            .ok_or(FlowError::Configuration)?
            .broker(&self.installation)
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
        self.installation.require_registry_write()?;
        let _authorization = self
            .authorizations
            .try_acquire()
            .map_err(|_error| FlowError::Token(BrokerError::Busy))?;
        if !self.installation.has_capacity()? {
            return Err(FlowError::AccountLimit);
        }
        let broker = self.broker()?;
        let loopback = Loopback::bind().await.map_err(FlowError::Loopback)?;
        let pending = broker
            .begin_capability_authorization(
                &loopback.redirect_uri(),
                AccountCapability::ReadOnly,
                AuthorizationIntent::Connect,
            )
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
            .complete_new(&broker, pending.session_handle(), &callback)
            .await?;
        let account = token.account_id().clone();
        let operation = match self.operations.get(&account) {
            Ok(operation) => operation,
            Err(error) => {
                return Ok(AddedAccount {
                    account,
                    already_present: false,
                    first_sync: Err(error),
                });
            }
        };
        let _permit = operation.permit.lock().await;
        // Registration was new, so generation zero is the original publication
        // expectation. A worker may already have refreshed/removed/upgraded it
        // after registry publication; never relabel this old token as newer.
        if let Err(error) = operation.validate(0) {
            return Ok(AddedAccount {
                account,
                already_present: false,
                first_sync: Err(error),
            });
        }
        self.invalidate_known(&account, &operation);
        Ok(self.connected_account(token, false).await)
    }

    async fn complete_new(
        &self,
        broker: &Broker,
        handle: &str,
        callback: &str,
    ) -> Result<CapabilityBrokerToken, FlowError> {
        let _connection = self.connections.lock().await;
        broker
            .complete_capability_authorization(handle, callback)
            .await
            .map_err(FlowError::Token)
    }

    /// Requests explicit Modify consent for the selected existing account.
    ///
    /// # Errors
    /// Sign-in, changed account/generation, or storage failures preserve the old
    /// grant. A committed grant is reported separately from a failed first sync.
    pub async fn upgrade_account<F: FnOnce(&str)>(
        &self,
        account: &AccountId,
        open_browser: F,
    ) -> Result<AddedAccount, FlowError> {
        self.authorize_existing(account, Some(AccountCapability::Modify), open_browser)
            .await
    }

    /// Reconnects the selected account while preserving its stored capability.
    ///
    /// # Errors
    /// Returns the same non-destructive authorization failures as `upgrade_account`.
    pub async fn reconnect_account<F: FnOnce(&str)>(
        &self,
        account: &AccountId,
        open_browser: F,
    ) -> Result<AddedAccount, FlowError> {
        self.authorize_existing(account, None, open_browser).await
    }

    async fn authorize_existing<F: FnOnce(&str)>(
        &self,
        account: &AccountId,
        requested: Option<AccountCapability>,
        open_browser: F,
    ) -> Result<AddedAccount, FlowError> {
        self.installation.require_registry_write()?;
        let _authorization = self
            .authorizations
            .try_acquire()
            .map_err(|_error| FlowError::Token(BrokerError::Busy))?;
        let broker = self.broker()?;
        let operation = self.operations.get(account)?;
        let loopback = Loopback::bind().await.map_err(FlowError::Loopback)?;
        let (generation, pending) = {
            let _permit = operation.permit.lock().await;
            self.prepare_existing(&broker, account, requested, &loopback.redirect_uri())?
        };
        let state = pending
            .authorization_url()
            .query_pairs()
            .find(|(key, _)| key == "state")
            .map(|(_, value)| value.into_owned())
            .ok_or(FlowError::Configuration)?;
        open_browser(pending.authorization_url().as_str());
        let callback = loopback
            .wait_for_callback(SIGN_IN_TIMEOUT, &state)
            .await
            .map_err(FlowError::Loopback)?;
        let _permit = operation.permit.lock().await;
        let token = self
            .complete_existing(
                &broker,
                account,
                generation,
                pending.session_handle(),
                &callback,
            )
            .await?;
        Ok(self.connected_account(token, true).await)
    }

    // Grant persistence has already succeeded and the caller holds its account
    // permit. All subsequent session/sync failures belong to first_sync.
    async fn connected_account(
        &self,
        token: CapabilityBrokerToken,
        already_present: bool,
    ) -> AddedAccount {
        let account = token.account_id().clone();
        let first_sync = match self.operations.get(&account) {
            Ok(operation) => match GmailSession::from_capability(token, operation.generation()) {
                Ok(session) => self.sync_with_session(&account, session).await,
                Err(error) => Err(FlowError::Session(error)),
            },
            Err(error) => Err(error),
        };
        AddedAccount {
            account,
            already_present,
            first_sync,
        }
    }

    // Capture the selected binding and exact request BEFORE browser launch.
    // Caller holds the account permit; begin loads the original opaque snapshot.
    fn prepare_existing(
        &self,
        broker: &Broker,
        account: &AccountId,
        requested: Option<AccountCapability>,
        redirect: &str,
    ) -> Result<(u64, tersa_token_broker_core::PendingAuthorization), FlowError> {
        let store = self.installation.open_store(account)?;
        let snapshot = store
            .load_credential_snapshot(account)
            .map_err(|_error| FlowError::Token(BrokerError::PersistenceFailed))?;
        let subject = AccountSubject::from_broker_validated(Zeroizing::new(
            snapshot
                .subject()
                .ok_or(FlowError::UnknownAccount)?
                .to_owned(),
        ))
        .map_err(|_error| FlowError::Token(BrokerError::IdentityUnverified))?;
        let intent = AuthorizationIntent::Upgrade(UpgradeBinding::new(account.clone(), subject));
        let pending = broker
            .begin_capability_authorization(
                redirect,
                requested.unwrap_or(snapshot.capability()),
                intent,
            )
            .map_err(FlowError::Token)?;
        Ok((self.operations.get(account)?.generation(), pending))
    }

    // Caller holds the account permit. Kept separate from the browser wait so
    // controlled transports can exercise the actual production completion boundary.
    async fn complete_existing(
        &self,
        broker: &Broker,
        account: &AccountId,
        generation: u64,
        handle: &str,
        callback: &str,
    ) -> Result<CapabilityBrokerToken, FlowError> {
        let operation = self.operations.get(account)?;
        operation.validate(generation)?;
        let token = broker
            .complete_capability_authorization(handle, callback)
            .await
            .map_err(FlowError::Token)?;
        self.invalidate_known(account, &operation);
        Ok(token)
    }

    pub(crate) fn invalidate(&self, account: &AccountId) -> Result<(), FlowError> {
        let operation = self.operations.get(account)?;
        self.invalidate_known(account, &operation);
        Ok(())
    }

    pub(crate) fn invalidate_known(
        &self,
        account: &AccountId,
        operation: &crate::coordination::AccountOperation,
    ) {
        operation.invalidate();
        self.sessions.forget(account);
    }

    /// Refreshes the account's access token and runs a bounded sync.
    ///
    /// # Errors
    ///
    /// Returns a [`FlowError`] for an unknown account, a token failure, or a
    /// gate or sync failure.
    pub async fn sync_account(&self, account: &AccountId) -> Result<SyncReport, FlowError> {
        let operation = self.operations.get(account)?;
        let _permit = operation.permit.lock().await;
        self.sync_under_permit(account).await
    }

    pub(crate) async fn sync_under_permit(
        &self,
        account: &AccountId,
    ) -> Result<SyncReport, FlowError> {
        self.with_session(account, |session| self.sync_with_session(account, session))
            .await
    }

    /// Clears one existing cache, closes its connection, then syncs that account.
    ///
    /// Requires a configured runtime, a caller-held installation lock for the
    /// WHOLE operation. Work through other runtimes or cloned store handles
    /// must not overlap. Shared-runtime operations use the account permit. Cached
    /// sessions contain HTTP/token state, not account-store connections.
    ///
    /// Clear itself preserves credentials/identity/recovery. Resync is exactly
    /// [`Self::sync_account`], with its existing identity gate and recent-mail
    /// policy. Normal broker behavior may rotate credentials or delete a revoked
    /// refresh token; this operation neither revokes nor restores a grant.
    ///
    /// Dropping an unpolled future changes nothing. Once clear commits, dropping
    /// during sync leaves that committed clear (and any normal sync progress)
    /// in place. No SQL transaction or clear connection spans the network wait.
    ///
    /// The compatibility receiver still prevents overlapping borrows; shared
    /// callers can use `reset_account_cache` with account serialization:
    ///
    /// ```compile_fail
    /// use tersa_sync_runtime::Runtime;
    /// use tersa_application::mailbox::AccountId;
    /// async fn overlap(runtime: &mut Runtime, account: &AccountId) {
    ///     let sync = runtime.sync_account(account);
    ///     let reset = runtime.reset_cache(account);
    ///     sync.await;
    ///     reset.await;
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// An error means pre-clear refusal, with no cache deletion. After commit,
    /// sync errors are returned as `Ok(CacheResetOutcome::ResyncFailed(_))`.
    /// Configuration errors are rejected by [`Runtime::new`] before this API.
    pub async fn reset_cache<'a>(
        &'a mut self,
        account: &'a AccountId,
    ) -> Result<CacheResetOutcome, CacheResetPreconditionError> {
        self.reset_account_cache(account).await
    }

    /// Clears and resynchronizes one account through shared runtime coordination.
    ///
    /// The caller holds the installation lock. Independent account operations
    /// and cached reads remain available. The permit spans clear and resync;
    /// no account permit is recursively acquired by the sync phase.
    ///
    /// # Errors
    /// Refusal leaves the cache intact. After clear commits, sync failure is
    /// returned separately as `CacheResetOutcome::ResyncFailed`.
    pub async fn reset_account_cache<'a>(
        &'a self,
        account: &'a AccountId,
    ) -> Result<CacheResetOutcome, CacheResetPreconditionError> {
        reset_cache_using(self, account, Self::sync_under_permit).await
    }

    /// Runs `work` with the account's session; see [`retry_rejected`].
    async fn with_session<R, F, Fut>(&self, account: &AccountId, work: F) -> Result<R, FlowError>
    where
        F: Fn(SharedSession) -> Fut,
        Fut: Future<Output = Result<R, FlowError>>,
    {
        retry_rejected(
            || self.session(account),
            |used: &SharedSession| {
                self.sessions.forget_if(account, |cached| cached.is(used));
                if let Ok(operation) = self.operations.get(account) {
                    operation.invalidate();
                }
            },
            work,
        )
        .await
    }

    /// Revokes the grant at Google (best effort), then deletes the account's
    /// credential and local data.
    ///
    /// # Errors
    ///
    /// Returns a [`FlowError`] when the account is unknown or local removal
    /// fails.
    pub async fn remove_account(&self, account: &AccountId) -> Result<Revocation, FlowError> {
        self.installation.require_registry_write()?;
        let operation = self.operations.get(account)?;
        let _permit = operation.permit.lock().await;
        let broker = self.broker()?;
        let subject = self.subject_of(account)?;
        let store = self.installation.open_store(account)?;
        // Pending commands refuse HERE, before any provider revocation.
        store
            .mark_disconnect_started(account)
            .await
            .map_err(InstallationError::Store)?;
        self.invalidate_known(account, &operation);
        let revocation = match broker.revoke_capability_grant(account, &subject).await {
            Ok(()) => Revocation::Confirmed,
            Err(BrokerError::RevokeUnconfirmed) => {
                store
                    .mark_revoke_unconfirmed(account)
                    .await
                    .map_err(InstallationError::Store)?;
                Revocation::Unconfirmed
            }
            Err(error) => return Err(FlowError::Token(error)),
        };
        // The call explicitly requests local cleanup even after an uncertain revoke.
        // Until that succeeds its durable marker remains available for recovery.
        drop(store);
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
        let operation = self.operations.get(account)?;
        let _permit = operation.permit.lock().await;
        self.with_session(account, |session| async move {
            let store = self.installation.open_store(account)?;
            gated_fetch(account, session, &self.hasher, store, message_id)
                .await
                .map(|message| message.into_content().into_bytes())
                .map_err(FlowError::Fetch)
        })
        .await
    }

    /// The account's Gmail session, refreshing its access token only when
    /// none is cached or the cached one is about to expire.
    async fn session(&self, account: &AccountId) -> Result<(SharedSession, Origin), FlowError> {
        self.subject_of(account)?;
        let result = self
            .sessions
            .get_or_refresh(account, || async {
                self.new_session(account).await.map_err(Arc::new)
            })
            .await
            .map_err(FlowError::Refresh)?;
        if !self.session_is_current(account, &result.0)? {
            self.invalidate(account)?;
            return Err(FlowError::Token(BrokerError::GrantChanged));
        }
        Ok(result)
    }

    /// Refreshes the account's access token into a new session, with the
    /// token's lifetime.
    async fn new_session(
        &self,
        account: &AccountId,
    ) -> Result<(SharedSession, Duration), FlowError> {
        let operation = self.operations.get(account)?;
        let subject = self.subject_of(account)?;
        let token = match self
            .broker()?
            .refresh_capability_grant(account, &subject)
            .await
        {
            Ok(token) => token,
            Err(error) => {
                // Rejected current authority cannot be reused, even if a refresh
                // persisted a revocation-only rotation before returning failure.
                self.invalidate_known(account, &operation);
                return Err(FlowError::Token(error));
            }
        };
        let lifetime = Duration::from_secs(token.token().expires_in_seconds());
        // A successful refresh may rotate credentials; advance even if the
        // provider omitted rotation, conservatively fencing old completions.
        self.invalidate_known(account, &operation);
        let session = GmailSession::from_capability(token, operation.generation())
            .map_err(FlowError::Session)?;
        Ok((SharedSession::new(session), lifetime))
    }

    // P7b dispatch must call this under the same account permit, then check
    // the recorded identity through its AccountFence before any provider write.
    pub(crate) fn session_is_current(
        &self,
        account: &AccountId,
        session: &SharedSession,
    ) -> Result<bool, FlowError> {
        let snapshot = self
            .installation
            .open_store(account)?
            .load_credential_snapshot(account)
            .map_err(|_error| FlowError::Token(BrokerError::PersistenceFailed))?;
        Ok(
            session.generation() == self.operations.get(account)?.generation()
                && snapshot.subject() == Some(session.subject().as_str())
                && snapshot.capability() == session.capability()
                && matches!(
                    snapshot.credential(),
                    tersa_store_sqlcipher::StoreCredential::Active(_)
                ),
        )
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

    async fn sync_with_session<S: AccountProfile + RemoteMailbox + SessionEmailAddress>(
        &self,
        account: &AccountId,
        session: S,
    ) -> Result<SyncReport, FlowError> {
        let store = self.installation.open_store(account)?;
        // The address is fetched with this session's own token, but it is
        // stored only after the identity gate has proven that this session
        // owns the account. A failed fetch or store never fails the sync;
        // the address simply stays as it was.
        let email = session.email_address().await.ok();
        let report = gated_sync(account, session, &self.hasher, store, default_sync_policy())
            .await
            .map_err(FlowError::Sync);
        if report.is_ok()
            && let Some(email) = email
            && let Ok(store) = self.installation.open_store(account)
        {
            let _ = store.store_email_address(account, &email);
        }
        report
    }
}

/// Runs `work` with a session from `session`. When Gmail rejects a cached
/// access token (it can lapse early, for example across a sleep, or be
/// revoked), that session is forgotten and `work` runs once more with a fresh
/// one. A freshly refreshed token that is rejected is not retried. `forget`
/// receives the rejected session, so it can leave a newer one in place.
async fn retry_rejected<S, R, Get, GetFut, Forget, Work, WorkFut>(
    session: Get,
    forget: Forget,
    work: Work,
) -> Result<R, FlowError>
where
    S: Clone,
    Get: Fn() -> GetFut,
    GetFut: Future<Output = Result<(S, Origin), FlowError>>,
    Forget: Fn(&S),
    Work: Fn(S) -> WorkFut,
    WorkFut: Future<Output = Result<R, FlowError>>,
{
    let (first, origin) = session().await?;
    let result = work(first.clone()).await;
    if !needs_authorization(&result) {
        return result;
    }
    forget(&first);
    if origin == Origin::Fresh {
        return result;
    }
    let (second, _origin) = session().await?;
    let result = work(second.clone()).await;
    if needs_authorization(&result) {
        forget(&second);
    }
    result
}

/// Whether Gmail rejected the access token.
fn needs_authorization<R>(result: &Result<R, FlowError>) -> bool {
    match result {
        Err(FlowError::Sync(GatedSyncError::Sync(failure))) => {
            failure.category()
                == SyncFailureSource::Remote(RemoteMailboxError::AuthorizationRequired)
        }
        Err(FlowError::Fetch(GatedFetchError::Remote(
            RemoteMailboxError::AuthorizationRequired,
        ))) => true,
        _ => false,
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
    use tersa_application::mailbox::RemoteMailboxError;
    use tersa_application::sync::{SyncFailure, SyncFailureSource};

    use std::cell::RefCell;

    use super::{FlowError, default_sync_policy, needs_authorization, retry_rejected};
    use crate::gate::{GatedFetchError, GatedSyncError};
    use crate::session_cache::Origin;

    fn rejected() -> FlowError {
        FlowError::Fetch(GatedFetchError::Remote(
            RemoteMailboxError::AuthorizationRequired,
        ))
    }

    /// What `retry_rejected` did: sessions handed out, forgotten, and used.
    #[derive(Debug, Default, PartialEq)]
    struct Calls {
        issued: Vec<u32>,
        forgotten: Vec<u32>,
        worked: Vec<u32>,
    }

    /// Runs `retry_rejected` with sessions numbered from 1 (the first from
    /// `first_origin`, later ones fresh) and `outcomes` for each `work` call.
    fn retry(
        first_origin: Origin,
        outcomes: Vec<Result<(), FlowError>>,
    ) -> (Result<(), FlowError>, Calls) {
        let calls = RefCell::new(Calls::default());
        let outcomes = RefCell::new(outcomes);
        let result = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime")
            .block_on(retry_rejected(
                || {
                    let mut calls = calls.borrow_mut();
                    let next = u32::try_from(calls.issued.len()).expect("few calls") + 1;
                    calls.issued.push(next);
                    let origin = if next == 1 {
                        first_origin
                    } else {
                        Origin::Fresh
                    };
                    std::future::ready(Ok((next, origin)))
                },
                |session: &u32| calls.borrow_mut().forgotten.push(*session),
                |session| {
                    calls.borrow_mut().worked.push(session);
                    std::future::ready(outcomes.borrow_mut().remove(0))
                },
            ));
        (result, calls.into_inner())
    }

    #[test]
    fn the_default_policy_is_valid() {
        let _policy = default_sync_policy();
    }

    #[test]
    fn only_a_rejected_token_retries_with_a_fresh_one() {
        let sync = |source| {
            Err::<(), _>(FlowError::Sync(GatedSyncError::Sync(
                SyncFailure::from_source_for_test(source),
            )))
        };
        let fetch = |error| Err::<(), _>(FlowError::Fetch(GatedFetchError::Remote(error)));
        assert!(needs_authorization(&sync(SyncFailureSource::Remote(
            RemoteMailboxError::AuthorizationRequired
        ))));
        assert!(needs_authorization(&fetch(
            RemoteMailboxError::AuthorizationRequired
        )));
        assert!(!needs_authorization(&sync(SyncFailureSource::Remote(
            RemoteMailboxError::Transport
        ))));
        assert!(!needs_authorization(&fetch(RemoteMailboxError::Transport)));
        assert!(!needs_authorization(&Err::<(), _>(
            FlowError::UnknownAccount
        )));
        assert!(!needs_authorization(&Ok(())));
    }

    #[test]
    fn a_rejected_cached_session_is_forgotten_and_retried_once() {
        let (result, calls) = retry(Origin::Cached, vec![Err(rejected()), Ok(())]);
        assert!(result.is_ok());
        assert_eq!(
            calls,
            Calls {
                issued: vec![1, 2],
                forgotten: vec![1],
                worked: vec![1, 2],
            }
        );
    }

    #[test]
    fn a_rejected_fresh_session_is_forgotten_but_not_retried() {
        let (result, calls) = retry(Origin::Fresh, vec![Err(rejected())]);
        assert!(needs_authorization(&result));
        assert_eq!(
            calls,
            Calls {
                issued: vec![1],
                forgotten: vec![1],
                worked: vec![1],
            }
        );
    }

    #[test]
    fn a_second_rejection_forgets_the_new_session_and_stops() {
        let (result, calls) = retry(Origin::Cached, vec![Err(rejected()), Err(rejected())]);
        assert!(needs_authorization(&result));
        assert_eq!(
            calls,
            Calls {
                issued: vec![1, 2],
                forgotten: vec![1, 2],
                worked: vec![1, 2],
            }
        );
    }

    #[test]
    fn other_failures_keep_the_session() {
        let offline = FlowError::Fetch(GatedFetchError::Remote(RemoteMailboxError::Transport));
        let (result, calls) = retry(Origin::Cached, vec![Err(offline)]);
        assert!(matches!(result, Err(FlowError::Fetch(_))));
        assert_eq!(
            calls,
            Calls {
                issued: vec![1],
                forgotten: vec![],
                worked: vec![1],
            }
        );
    }
}

#[cfg(test)]
#[path = "capability_tests.rs"]
mod capability_tests;
