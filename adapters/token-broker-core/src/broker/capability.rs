// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Adds bound capability lifecycle operations without activating runtime or storage adapters.

use super::{
    AuthorizationConfig, BrokerCore, BrokerError, BrokerToken, IDENTITY_FRESHNESS_SKEW_SECS,
    MAX_CALLBACK_LEN, MAX_REFRESH_TOKEN_LEN, MonotonicClock, PendingAuthorization,
    RefreshTokenStore, SessionHandle, SessionHandleEntropy, TokenTransport, ValidatedSubject,
    WallClock, map_oauth_error, map_token_error, parse_loopback_redirect, prepare_authorization,
};
use crate::{
    CapabilityGrantStore, CapabilityGrantStoreError, GrantCredential, StoredCapabilityGrant,
};
use tersa_application::{
    AccountCapability,
    mailbox::AccountId,
    profile::UpgradeBinding,
    scope::AcceptedScope,
    token::{
        AccountSubject, CapabilityRefreshOutcome, StoredGrantSnapshot, TokenError,
        exchange_capability_grant, refresh_stored_grant,
    },
};
use url::Url;
use zeroize::Zeroizing;

/// Captures Connect versus selected-account replacement before browser launch.
#[derive(Debug)]
pub enum AuthorizationIntent {
    /// Admit only a new subject; known subjects require explicit selected reconnect.
    Connect,
    /// Replace only this already known account/immutable subject, even if tokenless.
    Upgrade(UpgradeBinding),
}

/// Returns accepted account-bound access and scope provenance, never refresh credentials.
///
/// Runtime must invalidate prior access sessions and advance its process-local
/// generation while holding the account operation permit before exposing this
/// result. No persisted generation or runtime cache implementation is implied.
#[derive(Debug)]
pub struct CapabilityBrokerToken {
    account: AccountId,
    token: BrokerToken,
    accepted_scope: AcceptedScope,
}
impl CapabilityBrokerToken {
    /// Returns the actual admitted or explicitly selected account.
    #[must_use]
    pub fn account_id(&self) -> &AccountId {
        &self.account
    }
    /// Returns the accepted capability, bound to begin or trusted stored context.
    #[must_use]
    pub fn capability(&self) -> AccountCapability {
        self.accepted_scope.capability()
    }
    /// Returns complete accepted scope provenance, never a legacy readonly boolean.
    #[must_use]
    pub fn accepted_scope(&self) -> AcceptedScope {
        self.accepted_scope
    }
    /// Returns bounded short-lived access/subject/expiry to trusted composition.
    #[must_use]
    pub fn token(&self) -> &BrokerToken {
        &self.token
    }
    /// Transfers account-bound access and accepted scope to trusted runtime composition.
    #[must_use]
    pub fn into_parts(self) -> (AccountId, BrokerToken, AcceptedScope) {
        (self.account, self.token, self.accepted_scope)
    }
}

impl<T, S, C, W, E> BrokerCore<T, S, C, W, E>
where
    T: TokenTransport,
    S: RefreshTokenStore + CapabilityGrantStore,
    C: MonotonicClock + Clone,
    W: WallClock,
    E: SessionHandleEntropy,
{
    /// Begins an immutable capability/intent-bound session using the existing bounded registry.
    ///
    /// Upgrade verifies the selected existing binding before browser launch, but
    /// does not hold a permit across the user/browser wait. Missing credentials
    /// are legitimate known-account state; no registration occurs on this path.
    /// Runtime must serialize completion with all selected-account work and
    /// invalidate cached sessions under that same account permit after success.
    ///
    /// # Errors
    /// Returns closed redirect/configuration/registry failures, unknown or mismatched
    /// selected binding, subject Busy, or unreadable stored state. No grant writes occur.
    pub fn begin_capability_authorization(
        &self,
        redirect_uri: &str,
        capability: AccountCapability,
        intent: AuthorizationIntent,
    ) -> Result<PendingAuthorization, BrokerError> {
        let redirect = parse_loopback_redirect(redirect_uri)?;
        if let AuthorizationIntent::Upgrade(binding) = &intent {
            let subject = ValidatedSubject::new(binding.expected_subject().as_str())?;
            let _permit = self.permits.claim(subject.as_str())?;
            self.selected_grant(binding.account_id(), &subject)?;
        }
        let config = AuthorizationConfig::for_capability(
            self.client_id.clone(),
            redirect.clone(),
            self.session_ttl,
            capability,
        )
        .map_err(|_e| BrokerError::InvalidConfiguration)?;
        let _token_config = self.token_client_config(&redirect)?;
        let prepared =
            prepare_authorization(config, self.clock.clone()).map_err(map_oauth_error)?;
        let (authorization_url, session) = prepared.into_parts();
        let session_handle = self
            .registry
            .insert_capability(session, intent, &self.entropy)?;
        Ok(PendingAuthorization {
            authorization_url,
            session_handle,
        })
    }

    /// Completes only a capability session, consuming its intent before any callback validation.
    ///
    /// Routing a legacy handle here (or a capability handle to legacy completion)
    /// consumes it and fails. Upgrade claims the captured subject permit before
    /// exchange, snapshots the existing account only, and compares the returned
    /// subject before any write/revoke. Connect claims the validated new subject
    /// permit after exchange and refuses every already known subject, including
    /// tokenless accounts. Selected reconnect remains available for those accounts.
    ///
    /// # Errors
    /// Returns closed callback/token/freshness failures, incomplete scope evidence,
    /// wrong subject, missing refresh token, duplicate/unknown binding, stale CAS or
    /// store failure. Upgrade failures never revoke. Connect snapshots under its
    /// subject permit before freshness/access/missing-refresh checks: any known
    /// binding refuses Connect; unreadable state withholds cleanup. Only a
    /// definitive empty snapshot permits best-effort stranded-grant cleanup of
    /// post-success failures, retaining their original error.
    /// Upstream denied/under-scoped/incomplete/malformed exchange errors without
    /// `TokenSuccess` provide no safe cleanup identity/handle and never revoke;
    /// this includes oversized rotation rejected by application validation.
    /// No legacy token-only store fallback exists.
    pub async fn complete_capability_authorization(
        &self,
        session_handle: &str,
        callback_url: &str,
    ) -> Result<CapabilityBrokerToken, BrokerError> {
        let handle = SessionHandle::parse(session_handle)?;
        let (mut session, intent) = self.registry.claim_capability(&handle)?;
        let token_config = self.token_client_config(session.redirect_uri())?;
        if callback_url.len() > MAX_CALLBACK_LEN {
            return Err(BrokerError::InvalidInput);
        }
        let callback = Url::parse(callback_url).map_err(|_e| BrokerError::InvalidInput)?;
        let grant = session.finish(&callback).map_err(map_oauth_error)?;
        // Binding and permit precede the Upgrade exchange; no store lock spans it.
        let selected = match &intent {
            AuthorizationIntent::Connect => None,
            AuthorizationIntent::Upgrade(binding) => {
                let subject = ValidatedSubject::new(binding.expected_subject().as_str())?;
                let permit = self.permits.claim(subject.as_str())?;
                let snapshot = self.selected_grant(binding.account_id(), &subject)?;
                Some((subject, snapshot, permit))
            }
        };
        let success =
            exchange_capability_grant(&grant, &token_config, &self.transport, &self.clock)
                .await
                .map_err(map_token_error)?;
        drop(grant);
        let subject = ValidatedSubject::new(success.subject().as_str())
            .map_err(|_e| BrokerError::IdentityUnverified)?;
        if selected
            .as_ref()
            .is_some_and(|(expected, _, _)| expected != &subject)
        {
            return Err(BrokerError::IdentityMismatch);
        }
        let (account, token) = if let Some((_subject, snapshot, _permit)) = &selected {
            success
                .identity_expiry()
                .validate_fresh(self.wall_clock.unix_time(), IDENTITY_FRESHNESS_SKEW_SECS)
                .map_err(|_e| BrokerError::IdentityUnverified)?;
            let token = self.broker_token(&success)?;
            let refresh = completion_refresh(&success)?;
            self.store
                .replace_existing(snapshot, refresh, success.capability())
                .map_err(map_store_error)?;
            (snapshot.account_id().clone(), token)
        } else {
            let _permit = self.permits.claim(subject.as_str())?;
            // A known binding of ANY purpose is occupied, including Missing.
            // An unreadable snapshot never licenses cleanup or overwrite.
            if self
                .store
                .load_grant(&subject)
                .map_err(|_e| BrokerError::PersistenceFailed)?
                .is_some()
            {
                return Err(BrokerError::AccountAlreadyConnected);
            }
            let usable = (|| {
                success
                    .identity_expiry()
                    .validate_fresh(self.wall_clock.unix_time(), IDENTITY_FRESHNESS_SKEW_SECS)
                    .map_err(|_e| BrokerError::IdentityUnverified)?;
                let token = self.broker_token(&success)?;
                let refresh = completion_refresh(&success)?;
                Ok::<_, BrokerError>((token, refresh))
            })();
            let (token, refresh) = match usable {
                Ok(usable) => usable,
                Err(error) => {
                    // Only the definitive unknown/empty snapshot above permits
                    // existing bounded revoke_handle cleanup. Hold the subject
                    // permit across cleanup; its failure cannot mask the cause.
                    self.revoke_stranded_grant(&super::StoreSnapshot::Empty, &success)
                        .await;
                    return Err(error);
                }
            };
            let account = match self
                .store
                .connect_new(&subject, refresh, success.capability())
            {
                Ok(account) => account,
                Err(error) => {
                    // Conflict/duplicate or unreadable/known state never revokes over another grant.
                    if matches!(error, CapabilityGrantStoreError::Unavailable)
                        && matches!(self.store.load_grant(&subject), Ok(None))
                    {
                        self.revoke_best_effort(refresh).await;
                    }
                    return Err(map_store_error(error));
                }
            };
            (account, token)
        };
        let (_, _, _, _, accepted_scope) = success.into_capability_parts();
        Ok(CapabilityBrokerToken {
            account,
            token,
            accepted_scope,
        })
    }

    /// Refreshes one selected known account using an atomically loaded stored grant snapshot.
    ///
    /// Returned scope cannot promote capability. Scope-rejected valid rotation is
    /// retained solely for revocation and returns failure without access. Matched
    /// granted rotation preserves capability and is retained before wall-clock
    /// freshness/success minting, matching the existing ADR 0024 retention order.
    ///
    /// # Errors
    /// Distinguishes unknown account, known Missing token, scope-rejected/revocation-only
    /// state, subject mismatch, incomplete evidence and persistence failures.
    /// `ConsentRevoked` is returned only after confirmed credential deletion.
    pub async fn refresh_capability_grant(
        &self,
        account: &AccountId,
        account_subject: &str,
    ) -> Result<CapabilityBrokerToken, BrokerError> {
        let subject = ValidatedSubject::new(account_subject)?;
        let _permit = self.permits.claim(subject.as_str())?;
        let stored = self.selected_grant(account, &subject)?;
        let active = match stored.credential() {
            GrantCredential::Missing => return Err(BrokerError::MissingRefreshToken),
            GrantCredential::RevocationOnly(_) => return Err(BrokerError::InsufficientScope),
            GrantCredential::Active(token) => token,
        };
        let app_subject =
            AccountSubject::from_broker_validated(Zeroizing::new(subject.as_str().to_owned()))
                .map_err(|_e| BrokerError::PersistenceFailed)?;
        let snapshot = StoredGrantSnapshot::new(active.clone(), app_subject, stored.capability())
            .map_err(|_e| BrokerError::PersistenceFailed)?;
        let config = self.refresh_client_config()?;
        let outcome =
            match refresh_stored_grant(&snapshot, &config, &self.transport, &self.clock).await {
                Ok(outcome) => outcome,
                Err(TokenError::ConsentRevoked) => {
                    self.store
                        .delete_existing(&stored)
                        .map_err(|_e| BrokerError::PersistenceFailed)?;
                    return Err(BrokerError::ConsentRevoked);
                }
                Err(error) => return Err(map_token_error(error)),
            };
        match outcome {
            CapabilityRefreshOutcome::ScopeRejected { rotation, .. } => {
                if let Some(handle) = rotation {
                    self.store
                        .retain_revocation_rotation(&stored, &handle)
                        .map_err(map_store_error)?;
                }
                Err(BrokerError::InsufficientScope)
            }
            CapabilityRefreshOutcome::Granted(success) => {
                if let Some(rotation) = success.rotated_refresh_token() {
                    self.store
                        .rotate_existing(&stored, rotation)
                        .map_err(map_store_error)?;
                }
                success
                    .identity_expiry()
                    .validate_fresh(self.wall_clock.unix_time(), IDENTITY_FRESHNESS_SKEW_SECS)
                    .map_err(|_e| BrokerError::IdentityUnverified)?;
                let token = self.broker_token(&success)?;
                let (_, _, _, _, accepted_scope) = success.into_capability_parts();
                Ok(CapabilityBrokerToken {
                    account: account.clone(),
                    token,
                    accepted_scope,
                })
            }
        }
    }

    /// Revokes an existing selected grant's Active or revocation-only credential, without deleting it.
    ///
    /// Uses the existing at-most-two-call revoke contract; never reuses a rejected
    /// rotation for refresh. Runtime still owns durable disconnect intent/purge order.
    ///
    /// # Errors
    /// Returns unknown/mismatched binding, Busy, store failure or `RevokeUnconfirmed`.
    pub async fn revoke_capability_grant(
        &self,
        account: &AccountId,
        account_subject: &str,
    ) -> Result<(), BrokerError> {
        let subject = ValidatedSubject::new(account_subject)?;
        let _permit = self.permits.claim(subject.as_str())?;
        let stored = self.selected_grant(account, &subject)?;
        let token = match stored.credential() {
            GrantCredential::Missing => return Ok(()),
            GrantCredential::Active(token) | GrantCredential::RevocationOnly(token) => token,
        };
        for attempt in 0..2 {
            match self.transport.revoke(token).await {
                Ok(())
                | Err(
                    super::TokenTransportError::InvalidGrant
                    | super::TokenTransportError::InvalidToken,
                ) => return Ok(()),
                Err(_e) if attempt == 0 => {}
                Err(_e) => return Err(BrokerError::RevokeUnconfirmed),
            }
        }
        Err(BrokerError::RevokeUnconfirmed)
    }

    /// Deletes only an exact selected known credential, without provider revoke or account purge.
    ///
    /// # Errors
    /// Returns unknown/mismatched binding, Busy or a closed owning-store failure.
    pub fn delete_capability_grant(
        &self,
        account: &AccountId,
        account_subject: &str,
    ) -> Result<(), BrokerError> {
        let subject = ValidatedSubject::new(account_subject)?;
        let _permit = self.permits.claim(subject.as_str())?;
        let stored = self.selected_grant(account, &subject)?;
        self.store.delete_existing(&stored).map_err(map_store_error)
    }

    fn selected_grant(
        &self,
        account: &AccountId,
        subject: &ValidatedSubject,
    ) -> Result<StoredCapabilityGrant, BrokerError> {
        let snapshot = self
            .store
            .load_grant(subject)
            .map_err(map_store_error)?
            .ok_or(BrokerError::AccountUnknown)?;
        if snapshot.account_id() != account || snapshot.subject() != subject {
            return Err(BrokerError::IdentityMismatch);
        }
        Ok(snapshot)
    }
}

fn map_store_error(error: CapabilityGrantStoreError) -> BrokerError {
    match error {
        CapabilityGrantStoreError::Unavailable | CapabilityGrantStoreError::Invalid => {
            BrokerError::PersistenceFailed
        }
        CapabilityGrantStoreError::UnknownAccount => BrokerError::AccountUnknown,
        CapabilityGrantStoreError::AlreadyConnected => BrokerError::AccountAlreadyConnected,
        CapabilityGrantStoreError::Conflict => BrokerError::GrantChanged,
    }
}

fn completion_refresh(success: &super::TokenSuccess) -> Result<&Zeroizing<String>, BrokerError> {
    let token = success
        .rotated_refresh_token()
        .ok_or(BrokerError::MissingRefreshToken)?;
    if token.is_empty() || token.len() > MAX_REFRESH_TOKEN_LEN {
        return Err(BrokerError::MalformedResponse);
    }
    Ok(token)
}
