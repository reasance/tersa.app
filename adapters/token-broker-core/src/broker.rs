// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The in-process token-service composition (ADR-0024 and ADR 0031).
//!
//! [`BrokerCore`] wires the portable OAuth and token state machines to the
//! injected transport, refresh-token store, clocks, and entropy ports. It owns
//! the full lifecycle — begin/complete authorization, refresh, provider
//! revoke, and local delete — under the crate's security invariants: strict
//! literal-IPv4 loopback redirects with an explicit non-privileged port, an
//! atomically claimed bounded session registry, per-subject single-flight
//! permits released by RAII (a completion claims its account's permit before
//! any store read or write), persistence of any refresh credential BEFORE a
//! success is reported, snapshot-conditional cleanup of stranded
//! post-exchange grants (a provider revoke only ever runs against a
//! definitively empty store snapshot, because Google revocation is
//! grant-wide, and an unreadable snapshot fails closed before any store
//! write or revoke), a fail-safe non-destructive under-scoped completion
//! (nothing persisted, nothing revoked: no validated identity exists to
//! gate a grant-wide revoke), and public values that carry no refresh
//! token, PKCE verifier, state, or authorization code. No mutex guard is
//! held across an `.await`, and no access token is ever cached: every
//! success value is minted fresh from a provider round trip.

use std::fmt;
use std::time::Duration;

use tersa_application::oauth::{
    AuthorizationConfig, MonotonicClock, OAuthError, WallClock, prepare_authorization,
};
use tersa_application::token::{
    TokenClientConfig, TokenError, TokenScopeOutcome, TokenSuccess, TokenTransport,
    TokenTransportError, exchange_grant_with_scope_outcome,
    refresh_access_token_with_scope_outcome,
};
use url::Url;
use zeroize::Zeroizing;

use crate::error::BrokerError;
use crate::handle::SessionHandle;
use crate::permits::SubjectPermits;
use crate::ports::{RefreshTokenStore, SessionHandleEntropy};
use crate::registry::SessionRegistry;
use crate::subject::ValidatedSubject;

// Rust guideline compliant 1.0.

/// The only accepted redirect prefix: plain HTTP on the literal dotted-quad
/// IPv4 loopback with an explicit port. Requiring this exact prefix up front
/// rejects the non-canonical IPv4 encodings (`127.1`, integer or octal forms)
/// the URL parser would otherwise normalize to the same address.
const LOOPBACK_REDIRECT_PREFIX: &str = "http://127.0.0.1:";

/// The inclusive lower bound of the non-privileged port range accepted for
/// the loopback redirect (`1024..=65535`). There is deliberately no
/// upper-bound constant: a parsed URL port is already a `u16`, so 65,535 is
/// inherent and a `MAX` comparison would be a dead no-op. The accepted range
/// is the NON-PRIVILEGED range, not the IANA ephemeral range
/// (`49152..=65535`): only privilege separation is enforced.
const MIN_LOOPBACK_PORT: u16 = 1024;

/// Caps the redirect text accepted by `begin_authorization`. The accepted
/// shape is a few dozen bytes; anything larger is adversarial.
const MAX_REDIRECT_LEN: usize = 256;

/// Caps the callback text accepted by `complete_authorization`. A Google
/// loopback callback is a few hundred bytes.
const MAX_CALLBACK_LEN: usize = 4_096;

/// Caps a provider-minted access token. Real tokens are well under 2 KiB.
const MAX_ACCESS_TOKEN_LEN: usize = 4_096;

/// Caps a provider-minted or stored refresh token. Real tokens are ~512 bytes.
///
/// Google documents no maximum refresh-token length, so this hard bound has a
/// deliberate, diagnosable failure mode: an over-bound provider rotation is
/// rejected as `MalformedResponse` BEFORE any persistence or revoke input —
/// a visible terminal error, never a truncation or partial write. A sustained
/// rise in refresh-path `MalformedResponse` terminals should be read as a
/// possible provider-side change outgrowing the bound (a signal to review
/// this constant), not only as response corruption.
const MAX_REFRESH_TOKEN_LEN: usize = 1_024;

/// Caps the access-token lifetime the broker reports, in seconds (24 hours).
const MAX_EXPIRES_IN_SECS: u64 = 86_400;

/// The largest authorization-session TTL accepted at construction (one hour).
const MAX_SESSION_TTL: Duration = Duration::from_secs(3_600);

/// The wall-clock skew tolerated when validating `id_token` freshness, in
/// seconds. The established 120-second boundary preserves accepted identity
/// freshness behavior: tightening it would reject identities currently
/// accepted by the token service. A change requires explicit policy review.
const IDENTITY_FRESHNESS_SKEW_SECS: u64 = 120;

/// The public half of a pending authorization: the browser URL and the opaque
/// session handle needed to complete it exactly once.
///
/// `Debug` redacts both values: the URL carries the PKCE challenge and state.
pub struct PendingAuthorization {
    authorization_url: Url,
    session_handle: SessionHandle,
}

impl PendingAuthorization {
    /// Returns the authorization URL intended for the system browser.
    #[must_use]
    pub fn authorization_url(&self) -> &Url {
        &self.authorization_url
    }

    /// Returns the opaque session handle text the caller presents to
    /// [`BrokerCore::complete_authorization`] exactly once.
    #[must_use]
    pub fn session_handle(&self) -> &str {
        self.session_handle.as_str()
    }
}

impl fmt::Debug for PendingAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingAuthorization")
            .field("authorization_url", &"[REDACTED]")
            .field("session_handle", &self.session_handle)
            .finish()
    }
}

/// The only success value the broker exposes: a zeroizing access token, the
/// validated account subject, and a bounded positive lifetime in seconds.
///
/// No refresh token, PKCE verifier, state, or authorization code is ever part
/// of a broker success value, and `Debug` redacts the token and subject.
pub struct BrokerToken {
    access_token: Zeroizing<String>,
    subject: Zeroizing<String>,
    expires_in_seconds: u64,
}

impl BrokerToken {
    /// Returns the access token without transferring ownership.
    ///
    /// Returns the `Zeroizing` wrapper so callers clone without minting a
    /// non-zeroizing plaintext copy of this hot secret.
    #[must_use]
    pub fn access_token(&self) -> &Zeroizing<String> {
        &self.access_token
    }

    /// Returns the validated account subject without transferring ownership.
    ///
    /// The subject is account-identifying, not a secret: it is the storage key
    /// under which the refresh credential was persisted.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Returns the access token's remaining lifetime in seconds, measured
    /// against the broker's monotonic clock when the token was minted. Always
    /// positive and bounded by `MAX_EXPIRES_IN_SECS`.
    #[must_use]
    pub fn expires_in_seconds(&self) -> u64 {
        self.expires_in_seconds
    }
}

impl fmt::Debug for BrokerToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrokerToken")
            .field("access_token", &"[REDACTED]")
            .field("subject", &"[REDACTED]")
            .field("expires_in_seconds", &self.expires_in_seconds)
            .finish()
    }
}

/// The production token-broker lifecycle composition.
///
/// Generic over the token `T`ransport, the refresh-token `S`tore, the
/// cloneable monotonic `C`lock, the `W`all clock, and the session-handle
/// `E`ntropy source. Dependencies are stored by value and only ever borrowed
/// by the methods. The broker owns no async runtime: its async methods are
/// driven by the composition-owned runtime of the hosting process.
pub struct BrokerCore<T, S, C, W, E> {
    client_id: String,
    client_secret: Option<Zeroizing<String>>,
    session_ttl: Duration,
    transport: T,
    store: S,
    clock: C,
    wall_clock: W,
    entropy: E,
    registry: SessionRegistry<C>,
    permits: SubjectPermits,
}

impl<T, S, C, W, E> BrokerCore<T, S, C, W, E>
where
    T: TokenTransport,
    S: RefreshTokenStore,
    C: MonotonicClock + Clone,
    W: WallClock,
    E: SessionHandleEntropy,
{
    /// Creates a broker, validating the reusable client configuration.
    ///
    /// `dependencies` bundles the five ports in field order: `(transport,
    /// store, monotonic_clock, wall_clock, entropy)`. No redirect is accepted
    /// here: the redirect is supplied and strictly validated per authorization
    /// attempt in [`Self::begin_authorization`].
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::InvalidConfiguration`] when the client
    /// identifier is blank, a present client secret is blank, or the session
    /// TTL is zero or exceeds one hour.
    pub fn new(
        client_id: String,
        client_secret: Option<Zeroizing<String>>,
        session_ttl: Duration,
        dependencies: (T, S, C, W, E),
    ) -> Result<Self, BrokerError> {
        let (transport, store, clock, wall_clock, entropy) = dependencies;
        let blank_secret = client_secret
            .as_ref()
            .is_some_and(|secret| secret.trim().is_empty());
        if client_id.trim().is_empty()
            || session_ttl.is_zero()
            || session_ttl > MAX_SESSION_TTL
            || blank_secret
        {
            return Err(BrokerError::InvalidConfiguration);
        }
        Ok(Self {
            client_id,
            client_secret,
            session_ttl,
            transport,
            store,
            clock,
            wall_clock,
            entropy,
            registry: SessionRegistry::new(),
            permits: SubjectPermits::new(),
        })
    }

    /// Begins an authorization attempt for a strictly validated redirect.
    ///
    /// Accepts only `http://127.0.0.1:PORT/` with an explicit non-privileged
    /// port in `1024..=65535`, the exact root path, and no credentials,
    /// query, or fragment. The same client identifier feeds the authorization and token
    /// client configurations, so they match by construction; the token
    /// configuration is validated now (failing before the browser round trip)
    /// and rebuilt from the claimed session at completion.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::InvalidInput`] when the redirect is not the
    /// exact loopback root form, [`BrokerError::InvalidConfiguration`] when
    /// the reusable client configuration is unusable,
    /// [`BrokerError::Unavailable`] when entropy fails, and
    /// [`BrokerError::Busy`] when the bounded pending-session registry is at
    /// capacity (retry after pending sessions expire).
    pub fn begin_authorization(
        &self,
        redirect_uri: &str,
    ) -> Result<PendingAuthorization, BrokerError> {
        let redirect = parse_loopback_redirect(redirect_uri)?;
        let authorization_config =
            AuthorizationConfig::new(self.client_id.clone(), redirect.clone(), self.session_ttl)
                .map_err(|_error| BrokerError::InvalidConfiguration)?;
        let _validated_token_config = self.token_client_config(&redirect)?;
        let prepared = prepare_authorization(authorization_config, self.clock.clone())
            .map_err(map_oauth_error)?;
        let (authorization_url, session) = prepared.into_parts();
        let session_handle = self.registry.insert(session, &self.entropy)?;
        Ok(PendingAuthorization {
            authorization_url,
            session_handle,
        })
    }

    /// Completes an authorization attempt from its loopback callback.
    ///
    /// The session is claimed atomically BEFORE the callback is parsed or
    /// validated, so every callback attempt — valid, malformed, or replayed —
    /// is terminal. A granted response is keyed by its validated subject: the
    /// subject's single-flight permit is claimed immediately after subject
    /// validation and held (cancellation-safe, by RAII) across every later
    /// snapshot, store, and provider call, and the stored credential is
    /// snapshotted BEFORE it is replaced. On success the returned refresh
    /// token is required and persisted BEFORE the [`BrokerToken`] is
    /// returned.
    ///
    /// Post-exchange terminals run snapshot-conditional cleanup: only a
    /// DEFINITIVE empty snapshot licenses a best-effort provider revoke of
    /// the stranded grant, preferring a well-shaped rotated refresh token
    /// over the access token as the revoke handle. Google revocation is
    /// grant-wide, so a prior stored credential — potentially the working
    /// connection — is never revoked over, and a malformed, empty, or
    /// oversized token never becomes a persistence or revoke input. An
    /// unreadable snapshot fails closed as [`BrokerError::PersistenceFailed`]
    /// before any store write or revoke. When identity cannot be validated
    /// to the conservative subject shape there is no safe store key: none is
    /// fabricated, and nothing is persisted or revoked.
    ///
    /// The explicitly under-scoped outcome carries no validated identity by
    /// design (the scope verdict is decided before `id_token` validation),
    /// and the begin operation supplies no account
    /// identity, so no subject-keyed snapshot is possible and none is
    /// fabricated. The fail-safe contract is therefore non-destructive:
    /// nothing is persisted and NOTHING is revoked. An existing stored
    /// credential's surviving local bytes prove nothing — Google's
    /// grant-wide revoke could invalidate that unknown prior working grant
    /// at the provider — so no revoke runs without a keyed snapshot.
    /// Candidly, this can leave a first-connect under-scoped grant active at
    /// Google, and this API CANNOT offer an in-app manual revoke for it: the
    /// minted tokens were dropped and there is no validated subject or
    /// stored credential to key a revoke against. The caller must
    /// surface the failure, offer retain-or-retry recovery, and direct the
    /// user to their Google account-permissions page to revoke the grant
    /// manually. That cost is accepted because the alternative can destroy a
    /// working connection it cannot see.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::InvalidInput`] for a malformed handle, an
    /// oversized or unparsable callback, or a callback that does not match
    /// the pending session; [`BrokerError::SessionUnknown`] when the handle
    /// names no live session (unknown, expired, or consumed);
    /// [`BrokerError::Busy`] when the granted account's subject already has
    /// a mutation in flight; [`BrokerError::InsufficientScope`] when the
    /// grant omitted Gmail read access; [`BrokerError::MissingRefreshToken`]
    /// when the exchange granted no refresh token;
    /// [`BrokerError::IdentityUnverified`] when identity validation or
    /// freshness fails; [`BrokerError::PersistenceFailed`] when the stored
    /// credential could not be read or the refresh credential could not be
    /// stored; and the mapped transport, provider, or malformed-response
    /// terminal otherwise. An exchange-time `invalid_grant` (a stale,
    /// already redeemed, or mismatched authorization code) surfaces as the
    /// dedicated [`BrokerError::AuthorizationCodeRejected`] — the sign-in
    /// lapsed — never [`BrokerError::ConsentRevoked`]: nothing is stored on
    /// this path, so no local deletion is asserted or performed. The variant
    /// stays distinct from [`BrokerError::ProviderRejected`] so callers can
    /// offer sign-in-expired recovery without conflating provider rejection
    /// or revoked consent (ADR-0024).
    pub async fn complete_authorization(
        &self,
        session_handle: &str,
        callback_url: &str,
    ) -> Result<BrokerToken, BrokerError> {
        let handle = SessionHandle::parse(session_handle)?;
        // The claim IS the consumption: the session leaves the registry before
        // any callback validation runs, so a replay can only ever meet
        // `SessionUnknown`.
        let mut session = self.registry.claim(&handle)?;
        let token_config = self.token_client_config(session.redirect_uri())?;
        if callback_url.len() > MAX_CALLBACK_LEN {
            return Err(BrokerError::InvalidInput);
        }
        let callback = Url::parse(callback_url).map_err(|_error| BrokerError::InvalidInput)?;
        let grant = session.finish(&callback).map_err(map_oauth_error)?;
        let outcome =
            exchange_grant_with_scope_outcome(&grant, &token_config, &self.transport, &self.clock)
                .await
                .map_err(map_token_error)?;
        // The grant (authorization code + PKCE verifier) is redeemed: drop it
        // explicitly BEFORE the permit, snapshot, persistence, and cleanup
        // awaits so the zeroizing code/verifier storage is wiped as early as
        // possible instead of lingering for the rest of the method. The drop
        // is structural — `AuthorizationGrant`'s fields are `Zeroizing`, and
        // nothing below this line borrows the grant.
        drop(grant);
        match outcome {
            TokenScopeOutcome::Granted(success) => {
                // The validated subject is the only safe store key. When the
                // verified identity does not fit the conservative subject
                // shape there is no key to snapshot or persist under, and no
                // grant-wide revoke is safe: the minted tokens are dropped
                // unexposed, unpersisted, and unrevoked.
                let Ok(subject) = ValidatedSubject::new(success.subject().as_str()) else {
                    return Err(BrokerError::IdentityUnverified);
                };
                // Claim the subject permit BEFORE any store read or write, so
                // a completion never overlaps a refresh, revoke, delete, or
                // another completion for the same account. A held permit
                // answers Busy; the grant minted here is NOT cleaned up on
                // that race because a same-subject operation shares this
                // provider grant and the in-flight mutation owns it. The
                // guard is RAII: it stays held across the snapshot, store,
                // and revoke work below and releases on cancellation.
                let _permit = self.permits.claim(subject.as_str())?;
                // Snapshot the stored credential BEFORE replacing it. Only a
                // definitive empty read licenses a best-effort provider
                // revoke on a later terminal: Google revocation is
                // grant-wide, so a prior credential could be the working
                // connection and must never be revoked over. An unreadable
                // store fails closed immediately: the minted tokens are
                // dropped unpersisted and unrevoked rather than stored over
                // or revoked over an unknown occupant.
                let snapshot = match self.store.load(&subject) {
                    Ok(None) => StoreSnapshot::Empty,
                    Ok(Some(_stored)) => StoreSnapshot::Occupied,
                    Err(_error) => return Err(BrokerError::PersistenceFailed),
                };
                if success
                    .identity_expiry()
                    .validate_fresh(self.wall_clock.unix_time(), IDENTITY_FRESHNESS_SKEW_SECS)
                    .is_err()
                {
                    self.revoke_stranded_grant(&snapshot, &success).await;
                    return Err(BrokerError::IdentityUnverified);
                }
                let token = match self.broker_token(&success) {
                    Ok(token) => token,
                    Err(error) => {
                        self.revoke_stranded_grant(&snapshot, &success).await;
                        return Err(error);
                    }
                };
                let Some(refresh_token) = success.rotated_refresh_token() else {
                    self.revoke_stranded_grant(&snapshot, &success).await;
                    return Err(BrokerError::MissingRefreshToken);
                };
                if refresh_token.is_empty() || refresh_token.len() > MAX_REFRESH_TOKEN_LEN {
                    self.revoke_stranded_grant(&snapshot, &success).await;
                    return Err(BrokerError::MalformedResponse);
                }
                // Persist BEFORE success: a reported success must survive a
                // restart, and a persistence failure must fail closed.
                if self.store.store(&subject, refresh_token).is_err() {
                    self.revoke_stranded_grant(&snapshot, &success).await;
                    return Err(BrokerError::PersistenceFailed);
                }
                Ok(token)
            }
            TokenScopeOutcome::InsufficientScope { .. } => {
                // Fail-safe and non-destructive (see the method
                // documentation): the under-scoped outcome has no validated
                // identity and begin supplies no account
                // identity, so no subject-keyed snapshot exists to gate a
                // revoke — and a grant-wide revoke could kill an unknown
                // prior working grant. Nothing is persisted and nothing is
                // revoked; a possibly stranded first-connect grant is left
                // for the caller to retain/retry or to direct the user
                // to Google's account-permissions page for manual
                // revocation (this API has no validated subject or stored
                // credential to revoke against).
                Err(BrokerError::InsufficientScope)
            }
        }
    }

    /// Refreshes the stored credential for a validated subject.
    ///
    /// Serialized per subject through a single-flight permit. A
    /// `invalid_grant` answer deletes the stored token (consent is gone);
    /// transport, provider, malformed-response, and identity failures retain
    /// it for a retry. A successful refresh re-validates the exact subject
    /// FIRST — an identity mismatch never persists anything, including a
    /// rotation — and then persists a well-formed rotated refresh token
    /// BEFORE the `id_token` freshness and success-minting gates, mirroring
    /// the under-scoped rationale: a later terminal (stale or future
    /// identity, malformed access token or expiry) must not strand the grant
    /// without a local revocation handle. An explicitly under-scoped refresh
    /// persists a rotation first, then reports the scope failure.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::InvalidInput`] for invalid subject text,
    /// [`BrokerError::Busy`] when the subject already has a mutation in
    /// flight, [`BrokerError::MissingRefreshToken`] when nothing is stored,
    /// [`BrokerError::ConsentRevoked`] after deleting the stored token,
    /// [`BrokerError::IdentityMismatch`] when the refresh re-validated to a
    /// different account, [`BrokerError::InsufficientScope`] after persisting
    /// any rotation, and the mapped persistence, transport, provider,
    /// malformed-response, or identity terminal otherwise.
    pub async fn refresh_access_token(
        &self,
        account_subject: &str,
    ) -> Result<BrokerToken, BrokerError> {
        let subject = ValidatedSubject::new(account_subject)?;
        let _permit = self.permits.claim(subject.as_str())?;
        let stored = self
            .store
            .load(&subject)
            .map_err(|_error| BrokerError::PersistenceFailed)?
            .ok_or(BrokerError::MissingRefreshToken)?;
        if stored.is_empty() || stored.len() > MAX_REFRESH_TOKEN_LEN {
            // A well-behaved store reports a malformed item as `Invalid`; a
            // slipped-through value is a store-integrity failure.
            return Err(BrokerError::PersistenceFailed);
        }
        let token_config = self.refresh_client_config()?;
        let outcome = match refresh_access_token_with_scope_outcome(
            &stored,
            &token_config,
            &self.transport,
            &self.clock,
        )
        .await
        {
            Ok(outcome) => outcome,
            Err(TokenError::ConsentRevoked) => {
                // ConsentRevoked ASSERTS the stored credential was deleted.
                // A delete failure must therefore fail closed as
                // PersistenceFailed — the `?` below intentionally withholds
                // the re-connect signal — rather than falsely claim a
                // deletion that was never confirmed.
                self.store
                    .delete(&subject)
                    .map_err(|_error| BrokerError::PersistenceFailed)?;
                return Err(BrokerError::ConsentRevoked);
            }
            Err(error) => return Err(map_token_error(error)),
        };
        match outcome {
            TokenScopeOutcome::Granted(success) => {
                if success.subject().as_str() != subject.as_str() {
                    // The credential no longer belongs to the requested
                    // account. Retain the stored token and drop the minted
                    // tokens without exposing them — an identity mismatch
                    // must NEVER persist anything, including a rotation.
                    return Err(BrokerError::IdentityMismatch);
                }
                // Persist a well-formed rotation for the MATCHED subject
                // BEFORE the freshness and success-minting gates, mirroring
                // the under-scoped rationale: a later terminal (a stale or
                // future `id_token`, a malformed access token or expiry)
                // must not strand the grant without a local revocation
                // handle. A malformed rotation is rejected BEFORE any store
                // write, and a store failure fails closed.
                if let Some(rotated) = success.rotated_refresh_token() {
                    if rotated.is_empty() || rotated.len() > MAX_REFRESH_TOKEN_LEN {
                        return Err(BrokerError::MalformedResponse);
                    }
                    self.store
                        .store(&subject, rotated)
                        .map_err(|_error| BrokerError::PersistenceFailed)?;
                }
                success
                    .identity_expiry()
                    .validate_fresh(self.wall_clock.unix_time(), IDENTITY_FRESHNESS_SKEW_SECS)
                    .map_err(|_error| BrokerError::IdentityUnverified)?;
                let token = self.broker_token(&success)?;
                Ok(token)
            }
            TokenScopeOutcome::InsufficientScope {
                rotated_refresh_token,
                ..
            } => {
                // Retain any rotated credential before surfacing the
                // permission error, so the grant keeps a local revocation
                // handle.
                if let Some(rotated) = rotated_refresh_token {
                    if rotated.is_empty() || rotated.len() > MAX_REFRESH_TOKEN_LEN {
                        return Err(BrokerError::MalformedResponse);
                    }
                    self.store
                        .store(&subject, &rotated)
                        .map_err(|_error| BrokerError::PersistenceFailed)?;
                }
                Err(BrokerError::InsufficientScope)
            }
        }
    }

    /// Revokes the subject's grant at the provider, keeping the local copy.
    ///
    /// Serialized per subject. A missing stored token succeeds: the desired
    /// end state (no usable grant known locally) already holds. A provider
    /// `invalid_grant` or `invalid_token` answer succeeds for the same
    /// reason — both mean the grant is already gone at the provider
    /// (`invalid_token` is Google's revoke-endpoint answer for an unknown or
    /// already-revoked token) — and is confirmed IMMEDIATELY with one call.
    /// Any other failure (transport, provider, or malformed response) is
    /// retried exactly once; the per-subject permit is
    /// held across both awaits and the stored credential is loaded only
    /// once. Two retryable failures map to [`BrokerError::RevokeUnconfirmed`]
    /// and the stored token is NEVER deleted here — ADR-0024's disconnect
    /// ordering runs broker revoke and broker token delete as separate
    /// steps, and an unconfirmed revoke must stay visible.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::InvalidInput`] for invalid subject text,
    /// [`BrokerError::Busy`] when the subject already has a mutation in
    /// flight, [`BrokerError::PersistenceFailed`] when the store rejects the
    /// read or the stored item is unusable, and
    /// [`BrokerError::RevokeUnconfirmed`] when the provider did not confirm
    /// the revocation on either the first attempt or the single retry.
    pub async fn revoke_provider_grant(&self, account_subject: &str) -> Result<(), BrokerError> {
        let subject = ValidatedSubject::new(account_subject)?;
        let _permit = self.permits.claim(subject.as_str())?;
        let stored = self
            .store
            .load(&subject)
            .map_err(|_error| BrokerError::PersistenceFailed)?;
        let Some(token) = stored else {
            return Ok(());
        };
        if token.is_empty() || token.len() > MAX_REFRESH_TOKEN_LEN {
            return Err(BrokerError::PersistenceFailed);
        }
        // `invalid_grant` and `invalid_token` both mean the grant is already
        // gone at the provider: the desired end state holds, so the revoke is
        // confirmed immediately, with no pointless retry. (`invalid_token` is
        // Google's observed revoke-endpoint answer for an unknown or
        // already-revoked token.) Any other failure is retried exactly once; two
        // retryable failures leave the revoke visibly unconfirmed.
        match self.transport.revoke(&token).await {
            Ok(()) | Err(TokenTransportError::InvalidGrant | TokenTransportError::InvalidToken) => {
                Ok(())
            }
            Err(_first) => match self.transport.revoke(&token).await {
                Ok(())
                | Err(TokenTransportError::InvalidGrant | TokenTransportError::InvalidToken) => {
                    Ok(())
                }
                Err(_second) => Err(BrokerError::RevokeUnconfirmed),
            },
        }
    }

    /// Deletes the subject's stored refresh token. Idempotent by store
    /// contract: deleting an absent subject succeeds.
    ///
    /// Serialized per subject through the same single-flight permit as the
    /// other mutations, so a delete never overlaps a refresh or revoke.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::InvalidInput`] for invalid subject text,
    /// [`BrokerError::Busy`] when the subject already has a mutation in
    /// flight, and [`BrokerError::PersistenceFailed`] when the store rejects
    /// the delete.
    pub fn delete_stored_tokens(&self, account_subject: &str) -> Result<(), BrokerError> {
        let subject = ValidatedSubject::new(account_subject)?;
        let _permit = self.permits.claim(subject.as_str())?;
        self.store
            .delete(&subject)
            .map_err(|_error| BrokerError::PersistenceFailed)
    }

    /// Builds the validated token client configuration for `redirect`.
    ///
    /// The client identifier and secret come from the broker's own validated
    /// configuration, so the token configuration always matches the
    /// authorization configuration by construction.
    fn token_client_config(&self, redirect: &Url) -> Result<TokenClientConfig, BrokerError> {
        TokenClientConfig::new(
            self.client_id.clone(),
            redirect.clone(),
            self.client_secret.clone(),
        )
        .map_err(|_error| BrokerError::InvalidConfiguration)
    }

    /// Builds the token client configuration for a refresh grant.
    ///
    /// A refresh request never transmits `redirect_uri` (its parameters are
    /// the grant type, refresh token, client identifier, and optional
    /// secret), so an inert literal loopback URL satisfies the
    /// validated-config invariant without persisting a redirect per account.
    fn refresh_client_config(&self) -> Result<TokenClientConfig, BrokerError> {
        let redirect =
            Url::parse("http://127.0.0.1/").map_err(|_error| BrokerError::InvalidConfiguration)?;
        self.token_client_config(&redirect)
    }

    /// Mints the public success value from a validated token success.
    ///
    /// Bounds the access token and computes the remaining lifetime from the
    /// same monotonic clock that minted the deadline, saturating rather than
    /// panicking or overflowing; a zero or out-of-bound lifetime is a
    /// malformed response.
    fn broker_token(&self, success: &TokenSuccess) -> Result<BrokerToken, BrokerError> {
        let access_token = success.access_token().secret().clone();
        if access_token.len() > MAX_ACCESS_TOKEN_LEN {
            return Err(BrokerError::MalformedResponse);
        }
        let remaining = success
            .access_token()
            .expires_at()
            .saturating_sub(self.clock.now());
        let expires_in_seconds = remaining.as_secs();
        if expires_in_seconds == 0 || expires_in_seconds > MAX_EXPIRES_IN_SECS {
            return Err(BrokerError::MalformedResponse);
        }
        Ok(BrokerToken {
            access_token,
            subject: Zeroizing::new(success.subject().as_str().to_owned()),
            expires_in_seconds,
        })
    }

    /// Revokes a minted token at the provider, ignoring the outcome.
    ///
    /// Used only on paths that persist nothing: a permanently failed revoke
    /// there leaves a live token at the provider, but the caller has no local
    /// handle and no better remedy, and the failure must never mask the real
    /// terminal being reported.
    async fn revoke_best_effort(&self, token: &Zeroizing<String>) {
        let _outcome = self.transport.revoke(token).await;
    }

    /// Runs the snapshot-conditional best-effort cleanup for a granted
    /// response whose attempt ended terminally after the subject snapshot.
    ///
    /// Only a definitively empty snapshot licenses the revoke: Google
    /// revocation is grant-wide, so with a prior stored credential it could
    /// kill the working connection (an unreadable store never reaches this
    /// helper — it fails the attempt closed first). The revoke handle is a
    /// well-shaped rotated refresh token when present, otherwise a
    /// well-shaped access token; a malformed token is never a revoke input.
    /// The outcome is ignored, so cleanup never masks the terminal being
    /// reported.
    async fn revoke_stranded_grant(&self, snapshot: &StoreSnapshot, success: &TokenSuccess) {
        if !snapshot.licenses_revoke() {
            return;
        }
        if let Some(handle) = revoke_handle(success) {
            self.revoke_best_effort(handle).await;
        }
    }
}

impl<T, S, C, W, E> fmt::Debug for BrokerCore<T, S, C, W, E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrokerCore")
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_secret| "[REDACTED]"),
            )
            .field("session_ttl", &self.session_ttl)
            .field("registry", &self.registry)
            .field("permits", &self.permits)
            // The transport, store, clocks, and entropy ports have no
            // safe-to-print state; mark them omitted rather than expose them.
            .finish_non_exhaustive()
    }
}

/// The pre-mutation read of a subject's stored credential, taken under the
/// subject permit before any terminal decision that might revoke at the
/// provider. A failed read never reaches this type: it fails the attempt
/// closed before any store write or provider revoke.
enum StoreSnapshot {
    /// The store definitively holds no credential for the subject.
    Empty,
    /// The store holds a credential for the subject.
    Occupied,
}

impl StoreSnapshot {
    /// Whether a best-effort provider revoke of a just-minted stranded grant
    /// is licensed: only a definitive empty read. Google revocation is
    /// grant-wide, so an existing credential must never be revoked over —
    /// it could be the working connection.
    fn licenses_revoke(&self) -> bool {
        matches!(self, Self::Empty)
    }
}

/// Picks the best-effort provider-revoke handle for a granted response whose
/// attempt is terminal: a well-shaped rotated refresh token when present
/// (it identifies the grant directly), otherwise a well-shaped access token.
///
/// A malformed, empty, or oversized token is never a revoke input; when
/// neither token is well-shaped there is no safe handle and no revoke runs.
fn revoke_handle(success: &TokenSuccess) -> Option<&Zeroizing<String>> {
    if let Some(rotated) = success.rotated_refresh_token()
        && !rotated.is_empty()
        && rotated.len() <= MAX_REFRESH_TOKEN_LEN
    {
        return Some(rotated);
    }
    let access_token = success.access_token().secret();
    if access_token.is_empty() || access_token.len() > MAX_ACCESS_TOKEN_LEN {
        return None;
    }
    Some(access_token)
}

/// Parses a redirect, accepting only the exact root-form literal IPv4
/// loopback with an explicit non-privileged port: `http://127.0.0.1:PORT/`
/// with `PORT` in `1024..=65535` and no credentials, query, or fragment.
fn parse_loopback_redirect(text: &str) -> Result<Url, BrokerError> {
    if text.len() > MAX_REDIRECT_LEN || !text.starts_with(LOOPBACK_REDIRECT_PREFIX) {
        return Err(BrokerError::InvalidInput);
    }
    let url = Url::parse(text).map_err(|_error| BrokerError::InvalidInput)?;
    // A parsed URL port is already a `u16`, so only the lower bound of the
    // non-privileged range needs a check; 65,535 is inherent.
    let non_privileged_port = url.port().is_some_and(|port| port >= MIN_LOOPBACK_PORT);
    let exact_root_loopback = url.scheme() == "http"
        && url.host_str() == Some("127.0.0.1")
        && non_privileged_port
        && url.path() == "/"
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none();
    if exact_root_loopback {
        Ok(url)
    } else {
        Err(BrokerError::InvalidInput)
    }
}

/// Maps the OAuth state-machine failures into the closed broker vocabulary.
///
/// Callback-shape failures (missing, duplicate, or conflicting parameters,
/// redirect and state mismatches) are caller-input failures. An expired or
/// already consumed session answers [`BrokerError::SessionUnknown`]: the
/// handle no longer names a live session, and that is all a caller may learn.
fn map_oauth_error(error: OAuthError) -> BrokerError {
    match error {
        OAuthError::InvalidConfiguration => BrokerError::InvalidConfiguration,
        OAuthError::ProviderRejected => BrokerError::ProviderRejected,
        OAuthError::InsufficientScope => BrokerError::InsufficientScope,
        OAuthError::Expired | OAuthError::AlreadyConsumed => BrokerError::SessionUnknown,
        OAuthError::MissingParameter(_)
        | OAuthError::DuplicateParameter
        | OAuthError::ConflictingCallback
        | OAuthError::RedirectMismatch
        | OAuthError::StateMismatch => BrokerError::InvalidInput,
        // `EntropyUnavailable`, `NotExpired` (which never escapes `finish`),
        // and any future variant fail closed as an internal failure.
        _ => BrokerError::Unavailable,
    }
}

/// Maps the token state-machine failures into the closed broker vocabulary.
///
/// The exchange-only [`TokenError::AuthorizationCodeRejected`] keeps its own
/// dedicated broker variant: the sign-in lapsed, nothing is stored on the
/// exchange path, and callers must be able to distinguish sign-in-expired
/// recovery (ADR-0024) — folding it into
/// [`BrokerError::ProviderRejected`] would make that input indistinguishable
/// at the broker surface.
fn map_token_error(error: TokenError) -> BrokerError {
    match error {
        TokenError::InvalidConfiguration => BrokerError::InvalidConfiguration,
        TokenError::Transport => BrokerError::Transport,
        TokenError::ProviderRejected => BrokerError::ProviderRejected,
        TokenError::AuthorizationCodeRejected => BrokerError::AuthorizationCodeRejected,
        TokenError::MalformedResponse => BrokerError::MalformedResponse,
        TokenError::InsufficientScope => BrokerError::InsufficientScope,
        TokenError::ConsentRevoked => BrokerError::ConsentRevoked,
        TokenError::IdentityUnverified => BrokerError::IdentityUnverified,
        // Any future variant fails closed as an internal failure.
        _ => BrokerError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "test fixtures use static URLs and assert setup success before behavior"
    )]

    use std::collections::{HashMap, VecDeque};
    use std::fmt;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll, Waker};
    use std::time::Duration;

    use tersa_application::mailbox::BoxFuture;
    use tersa_application::oauth::{MonotonicClock, WallClock};
    use tersa_application::token::{
        ExchangeRequest, IdTokenClaims, RefreshRequest, TokenResponse, TokenTransport,
        TokenTransportError,
    };
    use url::Url;
    use zeroize::Zeroizing;

    use super::{
        BrokerCore, BrokerToken, MAX_ACCESS_TOKEN_LEN, MAX_CALLBACK_LEN, MAX_EXPIRES_IN_SECS,
        MAX_REDIRECT_LEN, MAX_REFRESH_TOKEN_LEN, MAX_SESSION_TTL, PendingAuthorization,
    };
    use crate::error::BrokerError;
    use crate::handle::SESSION_HANDLE_BYTES;
    use crate::ports::{RefreshTokenStore, RefreshTokenStoreError, SessionHandleEntropy};
    use crate::registry::MAX_PENDING_SESSIONS;
    use crate::subject::ValidatedSubject;

    const CLIENT_ID: &str = "broker-test-client";
    const REDIRECT: &str = "http://127.0.0.1:8080/";
    const SUBJECT: &str = "110169484474386276334";
    const OTHER_SUBJECT: &str = "210169484474386276335";
    const NOW: u64 = 1_700_000_000;

    // Sentinel VALUES shaped like real provider secrets (see the error-vocabulary
    // tests): any occurrence of one in a rendered `Debug` proves a live leak.
    // They are held in `Zeroizing<String>` whenever they flow through the
    // broker, transport, or store surfaces.
    const ACCESS_TOKEN: &str = "ya29.sentinel-access-token";
    const REFRESH_TOKEN: &str = "1//sentinel-refresh-token";
    const ROTATED_REFRESH_TOKEN: &str = "1//sentinel-rotated-refresh-token";
    const AUTH_CODE: &str = "4/0AfJM-sentinel-authorization-code";
    const CLIENT_SECRET: &str = "GOCSPX-sentinel-client-secret";

    type TestBroker =
        BrokerCore<FakeTransport, FakeStore, TestClock, TestWallClock, CounterEntropy>;

    /// Drives an immediately-ready fake-port future to completion, matching the
    /// established no-runtime fake-transport driver.
    fn ready<T, F: Future<Output = T>>(future: F) -> T {
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        let mut future = Box::pin(future);
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("the fake-driven broker future must be immediately ready"),
        }
    }

    /// A deterministic, cloneable monotonic clock counting whole seconds.
    #[derive(Clone, Debug, Default)]
    struct TestClock(Arc<AtomicU64>);

    impl TestClock {
        fn advance(&self, seconds: u64) {
            self.0.fetch_add(seconds, Ordering::Relaxed);
        }
    }

    impl MonotonicClock for TestClock {
        fn now(&self) -> Duration {
            Duration::from_secs(self.0.load(Ordering::Relaxed))
        }
    }

    /// A deterministic wall clock pinned to one Unix second.
    #[derive(Clone, Debug)]
    struct TestWallClock(u64);

    impl WallClock for TestWallClock {
        fn unix_time(&self) -> u64 {
            self.0
        }
    }

    /// Mints distinct handle bytes on every call, deterministically.
    #[derive(Debug, Default)]
    struct CounterEntropy(AtomicU64);

    impl SessionHandleEntropy for CounterEntropy {
        fn handle_bytes(&self) -> Result<[u8; SESSION_HANDLE_BYTES], BrokerError> {
            let counter = self.0.fetch_add(1, Ordering::Relaxed);
            let mut bytes = [0_u8; SESSION_HANDLE_BYTES];
            bytes[..8].copy_from_slice(&counter.to_be_bytes());
            Ok(bytes)
        }
    }

    /// A switchable entropy source: fails while its flag is set, then mints
    /// distinct handles like `CounterEntropy`, so a test can fail one begin
    /// and then recover on the SAME broker.
    #[derive(Clone, Debug, Default)]
    struct SwitchableEntropy {
        fail: Arc<AtomicBool>,
        counter: Arc<AtomicU64>,
    }

    impl SwitchableEntropy {
        fn failing() -> Self {
            Self {
                fail: Arc::new(AtomicBool::new(true)),
                ..Self::default()
            }
        }
    }

    impl SessionHandleEntropy for SwitchableEntropy {
        fn handle_bytes(&self) -> Result<[u8; SESSION_HANDLE_BYTES], BrokerError> {
            if self.fail.load(Ordering::Relaxed) {
                return Err(BrokerError::Unavailable);
            }
            let counter = self.counter.fetch_add(1, Ordering::Relaxed);
            let mut bytes = [0_u8; SESSION_HANDLE_BYTES];
            bytes[..8].copy_from_slice(&counter.to_be_bytes());
            Ok(bytes)
        }
    }

    /// One recorded cross-port call, in call order, for event-ordering
    /// assertions. Carries the subject (account-identifying test data, never a
    /// secret) only where the port is subject-keyed.
    #[derive(Clone, Debug, Eq, PartialEq)]
    enum Event {
        Exchange,
        Refresh,
        Revoke,
        Store(String),
        Load(String),
        Delete(String),
    }

    type SharedEvents = Arc<Mutex<Vec<Event>>>;

    fn events() -> SharedEvents {
        SharedEvents::default()
    }

    /// Fully validated Google identity claims for `subject`, valid across
    /// `[issued_at, expires_at]`.
    fn claims_for(subject: &str, issued_at: u64, expires_at: u64) -> IdTokenClaims {
        IdTokenClaims::new(
            Zeroizing::new(subject.to_owned()),
            vec![CLIENT_ID.to_owned()],
            "https://accounts.google.com".to_owned(),
            None,
            issued_at,
            expires_at,
        )
    }

    /// Fully validated Google identity claims fresh at `NOW`.
    fn valid_claims() -> IdTokenClaims {
        claims_for(SUBJECT, NOW - 10, NOW + 3_600)
    }

    /// A scripted token transport: every exchange or refresh resolves
    /// immediately with one reusable fully-shaped response unless a scripted
    /// exchange or refresh failure or a pending gate is installed, records
    /// its observed exchange requests and revoke handles, and appends to the
    /// shared event log. Its `Debug` redacts every secret it holds or
    /// observes.
    #[derive(Clone)]
    struct FakeTransport {
        events: SharedEvents,
        recorded: Arc<Mutex<Vec<ExchangeRequest>>>,
        revoked: Arc<Mutex<Vec<String>>>,
        access_token: Zeroizing<String>,
        expires_in: Duration,
        rotated_refresh_token: Option<Zeroizing<String>>,
        id_token_claims: Option<IdTokenClaims>,
        gmail_read_granted: bool,
        revoke_error: Option<TokenTransportError>,
        revoke_script: Arc<Mutex<VecDeque<Result<(), TokenTransportError>>>>,
        refresh_error: Option<TokenTransportError>,
        exchange_error: Option<TokenTransportError>,
        refresh_gate: Option<Arc<AtomicBool>>,
        revoke_gate: Option<Arc<AtomicBool>>,
    }

    impl FakeTransport {
        fn success(events: &SharedEvents, rotated_refresh_token: Option<&str>) -> Self {
            Self {
                events: Arc::clone(events),
                recorded: Arc::new(Mutex::new(Vec::new())),
                revoked: Arc::new(Mutex::new(Vec::new())),
                access_token: Zeroizing::new(ACCESS_TOKEN.to_owned()),
                expires_in: Duration::from_secs(3_600),
                rotated_refresh_token: rotated_refresh_token
                    .map(|token| Zeroizing::new(token.to_owned())),
                id_token_claims: Some(valid_claims()),
                gmail_read_granted: true,
                revoke_error: None,
                revoke_script: Arc::new(Mutex::new(VecDeque::new())),
                refresh_error: None,
                exchange_error: None,
                refresh_gate: None,
                revoke_gate: None,
            }
        }

        fn with_claims(mut self, claims: Option<IdTokenClaims>) -> Self {
            self.id_token_claims = claims;
            self
        }

        fn without_gmail_read(mut self) -> Self {
            self.gmail_read_granted = false;
            self
        }

        fn with_revoke_error(mut self, error: TokenTransportError) -> Self {
            self.revoke_error = Some(error);
            self
        }

        /// Scripts the exact revoke outcomes returned in call order. Once the
        /// script is exhausted, `revoke_error` (or success) applies again.
        fn with_revoke_script(mut self, outcomes: &[Result<(), TokenTransportError>]) -> Self {
            self.revoke_script = Arc::new(Mutex::new(outcomes.iter().copied().collect()));
            self
        }

        fn with_refresh_error(mut self, error: TokenTransportError) -> Self {
            self.refresh_error = Some(error);
            self
        }

        fn with_exchange_error(mut self, error: TokenTransportError) -> Self {
            self.exchange_error = Some(error);
            self
        }

        /// Holds every refresh response pending until `gate` opens, so a test
        /// can park a broker future across a real `.await` with no runtime.
        fn with_gated_refresh(mut self, gate: &Arc<AtomicBool>) -> Self {
            self.refresh_gate = Some(Arc::clone(gate));
            self
        }

        /// Holds every revoke response pending until `gate` opens, so a test
        /// can park a broker future inside its best-effort cleanup.
        fn with_gated_revoke(mut self, gate: &Arc<AtomicBool>) -> Self {
            self.revoke_gate = Some(Arc::clone(gate));
            self
        }

        /// Returns the recorded revoke handle texts, in call order.
        fn revoked_handles(&self) -> Vec<String> {
            self.revoked.lock().unwrap().clone()
        }

        fn with_access_token_and_expiry(
            mut self,
            access_token: &str,
            expires_in: Duration,
        ) -> Self {
            self.access_token = Zeroizing::new(access_token.to_owned());
            self.expires_in = expires_in;
            self
        }

        fn response(&self) -> TokenResponse {
            TokenResponse::new(
                self.access_token.clone(),
                self.expires_in,
                self.rotated_refresh_token.clone(),
                self.id_token_claims.clone(),
                self.gmail_read_granted,
            )
        }
    }

    impl fmt::Debug for FakeTransport {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("FakeTransport")
                .field("access_token", &"[REDACTED]")
                .field("expires_in", &self.expires_in)
                .field(
                    "rotated_refresh_token",
                    &self
                        .rotated_refresh_token
                        .as_ref()
                        .map(|_token| "[REDACTED]"),
                )
                .field("id_token_claims", &self.id_token_claims)
                .field("gmail_read_granted", &self.gmail_read_granted)
                .field("revoke_error", &self.revoke_error)
                .field("refresh_error", &self.refresh_error)
                .field("exchange_error", &self.exchange_error)
                .field("refresh_gated", &self.refresh_gate.is_some())
                .field("revoke_gated", &self.revoke_gate.is_some())
                .field(
                    "revoked_count",
                    &self.revoked.lock().map_or(0, |revoked| revoked.len()),
                )
                .field("recorded", &self.recorded)
                .finish_non_exhaustive()
        }
    }

    impl TokenTransport for FakeTransport {
        fn exchange(
            &self,
            request: ExchangeRequest,
        ) -> BoxFuture<'_, Result<TokenResponse, TokenTransportError>> {
            Box::pin(async move {
                self.events.lock().unwrap().push(Event::Exchange);
                self.recorded.lock().unwrap().push(request);
                if let Some(error) = self.exchange_error {
                    return Err(error);
                }
                Ok(self.response())
            })
        }

        fn refresh(
            &self,
            _request: RefreshRequest,
        ) -> BoxFuture<'_, Result<TokenResponse, TokenTransportError>> {
            Box::pin(async move {
                if let Some(gate) = &self.refresh_gate {
                    std::future::poll_fn(|_context| {
                        if gate.load(Ordering::Relaxed) {
                            Poll::Ready(())
                        } else {
                            Poll::Pending
                        }
                    })
                    .await;
                }
                self.events.lock().unwrap().push(Event::Refresh);
                if let Some(error) = self.refresh_error {
                    return Err(error);
                }
                Ok(self.response())
            })
        }

        fn revoke<'a>(
            &'a self,
            token: &'a Zeroizing<String>,
        ) -> BoxFuture<'a, Result<(), TokenTransportError>> {
            Box::pin(async move {
                if let Some(gate) = &self.revoke_gate {
                    std::future::poll_fn(|_context| {
                        if gate.load(Ordering::Relaxed) {
                            Poll::Ready(())
                        } else {
                            Poll::Pending
                        }
                    })
                    .await;
                }
                self.revoked.lock().unwrap().push(token.as_str().to_owned());
                self.events.lock().unwrap().push(Event::Revoke);
                self.revoke_script
                    .lock()
                    .unwrap()
                    .pop_front()
                    .unwrap_or_else(|| self.revoke_error.map_or(Ok(()), Err))
            })
        }
    }

    /// An in-memory refresh-token store with scripted per-operation failures,
    /// sharing the event log so persistence ordering against the transport is
    /// assertable. Its `Debug` never prints a stored token.
    #[derive(Clone)]
    struct FakeStore {
        events: SharedEvents,
        tokens: Arc<Mutex<HashMap<String, Zeroizing<String>>>>,
        store_error: Option<RefreshTokenStoreError>,
        load_error: Option<RefreshTokenStoreError>,
        delete_error: Option<RefreshTokenStoreError>,
    }

    impl FakeStore {
        fn new(events: &SharedEvents) -> Self {
            Self {
                events: Arc::clone(events),
                tokens: Arc::new(Mutex::new(HashMap::new())),
                store_error: None,
                load_error: None,
                delete_error: None,
            }
        }

        fn failing_store(events: &SharedEvents) -> Self {
            Self {
                store_error: Some(RefreshTokenStoreError::Unavailable),
                ..Self::new(events)
            }
        }

        fn failing_load(events: &SharedEvents) -> Self {
            Self {
                load_error: Some(RefreshTokenStoreError::Unavailable),
                ..Self::new(events)
            }
        }

        fn failing_delete(events: &SharedEvents) -> Self {
            Self {
                delete_error: Some(RefreshTokenStoreError::Unavailable),
                ..Self::new(events)
            }
        }

        /// Preloads a stored credential as fixture setup, bypassing the store
        /// port so the event log records only broker-driven operations.
        fn with_stored_token(self, subject: &str, token: &str) -> Self {
            self.tokens
                .lock()
                .unwrap()
                .insert(subject.to_owned(), Zeroizing::new(token.to_owned()));
            self
        }

        fn stored_token(&self, subject: &str) -> Option<String> {
            self.tokens
                .lock()
                .unwrap()
                .get(subject)
                .map(|token| token.as_str().to_owned())
        }

        fn is_empty(&self) -> bool {
            self.tokens.lock().unwrap().is_empty()
        }
    }

    impl fmt::Debug for FakeStore {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("FakeStore")
                .field("store_error", &self.store_error)
                .field("load_error", &self.load_error)
                .field("delete_error", &self.delete_error)
                .field(
                    "stored_subjects",
                    &self.tokens.lock().map_or(0, |tokens| tokens.len()),
                )
                .finish_non_exhaustive()
        }
    }

    impl RefreshTokenStore for FakeStore {
        fn store(
            &self,
            subject: &ValidatedSubject,
            token: &Zeroizing<String>,
        ) -> Result<(), RefreshTokenStoreError> {
            self.events
                .lock()
                .unwrap()
                .push(Event::Store(subject.as_str().to_owned()));
            if let Some(error) = self.store_error {
                return Err(error);
            }
            self.tokens
                .lock()
                .unwrap()
                .insert(subject.as_str().to_owned(), token.clone());
            Ok(())
        }

        fn load(
            &self,
            subject: &ValidatedSubject,
        ) -> Result<Option<Zeroizing<String>>, RefreshTokenStoreError> {
            self.events
                .lock()
                .unwrap()
                .push(Event::Load(subject.as_str().to_owned()));
            if let Some(error) = self.load_error {
                return Err(error);
            }
            Ok(self.tokens.lock().unwrap().get(subject.as_str()).cloned())
        }

        fn delete(&self, subject: &ValidatedSubject) -> Result<(), RefreshTokenStoreError> {
            self.events
                .lock()
                .unwrap()
                .push(Event::Delete(subject.as_str().to_owned()));
            if let Some(error) = self.delete_error {
                return Err(error);
            }
            self.tokens.lock().unwrap().remove(subject.as_str());
            Ok(())
        }
    }

    fn make_broker(
        transport: &FakeTransport,
        store: &FakeStore,
        client_secret: Option<&str>,
    ) -> TestBroker {
        BrokerCore::new(
            CLIENT_ID.to_owned(),
            client_secret.map(|secret| Zeroizing::new(secret.to_owned())),
            Duration::from_secs(600),
            (
                transport.clone(),
                store.clone(),
                TestClock::default(),
                TestWallClock(NOW),
                CounterEntropy::default(),
            ),
        )
        .unwrap()
    }

    fn query_value(url: &Url, name: &str) -> String {
        url.query_pairs()
            .find_map(|(key, value)| (key == name).then(|| value.into_owned()))
            .unwrap()
    }

    /// Builds the exact loopback callback Google would return for `pending`.
    fn callback_for(pending: &PendingAuthorization, code: &str) -> Url {
        let state = query_value(pending.authorization_url(), "state");
        let mut callback = Url::parse(REDIRECT).unwrap();
        callback
            .query_pairs_mut()
            .append_pair("state", &state)
            .append_pair("code", code);
        callback
    }

    /// Runs one full begin→callback→exchange lifecycle against the fakes.
    fn run_authorization(
        transport: &FakeTransport,
        store: &FakeStore,
    ) -> Result<BrokerToken, BrokerError> {
        let broker = make_broker(transport, store, None);
        let pending = broker.begin_authorization(REDIRECT).unwrap();
        let callback = callback_for(&pending, AUTH_CODE);
        ready(broker.complete_authorization(pending.session_handle(), callback.as_str()))
    }

    #[test]
    fn constructor_rejects_invalid_client_configuration() {
        let shared = events();
        let valid_ttl = Duration::from_secs(600);
        let make = |client_id: &str, client_secret: Option<Zeroizing<String>>, ttl: Duration| {
            BrokerCore::new(
                client_id.to_owned(),
                client_secret,
                ttl,
                (
                    FakeTransport::success(&shared, None),
                    FakeStore::new(&shared),
                    TestClock::default(),
                    TestWallClock(NOW),
                    CounterEntropy::default(),
                ),
            )
        };
        for blank_id in ["", "   "] {
            assert!(matches!(
                make(blank_id, None, valid_ttl),
                Err(BrokerError::InvalidConfiguration)
            ));
        }
        assert!(matches!(
            make(CLIENT_ID, Some(Zeroizing::new("   ".to_owned())), valid_ttl),
            Err(BrokerError::InvalidConfiguration)
        ));
        assert!(matches!(
            make(CLIENT_ID, None, Duration::ZERO),
            Err(BrokerError::InvalidConfiguration)
        ));
        assert!(matches!(
            make(CLIENT_ID, None, MAX_SESSION_TTL + Duration::from_secs(1)),
            Err(BrokerError::InvalidConfiguration)
        ));
        // The exact TTL bound and a present non-blank secret are accepted.
        assert!(make(CLIENT_ID, None, MAX_SESSION_TTL).is_ok());
        assert!(
            make(
                CLIENT_ID,
                Some(Zeroizing::new(CLIENT_SECRET.to_owned())),
                valid_ttl,
            )
            .is_ok()
        );
    }

    #[test]
    fn begin_accepts_only_the_exact_loopback_root_redirect() {
        let shared = events();
        let broker = make_broker(
            &FakeTransport::success(&shared, None),
            &FakeStore::new(&shared),
            None,
        );
        for accepted in [
            "http://127.0.0.1:1024/",
            "http://127.0.0.1:8080/",
            "http://127.0.0.1:65535/",
        ] {
            assert!(
                broker.begin_authorization(accepted).is_ok(),
                "must accept {accepted}"
            );
        }
        let mut oversized = REDIRECT.to_owned();
        oversized.push_str(&"A".repeat(MAX_REDIRECT_LEN));
        for rejected in [
            "http://127.0.0.1/",              // no explicit port
            "http://127.0.0.1:1023/",         // below the non-privileged range
            "http://localhost:8080/",         // named loopback
            "http://[::1]:8080/",             // IPv6 loopback
            "http://127.1:8080/",             // noncanonical IPv4
            "http://127.0.0.01:8080/",        // alternate spelling
            "HTTP://127.0.0.1:8080/",         // uppercase scheme
            "https://127.0.0.1:8080/",        // TLS scheme
            "http://127.0.0.1:8080/callback", // non-root path
            "http://user@127.0.0.1:8080/",    // credentials
            "http://user:pass@127.0.0.1:8080/",
            "http://127.0.0.1:8080/?a=b",      // query
            "http://127.0.0.1:8080/#fragment", // fragment
            oversized.as_str(),
        ] {
            assert!(
                matches!(
                    broker.begin_authorization(rejected),
                    Err(BrokerError::InvalidInput)
                ),
                "must reject {rejected}"
            );
        }
    }

    #[test]
    fn pending_authorization_debug_redacts_url_state_challenge_and_handle() {
        let shared = events();
        let broker = make_broker(
            &FakeTransport::success(&shared, None),
            &FakeStore::new(&shared),
            None,
        );
        let pending = broker.begin_authorization(REDIRECT).unwrap();
        let url = pending.authorization_url();
        let state = query_value(url, "state");
        let challenge = query_value(url, "code_challenge");
        let debug = format!("{pending:?}");
        assert!(debug.contains("[REDACTED]"));
        for sensitive in [
            url.as_str(),
            state.as_str(),
            challenge.as_str(),
            pending.session_handle(),
        ] {
            assert!(
                !debug.contains(sensitive),
                "PendingAuthorization Debug leaks {sensitive}: {debug}"
            );
        }
    }

    #[test]
    fn successful_authorization_persists_the_refresh_token_before_reporting_success() {
        let shared = events();
        let transport = FakeTransport::success(&shared, Some(REFRESH_TOKEN));
        let store = FakeStore::new(&shared);
        let broker = make_broker(&transport, &store, Some(CLIENT_SECRET));
        let pending = broker.begin_authorization(REDIRECT).unwrap();
        let challenge = query_value(pending.authorization_url(), "code_challenge");
        let callback = callback_for(&pending, AUTH_CODE);
        let token =
            ready(broker.complete_authorization(pending.session_handle(), callback.as_str()))
                .unwrap();

        assert_eq!(token.access_token().as_str(), ACCESS_TOKEN);
        assert_eq!(token.subject(), SUBJECT);
        assert_eq!(token.expires_in_seconds(), 3_600);
        assert!((1..=MAX_EXPIRES_IN_SECS).contains(&token.expires_in_seconds()));

        // The exchange ran before the subject snapshot, the snapshot before
        // the store write, and the store write completed before the success
        // could be observed.
        assert_eq!(
            *shared.lock().unwrap(),
            vec![
                Event::Exchange,
                Event::Load(SUBJECT.to_owned()),
                Event::Store(SUBJECT.to_owned()),
            ]
        );
        assert_eq!(store.stored_token(SUBJECT).as_deref(), Some(REFRESH_TOKEN));

        // The public success value redacts both the token and the subject.
        let debug = format!("{token:?}");
        assert!(debug.contains("[REDACTED]"));
        for sensitive in [ACCESS_TOKEN, SUBJECT, REFRESH_TOKEN] {
            assert!(
                !debug.contains(sensitive),
                "BrokerToken Debug leaks {sensitive}: {debug}"
            );
        }

        // The transport observed the exact exchange shape: the callback code,
        // the session's PKCE verifier, the exact redirect, and the client
        // identity, with the configured secret last.
        let recorded = transport.recorded.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        let parameters = recorded[0].parameters();
        drop(recorded);
        let pairs: Vec<(&str, &str)> = parameters
            .iter()
            .map(|(name, value)| (*name, value.as_str()))
            .collect();
        assert_eq!(pairs.len(), 6);
        assert_eq!(pairs[0], ("grant_type", "authorization_code"));
        assert_eq!(pairs[1], ("code", AUTH_CODE));
        assert_eq!(pairs[3], ("client_id", CLIENT_ID));
        assert_eq!(pairs[4], ("redirect_uri", REDIRECT));
        assert_eq!(pairs[5], ("client_secret", CLIENT_SECRET));
        assert_eq!(pairs[2].0, "code_verifier");
        let verifier = pairs[2].1;
        assert_eq!(verifier.len(), 43);
        assert!(
            verifier
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        );
        // The verifier is the session's secret, distinct from the public
        // challenge derived from it.
        assert_ne!(verifier, challenge);

        // The fake itself never renders a secret through Debug.
        let transport_debug = format!("{transport:?}");
        for sensitive in [
            ACCESS_TOKEN,
            REFRESH_TOKEN,
            AUTH_CODE,
            CLIENT_SECRET,
            verifier,
        ] {
            assert!(
                !transport_debug.contains(sensitive),
                "FakeTransport Debug leaks {sensitive}: {transport_debug}"
            );
        }
    }

    #[test]
    fn a_successful_reconnect_over_an_occupied_snapshot_replaces_the_credential_without_a_revoke() {
        // Ordinary reconnect: a credential is already stored for the
        // subject. The snapshot reads Occupied, the freshly minted rotation
        // is persisted over it BEFORE the success is reported, and no
        // cleanup revoke ever runs — Google revocation is grant-wide, so the
        // prior credential's grant must never be revoked over.
        let shared = events();
        let transport = FakeTransport::success(&shared, Some(ROTATED_REFRESH_TOKEN));
        let store = FakeStore::new(&shared).with_stored_token(SUBJECT, REFRESH_TOKEN);
        let token = run_authorization(&transport, &store).unwrap();
        assert_eq!(token.access_token().as_str(), ACCESS_TOKEN);
        assert_eq!(token.subject(), SUBJECT);
        // The exchange ran before the snapshot read, the read before the
        // replacement write — and no Revoke appears anywhere.
        assert_eq!(
            *shared.lock().unwrap(),
            vec![
                Event::Exchange,
                Event::Load(SUBJECT.to_owned()),
                Event::Store(SUBJECT.to_owned()),
            ]
        );
        assert!(transport.revoked_handles().is_empty());
        assert_eq!(
            store.stored_token(SUBJECT).as_deref(),
            Some(ROTATED_REFRESH_TOKEN)
        );
        // The success value still redacts the token and the subject.
        let debug = format!("{token:?}");
        for sensitive in [ACCESS_TOKEN, SUBJECT, ROTATED_REFRESH_TOKEN] {
            assert!(
                !debug.contains(sensitive),
                "BrokerToken Debug leaks {sensitive}: {debug}"
            );
        }
    }

    #[test]
    fn every_callback_attempt_consumes_the_session() {
        let shared = events();
        let broker = make_broker(
            &FakeTransport::success(&shared, Some(REFRESH_TOKEN)),
            &FakeStore::new(&shared),
            None,
        );

        // An unparsable callback consumes the session; a replay of the same
        // handle with the otherwise valid callback meets SessionUnknown.
        let pending = broker.begin_authorization(REDIRECT).unwrap();
        let handle = pending.session_handle().to_owned();
        let valid_callback = callback_for(&pending, AUTH_CODE);
        assert!(matches!(
            ready(broker.complete_authorization(&handle, "not a url")),
            Err(BrokerError::InvalidInput)
        ));
        assert!(matches!(
            ready(broker.complete_authorization(&handle, valid_callback.as_str())),
            Err(BrokerError::SessionUnknown)
        ));

        // A wrong-state callback consumes the session too.
        let pending = broker.begin_authorization(REDIRECT).unwrap();
        let handle = pending.session_handle().to_owned();
        let valid_callback = callback_for(&pending, AUTH_CODE);
        let wrong_state = format!("{REDIRECT}?state=wrong-state&code={AUTH_CODE}");
        assert!(matches!(
            ready(broker.complete_authorization(&handle, &wrong_state)),
            Err(BrokerError::InvalidInput)
        ));
        assert!(matches!(
            ready(broker.complete_authorization(&handle, valid_callback.as_str())),
            Err(BrokerError::SessionUnknown)
        ));

        // An oversized callback consumes the session before it is even parsed.
        let pending = broker.begin_authorization(REDIRECT).unwrap();
        let handle = pending.session_handle().to_owned();
        let valid_callback = callback_for(&pending, AUTH_CODE);
        let state = query_value(pending.authorization_url(), "state");
        let padding = "A".repeat(MAX_CALLBACK_LEN);
        let oversized = format!("{REDIRECT}?state={state}&code={padding}");
        assert!(matches!(
            ready(broker.complete_authorization(&handle, &oversized)),
            Err(BrokerError::InvalidInput)
        ));
        assert!(matches!(
            ready(broker.complete_authorization(&handle, valid_callback.as_str())),
            Err(BrokerError::SessionUnknown)
        ));

        // No malformed attempt ever reached the transport.
        assert!(shared.lock().unwrap().is_empty());
    }

    #[test]
    fn a_provider_denied_callback_maps_through_map_oauth_error_without_exchange_store_or_revoke() {
        // The user denied consent at the provider: the callback carries an
        // `error` parameter and no code. The state machine answers
        // OAuthError::ProviderRejected, which map_oauth_error maps to
        // BrokerError::ProviderRejected — distinct from the exchange-time
        // AuthorizationCodeRejected (the provider never saw a code). The
        // denial is terminal BEFORE any exchange, store access, or revoke,
        // and the session is consumed.
        let shared = events();
        let transport = FakeTransport::success(&shared, Some(REFRESH_TOKEN));
        let store = FakeStore::new(&shared).with_stored_token(SUBJECT, REFRESH_TOKEN);
        let broker = make_broker(&transport, &store, None);
        let pending = broker.begin_authorization(REDIRECT).unwrap();
        let handle = pending.session_handle().to_owned();
        let state = query_value(pending.authorization_url(), "state");
        let mut callback = Url::parse(REDIRECT).unwrap();
        callback
            .query_pairs_mut()
            .append_pair("state", &state)
            .append_pair("error", "access_denied");
        let result = ready(broker.complete_authorization(&handle, callback.as_str()));
        assert!(
            matches!(result, Err(BrokerError::ProviderRejected)),
            "a provider denial must be ProviderRejected: {result:?}"
        );
        // No exchange, no store read or write, no revoke; the prior stored
        // credential is retained untouched.
        assert!(shared.lock().unwrap().is_empty());
        assert!(transport.revoked_handles().is_empty());
        assert_eq!(store.stored_token(SUBJECT).as_deref(), Some(REFRESH_TOKEN));
        // Terminal and one-shot: a replay meets SessionUnknown.
        assert!(matches!(
            ready(broker.complete_authorization(&handle, callback.as_str())),
            Err(BrokerError::SessionUnknown)
        ));
        assert!(shared.lock().unwrap().is_empty());
    }

    #[test]
    fn an_under_scoped_callback_maps_through_map_oauth_error_without_exchange_store_or_revoke() {
        // The callback grants a code but its `scope` omits Gmail read
        // access: the state machine answers OAuthError::InsufficientScope,
        // which map_oauth_error maps to BrokerError::InsufficientScope —
        // BEFORE any exchange runs, so nothing is stored or revoked.
        let shared = events();
        let transport = FakeTransport::success(&shared, Some(REFRESH_TOKEN));
        let store = FakeStore::new(&shared).with_stored_token(SUBJECT, REFRESH_TOKEN);
        let broker = make_broker(&transport, &store, None);
        let pending = broker.begin_authorization(REDIRECT).unwrap();
        let handle = pending.session_handle().to_owned();
        let state = query_value(pending.authorization_url(), "state");
        let mut callback = Url::parse(REDIRECT).unwrap();
        callback
            .query_pairs_mut()
            .append_pair("state", &state)
            .append_pair("code", AUTH_CODE)
            .append_pair("scope", "openid email profile");
        let result = ready(broker.complete_authorization(&handle, callback.as_str()));
        assert!(
            matches!(result, Err(BrokerError::InsufficientScope)),
            "an under-scoped callback must be InsufficientScope: {result:?}"
        );
        // No exchange, no store read or write, no revoke; the prior stored
        // credential is retained untouched.
        assert!(shared.lock().unwrap().is_empty());
        assert!(transport.revoked_handles().is_empty());
        assert_eq!(store.stored_token(SUBJECT).as_deref(), Some(REFRESH_TOKEN));
        // Terminal and one-shot: a replay meets SessionUnknown.
        assert!(matches!(
            ready(broker.complete_authorization(&handle, callback.as_str())),
            Err(BrokerError::SessionUnknown)
        ));
        assert!(shared.lock().unwrap().is_empty());
    }

    #[test]
    fn a_claimed_but_expired_session_is_session_unknown_terminal_and_side_effect_free() {
        // The handle names a live session, but the session's deadline
        // elapsed before its callback arrived: `finish` answers Expired,
        // which map_oauth_error folds into SessionUnknown — all a caller may
        // learn. No exchange, store access, or revoke ever runs.
        let shared = events();
        let transport = FakeTransport::success(&shared, Some(REFRESH_TOKEN));
        let store = FakeStore::new(&shared);
        let clock = TestClock::default();
        let broker = BrokerCore::new(
            CLIENT_ID.to_owned(),
            None,
            Duration::from_secs(600),
            (
                transport.clone(),
                store.clone(),
                clock.clone(),
                TestWallClock(NOW),
                CounterEntropy::default(),
            ),
        )
        .unwrap();
        let pending = broker.begin_authorization(REDIRECT).unwrap();
        let handle = pending.session_handle().to_owned();
        let callback = callback_for(&pending, AUTH_CODE);
        clock.advance(601);
        let result = ready(broker.complete_authorization(&handle, callback.as_str()));
        assert!(
            matches!(result, Err(BrokerError::SessionUnknown)),
            "an expired session must be SessionUnknown: {result:?}"
        );
        assert!(shared.lock().unwrap().is_empty());
        assert!(transport.revoked_handles().is_empty());
        assert!(store.is_empty());
        // Terminal and one-shot: the claim already consumed the session, so
        // a replay meets the same SessionUnknown.
        assert!(matches!(
            ready(broker.complete_authorization(&handle, callback.as_str())),
            Err(BrokerError::SessionUnknown)
        ));
        assert!(shared.lock().unwrap().is_empty());
    }

    #[test]
    fn begin_authorization_at_capacity_is_busy_without_evicting_a_live_session() {
        // The public begin path enforces the bounded registry: with
        // MAX_PENDING_SESSIONS live sessions pending, the next begin answers
        // Busy and evicts nothing — every issued handle still completes.
        let shared = events();
        let transport = FakeTransport::success(&shared, Some(REFRESH_TOKEN));
        let store = FakeStore::new(&shared);
        let broker = make_broker(&transport, &store, None);
        let mut pending_sessions = Vec::new();
        for _ in 0..MAX_PENDING_SESSIONS {
            pending_sessions.push(broker.begin_authorization(REDIRECT).unwrap());
        }
        assert!(matches!(
            broker.begin_authorization(REDIRECT),
            Err(BrokerError::Busy)
        ));
        assert!(shared.lock().unwrap().is_empty());

        // No live session was evicted to make room: the first issued handle
        // still completes its full lifecycle.
        let first = pending_sessions.first().unwrap();
        let callback = callback_for(first, AUTH_CODE);
        let token = ready(broker.complete_authorization(first.session_handle(), callback.as_str()))
            .unwrap();
        assert_eq!(token.subject(), SUBJECT);
        assert_eq!(
            *shared.lock().unwrap(),
            vec![
                Event::Exchange,
                Event::Load(SUBJECT.to_owned()),
                Event::Store(SUBJECT.to_owned()),
            ]
        );
    }

    #[test]
    fn an_entropy_failure_at_begin_fails_closed_without_allocating_a_session() {
        // The entropy port fails: begin fails closed as Unavailable BEFORE a
        // session is allocated, with no transport, store, or registry side
        // effect and nothing sensitive in the rendered failure.
        let shared = events();
        let entropy = SwitchableEntropy::failing();
        let broker = BrokerCore::new(
            CLIENT_ID.to_owned(),
            None,
            Duration::from_secs(600),
            (
                FakeTransport::success(&shared, Some(REFRESH_TOKEN)),
                FakeStore::new(&shared),
                TestClock::default(),
                TestWallClock(NOW),
                entropy.clone(),
            ),
        )
        .unwrap();
        let result = broker.begin_authorization(REDIRECT);
        assert!(
            matches!(result, Err(BrokerError::Unavailable)),
            "an entropy failure must fail closed as Unavailable: {result:?}"
        );
        let rendered = format!("{result:?}");
        for sensitive in [REDIRECT, CLIENT_ID] {
            assert!(
                !rendered.contains(sensitive),
                "the begin failure leaks {sensitive}: {rendered}"
            );
        }
        assert!(shared.lock().unwrap().is_empty());
        // The entropy failure preceded insertion inside `registry.insert`, so
        // no session was allocated: the registry is still empty.
        assert!(
            format!("{broker:?}").contains("pending: 0"),
            "an entropy failure must leave the registry empty: {broker:?}"
        );

        // Once entropy recovers, a healthy begin on the SAME broker works and
        // its handle completes the full lifecycle.
        entropy.fail.store(false, Ordering::Relaxed);
        let pending = broker.begin_authorization(REDIRECT).unwrap();
        let callback = callback_for(&pending, AUTH_CODE);
        let token =
            ready(broker.complete_authorization(pending.session_handle(), callback.as_str()))
                .unwrap();
        assert_eq!(token.subject(), SUBJECT);
        assert_eq!(
            *shared.lock().unwrap(),
            vec![
                Event::Exchange,
                Event::Load(SUBJECT.to_owned()),
                Event::Store(SUBJECT.to_owned()),
            ]
        );
    }

    #[test]
    fn a_malformed_session_handle_is_rejected_before_any_registry_or_port_side_effect() {
        // A malformed handle fails shape validation BEFORE the registry is
        // touched: no claim runs, so a live session is never consumed by a
        // malformed attempt, and no transport, store, or revoke follows.
        let shared = events();
        let transport = FakeTransport::success(&shared, Some(REFRESH_TOKEN));
        let store = FakeStore::new(&shared);
        let broker = make_broker(&transport, &store, None);
        let pending = broker.begin_authorization(REDIRECT).unwrap();
        // The minted shape is 22 URL-safe base64 characters: wrong length or
        // wrong charset is malformed.
        let wrong_length = "A".repeat(23);
        let mut wrong_charset = pending.session_handle().to_owned();
        wrong_charset.replace_range(..1, "+");
        for malformed in ["", "short", wrong_length.as_str(), wrong_charset.as_str()] {
            assert!(
                matches!(
                    ready(broker.complete_authorization(malformed, REDIRECT)),
                    Err(BrokerError::InvalidInput)
                ),
                "a malformed handle must fail closed as InvalidInput: {malformed:?}"
            );
        }
        // No registry claim, transport call, store access, or revoke ran —
        // and the live session the malformed attempts never named is still
        // completable.
        assert!(shared.lock().unwrap().is_empty());
        assert!(transport.revoked_handles().is_empty());
        let callback = callback_for(&pending, AUTH_CODE);
        let token =
            ready(broker.complete_authorization(pending.session_handle(), callback.as_str()))
                .unwrap();
        assert_eq!(token.subject(), SUBJECT);
    }

    #[test]
    fn a_well_formed_unknown_session_handle_is_session_unknown_without_side_effects() {
        // The handle has the exact minted shape but names no live session:
        // SessionUnknown, with no transport, store, or revoke side effect,
        // and the same terminal answer on every attempt.
        let shared = events();
        let transport = FakeTransport::success(&shared, Some(REFRESH_TOKEN));
        let store = FakeStore::new(&shared).with_stored_token(SUBJECT, REFRESH_TOKEN);
        let broker = make_broker(&transport, &store, None);
        // 22 URL-safe base64 characters — the exact minted handle shape.
        let unknown = "A".repeat(22);
        for attempt in 0..2 {
            let result = ready(broker.complete_authorization(&unknown, REDIRECT));
            assert!(
                matches!(result, Err(BrokerError::SessionUnknown)),
                "attempt {attempt}: an unknown handle must be SessionUnknown: {result:?}"
            );
        }
        // No claim ever matched, so nothing ran: no exchange, no load, no
        // store, no revoke, and the stored credential is retained untouched.
        assert!(shared.lock().unwrap().is_empty());
        assert!(transport.revoked_handles().is_empty());
        assert_eq!(store.stored_token(SUBJECT).as_deref(), Some(REFRESH_TOKEN));
    }

    #[test]
    fn an_exchange_without_a_refresh_token_is_terminal_and_revokes_best_effort() {
        let shared = events();
        // The best-effort revoke may itself fail; the terminal must not change.
        let transport =
            FakeTransport::success(&shared, None).with_revoke_error(TokenTransportError::Transport);
        let store = FakeStore::new(&shared);
        let result = run_authorization(&transport, &store);
        assert!(matches!(result, Err(BrokerError::MissingRefreshToken)));
        // The store snapshot was definitively empty, so the stranded grant
        // was revoked best-effort after the snapshot read.
        assert_eq!(
            *shared.lock().unwrap(),
            vec![
                Event::Exchange,
                Event::Load(SUBJECT.to_owned()),
                Event::Revoke,
            ]
        );
        assert_eq!(transport.revoked_handles(), vec![ACCESS_TOKEN.to_owned()]);
        assert!(store.is_empty());
    }

    #[test]
    fn an_explicitly_under_scoped_completion_is_terminal_and_non_destructive() {
        // The under-scoped outcome has no validated identity by design and
        // begin supplies no account identity, so no
        // subject-keyed snapshot exists and no grant-wide revoke is safe:
        // the pinned fail-safe contract persists nothing and revokes
        // nothing. Any stranded first-connect grant is left for the caller
        // to retain/retry or to direct the user to Google's
        // account-permissions page — this API has no validated subject or
        // stored credential to revoke it against.
        let shared = events();
        let transport = FakeTransport::success(&shared, Some(REFRESH_TOKEN)).without_gmail_read();
        let store = FakeStore::new(&shared);
        let result = run_authorization(&transport, &store);
        assert!(matches!(result, Err(BrokerError::InsufficientScope)));
        // The exchange ran; no store read or write and no revoke ever did.
        assert_eq!(*shared.lock().unwrap(), vec![Event::Exchange]);
        assert!(transport.revoked_handles().is_empty());
        assert!(store.is_empty());

        // The contract is identical over a stored credential: no store read,
        // no revoke, and the stored credential is retained untouched — the
        // completion can never destroy an unknown prior working grant.
        let shared = events();
        let transport =
            FakeTransport::success(&shared, Some(ROTATED_REFRESH_TOKEN)).without_gmail_read();
        let store = FakeStore::new(&shared).with_stored_token(SUBJECT, REFRESH_TOKEN);
        let result = run_authorization(&transport, &store);
        assert!(matches!(result, Err(BrokerError::InsufficientScope)));
        assert_eq!(*shared.lock().unwrap(), vec![Event::Exchange]);
        assert!(transport.revoked_handles().is_empty());
        assert_eq!(store.stored_token(SUBJECT).as_deref(), Some(REFRESH_TOKEN));
    }

    #[test]
    fn an_exchange_failure_maps_to_its_terminal_without_store_or_revoke_side_effects() {
        // Every exchange failure is terminal BEFORE a subject exists: the
        // only observable event is the Exchange itself — no Load, no Store,
        // no Revoke — and a prior stored credential is retained untouched.
        for (error, expected) in [
            (TokenTransportError::Transport, BrokerError::Transport),
            (
                TokenTransportError::MalformedResponse,
                BrokerError::MalformedResponse,
            ),
            (
                TokenTransportError::ProviderRejected,
                BrokerError::ProviderRejected,
            ),
            // An exchange-time invalid_grant is a stale or used authorization
            // code: the token layer keeps it distinct as
            // `TokenError::AuthorizationCodeRejected`, and the broker preserves
            // that distinction so callers can offer sign-in-expired recovery
            // — NEVER ConsentRevoked, which claims
            // a stored credential was deleted (none exists on this path), and
            // never folded into the ordinary ProviderRejected.
            (
                TokenTransportError::InvalidGrant,
                BrokerError::AuthorizationCodeRejected,
            ),
        ] {
            let shared = events();
            let transport =
                FakeTransport::success(&shared, Some(REFRESH_TOKEN)).with_exchange_error(error);
            let store = FakeStore::new(&shared).with_stored_token(SUBJECT, REFRESH_TOKEN);
            let result = run_authorization(&transport, &store);
            let Err(actual) = &result else {
                panic!("expected an exchange failure for {error:?}, got {result:?}");
            };
            assert_eq!(*actual, expected, "mapping for {error:?}");
            assert_ne!(
                *actual,
                BrokerError::ConsentRevoked,
                "an exchange failure must never claim a credential deletion: {error:?}"
            );
            // No Load, Store, or Revoke side effects: the only observable
            // event is the Exchange, and the prior credential is untouched.
            assert_eq!(*shared.lock().unwrap(), vec![Event::Exchange]);
            assert!(transport.revoked_handles().is_empty());
            assert_eq!(store.stored_token(SUBJECT).as_deref(), Some(REFRESH_TOKEN));
        }
    }

    #[test]
    fn a_completion_rejects_a_subject_the_store_shape_rejects_without_side_effects() {
        // The token layer accepts any nonempty trimmed subject of at most 255
        // bytes, but the broker keys storage on the conservative visible-ASCII
        // ValidatedSubject shape. A subject the application validated yet the
        // store shape rejects (an inner space, non-ASCII text) fails as
        // IdentityUnverified BEFORE the permit, any store load or write, or
        // any revoke: no key is fabricated and nothing is persisted.
        for subject in ["has space", "unicode-ø-subject"] {
            let shared = events();
            let transport = FakeTransport::success(&shared, Some(REFRESH_TOKEN))
                .with_claims(Some(claims_for(subject, NOW - 10, NOW + 3_600)));
            let store = FakeStore::new(&shared);
            let result = run_authorization(&transport, &store);
            assert!(
                matches!(result, Err(BrokerError::IdentityUnverified)),
                "a store-shape-rejected subject must be IdentityUnverified: {result:?}"
            );
            assert_eq!(*shared.lock().unwrap(), vec![Event::Exchange]);
            assert!(transport.revoked_handles().is_empty());
            assert!(store.is_empty());
        }
    }

    #[test]
    fn a_missing_refresh_over_a_prior_stored_credential_never_revokes() {
        // The exchange granted no refresh token, but a credential is already
        // stored for the subject: a grant-wide revoke could kill the working
        // connection, so the minted access token is dropped without revoke.
        let shared = events();
        let transport = FakeTransport::success(&shared, None);
        let store = FakeStore::new(&shared).with_stored_token(SUBJECT, REFRESH_TOKEN);
        let result = run_authorization(&transport, &store);
        assert!(matches!(result, Err(BrokerError::MissingRefreshToken)));
        assert_eq!(
            *shared.lock().unwrap(),
            vec![Event::Exchange, Event::Load(SUBJECT.to_owned())]
        );
        assert!(transport.revoked_handles().is_empty());
        assert_eq!(store.stored_token(SUBJECT).as_deref(), Some(REFRESH_TOKEN));
    }

    #[test]
    fn an_unverifiable_identity_has_no_subject_snapshot_and_revokes_nothing() {
        // A missing or rejected id_token fails inside the token layer BEFORE
        // a TokenSuccess exists: there is no validated subject, hence no
        // store key, no snapshot, and no revoke handle the broker may use.
        let wrong_audience = IdTokenClaims::new(
            Zeroizing::new(SUBJECT.to_owned()),
            vec!["another-client".to_owned()],
            "https://accounts.google.com".to_owned(),
            None,
            NOW - 10,
            NOW + 3_600,
        );
        for claims in [None, Some(wrong_audience)] {
            let shared = events();
            let transport =
                FakeTransport::success(&shared, Some(REFRESH_TOKEN)).with_claims(claims);
            let store = FakeStore::new(&shared);
            let result = run_authorization(&transport, &store);
            assert!(
                matches!(result, Err(BrokerError::IdentityUnverified)),
                "identity failure must be IdentityUnverified: {result:?}"
            );
            // No token is exposed, nothing is persisted or read, and the
            // identity failure path performs no revoke.
            assert_eq!(*shared.lock().unwrap(), vec![Event::Exchange]);
            assert!(store.is_empty());
        }
    }

    #[test]
    fn a_stale_or_future_identity_revokes_only_over_a_definitive_empty_snapshot() {
        // The token layer verified the identity (so a subject exists) but the
        // broker's wall-clock freshness check fails: the snapshot rule
        // decides the cleanup.
        let stale = claims_for(SUBJECT, NOW - 7_200, NOW - 3_600);
        let future = claims_for(SUBJECT, NOW + 3_600, NOW + 7_200);
        for claims in [stale, future] {
            // A definitive empty snapshot licenses the best-effort revoke of
            // the stranded grant; the rotated refresh token is the preferred
            // handle.
            let shared = events();
            let transport = FakeTransport::success(&shared, Some(REFRESH_TOKEN))
                .with_claims(Some(claims.clone()));
            let store = FakeStore::new(&shared);
            let result = run_authorization(&transport, &store);
            assert!(
                matches!(result, Err(BrokerError::IdentityUnverified)),
                "freshness failure must be IdentityUnverified: {result:?}"
            );
            assert_eq!(
                *shared.lock().unwrap(),
                vec![
                    Event::Exchange,
                    Event::Load(SUBJECT.to_owned()),
                    Event::Revoke,
                ]
            );
            assert_eq!(transport.revoked_handles(), vec![REFRESH_TOKEN.to_owned()]);
            assert!(store.is_empty());

            // A prior stored credential must never be revoked over: Google
            // revocation is grant-wide and could kill the working
            // connection. The credential is retained untouched.
            let shared = events();
            let transport = FakeTransport::success(&shared, Some(ROTATED_REFRESH_TOKEN))
                .with_claims(Some(claims));
            let store = FakeStore::new(&shared).with_stored_token(SUBJECT, REFRESH_TOKEN);
            let result = run_authorization(&transport, &store);
            assert!(
                matches!(result, Err(BrokerError::IdentityUnverified)),
                "freshness failure must be IdentityUnverified: {result:?}"
            );
            assert_eq!(
                *shared.lock().unwrap(),
                vec![Event::Exchange, Event::Load(SUBJECT.to_owned())]
            );
            assert!(transport.revoked_handles().is_empty());
            assert_eq!(store.stored_token(SUBJECT).as_deref(), Some(REFRESH_TOKEN));
        }
    }

    #[test]
    fn the_identity_freshness_skew_matches_the_legacy_120_second_boundary() {
        // Preserve the established 120-second skew (see
        // IDENTITY_FRESHNESS_SKEW_SECS): one second inside the expiry boundary
        // is fresh; exactly on it is stale. Future-issued claims at the skew
        // boundary remain accepted by the existing validation contract.
        for claims in [
            claims_for(SUBJECT, NOW - 3_720, NOW - 119), // exp one second inside the skew
            claims_for(SUBJECT, NOW + 120, NOW + 7_200), // iat exactly at the future skew
        ] {
            let shared = events();
            let transport =
                FakeTransport::success(&shared, Some(REFRESH_TOKEN)).with_claims(Some(claims));
            let store = FakeStore::new(&shared);
            let token = run_authorization(&transport, &store).unwrap();
            assert_eq!(token.subject(), SUBJECT);
            assert_eq!(
                *shared.lock().unwrap(),
                vec![
                    Event::Exchange,
                    Event::Load(SUBJECT.to_owned()),
                    Event::Store(SUBJECT.to_owned()),
                ]
            );
        }
        for claims in [
            claims_for(SUBJECT, NOW - 3_720, NOW - 120), // exp exactly at the skew: stale
            claims_for(SUBJECT, NOW + 121, NOW + 7_200), /* iat one second past the future
                                                          * skew */
        ] {
            let shared = events();
            let transport =
                FakeTransport::success(&shared, Some(REFRESH_TOKEN)).with_claims(Some(claims));
            let store = FakeStore::new(&shared);
            let result = run_authorization(&transport, &store);
            assert!(
                matches!(result, Err(BrokerError::IdentityUnverified)),
                "an identity on or past the skew boundary must be IdentityUnverified: {result:?}"
            );
            // The definitive empty snapshot licensed the cleanup revoke.
            assert_eq!(
                *shared.lock().unwrap(),
                vec![
                    Event::Exchange,
                    Event::Load(SUBJECT.to_owned()),
                    Event::Revoke,
                ]
            );
            assert!(store.is_empty());
        }
    }

    #[test]
    fn a_store_write_failure_fails_closed_and_revokes_only_over_a_definitive_empty_snapshot() {
        // Definitive empty snapshot: the grant would be stranded live at the
        // provider with no local handle, so it is revoked best-effort. The
        // rotated refresh token is the preferred revoke handle, and the
        // terminal stays PersistenceFailed even when the revoke fails.
        let shared = events();
        let transport = FakeTransport::success(&shared, Some(REFRESH_TOKEN))
            .with_revoke_error(TokenTransportError::Transport);
        let store = FakeStore::failing_store(&shared);
        let result = run_authorization(&transport, &store);
        assert!(matches!(result, Err(BrokerError::PersistenceFailed)));
        assert_eq!(
            *shared.lock().unwrap(),
            vec![
                Event::Exchange,
                Event::Load(SUBJECT.to_owned()),
                Event::Store(SUBJECT.to_owned()),
                Event::Revoke,
            ]
        );
        assert_eq!(transport.revoked_handles(), vec![REFRESH_TOKEN.to_owned()]);
        assert!(store.is_empty());

        // A prior stored credential must never be revoked over: Google
        // revocation is grant-wide and could kill the working connection.
        let shared = events();
        let transport = FakeTransport::success(&shared, Some(ROTATED_REFRESH_TOKEN));
        let store = FakeStore::failing_store(&shared).with_stored_token(SUBJECT, REFRESH_TOKEN);
        let result = run_authorization(&transport, &store);
        assert!(matches!(result, Err(BrokerError::PersistenceFailed)));
        assert_eq!(
            *shared.lock().unwrap(),
            vec![
                Event::Exchange,
                Event::Load(SUBJECT.to_owned()),
                Event::Store(SUBJECT.to_owned()),
            ]
        );
        assert!(transport.revoked_handles().is_empty());
        assert_eq!(store.stored_token(SUBJECT).as_deref(), Some(REFRESH_TOKEN));
    }

    #[test]
    fn an_unreadable_store_snapshot_fails_closed_without_storing_or_revoking() {
        // The snapshot read fails after the subject permit is claimed: the
        // attempt fails closed immediately as PersistenceFailed, BEFORE any
        // freshness check, store write, or revoke. The minted tokens are
        // dropped unpersisted and unrevoked, and the unknown — potentially
        // working — stored credential is never stored over or grant-wide
        // revoked over.
        let shared = events();
        let transport = FakeTransport::success(&shared, Some(ROTATED_REFRESH_TOKEN));
        let store = FakeStore::failing_load(&shared).with_stored_token(SUBJECT, REFRESH_TOKEN);
        let result = run_authorization(&transport, &store);
        assert!(matches!(result, Err(BrokerError::PersistenceFailed)));
        // The exchange and the failed snapshot read ran; nothing else did.
        assert_eq!(
            *shared.lock().unwrap(),
            vec![Event::Exchange, Event::Load(SUBJECT.to_owned())]
        );
        assert!(transport.revoked_handles().is_empty());
        assert_eq!(store.stored_token(SUBJECT).as_deref(), Some(REFRESH_TOKEN));
    }

    #[test]
    fn out_of_bound_access_tokens_and_expiries_are_malformed_responses() {
        let oversized_token = format!("{ACCESS_TOKEN}{}", "A".repeat(MAX_ACCESS_TOKEN_LEN));
        let cases = [
            // The oversized access token is never a revoke input: the
            // well-shaped rotated refresh token is the handle.
            (oversized_token, Duration::from_secs(3_600), REFRESH_TOKEN),
            // An out-of-bound expiry leaves the access token well-shaped, but
            // the valid rotated refresh token is still the preferred handle.
            (ACCESS_TOKEN.to_owned(), Duration::ZERO, REFRESH_TOKEN),
            (
                ACCESS_TOKEN.to_owned(),
                Duration::from_secs(MAX_EXPIRES_IN_SECS + 1),
                REFRESH_TOKEN,
            ),
        ];
        for (access_token, expires_in, expected_handle) in cases {
            let shared = events();
            let transport = FakeTransport::success(&shared, Some(REFRESH_TOKEN))
                .with_access_token_and_expiry(&access_token, expires_in);
            let store = FakeStore::new(&shared);
            let result = run_authorization(&transport, &store);
            assert!(
                matches!(result, Err(BrokerError::MalformedResponse)),
                "out-of-bound provider outcome must be MalformedResponse: {result:?}"
            );
            // The definitive empty snapshot licensed the cleanup revoke.
            assert_eq!(
                *shared.lock().unwrap(),
                vec![
                    Event::Exchange,
                    Event::Load(SUBJECT.to_owned()),
                    Event::Revoke,
                ]
            );
            assert_eq!(
                transport.revoked_handles(),
                vec![expected_handle.to_owned()]
            );
            assert!(store.is_empty());
        }
    }

    #[test]
    fn a_malformed_rotated_refresh_is_never_a_persistence_or_revoke_input() {
        let oversized = format!("1//{}", "A".repeat(MAX_REFRESH_TOKEN_LEN));
        for rotated in ["", oversized.as_str()] {
            let shared = events();
            let transport = FakeTransport::success(&shared, Some(rotated));
            let store = FakeStore::new(&shared);
            let result = run_authorization(&transport, &store);
            assert!(
                matches!(result, Err(BrokerError::MalformedResponse)),
                "invalid rotation must be MalformedResponse: {result:?}"
            );
            // The definitive empty snapshot licensed the cleanup revoke, but
            // the handle is the well-shaped access token — never the
            // malformed rotated refresh token.
            assert_eq!(
                *shared.lock().unwrap(),
                vec![
                    Event::Exchange,
                    Event::Load(SUBJECT.to_owned()),
                    Event::Revoke,
                ]
            );
            assert_eq!(transport.revoked_handles(), vec![ACCESS_TOKEN.to_owned()]);
            assert!(store.is_empty());
        }
    }

    #[test]
    fn refresh_without_a_stored_token_never_contacts_the_transport() {
        let shared = events();
        let transport = FakeTransport::success(&shared, None);
        let store = FakeStore::new(&shared);
        let broker = make_broker(&transport, &store, None);
        assert!(matches!(
            ready(broker.refresh_access_token(SUBJECT)),
            Err(BrokerError::MissingRefreshToken)
        ));
        // The load ran; no refresh, store, or delete ever did.
        assert_eq!(
            *shared.lock().unwrap(),
            vec![Event::Load(SUBJECT.to_owned())]
        );
    }

    #[test]
    fn a_successful_refresh_without_rotation_retains_the_stored_token() {
        let shared = events();
        let transport = FakeTransport::success(&shared, None);
        let store = FakeStore::new(&shared).with_stored_token(SUBJECT, REFRESH_TOKEN);
        let broker = make_broker(&transport, &store, None);
        let token = ready(broker.refresh_access_token(SUBJECT)).unwrap();
        assert_eq!(token.access_token().as_str(), ACCESS_TOKEN);
        assert_eq!(token.subject(), SUBJECT);
        assert_eq!(token.expires_in_seconds(), 3_600);
        // No store write at all: the original credential stays exactly as
        // stored, and the success was minted only after the exact subject and
        // the id_token freshness validated (see the mismatch and staleness
        // cases below for the negative gate).
        assert_eq!(
            *shared.lock().unwrap(),
            vec![Event::Load(SUBJECT.to_owned()), Event::Refresh]
        );
        assert_eq!(store.stored_token(SUBJECT).as_deref(), Some(REFRESH_TOKEN));
    }

    #[test]
    fn a_successful_refresh_with_rotation_persists_the_new_token_before_reporting_success() {
        let shared = events();
        let transport = FakeTransport::success(&shared, Some(ROTATED_REFRESH_TOKEN));
        let store = FakeStore::new(&shared).with_stored_token(SUBJECT, REFRESH_TOKEN);
        let broker = make_broker(&transport, &store, None);
        let token = ready(broker.refresh_access_token(SUBJECT)).unwrap();
        assert_eq!(token.access_token().as_str(), ACCESS_TOKEN);
        // The rotation was persisted after the provider answer and BEFORE the
        // success could be observed.
        assert_eq!(
            *shared.lock().unwrap(),
            vec![
                Event::Load(SUBJECT.to_owned()),
                Event::Refresh,
                Event::Store(SUBJECT.to_owned()),
            ]
        );
        assert_eq!(
            store.stored_token(SUBJECT).as_deref(),
            Some(ROTATED_REFRESH_TOKEN)
        );
    }

    #[test]
    fn consent_revoked_deletes_the_stored_credential_and_a_delete_failure_fails_closed() {
        // An invalid_grant answer means consent is gone: the stored
        // credential is deleted before ConsentRevoked is reported.
        let shared = events();
        let transport = FakeTransport::success(&shared, None)
            .with_refresh_error(TokenTransportError::InvalidGrant);
        let store = FakeStore::new(&shared).with_stored_token(SUBJECT, REFRESH_TOKEN);
        let broker = make_broker(&transport, &store, None);
        assert!(matches!(
            ready(broker.refresh_access_token(SUBJECT)),
            Err(BrokerError::ConsentRevoked)
        ));
        assert_eq!(
            *shared.lock().unwrap(),
            vec![
                Event::Load(SUBJECT.to_owned()),
                Event::Refresh,
                Event::Delete(SUBJECT.to_owned()),
            ]
        );
        assert!(store.is_empty());

        // When the delete itself fails the broker fails closed as
        // PersistenceFailed: ConsentRevoked asserts the deletion happened,
        // so the re-connect signal is intentionally withheld, never falsely
        // reported.
        let shared = events();
        let transport = FakeTransport::success(&shared, None)
            .with_refresh_error(TokenTransportError::InvalidGrant);
        let store = FakeStore::failing_delete(&shared).with_stored_token(SUBJECT, REFRESH_TOKEN);
        let broker = make_broker(&transport, &store, None);
        assert!(matches!(
            ready(broker.refresh_access_token(SUBJECT)),
            Err(BrokerError::PersistenceFailed)
        ));
        assert_eq!(
            *shared.lock().unwrap(),
            vec![
                Event::Load(SUBJECT.to_owned()),
                Event::Refresh,
                Event::Delete(SUBJECT.to_owned()),
            ]
        );
        assert_eq!(store.stored_token(SUBJECT).as_deref(), Some(REFRESH_TOKEN));
    }

    #[test]
    fn failed_or_identity_unverified_refreshes_retain_the_stored_token() {
        // Transport, provider, and malformed-response failures are retryable:
        // the stored credential stays and no rotation is persisted.
        for (error, expected) in [
            (TokenTransportError::Transport, BrokerError::Transport),
            (
                TokenTransportError::ProviderRejected,
                BrokerError::ProviderRejected,
            ),
            (
                TokenTransportError::MalformedResponse,
                BrokerError::MalformedResponse,
            ),
        ] {
            let shared = events();
            let transport = FakeTransport::success(&shared, Some(ROTATED_REFRESH_TOKEN))
                .with_refresh_error(error);
            let store = FakeStore::new(&shared).with_stored_token(SUBJECT, REFRESH_TOKEN);
            let broker = make_broker(&transport, &store, None);
            let result = ready(broker.refresh_access_token(SUBJECT));
            assert_eq!(result.err(), Some(expected));
            assert_eq!(
                *shared.lock().unwrap(),
                vec![Event::Load(SUBJECT.to_owned()), Event::Refresh]
            );
            assert_eq!(store.stored_token(SUBJECT).as_deref(), Some(REFRESH_TOKEN));
        }

        // A missing id_token fails in the token layer BEFORE a TokenSuccess
        // exists, so there is no rotation to persist: the stored credential
        // is retained for a retry. (A stale or future id_token behaves
        // differently — the subject matched, so the rotation IS persisted
        // before the freshness gate; see the next test.)
        let shared = events();
        let transport =
            FakeTransport::success(&shared, Some(ROTATED_REFRESH_TOKEN)).with_claims(None);
        let store = FakeStore::new(&shared).with_stored_token(SUBJECT, REFRESH_TOKEN);
        let broker = make_broker(&transport, &store, None);
        let result = ready(broker.refresh_access_token(SUBJECT));
        assert_eq!(result.err(), Some(BrokerError::IdentityUnverified));
        assert_eq!(
            *shared.lock().unwrap(),
            vec![Event::Load(SUBJECT.to_owned()), Event::Refresh]
        );
        assert_eq!(store.stored_token(SUBJECT).as_deref(), Some(REFRESH_TOKEN));
    }

    #[test]
    fn a_granted_refresh_persists_a_valid_rotation_before_the_later_gates() {
        // A stale or future id_token fails the wall-clock freshness gate, but
        // the subject already matched: the well-formed rotation is persisted
        // FIRST, so the grant keeps a local revocation handle across the
        // terminal.
        let stale = claims_for(SUBJECT, NOW - 7_200, NOW - 3_600);
        let future = claims_for(SUBJECT, NOW + 3_600, NOW + 7_200);
        for claims in [stale, future] {
            let shared = events();
            let transport = FakeTransport::success(&shared, Some(ROTATED_REFRESH_TOKEN))
                .with_claims(Some(claims));
            let store = FakeStore::new(&shared).with_stored_token(SUBJECT, REFRESH_TOKEN);
            let broker = make_broker(&transport, &store, None);
            let result = ready(broker.refresh_access_token(SUBJECT));
            assert_eq!(result.err(), Some(BrokerError::IdentityUnverified));
            assert_eq!(
                *shared.lock().unwrap(),
                vec![
                    Event::Load(SUBJECT.to_owned()),
                    Event::Refresh,
                    Event::Store(SUBJECT.to_owned()),
                ]
            );
            assert_eq!(
                store.stored_token(SUBJECT).as_deref(),
                Some(ROTATED_REFRESH_TOKEN)
            );
        }

        // A malformed access token or an out-of-bound expiry reports
        // MalformedResponse — again AFTER the rotation was retained.
        let oversized_token = format!("{ACCESS_TOKEN}{}", "A".repeat(MAX_ACCESS_TOKEN_LEN));
        for (access_token, expires_in) in [
            (oversized_token, Duration::from_secs(3_600)),
            (ACCESS_TOKEN.to_owned(), Duration::ZERO),
            (
                ACCESS_TOKEN.to_owned(),
                Duration::from_secs(MAX_EXPIRES_IN_SECS + 1),
            ),
        ] {
            let shared = events();
            let transport = FakeTransport::success(&shared, Some(ROTATED_REFRESH_TOKEN))
                .with_access_token_and_expiry(&access_token, expires_in);
            let store = FakeStore::new(&shared).with_stored_token(SUBJECT, REFRESH_TOKEN);
            let broker = make_broker(&transport, &store, None);
            let result = ready(broker.refresh_access_token(SUBJECT));
            assert!(
                matches!(result, Err(BrokerError::MalformedResponse)),
                "out-of-bound provider outcome must be MalformedResponse: {result:?}"
            );
            assert_eq!(
                *shared.lock().unwrap(),
                vec![
                    Event::Load(SUBJECT.to_owned()),
                    Event::Refresh,
                    Event::Store(SUBJECT.to_owned()),
                ]
            );
            assert_eq!(
                store.stored_token(SUBJECT).as_deref(),
                Some(ROTATED_REFRESH_TOKEN)
            );
        }
    }

    #[test]
    fn a_granted_refresh_rejects_a_malformed_rotation_before_any_store_write() {
        // An empty or oversized rotation on a Granted refresh is a malformed
        // response rejected BEFORE any store write: the original credential
        // is never replaced.
        let oversized = format!("1//{}", "A".repeat(MAX_REFRESH_TOKEN_LEN));
        for rotated in ["", oversized.as_str()] {
            let shared = events();
            let transport = FakeTransport::success(&shared, Some(rotated));
            let store = FakeStore::new(&shared).with_stored_token(SUBJECT, REFRESH_TOKEN);
            let broker = make_broker(&transport, &store, None);
            let result = ready(broker.refresh_access_token(SUBJECT));
            assert!(
                matches!(result, Err(BrokerError::MalformedResponse)),
                "invalid rotation must be MalformedResponse: {result:?}"
            );
            assert_eq!(
                *shared.lock().unwrap(),
                vec![Event::Load(SUBJECT.to_owned()), Event::Refresh]
            );
            assert_eq!(store.stored_token(SUBJECT).as_deref(), Some(REFRESH_TOKEN));
        }
    }

    #[test]
    fn a_granted_refresh_rotation_store_failure_fails_closed() {
        // The rotation is well-formed but the store rejects the write: the
        // refresh fails closed as PersistenceFailed and the original
        // credential stays exactly as stored.
        let shared = events();
        let transport = FakeTransport::success(&shared, Some(ROTATED_REFRESH_TOKEN));
        let store = FakeStore::failing_store(&shared).with_stored_token(SUBJECT, REFRESH_TOKEN);
        let broker = make_broker(&transport, &store, None);
        let result = ready(broker.refresh_access_token(SUBJECT));
        assert_eq!(result.err(), Some(BrokerError::PersistenceFailed));
        assert_eq!(
            *shared.lock().unwrap(),
            vec![
                Event::Load(SUBJECT.to_owned()),
                Event::Refresh,
                Event::Store(SUBJECT.to_owned()),
            ]
        );
        assert_eq!(store.stored_token(SUBJECT).as_deref(), Some(REFRESH_TOKEN));
    }

    #[test]
    fn a_refresh_validating_to_a_different_subject_is_an_identity_mismatch_that_retains_the_token()
    {
        let shared = events();
        let transport = FakeTransport::success(&shared, Some(ROTATED_REFRESH_TOKEN))
            .with_claims(Some(claims_for(OTHER_SUBJECT, NOW - 10, NOW + 3_600)));
        let store = FakeStore::new(&shared).with_stored_token(SUBJECT, REFRESH_TOKEN);
        let broker = make_broker(&transport, &store, None);
        let result = ready(broker.refresh_access_token(SUBJECT));
        assert_eq!(result.err(), Some(BrokerError::IdentityMismatch));
        // No rotation persisted, nothing deleted: the original stays stored.
        assert_eq!(
            *shared.lock().unwrap(),
            vec![Event::Load(SUBJECT.to_owned()), Event::Refresh]
        );
        assert_eq!(store.stored_token(SUBJECT).as_deref(), Some(REFRESH_TOKEN));
    }

    #[test]
    fn an_under_scoped_refresh_persists_a_valid_rotation_before_reporting_the_scope_failure() {
        // A valid rotation is retained BEFORE the permission error surfaces,
        // so the grant keeps a local revocation handle.
        let shared = events();
        let transport =
            FakeTransport::success(&shared, Some(ROTATED_REFRESH_TOKEN)).without_gmail_read();
        let store = FakeStore::new(&shared).with_stored_token(SUBJECT, REFRESH_TOKEN);
        let broker = make_broker(&transport, &store, None);
        let result = ready(broker.refresh_access_token(SUBJECT));
        assert_eq!(result.err(), Some(BrokerError::InsufficientScope));
        assert_eq!(
            *shared.lock().unwrap(),
            vec![
                Event::Load(SUBJECT.to_owned()),
                Event::Refresh,
                Event::Store(SUBJECT.to_owned()),
            ]
        );
        assert_eq!(
            store.stored_token(SUBJECT).as_deref(),
            Some(ROTATED_REFRESH_TOKEN)
        );

        // No rotation: the original credential stays exactly as stored.
        let shared = events();
        let transport = FakeTransport::success(&shared, None).without_gmail_read();
        let store = FakeStore::new(&shared).with_stored_token(SUBJECT, REFRESH_TOKEN);
        let broker = make_broker(&transport, &store, None);
        let result = ready(broker.refresh_access_token(SUBJECT));
        assert_eq!(result.err(), Some(BrokerError::InsufficientScope));
        assert_eq!(
            *shared.lock().unwrap(),
            vec![Event::Load(SUBJECT.to_owned()), Event::Refresh]
        );
        assert_eq!(store.stored_token(SUBJECT).as_deref(), Some(REFRESH_TOKEN));

        // An empty or oversized rotation is a malformed response, rejected
        // BEFORE any store write: the original is never replaced.
        let oversized = format!("1//{}", "A".repeat(MAX_REFRESH_TOKEN_LEN));
        for rotated in ["", oversized.as_str()] {
            let shared = events();
            let transport = FakeTransport::success(&shared, Some(rotated)).without_gmail_read();
            let store = FakeStore::new(&shared).with_stored_token(SUBJECT, REFRESH_TOKEN);
            let broker = make_broker(&transport, &store, None);
            let result = ready(broker.refresh_access_token(SUBJECT));
            assert!(
                matches!(result, Err(BrokerError::MalformedResponse)),
                "invalid rotation must be MalformedResponse: {result:?}"
            );
            assert_eq!(
                *shared.lock().unwrap(),
                vec![Event::Load(SUBJECT.to_owned()), Event::Refresh]
            );
            assert_eq!(store.stored_token(SUBJECT).as_deref(), Some(REFRESH_TOKEN));
        }
    }

    #[test]
    fn provider_revoke_and_local_delete_are_strictly_separate() {
        // No stored token: revoke succeeds without touching the network.
        let shared = events();
        let transport = FakeTransport::success(&shared, None);
        let store = FakeStore::new(&shared);
        let broker = make_broker(&transport, &store, None);
        assert!(ready(broker.revoke_provider_grant(SUBJECT)).is_ok());
        assert_eq!(
            *shared.lock().unwrap(),
            vec![Event::Load(SUBJECT.to_owned())]
        );

        // A confirmed revoke contacts the provider but retains the stored
        // token; only the explicit delete removes it, and delete is
        // idempotent.
        let shared = events();
        let transport = FakeTransport::success(&shared, None);
        let store = FakeStore::new(&shared).with_stored_token(SUBJECT, REFRESH_TOKEN);
        let broker = make_broker(&transport, &store, None);
        assert!(ready(broker.revoke_provider_grant(SUBJECT)).is_ok());
        assert_eq!(
            *shared.lock().unwrap(),
            vec![Event::Load(SUBJECT.to_owned()), Event::Revoke]
        );
        assert_eq!(store.stored_token(SUBJECT).as_deref(), Some(REFRESH_TOKEN));
        assert!(broker.delete_stored_tokens(SUBJECT).is_ok());
        assert!(store.stored_token(SUBJECT).is_none());
        assert!(broker.delete_stored_tokens(SUBJECT).is_ok());

        // A provider invalid_grant answer means the grant is already gone at
        // the provider: the revoke counts as confirmed, and the stored token
        // is still retained until the explicit delete.
        let shared = events();
        let transport = FakeTransport::success(&shared, None)
            .with_revoke_error(TokenTransportError::InvalidGrant);
        let store = FakeStore::new(&shared).with_stored_token(SUBJECT, REFRESH_TOKEN);
        let broker = make_broker(&transport, &store, None);
        assert!(ready(broker.revoke_provider_grant(SUBJECT)).is_ok());
        assert_eq!(
            *shared.lock().unwrap(),
            vec![Event::Load(SUBJECT.to_owned()), Event::Revoke]
        );
        assert_eq!(store.stored_token(SUBJECT).as_deref(), Some(REFRESH_TOKEN));
        assert!(broker.delete_stored_tokens(SUBJECT).is_ok());
        assert!(store.stored_token(SUBJECT).is_none());

        // Google's observed revoke answer for an unknown or already-revoked
        // token is invalid_token: confirmed success for the same reason.
        let shared = events();
        let transport = FakeTransport::success(&shared, None)
            .with_revoke_error(TokenTransportError::InvalidToken);
        let store = FakeStore::new(&shared).with_stored_token(SUBJECT, REFRESH_TOKEN);
        let broker = make_broker(&transport, &store, None);
        assert!(ready(broker.revoke_provider_grant(SUBJECT)).is_ok());
        assert_eq!(
            *shared.lock().unwrap(),
            vec![Event::Load(SUBJECT.to_owned()), Event::Revoke]
        );
        assert_eq!(store.stored_token(SUBJECT).as_deref(), Some(REFRESH_TOKEN));

        // Any other provider failure is retried exactly once; two retryable
        // failures stay an unconfirmed revoke: visible, and the stored token
        // is retained.
        let shared = events();
        let transport = FakeTransport::success(&shared, None)
            .with_revoke_error(TokenTransportError::ProviderRejected);
        let store = FakeStore::new(&shared).with_stored_token(SUBJECT, REFRESH_TOKEN);
        let broker = make_broker(&transport, &store, None);
        assert!(matches!(
            ready(broker.revoke_provider_grant(SUBJECT)),
            Err(BrokerError::RevokeUnconfirmed)
        ));
        assert_eq!(
            *shared.lock().unwrap(),
            vec![
                Event::Load(SUBJECT.to_owned()),
                Event::Revoke,
                Event::Revoke,
            ]
        );
        assert_eq!(
            transport.revoked_handles(),
            vec![REFRESH_TOKEN.to_owned(), REFRESH_TOKEN.to_owned()]
        );
        assert_eq!(store.stored_token(SUBJECT).as_deref(), Some(REFRESH_TOKEN));

        // A persistent transport failure behaves identically: exactly one
        // retry, then the revoke stays visibly unconfirmed with the stored
        // token retained.
        let shared = events();
        let transport =
            FakeTransport::success(&shared, None).with_revoke_error(TokenTransportError::Transport);
        let store = FakeStore::new(&shared).with_stored_token(SUBJECT, REFRESH_TOKEN);
        let broker = make_broker(&transport, &store, None);
        assert!(matches!(
            ready(broker.revoke_provider_grant(SUBJECT)),
            Err(BrokerError::RevokeUnconfirmed)
        ));
        assert_eq!(
            *shared.lock().unwrap(),
            vec![
                Event::Load(SUBJECT.to_owned()),
                Event::Revoke,
                Event::Revoke,
            ]
        );
        assert_eq!(
            transport.revoked_handles(),
            vec![REFRESH_TOKEN.to_owned(), REFRESH_TOKEN.to_owned()]
        );
        assert_eq!(store.stored_token(SUBJECT).as_deref(), Some(REFRESH_TOKEN));
    }

    #[test]
    fn a_retryable_revoke_failure_is_retried_exactly_once_under_one_load() {
        // First attempt succeeds: exactly one provider call, no retry.
        let shared = events();
        let transport = FakeTransport::success(&shared, None);
        let store = FakeStore::new(&shared).with_stored_token(SUBJECT, REFRESH_TOKEN);
        let broker = make_broker(&transport, &store, None);
        assert!(ready(broker.revoke_provider_grant(SUBJECT)).is_ok());
        assert_eq!(
            *shared.lock().unwrap(),
            vec![Event::Load(SUBJECT.to_owned()), Event::Revoke]
        );
        assert_eq!(transport.revoked_handles(), vec![REFRESH_TOKEN.to_owned()]);
        assert_eq!(store.stored_token(SUBJECT).as_deref(), Some(REFRESH_TOKEN));

        // First attempt already gone (invalid_token, Google's answer for an
        // unknown or already-revoked token): confirmed immediately with one
        // call, no pointless retry.
        let shared = events();
        let transport = FakeTransport::success(&shared, None)
            .with_revoke_script(&[Err(TokenTransportError::InvalidToken)]);
        let store = FakeStore::new(&shared).with_stored_token(SUBJECT, REFRESH_TOKEN);
        let broker = make_broker(&transport, &store, None);
        assert!(ready(broker.revoke_provider_grant(SUBJECT)).is_ok());
        assert_eq!(
            *shared.lock().unwrap(),
            vec![Event::Load(SUBJECT.to_owned()), Event::Revoke]
        );
        assert_eq!(transport.revoked_handles(), vec![REFRESH_TOKEN.to_owned()]);
        assert_eq!(store.stored_token(SUBJECT).as_deref(), Some(REFRESH_TOKEN));

        // A retryable failure followed by a success: exactly two calls, the
        // revoke is confirmed, and the stored token is still retained (the
        // explicit delete remains the only local-removal step).
        let shared = events();
        let transport = FakeTransport::success(&shared, None)
            .with_revoke_script(&[Err(TokenTransportError::Transport), Ok(())]);
        let store = FakeStore::new(&shared).with_stored_token(SUBJECT, REFRESH_TOKEN);
        let broker = make_broker(&transport, &store, None);
        assert!(ready(broker.revoke_provider_grant(SUBJECT)).is_ok());
        assert_eq!(
            *shared.lock().unwrap(),
            vec![
                Event::Load(SUBJECT.to_owned()),
                Event::Revoke,
                Event::Revoke,
            ]
        );
        assert_eq!(
            transport.revoked_handles(),
            vec![REFRESH_TOKEN.to_owned(), REFRESH_TOKEN.to_owned()]
        );
        assert_eq!(store.stored_token(SUBJECT).as_deref(), Some(REFRESH_TOKEN));

        // A retryable failure followed by an already-gone answer: the retry
        // confirms the desired end state with exactly two calls.
        let shared = events();
        let transport = FakeTransport::success(&shared, None).with_revoke_script(&[
            Err(TokenTransportError::MalformedResponse),
            Err(TokenTransportError::InvalidGrant),
        ]);
        let store = FakeStore::new(&shared).with_stored_token(SUBJECT, REFRESH_TOKEN);
        let broker = make_broker(&transport, &store, None);
        assert!(ready(broker.revoke_provider_grant(SUBJECT)).is_ok());
        assert_eq!(
            *shared.lock().unwrap(),
            vec![
                Event::Load(SUBJECT.to_owned()),
                Event::Revoke,
                Event::Revoke,
            ]
        );
        assert_eq!(
            transport.revoked_handles(),
            vec![REFRESH_TOKEN.to_owned(), REFRESH_TOKEN.to_owned()]
        );
        assert_eq!(store.stored_token(SUBJECT).as_deref(), Some(REFRESH_TOKEN));

        // Two retryable failures: the retry budget is exhausted at exactly
        // two calls, the revoke is visibly RevokeUnconfirmed, and the stored
        // token is retained — strict revoke/delete separation holds.
        let shared = events();
        let transport = FakeTransport::success(&shared, None).with_revoke_script(&[
            Err(TokenTransportError::Transport),
            Err(TokenTransportError::ProviderRejected),
        ]);
        let store = FakeStore::new(&shared).with_stored_token(SUBJECT, REFRESH_TOKEN);
        let broker = make_broker(&transport, &store, None);
        assert!(matches!(
            ready(broker.revoke_provider_grant(SUBJECT)),
            Err(BrokerError::RevokeUnconfirmed)
        ));
        assert_eq!(
            *shared.lock().unwrap(),
            vec![
                Event::Load(SUBJECT.to_owned()),
                Event::Revoke,
                Event::Revoke,
            ]
        );
        assert_eq!(
            transport.revoked_handles(),
            vec![REFRESH_TOKEN.to_owned(), REFRESH_TOKEN.to_owned()]
        );
        assert_eq!(store.stored_token(SUBJECT).as_deref(), Some(REFRESH_TOKEN));
    }

    #[test]
    fn the_single_flight_permit_is_held_across_a_pending_refresh_and_released_on_drop() {
        let shared = events();
        let gate = Arc::new(AtomicBool::new(false));
        let transport =
            FakeTransport::success(&shared, Some(ROTATED_REFRESH_TOKEN)).with_gated_refresh(&gate);
        let store = FakeStore::new(&shared).with_stored_token(SUBJECT, REFRESH_TOKEN);
        let broker = make_broker(&transport, &store, None);

        // Poll the refresh once: the permit is claimed, the credential is
        // loaded, and the future is genuinely parked inside the gated
        // transport call (no Refresh event has fired).
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        let mut pending_refresh = Box::pin(broker.refresh_access_token(SUBJECT));
        assert!(matches!(
            pending_refresh.as_mut().poll(&mut context),
            Poll::Pending
        ));
        assert_eq!(
            *shared.lock().unwrap(),
            vec![Event::Load(SUBJECT.to_owned())]
        );

        // Every same-subject mutation is Busy while the permit is held: the
        // async methods answer on their first poll, the sync delete directly.
        assert!(matches!(
            ready(broker.refresh_access_token(SUBJECT)),
            Err(BrokerError::Busy)
        ));
        assert!(matches!(
            ready(broker.revoke_provider_grant(SUBJECT)),
            Err(BrokerError::Busy)
        ));
        assert!(matches!(
            broker.delete_stored_tokens(SUBJECT),
            Err(BrokerError::Busy)
        ));

        // Another subject is not blocked: its own terminal answers normally.
        assert!(matches!(
            ready(broker.refresh_access_token(OTHER_SUBJECT)),
            Err(BrokerError::MissingRefreshToken)
        ));
        assert!(broker.delete_stored_tokens(OTHER_SUBJECT).is_ok());

        // Cancelling the parked future releases the permit by RAII: the
        // subject is operable again, with no sleeping and no runtime.
        drop(pending_refresh);
        assert!(broker.delete_stored_tokens(SUBJECT).is_ok());
        assert!(store.stored_token(SUBJECT).is_none());
    }

    #[test]
    fn a_completion_parked_in_cleanup_holds_the_subject_permit_until_dropped() {
        // A completion that minted no refresh token ends terminal as
        // MissingRefreshToken; the definitive empty snapshot licenses the
        // best-effort cleanup revoke, and the gate parks the future inside
        // that revoke — AFTER the validated subject permit was claimed.
        let shared = events();
        let gate = Arc::new(AtomicBool::new(false));
        let transport = FakeTransport::success(&shared, None).with_gated_revoke(&gate);
        let store = FakeStore::new(&shared);
        let broker = make_broker(&transport, &store, None);
        let pending = broker.begin_authorization(REDIRECT).unwrap();
        let callback = callback_for(&pending, AUTH_CODE);

        // Poll the completion once: the exchange ran and the snapshot read
        // empty, and the future is genuinely parked inside the gated
        // best-effort revoke (no Revoke event has fired).
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        let mut completion =
            Box::pin(broker.complete_authorization(pending.session_handle(), callback.as_str()));
        assert!(matches!(
            completion.as_mut().poll(&mut context),
            Poll::Pending
        ));
        assert_eq!(
            *shared.lock().unwrap(),
            vec![Event::Exchange, Event::Load(SUBJECT.to_owned())]
        );

        // While the completion is parked, every same-subject mutation —
        // including the disconnect pair — answers Busy.
        assert!(matches!(
            ready(broker.refresh_access_token(SUBJECT)),
            Err(BrokerError::Busy)
        ));
        assert!(matches!(
            ready(broker.revoke_provider_grant(SUBJECT)),
            Err(BrokerError::Busy)
        ));
        assert!(matches!(
            broker.delete_stored_tokens(SUBJECT),
            Err(BrokerError::Busy)
        ));

        // Another completion that re-validates to the same subject reaches
        // the provider, then the held permit answers Busy BEFORE any store
        // read or write.
        let second = broker.begin_authorization(REDIRECT).unwrap();
        let second_callback = callback_for(&second, AUTH_CODE);
        assert!(matches!(
            ready(broker.complete_authorization(second.session_handle(), second_callback.as_str())),
            Err(BrokerError::Busy)
        ));
        assert_eq!(
            *shared.lock().unwrap(),
            vec![
                Event::Exchange,
                Event::Load(SUBJECT.to_owned()),
                Event::Exchange,
            ]
        );

        // Another subject is not blocked: its own terminal answers normally.
        assert!(matches!(
            ready(broker.refresh_access_token(OTHER_SUBJECT)),
            Err(BrokerError::MissingRefreshToken)
        ));

        // Dropping the parked completion releases the permit by RAII: the
        // gated revoke never fires, and the subject is operable again.
        drop(completion);
        assert!(transport.revoked_handles().is_empty());
        assert!(broker.delete_stored_tokens(SUBJECT).is_ok());
        assert!(matches!(
            ready(broker.refresh_access_token(SUBJECT)),
            Err(BrokerError::MissingRefreshToken)
        ));
    }

    #[test]
    fn stored_token_bounds_invalid_subjects_and_debug_redaction_stay_fail_closed() {
        // An empty or oversized stored item is a store-integrity failure:
        // refresh and revoke fail closed without contacting the transport.
        let oversized = format!("1//{}", "A".repeat(MAX_REFRESH_TOKEN_LEN));
        for stored in ["", oversized.as_str()] {
            let shared = events();
            let transport = FakeTransport::success(&shared, None);
            let store = FakeStore::new(&shared).with_stored_token(SUBJECT, stored);
            let broker = make_broker(&transport, &store, None);
            assert!(matches!(
                ready(broker.refresh_access_token(SUBJECT)),
                Err(BrokerError::PersistenceFailed)
            ));
            assert!(matches!(
                ready(broker.revoke_provider_grant(SUBJECT)),
                Err(BrokerError::PersistenceFailed)
            ));
            // Only the two loads ran: no transport call, no store mutation.
            assert_eq!(
                *shared.lock().unwrap(),
                vec![
                    Event::Load(SUBJECT.to_owned()),
                    Event::Load(SUBJECT.to_owned()),
                ]
            );
            assert_eq!(store.stored_token(SUBJECT).as_deref(), Some(stored));
        }

        // A store read failure fails closed identically on both read paths.
        let shared = events();
        let transport = FakeTransport::success(&shared, None);
        let store = FakeStore::failing_load(&shared);
        let broker = make_broker(&transport, &store, None);
        assert!(matches!(
            ready(broker.refresh_access_token(SUBJECT)),
            Err(BrokerError::PersistenceFailed)
        ));
        assert!(matches!(
            ready(broker.revoke_provider_grant(SUBJECT)),
            Err(BrokerError::PersistenceFailed)
        ));
        assert_eq!(
            *shared.lock().unwrap(),
            vec![
                Event::Load(SUBJECT.to_owned()),
                Event::Load(SUBJECT.to_owned()),
            ]
        );

        // Invalid subject text is rejected before any permit, store, or
        // transport interaction. 256 bytes exceeds the 255-byte subject cap.
        let oversized_subject = "1".repeat(256);
        for invalid in ["", "has space", oversized_subject.as_str()] {
            let shared = events();
            let transport = FakeTransport::success(&shared, None);
            let store = FakeStore::new(&shared);
            let broker = make_broker(&transport, &store, None);
            assert!(matches!(
                ready(broker.refresh_access_token(invalid)),
                Err(BrokerError::InvalidInput)
            ));
            assert!(matches!(
                ready(broker.revoke_provider_grant(invalid)),
                Err(BrokerError::InvalidInput)
            ));
            assert!(matches!(
                broker.delete_stored_tokens(invalid),
                Err(BrokerError::InvalidInput)
            ));
            assert!(shared.lock().unwrap().is_empty());
        }

        // With live secrets loaded, no broker, fake, or token Debug rendering
        // leaks one.
        let shared = events();
        let transport = FakeTransport::success(&shared, Some(ROTATED_REFRESH_TOKEN));
        let store = FakeStore::new(&shared).with_stored_token(SUBJECT, REFRESH_TOKEN);
        let broker = make_broker(&transport, &store, Some(CLIENT_SECRET));
        let token = ready(broker.refresh_access_token(SUBJECT)).unwrap();
        for rendered in [
            format!("{broker:?}"),
            format!("{transport:?}"),
            format!("{store:?}"),
            format!("{token:?}"),
        ] {
            for sensitive in [
                ACCESS_TOKEN,
                REFRESH_TOKEN,
                ROTATED_REFRESH_TOKEN,
                CLIENT_SECRET,
                SUBJECT,
            ] {
                assert!(
                    !rendered.contains(sensitive),
                    "Debug leaks {sensitive}: {rendered}"
                );
            }
        }
    }
}
