// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Implements capability-bound token operations without storage or transport defaults.

use super::{
    AccountCapability, AccountSubject, AuthorizationGrant, BoxFuture, ExchangeRequest,
    MonotonicClock, RefreshRequest, ScopeRejection, TokenClientConfig, TokenError, TokenResponse,
    TokenSuccess, TokenTransport, fmt, map_exchange_transport_error, map_transport_error,
};
use zeroize::Zeroizing;

/// Binds a trusted atomically loaded credential to its stored subject and capability.
///
/// The owning store/broker must load all three fields as one snapshot under its
/// account coordination. Construction validates only the token bound, not store
/// provenance, live consent, account routing or current credential generation.
/// Refresh can neither override this capability nor infer one from a response.
pub struct StoredGrantSnapshot {
    refresh_token: Zeroizing<String>,
    subject: AccountSubject,
    capability: AccountCapability,
}
impl StoredGrantSnapshot {
    /// Defensive refresh-token byte bound retained from the ADR 0024 broker contract.
    pub const MAX_REFRESH_TOKEN_BYTES: usize = 1_024;

    /// Constructs a snapshot from trusted stored grant fields, without performing I/O.
    ///
    /// # Errors
    ///
    /// Rejects an empty token or more than 1,024 bytes as malformed. Google has
    /// no documented maximum; exceeding this defensive bound requires review.
    pub fn new(
        refresh_token: Zeroizing<String>,
        subject: AccountSubject,
        capability: AccountCapability,
    ) -> Result<Self, TokenError> {
        validate_refresh_token(&refresh_token)?;
        Ok(Self {
            refresh_token,
            subject,
            capability,
        })
    }
    /// Returns the trusted stored capability, never a response-derived promotion.
    #[must_use]
    pub fn capability(&self) -> AccountCapability {
        self.capability
    }
    /// Returns the subject that every granted refresh must match.
    #[must_use]
    pub fn subject(&self) -> &AccountSubject {
        &self.subject
    }
}
impl fmt::Debug for StoredGrantSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredGrantSnapshot")
            .field("refresh_token", &"[REDACTED]")
            .field("subject", &"[REDACTED]")
            .field("capability", &self.capability)
            .finish()
    }
}

/// Retains a validated refresh rotation solely as a rejected grant's revocation handle.
///
/// This is neither usable access nor acceptance of identity/capability. Only the
/// trusted owning broker may persist it for ADR 0024 cleanup, preserving stored
/// capability. It never licenses new mailbox work or first-connect cleanup.
pub struct RefreshRevocationHandle(Zeroizing<String>);
impl RefreshRevocationHandle {
    /// Exposes the zeroizing credential only for owning-broker retention or revocation.
    #[must_use]
    pub fn secret_for_revocation(&self) -> &Zeroizing<String> {
        &self.0
    }
    /// Transfers the zeroizing credential for owning-account revocation-handle persistence.
    #[must_use]
    pub fn into_secret_for_revocation(self) -> Zeroizing<String> {
        self.0
    }
}
impl fmt::Debug for RefreshRevocationHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RefreshRevocationHandle([REDACTED])")
    }
}

/// Distinguishes accepted refresh access from scope-rejected cleanup evidence.
#[derive(Debug)]
pub enum CapabilityRefreshOutcome {
    /// A same-subject response accepted for exactly the stored capability.
    Granted(TokenSuccess),
    /// Scope rejected before identity; no access token or validated response subject escapes.
    ScopeRejected {
        /// Closed policy reason, never raw provider scopes.
        reason: ScopeRejection,
        /// A bounded rotation retained solely for the existing grant's revocation.
        rotation: Option<RefreshRevocationHandle>,
    },
}

/// Exchanges a callback-validated grant using its immutable requested capability.
///
/// No capability override exists. Scope rejection drops all credentials before
/// identity validation and returns no cleanup handle: first-connect/upgrade
/// scope failures must neither persist nor revoke. Legacy boolean transports
/// cannot successfully service this API, even for readonly requests.
///
/// # Errors
///
/// Returns closed exchange transport errors, malformed token bounds/expiry,
/// unavailable full evidence, insufficient scope, or unverified identity.
/// Identity freshness must still be checked by the concrete session against its
/// wall clock using [`TokenSuccess::identity_expiry`], as in the readonly flow.
pub fn exchange_capability_grant<'a, T: TokenTransport, C: MonotonicClock>(
    grant: &AuthorizationGrant,
    config: &'a TokenClientConfig,
    transport: &'a T,
    clock: &'a C,
) -> BoxFuture<'a, Result<TokenSuccess, TokenError>> {
    let request = ExchangeRequest::new(grant, config);
    let expected = grant.requested_capability();
    Box::pin(async move {
        let response = transport
            .exchange(request)
            .await
            .map_err(map_exchange_transport_error)?;
        validate_rotation(&response)?;
        let accepted = response
            .scope_evidence
            .validate_for(expected)
            .map_err(scope_error)?;
        validate_response_bounds(&response)?;
        TokenSuccess::from_parts(
            response.access_token,
            response.expires_in,
            response.rotated_refresh_token,
            response.id_token_claims,
            accepted,
            clock.now(),
            config,
        )
    })
}

/// Refreshes using a trusted stored snapshot, without changing its capability.
///
/// Scope rejection drops the access token before identity validation. A valid
/// rotation may escape only as a revocation handle; incomplete legacy evidence
/// fails entirely. Successful identity must equal the snapshot subject before
/// any rotation can be used as a granted replacement. No persistence occurs.
///
/// # Errors
///
/// Returns closed refresh transport errors (including refresh-only consent
/// revocation), malformed bounds/expiry, unavailable full scope evidence,
/// unverified identity or identity mismatch. Session freshness, atomic retention,
/// current generation checks and deletion-before-reconnect remain broker duties.
pub fn refresh_stored_grant<'a, T: TokenTransport, C: MonotonicClock>(
    stored: &'a StoredGrantSnapshot,
    config: &'a TokenClientConfig,
    transport: &'a T,
    clock: &'a C,
) -> BoxFuture<'a, Result<CapabilityRefreshOutcome, TokenError>> {
    let mut request = RefreshRequest::new(&stored.refresh_token, config);
    request.stored_capability = stored.capability;
    Box::pin(async move {
        let response = transport
            .refresh(request)
            .await
            .map_err(map_transport_error)?;
        validate_rotation(&response)?;
        let accepted = match response.scope_evidence.validate_for(stored.capability) {
            Ok(accepted) => accepted,
            Err(ScopeRejection::IncompleteEvidence) => {
                return Err(TokenError::ScopeEvidenceUnavailable);
            }
            Err(reason) => {
                return Ok(CapabilityRefreshOutcome::ScopeRejected {
                    reason,
                    rotation: response.rotated_refresh_token.map(RefreshRevocationHandle),
                });
            }
        };
        validate_response_bounds(&response)?;
        let success = TokenSuccess::from_parts(
            response.access_token,
            response.expires_in,
            response.rotated_refresh_token,
            response.id_token_claims,
            accepted,
            clock.now(),
            config,
        )?;
        if success.subject().as_str() != stored.subject.as_str() {
            return Err(TokenError::IdentityMismatch);
        }
        Ok(CapabilityRefreshOutcome::Granted(success))
    })
}

fn scope_error(error: ScopeRejection) -> TokenError {
    match error {
        ScopeRejection::IncompleteEvidence => TokenError::ScopeEvidenceUnavailable,
        _ => TokenError::InsufficientScope,
    }
}
fn validate_refresh_token(token: &str) -> Result<(), TokenError> {
    if token.is_empty() || token.len() > StoredGrantSnapshot::MAX_REFRESH_TOKEN_BYTES {
        return Err(TokenError::MalformedResponse);
    }
    Ok(())
}
fn validate_response_bounds(response: &TokenResponse) -> Result<(), TokenError> {
    // Retain the existing broker's 4 KiB access / 24-hour lifetime defenses.
    // These are local bounds, not claims about provider capacity.
    if response.access_token.is_empty()
        || response.access_token.len() > 4_096
        || response.expires_in.as_secs() == 0
        || response.expires_in.as_secs() > 86_400
    {
        return Err(TokenError::MalformedResponse);
    }
    Ok(())
}

fn validate_rotation(response: &TokenResponse) -> Result<(), TokenError> {
    if let Some(token) = &response.rotated_refresh_token {
        validate_refresh_token(token)?;
    }
    Ok(())
}
