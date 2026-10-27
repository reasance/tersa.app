// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The closed, copyable broker failure vocabulary.
//!
//! Every variant is bare: no raw input, handle, URL, subject, provider body,
//! or secret ever rides an error, so `Debug`/`Display` are safe to log.

use std::fmt;

/// Describes a terminal broker lifecycle failure without sensitive values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BrokerError {
    /// A caller-supplied value failed validation: the redirect URI was not an
    /// exact root-form literal IPv4 loopback with an explicit non-privileged
    /// port, the session handle was malformed, the subject was not conservative
    /// Google-subject text, the callback URL was oversized or unparsable, or
    /// the callback did not match the pending session (redirect, state,
    /// parameter shape).
    InvalidInput,
    /// The broker configuration itself is unusable (for example a zero
    /// authorization lifetime).
    InvalidConfiguration,
    /// An internal resource is unavailable: cryptographic entropy failed, a
    /// lock was poisoned (the broker fails closed), or a unique session
    /// handle could not be allocated within the attempt bound.
    Unavailable,
    /// A bounded resource is momentarily exhausted: the pending-session
    /// registry is at capacity (retry after pending sessions expire), another
    /// mutation already holds the subject's single-flight permit, or the
    /// global bounded subject-permit table is full even though the requested
    /// subject has no current mutation. Every cause is bounded and transient
    /// — the caller backs off and retries — and the variant deliberately
    /// carries no subject or count, so no account identity leaks through it.
    Busy,
    /// The session handle names no live pending session: it is unknown, it
    /// expired, or a prior callback already consumed it. Every callback
    /// attempt is terminal, so this is the only answer a replay ever gets.
    SessionUnknown,
    /// The provider rejected the request or the authorization attempt with an
    /// error other than a refresh-time `invalid_grant` (which is
    /// [`Self::ConsentRevoked`]) or an exchange-time `invalid_grant` (which
    /// is [`Self::AuthorizationCodeRejected`]).
    ProviderRejected,
    /// The provider rejected the authorization code at exchange time with an
    /// `invalid_grant` answer: the code was stale, already redeemed, or
    /// mismatched, so the sign-in itself lapsed. Non-destructive: nothing is
    /// stored on the exchange path, so this is never a deletion license and
    /// never [`Self::ConsentRevoked`]. The broker keeps this terminal distinct
    /// from [`Self::ProviderRejected`] so callers can offer sign-in-expired
    /// "sign in again" recovery (ADR-0024) without exposing provider data or
    /// conflating it with revoked consent.
    AuthorizationCodeRejected,
    /// The token or revocation endpoint could not be reached.
    Transport,
    /// A provider response did not parse into a complete, bounded token
    /// response (including an out-of-bound access token or expiry).
    MalformedResponse,
    /// The granted scope set omitted Gmail read access. On exchange nothing
    /// was persisted and nothing was revoked: the under-scoped outcome has
    /// no validated identity, so no subject-keyed snapshot is possible and
    /// no grant-wide revoke is safe. The fail-safe contract is deliberately
    /// non-destructive — it can leave a first-connect under-scoped grant
    /// active at the provider, which this API cannot revoke in-app (the
    /// minted tokens were dropped and no validated subject or stored
    /// credential exists to revoke against). The caller must offer
    /// retain-or-retry recovery and direct the user to their Google
    /// account-permissions page for manual revocation; the contract can
    /// never destroy an unknown prior working grant. On refresh any rotated
    /// credential was persisted first.
    InsufficientScope,
    /// The token response carried no verified account identity, or its
    /// `id_token` failed freshness validation against the wall clock.
    /// Non-destructive: any stored credential is retained for a retry.
    IdentityUnverified,
    /// A refresh succeeded but re-validated to a DIFFERENT subject than the
    /// one the credential was stored under. The stored token is retained; the
    /// minted access token is dropped without being exposed.
    IdentityMismatch,
    /// No usable refresh token exists: the exchange granted no refresh token
    /// (the stranded grant was revoked best-effort, but only when a
    /// definitive empty store snapshot licensed the grant-wide revoke), or
    /// none is stored for the subject. Re-connect is required.
    MissingRefreshToken,
    /// A refresh-time provider `invalid_grant`: consent was withdrawn or the
    /// stored refresh token expired. The stored token was deleted; re-connect
    /// is required. An exchange-time `invalid_grant` (a stale or used
    /// authorization code) never produces this variant — it surfaces as
    /// [`Self::AuthorizationCodeRejected`] because no stored credential
    /// exists to delete.
    ConsentRevoked,
    /// The refresh-token store rejected a read, write, or delete. On a
    /// persistence-first path the broker fails closed rather than reporting a
    /// success whose credential was never durably stored. An unreadable
    /// pre-mutation snapshot during completion fails closed the same way,
    /// before any store write or provider revoke.
    ///
    /// Callers must not treat every `PersistenceFailed` as an ordinary
    /// transient: after a definitive refresh-time `invalid_grant`, a delete
    /// failure intentionally fails closed HERE instead of reporting
    /// [`Self::ConsentRevoked`], withholding the re-connect signal until the
    /// local deletion can be confirmed — a persistent store failure on that
    /// path is a stuck dead credential, not a retry-and-forget hiccup.
    PersistenceFailed,
    /// The provider did not confirm a requested grant revocation. The local
    /// stored token is deliberately NOT deleted: ADR-0024's disconnect
    /// ordering runs broker revoke and broker token delete as separate steps,
    /// and an unconfirmed revoke must stay visible.
    RevokeUnconfirmed,
}

impl fmt::Display for BrokerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidInput => "the broker rejected the supplied input",
            Self::InvalidConfiguration => "invalid broker configuration",
            Self::Unavailable => "a broker-internal resource is unavailable",
            Self::Busy => "a bounded broker resource is momentarily exhausted",
            Self::SessionUnknown => "the authorization session is unknown, expired, or consumed",
            Self::ProviderRejected => "the OAuth provider rejected the request",
            Self::AuthorizationCodeRejected => "the authorization code was rejected; sign in again",
            Self::Transport => "the provider endpoint could not be reached",
            Self::MalformedResponse => "the provider returned an unusable response",
            Self::InsufficientScope => "the grant omitted Gmail read access",
            Self::IdentityUnverified => "the account identity could not be verified",
            Self::IdentityMismatch => "the credential no longer belongs to the requested account",
            Self::MissingRefreshToken => "no refresh token is available; re-connect is required",
            Self::ConsentRevoked => "consent was revoked; re-connect is required",
            Self::PersistenceFailed => "the refresh-token store failed",
            Self::RevokeUnconfirmed => "the provider did not confirm the revocation",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for BrokerError {}

#[cfg(test)]
mod tests {
    use super::BrokerError;

    #[test]
    fn display_and_debug_carry_no_sensitive_content() {
        let errors = [
            BrokerError::InvalidInput,
            BrokerError::InvalidConfiguration,
            BrokerError::Unavailable,
            BrokerError::Busy,
            BrokerError::SessionUnknown,
            BrokerError::ProviderRejected,
            BrokerError::AuthorizationCodeRejected,
            BrokerError::Transport,
            BrokerError::MalformedResponse,
            BrokerError::InsufficientScope,
            BrokerError::IdentityUnverified,
            BrokerError::IdentityMismatch,
            BrokerError::MissingRefreshToken,
            BrokerError::ConsentRevoked,
            BrokerError::PersistenceFailed,
            BrokerError::RevokeUnconfirmed,
        ];
        // Sentinel VALUES shaped like real provider and account secrets. They
        // never legitimately occur in static safe copy, so any occurrence in a
        // rendered error proves a live secret leaked into the failure
        // vocabulary. Substring shapes (for example "refresh-token") are
        // deliberately NOT used: they false-positive on safe copy such as
        // "the refresh-token store failed".
        let sentinels = [
            "ya29.sentinel-access-token",
            "1//sentinel-refresh-token",
            "4/0AfJM-sentinel-authorization-code",
            "sentinel-pkce-verifier",
            "sentinel-oauth-state",
            "GOCSPX-sentinel-client-secret",
            "110169484474386276334",
        ];
        for error in errors {
            let rendered = format!("{error} {error:?}");
            for sentinel in sentinels {
                assert!(
                    !rendered.contains(sentinel),
                    "{error:?} leaks {sentinel}: {rendered}"
                );
            }
        }
    }
}
