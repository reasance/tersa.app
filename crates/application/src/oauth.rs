// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Implements the portable OAuth authorization-code and PKCE state machine.
//!
//! This module prepares a Google authorization request and validates exactly
//! one redirect. It intentionally does not exchange the authorization code,
//! persist tokens, contact Gmail, or launch a browser. Platform adapters own
//! the browser and redirect transport.

use std::fmt;
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use tersa_domain::account::AccountCapability;
use url::Url;
use zeroize::{Zeroize, Zeroizing};

use crate::scope::{ScopeEvidence, requested_scope};

// Rust guideline compliant 1.0.

#[doc(inline)]
pub use crate::scope::{GMAIL_READONLY_SCOPE, OPENID_SCOPE, REQUESTED_SCOPE};

const GOOGLE_AUTHORIZATION_ENDPOINT: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const SECRET_BYTES: usize = 32;

/// Supplies monotonic time to an authorization session.
pub trait MonotonicClock: fmt::Debug + Send + Sync {
    /// Returns elapsed monotonic time from a clock-specific origin.
    fn now(&self) -> Duration;
}

/// Uses [`Instant`] as the production monotonic clock.
#[derive(Debug)]
pub struct SystemMonotonicClock {
    origin: Instant,
}

impl SystemMonotonicClock {
    /// Creates a monotonic clock with a new process-local origin.
    #[must_use]
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Default for SystemMonotonicClock {
    fn default() -> Self {
        Self::new()
    }
}

impl MonotonicClock for SystemMonotonicClock {
    fn now(&self) -> Duration {
        self.origin.elapsed()
    }
}

/// Supplies wall-clock (Unix) time for validating token-response timestamps.
///
/// Distinct from [`MonotonicClock`]: an `id_token`'s `exp`/`iat` are absolute Unix
/// timestamps, so validating their freshness needs a real calendar clock. The pure
/// token layer never uses this — it is injected only into the concrete session that
/// validates `id_token` freshness, keeping that layer monotonic-clock-only.
pub trait WallClock: fmt::Debug + Send + Sync {
    /// Returns seconds since the Unix epoch.
    fn unix_time(&self) -> u64;
}

/// Uses the operating-system clock as the production wall clock.
#[derive(Debug, Default)]
pub struct SystemWallClock;

impl WallClock for SystemWallClock {
    fn unix_time(&self) -> u64 {
        // A clock before the Unix epoch is impossible in practice; on that error
        // return the maximum so every token reads as expired (fail closed) rather
        // than as freshly issued.
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(u64::MAX, |elapsed| elapsed.as_secs())
    }
}

/// Configures one Google OAuth authorization attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationConfig {
    client_id: String,
    redirect_uri: Url,
    lifetime: Duration,
    requested_capability: AccountCapability,
}

impl AuthorizationConfig {
    /// Creates a validated readonly compatibility authorization configuration.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthError::InvalidConfiguration`] when the client identifier
    /// is blank, the redirect contains credentials, query, or fragment, or the
    /// lifetime is zero.
    pub fn new<T: Into<String>>(
        client_id: T,
        redirect_uri: Url,
        lifetime: Duration,
    ) -> Result<Self, OAuthError> {
        Self::for_capability(
            client_id,
            redirect_uri,
            lifetime,
            AccountCapability::ReadOnly,
        )
    }

    /// Creates an authorization attempt with an explicitly selected immutable capability.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthError::InvalidConfiguration`] under the same conditions as
    /// [`Self::new`]. No existing grant is changed by constructing this value.
    pub fn for_capability<T: Into<String>>(
        client_id: T,
        redirect_uri: Url,
        lifetime: Duration,
        requested_capability: AccountCapability,
    ) -> Result<Self, OAuthError> {
        let client_id = client_id.into();
        let has_credentials =
            !redirect_uri.username().is_empty() || redirect_uri.password().is_some();
        if client_id.trim().is_empty()
            || lifetime.is_zero()
            || has_credentials
            || redirect_uri.query().is_some()
            || redirect_uri.fragment().is_some()
        {
            return Err(OAuthError::InvalidConfiguration);
        }

        Ok(Self {
            client_id,
            redirect_uri,
            lifetime,
            requested_capability,
        })
    }

    /// Returns the exact registered redirect URI.
    #[must_use]
    pub fn redirect_uri(&self) -> &Url {
        &self.redirect_uri
    }

    /// Returns the capability this configuration will bind at begin.
    #[must_use]
    pub fn requested_capability(&self) -> AccountCapability {
        self.requested_capability
    }
}

/// Contains the public authorization URL and its pending state machine.
pub struct PreparedAuthorization<C> {
    authorization_url: Url,
    session: AuthorizationSession<C>,
}

impl<C> fmt::Debug for PreparedAuthorization<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedAuthorization")
            .field("authorization_url", &"[REDACTED]")
            .field("session", &self.session)
            .finish()
    }
}

impl<C> PreparedAuthorization<C> {
    /// Returns the capability immutably bound to the prepared session.
    #[must_use]
    pub fn requested_capability(&self) -> AccountCapability {
        self.session.requested_capability
    }
    /// Returns the authorization URL intended for the system browser.
    #[must_use]
    pub fn authorization_url(&self) -> &Url {
        &self.authorization_url
    }

    /// Separates the public URL from its one-shot session.
    #[must_use]
    pub fn into_parts(self) -> (Url, AuthorizationSession<C>) {
        (self.authorization_url, self.session)
    }
}

/// Owns the sensitive state for one pending authorization attempt.
pub struct AuthorizationSession<C> {
    clock: C,
    expires_at: Duration,
    redirect_uri: Url,
    state: Zeroizing<Vec<u8>>,
    verifier: Zeroizing<String>,
    consumed: bool,
    requested_capability: AccountCapability,
}

impl<C> fmt::Debug for AuthorizationSession<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationSession")
            .field("expires_at", &self.expires_at)
            .field("redirect_uri", &"[REDACTED]")
            .field("clock", &"[MONOTONIC]")
            .field("state", &"[REDACTED]")
            .field("verifier", &"[REDACTED]")
            .field("consumed", &self.consumed)
            .field("requested_capability", &self.requested_capability)
            .finish()
    }
}

impl<C: MonotonicClock> AuthorizationSession<C> {
    /// Returns the capability bound at begin, with no setter or finish override.
    #[must_use]
    pub fn requested_capability(&self) -> AccountCapability {
        self.requested_capability
    }
    /// Returns the exact registered redirect URI.
    #[must_use]
    pub fn redirect_uri(&self) -> &Url {
        &self.redirect_uri
    }

    /// Validates and consumes the one permitted redirect.
    ///
    /// The session is consumed before validation, so every callback attempt is
    /// terminal, including malformed and adversarial callbacks.
    ///
    /// # Errors
    ///
    /// Returns a typed error for replay, expiry, malformed callbacks, provider
    /// errors, redirect mismatch, or state mismatch.
    pub fn finish(&mut self, callback: &Url) -> Result<AuthorizationGrant, OAuthError> {
        self.consume()?;
        let result = self.validate_callback(callback);
        self.state.zeroize();
        if result.is_err() {
            self.verifier.zeroize();
        }
        result
    }

    /// Cancels and consumes the pending session.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthError::AlreadyConsumed`] after any terminal outcome.
    pub fn cancel(&mut self) -> Result<(), OAuthError> {
        self.consume()?;
        self.state.zeroize();
        self.verifier.zeroize();
        Ok(())
    }

    /// Expires and consumes the session once its deadline has elapsed.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthError::NotExpired`] before the deadline or
    /// [`OAuthError::AlreadyConsumed`] after a terminal outcome.
    pub fn expire(&mut self) -> Result<(), OAuthError> {
        if self.consumed {
            return Err(OAuthError::AlreadyConsumed);
        }
        if self.clock.now() < self.expires_at {
            return Err(OAuthError::NotExpired);
        }
        self.consume()?;
        self.state.zeroize();
        self.verifier.zeroize();
        Ok(())
    }

    fn consume(&mut self) -> Result<(), OAuthError> {
        if self.consumed {
            return Err(OAuthError::AlreadyConsumed);
        }
        self.consumed = true;
        Ok(())
    }

    fn validate_callback(&mut self, callback: &Url) -> Result<AuthorizationGrant, OAuthError> {
        if self.clock.now() >= self.expires_at {
            return Err(OAuthError::Expired);
        }
        self.validate_redirect(callback)?;

        let parameters = unique_query_parameters(callback)?;
        let state = required_parameter(&parameters, "state")?;
        if self.state.as_slice().ct_eq(state.as_bytes()).unwrap_u8() != 1 {
            return Err(OAuthError::StateMismatch);
        }
        let code = parameters.get("code");
        let provider_error = parameters.get("error");
        match (code, provider_error) {
            (Some(_), Some(_)) => Err(OAuthError::ConflictingCallback),
            (None, Some(_)) => Err(OAuthError::ProviderRejected),
            (None, None) => Err(OAuthError::MissingParameter("code")),
            (Some(code), None) if code.is_empty() => Err(OAuthError::MissingParameter("code")),
            (Some(code), None) => {
                let scope_evidence = ScopeEvidence::from_scope_field(
                    parameters.get("scope").map(|scope| scope.as_str()),
                )
                .map_err(|_error| OAuthError::InvalidScopeEvidence)?;
                scope_evidence
                    .validate_for(self.requested_capability)
                    .map_err(|_reason| OAuthError::InsufficientScope)?;
                Ok(AuthorizationGrant {
                    code: code.clone(),
                    verifier: Zeroizing::new(std::mem::take(&mut *self.verifier)),
                    requested_capability: self.requested_capability,
                    scope_evidence,
                })
            }
        }
    }

    fn validate_redirect(&self, callback: &Url) -> Result<(), OAuthError> {
        let callback_identity = callback
            .as_str()
            .split_once('?')
            .map_or(callback.as_str(), |(identity, _query)| identity);
        if callback.fragment().is_some() || callback_identity != self.redirect_uri.as_str() {
            return Err(OAuthError::RedirectMismatch);
        }
        Ok(())
    }
}

/// Holds the short-lived code and verifier for a future token exchange.
pub struct AuthorizationGrant {
    code: Zeroizing<String>,
    verifier: Zeroizing<String>,
    requested_capability: AccountCapability,
    scope_evidence: ScopeEvidence,
}

impl AuthorizationGrant {
    /// Returns the capability bound at begin and validated at the callback.
    #[must_use]
    pub fn requested_capability(&self) -> AccountCapability {
        self.requested_capability
    }

    /// Returns callback scope provenance without any raw scope text.
    #[must_use]
    pub fn scope_evidence(&self) -> ScopeEvidence {
        self.scope_evidence
    }
    /// Returns the authorization code without transferring ownership.
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Returns the PKCE verifier without transferring ownership.
    #[must_use]
    pub fn verifier(&self) -> &str {
        &self.verifier
    }
}

impl fmt::Debug for AuthorizationGrant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationGrant")
            .field("requested_capability", &self.requested_capability)
            .field("scope_evidence", &self.scope_evidence)
            .field("code", &"[REDACTED]")
            .field("verifier", &"[REDACTED]")
            .finish()
    }
}

/// Describes a terminal or configuration failure without sensitive values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum OAuthError {
    /// A required configuration value is absent or unsafe.
    InvalidConfiguration,
    /// The operating system could not provide cryptographic randomness.
    EntropyUnavailable,
    /// A callback parameter is missing.
    MissingParameter(&'static str),
    /// A callback parameter occurs more than once.
    DuplicateParameter,
    /// The callback includes both a code and provider error.
    ConflictingCallback,
    /// The provider returned an OAuth error.
    ProviderRejected,
    /// The explicit scopes do not satisfy the bound requested capability.
    InsufficientScope,
    /// The callback scope field exceeds the defensive parser bounds.
    InvalidScopeEvidence,
    /// The callback redirect does not exactly match the configured redirect.
    RedirectMismatch,
    /// The returned state does not match the pending session.
    StateMismatch,
    /// The authorization deadline elapsed.
    Expired,
    /// The session has not yet reached its deadline.
    NotExpired,
    /// A terminal outcome already consumed the session.
    AlreadyConsumed,
}

impl fmt::Display for OAuthError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidConfiguration => "invalid OAuth configuration",
            Self::EntropyUnavailable => "cryptographic entropy is unavailable",
            Self::MissingParameter(_) => "the OAuth callback is incomplete",
            Self::DuplicateParameter => "the OAuth callback contains duplicate parameters",
            Self::ConflictingCallback => "the OAuth callback contains conflicting outcomes",
            Self::ProviderRejected => "the OAuth provider rejected the request",
            Self::InsufficientScope => "the OAuth grant does not match the requested capability",
            Self::InvalidScopeEvidence => "the OAuth scope field exceeds its bounds",
            Self::RedirectMismatch => "the OAuth redirect does not match",
            Self::StateMismatch => "the OAuth state does not match",
            Self::Expired => "the OAuth request expired",
            Self::NotExpired => "the OAuth request has not expired",
            Self::AlreadyConsumed => "the OAuth request was already consumed",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for OAuthError {}

/// Prepares an authorization request using operating-system randomness.
///
/// # Errors
///
/// Returns [`OAuthError::EntropyUnavailable`] when the OS CSPRNG fails.
pub fn prepare_authorization<C: MonotonicClock>(
    config: AuthorizationConfig,
    clock: C,
) -> Result<PreparedAuthorization<C>, OAuthError> {
    let mut verifier_bytes = Zeroizing::new([0_u8; SECRET_BYTES]);
    let mut state_bytes = Zeroizing::new([0_u8; SECRET_BYTES]);
    getrandom::fill(&mut *verifier_bytes).map_err(|_error| OAuthError::EntropyUnavailable)?;
    getrandom::fill(&mut *state_bytes).map_err(|_error| OAuthError::EntropyUnavailable)?;
    prepare_with_secrets(config, clock, &verifier_bytes[..], &state_bytes[..])
}

fn prepare_with_secrets<C: MonotonicClock>(
    config: AuthorizationConfig,
    clock: C,
    verifier_bytes: &[u8],
    state_bytes: &[u8],
) -> Result<PreparedAuthorization<C>, OAuthError> {
    if verifier_bytes.len() != SECRET_BYTES || state_bytes.len() != SECRET_BYTES {
        return Err(OAuthError::InvalidConfiguration);
    }
    let verifier = Zeroizing::new(URL_SAFE_NO_PAD.encode(verifier_bytes));
    let state = Zeroizing::new(URL_SAFE_NO_PAD.encode(state_bytes));
    let challenge = pkce_challenge(&verifier);
    let now = clock.now();
    let expires_at = now
        .checked_add(config.lifetime)
        .ok_or(OAuthError::InvalidConfiguration)?;

    let mut authorization_url =
        Url::parse(GOOGLE_AUTHORIZATION_ENDPOINT).expect("the static Google URL is valid");
    authorization_url
        .query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &config.client_id)
        .append_pair("redirect_uri", config.redirect_uri.as_str())
        .append_pair("scope", requested_scope(config.requested_capability))
        .append_pair("state", &state)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("access_type", "offline")
        // The browser rung is reached only when no usable refresh token is
        // stored. Google normally returns a refresh token only on the first
        // authorization, so an explicit re-consent is required after local
        // deletion, provider revocation, or testing-token expiry.
        .append_pair("prompt", "consent");

    Ok(PreparedAuthorization {
        authorization_url,
        session: AuthorizationSession {
            clock,
            expires_at,
            redirect_uri: config.redirect_uri,
            state: Zeroizing::new(state.as_bytes().to_vec()),
            verifier,
            consumed: false,
            requested_capability: config.requested_capability,
        },
    })
}

fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn unique_query_parameters(
    callback: &Url,
) -> Result<std::collections::BTreeMap<String, Zeroizing<String>>, OAuthError> {
    let mut parameters = std::collections::BTreeMap::new();
    for (name, value) in callback.query_pairs() {
        if parameters
            .insert(name.into_owned(), Zeroizing::new(value.into_owned()))
            .is_some()
        {
            return Err(OAuthError::DuplicateParameter);
        }
    }
    Ok(parameters)
}

fn required_parameter<'a>(
    parameters: &'a std::collections::BTreeMap<String, Zeroizing<String>>,
    name: &'static str,
) -> Result<&'a str, OAuthError> {
    parameters
        .get(name)
        .filter(|value| !value.is_empty())
        .map(|value| value.as_str())
        .ok_or(OAuthError::MissingParameter(name))
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "test fixtures use static URLs and assert setup success before behavior"
    )]

    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{
        AuthorizationConfig, GMAIL_READONLY_SCOPE, MonotonicClock, OAuthError, OPENID_SCOPE,
        REQUESTED_SCOPE, SystemMonotonicClock, pkce_challenge, prepare_authorization,
        prepare_with_secrets,
    };
    use std::time::Duration;
    use url::Url;

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

    fn make_prepared(seed: u8) -> super::PreparedAuthorization<TestClock> {
        let redirect = Url::parse("app.tersa.oauth.test:/oauth/callback").unwrap();
        let config =
            AuthorizationConfig::new("public-test-client", redirect, Duration::from_secs(60))
                .unwrap();
        prepare_with_secrets(config, TestClock::default(), &[seed; 32], &[seed + 1; 32]).unwrap()
    }

    fn state(url: &Url) -> String {
        url.query_pairs()
            .find_map(|(name, value)| (name == "state").then(|| value.into_owned()))
            .unwrap()
    }

    fn make_callback(url: &Url, code: &str) -> Url {
        let mut callback = Url::parse("app.tersa.oauth.test:/oauth/callback").unwrap();
        callback
            .query_pairs_mut()
            .append_pair("state", &state(url))
            .append_pair("code", code);
        callback
    }

    #[test]
    fn matches_the_rfc_7636_s256_vector() {
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn generates_well_shaped_verifier_state_and_exact_parameters() {
        let prepared = make_prepared(7);
        let pairs: Vec<_> = prepared.authorization_url().query_pairs().collect();
        let parameters: BTreeMap<_, _> = pairs.iter().cloned().collect();
        assert_eq!(pairs.len(), 9);
        assert_eq!(parameters.len(), pairs.len());
        assert_eq!(parameters.get("scope").unwrap(), REQUESTED_SCOPE);
        assert_eq!(
            GMAIL_READONLY_SCOPE,
            "https://www.googleapis.com/auth/gmail.readonly"
        );
        // `openid` is requested additively for the identity-gate `sub`; the Gmail
        // read-only scope is unchanged.
        assert_eq!(
            REQUESTED_SCOPE,
            format!("{OPENID_SCOPE} {GMAIL_READONLY_SCOPE}")
        );
        assert!(
            REQUESTED_SCOPE
                .split(' ')
                .any(|s| s == GMAIL_READONLY_SCOPE)
        );
        assert_eq!(parameters.get("code_challenge_method").unwrap(), "S256");
        assert_eq!(parameters.get("response_type").unwrap(), "code");
        assert_eq!(parameters.get("client_id").unwrap(), "public-test-client");
        assert_eq!(
            parameters.get("redirect_uri").unwrap(),
            "app.tersa.oauth.test:/oauth/callback"
        );
        assert_eq!(parameters.get("access_type").unwrap(), "offline");
        assert_eq!(parameters.get("prompt").unwrap(), "consent");
        let state = parameters.get("state").unwrap();
        let challenge = parameters.get("code_challenge").unwrap();
        assert_eq!(state.len(), 43);
        assert_eq!(challenge.len(), 43);
        assert!(
            state
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        );
        let debug = format!("{prepared:?}");
        assert!(!debug.contains(state.as_ref()));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn operating_system_entropy_makes_sessions_unique() {
        let redirect = Url::parse("app.tersa.oauth.test:/oauth/callback").unwrap();
        let config =
            AuthorizationConfig::new("public-test-client", redirect, Duration::from_secs(60))
                .unwrap();
        let first = prepare_authorization(config.clone(), SystemMonotonicClock::new()).unwrap();
        let second = prepare_authorization(config, SystemMonotonicClock::new()).unwrap();
        assert_ne!(
            state(first.authorization_url()),
            state(second.authorization_url())
        );
        let first_challenge = first
            .authorization_url()
            .query_pairs()
            .find_map(|(name, value)| (name == "code_challenge").then(|| value.into_owned()))
            .unwrap();
        let second_challenge = second
            .authorization_url()
            .query_pairs()
            .find_map(|(name, value)| (name == "code_challenge").then(|| value.into_owned()))
            .unwrap();
        assert_ne!(first_challenge, second_challenge);
    }

    #[test]
    fn accepts_one_exact_callback_and_redacts_the_grant() {
        let prepared = make_prepared(1);
        let callback = make_callback(prepared.authorization_url(), "short-lived-code");
        let (_, mut session) = prepared.into_parts();
        let grant = session.finish(&callback).unwrap();
        assert_eq!(grant.code(), "short-lived-code");
        assert_eq!(grant.verifier().len(), 43);
        assert!(
            grant
                .verifier()
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        );
        assert!(!format!("{grant:?}").contains("short-lived-code"));
        assert!(matches!(
            session.finish(&callback),
            Err(OAuthError::AlreadyConsumed)
        ));
    }

    #[test]
    fn callback_scope_policy_is_bound_to_the_prepared_capability() {
        // Contract: exact request scopes, absence vs explicit empty, both mismatch
        // directions and forbidden grants. Regression: mutable capability or a
        // readonly boolean admits a broadened/under-scoped callback.
        use crate::scope::{
            FULL_MAIL_SCOPE, GMAIL_MODIFY_SCOPE, GMAIL_SEND_SCOPE, MODIFY_REQUESTED_SCOPE,
            ScopeEvidence,
        };
        use tersa_domain::account::AccountCapability::{Modify, ReadOnly};
        let both = format!("{GMAIL_READONLY_SCOPE} {GMAIL_MODIFY_SCOPE}");
        let send = format!("{GMAIL_READONLY_SCOPE} {GMAIL_SEND_SCOPE}");
        let full = format!("{GMAIL_MODIFY_SCOPE} {FULL_MAIL_SCOPE}");
        for (capability, returned, accepted) in [
            (ReadOnly, None, true),
            (Modify, None, true),
            (ReadOnly, Some(REQUESTED_SCOPE), true),
            (Modify, Some(MODIFY_REQUESTED_SCOPE), true),
            (Modify, Some(both.as_str()), true),
            (ReadOnly, Some(""), false),
            (Modify, Some(""), false),
            (ReadOnly, Some(OPENID_SCOPE), false),
            (Modify, Some(GMAIL_READONLY_SCOPE), false),
            (ReadOnly, Some(GMAIL_MODIFY_SCOPE), false),
            (ReadOnly, Some(both.as_str()), false),
            (ReadOnly, Some(send.as_str()), false),
            (Modify, Some(full.as_str()), false),
        ] {
            let config = AuthorizationConfig::for_capability(
                "public-test-client",
                Url::parse("app.tersa.oauth.test:/oauth/callback").unwrap(),
                Duration::from_secs(60),
                capability,
            )
            .unwrap();
            let prepared =
                prepare_with_secrets(config, TestClock::default(), &[31; 32], &[32; 32]).unwrap();
            let request: BTreeMap<_, _> = prepared.authorization_url().query_pairs().collect();
            assert_eq!(
                request.get("scope").unwrap(),
                match capability {
                    ReadOnly => REQUESTED_SCOPE,
                    Modify => MODIFY_REQUESTED_SCOPE,
                }
            );
            assert_eq!(prepared.requested_capability(), capability);
            let mut callback = make_callback(prepared.authorization_url(), "capability-code");
            if let Some(scope) = returned {
                callback.query_pairs_mut().append_pair("scope", scope);
            }
            let (_, mut session) = prepared.into_parts();
            assert_eq!(session.requested_capability(), capability);
            let result = session.finish(&callback);
            if accepted {
                let grant = result.unwrap();
                assert_eq!(grant.requested_capability(), capability);
                assert_eq!(
                    matches!(grant.scope_evidence(), ScopeEvidence::Absent),
                    returned.is_none()
                );
                assert_eq!(grant.code(), "capability-code");
            } else {
                assert!(matches!(result, Err(OAuthError::InsufficientScope)));
            }
            assert!(matches!(
                session.finish(&callback),
                Err(OAuthError::AlreadyConsumed)
            ));
        }
    }

    #[test]
    fn rejects_wrong_missing_and_duplicate_state_or_code() {
        let cases = [
            "?state=wrong&code=ok",
            "?code=ok",
            "?state=wrong&state=wrong&code=ok",
            "?state=wrong&code=one&code=two",
        ];
        for suffix in cases {
            let prepared = make_prepared(2);
            let mut callback = Url::parse("app.tersa.oauth.test:/oauth/callback").unwrap();
            callback.set_query(Some(suffix.trim_start_matches('?')));
            let (_, mut session) = prepared.into_parts();
            assert!(session.finish(&callback).is_err());
            assert!(matches!(
                session.finish(&callback),
                Err(OAuthError::AlreadyConsumed)
            ));
        }
    }

    #[test]
    fn rejects_conflicting_or_provider_error_outcomes() {
        let prepared = make_prepared(3);
        let returned_state = state(prepared.authorization_url());
        let mut conflicting = Url::parse("app.tersa.oauth.test:/oauth/callback").unwrap();
        conflicting
            .query_pairs_mut()
            .append_pair("state", &returned_state)
            .append_pair("code", "code")
            .append_pair("error", "access_denied");
        let (_, mut session) = prepared.into_parts();
        assert!(matches!(
            session.finish(&conflicting),
            Err(OAuthError::ConflictingCallback)
        ));

        let prepared = make_prepared(4);
        let returned_state = state(prepared.authorization_url());
        let mut rejected = Url::parse("app.tersa.oauth.test:/oauth/callback").unwrap();
        rejected
            .query_pairs_mut()
            .append_pair("state", &returned_state)
            .append_pair("error", "access_denied");
        let (_, mut session) = prepared.into_parts();
        assert!(matches!(
            session.finish(&rejected),
            Err(OAuthError::ProviderRejected)
        ));
    }

    #[test]
    fn rejects_missing_code_and_any_redirect_difference() {
        let prepared = make_prepared(8);
        let returned_state = state(prepared.authorization_url());
        let mut missing_code = Url::parse("app.tersa.oauth.test:/oauth/callback").unwrap();
        missing_code
            .query_pairs_mut()
            .append_pair("state", &returned_state);
        let (_, mut session) = prepared.into_parts();
        assert!(matches!(
            session.finish(&missing_code),
            Err(OAuthError::MissingParameter("code"))
        ));

        let prepared = make_prepared(11);
        let empty_code = make_callback(prepared.authorization_url(), "");
        let (_, mut session) = prepared.into_parts();
        assert!(matches!(
            session.finish(&empty_code),
            Err(OAuthError::MissingParameter("code"))
        ));

        let prepared = make_prepared(9);
        let mut wrong_redirect = make_callback(prepared.authorization_url(), "code");
        wrong_redirect.set_path("/oauth/other");
        let (_, mut session) = prepared.into_parts();
        assert!(matches!(
            session.finish(&wrong_redirect),
            Err(OAuthError::RedirectMismatch)
        ));
    }

    #[test]
    fn cancellation_and_expiry_are_terminal() {
        let prepared = make_prepared(5);
        let callback = make_callback(prepared.authorization_url(), "code");
        let (_, mut cancelled) = prepared.into_parts();
        assert_eq!(cancelled.cancel(), Ok(()));
        assert!(matches!(
            cancelled.finish(&callback),
            Err(OAuthError::AlreadyConsumed)
        ));

        let prepared = make_prepared(6);
        let callback = make_callback(prepared.authorization_url(), "code");
        let clock = prepared.session.clock.clone();
        let (_, mut expired) = prepared.into_parts();
        clock.advance(60);
        assert!(matches!(
            expired.finish(&callback),
            Err(OAuthError::Expired)
        ));
        assert!(matches!(
            expired.finish(&callback),
            Err(OAuthError::AlreadyConsumed)
        ));

        let prepared = make_prepared(7);
        let callback = make_callback(prepared.authorization_url(), "code");
        let clock = prepared.session.clock.clone();
        let (_, mut explicitly_expired) = prepared.into_parts();
        clock.advance(60);
        assert_eq!(explicitly_expired.expire(), Ok(()));
        assert!(matches!(
            explicitly_expired.finish(&callback),
            Err(OAuthError::AlreadyConsumed)
        ));
    }

    #[test]
    fn concurrent_sessions_remain_isolated() {
        let first = make_prepared(10);
        let second = make_prepared(20);
        let first_callback = make_callback(first.authorization_url(), "first-code");
        let second_callback = make_callback(second.authorization_url(), "second-code");
        let (_, mut first_session) = first.into_parts();
        let (_, mut second_session) = second.into_parts();
        assert_eq!(
            first_session.finish(&first_callback).unwrap().code(),
            "first-code"
        );
        assert_eq!(
            second_session.finish(&second_callback).unwrap().code(),
            "second-code"
        );
    }
}
