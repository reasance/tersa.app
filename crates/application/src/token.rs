// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Implements the portable token exchange and refresh state machine.
//!
//! This module models the token endpoint conversation as I/O-free structured
//! data: request values describe the endpoint POST parameters, a
//! `TokenTransport` port sends them, and the state machine interprets parsed
//! responses into typed outcomes. It intentionally does not encode wire
//! formats, perform HTTP, parse JSON, persist tokens, or revoke consent.
//! Platform adapters own the transport; the composition owns persistence and
//! re-connect routing.

use std::fmt;
use std::time::Duration;

use tersa_domain::account::AccountCapability;
use url::Url;
use zeroize::Zeroizing;

use crate::mailbox::BoxFuture;
use crate::oauth::{AuthorizationGrant, MonotonicClock};
use crate::scope::{AcceptedScope, ScopeEvidence, ScopeRejection};

mod capability;
#[doc(inline)]
pub use capability::{
    CapabilityRefreshOutcome, RefreshRevocationHandle, StoredGrantSnapshot,
    exchange_capability_grant, refresh_stored_grant,
};

// Rust guideline compliant 1.0.

/// Configures the OAuth client identity presented to the token endpoint.
#[derive(Clone)]
pub struct TokenClientConfig {
    client_id: String,
    redirect_uri: Url,
    client_secret: Option<Zeroizing<String>>,
}

impl TokenClientConfig {
    /// Creates a validated token client configuration.
    ///
    /// The client secret is optional because the Desktop client posture is
    /// resolved empirically before the request shape freezes: both the
    /// secret-required and secret-absent shapes stay representable, and any
    /// secret sent is the non-confidential Desktop client value.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError::InvalidConfiguration`] when the client identifier
    /// is blank, the redirect contains credentials, a query, or a fragment, or
    /// a present client secret is blank.
    pub fn new<T: Into<String>>(
        client_id: T,
        redirect_uri: Url,
        client_secret: Option<Zeroizing<String>>,
    ) -> Result<Self, TokenError> {
        let client_id = client_id.into();
        let has_credentials =
            !redirect_uri.username().is_empty() || redirect_uri.password().is_some();
        let blank_secret = client_secret
            .as_ref()
            .is_some_and(|secret| secret.trim().is_empty());
        if client_id.trim().is_empty()
            || has_credentials
            || redirect_uri.query().is_some()
            || redirect_uri.fragment().is_some()
            || blank_secret
        {
            return Err(TokenError::InvalidConfiguration);
        }

        Ok(Self {
            client_id,
            redirect_uri,
            client_secret,
        })
    }

    /// Returns the public OAuth client identifier.
    #[must_use]
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// Returns the exact registered redirect URI.
    #[must_use]
    pub fn redirect_uri(&self) -> &Url {
        &self.redirect_uri
    }

    /// Returns the optional non-confidential client secret.
    #[must_use]
    pub fn client_secret(&self) -> Option<&Zeroizing<String>> {
        self.client_secret.as_ref()
    }
}

impl fmt::Debug for TokenClientConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TokenClientConfig")
            .field("client_id", &self.client_id)
            .field("redirect_uri", &self.redirect_uri)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_secret| "[REDACTED]"),
            )
            .finish()
    }
}

/// Describes an authorization-code exchange as ordered endpoint parameters.
///
/// The parameters are structured data for a transport to encode, never wire
/// bytes: no percent- or form-encoding happens here.
pub struct ExchangeRequest {
    code: Zeroizing<String>,
    code_verifier: Zeroizing<String>,
    client_id: String,
    redirect_uri: Url,
    client_secret: Option<Zeroizing<String>>,
    requested_capability: AccountCapability,
}

impl ExchangeRequest {
    fn new(grant: &AuthorizationGrant, config: &TokenClientConfig) -> Self {
        Self {
            code: Zeroizing::new(grant.code().to_owned()),
            code_verifier: Zeroizing::new(grant.verifier().to_owned()),
            client_id: config.client_id().to_owned(),
            redirect_uri: config.redirect_uri().clone(),
            client_secret: config.client_secret().cloned(),
            requested_capability: grant.requested_capability(),
        }
    }

    /// Returns the capability bound to the validated authorization grant.
    #[must_use]
    pub fn requested_capability(&self) -> AccountCapability {
        self.requested_capability
    }

    /// Returns the ordered parameters a transport encodes for the endpoint.
    ///
    /// `client_secret` is emitted last and only when configured, so the
    /// secret-present and secret-absent shapes share one parameter prefix.
    #[must_use]
    pub fn parameters(&self) -> Vec<(&'static str, Zeroizing<String>)> {
        let mut parameters = vec![
            (
                "grant_type",
                Zeroizing::new("authorization_code".to_owned()),
            ),
            ("code", self.code.clone()),
            ("code_verifier", self.code_verifier.clone()),
            ("client_id", Zeroizing::new(self.client_id.clone())),
            (
                "redirect_uri",
                Zeroizing::new(self.redirect_uri.as_str().to_owned()),
            ),
        ];
        if let Some(secret) = &self.client_secret {
            parameters.push(("client_secret", secret.clone()));
        }
        parameters
    }
}

impl fmt::Debug for ExchangeRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExchangeRequest")
            .field("requested_capability", &self.requested_capability)
            .field("code", &"[REDACTED]")
            .field("code_verifier", &"[REDACTED]")
            .field("client_id", &self.client_id)
            .field("redirect_uri", &self.redirect_uri)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_secret| "[REDACTED]"),
            )
            .finish()
    }
}

/// Describes a refresh-token exchange as ordered endpoint parameters.
///
/// The parameters are structured data for a transport to encode, never wire
/// bytes: no percent- or form-encoding happens here.
pub struct RefreshRequest {
    refresh_token: Zeroizing<String>,
    client_id: String,
    client_secret: Option<Zeroizing<String>>,
    stored_capability: AccountCapability,
}

impl RefreshRequest {
    fn new(refresh_token: &Zeroizing<String>, config: &TokenClientConfig) -> Self {
        Self {
            refresh_token: refresh_token.clone(),
            client_id: config.client_id().to_owned(),
            client_secret: config.client_secret().cloned(),
            stored_capability: AccountCapability::ReadOnly,
        }
    }

    /// Returns the trusted stored capability; refresh never asks to broaden it.
    #[must_use]
    pub fn stored_capability(&self) -> AccountCapability {
        self.stored_capability
    }

    /// Returns the ordered parameters a transport encodes for the endpoint.
    ///
    /// `client_secret` is emitted last and only when configured, so the
    /// secret-present and secret-absent shapes share one parameter prefix.
    #[must_use]
    pub fn parameters(&self) -> Vec<(&'static str, Zeroizing<String>)> {
        let mut parameters = vec![
            ("grant_type", Zeroizing::new("refresh_token".to_owned())),
            ("refresh_token", self.refresh_token.clone()),
            ("client_id", Zeroizing::new(self.client_id.clone())),
        ];
        if let Some(secret) = &self.client_secret {
            parameters.push(("client_secret", secret.clone()));
        }
        parameters
    }
}

impl fmt::Debug for RefreshRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RefreshRequest")
            .field("stored_capability", &self.stored_capability)
            .field("refresh_token", &"[REDACTED]")
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_secret| "[REDACTED]"),
            )
            .finish()
    }
}

/// Reports why a broker-supplied subject failed the boundary re-check.
///
/// A small closed set that never echoes any part of the subject: the value is
/// account-identifying and must never be logged or displayed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BrokerSubjectError {
    /// The subject was empty.
    Empty,
    /// The subject exceeded the accepted UTF-8 byte cap.
    Oversized,
    /// The subject carried whitespace, control, or non-ASCII characters.
    InvalidCharacters,
}

impl fmt::Display for BrokerSubjectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Empty => "the broker reply carried an empty account subject",
            Self::Oversized => "the broker reply carried an oversized account subject",
            Self::InvalidCharacters => "the broker reply carried a subject with invalid characters",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for BrokerSubjectError {}

/// The immutable `OpenID` Connect subject (`sub`) of the connected account.
///
/// Not a secret, but account-identifying: held in zeroizing memory, redacted in
/// `Debug`, and never logged or displayed. It is the account-identity gate input
/// (a stable per-`(issuer, client)` identifier that Google never reuses), unlike
/// an email address, which is mutable and reusable.
pub struct AccountSubject(Zeroizing<String>);

impl AccountSubject {
    /// Wraps a validated subject.
    ///
    /// Deliberately crate-private: the only producers are
    /// [`validate_account_subject`] and the ADR-0024 broker boundary
    /// [`Self::from_broker_validated`], so an [`AccountSubject`] is proof the
    /// subject passed a trusted validation. The identity gate must be fed a
    /// subject only via [`TokenSuccess::subject`] or that broker boundary (never
    /// a hand-minted one), so a caller cannot fabricate an unvalidated identity.
    #[must_use]
    pub(crate) fn new(subject: Zeroizing<String>) -> Self {
        Self(subject)
    }

    /// Wraps a subject already validated by the ADR-0024 token broker.
    ///
    /// This is ONLY the trusted broker boundary, not general OIDC validation:
    /// the separately signed token broker verified the `id_token` (issuer,
    /// audience, signature) and hands this process the `sub` out of band. This
    /// constructor re-checks the value's SHAPE conservatively — non-empty, at
    /// most 255 UTF-8 bytes, printable non-whitespace ASCII
    /// only — and performs NO OIDC validation, so it must never be fed a
    /// subject the broker did not validate. A Google `sub` is a short ASCII
    /// digit string; the printable-ASCII band is deliberately wider than that
    /// but still rejects whitespace, control, and non-ASCII input.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerSubjectError`] naming the failed check without echoing
    /// any part of the subject.
    pub fn from_broker_validated(subject: Zeroizing<String>) -> Result<Self, BrokerSubjectError> {
        if subject.is_empty() {
            return Err(BrokerSubjectError::Empty);
        }
        if subject.len() > MAX_SUBJECT_LEN {
            return Err(BrokerSubjectError::Oversized);
        }
        // Printable ASCII excluding the space (0x20): rejects every control
        // byte, DEL, every whitespace form, and every non-ASCII byte.
        if !subject.bytes().all(|byte| (0x21..=0x7E).contains(&byte)) {
            return Err(BrokerSubjectError::InvalidCharacters);
        }
        Ok(Self(subject))
    }

    /// Returns the subject without transferring ownership.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Constructs a subject from a raw value for tests in OTHER crates.
    ///
    /// Available only under `cfg(test)` or the `test-util` feature, so production
    /// callers still cannot mint an unvalidated subject — the invariant that only
    /// `validate_account_subject` produces one holds in shipped code.
    #[cfg(any(test, feature = "test-util"))]
    #[must_use]
    pub fn from_raw_for_test(subject: Zeroizing<String>) -> Self {
        Self(subject)
    }
}

impl fmt::Debug for AccountSubject {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AccountSubject([REDACTED])")
    }
}

/// The identity claims decoded from an `id_token`, BEFORE semantic validation.
///
/// The transport decodes these from the token-endpoint response body — received
/// over its hardened TLS channel directly from the token endpoint, never from a
/// front channel — so the signature is not verified (the TLS origin authenticates
/// the issuer). The application layer validates `audience` and `issuer` before
/// trusting `subject`; an unvalidated value must never reach the gate.
#[derive(Clone)]
pub struct IdTokenClaims {
    subject: Zeroizing<String>,
    audiences: Vec<String>,
    issuer: String,
    authorized_party: Option<String>,
    issued_at: u64,
    expires_at: u64,
}

impl IdTokenClaims {
    /// Assembles decoded claims from the transport.
    ///
    /// `authorized_party` is the OIDC `azp` claim, required to trust an
    /// `id_token` whose `aud` carries audiences beyond the client identifier.
    /// `issued_at`/`expires_at` are the `iat`/`exp` Unix-second claims; their
    /// presence is a structural requirement (the transport rejects a token
    /// missing them), and their freshness is validated later against a wall clock
    /// in the concrete session — never in this monotonic-clock-only layer.
    #[must_use]
    pub fn new(
        subject: Zeroizing<String>,
        audiences: Vec<String>,
        issuer: String,
        authorized_party: Option<String>,
        issued_at: u64,
        expires_at: u64,
    ) -> Self {
        Self {
            subject,
            audiences,
            issuer,
            authorized_party,
            issued_at,
            expires_at,
        }
    }
}

impl fmt::Debug for IdTokenClaims {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IdTokenClaims")
            .field("subject", &"[REDACTED]")
            .field("audiences", &self.audiences.len())
            .field("issuer", &self.issuer)
            .field("authorized_party", &self.authorized_party)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// The `iat`/`exp` freshness window of an `id_token`, in Unix seconds.
///
/// Carried out of the token layer so the concrete session can validate it against
/// a wall clock. The check itself is pure arithmetic over a caller-supplied `now`,
/// so the token layer stays clock-free.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdentityExpiry {
    issued_at: u64,
    expires_at: u64,
}

impl IdentityExpiry {
    #[cfg(test)]
    fn new_for_test(issued_at: u64, expires_at: u64) -> Self {
        Self {
            issued_at,
            expires_at,
        }
    }

    /// Validates the token is fresh at `now` (Unix seconds) within `skew_secs`.
    ///
    /// Rejects an expired token (`now >= exp + skew`) and a future-minted one
    /// (`iat > now + skew`) with the non-destructive [`TokenError::IdentityUnverified`].
    ///
    /// # Errors
    ///
    /// Returns [`TokenError::IdentityUnverified`] when the token is expired or
    /// implausibly future-dated.
    pub fn validate_fresh(&self, now: u64, skew_secs: u64) -> Result<(), TokenError> {
        if now >= self.expires_at.saturating_add(skew_secs) {
            return Err(TokenError::IdentityUnverified);
        }
        if self.issued_at > now.saturating_add(skew_secs) {
            return Err(TokenError::IdentityUnverified);
        }
        Ok(())
    }
}

/// The accepted `OpenID` Connect issuers for Google-minted `id_token`s.
const GOOGLE_ISSUERS: &[&str] = &["accounts.google.com", "https://accounts.google.com"];

/// Caps the accepted subject length. A Google `sub` is ~21 digits.
const MAX_SUBJECT_LEN: usize = 255;

/// Carries an already-parsed token endpoint response.
///
/// The transport parses the response body; this value never holds wire bytes
/// or JSON. The optional refresh token models provider rotation. The optional
/// identity claims are present when the response carried an `id_token`.
/// Scope evidence preserves absence and explicit facts without provider text.
/// The legacy boolean constructor records its limited provenance explicitly.
pub struct TokenResponse {
    access_token: Zeroizing<String>,
    expires_in: Duration,
    rotated_refresh_token: Option<Zeroizing<String>>,
    id_token_claims: Option<IdTokenClaims>,
    scope_evidence: ScopeEvidence,
}

impl TokenResponse {
    /// Creates a readonly compatibility response with explicitly incomplete scope evidence.
    ///
    /// The boolean never counts as absent-field evidence and cannot authorize
    /// any capability-aware exchange or refresh, including a readonly one.
    #[must_use]
    pub fn new(
        access_token: Zeroizing<String>,
        expires_in: Duration,
        rotated_refresh_token: Option<Zeroizing<String>>,
        id_token_claims: Option<IdTokenClaims>,
        gmail_read_granted: bool,
    ) -> Self {
        Self {
            access_token,
            expires_in,
            rotated_refresh_token,
            id_token_claims,
            scope_evidence: ScopeEvidence::LegacyReadOnly {
                granted: gmail_read_granted,
            },
        }
    }

    /// Creates a response retaining the complete parser's scope-field provenance.
    ///
    /// Producers must reduce the actual field through
    /// [`ScopeEvidence::from_scope_field`]. This constructor performs no wire,
    /// scope, identity, freshness or grant-authority validation by itself.
    #[must_use]
    pub fn with_scope_evidence(
        access_token: Zeroizing<String>,
        expires_in: Duration,
        rotated_refresh_token: Option<Zeroizing<String>>,
        id_token_claims: Option<IdTokenClaims>,
        scope_evidence: ScopeEvidence,
    ) -> Self {
        Self {
            access_token,
            expires_in,
            rotated_refresh_token,
            id_token_claims,
            scope_evidence,
        }
    }

    /// Returns closed scope evidence, including any legacy producer limitation.
    #[must_use]
    pub fn scope_evidence(&self) -> ScopeEvidence {
        self.scope_evidence
    }

    /// Returns the granted access token without transferring ownership.
    ///
    /// Returns the `Zeroizing` wrapper so callers clone without minting a
    /// non-zeroizing plaintext copy of this hot secret.
    #[must_use]
    pub fn access_token(&self) -> &Zeroizing<String> {
        &self.access_token
    }

    /// Returns the access-token lifetime measured in seconds.
    #[must_use]
    pub fn expires_in(&self) -> Duration {
        self.expires_in
    }

    /// Returns the rotated refresh token when the provider rotated it.
    #[must_use]
    pub fn rotated_refresh_token(&self) -> Option<&Zeroizing<String>> {
        self.rotated_refresh_token.as_ref()
    }

    /// Returns the readonly compatibility verdict, never Modify authorization.
    ///
    /// This lossy view must not be used in capability-aware flows.
    #[must_use]
    pub fn gmail_read_granted(&self) -> bool {
        self.scope_evidence.validate_readonly_compat().is_ok()
    }

    /// Separates readonly compatibility fields, intentionally losing scope provenance.
    ///
    /// Capability-aware processing must retain [`Self::scope_evidence`] instead.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        Zeroizing<String>,
        Duration,
        Option<Zeroizing<String>>,
        Option<IdTokenClaims>,
        bool,
    ) {
        let gmail_read_granted = self.gmail_read_granted();
        (
            self.access_token,
            self.expires_in,
            self.rotated_refresh_token,
            self.id_token_claims,
            gmail_read_granted,
        )
    }
}

impl fmt::Debug for TokenResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TokenResponse")
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
            .field("scope_evidence", &self.scope_evidence)
            .finish()
    }
}

/// Sends token requests to the provider token endpoint.
///
/// Implementations own the wire encoding, the HTTP exchange, and response
/// parsing; this layer supplies structured parameters and consumes parsed
/// values only.
/// Capability-aware producers must use [`TokenResponse::with_scope_evidence`]
/// with the actual parsed field's presence. The boolean constructor is limited
/// to readonly compatibility and fails closed in capability-aware operations.
pub trait TokenTransport: fmt::Debug + Send + Sync {
    /// Exchanges an authorization-code request for a token response.
    ///
    /// The port is asynchronous and runtime-agnostic (a [`BoxFuture`], matching
    /// the crate's other network ports), so the composition-owned current-thread
    /// runtime drives it without a nested `block_on`.
    ///
    /// # Errors
    ///
    /// Resolves to a typed transport or protocol failure without provider data.
    fn exchange(
        &self,
        request: ExchangeRequest,
    ) -> BoxFuture<'_, Result<TokenResponse, TokenTransportError>>;

    /// Exchanges a refresh-token request for a token response.
    ///
    /// # Errors
    ///
    /// Resolves to a typed transport or protocol failure without provider data.
    fn refresh(
        &self,
        request: RefreshRequest,
    ) -> BoxFuture<'_, Result<TokenResponse, TokenTransportError>>;

    /// Revokes a token at the provider's revocation endpoint, best-effort.
    ///
    /// Callers treat revocation as best-effort and never gate local state on it
    /// succeeding, but the two call paths differ materially: the ADR-0023
    /// disconnect composition still deletes the local token when this call
    /// fails, while the connect flow's cancel fences store nothing (or delete
    /// the just-stored token first), so a permanently-failed revoke THERE
    /// leaves a live token at the provider with no in-app remedy — the fences
    /// therefore retry once before giving up.
    ///
    /// # Errors
    ///
    /// Resolves to a typed transport or protocol failure without provider data.
    /// A well-formed answer that the submitted token is unknown or already
    /// invalid at the provider (Google's HTTP 400 `invalid_token`) resolves to
    /// [`TokenTransportError::InvalidToken`], so a caller can confirm the
    /// desired end state for an already-gone grant.
    #[must_use]
    fn revoke<'a>(
        &'a self,
        token: &'a Zeroizing<String>,
    ) -> BoxFuture<'a, Result<(), TokenTransportError>>;
}

/// Describes a token transport or protocol failure without provider data.
///
/// Variants never carry echoed request parameters or response bodies: the
/// parsing transport reduces provider error bodies to bare variants.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum TokenTransportError {
    /// The request could not be delivered or no response arrived.
    Transport,
    /// The endpoint answered the well-formed `invalid_grant` error.
    InvalidGrant,
    /// The endpoint answered the well-formed `invalid_token` error: the
    /// submitted token is unknown or already invalid at the provider.
    ///
    /// Only a revocation endpoint emits this answer in practice (Google
    /// answers HTTP 400 `invalid_token` when asked to revoke an unknown or
    /// already-revoked token). The exchange and refresh state machines
    /// therefore map it to the conservative [`TokenError::ProviderRejected`];
    /// revoke callers may treat it as confirmation that the grant is already
    /// gone.
    InvalidToken,
    /// The endpoint answered any other well-formed error.
    ProviderRejected,
    /// The response did not parse into a complete token response.
    MalformedResponse,
}

impl fmt::Display for TokenTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Transport => "the token endpoint could not be reached",
            Self::InvalidGrant => "the token endpoint reported an invalid grant",
            Self::InvalidToken => "the endpoint reported an unknown or invalid token",
            Self::ProviderRejected => "the token endpoint rejected the request",
            Self::MalformedResponse => "the token endpoint returned an incomplete response",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for TokenTransportError {}

/// Describes a terminal token lifecycle failure without sensitive values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum TokenError {
    /// A required configuration value is absent or unusable.
    InvalidConfiguration,
    /// The token endpoint could not be reached.
    Transport,
    /// The provider rejected the request with an error other than a
    /// refresh-time `invalid_grant` (which is [`Self::ConsentRevoked`]) or an
    /// exchange-time `invalid_grant` (which is
    /// [`Self::AuthorizationCodeRejected`]).
    ProviderRejected,
    /// The token endpoint answered the authorization-code EXCHANGE with
    /// `invalid_grant`: the authorization code was stale, already redeemed,
    /// or mismatched, so the sign-in itself lapsed and must be re-run.
    ///
    /// Only the EXCHANGE path produces this terminal. It is non-destructive —
    /// no stored credential exists on that path, so it is never a deletion
    /// license and never [`Self::ConsentRevoked`] — but it is also NOT an
    /// ordinary retryable rejection: the connect composition routes it to the
    /// re-connect ("sign in again") recovery, not to a bare retry.
    AuthorizationCodeRejected,
    /// The endpoint response did not parse into a complete token response.
    MalformedResponse,
    /// Explicit scope evidence does not satisfy the bound requested capability.
    InsufficientScope,
    /// The transport or selected compatibility flow supplies no complete scope evidence.
    ScopeEvidenceUnavailable,
    /// A refresh response identifies a different subject than the trusted stored grant.
    IdentityMismatch,
    /// The stored refresh token lost validity at the provider — consent was
    /// withdrawn or the token expired — and re-consent is required.
    ///
    /// Only the REFRESH path produces this terminal: a refresh-time
    /// `invalid_grant` answers about a persisted credential, which the
    /// composition deletes before reporting. An exchange-time `invalid_grant`
    /// maps to [`Self::AuthorizationCodeRejected`] instead, because no stored
    /// credential exists to delete for a stale authorization code.
    ConsentRevoked,
    /// The token op succeeded but its `id_token` was absent or failed identity
    /// validation (`aud`/`iss`/`sub`).
    ///
    /// This is deliberately DISTINCT from [`Self::ConsentRevoked`]: it is
    /// non-destructive. The refresh token stays valid and stored — the sync is
    /// blocked and the op may be retried, rather than the credential being
    /// deleted for a merely missing claim.
    IdentityUnverified,
}

impl fmt::Display for TokenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidConfiguration => "invalid token client configuration",
            Self::Transport => "the token endpoint could not be reached",
            Self::ProviderRejected => "the token endpoint rejected the request",
            Self::AuthorizationCodeRejected => "the authorization code was rejected; sign in again",
            Self::MalformedResponse => "the token endpoint returned an incomplete response",
            Self::InsufficientScope => "the token grant does not match the required capability",
            Self::ScopeEvidenceUnavailable => "complete capability scope evidence is unavailable",
            Self::IdentityMismatch => {
                "the refreshed account identity does not match the stored grant"
            }
            Self::ConsentRevoked => "the granted consent was revoked and re-connect is required",
            Self::IdentityUnverified => "the token response carried no verified account identity",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for TokenError {}

/// Holds an access token and its monotonic expiry deadline.
///
/// The access token is in-memory only and never persisted. `expires_at` is a
/// monotonic `Duration` comparable only against the same [`MonotonicClock`]
/// origin that minted it (a fresh origin per process); it must never be
/// persisted across restarts or compared against a different clock.
pub struct AccessToken {
    secret: Zeroizing<String>,
    expires_at: Duration,
}

impl AccessToken {
    /// Returns the access token without transferring ownership.
    ///
    /// Returns the `Zeroizing` wrapper so callers clone without minting a
    /// non-zeroizing plaintext copy of this hot secret.
    #[must_use]
    pub fn secret(&self) -> &Zeroizing<String> {
        &self.secret
    }

    /// Returns the monotonic deadline after which the token is expired.
    ///
    /// Comparable only against the originating clock; never persist it.
    #[must_use]
    pub fn expires_at(&self) -> Duration {
        self.expires_at
    }
}

impl fmt::Debug for AccessToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccessToken")
            .field("secret", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Carries a granted access token, any rotated refresh token, the validated
/// account subject, accepted capability and scope provenance.
///
/// A validated [`AccountSubject`] is MANDATORY to construct: a token op that
/// yields an access token but no verified `sub` fails entirely
/// ([`TokenError::IdentityUnverified`]). This is structural — the access token
/// and the identity gate's `sub` therefore always originate from the SAME token
/// response, and no path can drive a sync with an access token whose account
/// identity was never verified.
pub struct TokenSuccess {
    access_token: AccessToken,
    rotated_refresh_token: Option<Zeroizing<String>>,
    subject: AccountSubject,
    identity_expiry: IdentityExpiry,
    accepted_scope: AcceptedScope,
}

impl TokenSuccess {
    fn from_parts(
        access_token: Zeroizing<String>,
        expires_in: Duration,
        rotated_refresh_token: Option<Zeroizing<String>>,
        id_token_claims: Option<IdTokenClaims>,
        accepted_scope: AcceptedScope,
        now: Duration,
        config: &TokenClientConfig,
    ) -> Result<Self, TokenError> {
        if access_token.is_empty() {
            return Err(TokenError::MalformedResponse);
        }
        // `expires_in` is provider-controlled (parsed by the transport), so an
        // overflow is a malformed response, not a client-configuration fault.
        let expires_at = now
            .checked_add(expires_in)
            .ok_or(TokenError::MalformedResponse)?;
        let (subject, identity_expiry) = validate_account_subject(id_token_claims, config)?;
        Ok(Self {
            access_token: AccessToken {
                secret: access_token,
                expires_at,
            },
            rotated_refresh_token,
            subject,
            identity_expiry,
            accepted_scope,
        })
    }

    /// Returns the granted access token with its monotonic expiry.
    #[must_use]
    pub fn access_token(&self) -> &AccessToken {
        &self.access_token
    }

    /// Returns the validated subject of the account this token grants access to.
    #[must_use]
    pub fn subject(&self) -> &AccountSubject {
        &self.subject
    }

    /// Returns the `id_token`'s Unix-second freshness window, for the session to
    /// validate against a wall clock.
    #[must_use]
    pub fn identity_expiry(&self) -> IdentityExpiry {
        self.identity_expiry
    }

    /// Returns the rotated refresh token when the provider rotated it.
    ///
    /// Google may return a new refresh token on exchange or refresh; its
    /// presence replaces the stored token and its absence keeps it.
    #[must_use]
    pub fn rotated_refresh_token(&self) -> Option<&Zeroizing<String>> {
        self.rotated_refresh_token.as_ref()
    }

    /// Returns the accepted capability, bound to request or trusted stored context.
    #[must_use]
    pub fn capability(&self) -> AccountCapability {
        self.accepted_scope.capability()
    }

    /// Returns accepted scope provenance, including readonly compatibility limitations.
    #[must_use]
    pub fn accepted_scope(&self) -> AcceptedScope {
        self.accepted_scope
    }

    /// Returns readable-token compatibility, never a separate Modify authority proof.
    #[must_use]
    pub fn gmail_read_granted(&self) -> bool {
        true
    }

    /// Separates the access token, any rotated refresh token, the subject, and the
    /// identity freshness window.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        AccessToken,
        Option<Zeroizing<String>>,
        AccountSubject,
        IdentityExpiry,
        bool,
    ) {
        (
            self.access_token,
            self.rotated_refresh_token,
            self.subject,
            self.identity_expiry,
            true,
        )
    }

    /// Separates success while retaining accepted capability and scope provenance.
    #[must_use]
    pub fn into_capability_parts(
        self,
    ) -> (
        AccessToken,
        Option<Zeroizing<String>>,
        AccountSubject,
        IdentityExpiry,
        AcceptedScope,
    ) {
        (
            self.access_token,
            self.rotated_refresh_token,
            self.subject,
            self.identity_expiry,
            self.accepted_scope,
        )
    }
}

/// Preserves provider tokens needed to handle an explicitly under-scoped token
/// operation without stranding its grant.
///
/// The insufficient-scope outcome is decided before `id_token` identity
/// validation. This lets the lifecycle revoke a grant it must reject even when
/// the same response omitted or malformed its identity claims. The secret is
/// zeroized on drop and never exposed by `Debug`.
pub enum TokenScopeOutcome {
    /// The response carried Gmail read access and a verified account identity.
    Granted(TokenSuccess),
    /// The response explicitly omitted Gmail read access; its tokens remain
    /// available for provider revocation or refresh-token rotation handling.
    InsufficientScope {
        /// The access token minted by the under-scoped operation.
        access_token: Zeroizing<String>,
        /// A rotated refresh token, when the provider returned one.
        rotated_refresh_token: Option<Zeroizing<String>>,
    },
}

impl fmt::Debug for TokenScopeOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Granted(success) => formatter.debug_tuple("Granted").field(success).finish(),
            Self::InsufficientScope {
                access_token: _access_token,
                rotated_refresh_token,
            } => formatter
                .debug_struct("InsufficientScope")
                .field("access_token", &"[REDACTED]")
                .field(
                    "rotated_refresh_token",
                    &rotated_refresh_token.as_ref().map(|_token| "[REDACTED]"),
                )
                .finish(),
        }
    }
}

fn scope_outcome_from_response(
    response: TokenResponse,
    now: Duration,
    config: &TokenClientConfig,
) -> Result<TokenScopeOutcome, TokenError> {
    let TokenResponse {
        access_token,
        expires_in,
        rotated_refresh_token,
        id_token_claims,
        scope_evidence,
    } = response;
    if access_token.is_empty() {
        return Err(TokenError::MalformedResponse);
    }
    let Ok(accepted_scope) = scope_evidence.validate_readonly_compat() else {
        return Ok(TokenScopeOutcome::InsufficientScope {
            access_token,
            rotated_refresh_token,
        });
    };
    TokenSuccess::from_parts(
        access_token,
        expires_in,
        rotated_refresh_token,
        id_token_claims,
        accepted_scope,
        now,
        config,
    )
    .map(TokenScopeOutcome::Granted)
}

/// Validates decoded `id_token` claims and extracts the account subject.
///
/// Returns [`TokenError::IdentityUnverified`] — never a destructive terminal —
/// when the claims are absent, minted for another client (`aud`), issued by a
/// non-Google issuer (`iss`), or carry an empty or oversized `sub`. The
/// `id_token` signature is intentionally NOT verified: it is only ever received
/// over the transport's hardened TLS channel directly from the token endpoint,
/// which authenticates the issuer (OIDC Core 3.1.3.7). The `aud == client_id`
/// check is what makes that decode-only posture sound.
fn validate_account_subject(
    claims: Option<IdTokenClaims>,
    config: &TokenClientConfig,
) -> Result<(AccountSubject, IdentityExpiry), TokenError> {
    let claims = claims.ok_or(TokenError::IdentityUnverified)?;
    let client_id = config.client_id();
    // A single audience must equal this client. An id_token carrying additional
    // audiences is trusted only when `azp` names this client (OIDC Core 3.1.3.7):
    // otherwise a token minted for another client that merely lists this one is
    // rejected.
    let single_exact_audience = claims.audiences.len() == 1 && claims.audiences[0] == client_id;
    let multi_audience_authorized = claims
        .audiences
        .iter()
        .any(|audience| audience == client_id)
        && claims.authorized_party.as_deref() == Some(client_id);
    if !(single_exact_audience || multi_audience_authorized) {
        return Err(TokenError::IdentityUnverified);
    }
    if !GOOGLE_ISSUERS.contains(&claims.issuer.as_str()) {
        return Err(TokenError::IdentityUnverified);
    }
    let subject = claims.subject.trim();
    if subject.is_empty() || subject.len() > MAX_SUBJECT_LEN {
        return Err(TokenError::IdentityUnverified);
    }
    // Store the trimmed subject so a padded value cannot hash differently than
    // the same account's un-padded value.
    let subject = AccountSubject::new(Zeroizing::new(subject.to_owned()));
    // `exp`/`iat` presence is guaranteed structurally by the transport parse; the
    // freshness comparison happens later in the session against a wall clock.
    let identity_expiry = IdentityExpiry {
        issued_at: claims.issued_at,
        expires_at: claims.expires_at,
    };
    Ok((subject, identity_expiry))
}

impl fmt::Debug for TokenSuccess {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TokenSuccess")
            .field("access_token", &self.access_token)
            .field(
                "rotated_refresh_token",
                &self
                    .rotated_refresh_token
                    .as_ref()
                    .map(|_token| "[REDACTED]"),
            )
            .field("subject", &self.subject)
            .field("identity_expiry", &self.identity_expiry)
            .field("accepted_scope", &self.accepted_scope)
            .finish()
    }
}

/// Exchanges a validated authorization grant for a token success.
///
/// This is a readonly compatibility API. Modify grants fail before transport;
/// use [`exchange_capability_grant`] for capability-aware response processing.
///
/// Builds the authorization-code request from the grant and client
/// configuration, sends it through the transport, and interprets the outcome.
/// An `invalid_grant` protocol answer maps to
/// [`TokenError::AuthorizationCodeRejected`]: on the exchange it means the
/// authorization code was stale, already redeemed, or mismatched — the
/// sign-in lapsed and must be re-run. No stored credential exists on this
/// path, so the terminal is non-destructive and never the deletion-licensing
/// [`TokenError::ConsentRevoked`], which is reserved for the refresh path
/// (see [`refresh_access_token`]).
///
/// # Errors
///
/// Returns [`TokenError::AuthorizationCodeRejected`] when the provider
/// answered the exchange with `invalid_grant` (a stale or used authorization
/// code), [`TokenError::ProviderRejected`] for any other provider rejection,
/// [`TokenError::Transport`] when the endpoint is unreachable, and
/// [`TokenError::MalformedResponse`] for an unparsable response.
pub fn exchange_grant<'a, T: TokenTransport, C: MonotonicClock>(
    grant: &AuthorizationGrant,
    config: &'a TokenClientConfig,
    transport: &'a T,
    clock: &'a C,
) -> BoxFuture<'a, Result<TokenSuccess, TokenError>> {
    let outcome = exchange_grant_with_scope_outcome(grant, config, transport, clock);
    Box::pin(async move {
        match outcome.await? {
            TokenScopeOutcome::Granted(success) => Ok(success),
            TokenScopeOutcome::InsufficientScope { .. } => Err(TokenError::InsufficientScope),
        }
    })
}

/// Exchanges a validated authorization grant while preserving a revocation
/// handle for an explicitly under-scoped response.
///
/// Unlike [`exchange_grant`], this lifecycle-oriented variant reports
/// insufficient scope before validating `id_token` claims. A caller that will
/// reject a first-time grant can therefore revoke it without persisting any
/// credential, even if identity validation would also fail.
/// This is readonly compatibility only; Modify grants fail before transport.
/// Retention/revocation still requires the owning lifecycle's trusted identity
/// context; this legacy result is not permission for unverified-grant cleanup.
///
/// # Errors
///
/// Returns the same transport, provider, and malformed-response errors as
/// [`exchange_grant`]. Identity validation is applied only to responses whose
/// explicit scope verdict includes Gmail read access.
pub fn exchange_grant_with_scope_outcome<'a, T: TokenTransport, C: MonotonicClock>(
    grant: &AuthorizationGrant,
    config: &'a TokenClientConfig,
    transport: &'a T,
    clock: &'a C,
) -> BoxFuture<'a, Result<TokenScopeOutcome, TokenError>> {
    let request = ExchangeRequest::new(grant, config);
    let requested_capability = grant.requested_capability();
    Box::pin(async move {
        if requested_capability != AccountCapability::ReadOnly {
            return Err(TokenError::ScopeEvidenceUnavailable);
        }
        let response = transport
            .exchange(request)
            .await
            .map_err(map_exchange_transport_error)?;
        scope_outcome_from_response(response, clock.now(), config)
    })
}

/// Refreshes an access token using the stored refresh token.
///
/// This is readonly compatibility only. Capability-aware refresh must use
/// [`refresh_stored_grant`] with a trusted token/subject/capability snapshot.
///
/// Builds the refresh-token request from the stored token and client
/// configuration, sends it through the transport, and interprets the outcome.
/// Unlike the exchange path, a refresh-time `invalid_grant` answers about the
/// STORED credential, so it maps to the destructive
/// [`TokenError::ConsentRevoked`] terminal the composition routes to
/// re-connect after deleting the dead credential.
///
/// # Errors
///
/// Returns [`TokenError::ConsentRevoked`] when consent was withdrawn or the
/// refresh token expired, [`TokenError::Transport`] when the endpoint is
/// unreachable, [`TokenError::ProviderRejected`] for any other provider error,
/// and [`TokenError::MalformedResponse`] for an unparsable response.
pub fn refresh_access_token<'a, T: TokenTransport, C: MonotonicClock>(
    refresh_token: &Zeroizing<String>,
    config: &'a TokenClientConfig,
    transport: &'a T,
    clock: &'a C,
) -> BoxFuture<'a, Result<TokenSuccess, TokenError>> {
    let outcome = refresh_access_token_with_scope_outcome(refresh_token, config, transport, clock);
    Box::pin(async move {
        match outcome.await? {
            TokenScopeOutcome::Granted(success) => Ok(success),
            TokenScopeOutcome::InsufficientScope { .. } => Err(TokenError::InsufficientScope),
        }
    })
}

/// Refreshes an access token while preserving any rotated credential from an
/// explicitly under-scoped response.
///
/// This lifecycle-oriented variant lets the caller retain a rotated refresh
/// token before surfacing the permission error, so provider rotation cannot
/// leave the grant without a local revocation handle. Scope is decided before
/// `id_token` identity validation for the same reason as
/// [`exchange_grant_with_scope_outcome`].
///
/// # Errors
///
/// Returns the same transport, provider, and malformed-response errors as
/// [`refresh_access_token`]. Identity validation is applied only to responses
/// whose explicit scope verdict includes Gmail read access.
pub fn refresh_access_token_with_scope_outcome<'a, T: TokenTransport, C: MonotonicClock>(
    refresh_token: &Zeroizing<String>,
    config: &'a TokenClientConfig,
    transport: &'a T,
    clock: &'a C,
) -> BoxFuture<'a, Result<TokenScopeOutcome, TokenError>> {
    let request = RefreshRequest::new(refresh_token, config);
    Box::pin(async move {
        let response = transport
            .refresh(request)
            .await
            .map_err(map_transport_error)?;
        scope_outcome_from_response(response, clock.now(), config)
    })
}

fn map_transport_error(error: TokenTransportError) -> TokenError {
    match error {
        TokenTransportError::Transport => TokenError::Transport,
        TokenTransportError::InvalidGrant => TokenError::ConsentRevoked,
        // `invalid_token` is a revocation-endpoint answer; if a transport ever
        // surfaces it on exchange or refresh it is an ordinary provider
        // rejection, never a license to delete a stored credential.
        TokenTransportError::InvalidToken | TokenTransportError::ProviderRejected => {
            TokenError::ProviderRejected
        }
        TokenTransportError::MalformedResponse => TokenError::MalformedResponse,
    }
}

/// Maps a transport failure in the authorization-code exchange context.
///
/// An `invalid_grant` answer here means the authorization code was stale,
/// already redeemed, or mismatched — NOT that a stored refresh token lost
/// consent — so it maps to [`TokenError::AuthorizationCodeRejected`]: the
/// non-destructive sign-in-expired terminal the connect composition routes to
/// the re-connect recovery. It is deliberately distinct both from
/// [`TokenError::ConsentRevoked`], which the compositions treat as a license
/// to delete a stored credential (none exists on this path), and from
/// [`TokenError::ProviderRejected`], which is an ordinary retryable
/// rejection. The refresh path keeps the `invalid_grant` →
/// [`TokenError::ConsentRevoked`] mapping via [`map_transport_error`].
fn map_exchange_transport_error(error: TokenTransportError) -> TokenError {
    match error {
        TokenTransportError::InvalidGrant => TokenError::AuthorizationCodeRejected,
        other => map_transport_error(other),
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "test fixtures use static URLs and assert setup success before behavior"
    )]

    use std::fmt;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll, Waker};
    use std::time::Duration;

    use url::Url;
    use zeroize::Zeroizing;

    use super::{
        AccountSubject, BrokerSubjectError, ExchangeRequest, IdTokenClaims, RefreshRequest,
        TokenClientConfig, TokenError, TokenResponse, TokenTransport, TokenTransportError,
        exchange_grant, refresh_access_token,
    };
    use crate::mailbox::BoxFuture;
    use crate::oauth::{
        AuthorizationConfig, AuthorizationGrant, MonotonicClock, prepare_authorization,
    };
    use tersa_domain::account::AccountCapability;

    /// Drives an immediately-ready fake-transport future to completion.
    fn now_ready<T>(mut future: BoxFuture<'_, T>) -> T {
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("the fake transport future must be immediately ready"),
        }
    }

    #[derive(Clone, Debug, Default)]
    struct TestClock(Arc<AtomicU64>);

    impl MonotonicClock for TestClock {
        fn now(&self) -> Duration {
            Duration::from_secs(self.0.load(Ordering::Relaxed))
        }
    }

    #[derive(Debug)]
    enum RecordedRequest {
        Exchange(ExchangeRequest),
        Refresh(RefreshRequest),
    }

    impl RecordedRequest {
        fn parameters(&self) -> Vec<(&'static str, Zeroizing<String>)> {
            match self {
                Self::Exchange(request) => request.parameters(),
                Self::Refresh(request) => request.parameters(),
            }
        }
    }

    struct FakeTransport {
        error: Option<TokenTransportError>,
        rotated_refresh_token: Option<Zeroizing<String>>,
        id_token_claims: Option<IdTokenClaims>,
        recorded: Mutex<Vec<RecordedRequest>>,
        scope_evidence: Option<crate::scope::ScopeEvidence>,
        access_token: Zeroizing<String>,
        expires_in: Duration,
    }

    const TEST_SUBJECT: &str = "test-subject-123";

    const TEST_IAT: u64 = 1_000;
    const TEST_EXP: u64 = 5_000;

    fn valid_claims() -> IdTokenClaims {
        IdTokenClaims::new(
            Zeroizing::new(TEST_SUBJECT.to_owned()),
            vec!["public-test-client".to_owned()],
            "https://accounts.google.com".to_owned(),
            None,
            TEST_IAT,
            TEST_EXP,
        )
    }

    impl fmt::Debug for FakeTransport {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("FakeTransport")
                .field("scope_evidence", &self.scope_evidence)
                .field("access_token", &"[REDACTED]")
                .field("expires_in", &self.expires_in)
                .field("error", &self.error)
                .field(
                    "rotated_refresh_token",
                    &self
                        .rotated_refresh_token
                        .as_ref()
                        .map(|_token| "[REDACTED]"),
                )
                .field("id_token_claims", &self.id_token_claims)
                .field("recorded", &self.recorded)
                .finish()
        }
    }

    impl FakeTransport {
        fn success(rotated_refresh_token: Option<&str>) -> Self {
            Self {
                error: None,
                rotated_refresh_token: rotated_refresh_token
                    .map(|token| Zeroizing::new(token.to_owned())),
                id_token_claims: Some(valid_claims()),
                recorded: Mutex::new(Vec::new()),
                scope_evidence: None,
                access_token: Zeroizing::new("fake-access-token".to_owned()),
                expires_in: Duration::from_secs(3_600),
            }
        }

        fn failing(error: TokenTransportError) -> Self {
            Self {
                error: Some(error),
                rotated_refresh_token: None,
                id_token_claims: Some(valid_claims()),
                recorded: Mutex::new(Vec::new()),
                scope_evidence: None,
                access_token: Zeroizing::new("fake-access-token".to_owned()),
                expires_in: Duration::from_secs(3_600),
            }
        }

        fn with_id_token_claims(mut self, claims: Option<IdTokenClaims>) -> Self {
            self.id_token_claims = claims;
            self
        }

        fn with_scope_evidence(mut self, evidence: crate::scope::ScopeEvidence) -> Self {
            self.scope_evidence = Some(evidence);
            self
        }

        fn outcome(&self) -> Result<TokenResponse, TokenTransportError> {
            match self.error {
                Some(error) => Err(error),
                None => Ok(if let Some(evidence) = self.scope_evidence {
                    TokenResponse::with_scope_evidence(
                        self.access_token.clone(),
                        self.expires_in,
                        self.rotated_refresh_token.clone(),
                        self.id_token_claims.clone(),
                        evidence,
                    )
                } else {
                    TokenResponse::new(
                        self.access_token.clone(),
                        self.expires_in,
                        self.rotated_refresh_token.clone(),
                        self.id_token_claims.clone(),
                        true,
                    )
                }),
            }
        }
    }

    impl TokenTransport for FakeTransport {
        fn exchange(
            &self,
            request: ExchangeRequest,
        ) -> BoxFuture<'_, Result<TokenResponse, TokenTransportError>> {
            Box::pin(async move {
                self.recorded
                    .lock()
                    .unwrap()
                    .push(RecordedRequest::Exchange(request));
                self.outcome()
            })
        }

        fn refresh(
            &self,
            request: RefreshRequest,
        ) -> BoxFuture<'_, Result<TokenResponse, TokenTransportError>> {
            Box::pin(async move {
                self.recorded
                    .lock()
                    .unwrap()
                    .push(RecordedRequest::Refresh(request));
                self.outcome()
            })
        }

        fn revoke<'a>(
            &'a self,
            _token: &'a Zeroizing<String>,
        ) -> BoxFuture<'a, Result<(), TokenTransportError>> {
            Box::pin(async { Ok(()) })
        }
    }

    fn test_redirect() -> Url {
        Url::parse("app.tersa.oauth.test:/oauth/callback").unwrap()
    }

    fn make_config(client_secret: Option<&str>) -> TokenClientConfig {
        TokenClientConfig::new(
            "public-test-client",
            test_redirect(),
            client_secret.map(|secret| Zeroizing::new(secret.to_owned())),
        )
        .unwrap()
    }

    fn make_grant(code: &str) -> AuthorizationGrant {
        make_capability_grant(code, tersa_domain::account::AccountCapability::ReadOnly)
    }

    fn make_capability_grant(
        code: &str,
        capability: tersa_domain::account::AccountCapability,
    ) -> AuthorizationGrant {
        let config = AuthorizationConfig::for_capability(
            "public-test-client",
            test_redirect(),
            Duration::from_secs(60),
            capability,
        )
        .unwrap();
        let prepared = prepare_authorization(config, TestClock::default()).unwrap();
        let state = prepared
            .authorization_url()
            .query_pairs()
            .find_map(|(name, value)| (name == "state").then(|| value.into_owned()))
            .unwrap();
        let mut callback = test_redirect();
        callback
            .query_pairs_mut()
            .append_pair("state", &state)
            .append_pair("code", code);
        let (_, mut session) = prepared.into_parts();
        session.finish(&callback).unwrap()
    }

    fn stored_grant(capability: AccountCapability) -> super::StoredGrantSnapshot {
        super::StoredGrantSnapshot::new(
            Zeroizing::new("stored-refresh-sentinel".to_owned()),
            AccountSubject::from_broker_validated(Zeroizing::new(TEST_SUBJECT.to_owned())).unwrap(),
            capability,
        )
        .unwrap()
    }

    // Contract: exchange derives capability from the grant, retaining full provenance.
    // Regression: exchange drops request context or treats a Modify response as a boolean.
    #[test]
    fn capability_exchange_preserves_request_binding_and_scope_provenance() {
        use crate::scope::{GMAIL_MODIFY_SCOPE, GMAIL_READONLY_SCOPE, ScopeEvidence};
        let config = make_config(None);
        let clock = TestClock::default();
        let both = format!("{GMAIL_MODIFY_SCOPE} {GMAIL_READONLY_SCOPE}");
        for (capability, field) in [
            (AccountCapability::ReadOnly, None),
            (AccountCapability::Modify, None),
            (AccountCapability::Modify, Some(both.as_str())),
        ] {
            let grant = make_capability_grant("bound-code-sentinel", capability);
            let evidence = ScopeEvidence::from_scope_field(field).unwrap();
            let transport =
                FakeTransport::success(Some("rotation-sentinel")).with_scope_evidence(evidence);
            let success = now_ready(super::exchange_capability_grant(
                &grant, &config, &transport, &clock,
            ))
            .unwrap();
            assert_eq!(success.capability(), capability);
            assert_eq!(success.accepted_scope().evidence(), evidence);
            assert_eq!(success.subject().as_str(), TEST_SUBJECT);
            let recorded = transport.recorded.lock().unwrap();
            let RecordedRequest::Exchange(request) = &recorded[0] else {
                panic!("expected exchange");
            };
            assert_eq!(request.requested_capability(), capability);
            let (_, rotation, _, _, accepted) = success.into_capability_parts();
            assert_eq!(accepted.capability(), capability);
            assert_eq!(rotation.unwrap().as_str(), "rotation-sentinel");
        }
    }

    // Contract: legacy evidence is incomplete for BOTH capabilities; old APIs stay readonly.
    // Regression: a legacy true boolean is reinterpreted as absent scope or Modify authority.
    #[test]
    fn legacy_evidence_cannot_elevate_or_service_capability_flows() {
        use crate::scope::ScopeEvidence;
        let config = make_config(None);
        let clock = TestClock::default();
        for capability in [AccountCapability::ReadOnly, AccountCapability::Modify] {
            let grant = make_capability_grant("legacy-code", capability);
            let transport = FakeTransport::success(None);
            assert!(matches!(
                now_ready(super::exchange_capability_grant(
                    &grant, &config, &transport, &clock
                )),
                Err(TokenError::ScopeEvidenceUnavailable)
            ));
            assert!(matches!(
                now_ready(super::refresh_stored_grant(
                    &stored_grant(capability),
                    &config,
                    &transport,
                    &clock
                )),
                Err(TokenError::ScopeEvidenceUnavailable)
            ));
        }
        let transport = FakeTransport::success(None);
        let modify = make_capability_grant("modify-code", AccountCapability::Modify);
        assert!(matches!(
            now_ready(exchange_grant(&modify, &config, &transport, &clock)),
            Err(TokenError::ScopeEvidenceUnavailable)
        ));
        assert!(transport.recorded.lock().unwrap().is_empty());
        let readonly = now_ready(exchange_grant(
            &make_grant("readonly-code"),
            &config,
            &transport,
            &clock,
        ))
        .unwrap();
        assert_eq!(readonly.capability(), AccountCapability::ReadOnly);
        assert_eq!(
            readonly.accepted_scope().evidence(),
            ScopeEvidence::LegacyReadOnly { granted: true }
        );
    }

    // Contract: rejected exchange scopes expose no grant; rejected refresh exposes only rotation.
    // Regression: identity runs first, a readonly grant promotes, or rejected access escapes.
    #[test]
    fn scope_rejection_precedes_identity_and_retains_only_refresh_cleanup() {
        use crate::scope::{
            GMAIL_MODIFY_SCOPE, GMAIL_READONLY_SCOPE, ScopeEvidence, ScopeRejection,
        };
        let config = make_config(None);
        let clock = TestClock::default();
        let modify = make_capability_grant("modify-code", AccountCapability::Modify);
        for explicit in [GMAIL_READONLY_SCOPE, ""] {
            let reduced = FakeTransport::success(Some("discarded-rotation"))
                .with_id_token_claims(None)
                .with_scope_evidence(ScopeEvidence::from_scope_field(Some(explicit)).unwrap());
            assert!(matches!(
                now_ready(super::exchange_capability_grant(
                    &modify, &config, &reduced, &clock
                )),
                Err(TokenError::InsufficientScope)
            ));
        }
        let both = format!("{GMAIL_READONLY_SCOPE} {GMAIL_MODIFY_SCOPE}");
        let mut broadened = FakeTransport::success(Some("revocation-rotation-sentinel"))
            .with_id_token_claims(None)
            .with_scope_evidence(ScopeEvidence::from_scope_field(Some(&both)).unwrap());
        // Scope rejection needs no usable access or expiry; preserve valid rotation anyway.
        broadened.access_token = Zeroizing::new(String::new());
        broadened.expires_in = Duration::ZERO;
        let stored = stored_grant(AccountCapability::ReadOnly);
        let outcome = now_ready(super::refresh_stored_grant(
            &stored, &config, &broadened, &clock,
        ))
        .unwrap();
        let debug = format!("{outcome:?}");
        let super::CapabilityRefreshOutcome::ScopeRejected { reason, rotation } = outcome else {
            panic!("must reject broadened scope");
        };
        assert_eq!(reason, ScopeRejection::CapabilityMismatch);
        assert_eq!(
            rotation.unwrap().into_secret_for_revocation().as_str(),
            "revocation-rotation-sentinel"
        );
        assert!(!debug.contains("revocation-rotation-sentinel"));
        assert!(!debug.contains(TEST_SUBJECT));
    }

    // Contract: refresh inherits stored capability and refuses a different response subject.
    // Regression: response-controlled promotion or rotation accepted for another account.
    #[test]
    fn refresh_uses_one_stored_snapshot_and_matches_its_subject() {
        use crate::scope::ScopeEvidence;
        let config = make_config(None);
        let clock = TestClock::default();
        for capability in [AccountCapability::ReadOnly, AccountCapability::Modify] {
            let stored = stored_grant(capability);
            let transport = FakeTransport::success(Some("rotation-sentinel"))
                .with_scope_evidence(ScopeEvidence::Absent);
            let outcome = now_ready(super::refresh_stored_grant(
                &stored, &config, &transport, &clock,
            ))
            .unwrap();
            let super::CapabilityRefreshOutcome::Granted(success) = outcome else {
                panic!("absent scope inherits stored capability");
            };
            assert_eq!(success.capability(), capability);
            assert_eq!(success.accepted_scope().evidence(), ScopeEvidence::Absent);
            let recorded = transport.recorded.lock().unwrap();
            let RecordedRequest::Refresh(request) = &recorded[0] else {
                panic!("expected refresh");
            };
            assert_eq!(request.stored_capability(), capability);
            assert_eq!(stored.capability(), capability);
            assert_eq!(stored.subject().as_str(), TEST_SUBJECT);
            assert!(!format!("{stored:?}").contains("stored-refresh-sentinel"));
        }
        let wrong_subject = IdTokenClaims::new(
            Zeroizing::new("other-subject-sentinel".to_owned()),
            vec!["public-test-client".to_owned()],
            "https://accounts.google.com".to_owned(),
            None,
            TEST_IAT,
            TEST_EXP,
        );
        let transport = FakeTransport::success(Some("must-not-persist"))
            .with_scope_evidence(ScopeEvidence::Absent)
            .with_id_token_claims(Some(wrong_subject));
        assert!(matches!(
            now_ready(super::refresh_stored_grant(
                &stored_grant(AccountCapability::Modify),
                &config,
                &transport,
                &clock
            )),
            Err(TokenError::IdentityMismatch)
        ));
    }

    // Contract: capability APIs enforce token/rotation bounds before granting or retaining.
    // Regression: an unsupported producer or rejected scope bypasses the credential cap.
    #[test]
    fn capability_responses_bound_grants_and_rejected_refresh_rotations() {
        use crate::scope::{GMAIL_READONLY_SCOPE, ScopeEvidence};
        let config = make_config(None);
        let clock = TestClock::default();
        let grant = make_capability_grant("bound-code", AccountCapability::Modify);
        for (access, seconds, rotation) in [
            ("x".repeat(4_097), 3_600, None),
            ("x".to_owned(), 0, None),
            ("x".to_owned(), 86_401, None),
            ("x".to_owned(), 3_600, Some(String::new())),
            ("x".to_owned(), 3_600, Some("r".repeat(1_025))),
        ] {
            let mut transport =
                FakeTransport::success(None).with_scope_evidence(ScopeEvidence::Absent);
            transport.access_token = Zeroizing::new(access);
            transport.expires_in = Duration::from_secs(seconds);
            transport.rotated_refresh_token = rotation.map(Zeroizing::new);
            assert!(matches!(
                now_ready(super::exchange_capability_grant(
                    &grant, &config, &transport, &clock
                )),
                Err(TokenError::MalformedResponse)
            ));
        }
        for invalid in [String::new(), "r".repeat(1_025)] {
            assert!(matches!(
                super::StoredGrantSnapshot::new(
                    Zeroizing::new(invalid.clone()),
                    AccountSubject::from_broker_validated(Zeroizing::new(TEST_SUBJECT.to_owned()))
                        .unwrap(),
                    AccountCapability::Modify
                ),
                Err(TokenError::MalformedResponse)
            ));
            let transport = FakeTransport::success(Some(&invalid)).with_scope_evidence(
                ScopeEvidence::from_scope_field(Some(GMAIL_READONLY_SCOPE)).unwrap(),
            );
            assert!(matches!(
                now_ready(super::refresh_stored_grant(
                    &stored_grant(AccountCapability::Modify),
                    &config,
                    &transport,
                    &clock
                )),
                Err(TokenError::MalformedResponse)
            ));
        }
    }

    #[test]
    fn rejects_invalid_client_configuration() {
        let secret = || Some(Zeroizing::new("non-confidential-secret".to_owned()));
        let with_query = Url::parse("app.tersa.oauth.test:/oauth/callback?probe=1").unwrap();
        assert_eq!(
            TokenClientConfig::new("   ", test_redirect(), secret()).unwrap_err(),
            TokenError::InvalidConfiguration
        );
        assert_eq!(
            TokenClientConfig::new("public-test-client", with_query, secret()).unwrap_err(),
            TokenError::InvalidConfiguration
        );
        assert_eq!(
            TokenClientConfig::new(
                "public-test-client",
                test_redirect(),
                Some(Zeroizing::new("   ".to_owned())),
            )
            .unwrap_err(),
            TokenError::InvalidConfiguration
        );
    }

    fn claims(subject: &str, audiences: &[&str], issuer: &str, azp: Option<&str>) -> IdTokenClaims {
        IdTokenClaims::new(
            Zeroizing::new(subject.to_owned()),
            audiences
                .iter()
                .map(|audience| (*audience).to_owned())
                .collect(),
            issuer.to_owned(),
            azp.map(str::to_owned),
            TEST_IAT,
            TEST_EXP,
        )
    }

    #[test]
    fn identity_expiry_accepts_fresh_and_rejects_stale_or_future_tokens() {
        let expiry = super::IdentityExpiry::new_for_test(1_000, 5_000);
        // Fresh: iat <= now <= exp.
        assert!(expiry.validate_fresh(3_000, 60).is_ok());
        // Within skew of expiry: still fresh.
        assert!(expiry.validate_fresh(5_030, 60).is_ok());
        // Expired: now >= exp + skew.
        assert_eq!(
            expiry.validate_fresh(5_100, 60),
            Err(TokenError::IdentityUnverified)
        );
        // Future-minted: iat > now + skew.
        assert_eq!(
            expiry.validate_fresh(900, 60),
            Err(TokenError::IdentityUnverified)
        );
    }

    #[test]
    fn exchange_exposes_the_validated_subject() {
        let grant = make_grant("exchange-code");
        let config = make_config(None);
        let success = now_ready(exchange_grant(
            &grant,
            &config,
            &FakeTransport::success(Some("refresh")),
            &TestClock::default(),
        ))
        .unwrap();
        assert_eq!(success.subject().as_str(), TEST_SUBJECT);
        // The subject must never leak through Debug.
        assert_eq!(
            format!("{:?}", success.subject()),
            "AccountSubject([REDACTED])"
        );
    }

    #[test]
    fn refresh_exposes_the_validated_subject() {
        let config = make_config(None);
        let refresh_token = Zeroizing::new("stored-refresh-token".to_owned());
        let success = now_ready(refresh_access_token(
            &refresh_token,
            &config,
            &FakeTransport::success(None),
            &TestClock::default(),
        ))
        .unwrap();
        assert_eq!(success.subject().as_str(), TEST_SUBJECT);
    }

    #[test]
    fn a_missing_id_token_fails_closed_without_deleting_the_credential() {
        let grant = make_grant("exchange-code");
        let config = make_config(None);
        let error = now_ready(exchange_grant(
            &grant,
            &config,
            &FakeTransport::success(None).with_id_token_claims(None),
            &TestClock::default(),
        ))
        .unwrap_err();
        // Non-destructive: NOT ConsentRevoked (which would delete the token).
        assert_eq!(error, TokenError::IdentityUnverified);
        assert_ne!(error, TokenError::ConsentRevoked);
    }

    #[test]
    fn a_wrong_audience_is_rejected() {
        let grant = make_grant("exchange-code");
        let config = make_config(None);
        let transport = FakeTransport::success(None).with_id_token_claims(Some(claims(
            "subject",
            &["another-client"],
            "https://accounts.google.com",
            None,
        )));
        assert_eq!(
            now_ready(exchange_grant(
                &grant,
                &config,
                &transport,
                &TestClock::default()
            ))
            .unwrap_err(),
            TokenError::IdentityUnverified
        );
    }

    #[test]
    fn a_non_google_issuer_is_rejected() {
        let grant = make_grant("exchange-code");
        let config = make_config(None);
        let transport = FakeTransport::success(None).with_id_token_claims(Some(claims(
            "subject",
            &["public-test-client"],
            "https://accounts.evil.example",
            None,
        )));
        assert_eq!(
            now_ready(exchange_grant(
                &grant,
                &config,
                &transport,
                &TestClock::default()
            ))
            .unwrap_err(),
            TokenError::IdentityUnverified
        );
    }

    #[test]
    fn an_empty_subject_is_rejected() {
        let grant = make_grant("exchange-code");
        let config = make_config(None);
        let transport = FakeTransport::success(None).with_id_token_claims(Some(claims(
            "   ",
            &["public-test-client"],
            "https://accounts.google.com",
            None,
        )));
        assert_eq!(
            now_ready(exchange_grant(
                &grant,
                &config,
                &transport,
                &TestClock::default()
            ))
            .unwrap_err(),
            TokenError::IdentityUnverified
        );
    }

    #[test]
    fn the_bare_google_issuer_form_is_accepted() {
        let grant = make_grant("exchange-code");
        let config = make_config(None);
        let transport = FakeTransport::success(None).with_id_token_claims(Some(claims(
            "subject-xyz",
            &["public-test-client"],
            "accounts.google.com",
            None,
        )));
        let success = now_ready(exchange_grant(
            &grant,
            &config,
            &transport,
            &TestClock::default(),
        ))
        .unwrap();
        assert_eq!(success.subject().as_str(), "subject-xyz");
    }

    fn exchange_claims(claims: IdTokenClaims) -> Result<String, TokenError> {
        let grant = make_grant("exchange-code");
        let config = make_config(None);
        let transport = FakeTransport::success(None).with_id_token_claims(Some(claims));
        now_ready(exchange_grant(
            &grant,
            &config,
            &transport,
            &TestClock::default(),
        ))
        .map(|success| success.subject().as_str().to_owned())
    }

    #[test]
    fn a_multi_audience_without_azp_is_rejected() {
        assert_eq!(
            exchange_claims(claims(
                "subject",
                &["public-test-client", "another-client"],
                "https://accounts.google.com",
                None,
            ))
            .err(),
            Some(TokenError::IdentityUnverified)
        );
    }

    #[test]
    fn a_multi_audience_with_a_matching_azp_is_accepted() {
        assert_eq!(
            exchange_claims(claims(
                "subject",
                &["public-test-client", "another-client"],
                "https://accounts.google.com",
                Some("public-test-client"),
            ))
            .ok(),
            Some("subject".to_owned())
        );
    }

    #[test]
    fn a_multi_audience_with_a_wrong_azp_is_rejected() {
        assert_eq!(
            exchange_claims(claims(
                "subject",
                &["public-test-client", "another-client"],
                "https://accounts.google.com",
                Some("another-client"),
            ))
            .err(),
            Some(TokenError::IdentityUnverified)
        );
    }

    #[test]
    fn a_padded_subject_is_trimmed_before_use() {
        assert_eq!(
            exchange_claims(claims(
                "  padded-subject  ",
                &["public-test-client"],
                "https://accounts.google.com",
                None,
            ))
            .ok(),
            Some("padded-subject".to_owned())
        );
    }

    #[test]
    fn builds_exchange_requests_with_and_without_client_secret() {
        let grant = make_grant("exchange-code");

        let transport = FakeTransport::success(None);
        let config = make_config(Some("non-confidential-secret"));
        now_ready(exchange_grant(
            &grant,
            &config,
            &transport,
            &TestClock::default(),
        ))
        .unwrap();
        let recorded = transport.recorded.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        let parameters = recorded[0].parameters();
        let pairs: Vec<(&str, &str)> = parameters
            .iter()
            .map(|(name, value)| (*name, value.as_str()))
            .collect();
        assert_eq!(
            pairs,
            [
                ("grant_type", "authorization_code"),
                ("code", "exchange-code"),
                ("code_verifier", grant.verifier()),
                ("client_id", "public-test-client"),
                ("redirect_uri", "app.tersa.oauth.test:/oauth/callback"),
                ("client_secret", "non-confidential-secret"),
            ]
        );
        drop(recorded);

        let transport = FakeTransport::success(None);
        let config = make_config(None);
        now_ready(exchange_grant(
            &grant,
            &config,
            &transport,
            &TestClock::default(),
        ))
        .unwrap();
        let recorded = transport.recorded.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        let parameters = recorded[0].parameters();
        let pairs: Vec<(&str, &str)> = parameters
            .iter()
            .map(|(name, value)| (*name, value.as_str()))
            .collect();
        assert_eq!(
            pairs,
            [
                ("grant_type", "authorization_code"),
                ("code", "exchange-code"),
                ("code_verifier", grant.verifier()),
                ("client_id", "public-test-client"),
                ("redirect_uri", "app.tersa.oauth.test:/oauth/callback"),
            ]
        );
    }

    #[test]
    fn builds_refresh_requests_with_and_without_client_secret() {
        let refresh_token = Zeroizing::new("stored-refresh-token".to_owned());

        let transport = FakeTransport::success(None);
        let config = make_config(Some("non-confidential-secret"));
        now_ready(refresh_access_token(
            &refresh_token,
            &config,
            &transport,
            &TestClock::default(),
        ))
        .unwrap();
        let recorded = transport.recorded.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        let parameters = recorded[0].parameters();
        let pairs: Vec<(&str, &str)> = parameters
            .iter()
            .map(|(name, value)| (*name, value.as_str()))
            .collect();
        assert_eq!(
            pairs,
            [
                ("grant_type", "refresh_token"),
                ("refresh_token", "stored-refresh-token"),
                ("client_id", "public-test-client"),
                ("client_secret", "non-confidential-secret"),
            ]
        );
        drop(recorded);

        let transport = FakeTransport::success(None);
        let config = make_config(None);
        now_ready(refresh_access_token(
            &refresh_token,
            &config,
            &transport,
            &TestClock::default(),
        ))
        .unwrap();
        let recorded = transport.recorded.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        let parameters = recorded[0].parameters();
        let pairs: Vec<(&str, &str)> = parameters
            .iter()
            .map(|(name, value)| (*name, value.as_str()))
            .collect();
        assert_eq!(
            pairs,
            [
                ("grant_type", "refresh_token"),
                ("refresh_token", "stored-refresh-token"),
                ("client_id", "public-test-client"),
            ]
        );
    }

    #[test]
    fn exchange_success_models_rotation_presence_and_absence() {
        let grant = make_grant("exchange-code");
        let config = make_config(None);
        let clock = TestClock::default();

        let transport = FakeTransport::success(Some("rotated-refresh-token"));
        let success = now_ready(exchange_grant(&grant, &config, &transport, &clock)).unwrap();
        assert_eq!(
            success.access_token().secret().as_str(),
            "fake-access-token"
        );
        assert_eq!(
            success.access_token().expires_at(),
            Duration::from_secs(3_600)
        );
        assert_eq!(
            success.rotated_refresh_token().map(|token| token.as_str()),
            Some("rotated-refresh-token")
        );

        let transport = FakeTransport::success(None);
        let success = now_ready(exchange_grant(&grant, &config, &transport, &clock)).unwrap();
        assert_eq!(
            success.access_token().secret().as_str(),
            "fake-access-token"
        );
        assert!(success.rotated_refresh_token().is_none());
    }

    #[test]
    fn refresh_success_rotates_or_keeps_the_stored_refresh_token() {
        let refresh_token = Zeroizing::new("stored-refresh-token".to_owned());
        let config = make_config(None);
        let clock = TestClock::default();

        let transport = FakeTransport::success(Some("rotated-refresh-token"));
        let success = now_ready(refresh_access_token(
            &refresh_token,
            &config,
            &transport,
            &clock,
        ))
        .unwrap();
        let (access_token, rotated, subject, expiry, gmail_read_granted) = success.into_parts();
        assert_eq!(subject.as_str(), TEST_SUBJECT);
        assert_eq!(
            expiry,
            super::IdentityExpiry::new_for_test(TEST_IAT, TEST_EXP)
        );
        assert_eq!(access_token.secret().as_str(), "fake-access-token");
        assert_eq!(access_token.expires_at(), Duration::from_secs(3_600));
        assert!(gmail_read_granted);
        assert_eq!(
            rotated.as_ref().map(|token| token.as_str()),
            Some("rotated-refresh-token")
        );

        let transport = FakeTransport::success(None);
        let success = now_ready(refresh_access_token(
            &refresh_token,
            &config,
            &transport,
            &clock,
        ))
        .unwrap();
        assert!(success.rotated_refresh_token().is_none());
    }

    #[test]
    fn maps_invalid_grant_by_flow_exchange_rejected_refresh_consent_revoked() {
        // Exchange: an invalid_grant answer is a stale, used, or mismatched
        // authorization code — the sign-in lapsed. The terminal is the
        // dedicated, non-destructive AuthorizationCodeRejected: never
        // ConsentRevoked (no stored credential exists to delete) and never
        // the ordinary retryable ProviderRejected.
        let grant = make_grant("exchange-code");
        let config = make_config(None);
        let transport = FakeTransport::failing(TokenTransportError::InvalidGrant);
        let exchange_error = now_ready(exchange_grant(
            &grant,
            &config,
            &transport,
            &TestClock::default(),
        ))
        .unwrap_err();
        assert_eq!(exchange_error, TokenError::AuthorizationCodeRejected);
        assert_ne!(exchange_error, TokenError::ConsentRevoked);
        assert_ne!(exchange_error, TokenError::ProviderRejected);
        assert_eq!(
            now_ready(super::exchange_capability_grant(
                &grant,
                &config,
                &transport,
                &TestClock::default()
            ))
            .unwrap_err(),
            TokenError::AuthorizationCodeRejected
        );

        // Refresh: the same answer is about the stored credential, so it stays
        // the destructive ConsentRevoked terminal.
        let refresh_token = Zeroizing::new("stored-refresh-token".to_owned());
        let transport = FakeTransport::failing(TokenTransportError::InvalidGrant);
        assert_eq!(
            now_ready(refresh_access_token(
                &refresh_token,
                &config,
                &transport,
                &TestClock::default()
            ))
            .unwrap_err(),
            TokenError::ConsentRevoked
        );
        assert!(matches!(
            now_ready(super::refresh_stored_grant(
                &stored_grant(AccountCapability::ReadOnly),
                &config,
                &transport,
                &TestClock::default()
            )),
            Err(TokenError::ConsentRevoked)
        ));
    }

    #[test]
    fn maps_invalid_token_to_provider_rejected_on_exchange_and_refresh() {
        // `invalid_token` is a revocation-endpoint answer; on the token
        // endpoint it must never become the destructive ConsentRevoked.
        let grant = make_grant("exchange-code");
        let config = make_config(None);
        let transport = FakeTransport::failing(TokenTransportError::InvalidToken);
        assert_eq!(
            now_ready(exchange_grant(
                &grant,
                &config,
                &transport,
                &TestClock::default()
            ))
            .unwrap_err(),
            TokenError::ProviderRejected
        );

        let refresh_token = Zeroizing::new("stored-refresh-token".to_owned());
        let transport = FakeTransport::failing(TokenTransportError::InvalidToken);
        assert_eq!(
            now_ready(refresh_access_token(
                &refresh_token,
                &config,
                &transport,
                &TestClock::default()
            ))
            .unwrap_err(),
            TokenError::ProviderRejected
        );
    }

    #[test]
    fn maps_remaining_transport_failures_to_distinct_terminals() {
        let cases = [
            (TokenTransportError::Transport, TokenError::Transport),
            (
                TokenTransportError::ProviderRejected,
                TokenError::ProviderRejected,
            ),
            (
                TokenTransportError::MalformedResponse,
                TokenError::MalformedResponse,
            ),
        ];
        let grant = make_grant("exchange-code");
        let config = make_config(None);
        for (transport_error, expected) in cases {
            let transport = FakeTransport::failing(transport_error);
            assert_eq!(
                now_ready(exchange_grant(
                    &grant,
                    &config,
                    &transport,
                    &TestClock::default()
                ))
                .unwrap_err(),
                expected
            );
        }
    }

    #[test]
    fn secrets_never_appear_in_debug_output() {
        let grant = make_grant("super-secret-code");
        let config = make_config(Some("super-client-secret"));
        let transport = FakeTransport::success(Some("super-rotated-refresh"));
        let success = now_ready(exchange_grant(
            &grant,
            &config,
            &transport,
            &TestClock::default(),
        ))
        .unwrap();
        let recorded = transport.recorded.lock().unwrap();
        assert_eq!(recorded.len(), 1);

        let response = TokenResponse::new(
            Zeroizing::new("super-access-token".to_owned()),
            Duration::from_secs(60),
            Some(Zeroizing::new("super-rotated-refresh".to_owned())),
            Some(valid_claims()),
            true,
        );
        for rendered in [
            format!("{:?}", recorded[0]),
            format!("{config:?}"),
            format!("{success:?}"),
            format!("{:?}", success.access_token()),
            format!("{response:?}"),
        ] {
            assert!(rendered.contains("[REDACTED]"));
            for secret in [
                "super-secret-code",
                "super-client-secret",
                "super-rotated-refresh",
                "super-access-token",
                "fake-access-token",
                grant.verifier(),
            ] {
                assert!(!rendered.contains(secret));
            }
        }
        drop(recorded);

        let refresh_token = Zeroizing::new("super-stored-refresh".to_owned());
        let transport = FakeTransport::success(None);
        now_ready(refresh_access_token(
            &refresh_token,
            &config,
            &transport,
            &TestClock::default(),
        ))
        .unwrap();
        let recorded = transport.recorded.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        let rendered = format!("{:?}", recorded[0]);
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("super-stored-refresh"));
        assert!(!rendered.contains("super-client-secret"));
    }

    #[test]
    fn broker_boundary_accepts_a_conservative_google_subject() {
        // A Google `sub` is a ~21-digit ASCII string.
        let subject = AccountSubject::from_broker_validated(Zeroizing::new(
            "112233445566778899001".to_owned(),
        ))
        .unwrap();
        assert_eq!(subject.as_str(), "112233445566778899001");
        // The 255-UTF-8-byte cap is inclusive.
        let maxed = AccountSubject::from_broker_validated(Zeroizing::new("1".repeat(255))).unwrap();
        assert_eq!(maxed.as_str().len(), 255);
    }

    #[test]
    fn broker_boundary_rejects_empty_oversized_and_malformed_subjects() {
        assert_eq!(
            AccountSubject::from_broker_validated(Zeroizing::new(String::new())).unwrap_err(),
            BrokerSubjectError::Empty
        );
        assert_eq!(
            AccountSubject::from_broker_validated(Zeroizing::new("1".repeat(256))).unwrap_err(),
            BrokerSubjectError::Oversized
        );
        for malformed in [
            "has space".to_owned(),
            " leading-space".to_owned(),
            "trailing-space ".to_owned(),
            "tab\tsubject".to_owned(),
            "newline\nsubject".to_owned(),
            "control\u{1}subject".to_owned(),
            "del\u{7f}subject".to_owned(),
            "non-ascii-é".to_owned(),
        ] {
            assert_eq!(
                AccountSubject::from_broker_validated(Zeroizing::new(malformed)).unwrap_err(),
                BrokerSubjectError::InvalidCharacters
            );
        }
    }

    #[test]
    fn broker_boundary_never_echoes_the_subject() {
        let probe = "probe-subject-value";
        let subject =
            AccountSubject::from_broker_validated(Zeroizing::new(probe.to_owned())).unwrap();
        let rendered = format!("{subject:?}");
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains(probe));
        for error in [
            BrokerSubjectError::Empty,
            BrokerSubjectError::Oversized,
            BrokerSubjectError::InvalidCharacters,
        ] {
            assert!(!format!("{error:?}").contains(probe));
            assert!(!format!("{error}").contains(probe));
        }
    }
}
