// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Reduces bounded scope fields to closed evidence and applies capability policy.
//!
//! Callback and token producers use the same parser and predicate. Raw provider
//! text is borrowed only during reduction, never retained in facts or errors.
//! Absent fields inherit an immutable request/stored capability; explicit empty
//! fields do not. Legacy booleans remain visibly incomplete evidence and cannot
//! authorize a capability-aware flow. These values do not prove live authority.

use std::fmt;
use tersa_domain::account::AccountCapability;

/// The Gmail scope granting readonly access.
pub const GMAIL_READONLY_SCOPE: &str = "https://www.googleapis.com/auth/gmail.readonly";
/// The Gmail scope granting the approved mutation capability.
pub const GMAIL_MODIFY_SCOPE: &str = "https://www.googleapis.com/auth/gmail.modify";
/// The forbidden send scope, recognized only for rejection.
pub const GMAIL_SEND_SCOPE: &str = "https://www.googleapis.com/auth/gmail.send";
/// The forbidden full-mail scope, recognized only for rejection.
pub const FULL_MAIL_SCOPE: &str = "https://mail.google.com/";
/// The identity scope requested alongside the selected Gmail scope.
pub const OPENID_SCOPE: &str = "openid";
/// The readonly compatibility request's complete scope string.
pub const REQUESTED_SCOPE: &str = "openid https://www.googleapis.com/auth/gmail.readonly";
/// The explicit Modify request's complete scope string.
pub const MODIFY_REQUESTED_SCOPE: &str = "openid https://www.googleapis.com/auth/gmail.modify";

/// Selects exactly identity plus one Gmail scope, never a broader grant.
#[must_use]
pub fn requested_scope(capability: AccountCapability) -> &'static str {
    match capability {
        AccountCapability::ReadOnly => REQUESTED_SCOPE,
        AccountCapability::Modify => MODIFY_REQUESTED_SCOPE,
    }
}

/// Reports rejected scope-field bounds without retaining input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScopeFieldError {
    /// The input exceeds the defensive byte bound.
    TooLarge,
    /// The input exceeds the defensive scope-token count.
    TooManyScopes,
}
impl fmt::Display for ScopeFieldError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("scope field exceeds its defensive bounds")
    }
}
impl std::error::Error for ScopeFieldError {}

/// Retains only recognized permission facts from an explicitly present field.
///
/// Unknown scope tokens are not retained. Only the exact case-sensitive Gmail
/// identifiers matter to this predicate; identity validation remains separate.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ExplicitScopeFacts {
    readonly: bool,
    modify: bool,
    forbidden: bool,
}

/// Preserves scope-field provenance without raw provider strings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScopeEvidence {
    /// A complete parser observed that the field was absent.
    Absent,
    /// A complete parser observed the explicit field, possibly empty.
    Explicit(ExplicitScopeFacts),
    /// A legacy producer supplied only its lossy readonly verdict.
    ///
    /// This cannot distinguish absence, forbidden scopes or excess capability.
    LegacyReadOnly {
        /// The legacy readonly verdict, never Modify or absence evidence.
        granted: bool,
    },
}
impl ScopeEvidence {
    /// Defensive decoded scope-field byte bound, not a provider capacity claim.
    pub const MAX_BYTES: usize = 4_096;
    /// Defensive token count, including duplicates and unrecognized tokens.
    pub const MAX_SCOPES: usize = 64;

    /// Reduces an absent or explicit scope field without retaining its text.
    ///
    /// Producers must pass the actual field's presence, never convert an empty
    /// or legacy boolean result into absence. ASCII whitespace separates scopes,
    /// consistent with the existing callback parser. Unknown tokens are ignored.
    ///
    /// # Errors
    ///
    /// Rejects more than 4,096 decoded UTF-8 bytes or 64 scope tokens.
    pub fn from_scope_field(field: Option<&str>) -> Result<Self, ScopeFieldError> {
        let Some(field) = field else {
            return Ok(Self::Absent);
        };
        if field.len() > Self::MAX_BYTES {
            return Err(ScopeFieldError::TooLarge);
        }
        let mut facts = ExplicitScopeFacts::default();
        for (index, token) in field.split_ascii_whitespace().enumerate() {
            if index >= Self::MAX_SCOPES {
                return Err(ScopeFieldError::TooManyScopes);
            }
            match token {
                GMAIL_READONLY_SCOPE => facts.readonly = true,
                GMAIL_MODIFY_SCOPE => facts.modify = true,
                GMAIL_SEND_SCOPE | FULL_MAIL_SCOPE => facts.forbidden = true,
                _ => {}
            }
        }
        Ok(Self::Explicit(facts))
    }

    /// Applies the single capability predicate using immutable request or stored context.
    ///
    /// # Errors
    ///
    /// Rejects incomplete legacy evidence, forbidden scopes, a readonly request
    /// containing Modify, or any explicit field lacking the required Gmail scope.
    pub fn validate_for(
        self,
        requested: AccountCapability,
    ) -> Result<AcceptedScope, ScopeRejection> {
        match self {
            Self::LegacyReadOnly { .. } => return Err(ScopeRejection::IncompleteEvidence),
            Self::Absent => {}
            Self::Explicit(facts) => {
                if facts.forbidden {
                    return Err(ScopeRejection::ForbiddenScope);
                }
                if requested == AccountCapability::ReadOnly && facts.modify {
                    return Err(ScopeRejection::CapabilityMismatch);
                }
                let required = match requested {
                    AccountCapability::ReadOnly => facts.readonly,
                    AccountCapability::Modify => facts.modify,
                };
                if !required {
                    return Err(ScopeRejection::InsufficientScope);
                }
            }
        }
        Ok(AcceptedScope {
            capability: requested,
            evidence: self,
        })
    }

    pub(crate) fn validate_readonly_compat(self) -> Result<AcceptedScope, ScopeRejection> {
        match self {
            Self::LegacyReadOnly { granted: true } => Ok(AcceptedScope {
                capability: AccountCapability::ReadOnly,
                evidence: self,
            }),
            Self::LegacyReadOnly { granted: false } => Err(ScopeRejection::InsufficientScope),
            _ => self.validate_for(AccountCapability::ReadOnly),
        }
    }
}

/// Reports a closed capability-policy rejection without provider data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScopeRejection {
    /// Only a lossy legacy verdict was supplied.
    IncompleteEvidence,
    /// The explicit field lacks the requested capability's exact Gmail scope.
    InsufficientScope,
    /// A readonly request explicitly received Modify.
    CapabilityMismatch,
    /// Send or full-mail permission appeared in the explicit field.
    ForbiddenScope,
}
impl fmt::Display for ScopeRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("scope evidence does not satisfy the bound capability")
    }
}
impl std::error::Error for ScopeRejection {}

/// Binds accepted scope evidence to the capability that was actually requested.
///
/// Legacy readonly compatibility successes retain their legacy provenance; only
/// [`ScopeEvidence::validate_for`] accepts complete evidence for new flows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcceptedScope {
    capability: AccountCapability,
    evidence: ScopeEvidence,
}
impl AcceptedScope {
    /// Returns the bound capability, never inferred from a broader response.
    #[must_use]
    pub fn capability(self) -> AccountCapability {
        self.capability
    }
    /// Returns the original closed scope evidence, preserving producer limitations.
    #[must_use]
    pub fn evidence(self) -> ScopeEvidence {
        self.evidence
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Contract: bounded reduction retains closed facts, never raw unknown tokens.
    // Regression: unbounded provider scope input or raw-string leakage in Debug.
    #[test]
    fn scope_reduction_is_bounded_and_does_not_retain_provider_text() {
        assert!(ScopeEvidence::from_scope_field(Some(&"x".repeat(4_096))).is_ok());
        assert_eq!(
            ScopeEvidence::from_scope_field(Some(&"x".repeat(4_097))),
            Err(ScopeFieldError::TooLarge)
        );
        assert!(ScopeEvidence::from_scope_field(Some(&"unknown ".repeat(64))).is_ok());
        assert_eq!(
            ScopeEvidence::from_scope_field(Some(&"unknown ".repeat(65))),
            Err(ScopeFieldError::TooManyScopes)
        );
        let evidence = ScopeEvidence::from_scope_field(Some("provider-scope-sentinel"))
            .expect("bounded field");
        assert!(!format!("{evidence:?}").contains("provider-scope-sentinel"));
        assert!(
            !ScopeFieldError::TooLarge
                .to_string()
                .contains("provider-scope-sentinel")
        );
    }
}
