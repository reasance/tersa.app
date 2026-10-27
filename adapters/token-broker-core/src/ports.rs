// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The narrow ports the broker composition is generic over.
//!
//! [`RefreshTokenStore`] is keyed ONLY by validated subject text: no generic
//! key, query, or service parameter exists, so a caller cannot turn the
//! credential store into a general-purpose secret-store interface (ADR-0024).
//! [`SessionHandleEntropy`] makes session-handle randomness injectable so
//! deterministic tests never depend on OS randomness; the production default
//! uses `getrandom`.

use std::fmt;

use zeroize::Zeroizing;

use crate::error::BrokerError;
use crate::handle::SESSION_HANDLE_BYTES;
use crate::subject::ValidatedSubject;

/// A closed, redacted failure of the refresh-token store.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RefreshTokenStoreError {
    /// The store could not perform the operation.
    Unavailable,
    /// A stored item was malformed: wrong type, oversized, or undecodable.
    Invalid,
}

impl fmt::Display for RefreshTokenStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Unavailable => "the refresh-token store operation failed",
            Self::Invalid => "the stored refresh-token item was malformed",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for RefreshTokenStoreError {}

/// The per-subject refresh-token store consumed by the broker composition.
///
/// The refresh token is the only persisted OAuth credential. It is keyed only
/// by [`ValidatedSubject`], moved in and out as [`Zeroizing`] values, and is
/// never logged. Implementations must treat deleting an absent subject as a
/// success so [`BrokerCore::delete_stored_tokens`](crate::BrokerCore::delete_stored_tokens)
/// stays idempotent.
pub trait RefreshTokenStore: fmt::Debug + Send + Sync {
    /// Persists `token` for `subject`, replacing any existing token in place.
    ///
    /// # Errors
    ///
    /// Returns a redacted [`RefreshTokenStoreError`] when the store rejects
    /// the write.
    fn store(
        &self,
        subject: &ValidatedSubject,
        token: &Zeroizing<String>,
    ) -> Result<(), RefreshTokenStoreError>;

    /// Loads the stored token for `subject`, or `None` when absent.
    ///
    /// # Errors
    ///
    /// Returns a redacted [`RefreshTokenStoreError`] when the store rejects
    /// the read or the item is malformed. An absent item is `Ok(None)`, never
    /// an error.
    fn load(
        &self,
        subject: &ValidatedSubject,
    ) -> Result<Option<Zeroizing<String>>, RefreshTokenStoreError>;

    /// Deletes the stored token for `subject`. Idempotent: deleting an absent
    /// subject succeeds.
    ///
    /// # Errors
    ///
    /// Returns a redacted [`RefreshTokenStoreError`] when the store rejects
    /// the delete.
    fn delete(&self, subject: &ValidatedSubject) -> Result<(), RefreshTokenStoreError>;
}

/// Supplies the raw entropy for opaque authorization-session handles.
///
/// Tiny by design so tests can inject deterministic or scripted bytes
/// (including deliberate collisions) without touching OS randomness.
pub trait SessionHandleEntropy: fmt::Debug + Send + Sync {
    /// Returns [`SESSION_HANDLE_BYTES`] fresh random bytes.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::Unavailable`] when randomness cannot be
    /// produced; the caller fails closed rather than minting a weak handle.
    fn handle_bytes(&self) -> Result<[u8; SESSION_HANDLE_BYTES], BrokerError>;
}

/// The production entropy source, backed by the operating-system CSPRNG.
#[derive(Clone, Copy, Debug, Default)]
pub struct GetRandomEntropy;

impl SessionHandleEntropy for GetRandomEntropy {
    fn handle_bytes(&self) -> Result<[u8; SESSION_HANDLE_BYTES], BrokerError> {
        let mut bytes = [0_u8; SESSION_HANDLE_BYTES];
        getrandom::fill(&mut bytes).map_err(|_error| BrokerError::Unavailable)?;
        Ok(bytes)
    }
}
