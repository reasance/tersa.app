// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! In-process token-service lifecycle core (ADR-0024 and ADR 0031).
//!
//! This runtime-agnostic in-process service owns OAuth code exchange, refresh,
//! refresh-token persistence, rotation, deletion, and provider revoke over
//! generic ports, and never exposes a refresh token, PKCE verifier, state, or
//! authorization code across its API. It contains no OS keyring code or IPC.
//! `tersa-sync-runtime` supplies the Google transport, loopback listener, and
//! account-bound `SQLCipher` credential store. This logical capability boundary
//! provides no process isolation from the installation root key (ADR 0031).
//!
//! Security invariants enforced here:
//!
//! - `begin_authorization` accepts only an exact root-form literal IPv4
//!   loopback redirect with an explicit non-privileged port.
//! - Pending authorization sessions live in a bounded registry with an
//!   absolute TTL, deterministic reaping, no live-entry eviction, and
//!   poisoned-lock fail-closed wiping; a completion claims its session
//!   atomically BEFORE any callback validation, so every callback is terminal.
//!   Session handles are held in zeroizing memory everywhere, including the
//!   registry's owned key copies, so no removal path leaves handle bytes in
//!   freed heap.
//! - Token mutations serialize per validated subject through bounded
//!   single-flight permits released by RAII guards (cancellation-safe); no
//!   mutex guard is held across an `.await`. A completion claims its
//!   account's permit immediately after subject validation, before any
//!   store read or write.
//! - A granted exchange snapshots the stored credential under the permit
//!   before replacing it; a stranded post-exchange grant is revoked
//!   best-effort only when that snapshot is definitively empty, because
//!   Google revocation is grant-wide and a prior credential could be the
//!   working connection. An unreadable snapshot fails closed as
//!   `PersistenceFailed` before any store write or revoke.
//! - An explicitly under-scoped completion carries no validated identity and
//!   the begin operation supplies no account identity, so no
//!   subject-keyed snapshot is possible: it fails safe and non-destructively
//!   (nothing persisted, nothing revoked). This can leave a first-connect
//!   under-scoped grant active at the provider, and this API cannot offer an
//!   in-app manual revoke for it — the minted tokens were dropped and there
//!   is no validated subject or stored credential to revoke against. The
//!   caller must surface the failure, offer retain-or-retry recovery,
//!   and direct the user to their Google account-permissions page for manual
//!   revocation.
//! - Success values carry only a zeroizing access token, a zeroizing subject,
//!   and a bounded positive expiry; every `Debug`/`Display` redacts
//!   account-identifying and secret-bearing values.
//! - The closed broker error vocabulary keeps an exchange-time
//!   authorization-code rejection (`BrokerError::AuthorizationCodeRejected` —
//!   the sign-in lapsed) distinct from an ordinary provider rejection, so the
//!   caller can distinguish sign-in-expired recovery from provider rejection
//!   and revoked consent (ADR-0024).

#![forbid(unsafe_code)]

mod broker;
mod error;
mod handle;
mod permits;
mod ports;
mod registry;
mod subject;

pub use broker::{BrokerCore, BrokerToken, PendingAuthorization};
pub use error::BrokerError;
pub use handle::{SESSION_HANDLE_BYTES, SessionHandle};
pub use ports::{
    GetRandomEntropy, RefreshTokenStore, RefreshTokenStoreError, SessionHandleEntropy,
};
pub use subject::ValidatedSubject;

// Rust guideline compliant 1.0.
