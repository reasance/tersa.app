// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! In-process account runtime for tersa (ADR 0031).
//!
//! Composes the token service (`tersa-token-broker-core`), the Gmail REST
//! adapter, the encrypted store and registry, and the identity gate into the
//! account flows: add, sync, and remove. Everything runs in one process; the
//! refresh token lives in the account's encrypted database.

#![forbid(unsafe_code)]
#![expect(
    clippy::multiple_inherent_impl,
    reason = "Runtime flow modules keep account-permit ownership and cached reads separate"
)]

mod cache_reset;
mod commands;
mod composition;
mod coordination;
mod flows;
mod gate;
mod grants;
mod history;
mod installation;
mod loopback;
mod mailbox_ports;
mod online;
mod session;
mod session_cache;
mod views;

pub use cache_reset::{CacheResetOutcome, CacheResetPreconditionError};
pub use flows::{
    AddedAccount, FlowError, OAuthClient, Revocation, Runtime, SIGN_IN_TIMEOUT, default_sync_policy,
};
pub use gate::{GatedFetchError, GatedSyncError, gated_fetch, gated_sync};
pub use installation::{
    Installation, InstallationError, InstallationHasher, InstallationLock, InstallationTokens,
    LockError, has_local_data,
};
pub use loopback::{Loopback, LoopbackError};
pub use session::{GmailSession, GmailSessionError, SharedSession};

pub use composition::CompositionError;
pub use history::{AccountHistoryReport, BodyPhaseReport};

pub use commands::{
    AccountCommandReport, AccountCommandStatus, CacheConvergenceReport, CommandIntent,
    CredentialPurpose,
};

pub use views::{
    CachedMailboxFilter, CachedViewContinuation, CachedViewPage, CachedViewRow, CachedViewScope,
    PendingMessageProjection,
};
