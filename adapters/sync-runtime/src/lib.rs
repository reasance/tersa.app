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

mod flows;
mod gate;
mod installation;
mod loopback;
mod session;
mod session_cache;

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
