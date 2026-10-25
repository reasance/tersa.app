// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Application commands, queries, and use-case orchestration for tersa.app.

#![forbid(unsafe_code)]

/// Account-identity gate ports and the pure preserve-vs-clear decision.
pub mod identity;
/// Privacy-safe durable sync freshness and disconnect-recovery metadata.
pub mod lifecycle;
/// Shared inward mailbox ports and pagination contracts.
pub mod mailbox;
pub mod oauth;
/// Bounded recent-snapshot mailbox synchronization and cache orchestration.
pub mod sync;
/// Portable token exchange and refresh lifecycle over a transport port.
pub mod token;

// Rust guideline compliant 1.0.
