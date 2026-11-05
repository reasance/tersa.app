// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Application commands, queries, and use-case orchestration for tersa.app.

#![forbid(unsafe_code)]

/// Shared account capability for consumers using the application dependency.
#[doc(inline)]
pub use tersa_domain::account::AccountCapability;

/// Closed mailbox command transport and durable lifecycle contracts.
pub mod command;
/// Bounded History, metadata and atomic cursor transaction contracts.
pub mod history;
/// Complete message-bound provider observations and shared contract failures.
pub mod mailbox_state;
/// Readonly existing-account metadata and selected-account Upgrade binding.
pub mod profile;

/// Account-identity gate ports and the pure preserve-vs-clear decision.
pub mod identity;
/// Privacy-safe durable sync freshness and disconnect-recovery metadata.
pub mod lifecycle;
/// Shared inward mailbox ports and pagination contracts.
pub mod mailbox;
pub mod oauth;
/// Shared bounded scope evidence and capability acceptance policy.
pub mod scope;
/// Bounded recent-snapshot mailbox synchronization and cache orchestration.
pub mod sync;
/// Portable token exchange and refresh lifecycle over a transport port.
pub mod token;
/// Bounded, account-scoped unified mailbox reads and continuations.
pub mod unified_mailbox;

// Rust guideline compliant 1.0.
