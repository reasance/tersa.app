// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Application commands, queries, and use-case orchestration for tersa.app.
//!
//! Consumers can use the shared closed command values through [`crate::command`],
//! label values through [`crate::mailbox_state`] and cursors through
//! [`crate::history`]. These reexports retain the original types and validation.
//! Construction validates intent; admission and live authority remain store/runtime
//! responsibilities.
//!
//! ```
//! use tersa_application::{
//!     AccountCapability,
//!     command::{CommandError, MailboxCommand, MailboxCommandId, MessageAction, MessageTargets},
//!     history::{HistoryCursor, InvalidHistoryCursor},
//!     mailbox::{AccountId, MessageId},
//!     mailbox_state::{LabelDefinition, LabelError, LabelId, LabelKind, LabelName, UserLabel},
//! };
//!
//! fn label_intent(
//!     account: AccountId,
//!     message: MessageId,
//!     label: UserLabel,
//! ) -> Result<MailboxCommand, CommandError> {
//!     MailboxCommand::message_state(
//!         AccountCapability::Modify,
//!         MailboxCommandId::new("fresh-command")?,
//!         MessageTargets::new(account, vec![message])?,
//!         &MessageAction::ApplyLabel(label),
//!     )
//! }
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let account = AccountId::new("account")?;
//! let definition: Result<LabelDefinition, LabelError> = LabelDefinition::new(
//!     account.clone(), LabelId::new("Label_1")?, LabelName::new("Follow up")?, LabelKind::User,
//! );
//! let intent = label_intent(account, MessageId::new("message")?, definition?.user_label()?)?;
//! let cursor: Result<HistoryCursor, InvalidHistoryCursor> = HistoryCursor::new("42");
//! # let _ = (intent, cursor?);
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]

/// Shared account capability for consumers using the application dependency.
#[doc(inline)]
pub use tersa_domain::account::AccountCapability;

/// Closed mailbox command transport and durable lifecycle contracts.
pub mod command;
/// Offline command intents and bounded fresh reconciliation/guarded dispatch.
pub mod command_coordinator;
/// Bounded History, metadata and atomic cursor transaction contracts.
pub mod history;
/// Pure bounded History and baseline-first snapshot orchestration.
pub mod history_sync;
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
