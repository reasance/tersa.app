// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! UI-neutral view models and serializable navigation state for tersa.app.

#![forbid(unsafe_code)]

/// UI-neutral mailbox view models projected from metadata documents.
pub mod html;
pub mod mailbox;
pub mod message;
pub mod terminal;

/// Returns the protocol version expected by platform presentation adapters.
///
/// This small stable surface lets platform bootstraps prove that they link the
/// shared presentation crate before richer view models are introduced.
#[must_use]
pub const fn presentation_protocol_version() -> u32 {
    1
}

// Rust guideline compliant 1.0.
