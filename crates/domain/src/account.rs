// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Defines the closed account capability without OAuth or transport policy.
//!
//! Application policy validates scopes and persists the accepted capability.
//! This value alone is not proof of a current credential or dispatch permission.

/// Describes the accepted mailbox access capability of an account.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountCapability {
    /// Allows mailbox reads only.
    ReadOnly,
    /// Allows the closed mailbox command set as well as reads.
    Modify,
}
