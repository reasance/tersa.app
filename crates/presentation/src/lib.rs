// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Message rendering for tersa: the body to show, HTML converted to text,
//! and text made safe for the terminal.

#![forbid(unsafe_code)]

pub mod html;
pub mod message;
pub mod terminal;

// Rust guideline compliant 1.0.
