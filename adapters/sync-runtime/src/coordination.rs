// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Process-local account permits; callers still hold the installation lock.

use crate::FlowError;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tersa_application::mailbox::AccountId;

#[derive(Default)]
pub(crate) struct AccountOperation {
    pub(crate) permit: Arc<tokio::sync::Mutex<()>>,
    generation: AtomicU64,
}
impl AccountOperation {
    pub(crate) fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }
    pub(crate) fn invalidate(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
    }
    pub(crate) fn validate(&self, expected: u64) -> Result<(), FlowError> {
        if self.generation() == expected {
            Ok(())
        } else {
            Err(FlowError::Token(
                tersa_token_broker_core::BrokerError::GrantChanged,
            ))
        }
    }
}
#[derive(Default)]
pub(crate) struct Accounts(Mutex<HashMap<AccountId, Arc<AccountOperation>>>);
impl Accounts {
    pub(crate) fn get(&self, account: &AccountId) -> Result<Arc<AccountOperation>, FlowError> {
        Ok(Arc::clone(
            self.0
                .lock()
                .map_err(|_error| FlowError::Configuration)?
                .entry(account.clone())
                .or_default(),
        ))
    }
}
