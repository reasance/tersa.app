// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Shares hardened transport configuration, creating isolated credential expectations per operation.

use crate::flows::SharedMonotonicClock;
use crate::grants::OperationGrants;
use crate::{FlowError, Installation, OAuthClient};
use std::sync::Arc;
use tersa_application::{
    mailbox::BoxFuture,
    oauth::{SystemMonotonicClock, SystemWallClock},
    token::{ExchangeRequest, RefreshRequest, TokenResponse, TokenTransport, TokenTransportError},
};
use tersa_token_broker_core::{BrokerCore, GetRandomEntropy};
use zeroize::Zeroizing;

#[derive(Clone, Debug)]
pub(crate) struct SharedTransport(pub(crate) Arc<dyn TokenTransport>);
impl TokenTransport for SharedTransport {
    fn exchange(
        &self,
        request: ExchangeRequest,
    ) -> BoxFuture<'_, Result<TokenResponse, TokenTransportError>> {
        self.0.exchange(request)
    }
    fn refresh(
        &self,
        request: RefreshRequest,
    ) -> BoxFuture<'_, Result<TokenResponse, TokenTransportError>> {
        self.0.refresh(request)
    }
    fn revoke<'a>(
        &'a self,
        token: &'a Zeroizing<String>,
    ) -> BoxFuture<'a, Result<(), TokenTransportError>> {
        self.0.revoke(token)
    }
}
pub(crate) type Broker = BrokerCore<
    SharedTransport,
    OperationGrants,
    SharedMonotonicClock,
    SystemWallClock,
    GetRandomEntropy,
>;
pub(crate) struct Online {
    client: OAuthClient,
    transport: SharedTransport,
}
impl Online {
    pub(crate) fn new(client: OAuthClient, transport: impl TokenTransport + 'static) -> Self {
        Self {
            client,
            transport: SharedTransport(Arc::new(transport)),
        }
    }
    pub(crate) fn broker(&self, installation: &Arc<Installation>) -> Result<Broker, FlowError> {
        BrokerCore::new(
            self.client.client_id.clone(),
            self.client.client_secret.clone(),
            std::time::Duration::from_secs(600),
            (
                self.transport.clone(),
                OperationGrants::new(Arc::clone(installation)),
                SharedMonotonicClock(Arc::new(SystemMonotonicClock::new())),
                SystemWallClock,
                GetRandomEntropy,
            ),
        )
        .map_err(|_error| FlowError::Configuration)
    }
}
