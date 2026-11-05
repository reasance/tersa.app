// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Controlled provider facts used by the real coordinator/store, never network calls.
use std::{
    collections::BTreeMap,
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
use tersa_application::{
    command::{
        CommandDispatchError, DispatchFact, DispatchReceipt, RemoteCommandOutcome,
        RemoteMailboxCommands, UserLabelObservation,
    },
    history::{
        CapturedBaseline, GmailHistoryFeed, HistoryFeedError, HistoryPage, HistoryQuery,
        SnapshotPage,
    },
    mailbox::{AccountId, BoxFuture, PageToken},
    mailbox_state::{
        LabelCatalog, LabelDefinition, LabelId, LabelMembership, MessageKey, MessageObservation,
        MetadataObservation, MetadataReadError, RemoteMessageState, UserLabel,
    },
};
#[derive(Default)]
pub(super) struct Port {
    rows: Mutex<BTreeMap<String, Vec<LabelId>>>,
    pub labels: Mutex<Vec<LabelDefinition>>,
    pub sends: AtomicUsize,
}
impl Port {
    pub fn row(&self, id: &str, labels: &[&str]) {
        self.rows.lock().expect("rows").insert(
            id.to_owned(),
            labels
                .iter()
                .map(|id| LabelId::new(*id).expect("label"))
                .collect(),
        );
    }
    fn read_label_catalog<'a>(
        &'a self,
        account: &'a AccountId,
    ) -> BoxFuture<'a, Result<LabelCatalog, MetadataReadError>> {
        Box::pin(async move {
            Ok(
                LabelCatalog::new(account.clone(), self.labels.lock().expect("labels").clone())
                    .expect("catalog"),
            )
        })
    }
    fn read_user_label<'a>(
        &'a self,
        label: &'a UserLabel,
    ) -> BoxFuture<'a, Result<UserLabelObservation, MetadataReadError>> {
        Box::pin(async move {
            let definition = self
                .labels
                .lock()
                .expect("labels")
                .iter()
                .find(|definition| definition.id() == label.id())
                .cloned();
            Ok(UserLabelObservation::new(label.clone(), definition).expect("known label"))
        })
    }
}
impl GmailHistoryFeed for Port {
    fn history_page<'a>(
        &'a self,
        _query: &'a HistoryQuery,
    ) -> BoxFuture<'a, Result<HistoryPage, HistoryFeedError>> {
        Box::pin(async { panic!("command-only test must not read History") })
    }
    fn capture_baseline<'a>(
        &'a self,
        _account: &'a AccountId,
    ) -> BoxFuture<'a, Result<CapturedBaseline, MetadataReadError>> {
        Box::pin(async { panic!("command-only test must not capture a baseline") })
    }
    fn snapshot_page<'a>(
        &'a self,
        _baseline: &'a CapturedBaseline,
        _continuation: Option<&'a PageToken>,
    ) -> BoxFuture<'a, Result<SnapshotPage, MetadataReadError>> {
        Box::pin(async { panic!("command-only test must not read a snapshot") })
    }
    fn message_metadata<'a>(
        &'a self,
        _key: &'a MessageKey,
    ) -> BoxFuture<'a, Result<MetadataObservation, MetadataReadError>> {
        Box::pin(async { panic!("command-only test must not fetch headers") })
    }
    fn observe_message<'a>(
        &'a self,
        key: &'a MessageKey,
    ) -> BoxFuture<'a, Result<MessageObservation, MetadataReadError>> {
        Box::pin(async move {
            let state = self
                .rows
                .lock()
                .expect("rows")
                .get(key.message_id().as_str())
                .map_or(RemoteMessageState::Missing, |labels| {
                    RemoteMessageState::Known(
                        LabelMembership::new(key.account_id().clone(), labels.clone())
                            .expect("membership"),
                    )
                });
            Ok(MessageObservation::new(key.clone(), state).expect("observation"))
        })
    }
}

impl RemoteMailboxCommands for Port {
    fn dispatch<'a>(
        &'a self,
        receipt: &'a DispatchReceipt,
    ) -> BoxFuture<'a, Result<RemoteCommandOutcome, CommandDispatchError>> {
        Box::pin(async move {
            self.sends.fetch_add(1, Ordering::SeqCst);
            Ok(RemoteCommandOutcome::new(receipt, DispatchFact::Ambiguous).expect("possible send"))
        })
    }
    fn label_catalog<'a>(
        &'a self,
        account: &'a AccountId,
    ) -> BoxFuture<'a, Result<LabelCatalog, MetadataReadError>> {
        self.read_label_catalog(account)
    }
    fn observe_user_label<'a>(
        &'a self,
        label: &'a UserLabel,
    ) -> BoxFuture<'a, Result<UserLabelObservation, MetadataReadError>> {
        self.read_user_label(label)
    }
}
