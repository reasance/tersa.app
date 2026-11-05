// This Source Code Form is subject to the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Production cached views use runtime filtering and opaque runtime continuations.

use crate::tui::{MailContinuation, MailPage, MailSource, ReadMarker, Row, ViewScope};
use std::{cell::RefCell, sync::Arc};
use tersa_application::{
    command::MailboxField,
    mailbox::{AccountId, MailboxReader, MessageId},
    mailbox_state::{LabelCatalog, LabelId, LabelKind},
};
use tersa_presentation::{terminal::SafeText, triage as p8};
use tersa_store_sqlcipher::CachedProviderState;
use tersa_sync_runtime::{CachedMailboxFilter, CachedViewRow, CachedViewScope, Runtime};

pub(crate) struct RuntimeSource {
    runtime: Arc<Runtime>,
    executor: tokio::runtime::Runtime,
    filter: RefCell<CachedMailboxFilter>,
}
impl RuntimeSource {
    pub(super) fn new(runtime: Arc<Runtime>, executor: tokio::runtime::Runtime) -> Self {
        Self {
            runtime,
            executor,
            filter: RefCell::new(CachedMailboxFilter::Recent),
        }
    }
}
impl MailSource for RuntimeSource {
    fn page(
        &self,
        scope: &ViewScope,
        continuation: Option<&MailContinuation>,
        limit: u16,
    ) -> Result<MailPage, ()> {
        let scope = match scope {
            ViewScope::All => CachedViewScope::All,
            ViewScope::Account(account) => CachedViewScope::Account(account.clone()),
        };
        let continuation = match continuation {
            None => None,
            Some(MailContinuation::Runtime(value)) => Some(value),
            Some(MailContinuation::Legacy(_)) => return Err(()),
        };
        let page = self
            .executor
            .block_on(
                self.runtime
                    .cached_view(&scope, &self.filter.borrow(), limit, continuation),
            )
            .map_err(|_error| ())?;
        let mut catalogs = std::collections::HashMap::new();
        for row in &page.rows {
            catalogs
                .entry(row.account.clone())
                .or_insert_with(|| self.label_catalog(&row.account).ok().flatten());
        }
        let rows = page
            .rows
            .into_iter()
            .map(|raw| {
                let mut row = Row::from_envelope(&raw.envelope, &raw.account);
                // P7b supplies legacy display for ReadOnly and complete observed
                // read state for Modify. Absence remains visible in the list.
                row.read = match raw.display_unread {
                    Some(unread) => ReadMarker::from_unread(unread),
                    None => match &raw.observed {
                        CachedProviderState::Missing => ReadMarker::Missing,
                        CachedProviderState::Unknown | CachedProviderState::Known(_) => {
                            ReadMarker::Unknown
                        }
                    },
                };
                row.triage = Some(message_document(
                    &raw,
                    catalogs.get(&raw.account).and_then(Option::as_ref),
                ));
                row.capability = Some(raw.capability);
                row.observed = Some(raw.observed);
                row
            })
            .collect();
        Ok(MailPage {
            rows,
            continuation: page.continuation.map(MailContinuation::Runtime),
            unavailable_accounts: page.unavailable_accounts,
        })
    }
    fn message(&self, account: &AccountId, id: &MessageId) -> Result<Option<Vec<u8>>, ()> {
        let store = self
            .runtime
            .installation()
            .open_store_for_display(account)
            .map_err(|_error| ())?;
        self.executor
            .block_on(store.get_message(account, id))
            .map(|message| message.map(|message| message.into_content().into_bytes()))
            .map_err(|_error| ())
    }
    fn account_labels(&self) -> Vec<(AccountId, SafeText)> {
        self.runtime
            .installation()
            .accounts()
            .unwrap_or_default()
            .into_iter()
            .map(|account| {
                let metadata = self
                    .executor
                    .block_on(self.runtime.account_metadata(&account))
                    .ok();
                let label = metadata
                    .as_ref()
                    .and_then(|metadata| metadata.email())
                    .map_or_else(
                        || p8::render_identifier(account.as_str()),
                        |email| {
                            p8::render_account(p8::AccountInput {
                                name: email.as_str(),
                                identifier: account.as_str(),
                                capability: capability(
                                    metadata
                                        .as_ref()
                                        .expect("metadata for stored email")
                                        .capability(),
                                ),
                                authority: p8::Authority::Unavailable,
                            })
                            .name
                        },
                    );
                (account, label)
            })
            .collect()
    }
    fn set_filter(&self, filter: &CachedMailboxFilter) -> Result<(), ()> {
        *self.filter.borrow_mut() = filter.clone();
        Ok(())
    }
    fn account_state(
        &self,
        account: &AccountId,
    ) -> Result<tersa_sync_runtime::AccountCommandStatus, ()> {
        self.executor
            .block_on(self.runtime.command_status(account))
            .map_err(|_error| ())
    }
    fn label_catalog(&self, account: &AccountId) -> Result<Option<LabelCatalog>, ()> {
        self.runtime
            .cached_label_catalog(account)
            .map_err(|_error| ())
    }
}
fn capability(value: tersa_application::AccountCapability) -> p8::Capability {
    match value {
        tersa_application::AccountCapability::ReadOnly => p8::Capability::ReadOnly,
        tersa_application::AccountCapability::Modify => p8::Capability::Modify,
    }
}
fn label<'a>(id: &'a LabelId, catalog: Option<&'a LabelCatalog>) -> p8::LabelInput<'a> {
    p8::LabelInput {
        name: catalog
            .and_then(|catalog| catalog.definitions().iter().find(|label| label.id() == id))
            .map(|label| label.name().as_str()),
        identifier: id.as_str(),
    }
}
fn observed_labels<'a>(
    row: &'a CachedViewRow,
    catalog: Option<&'a LabelCatalog>,
) -> (Vec<p8::LabelInput<'a>>, bool) {
    let mut unknown_definition = false;
    let labels: Vec<_> = match &row.observed {
        CachedProviderState::Known(membership) => membership
            .ids()
            .iter()
            .filter(|id| {
                if matches!(
                    id.as_str(),
                    "INBOX" | "TRASH" | "SPAM" | "UNREAD" | "STARRED"
                ) {
                    return false;
                }
                if let Some(definition) = catalog.and_then(|catalog| {
                    catalog
                        .definitions()
                        .iter()
                        .find(|definition| definition.id() == *id)
                }) {
                    definition.kind() == LabelKind::User
                } else {
                    unknown_definition = true;
                    true
                } // Display only, not actionable User classification.
            })
            .map(|id| label(id, catalog))
            .collect(),
        _ => Vec::new(),
    };
    (labels, unknown_definition)
}
fn message_document(
    row: &CachedViewRow,
    catalog: Option<&LabelCatalog>,
) -> p8::MessageStateDocument {
    let (labels, unknown_definition) = observed_labels(row, catalog);
    let observed = match &row.observed {
        CachedProviderState::Unknown => p8::ObservedState::Unknown,
        CachedProviderState::Missing => p8::ObservedState::Missing,
        CachedProviderState::Known(membership) => {
            let has = |value| membership.ids().iter().any(|id| id.as_str() == value);
            p8::ObservedState::Known(p8::ObservedMessage {
                unread: has("UNREAD"),
                starred: has("STARRED"),
                folders: p8::Folders {
                    inbox: has("INBOX"),
                    trash: has("TRASH"),
                    spam: has("SPAM"),
                },
                labels: &labels,
            })
        }
    };
    let pending = row.pending.as_deref().unwrap_or_default();
    let label_sets: Vec<_> = pending
        .iter()
        .map(|projection| {
            let adds = projection
                .desired
                .memberships()
                .iter()
                .filter_map(|field| match field.field() {
                    MailboxField::UserLabel(user) if field.is_present() => {
                        Some(label(user.id(), catalog))
                    }
                    _ => None,
                })
                .collect::<Vec<_>>();
            let removes = projection
                .desired
                .memberships()
                .iter()
                .filter_map(|field| match field.field() {
                    MailboxField::UserLabel(user) if !field.is_present() => {
                        Some(label(user.id(), catalog))
                    }
                    _ => None,
                })
                .collect::<Vec<_>>();
            (adds, removes)
        })
        .collect();
    let projections: Vec<_> = pending
        .iter()
        .zip(&label_sets)
        .map(|(projection, (adds, removes))| {
            let mut desired = p8::DesiredMessage {
                add_labels: adds,
                remove_labels: removes,
                ..p8::DesiredMessage::default()
            };
            for field in projection.desired.memberships() {
                let value = Some(field.is_present());
                match field.field() {
                    MailboxField::Unread => desired.unread = value,
                    MailboxField::Starred => desired.starred = value,
                    MailboxField::Inbox => desired.inbox = value,
                    MailboxField::Trash => desired.trash = value,
                    MailboxField::Spam => desired.spam = value,
                    MailboxField::UserLabel(_) => {}
                }
            }
            let status = match projection.status {
                tersa_application::command::MailboxCommandStatus::Queued => {
                    p8::PendingStatus::Queued
                }
                tersa_application::command::MailboxCommandStatus::Dispatching => {
                    p8::PendingStatus::Dispatching
                }
                tersa_application::command::MailboxCommandStatus::Ambiguous => {
                    p8::PendingStatus::Ambiguous
                }
                _ => p8::PendingStatus::NeedsAttention,
            };
            p8::PendingInput { status, desired }
        })
        .collect();
    let mut doc = p8::render_message_state(p8::MessageStateInput {
        capability: capability(row.capability),
        legacy_unread: row.envelope.is_unread(),
        observed,
        pending: &projections,
    });
    if unknown_definition {
        doc.label_state = SafeText::single_line(
            "Observed label IDs; some definitions/classifications are unavailable.",
        );
    }
    doc
}
