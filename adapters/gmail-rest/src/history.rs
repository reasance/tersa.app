// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Implements GET-only History, baseline, metadata, snapshot and label reads.
//!
//! Provider envelopes are validated before exposing any whole-record prefix.
//! Raw generic and specific references both consume processing budget; normalized
//! events omit generic entries covered by specific events and coalesce duplicates.
//! No response cursor is persisted, no fallback/retention policy is run, and no
//! mailbox mutation endpoint is available through this module.

use super::json_object::Object;
use super::{
    AccountId, BASE_URL, BoxFuture, GmailMailbox, GmailMetadata, JSON_LIMIT, MessageFormat,
    MessageId, PageSize, PageToken, RemoteMailboxError, Request, ThreadId, Url, envelope_from,
    list_request, message_request,
};
use serde::{
    Deserialize,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Number, Value};
use std::collections::{BTreeMap, BTreeSet};
use tersa_application::{
    history::{
        CapturedBaseline, GmailHistoryFeed, HistoryEvent, HistoryEventKind, HistoryFeedError,
        HistoryPage, HistoryQuery, HistoryRecord, LocalHistoryStop, MAX_HISTORY_RECORDS,
        MAX_PAGE_REFERENCES, MAX_RECORD_MESSAGES, ProviderContinuation, SNAPSHOT_PAGE_SIZE,
        SnapshotPage,
    },
    mailbox_state::{
        ContractError, MessageKey, MessageMetadata, MessageObservation, MetadataObservation,
        MetadataReadError, RemoteMessageState,
    },
};
use tersa_domain::{
    history::HistoryCursor,
    label::{LabelCatalog, LabelDefinition, LabelId, LabelKind, LabelMembership, LabelName},
};

type ProfileBaseline = Object<ProfileBaselineFields>;
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProfileBaselineFields {
    history_id: String,
}

const HISTORY_FIELDS: &str = "history(id,messages(id),messagesAdded(message(id)),messagesDeleted(message(id)),labelsAdded(message(id),labelIds),labelsRemoved(message(id),labelIds)),nextPageToken,historyId";

fn invalid() -> MetadataReadError {
    MetadataReadError::InvalidResponse
}
fn map_read(error: RemoteMailboxError) -> MetadataReadError {
    match error {
        RemoteMailboxError::AuthorizationRequired => MetadataReadError::AuthorizationRequired,
        RemoteMailboxError::RateLimited => MetadataReadError::RateLimited,
        RemoteMailboxError::Transport => MetadataReadError::Transport,
        // Resource-specific callers intercept 404. A generic read failure is
        // never History expiry, profile absence or a missing-message proof.
        _ => invalid(),
    }
}
fn read_request(segments: &[&str], query: &[(&str, String)]) -> Result<Request, MetadataReadError> {
    Request::new(
        Url::parse(BASE_URL).map_err(|_e| invalid())?,
        segments,
        query,
    )
    .map_err(map_read)
}
fn continuation(token: Option<String>) -> Result<ProviderContinuation, MetadataReadError> {
    token
        .map(PageToken::new)
        .transpose()
        .map(|token| token.map_or(ProviderContinuation::End, ProviderContinuation::Next))
        .map_err(|_e| invalid())
}

impl GmailHistoryFeed for GmailMailbox {
    fn history_page<'a>(
        &'a self,
        query: &'a HistoryQuery,
    ) -> BoxFuture<'a, Result<HistoryPage, HistoryFeedError>> {
        Box::pin(async move {
            self.checked_account(query.account_id())
                .map_err(map_read)
                .map_err(HistoryFeedError::Read)?;
            let mut params = vec![
                ("startHistoryId", query.start().as_str().to_owned()),
                ("maxResults", query.page_size().get().to_string()),
                ("fields", HISTORY_FIELDS.to_owned()),
            ];
            if let Some(token) = query.continuation() {
                params.push(("pageToken", token.as_str().to_owned()));
            }
            let request = read_request(&["history"], &params).map_err(HistoryFeedError::Read)?;
            let response = self
                .transport
                .get(request, JSON_LIMIT)
                .await
                .map_err(super::TransportError::into_mailbox_error)
                .map_err(map_read)
                .map_err(HistoryFeedError::Read)?;
            match response.status {
                200..300 => decode_history(&response.body, query),
                404 => Err(HistoryFeedError::CursorExpired),
                400 if query.continuation().is_some() => Err(HistoryFeedError::InvalidContinuation),
                status => Err(HistoryFeedError::Read(map_read(super::map_status(
                    status,
                    &response.body,
                )))),
            }
        })
    }
    fn capture_baseline<'a>(
        &'a self,
        account: &'a AccountId,
    ) -> BoxFuture<'a, Result<CapturedBaseline, MetadataReadError>> {
        Box::pin(async move {
            self.checked_account(account).map_err(map_read)?;
            let Object(profile): ProfileBaseline = self
                .request_json(
                    read_request(&["profile"], &[("fields", "historyId".to_owned())])?,
                    JSON_LIMIT,
                )
                .await
                .map_err(|error| match error {
                    RemoteMailboxError::NotFound => MetadataReadError::ProfileMissing,
                    _ => map_read(error),
                })?;
            Ok(CapturedBaseline::new(
                account.clone(),
                HistoryCursor::new(profile.history_id).map_err(|_e| invalid())?,
            ))
        })
    }
    fn snapshot_page<'a>(
        &'a self,
        baseline: &'a CapturedBaseline,
        token: Option<&'a PageToken>,
    ) -> BoxFuture<'a, Result<SnapshotPage, MetadataReadError>> {
        Box::pin(async move {
            self.checked_account(baseline.account_id())
                .map_err(map_read)?;
            let size = PageSize::new(u16::try_from(SNAPSHOT_PAGE_SIZE).map_err(|_e| invalid())?)
                .map_err(|_e| invalid())?;
            let Object(list): SnapshotList = self
                .request_json(list_request(size, token).map_err(map_read)?, JSON_LIMIT)
                .await
                .map_err(map_read)?;
            if list.messages.len() > SNAPSHOT_PAGE_SIZE {
                return Err(invalid());
            }
            let next = continuation(list.next_page_token)?;
            let mut listed = Vec::new();
            let mut seen = BTreeSet::new();
            // Validate the complete list before hydration; omission is never
            // used as target-absence proof for pending commands.
            for Object(item) in list.messages {
                let id = MessageId::new(item.id).map_err(|_e| invalid())?;
                let thread = ThreadId::new(item.thread_id).map_err(|_e| invalid())?;
                if !seen.insert(id.as_str().to_owned()) {
                    return Err(invalid());
                }
                // Validate path safety before any hydration request.
                message_request(&id, MessageFormat::Metadata).map_err(map_read)?;
                listed.push((id, thread));
            }
            let mut items = Vec::new();
            for (id, thread) in listed {
                let key = MessageKey::new(baseline.account_id().clone(), id);
                match self.message_metadata(&key).await? {
                    MetadataObservation::Missing(_) => {} // exact hydration GET 404, not list omission
                    MetadataObservation::Known(metadata) => {
                        if metadata.envelope().thread_id() != &thread {
                            return Err(invalid());
                        }
                        items.push(metadata);
                    }
                }
            }
            SnapshotPage::new(baseline.clone(), items, next).map_err(|_e| invalid())
        })
    }
    fn observe_message<'a>(
        &'a self,
        key: &'a MessageKey,
    ) -> BoxFuture<'a, Result<MessageObservation, MetadataReadError>> {
        Box::pin(async move {
            self.checked_account(key.account_id()).map_err(map_read)?;
            let body = match self
                .request_body(
                    message_request(key.message_id(), MessageFormat::Minimal).map_err(map_read)?,
                    JSON_LIMIT,
                )
                .await
            {
                Ok(body) => body,
                Err(RemoteMailboxError::NotFound) => {
                    return MessageObservation::new(key.clone(), RemoteMessageState::Missing)
                        .map_err(|_e| invalid());
                }
                Err(error) => return Err(map_read(error)),
            };
            let Object(message): MinimalMessage =
                serde_json::from_slice(&body).map_err(|_e| invalid())?;
            if message.id != key.message_id().as_str() {
                return Err(invalid());
            }
            let membership = complete_membership(key.account_id(), message.label_ids)?;
            MessageObservation::new(key.clone(), RemoteMessageState::Known(membership))
                .map_err(|_e| invalid())
        })
    }
    fn message_metadata<'a>(
        &'a self,
        key: &'a MessageKey,
    ) -> BoxFuture<'a, Result<MetadataObservation, MetadataReadError>> {
        Box::pin(async move {
            self.checked_account(key.account_id()).map_err(map_read)?;
            let body = match self
                .request_body(
                    message_request(key.message_id(), MessageFormat::Metadata).map_err(map_read)?,
                    JSON_LIMIT,
                )
                .await
            {
                Ok(body) => body,
                Err(RemoteMailboxError::NotFound) => {
                    return Ok(MetadataObservation::Missing(key.clone()));
                }
                Err(error) => return Err(map_read(error)),
            };
            let message: GmailMetadata = serde_json::from_slice(&body).map_err(|_e| invalid())?;
            let membership = complete_membership(key.account_id(), message.0.label_ids.clone())?;
            let envelope = envelope_from(message, key.message_id()).map_err(map_read)?;
            MessageMetadata::new(key.clone(), envelope, membership)
                .map(MetadataObservation::Known)
                .map_err(|_e| invalid())
        })
    }
}

type SnapshotList = Object<SnapshotListFields>;
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SnapshotListFields {
    #[serde(default)]
    messages: Vec<super::ListedMessage>,
    #[serde(default, deserialize_with = "present_string")]
    next_page_token: Option<String>,
}
fn present_string<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    String::deserialize(deserializer).map(Some)
}

type MinimalMessage = Object<MinimalMessageFields>;
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MinimalMessageFields {
    id: String,
    // This is a fixed exact messages.get requesting labelIds. ProtoJSON omits
    // empty repeated fields; missing means the observed empty set here only.
    #[serde(default)]
    label_ids: Vec<String>,
}
fn complete_membership(
    account: &AccountId,
    raw: Vec<String>,
) -> Result<LabelMembership, MetadataReadError> {
    if raw.len() > LabelMembership::MAX_LABELS {
        return Err(invalid());
    }
    let ids = raw
        .into_iter()
        .map(LabelId::new)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_e| invalid())?;
    LabelMembership::new(account.clone(), ids).map_err(|_e| invalid())
}

type LabelsDocument = Object<LabelEntries>;
type LabelDocument = Object<LabelFields>;
#[derive(Deserialize)]
struct LabelEntries {
    labels: Vec<LabelDocument>,
}
#[derive(Deserialize)]
struct LabelFields {
    id: String,
    name: String,
    #[serde(rename = "type")]
    kind: String,
}
fn label_definition(
    account: &AccountId,
    value: LabelDocument,
) -> Result<LabelDefinition, MetadataReadError> {
    let Object(value) = value;
    let kind = match value.kind.as_str() {
        "system" => LabelKind::System,
        "user" => LabelKind::User,
        _ => return Err(invalid()),
    };
    LabelDefinition::new(
        account.clone(),
        LabelId::new(value.id).map_err(|_e| invalid())?,
        LabelName::new(value.name).map_err(|_e| invalid())?,
        kind,
    )
    .map_err(|_e| invalid())
}
pub(super) fn decode_label_response(
    account: &AccountId,
    body: &[u8],
) -> Result<LabelDefinition, MetadataReadError> {
    let value: LabelDocument = serde_json::from_slice(body).map_err(|_e| invalid())?;
    label_definition(account, value)
}

pub(super) async fn read_label_catalog(
    mailbox: &GmailMailbox,
    account: &AccountId,
) -> Result<LabelCatalog, MetadataReadError> {
    mailbox.checked_account(account).map_err(map_read)?;
    let Object(labels): LabelsDocument = mailbox
        .request_json(
            read_request(
                &["labels"],
                &[("fields", "labels(id,name,type)".to_owned())],
            )?,
            JSON_LIMIT,
        )
        .await
        .map_err(map_read)?;
    if labels.labels.len() > LabelCatalog::MAX_LABELS {
        return Err(invalid());
    }
    let definitions = labels
        .labels
        .into_iter()
        .map(|value| label_definition(account, value))
        .collect::<Result<Vec<_>, _>>()?;
    LabelCatalog::new(account.clone(), definitions).map_err(|_e| invalid())
}

pub(super) async fn read_label_definition(
    mailbox: &GmailMailbox,
    account: &AccountId,
    id: &LabelId,
) -> Result<Option<LabelDefinition>, MetadataReadError> {
    mailbox.checked_account(account).map_err(map_read)?;
    let request = read_request(
        &["labels", id.as_str()],
        &[("fields", "id,name,type".to_owned())],
    )?;
    let value: LabelDocument = match mailbox.request_json(request, JSON_LIMIT).await {
        Ok(value) => value,
        Err(RemoteMailboxError::NotFound) => return Ok(None),
        Err(error) => return Err(map_read(error)),
    };
    let definition = label_definition(account, value)?;
    if definition.id() != id {
        return Err(invalid());
    }
    Ok(Some(definition))
}
type HistoryDocument = Object<HistoryDocumentFields>;
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HistoryDocumentFields {
    history_id: String,
    #[serde(default)]
    history: Vec<RecordDocument>,
    #[serde(default, deserialize_with = "present_value")]
    next_page_token: Option<Value>,
}
type RecordDocument = Object<RecordDocumentFields>;
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RecordDocumentFields {
    id: String,
    #[serde(default, deserialize_with = "present_value")]
    messages: Option<Value>,
    #[serde(default, deserialize_with = "present_value")]
    messages_added: Option<Value>,
    #[serde(default, deserialize_with = "present_value")]
    messages_deleted: Option<Value>,
    #[serde(default, deserialize_with = "present_value")]
    labels_added: Option<Value>,
    #[serde(default, deserialize_with = "present_value")]
    labels_removed: Option<Value>,
}
fn present_value<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Value>, D::Error> {
    Value::deserialize(deserializer).map(Some)
}
fn history_invalid() -> HistoryFeedError {
    HistoryFeedError::Read(invalid())
}
fn decode_history(body: &[u8], query: &HistoryQuery) -> Result<HistoryPage, HistoryFeedError> {
    if body.len() > JSON_LIMIT {
        return Err(history_invalid());
    }
    // Reject duplicate JSON keys instead of letting a generic Value silently
    // choose one message/cursor identity. The raw document is capped at 2 MiB.
    let strict: StrictValue = serde_json::from_slice(body).map_err(|_e| history_invalid())?;
    let Object(page): HistoryDocument =
        serde_json::from_value(strict.0).map_err(|_e| history_invalid())?;
    if page.history.len() > MAX_HISTORY_RECORDS {
        return Err(history_invalid());
    }
    let head = HistoryCursor::new(page.history_id).map_err(|_e| history_invalid())?;
    let raw_next = match page.next_page_token {
        None => None,
        Some(Value::String(token)) => Some(token),
        Some(_) => return Err(HistoryFeedError::InvalidContinuation),
    };
    let next = continuation(raw_next).map_err(|_e| HistoryFeedError::InvalidContinuation)?;
    let mut ids = Vec::with_capacity(page.history.len());
    let mut previous = query.predecessor();
    if &head < previous {
        return Err(history_invalid());
    }
    // Validate ALL record IDs/order, including those beyond a local prefix.
    for raw in &page.history {
        let id = HistoryCursor::new(raw.0.id.as_str()).map_err(|_e| history_invalid())?;
        if &id <= previous || id > head {
            return Err(history_invalid());
        }
        ids.push(id);
        previous = ids.last().ok_or_else(history_invalid)?;
    }
    let count = page.history.len();
    let mut remaining = MAX_PAGE_REFERENCES;
    let mut records = Vec::new();
    let mut stop = None;
    for (raw, id) in page.history.into_iter().zip(ids) {
        match decode_record(query.account_id(), id, raw, remaining) {
            Ok(record) => {
                remaining -= record.decoded_references();
                records.push(record);
            }
            Err(reason) => {
                stop = Some(reason);
                break;
            }
        }
    }
    HistoryPage::new(query.clone(), head, records, next, stop, count).map_err(|error| match error {
        ContractError::Continuation => HistoryFeedError::InvalidContinuation,
        _ => history_invalid(),
    })
}

#[derive(Default)]
struct Changes {
    added: bool,
    deleted: bool,
    generic: bool,
    labels_added: BTreeSet<LabelId>,
    labels_removed: BTreeSet<LabelId>,
}
fn decode_record(
    account: &AccountId,
    id: HistoryCursor,
    raw: RecordDocument,
    remaining: usize,
) -> Result<HistoryRecord, LocalHistoryStop> {
    let Object(raw) = raw;
    let bad = LocalHistoryStop::RecoveryRequired;
    let arrays = [
        raw.messages,
        raw.messages_added,
        raw.messages_deleted,
        raw.labels_added,
        raw.labels_removed,
    ];
    let mut references: usize = 0;
    for field in arrays.iter().flatten() {
        let list = field.as_array().ok_or(bad)?;
        references = references.checked_add(list.len()).ok_or(bad)?;
    }
    if references > MAX_PAGE_REFERENCES {
        return Err(bad);
    }
    if references > remaining {
        return Err(LocalHistoryStop::ReferenceBudget);
    }
    let mut changes: BTreeMap<String, Changes> = BTreeMap::new();
    for (kind, field) in arrays.into_iter().enumerate() {
        let Some(Value::Array(values)) = field else {
            continue;
        };
        for entry in values {
            let message = if kind == 0 {
                &entry
            } else {
                entry.get("message").ok_or(bad)?
            };
            let message_id = message.get("id").and_then(Value::as_str).ok_or(bad)?;
            MessageId::new(message_id).map_err(|_e| bad)?;
            let change = changes.entry(message_id.to_owned()).or_default();
            match kind {
                0 => change.generic = true,
                1 => change.added = true,
                2 => change.deleted = true,
                3 | 4 => {
                    let labels = entry.get("labelIds").and_then(Value::as_array).ok_or(bad)?;
                    if labels.is_empty() || labels.len() > LabelMembership::MAX_LABELS {
                        return Err(bad);
                    }
                    let target = if kind == 3 {
                        &mut change.labels_added
                    } else {
                        &mut change.labels_removed
                    };
                    for label in labels {
                        target.insert(LabelId::new(label.as_str().ok_or(bad)?).map_err(|_e| bad)?);
                    }
                    if target.len() > LabelMembership::MAX_LABELS {
                        return Err(bad);
                    }
                }
                _ => return Err(bad),
            }
            if changes.len() > MAX_RECORD_MESSAGES {
                return Err(bad);
            }
        }
    }
    let mut events = Vec::new();
    for (message, change) in changes {
        let key = MessageKey::new(account.clone(), MessageId::new(message).map_err(|_e| bad)?);
        let specific = change.added
            || change.deleted
            || !change.labels_added.is_empty()
            || !change.labels_removed.is_empty();
        let kinds = [
            change.added.then_some(HistoryEventKind::Added),
            change.deleted.then_some(HistoryEventKind::Deleted),
            (!change.labels_added.is_empty()).then_some(HistoryEventKind::LabelsAdded(
                change.labels_added.into_iter().collect(),
            )),
            (!change.labels_removed.is_empty()).then_some(HistoryEventKind::LabelsRemoved(
                change.labels_removed.into_iter().collect(),
            )),
            (change.generic && !specific).then_some(HistoryEventKind::Changed),
        ];
        for kind in kinds.into_iter().flatten() {
            events.push(HistoryEvent::new(key.clone(), kind).map_err(|_e| bad)?);
        }
    }
    HistoryRecord::new(account.clone(), id, events, references).map_err(|_e| bad)
}

// serde_json::Value normally discards duplicate object keys. Reject them for the
// deferred record payload as well as the typed outer envelope, without raw logs.
struct StrictValue(Value);
impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct StrictVisitor;
        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = Value;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("unambiguous JSON value")
            }
            fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
                Ok(Value::Null)
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Value, E> {
                Ok(Value::Bool(v))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Value, E> {
                Ok(Value::Number(v.into()))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Value, E> {
                Ok(Value::Number(v.into()))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Value, E> {
                Number::from_f64(v)
                    .map(Value::Number)
                    .ok_or_else(|| E::custom("invalid JSON number"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Value, E> {
                Ok(Value::String(v.to_owned()))
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Value, E> {
                Ok(Value::String(v))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
                let mut values = Vec::new();
                while let Some(v) = seq.next_element::<StrictValue>()? {
                    values.push(v.0);
                }
                Ok(Value::Array(values))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
                let mut values = Map::new();
                while let Some((k, v)) = map.next_entry::<String, StrictValue>()? {
                    if values.insert(k, v.0).is_some() {
                        return Err(de::Error::custom("duplicate JSON key"));
                    }
                }
                Ok(Value::Object(values))
            }
        }
        deserializer.deserialize_any(StrictVisitor).map(Self)
    }
}
