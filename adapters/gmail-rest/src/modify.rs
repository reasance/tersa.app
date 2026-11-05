// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Sends only the approved mailbox writes from a durable, account-bound receipt.
//!
//! Requests are validated/encoded in full before any HTTP. Equal compensation
//! restore patches are grouped deterministically; only receipt-selected unsettled
//! IDs are sent. No transport retry occurs. Acknowledgement is not reconciliation
//! or Complete. Runtime owns the account permit, actual stored identity/capability
//! and current process-local credential generation; constructor values are trusted
//! inputs, not live database/session proof. Drop leaves Dispatching for recovery.

use super::json_object::Object;
use super::{
    BASE_URL, BoundedBody, GmailMailbox, HttpResponse, JSON_LIMIT, ReqwestTransport,
    TransportError, TransportFuture, hardened_client_builder, validate_access_token,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fmt,
    sync::atomic::{AtomicBool, Ordering},
};
use tersa_application::{
    AccountCapability,
    command::{
        CommandDispatchError, CommandRejection, DispatchFact, DispatchReceipt,
        RemoteCommandOutcome, RemoteMailboxCommands, UserLabelObservation, WriteAcknowledgement,
    },
    mailbox::{AccountId, BoxFuture},
    mailbox_state::MetadataReadError,
    scope::AcceptedScope,
};
use tersa_domain::{
    command::{DesiredMailboxState, MailboxCommandKind, MailboxCommandStatus, MailboxField},
    label::{LabelCatalog, LabelDefinition, LabelName, UserLabel},
    mailbox::MessageId,
};
use url::Url;
use zeroize::Zeroizing;

/// Executes one operation's closed Modify receipt, separately from GET-only `GmailMailbox`.
///
/// P7 must hold the account operation permit, verify actual persisted capability,
/// identity, access expiry and credential generation, then construct/use/drop this
/// component for one dispatch operation. Rotation/Upgrade/remove invalidates prior
/// access under that same permit. This adapter has no store and cannot observe
/// those changes itself; the one-dispatch guard is not a live-generation fence.
pub struct GmailModifyMailbox {
    account: AccountId,
    reads: GmailMailbox,
    writes: Box<dyn ModifyTransport>,
    dispatched: AtomicBool,
}
impl fmt::Debug for GmailModifyMailbox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GmailModifyMailbox([REDACTED])")
    }
}
impl GmailModifyMailbox {
    /// Creates a bound Modify component from trusted current grant/session values.
    ///
    /// # Errors
    /// Rejects non-Modify stored capability, readonly/legacy/incomplete accepted
    /// scope, and invalid bearer tokens before constructing clients. Client setup
    /// failure is `InvalidRequest`. No network or persistence is performed here.
    pub fn new(
        account: AccountId,
        access_token: String,
        persisted_capability: AccountCapability,
        accepted_scope: AcceptedScope,
    ) -> Result<Self, CommandDispatchError> {
        let token = Zeroizing::new(access_token);
        authorize(&token, persisted_capability, accepted_scope)?;
        let client = hardened_client_builder()
            // Override reqwest's default protocol-NACK replay for write operations.
            .retry(reqwest::retry::never())
            .build()
            .map_err(|_e| CommandDispatchError::InvalidRequest)?;
        let reads = GmailMailbox {
            account: account.clone(),
            transport: Box::new(ReqwestTransport {
                client: client.clone(),
                token: token.clone(),
            }),
        };
        Ok(Self {
            account,
            reads,
            writes: Box::new(ReqwestModifyTransport { client, token }),
            dispatched: AtomicBool::new(false),
        })
    }

    #[cfg(test)]
    fn with_transports<R: super::Transport + 'static, W: ModifyTransport + 'static>(
        account: AccountId,
        access_token: String,
        persisted: AccountCapability,
        scope: AcceptedScope,
        reads: R,
        writes: W,
    ) -> Result<Self, CommandDispatchError> {
        let token = Zeroizing::new(access_token);
        authorize(&token, persisted, scope)?;
        Ok(Self {
            reads: GmailMailbox::with_transport(account.clone(), reads),
            account,
            writes: Box::new(writes),
            dispatched: AtomicBool::new(false),
        })
    }
}
fn authorize(
    token: &str,
    persisted: AccountCapability,
    scope: AcceptedScope,
) -> Result<(), CommandDispatchError> {
    if persisted != AccountCapability::Modify
        || scope.capability() != AccountCapability::Modify
        || scope
            .evidence()
            .validate_for(AccountCapability::Modify)
            .is_err()
        || validate_access_token(token).is_err()
        || !token.bytes().all(|b| b.is_ascii_graphic())
    {
        return Err(CommandDispatchError::AuthorizationRequired);
    }
    Ok(())
}

impl RemoteMailboxCommands for GmailModifyMailbox {
    fn dispatch<'a>(
        &'a self,
        receipt: &'a DispatchReceipt,
    ) -> BoxFuture<'a, Result<RemoteCommandOutcome, CommandDispatchError>> {
        Box::pin(async move {
            let requests = prepare(&self.account, receipt)?;
            // Consume only after ALL requests validate, but before any possible send.
            self.dispatched
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .map_err(|_e| CommandDispatchError::InvalidRequest)?;
            let mut earlier_possible = false;
            let mut acknowledged = None;
            for request in requests {
                let expected = request.expected.clone();
                let fact = match self.writes.send(request).await {
                    Err(_e) => DispatchFact::Ambiguous,
                    Ok(response) => response_fact(&self.account, &expected, &response),
                };
                match fact {
                    DispatchFact::Acknowledged(ack) => {
                        earlier_possible = true;
                        acknowledged = Some(ack);
                    }
                    DispatchFact::Rejected(_) if earlier_possible => {
                        return Ok(outcome(receipt, DispatchFact::Ambiguous));
                    }
                    stopped => return Ok(outcome(receipt, stopped)),
                }
            }
            let fact = acknowledged.map_or(DispatchFact::Ambiguous, DispatchFact::Acknowledged);
            Ok(outcome(receipt, fact))
        })
    }
    fn label_catalog<'a>(
        &'a self,
        account: &'a AccountId,
    ) -> BoxFuture<'a, Result<LabelCatalog, MetadataReadError>> {
        Box::pin(async move { self.reads.label_catalog(account).await })
    }
    fn observe_user_label<'a>(
        &'a self,
        target: &'a UserLabel,
    ) -> BoxFuture<'a, Result<UserLabelObservation, MetadataReadError>> {
        Box::pin(async move {
            let definition = self
                .reads
                .label_definition(target.account_id(), target.id())
                .await?;
            UserLabelObservation::new(target.clone(), definition)
                .map_err(|_e| MetadataReadError::InvalidResponse)
        })
    }
}
fn outcome(receipt: &DispatchReceipt, fact: DispatchFact) -> RemoteCommandOutcome {
    // An invalid acknowledgement after possible send must still be Ambiguous,
    // never a pre-dispatch Err. Ambiguous construction itself has no shape guard.
    RemoteCommandOutcome::new(receipt, fact).unwrap_or_else(|_e| {
        RemoteCommandOutcome::new(receipt, DispatchFact::Ambiguous)
            .expect("Ambiguous accepts every validated receipt")
    })
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
struct Patch {
    add: Vec<String>,
    remove: Vec<String>,
}
fn patch(
    account: &AccountId,
    desired: &DesiredMailboxState,
) -> Result<Patch, CommandDispatchError> {
    if desired.account_id() != account {
        return Err(CommandDispatchError::InvalidRequest);
    }
    let mut result = Patch {
        add: Vec::new(),
        remove: Vec::new(),
    };
    for membership in desired.memberships() {
        let id = match membership.field() {
            MailboxField::Unread => "UNREAD",
            MailboxField::Starred => "STARRED",
            MailboxField::Inbox => "INBOX",
            MailboxField::Trash => "TRASH",
            MailboxField::Spam => "SPAM",
            MailboxField::UserLabel(label) => {
                check_user(account, label)?;
                label.id().as_str()
            }
        };
        if membership.is_present() {
            result.add.push(id.to_owned());
        } else {
            result.remove.push(id.to_owned());
        }
    }
    result.add.sort_unstable();
    result.remove.sort_unstable();
    Ok(result)
}
fn check_user(account: &AccountId, label: &UserLabel) -> Result<(), CommandDispatchError> {
    if label.account_id() != account {
        return Err(CommandDispatchError::InvalidRequest);
    }
    UserLabel::from_classified_id(account.clone(), label.id().clone())
        .map_err(|_e| CommandDispatchError::InvalidRequest)?;
    // Trusted prior classification is not fresh provider verification. P6/P7
    // reconcile known labels before store preparation; read helpers remain available.
    Ok(())
}
fn check_message(id: &MessageId) -> Result<(), CommandDispatchError> {
    // Keep the exact-ID read contract: these path-only identities cannot be
    // freshly reconciled by P4a and are never admitted to a write batch here.
    if matches!(id.as_str(), "." | "..") {
        return Err(CommandDispatchError::InvalidRequest);
    }
    Ok(())
}
fn prepare(
    account: &AccountId,
    receipt: &DispatchReceipt,
) -> Result<Vec<PreparedWrite>, CommandDispatchError> {
    let snapshot = receipt.snapshot();
    let command = snapshot.command();
    if command.account_id() != account
        || snapshot.stamp().key().account_id() != account
        || snapshot.status() != MailboxCommandStatus::Dispatching
    {
        return Err(CommandDispatchError::InvalidRequest);
    }
    match command.kind() {
        MailboxCommandKind::MessageState { targets, desired } => {
            let selected = receipt
                .targets()
                .ok_or(CommandDispatchError::InvalidRequest)?;
            if selected.account_id() != account
                || selected.ids().iter().any(|id| !targets.ids().contains(id))
            {
                return Err(CommandDispatchError::InvalidRequest);
            }
            for id in selected.ids() {
                check_message(id)?;
            }
            Ok(vec![batch(
                selected.ids().iter().map(MessageId::as_str).collect(),
                &patch(account, desired)?,
            )?])
        }
        MailboxCommandKind::Compensate(compensation) => {
            let selected = receipt
                .targets()
                .ok_or(CommandDispatchError::InvalidRequest)?;
            if selected.account_id() != account || compensation.account_id() != account {
                return Err(CommandDispatchError::InvalidRequest);
            }
            let mut groups: BTreeMap<Patch, Vec<&str>> = BTreeMap::new();
            for id in selected.ids() {
                check_message(id)?;
                let item = compensation
                    .items()
                    .iter()
                    .find(|item| item.message_id() == id)
                    .ok_or(CommandDispatchError::InvalidRequest)?;
                groups
                    .entry(patch(account, item.condition().restore_state())?)
                    .or_default()
                    .push(id.as_str());
            }
            groups
                .into_iter()
                .map(|(patch, ids)| batch(ids, &patch))
                .collect()
        }
        MailboxCommandKind::CreateLabel(name) => {
            if receipt.targets().is_some() {
                return Err(CommandDispatchError::InvalidRequest);
            }
            Ok(vec![request(
                Method::Post,
                &["labels"],
                Some(name_body(name)?),
                Expected::Create(name.clone()),
            )?])
        }
        MailboxCommandKind::RenameLabel { label, name } => {
            if receipt.targets().is_some() {
                return Err(CommandDispatchError::InvalidRequest);
            }
            check_user(account, label)?;
            Ok(vec![request(
                Method::Patch,
                &["labels", label.id().as_str()],
                Some(name_body(name)?),
                Expected::Rename {
                    label: label.clone(),
                    name: name.clone(),
                },
            )?])
        }
        MailboxCommandKind::DeleteLabel(label) => {
            if receipt.targets().is_some() {
                return Err(CommandDispatchError::InvalidRequest);
            }
            check_user(account, label)?;
            Ok(vec![request(
                Method::Delete,
                &["labels", label.id().as_str()],
                None,
                Expected::Delete,
            )?])
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Method {
    Post,
    Patch,
    Delete,
}
#[derive(Clone)]
enum Expected {
    Batch,
    Create(LabelName),
    Rename { label: UserLabel, name: LabelName },
    Delete,
}
struct PreparedWrite {
    method: Method,
    url: Url,
    body: Option<Zeroizing<Vec<u8>>>,
    expected: Expected,
}
impl fmt::Debug for PreparedWrite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PreparedWrite([REDACTED])")
    }
}
fn request(
    method: Method,
    segments: &[&str],
    body: Option<Zeroizing<Vec<u8>>>,
    expected: Expected,
) -> Result<PreparedWrite, CommandDispatchError> {
    let mut url = Url::parse(BASE_URL).map_err(|_e| CommandDispatchError::InvalidRequest)?;
    url.path_segments_mut()
        .map_err(|()| CommandDispatchError::InvalidRequest)?
        .pop_if_empty()
        .extend(segments);
    Ok(PreparedWrite {
        method,
        url,
        body,
        expected,
    })
}
#[derive(Serialize)]
struct BatchBody<'a> {
    ids: Vec<&'a str>,
    #[serde(rename = "addLabelIds")]
    add: &'a [String],
    #[serde(rename = "removeLabelIds")]
    remove: &'a [String],
}
#[derive(Serialize)]
struct NameBody<'a> {
    name: &'a str,
}
fn encoded<T: Serialize>(body: &T) -> Result<Zeroizing<Vec<u8>>, CommandDispatchError> {
    let bytes = Zeroizing::new(
        serde_json::to_vec(body).map_err(|_e| CommandDispatchError::InvalidRequest)?,
    );
    if bytes.len() > JSON_LIMIT {
        return Err(CommandDispatchError::InvalidRequest);
    }
    Ok(bytes)
}
fn name_body(name: &LabelName) -> Result<Zeroizing<Vec<u8>>, CommandDispatchError> {
    encoded(&NameBody {
        name: name.as_str(),
    })
}
fn batch(ids: Vec<&str>, patch: &Patch) -> Result<PreparedWrite, CommandDispatchError> {
    if ids.is_empty() || ids.len() > 1_000 {
        return Err(CommandDispatchError::InvalidRequest);
    }
    let body = encoded(&BatchBody {
        ids,
        add: &patch.add,
        remove: &patch.remove,
    })?;
    request(
        Method::Post,
        &["messages", "batchModify"],
        Some(body),
        Expected::Batch,
    )
}

fn response_fact(
    account: &AccountId,
    expected: &Expected,
    response: &HttpResponse,
) -> DispatchFact {
    if !(200..300).contains(&response.status) {
        return rejection(response.status, &response.body)
            .map_or(DispatchFact::Ambiguous, DispatchFact::Rejected);
    }
    let ack = match expected {
        // Empty batch success is ACK only. Accept the wire-empty/Empty-object
        // forms at 200, plus a genuinely bodyless HTTP No Content acknowledgement.
        Expected::Batch
            if (response.status == 200 && empty_ack(&response.body))
                || (response.status == 204 && response.body.is_empty()) =>
        {
            Some(WriteAcknowledgement::MessageBatchAccepted)
        }
        Expected::Create(name) if matches!(response.status, 200 | 201) => {
            decode_user(account, &response.body)
                .filter(|label| label.name() == name)
                .map(WriteAcknowledgement::LabelCreated)
        }
        // labels.patch documents a returned Label; require exact User ID/name.
        Expected::Rename { label, name } if response.status == 200 => {
            decode_user(account, &response.body)
                .filter(|observed| observed.id() == label.id() && observed.name() == name)
                .map(|_label| WriteAcknowledgement::LabelDefinitionAccepted)
        }
        // labels.delete documents an empty JSON object, not a returned Label.
        // Treat unexpected empty/truncated/other shapes conservatively as ambiguous.
        Expected::Delete if response.status == 200 && empty_object(&response.body) => {
            Some(WriteAcknowledgement::LabelDefinitionAccepted)
        }
        _ => None,
    };
    ack.map_or(DispatchFact::Ambiguous, DispatchFact::Acknowledged)
}
fn decode_user(account: &AccountId, body: &[u8]) -> Option<LabelDefinition> {
    let label = super::history::decode_label_response(account, body).ok()?;
    label.user_label().ok()?;
    Some(label)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyObject {}
fn empty_object(bytes: &[u8]) -> bool {
    serde_json::from_slice::<Object<EmptyObject>>(bytes).is_ok()
}

fn empty_ack(bytes: &[u8]) -> bool {
    bytes.iter().all(u8::is_ascii_whitespace) || empty_object(bytes)
}

#[derive(Deserialize)]
struct ErrorDocument {
    error: Object<ErrorDetail>,
}
#[derive(Deserialize)]
struct ErrorDetail {
    code: u16,
    #[serde(default)]
    errors: Vec<Object<ErrorReason>>,
    status: Option<String>,
}
#[derive(Deserialize)]
struct ErrorReason {
    reason: String,
}

fn rejection(status: u16, body: &[u8]) -> Option<CommandRejection> {
    // HTTP408/3xx/5xx and all unrecognized statuses cannot prove non-application.
    // Only established Gmail error envelopes at these documented HTTP categories
    // are classified as rejection; malformed/mismatched bodies remain ambiguous.
    if !matches!(status, 400 | 401 | 403 | 404 | 429) {
        return None;
    }
    let parsed: Object<ErrorDocument> = serde_json::from_slice(body).ok()?;
    let detail = parsed.0.error.0;
    if detail.code != status || detail.errors.len() > 64 {
        return None;
    }
    let has = |reasons: &[&str]| {
        detail
            .errors
            .iter()
            .any(|error| reasons.contains(&error.0.reason.as_str()))
    };
    let named = detail.status.as_deref();
    match status {
        401 if has(&["authError"]) || named == Some("UNAUTHENTICATED") => {
            Some(CommandRejection::AuthorizationRequired)
        }
        403 if has(&[
            "dailyLimitExceeded",
            "rateLimitExceeded",
            "userRateLimitExceeded",
            "quotaExceeded",
        ]) =>
        {
            Some(CommandRejection::RateLimited)
        }
        403 if has(&["authError", "insufficientPermissions", "domainPolicy"])
            || named == Some("PERMISSION_DENIED") =>
        {
            Some(CommandRejection::AuthorizationRequired)
        }
        429 if has(&[
            "rateLimitExceeded",
            "userRateLimitExceeded",
            "quotaExceeded",
        ]) || named == Some("RESOURCE_EXHAUSTED") =>
        {
            Some(CommandRejection::RateLimited)
        }
        400 if has(&["badRequest", "invalidArgument"]) || named == Some("INVALID_ARGUMENT") => {
            Some(CommandRejection::Rejected)
        }
        404 if has(&["notFound"]) || named == Some("NOT_FOUND") => Some(CommandRejection::Rejected),
        _ => None,
    }
}

trait ModifyTransport: Send + Sync {
    fn send(&self, request: PreparedWrite) -> TransportFuture<'_>;
}
struct ReqwestModifyTransport {
    client: reqwest::Client,
    token: Zeroizing<String>,
}
impl ModifyTransport for ReqwestModifyTransport {
    fn send(&self, request: PreparedWrite) -> TransportFuture<'_> {
        Box::pin(async move {
            let method = match request.method {
                Method::Post => reqwest::Method::POST,
                Method::Patch => reqwest::Method::PATCH,
                Method::Delete => reqwest::Method::DELETE,
            };
            let mut builder = self
                .client
                .request(method, request.url)
                .bearer_auth(&*self.token);
            if let Some(body) = request.body {
                builder = builder
                    .header(reqwest::header::CONTENT_TYPE, "application/json")
                    .body(body.to_vec());
            }
            let mut response = builder.send().await.map_err(|_e| TransportError::Network)?;
            let status = response.status().as_u16();
            let length = response
                .content_length()
                .and_then(|length| usize::try_from(length).ok());
            let mut body = BoundedBody::new(length, JSON_LIMIT)?;
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|_e| TransportError::Network)?
            {
                body.push(&chunk)?;
            }
            Ok(HttpResponse {
                status,
                body: body.finish()?,
            })
        })
    }
}

#[cfg(test)]
mod tests;
