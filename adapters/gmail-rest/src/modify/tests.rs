// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Controlled wire effects, not live authorization, SQL durability or provider atomicity proof.

use super::*;
use serde_json::{Value, json};
use std::{
    collections::VecDeque,
    future::pending,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
    time::Duration,
};
use tersa_application::{
    command::{
        CommandItemProgress, CommandKey, CommandProgress, CommandSnapshot, CommandStamp,
        LabelItemProgress,
    },
    mailbox_state::MessageKey,
    oauth::MonotonicClock,
    scope::ScopeEvidence,
    token::{
        ExchangeRequest, IdTokenClaims, RefreshRequest, TokenClientConfig, TokenResponse,
        TokenTransport, TokenTransportError, refresh_access_token,
    },
};
use tersa_domain::{
    command::{
        CommandItemOutcome, CompensationBatch, ConditionalCompensation, MailboxCommand,
        MailboxCommandId, MessageAction, MessageCompensation, MessageTargets,
    },
    label::LabelId,
};

#[derive(Clone)]
struct Fake {
    writes: Arc<Mutex<Vec<Captured>>>,
    gets: Arc<Mutex<Vec<String>>>,
    write_replies: Arc<Mutex<VecDeque<Reply>>>,
    read_replies: Arc<Mutex<VecDeque<Reply>>>,
}
#[derive(Debug)]
struct Captured {
    method: Method,
    url: String,
    body: Option<Vec<u8>>,
}
enum Reply {
    Response {
        status: u16,
        length: Option<usize>,
        chunks: Vec<Vec<u8>>,
    },
    Network,
    Pending(Arc<AtomicBool>),
}
struct DropSignal(Arc<AtomicBool>);
impl Drop for DropSignal {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}
impl Fake {
    fn new(writes: Vec<Reply>, reads: Vec<Reply>) -> Self {
        Self {
            writes: Arc::new(Mutex::new(Vec::new())),
            gets: Arc::new(Mutex::new(Vec::new())),
            write_replies: Arc::new(Mutex::new(writes.into())),
            read_replies: Arc::new(Mutex::new(reads.into())),
        }
    }
}
fn reply(status: u16, body: &str) -> Reply {
    Reply::Response {
        status,
        length: Some(body.len()),
        chunks: body.as_bytes().chunks(7).map(<[u8]>::to_vec).collect(),
    }
}
fn response(reply: Option<Reply>, limit: usize) -> TransportFuture<'static> {
    Box::pin(async move {
        match reply {
            Some(Reply::Response {
                status,
                length,
                chunks,
            }) => {
                let mut body = BoundedBody::new(length, limit)?;
                for chunk in chunks {
                    body.push(&chunk)?;
                }
                Ok(HttpResponse {
                    status,
                    body: body.finish()?,
                })
            }
            Some(Reply::Pending(signal)) => {
                let _signal = DropSignal(signal);
                pending::<()>().await;
                unreachable!("pending fixture");
            }
            Some(Reply::Network) | None => Err(TransportError::Network),
        }
    })
}
impl ModifyTransport for Fake {
    fn send(&self, request: PreparedWrite) -> TransportFuture<'_> {
        self.writes.lock().expect("writes").push(Captured {
            method: request.method,
            url: request.url.into(),
            body: request.body.map(|body| body.to_vec()),
        });
        response(
            self.write_replies.lock().expect("reply").pop_front(),
            JSON_LIMIT,
        )
    }
}
impl super::super::Transport for Fake {
    fn get(&self, request: super::super::Request, limit: usize) -> TransportFuture<'_> {
        self.gets.lock().expect("gets").push(request.url.into());
        response(self.read_replies.lock().expect("reply").pop_front(), limit)
    }
}
fn ready<F: Future>(future: F) -> F::Output {
    let mut future = Box::pin(future);
    let mut context = Context::from_waker(Waker::noop());
    match future.as_mut().poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("immediate controlled reply expected"),
    }
}
fn account() -> AccountId {
    AccountId::new("account-sentinel").expect("account")
}
fn id(value: &str) -> MessageId {
    MessageId::new(value).expect("ID")
}
fn user() -> UserLabel {
    UserLabel::from_classified_id(account(), LabelId::new("Label_known").expect("ID"))
        .expect("trusted User classification")
}
fn accepted(capability: AccountCapability) -> AcceptedScope {
    ScopeEvidence::Absent
        .validate_for(capability)
        .expect("complete bound scope fixture")
}
fn component(fake: &Fake) -> GmailModifyMailbox {
    GmailModifyMailbox::with_transports(
        account(),
        "access-token-sentinel".to_owned(),
        AccountCapability::Modify,
        accepted(AccountCapability::Modify),
        fake.clone(),
        fake.clone(),
    )
    .expect("authorized component fixture")
}
fn snapshot(command: MailboxCommand, progress: CommandProgress) -> CommandSnapshot {
    let stamp = CommandStamp::new(
        CommandKey::new(command.account_id().clone(), command.id().clone()),
        7,
    );
    CommandSnapshot::new(
        command,
        stamp,
        MailboxCommandStatus::Dispatching,
        1,
        progress,
        None,
    )
    .expect("trusted durable snapshot fixture")
}
fn message_receipt(
    action: &MessageAction,
    all: &[&str],
    selected: &[&str],
    settled: &[&str],
) -> DispatchReceipt {
    let targets = MessageTargets::new(account(), all.iter().map(|value| id(value)).collect())
        .expect("targets");
    let command = MailboxCommand::message_state(
        AccountCapability::Modify,
        MailboxCommandId::new("command-sentinel").expect("command"),
        targets,
        action,
    )
    .expect("command");
    let progress = CommandProgress::Messages(
        all.iter()
            .map(|value| {
                CommandItemProgress::new(
                    MessageKey::new(account(), id(value)),
                    settled
                        .contains(value)
                        .then_some(CommandItemOutcome::DesiredStateObserved),
                )
            })
            .collect(),
    );
    DispatchReceipt::from_committed(
        snapshot(command, progress),
        Some(
            MessageTargets::new(account(), selected.iter().map(|value| id(value)).collect())
                .expect("selected"),
        ),
    )
    .expect("committed receipt fixture")
}
fn label_receipt(kind: u8, name: &str) -> DispatchReceipt {
    let command_id = MailboxCommandId::new("command-sentinel").expect("command");
    let name = LabelName::new(name).expect("name");
    let command = match kind {
        0 => MailboxCommand::create_label(AccountCapability::Modify, command_id, account(), name),
        1 => MailboxCommand::rename_label(AccountCapability::Modify, command_id, user(), name),
        _ => MailboxCommand::delete_label(AccountCapability::Modify, command_id, user()),
    }
    .expect("label command");
    DispatchReceipt::from_committed(
        snapshot(command, CommandProgress::Label(LabelItemProgress::Pending)),
        None,
    )
    .expect("label receipt")
}
fn compensation_receipt(invalid_later: bool) -> DispatchReceipt {
    let expected = DesiredMailboxState::from_touched_fields(
        account(),
        vec![(MailboxField::Trash, true), (MailboxField::Inbox, false)],
    )
    .expect("stored expected post");
    let values = if invalid_later {
        vec![("!valid", false), ("..", true)]
    } else {
        vec![("a", false), ("b", true), ("c", false), ("settled", true)]
    };
    let items = values
        .iter()
        .map(|(message, inbox)| {
            let restore = DesiredMailboxState::from_touched_fields(
                account(),
                vec![(MailboxField::Trash, false), (MailboxField::Inbox, *inbox)],
            )
            .expect("recorded pre-state");
            MessageCompensation::new(
                id(message),
                ConditionalCompensation::new(expected.clone(), restore)
                    .expect("conditional fields"),
            )
        })
        .collect();
    let command = MailboxCommand::compensate(
        AccountCapability::Modify,
        MailboxCommandId::new("command-sentinel").expect("command"),
        CompensationBatch::new(account(), items).expect("batch"),
    )
    .expect("compensation");
    let progress = CommandProgress::Messages(
        values
            .iter()
            .map(|(value, _)| {
                CommandItemProgress::new(
                    MessageKey::new(account(), id(value)),
                    (*value == "settled").then_some(CommandItemOutcome::DesiredStateObserved),
                )
            })
            .collect(),
    );
    let selected = values
        .iter()
        .filter(|(value, _)| *value != "settled")
        .map(|(value, _)| id(value))
        .collect();
    DispatchReceipt::from_committed(
        snapshot(command, progress),
        Some(MessageTargets::new(account(), selected).expect("selected")),
    )
    .expect("receipt")
}
fn body(request: &Captured) -> Value {
    serde_json::from_slice(request.body.as_ref().expect("JSON body")).expect("encoded JSON")
}
fn error(status: u16, reason: &str) -> String {
    json!({"error":{"code":status,"errors":[{"reason":reason}]}}).to_string()
}

// Contract: current complete Modify plus stored Modify is mandatory; legacy true is insufficient.
// Regression: a constructor bypasses one authority input or accepts an invalid bearer before transport.
#[test]
fn constructor_rejects_readonly_legacy_scope_and_invalid_tokens_before_transport() {
    #[derive(Debug)]
    struct Clock;
    impl MonotonicClock for Clock {
        fn now(&self) -> Duration {
            Duration::ZERO
        }
    }
    #[derive(Debug)]
    struct Legacy;
    impl TokenTransport for Legacy {
        fn exchange(
            &self,
            _request: ExchangeRequest,
        ) -> BoxFuture<'_, Result<TokenResponse, TokenTransportError>> {
            Box::pin(async { Err(TokenTransportError::Transport) })
        }
        fn refresh(
            &self,
            _request: RefreshRequest,
        ) -> BoxFuture<'_, Result<TokenResponse, TokenTransportError>> {
            Box::pin(async {
                Ok(TokenResponse::new(
                    Zeroizing::new("legacy-access".to_owned()),
                    Duration::from_secs(60),
                    None,
                    Some(IdTokenClaims::new(
                        Zeroizing::new("subject".to_owned()),
                        vec!["client".to_owned()],
                        "accounts.google.com".to_owned(),
                        None,
                        1,
                        100,
                    )),
                    true,
                ))
            })
        }
        fn revoke<'a>(
            &'a self,
            _token: &'a Zeroizing<String>,
        ) -> BoxFuture<'a, Result<(), TokenTransportError>> {
            Box::pin(async { Ok(()) })
        }
    }
    let config = TokenClientConfig::new(
        "client",
        Url::parse("http://127.0.0.1:8080/").expect("redirect"),
        None,
    )
    .expect("config");
    let legacy = ready(refresh_access_token(
        &Zeroizing::new("refresh".to_owned()),
        &config,
        &Legacy,
        &Clock,
    ))
    .expect("legacy compatibility success")
    .accepted_scope();
    for (persisted, scope) in [
        (
            AccountCapability::ReadOnly,
            accepted(AccountCapability::Modify),
        ),
        (
            AccountCapability::Modify,
            accepted(AccountCapability::ReadOnly),
        ),
        (AccountCapability::Modify, legacy),
    ] {
        assert!(matches!(
            GmailModifyMailbox::new(account(), "access".to_owned(), persisted, scope),
            Err(CommandDispatchError::AuthorizationRequired)
        ));
    }
    for token in [
        String::new(),
        "bad\nheader".to_owned(),
        "has space".to_owned(),
        "é".to_owned(),
        "x".repeat(16 * 1024 + 1),
    ] {
        let fake = Fake::new(vec![], vec![]);
        assert!(matches!(
            GmailModifyMailbox::with_transports(
                account(),
                token,
                AccountCapability::Modify,
                accepted(AccountCapability::Modify),
                fake.clone(),
                fake.clone()
            ),
            Err(CommandDispatchError::AuthorizationRequired)
        ));
        assert!(fake.writes.lock().expect("writes").is_empty());
    }
}

// Contract: only receipt-selected unsettled IDs and exact approved memberships reach batchModify.
// Regression: aggregate targets resend, touched fields broaden, or the route becomes a direct trash/delete endpoint.
#[test]
fn every_approved_message_patch_has_exact_closed_wire_body_and_selected_subset() {
    let cases = [
        (MessageAction::Read, json!([]), json!(["UNREAD"])),
        (MessageAction::Unread, json!(["UNREAD"]), json!([])),
        (MessageAction::Star, json!(["STARRED"]), json!([])),
        (MessageAction::Unstar, json!([]), json!(["STARRED"])),
        (MessageAction::Archive, json!([]), json!(["INBOX"])),
        (MessageAction::Trash, json!(["TRASH"]), json!(["INBOX"])),
        (MessageAction::Restore, json!(["INBOX"]), json!(["TRASH"])),
        (MessageAction::Spam, json!(["SPAM"]), json!(["INBOX"])),
        (MessageAction::ClearSpam, json!(["INBOX"]), json!(["SPAM"])),
        (
            MessageAction::ApplyLabel(user()),
            json!(["Label_known"]),
            json!([]),
        ),
        (
            MessageAction::RemoveLabel(user()),
            json!([]),
            json!(["Label_known"]),
        ),
    ];
    for (action, add, remove) in cases {
        let receipt = message_receipt(
            &action,
            &["a", "b", "c", "settled"],
            &["a", "c"],
            &["settled"],
        );
        let fake = Fake::new(vec![reply(200, "")], vec![]);
        let client = component(&fake);
        let result = ready(client.dispatch(&receipt)).expect("ACK fact");
        assert_eq!(
            result.fact(),
            &DispatchFact::Acknowledged(WriteAcknowledgement::MessageBatchAccepted)
        );
        assert_eq!(result.stamp().revision(), 7);
        let requests = fake.writes.lock().expect("writes");
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, Method::Post);
        assert_eq!(
            requests[0].url,
            "https://gmail.googleapis.com/gmail/v1/users/me/messages/batchModify"
        );
        assert_eq!(
            body(&requests[0]),
            json!({"ids":["a","c"],"addLabelIds":add,"removeLabelIds":remove})
        );
        drop(requests);
        assert!(matches!(
            ready(client.dispatch(&receipt)),
            Err(CommandDispatchError::InvalidRequest)
        ));
        assert_eq!(fake.writes.lock().expect("writes").len(), 1);
    }
}

// Contract: compensation groups equal restore patches, excludes settled IDs and validates every group first.
// Regression: per-target states collapse, settled targets resend, or a later invalid target follows an earlier HTTP write.
#[test]
fn compensation_prebuilds_all_groups_and_after_first_effect_cannot_report_rejection() {
    let receipt = compensation_receipt(false);
    for (second, expected) in [
        (
            reply(200, "{}"),
            DispatchFact::Acknowledged(WriteAcknowledgement::MessageBatchAccepted),
        ),
        (
            reply(403, &error(403, "insufficientPermissions")),
            DispatchFact::Ambiguous,
        ),
        (Reply::Network, DispatchFact::Ambiguous),
    ] {
        let fake = Fake::new(vec![reply(200, ""), second], vec![]);
        let client = component(&fake);
        let result = ready(client.dispatch(&receipt)).expect("aggregate fact");
        let requests = fake.writes.lock().expect("writes");
        assert_eq!(requests.len(), 2);
        assert_eq!(
            body(&requests[0]),
            json!({"ids":["a","c"],"addLabelIds":[],"removeLabelIds":["INBOX","TRASH"]})
        );
        assert_eq!(
            body(&requests[1]),
            json!({"ids":["b"],"addLabelIds":["INBOX"],"removeLabelIds":["TRASH"]})
        );
        assert_eq!(result.fact(), &expected);
    }
    let fake = Fake::new(
        vec![reply(400, &error(400, "badRequest")), reply(200, "")],
        vec![],
    );
    assert_eq!(
        ready(component(&fake).dispatch(&receipt))
            .expect("first-group rejection")
            .fact(),
        &DispatchFact::Rejected(CommandRejection::Rejected)
    );
    assert_eq!(fake.writes.lock().expect("writes").len(), 1);
    let fake = Fake::new(vec![reply(200, "")], vec![]);
    let client = component(&fake);
    assert!(matches!(
        ready(client.dispatch(&compensation_receipt(true))),
        Err(CommandDispatchError::InvalidRequest)
    ));
    assert!(fake.writes.lock().expect("writes").is_empty());
}

// Contract: every allowed definition operation uses its sole method/path/body and validates success shape.
// Regression: PUT/arbitrary paths, extra provider fields or mismatched returned definition become success.
#[test]
fn label_create_rename_delete_have_exact_wire_requests_and_success_documents() {
    let name = " exact-name-sentinel e\u{301} ";
    for (kind, method, url, response) in [
        (
            0,
            Method::Post,
            "https://gmail.googleapis.com/gmail/v1/users/me/labels",
            r#"{"id":"Label_created","name":"exact-name-sentinel","type":"user"}"#,
        ),
        (
            1,
            Method::Patch,
            "https://gmail.googleapis.com/gmail/v1/users/me/labels/Label_known",
            r#"{"id":"Label_known","name":"exact-name-sentinel","type":"user"}"#,
        ),
        (
            2,
            Method::Delete,
            "https://gmail.googleapis.com/gmail/v1/users/me/labels/Label_known",
            "{}",
        ),
    ] {
        let mut document: Value = serde_json::from_str(response).expect("response fixture");
        if kind != 2 {
            document["name"] = json!(name);
        }
        let response = document.to_string();
        let fake = Fake::new(vec![reply(200, &response)], vec![]);
        let client = component(&fake);
        let receipt = label_receipt(kind, name);
        let result = ready(client.dispatch(&receipt)).expect("valid definition ACK");
        assert_eq!(result.stamp().revision(), 7);
        if kind == 0 {
            let DispatchFact::Acknowledged(WriteAcknowledgement::LabelCreated(created)) =
                result.fact()
            else {
                panic!("validated create ACK");
            };
            assert_eq!(created.id().as_str(), "Label_created");
            assert_eq!(created.account_id(), &account());
        } else {
            assert_eq!(
                result.fact(),
                &DispatchFact::Acknowledged(WriteAcknowledgement::LabelDefinitionAccepted)
            );
        }
        let requests = fake.writes.lock().expect("writes");
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, method);
        assert_eq!(requests[0].url, url);
        if kind == 2 {
            assert!(requests[0].body.is_none());
        } else {
            assert_eq!(body(&requests[0]), json!({"name":name}));
        }
    }
}

// Contract: malformed/mismatched definition success and missing/wrong API response shapes remain ambiguous.
// Regression: empty PATCH/DELETE response or a System/foreign ID/name creates fabricated success.
#[test]
fn malformed_label_success_never_adopts_or_acknowledges_invalid_definition() {
    for (kind, status, body) in [
        (0, 200, r#"{"id":"INBOX","name":"name","type":"user"}"#),
        (0, 200, r#"{"id":"INBOX","name":"name","type":"system"}"#),
        (0, 200, r#"{"id":"Label_new","name":"wrong","type":"user"}"#),
        (0, 200, r#"{"id":"bad/id","name":"name","type":"user"}"#),
        (0, 200, "{}"),
        (
            0,
            200,
            r#"{"id":"Label_created","id":"Label_created","name":"name","type":"user"}"#,
        ),
        (0, 200, r#"["Label_created","name","user"]"#),
        (1, 200, r#"["Label_known","name","user"]"#),
        (
            1,
            200,
            r#"{"id":"Label_other","name":"name","type":"user"}"#,
        ),
        (
            1,
            200,
            r#"{"id":"Label_known","name":"wrong","type":"user"}"#,
        ),
        (1, 200, ""),
        (1, 204, ""),
        (2, 200, ""),
        (2, 200, "[]"),
        (2, 204, ""),
        (2, 200, r#"{"id":"Label_known"}"#),
    ] {
        let fake = Fake::new(vec![reply(status, body)], vec![]);
        let client = component(&fake);
        assert_eq!(
            ready(client.dispatch(&label_receipt(kind, "name")))
                .expect("possible application")
                .fact(),
            &DispatchFact::Ambiguous
        );
        assert_eq!(fake.writes.lock().expect("writes").len(), 1);
    }
}

// Contract: only established first-request rejections are definite; 408/redirect/uncertain statuses remain ambiguous.
// Regression: blanket 4xx rejection, retry after timeout, or malformed error body proves non-application.
#[test]
fn status_and_body_failures_are_conservative_and_never_retried() {
    let cases = [
        (
            reply(400, &error(400, "badRequest")),
            DispatchFact::Rejected(CommandRejection::Rejected),
        ),
        (
            reply(401, &error(401, "authError")),
            DispatchFact::Rejected(CommandRejection::AuthorizationRequired),
        ),
        (
            reply(403, &error(403, "userRateLimitExceeded")),
            DispatchFact::Rejected(CommandRejection::RateLimited),
        ),
        (
            reply(404, &error(404, "notFound")),
            DispatchFact::Rejected(CommandRejection::Rejected),
        ),
        (
            reply(429, &error(429, "rateLimitExceeded")),
            DispatchFact::Rejected(CommandRejection::RateLimited),
        ),
        (
            reply(408, &error(408, "badRequest")),
            DispatchFact::Ambiguous,
        ),
        (reply(302, ""), DispatchFact::Ambiguous),
        (
            reply(500, &error(500, "backendError")),
            DispatchFact::Ambiguous,
        ),
        (reply(409, &error(409, "conflict")), DispatchFact::Ambiguous),
        (reply(400, &error(400, "unknown")), DispatchFact::Ambiguous),
        (
            reply(401, &error(400, "authError")),
            DispatchFact::Ambiguous,
        ),
        (reply(403, "not-json"), DispatchFact::Ambiguous),
        (
            reply(400, r#"[[400,[["badRequest"]],null]]"#),
            DispatchFact::Ambiguous,
        ),
        (
            reply(400, r#"{"error":[400,[["badRequest"]],null]}"#),
            DispatchFact::Ambiguous,
        ),
        (
            reply(400, r#"{"error":{"code":400,"errors":[["badRequest"]]}}"#),
            DispatchFact::Ambiguous,
        ),
        (reply(200, "[]"), DispatchFact::Ambiguous),
        (reply(200, "{"), DispatchFact::Ambiguous),
        (reply(200, r#"{"unexpected":1}"#), DispatchFact::Ambiguous),
        (Reply::Network, DispatchFact::Ambiguous),
        (
            Reply::Response {
                status: 200,
                length: Some(JSON_LIMIT + 1),
                chunks: vec![],
            },
            DispatchFact::Ambiguous,
        ),
        (
            Reply::Response {
                status: 200,
                length: Some(100),
                chunks: vec![b"{}".to_vec()],
            },
            DispatchFact::Ambiguous,
        ),
    ];
    for (first, expected) in cases {
        let fake = Fake::new(vec![first, reply(200, "")], vec![]);
        let client = component(&fake);
        let result =
            ready(client.dispatch(&message_receipt(&MessageAction::Read, &["m"], &["m"], &[])))
                .expect("transport fact");
        assert_eq!(result.fact(), &expected);
        assert_eq!(fake.writes.lock().expect("writes").len(), 1);
    }
}

// Contract: dispatch and reconciliation reads remain account-bound, and dropped writes retain uncertainty.
// Regression: a wrong account sends HTTP, read helpers duplicate mutation authority, or pending work detaches/retries.
#[test]
fn foreign_receipts_reads_and_pending_dispatch_preserve_boundaries() {
    let fake = Fake::new(
        vec![],
        vec![
            reply(
                200,
                r#"{"labels":[{"id":"Label_known","name":"n","type":"user"}]}"#,
            ),
            reply(200, r#"{"id":"Label_known","name":"n","type":"user"}"#),
            reply(404, ""),
        ],
    );
    let client = component(&fake);
    assert_eq!(
        ready(client.label_catalog(&account()))
            .expect("GET catalog")
            .definitions()
            .len(),
        1
    );
    assert!(
        ready(client.observe_user_label(&user()))
            .expect("known GET")
            .definition()
            .is_some()
    );
    assert!(
        ready(client.observe_user_label(&user()))
            .expect("exact missing GET")
            .definition()
            .is_none()
    );
    assert!(fake.writes.lock().expect("writes").is_empty());
    let other = AccountId::new("other-account").expect("account");
    let foreign_targets = MessageTargets::new(other.clone(), vec![id("m")]).expect("targets");
    let command = MailboxCommand::message_state(
        AccountCapability::Modify,
        MailboxCommandId::new("foreign").expect("ID"),
        foreign_targets.clone(),
        &MessageAction::Read,
    )
    .expect("command");
    let progress = CommandProgress::Messages(vec![CommandItemProgress::new(
        MessageKey::new(other.clone(), id("m")),
        None,
    )]);
    let receipt =
        DispatchReceipt::from_committed(snapshot(command, progress), Some(foreign_targets))
            .expect("foreign receipt");
    assert!(matches!(
        ready(client.dispatch(&receipt)),
        Err(CommandDispatchError::InvalidRequest)
    ));
    assert_eq!(
        ready(client.label_catalog(&other)),
        Err(MetadataReadError::AuthorizationRequired)
    );
    assert!(fake.writes.lock().expect("writes").is_empty());
    assert_eq!(fake.gets.lock().expect("gets").len(), 3);
    let dropped = Arc::new(AtomicBool::new(false));
    let fake = Fake::new(vec![Reply::Pending(Arc::clone(&dropped))], vec![]);
    let client = component(&fake);
    let receipt = message_receipt(&MessageAction::Read, &["m"], &["m"], &[]);
    let mut future = client.dispatch(&receipt);
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
    drop(future);
    assert!(dropped.load(Ordering::SeqCst));
    assert_eq!(fake.writes.lock().expect("writes").len(), 1);
    assert!(matches!(
        ready(client.dispatch(&receipt)),
        Err(CommandDispatchError::InvalidRequest)
    ));
    for output in [
        format!("{client:?}"),
        format!(
            "{:?}",
            prepare(&account(), &receipt).expect("private prepared requests")
        ),
    ] {
        for sentinel in [
            "account-sentinel",
            "command-sentinel",
            "access-token-sentinel",
            "Label_known",
        ] {
            assert!(!output.contains(sentinel));
        }
    }
}

// Contract: every reused label read requires objects, preserving scalar IDs/name/User and duplicate rejection.
// Regression: exact GET/catalog entries accept arrays while the write ACK decoder rejects them (or vice versa).
#[test]
fn shared_label_object_guard_rejects_otherwise_valid_arrays_and_duplicate_fields() {
    for (catalog, response) in [
        (false, r#"["Label_known","n","user"]"#),
        (true, r#"{"labels":[["Label_known","n","user"]]}"#),
        (true, r#"[[{"id":"Label_known","name":"n","type":"user"}]]"#),
        (
            false,
            r#"{"id":"Label_known","id":"Label_known","name":"n","type":"user"}"#,
        ),
        (
            true,
            r#"{"labels":[{"id":"Label_known","id":"Label_known","name":"n","type":"user"}]}"#,
        ),
    ] {
        let fake = Fake::new(vec![], vec![reply(200, response)]);
        let client = component(&fake);
        if catalog {
            assert_eq!(
                ready(client.label_catalog(&account())),
                Err(MetadataReadError::InvalidResponse)
            );
        } else {
            assert_eq!(
                ready(client.observe_user_label(&user())),
                Err(MetadataReadError::InvalidResponse)
            );
        }
        assert_eq!(fake.gets.lock().expect("GETs").len(), 1);
        assert!(fake.writes.lock().expect("writes").is_empty());
    }
}
