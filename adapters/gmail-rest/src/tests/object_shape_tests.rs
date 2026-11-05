// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Wire regressions for positional resources, preserving actual protocol lists.

use super::*;
use serde_json::{Value, json as document};
use tersa_application::{
    history::{
        CapturedBaseline, GmailHistoryFeed, HistoryEventKind, HistoryFeedError,
        HistoryPageProgress, HistoryQuery, LocalHistoryStop, ProviderContinuation,
    },
    mailbox_state::{MessageKey, MetadataObservation, MetadataReadError, RemoteMessageState},
};
use tersa_domain::history::HistoryCursor;

fn key() -> MessageKey {
    MessageKey::new(account(ACCOUNT), message_id("m"))
}
fn cursor(value: &str) -> HistoryCursor {
    HistoryCursor::new(value).expect("cursor")
}
fn query() -> HistoryQuery {
    HistoryQuery::new(
        account(ACCOUNT),
        cursor("9"),
        PageSize::new(500).expect("size"),
    )
}
fn mailbox(replies: Vec<Reply>) -> (GmailMailbox, FakeTransport) {
    let fake = FakeTransport::new(replies);
    (
        GmailMailbox::with_transport(account(ACCOUNT), fake.clone()),
        fake,
    )
}
fn metadata_document() -> Value {
    document!({"id":"m","threadId":"t","internalDate":"42","labelIds":[],"snippet":"","payload":{"headers":[{"name":"From","value":"Sender"}]}})
}

// Contract: messages.list is an object containing a real list of object references.
// Regression: a positional page or listed reference hydrates as a legitimate mailbox result.
#[test]
fn list_and_reference_object_shapes_reject_otherwise_valid_positional_arrays() {
    for body in [
        r#"[[{"id":"m","threadId":"t"}],null]"#,
        r#"{"messages":[["m","t"]]}"#,
    ] {
        let (mailbox, transport) = mailbox(vec![
            json(200, body),
            json(200, &metadata_document().to_string()),
        ]);
        assert_eq!(
            ready(mailbox.list_recent_envelopes(
                &account(ACCOUNT),
                PageSize::new(25).expect("size"),
                None
            )),
            Err(RemoteMailboxError::InvalidResponse)
        );
        assert_eq!(transport.requests().len(), 1); // Reject before valid metadata could hydrate.
    }
    let (mailbox, _) = mailbox(vec![
        json(200, r#"{"messages":[{"id":"m","threadId":"t"}]}"#),
        json(200, &metadata_document().to_string()),
    ]);
    assert_eq!(
        ready(mailbox.list_recent_envelopes(
            &account(ACCOUNT),
            PageSize::new(25).expect("size"),
            None
        ))
        .expect("object page/reference")
        .items()
        .len(),
        1
    );
}

// Contract: Known membership requires a message object and actual payload/header objects.
// Regression: positional metadata or nested header data becomes complete provider evidence.
#[test]
fn metadata_payload_and_header_objects_cannot_be_positional_arrays() {
    let mut payload_array = metadata_document();
    payload_array["payload"] = document!([[{"name":"From","value":"Sender"}]]);
    let mut header_array = metadata_document();
    header_array["payload"] = document!({"headers":[["From","Sender"]]});
    for value in [
        document!(["m","t","42",[],"",{"headers":[{"name":"From","value":"Sender"}]}]),
        payload_array,
        header_array,
    ] {
        let (mailbox, _) = mailbox(vec![json(200, &value.to_string())]);
        assert_eq!(
            ready(mailbox.message_metadata(&key())),
            Err(MetadataReadError::InvalidResponse)
        );
    }
    let (mailbox, _) = mailbox(vec![
        json(200, &metadata_document().to_string()),
        json(200, r#"{"id":"m","threadId":"t","internalDate":"42"}"#),
    ]);
    for _ in 0..2 {
        let MetadataObservation::Known(metadata) = ready(mailbox.message_metadata(&key()))
            .expect("object metadata and legitimate omissions")
        else {
            panic!("Known object");
        };
        let RemoteMessageState::Known(labels) = metadata.observation().state() else {
            panic!("full membership");
        };
        assert!(labels.ids().is_empty());
    }
}

// Contract: minimal/raw/profile/baseline/snapshot resources are objects, not positional authority.
// Regression: arrays yield Known-empty labels, raw message content, an address or a cursor.
#[test]
fn remaining_get_resource_objects_reject_valid_value_arrays() {
    let (mailbox, _) = mailbox(vec![json(200, r#"["m",[]]"#)]);
    assert_eq!(
        ready(mailbox.observe_message(&key())),
        Err(MetadataReadError::InvalidResponse)
    );
    let (mailbox, _) = self::mailbox(vec![
        json(200, &metadata_document().to_string()),
        json(200, r#"["m","t","Ym9keQ"]"#),
    ]);
    assert_eq!(
        ready(mailbox.fetch_message(&account(ACCOUNT), &message_id("m"))),
        Err(RemoteMailboxError::InvalidResponse)
    );
    let (mailbox, _) = self::mailbox(vec![
        json(200, r#"["reader@example.test"]"#),
        json(200, r#"["50"]"#),
        json(200, "[[]]"),
        json(200, r#"{"messages":[["m","t"]]}"#),
        json(200, &metadata_document().to_string()),
    ]);
    assert_eq!(
        ready(mailbox.email_address()),
        Err(RemoteMailboxError::InvalidResponse)
    );
    assert_eq!(
        ready(mailbox.capture_baseline(&account(ACCOUNT))),
        Err(MetadataReadError::InvalidResponse)
    );
    let baseline = CapturedBaseline::new(account(ACCOUNT), cursor("50"));
    assert_eq!(
        ready(mailbox.snapshot_page(&baseline, None)),
        Err(MetadataReadError::InvalidResponse)
    );
    assert_eq!(
        ready(mailbox.snapshot_page(&baseline, None)),
        Err(MetadataReadError::InvalidResponse)
    );
}

// Contract: object-only conversion cannot change optional repeated-field defaults or raw borrowing.
// Regression: wrapping DTOs rejects genuine empty/list shapes or changes exact message identity.
#[test]
fn valid_object_resources_preserve_omitted_lists_and_real_arrays() {
    let (mailbox, _) = mailbox(vec![
        json(200, r#"{"id":"m"}"#),
        json(200, r#"{"emailAddress":"reader@example.test"}"#),
        json(200, r#"{"historyId":"50"}"#),
        json(200, "{}"),
        json(200, &metadata_document().to_string()),
        json(200, r#"{"id":"m","threadId":"t","raw":"Ym9keQ"}"#),
    ]);
    assert!(
        matches!(ready(mailbox.observe_message(&key())).expect("unlabeled object").state(),RemoteMessageState::Known(labels) if labels.ids().is_empty())
    );
    assert_eq!(
        ready(mailbox.email_address())
            .expect("profile object")
            .as_str(),
        "reader@example.test"
    );
    let baseline = ready(mailbox.capture_baseline(&account(ACCOUNT))).expect("baseline object");
    assert_eq!(baseline.cursor().as_str(), "50");
    assert!(
        ready(mailbox.snapshot_page(&baseline, None))
            .expect("omitted candidate list")
            .items()
            .is_empty()
    );
    assert_eq!(
        ready(mailbox.fetch_message(&account(ACCOUNT), &message_id("m")))
            .expect("raw object")
            .content()
            .as_bytes(),
        b"body"
    );
    let (mailbox, _) = self::mailbox(vec![json(200, "{}")]);
    assert!(
        ready(mailbox.list_recent_envelopes(
            &account(ACCOUNT),
            PageSize::new(25).expect("size"),
            None
        ))
        .expect("omitted recent list")
        .items()
        .is_empty()
    );
}

// Contract: typed History conversions still require objects after StrictValue, before prefix exposure.
// Regression: positional envelopes/records become a cursor or a decoded no-op record.
#[test]
fn history_typed_envelope_and_records_remain_objects_after_value_conversion() {
    for body in [
        r#"["99",[]]"#,
        r#"{"historyId":"99","history":[["10"]]}"#,
        r#"{"historyId":"99","history":[{"id":"10","messages":[{"id":"m"}]},["11"]]}"#,
    ] {
        let (mailbox, _) = mailbox(vec![json(200, body)]);
        assert_eq!(
            ready(mailbox.history_page(&query())),
            Err(HistoryFeedError::Read(MetadataReadError::InvalidResponse))
        );
    }
    let (mailbox, _) = mailbox(vec![json(200, r#"{"historyId":"99"}"#)]);
    assert!(matches!(
        ready(mailbox.history_page(&query()))
            .expect("omitted history list")
            .progress(),
        HistoryPageProgress::Complete(ProviderContinuation::End)
    ));
}

// Contract: nested event resources already reject arrays locally; actual lists and raw budgets survive.
// Regression: object guards accidentally reject history/event lists or move record errors to whole-page errors.
#[test]
fn history_event_arrays_keep_local_record_failure_and_duplicate_reference_accounting() {
    for broken in [
        document!({"id":"11","messagesAdded":[[{"id":"m"}]]}),
        document!({"id":"11","messagesAdded":[{"message":["m"]}]}),
        document!({"id":"11","messages":[["m"]]}),
    ] {
        let body =
            document!({"historyId":"99","history":[{"id":"10","messages":[{"id":"m"}]},broken]});
        let (mailbox, _) = mailbox(vec![json(200, &body.to_string())]);
        let page = ready(mailbox.history_page(&query())).expect("valid whole-record prefix");
        assert_eq!(page.records().len(), 1);
        assert!(matches!(
            page.progress(),
            HistoryPageProgress::LocalPrefix {
                reason: LocalHistoryStop::RecoveryRequired,
                ..
            }
        ));
    }
    let (mailbox, _) = mailbox(vec![json(
        200,
        r#"{"historyId":"99","history":[{"id":"10","messages":[{"id":"m"},{"id":"m"},{"id":"uncovered"}],"messagesAdded":[{"message":{"id":"m"}}]}]}"#,
    )]);
    let page = ready(mailbox.history_page(&query())).expect("object events inside real arrays");
    assert_eq!(page.records()[0].decoded_references(), 4);
    assert_eq!(page.records()[0].events().len(), 2);
    assert!(matches!(
        page.records()[0].events()[1].kind(),
        HistoryEventKind::Changed
    ));
}

// Contract: OAuth success/claims require objects before absent scope or account identity can be trusted.
// Regression: token/claim arrays produce inherited capability or usable token identity.
#[test]
fn token_success_and_claim_objects_reject_valid_positional_arrays() {
    let identity = jwt(
        r#"{"sub":"subject","aud":"public-test-client","iss":"accounts.google.com","iat":1000,"exp":5000}"#,
    );
    let claims_array =
        jwt(r#"["subject","public-test-client","accounts.google.com",null,1000,5000]"#);
    for body in [
        document!(["access", 3599, "refresh", "Bearer"]),
        document!([
            "access",
            3599,
            "refresh",
            "Bearer",
            "openid https://www.googleapis.com/auth/gmail.readonly",
            identity
        ]),
        document!({"access_token":"access","expires_in":3599,"refresh_token":"refresh","token_type":"Bearer","id_token":claims_array}),
    ] {
        let transport = GmailTokenTransport::with_transport(FakePostTransport::new(vec![json(
            200,
            &body.to_string(),
        )]));
        let (_, request) = captured_exchange(None);
        assert!(matches!(
            ready(transport.exchange(request)),
            Err(TokenTransportError::MalformedResponse)
        ));
    }
    let identity = jwt(
        r#"{"sub":"subject","aud":["public-test-client","other"],"azp":"public-test-client","iss":"accounts.google.com","iat":1000,"exp":5000}"#,
    );
    let body = document!({"access_token":"access","expires_in":3599,"token_type":"Bearer","id_token":identity});
    let transport = GmailTokenTransport::with_transport(FakePostTransport::new(vec![json(
        200,
        &body.to_string(),
    )]));
    let grant = make_grant("code");
    let success = ready(exchange_grant(
        &grant,
        &make_config(None),
        &transport,
        &TestClock::default(),
    ))
    .expect("object token/claims with real audience array");
    assert_eq!(success.subject().as_str(), "subject");
    assert!(matches!(
        success.accepted_scope().evidence(),
        tersa_application::scope::ScopeEvidence::Absent
    ));
}

// Contract: non-object errors cannot become destructive invalid_grant/invalid_token evidence.
// Regression: array errors falsely license credential deletion or confirmed revocation.
#[test]
fn oauth_error_object_shapes_never_fabricate_invalid_grant_or_token_facts() {
    let transport = GmailTokenTransport::with_transport(FakePostTransport::new(vec![json(
        400,
        r#"["invalid_grant"]"#,
    )]));
    assert!(matches!(
        ready(transport.refresh(captured_refresh(None))),
        Err(TokenTransportError::MalformedResponse)
    ));
    for body in [r#"["invalid_token"]"#, r#"["invalid_grant"]"#] {
        let transport =
            GmailTokenTransport::with_transport(FakePostTransport::new(vec![json(400, body)]));
        assert_eq!(
            ready(transport.revoke(&Zeroizing::new("revocation-handle".to_owned()))),
            Err(TokenTransportError::MalformedResponse)
        );
    }
    let transport = GmailTokenTransport::with_transport(FakePostTransport::new(vec![
        json(400, r#"{"error":"invalid_grant"}"#),
        json(400, r#"{"error":"invalid_token"}"#),
    ]));
    assert!(matches!(
        ready(transport.refresh(captured_refresh(None))),
        Err(TokenTransportError::InvalidGrant)
    ));
    assert_eq!(
        ready(transport.revoke(&Zeroizing::new("revocation-handle".to_owned()))),
        Err(TokenTransportError::InvalidToken)
    );
}

// Contract: Gmail's nested error resources must be objects before classifying authorization failures.
// Regression: positional outer/detail/reason arrays are interpreted as established provider errors.
#[test]
fn get_error_objects_reject_nested_positional_reasons() {
    for body in [
        r#"[[[["authError"]]]]"#,
        r#"{"error":[[{"reason":"authError"}]]}"#,
        r#"{"error":{"errors":[["authError"]]}}"#,
    ] {
        let (mailbox, _) = mailbox(vec![json(403, body)]);
        assert_eq!(
            ready(mailbox.email_address()),
            Err(RemoteMailboxError::InvalidResponse)
        );
    }
    let (mailbox, _) = mailbox(vec![json(
        403,
        r#"{"error":{"errors":[{"reason":"authError"}]}}"#,
    )]);
    assert_eq!(
        ready(mailbox.email_address()),
        Err(RemoteMailboxError::AuthorizationRequired)
    );
}

// Contract: strict object guards keep duplicate-key rejection and null/absent semantics.
// Regression: a Value roundtrip loses duplicate keys or null is converted to legitimate omission.
#[test]
fn object_guard_keeps_duplicate_rejection_and_deliberate_optional_field_semantics() {
    for body in [r#"{"id":"m","id":"m"}"#, r#"{"id":"m","labelIds":null}"#] {
        let (mailbox, _) = mailbox(vec![json(200, body)]);
        assert_eq!(
            ready(mailbox.observe_message(&key())),
            Err(MetadataReadError::InvalidResponse)
        );
    }
    for body in [
        r#"{"access_token":"a","access_token":"a","expires_in":3599,"token_type":"Bearer"}"#,
        r#"{"access_token":"a","expires_in":3599,"token_type":"Bearer","scope":null}"#,
    ] {
        let transport =
            GmailTokenTransport::with_transport(FakePostTransport::new(vec![json(200, body)]));
        let (_, request) = captured_exchange(None);
        assert!(matches!(
            ready(transport.exchange(request)),
            Err(TokenTransportError::MalformedResponse)
        ));
    }
}
