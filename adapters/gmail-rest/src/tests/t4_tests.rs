// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Deterministic request/response evidence, not live provider or persistence proof.

use super::*;
use serde_json::{Value, json as document};
use tersa_application::{
    AccountCapability,
    history::{
        CapturedBaseline, GmailHistoryFeed, HistoryCheckpoint, HistoryEventKind, HistoryFeedError,
        HistoryPageProgress, HistoryQuery, LocalHistoryStop, ProviderContinuation,
    },
    identity::IdentityHash,
    mailbox_state::{MessageKey, MetadataObservation, MetadataReadError, RemoteMessageState},
    profile::AccountFence,
    scope::ScopeEvidence,
    token::{
        AccountSubject, CapabilityRefreshOutcome, StoredGrantSnapshot, TokenError,
        exchange_capability_grant, refresh_stored_grant,
    },
};
use tersa_domain::{
    history::HistoryCursor,
    label::{LabelId, LabelKind},
};

fn cursor(value: &str) -> HistoryCursor {
    HistoryCursor::new(value).expect("synthetic cursor")
}
fn key(value: &str) -> MessageKey {
    MessageKey::new(account(ACCOUNT), message_id(value))
}
fn query() -> HistoryQuery {
    HistoryQuery::new(
        account(ACCOUNT),
        cursor("9"),
        PageSize::new(500).expect("size"),
    )
}
fn mailbox(replies: Vec<Reply>) -> (GmailMailbox, FakeTransport) {
    let transport = FakeTransport::new(replies);
    (
        GmailMailbox::with_transport(account(ACCOUNT), transport.clone()),
        transport,
    )
}
fn history_body(records: Value) -> String {
    let mut body = serde_json::Map::new();
    body.insert("historyId".to_owned(), document!("9999"));
    body.insert("history".to_owned(), records);
    Value::Object(body).to_string()
}
fn query_value(url: &Url, name: &str) -> String {
    url.query_pairs()
        .find_map(|(key, value)| (key == name).then(|| value.into_owned()))
        .expect("expected request parameter")
}
fn token_body(scope: Option<Value>, identity: &str) -> String {
    let mut body = document!({"access_token":"access-sentinel","expires_in":3599,"refresh_token":"refresh-sentinel","token_type":"Bearer","id_token":identity});
    if let Some(scope) = scope {
        body["scope"] = scope;
    }
    body.to_string()
}
fn identity() -> String {
    jwt(
        r#"{"sub":"subject-sentinel","aud":"public-test-client","iss":"https://accounts.google.com","iat":1000,"exp":5000}"#,
    )
}

// Contract: bound exchange/refresh context reaches parsing and valid Modify identity is not suppressed.
// Regression: the transport guesses from response scopes or reduces evidence to a readonly boolean.
#[test]
fn token_wire_preserves_scope_presence_and_bound_capability_for_exchange_and_refresh() {
    for (capability, scope) in [
        (AccountCapability::ReadOnly, None),
        (AccountCapability::Modify, None),
        (
            AccountCapability::Modify,
            Some(document!(
                "openid https://www.googleapis.com/auth/gmail.modify https://www.googleapis.com/auth/gmail.readonly"
            )),
        ),
    ] {
        let body = token_body(scope.clone(), &identity());
        let transport =
            GmailTokenTransport::with_transport(FakePostTransport::new(vec![json(200, &body)]));
        let grant = make_grant_for("capability-code", capability);
        let result = ready(exchange_capability_grant(
            &grant,
            &make_config(None),
            &transport,
            &TestClock::default(),
        ))
        .expect("bound exchange");
        assert_eq!(result.capability(), capability);
        assert_eq!(result.subject().as_str(), "subject-sentinel");
        assert_eq!(
            matches!(result.accepted_scope().evidence(), ScopeEvidence::Absent),
            scope.is_none()
        );
        let stored = StoredGrantSnapshot::new(
            Zeroizing::new("stored-sentinel".to_owned()),
            AccountSubject::from_broker_validated(Zeroizing::new("subject-sentinel".to_owned()))
                .expect("trusted stored subject"),
            capability,
        )
        .expect("stored context");
        let transport =
            GmailTokenTransport::with_transport(FakePostTransport::new(vec![json(200, &body)]));
        let result = ready(refresh_stored_grant(
            &stored,
            &make_config(None),
            &transport,
            &TestClock::default(),
        ))
        .expect("bound refresh");
        let CapabilityRefreshOutcome::Granted(success) = result else {
            panic!("valid scope denied");
        };
        assert_eq!(success.capability(), capability);
    }
}

// Contract: rejected scope skips malformed identity, while JSON null/type is not absent evidence.
// Regression: absence/null collapse or wrong-capability identity errors mask the scope boundary.
#[test]
fn token_wire_rejects_cross_capability_and_null_scopes_without_fabricating_absence() {
    for (capability, scope) in [
        (
            AccountCapability::ReadOnly,
            "openid https://www.googleapis.com/auth/gmail.modify https://www.googleapis.com/auth/gmail.readonly",
        ),
        (
            AccountCapability::Modify,
            "openid https://www.googleapis.com/auth/gmail.readonly",
        ),
    ] {
        let transport = GmailTokenTransport::with_transport(FakePostTransport::new(vec![json(
            200,
            &token_body(Some(document!(scope)), "malformed-jwt"),
        )]));
        let grant = make_grant_for("code", capability);
        let config = make_config(None);
        let clock = TestClock::default();
        let result = if capability == AccountCapability::ReadOnly {
            ready(exchange_grant(&grant, &config, &transport, &clock))
        } else {
            ready(exchange_capability_grant(
                &grant, &config, &transport, &clock,
            ))
        };
        assert!(matches!(result, Err(TokenError::InsufficientScope)));
    }
    for scope in [
        Value::Null,
        document!(42),
        document!([]),
        document!("x".repeat(4097)),
    ] {
        let transport = GmailTokenTransport::with_transport(FakePostTransport::new(vec![json(
            200,
            &token_body(Some(scope), &identity()),
        )]));
        let (_, request) = captured_exchange(None);
        assert!(matches!(
            ready(transport.exchange(request)),
            Err(TokenTransportError::MalformedResponse)
        ));
    }
    let transport = GmailTokenTransport::with_transport(FakePostTransport::new(vec![json(
        200,
        &token_body(Some(document!("")), "malformed-jwt"),
    )]));
    let (_, request) = captured_exchange(None);
    let response = ready(transport.exchange(request)).expect("explicit empty scope evidence");
    assert!(matches!(
        response.scope_evidence(),
        ScopeEvidence::Explicit(_)
    ));
    assert!(!response.gmail_read_granted());
    assert!(response.into_parts().3.is_none());
}

// Contract: specific events apply once, uncovered generics survive, and ALL raw references count.
// Regression: double application, dropped Changed targets or deduplicated budget accounting.
#[test]
fn history_wire_normalizes_events_but_counts_duplicate_raw_references() {
    let body = history_body(
        document!([{"id":"10","messages":[{"id":"a"},{"id":"b"},{"id":"a"}],
        "messagesAdded":[{"message":{"id":"a"}},{"message":{"id":"a"}}],
        "labelsAdded":[{"message":{"id":"a"},"labelIds":["Label_1"]},{"message":{"id":"a"},"labelIds":["Label_2","Label_1"]}],
        "labelsRemoved":[{"message":{"id":"c"},"labelIds":["UNREAD"]}]}]),
    );
    let (mailbox, transport) = mailbox(vec![json(200, &body)]);
    let page = ready(mailbox.history_page(&query())).expect("History page");
    assert_eq!(page.response_cursor().as_str(), "9999");
    let record = &page.records()[0];
    assert_eq!(record.id().as_str(), "10");
    assert_eq!(record.decoded_references(), 8);
    let events: Vec<_> = record
        .events()
        .iter()
        .map(|event| {
            (
                event.key().message_id().as_str(),
                match event.kind() {
                    HistoryEventKind::Added => "added",
                    HistoryEventKind::LabelsAdded(_) => "labels-added",
                    HistoryEventKind::LabelsRemoved(_) => "labels-removed",
                    HistoryEventKind::Changed => "changed",
                    HistoryEventKind::Deleted => "deleted",
                },
            )
        })
        .collect();
    assert_eq!(
        events,
        [
            ("a", "added"),
            ("a", "labels-added"),
            ("b", "changed"),
            ("c", "labels-removed")
        ]
    );
    let HistoryEventKind::LabelsAdded(labels) = record.events()[1].kind() else {
        panic!("coalesced delta");
    };
    assert_eq!(
        labels.iter().map(LabelId::as_str).collect::<Vec<_>>(),
        ["Label_1", "Label_2"]
    );
    assert!(
        record
            .affected()
            .iter()
            .all(|key| key.account_id() == &account(ACCOUNT))
    );
    let request = &transport.requests()[0];
    let url = Url::parse(&request.0).expect("URL");
    assert_eq!(
        url.as_str().split('?').next(),
        Some("https://gmail.googleapis.com/gmail/v1/users/me/history")
    );
    assert_eq!(query_value(&url, "startHistoryId"), "9");
    assert_eq!(query_value(&url, "maxResults"), "500");
    assert_eq!(
        query_value(&url, "fields"),
        "history(id,messages(id),messagesAdded(message(id)),messagesDeleted(message(id)),labelsAdded(message(id),labelIds),labelsRemoved(message(id),labelIds)),nextPageToken,historyId"
    );
    assert_eq!(request.1, 2_097_152);
}

// Contract: decoding stops at whole-record bounds instead of rejecting every large valid page.
// Regression: raw duplicates bypass budget, a single over-limit record applies, or local prefix looks complete.
#[test]
fn history_wire_exposes_whole_record_prefix_for_budget_and_record_failure() {
    let records: Vec<_> = (10..21)
        .map(|id| document!({"id":id.to_string(),"messages":vec![document!({"id":"m"});1000]}))
        .collect();
    let (mailbox, _) = mailbox(vec![json(200, &history_body(document!(records)))]);
    let page = ready(mailbox.history_page(&query())).expect("bounded prefix");
    assert_eq!(page.records().len(), 10);
    assert_eq!(page.records().last().expect("prefix").id().as_str(), "19");
    assert_eq!(
        page.records()
            .iter()
            .map(tersa_application::history::HistoryRecord::decoded_references)
            .sum::<usize>(),
        10_000
    );
    assert!(page.records().iter().all(|r| r.events().len() == 1));
    assert!(matches!(
        page.progress(),
        HistoryPageProgress::LocalPrefix {
            provider: ProviderContinuation::End,
            reason: LocalHistoryStop::ReferenceBudget
        }
    ));
    for messages in [
        vec![document!({"id":"m"}); 10_001],
        (0..1001)
            .map(|id| document!({"id":format!("m-{id}")}))
            .collect(),
    ] {
        let (mailbox, _) = self::mailbox(vec![json(
            200,
            &history_body(document!([{"id":"10","messages":messages}])),
        )]);
        let page =
            ready(mailbox.history_page(&query())).expect("explicit undecidable first record");
        assert!(page.records().is_empty());
        assert!(matches!(
            page.progress(),
            HistoryPageProgress::LocalPrefix {
                reason: LocalHistoryStop::RecoveryRequired,
                ..
            }
        ));
    }
    let distinct: Vec<_> = (0..1000)
        .map(|id| document!({"id": format!("m-{id}")}))
        .collect();
    let (mailbox, _) = self::mailbox(vec![json(
        200,
        &history_body(document!([{"id":"10","messages":distinct}])),
    )]);
    let page = ready(mailbox.history_page(&query())).expect("full 1,000-target record");
    assert_eq!(page.records().len(), 1);
    assert_eq!(page.records()[0].affected().len(), 1_000);
    assert!(matches!(
        page.progress(),
        HistoryPageProgress::Complete(ProviderContinuation::End)
    ));
    let (mailbox, _) = self::mailbox(vec![json(
        200,
        &history_body(
            document!([{"id":"10","messages":[{"id":"m"}]},{"id":"11","messagesAdded":[{"message":{}}]},{"id":"12","messages":[{"id":"later"}]}]),
        ),
    )]);
    let page = ready(mailbox.history_page(&query())).expect("valid prefix before malformed event");
    assert_eq!(page.records().len(), 1);
    assert!(matches!(
        page.progress(),
        HistoryPageProgress::LocalPrefix {
            reason: LocalHistoryStop::RecoveryRequired,
            ..
        }
    ));
}

// Contract: envelope IDs/pagination are validated even beyond a locally stopped record.
// Regression: a valid-looking prefix escapes an unordered, duplicate or malformed envelope.
#[test]
fn history_wire_validates_entire_envelope_before_returning_any_prefix() {
    let cases = [
        history_body(document!([{"id":"10"},{"id":"11","messagesAdded":null},{"id":"9"}])),
        history_body(document!([{"id":"10"},{"id":"10"}])),
        history_body(document!([{"id":"010"}])),
        r#"{"historyId":"8","history":[]}"#.to_owned(),
        r#"{"historyId":"99","history":[{"id":"10","messages":[{"id":"a","id":"b"}]}]}"#.to_owned(),
        history_body(document!(
            (10..511)
                .map(|id| document!({"id":id.to_string()}))
                .collect::<Vec<_>>()
        )),
    ];
    for body in cases {
        let (mailbox, _) = mailbox(vec![json(200, &body)]);
        assert!(matches!(
            ready(mailbox.history_page(&query())),
            Err(HistoryFeedError::Read(MetadataReadError::InvalidResponse))
        ));
    }
    let (mailbox, _) = mailbox(vec![Reply::Response {
        status: 200,
        content_length: Some(2_097_153),
        chunks: vec![b"{}".to_vec()],
    }]);
    assert!(matches!(
        ready(mailbox.history_page(&query())),
        Err(HistoryFeedError::Read(MetadataReadError::InvalidResponse))
    ));
}

// Contract: actual empty intermediate pages can continue with unchanged checkpoint and opaque token.
// Regression: empty pages fabricate progress, repeated tokens pass, or HTTP status broadens fallback.
#[test]
fn history_empty_continuation_and_resource_specific_404s_remain_distinct() {
    let body = r#"{"historyId":"99","nextPageToken":"page+/=?&"}"#;
    let (mailbox, transport) = mailbox(vec![
        json(200, body),
        json(400, "{}"),
        json(404, "{}"),
        json(404, "{}"),
        json(404, "{}"),
        json(404, "{}"),
    ]);
    let page = ready(mailbox.history_page(&query())).expect("empty intermediate");
    assert!(page.records().is_empty());
    let checkpoint = HistoryCheckpoint::new(
        AccountFence::new(account(ACCOUNT), IdentityHash::from_bytes([7; 32])),
        Some(cursor("9")),
    );
    let next =
        HistoryQuery::continue_after(&page, &checkpoint).expect("unchanged matching local context");
    assert!(matches!(
        ready(mailbox.history_page(&next)),
        Err(HistoryFeedError::InvalidContinuation)
    ));
    assert!(matches!(
        ready(mailbox.history_page(&query())),
        Err(HistoryFeedError::CursorExpired)
    ));
    assert!(matches!(
        ready(mailbox.capture_baseline(&account(ACCOUNT))),
        Err(MetadataReadError::ProfileMissing)
    ));
    assert!(matches!(
        ready(mailbox.observe_message(&key("missing")))
            .expect("observed absence")
            .state(),
        RemoteMessageState::Missing
    ));
    assert!(matches!(
        ready(mailbox.message_metadata(&key("missing"))).expect("metadata absence"),
        MetadataObservation::Missing(_)
    ));
    let url = Url::parse(&transport.requests()[1].0).expect("URL");
    assert_eq!(query_value(&url, "pageToken"), "page+/=?&");
    assert_eq!(query_value(&url, "startHistoryId"), "9");
    let (mailbox, _) = self::mailbox(vec![json(200, body), json(200, body)]);
    let page = ready(mailbox.history_page(&query())).expect("first page");
    let next = HistoryQuery::continue_after(&page, &checkpoint).expect("continued context");
    assert!(matches!(
        ready(mailbox.history_page(&next)),
        Err(HistoryFeedError::InvalidContinuation)
    ));
}

// Contract: exact fixed-projection GETs may omit an empty repeated labelIds; invalid sets never become complete.
// Regression: archive+read unlabeled messages fail forever, or null/partial/overflow data supplies false absence.
#[test]
fn full_membership_reads_accept_unlabeled_messages_and_fail_closed_on_invalid_sets() {
    for labels in [None, Some(document!([]))] {
        let mut body = document!({"id":"m/a?b"});
        if let Some(labels) = labels {
            body["labelIds"] = labels;
        }
        let (mailbox, transport) = mailbox(vec![json(200, &body.to_string())]);
        let observed =
            ready(mailbox.observe_message(&key("m/a?b"))).expect("observed unlabeled message");
        let RemoteMessageState::Known(membership) = observed.state() else {
            panic!("empty is Known, not Missing");
        };
        assert!(membership.ids().is_empty());
        let url = Url::parse(&transport.requests()[0].0).expect("URL");
        assert_eq!(url.path(), "/gmail/v1/users/me/messages/m%2Fa%3Fb");
        assert_eq!(query_value(&url, "format"), "minimal");
        assert_eq!(query_value(&url, "fields"), "id,labelIds");
    }
    for labels in [
        Value::Null,
        document!("UNREAD"),
        document!(["INBOX", "INBOX"]),
        document!(["bad/id"]),
        document!((0..513).map(|i| format!("Label_{i}")).collect::<Vec<_>>()),
    ] {
        let (mailbox, _) = mailbox(vec![json(
            200,
            &document!({"id":"m","labelIds":labels}).to_string(),
        )]);
        assert_eq!(
            ready(mailbox.observe_message(&key("m"))),
            Err(MetadataReadError::InvalidResponse)
        );
    }
    for body in [
        r#"{"id":"wrong","labelIds":[]}"#,
        "{}",
        r#"{"id":"m","labelIds":["UNREAD"]"#,
    ] {
        let (mailbox, _) = mailbox(vec![json(200, body)]);
        assert_eq!(
            ready(mailbox.observe_message(&key("m"))),
            Err(MetadataReadError::InvalidResponse)
        );
    }
    // Sparse valid JSON is not complete evidence if the declared body length mismatches.
    let sparse = br#"{"id":"m"}"#;
    for length in [sparse.len() - 1, sparse.len() + 10] {
        let (mailbox, _) = mailbox(vec![Reply::Response {
            status: 200,
            content_length: Some(length),
            chunks: vec![sparse.to_vec()],
        }]);
        assert_eq!(
            ready(mailbox.observe_message(&key("m"))),
            Err(MetadataReadError::InvalidResponse)
        );
    }
    let body =
        document!({"id":"m","labelIds":(0..512).map(|i|format!("Label_{i}")).collect::<Vec<_>>()});
    let (mailbox, _) = mailbox(vec![json(200, &body.to_string())]);
    let RemoteMessageState::Known(labels) = ready(mailbox.observe_message(&key("m")))
        .expect("full bound")
        .state()
        .clone()
    else {
        panic!("Known set");
    };
    assert_eq!(labels.ids().len(), 512);
}

// Contract: baseline is narrow and snapshot preserves existing recent defaults without raw-body fetching.
// Regression: list omissions settle targets, body fetching reads labels, or snapshot changes retention filters.
#[test]
fn baseline_and_snapshot_metadata_use_narrow_gets_and_preserve_listing_defaults() {
    let unlabeled = r#"{"id":"m","threadId":"t","internalDate":"42"}"#;
    let (mailbox, transport) = mailbox(vec![
        json(200, r#"{"historyId":"50"}"#),
        json(
            200,
            r#"{"messages":[{"id":"m","threadId":"t"},{"id":"gone","threadId":"g"}]}"#,
        ),
        json(200, unlabeled),
        json(404, "{}"),
    ]);
    let baseline = ready(mailbox.capture_baseline(&account(ACCOUNT))).expect("baseline");
    let page = ready(mailbox.snapshot_page(&baseline, None)).expect("snapshot metadata");
    assert_eq!(page.baseline().cursor().as_str(), "50");
    assert_eq!(page.items().len(), 1);
    let RemoteMessageState::Known(labels) = page.items()[0].observation().state() else {
        panic!("full membership");
    };
    assert!(labels.ids().is_empty());
    let requests = transport.requests();
    assert_eq!(requests.len(), 4);
    let profile = Url::parse(&requests[0].0).expect("URL");
    assert_eq!(query_value(&profile, "fields"), "historyId");
    let listing = Url::parse(&requests[1].0).expect("URL");
    assert_eq!(query_value(&listing, "maxResults"), "25");
    assert_eq!(listing.query_pairs().count(), 2);
    assert_eq!(
        query_value(&listing, "fields"),
        "messages(id,threadId),nextPageToken"
    );
    for request in &requests[2..] {
        let url = Url::parse(&request.0).expect("URL");
        assert_eq!(query_value(&url, "format"), "metadata");
        assert_eq!(
            query_value(&url, "fields"),
            "id,threadId,internalDate,labelIds,snippet,payload(headers)"
        );
    }
    let (mailbox, _) = self::mailbox(vec![
        json(200, r#"{"messages":[{"id":"m","threadId":"wrong"}]}"#),
        json(200, unlabeled),
    ]);
    assert_eq!(
        ready(mailbox.snapshot_page(&baseline, None)),
        Err(MetadataReadError::InvalidResponse)
    );
}

// Contract: label reads preserve exact names/kinds, complete catalog and exact known identity.
// Regression: names normalize, system IDs become User targets, or overflow/mismatched GETs become guessed definitions.
#[test]
fn readonly_label_reads_are_complete_exact_and_never_require_modify_authority() {
    let body = r#"{"labels":[{"id":"INBOX","name":"Inbox","type":"system"},{"id":"Label_1","name":"e\u0301","type":"user"},{"id":"Label_2","name":"é","type":"user"}]}"#;
    let (mailbox, transport) = mailbox(vec![
        json(200, body),
        json(200, r#"{"id":"Label_1","name":"e\u0301","type":"user"}"#),
        json(404, "{}"),
    ]);
    let catalog = ready(mailbox.label_catalog(&account(ACCOUNT))).expect("complete catalog");
    assert_eq!(catalog.definitions().len(), 3);
    assert_eq!(catalog.definitions()[0].kind(), LabelKind::System);
    assert_eq!(
        catalog.definitions()[1].name().as_str().as_bytes(),
        "e\u{301}".as_bytes()
    );
    assert_ne!(
        catalog.definitions()[1].name(),
        catalog.definitions()[2].name()
    );
    let id = LabelId::new("Label_1").expect("label");
    assert_eq!(
        ready(mailbox.label_definition(&account(ACCOUNT), &id))
            .expect("known GET")
            .expect("present")
            .id(),
        &id
    );
    assert!(
        ready(mailbox.label_definition(&account(ACCOUNT), &id))
            .expect("exact absence")
            .is_none()
    );
    let url = Url::parse(&transport.requests()[0].0).expect("URL");
    assert_eq!(url.path(), "/gmail/v1/users/me/labels");
    assert_eq!(query_value(&url, "fields"), "labels(id,name,type)");
    for body in [
        r#"{"labels":[{"id":"INBOX","name":"wrong","type":"user"}]}"#,
        r#"{"labels":[{"id":"Label_1","name":"x","type":"unknown"}]}"#,
        r#"{"labels":[{"id":"Label_1","name":"x","type":"user"},{"id":"Label_1","name":"x","type":"user"}]}"#,
        "{}",
    ] {
        let (mailbox, _) = self::mailbox(vec![json(200, body)]);
        assert_eq!(
            ready(mailbox.label_catalog(&account(ACCOUNT))),
            Err(MetadataReadError::InvalidResponse)
        );
    }
    let body = document!({"labels":(0..501).map(|i|document!({"id":format!("Label_{i}"),"name":"x","type":"user"})).collect::<Vec<_>>()});
    let (mailbox, _) = self::mailbox(vec![
        json(200, &body.to_string()),
        json(200, r#"{"id":"Label_2","name":"x","type":"user"}"#),
    ]);
    assert_eq!(
        ready(mailbox.label_catalog(&account(ACCOUNT))),
        Err(MetadataReadError::InvalidResponse)
    );
    assert_eq!(
        ready(mailbox.label_definition(&account(ACCOUNT), &id)),
        Err(MetadataReadError::InvalidResponse)
    );
}

// Contract: all new read entrypoints reject foreign account bindings before transport work.
// Regression: one newly added endpoint bypasses the account-bound GET adapter check.
#[test]
fn new_read_entrypoints_reject_foreign_accounts_without_requests() {
    let (mailbox, transport) = mailbox(vec![]);
    let other = account("other-account");
    let query = HistoryQuery::new(
        other.clone(),
        cursor("9"),
        PageSize::new(500).expect("size"),
    );
    let key = MessageKey::new(other.clone(), message_id("m"));
    let baseline = CapturedBaseline::new(other.clone(), cursor("9"));
    assert!(matches!(
        ready(mailbox.history_page(&query)),
        Err(HistoryFeedError::Read(
            MetadataReadError::AuthorizationRequired
        ))
    ));
    assert_eq!(
        ready(mailbox.capture_baseline(&other)),
        Err(MetadataReadError::AuthorizationRequired)
    );
    assert_eq!(
        ready(mailbox.observe_message(&key)),
        Err(MetadataReadError::AuthorizationRequired)
    );
    assert_eq!(
        ready(mailbox.message_metadata(&key)),
        Err(MetadataReadError::AuthorizationRequired)
    );
    assert_eq!(
        ready(mailbox.snapshot_page(&baseline, None)),
        Err(MetadataReadError::AuthorizationRequired)
    );
    assert_eq!(
        ready(mailbox.label_catalog(&other)),
        Err(MetadataReadError::AuthorizationRequired)
    );
    assert_eq!(
        ready(mailbox.label_definition(&other, &LabelId::new("Label_1").expect("label"))),
        Err(MetadataReadError::AuthorizationRequired)
    );
    assert!(transport.requests().is_empty());
}
