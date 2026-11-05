// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Key-to-production-worker transitions over actual synthetic `SQLCipher` accounts.
mod ports;
use super::super::{
    app::ReadMarker,
    finish_work, initial_app,
    integration_tests::{components, message},
};
use super::*;
use crate::test_support::LocalFixture as Fixture;
use ports::Port;
use ratatui::{Terminal, backend::TestBackend};
use std::{
    sync::atomic::Ordering,
    time::{Duration, Instant},
};
use tersa_application::{
    command::CommandAdmissionOutcome,
    command_coordinator::{CommandDriveReport, MailboxCommandCoordinator},
    identity::AccountIdentityStore,
    mailbox::{MailboxStore, MessageId},
    mailbox_state::{LabelCatalog, LabelId, LabelKind},
    profile::AccountFence,
};
use tersa_sync_runtime::{AccountCommandReport, Runtime};

fn executor() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("executor")
}
fn press(
    app: &mut App,
    source: &dyn MailSource,
    workers: &mut Workers,
    code: KeyCode,
) -> Option<Request> {
    // The production loop renders the current state before reading the next input.
    screen(app);
    let key = KeyEvent::new(code, KeyModifiers::NONE);
    if app.triage.modal.is_some() {
        return super::key(app, source, workers, key);
    }
    match app.key(key) {
        Some(Request::Triage(tool)) => {
            open(app, source, workers, tool);
            None
        }
        request => request,
    }
}
fn down(app: &mut App, source: &dyn MailSource, workers: &mut Workers, count: usize) {
    for _ in 0..count {
        press(app, source, workers, KeyCode::Down);
    }
}
fn choose(app: &mut App, source: &dyn MailSource, workers: &mut Workers, count: usize) {
    down(app, source, workers, count);
    press(app, source, workers, KeyCode::Enter);
}
fn wait(
    app: &mut App,
    source: &dyn MailSource,
    workers: &mut Workers,
    account: &AccountId,
    request: u64,
) {
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        finish_work(workers, app, source, 1);
        if matches!(app.control_results.get(account), Some(ControlEvent::Finished(binding, _)) if binding.request == request)
        {
            return;
        }
        assert!(
            Instant::now() < until,
            "owned worker result {account:?}/{request} must arrive; got {:?}; status {:?}",
            app.control_results,
            app.status
        );
        std::thread::yield_now();
    }
}
fn screen(app: &mut App) -> String {
    screen_at(app, 120, 32)
}
fn screen_at(app: &mut App, width: u16, height: u16) -> String {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("terminal");
    terminal
        .draw(|frame| super::super::view::draw(frame, app, 1))
        .expect("draw");
    let buffer = terminal.backend().buffer();
    (0..height)
        .map(|y| {
            (0..width)
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n")
}
fn seed_headers(fixture: &Fixture, account: &AccountId, ids: &[&str]) {
    let store = fixture.installation.open_store(account).expect("store");
    executor()
        .block_on(store.upsert_envelopes(
            account,
            &ids.iter().map(|id| message(id, 1)).collect::<Vec<_>>(),
        ))
        .expect("headers");
}
fn local(fixture: &Fixture) -> Runtime {
    Runtime::local(Arc::clone(&fixture.installation))
}
fn fence(fixture: &Fixture, account: &AccountId) -> AccountFence {
    let store = fixture.installation.open_store(account).expect("store");
    AccountFence::new(
        account.clone(),
        executor()
            .block_on(store.load_identity(account))
            .expect("identity")
            .expect("known"),
    )
}
fn admit(runtime: &Runtime, account: &AccountId, id: &str) -> CommandSnapshot {
    let outcome = executor()
        .block_on(
            runtime.admit_command(
                account,
                &CommandIntent::Messages {
                    targets: MessageTargets::new(
                        account.clone(),
                        vec![MessageId::new(id).expect("id")],
                    )
                    .expect("targets"),
                    action: MessageAction::Read,
                },
            ),
        )
        .expect("admit");
    let CommandAdmissionOutcome::Admitted(saved) = outcome else {
        panic!("fresh command")
    };
    *saved
}
fn complete(fixture: &Fixture, account: &AccountId, port: &Port, id: &str) -> CommandDriveReport {
    let store = fixture.installation.open_store(account).expect("store");
    let fence = fence(fixture, account);
    port.row(id, &["UNREAD"]);
    let sent = executor().block_on(MailboxCommandCoordinator::new(&store).drive(
        &fence,
        port,
        port,
        &CommandWritePolicy::Automatic,
    ));
    assert!(sent.dispatch_invoked());
    port.row(id, &[]);
    let result =
        executor().block_on(MailboxCommandCoordinator::new(&store).observe(&fence, port, port));
    assert_eq!(
        result.snapshot().expect("result").status(),
        MailboxCommandStatus::Complete
    );
    result
}
fn open_queue(app: &mut App, source: &dyn MailSource, workers: &mut Workers) {
    press(app, source, workers, KeyCode::Char('Q'));
    // All requires an explicit account; single-account scope has an exact owner.
    if app.scope == ViewScope::All {
        choose(app, source, workers, 0);
    }
}
fn label(account: &AccountId, id: &str, name: &str) -> LabelDefinition {
    LabelDefinition::new(
        account.clone(),
        LabelId::new(id).expect("id"),
        LabelName::new(name).expect("name"),
        LabelKind::User,
    )
    .expect("user")
}
fn catalog(fixture: &Fixture, account: &AccountId, definitions: Vec<LabelDefinition>) {
    fixture
        .installation
        .open_store(account)
        .expect("store")
        .replace_cached_label_catalog(
            &fence(fixture, account),
            &LabelCatalog::new(account.clone(), definitions).expect("catalog"),
        )
        .expect("cache catalog");
}

#[test]
fn key_actions_partition_duplicate_ids_and_keep_unknown_pending_and_readonly_distinct() {
    let fixture = Fixture::new();
    let a = &fixture.accounts[0];
    let b = &fixture.accounts[1];
    for account in [a, b] {
        seed_headers(&fixture, account, &["same"]);
    }
    let (source, mut workers) = components(&fixture);
    let mut app = initial_app(&source).expect("app");
    assert!(app.rows.iter().all(|row| row.read == ReadMarker::Unknown));
    press(&mut app, &source, &mut workers, KeyCode::Char('V'));
    assert_eq!(app.triage.batch.len(), 2);
    press(&mut app, &source, &mut workers, KeyCode::Char('m'));
    choose(&mut app, &source, &mut workers, 1); // Explicit Unread, never toggle Unknown.
    wait(&mut app, &source, &mut workers, a, 1);
    wait(&mut app, &source, &mut workers, b, 1);
    for account in [a, b] {
        let status = source.account_state(account).expect("owner");
        assert_eq!(status.pending.len(), 1);
        let MailboxCommandKind::MessageState { targets, desired } =
            status.pending[0].command().kind()
        else {
            panic!("messages")
        };
        assert_eq!(targets.account_id(), account);
        assert_eq!(targets.ids(), [MessageId::new("same").expect("id")]);
        assert!(desired.memberships()[0].is_present());
        assert!(
            matches!(app.control_results.get(account), Some(ControlEvent::Finished(_,Ok(result))) if matches!(result.as_ref(), super::super::control::ControlResult::Changed { online:Some(Err(_)), .. }))
        );
    }
    // Results do not retarget the frozen submission dialog; its close reloads observations.
    assert!(screen(&mut app).contains("Independent account submissions"));
    press(&mut app, &source, &mut workers, KeyCode::Esc);
    finish_work(&mut workers, &mut app, &source, 1);
    assert!(screen(&mut app).contains('◷'));
    press(&mut app, &source, &mut workers, KeyCode::Char('i'));
    let detail = screen(&mut app);
    assert!(detail.contains("unknown") || detail.contains("Unknown"));
    assert!(detail.contains("Pending") && detail.contains("unread"));
    press(&mut app, &source, &mut workers, KeyCode::Esc);
    let store = fixture.installation.open_store(b).expect("store");
    store
        .replace_credential_snapshot(
            &store.load_credential_snapshot(b).expect("snapshot"),
            AccountCapability::ReadOnly,
            &tersa_store_sqlcipher::StoreCredential::Active(zeroize::Zeroizing::new(
                "synthetic-readonly".to_owned(),
            )),
        )
        .expect("readonly");
    press(&mut app, &source, &mut workers, KeyCode::Char('V'));
    press(&mut app, &source, &mut workers, KeyCode::Char('m'));
    choose(&mut app, &source, &mut workers, 0);
    let rendered = screen(&mut app);
    assert!(rendered.contains("ReadOnly") && rendered.contains("Upgrade"));
    wait(&mut app, &source, &mut workers, a, 2);
    assert_eq!(source.account_state(a).expect("a").pending.len(), 2);
    assert_eq!(source.account_state(b).expect("b").pending.len(), 1);
}

#[test]
fn undo_confirmation_carries_exact_source_through_real_ordered_worker_admission() {
    let fixture = Fixture::new();
    let account = &fixture.accounts[0];
    let runtime = local(&fixture);
    let port = Port::default();
    admit(&runtime, account, "a");
    complete(&fixture, account, &port, "a");
    let (source, mut workers) = components(&fixture);
    let mut app = initial_app(&source).expect("app");
    super::super::change_view(
        &mut app,
        &source,
        &mut workers,
        ViewScope::Account(account.clone()),
    )
    .expect("view");
    press(&mut app, &source, &mut workers, KeyCode::Char('A'));
    choose(&mut app, &source, &mut workers, 5); // Exact retained A -> warning.
    assert!(screen(&mut app).contains("conditional") || screen(&mut app).contains("Conditional"));
    press(&mut app, &source, &mut workers, KeyCode::Enter); // Default Cancel.
    assert!(
        source
            .account_state(account)
            .expect("state")
            .pending
            .is_empty()
    );
    press(&mut app, &source, &mut workers, KeyCode::Char('A'));
    choose(&mut app, &source, &mut workers, 5);
    admit(&runtime, account, "b");
    complete(&fixture, account, &port, "b");
    let before = source.account_state(account).expect("B");
    let b = before.undo.expect("candidate B");
    choose(&mut app, &source, &mut workers, 1); // Still confirmed A, not latest B.
    wait(&mut app, &source, &mut workers, account, 1);
    assert!(matches!(
        app.control_results.get(account),
        Some(ControlEvent::Finished(_, Err(_)))
    ));
    let rejected = source.account_state(account).expect("after rejection");
    assert!(
        rejected.pending.is_empty(),
        "stale A must not silently admit B's Undo"
    );
    assert_eq!(rejected.undo.as_ref(), Some(&b));
    press(&mut app, &source, &mut workers, KeyCode::Char('A'));
    choose(&mut app, &source, &mut workers, 5);
    choose(&mut app, &source, &mut workers, 1);
    wait(&mut app, &source, &mut workers, account, 2);
    let state = source.account_state(account).expect("queued offline Undo");
    assert_eq!(state.pending.len(), 1);
    assert_eq!(
        state.pending[0].command().kind(),
        &MailboxCommandKind::Compensate(b.compensation().clone())
    );
    assert_eq!(state.pending[0].status(), MailboxCommandStatus::Queued);
    assert_eq!(port.sends.load(Ordering::SeqCst), 2);
}

#[test]
fn exact_label_inputs_and_colliding_names_never_become_routing_identity() {
    let fixture = Fixture::new();
    let account = &fixture.accounts[0];
    let first = label(account, "u1", "same");
    let second = label(account, "u2", "same\u{1b}[31m");
    catalog(&fixture, account, vec![first.clone(), second.clone()]);
    let (source, mut workers) = components(&fixture);
    let mut app = initial_app(&source).expect("app");
    press(&mut app, &source, &mut workers, KeyCode::Char('L'));
    assert!(screen(&mut app).contains("Choose exact account"));
    choose(&mut app, &source, &mut workers, 0);
    let text = screen(&mut app);
    assert!(text.contains("u1") && text.contains("u2"));
    assert!(!text.contains('\u{1b}'));
    choose(&mut app, &source, &mut workers, 3); // Second raw ID, despite equal display names.
    choose(&mut app, &source, &mut workers, 0); // Rename.
    let exact = "renamed\u{1b}]52;c;payload\u{7}\n\0";
    screen(&mut app);
    paste(&mut app, exact);
    assert!(!screen(&mut app).contains('\u{1b}'));
    press(&mut app, &source, &mut workers, KeyCode::Enter);
    wait(&mut app, &source, &mut workers, account, 1);
    let saved = source.account_state(account).expect("state");
    let MailboxCommandKind::RenameLabel {
        label: target_label,
        name,
    } = saved.pending[0].command().kind()
    else {
        panic!("rename")
    };
    assert_eq!(target_label.id(), second.id());
    assert_eq!(name.as_str(), exact);
    // Delete is warning-bound and default-cancelled; both Esc and Enter keep intent unchanged.
    for escape in [KeyCode::Esc, KeyCode::Enter] {
        delete_dialog(&mut app, &source, &mut workers);
        let warning = screen(&mut app).to_lowercase();
        assert!(
            warning.contains("membership")
                && warning.contains("messages")
                && warning.contains("undo")
        );
        press(&mut app, &source, &mut workers, escape);
        assert_eq!(
            source
                .account_state(account)
                .expect("unchanged")
                .pending
                .len(),
            1
        );
    }
    delete_dialog(&mut app, &source, &mut workers);
    catalog(
        &fixture,
        account,
        vec![label(account, "u1", "changed"), second],
    );
    choose(&mut app, &source, &mut workers, 1);
    assert!(screen(&mut app).contains("changed"));
    assert_eq!(
        source
            .account_state(account)
            .expect("stale delete refused")
            .pending
            .len(),
        1
    );
    press(&mut app, &source, &mut workers, KeyCode::Esc);
    delete_dialog(&mut app, &source, &mut workers);
    choose(&mut app, &source, &mut workers, 1);
    wait(&mut app, &source, &mut workers, account, 2);
    assert!(
        matches!(source.account_state(account).expect("delete admitted").pending[1].command().kind(), MailboxCommandKind::DeleteLabel(target) if target.id().as_str() == "u1")
    );
    press(&mut app, &source, &mut workers, KeyCode::Char('L'));
    choose(&mut app, &source, &mut workers, 0);
    choose(&mut app, &source, &mut workers, 1);
    screen(&mut app);
    paste(&mut app, "exact new name");
    press(&mut app, &source, &mut workers, KeyCode::Enter);
    wait(&mut app, &source, &mut workers, account, 3);
    assert!(
        matches!(source.account_state(account).expect("create admitted").pending[2].command().kind(), MailboxCommandKind::CreateLabel(name) if name.as_str() == "exact new name")
    );
}

#[test]
fn queued_cancel_retry_risk_and_warned_abandon_reach_real_local_controls() {
    let fixture = Fixture::new();
    let account = &fixture.accounts[0];
    let runtime = local(&fixture);
    let port = Port::default();
    let (source, mut workers) = components(&fixture);
    let mut app = initial_app(&source).expect("app");
    admit(&runtime, account, "cancel");
    queue_action(&mut app, &source, &mut workers, 1);
    wait(&mut app, &source, &mut workers, account, 1);
    let cancelled = source.account_state(account).expect("cancelled");
    assert!(cancelled.pending.is_empty());
    assert_eq!(
        cancelled.terminal.summaries()[0].status(),
        MailboxCommandStatus::Cancelled
    );
    executor()
        .block_on(runtime.admit_command(
            account,
            &CommandIntent::CreateLabel(LabelName::new("new label").expect("name")),
        ))
        .expect("create admitted");
    let store = fixture.installation.open_store(account).expect("store");
    let fence = fence(&fixture, account);
    let possible = executor().block_on(MailboxCommandCoordinator::new(&store).drive(
        &fence,
        &port,
        &port,
        &CommandWritePolicy::Automatic,
    ));
    assert!(possible.dispatch_invoked());
    assert_eq!(
        source
            .account_state(account)
            .expect("possible send")
            .pending[0]
            .status(),
        MailboxCommandStatus::Ambiguous
    );
    queue_action(&mut app, &source, &mut workers, 1);
    assert!(screen(&mut app).to_lowercase().contains("duplicate"));
    press(&mut app, &source, &mut workers, KeyCode::Enter); // Default Cancel never authorizes.
    assert!(
        source.account_state(account).expect("no consent").pending[0]
            .retry_authorization()
            .is_none()
    );
    for request in [2, 3] {
        // Tokenless retry saves a ticket; a later explicit retry reuses that exact ticket.
        open_queue(&mut app, &source, &mut workers);
        choose(&mut app, &source, &mut workers, 0);
        choose(&mut app, &source, &mut workers, 1);
        assert!(screen(&mut app).to_lowercase().contains("duplicate"));
        choose(&mut app, &source, &mut workers, 1);
        wait(&mut app, &source, &mut workers, account, request);
        assert!(
            source
                .account_state(account)
                .expect("ticket retained")
                .pending[0]
                .retry_authorization()
                .is_some()
        );
    }
    queue_action(&mut app, &source, &mut workers, 2);
    let warning = screen(&mut app).to_lowercase();
    assert!(
        warning.contains("already") && warning.contains("recovery") && warning.contains("rollback")
    );
    press(&mut app, &source, &mut workers, KeyCode::Esc);
    assert_eq!(
        source
            .account_state(account)
            .expect("not abandoned")
            .pending
            .len(),
        1
    );
    queue_action(&mut app, &source, &mut workers, 2);
    choose(&mut app, &source, &mut workers, 1);
    wait(&mut app, &source, &mut workers, account, 4);
    let abandoned = source.account_state(account).expect("abandoned");
    assert!(abandoned.pending.is_empty());
    assert!(
        abandoned
            .terminal
            .summaries()
            .iter()
            .any(|s| s.status() == MailboxCommandStatus::Abandoned)
    );
    assert_eq!(
        port.sends.load(Ordering::SeqCst),
        1,
        "local controls never issue another provider attempt"
    );
}

#[test]
fn receipt_b_and_terminal_followup_a_keep_distinct_identities_in_queue_and_notice() {
    use super::super::control::{ControlResult, Durable};
    let fixture = Fixture::new();
    let account = &fixture.accounts[0];
    let runtime = local(&fixture);
    let port = Port::default();
    let a = admit(&runtime, account, "a");
    let store = fixture.installation.open_store(account).expect("store");
    let fence = fence(&fixture, account);
    port.row("a", &["UNREAD"]);
    let sent = executor().block_on(MailboxCommandCoordinator::new(&store).drive(
        &fence,
        &port,
        &port,
        &CommandWritePolicy::Automatic,
    ));
    assert!(sent.dispatch_invoked());
    let b = admit(&runtime, account, "b"); // Newly admitted while A is oldest.
    port.row("a", &[]);
    let followup =
        executor().block_on(MailboxCommandCoordinator::new(&store).observe(&fence, &port, &port));
    assert_eq!(
        followup.snapshot().expect("A result").command().id(),
        a.command().id()
    );
    assert_eq!(
        followup.snapshot().expect("A result").status(),
        MailboxCommandStatus::Complete
    );
    let result = ControlResult::Changed {
        durable: Durable::Admitted(b.stamp().clone()),
        online: Some(Ok(AccountCommandReport {
            command: followup,
            convergence: None,
        })),
    };
    let text = result.notice().to_string();
    assert!(text.contains(&format!(
        "Intent durably admitted: {}",
        b.command().id().as_str()
    )));
    assert!(text.contains(&format!(
        "Processed command {}: Complete",
        a.command().id().as_str()
    )));
    assert!(!text.contains(&format!(
        "Processed command {}: Complete",
        b.command().id().as_str()
    )));
    let (source, mut workers) = components(&fixture);
    let mut app = initial_app(&source).expect("app");
    app.triage.record(account.clone(), result.notice());
    open_queue(&mut app, &source, &mut workers);
    choose(&mut app, &source, &mut workers, 0);
    let saved = source.account_state(account).expect("actual queue");
    assert_eq!(saved.pending[0].command().id(), b.command().id());
    assert_eq!(saved.pending[0].status(), MailboxCommandStatus::Queued);
    assert!(screen(&mut app).contains("Queued"));
}

#[test]
fn bounded_batch_selection_clears_on_search_reload_and_view_changes_without_truncation() {
    let fixture = Fixture::new();
    let account = &fixture.accounts[0];
    let (source, mut workers) = components(&fixture);
    let rows = (0..1_001)
        .map(|id| {
            super::super::Row::sample(
                account.as_str(),
                &format!("m{id}"),
                "sender",
                "subject",
                false,
            )
        })
        .collect();
    let mut app = App::new(source.account_labels(), rows);
    press(&mut app, &source, &mut workers, KeyCode::Char('v'));
    let original = app.triage.batch.clone();
    press(&mut app, &source, &mut workers, KeyCode::Char('V'));
    assert_eq!(
        app.triage.batch, original,
        "oversized select-shown never silently truncates"
    );
    assert_eq!(
        app.rows.len(),
        1_001,
        "selection cap is not a total pagination cap"
    );
    app.rows.pop();
    app.shown.pop();
    press(&mut app, &source, &mut workers, KeyCode::Char('V'));
    assert_eq!(app.triage.batch.len(), 1_000);
    press(&mut app, &source, &mut workers, KeyCode::Char('/'));
    assert!(app.triage.batch.is_empty());
    app.paste_search("subject");
    assert_eq!(app.shown.len(), 1_000);
    app.paste_search(&"x".repeat(257));
    assert_eq!(app.search.query, "subject");
    press(&mut app, &source, &mut workers, KeyCode::Esc);
    press(&mut app, &source, &mut workers, KeyCode::Char('v'));
    app.reload(app.rows.clone(), true);
    assert!(app.triage.batch.is_empty());
    press(&mut app, &source, &mut workers, KeyCode::Char('v'));
    super::super::change_view(
        &mut app,
        &source,
        &mut workers,
        ViewScope::Account(account.clone()),
    )
    .expect("new generation");
    assert!(app.triage.batch.is_empty());
    assert!(app.rows.iter().all(|r| &r.account == account));
}

fn observed_cache(fixture: &Fixture, account: &AccountId, entries: &[(&str, &[&str])]) {
    use tersa_application::{
        history::{
            CapturedBaseline, HistoryCursor, HistoryCursorStore, SnapshotCommit, SnapshotCoverage,
            SnapshotFallbackReason,
        },
        mailbox_state::{LabelMembership, MessageKey, MessageMetadata},
    };
    let store = fixture.installation.open_store(account).expect("store");
    let fence = fence(fixture, account);
    let executor = executor();
    let entries = entries
        .iter()
        .map(|(id, labels)| {
            MessageMetadata::new(
                MessageKey::new(account.clone(), MessageId::new(*id).expect("id")),
                message(id, 1),
                LabelMembership::new(
                    account.clone(),
                    labels
                        .iter()
                        .map(|id| LabelId::new(*id).expect("label"))
                        .collect(),
                )
                .expect("labels"),
            )
            .expect("metadata")
        })
        .collect();
    let commit = SnapshotCommit::new(
        executor
            .block_on(store.checkpoint(&fence))
            .expect("checkpoint"),
        CapturedBaseline::new(account.clone(), HistoryCursor::new("1").expect("cursor")),
        entries,
        SnapshotCoverage::RecentChainEnded,
        SnapshotFallbackReason::NoCursor,
    )
    .expect("snapshot");
    executor
        .block_on(store.commit_snapshot(&commit))
        .expect("observed snapshot");
}
#[test]
fn filter_keys_query_observed_memberships_and_exact_user_label_owner() {
    let fixture = Fixture::new();
    let a = &fixture.accounts[0];
    let b = &fixture.accounts[1];
    let user = label(a, "user", "same name");
    catalog(&fixture, a, vec![user]);
    catalog(&fixture, b, vec![label(b, "user", "same name")]);
    observed_cache(
        &fixture,
        a,
        &[
            ("in-a", &["INBOX", "user"]),
            ("trash-a", &["TRASH"]),
            ("spam-a", &["SPAM"]),
        ],
    );
    observed_cache(&fixture, b, &[("in-b", &["INBOX", "user"])]);
    seed_headers(&fixture, a, &["unknown"]);
    let (source, mut workers) = components(&fixture);
    let mut app = initial_app(&source).expect("app");
    assert!(app.rows.iter().any(|r| r.id.as_str() == "unknown"));

    press(&mut app, &source, &mut workers, KeyCode::Char('V'));
    press(&mut app, &source, &mut workers, KeyCode::Char('m'));
    choose(&mut app, &source, &mut workers, 9); // Apply label, explicit owner choice.
    choose(&mut app, &source, &mut workers, 0);
    choose(&mut app, &source, &mut workers, 1);
    assert!(screen(&mut app).contains("another account"));
    wait(&mut app, &source, &mut workers, a, 1);
    assert!(
        source
            .account_state(b)
            .expect("peer not retargeted")
            .pending
            .is_empty()
    );
    assert_eq!(
        source.account_state(a).expect("owned group").pending[0]
            .counts()
            .total(),
        4
    );
    press(&mut app, &source, &mut workers, KeyCode::Esc);
    finish_work(&mut workers, &mut app, &source, 1);
    press(&mut app, &source, &mut workers, KeyCode::Char('v'));
    press(&mut app, &source, &mut workers, KeyCode::Char('F'));
    down(&mut app, &source, &mut workers, 1);
    let Some(Request::ChangeFilter(filter)) =
        press(&mut app, &source, &mut workers, KeyCode::Enter)
    else {
        panic!("filter request")
    };
    super::super::change_filter(&mut app, &source, &mut workers, filter).expect("query");
    assert!(app.triage.batch.is_empty());
    assert_eq!(app.rows.len(), 2);
    assert!(app.rows.iter().all(|r| r.id.as_str().starts_with("in-")));
    assert!(screen(&mut app).contains("Observed Inbox"));
    press(&mut app, &source, &mut workers, KeyCode::Char('F'));
    choose(&mut app, &source, &mut workers, 4); // User-label catalog in A.
    down(&mut app, &source, &mut workers, 1);
    let Some(Request::ChangeFilter(filter)) =
        press(&mut app, &source, &mut workers, KeyCode::Enter)
    else {
        panic!("user filter")
    };
    super::super::change_filter(&mut app, &source, &mut workers, filter)
        .expect("owner-bound query");
    assert_eq!(app.rows.len(), 1);
    assert_eq!(&app.rows[0].account, a);
    assert_eq!(app.rows[0].id.as_str(), "in-a");
    super::super::change_view(
        &mut app,
        &source,
        &mut workers,
        ViewScope::Account(b.clone()),
    )
    .expect("peer view");
    assert_eq!(app.filter, CachedMailboxFilter::Recent);
    assert!(app.rows.iter().all(|r| &r.account == b));
}

#[test]
fn late_owner_result_cannot_replace_a_frozen_other_account_dialog() {
    let fixture = Fixture::new();
    let a = &fixture.accounts[0];
    let b = &fixture.accounts[1];
    seed_headers(&fixture, a, &["same"]);
    seed_headers(&fixture, b, &["same"]);
    let (source, mut workers) = components(&fixture);
    let mut app = initial_app(&source).expect("app");
    press(&mut app, &source, &mut workers, KeyCode::Char('m'));
    choose(&mut app, &source, &mut workers, 0);
    press(&mut app, &source, &mut workers, KeyCode::Esc);
    press(&mut app, &source, &mut workers, KeyCode::Char('A'));
    choose(&mut app, &source, &mut workers, 1); // Explicit account B.
    wait(&mut app, &source, &mut workers, a, 1);
    assert!(app.triage.modal.is_some());
    assert!(app.triage.deferred_reload);
    // The preserved modal still routes its Upgrade to B, not the account that finished.
    choose(&mut app, &source, &mut workers, 3);
    wait(&mut app, &source, &mut workers, b, 1);
    assert!(
        matches!(app.control_results.get(b), Some(ControlEvent::Finished(binding,Err(_))) if &binding.account == b)
    );
    assert_eq!(source.account_state(a).expect("A").pending.len(), 1);
    assert!(source.account_state(b).expect("B").pending.is_empty());
}

fn queue_action(app: &mut App, source: &dyn MailSource, workers: &mut Workers, index: usize) {
    open_queue(app, source, workers);
    choose(app, source, workers, 0);
    choose(app, source, workers, index);
}

fn delete_dialog(app: &mut App, source: &dyn MailSource, workers: &mut Workers) {
    press(app, source, workers, KeyCode::Char('L'));
    choose(app, source, workers, 0);
    choose(app, source, workers, 2);
    choose(app, source, workers, 1);
}

#[test]
fn hidden_confirmation_cannot_admit_until_a_supported_frame_is_drawn() {
    let fixture = Fixture::new();
    let account = &fixture.accounts[0];
    let original = admit(&local(&fixture), account, "keep-existing-intent");
    catalog(
        &fixture,
        account,
        vec![label(account, "u1", "visible target")],
    );
    let (source, mut workers) = components(&fixture);
    let mut app = initial_app(&source).expect("app");
    delete_dialog(&mut app, &source, &mut workers);
    down(&mut app, &source, &mut workers, 1); // Select Confirm at supported size.
    assert!(screen(&mut app).contains("visible target"));
    let prior = workers
        .accounts
        .iter_mut()
        .find(|w| &w.account == account)
        .expect("owner")
        .control(ControlJob::Status, app.view_epoch)
        .expect("ordered checkpoint");
    wait(&mut app, &source, &mut workers, account, prior.request);
    let before = source.account_state(account).expect("before hidden Enter");
    let resize = screen_at(&mut app, 31, 8);
    assert!(resize.contains("Resize"));
    assert!(!resize.contains("visible target"));
    modal_key(&mut app, &source, &mut workers, KeyCode::Enter);
    let barrier = workers
        .accounts
        .iter_mut()
        .find(|w| &w.account == account)
        .expect("owner")
        .control(ControlJob::Status, app.view_epoch)
        .expect("FIFO barrier");
    wait(&mut app, &source, &mut workers, account, barrier.request);
    let after = source.account_state(account).expect("after hidden Enter");
    assert_eq!(
        after.pending, before.pending,
        "invisible confirmation must not admit a label deletion"
    );
    assert_eq!(after.terminal, before.terminal);
    assert_eq!(
        barrier.request,
        prior.request + 1,
        "hidden Enter must not submit a control job"
    );
    let modal = app.triage.modal.as_ref().expect("confirmation retained");
    let position = (modal.selected, modal.scroll, modal.follow_selection);
    for code in [
        KeyCode::Up,
        KeyCode::Down,
        KeyCode::Char('j'),
        KeyCode::Char('k'),
        KeyCode::PageDown,
        KeyCode::PageUp,
        KeyCode::Char(' '),
        KeyCode::Char('x'),
        KeyCode::Backspace,
    ] {
        modal_key(&mut app, &source, &mut workers, code);
    }
    let modal = app.triage.modal.as_ref().expect("still hidden");
    assert_eq!(
        (modal.selected, modal.scroll, modal.follow_selection),
        position
    );
    assert!(screen(&mut app).contains("visible target"));
    modal_key(&mut app, &source, &mut workers, KeyCode::Enter);
    wait(
        &mut app,
        &source,
        &mut workers,
        account,
        barrier.request + 1,
    );
    let admitted = source.account_state(account).expect("visible confirmation");
    assert_eq!(admitted.pending.len(), 2);
    assert_eq!(
        admitted.pending[0], original,
        "already-admitted work is unchanged"
    );
    assert!(
        matches!(admitted.pending[1].command().kind(), MailboxCommandKind::DeleteLabel(target) if target.id().as_str() == "u1")
    );
}

#[test]
fn unrendered_or_hidden_name_inputs_ignore_edits_paste_and_submit_but_allow_escape_and_quit() {
    let fixture = Fixture::new();
    let account = &fixture.accounts[0];
    let (source, mut workers) = components(&fixture);
    let mut app = initial_app(&source).expect("app");
    name_dialog(&mut app, &source, &mut workers);
    // Opening a new modal is not proof that its frame was rendered.
    for code in [KeyCode::Char('x'), KeyCode::Enter] {
        modal_key(&mut app, &source, &mut workers, code);
    }
    paste(&mut app, "unseen");
    assert_eq!(name_text(&app), "");
    screen(&mut app);
    paste(&mut app, "kept exactly");
    screen_at(&mut app, 32, 7); // Height guard, independently of the width case above.
    let modal = app.triage.modal.as_ref().expect("name prompt");
    let position = (modal.selected, modal.scroll, modal.follow_selection);
    for code in [
        KeyCode::Down,
        KeyCode::Char('j'),
        KeyCode::PageDown,
        KeyCode::Char(' '),
        KeyCode::Char('x'),
        KeyCode::Backspace,
        KeyCode::Enter,
    ] {
        modal_key(&mut app, &source, &mut workers, code);
    }
    paste(&mut app, "hidden suffix");
    super::key(
        &mut app,
        &source,
        &mut workers,
        KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL),
    );
    let modal = app.triage.modal.as_ref().expect("name prompt retained");
    assert_eq!(
        (modal.selected, modal.scroll, modal.follow_selection),
        position
    );
    assert_eq!(name_text(&app), "kept exactly");
    screen(&mut app);
    // The production Resize event invalidates the last supported frame. Merely
    // knowing the previous dimensions cannot authorize input before the redraw.
    app.triage.invalidate_modal_viewport();
    modal_key(&mut app, &source, &mut workers, KeyCode::Backspace);
    paste(&mut app, "not yet rendered");
    modal_key(&mut app, &source, &mut workers, KeyCode::Enter);
    assert_eq!(name_text(&app), "kept exactly");
    assert!(screen(&mut app).contains("kept exactly"));
    screen_at(&mut app, 31, 7);
    modal_key(&mut app, &source, &mut workers, KeyCode::Esc);
    assert!(app.triage.modal.is_none());
    assert!(!app.quit);
    name_dialog(&mut app, &source, &mut workers);
    screen_at(&mut app, 31, 7);
    super::key(
        &mut app,
        &source,
        &mut workers,
        KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
    );
    assert!(app.quit);
    assert!(app.triage.modal.is_none());
    let barrier = workers
        .accounts
        .iter_mut()
        .find(|w| &w.account == account)
        .expect("owner")
        .control(ControlJob::Status, app.view_epoch)
        .expect("FIFO barrier");
    wait(&mut app, &source, &mut workers, account, barrier.request);
    assert!(
        source
            .account_state(account)
            .expect("no hidden name submission")
            .pending
            .is_empty()
    );
    assert_eq!(
        barrier.request, 1,
        "no hidden edit/submit created a control job"
    );
}
fn name_dialog(app: &mut App, source: &dyn MailSource, workers: &mut Workers) {
    press(app, source, workers, KeyCode::Char('L'));
    choose(app, source, workers, 0);
    choose(app, source, workers, 1);
}
fn name_text(app: &App) -> &str {
    &app.triage
        .modal
        .as_ref()
        .expect("modal")
        .input
        .as_ref()
        .expect("name input")
        .raw
}

fn modal_key(app: &mut App, source: &dyn MailSource, workers: &mut Workers, code: KeyCode) {
    super::key(
        app,
        source,
        workers,
        KeyEvent::new(code, KeyModifiers::NONE),
    );
}
