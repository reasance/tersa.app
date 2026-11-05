// This Source Code Form is subject to the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Actual offline composition and bounded worker behavior; no provider/keyring.

use super::control::{
    ControlEvent, ControlJob, ControlResult, Durable, MAX_CONTROLS, Progress, ProgressSink,
};
use super::worker::InterruptedPhase;
use super::*;
use std::sync::{Arc, mpsc};
use tersa_application::{
    command::{MessageAction, MessageTargets},
    history::{
        CapturedBaseline, HistoryCursor, HistoryCursorStore, SnapshotCommit, SnapshotCoverage,
        SnapshotFallbackReason,
    },
    identity::AccountIdentityStore,
    mailbox::{HeaderText, MailboxStore, MessageEnvelope, ThreadId, UnixTimestampMillis},
    mailbox_state::{LabelId, LabelMembership, MessageKey as TypedKey, MessageMetadata},
    profile::AccountFence,
};
use tersa_sync_runtime::{CommandIntent, InstallationLock};

const WAIT: Duration = Duration::from_secs(5);
use crate::test_support::LocalFixture as Fixture;
fn components(fixture: &Fixture) -> (impl MailSource, Workers) {
    let context = crate::commands::Context {
        paths: crate::config::Paths {
            config_dir: fixture.path.join("config"),
            data_dir: fixture.path.clone(),
        },
        config: crate::config::Config::for_test(None),
    };
    let (source, remotes) =
        crate::commands::tui_components(&context, Arc::clone(&fixture.installation))
            .expect("offline components");
    (source, Workers::start(remotes).expect("workers"))
}
fn message(id: &str, at: i64) -> MessageEnvelope {
    MessageEnvelope::new(
        MessageId::new(id).expect("id"),
        ThreadId::new("thread").expect("thread"),
        HeaderText::new("sender").expect("sender"),
        HeaderText::new("subject").expect("subject"),
        HeaderText::new("preview").expect("preview"),
        UnixTimestampMillis::new(at).expect("time"),
        false,
    )
}
fn intent(account: &AccountId, id: &str) -> CommandIntent {
    CommandIntent::Messages {
        targets: MessageTargets::new(account.clone(), vec![MessageId::new(id).expect("id")])
            .expect("targets"),
        action: MessageAction::Read,
    }
}
fn final_event(worker: &mut Worker) -> ControlEvent {
    loop {
        let Done::Control(event) = worker.done.recv_timeout(WAIT).expect("control event") else {
            panic!("unexpected fetch/sync")
        };
        let final_result = matches!(event, ControlEvent::Finished(_, _));
        assert!(worker.finish_control(&event));
        if final_result {
            return event;
        }
    }
}
#[test]
fn real_offline_components_commit_before_online_failure_and_keep_exact_account() {
    let fixture = Fixture::new();
    let (source, mut workers) = components(&fixture);
    let account = fixture.accounts[0].clone();
    let worker = workers
        .accounts
        .iter_mut()
        .find(|w| w.account == account)
        .expect("account worker despite missing OAuth");
    worker
        .control(
            ControlJob::Admit {
                intent: intent(&account, "m"),
                resume: true,
            },
            7,
        )
        .expect("submitted, not yet durable");
    let ControlEvent::Progress(binding, Progress::Durable(Durable::Admitted(stamp))) =
        (match worker.done.recv_timeout(WAIT).expect("durable event") {
            Done::Control(event) => event,
            _ => panic!("event"),
        })
    else {
        panic!("receipt precedes online failure")
    };
    assert_eq!(binding.account, account);
    assert_eq!(binding.epoch, 7);
    assert_eq!(stamp.key().account_id(), &account);
    let final_result = final_event(worker);
    assert!(
        matches!(
            final_result,
            ControlEvent::Finished(_,Ok(result)) if matches!(result.as_ref(),ControlResult::Changed { online: Some(Err(_)), .. })
        ),
        "config failure must not become admission failure"
    );
    assert_eq!(
        source
            .account_state(&account)
            .expect("actual cached status")
            .pending
            .len(),
        1
    );
    assert!(
        source
            .account_state(&fixture.accounts[1])
            .expect("peer status")
            .pending
            .is_empty()
    );
    assert!(
        source
            .label_catalog(&account)
            .expect("cached catalog")
            .is_none()
    );
    worker
        .control(ControlJob::Cancel(stamp), 8)
        .expect("cancel submitted");
    assert!(matches!(
        final_event(worker),
        ControlEvent::Finished(_, Ok(result)) if matches!(result.as_ref(), ControlResult::Changed {durable: Durable::Cancelled(_),online:None})
    ));
    assert!(
        source
            .account_state(&account)
            .expect("status")
            .pending
            .is_empty()
    );
}
fn seed_filtered(fixture: &Fixture, workers: &mut Workers, account: &AccountId) {
    let store = fixture.installation.open_store(account).expect("store");
    let executor = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("executor");
    let envelopes: Vec<_> = (0..250)
        .map(|i| message(&format!("m{i:03}"), 300 - i))
        .collect();
    executor
        .block_on(store.upsert_envelopes(account, &envelopes))
        .expect("cached rows");
    // Real admission pins every row before a baseline/snapshot prunes the recent cache.
    let targets = MessageTargets::new(
        account.clone(),
        envelopes.iter().map(|e| e.message_id().clone()).collect(),
    )
    .expect("targets");
    workers
        .accounts
        .iter_mut()
        .find(|w| &w.account == account)
        .expect("worker")
        .control(
            ControlJob::Admit {
                intent: CommandIntent::Messages {
                    targets,
                    action: MessageAction::Archive,
                },
                resume: false,
            },
            0,
        )
        .expect("admit");
    final_event(
        workers
            .accounts
            .iter_mut()
            .find(|w| &w.account == account)
            .expect("worker"),
    );
    let identity = executor
        .block_on(store.load_identity(account))
        .expect("identity")
        .expect("known");
    let fence = AccountFence::new(account.clone(), identity);
    let metadata = MessageMetadata::new(
        TypedKey::new(account.clone(), MessageId::new("m249").expect("id")),
        message("m249", 51),
        LabelMembership::new(
            account.clone(),
            vec![
                LabelId::new("INBOX").expect("label"),
                LabelId::new("UNREAD").expect("label"),
            ],
        )
        .expect("membership"),
    )
    .expect("metadata");
    let request = SnapshotCommit::new(
        executor
            .block_on(store.checkpoint(&fence))
            .expect("checkpoint"),
        CapturedBaseline::new(account.clone(), HistoryCursor::new("1").expect("cursor")),
        vec![metadata],
        SnapshotCoverage::RecentTruncated,
        SnapshotFallbackReason::NoCursor,
    )
    .expect("actual observation fixture");
    executor
        .block_on(store.commit_snapshot(&request))
        .expect("atomic observed cache");
}

#[test]
fn real_source_uses_filtered_runtime_continuations_and_preserves_deep_pages() {
    let fixture = Fixture::new();
    let (source, mut workers) = components(&fixture);
    let account = &fixture.accounts[0];
    seed_filtered(&fixture, &mut workers, account);
    let page = source
        .page(&ViewScope::Account(account.clone()), None, 200)
        .expect("Recent");
    assert_eq!(page.rows.len(), 200);
    assert!(matches!(
        page.continuation,
        Some(MailContinuation::Runtime(_))
    ));
    assert!(!page.rows.iter().any(|row| row.id.as_str() == "m249"));
    let next = source
        .page(
            &ViewScope::Account(account.clone()),
            page.continuation.as_ref(),
            200,
        )
        .expect("next runtime page");
    assert_eq!(next.rows.len(), 50);
    source
        .set_filter(&tersa_sync_runtime::CachedMailboxFilter::Inbox)
        .expect("filter");
    assert!(
        source
            .page(
                &ViewScope::Account(account.clone()),
                page.continuation.as_ref(),
                200
            )
            .is_err(),
        "old Recent continuation cannot become an Inbox cursor"
    );
    let filtered = source
        .page(&ViewScope::Account(account.clone()), None, 200)
        .expect("filtered");
    assert_eq!(filtered.rows.len(), 1);
    assert_eq!(filtered.rows[0].id.as_str(), "m249");
    assert_eq!(filtered.rows[0].read, super::ReadMarker::Unread);
    assert_eq!(
        filtered.rows[0]
            .triage
            .as_ref()
            .expect("P8 document")
            .read
            .as_str(),
        "Observed: unread"
    );
    assert!(filtered.rows[0].observed.is_some());
}

struct Ordered {
    started: mpsc::Sender<(AccountId, u64)>,
    release: Arc<tokio::sync::Notify>,
}
impl Remote for Ordered {
    fn fetch<'a>(&'a self, _: &'a AccountId, _: &'a MessageId) -> Pending<'a, Vec<u8>> {
        Box::pin(std::future::pending())
    }
    fn sync<'a>(&'a self, _: &'a AccountId) -> Pending<'a, ()> {
        Box::pin(std::future::pending())
    }
    fn control<'a>(
        &'a self,
        account: &'a AccountId,
        _: ControlJob,
        progress: &'a ProgressSink,
    ) -> Pending<'a, ControlResult> {
        Box::pin(async move {
            self.started
                .send((account.clone(), progress.binding.request))
                .expect("start");
            self.release.notified().await;
            Ok(ControlResult::Catalog(None))
        })
    }
}
#[test]
fn control_fifo_and_completed_result_accounting_are_bounded_and_accounts_are_independent() {
    let (started, events) = mpsc::channel();
    let a = AccountId::new("a").expect("account");
    let b = AccountId::new("b").expect("account");
    let release_a = Arc::new(tokio::sync::Notify::new());
    let release_b = Arc::new(tokio::sync::Notify::new());
    let mut workers = Workers::start(vec![
        (
            a.clone(),
            Box::new(Ordered {
                started: started.clone(),
                release: Arc::clone(&release_a),
            }),
        ),
        (
            b.clone(),
            Box::new(Ordered {
                started,
                release: Arc::clone(&release_b),
            }),
        ),
    ])
    .expect("workers");
    for _ in 0..MAX_CONTROLS {
        workers.accounts[0]
            .control(ControlJob::Status, 9)
            .expect("bounded slot");
    }
    assert!(workers.accounts[0].control(ControlJob::Status, 9).is_none());
    assert_eq!(events.recv_timeout(WAIT).expect("first"), (a.clone(), 1));
    workers.accounts[1]
        .control(ControlJob::Status, 9)
        .expect("peer");
    assert_eq!(events.recv_timeout(WAIT).expect("independent peer"), (b, 1));
    release_a.notify_one();
    assert_eq!(events.recv_timeout(WAIT).expect("ordered second"), (a, 2));

    assert!(
        workers.accounts[0].control(ControlJob::Status, 9).is_none(),
        "completed-but-unconsumed result retains its slot"
    );
    let Done::Control(event) = workers.accounts[0]
        .done
        .recv_timeout(WAIT)
        .expect("first result")
    else {
        panic!("control")
    };
    assert!(workers.accounts[0].finish_control(&event));
    assert!(workers.accounts[0].control(ControlJob::Status, 9).is_some());
    workers.stop_all();
    assert!(
        workers.accounts[0]
            .interrupted_controls
            .iter()
            .any(|entry| entry.phase == InterruptedPhase::NotStarted)
    );
    assert!(
        workers.accounts[0]
            .interrupted_controls
            .iter()
            .any(|entry| entry.phase == InterruptedPhase::OutcomeUnknown)
    );
}

struct HoldAfterReceipt {
    inner: Box<dyn Remote>,
    saved: mpsc::Sender<()>,
}
impl Remote for HoldAfterReceipt {
    fn fetch<'a>(&'a self, account: &'a AccountId, id: &'a MessageId) -> Pending<'a, Vec<u8>> {
        self.inner.fetch(account, id)
    }
    fn sync<'a>(&'a self, account: &'a AccountId) -> Pending<'a, ()> {
        self.inner.sync(account)
    }
    fn control<'a>(
        &'a self,
        account: &'a AccountId,
        job: ControlJob,
        progress: &'a ProgressSink,
    ) -> Pending<'a, ControlResult> {
        Box::pin(async move {
            let _saved = self.inner.control(account, job, progress).await?;
            self.saved.send(()).expect("receipt stage");
            std::future::pending().await
        })
    }
}
#[test]
fn shutdown_drops_owned_control_work_without_cancelling_its_durable_intent() {
    let fixture = Fixture::new();
    let context = crate::commands::Context {
        paths: crate::config::Paths {
            config_dir: fixture.path.join("config"),
            data_dir: fixture.path.clone(),
        },
        config: crate::config::Config::for_test(None),
    };
    let (source, mut remotes) =
        crate::commands::tui_components(&context, Arc::clone(&fixture.installation))
            .expect("components");
    let (saved, ready) = mpsc::channel();
    let (account, inner) = remotes.remove(0);
    remotes.insert(
        0,
        (account.clone(), Box::new(HoldAfterReceipt { inner, saved })),
    );
    let mut workers = Workers::start(remotes).expect("workers");
    workers.accounts[0]
        .control(
            ControlJob::Admit {
                intent: intent(&account, "m"),
                resume: false,
            },
            11,
        )
        .expect("request");
    ready
        .recv_timeout(WAIT)
        .expect("real durable admission completed");
    let Done::Control(event) = workers.accounts[0]
        .done
        .recv_timeout(WAIT)
        .expect("receipt")
    else {
        panic!("event")
    };
    assert!(workers.accounts[0].finish_control(&event));
    workers.accounts[0]
        .control(ControlJob::Status, 11)
        .expect("unstarted request");
    workers.stop_all();
    assert_eq!(
        workers.accounts[0]
            .interrupted_controls
            .iter()
            .map(|entry| entry.phase)
            .collect::<Vec<_>>(),
        vec![
            InterruptedPhase::DurableReceiptObserved,
            InterruptedPhase::NotStarted
        ]
    );
    drop(workers); // Native owner joins before the caller's installation lock can leave scope.
    assert_eq!(
        source.account_state(&account).expect("saved state").pending[0].status(),
        tersa_application::command::MailboxCommandStatus::Queued
    );
    assert!(
        InstallationLock::acquire_existing(&fixture.path).is_err(),
        "caller still holds installation lock after worker join"
    );
}
struct Links;
impl Remote for Links {
    fn fetch<'a>(&'a self, _: &'a AccountId, _: &'a MessageId) -> Pending<'a, Vec<u8>> {
        Box::pin(std::future::pending())
    }
    fn sync<'a>(&'a self, _: &'a AccountId) -> Pending<'a, ()> {
        Box::pin(std::future::pending())
    }
    fn control<'a>(
        &'a self,
        _: &'a AccountId,
        _: ControlJob,
        progress: &'a ProgressSink,
    ) -> Pending<'a, ControlResult> {
        Box::pin(async move {
            for _ in 0..10 {
                progress
                    .authorization("https://accounts.google.com/?state=synthetic\n\u{202e}state");
            }
            assert!(!progress.authorization(&"x".repeat(20 * 1024)));
            Ok(ControlResult::Catalog(None))
        })
    }
}
#[test]
fn authorization_events_are_bounded_sanitized_and_keep_the_captured_binding() {
    let account = AccountId::new("link-account").expect("account");
    let mut worker = Worker::start(account.clone(), Box::new(Links)).expect("worker");
    let binding = worker.control(ControlJob::Upgrade, 42).expect("request");
    let mut links = 0;
    loop {
        let Done::Control(event) = worker.done.recv_timeout(WAIT).expect("event") else {
            panic!("control")
        };
        assert_eq!(event.binding().account, account);
        assert_eq!(event.binding().request, binding.request);
        assert_eq!(event.binding().epoch, 42);
        assert!(worker.finish_control(&event));
        match event {
            ControlEvent::Progress(_, Progress::AuthorizationLink(link)) => {
                links += 1;
                assert!(!link.as_str().contains('\n') && !link.as_str().contains('\u{202e}'));
            }
            ControlEvent::Finished(_, _) => break,
            ControlEvent::Progress(..) => panic!("unexpected progress"),
        }
    }
    assert_eq!(links, 2);
    assert!(
        worker.control(ControlJob::Reconnect, 43).is_some(),
        "consuming final event releases its bounded slot"
    );
}

#[test]
fn late_real_control_receipts_update_owner_state_without_retargeting_the_new_view() {
    let fixture = Fixture::new();
    let (source, mut workers) = components(&fixture);
    let a = fixture.accounts[0].clone();
    let b = fixture.accounts[1].clone();
    let executor = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("executor");
    for account in [&a, &b] {
        executor
            .block_on(
                fixture
                    .installation
                    .open_store(account)
                    .expect("store")
                    .upsert_envelopes(account, &[message("same", 1)]),
            )
            .expect("headers");
    }
    let mut app = initial_app(&source).expect("app");
    let original_epoch = app.view_epoch;
    workers
        .accounts
        .iter_mut()
        .find(|worker| worker.account == a)
        .expect("A")
        .control(
            ControlJob::Admit {
                intent: intent(&a, "same"),
                resume: false,
            },
            original_epoch,
        )
        .expect("submit A");
    change_view(
        &mut app,
        &source,
        &mut workers,
        ViewScope::Account(b.clone()),
    )
    .expect("view B");
    app.status = Some("Current B dialog status".to_owned());
    let until = Instant::now() + WAIT;
    while !app.control_results.contains_key(&a)
        || !matches!(
            app.control_results.get(&a),
            Some(ControlEvent::Finished(..))
        )
    {
        assert!(Instant::now() < until, "A result consumed");
        finish_work(&mut workers, &mut app, &source, 1);
        std::thread::yield_now();
    }
    assert_eq!(app.scope, ViewScope::Account(b.clone()));
    assert!(app.rows.iter().all(|row| row.account == b));
    assert_eq!(app.status.as_deref(), Some("Current B dialog status"));
    assert_eq!(
        source
            .account_state(&a)
            .expect("owner status")
            .pending
            .len(),
        1
    );
    assert!(
        source
            .account_state(&b)
            .expect("peer status")
            .pending
            .is_empty()
    );
    assert_eq!(
        app.control_results
            .get(&a)
            .expect("bound result")
            .binding()
            .epoch,
        original_epoch
    );
}

fn marker_envelope(id: &str, unread: bool, at: i64) -> MessageEnvelope {
    MessageEnvelope::new(
        MessageId::new(id).expect("id"),
        ThreadId::new("thread").expect("thread"),
        HeaderText::new("sender").expect("sender"),
        HeaderText::new(id).expect("subject"),
        HeaderText::new("preview").expect("preview"),
        UnixTimestampMillis::new(at).expect("time"),
        unread,
    )
}
fn seed_marker_observations(fixture: &Fixture, workers: &mut Workers) {
    let account = &fixture.accounts[0];
    let store = fixture
        .installation
        .open_store(account)
        .expect("Modify store");
    let executor = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("executor");
    executor
        .block_on(store.upsert_envelopes(
            account,
            &[
                marker_envelope("marker-unknown", true, 6),
                marker_envelope("marker-read", true, 5),
                marker_envelope("marker-unread", false, 4),
                marker_envelope("marker-missing", true, 3),
            ],
        ))
        .expect("local cached headers");
    // The missing observation must remain retained after its envelope is removed.
    let worker = workers
        .accounts
        .iter_mut()
        .find(|worker| &worker.account == account)
        .expect("worker");
    worker
        .control(
            ControlJob::Admit {
                intent: intent(account, "marker-missing"),
                resume: false,
            },
            0,
        )
        .expect("pin missing target");
    final_event(worker);
    let identity = executor
        .block_on(store.load_identity(account))
        .expect("identity")
        .expect("known");
    let fence = AccountFence::new(account.clone(), identity);
    let metadata = [("marker-read", false, 5), ("marker-unread", true, 4)]
        .into_iter()
        .map(|(id, unread, at)| {
            MessageMetadata::new(
                TypedKey::new(account.clone(), MessageId::new(id).expect("id")),
                marker_envelope(id, unread, at),
                LabelMembership::new(
                    account.clone(),
                    if unread {
                        vec![LabelId::new("UNREAD").expect("label")]
                    } else {
                        Vec::new()
                    },
                )
                .expect("membership"),
            )
            .expect("metadata")
        })
        .collect();
    let snapshot = SnapshotCommit::new(
        executor
            .block_on(store.checkpoint(&fence))
            .expect("checkpoint"),
        CapturedBaseline::new(account.clone(), HistoryCursor::new("1").expect("cursor")),
        metadata,
        SnapshotCoverage::RecentChainEnded,
        SnapshotFallbackReason::NoCursor,
    )
    .expect("observed snapshot");
    executor
        .block_on(store.commit_snapshot(&snapshot))
        .expect("observed state saved");
    seed_missing_marker(&store, &executor, fence);
}

fn seed_missing_marker(
    store: &tersa_store_sqlcipher::SqlCipherMailboxStore,
    executor: &tokio::runtime::Runtime,
    fence: AccountFence,
) {
    use tersa_application::{
        history::{
            DecidedHistoryRecord, HistoryDecision, HistoryEvent, HistoryEventKind, HistoryPage,
            HistoryQuery, HistoryRecord, ProviderContinuation,
        },
        mailbox::PageSize,
        mailbox_state::{MessageObservation, RemoteMessageState},
    };
    let owner = fence.account_id().clone();
    let account = &owner;
    let key = TypedKey::new(
        account.clone(),
        MessageId::new("marker-missing").expect("id"),
    );
    let record = HistoryRecord::new(
        account.clone(),
        HistoryCursor::new("2").expect("cursor"),
        vec![HistoryEvent::new(key.clone(), HistoryEventKind::Deleted).expect("event")],
        1,
    )
    .expect("record");
    let page = HistoryPage::new(
        HistoryQuery::new(
            account.clone(),
            HistoryCursor::new("1").expect("cursor"),
            PageSize::new(25).expect("size"),
        ),
        HistoryCursor::new("2").expect("cursor"),
        vec![record],
        ProviderContinuation::End,
        None,
        1,
    )
    .expect("page");
    let decision = DecidedHistoryRecord::new(
        fence,
        &page,
        0,
        vec![HistoryDecision::Observe(
            MessageObservation::new(key, RemoteMessageState::Missing).expect("missing"),
        )],
    )
    .expect("decided record");
    executor
        .block_on(store.apply_record(&decision))
        .expect("retained exact-key Missing observation");
    // A compatibility header update can coexist with retained Missing evidence;
    // it must not reinterpret that observation as either read or unread.
    executor
        .block_on(store.upsert_envelopes(account, &[marker_envelope("marker-missing", true, 3)]))
        .expect("cached compatibility header");
}

#[test]
fn real_cached_source_draws_unknown_and_missing_without_inventing_modify_read_state() {
    let fixture = Fixture::new();
    let executor = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("executor");
    let legacy = fixture
        .installation
        .open_store(&fixture.accounts[1])
        .expect("ReadOnly store");
    let expected = legacy
        .load_credential_snapshot(&fixture.accounts[1])
        .expect("grant");
    legacy
        .replace_credential_snapshot(
            &expected,
            tersa_application::AccountCapability::ReadOnly,
            &tersa_store_sqlcipher::StoreCredential::Active(zeroize::Zeroizing::new(
                "synthetic-readonly".to_owned(),
            )),
        )
        .expect("ReadOnly fixture");
    executor
        .block_on(legacy.upsert_envelopes(
            &fixture.accounts[1],
            &[
                marker_envelope("marker-local-unread", true, 2),
                marker_envelope("marker-local-read", false, 1),
            ],
        ))
        .expect("legacy local flags");
    let (source, mut workers) = components(&fixture);
    seed_marker_observations(&fixture, &mut workers);
    let mut app = initial_app(&source).expect("actual runtime source to App");
    let mut terminal =
        ratatui::Terminal::new(ratatui::backend::TestBackend::new(120, 16)).expect("terminal");
    terminal
        .draw(|frame| view::draw(frame, &mut app, 1_761_000_000_000))
        .expect("current list rendering");
    let buffer = terminal.backend().buffer();
    // Known provider flags and ReadOnly's local flags are independent controls.
    // The unknown row is locally unread, but must display neither known glyph.
    for (subject, marker) in [
        ("marker-local-unread", "●"),
        ("marker-local-read", " "),
        ("marker-unread", "●"),
        ("marker-read", " "),
        ("marker-unknown", "?"),
        ("marker-missing", "×"),
    ] {
        let y = (0..16)
            .find(|&y| {
                (0..120)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
                    .contains(subject)
            })
            .expect("case rendered in current list");
        assert_eq!(
            buffer[(0, y)].symbol(),
            marker,
            "read marker for {subject} must reflect its actual legacy/observed/unknown/missing fact"
        );
    }
}
