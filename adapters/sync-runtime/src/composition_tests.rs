// This Source Code Form is subject to the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Runtime transition evidence over real `SQLCipher` and controlled provider ports.

use super::*;
use crate::mailbox_ports::{AccountMailbox, MailboxFactory};
use crate::{CachedMailboxFilter, CachedViewScope, CommandIntent, CompositionError};
use std::collections::BTreeMap;
use std::pin::pin;
use std::sync::atomic::AtomicBool;
use std::task::{Context, Poll, Waker};
use tersa_application::{
    command::{
        AbandonConfirmation, CommandAdmissionOutcome, CommandDispatchError, CommandKey,
        CommandLabelReader, DispatchFact, DispatchReceipt, DuplicateRiskConfirmation,
        MailboxCommandId, MailboxCommandStatus, MessageAction, MessageTargets,
        RemoteCommandOutcome, RemoteMailboxCommands, UserLabelObservation, WriteAcknowledgement,
    },
    command_coordinator::{CommandDriveStop, CommandWritePolicy},
    history::{
        CapturedBaseline, GmailHistoryFeed, HistoryCursor, HistoryEvent, HistoryEventKind,
        HistoryFeedError, HistoryPage, HistoryQuery, HistoryRecord, ProviderContinuation,
        SnapshotPage,
    },
    history_sync::HistorySyncStop,
    identity::{AccountIdentityHasher, normalize_subject},
    mailbox::{
        AccountEmail, HeaderText, MailboxReader, MailboxStore, Message, MessageContent,
        MessageEnvelope, Page, PageToken, ThreadId, UnixTimestampMillis,
    },
    mailbox_state::{
        LabelCatalog, LabelDefinition, LabelId, LabelKind, LabelMembership, LabelName, MessageKey,
        MessageMetadata, MessageObservation, MetadataObservation, MetadataReadError,
        RemoteMessageState, UserLabel,
    },
};

#[derive(Clone)]
struct Row {
    envelope: MessageEnvelope,
    labels: Vec<LabelId>,
}
#[derive(Default)]
struct Provider {
    rows: Mutex<BTreeMap<String, Row>>,
    snapshot: Mutex<Vec<String>>,
    history: Mutex<VecDeque<(HistoryCursor, Vec<HistoryRecord>)>>,
    facts: Mutex<VecDeque<DispatchFact>>,
    fetched: Mutex<Vec<String>>,
    catalog: Mutex<Vec<LabelDefinition>>,
    fail_history: AtomicBool,
    fail_catalog: AtomicBool,
    fail_body: AtomicBool,
    fetch_wait: Mutex<Option<Arc<tokio::sync::Notify>>>,
    dispatch_wait: Mutex<Option<Arc<tokio::sync::Notify>>>,
    evidence_wait: Mutex<Option<Arc<tokio::sync::Notify>>>,
    dispatches: AtomicUsize,
    writers: AtomicUsize,
}
impl std::fmt::Debug for Provider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ControlledProvider")
    }
}
fn envelope(id: &str, at: i64, unread: bool) -> MessageEnvelope {
    MessageEnvelope::new(
        MessageId::new(id).expect("id"),
        ThreadId::new("thread").expect("thread"),
        HeaderText::new("sender").expect("sender"),
        HeaderText::new("subject").expect("subject"),
        HeaderText::new("preview").expect("preview"),
        UnixTimestampMillis::new(at).expect("time"),
        unread,
    )
}
impl Provider {
    fn select_snapshot(&self, ids: &[&str]) {
        *self.snapshot.lock().expect("snapshot") = ids.iter().map(|id| (*id).to_owned()).collect();
    }
    fn row(&self, id: &str, at: i64, labels: &[&str]) {
        self.rows.lock().expect("rows").insert(
            id.to_owned(),
            Row {
                envelope: envelope(id, at, false),
                labels: labels
                    .iter()
                    .map(|s| LabelId::new(*s).expect("label"))
                    .collect(),
            },
        );
    }
    fn metadata(&self, account: &AccountId, id: &str) -> Option<MessageMetadata> {
        self.rows.lock().expect("rows").get(id).map(|row| {
            MessageMetadata::new(
                MessageKey::new(account.clone(), MessageId::new(id).expect("id")),
                row.envelope.clone(),
                LabelMembership::new(account.clone(), row.labels.clone()).expect("labels"),
            )
            .expect("metadata")
        })
    }
}
#[derive(Debug)]
struct Factory(Arc<Provider>);
struct Reads {
    account: AccountId,
    provider: Arc<Provider>,
}
struct Writes {
    reads: Reads,
    dispatched: AtomicBool,
}
impl MailboxFactory for Factory {
    fn read(
        &self,
        account: AccountId,
        _token: &Zeroizing<String>,
    ) -> Result<Arc<dyn AccountMailbox>, RemoteMailboxError> {
        Ok(Arc::new(Reads {
            account,
            provider: Arc::clone(&self.0),
        }))
    }
    fn writer(
        &self,
        account: AccountId,
        _token: &Zeroizing<String>,
        capability: AccountCapability,
        scope: tersa_application::scope::AcceptedScope,
    ) -> Result<Box<dyn RemoteMailboxCommands>, CommandDispatchError> {
        assert_eq!(capability, AccountCapability::Modify);
        assert_eq!(scope.capability(), AccountCapability::Modify);
        self.0.writers.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(Writes {
            reads: Reads {
                account,
                provider: Arc::clone(&self.0),
            },
            dispatched: AtomicBool::new(false),
        }))
    }
}
impl RemoteMailbox for Reads {
    fn list_recent_envelopes<'a>(
        &'a self,
        _account: &'a AccountId,
        _size: PageSize,
        _page: Option<&'a PageToken>,
    ) -> BoxFuture<'a, Result<Page<MessageEnvelope>, RemoteMailboxError>> {
        Box::pin(async { panic!("History must not use the legacy snapshot coordinator") })
    }
    fn fetch_message<'a>(
        &'a self,
        account: &'a AccountId,
        id: &'a MessageId,
    ) -> BoxFuture<'a, Result<Message, RemoteMailboxError>> {
        Box::pin(async move {
            assert_eq!(account, &self.account);
            self.provider
                .fetched
                .lock()
                .expect("fetches")
                .push(id.as_str().to_owned());
            let wait = self.provider.fetch_wait.lock().expect("fetch gate").clone();
            if let Some(wait) = wait {
                wait.notified().await;
            }
            if self.provider.fail_body.load(Ordering::SeqCst) {
                return Err(RemoteMailboxError::Transport);
            }
            let row = self
                .provider
                .rows
                .lock()
                .expect("rows")
                .get(id.as_str())
                .cloned()
                .expect("requested existing body");
            Ok(Message::new(
                row.envelope,
                MessageContent::new(b"Subject: synthetic\r\n\r\nbody".to_vec()).expect("body"),
            ))
        })
    }
}
impl SessionEmailAddress for Reads {
    fn email_address(&self) -> BoxFuture<'_, Result<AccountEmail, RemoteMailboxError>> {
        Box::pin(async { Ok(AccountEmail::new("synthetic@example.test").expect("email")) })
    }
}
impl GmailHistoryFeed for Reads {
    fn history_page<'a>(
        &'a self,
        query: &'a HistoryQuery,
    ) -> BoxFuture<'a, Result<HistoryPage, HistoryFeedError>> {
        Box::pin(async move {
            assert_eq!(query.account_id(), &self.account);
            if self.provider.fail_history.load(Ordering::SeqCst) {
                return Err(HistoryFeedError::Read(MetadataReadError::Transport));
            }
            let (head, records) = self
                .provider
                .history
                .lock()
                .expect("history")
                .pop_front()
                .unwrap_or_else(|| (query.start().clone(), Vec::new()));
            let count = records.len();
            Ok(HistoryPage::new(
                query.clone(),
                head,
                records,
                ProviderContinuation::End,
                None,
                count,
            )
            .expect("provider page"))
        })
    }
    fn capture_baseline<'a>(
        &'a self,
        account: &'a AccountId,
    ) -> BoxFuture<'a, Result<CapturedBaseline, MetadataReadError>> {
        Box::pin(async move {
            assert_eq!(account, &self.account);
            Ok(CapturedBaseline::new(
                account.clone(),
                HistoryCursor::new("1").expect("cursor"),
            ))
        })
    }
    fn snapshot_page<'a>(
        &'a self,
        baseline: &'a CapturedBaseline,
        page: Option<&'a PageToken>,
    ) -> BoxFuture<'a, Result<SnapshotPage, MetadataReadError>> {
        Box::pin(async move {
            assert!(page.is_none());
            let ids = self.provider.snapshot.lock().expect("snapshot").clone();
            let metadata = ids
                .iter()
                .map(|id| {
                    self.provider
                        .metadata(&self.account, id)
                        .expect("snapshot metadata")
                })
                .collect();
            Ok(
                SnapshotPage::new(baseline.clone(), metadata, ProviderContinuation::End)
                    .expect("snapshot"),
            )
        })
    }
    fn observe_message<'a>(
        &'a self,
        key: &'a MessageKey,
    ) -> BoxFuture<'a, Result<MessageObservation, MetadataReadError>> {
        Box::pin(async move {
            assert_eq!(key.account_id(), &self.account);
            let wait = self
                .provider
                .evidence_wait
                .lock()
                .expect("evidence gate")
                .clone();
            if let Some(wait) = wait {
                wait.notified().await;
            }
            Ok(self
                .provider
                .metadata(&self.account, key.message_id().as_str())
                .map_or_else(
                    || {
                        MessageObservation::new(key.clone(), RemoteMessageState::Missing)
                            .expect("missing")
                    },
                    |value| value.observation().clone(),
                ))
        })
    }
    fn message_metadata<'a>(
        &'a self,
        key: &'a MessageKey,
    ) -> BoxFuture<'a, Result<MetadataObservation, MetadataReadError>> {
        Box::pin(async move {
            assert_eq!(key.account_id(), &self.account);
            Ok(self
                .provider
                .metadata(&self.account, key.message_id().as_str())
                .map_or_else(
                    || MetadataObservation::Missing(key.clone()),
                    MetadataObservation::Known,
                ))
        })
    }
}
impl CommandLabelReader for Reads {
    fn read_label_catalog<'a>(
        &'a self,
        account: &'a AccountId,
    ) -> BoxFuture<'a, Result<LabelCatalog, MetadataReadError>> {
        Box::pin(async move {
            assert_eq!(account, &self.account);
            if self.provider.fail_catalog.load(Ordering::SeqCst) {
                return Err(MetadataReadError::Transport);
            }
            Ok(LabelCatalog::new(
                account.clone(),
                self.provider.catalog.lock().expect("catalog").clone(),
            )
            .expect("catalog"))
        })
    }
    fn read_user_label<'a>(
        &'a self,
        target: &'a UserLabel,
    ) -> BoxFuture<'a, Result<UserLabelObservation, MetadataReadError>> {
        Box::pin(async move {
            assert_eq!(target.account_id(), &self.account);
            let definition = self
                .provider
                .catalog
                .lock()
                .expect("catalog")
                .iter()
                .find(|definition| definition.id() == target.id())
                .cloned();
            Ok(UserLabelObservation::new(target.clone(), definition).expect("label observation"))
        })
    }
}
impl RemoteMailboxCommands for Writes {
    fn dispatch<'a>(
        &'a self,
        receipt: &'a DispatchReceipt,
    ) -> BoxFuture<'a, Result<RemoteCommandOutcome, CommandDispatchError>> {
        Box::pin(async move {
            assert_eq!(
                receipt.snapshot().command().account_id(),
                &self.reads.account
            );
            assert!(
                !self.dispatched.swap(true, Ordering::SeqCst),
                "one-shot writer reused"
            );
            self.reads
                .provider
                .dispatches
                .fetch_add(1, Ordering::SeqCst);
            let wait = self
                .reads
                .provider
                .dispatch_wait
                .lock()
                .expect("dispatch gate")
                .clone();
            if let Some(wait) = wait {
                wait.notified().await;
            }
            let fact = self
                .reads
                .provider
                .facts
                .lock()
                .expect("outcome")
                .pop_front()
                .unwrap_or(DispatchFact::Acknowledged(
                    WriteAcknowledgement::MessageBatchAccepted,
                ));
            Ok(RemoteCommandOutcome::new(receipt, fact).expect("transport fact"))
        })
    }
    fn label_catalog<'a>(
        &'a self,
        account: &'a AccountId,
    ) -> BoxFuture<'a, Result<LabelCatalog, MetadataReadError>> {
        self.reads.read_label_catalog(account)
    }
    fn observe_user_label<'a>(
        &'a self,
        label: &'a UserLabel,
    ) -> BoxFuture<'a, Result<UserLabelObservation, MetadataReadError>> {
        self.reads.read_user_label(label)
    }
}
async fn command_state(runtime: &Runtime, account: &AccountId) -> crate::AccountCommandStatus {
    runtime.command_status(account).await.expect("status")
}
async fn cached(f: &Fixture, filter: &CachedMailboxFilter) -> crate::CachedViewPage {
    f.runtime
        .cached_view(&CachedViewScope::All, filter, 200, None)
        .await
        .expect("cached view")
}
fn restart(f: &mut Fixture, provider: &Arc<Provider>) {
    let installation = Arc::clone(&f.runtime.installation);
    let old = std::mem::replace(&mut f.runtime, Runtime::local(installation));
    drop(old);
    f.runtime.online = Some(Online::new(
        OAuthClient {
            client_id: CLIENT.to_owned(),
            client_secret: None,
        },
        Port(Arc::clone(&f.port)),
    ));
    f.runtime.mailboxes = Arc::new(Factory(Arc::clone(provider)));
}
fn history_event(
    provider: &Provider,
    account: &AccountId,
    id: &str,
    cursor: &str,
    kind: HistoryEventKind,
) {
    let record = HistoryRecord::new(
        account.clone(),
        HistoryCursor::new(cursor).expect("cursor"),
        vec![
            HistoryEvent::new(
                MessageKey::new(account.clone(), MessageId::new(id).expect("id")),
                kind,
            )
            .expect("event"),
        ],
        1,
    )
    .expect("record");
    provider
        .history
        .lock()
        .expect("history")
        .push_back((HistoryCursor::new(cursor).expect("cursor"), vec![record]));
}

fn fixture(capability: AccountCapability) -> (Fixture, Arc<Provider>) {
    let mut f = Fixture::new(
        capability,
        vec![
            Ok(response(SUBJECT, ScopeEvidence::Absent, None)),
            Ok(response(SUBJECT, ScopeEvidence::Absent, None)),
        ],
    );
    let provider = Arc::new(Provider::default());
    f.runtime.mailboxes = Arc::new(Factory(Arc::clone(&provider)));
    (f, provider)
}
async fn record_identity(f: &Fixture) -> tersa_application::profile::AccountFence {
    let account_subject = AccountSubject::from_broker_validated(secret(SUBJECT)).expect("subject");
    let identity = crate::InstallationHasher(Arc::clone(&f.runtime.installation))
        .hash(&f.account, &normalize_subject(&account_subject))
        .expect("hash");
    let store = f
        .runtime
        .installation
        .open_store(&f.account)
        .expect("store");
    store
        .reconcile_identity(&f.account, &identity, IdentityReconcile::RecordOnly, None)
        .await
        .expect("record identity");
    store
        .record_successful_sync(&f.account, 123)
        .await
        .expect("prior successful sync");
    tersa_application::profile::AccountFence::new(f.account.clone(), identity)
}
fn targets(account: &AccountId, ids: &[&str]) -> MessageTargets {
    MessageTargets::new(
        account.clone(),
        ids.iter()
            .map(|id| MessageId::new(*id).expect("target"))
            .collect(),
    )
    .expect("targets")
}
fn admitted(outcome: CommandAdmissionOutcome) -> tersa_application::command::CommandSnapshot {
    match outcome {
        CommandAdmissionOutcome::Admitted(snapshot) => *snapshot,
        CommandAdmissionOutcome::Retained(_) => panic!("fresh admission"),
    }
}
fn intent(account: &AccountId, ids: &[&str], action: MessageAction) -> CommandIntent {
    CommandIntent::Messages {
        targets: targets(account, ids),
        action,
    }
}

#[test]
fn offline_local_controls_preserve_exact_account_and_work_after_token_loss() {
    drive(async {
        let (mut f, _) = fixture(AccountCapability::Modify);
        record_identity(&f).await;
        let store = f
            .runtime
            .installation
            .open_store(&f.account)
            .expect("store");
        store
            .delete_credential_snapshot(&f.snapshot())
            .expect("lose token");
        f.runtime.online = None;
        let saved = admitted(
            f.runtime
                .admit_command(
                    &f.account,
                    &intent(&f.account, &["m"], MessageAction::Trash),
                )
                .await
                .expect("offline admission"),
        );
        assert_eq!(command_state(&f.runtime, &f.account).await.pending.len(), 1);
        assert!(
            f.runtime
                .command_lookup(&f.account, &MailboxCommandId::new("unknown").expect("id"))
                .await
                .expect("lookup")
                .is_none()
        );
        let wrong = AccountId::new("wrong-account").expect("account");
        assert!(
            f.runtime
                .admit_command(&f.account, &intent(&wrong, &["m"], MessageAction::Trash))
                .await
                .is_err()
        );
        assert!(
            f.runtime
                .drive_commands(&f.account, Some(&CommandWritePolicy::Automatic))
                .await
                .is_err()
        );
        f.runtime
            .cancel_command(&f.account, saved.stamp())
            .await
            .expect("offline cancel");
        assert!(
            command_state(&f.runtime, &f.account)
                .await
                .pending
                .is_empty()
        );
        assert_eq!(f.port.refreshes.load(Ordering::SeqCst), 0);
        let (readonly, _) = fixture(AccountCapability::ReadOnly);
        record_identity(&readonly).await;
        assert!(matches!(
            readonly
                .runtime
                .admit_command(
                    &readonly.account,
                    &intent(&readonly.account, &["m"], MessageAction::Trash)
                )
                .await,
            Err(CompositionError::Intent(
                tersa_application::command::CommandError::ReadOnly
            ))
        ));
    });
}

#[test]
fn history_body_phase_uses_current_recent_rows_skips_cached_and_retains_metadata_on_error() {
    drive(async {
        let (f, provider) = fixture(AccountCapability::ReadOnly);
        for i in 0..25 {
            let id = format!("m{i:02}");
            provider.row(&id, i, &["INBOX"]);
            provider.snapshot.lock().expect("snapshot").push(id);
        }
        let store = f
            .runtime
            .installation
            .open_store(&f.account)
            .expect("store");
        store
            .put_message(
                &f.account,
                &Message::new(
                    envelope("unchanged", 100, false),
                    MessageContent::new(b"cached".to_vec()).expect("body"),
                ),
            )
            .await
            .expect("cached survivor");
        let report = f.runtime.sync_history(&f.account).await.expect("history");
        assert!(matches!(
            report.metadata.stop(),
            HistorySyncStop::SnapshotCommitted(_)
        ));
        assert_eq!(report.metadata.progress().snapshot_messages_committed, 25);
        assert_eq!(
            (
                report.bodies.selected,
                report.bodies.requests,
                report.bodies.cached
            ),
            (25, 24, 24)
        );
        assert!(report.bodies.failure.is_none());
        assert!(
            !provider
                .fetched
                .lock()
                .expect("fetches")
                .iter()
                .any(|id| id == "unchanged" || id == "m00")
        );
        provider.row("new", 200, &["INBOX", "UNREAD"]);
        provider.fail_body.store(true, Ordering::SeqCst);
        let record = HistoryRecord::new(
            f.account.clone(),
            HistoryCursor::new("2").expect("cursor"),
            vec![
                HistoryEvent::new(
                    MessageKey::new(f.account.clone(), MessageId::new("new").expect("id")),
                    HistoryEventKind::Added,
                )
                .expect("event"),
            ],
            1,
        )
        .expect("record");
        provider
            .history
            .lock()
            .expect("history")
            .push_back((HistoryCursor::new("2").expect("cursor"), vec![record]));
        let report = f
            .runtime
            .sync_history(&f.account)
            .await
            .expect("second history");
        assert_eq!(report.metadata.progress().records_committed, 1);
        assert_eq!(
            report
                .metadata
                .checkpoint()
                .expect("checkpoint")
                .cursor()
                .expect("cursor")
                .as_str(),
            "2"
        );
        assert!(report.bodies.failure.is_some());
        assert_eq!(report.bodies.cached, 0);
        assert!(
            store
                .get_message(&f.account, &MessageId::new("new").expect("id"))
                .await
                .expect("cached body")
                .is_none()
        );
    });
}

#[test]
fn cancelled_dispatch_survives_restart_and_readonly_observation_does_not_construct_writer() {
    drive(async {
        let (mut f, provider) = fixture(AccountCapability::Modify);
        record_identity(&f).await;
        provider.row("m", 1, &["INBOX", "UNREAD"]);
        let saved = admitted(
            f.runtime
                .admit_command(&f.account, &intent(&f.account, &["m"], MessageAction::Read))
                .await
                .expect("admit"),
        );
        let release = Arc::new(tokio::sync::Notify::new());
        *provider.dispatch_wait.lock().expect("gate") = Some(release);
        {
            let mut dispatch = pin!(
                f.runtime
                    .drive_commands(&f.account, Some(&CommandWritePolicy::Automatic))
            );
            assert!(matches!(
                dispatch
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop())),
                Poll::Pending
            ));
        }
        let status = command_state(&f.runtime, &f.account).await;
        assert_eq!(
            status.pending[0].status(),
            MailboxCommandStatus::Dispatching
        );
        assert_eq!(provider.dispatches.load(Ordering::SeqCst), 1);
        restart(&mut f, &provider);
        let restarted = &f.runtime;
        let observation = restarted
            .drive_commands(&f.account, None)
            .await
            .expect("readonly observation");
        assert_eq!(
            observation.command.stop(),
            CommandDriveStop::ObservationOnly
        );
        let recovered = observation.command.snapshot().expect("recovered command");
        assert_eq!(recovered.status(), MailboxCommandStatus::Ambiguous);
        assert_eq!(provider.writers.load(Ordering::SeqCst), 1);
        assert_eq!(recovered.command().id(), saved.command().id());
        restarted
            .authorize_command_retry(&f.account, recovered.stamp())
            .await
            .expect("explicit ticket");
        assert!(
            command_state(restarted, &f.account).await.pending[0]
                .retry_authorization()
                .is_some()
        );
        let automatic = restarted
            .drive_commands(&f.account, Some(&CommandWritePolicy::Automatic))
            .await
            .expect("background pass");
        assert!(!automatic.command.dispatch_invoked());
        assert!(
            command_state(restarted, &f.account).await.pending[0]
                .retry_authorization()
                .is_some()
        );
        *provider.dispatch_wait.lock().expect("gate") = None;
        let key = CommandKey::new(f.account.clone(), saved.command().id().clone());
        let retried = restarted
            .drive_commands(
                &f.account,
                Some(&CommandWritePolicy::ExplicitRetry {
                    key,
                    duplicate_risk: DuplicateRiskConfirmation::NotConfirmed,
                }),
            )
            .await
            .expect("one explicit retry");
        assert_eq!(
            retried.command.stop(),
            CommandDriveStop::AwaitingObservation
        );
        assert_eq!(provider.dispatches.load(Ordering::SeqCst), 2);

        restarted
            .abandon_command(
                &f.account,
                command_state(restarted, &f.account).await.pending[0].stamp(),
                AbandonConfirmation::ProviderMayAlreadyHaveApplied,
            )
            .await
            .expect("warned local abandon");
        assert_eq!(provider.dispatches.load(Ordering::SeqCst), 2);
    });
}

#[test]
fn one_pass_never_drains_queue_and_completed_command_reports_real_convergence_failure() {
    drive(async {
        let (f, provider) = fixture(AccountCapability::Modify);
        record_identity(&f).await;
        provider.row("m", 1, &["INBOX", "UNREAD"]);
        provider.select_snapshot(&["m"]);
        f.runtime
            .sync_history(&f.account)
            .await
            .expect("initial observed cache");
        let first = admitted(
            f.runtime
                .admit_command(&f.account, &intent(&f.account, &["m"], MessageAction::Read))
                .await
                .expect("first"),
        );
        f.runtime
            .admit_command(
                &f.account,
                &intent(&f.account, &["m"], MessageAction::Trash),
            )
            .await
            .expect("second");
        let sent = f
            .runtime
            .drive_commands(&f.account, Some(&CommandWritePolicy::Automatic))
            .await
            .expect("drive");
        assert_eq!(sent.command.stop(), CommandDriveStop::AwaitingObservation);
        assert_eq!(provider.dispatches.load(Ordering::SeqCst), 1);
        assert_eq!(command_state(&f.runtime, &f.account).await.pending.len(), 2);
        provider.row("m", 1, &["INBOX"]);
        provider.fail_catalog.store(true, Ordering::SeqCst);
        provider.fail_history.store(true, Ordering::SeqCst);
        let settled = f
            .runtime
            .drive_commands(&f.account, None)
            .await
            .expect("settle");
        assert_eq!(settled.command.stop(), CommandDriveStop::Terminal);
        assert_eq!(
            settled.command.snapshot().expect("terminal").command().id(),
            first.command().id()
        );
        assert_eq!(
            settled.command.snapshot().expect("terminal").status(),
            MailboxCommandStatus::Complete
        );
        let convergence = settled.convergence.expect("convergence attempted");
        assert!(convergence.catalog.is_err());
        assert!(matches!(
            convergence.history.expect("History report").metadata.stop(),
            HistorySyncStop::RecoveryRequired(_)
        ));
        let unchanged = cached(&f, &CachedMailboxFilter::Recent).await;
        assert_eq!(
            unchanged.rows[0].display_unread,
            Some(true),
            "terminal intent is not substituted for cached observations"
        );
        assert_eq!(provider.dispatches.load(Ordering::SeqCst), 1);
        assert_eq!(command_state(&f.runtime, &f.account).await.pending.len(), 1);
        f.runtime
            .admit_undo(&f.account)
            .await
            .expect_err("later pending command blocks undo admission");
        provider.fail_history.store(false, Ordering::SeqCst);
        provider.fail_catalog.store(false, Ordering::SeqCst);
        history_event(
            &provider,
            &f.account,
            "m",
            "2",
            HistoryEventKind::LabelsRemoved(vec![LabelId::new("UNREAD").expect("label")]),
        );
        f.runtime
            .sync_history(&f.account)
            .await
            .expect("actual History convergence");
        let converged = cached(&f, &CachedMailboxFilter::Recent).await;
        assert_eq!(converged.rows[0].display_unread, Some(false));
    });
}

#[test]
fn observed_filter_precedes_global_cap_and_all_user_label_does_not_read_peer() {
    drive(async {
        let (f, provider) = fixture(AccountCapability::Modify);
        record_identity(&f).await;
        let store = f
            .runtime
            .installation
            .open_store(&f.account)
            .expect("store");
        let envelopes: Vec<_> = (0..250)
            .map(|i| envelope(&format!("m{i:03}"), 300 - i, false))
            .collect();
        store
            .upsert_envelopes(&f.account, &envelopes)
            .await
            .expect("cached rows");
        let names: Vec<_> = envelopes.iter().map(|e| e.message_id().as_str()).collect();
        f.runtime
            .admit_command(
                &f.account,
                &intent(&f.account, &names, MessageAction::Archive),
            )
            .await
            .expect("retain pins without changing observed state");
        provider.row("m249", 51, &["INBOX", "UNREAD", "Label_exact"]);
        provider.select_snapshot(&["m249"]);
        provider.fail_body.store(true, Ordering::SeqCst);
        f.runtime
            .sync_history(&f.account)
            .await
            .expect("real snapshot metadata");
        let recent = cached(&f, &CachedMailboxFilter::Recent).await;
        assert_eq!(recent.rows.len(), 200);
        assert!(recent.continuation.is_some());
        assert!(
            !recent
                .rows
                .iter()
                .any(|row| row.envelope.message_id().as_str() == "m249")
        );
        let inbox = cached(&f, &CachedMailboxFilter::Inbox).await;
        assert_eq!(inbox.rows.len(), 1);
        assert_eq!(inbox.rows[0].display_unread, Some(true));
        assert!(
            !inbox.rows[0].envelope.is_unread(),
            "legacy sticky display is distinct"
        );
        assert_eq!(inbox.rows[0].pending.as_ref().expect("identity").len(), 1);
        let user = UserLabel::from_classified_id(
            f.account.clone(),
            LabelId::new("Label_exact").expect("id"),
        )
        .expect("User label");
        let peer = OperationGrants::new(Arc::clone(&f.runtime.installation))
            .connect_new(
                &ValidatedSubject::new("peer").expect("subject"),
                &secret("peer-token"),
                AccountCapability::ReadOnly,
            )
            .expect("peer");
        fs::remove_file(f.runtime.installation.cache_path_for_test(&peer))
            .expect("unreadable peer");
        let filtered = cached(&f, &CachedMailboxFilter::UserLabel(user)).await;
        assert_eq!(filtered.rows.len(), 1);
        assert!(filtered.unavailable_accounts.is_empty());
        assert!(
            f.runtime
                .cached_view(
                    &CachedViewScope::All,
                    &CachedMailboxFilter::Inbox,
                    200,
                    recent.continuation.as_ref()
                )
                .await
                .is_err()
        );
        let next = f
            .runtime
            .cached_view(
                &CachedViewScope::Account(f.account.clone()),
                &CachedMailboxFilter::Recent,
                200,
                None,
            )
            .await
            .expect("account page");
        let rest = f
            .runtime
            .cached_view(
                &CachedViewScope::Account(f.account.clone()),
                &CachedMailboxFilter::Recent,
                200,
                next.continuation.as_ref(),
            )
            .await
            .expect("continuation");
        assert_eq!(rest.rows.len(), 50);
    });
}

#[test]
fn body_completion_rechecks_identity_and_never_overwrites_a_new_identity_collision() {
    drive(async {
        let (f, provider) = fixture(AccountCapability::ReadOnly);
        let original = record_identity(&f).await;
        provider.row("m", 1, &["INBOX"]);
        provider.select_snapshot(&["m"]);
        let release = Arc::new(tokio::sync::Notify::new());
        *provider.fetch_wait.lock().expect("gate") = Some(Arc::clone(&release));
        let mut sync = pin!(f.runtime.sync_history(&f.account));
        assert!(matches!(
            sync.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        ));
        assert_eq!(provider.fetched.lock().expect("fetches").len(), 1);
        let store = f
            .runtime
            .installation
            .open_store(&f.account)
            .expect("store");
        store
            .reconcile_identity(
                &f.account,
                &IdentityHash::from_bytes([8; 32]),
                IdentityReconcile::ClearMailboxAndRecord,
                Some(original.identity()),
            )
            .await
            .expect("concurrent identity replacement");
        store
            .put_message(
                &f.account,
                &Message::new(
                    envelope("m", 100, false),
                    MessageContent::new(b"new identity body".to_vec()).expect("body"),
                ),
            )
            .await
            .expect("new identity collision");
        release.notify_one();
        let report = sync.await.expect("historical metadata progress retained");
        assert_eq!(report.metadata.progress().snapshot_messages_committed, 1);
        assert_eq!(report.bodies.cached, 0);
        assert!(matches!(
            report.bodies.failure,
            Some(CompositionError::IdentityChanged)
        ));
        assert_eq!(
            store
                .get_message(&f.account, &MessageId::new("m").expect("id"))
                .await
                .expect("read")
                .expect("new identity body")
                .into_content()
                .into_bytes(),
            b"new identity body"
        );
    });
}

#[test]
fn history_holds_the_account_permit_but_cached_reads_and_other_accounts_remain_available() {
    drive(async {
        let (mut f, provider) = fixture(AccountCapability::ReadOnly);
        record_identity(&f).await;
        provider.row("m", 1, &["INBOX"]);
        provider.select_snapshot(&["m"]);
        *provider.fetch_wait.lock().expect("gate") = Some(Arc::new(tokio::sync::Notify::new()));
        let other_subject = ValidatedSubject::new("independent").expect("subject");
        let other = OperationGrants::new(Arc::clone(&f.runtime.installation))
            .connect_new(&other_subject, &secret("other"), AccountCapability::Modify)
            .expect("account");
        let other_hash = crate::InstallationHasher(Arc::clone(&f.runtime.installation))
            .hash(
                &other,
                &normalize_subject(
                    &AccountSubject::from_broker_validated(secret("independent")).expect("subject"),
                ),
            )
            .expect("hash");
        f.runtime
            .installation
            .open_store(&other)
            .expect("store")
            .reconcile_identity(&other, &other_hash, IdentityReconcile::RecordOnly, None)
            .await
            .expect("identity");
        {
            let mut sync = pin!(f.runtime.sync_history(&f.account));
            let mut cx = Context::from_waker(Waker::noop());
            assert!(matches!(sync.as_mut().poll(&mut cx), Poll::Pending));
            let mut reset = pin!(f.runtime.reset_account_cache(&f.account));
            assert!(matches!(reset.as_mut().poll(&mut cx), Poll::Pending));
            let page = f
                .runtime
                .cached_view(
                    &CachedViewScope::Account(f.account.clone()),
                    &CachedMailboxFilter::Recent,
                    200,
                    None,
                )
                .await
                .expect("concurrent cached read");
            assert_eq!(page.rows.len(), 1);
            f.runtime
                .admit_command(
                    &other,
                    &intent(&other, &["other-message"], MessageAction::Read),
                )
                .await
                .expect("independent account admission");
        } // Dropping the body future releases its permit without a detached fetch/cache.
        f.runtime.online = None;
        assert!(matches!(
            f.runtime
                .reset_account_cache(&f.account)
                .await
                .expect("clear committed"),
            CacheResetOutcome::ResyncFailed(_)
        ));
        assert!(
            f.runtime
                .cached_view(
                    &CachedViewScope::Account(f.account.clone()),
                    &CachedMailboxFilter::Recent,
                    200,
                    None
                )
                .await
                .expect("reset view")
                .rows
                .is_empty()
        );
    });
}

#[test]
fn a_generation_change_during_reconciliation_denies_before_transport_and_preserves_dispatching() {
    drive(async {
        let (f, provider) = fixture(AccountCapability::Modify);
        record_identity(&f).await;
        provider.row("m", 1, &["INBOX", "UNREAD"]);
        f.runtime
            .admit_command(&f.account, &intent(&f.account, &["m"], MessageAction::Read))
            .await
            .expect("admit");
        let release = Arc::new(tokio::sync::Notify::new());
        *provider.evidence_wait.lock().expect("gate") = Some(Arc::clone(&release));
        let mut command = pin!(
            f.runtime
                .drive_commands(&f.account, Some(&CommandWritePolicy::Automatic))
        );
        assert!(matches!(
            command
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        ));
        f.runtime
            .invalidate(&f.account)
            .expect("new session generation");
        release.notify_one();
        let result = command.await.expect("coordinator report");
        assert!(
            matches!(result.command.stop(), CommandDriveStop::RecoveryRequired(failure) if matches!(failure.error, tersa_application::command_coordinator::CommandCoordinatorError::DispatchDenied(CommandDispatchError::AuthorizationRequired)))
        );
        assert_eq!(provider.dispatches.load(Ordering::SeqCst), 0);
        assert_eq!(
            f.runtime
                .command_status(&f.account)
                .await
                .expect("durable state")
                .pending[0]
                .status(),
            MailboxCommandStatus::Dispatching
        );
    });
}

#[test]
fn readonly_observation_settles_label_work_without_constructing_modify_transport() {
    drive(async {
        let (f, provider) = fixture(AccountCapability::Modify);
        record_identity(&f).await;
        let definition = LabelDefinition::new(
            f.account.clone(),
            LabelId::new("Label_1").expect("id"),
            LabelName::new("label").expect("name"),
            LabelKind::User,
        )
        .expect("definition");
        f.runtime
            .admit_command(
                &f.account,
                &CommandIntent::DeleteLabel(definition.user_label().expect("user")),
            )
            .await
            .expect("admit");
        let store = f
            .runtime
            .installation
            .open_store(&f.account)
            .expect("store");
        store
            .replace_credential_snapshot(
                &f.snapshot(),
                AccountCapability::ReadOnly,
                &StoreCredential::Active(secret("readonly-grant")),
            )
            .expect("stored readonly context");
        let denied = f
            .runtime
            .drive_commands(&f.account, Some(&CommandWritePolicy::Automatic))
            .await;
        assert!(matches!(denied, Err(CompositionError::Authority)));
        let settled = f
            .runtime
            .drive_commands(&f.account, None)
            .await
            .expect("readonly exact-ID observation");
        assert_eq!(settled.command.stop(), CommandDriveStop::Terminal);
        assert_eq!(
            settled.command.snapshot().expect("terminal").status(),
            MailboxCommandStatus::Complete
        );
        assert_eq!(provider.writers.load(Ordering::SeqCst), 0);
        assert_eq!(provider.dispatches.load(Ordering::SeqCst), 0);
    });
}

#[test]
fn offline_conditional_undo_is_admitted_without_token_but_post_state_mismatch_never_dispatches() {
    drive(async {
        let (f, provider) = fixture(AccountCapability::Modify);
        record_identity(&f).await;
        provider.row("m", 1, &["INBOX", "UNREAD"]);
        f.runtime
            .admit_command(&f.account, &intent(&f.account, &["m"], MessageAction::Read))
            .await
            .expect("admit");
        f.runtime
            .drive_commands(&f.account, Some(&CommandWritePolicy::Automatic))
            .await
            .expect("first dispatch");
        provider.row("m", 1, &["INBOX"]);
        let complete = f
            .runtime
            .drive_commands(&f.account, None)
            .await
            .expect("confirm complete");
        assert_eq!(
            complete.command.snapshot().expect("snapshot").status(),
            MailboxCommandStatus::Complete
        );
        let store = f
            .runtime
            .installation
            .open_store(&f.account)
            .expect("store");
        store
            .delete_credential_snapshot(&f.snapshot())
            .expect("token lost");
        let undo = admitted(
            f.runtime
                .admit_undo(&f.account)
                .await
                .expect("offline conditional undo"),
        );
        assert_eq!(undo.status(), MailboxCommandStatus::Queued);
        assert_eq!(provider.dispatches.load(Ordering::SeqCst), 1);
        let bridge = OperationGrants::new(Arc::clone(&f.runtime.installation));
        let expected = bridge
            .load_grant(&subject())
            .expect("grant")
            .expect("known");
        bridge
            .replace_existing(&expected, &secret("reconnected"), AccountCapability::Modify)
            .expect("selected reconnect fixture");
        f.runtime
            .invalidate(&f.account)
            .expect("new grant generation");
        provider.row("m", 1, &["INBOX", "UNREAD"]); // Changed since the original confirmed post-state.
        let refused = f
            .runtime
            .drive_commands(&f.account, Some(&CommandWritePolicy::Automatic))
            .await
            .expect("guarded undo report");
        assert!(!refused.command.dispatch_invoked());
        assert_eq!(provider.dispatches.load(Ordering::SeqCst), 1);
    });
}
