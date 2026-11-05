// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

mod p5c {
    use super::*;
    use tersa_application::{
        command::{
            AbandonConfirmation, CommandAdmission, CommandAdmissionOutcome, CommandEvidence,
            CommandKey, CommandPrecondition, CommandReconciliation, CommandSnapshot,
            DispatchAuthorization, DispatchFact, DispatchPreparation, DispatchReceipt,
            DuplicateRiskConfirmation, MailboxCommandStore, ReconciliationFailure,
            RemoteCommandOutcome, RetainedCommand, UndoAdmission, UserLabelObservation,
            WriteAcknowledgement,
        },
        mailbox_state::{
            MessageKey, MessageObservation, MessageObservations, RemoteMessageState,
            TriageStoreError as Error,
        },
        profile::AccountFence,
    };
    use tersa_domain::{
        account::AccountCapability,
        command::{
            MailboxCommand, MailboxCommandId, MailboxCommandStatus as Status, MessageAction,
            MessageTargets,
        },
        label::{LabelCatalog, LabelDefinition, LabelId, LabelKind, LabelMembership, LabelName},
    };
    fn bound() -> AccountFence {
        AccountFence::new(account(), fence())
    }
    fn setup(name: &str) -> (TestDatabase, SqlCipherMailboxStore) {
        let (db, store) = open(name);
        record_fence(&store);
        store.update_recovery(None).unwrap();
        store.connection.lock().unwrap().execute("UPDATE account_binding SET broker_subject='subject',refresh_token='synthetic-token',credential_purpose=1,capability=1",[]).unwrap();
        (db, store)
    }
    fn id(value: &str) -> MailboxCommandId {
        MailboxCommandId::new(value).unwrap()
    }
    fn targets(ids: &[&str]) -> MessageTargets {
        MessageTargets::new(
            account(),
            ids.iter().map(|s| MessageId::new(*s).unwrap()).collect(),
        )
        .unwrap()
    }
    fn intent(value: &str, ids: &[&str], action: &MessageAction) -> MailboxCommand {
        MailboxCommand::message_state(AccountCapability::Modify, id(value), targets(ids), action)
            .unwrap()
    }
    fn create(value: &str) -> MailboxCommand {
        MailboxCommand::create_label(
            AccountCapability::Modify,
            id(value),
            account(),
            LabelName::new("exact\0name").unwrap(),
        )
        .unwrap()
    }
    fn admit(store: &SqlCipherMailboxStore, command: MailboxCommand) -> CommandSnapshot {
        match run(MailboxCommandStore::admit(
            store,
            &CommandAdmission::new(bound(), command).unwrap(),
        ))
        .unwrap()
        {
            CommandAdmissionOutcome::Admitted(s) => *s,
            CommandAdmissionOutcome::Retained(_) => panic!("expected new durable admission"),
        }
    }
    fn pre(snapshot: &CommandSnapshot) -> CommandPrecondition {
        CommandPrecondition::new(bound(), snapshot.stamp().clone()).unwrap()
    }
    fn evidence(
        snapshot: &CommandSnapshot,
        states: &[(&str, Option<&[&str]>)],
    ) -> CommandReconciliation {
        let ids: Vec<_> = states.iter().map(|(id, _)| *id).collect();
        let observations = states
            .iter()
            .map(|(id, labels)| {
                MessageObservation::new(
                    MessageKey::new(account(), MessageId::new(*id).unwrap()),
                    labels.map_or(RemoteMessageState::Missing, |labels| {
                        RemoteMessageState::Known(
                            LabelMembership::new(
                                account(),
                                labels.iter().map(|s| LabelId::new(*s).unwrap()).collect(),
                            )
                            .unwrap(),
                        )
                    }),
                )
                .unwrap()
            })
            .collect();
        CommandReconciliation::new(
            snapshot.clone(),
            CommandEvidence::Messages {
                observations: MessageObservations::new(targets(&ids), observations).unwrap(),
                user_label: None,
            },
        )
        .unwrap()
    }
    fn catalog(snapshot: &CommandSnapshot, ids: &[&str]) -> CommandReconciliation {
        CommandReconciliation::new(
            snapshot.clone(),
            CommandEvidence::CreateCatalog(
                LabelCatalog::new(
                    account(),
                    ids.iter()
                        .map(|id| {
                            LabelDefinition::new(
                                account(),
                                LabelId::new(*id).unwrap(),
                                LabelName::new("exact\0name").unwrap(),
                                LabelKind::User,
                            )
                            .unwrap()
                        })
                        .collect(),
                )
                .unwrap(),
            ),
        )
        .unwrap()
    }
    fn prepare(
        store: &SqlCipherMailboxStore,
        rec: CommandReconciliation,
        ids: Option<&[&str]>,
        authorization: DispatchAuthorization,
        risk: DuplicateRiskConfirmation,
    ) -> Result<DispatchReceipt, Error> {
        run(store.prepare_dispatch(
            &DispatchPreparation::new(
                pre(rec.snapshot()),
                rec,
                ids.map(targets),
                authorization,
                risk,
            )
            .unwrap(),
        ))
    }
    fn settle(store: &SqlCipherMailboxStore, rec: &CommandReconciliation) -> CommandSnapshot {
        run(MailboxCommandStore::reconcile(
            store,
            &pre(rec.snapshot()),
            rec,
        ))
        .unwrap()
    }
    fn lookup(store: &SqlCipherMailboxStore, name: &str) -> Option<RetainedCommand> {
        run(store.lookup(&bound(), &CommandKey::new(account(), id(name)))).unwrap()
    }
    fn full(store: &SqlCipherMailboxStore, name: &str) -> CommandSnapshot {
        match lookup(store, name).unwrap() {
            RetainedCommand::Full(s) => *s,
            RetainedCommand::Terminal(_) => panic!("expected retained full body"),
        }
    }
    fn count(store: &SqlCipherMailboxStore, table: &str) -> i64 {
        store
            .connection
            .lock()
            .unwrap()
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .unwrap()
    }
    fn lose_access(store: &SqlCipherMailboxStore) {
        store
            .connection
            .lock()
            .unwrap()
            .execute(
                "UPDATE account_binding SET refresh_token=NULL,credential_purpose=0,capability=0",
                [],
            )
            .unwrap();
    }
    fn fault(store: &SqlCipherMailboxStore, after: &str) {
        store.connection.lock().unwrap().execute_batch(&format!("CREATE TEMP TABLE fault_parent(id INTEGER PRIMARY KEY); CREATE TEMP TABLE fault_child(id INTEGER REFERENCES fault_parent(id) DEFERRABLE INITIALLY DEFERRED); CREATE TEMP TRIGGER command_fault AFTER {after} BEGIN INSERT INTO fault_child VALUES (1); END;")).unwrap();
    }
    fn unfault(store: &SqlCipherMailboxStore) {
        store
            .connection
            .lock()
            .unwrap()
            .execute_batch(
                "DROP TRIGGER command_fault; DROP TABLE fault_child; DROP TABLE fault_parent;",
            )
            .unwrap();
    }
    fn abandon(store: &SqlCipherMailboxStore, snapshot: &CommandSnapshot) {
        run(store.abandon(
            &pre(snapshot),
            AbandonConfirmation::ProviderMayAlreadyHaveApplied,
        ))
        .unwrap();
    }

    // Storage owns replay and admission atomicity; receipts below all come from production SQL.
    #[test]
    fn admission_rolls_back_after_attempted_work_and_replays_saved_state_without_requeue() {
        let (_db, store) = setup("p5c-admit");
        fault(&store, "INSERT ON main.command_fields");
        let request =
            CommandAdmission::new(bound(), intent("a", &["m"], &MessageAction::Trash)).unwrap();
        assert_eq!(run(store.admit(&request)), Err(Error::Storage));
        assert_eq!(count(&store, "mailbox_commands"), 0);
        assert_eq!(count(&store, "command_fields"), 0);
        let fifo: i64 = store
            .connection
            .lock()
            .unwrap()
            .query_row("SELECT next_fifo FROM mailbox_checkpoint", [], |r| r.get(0))
            .unwrap();
        assert_eq!(fifo, 1);
        unfault(&store);
        let saved = admit(&store, request.command().clone());
        let different = CommandAdmission::new(bound(), create("a")).unwrap();
        assert_eq!(
            run(store.admit(&different)).unwrap(),
            CommandAdmissionOutcome::Retained(RetainedCommand::Full(Box::new(saved.clone())))
        );
        run(store.cancel_queued(&pre(&saved))).unwrap();
        assert!(
            matches!(run(store.admit(&request)).unwrap(),CommandAdmissionOutcome::Retained(RetainedCommand::Terminal(s)) if s.status()==Status::Cancelled)
        );
        assert!(lookup(&store, "unknown").is_none());
        assert_eq!(count(&store, "mailbox_commands"), 0);
    }
    #[test]
    fn both_admission_limits_are_atomic_under_competing_connections() {
        for target_limit in [false, true] {
            let (db, store) = setup(if target_limit {
                "p5c-target-race"
            } else {
                "p5c-slot-race"
            });
            if target_limit {
                for batch in 0..5 {
                    let size = if batch == 4 { 95 } else { 1000 };
                    let ids: Vec<_> = (0..size).map(|n| format!("m{n}")).collect();
                    let ids: Vec<_> = ids.iter().map(String::as_str).collect();
                    admit(
                        &store,
                        intent(&format!("batch{batch}"), &ids, &MessageAction::Read),
                    );
                }
            } else {
                for n in 0..31 {
                    admit(&store, create(&format!("label{n}")));
                }
            }
            let other = SqlCipherMailboxStore::open(account(), db.path(), key(7)).unwrap();
            let barrier = std::sync::Barrier::new(2);
            let results = thread::scope(|scope| {
                let first = scope.spawn(|| {
                    barrier.wait();
                    run(store.admit(
                        &CommandAdmission::new(
                            bound(),
                            intent("racer1", &["m"], &MessageAction::Read),
                        )
                        .unwrap(),
                    ))
                });
                let second = scope.spawn(|| {
                    barrier.wait();
                    run(other.admit(
                        &CommandAdmission::new(
                            bound(),
                            intent("racer2", &["m"], &MessageAction::Read),
                        )
                        .unwrap(),
                    ))
                });
                [first.join().unwrap(), second.join().unwrap()]
            });
            assert_eq!(
                results
                    .iter()
                    .filter(|r| matches!(r, Ok(CommandAdmissionOutcome::Admitted(_))))
                    .count(),
                1
            );
            assert_eq!(
                results
                    .iter()
                    .filter(|r| **r == Err(Error::QuotaExceeded))
                    .count(),
                1
            );
            assert_eq!(
                count(&store, "command_items"),
                if target_limit { 4096 } else { 1 }
            );
        }
    }
    #[test]
    fn account_identity_revision_and_fifo_are_rechecked_and_later_queued_can_cancel() {
        let (_db, store) = setup("p5c-fences");
        let first = admit(&store, intent("first", &["m"], &MessageAction::Read));
        let later = admit(&store, intent("later", &["n"], &MessageAction::Read));
        assert_eq!(
            prepare(
                &store,
                evidence(&later, &[("n", Some(&["UNREAD"]))]),
                Some(&["n"]),
                DispatchAuthorization::Automatic,
                DuplicateRiskConfirmation::NotConfirmed
            ),
            Err(Error::Conflict)
        );
        run(store.cancel_queued(&pre(&later))).unwrap();
        let bad_fence = AccountFence::new(account(), IdentityHash::from_bytes([88; 32]));
        assert_eq!(
            run(store.oldest_pending(&bad_fence)),
            Err(Error::IdentityChanged)
        );
        assert_eq!(
            run(store.reconciliation_failed(
                &CommandPrecondition::new(bad_fence, first.stamp().clone()).unwrap(),
                ReconciliationFailure::ReadUnavailable
            )),
            Err(Error::IdentityChanged)
        );
        assert_eq!(full(&store, "first"), first);

        let foreign = AccountFence::new(AccountId::new("foreign").unwrap(), fence());
        assert_eq!(
            run(store.oldest_pending(&foreign)),
            Err(Error::UnknownAccount)
        );
        let changed =
            run(store.reconciliation_failed(&pre(&first), ReconciliationFailure::ReadUnavailable))
                .unwrap();
        assert_eq!(run(store.cancel_queued(&pre(&first))), Err(Error::Conflict));
        assert_eq!(
            prepare(
                &store,
                evidence(&changed, &[("m", Some(&["UNREAD"]))]),
                Some(&["m"]),
                DispatchAuthorization::Automatic,
                DuplicateRiskConfirmation::NotConfirmed
            )
            .unwrap()
            .snapshot()
            .automatic_attempts(),
            1
        );
    }
    #[test]
    fn local_cancel_settlement_and_abandon_survive_access_loss_and_block_new_writes() {
        let (_db, store) = setup("p5c-offline");
        let a = admit(&store, intent("a", &["a"], &MessageAction::Read));
        let b = admit(&store, intent("b", &["b"], &MessageAction::Read));
        let c = admit(&store, intent("c", &["c"], &MessageAction::Read));
        lose_access(&store);
        assert_eq!(
            run(store.admit(&CommandAdmission::new(bound(), create("denied")).unwrap())),
            Err(Error::ReadOnly)
        );
        assert_eq!(
            prepare(
                &store,
                evidence(&a, &[("a", Some(&["UNREAD"]))]),
                Some(&["a"]),
                DispatchAuthorization::Automatic,
                DuplicateRiskConfirmation::NotConfirmed
            ),
            Err(Error::ReadOnly)
        );
        run(store.cancel_queued(&pre(&a))).unwrap();
        assert_eq!(
            settle(&store, &evidence(&b, &[("b", Some(&[]))])).status(),
            Status::Complete
        );
        abandon(&store, &c);
        assert!(run(store.oldest_pending(&bound())).unwrap().is_none());
    }
    #[test]
    fn predispatch_commit_failure_has_no_receipt_and_restart_before_record_is_ambiguous() {
        let (db, store) = setup("p5c-dispatch");
        let saved = admit(&store, intent("send", &["m"], &MessageAction::Read));
        fault(&store, "UPDATE OF status ON main.mailbox_commands");
        assert_eq!(
            prepare(
                &store,
                evidence(&saved, &[("m", Some(&["UNREAD"]))]),
                Some(&["m"]),
                DispatchAuthorization::Automatic,
                DuplicateRiskConfirmation::NotConfirmed
            ),
            Err(Error::Storage)
        );
        assert_eq!(full(&store, "send"), saved);
        unfault(&store);
        let receipt = prepare(
            &store,
            evidence(&saved, &[("m", Some(&["UNREAD"]))]),
            Some(&["m"]),
            DispatchAuthorization::Automatic,
            DuplicateRiskConfirmation::NotConfirmed,
        )
        .unwrap();
        assert_eq!(receipt.snapshot().status(), Status::Dispatching);
        drop(store);
        let reopened = SqlCipherMailboxStore::open(account(), db.path(), key(7)).unwrap();
        let recovered = run(reopened.recover_dispatching(&pre(receipt.snapshot()))).unwrap();
        assert_eq!(recovered.status(), Status::Ambiguous);
        assert_eq!(recovered.automatic_attempts(), 1);
        let outcome = RemoteCommandOutcome::new(
            &receipt,
            DispatchFact::Acknowledged(WriteAcknowledgement::MessageBatchAccepted),
        )
        .unwrap();
        assert_eq!(
            run(reopened.record_dispatch(&pre(receipt.snapshot()), &outcome)),
            Err(Error::Conflict)
        );
        assert_eq!(
            run(reopened.cancel_queued(&pre(&recovered))),
            Err(Error::NotEligible)
        );
    }
    #[test]
    fn ack_never_completes_and_settlement_commit_failure_preserves_dispatch_evidence() {
        let (_db, store) = setup("p5c-ack");
        let saved = admit(&store, intent("send", &["m"], &MessageAction::Read));
        let receipt = prepare(
            &store,
            evidence(&saved, &[("m", Some(&["UNREAD"]))]),
            Some(&["m"]),
            DispatchAuthorization::Automatic,
            DuplicateRiskConfirmation::NotConfirmed,
        )
        .unwrap();
        let outcome = RemoteCommandOutcome::new(
            &receipt,
            DispatchFact::Acknowledged(WriteAcknowledgement::MessageBatchAccepted),
        )
        .unwrap();
        let acked = run(store.record_dispatch(&pre(receipt.snapshot()), &outcome)).unwrap();
        assert_eq!(acked.status(), Status::Ambiguous);
        fault(&store, "INSERT ON main.terminal_commands");
        let rec = evidence(&acked, &[("m", Some(&[]))]);
        assert_eq!(
            run(MailboxCommandStore::reconcile(&store, &pre(&acked), &rec)),
            Err(Error::Storage)
        );
        assert_eq!(full(&store, "send"), acked);
        assert_eq!(count(&store, "terminal_commands"), 0);
        unfault(&store);
        assert_eq!(settle(&store, &rec).status(), Status::Complete);
        assert!(run(store.undo_candidate(&bound())).unwrap().is_some());
    }
    #[test]
    fn three_automatic_attempts_then_single_use_retry_keep_budget_and_refresh_ticket_revisions() {
        let (_db, store) = setup("p5c-budgets");
        let mut saved = admit(&store, intent("send", &["m"], &MessageAction::Read));
        for attempts in 1..=3 {
            let receipt = prepare(
                &store,
                evidence(&saved, &[("m", Some(&["UNREAD"]))]),
                Some(&["m"]),
                DispatchAuthorization::Automatic,
                DuplicateRiskConfirmation::NotConfirmed,
            )
            .unwrap();
            assert_eq!(receipt.snapshot().automatic_attempts(), attempts);
            saved = run(store.recover_dispatching(&pre(receipt.snapshot()))).unwrap();
            saved = settle(&store, &evidence(&saved, &[("m", Some(&["UNREAD"]))]));
        }
        assert_eq!(saved.status(), Status::NeedsAttention);
        assert_eq!(
            prepare(
                &store,
                evidence(&saved, &[("m", Some(&["UNREAD"]))]),
                Some(&["m"]),
                DispatchAuthorization::Automatic,
                DuplicateRiskConfirmation::NotConfirmed
            ),
            Err(Error::NotEligible)
        );
        let old_ticket = run(store.authorize_retry(&pre(&saved))).unwrap();
        let authorized = full(&store, "send");
        saved = settle(&store, &evidence(&authorized, &[("m", Some(&["UNREAD"]))]));
        assert_ne!(saved.retry_authorization(), Some(&old_ticket));
        let ticket = saved.retry_authorization().unwrap().clone();
        let receipt = prepare(
            &store,
            evidence(&saved, &[("m", Some(&["UNREAD"]))]),
            Some(&["m"]),
            DispatchAuthorization::Explicit(ticket.clone()),
            DuplicateRiskConfirmation::NotConfirmed,
        )
        .unwrap();
        assert_eq!(
            prepare(
                &store,
                evidence(&saved, &[("m", Some(&["UNREAD"]))]),
                Some(&["m"]),
                DispatchAuthorization::Explicit(ticket),
                DuplicateRiskConfirmation::NotConfirmed
            ),
            Err(Error::Conflict)
        );
        assert_eq!(receipt.snapshot().automatic_attempts(), 3);
        assert!(receipt.snapshot().retry_authorization().is_none());
        let failed = run(store.reconciliation_failed(
            &pre(receipt.snapshot()),
            ReconciliationFailure::ReadUnavailable,
        ))
        .unwrap();
        assert!(failed.retry_authorization().is_none());
        assert_eq!(
            run(store.record_dispatch(
                &pre(receipt.snapshot()),
                &RemoteCommandOutcome::new(&receipt, DispatchFact::Ambiguous).unwrap()
            )),
            Err(Error::Conflict)
        );
    }
    #[test]
    fn ambiguous_create_requires_fresh_zero_and_confirmed_explicit_retry_or_adopts_one() {
        let (_db, store) = setup("p5c-create");
        let saved = admit(&store, create("create"));
        let receipt = prepare(
            &store,
            catalog(&saved, &[]),
            None,
            DispatchAuthorization::Automatic,
            DuplicateRiskConfirmation::NotConfirmed,
        )
        .unwrap();
        let saved = run(store.recover_dispatching(&pre(receipt.snapshot()))).unwrap();
        assert_eq!(
            prepare(
                &store,
                catalog(&saved, &[]),
                None,
                DispatchAuthorization::Automatic,
                DuplicateRiskConfirmation::NotConfirmed
            ),
            Err(Error::NotEligible)
        );
        run(store.authorize_retry(&pre(&saved))).unwrap();
        let mut saved = full(&store, "create");
        let ticket = saved.retry_authorization().unwrap().clone();
        assert_eq!(
            prepare(
                &store,
                catalog(&saved, &[]),
                None,
                DispatchAuthorization::Explicit(ticket.clone()),
                DuplicateRiskConfirmation::NotConfirmed
            ),
            Err(Error::NotEligible)
        );
        assert_eq!(
            prepare(
                &store,
                catalog(&saved, &["Label_a", "Label_b"]),
                None,
                DispatchAuthorization::Explicit(ticket.clone()),
                DuplicateRiskConfirmation::Confirmed
            ),
            Err(Error::NotEligible)
        );
        let receipt = prepare(
            &store,
            catalog(&saved, &[]),
            None,
            DispatchAuthorization::Explicit(ticket),
            DuplicateRiskConfirmation::Confirmed,
        )
        .unwrap();
        saved = run(store.recover_dispatching(&pre(receipt.snapshot()))).unwrap();
        saved = settle(&store, &catalog(&saved, &["Label_a", "Label_b"]));
        assert!(!saved.status().is_terminal());
        saved = settle(&store, &catalog(&saved, &["Label_a"]));
        assert_eq!(saved.status(), Status::Complete);
        assert!(run(store.undo_candidate(&bound())).unwrap().is_none());
    }
    #[test]
    fn initial_satisfied_targets_keep_truthful_full_target_undo_and_all_missing_is_partial() {
        let (_db, store) = setup("p5c-prestate");
        let saved = admit(
            &store,
            intent("read", &["already", "unread"], &MessageAction::Read),
        );
        let saved = settle(
            &store,
            &evidence(
                &saved,
                &[("already", Some(&[])), ("unread", Some(&["UNREAD"]))],
            ),
        );
        let receipt = prepare(
            &store,
            evidence(
                &saved,
                &[("already", Some(&[])), ("unread", Some(&["UNREAD"]))],
            ),
            Some(&["unread"]),
            DispatchAuthorization::Automatic,
            DuplicateRiskConfirmation::NotConfirmed,
        )
        .unwrap();
        let saved = run(store.recover_dispatching(&pre(receipt.snapshot()))).unwrap();
        let done = settle(
            &store,
            &evidence(&saved, &[("already", Some(&[])), ("unread", Some(&[]))]),
        );
        assert_eq!(done.status(), Status::Complete);
        let candidate = run(store.undo_candidate(&bound())).unwrap().unwrap();
        let items = candidate.compensation().items();
        assert_eq!(items.len(), 2);
        assert!(!items[0].condition().restore_state().memberships()[0].is_present());
        assert!(items[1].condition().restore_state().memberships()[0].is_present());
        let missing = admit(&store, intent("missing", &["x", "y"], &MessageAction::Read));
        let partial = settle(&store, &evidence(&missing, &[("x", None), ("y", None)]));
        assert_eq!(partial.status(), Status::Partial);
        assert_eq!(partial.counts().satisfied(), 0);
        assert_eq!(partial.counts().target_missing(), 2);
        assert_eq!(
            run(store.undo_candidate(&bound())).unwrap(),
            Some(candidate)
        );
    }
    fn undo(store: &SqlCipherMailboxStore, name: &str) -> CommandSnapshot {
        let candidate = run(store.undo_candidate(&bound())).unwrap().unwrap();
        let command = MailboxCommand::compensate(
            AccountCapability::Modify,
            id(name),
            candidate.compensation().clone(),
        )
        .unwrap();
        match run(store.admit_undo(&UndoAdmission::new(bound(), candidate, command).unwrap()))
            .unwrap()
        {
            CommandAdmissionOutcome::Admitted(s) => *s,
            CommandAdmissionOutcome::Retained(_) => panic!("new undo"),
        }
    }
    fn complete_read(store: &SqlCipherMailboxStore) {
        let saved = admit(store, intent("original", &["a", "b"], &MessageAction::Read));
        let receipt = prepare(
            store,
            evidence(
                &saved,
                &[("a", Some(&["UNREAD"])), ("b", Some(&["UNREAD"]))],
            ),
            Some(&["a", "b"]),
            DispatchAuthorization::Automatic,
            DuplicateRiskConfirmation::NotConfirmed,
        )
        .unwrap();
        settle(
            store,
            &evidence(receipt.snapshot(), &[("a", Some(&[])), ("b", Some(&[]))]),
        );
    }
    #[test]
    fn undo_checks_whole_set_before_any_write_and_generic_early_complete_cannot_bypass_it() {
        let (_db, store) = setup("p5c-undo-refusal");
        complete_read(&store);
        let saved = undo(&store, "undo");
        let later = admit(&store, create("later"));
        let changed = evidence(&saved, &[("a", Some(&["UNREAD"])), ("b", Some(&[]))]);
        assert_eq!(
            prepare(
                &store,
                changed.clone(),
                Some(&["b"]),
                DispatchAuthorization::Automatic,
                DuplicateRiskConfirmation::NotConfirmed
            ),
            Err(Error::NotEligible)
        );
        let refused = settle(&store, &changed);
        assert_eq!(refused.status(), Status::NeedsAttention);
        assert_eq!(refused.counts().satisfied(), 0);
        assert_eq!(refused.automatic_attempts(), 0);
        let restored_by_actor = evidence(
            &refused,
            &[("a", Some(&["UNREAD"])), ("b", Some(&["UNREAD"]))],
        );
        let still_refused = settle(&store, &restored_by_actor);
        assert_eq!(still_refused.status(), Status::NeedsAttention);
        assert_eq!(still_refused.counts().satisfied(), 0);
        // Own and later queued commands do not reapply the undo admission-only gate.
        let receipt = prepare(
            &store,
            evidence(&still_refused, &[("a", Some(&[])), ("b", Some(&[]))]),
            Some(&["a", "b"]),
            DispatchAuthorization::Automatic,
            DuplicateRiskConfirmation::NotConfirmed,
        )
        .unwrap();
        assert_eq!(receipt.snapshot().status(), Status::Dispatching);
        assert_eq!(
            prepare(
                &store,
                catalog(&later, &[]),
                None,
                DispatchAuthorization::Automatic,
                DuplicateRiskConfirmation::NotConfirmed
            ),
            Err(Error::Conflict)
        );
    }
    #[test]
    fn partial_compensation_recovery_does_not_reapply_original_condition_to_restored_targets() {
        let (db, store) = setup("p5c-undo-recovery");
        complete_read(&store);
        let source = run(store.undo_candidate(&bound())).unwrap().unwrap();
        let saved = undo(&store, "undo");
        let receipt = prepare(
            &store,
            evidence(&saved, &[("a", Some(&[])), ("b", Some(&[]))]),
            Some(&["a", "b"]),
            DispatchAuthorization::Automatic,
            DuplicateRiskConfirmation::NotConfirmed,
        )
        .unwrap();
        let saved = settle(
            &store,
            &evidence(
                receipt.snapshot(),
                &[("a", Some(&["UNREAD"])), ("b", Some(&[]))],
            ),
        );
        assert_eq!(saved.counts().satisfied(), 1);
        drop(store);
        let store = SqlCipherMailboxStore::open(account(), db.path(), key(7)).unwrap();
        let receipt = prepare(
            &store,
            evidence(&saved, &[("a", Some(&["UNREAD"])), ("b", Some(&[]))]),
            Some(&["b"]),
            DispatchAuthorization::Automatic,
            DuplicateRiskConfirmation::NotConfirmed,
        )
        .unwrap();
        let complete = settle(
            &store,
            &evidence(
                receipt.snapshot(),
                &[("a", Some(&["UNREAD"])), ("b", Some(&["UNREAD"]))],
            ),
        );
        assert_eq!(complete.status(), Status::Complete);
        assert_eq!(run(store.undo_candidate(&bound())).unwrap(), Some(source));
    }
    #[test]
    fn undo_admission_rejects_preexisting_work_and_stale_source_and_label_crud_keeps_slot() {
        let (_db, store) = setup("p5c-undo-admit");
        complete_read(&store);
        let candidate = run(store.undo_candidate(&bound())).unwrap().unwrap();
        let cmd = MailboxCommand::compensate(
            AccountCapability::Modify,
            id("undo"),
            candidate.compensation().clone(),
        )
        .unwrap();
        assert!(CommandAdmission::new(bound(), cmd.clone()).is_err());
        let request = UndoAdmission::new(bound(), candidate.clone(), cmd).unwrap();
        let blocker = admit(&store, create("label"));
        assert_eq!(run(store.admit_undo(&request)), Err(Error::NotEligible));
        settle(&store, &catalog(&blocker, &["Label_a"]));
        assert_eq!(
            run(store.undo_candidate(&bound())).unwrap(),
            Some(candidate)
        );
        let newest = admit(&store, intent("newest", &["z"], &MessageAction::Read));
        settle(&store, &evidence(&newest, &[("z", Some(&[]))]));
        assert_eq!(run(store.admit_undo(&request)), Err(Error::NotEligible));
    }
    #[test]
    fn warned_abandon_commit_failure_keeps_fifo_pins_and_lifecycle_guards() {
        let (_db, store) = setup("p5c-abandon");
        let saved = admit(&store, intent("send", &["pinned"], &MessageAction::Read));
        let receipt = prepare(
            &store,
            evidence(&saved, &[("pinned", Some(&["UNREAD"]))]),
            Some(&["pinned"]),
            DispatchAuthorization::Automatic,
            DuplicateRiskConfirmation::NotConfirmed,
        )
        .unwrap();
        let saved = run(store.recover_dispatching(&pre(receipt.snapshot()))).unwrap();
        fault(&store, "INSERT ON main.terminal_commands");
        assert_eq!(
            run(store.abandon(
                &pre(&saved),
                AbandonConfirmation::ProviderMayAlreadyHaveApplied
            )),
            Err(Error::Storage)
        );
        assert_eq!(full(&store, "send"), saved);
        assert_eq!(count(&store, "command_items"), 1);
        assert_eq!(
            store.clear_cached_mail(&account()),
            Err(CacheResetError::Ineligible)
        );
        assert!(run(store.purge_account(&account())).is_err());
        unfault(&store);
        abandon(&store, &saved);
        assert_eq!(count(&store, "command_items"), 0);
        assert!(
            matches!(lookup(&store,"send"),Some(RetainedCommand::Terminal(s)) if s.status()==Status::Abandoned)
        );
        store.clear_cached_mail(&account()).unwrap();
        assert!(lookup(&store, "send").is_none());
        let snapshot = store.load_credential_snapshot(&account()).unwrap();
        assert_eq!(snapshot.capability(), AccountCapability::Modify);
        assert!(matches!(
            snapshot.credential(),
            crate::StoreCredential::Active(_)
        ));
    }
    #[test]
    fn retention_keeps_128_summaries_and_one_older_undo_with_pins_beyond_recent_cache() {
        let (_db, store) = setup("p5c-retention");
        complete_read(&store);
        let candidate = run(store.undo_candidate(&bound())).unwrap().unwrap();
        // Exercise the real legacy pruning path: both candidate targets survive keep-1.
        run(store.reconcile_recent_envelopes(
            &account(),
            &[
                envelope("a", "thread", 1),
                envelope("b", "thread", 2),
                envelope("recent", "thread", 999),
            ],
            StoreLimit::new(1).unwrap(),
            &fence(),
        ))
        .unwrap();
        assert_eq!(count(&store, "messages"), 3);
        for n in 0..129 {
            let saved = admit(&store, create(&format!("cancel{n}")));
            run(store.cancel_queued(&pre(&saved))).unwrap();
        }
        assert_eq!(
            run(store.terminal_summaries(&bound()))
                .unwrap()
                .summaries()
                .len(),
            128
        );
        assert!(lookup(&store, "cancel0").is_none());
        assert!(matches!(
            lookup(&store, "original"),
            Some(RetainedCommand::Full(_))
        ));
        assert_eq!(
            run(store.undo_candidate(&bound())).unwrap(),
            Some(candidate)
        );
        assert_eq!(count(&store, "mailbox_commands"), 1);
        store.clear_cached_mail(&account()).unwrap();
        assert_eq!(count(&store, "mailbox_commands"), 0);
        assert_eq!(count(&store, "messages"), 0);
        assert!(run(store.undo_candidate(&bound())).unwrap().is_none());
    }
    #[test]
    fn bounded_decoding_rejects_corrupt_dispatch_relationships_and_orphan_memberships() {
        for corruption in [
            "PRAGMA ignore_check_constraints=ON; UPDATE mailbox_commands SET dispatch_started=1,dispatch_revision=zeroblob(8),dispatch_authorization=1",
            "PRAGMA foreign_keys=OFF; INSERT INTO command_item_memberships VALUES ('send','orphan','UNREAD'); PRAGMA foreign_keys=ON",
            "PRAGMA ignore_check_constraints=ON; UPDATE mailbox_commands SET revision=zeroblob(9)",
            "PRAGMA ignore_check_constraints=ON; INSERT INTO command_item_memberships VALUES ('send','m',CAST(zeroblob(257) AS TEXT))",
        ] {
            let (_db, store) = setup("p5c-corrupt");
            let saved = admit(&store, intent("send", &["m"], &MessageAction::Read));
            store
                .connection
                .lock()
                .unwrap()
                .execute_batch(corruption)
                .unwrap();
            assert_eq!(run(store.cancel_queued(&pre(&saved))), Err(Error::Corrupt));
            assert_eq!(count(&store, "mailbox_commands"), 1);
            assert_eq!(count(&store, "terminal_commands"), 0);
        }
    }
    #[test]
    fn known_user_label_is_freshly_verified_for_dispatch_and_undo_whole_set_guard() {
        let (_db, store) = setup("p5c-user-label");
        let definition = LabelDefinition::new(
            account(),
            LabelId::new("Label_a").unwrap(),
            LabelName::new("name").unwrap(),
            LabelKind::User,
        )
        .unwrap();
        let label = definition.user_label().unwrap();
        let saved = admit(
            &store,
            intent("label", &["m"], &MessageAction::ApplyLabel(label.clone())),
        );
        let observed = |snapshot: &CommandSnapshot, present: bool, exists: bool| {
            let base = evidence_raw(snapshot, present.then_some("Label_a"));
            CommandReconciliation::new(
                snapshot.clone(),
                CommandEvidence::Messages {
                    observations: base,
                    user_label: Some(
                        UserLabelObservation::new(
                            label.clone(),
                            exists.then(|| definition.clone()),
                        )
                        .unwrap(),
                    ),
                },
            )
            .unwrap()
        };
        assert_eq!(
            prepare(
                &store,
                observed(&saved, false, false),
                Some(&["m"]),
                DispatchAuthorization::Automatic,
                DuplicateRiskConfirmation::NotConfirmed
            ),
            Err(Error::NotEligible)
        );
        let receipt = prepare(
            &store,
            observed(&saved, false, true),
            Some(&["m"]),
            DispatchAuthorization::Automatic,
            DuplicateRiskConfirmation::NotConfirmed,
        )
        .unwrap();
        settle(&store, &observed(receipt.snapshot(), true, true));
        let saved = undo(&store, "undo");
        assert_eq!(
            prepare(
                &store,
                observed(&saved, true, false),
                Some(&["m"]),
                DispatchAuthorization::Automatic,
                DuplicateRiskConfirmation::NotConfirmed
            ),
            Err(Error::NotEligible)
        );
        assert_eq!(
            settle(&store, &observed(&saved, true, false))
                .counts()
                .satisfied(),
            0
        );
    }
    #[test]
    fn explicit_only_dispatch_survives_restart_and_failed_reads_with_zero_automatic_attempts() {
        let (db, store) = setup("p5c-explicit-only");
        let saved = admit(&store, intent("send", &["m"], &MessageAction::Read));
        let failed =
            run(store.reconciliation_failed(&pre(&saved), ReconciliationFailure::ReadUnavailable))
                .unwrap();
        let ticket = run(store.authorize_retry(&pre(&failed))).unwrap();
        let saved = full(&store, "send");
        let receipt = prepare(
            &store,
            evidence(&saved, &[("m", Some(&["UNREAD"]))]),
            Some(&["m"]),
            DispatchAuthorization::Explicit(ticket),
            DuplicateRiskConfirmation::NotConfirmed,
        )
        .unwrap();
        assert_eq!(receipt.snapshot().automatic_attempts(), 0);
        drop(store);
        let store = SqlCipherMailboxStore::open(account(), db.path(), key(7)).unwrap();
        let saved = run(store.recover_dispatching(&pre(receipt.snapshot()))).unwrap();
        let failed =
            run(store.reconciliation_failed(&pre(&saved), ReconciliationFailure::InvalidEvidence))
                .unwrap();
        assert_eq!(failed.automatic_attempts(), 0);
        assert_eq!(
            run(store.cancel_queued(&pre(&failed))),
            Err(Error::NotEligible)
        );
        let markers: (Vec<u8>,i64,Option<i64>) = store.connection.lock().unwrap().query_row("SELECT dispatch_revision,dispatch_authorization,dispatch_fact FROM mailbox_commands",[],|r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
        assert_eq!(
            markers,
            (
                receipt.snapshot().stamp().revision().to_be_bytes().to_vec(),
                1,
                None
            )
        );
    }
    #[test]
    fn every_nonterminal_state_blocks_actual_reset_purge_and_identity_replacement() {
        for state in [
            Status::Queued,
            Status::Dispatching,
            Status::Ambiguous,
            Status::NeedsAttention,
        ] {
            let (_db, store) = setup("p5c-lifecycle");
            let mut saved = admit(&store, intent("send", &["m"], &MessageAction::Read));
            if state != Status::Queued {
                let receipt = prepare(
                    &store,
                    evidence(&saved, &[("m", Some(&["UNREAD"]))]),
                    Some(&["m"]),
                    DispatchAuthorization::Automatic,
                    DuplicateRiskConfirmation::NotConfirmed,
                )
                .unwrap();
                saved = receipt.snapshot().clone();
                if state == Status::Ambiguous {
                    saved = run(store.recover_dispatching(&pre(&saved))).unwrap();
                }
                if state == Status::NeedsAttention {
                    saved = run(store.reconciliation_failed(
                        &pre(&saved),
                        ReconciliationFailure::ReadUnavailable,
                    ))
                    .unwrap();
                }
            }
            assert_eq!(saved.status(), state);
            assert_eq!(
                store.clear_cached_mail(&account()),
                Err(CacheResetError::Ineligible)
            );
            assert_eq!(
                run(store.purge_account(&account())),
                Err(MailboxStoreError::Storage)
            );
            for action in [
                IdentityReconcile::RecordOnly,
                IdentityReconcile::ClearMailboxAndRecord,
            ] {
                assert_eq!(
                    run(store.reconcile_identity(
                        &account(),
                        &IdentityHash::from_bytes([8; 32]),
                        action,
                        Some(&fence())
                    )),
                    Err(MailboxStoreError::Storage)
                );
            }
            assert_eq!(full(&store, "send"), saved);
            abandon(&store, &saved);
            run(store.purge_account(&account())).unwrap();
            assert_eq!(count(&store, "terminal_commands"), 0);
            assert_eq!(count(&store, "account_identity"), 0);
            let grant = store.load_credential_snapshot(&account()).unwrap();
            assert_eq!(grant.capability(), AccountCapability::ReadOnly);
            assert!(grant.subject().is_none());
        }
    }
    #[test]
    fn message_rejection_observed_missing_and_known_failures_remain_partial_after_later_dispatch() {
        let (_db, store) = setup("p5c-known-failure");
        let saved = admit(&store, intent("send", &["a", "b"], &MessageAction::Read));
        let receipt = prepare(
            &store,
            evidence(
                &saved,
                &[("a", Some(&["UNREAD"])), ("b", Some(&["UNREAD"]))],
            ),
            Some(&["a"]),
            DispatchAuthorization::Automatic,
            DuplicateRiskConfirmation::NotConfirmed,
        )
        .unwrap();
        let rejected = RemoteCommandOutcome::new(
            &receipt,
            DispatchFact::Rejected(tersa_application::command::CommandRejection::Rejected),
        )
        .unwrap();
        let saved = run(store.record_dispatch(&pre(receipt.snapshot()), &rejected)).unwrap();
        let saved = settle(
            &store,
            &evidence(
                &saved,
                &[("a", Some(&["UNREAD"])), ("b", Some(&["UNREAD"]))],
            ),
        );
        assert_eq!(saved.counts().failed(), 1);
        assert_eq!(saved.counts().pending(), 1);
        let ticket = run(store.authorize_retry(&pre(&saved))).unwrap();
        let saved = full(&store, "send");
        let receipt = prepare(
            &store,
            evidence(
                &saved,
                &[("a", Some(&["UNREAD"])), ("b", Some(&["UNREAD"]))],
            ),
            Some(&["b"]),
            DispatchAuthorization::Explicit(ticket),
            DuplicateRiskConfirmation::NotConfirmed,
        )
        .unwrap();
        let saved = run(store.recover_dispatching(&pre(receipt.snapshot()))).unwrap();
        let done = settle(
            &store,
            &evidence(&saved, &[("a", Some(&["UNREAD"])), ("b", None)]),
        );
        assert_eq!(done.status(), Status::Partial);
        assert_eq!(done.counts().failed(), 1);
        assert_eq!(done.counts().target_missing(), 1);
    }
    #[test]
    fn known_label_rename_and_delete_require_actual_observations_not_acknowledgements() {
        let (_db, store) = setup("p5c-label-crud");
        let definition = |name: &str| {
            LabelDefinition::new(
                account(),
                LabelId::new("Label_a").unwrap(),
                LabelName::new(name).unwrap(),
                LabelKind::User,
            )
            .unwrap()
        };
        let label = definition("old").user_label().unwrap();
        let saved = admit(
            &store,
            MailboxCommand::rename_label(
                AccountCapability::Modify,
                id("rename"),
                label.clone(),
                LabelName::new("new\0name").unwrap(),
            )
            .unwrap(),
        );
        let observed = |snapshot: &CommandSnapshot, definition| {
            CommandReconciliation::new(
                snapshot.clone(),
                CommandEvidence::UserLabel(
                    UserLabelObservation::new(label.clone(), definition).unwrap(),
                ),
            )
            .unwrap()
        };
        let receipt = prepare(
            &store,
            observed(&saved, Some(definition("old"))),
            None,
            DispatchAuthorization::Automatic,
            DuplicateRiskConfirmation::NotConfirmed,
        )
        .unwrap();
        let saved = run(store.record_dispatch(
            &pre(receipt.snapshot()),
            &RemoteCommandOutcome::new(
                &receipt,
                DispatchFact::Acknowledged(WriteAcknowledgement::LabelDefinitionAccepted),
            )
            .unwrap(),
        ))
        .unwrap();
        assert_eq!(saved.status(), Status::Ambiguous);
        assert_eq!(
            settle(&store, &observed(&saved, Some(definition("new\0name")))).status(),
            Status::Complete
        );
        let saved = admit(
            &store,
            MailboxCommand::delete_label(AccountCapability::Modify, id("delete"), label.clone())
                .unwrap(),
        );
        let receipt = prepare(
            &store,
            observed(&saved, Some(definition("new\0name"))),
            None,
            DispatchAuthorization::Automatic,
            DuplicateRiskConfirmation::NotConfirmed,
        )
        .unwrap();
        assert_eq!(
            settle(&store, &observed(receipt.snapshot(), None)).status(),
            Status::Complete
        );
    }
    #[test]
    fn fresh_selected_targets_must_be_unmet_and_counters_never_wrap() {
        let (_db, store) = setup("p5c-selection");
        let saved = admit(&store, intent("send", &["m"], &MessageAction::Read));
        assert_eq!(
            prepare(
                &store,
                evidence(&saved, &[("m", Some(&[]))]),
                Some(&["m"]),
                DispatchAuthorization::Automatic,
                DuplicateRiskConfirmation::NotConfirmed
            ),
            Err(Error::NotEligible)
        );
        store
            .connection
            .lock()
            .unwrap()
            .execute(
                "UPDATE mailbox_commands SET revision=?1",
                [u64::MAX.to_be_bytes()],
            )
            .unwrap();
        let exhausted = full(&store, "send");
        assert_eq!(
            run(store.cancel_queued(&pre(&exhausted))),
            Err(Error::NotEligible)
        );
        assert_eq!(full(&store, "send"), exhausted);
        store
            .connection
            .lock()
            .unwrap()
            .execute("UPDATE mailbox_checkpoint SET next_fifo=?1", [i64::MAX])
            .unwrap();
        assert_eq!(
            run(store.admit(&CommandAdmission::new(bound(), create("overflow")).unwrap())),
            Err(Error::NotEligible)
        );
        assert_eq!(count(&store, "mailbox_commands"), 1);
    }
    #[test]
    fn disconnect_start_refuses_before_lifecycle_change_but_post_attempt_fact_and_local_disposition_work()
     {
        let (_db, store) = setup("p5c-disconnect-start");
        let saved = admit(&store, intent("send", &["m"], &MessageAction::Read));
        let before = run(store.lifecycle_metadata(&account())).unwrap();
        assert_eq!(
            run(store.mark_disconnect_started(&account())),
            Err(MailboxStoreError::Storage)
        );
        assert_eq!(run(store.lifecycle_metadata(&account())).unwrap(), before);
        run(store.mark_revoke_unconfirmed(&account())).unwrap();
        lose_access(&store);
        run(store.cancel_queued(&pre(&saved))).unwrap();
        run(store.mark_disconnect_started(&account())).unwrap();
        assert_eq!(
            run(store.lifecycle_metadata(&account()))
                .unwrap()
                .recovery(),
            Some(DisconnectRecoveryState::IncompleteTeardown)
        );
    }
    #[test]
    fn ordinary_remove_already_absent_completes_without_definition_but_missing_label_refuses_undo()
    {
        let (_db, store) = setup("p5c-remove-missing-label");
        let label = tersa_domain::label::UserLabel::from_classified_id(
            account(),
            LabelId::new("Label_gone").unwrap(),
        )
        .unwrap();
        let saved = admit(
            &store,
            intent("remove", &["m"], &MessageAction::RemoveLabel(label.clone())),
        );
        let observed = |snapshot: &CommandSnapshot| {
            CommandReconciliation::new(
                snapshot.clone(),
                CommandEvidence::Messages {
                    observations: evidence_raw(snapshot, None),
                    user_label: Some(UserLabelObservation::new(label.clone(), None).unwrap()),
                },
            )
            .unwrap()
        };
        let complete = settle(&store, &observed(&saved));
        assert_eq!(complete.status(), Status::Complete);
        assert_eq!(complete.automatic_attempts(), 0);
        let undo = undo(&store, "undo");
        let refused = settle(&store, &observed(&undo));
        assert_eq!(refused.status(), Status::NeedsAttention);
        assert_eq!(refused.counts().satisfied(), 0);
        assert_eq!(
            prepare(
                &store,
                observed(&refused),
                Some(&["m"]),
                DispatchAuthorization::Automatic,
                DuplicateRiskConfirmation::NotConfirmed
            ),
            Err(Error::NotEligible)
        );
    }
    #[test]
    fn command_observations_round_trip_full_membership_and_reject_overflow_or_orphan_undo_ancestry()
    {
        let (_db, store) = setup("p5c-membership-bound");
        let labels: Vec<_> = (0..512).map(|n| format!("Label_{n}")).collect();
        let labels: Vec<_> = labels.iter().map(String::as_str).collect();
        let saved = admit(&store, intent("send", &["m"], &MessageAction::Read));
        // Full 512-label observation is durable command evidence, not the separate cached-read parser.
        let done = settle(&store, &evidence(&saved, &[("m", Some(&labels))]));
        assert_eq!(done.status(), Status::Complete);
        assert_eq!(count(&store, "command_item_memberships"), 512);
        assert_eq!(full(&store, "send"), done);
        store
            .connection
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO command_item_memberships VALUES ('send','m','overflow')",
                [],
            )
            .unwrap();
        assert_eq!(run(store.undo_candidate(&bound())), Err(Error::Corrupt));
        store
            .connection
            .lock()
            .unwrap()
            .execute(
                "DELETE FROM command_item_memberships WHERE label_id='overflow'",
                [],
            )
            .unwrap();
        let saved = undo(&store, "undo");
        store
            .connection
            .lock()
            .unwrap()
            .execute(
                "UPDATE mailbox_commands SET undo_source_id='orphan' WHERE command_id='undo'",
                [],
            )
            .unwrap();
        assert_eq!(run(store.cancel_queued(&pre(&saved))), Err(Error::Corrupt));
        assert_eq!(count(&store, "mailbox_commands"), 2);
    }
    #[test]
    fn legacy_large_envelope_reconcile_keeps_its_existing_limit_with_pending_pins() {
        let (_db, store) = setup("p5c-legacy-large");
        let saved = admit(&store, intent("pending", &["pinned"], &MessageAction::Read));
        let mut envelopes: Vec<_> = (0..7000)
            .map(|n| envelope(&format!("m{n}"), "thread", i64::from(n)))
            .collect();
        envelopes.push(envelope("pinned", "thread", 0));
        run(store.reconcile_recent_envelopes(
            &account(),
            &envelopes,
            StoreLimit::new(7000).unwrap(),
            &fence(),
        ))
        .unwrap();
        assert_eq!(count(&store, "messages"), 7001);
        assert_eq!(full(&store, "pending"), saved);
        run(store.cancel_queued(&pre(&saved))).unwrap();
        assert_eq!(count(&store, "messages"), 7001);
    }
    fn evidence_raw(_snapshot: &CommandSnapshot, label: Option<&str>) -> MessageObservations {
        MessageObservations::new(
            targets(&["m"]),
            vec![
                MessageObservation::new(
                    MessageKey::new(account(), MessageId::new("m").unwrap()),
                    RemoteMessageState::Known(
                        LabelMembership::new(
                            account(),
                            label
                                .map(|l| vec![LabelId::new(l).unwrap()])
                                .unwrap_or_default(),
                        )
                        .unwrap(),
                    ),
                )
                .unwrap(),
            ],
        )
        .unwrap()
    }
}
