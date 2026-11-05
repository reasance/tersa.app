// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

mod p7b_reads {
    use super::*;
    use crate::CachedMailboxFilter as Filter;
    use tersa_application::{
        command::{
            CommandAdmission, CommandAdmissionOutcome, CommandEvidence, CommandPrecondition,
            CommandReconciliation, CommandSnapshot, DispatchAuthorization, DispatchPreparation,
            DuplicateRiskConfirmation, MailboxCommandStore, ReconciliationFailure,
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
        label::{LabelId, LabelMembership, LabelName, UserLabel},
    };

    fn bound() -> AccountFence {
        AccountFence::new(account(), fence())
    }
    fn setup(name: &str) -> (TestDatabase, SqlCipherMailboxStore) {
        let (db, store) = open(name);
        record_fence(&store);
        (db, store)
    }
    fn reader(db: &TestDatabase) -> SqlCipherMailboxReader {
        SqlCipherMailboxReader::open_read_only(account(), db.path(), key(7)).unwrap()
    }
    fn limit(n: u16) -> StoreLimit {
        StoreLimit::new(n).unwrap()
    }
    fn user(owner: &AccountId, id: &str) -> UserLabel {
        UserLabel::from_classified_id(owner.clone(), LabelId::new(id).unwrap()).unwrap()
    }
    fn observe(store: &SqlCipherMailboxStore, id: &str, labels: &[&str]) {
        let c = store.connection.lock().unwrap();
        c.execute("INSERT INTO provider_messages VALUES (?1,1)", [id])
            .unwrap();
        for label in labels {
            c.execute(
                "INSERT INTO provider_memberships VALUES (?1,?2)",
                params![id, label],
            )
            .unwrap();
        }
    }
    fn ids(envelopes: &[MessageEnvelope]) -> Vec<&str> {
        envelopes.iter().map(|e| e.message_id().as_str()).collect()
    }
    fn grant(store: &SqlCipherMailboxStore) {
        store
            .connection
            .lock()
            .unwrap()
            .execute(
                "UPDATE account_binding SET broker_subject='synthetic-subject',capability=1",
                [],
            )
            .unwrap();
    }
    fn admit(
        store: &SqlCipherMailboxStore,
        name: &str,
        targets: &[&str],
        action: &MessageAction,
    ) -> CommandSnapshot {
        let command = MailboxCommand::message_state(
            AccountCapability::Modify,
            MailboxCommandId::new(name).unwrap(),
            MessageTargets::new(
                account(),
                targets
                    .iter()
                    .map(|id| MessageId::new(*id).unwrap())
                    .collect(),
            )
            .unwrap(),
            action,
        )
        .unwrap();
        admit_command(store, command)
    }
    fn admit_label(store: &SqlCipherMailboxStore, name: &str) -> CommandSnapshot {
        admit_command(
            store,
            MailboxCommand::create_label(
                AccountCapability::Modify,
                MailboxCommandId::new(name).unwrap(),
                account(),
                LabelName::new("label").unwrap(),
            )
            .unwrap(),
        )
    }
    fn admit_command(store: &SqlCipherMailboxStore, command: MailboxCommand) -> CommandSnapshot {
        match run(store.admit(&CommandAdmission::new(bound(), command).unwrap())).unwrap() {
            CommandAdmissionOutcome::Admitted(s) => *s,
            CommandAdmissionOutcome::Retained(_) => panic!("fresh command expected"),
        }
    }
    fn pre(snapshot: &CommandSnapshot) -> CommandPrecondition {
        CommandPrecondition::new(bound(), snapshot.stamp().clone()).unwrap()
    }
    fn evidence(
        snapshot: &CommandSnapshot,
        targets: &[&str],
        labels: &[&str],
    ) -> CommandReconciliation {
        let targets = MessageTargets::new(
            account(),
            targets
                .iter()
                .map(|id| MessageId::new(*id).unwrap())
                .collect(),
        )
        .unwrap();
        let observations = targets
            .ids()
            .iter()
            .map(|id| {
                MessageObservation::new(
                    MessageKey::new(account(), id.clone()),
                    RemoteMessageState::Known(
                        LabelMembership::new(
                            account(),
                            labels.iter().map(|l| LabelId::new(*l).unwrap()).collect(),
                        )
                        .unwrap(),
                    ),
                )
                .unwrap()
            })
            .collect();
        CommandReconciliation::new(
            snapshot.clone(),
            CommandEvidence::Messages {
                observations: MessageObservations::new(targets, observations).unwrap(),
                user_label: None,
            },
        )
        .unwrap()
    }

    // Regression: filtering an unfiltered 200-row window loses every older match and breaks pagination.
    #[test]
    fn filter_precedes_limit_and_equal_timestamp_pages_do_not_skip_or_duplicate() {
        let (db, store) = setup("p7b-filter-pagination");
        let rows: Vec<_> = (0..650)
            .map(|n| {
                envelope(
                    &format!("m{n:04}"),
                    "thread",
                    if n < 250 { 100 } else { 50 },
                )
            })
            .collect();
        run(store.upsert_envelopes(&account(), &rows)).unwrap();
        for n in 250..650 {
            observe(&store, &format!("m{n:04}"), &["INBOX"]);
        }
        let reader = reader(&db);
        for page_size in [1, 200, 201] {
            let mut after = None;
            let mut found = Vec::new();
            loop {
                let page = reader
                    .list_filtered_envelopes_after(
                        &account(),
                        &Filter::Inbox,
                        after.as_ref(),
                        limit(page_size),
                    )
                    .unwrap();
                assert!(page.len() <= usize::from(page_size));
                if page.is_empty() {
                    break;
                }
                after = page.last().map(EnvelopeCursor::after);
                found.extend(ids(&page).into_iter().map(str::to_owned));
            }
            assert_eq!(
                found,
                (250..650).map(|n| format!("m{n:04}")).collect::<Vec<_>>()
            );
        }
        let page = store
            .list_filtered_envelopes_after(&account(), &Filter::Inbox, None, limit(201))
            .unwrap();
        assert_eq!(page.len(), 201);
        assert_eq!(page[0].message_id().as_str(), "m0250");
        assert_eq!(
            reader.list_filtered_envelopes_after(&account(), &Filter::Recent, None, limit(202)),
            Err(MailboxStoreError::Storage)
        );
    }
    #[test]
    fn recent_keeps_unknown_and_known_empty_while_observed_filters_ignore_pending_intent() {
        let (db, store) = setup("p7b-filter-state");
        let rows: Vec<_> = [
            "unknown", "empty", "missing", "inbox", "trash", "spam", "pending",
        ]
        .into_iter()
        .map(|id| envelope(id, "thread", 10))
        .collect();
        run(store.upsert_envelopes(&account(), &rows)).unwrap();
        observe(&store, "empty", &[]);
        store
            .connection
            .lock()
            .unwrap()
            .execute("INSERT INTO provider_messages VALUES('missing',0)", [])
            .unwrap();
        observe(&store, "inbox", &["INBOX", "UNREAD"]);
        observe(&store, "trash", &["TRASH"]);
        observe(&store, "spam", &["SPAM"]);
        observe(&store, "pending", &[]);
        run(store.mark_message_read(&account(), &MessageId::new("inbox").unwrap())).unwrap();
        grant(&store);
        admit(
            &store,
            "pending-restore",
            &["pending"],
            &MessageAction::Restore,
        );
        let reader = reader(&db);
        assert_eq!(
            ids(&reader
                .list_filtered_envelopes_after(&account(), &Filter::Recent, None, limit(201))
                .unwrap()),
            [
                "empty", "inbox", "missing", "pending", "spam", "trash", "unknown"
            ]
        );
        for (filter, id) in [
            (Filter::Inbox, "inbox"),
            (Filter::Trash, "trash"),
            (Filter::Spam, "spam"),
        ] {
            let page = reader
                .list_filtered_envelopes_after(&account(), &filter, None, limit(201))
                .unwrap();
            assert_eq!(ids(&page), [id]);
            assert_eq!(page[0].is_unread(), id != "inbox"); // Existing sticky local-read display remains effective.
        }
    }
    #[test]
    fn user_filters_route_exact_ids_and_accounts_without_resolving_equal_names() {
        let (db, store) = setup("p7b-user-filter");
        run(store.upsert_envelopes(
            &account(),
            &[envelope("a", "thread", 1), envelope("b", "thread", 1)],
        ))
        .unwrap();
        observe(&store, "a", &["Label_a"]);
        observe(&store, "b", &["Label_b"]);
        store.connection.lock().unwrap().execute_batch("UPDATE mailbox_checkpoint SET catalog_known=1; INSERT INTO provider_labels VALUES('Label_a','same',1),('Label_b','same',1)").unwrap();
        let reader = reader(&db);
        let foreign = AccountId::new("account-b").unwrap();
        assert_eq!(
            ids(&reader
                .list_filtered_envelopes_after(
                    &account(),
                    &Filter::UserLabel(user(&account(), "Label_a")),
                    None,
                    limit(201)
                )
                .unwrap()),
            ["a"]
        );
        assert_eq!(
            ids(&store
                .list_filtered_envelopes_after(
                    &account(),
                    &Filter::UserLabel(user(&account(), "Label_b")),
                    None,
                    limit(201)
                )
                .unwrap()),
            ["b"]
        );
        assert_eq!(
            reader.list_filtered_envelopes_after(&foreign, &Filter::Recent, None, limit(1)),
            Err(MailboxStoreError::Storage)
        );
        assert_eq!(
            reader.list_filtered_envelopes_after(
                &account(),
                &Filter::UserLabel(user(&foreign, "Label_a")),
                None,
                limit(1)
            ),
            Err(MailboxStoreError::Storage)
        );
    }
    #[test]
    fn readonly_legacy_pages_and_empty_queue_preserve_files_and_actual_identity_fence() {
        for version in [1, 2] {
            let (db, anchor) = version_1_store("p7b-legacy");
            if version == 2 {
                anchor.execute_batch(MIGRATION_V2_ACCOUNT_EMAIL).unwrap();
                anchor.pragma_update(None, "user_version", 2).unwrap();
            }
            anchor
                .execute(
                    "INSERT INTO account_identity VALUES (?1,?2,2)",
                    params![account().as_str(), fence().as_bytes()],
                )
                .unwrap();
            let main = fs::read(db.path()).unwrap();
            let wal = fs::read(wal_path(&db)).unwrap();
            let reader = reader(&db);
            assert_eq!(
                ids(&reader
                    .list_filtered_envelopes_after(&account(), &Filter::Recent, None, limit(201))
                    .unwrap()),
                ["m1", "m0"]
            );
            for filter in [
                Filter::Inbox,
                Filter::Trash,
                Filter::Spam,
                Filter::UserLabel(user(&account(), "Label_a")),
            ] {
                assert!(
                    reader
                        .list_filtered_envelopes_after(&account(), &filter, None, limit(201))
                        .unwrap()
                        .is_empty()
                );
            }
            assert!(reader.pending_commands(&bound()).unwrap().is_empty());
            assert_eq!(
                reader.pending_commands(&AccountFence::new(
                    account(),
                    IdentityHash::from_bytes([8; 32])
                )),
                Err(Error::IdentityChanged)
            );
            assert_eq!(
                reader.pending_commands(&AccountFence::new(
                    AccountId::new("foreign").unwrap(),
                    fence()
                )),
                Err(Error::UnknownAccount)
            );
            assert_eq!(
                anchor
                    .query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
                    .unwrap(),
                version
            );
            assert_eq!(fs::read(db.path()).unwrap(), main);
            assert_eq!(fs::read(wal_path(&db)).unwrap(), wal);
            assert_eq!(reader.connection.lock().unwrap().total_changes(), 0);
        }
    }
    #[test]
    fn pending_reads_survive_reopen_keep_all_fifo_entries_and_never_recover_dispatching() {
        let (db, store) = setup("p7b-pending-reopen");
        grant(&store);
        let cancelled = admit_label(&store, "cancelled");
        run(store.cancel_queued(&pre(&cancelled))).unwrap();
        let complete = admit(&store, "complete", &["done"], &MessageAction::Read);
        run(MailboxCommandStore::reconcile(
            &store,
            &pre(&complete),
            &evidence(&complete, &["done"], &[]),
        ))
        .unwrap();
        let first = admit(&store, "first", &["m"], &MessageAction::Read);
        let receipt = run(store.prepare_dispatch(
            &DispatchPreparation::new(
                pre(&first),
                evidence(&first, &["m"], &["UNREAD"]),
                Some(MessageTargets::new(account(), vec![MessageId::new("m").unwrap()]).unwrap()),
                DispatchAuthorization::Automatic,
                DuplicateRiskConfirmation::NotConfirmed,
            )
            .unwrap(),
        ))
        .unwrap();
        let second = admit(&store, "second", &["m", "n"], &MessageAction::Star);
        let third = admit_label(&store, "third");
        store
            .connection
            .lock()
            .unwrap()
            .execute("UPDATE account_binding SET capability=0", [])
            .unwrap();
        drop(store);
        let store = SqlCipherMailboxStore::open(account(), db.path(), key(7)).unwrap();
        let reader = reader(&db);
        let expected = vec![receipt.snapshot().clone(), second, third];
        let before = (
            fs::read(db.path()).unwrap(),
            fs::read(wal_path(&db)).unwrap(),
        );
        assert_eq!(store.pending_commands(&bound()).unwrap(), expected);
        assert_eq!(reader.pending_commands(&bound()).unwrap(), expected);
        assert_eq!(
            reader.pending_commands(&bound()).unwrap()[0].status(),
            Status::Dispatching
        );
        assert_eq!(
            (
                fs::read(db.path()).unwrap(),
                fs::read(wal_path(&db)).unwrap()
            ),
            before
        );
        assert_eq!(reader.connection.lock().unwrap().total_changes(), 0);
        let ambiguous = run(store.recover_dispatching(&pre(receipt.snapshot()))).unwrap();
        assert_eq!(reader.pending_commands(&bound()).unwrap()[0], ambiguous);
        let attention =
            run(store
                .reconciliation_failed(&pre(&ambiguous), ReconciliationFailure::ReadUnavailable))
            .unwrap();
        assert_eq!(reader.pending_commands(&bound()).unwrap()[0], attention);
    }
    #[test]
    fn pending_bounds_are_complete_and_overflow_in_later_work_cannot_silently_truncate() {
        let (db, store) = setup("p7b-pending-bounds");
        grant(&store);
        for batch in 0..5 {
            let n = if batch == 4 { 96 } else { 1000 };
            let ids: Vec<_> = (0..n).map(|n| format!("m{n:04}")).collect();
            admit(
                &store,
                &format!("batch{batch}"),
                &ids.iter().map(String::as_str).collect::<Vec<_>>(),
                &MessageAction::Read,
            );
        }
        for n in 0..27 {
            admit_label(&store, &format!("label{n}"));
        }
        let reader = reader(&db);
        let pending = reader.pending_commands(&bound()).unwrap();
        assert_eq!(pending.len(), 32);
        assert_eq!(
            pending
                .iter()
                .map(|s| usize::from(s.counts().total()))
                .take(5)
                .sum::<usize>(),
            4096
        );
        store.connection.lock().unwrap().execute_batch("INSERT INTO mailbox_commands (command_id,revision,fifo,kind,status,label_name) VALUES('overflow',zeroblob(8),33,2,0,'name'); UPDATE mailbox_checkpoint SET next_fifo=34").unwrap();
        assert_eq!(reader.pending_commands(&bound()), Err(Error::Corrupt));
        store.connection.lock().unwrap().execute_batch("DELETE FROM mailbox_commands WHERE command_id='overflow'; INSERT INTO command_items(command_id,message_id) VALUES('batch4','extra'); INSERT INTO command_fields(command_id,message_id,field_id,user_label,desired) VALUES('batch4','extra','UNREAD',0,0)").unwrap();
        assert_eq!(reader.pending_commands(&bound()), Err(Error::Corrupt));
    }
    #[test]
    fn later_pending_evidence_corruption_and_fence_failures_reject_entire_read() {
        let (db, store) = setup("p7b-pending-corrupt");
        grant(&store);
        admit_label(&store, "first");
        admit(&store, "later", &["m"], &MessageAction::Read);
        let reader = reader(&db);
        assert_eq!(reader.pending_commands(&bound()).unwrap().len(), 2);
        store.connection.lock().unwrap().execute_batch("PRAGMA foreign_keys=OFF; INSERT INTO command_item_memberships VALUES('later','orphan','UNREAD'); PRAGMA foreign_keys=ON").unwrap();
        assert_eq!(reader.pending_commands(&bound()), Err(Error::Corrupt));
        store.connection.lock().unwrap().execute_batch("DELETE FROM command_item_memberships; UPDATE account_identity SET identity_hash=zeroblob(32)").unwrap();
        assert_eq!(
            reader.pending_commands(&bound()),
            Err(Error::IdentityChanged)
        );
        assert_eq!(
            store.pending_commands(&AccountFence::new(
                AccountId::new("foreign").unwrap(),
                fence()
            )),
            Err(Error::UnknownAccount)
        );
    }
    #[test]
    fn filtered_rows_reject_corrupt_envelopes_or_full_membership_instead_of_returning_partial_success()
     {
        for membership_overflow in [false, true] {
            let (db, store) = setup("p7b-filter-corrupt");
            run(store.upsert_envelopes(&account(), &[envelope("m", "thread", 1)])).unwrap();
            observe(&store, "m", &["INBOX"]);
            let reader = reader(&db);
            if membership_overflow {
                let c = store.connection.lock().unwrap();
                // Uncached corrupt state is outside this page, not an implicit FK/integrity walk.
                c.execute("INSERT INTO provider_messages VALUES('uncached',1)", [])
                    .unwrap();
                for n in 0..513 {
                    c.execute(
                        "INSERT INTO provider_memberships VALUES('uncached',?1)",
                        [format!("Label_{n}")],
                    )
                    .unwrap();
                }
                drop(c);
                assert_eq!(
                    reader
                        .list_filtered_envelopes_after(&account(), &Filter::Inbox, None, limit(1))
                        .unwrap()
                        .len(),
                    1
                );
                let c = store.connection.lock().unwrap();
                for n in 0..511 {
                    c.execute(
                        "INSERT INTO provider_memberships VALUES('m',?1)",
                        [format!("Label_{n}")],
                    )
                    .unwrap();
                }
                drop(c);
                assert_eq!(
                    reader
                        .list_filtered_envelopes_after(&account(), &Filter::Inbox, None, limit(1))
                        .unwrap()
                        .len(),
                    1
                );
                store
                    .connection
                    .lock()
                    .unwrap()
                    .execute(
                        "INSERT INTO provider_memberships VALUES('m','overflow')",
                        [],
                    )
                    .unwrap();
            } else {
                store
                    .connection
                    .lock()
                    .unwrap()
                    .execute_batch(
                        "PRAGMA ignore_check_constraints=ON; UPDATE messages SET unread=2",
                    )
                    .unwrap();
            }
            assert_eq!(
                reader.list_filtered_envelopes_after(&account(), &Filter::Inbox, None, limit(1)),
                Err(MailboxStoreError::Corrupted)
            );
        }
    }
    #[test]
    fn both_read_surfaces_avoid_body_pages_and_make_no_changes() {
        let (db, store) = setup("p7b-no-body");
        grant(&store);
        run(store.put_message(
            &account(),
            &Message::new(
                envelope("m", "thread", 1),
                MessageContent::new(vec![b'x'; 256 * 1024]).unwrap(),
            ),
        ))
        .unwrap();
        observe(&store, "m", &["INBOX"]);
        let pending = admit(&store, "pending", &["m"], &MessageAction::Star);
        store
            .connection
            .lock()
            .unwrap()
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .unwrap();
        let reader = reader(&db);
        drop(store);
        let mut bytes = fs::read(db.path()).unwrap();
        let middle = bytes.len() / 2;
        bytes[middle] ^= 0xff;
        fs::write(db.path(), bytes).unwrap();
        reader
            .connection
            .lock()
            .unwrap()
            .execute_batch("PRAGMA shrink_memory")
            .unwrap();
        let before = fs::read(db.path()).unwrap();
        assert_eq!(
            ids(&reader
                .list_filtered_envelopes_after(&account(), &Filter::Inbox, None, limit(201))
                .unwrap()),
            ["m"]
        );
        assert_eq!(reader.pending_commands(&bound()).unwrap(), [pending]);
        assert!(run(reader.get_message(&account(), &MessageId::new("m").unwrap())).is_err());
        assert_eq!(fs::read(db.path()).unwrap(), before);
        assert_eq!(reader.connection.lock().unwrap().total_changes(), 0);
    }
}
