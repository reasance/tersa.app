// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

mod p5b {
    use super::*;
    use crate::CachedProviderState;
    use tersa_application::{
        history::{
            CapturedBaseline, DecidedHistoryRecord, HistoryCursorStore, HistoryDecision,
            HistoryEvent, HistoryEventKind, HistoryPage, HistoryQuery, HistoryRecord,
            LocalHistoryPresence, ProviderContinuation, SnapshotCommit, SnapshotCoverage,
            SnapshotFallbackReason, TerminalHistoryCheckpoint,
        },
        mailbox::PageSize,
        mailbox_state::{
            MessageKey, MessageMetadata, MessageObservation, RemoteMessageState,
            TriageStoreError as Error,
        },
        profile::{AccountFence, AccountMetadataReader},
    };
    use tersa_domain::{
        history::HistoryCursor,
        label::{LabelCatalog, LabelDefinition, LabelId, LabelKind, LabelMembership, LabelName},
    };

    fn cursor(value: &str) -> HistoryCursor {
        HistoryCursor::new(value).unwrap()
    }
    fn bound() -> AccountFence {
        AccountFence::new(account(), fence())
    }
    fn message_key(id: &str) -> MessageKey {
        MessageKey::new(account(), MessageId::new(id).unwrap())
    }
    fn metadata(id: &str, at: i64, labels: &[&str]) -> MessageMetadata {
        MessageMetadata::new(
            message_key(id),
            envelope(id, "thread", at),
            LabelMembership::new(
                account(),
                labels.iter().map(|id| LabelId::new(*id).unwrap()).collect(),
            )
            .unwrap(),
        )
        .unwrap()
    }
    fn setup(name: &str) -> (TestDatabase, SqlCipherMailboxStore) {
        let (database, store) = open(name);
        record_fence(&store);
        (database, store)
    }
    fn snapshot_request(
        store: &SqlCipherMailboxStore,
        baseline: &str,
        metadata: Vec<MessageMetadata>,
    ) -> SnapshotCommit {
        let checkpoint = run(store.checkpoint(&bound())).unwrap();
        let reason = if checkpoint.cursor().is_none() {
            SnapshotFallbackReason::NoCursor
        } else {
            SnapshotFallbackReason::HistoryCursorExpired
        };
        SnapshotCommit::new(
            checkpoint,
            CapturedBaseline::new(account(), cursor(baseline)),
            metadata,
            SnapshotCoverage::RecentTruncated,
            reason,
        )
        .unwrap()
    }
    fn start(store: &SqlCipherMailboxStore, values: Vec<MessageMetadata>) {
        run(store.commit_snapshot(&snapshot_request(store, "10", values))).unwrap();
    }
    fn history_page(
        predecessor: &str,
        records: Vec<(&str, Vec<(&str, HistoryEventKind)>)>,
    ) -> HistoryPage {
        let records: Vec<_> = records
            .into_iter()
            .map(|(id, events)| {
                let count = events.len();
                HistoryRecord::new(
                    account(),
                    cursor(id),
                    events
                        .into_iter()
                        .map(|(id, kind)| HistoryEvent::new(message_key(id), kind).unwrap())
                        .collect(),
                    count,
                )
                .unwrap()
            })
            .collect();
        let count = records.len();
        HistoryPage::new(
            HistoryQuery::new(account(), cursor(predecessor), PageSize::new(25).unwrap()),
            cursor("999"),
            records,
            ProviderContinuation::End,
            None,
            count,
        )
        .unwrap()
    }
    fn decided(
        page: &HistoryPage,
        index: usize,
        decisions: Vec<HistoryDecision>,
    ) -> DecidedHistoryRecord {
        DecidedHistoryRecord::new(bound(), page, index, decisions).unwrap()
    }
    fn known(store: &SqlCipherMailboxStore, id: &str) -> CachedProviderState {
        store.cached_provider_state(&message_key(id)).unwrap()
    }
    fn raw_values(connection: &Connection, sql: &str) -> Vec<Vec<rusqlite::types::Value>> {
        let mut statement = connection.prepare(sql).unwrap();
        let columns = statement.column_count();
        statement
            .query_map([], |row| (0..columns).map(|i| row.get(i)).collect())
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
    }
    fn state(store: &SqlCipherMailboxStore) -> Vec<Vec<Vec<rusqlite::types::Value>>> {
        let c = store.connection.lock().unwrap();
        [
            "SELECT * FROM messages ORDER BY message_id",
            "SELECT * FROM provider_messages ORDER BY message_id",
            "SELECT * FROM provider_memberships ORDER BY message_id,label_id",
            "SELECT * FROM mailbox_checkpoint",
            "SELECT * FROM mailbox_commands ORDER BY command_id",
            "SELECT * FROM command_items ORDER BY command_id,message_id",
            "SELECT * FROM command_fields ORDER BY command_id,message_id,field_id",
            "SELECT * FROM mailbox_undo",
        ]
        .iter()
        .map(|sql| raw_values(&c, sql))
        .collect()
    }
    // Seeds durable rows directly; this is not P5c admission/transition evidence.
    fn seed_pin(store: &SqlCipherMailboxStore, command: &str, message: &str, undo: bool) {
        let c = store.connection.lock().unwrap();
        let fifo: i64 = c
            .query_row("SELECT next_fifo FROM mailbox_checkpoint", [], |r| r.get(0))
            .unwrap();
        c.execute("INSERT INTO mailbox_commands(command_id,revision,fifo,kind,status) VALUES (?1,zeroblob(8),?2,0,?3)",params![command,fifo,if undo {4} else {0}]).unwrap();
        c.execute(
            "INSERT INTO command_items(command_id,message_id,outcome) VALUES (?1,?2,?3)",
            params![command, message, if undo { Some(0) } else { None::<i32> }],
        )
        .unwrap();
        c.execute(
            "INSERT INTO command_fields VALUES (?1,?2,'UNREAD',0,0,?3,?4,NULL)",
            params![
                command,
                message,
                if undo { Some(1) } else { None::<i32> },
                if undo { Some(0) } else { None::<i32> }
            ],
        )
        .unwrap();
        if undo {
            c.execute("INSERT INTO mailbox_undo VALUES(1,?1)", [command])
                .unwrap();
        }
        c.execute(
            "UPDATE mailbox_checkpoint SET next_fifo = next_fifo + 1",
            [],
        )
        .unwrap();
    }
    fn fail_commit(store: &SqlCipherMailboxStore, trigger: &str) {
        store.connection.lock().unwrap().execute_batch(&format!(
            "CREATE TEMP TABLE failure_parent(id INTEGER PRIMARY KEY);
             CREATE TEMP TABLE failure_child(id INTEGER REFERENCES failure_parent(id) DEFERRABLE INITIALLY DEFERRED);
             CREATE TEMP TRIGGER failure AFTER {trigger} BEGIN INSERT INTO failure_child VALUES(1); END;"
        )).unwrap();
    }

    // Metadata/membership/cursor stay indivisible; sticky display and body custody remain separate.
    #[test]
    fn history_records_keep_exact_cursor_prefix_bodies_and_sticky_read_state() {
        let (database, store) = setup("p5b-prefix");
        let old = Message::new(
            envelope("a", "thread", 1),
            MessageContent::new(b"body sentinel".to_vec()).unwrap(),
        );
        run(store.put_message(&account(), &old)).unwrap();
        run(store.mark_message_read(&account(), &MessageId::new("a").unwrap())).unwrap();
        start(&store, vec![metadata("a", 1, &[])]);
        let page = history_page(
            "10",
            vec![
                ("14", vec![("a", HistoryEventKind::Changed)]),
                ("29", vec![("b", HistoryEventKind::Added)]),
            ],
        );
        let first = decided(
            &page,
            0,
            vec![HistoryDecision::Metadata(metadata(
                "a",
                4,
                &["UNREAD", "Label_a"],
            ))],
        );
        assert_eq!(
            run(store.apply_record(&first)).unwrap().cursor(),
            Some(&cursor("14"))
        );
        let cached = run(store.list_envelopes(&account(), StoreLimit::new(10).unwrap())).unwrap();
        assert!(!cached[0].is_unread());
        assert_eq!(
            run(store.get_message(&account(), &MessageId::new("a").unwrap()))
                .unwrap()
                .unwrap()
                .content()
                .as_bytes(),
            b"body sentinel"
        );
        assert!(
            matches!(known(&store,"a"),CachedProviderState::Known(labels) if labels.ids().len() == 2)
        );
        let before = state(&store);
        // A real SQL error after envelope/membership attempts must retain the first complete record.
        store.connection.lock().unwrap().execute_batch("CREATE TEMP TRIGGER reject_cursor BEFORE UPDATE OF history_cursor ON main.mailbox_checkpoint BEGIN SELECT RAISE(ABORT,'fixture'); END;").unwrap();
        assert_eq!(
            run(store
                .checkpoint_chain_end(&TerminalHistoryCheckpoint::new(bound(), &page).unwrap())),
            Err(Error::Conflict)
        );
        let second = decided(
            &page,
            1,
            vec![HistoryDecision::Metadata(metadata("b", 5, &[]))],
        );
        assert_eq!(run(store.apply_record(&second)), Err(Error::Storage));
        assert_eq!(state(&store), before);
        store
            .connection
            .lock()
            .unwrap()
            .execute_batch("DROP TRIGGER reject_cursor")
            .unwrap();
        drop(store);
        let store = SqlCipherMailboxStore::open(account(), database.path(), key(7)).unwrap();
        assert_eq!(
            run(store.checkpoint(&bound())).unwrap().cursor(),
            Some(&cursor("14"))
        );
        assert_eq!(run(store.apply_record(&first)), Err(Error::Conflict));
        assert_eq!(
            run(store.apply_record(&second)).unwrap().cursor(),
            Some(&cursor("29"))
        );
        assert_eq!(
            known(&store, "b"),
            CachedProviderState::Known(LabelMembership::new(account(), vec![]).unwrap())
        );
        let terminal = TerminalHistoryCheckpoint::new(bound(), &page).unwrap();
        assert_eq!(
            run(store.checkpoint_chain_end(&terminal)).unwrap().cursor(),
            Some(&cursor("999"))
        );
    }

    #[test]
    fn record_and_snapshot_deferred_commit_failure_roll_back_all_attempted_rows() {
        for snapshot in [false, true] {
            let (_database, store) = setup("p5b-commit-rollback");
            start(
                &store,
                if snapshot {
                    (0..100)
                        .map(|n| metadata(&format!("old-{n:03}"), 1, &["UNREAD"]))
                        .collect()
                } else {
                    vec![metadata("old", 1, &["UNREAD"])]
                },
            );
            let before = state(&store);
            fail_commit(
                &store,
                "UPDATE OF history_cursor ON main.mailbox_checkpoint",
            );
            let attempt = || {
                if snapshot {
                    run(store.commit_snapshot(&snapshot_request(
                        &store,
                        "50",
                        (0..100)
                            .map(|n| metadata(&format!("new-{n:03}"), 9, &["Label_a"]))
                            .collect(),
                    )))
                } else {
                    let page = history_page(
                        "10",
                        vec![(
                            "12",
                            vec![
                                ("new", HistoryEventKind::Added),
                                ("old", HistoryEventKind::Changed),
                            ],
                        )],
                    );
                    run(store.apply_record(&decided(
                        &page,
                        0,
                        vec![
                            HistoryDecision::Metadata(metadata("new", 9, &[])),
                            HistoryDecision::Metadata(metadata("old", 2, &[])),
                        ],
                    )))
                }
            };
            let result = attempt();
            assert_eq!(result, Err(Error::Storage));
            assert_eq!(state(&store), before);
            assert!(store.connection.lock().unwrap().is_autocommit());
            store
                .connection
                .lock()
                .unwrap()
                .execute_batch("DROP TRIGGER failure")
                .unwrap();
            assert_eq!(
                attempt().unwrap().cursor(),
                Some(&cursor(if snapshot { "50" } else { "12" }))
            );
        }
    }

    // Wrong owner, moved/absent/corrupt identity and stale predecessor cannot advance any cursor.
    #[test]
    fn history_identity_and_predecessor_fences_reject_without_provisioning_or_partial_application()
    {
        let (_database, store) = setup("p5b-fences");
        start(&store, vec![]);
        let before = state(&store);
        let foreign = AccountFence::new(AccountId::new("other").unwrap(), fence());
        assert_eq!(run(store.checkpoint(&foreign)), Err(Error::UnknownAccount));
        let wrong = AccountFence::new(account(), IdentityHash::from_bytes([1; 32]));
        assert_eq!(run(store.checkpoint(&wrong)), Err(Error::IdentityChanged));
        let page = history_page("11", vec![("12", vec![("a", HistoryEventKind::Added)])]);
        let stale = decided(
            &page,
            0,
            vec![HistoryDecision::Metadata(metadata("a", 1, &[]))],
        );
        assert_eq!(run(store.apply_record(&stale)), Err(Error::Conflict));
        let end = TerminalHistoryCheckpoint::new(bound(), &page).unwrap();
        assert_eq!(run(store.checkpoint_chain_end(&end)), Err(Error::Conflict));
        assert_eq!(state(&store), before);
        for sql in [
            "DELETE FROM account_identity",
            "INSERT INTO account_identity VALUES ('account-a',X'00',2)",
        ] {
            store.connection.lock().unwrap().execute_batch(sql).unwrap();
            assert_eq!(
                run(store.checkpoint(&bound())),
                Err(if sql.starts_with("DELETE") {
                    Error::IdentityChanged
                } else {
                    Error::Corrupt
                })
            );
            assert_eq!(state(&store), before);
        }
    }

    // Target acquisition after classification invalidates Irrelevant inside the actual writer transaction.
    #[test]
    fn irrelevant_classification_is_rechecked_after_pin_or_cache_races() {
        for pinned in [false, true] {
            let (_database, store) = setup("p5b-pin-race");
            start(&store, vec![]);
            let page = history_page(
                "10",
                vec![(
                    "12",
                    vec![
                        ("aa-new", HistoryEventKind::Added),
                        ("target", HistoryEventKind::Changed),
                    ],
                )],
            );
            let local = run(store.classify_record(&bound(), &page.records()[0])).unwrap();
            assert_eq!(local.states()[0].1, LocalHistoryPresence::OutsideCache);
            let request = decided(
                &page,
                0,
                vec![
                    HistoryDecision::Metadata(metadata("aa-new", 9, &[])),
                    HistoryDecision::Irrelevant(message_key("target")),
                ],
            );
            if pinned {
                seed_pin(&store, "pending", "target", false);
            } else {
                run(store.upsert_envelopes(&account(), &[envelope("target", "thread", 1)]))
                    .unwrap();
            }
            let before = state(&store);
            assert_eq!(run(store.apply_record(&request)), Err(Error::Conflict));
            assert_eq!(state(&store), before);
        }
    }

    // Cache/pin classification and deterministic top-100 retention preserve both pin families.
    #[test]
    fn pruning_keeps_pending_and_undo_pins_and_missing_never_settles_them() {
        let (database, store) = setup("p5b-pins");
        seed_pin(&store, "pending", "old-pending", false);
        seed_pin(&store, "undo", "old-undo", true);
        start(
            &store,
            vec![
                metadata("old-pending", 1, &["UNREAD"]),
                metadata("old-undo", 1, &[]),
            ],
        );
        let page = history_page(
            "10",
            vec![(
                "12",
                vec![
                    ("old-pending", HistoryEventKind::Changed),
                    ("outside", HistoryEventKind::Changed),
                ],
            )],
        );
        let local = run(store.classify_record(&bound(), &page.records()[0])).unwrap();
        assert_eq!(local.states()[0].1, LocalHistoryPresence::CachedAndPinned);
        assert_eq!(local.states()[1].1, LocalHistoryPresence::OutsideCache);
        let values = (0..100)
            .rev()
            .map(|n| metadata(&format!("new-{n:03}"), 20, &[]))
            .collect();
        run(store.commit_snapshot(&snapshot_request(&store, "30", values))).unwrap();
        let cache = run(store.list_envelopes(&account(), StoreLimit::new(200).unwrap())).unwrap();
        assert_eq!(cache.len(), 102);
        assert_eq!(cache[0].message_id().as_str(), "new-000");
        assert_eq!(
            known(&store, "old-pending"),
            CachedProviderState::Known(
                LabelMembership::new(account(), vec![LabelId::new("UNREAD").unwrap()]).unwrap()
            )
        );
        let queue_before = {
            let c = store.connection.lock().unwrap();
            [
                "SELECT * FROM mailbox_commands ORDER BY command_id",
                "SELECT * FROM command_items ORDER BY command_id",
                "SELECT * FROM command_fields ORDER BY command_id",
                "SELECT * FROM mailbox_undo",
            ]
            .iter()
            .map(|sql| raw_values(&c, sql))
            .collect::<Vec<_>>()
        };
        let page = history_page(
            "30",
            vec![("31", vec![("old-pending", HistoryEventKind::Deleted)])],
        );
        let missing =
            MessageObservation::new(message_key("old-pending"), RemoteMessageState::Missing)
                .unwrap();
        run(store.apply_record(&decided(&page, 0, vec![HistoryDecision::Observe(missing)])))
            .unwrap();
        assert_eq!(known(&store, "old-pending"), CachedProviderState::Missing);
        let local = run(store.classify_record(&bound(), &page.records()[0])).unwrap();
        assert_eq!(local.states()[0].1, LocalHistoryPresence::Pinned);
        let c = store.connection.lock().unwrap();
        let queue_after = [
            "SELECT * FROM mailbox_commands ORDER BY command_id",
            "SELECT * FROM command_items ORDER BY command_id",
            "SELECT * FROM command_fields ORDER BY command_id",
            "SELECT * FROM mailbox_undo",
        ]
        .iter()
        .map(|sql| raw_values(&c, sql))
        .collect::<Vec<_>>();
        assert_eq!(queue_after, queue_before);
        drop(c);
        drop(store);
        let store = SqlCipherMailboxStore::open(account(), database.path(), key(7)).unwrap();
        assert_eq!(known(&store, "old-pending"), CachedProviderState::Missing);
        assert!(matches!(
            known(&store, "old-undo"),
            CachedProviderState::Known(_)
        ));
    }

    #[test]
    fn record_additions_compete_for_keep_100_and_irrelevant_observations_do_not_accumulate() {
        let (_database, store) = setup("p5b-retention");
        start(
            &store,
            (0..100)
                .map(|n| metadata(&format!("m{n:03}"), 10, &[]))
                .collect(),
        );
        let page = history_page(
            "10",
            vec![(
                "12",
                vec![
                    ("aa", HistoryEventKind::Added),
                    ("zz", HistoryEventKind::Added),
                    ("irrelevant", HistoryEventKind::Deleted),
                ],
            )],
        );
        let decisions = vec![
            HistoryDecision::Metadata(metadata("aa", 10, &[])),
            HistoryDecision::Metadata(metadata("zz", 1, &[])),
            HistoryDecision::Observe(
                MessageObservation::new(message_key("irrelevant"), RemoteMessageState::Missing)
                    .unwrap(),
            ),
        ];
        run(store.apply_record(&decided(&page, 0, decisions))).unwrap();
        let cache = run(store.list_envelopes(&account(), StoreLimit::new(200).unwrap())).unwrap();
        assert_eq!(cache.len(), 100);
        assert_eq!(cache[0].message_id().as_str(), "aa");
        assert_eq!(known(&store, "zz"), CachedProviderState::Unknown);
        assert_eq!(known(&store, "m099"), CachedProviderState::Unknown);
        assert_eq!(known(&store, "irrelevant"), CachedProviderState::Unknown);
    }

    #[test]
    fn exact_membership_consumers_reject_overflow_malformed_and_orphan_children() {
        for damage in [
            "INSERT INTO provider_memberships VALUES ('target','orphan')",
            "INSERT INTO provider_messages VALUES('target',0); INSERT INTO provider_memberships VALUES('target','orphan')",
            "INSERT INTO provider_messages VALUES('target',1); WITH RECURSIVE n(x) AS (VALUES(0) UNION ALL SELECT x+1 FROM n WHERE x < 512) INSERT INTO provider_memberships SELECT 'target','Label_'||x FROM n",
            "INSERT INTO provider_messages VALUES('target',1); INSERT INTO provider_memberships VALUES('target','bad/path')",
            "INSERT INTO provider_messages VALUES('target',99)",
        ] {
            let (_database, store) = setup("p5b-membership-corrupt");
            start(&store, vec![]);
            store.connection.lock().unwrap().execute_batch(&format!("PRAGMA foreign_keys = OFF; PRAGMA ignore_check_constraints = ON; {damage}; PRAGMA foreign_keys = ON; PRAGMA ignore_check_constraints = OFF;")).unwrap();
            let before = state(&store);
            assert_eq!(
                store.cached_provider_state(&message_key("target")),
                Err(Error::Corrupt)
            );
            let page = history_page(
                "10",
                vec![("11", vec![("target", HistoryEventKind::Changed)])],
            );
            let request = decided(
                &page,
                0,
                vec![HistoryDecision::Metadata(metadata("target", 1, &[]))],
            );
            assert_eq!(run(store.apply_record(&request)), Err(Error::Corrupt));
            assert_eq!(state(&store), before);
        }
    }

    // Skip consumers must not conceal dangling command/undo relationships through inner joins.
    #[test]
    fn pin_readers_fail_closed_on_orphans_missing_targets_invalid_masks_and_overflow() {
        for damage in [
            "INSERT INTO command_items(command_id,message_id) VALUES('orphan','target')",
            "INSERT INTO mailbox_undo VALUES(1,'missing-command')",
            "INSERT INTO mailbox_commands(command_id,revision,fifo,kind,status) VALUES('empty',zeroblob(8),1,0,0)",
            "INSERT INTO command_fields VALUES('orphan','target','UNREAD',0,0,NULL,NULL,NULL)",
            "INSERT INTO mailbox_commands(command_id,revision,fifo,kind,status) VALUES('pending',zeroblob(8),1,0,0); INSERT INTO command_items(command_id,message_id) VALUES('pending','target')",
            "INSERT INTO mailbox_commands(command_id,revision,fifo,kind,status) VALUES('pending',zeroblob(8),1,0,0); INSERT INTO command_items(command_id,message_id) VALUES('pending','target'); INSERT INTO command_fields VALUES('pending','target','UNREAD',0,0,NULL,NULL,NULL),('pending','target','STARRED',0,0,NULL,NULL,NULL)",
            "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x < 34) INSERT INTO mailbox_commands(command_id,revision,fifo,kind,status,label_name) SELECT 'c'||x,zeroblob(8),x,2,0,'name' FROM n",
        ] {
            let (_database, store) = setup("p5b-pin-corrupt");
            start(&store, vec![]);
            store
                .connection
                .lock()
                .unwrap()
                .execute_batch(&format!(
                    "PRAGMA foreign_keys = OFF; {damage}; PRAGMA foreign_keys = ON;"
                ))
                .unwrap();
            let before = state(&store);
            let page = history_page(
                "10",
                vec![("12", vec![("target", HistoryEventKind::Changed)])],
            );
            assert_eq!(
                run(store.classify_record(&bound(), &page.records()[0])),
                Err(Error::Corrupt)
            );
            let request = decided(
                &page,
                0,
                vec![HistoryDecision::Irrelevant(message_key("target"))],
            );
            assert_eq!(run(store.apply_record(&request)), Err(Error::Corrupt));
            assert_eq!(state(&store), before);
        }
    }
    #[test]
    fn cached_catalog_is_bounded_exact_and_atomic_without_rewriting_membership() {
        let (_database, store) = setup("p5b-catalog");
        start(&store, vec![metadata("a", 1, &["UNREAD"])]);
        let membership = known(&store, "a");
        assert_eq!(store.cached_label_catalog(&account()).unwrap(), None);
        let empty = LabelCatalog::new(account(), vec![]).unwrap();
        store
            .replace_cached_label_catalog(&bound(), &empty)
            .unwrap();
        assert_eq!(
            store.cached_label_catalog(&account()).unwrap(),
            Some(empty.clone())
        );
        let value = LabelCatalog::new(
            account(),
            vec![
                LabelDefinition::new(
                    account(),
                    LabelId::new("Label_a").unwrap(),
                    LabelName::new(" e\u{301}\0\n\u{202e}é ").unwrap(),
                    LabelKind::User,
                )
                .unwrap(),
            ],
        )
        .unwrap();
        store
            .replace_cached_label_catalog(&bound(), &value)
            .unwrap();
        assert_eq!(
            store.cached_label_catalog(&account()).unwrap(),
            Some(value.clone())
        );
        assert_eq!(known(&store, "a"), membership);
        let wrong = AccountFence::new(account(), IdentityHash::from_bytes([1; 32]));
        assert_eq!(
            store.replace_cached_label_catalog(&wrong, &empty),
            Err(Error::IdentityChanged)
        );
        fail_commit(&store, "UPDATE OF catalog_known ON main.mailbox_checkpoint");
        assert_eq!(
            store.replace_cached_label_catalog(&bound(), &empty),
            Err(Error::Storage)
        );
        assert_eq!(store.cached_label_catalog(&account()).unwrap(), Some(value));
        assert_eq!(known(&store, "a"), membership);
    }

    #[test]
    fn cached_catalog_rejects_overflow_bad_definitions_and_unknown_with_rows() {
        for damage in [
            "WITH RECURSIVE n(x) AS (VALUES(0) UNION ALL SELECT x+1 FROM n WHERE x < 500) INSERT INTO provider_labels SELECT 'Label_'||x,'name',1 FROM n",
            "INSERT INTO provider_labels VALUES('UNREAD','name',1)",
            "INSERT INTO provider_labels VALUES('bad/path','name',1)",
            "INSERT INTO provider_labels VALUES('Label_a','name',99)",
            "INSERT INTO provider_labels VALUES('Label_a',replace(hex(zeroblob(1025)),'0','a'),1)",
            "INSERT INTO provider_labels VALUES('Label_a','name',1); UPDATE mailbox_checkpoint SET catalog_known = 0",
        ] {
            let (_database, store) = setup("p5b-catalog-corrupt");
            store.connection.lock().unwrap().execute_batch(&format!("PRAGMA ignore_check_constraints = ON; UPDATE mailbox_checkpoint SET catalog_known = 1; {damage}; PRAGMA ignore_check_constraints = OFF;")).unwrap();
            assert_eq!(store.cached_label_catalog(&account()), Err(Error::Corrupt));
            let before = raw_values(
                &store.connection.lock().unwrap(),
                "SELECT * FROM provider_labels ORDER BY label_id",
            );
            assert_eq!(
                store.replace_cached_label_catalog(
                    &bound(),
                    &LabelCatalog::new(account(), vec![]).unwrap()
                ),
                Err(Error::Corrupt)
            );
            assert_eq!(
                raw_values(
                    &store.connection.lock().unwrap(),
                    "SELECT * FROM provider_labels ORDER BY label_id"
                ),
                before
            );
        }
    }

    #[test]
    fn readonly_v1_v2_v3_profiles_and_unknown_provider_metadata_never_migrate_or_write() {
        for version in [1, 2, 3] {
            let (database, anchor) = if version < 3 {
                let (database, anchor) = version_1_store("p5b-legacy-reader");
                if version == 2 {
                    anchor.execute_batch(MIGRATION_V2_ACCOUNT_EMAIL).unwrap();
                    anchor.pragma_update(None, "user_version", 2).unwrap();
                }
                anchor
                    .execute(
                        "UPDATE account_binding SET broker_subject = 'reader-subject'",
                        [],
                    )
                    .unwrap();
                (database, anchor)
            } else {
                let (database, store) = setup("p5b-current-reader");
                store
                    .store_broker_subject(&account(), "reader-subject")
                    .unwrap();
                store
                    .connection
                    .lock()
                    .unwrap()
                    .execute("UPDATE account_binding SET capability = 1", [])
                    .unwrap();
                let anchor = raw_existing_connection(&database);
                apply_key(&anchor, &key(7).0).unwrap();
                (database, anchor)
            };
            let main = fs::read(database.path()).unwrap();
            let wal = fs::read(wal_path(&database)).unwrap();
            let reader =
                SqlCipherMailboxReader::open_read_only(account(), database.path(), key(7)).unwrap();
            let metadata = run(reader.read_metadata(&account())).unwrap().unwrap();
            assert!(metadata.email().is_none());
            assert_eq!(
                metadata.capability(),
                if version == 3 {
                    AccountCapability::Modify
                } else {
                    AccountCapability::ReadOnly
                }
            );
            assert_eq!(
                reader.cached_provider_state(&message_key("m1")).unwrap(),
                CachedProviderState::Unknown
            );
            assert!(reader.cached_label_catalog(&account()).unwrap().is_none());
            assert_eq!(
                run(reader.read_upgrade_binding(&account()))
                    .unwrap()
                    .unwrap()
                    .expected_subject()
                    .as_str(),
                "reader-subject"
            );
            assert!(
                run(reader.read_metadata(&AccountId::new("unknown").unwrap()))
                    .unwrap()
                    .is_none()
            );
            assert_eq!(
                anchor
                    .query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
                    .unwrap(),
                version
            );
            assert_eq!(reader.connection.lock().unwrap().total_changes(), 0);
            drop(reader);
            assert_eq!(fs::read(database.path()).unwrap(), main);
            assert_eq!(fs::read(wal_path(&database)).unwrap(), wal);
            if version < 3 {
                let held =
                    SqlCipherMailboxReader::open_read_only(account(), database.path(), key(7))
                        .unwrap();
                let _writer =
                    SqlCipherMailboxStore::open(account(), database.path(), key(7)).unwrap();
                assert!(
                    run(held.read_metadata(&account()))
                        .unwrap()
                        .unwrap()
                        .email()
                        .is_none()
                );
                assert_eq!(
                    held.cached_provider_state(&message_key("m1")).unwrap(),
                    CachedProviderState::Unknown
                );
                assert!(held.cached_label_catalog(&account()).unwrap().is_none());
                assert_eq!(
                    run(held.read_upgrade_binding(&account()))
                        .unwrap()
                        .unwrap()
                        .expected_subject()
                        .as_str(),
                    "reader-subject"
                );
                assert_eq!(held.connection.lock().unwrap().total_changes(), 0);
            }
        }
    }

    // New cached/profile reads strengthen the constructor-only legacy path boundary.
    #[test]
    fn new_readonly_entrypoints_reject_replaced_main_or_missing_sidecar_without_repair() {
        for operation in 0..4 {
            for fault in 0..3 {
                let (database, store) = setup("p5b-reader-path");
                store
                    .store_broker_subject(&account(), "reader-subject")
                    .unwrap();
                let reader =
                    SqlCipherMailboxReader::open_read_only(account(), database.path(), key(7))
                        .unwrap();
                match fault {
                    0 => {
                        fs::rename(database.path(), database.path().with_extension("moved"))
                            .unwrap();
                        fs::write(database.path(), b"replacement").unwrap();
                    }
                    1 => {
                        fs::remove_file(wal_path(&database)).unwrap();
                    }
                    _ => {
                        fs::set_permissions(shm_path(&database), fs::Permissions::from_mode(0o640))
                            .unwrap();
                    }
                }
                let main = fs::read(database.path()).unwrap();
                let wal = fs::read(wal_path(&database)).ok();
                let failed = match operation {
                    0 => reader.cached_provider_state(&message_key("m1")).is_err(),
                    1 => reader.cached_label_catalog(&account()).is_err(),
                    2 => run(reader.read_metadata(&account())).is_err(),
                    _ => run(reader.read_upgrade_binding(&account())).is_err(),
                };
                assert!(failed, "operation {operation} fault {fault}");
                assert_eq!(fs::read(database.path()).unwrap(), main);
                assert_eq!(fs::read(wal_path(&database)).ok(), wal);
                assert_eq!(reader.connection.lock().unwrap().total_changes(), 0);
            }
        }
    }

    // A corrupt body overflow page cannot turn metadata-only reads into body scans.
    #[test]
    fn new_metadata_reads_and_classification_do_not_visit_cached_body_pages() {
        let (database, store) = setup("p5b-no-body-scan");
        store
            .store_broker_subject(&account(), "reader-subject")
            .unwrap();
        start(&store, vec![metadata("a", 1, &[])]);
        run(store.put_message(
            &account(),
            &Message::new(
                envelope("a", "thread", 1),
                MessageContent::new(vec![b'x'; 256 * 1024]).unwrap(),
            ),
        ))
        .unwrap();
        store
            .connection
            .lock()
            .unwrap()
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .unwrap();
        let reader =
            SqlCipherMailboxReader::open_read_only(account(), database.path(), key(7)).unwrap();
        drop(store);
        let mut bytes = fs::read(database.path()).unwrap();
        let middle = bytes.len() / 2;
        bytes[middle] ^= 0xff;
        fs::write(database.path(), bytes).unwrap();
        reader
            .connection
            .lock()
            .unwrap()
            .execute_batch("PRAGMA shrink_memory")
            .unwrap();
        assert!(matches!(
            reader.cached_provider_state(&message_key("a")).unwrap(),
            CachedProviderState::Known(_)
        ));
        assert!(reader.cached_label_catalog(&account()).unwrap().is_none());
        assert!(run(reader.read_metadata(&account())).unwrap().is_some());
        assert!(
            run(reader.read_upgrade_binding(&account()))
                .unwrap()
                .is_some()
        );
        let store = SqlCipherMailboxStore::open_with_scan(
            account(),
            database.path(),
            key(7),
            IntegrityScan::Skip,
        )
        .unwrap();
        let page = history_page("10", vec![("12", vec![("a", HistoryEventKind::Changed)])]);
        assert_eq!(
            run(store.classify_record(&bound(), &page.records()[0]))
                .unwrap()
                .states()[0]
                .1,
            LocalHistoryPresence::Cached
        );
        assert!(run(store.get_message(&account(), &MessageId::new("a").unwrap())).is_err());
        assert_eq!(reader.connection.lock().unwrap().total_changes(), 0);
    }
    #[test]
    fn history_accepts_validated_observations_without_a_usable_grant_and_unpolled_writes_do_nothing()
     {
        let (_database, store) = setup("p5b-no-usable-grant");
        store
            .store_broker_subject(&account(), "bound-subject")
            .unwrap();
        let expected = store.load_credential_snapshot(&account()).unwrap();
        store
            .replace_credential_snapshot(
                &expected,
                AccountCapability::Modify,
                &StoreCredential::RevocationOnly(Zeroizing::new(
                    "revocation-only-fixture".to_owned(),
                )),
            )
            .unwrap();
        assert!(store.load_refresh_token(&account()).is_err());
        let request = snapshot_request(&store, "10", vec![metadata("a", 1, &[])]);
        let before = state(&store);
        drop(store.commit_snapshot(&request));
        assert_eq!(state(&store), before);
        run(store.commit_snapshot(&request)).unwrap();
        let page = history_page("10", vec![("11", vec![("a", HistoryEventKind::Changed)])]);
        let request = decided(
            &page,
            0,
            vec![HistoryDecision::Metadata(metadata("a", 2, &["UNREAD"]))],
        );
        let before = state(&store);
        drop(store.apply_record(&request));
        assert_eq!(state(&store), before);
        assert_eq!(
            run(store.apply_record(&request)).unwrap().cursor(),
            Some(&cursor("11"))
        );
    }

    #[test]
    fn exact_key_read_does_not_scan_unrelated_membership_and_enforces_batch_key_bounds() {
        let (_database, store) = setup("p5b-exact-key");
        start(&store, vec![metadata("a", 1, &[])]);
        store.connection.lock().unwrap().execute_batch("INSERT INTO provider_messages VALUES('unrelated',1); WITH RECURSIVE n(x) AS (VALUES(0) UNION ALL SELECT x+1 FROM n WHERE x < 512) INSERT INTO provider_memberships SELECT 'unrelated','Label_'||x FROM n").unwrap();
        assert!(
            matches!(known(&store,"a"),CachedProviderState::Known(labels) if labels.ids().is_empty())
        );
        assert_eq!(
            store.cached_provider_state(&message_key("unrelated")),
            Err(Error::Corrupt)
        );
        let id = MessageId::new("a").unwrap();
        assert_eq!(
            store.cached_provider_states(&account(), &vec![id.clone(); 201]),
            Err(Error::QuotaExceeded)
        );
        assert_eq!(
            store.cached_provider_states(&account(), &[id.clone(), id.clone()]),
            Err(Error::Conflict)
        );
        assert_eq!(
            store.cached_provider_states(
                &AccountId::new("foreign").unwrap(),
                std::slice::from_ref(&id)
            ),
            Err(Error::UnknownAccount)
        );
        let rows = store
            .cached_provider_states(&account(), &[MessageId::new("unknown").unwrap(), id])
            .unwrap();
        assert_eq!(rows[0].key(), &message_key("unknown"));
        assert_eq!(rows[0].state(), &CachedProviderState::Unknown);
        assert_eq!(rows[1].key(), &message_key("a"));
    }
    #[test]
    fn a_thousand_target_record_commits_once_and_exact_membership_and_catalog_bounds_are_usable() {
        let (_database, store) = setup("p5b-max-record");
        start(&store, vec![]);
        let ids: Vec<_> = (0..1000).map(|n| format!("m{n:04}")).collect();
        let page = history_page(
            "10",
            vec![(
                "11",
                ids.iter()
                    .map(|id| (id.as_str(), HistoryEventKind::Added))
                    .collect(),
            )],
        );
        let request = decided(
            &page,
            0,
            ids.iter()
                .enumerate()
                .map(|(n, id)| {
                    HistoryDecision::Metadata(metadata(id, i64::try_from(n).unwrap(), &[]))
                })
                .collect(),
        );
        assert_eq!(
            run(store.apply_record(&request)).unwrap().cursor(),
            Some(&cursor("11"))
        );
        let cache = run(store.list_envelopes(&account(), StoreLimit::new(200).unwrap())).unwrap();
        assert_eq!(cache.len(), 100);
        assert_eq!(cache[0].message_id().as_str(), "m0999");
        let labels: Vec<_> = (0..512).map(|n| format!("Label_{n}")).collect();
        let page = history_page(
            "11",
            vec![("12", vec![("m0999", HistoryEventKind::Changed)])],
        );
        let request = decided(
            &page,
            0,
            vec![HistoryDecision::Metadata(metadata(
                "m0999",
                999,
                &labels.iter().map(String::as_str).collect::<Vec<_>>(),
            ))],
        );
        run(store.apply_record(&request)).unwrap();
        assert!(
            matches!(known(&store,"m0999"),CachedProviderState::Known(membership) if membership.ids().len() == 512)
        );
        let catalog = LabelCatalog::new(
            account(),
            (0..500)
                .map(|n| {
                    LabelDefinition::new(
                        account(),
                        LabelId::new(format!("Label_{n}")).unwrap(),
                        LabelName::new("same exact name").unwrap(),
                        LabelKind::User,
                    )
                    .unwrap()
                })
                .collect(),
        )
        .unwrap();
        store
            .replace_cached_label_catalog(&bound(), &catalog)
            .unwrap();
        assert_eq!(
            store.cached_label_catalog(&account()).unwrap(),
            Some(catalog)
        );
        assert!(
            matches!(known(&store,"m0999"),CachedProviderState::Known(membership) if membership.ids().len() == 512)
        );
    }
    #[test]
    fn upgrade_binding_rejects_missing_subject_and_unreadable_or_foreign_identity_as_corrupt() {
        for damage in [
            "UPDATE account_binding SET broker_subject = NULL",
            "UPDATE account_binding SET broker_subject = 'invalid subject'",
            "UPDATE account_identity SET identity_hash = X'00'",
            "UPDATE account_identity SET algo_version = 1",
            "INSERT INTO account_identity SELECT 'other-account',identity_hash,algo_version FROM account_identity",
        ] {
            let (_database, store) = setup("p5b-binding-corrupt");
            store
                .store_broker_subject(&account(), "bound-subject")
                .unwrap();
            store
                .connection
                .lock()
                .unwrap()
                .execute_batch(damage)
                .unwrap();
            assert!(matches!(
                run(store.read_upgrade_binding(&account())),
                Err(Error::Corrupt)
            ));
            assert!(
                run(store.read_upgrade_binding(&AccountId::new("unknown").unwrap()))
                    .unwrap()
                    .is_none()
            );
        }
    }
    #[test]
    fn snapshot_owner_identity_and_cursor_cas_fail_before_changing_metadata_or_baseline() {
        use tersa_application::history::HistoryCheckpoint;
        let (_database, store) = setup("p5b-snapshot-fences");
        start(&store, vec![metadata("old", 1, &[])]);
        let before = state(&store);
        for (fence, prior, error) in [
            (
                AccountFence::new(AccountId::new("other").unwrap(), fence()),
                "10",
                Error::UnknownAccount,
            ),
            (
                AccountFence::new(account(), IdentityHash::from_bytes([1; 32])),
                "10",
                Error::IdentityChanged,
            ),
            (bound(), "11", Error::Conflict),
        ] {
            let snapshot = SnapshotCommit::new(
                HistoryCheckpoint::new(fence.clone(), Some(cursor(prior))),
                CapturedBaseline::new(fence.account_id().clone(), cursor("50")),
                vec![],
                SnapshotCoverage::RecentChainEnded,
                SnapshotFallbackReason::HistoryCursorExpired,
            )
            .unwrap();
            assert_eq!(run(store.commit_snapshot(&snapshot)), Err(error));
            let record =
                HistoryRecord::new(fence.account_id().clone(), cursor("12"), vec![], 0).unwrap();
            let page = HistoryPage::new(
                HistoryQuery::new(
                    fence.account_id().clone(),
                    cursor(prior),
                    PageSize::new(25).unwrap(),
                ),
                cursor("50"),
                vec![record],
                ProviderContinuation::End,
                None,
                1,
            )
            .unwrap();
            let request = DecidedHistoryRecord::new(fence, &page, 0, vec![]).unwrap();
            assert_eq!(run(store.apply_record(&request)), Err(error));
            assert_eq!(state(&store), before);
        }
    }
    #[test]
    fn history_writes_refuse_disabled_foreign_key_enforcement_without_mutation() {
        let (_database, store) = setup("p5b-foreign-key-enforcement");
        let request = snapshot_request(&store, "10", vec![metadata("a", 1, &[])]);
        let before = state(&store);
        store
            .connection
            .lock()
            .unwrap()
            .execute_batch("PRAGMA foreign_keys = OFF")
            .unwrap();
        assert_eq!(run(store.commit_snapshot(&request)), Err(Error::Corrupt));
        assert_eq!(state(&store), before);
        store
            .connection
            .lock()
            .unwrap()
            .execute_batch("PRAGMA foreign_keys = ON")
            .unwrap();
        run(store.commit_snapshot(&request)).unwrap();
    }
}
