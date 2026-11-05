// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

mod p5a {
    use super::*;
    use rusqlite::types::Value;

    fn version_2_store(name: &str) -> (TestDatabase, Connection) {
        let (database, connection) = version_1_store(name);
        connection
            .execute_batch(MIGRATION_V2_ACCOUNT_EMAIL)
            .unwrap();
        connection
            .pragma_update(None, "user_version", SCHEMA_VERSION_2)
            .unwrap();
        assert_eq!(schema(&connection).unwrap(), canonical_schema_v2());
        (database, connection)
    }

    fn values(connection: &Connection, sql: &str) -> Vec<Vec<Value>> {
        let mut statement = connection.prepare(sql).unwrap();
        let count = statement.column_count();
        statement
            .query_map([], |row| (0..count).map(|i| row.get(i)).collect())
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
    }

    fn legacy_values(connection: &Connection, version: i64) -> Vec<Vec<Vec<Value>>> {
        let mut result = vec![
            values(
                connection,
                "SELECT singleton,account_id,broker_subject,refresh_token FROM account_binding",
            ),
            values(
                connection,
                "SELECT * FROM account_identity ORDER BY account_id",
            ),
            values(
                connection,
                "SELECT * FROM account_lifecycle ORDER BY singleton",
            ),
            values(connection, "SELECT * FROM messages ORDER BY message_id"),
        ];
        if version >= 2 {
            result.push(values(
                connection,
                "SELECT email_address FROM account_binding",
            ));
        }
        result
    }

    fn populate_legacy(anchor: &Connection, version: i64, token_len: usize) {
        let token = (token_len > 0).then(|| "x".repeat(token_len));
        anchor.execute("UPDATE account_binding SET broker_subject = 'immutable-subject', refresh_token = ?1",[&token]).unwrap();
        anchor
            .execute(
                "INSERT INTO account_identity VALUES (?1, ?2, 2)",
                params![account().as_str(), &[9u8; 32][..]],
            )
            .unwrap();
        anchor.execute_batch("INSERT INTO account_lifecycle VALUES (1,2,123); UPDATE messages SET unread = 0 WHERE message_id = 'm1';").unwrap();
        if version == 2 {
            anchor
                .execute(
                    "UPDATE account_binding SET email_address = 'legacy@example.test'",
                    [],
                )
                .unwrap();
        }
    }

    // Protects old-format preservation and complete current-format convergence.
    // Existing v1 mail fixtures did not cover v2/email, long tokens or lifecycle/identity together.
    #[test]
    fn owned_v1_v2_migrate_to_fresh_v3_without_losing_any_legacy_state() {
        let (_fresh_db, fresh) = open("p5a-fresh");
        let expected_schema = schema_state(&fresh);
        for version in [1, 2] {
            for token_len in [0, 1024, 1025, 4096] {
                let (database, anchor) = if version == 1 {
                    version_1_store("p5a-v1")
                } else {
                    version_2_store("p5a-v2")
                };
                populate_legacy(&anchor, version, token_len);
                let before = legacy_values(&anchor, version);
                let main = fs::read(database.path()).unwrap();
                let wal = fs::read(wal_path(&database)).unwrap();
                let reader =
                    SqlCipherMailboxReader::open_read_only(account(), database.path(), key(7))
                        .unwrap();
                assert_eq!(
                    reader
                        .load_email_address(&account())
                        .unwrap()
                        .map(|e| e.as_str().to_owned()),
                    (version == 2).then(|| "legacy@example.test".to_owned())
                );
                assert_eq!(fs::read(database.path()).unwrap(), main);
                assert_eq!(fs::read(wal_path(&database)).unwrap(), wal);
                assert_eq!(
                    anchor
                        .query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
                        .unwrap(),
                    version
                );
                let store =
                    SqlCipherMailboxStore::open(account(), database.path(), key(7)).unwrap();
                assert_eq!(schema_state(&store), expected_schema);
                {
                    let c = store.connection.lock().unwrap();
                    assert_eq!(legacy_values(&c, version), before);
                    assert_eq!(
                        values(
                            &c,
                            "SELECT capability,credential_purpose FROM account_binding"
                        ),
                        vec![vec![
                            Value::Integer(0),
                            Value::Integer(i64::from(token_len > 0))
                        ]]
                    );
                    assert_eq!(
                        values(
                            &c,
                            "SELECT history_cursor,recovery_required,catalog_known FROM mailbox_checkpoint"
                        ),
                        vec![vec![Value::Null, Value::Integer(0), Value::Integer(0)]]
                    );
                    for table in [
                        "mailbox_commands",
                        "provider_labels",
                        "provider_messages",
                        "terminal_commands",
                        "mailbox_undo",
                    ] {
                        assert!(values(&c, &format!("SELECT * FROM {table}")).is_empty());
                    }
                }
                // Held reader sees a complete known format after writer migration.
                assert_eq!(
                    reader
                        .load_email_address(&account())
                        .unwrap()
                        .map(|e| e.as_str().to_owned()),
                    (version == 2).then(|| "legacy@example.test".to_owned())
                );
                if token_len > 1024 {
                    assert_eq!(
                        store.load_credential_snapshot(&account()),
                        Err(CredentialStoreError::Invalid)
                    );
                    assert_eq!(
                        store.load_refresh_token(&account()),
                        Err(MailboxStoreError::Corrupted)
                    );
                    assert_eq!(
                        store.clear_refresh_token(&account()),
                        Err(MailboxStoreError::Corrupted)
                    );
                } else {
                    assert_eq!(
                        store
                            .load_credential_snapshot(&account())
                            .unwrap()
                            .capability(),
                        AccountCapability::ReadOnly
                    );
                }
            }
        }
    }

    // Forces a genuine deferred SQLite commit failure, after ALTER/UPDATE/version work.
    // A pre-operation failpoint would not protect rollback of the v1 email step.
    fn deferred_failure(connection: &Connection, trigger: &str) {
        connection.execute_batch(
            "PRAGMA foreign_keys = ON; PRAGMA temp_store = MEMORY; PRAGMA secure_delete = ON;
             CREATE TEMP TABLE fault_parent (id INTEGER PRIMARY KEY);
             CREATE TEMP TABLE fault_child (id INTEGER REFERENCES fault_parent(id) DEFERRABLE INITIALLY DEFERRED);"
        ).unwrap();
        connection.execute_batch(trigger).unwrap();
    }

    #[test]
    fn migration_commit_failure_rolls_back_email_objects_version_and_rows() {
        for version in [1, 2] {
            let (_database, anchor) = if version == 1 {
                version_1_store("p5a-rollback1")
            } else {
                version_2_store("p5a-rollback2")
            };
            let before = legacy_values(&anchor, version);
            let objects = schema(&anchor).unwrap();
            deferred_failure(
                &anchor,
                "CREATE TEMP TRIGGER migration_fault AFTER UPDATE OF credential_purpose ON main.account_binding BEGIN INSERT INTO fault_child VALUES (999); END;",
            );
            assert!(upgrade_schema(&anchor, &account()).is_err());
            assert!(anchor.is_autocommit());
            assert_eq!(
                anchor
                    .query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
                    .unwrap(),
                version
            );
            assert_eq!(schema(&anchor).unwrap(), objects);
            assert_eq!(legacy_values(&anchor, version), before);
            assert!(values(&anchor, "SELECT * FROM fault_child").is_empty());
            anchor
                .execute_batch("DROP TRIGGER migration_fault")
                .unwrap();
            upgrade_schema(&anchor, &account()).unwrap();
            assert_eq!(schema(&anchor).unwrap(), canonical_schema());
        }
    }

    // Existing schema refusal fixtures do not include recognized old layouts with malformed rows.
    #[test]
    fn malformed_old_owned_rows_never_get_upgraded_or_repaired() {
        for version in [1, 2] {
            for damage in [
                "UPDATE messages SET subject = zeroblob(1048576)",
                "UPDATE account_binding SET broker_subject = X'01'",
                "UPDATE account_binding SET broker_subject = 'invalid subject'",
                "INSERT INTO account_identity VALUES ('foreign-account', X'00', 1)",
            ] {
                let (database, anchor) = if version == 1 {
                    version_1_store("p5a-corrupt1")
                } else {
                    version_2_store("p5a-corrupt2")
                };
                anchor.execute_batch(damage).unwrap();
                let main = fs::read(database.path()).unwrap();
                let wal = fs::read(wal_path(&database)).unwrap();
                assert!(matches!(
                    SqlCipherMailboxStore::open(account(), database.path(), key(7)),
                    Err(MailboxStoreError::Corrupted)
                ));
                assert_eq!(fs::read(database.path()).unwrap(), main);
                assert_eq!(fs::read(wal_path(&database)).unwrap(), wal);
                assert_eq!(
                    anchor
                        .query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
                        .unwrap(),
                    version
                );
            }
        }
    }

    fn bound_store(name: &str) -> (TestDatabase, SqlCipherMailboxStore) {
        let (database, store) = open(name);
        store
            .store_broker_subject(&account(), "subject-private")
            .unwrap();
        record_fence(&store);
        store
            .store_refresh_token(&account(), "legacy-private")
            .unwrap();
        (database, store)
    }
    fn active(value: &str) -> StoreCredential {
        StoreCredential::Active(Zeroizing::new(value.to_owned()))
    }

    fn assert_legacy_denied(store: &SqlCipherMailboxStore) {
        assert_eq!(
            store.load_refresh_token(&account()),
            Err(MailboxStoreError::Corrupted)
        );
        assert_eq!(
            store.store_refresh_token(&account(), "overwrite"),
            Err(MailboxStoreError::Corrupted)
        );
        assert_eq!(
            store.clear_refresh_token(&account()),
            Err(MailboxStoreError::Corrupted)
        );
    }

    // Full snapshot CAS, unsupported legacy states, and atomic token/capability custody share one boundary.
    #[test]
    fn credential_cas_is_atomic_and_legacy_apis_cannot_use_or_downgrade_advanced_grants() {
        let (database, store) = bound_store("p5a-grants");
        let old = store.load_credential_snapshot(&account()).unwrap();
        let next = active("modify-private");
        store
            .replace_credential_snapshot(&old, AccountCapability::Modify, &next)
            .unwrap();
        let modified = store.load_credential_snapshot(&account()).unwrap();
        assert_eq!(modified.capability(), AccountCapability::Modify);
        assert_eq!(modified.credential(), &next);
        assert_eq!(modified.subject(), Some("subject-private"));
        assert_eq!(modified.identity(), Some(&[9; 32]));
        assert_eq!(
            store.replace_credential_snapshot(
                &old,
                AccountCapability::ReadOnly,
                &active("delayed")
            ),
            Err(CredentialStoreError::Conflict)
        );
        assert_eq!(
            store.delete_credential_snapshot(&old),
            Err(CredentialStoreError::Conflict)
        );
        assert_legacy_denied(&store);
        assert_eq!(
            store.load_credential_snapshot(&account()).unwrap(),
            modified
        );
        store.delete_credential_snapshot(&modified).unwrap();
        let modify_missing = store.load_credential_snapshot(&account()).unwrap();
        assert_eq!(modify_missing.capability(), AccountCapability::Modify);
        assert_eq!(modify_missing.credential(), &StoreCredential::Missing);
        assert_legacy_denied(&store);
        let revoke = StoreCredential::RevocationOnly(Zeroizing::new("revoke-private".to_owned()));
        store
            .replace_credential_snapshot(&modify_missing, AccountCapability::ReadOnly, &revoke)
            .unwrap();
        assert_legacy_denied(&store);
        let revocation = store.load_credential_snapshot(&account()).unwrap();
        drop(store);
        let store = SqlCipherMailboxStore::open(account(), database.path(), key(7)).unwrap();
        assert_eq!(
            store.load_credential_snapshot(&account()).unwrap(),
            revocation
        );
        store.delete_credential_snapshot(&revocation).unwrap();
        assert_eq!(store.load_refresh_token(&account()), Ok(None));
        let missing = store.load_credential_snapshot(&account()).unwrap();
        assert_eq!(missing.subject(), Some("subject-private"));
        assert_eq!(missing.credential(), &StoreCredential::Missing);
        assert_eq!(
            store.delete_credential_snapshot(&revocation),
            Err(CredentialStoreError::Conflict)
        );
        assert_eq!(
            store.load_credential_snapshot(&AccountId::new("unknown").unwrap()),
            Err(CredentialStoreError::UnknownAccount)
        );
        for secret in [
            "subject-private",
            "legacy-private",
            "modify-private",
            "revoke-private",
            "account-a",
        ] {
            assert!(!format!("{old:?} {missing:?} {revoke:?}").contains(secret));
        }
    }

    #[test]
    fn credential_commit_failure_rolls_back_complete_pair_and_purpose() {
        let (_database, store) = bound_store("p5a-grant-rollback");
        let old = store.load_credential_snapshot(&account()).unwrap();
        deferred_failure(
            &store.connection.lock().unwrap(),
            "CREATE TEMP TRIGGER grant_fault AFTER UPDATE OF refresh_token ON main.account_binding BEGIN INSERT INTO fault_child VALUES (999); END;",
        );
        for (capability, credential) in [
            (AccountCapability::Modify, active("new-private")),
            (
                AccountCapability::ReadOnly,
                StoreCredential::RevocationOnly(Zeroizing::new("revoke-private".to_owned())),
            ),
            (AccountCapability::ReadOnly, StoreCredential::Missing),
        ] {
            assert_eq!(
                store.replace_credential_snapshot(&old, capability, &credential),
                Err(CredentialStoreError::Storage)
            );
            assert_eq!(store.load_credential_snapshot(&account()).unwrap(), old);
        }
        store
            .connection
            .lock()
            .unwrap()
            .execute_batch("DROP TRIGGER grant_fault")
            .unwrap();
        store
            .replace_credential_snapshot(
                &old,
                AccountCapability::Modify,
                &active(&"x".repeat(1024)),
            )
            .unwrap();
        let current = store.load_credential_snapshot(&account()).unwrap();
        for value in [String::new(), "x".repeat(1025)] {
            assert_eq!(
                store.replace_credential_snapshot(
                    &current,
                    AccountCapability::Modify,
                    &active(&value)
                ),
                Err(CredentialStoreError::Invalid)
            );
            assert_eq!(store.load_credential_snapshot(&account()).unwrap(), current);
        }
    }

    // Changing each expected component must independently reject a delayed replacement.
    #[test]
    fn credential_cas_compares_identity_subject_capability_purpose_and_token() {
        for sql in [
            "UPDATE account_identity SET identity_hash = zeroblob(32)",
            "DELETE FROM account_identity",
            "UPDATE account_binding SET broker_subject = 'changed-subject'",
            "UPDATE account_binding SET capability = 1",
            "UPDATE account_binding SET credential_purpose = 2",
            "UPDATE account_binding SET refresh_token = 'changed-token'",
            "UPDATE account_binding SET refresh_token = NULL,credential_purpose = 0",
        ] {
            let (_database, store) = bound_store("p5a-stale-grant");
            let old = store.load_credential_snapshot(&account()).unwrap();
            store.connection.lock().unwrap().execute_batch(sql).unwrap();
            let changed = store.load_credential_snapshot(&account()).unwrap();
            assert_ne!(changed, old);
            assert_eq!(
                store.replace_credential_snapshot(
                    &old,
                    AccountCapability::Modify,
                    &active("delayed")
                ),
                Err(CredentialStoreError::Conflict),
                "{sql}"
            );
            assert_eq!(store.load_credential_snapshot(&account()).unwrap(), changed);
        }
        let (_database, store) = open("p5a-bootstrap-identity");
        store.store_broker_subject(&account(), "subject").unwrap();
        let old = store.load_credential_snapshot(&account()).unwrap();
        record_fence(&store);
        assert_eq!(
            store.replace_credential_snapshot(&old, AccountCapability::Modify, &active("delayed")),
            Err(CredentialStoreError::Conflict)
        );
    }

    #[test]
    fn corrupt_capability_purpose_and_combinations_are_errors_without_mutation() {
        for sql in [
            "UPDATE account_binding SET capability = 99",
            "UPDATE account_binding SET capability = X'00'",
            "UPDATE account_binding SET credential_purpose = 99",
            "UPDATE account_binding SET credential_purpose = X'00'",
            "UPDATE account_binding SET credential_purpose = 0",
            "UPDATE account_binding SET refresh_token = NULL",
            "UPDATE account_binding SET refresh_token = zeroblob(2000000)",
            "UPDATE account_binding SET refresh_token = ''",
        ] {
            let (database, store) = bound_store("p5a-corrupt-grant");
            store.connection.lock().unwrap().execute_batch(&format!("PRAGMA ignore_check_constraints = ON; {sql}; PRAGMA ignore_check_constraints = OFF;")).unwrap();
            let before = reset_snapshot(&store, true);
            assert_eq!(
                store.load_credential_snapshot(&account()),
                Err(CredentialStoreError::Invalid),
                "{sql}"
            );
            assert_eq!(
                store.load_refresh_token(&account()),
                Err(MailboxStoreError::Corrupted),
                "{sql}"
            );
            assert_eq!(
                store.store_refresh_token(&account(), "replacement"),
                Err(MailboxStoreError::Corrupted)
            );
            assert_eq!(reset_snapshot(&store, true), before);
            let main = fs::read(database.path()).unwrap();
            let wal = fs::read(wal_path(&database)).unwrap();
            assert!(matches!(
                SqlCipherMailboxReader::open_read_only(account(), database.path(), key(7)),
                Err(MailboxStoreError::Corrupted)
            ));
            assert!(matches!(
                SqlCipherMailboxStore::open_with_scan(
                    account(),
                    database.path(),
                    key(7),
                    IntegrityScan::Skip
                ),
                Err(MailboxStoreError::Corrupted)
            ));
            assert_eq!(fs::read(database.path()).unwrap(), main);
            assert_eq!(fs::read(wal_path(&database)).unwrap(), wal);
        }
    }

    // Layout can retain explicit-only dispatch across status/revision changes and a crash.
    // This is SQL evidence preservation, not implementation of P5c transitions.
    #[test]
    fn explicit_dispatch_and_passed_compensation_guard_survive_reopen_and_cache_deletion() {
        let (database, store) = bound_store("p5a-dispatch-evidence");
        {
            let c = store.connection.lock().unwrap();
            c.execute_batch(
                "INSERT INTO mailbox_commands (command_id,revision,fifo,kind,status,automatic_attempts,dispatch_started,dispatch_revision,dispatch_authorization,compensation_guard_revision,undo_source_id,undo_source_revision)
                 VALUES ('compensation',X'0000000000000002',1,1,1,0,1,X'0000000000000002',1,X'0000000000000001','source',X'0000000000000001');
                 INSERT INTO command_items (command_id,message_id,observation,dispatch_selected) VALUES ('compensation','m1',1,1),('compensation','m2',1,1);
                 INSERT INTO command_fields VALUES ('compensation','m1','UNREAD',0,1,0,NULL,0),('compensation','m2','UNREAD',0,1,0,NULL,0);
                 INSERT INTO command_item_memberships VALUES ('compensation','m1','Label_exact');
                 UPDATE mailbox_checkpoint SET next_fifo = 2;
                 UPDATE mailbox_commands SET status = 3,revision = X'0000000000000003',reconciliation_failure = 0;
                 UPDATE command_items SET outcome = 0 WHERE message_id = 'm1';
                 UPDATE command_fields SET post_state = 1 WHERE message_id = 'm1';
                 DELETE FROM messages; DELETE FROM provider_labels;"
            ).unwrap();
        }
        drop(store);
        let store = SqlCipherMailboxStore::open(account(), database.path(), key(7)).unwrap();
        let c = store.connection.lock().unwrap();
        assert_eq!(
            values(
                &c,
                "SELECT automatic_attempts,dispatch_started,hex(dispatch_revision),dispatch_authorization,dispatch_fact,hex(compensation_guard_revision),hex(revision),status FROM mailbox_commands"
            ),
            vec![vec![
                Value::Integer(0),
                Value::Integer(1),
                Value::Text("0000000000000002".into()),
                Value::Integer(1),
                Value::Null,
                Value::Text("0000000000000001".into()),
                Value::Text("0000000000000003".into()),
                Value::Integer(3)
            ]]
        );
        assert_eq!(
            values(
                &c,
                "SELECT outcome,pre_state,post_state,expected_post_state FROM command_items JOIN command_fields USING(command_id,message_id) ORDER BY message_id"
            ),
            vec![
                vec![
                    Value::Integer(0),
                    Value::Integer(0),
                    Value::Integer(1),
                    Value::Integer(0)
                ],
                vec![
                    Value::Null,
                    Value::Integer(0),
                    Value::Null,
                    Value::Integer(0)
                ]
            ]
        );
        assert_eq!(
            values(&c, "SELECT label_id FROM command_item_memberships"),
            vec![vec![Value::Text("Label_exact".into())]]
        );
    }

    // Proves all pre-P5c destructive entry points refuse durable target/undo bodies.
    #[test]
    fn legacy_destructive_paths_refuse_command_evidence_and_reset_clears_only_cache_state() {
        for undo in [false, true] {
            let (_database, store) = reset_fixture("p5a-legacy-guards", &account());
            {
                let c = store.connection.lock().unwrap();
                c.execute_batch(
                    "INSERT INTO mailbox_commands (command_id,revision,fifo,kind,status) VALUES ('retained',zeroblob(8),1,0,0);
                     INSERT INTO command_items (command_id,message_id) VALUES ('retained','pinned');
                     INSERT INTO command_fields (command_id,message_id,field_id,user_label,desired) VALUES ('retained','pinned','UNREAD',0,0);
                     UPDATE mailbox_checkpoint SET next_fifo = 2;"
                ).unwrap();
                if undo {
                    c.execute_batch("UPDATE mailbox_commands SET status = 4; UPDATE command_items SET outcome = 0; INSERT INTO mailbox_undo VALUES (1,'retained');").unwrap();
                }
            }
            let before = reset_snapshot(&store, true);
            let rows = values(
                &store.connection.lock().unwrap(),
                "SELECT * FROM command_fields",
            );
            assert!(store.clear_cached_mail(&account()).is_err());
            assert!(run(store.purge_account(&account())).is_err());
            assert!(
                run(store.reconcile_identity(
                    &account(),
                    &IdentityHash::from_bytes([5; 32]),
                    IdentityReconcile::ClearMailboxAndRecord,
                    Some(&fence())
                ))
                .is_err()
            );
            assert!(
                run(store.reconcile_recent_envelopes(
                    &account(),
                    &[],
                    StoreLimit::new(1).unwrap(),
                    &fence()
                ))
                .is_err()
            );
            assert_eq!(reset_snapshot(&store, true), before);
            assert_eq!(
                values(
                    &store.connection.lock().unwrap(),
                    "SELECT * FROM command_fields"
                ),
                rows
            );
        }
        let (_database, store) = reset_fixture("p5a-reset-metadata", &account());
        let snapshot = store.load_credential_snapshot(&account()).unwrap();
        store.connection.lock().unwrap().execute_batch(
            "UPDATE mailbox_checkpoint SET history_cursor = '42',catalog_known = 1,recovery_required = 1;
             INSERT INTO provider_labels VALUES ('Label_a','exact',1);
             INSERT INTO provider_messages VALUES ('body',1);
             INSERT INTO provider_memberships VALUES ('body','Label_a');
             INSERT INTO terminal_commands VALUES ('expired',zeroblob(8),1,7,0,1,0,0,0);"
        ).unwrap();
        store.clear_cached_mail(&account()).unwrap();
        assert_eq!(
            store.load_credential_snapshot(&account()).unwrap(),
            snapshot
        );
        let c = store.connection.lock().unwrap();
        assert_eq!(
            values(
                &c,
                "SELECT history_cursor,catalog_known,recovery_required FROM mailbox_checkpoint"
            ),
            vec![vec![Value::Null, Value::Integer(0), Value::Integer(0)]]
        );
        for table in [
            "provider_labels",
            "provider_messages",
            "provider_memberships",
            "terminal_commands",
        ] {
            assert!(values(&c, &format!("SELECT * FROM {table}")).is_empty());
        }
    }

    // Provider names permit Unicode/control/NUL bytes; schema validation must not sanitize them.
    #[test]
    fn exact_provider_label_bytes_survive_validation_and_membership_is_independent_of_local_unread()
    {
        let (database, store) = open("p5a-exact-label");
        run(store.upsert_envelopes(&account(), &[envelope("m1", "thread", 1)])).unwrap();
        let name = " e\u{301}\0\n\u{202e}é ";
        {
            let c = store.connection.lock().unwrap();
            c.execute(
                "INSERT INTO provider_labels VALUES ('Label_a',?1,1)",
                [name],
            )
            .unwrap();
            c.execute_batch("INSERT INTO provider_messages VALUES ('m1',1); INSERT INTO provider_memberships VALUES ('m1','UNREAD');
                UPDATE messages SET unread = 0; UPDATE mailbox_checkpoint SET catalog_known = 1;").unwrap();
        }
        drop(store);
        let store = SqlCipherMailboxStore::open(account(), database.path(), key(7)).unwrap();
        let c = store.connection.lock().unwrap();
        assert_eq!(
            values(&c, "SELECT name FROM provider_labels"),
            vec![vec![Value::Text(name.to_owned())]]
        );
        assert_eq!(
            values(&c, "SELECT unread FROM messages"),
            vec![vec![Value::Integer(0)]]
        );
        assert_eq!(
            values(&c, "SELECT label_id FROM provider_memberships"),
            vec![vec![Value::Text("UNREAD".into())]]
        );
    }
    // A damaged membership page must not be read by envelope/ownership operations.
    // Actual SQLCipher page authentication supplies the negative control.
    #[test]
    fn repeated_metadata_and_skipped_opens_do_not_visit_membership_pages() {
        let (database, store) = open("p5a-no-membership-scan");
        store
            .store_email_address(
                &account(),
                &AccountEmail::new("metadata@example.test").unwrap(),
            )
            .unwrap();
        run(store.upsert_envelopes(&account(), &[envelope("m1", "thread", 1)])).unwrap();
        let (root, page_size): (usize, usize) = {
            let c = store.connection.lock().unwrap();
            c.execute_batch("INSERT INTO provider_messages VALUES ('m1',1); INSERT INTO provider_memberships VALUES ('m1','UNREAD'); PRAGMA wal_checkpoint(TRUNCATE);").unwrap();
            (
                c.query_row(
                    "SELECT rootpage FROM sqlite_schema WHERE name = 'provider_memberships'",
                    [],
                    |r| r.get::<_, u32>(0),
                )
                .unwrap()
                .try_into()
                .unwrap(),
                c.query_row("PRAGMA cipher_page_size", [], |r| r.get::<_, String>(0))
                    .unwrap()
                    .parse()
                    .unwrap(),
            )
        };
        let full_started = Instant::now();
        let reader =
            SqlCipherMailboxReader::open_read_only(account(), database.path(), key(7)).unwrap();
        let full_elapsed = full_started.elapsed();
        drop(store);
        let mut bytes = fs::read(database.path()).unwrap();
        bytes[(root - 1) * page_size + 100] ^= 0xff;
        fs::write(database.path(), bytes).unwrap();
        reader
            .connection
            .lock()
            .unwrap()
            .execute_batch("PRAGMA shrink_memory")
            .unwrap();
        let repeated_started = Instant::now();
        for _ in 0..3 {
            assert_eq!(
                reader
                    .load_email_address(&account())
                    .unwrap()
                    .unwrap()
                    .as_str(),
                "metadata@example.test"
            );
            assert_eq!(
                run(reader.list_envelopes(&account(), StoreLimit::new(10).unwrap()))
                    .unwrap()
                    .len(),
                1
            );
        }
        let repeated_elapsed = repeated_started.elapsed();
        assert_eq!(reader.connection.lock().unwrap().total_changes(), 0);
        drop(reader);
        let skip_started = Instant::now();
        let skipped = SqlCipherMailboxStore::open_with_scan(
            account(),
            database.path(),
            key(7),
            IntegrityScan::Skip,
        )
        .unwrap();
        eprintln!(
            "synthetic v3 timing: readonly Full open {full_elapsed:?}; 3 metadata/envelope passes {repeated_elapsed:?}; Skip writer open {:?}",
            skip_started.elapsed()
        );
        assert_eq!(
            skipped
                .load_email_address(&account())
                .unwrap()
                .unwrap()
                .as_str(),
            "metadata@example.test"
        );
        assert!(
            skipped
                .connection
                .lock()
                .unwrap()
                .query_row("SELECT count(*) FROM provider_memberships", [], |r| r
                    .get::<_, i64>(0))
                .is_err()
        );
        assert!(matches!(
            SqlCipherMailboxStore::open(account(), database.path(), key(7)),
            Err(MailboxStoreError::Corrupted)
        ));
    }
}
