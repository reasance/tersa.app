// This Source Code Form is subject to the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Offline provenance tool for encrypted test-only metadata fixtures.
//! Compile manually against already-built workspace rlibs; never run by CI.
//! The root, account, subject and token below are public synthetic test values.

use rusqlite::{Connection, params};
use tersa_domain::mailbox::AccountId;
use tersa_keys::{
    AccountKeyPurpose, InstallationKeyPurpose, RootKey, account_identity_hash, derive_account_key,
    derive_installation_key,
};
use zeroize::Zeroizing;

fn main() {
    let output = std::env::args_os().nth(1).expect("output path");
    let kind = std::env::args().nth(2).unwrap_or_else(|| "v1".to_owned());
    let root = RootKey::from_bytes(Zeroizing::new([7; 32]));
    let account = AccountId::new("acct_00000000000000000000000000000001").expect("fixture ID");
    let key = if kind == "unclaimed-registry" {
        derive_installation_key(&root, InstallationKeyPurpose::RegistryDatabaseV1)
            .expect("registry key")
            .into_bytes()
    } else {
        derive_account_key(&root, &account, AccountKeyPurpose::SqlCipherDatabaseV1)
            .expect("fixture key")
            .into_bytes()
    };
    let hex: String = key.iter().map(|byte| format!("{byte:02x}")).collect();
    let connection = Connection::open(output).expect("fixture database");
    connection
        .pragma_update(None, "key", format!("x'{hex}'"))
        .expect("raw synthetic key");
    if kind.starts_with("unclaimed-") {
        connection
            .execute_batch("CREATE TABLE unrelated(value TEXT);")
            .expect("encrypted but unclaimed database");
        if kind == "unclaimed-mailbox" {
            connection
                .execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_checkpoint(TRUNCATE);")
                .expect("checkpointed WAL-mode main");
        }
        connection.close().expect("close unclaimed fixture");
        return;
    }
    assert_eq!(kind, "v1");
    connection
        .execute_batch(include_str!(
            "../../../store-sqlcipher/migrations/0001_account_mailbox.sql"
        ))
        .expect("shipped v1 schema");
    connection
        .execute(
            "INSERT INTO account_binding VALUES (1, ?1, 'v1-preview-subject', 'v1-preview-token')",
            params![account.as_str()],
        )
        .expect("binding");
    let identity = account_identity_hash(&root, &account, b"v1-preview-subject").expect("identity");
    connection
        .execute(
            "INSERT INTO account_identity VALUES (?1, ?2, 2)",
            params![account.as_str(), &identity[..]],
        )
        .expect("identity row");
    connection
        .execute_batch(
            "INSERT INTO account_lifecycle VALUES (1, NULL, 12345);
             INSERT INTO messages VALUES ('old-v1', 'thread', 'Sender', 'Old v1', 'Preview', 10, 0, X'626F6479');
             PRAGMA application_id = 0x54534D31;
             PRAGMA user_version = 1;
             PRAGMA journal_mode = WAL;
             PRAGMA wal_checkpoint(TRUNCATE);",
        )
        .expect("fixture rows and WAL-mode main");
    connection.close().expect("close checkpointed fixture");
}
