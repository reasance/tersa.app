// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Encrypted account registry (ADR 0026, carried over by ADR 0031).
//!
//! The registry holds only `(AccountId, RegistryDedupTag, position)`: enough
//! to list accounts in order and to reject adding the same Google account
//! twice. It holds no messages, profiles, subjects, tokens, or labels. The
//! dedup tag is an HMAC of the OAuth subject under an installation key, so
//! the registry is a same-installation equality oracle and nothing more.

use std::fmt;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::sync::Mutex;

use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use tersa_domain::mailbox::AccountId;
use zeroize::Zeroizing;

/// Maximum number of registered accounts.
pub const MAX_ACCOUNTS: usize = 5;
/// Length of a registry dedup tag.
pub const DEDUP_TAG_LEN: usize = 32;

const APPLICATION_ID: i64 = 0x5453_5231; // "TSR1"
const VERSION: i64 = 1;
const SCHEMA: &str = "CREATE TABLE registry_accounts ( \
    account_id TEXT PRIMARY KEY CHECK (length(CAST(account_id AS BLOB)) BETWEEN 1 AND 256), \
    dedup_tag BLOB NOT NULL UNIQUE CHECK (length(dedup_tag) = 32), \
    position INTEGER NOT NULL UNIQUE CHECK (position >= 0) )";

/// Registry failures. Variants carry no account data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RegistryError {
    /// The database could not be read or written.
    Storage,
    /// The database is not a valid registry, or the key is wrong.
    Corrupted,
    /// The registry already holds [`MAX_ACCOUNTS`] accounts.
    Full,
    /// The account or its Google identity is already registered.
    Duplicate,
    /// The parent directory is not owner-only.
    UnsafeLocation,
}

impl fmt::Display for RegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Storage => "the account registry could not be accessed",
            Self::Corrupted => "the account registry is damaged or the key is wrong",
            Self::Full => "the maximum number of accounts is already registered",
            Self::Duplicate => "this account is already registered",
            Self::UnsafeLocation => "the registry directory must be owner-only",
        })
    }
}

impl std::error::Error for RegistryError {}

/// The encrypted account registry.
pub struct SqlCipherRegistry {
    connection: Mutex<Connection>,
}

impl fmt::Debug for SqlCipherRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SqlCipherRegistry([REDACTED])")
    }
}

impl SqlCipherRegistry {
    /// Opens or creates the registry at `path` with `key`.
    ///
    /// The parent directory must already exist, be owned by the current
    /// user, and grant no group or other access.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::UnsafeLocation`] for a shared parent,
    /// [`RegistryError::Corrupted`] for a wrong key or foreign database, and
    /// [`RegistryError::Storage`] for I/O failures.
    pub fn open(path: &Path, key: &Zeroizing<[u8; 32]>) -> Result<Self, RegistryError> {
        // SQLite's NOFOLLOW rejects a symlink in any path component, so
        // resolve the parent first (on macOS the temp and home trees sit
        // behind /var -> /private/var); the leaf stays NOFOLLOW-protected.
        let name = path.file_name().ok_or(RegistryError::Storage)?;
        let parent = fs::canonicalize(path.parent().ok_or(RegistryError::Storage)?)
            .map_err(|_error| RegistryError::Storage)?;
        let path = parent.join(name);
        let parent_metadata =
            fs::symlink_metadata(&parent).map_err(|_error| RegistryError::Storage)?;
        if !parent_metadata.is_dir()
            || parent_metadata.mode() & 0o077 != 0
            || parent_metadata.uid() != rustix::process::geteuid().as_raw()
        {
            return Err(RegistryError::UnsafeLocation);
        }

        let connection = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|_error| RegistryError::Storage)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .map_err(|_error| RegistryError::Storage)?;
        crate::store::apply_key(&connection, key).map_err(|_error| RegistryError::Storage)?;
        connection
            .execute_batch(
                "PRAGMA cipher_memory_security = ON;
                 PRAGMA secure_delete = ON;
                 PRAGMA temp_store = MEMORY;",
            )
            .map_err(classify)?;

        let application_id: i64 = connection
            .query_row("PRAGMA application_id", [], |row| row.get(0))
            .map_err(classify)?;
        let user_version: i64 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(classify)?;
        let schema = schema(&connection)?;
        if application_id == 0 && user_version == 0 && schema.is_empty() {
            let transaction = connection
                .unchecked_transaction()
                .map_err(|_error| RegistryError::Storage)?;
            transaction.execute_batch(SCHEMA).map_err(classify)?;
            transaction
                .pragma_update(None, "application_id", APPLICATION_ID)
                .map_err(classify)?;
            transaction
                .pragma_update(None, "user_version", VERSION)
                .map_err(classify)?;
            transaction.commit().map_err(classify)?;
        } else if application_id != APPLICATION_ID
            || user_version != VERSION
            || schema != [normalize(SCHEMA)]
        {
            return Err(RegistryError::Corrupted);
        }

        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    /// Authenticates an existing registry without creation or write authority.
    ///
    /// Missing, empty and unclaimed databases are refused. Existing ownership,
    /// owner-only permissions, format and rows are checked without chmod,
    /// schema initialization, migration or journal repair. A WAL registry must
    /// already have its coordination files; ordinary shared-memory bookkeeping
    /// is not a database/schema write. The existing bootstrap opener is separate.
    ///
    /// # Errors
    ///
    /// Returns `Storage` for missing/unusable files, `UnsafeLocation` for
    /// unsafe ownership/permissions and `Corrupted` for an invalid key/format.
    pub fn open_existing(path: &Path, key: &Zeroizing<[u8; 32]>) -> Result<Self, RegistryError> {
        let name = path.file_name().ok_or(RegistryError::Storage)?;
        let parent = fs::canonicalize(path.parent().ok_or(RegistryError::Storage)?)
            .map_err(|_error| RegistryError::Storage)?;
        let path = parent.join(name);
        let before = existing_registry_files(&path)?;
        let mut connection = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|_error| RegistryError::Storage)?;
        crate::store::disable_and_verify_checkpoint_on_close(&connection)
            .map_err(|_error| RegistryError::Storage)?;
        crate::store::opened_file_has_moved(&connection)
            .map_err(|_error| RegistryError::Storage)?;
        if before.1.is_some() {
            crate::store::set_and_verify_persistent_wal(&connection)
                .map_err(|_error| RegistryError::Storage)?;
        }
        crate::store::apply_key(&connection, key).map_err(classify)?;
        connection.execute_batch("PRAGMA cipher_memory_security = ON; PRAGMA temp_store = MEMORY; PRAGMA query_only = ON;").map_err(classify)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(classify)?;
        validate_existing_registry(&transaction)?;
        transaction.commit().map_err(classify)?;
        if existing_registry_files(&path)? != before {
            return Err(RegistryError::Storage);
        }
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    /// Registered accounts in display order.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::Storage`] or [`RegistryError::Corrupted`].
    pub fn accounts(&self) -> Result<Vec<AccountId>, RegistryError> {
        let connection = self.lock()?;
        let mut statement = connection
            .prepare("SELECT account_id FROM registry_accounts ORDER BY position ASC")
            .map_err(classify)?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(classify)?;
        rows.map(|row| {
            let value = row.map_err(classify)?;
            AccountId::new(value).map_err(|_error| RegistryError::Corrupted)
        })
        .collect()
    }

    /// The account registered under `tag`, if any.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::Storage`] or [`RegistryError::Corrupted`].
    pub fn find_by_tag(
        &self,
        tag: &[u8; DEDUP_TAG_LEN],
    ) -> Result<Option<AccountId>, RegistryError> {
        let connection = self.lock()?;
        let value: Option<String> = connection
            .query_row(
                "SELECT account_id FROM registry_accounts WHERE dedup_tag = ?1",
                params![&tag[..]],
                |row| row.get(0),
            )
            .optional()
            .map_err(classify)?;
        value
            .map(|value| AccountId::new(value).map_err(|_error| RegistryError::Corrupted))
            .transpose()
    }

    /// Appends `account` with its dedup `tag`.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::Full`] at [`MAX_ACCOUNTS`],
    /// [`RegistryError::Duplicate`] when the account or tag exists, or a
    /// storage error.
    pub fn register(
        &self,
        account: &AccountId,
        tag: &[u8; DEDUP_TAG_LEN],
    ) -> Result<(), RegistryError> {
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(classify)?;
        let (count, next): (i64, i64) = transaction
            .query_row(
                "SELECT count(*), coalesce(max(position) + 1, 0) FROM registry_accounts",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(classify)?;
        if usize::try_from(count).map_err(|_error| RegistryError::Corrupted)? >= MAX_ACCOUNTS {
            return Err(RegistryError::Full);
        }
        let duplicate: bool = transaction
            .query_row(
                "SELECT EXISTS (SELECT 1 FROM registry_accounts WHERE account_id = ?1 OR dedup_tag = ?2)",
                params![account.as_str(), &tag[..]],
                |row| row.get(0),
            )
            .map_err(classify)?;
        if duplicate {
            return Err(RegistryError::Duplicate);
        }
        transaction
            .execute(
                "INSERT INTO registry_accounts (account_id, dedup_tag, position) VALUES (?1, ?2, ?3)",
                params![account.as_str(), &tag[..], next],
            )
            .map_err(classify)?;
        transaction.commit().map_err(classify)
    }

    /// Removes `account`. Returns whether it was registered.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::Storage`] or [`RegistryError::Corrupted`].
    pub fn remove(&self, account: &AccountId) -> Result<bool, RegistryError> {
        let connection = self.lock()?;
        let removed = connection
            .execute(
                "DELETE FROM registry_accounts WHERE account_id = ?1",
                params![account.as_str()],
            )
            .map_err(classify)?;
        Ok(removed == 1)
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>, RegistryError> {
        self.connection
            .lock()
            .map_err(|_poison| RegistryError::Storage)
    }
}

// Identity-only snapshots deliberately exclude SHM contents and timestamps:
// authenticated read-only WAL coordination may update its existing read marks.
type RegistryFileIdentity = (u64, u64, u32, u32);
type RegistryFiles = (
    RegistryFileIdentity,
    Option<RegistryFileIdentity>,
    Option<RegistryFileIdentity>,
    RegistryFileIdentity,
);

fn existing_registry_file(path: &Path) -> Result<RegistryFileIdentity, RegistryError> {
    let metadata = fs::symlink_metadata(path).map_err(|_error| RegistryError::Storage)?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o7777 != 0o600
    {
        return Err(RegistryError::UnsafeLocation);
    }
    Ok((
        metadata.dev(),
        metadata.ino(),
        metadata.uid(),
        metadata.mode(),
    ))
}

fn existing_registry_files(path: &Path) -> Result<RegistryFiles, RegistryError> {
    let parent = fs::symlink_metadata(path.parent().ok_or(RegistryError::Storage)?)
        .map_err(|_error| RegistryError::Storage)?;
    if !parent.is_dir()
        || parent.uid() != rustix::process::geteuid().as_raw()
        || parent.mode() & 0o077 != 0
    {
        return Err(RegistryError::UnsafeLocation);
    }
    let main = existing_registry_file(path)?;
    if fs::metadata(path)
        .map_err(|_error| RegistryError::Storage)?
        .len()
        == 0
    {
        return Err(RegistryError::Corrupted);
    }
    let sidecar = |suffix: &str| -> Result<Option<RegistryFileIdentity>, RegistryError> {
        let mut name = path.as_os_str().to_os_string();
        name.push(suffix);
        let path = Path::new(&name);
        match fs::symlink_metadata(path) {
            Ok(_) => existing_registry_file(path).map(Some),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_error) => Err(RegistryError::Storage),
        }
    };
    // Refuse journal recovery or creation of a missing WAL coordination leaf.
    if sidecar("-journal")?.is_some() {
        return Err(RegistryError::Storage);
    }
    let wal = sidecar("-wal")?;
    let shm = sidecar("-shm")?;
    if wal.is_some() != shm.is_some() {
        return Err(RegistryError::Storage);
    }
    Ok((
        main,
        wal,
        shm,
        (parent.dev(), parent.ino(), parent.uid(), parent.mode()),
    ))
}

fn validate_existing_registry(connection: &Connection) -> Result<(), RegistryError> {
    let application: i64 = connection
        .query_row("PRAGMA application_id", [], |row| row.get(0))
        .map_err(classify)?;
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(classify)?;
    if application != APPLICATION_ID || version != VERSION {
        return Err(RegistryError::Corrupted);
    }
    // The canonical schema has one short statement. Bound unknown schema/row
    // materialization before accepting an authenticated but foreign database.
    let mut statement = connection.prepare("SELECT CASE WHEN typeof(sql) = 'text' AND length(CAST(sql AS BLOB)) <= 16384 THEN sql END FROM sqlite_master WHERE sql IS NOT NULL ORDER BY name LIMIT 2").map_err(classify)?;
    let objects = statement
        .query_map([], |row| row.get::<_, Option<String>>(0))
        .map_err(classify)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(classify)?;
    if objects.len() != 1
        || objects[0].as_deref().map(normalize).as_deref() != Some(normalize(SCHEMA).as_str())
    {
        return Err(RegistryError::Corrupted);
    }
    let mut statement = connection.prepare("SELECT CASE WHEN typeof(account_id) = 'text' AND length(CAST(account_id AS BLOB)) BETWEEN 1 AND 256 THEN account_id END, CASE WHEN typeof(dedup_tag) = 'blob' AND length(dedup_tag) = 32 THEN 1 ELSE 0 END, CASE WHEN typeof(position) = 'integer' AND position >= 0 THEN position END FROM registry_accounts ORDER BY position ASC LIMIT ?1").map_err(classify)?;
    let rows = statement
        .query_map(
            [i64::try_from(MAX_ACCOUNTS + 1).map_err(|_error| RegistryError::Corrupted)?],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                ))
            },
        )
        .map_err(classify)?;
    let mut count = 0;
    for row in rows {
        let (account, valid_tag, position) = row.map_err(classify)?;
        let account = account.ok_or(RegistryError::Corrupted)?;
        if AccountId::new(account).is_err() || valid_tag != 1 || position.is_none() {
            return Err(RegistryError::Corrupted);
        }
        count += 1;
        if count > MAX_ACCOUNTS {
            return Err(RegistryError::Corrupted);
        }
    }
    let integrity: String = connection
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(classify)?;
    let cipher_failure = connection
        .prepare("PRAGMA cipher_integrity_check")
        .and_then(|mut statement| statement.query([])?.next().map(|row| row.is_some()))
        .map_err(classify)?;
    if integrity != "ok" || cipher_failure {
        return Err(RegistryError::Corrupted);
    }
    Ok(())
}

fn schema(connection: &Connection) -> Result<Vec<String>, RegistryError> {
    let mut statement = connection
        .prepare("SELECT sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY name")
        .map_err(classify)?;
    let rows = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(classify)?;
    rows.map(|row| row.map(|sql| normalize(&sql)).map_err(classify))
        .collect()
}

fn normalize(sql: &str) -> String {
    sql.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "rusqlite Result::map_err supplies owned errors"
)]
fn classify(error: rusqlite::Error) -> RegistryError {
    match error {
        rusqlite::Error::SqliteFailure(sqlite, _)
            if matches!(
                sqlite.code,
                rusqlite::ErrorCode::DatabaseCorrupt | rusqlite::ErrorCode::NotADatabase
            ) =>
        {
            RegistryError::Corrupted
        }
        _ => RegistryError::Storage,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    use tersa_domain::mailbox::AccountId;
    use zeroize::Zeroizing;

    use super::{MAX_ACCOUNTS, RegistryError, SqlCipherRegistry};

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "tersa-registry-{name}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos()
            ));
            fs::create_dir_all(&path).expect("dir");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("chmod");
            Self(path)
        }

        fn database(&self) -> PathBuf {
            self.0.join("registry.sqlite3")
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn key(byte: u8) -> Zeroizing<[u8; 32]> {
        Zeroizing::new([byte; 32])
    }

    fn account(index: usize) -> AccountId {
        AccountId::new(format!("acct_{index:032x}")).expect("account")
    }

    fn tag(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn registers_lists_finds_and_removes_in_order() {
        let dir = TempDir::new("order");
        let registry = SqlCipherRegistry::open(&dir.database(), &key(1)).expect("open");
        registry.register(&account(2), &tag(2)).expect("register");
        registry.register(&account(1), &tag(1)).expect("register");
        assert_eq!(
            registry.accounts().expect("list"),
            vec![account(2), account(1)]
        );
        assert_eq!(
            registry.find_by_tag(&tag(1)).expect("find"),
            Some(account(1))
        );
        assert_eq!(registry.find_by_tag(&tag(9)).expect("find"), None);
        assert!(registry.remove(&account(2)).expect("remove"));
        assert!(!registry.remove(&account(2)).expect("remove"));
        drop(registry);

        let reopened = SqlCipherRegistry::open(&dir.database(), &key(1)).expect("reopen");
        assert_eq!(reopened.accounts().expect("list"), vec![account(1)]);
        assert_eq!(
            fs::metadata(dir.database())
                .expect("meta")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn rejects_duplicates_and_enforces_the_cap() {
        let dir = TempDir::new("cap");
        let registry = SqlCipherRegistry::open(&dir.database(), &key(1)).expect("open");
        registry.register(&account(0), &tag(0)).expect("register");
        assert_eq!(
            registry.register(&account(0), &tag(7)),
            Err(RegistryError::Duplicate)
        );
        assert_eq!(
            registry.register(&account(7), &tag(0)),
            Err(RegistryError::Duplicate)
        );
        for index in 1..MAX_ACCOUNTS {
            let byte = u8::try_from(index).expect("small");
            registry
                .register(&account(index), &tag(byte))
                .expect("register");
        }
        assert_eq!(
            registry.register(&account(99), &tag(99)),
            Err(RegistryError::Full)
        );
    }

    #[test]
    fn wrong_key_is_corruption_and_shared_parent_is_refused() {
        let dir = TempDir::new("key");
        drop(SqlCipherRegistry::open(&dir.database(), &key(1)).expect("open"));
        assert!(matches!(
            SqlCipherRegistry::open(&dir.database(), &key(2)),
            Err(RegistryError::Corrupted)
        ));

        fs::set_permissions(&dir.0, fs::Permissions::from_mode(0o755)).expect("chmod");
        assert!(matches!(
            SqlCipherRegistry::open(&dir.database(), &key(1)),
            Err(RegistryError::UnsafeLocation)
        ));
    }

    #[test]
    fn debug_is_redacted() {
        let dir = TempDir::new("debug");
        let registry = SqlCipherRegistry::open(&dir.database(), &key(1)).expect("open");
        assert_eq!(format!("{registry:?}"), "SqlCipherRegistry([REDACTED])");
    }

    fn snapshot(dir: &TempDir) -> Vec<(PathBuf, Vec<u8>, u32)> {
        let mut files: Vec<_> = fs::read_dir(&dir.0)
            .expect("directory")
            .map(|entry| entry.expect("entry").path())
            .filter(|path| path.is_file())
            .map(|path| {
                let bytes = fs::read(&path).expect("bytes");
                let mode = fs::metadata(&path).expect("metadata").permissions().mode();
                (path, bytes, mode)
            })
            .collect();
        files.sort_by(|left, right| left.0.cmp(&right.0));
        files
    }
    fn raw(dir: &TempDir) -> rusqlite::Connection {
        let connection = rusqlite::Connection::open(dir.database()).expect("fixture connection");
        crate::store::apply_key(&connection, &key(1)).expect("fixture key");
        connection
    }

    #[test]
    fn existing_registry_is_authenticated_readonly_and_preserves_dedup_order() {
        let dir = TempDir::new("existing-readonly");
        let writer = SqlCipherRegistry::open(&dir.database(), &key(1)).expect("bootstrap");
        writer.register(&account(2), &tag(2)).expect("register");
        writer.register(&account(1), &tag(1)).expect("register");
        drop(writer);
        let before = snapshot(&dir);
        let reader = SqlCipherRegistry::open_existing(&dir.database(), &key(1)).expect("existing");
        assert_eq!(
            reader.accounts().expect("accounts"),
            [account(2), account(1)]
        );
        assert_eq!(
            reader.find_by_tag(&tag(1)).expect("dedup"),
            Some(account(1))
        );
        assert_eq!(reader.find_by_tag(&tag(9)).expect("missing tag"), None);
        assert!(reader.register(&account(3), &tag(3)).is_err());
        assert!(reader.remove(&account(2)).is_err());
        assert_eq!(format!("{reader:?}"), "SqlCipherRegistry([REDACTED])");
        drop(reader);
        assert_eq!(snapshot(&dir), before);
        let writer = SqlCipherRegistry::open(&dir.database(), &key(1)).expect("writer unchanged");
        writer
            .register(&account(3), &tag(3))
            .expect("writer still writes");
    }

    #[test]
    fn existing_registry_missing_file_or_parent_creates_nothing() {
        let dir = TempDir::new("existing-missing");
        for path in [
            dir.database(),
            dir.0.join("missing-parent").join("registry.sqlite3"),
        ] {
            assert!(matches!(
                SqlCipherRegistry::open_existing(&path, &key(1)),
                Err(RegistryError::Storage)
            ));
            assert!(!path.exists());
        }
        assert!(fs::read_dir(&dir.0).expect("directory").next().is_none());
    }

    #[test]
    fn existing_registry_never_claims_zero_or_encrypted_unclaimed_files() {
        for encrypted in [false, true] {
            let dir = TempDir::new("existing-unclaimed");
            if encrypted {
                let connection = raw(&dir);
                connection
                    .execute_batch("PRAGMA user_version = 0;")
                    .expect("unclaimed");
            } else {
                fs::write(dir.database(), b"").expect("empty file");
            }
            fs::set_permissions(dir.database(), fs::Permissions::from_mode(0o600)).expect("mode");
            let before = snapshot(&dir);
            assert!(matches!(
                SqlCipherRegistry::open_existing(&dir.database(), &key(1)),
                Err(RegistryError::Corrupted)
            ));
            assert_eq!(snapshot(&dir), before);
            let writer = SqlCipherRegistry::open(&dir.database(), &key(1))
                .expect("ordinary bootstrap unchanged");
            writer
                .register(&account(1), &tag(1))
                .expect("initialized normally");
        }
    }

    #[test]
    fn existing_registry_rejects_key_markers_schema_and_rows_without_writes() {
        for fault in 0..7 {
            let dir = TempDir::new("existing-invalid");
            let writer = SqlCipherRegistry::open(&dir.database(), &key(1)).expect("writer");
            writer.register(&account(1), &tag(1)).expect("account");
            drop(writer);
            if fault > 0 {
                let connection = raw(&dir);
                let sql = match fault {
                    1 => "PRAGMA application_id = 1;",
                    2 => "PRAGMA user_version = 999;",
                    3 => "CREATE TABLE future_object (value TEXT);",
                    4 => "UPDATE registry_accounts SET account_id = 'bad@example.test';",
                    5 => {
                        "PRAGMA ignore_check_constraints = ON; UPDATE registry_accounts SET dedup_tag = X'00';"
                    }
                    _ => {
                        "PRAGMA ignore_check_constraints = ON; UPDATE registry_accounts SET position = -1;"
                    }
                };
                connection.execute_batch(sql).expect("fault fixture");
            }
            let before = snapshot(&dir);
            assert!(matches!(
                SqlCipherRegistry::open_existing(
                    &dir.database(),
                    &key(if fault == 0 { 2 } else { 1 })
                ),
                Err(RegistryError::Corrupted)
            ));
            assert_eq!(snapshot(&dir), before, "fault {fault}");
        }
    }

    #[test]
    fn existing_registry_does_not_repair_permissions_or_follow_a_leaf_symlink() {
        let dir = TempDir::new("existing-permissions");
        drop(SqlCipherRegistry::open(&dir.database(), &key(1)).expect("writer"));
        fs::set_permissions(&dir.0, fs::Permissions::from_mode(0o755)).expect("parent mode");
        let before = snapshot(&dir);
        assert!(matches!(
            SqlCipherRegistry::open_existing(&dir.database(), &key(1)),
            Err(RegistryError::UnsafeLocation)
        ));
        assert_eq!(
            fs::metadata(&dir.0).expect("parent").permissions().mode() & 0o777,
            0o755
        );
        assert_eq!(snapshot(&dir), before);
        fs::set_permissions(&dir.0, fs::Permissions::from_mode(0o700)).expect("restore parent");
        fs::set_permissions(dir.database(), fs::Permissions::from_mode(0o644)).expect("file mode");
        let before = snapshot(&dir);
        assert!(matches!(
            SqlCipherRegistry::open_existing(&dir.database(), &key(1)),
            Err(RegistryError::UnsafeLocation)
        ));
        assert_eq!(snapshot(&dir), before);
        drop(
            SqlCipherRegistry::open(&dir.database(), &key(1))
                .expect("ordinary writer can normalize its file"),
        );
        assert_eq!(
            fs::metadata(dir.database())
                .expect("file")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let link = dir.0.join("linked.sqlite3");
        std::os::unix::fs::symlink(dir.database(), &link).expect("symlink");
        assert!(matches!(
            SqlCipherRegistry::open_existing(&link, &key(1)),
            Err(RegistryError::UnsafeLocation)
        ));
        assert!(
            fs::symlink_metadata(link)
                .expect("link remains")
                .is_symlink()
        );
    }

    #[test]
    fn existing_registry_reads_committed_wal_without_checkpoint_or_database_changes() {
        let dir = TempDir::new("existing-wal");
        drop(SqlCipherRegistry::open(&dir.database(), &key(1)).expect("bootstrap"));
        let anchor = raw(&dir);
        anchor
            .execute_batch("PRAGMA journal_mode = WAL;")
            .expect("WAL");
        crate::store::set_and_verify_persistent_wal(&anchor).expect("persistent");
        anchor
            .execute(
                "INSERT INTO registry_accounts VALUES (?1, ?2, 0)",
                rusqlite::params![account(1).as_str(), &tag(1)[..]],
            )
            .expect("WAL commit");
        let wal = PathBuf::from(format!("{}-wal", dir.database().display()));
        let shm = PathBuf::from(format!("{}-shm", dir.database().display()));
        for path in [&wal, &shm] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("mode");
        }
        crate::store::disable_and_verify_checkpoint_on_close(&anchor)
            .expect("fixture keeps committed WAL on close");
        drop(anchor); // Read-only constructor is now the sole connection.
        let main_before = fs::read(dir.database()).expect("main");
        let wal_before = fs::read(&wal).expect("wal");
        let reader = SqlCipherRegistry::open_existing(&dir.database(), &key(1)).expect("read WAL");
        assert_eq!(reader.accounts().expect("accounts"), [account(1)]);
        assert_eq!(
            reader.find_by_tag(&tag(1)).expect("dedup"),
            Some(account(1))
        );
        drop(reader);
        assert_eq!(fs::read(dir.database()).expect("main"), main_before);
        assert_eq!(fs::read(wal).expect("wal"), wal_before);
        // SHM read marks are allowed bookkeeping; removing it must not cause
        // this opener to recreate it or claim a different database.
        fs::remove_file(&shm).expect("missing coordination");
        assert!(matches!(
            SqlCipherRegistry::open_existing(&dir.database(), &key(1)),
            Err(RegistryError::Storage)
        ));
        assert!(!shm.exists());
    }
}
