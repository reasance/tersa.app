// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Provides an account-scoped `SQLCipher` mailbox store.
//!
//! This adapter has synchronous database internals and lazy runtime-free
//! futures. Callers must poll it on a bounded blocking executor rather than a
//! latency-sensitive async executor thread. It deliberately owns neither blob
//! encryption nor cross-file commit orchestration.
// Rust guideline compliant 1.0.

#![deny(unsafe_code)]

mod store {
    use std::collections::HashSet;
    use std::ffi::{OsStr, OsString};
    use std::fmt;
    use std::io::{self, ErrorKind};
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use std::time::Duration;

    use rusqlite::config::DbConfig;
    use rusqlite::{Connection, ErrorCode, OpenFlags, Transaction, TransactionBehavior, params};
    use rustix::fd::OwnedFd;
    use rustix::fs::{self, AtFlags, CWD, FileType, Mode, OFlags};
    use tersa_application::identity::{AccountIdentityStore, IdentityHash, IdentityReconcile};
    use tersa_application::lifecycle::{
        AccountLifecycleMetadata, AccountLifecycleStore, DisconnectRecoveryState,
    };
    use tersa_application::mailbox::{
        AccountEmail, AccountPurgeStore, BoxFuture, EnvelopeCursor, MailboxReader, MailboxStore,
        MailboxStoreError, StoreLimit,
    };
    use tersa_domain::mailbox::{
        AccountId, HeaderText, Message, MessageContent, MessageEnvelope, MessageId, ThreadId,
        UnixTimestampMillis,
    };
    use zeroize::{Zeroize, Zeroizing};

    // Fixed ownership marker for this product account-store schema.
    const APPLICATION_ID: i64 = 0x5453_4D31;
    // The schema carries a shipped-store upgrade path: `MIGRATION` creates a
    // fresh store on the current version, and a store found on the previous
    // version upgrades in one transaction on the next writable open. A store
    // whose version or objects match neither the current nor the previous
    // schema opens as `Corrupted` and is never rewritten here.
    const VERSION: i64 = 2;
    // The previous shipped schema version, accepted read-only and upgraded on
    // the next writable open.
    const SCHEMA_VERSION_1: i64 = 1;
    // Derivation version of the stored account-identity hash. A row written by a
    // different algorithm reads as incompatible (fail closed), never a first
    // connect. Bumped 1 -> 2 in 3d-3a when the gate switched from hashing the
    // mutable email address to the immutable OIDC subject: a stale v1 (email-scheme)
    // row now fails closed rather than being value-compared against a sub-scheme
    // hash, so a scheme change can never produce a false match. Pre-release with no
    // shipped stores, so a v1 dev store reads `Corrupted` and is re-bootstrapped.
    const IDENTITY_ALGO_VERSION: i64 = 2;
    const CANONICAL_SCHEMA_OBJECT_COUNT: usize = 6;
    const MAX_SCHEMA_KIND_LEN: i64 = 16;
    const MAX_SCHEMA_NAME_LEN: i64 = 256;
    const MAX_SCHEMA_SQL_LEN: i64 = 16 * 1_024;
    // Bounds lock waits without introducing retries or background work.
    const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
    const MIGRATION: &str = include_str!("../migrations/0001_account_mailbox.sql");
    const MIGRATION_V2_ACCOUNT_EMAIL: &str = include_str!("../migrations/0002_account_email.sql");
    const RECOVERY_STAGE_LIMIT: usize = 8;

    /// Owns a redacted, zeroizing `SQLCipher` database key.
    pub struct DatabaseKey(Zeroizing<[u8; 32]>);

    impl DatabaseKey {
        /// Creates a database key from exactly 32 raw bytes.
        #[must_use]
        pub fn new(bytes: [u8; 32]) -> Self {
            Self(Zeroizing::new(bytes))
        }

        /// Consumes an already protected key without materializing raw bytes.
        #[must_use]
        pub fn from_zeroizing(bytes: Zeroizing<[u8; 32]>) -> Self {
            Self(bytes)
        }
    }

    impl fmt::Debug for DatabaseKey {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("DatabaseKey([REDACTED])")
        }
    }

    /// Whether opening a database reads all of it to check every page.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum IntegrityScan {
        /// Run `PRAGMA integrity_check` and `PRAGMA cipher_integrity_check`,
        /// which read the whole database, so their cost grows with the cache.
        Full,
        /// Skip both scans, for a database this process already scanned.
        /// Every other check still runs, and `SQLCipher` still authenticates
        /// each page when it is read, so a damaged page fails the read.
        Skip,
    }

    /// Stores one account's mailbox in one `SQLCipher` database file.
    pub struct SqlCipherMailboxStore {
        account: AccountId,
        connection: Mutex<Connection>,
        #[cfg(test)]
        fail_next_mutation: Mutex<Option<usize>>,
    }

    impl fmt::Debug for SqlCipherMailboxStore {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("SqlCipherMailboxStore([REDACTED])")
        }
    }

    /// Classifies strict read-only opening without exposing backend details.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum ReadOnlyMailboxOpenFailure {
        /// The existing profile or its coordination files are unavailable.
        Storage,
        /// The key, owner, schema, rows, or integrity checks were invalid.
        Corrupted,
    }

    /// Reads envelope rows, but no complete message bodies, from one account database.
    ///
    /// This type intentionally implements `MailboxReader`, not `MailboxStore`:
    ///
    /// ```compile_fail
    /// use tersa_application::mailbox::MailboxStore;
    /// use tersa_store_sqlcipher::SqlCipherMailboxReader;
    ///
    /// fn require_store<T: MailboxStore>() {}
    /// require_store::<SqlCipherMailboxReader>();
    /// ```
    pub struct SqlCipherMailboxReader {
        account: AccountId,
        connection: Mutex<Connection>,
    }

    impl fmt::Debug for SqlCipherMailboxReader {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("SqlCipherMailboxReader([REDACTED])")
        }
    }

    impl SqlCipherMailboxReader {
        /// Opens an existing persistent-WAL account database without write authority.
        ///
        /// The main database, WAL, and shared-memory sidecar must already be
        /// regular files. It exposes no creation, migration, checkpoint,
        /// repair, or journal-mode operation. The bundled VFS can internally
        /// recreate a sidecar if same-user malware deletes it after preflight;
        /// the post-read identity check fails that open, but cannot undo the
        /// already-created entry.
        ///
        /// # Errors
        ///
        /// Returns opaque corruption for an invalid key, owner, schema, row,
        /// or integrity result. Missing, moved, or unusable files return an
        /// opaque storage error.
        pub fn open_read_only<P: AsRef<Path>>(
            account: AccountId,
            path: P,
            key: DatabaseKey,
        ) -> Result<Self, MailboxStoreError> {
            Self::open_read_only_classified(account, path, key).map_err(|failure| match failure {
                ReadOnlyMailboxOpenFailure::Storage => MailboxStoreError::Storage,
                ReadOnlyMailboxOpenFailure::Corrupted => MailboxStoreError::Corrupted,
            })
        }

        /// Opens an existing account database and preserves the closed failure class.
        ///
        /// This constructor has the same strict read-only behavior as
        /// [`Self::open_read_only`]. It exists so a trusted composition crate
        /// can map the two approved failure classes without depending directly
        /// on the application port crate.
        ///
        /// # Errors
        ///
        /// Returns storage for an unavailable profile or coordination file and
        /// corruption for invalid encrypted or persisted state.
        pub fn open_read_only_classified<P: AsRef<Path>>(
            account: AccountId,
            path: P,
            key: DatabaseKey,
        ) -> Result<Self, ReadOnlyMailboxOpenFailure> {
            Self::open_read_only_with_hooks(
                account,
                path.as_ref(),
                key,
                |_path| {},
                |_path| {},
                |_path| {},
            )
            .map_err(|error| match error {
                MailboxStoreError::Storage => ReadOnlyMailboxOpenFailure::Storage,
                _ => ReadOnlyMailboxOpenFailure::Corrupted,
            })
        }

        fn open_read_only_with_hooks(
            account: AccountId,
            path: &Path,
            mut key: DatabaseKey,
            after_preflight: impl FnOnce(&Path),
            before_live_read: impl FnOnce(&Path),
            after_live_read: impl FnOnce(&Path),
        ) -> Result<Self, MailboxStoreError> {
            let outcome = (|| {
                let canonical_path = canonical_database_path(path)?;
                let identities = preflight_read_only_files(&canonical_path)?;
                after_preflight(&canonical_path);
                let connection = open_read_only_connection(&canonical_path)?;
                disable_and_verify_checkpoint_on_close(&connection)?;
                opened_file_has_moved(&connection)?;
                verify_read_only_file_identities(&canonical_path, identities)?;
                set_and_verify_persistent_wal(&connection)?;
                before_live_read(&canonical_path);
                configure_read_only(&connection, &account, &key.0)?;
                after_live_read(&canonical_path);
                verify_read_only_file_identities(&canonical_path, identities)?;
                Ok(Self {
                    account,
                    connection: Mutex::new(connection),
                })
            })();
            key.0.zeroize();
            outcome.map_err(mailbox_open_error)
        }

        fn checked_account(&self, account: &AccountId) -> Result<(), MailboxStoreError> {
            (self.account == *account)
                .then_some(())
                .ok_or(MailboxStoreError::Storage)
        }

        fn list(
            &self,
            thread: Option<&ThreadId>,
            limit: StoreLimit,
        ) -> Result<Vec<MessageEnvelope>, MailboxStoreError> {
            let mut connection = self
                .connection
                .lock()
                .map_err(|_poison| MailboxStoreError::Storage)?;
            list_envelopes(&mut connection, thread, limit)
        }

        fn load_complete_message(
            &self,
            id: &MessageId,
        ) -> Result<Option<Message>, MailboxStoreError> {
            let connection = self
                .connection
                .lock()
                .map_err(|_poison| MailboxStoreError::Storage)?;
            get_complete_message(&connection, id)
        }
    }

    impl SqlCipherMailboxStore {
        /// Opens or creates the database for `account` at caller-selected `path`.
        ///
        /// The key is consumed, applied before schema reads, and zeroized after
        /// use. A fresh file is claimed only when its `SQLite` schema is empty.
        ///
        /// # Errors
        ///
        /// Returns opaque corruption for a wrong key, unknown owner, invalid
        /// schema, or failed integrity validation; operational failures return
        /// opaque storage errors.
        pub fn open<P: AsRef<Path>>(
            account: AccountId,
            path: P,
            key: DatabaseKey,
        ) -> Result<Self, MailboxStoreError> {
            Self::open_with_scan(account, path, key, IntegrityScan::Full)
        }

        /// Opens like [`Self::open`], running the whole-database integrity
        /// scans only when `scan` is [`IntegrityScan::Full`].
        ///
        /// # Errors
        ///
        /// The same as [`Self::open`].
        pub fn open_with_scan<P: AsRef<Path>>(
            account: AccountId,
            path: P,
            key: DatabaseKey,
            scan: IntegrityScan,
        ) -> Result<Self, MailboxStoreError> {
            Self::open_inner_impl(account, path.as_ref(), key, scan, &mut |_point, _path| {
                Ok(())
            })
        }

        /// Opens the database for `account` at `path` ONLY if its file already
        /// exists; an absent file is `Ok(None)` and is NEVER created.
        ///
        /// This is the disconnect purge's open: [`Self::open`] claims and
        /// creates a fresh database for an absent path, and a teardown must
        /// never create artifacts for a never-connected account. The presence
        /// check runs before any open work; an I/O error checking it is
        /// UNKNOWN, not absent, and fails closed as storage — disconnect must
        /// not report a successful purge of data it could not even stat. The
        /// check is inherently TOCTOU, but benignly: a file that appears
        /// afterward is simply opened and purged, and nothing in this design
        /// deletes a database file.
        ///
        /// # Errors
        ///
        /// Returns the same errors as [`Self::open`] for a present file, and
        /// [`MailboxStoreError::Storage`] when the presence check itself fails.
        pub fn open_existing<P: AsRef<Path>>(
            account: AccountId,
            path: P,
            key: DatabaseKey,
        ) -> Result<Option<Self>, MailboxStoreError> {
            match path.as_ref().try_exists() {
                Ok(true) => Self::open(account, path, key).map(Some),
                Ok(false) => Ok(None),
                Err(_error) => Err(MailboxStoreError::Storage),
            }
        }

        #[cfg(test)]
        fn open_inner(
            account: AccountId,
            path: &Path,
            key: DatabaseKey,
            after_preflight: impl FnOnce(&Path),
        ) -> Result<Self, MailboxStoreError> {
            let mut after_preflight = Some(after_preflight);
            Self::open_inner_impl(
                account,
                path,
                key,
                IntegrityScan::Full,
                &mut |point, canonical_path| {
                    if point == WriterHook::AfterSnapshot {
                        after_preflight.take().expect("hook runs once")(canonical_path);
                    }
                    Ok(())
                },
            )
        }

        #[cfg(test)]
        fn open_inner_with_hooks(
            account: AccountId,
            path: &Path,
            key: DatabaseKey,
            after_preflight: impl FnOnce(&Path),
            after_open: impl FnOnce(&Path),
        ) -> Result<Self, MailboxStoreError> {
            let mut after_preflight = Some(after_preflight);
            let mut after_open = Some(after_open);
            Self::open_inner_impl(
                account,
                path,
                key,
                IntegrityScan::Full,
                &mut |point, canonical_path| {
                    match point {
                        WriterHook::AfterSnapshot => {
                            after_preflight.take().expect("hook runs once")(canonical_path);
                        }
                        WriterHook::AfterOpen => {
                            after_open.take().expect("hook runs once")(canonical_path);
                        }
                        _ => {}
                    }
                    Ok(())
                },
            )
        }

        #[cfg(test)]
        fn open_inner_with_writer_hook(
            account: AccountId,
            path: &Path,
            key: DatabaseKey,
            hook: &mut dyn FnMut(WriterHook, &Path) -> Result<(), OpenFailure>,
        ) -> Result<Self, MailboxStoreError> {
            Self::open_inner_impl(account, path, key, IntegrityScan::Full, hook)
        }

        fn open_inner_impl(
            account: AccountId,
            path: &Path,
            mut key: DatabaseKey,
            scan: IntegrityScan,
            hook: &mut dyn FnMut(WriterHook, &Path) -> Result<(), OpenFailure>,
        ) -> Result<Self, MailboxStoreError> {
            let canonical_path = canonical_database_path(path).map_err(|kind| match kind {
                OpenFailure::Corrupted => MailboxStoreError::Corrupted,
                OpenFailure::Storage => MailboxStoreError::Storage,
            })?;
            let mut leaf = LeafGuard::open(&canonical_path).map_err(|kind| match kind {
                OpenFailure::Corrupted => MailboxStoreError::Corrupted,
                OpenFailure::Storage => MailboxStoreError::Storage,
            })?;
            let existing_preflight = if leaf.snapshot.main.is_some() {
                let preflight =
                    match preflight_existing(&canonical_path, &account, &key.0, &leaf, scan) {
                        Ok(preflight) => preflight,
                        Err(kind) => {
                            key.0.zeroize();
                            return Err(mailbox_open_error(kind));
                        }
                    };
                if let Err(kind) = leaf.require_snapshot_unchanged() {
                    key.0.zeroize();
                    return Err(mailbox_open_error(kind));
                }
                Some(preflight)
            } else {
                None
            };
            if let Err(kind) = hook(WriterHook::AfterSnapshot, &canonical_path) {
                leaf.cleanup_fresh_candidates(hook, &canonical_path);
                key.0.zeroize();
                return Err(mailbox_open_error(kind));
            }
            if leaf.snapshot.is_fresh() {
                if let Err(kind) = hook(WriterHook::BeforeFreshClaim, &canonical_path) {
                    leaf.cleanup_fresh_candidates(hook, &canonical_path);
                    key.0.zeroize();
                    return Err(mailbox_open_error(kind));
                }
                if let Err(kind) = leaf.claim_fresh_main() {
                    leaf.cleanup_fresh_candidates(hook, &canonical_path);
                    key.0.zeroize();
                    return Err(mailbox_open_error(kind));
                }
                if let Err(kind) = hook(WriterHook::AfterFreshClaim, &canonical_path) {
                    leaf.cleanup_fresh_candidates(hook, &canonical_path);
                    key.0.zeroize();
                    return Err(mailbox_open_error(kind));
                }
            }
            let connection = match open_connection(&canonical_path) {
                Ok(connection) => connection,
                Err(kind) => {
                    leaf.cleanup_fresh_candidates(hook, &canonical_path);
                    key.0.zeroize();
                    return Err(mailbox_open_error(kind));
                }
            };
            let outcome = (|| {
                hook(WriterHook::AfterOpen, &canonical_path)?;
                if existing_preflight.is_some() {
                    leaf.require_snapshot_unchanged()?;
                }
                opened_file_has_moved(&connection)?;
                leaf.require_main_identity()?;
                let fresh = configure_storage(&connection, &account, &key.0)?;
                if fresh {
                    materialize_fresh_wal(&connection)?;
                }
                if fresh || existing_preflight.is_some_and(ExistingPreflight::permits_new_sidecars)
                {
                    // SQLite creates the WAL and SHM leaves under the process
                    // umask as soon as WAL is selected. Normalize those leaves
                    // through identity-bound descriptors before migration or
                    // final validation. Cleanup authority remains fresh-main
                    // O_EXCL provenance only.
                    leaf.normalize_fresh_leaves(hook, &canonical_path)?;
                }
                if fresh {
                    hook(WriterHook::AfterFreshWalNormalization, &canonical_path)?;
                    hook(WriterHook::BeforeFreshMigration, &canonical_path)?;
                    migrate_fresh(&connection, &account)?;
                    // Migration can create another coordination leaf; repeat
                    // the identity-bound normalization before accepting it.
                    leaf.normalize_fresh_leaves(hook, &canonical_path)?;
                    leaf.mark_fresh_migration_succeeded();
                    hook(WriterHook::AfterFreshMigration, &canonical_path)?;
                }
                set_and_verify_persistent_wal(&connection)?;
                validate_health(&connection, scan)?;
                if let Some(preflight) = existing_preflight {
                    leaf.require_existing_writer_state(preflight)?;
                }
                Ok(())
            })();
            key.0.zeroize();
            if let Err(kind) = outcome {
                // SQLite must release its handles before descriptor-relative cleanup.
                drop(connection);
                leaf.cleanup_fresh_candidates(hook, &canonical_path);
                return Err(mailbox_open_error(kind));
            }
            Ok(Self {
                account,
                connection: Mutex::new(connection),
                #[cfg(test)]
                fail_next_mutation: Mutex::new(None),
            })
        }

        #[cfg(test)]
        fn fail_next_mutation(&self) {
            if let Ok(mut failpoint) = self.fail_next_mutation.lock() {
                *failpoint = Some(1);
            }
        }

        #[cfg(test)]
        fn fail_mutation_at(&self, checkpoint: usize) {
            if let Ok(mut failpoint) = self.fail_next_mutation.lock() {
                *failpoint = Some(checkpoint);
            }
        }

        #[cfg(test)]
        fn take_failpoint(&self) -> Result<bool, MailboxStoreError> {
            let mut failpoint = self
                .fail_next_mutation
                .lock()
                .map_err(|_poison| MailboxStoreError::Storage)?;
            let Some(checkpoint) = *failpoint else {
                return Ok(false);
            };
            if checkpoint == 1 {
                *failpoint = None;
                return Ok(true);
            }
            *failpoint = Some(checkpoint - 1);
            Ok(false)
        }

        fn checked_account(&self, account: &AccountId) -> Result<(), MailboxStoreError> {
            (self.account == *account)
                .then_some(())
                .ok_or(MailboxStoreError::Storage)
        }

        fn with_connection<T>(
            &self,
            operation: impl FnOnce(&mut Connection) -> Result<T, MailboxStoreError>,
        ) -> Result<T, MailboxStoreError> {
            let mut connection = self
                .connection
                .lock()
                .map_err(|_poison| MailboxStoreError::Storage)?;
            operation(&mut connection)
        }

        /// Stores the account's broker routing subject in the binding row.
        ///
        /// The subject is an encrypted account-identifying broker routing
        /// key: it is never logged or displayed, and it is not an OAuth
        /// credential. Error values never echo the subject. Exactly one
        /// binding row must match the exact account, otherwise the store is
        /// corrupt.
        ///
        /// # Errors
        ///
        /// Returns storage for an account mismatch, an invalid subject (not
        /// 1..=255 bytes of printable non-space ASCII), or a backend failure,
        /// and corruption when the binding row is missing or mismatched.
        pub fn store_broker_subject(
            &self,
            account: &AccountId,
            subject: &str,
        ) -> Result<(), MailboxStoreError> {
            self.checked_account(account)?;
            if !is_valid_broker_subject(subject) {
                return Err(MailboxStoreError::Storage);
            }
            self.with_connection(|connection| {
                let changed = connection
                    .execute(
                        "UPDATE account_binding SET broker_subject = ?1 WHERE singleton = 1 AND account_id = ?2",
                        params![subject, account.as_str()],
                    )
                    .map_err(store_error)?;
                (changed == 1)
                    .then_some(())
                    .ok_or(MailboxStoreError::Corrupted)
            })
        }

        /// Loads the account's broker routing subject from the binding row.
        ///
        /// The subject is an encrypted account-identifying broker routing
        /// key: it is never logged or displayed, it is not an OAuth
        /// credential, and it is wrapped in [`Zeroizing`] immediately so its
        /// plaintext lifetime stays minimal. A SQL NULL subject returns
        /// `None`; a missing or mismatched binding row, a non-text subject, or
        /// text violating the stored shape is corruption, never `None`.
        ///
        /// # Errors
        ///
        /// Returns storage for an account mismatch or backend failure and
        /// corruption for a missing or mismatched binding row or an invalid
        /// persisted subject.
        pub fn load_broker_subject(
            &self,
            account: &AccountId,
        ) -> Result<Option<Zeroizing<String>>, MailboxStoreError> {
            self.checked_account(account)?;
            self.with_connection(|connection| {
                let row = connection.query_row(
                    "SELECT typeof(broker_subject), CASE WHEN typeof(broker_subject) = 'text' THEN broker_subject END, CASE WHEN typeof(account_id) = 'text' THEN account_id END FROM account_binding WHERE singleton = 1",
                    [],
                    |row| {
                        let subject_type: String = row.get(0)?;
                        let subject: Option<String> = row.get(1)?;
                        let binding: Option<String> = row.get(2)?;
                        Ok((subject_type, subject, binding))
                    },
                );
                let (subject_type, subject, binding) = match row {
                    Ok(values) => values,
                    Err(rusqlite::Error::QueryReturnedNoRows) => {
                        return Err(MailboxStoreError::Corrupted);
                    }
                    Err(error) => return Err(store_error(error)),
                };
                if binding.as_deref() != Some(account.as_str()) {
                    return Err(MailboxStoreError::Corrupted);
                }
                match subject_type.as_str() {
                    "null" => Ok(None),
                    "text" => {
                        let subject = subject.ok_or(MailboxStoreError::Corrupted)?;
                        if !is_valid_broker_subject(&subject) {
                            return Err(MailboxStoreError::Corrupted);
                        }
                        Ok(Some(Zeroizing::new(subject)))
                    }
                    _ => Err(MailboxStoreError::Corrupted),
                }
            })
        }

        /// Stores the account's Gmail address in the binding row for display.
        ///
        /// The address is protected only by the database encryption and is
        /// never logged. It is validated by construction, so this method
        /// does not re-check its shape; the column CHECK bounds reject a
        /// foreign write that bypasses this type.
        ///
        /// # Errors
        ///
        /// Returns storage for an account mismatch or backend failure and
        /// corruption for a missing or mismatched binding row.
        pub fn store_email_address(
            &self,
            account: &AccountId,
            email: &AccountEmail,
        ) -> Result<(), MailboxStoreError> {
            self.checked_account(account)?;
            self.with_connection(|connection| {
                let changed = connection
                    .execute(
                        "UPDATE account_binding SET email_address = ?1 WHERE singleton = 1 AND account_id = ?2",
                        params![email.as_str(), account.as_str()],
                    )
                    .map_err(store_error)?;
                (changed == 1)
                    .then_some(())
                    .ok_or(MailboxStoreError::Corrupted)
            })
        }

        /// Loads the account's Gmail address from the binding row.
        ///
        /// The address lives only in this account's database and is never
        /// logged. A store still on the previous schema has no address
        /// column, so the load returns `None` instead of failing. A SQL NULL
        /// address also returns `None`; a missing or mismatched binding row,
        /// a non-text address, or text violating the stored shape is
        /// corruption, never `None`.
        ///
        /// # Errors
        ///
        /// Returns storage for an account mismatch or backend failure and
        /// corruption for a missing or mismatched binding row or an invalid
        /// persisted address.
        pub fn load_email_address(
            &self,
            account: &AccountId,
        ) -> Result<Option<AccountEmail>, MailboxStoreError> {
            self.checked_account(account)?;
            self.with_connection(|connection| {
                let version: i64 = connection
                    .query_row("PRAGMA user_version", [], |row| row.get(0))
                    .map_err(store_error)?;
                if version == SCHEMA_VERSION_1 {
                    return Ok(None);
                }
                if version != VERSION {
                    return Err(MailboxStoreError::Corrupted);
                }
                let row = connection.query_row(
                    "SELECT typeof(email_address), CASE WHEN typeof(email_address) = 'text' THEN email_address END, CASE WHEN typeof(account_id) = 'text' THEN account_id END FROM account_binding WHERE singleton = 1",
                    [],
                    |row| {
                        let address_type: String = row.get(0)?;
                        let address: Option<String> = row.get(1)?;
                        let binding: Option<String> = row.get(2)?;
                        Ok((address_type, address, binding))
                    },
                );
                let (address_type, address, binding) = match row {
                    Ok(values) => values,
                    Err(rusqlite::Error::QueryReturnedNoRows) => {
                        return Err(MailboxStoreError::Corrupted);
                    }
                    Err(error) => return Err(store_error(error)),
                };
                if binding.as_deref() != Some(account.as_str()) {
                    return Err(MailboxStoreError::Corrupted);
                }
                match address_type.as_str() {
                    "null" => Ok(None),
                    "text" => {
                        let address = address.ok_or(MailboxStoreError::Corrupted)?;
                        AccountEmail::new(address)
                            .map(Some)
                            .map_err(|_error| MailboxStoreError::Corrupted)
                    }
                    _ => Err(MailboxStoreError::Corrupted),
                }
            })
        }

        /// Stores the account's OAuth refresh token in the binding row.
        ///
        /// The token is protected only by the database encryption and is never
        /// logged. It must be 1..=4096 bytes of printable non-space ASCII.
        ///
        /// # Errors
        ///
        /// Returns storage for an account mismatch, an invalid token, or a
        /// backend failure, and corruption when the binding row is missing or
        /// mismatched.
        pub fn store_refresh_token(
            &self,
            account: &AccountId,
            token: &str,
        ) -> Result<(), MailboxStoreError> {
            self.checked_account(account)?;
            if !is_valid_refresh_token(token) {
                return Err(MailboxStoreError::Storage);
            }
            self.update_refresh_token(account, Some(token))
        }

        /// Removes the account's OAuth refresh token, if any.
        ///
        /// # Errors
        ///
        /// Returns storage for an account mismatch or backend failure and
        /// corruption when the binding row is missing or mismatched.
        pub fn clear_refresh_token(&self, account: &AccountId) -> Result<(), MailboxStoreError> {
            self.checked_account(account)?;
            self.update_refresh_token(account, None)
        }

        fn update_refresh_token(
            &self,
            account: &AccountId,
            token: Option<&str>,
        ) -> Result<(), MailboxStoreError> {
            self.with_connection(|connection| {
                let changed = connection
                    .execute(
                        "UPDATE account_binding SET refresh_token = ?1 WHERE singleton = 1 AND account_id = ?2",
                        params![token, account.as_str()],
                    )
                    .map_err(store_error)?;
                (changed == 1)
                    .then_some(())
                    .ok_or(MailboxStoreError::Corrupted)
            })
        }

        /// Loads the account's OAuth refresh token.
        ///
        /// A SQL NULL token returns `None`; a missing or mismatched binding row,
        /// a non-text token, or text violating the stored shape is corruption.
        ///
        /// # Errors
        ///
        /// Returns storage for an account mismatch or backend failure and
        /// corruption for a missing or mismatched binding row or an invalid
        /// persisted token.
        pub fn load_refresh_token(
            &self,
            account: &AccountId,
        ) -> Result<Option<Zeroizing<String>>, MailboxStoreError> {
            self.checked_account(account)?;
            self.with_connection(|connection| {
                let row = connection.query_row(
                    "SELECT typeof(refresh_token), CASE WHEN typeof(refresh_token) = 'text' THEN refresh_token END, CASE WHEN typeof(account_id) = 'text' THEN account_id END FROM account_binding WHERE singleton = 1",
                    [],
                    |row| {
                        let token_type: String = row.get(0)?;
                        let token: Option<String> = row.get(1)?;
                        let binding: Option<String> = row.get(2)?;
                        Ok((token_type, token.map(Zeroizing::new), binding))
                    },
                );
                let (token_type, token, binding) = match row {
                    Ok(values) => values,
                    Err(rusqlite::Error::QueryReturnedNoRows) => {
                        return Err(MailboxStoreError::Corrupted);
                    }
                    Err(error) => return Err(store_error(error)),
                };
                if binding.as_deref() != Some(account.as_str()) {
                    return Err(MailboxStoreError::Corrupted);
                }
                match token_type.as_str() {
                    "null" => Ok(None),
                    "text" => {
                        let token = token.ok_or(MailboxStoreError::Corrupted)?;
                        if !is_valid_refresh_token(&token) {
                            return Err(MailboxStoreError::Corrupted);
                        }
                        Ok(Some(token))
                    }
                    _ => Err(MailboxStoreError::Corrupted),
                }
            })
        }

        fn upsert(&self, envelopes: &[MessageEnvelope]) -> Result<(), MailboxStoreError> {
            self.with_connection(|connection| {
                let transaction = connection.transaction().map_err(store_error)?;
                for envelope in envelopes {
                    write_envelope(&transaction, envelope, None)?;
                    #[cfg(test)]
                    if self.take_failpoint()? {
                        return Err(MailboxStoreError::Storage);
                    }
                }
                transaction.commit().map_err(store_error)
            })
        }

        fn put(&self, message: &Message) -> Result<(), MailboxStoreError> {
            self.with_connection(|connection| {
                let transaction = connection.transaction().map_err(store_error)?;
                write_envelope(
                    &transaction,
                    message.envelope(),
                    Some(message.content().as_bytes()),
                )?;
                #[cfg(test)]
                if self.take_failpoint()? {
                    return Err(MailboxStoreError::Storage);
                }
                transaction.commit().map_err(store_error)
            })
        }

        fn reconcile(
            &self,
            account: &AccountId,
            envelopes: &[MessageEnvelope],
            keep_limit: StoreLimit,
            fence: &IdentityHash,
        ) -> Result<Vec<MessageId>, MailboxStoreError> {
            if envelopes.len() > usize::from(StoreLimit::MAX) {
                return Err(MailboxStoreError::Storage);
            }
            self.with_connection(|connection| {
                // BEGIN IMMEDIATE takes the write lock up front, so the identity
                // fence read below cannot race a concurrent identity change and the
                // abort is deterministic rather than a snapshot-conflict at commit.
                let transaction = connection
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .map_err(store_error)?;
                let has_null_identifier: bool = transaction
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM messages WHERE message_id IS NULL)",
                        [],
                        |row| row.get(0),
                    )
                    .map_err(store_error)?;
                if has_null_identifier {
                    return Err(MailboxStoreError::Corrupted);
                }
                for envelope in envelopes {
                    write_envelope(&transaction, envelope, None)?;
                    #[cfg(test)]
                    if self.take_failpoint()? {
                        return Err(MailboxStoreError::Storage);
                    }
                }
                transaction.execute(
                    "DELETE FROM messages WHERE message_id NOT IN (SELECT message_id FROM messages ORDER BY received_at DESC, message_id ASC LIMIT ?1)",
                    params![i64::from(keep_limit.get())],
                ).map_err(store_error)?;
                #[cfg(test)]
                if self.take_failpoint()? {
                    return Err(MailboxStoreError::Storage);
                }
                let mut survivors = Vec::with_capacity(envelopes.len());
                let mut seen = HashSet::with_capacity(envelopes.len());
                {
                    let mut statement = transaction
                        .prepare("SELECT EXISTS(SELECT 1 FROM messages WHERE message_id = ?1)")
                        .map_err(store_error)?;
                    for envelope in envelopes {
                        if !seen.insert(envelope.message_id().clone()) {
                            continue;
                        }
                        let exists: bool = statement
                            .query_row(params![envelope.message_id().as_str()], |row| row.get(0))
                            .map_err(store_error)?;
                        if exists {
                            survivors.push(envelope.message_id().clone());
                        }
                    }
                }
                assert_identity_unchanged(&transaction, account, fence)?;
                transaction.commit().map_err(store_error)?;
                Ok(survivors)
            })
        }

        fn read_identity_hash(
            &self,
            account: &AccountId,
        ) -> Result<Option<[u8; 32]>, MailboxStoreError> {
            self.with_connection(|connection| {
                let row = connection.query_row(
                    "SELECT CASE WHEN typeof(identity_hash) = 'blob' AND length(identity_hash) = 32 THEN identity_hash END, CASE WHEN typeof(algo_version) = 'integer' THEN algo_version END FROM account_identity WHERE account_id = ?1",
                    params![account.as_str()],
                    |row| {
                        let hash: Option<Vec<u8>> = row.get(0)?;
                        let version: Option<i64> = row.get(1)?;
                        Ok((hash, version))
                    },
                );
                match row {
                    Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                    Err(error) => Err(store_error(error)),
                    Ok((Some(hash), Some(version))) if version == IDENTITY_ALGO_VERSION => {
                        let bytes: [u8; 32] = hash
                            .try_into()
                            .map_err(|_length| MailboxStoreError::Corrupted)?;
                        Ok(Some(bytes))
                    }
                    // A present-but-unreadable or version-incompatible row must
                    // fail closed, never degrade to "no identity yet".
                    Ok(_) => Err(MailboxStoreError::Corrupted),
                }
            })
        }

        fn write_identity_hash(
            &self,
            account: &AccountId,
            fresh: &[u8; 32],
            clear_mailbox: bool,
            expected: Option<&[u8; 32]>,
        ) -> Result<(), MailboxStoreError> {
            self.with_connection(|connection| {
                // BEGIN IMMEDIATE takes the write lock up front so the compare-and-
                // set read below cannot race a concurrent identity record and the
                // abort is deterministic — not a snapshot conflict at commit, and no
                // cross-process lock-upgrade busy from a read-then-write in DEFERRED.
                let transaction = connection
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .map_err(store_error)?;
                assert_identity_matches_expected(&transaction, account, expected)?;
                if clear_mailbox {
                    transaction
                        .execute("DELETE FROM messages", [])
                        .map_err(store_error)?;
                    #[cfg(test)]
                    if self.take_failpoint()? {
                        return Err(MailboxStoreError::Storage);
                    }
                    // Mailbox freshness belongs to the recorded identity. A
                    // replacement identity must not inherit prior mail's
                    // successful-sync timestamp, and this update commits with
                    // the mailbox clear and identity record below.
                    transaction
                        .execute(
                            "UPDATE account_lifecycle SET last_successful_sync_unix_millis = NULL WHERE singleton = 1",
                            [],
                        )
                        .map_err(store_error)?;
                    #[cfg(test)]
                    if self.take_failpoint()? {
                        return Err(MailboxStoreError::Storage);
                    }
                    // The display address belongs to the replaced identity's
                    // mailbox session too: cleared in this same commit, a
                    // replacement identity starts address-less until its own
                    // sync stores one, and the previous account's Gmail
                    // address never reaches the listing or the interface.
                    let cleared = transaction
                        .execute(
                            "UPDATE account_binding SET email_address = NULL WHERE singleton = 1 AND account_id = ?1",
                            params![account.as_str()],
                        )
                        .map_err(store_error)?;
                    if cleared != 1 {
                        return Err(MailboxStoreError::Corrupted);
                    }
                    #[cfg(test)]
                    if self.take_failpoint()? {
                        return Err(MailboxStoreError::Storage);
                    }
                }
                transaction
                    .execute(
                        "INSERT INTO account_identity (account_id, identity_hash, algo_version) VALUES (?1, ?2, ?3) ON CONFLICT(account_id) DO UPDATE SET identity_hash = excluded.identity_hash, algo_version = excluded.algo_version",
                        params![account.as_str(), &fresh[..], IDENTITY_ALGO_VERSION],
                    )
                    .map_err(store_error)?;
                #[cfg(test)]
                if self.take_failpoint()? {
                    return Err(MailboxStoreError::Storage);
                }
                transaction.commit().map_err(store_error)
            })
        }

        #[cfg(test)]
        fn write_identity_hash_with_version(
            &self,
            account: &AccountId,
            fresh: &[u8; 32],
            version: i64,
        ) -> Result<(), MailboxStoreError> {
            self.with_connection(|connection| {
                connection
                    .execute(
                        "INSERT INTO account_identity (account_id, identity_hash, algo_version) VALUES (?1, ?2, ?3) ON CONFLICT(account_id) DO UPDATE SET identity_hash = excluded.identity_hash, algo_version = excluded.algo_version",
                        params![account.as_str(), &fresh[..], version],
                    )
                    .map_err(store_error)?;
                Ok(())
            })
        }

        /// Destroys the account's local data in ONE transaction: every mailbox
        /// row and the account-identity row die in the same commit, so a crash
        /// mid-purge never leaves a half-torn-down account.
        ///
        /// PERMIT-HOLDER-ONLY, DESTRUCTIVE-ONLY: the caller must hold the
        /// slot's whole-cycle permit, and the purge takes no fence or identity
        /// hash — it cannot inject stale state, only destroy. `messages` is
        /// cleared WITHOUT an account clause (the database file is per-account,
        /// exactly as the identity-clearing reconcile does), and the
        /// `account_binding` singleton is deliberately left intact: the file
        /// stays bound to its account, so a later re-connect passes the
        /// open-time binding check instead of failing as an unknown owner. Its
        /// `broker_subject` — the encrypted account-identifying broker routing
        /// key, never an OAuth credential — and the `refresh_token` credential
        /// are cleared in the same commit, because neither may outlive the
        /// account's local data.
        fn purge(&self, account: &AccountId) -> Result<(), MailboxStoreError> {
            self.with_connection(|connection| {
                // BEGIN IMMEDIATE takes the write lock up front, mirroring the
                // reconcile clear+write transaction: both DELETE statements
                // commit or roll back together.
                let transaction = connection
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .map_err(store_error)?;
                transaction
                    .execute("DELETE FROM messages", [])
                    .map_err(store_error)?;
                #[cfg(test)]
                if self.take_failpoint()? {
                    return Err(MailboxStoreError::Storage);
                }
                transaction
                    .execute(
                        "DELETE FROM account_identity WHERE account_id = ?1",
                        params![account.as_str()],
                    )
                    .map_err(store_error)?;
                let cleared = transaction
                    .execute(
                        "UPDATE account_binding SET broker_subject = NULL, refresh_token = NULL WHERE singleton = 1 AND account_id = ?1",
                        params![account.as_str()],
                    )
                    .map_err(store_error)?;
                if cleared != 1 {
                    return Err(MailboxStoreError::Corrupted);
                }
                // Freshness is mailbox-derived and must never outlive a local
                // purge. The disconnect recovery marker is intentionally NOT
                // cleared here: it is the durable evidence that tells a later
                // retry/relaunch whether provider revoke remained unconfirmed.
                transaction
                    .execute(
                        "UPDATE account_lifecycle SET last_successful_sync_unix_millis = NULL WHERE singleton = 1",
                        [],
                    )
                    .map_err(store_error)?;
                #[cfg(test)]
                if self.take_failpoint()? {
                    return Err(MailboxStoreError::Storage);
                }
                transaction.commit().map_err(store_error)
            })
        }

        fn read_lifecycle_metadata(&self) -> Result<AccountLifecycleMetadata, MailboxStoreError> {
            self.with_connection(|connection| {
                let row = connection.query_row(
                    "SELECT typeof(disconnect_recovery), CASE WHEN typeof(disconnect_recovery) = 'integer' THEN disconnect_recovery ELSE 0 END, typeof(last_successful_sync_unix_millis), CASE WHEN typeof(last_successful_sync_unix_millis) = 'integer' THEN last_successful_sync_unix_millis ELSE 0 END FROM account_lifecycle WHERE singleton = 1",
                    [],
                    |row| {
                        let recovery_type: String = row.get(0)?;
                        let recovery_value: i64 = row.get(1)?;
                        let freshness_type: String = row.get(2)?;
                        let freshness_value: i64 = row.get(3)?;
                        Ok((recovery_type, recovery_value, freshness_type, freshness_value))
                    },
                );
                let (recovery_type, recovery_value, freshness_type, freshness_value) = match row {
                    Ok(values) => values,
                    Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(AccountLifecycleMetadata::default()),
                    Err(error) => return Err(store_error(error)),
                };
                let recovery = match (recovery_type.as_str(), recovery_value) {
                    ("null", _) => None,
                    ("integer", 1) => Some(DisconnectRecoveryState::IncompleteTeardown),
                    ("integer", 2) => Some(DisconnectRecoveryState::RevokeUnconfirmed),
                    _ => return Err(MailboxStoreError::Corrupted),
                };
                let freshness = match (freshness_type.as_str(), freshness_value) {
                    ("null", _) => None,
                    ("integer", value) if value >= 0 => Some(value),
                    _ => return Err(MailboxStoreError::Corrupted),
                };
                AccountLifecycleMetadata::new(recovery, freshness)
                    .ok_or(MailboxStoreError::Corrupted)
            })
        }

        fn update_recovery(
            &self,
            recovery: Option<DisconnectRecoveryState>,
        ) -> Result<(), MailboxStoreError> {
            let value = recovery.map_or(0_i64, |state| match state {
                DisconnectRecoveryState::IncompleteTeardown => 1,
                DisconnectRecoveryState::RevokeUnconfirmed => 2,
            });
            self.with_connection(|connection| {
                connection
                    .execute(
                        "INSERT INTO account_lifecycle (singleton, disconnect_recovery, last_successful_sync_unix_millis) VALUES (1, NULLIF(?1, 0), NULL) ON CONFLICT(singleton) DO UPDATE SET disconnect_recovery = excluded.disconnect_recovery",
                        params![value],
                    )
                    .map_err(store_error)?;
                Ok(())
            })
        }

        fn record_successful_sync_at(&self, unix_millis: i64) -> Result<(), MailboxStoreError> {
            if unix_millis < 0 {
                return Err(MailboxStoreError::Corrupted);
            }
            self.with_connection(|connection| {
                connection
                    .execute(
                        "INSERT INTO account_lifecycle (singleton, disconnect_recovery, last_successful_sync_unix_millis) VALUES (1, NULL, ?1) ON CONFLICT(singleton) DO UPDATE SET last_successful_sync_unix_millis = excluded.last_successful_sync_unix_millis",
                        params![unix_millis],
                    )
                    .map_err(store_error)?;
                Ok(())
            })
        }

        fn cache_if_present(
            &self,
            account: &AccountId,
            message: &Message,
            fence: &IdentityHash,
        ) -> Result<bool, MailboxStoreError> {
            self.with_connection(|connection| {
                let transaction = connection
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .map_err(store_error)?;
                let changed = transaction.execute(
                    "UPDATE messages SET thread_id = ?2, sender = ?3, subject = ?4, preview = ?5, received_at = ?6, unread = CASE WHEN unread = 0 THEN 0 ELSE ?7 END, content = ?8 WHERE message_id = ?1",
                    params![message.envelope().message_id().as_str(), message.envelope().thread_id().as_str(), message.envelope().from().as_str(), message.envelope().subject().as_str(), message.envelope().preview().as_str(), message.envelope().received_at().as_millis(), i64::from(message.envelope().is_unread()), message.content().as_bytes()],
                ).map_err(store_error)?;
                #[cfg(test)]
                if self.take_failpoint()? {
                    return Err(MailboxStoreError::Storage);
                }
                // Fence the body write too: `messages` is keyed by message_id alone,
                // and Gmail message IDs are not guaranteed distinct across accounts,
                // so a stale body-fetch could otherwise land on a colliding row in a
                // different account's mailbox.
                assert_identity_unchanged(&transaction, account, fence)?;
                transaction.commit().map_err(store_error)?;
                Ok(changed == 1)
            })
        }

        fn list(
            &self,
            thread: Option<&ThreadId>,
            limit: StoreLimit,
        ) -> Result<Vec<MessageEnvelope>, MailboxStoreError> {
            self.with_connection(|connection| list_envelopes(connection, thread, limit))
        }

        fn load_complete_message(
            &self,
            id: &MessageId,
        ) -> Result<Option<Message>, MailboxStoreError> {
            self.with_connection(|connection| get_complete_message(connection, id))
        }

        fn mark_one_message_read(&self, message_id: &MessageId) -> Result<(), MailboxStoreError> {
            self.with_connection(|connection| {
                connection
                    .execute(
                        "UPDATE messages SET unread = 0 WHERE message_id = ?1 AND unread = 1",
                        params![message_id.as_str()],
                    )
                    .map_err(store_error)?;
                Ok(())
            })
        }

        fn mark_one_thread_read(&self, thread_id: &ThreadId) -> Result<(), MailboxStoreError> {
            self.with_connection(|connection| {
                connection
                    .execute(
                        "UPDATE messages SET unread = 0 WHERE thread_id = ?1 AND unread = 1",
                        params![thread_id.as_str()],
                    )
                    .map_err(store_error)?;
                Ok(())
            })
        }
    }

    fn get_complete_message(
        connection: &Connection,
        id: &MessageId,
    ) -> Result<Option<Message>, MailboxStoreError> {
        let max_content_len = i64::try_from(MessageContent::MAX_LEN)
            .map_err(|_error| MailboxStoreError::Corrupted)?;
        let mut statement = connection
            .prepare(
                "SELECT CASE WHEN typeof(message_id) = 'text' AND length(CAST(message_id AS BLOB)) <= 256 THEN message_id END, \
                 CASE WHEN typeof(thread_id) = 'text' AND length(CAST(thread_id AS BLOB)) <= 256 THEN thread_id END, \
                 CASE WHEN typeof(sender) = 'text' AND length(CAST(sender AS BLOB)) <= 1024 THEN sender END, \
                 CASE WHEN typeof(subject) = 'text' AND length(CAST(subject AS BLOB)) <= 1024 THEN subject END, \
                 CASE WHEN typeof(preview) = 'text' AND length(CAST(preview AS BLOB)) <= 1024 THEN preview END, \
                 CASE WHEN typeof(received_at) = 'integer' THEN received_at END, \
                 CASE WHEN typeof(unread) = 'integer' THEN unread END, \
                 CASE WHEN content IS NULL THEN 0 WHEN typeof(content) = 'blob' AND length(content) <= ?2 THEN 1 ELSE -1 END, \
                 CASE WHEN typeof(content) = 'blob' AND length(content) <= ?2 THEN content END \
                 FROM messages WHERE message_id = ?1",
            )
            .map_err(store_error)?;
        let mut rows = statement
            .query(params![id.as_str(), max_content_len])
            .map_err(store_error)?;
        let Some(row) = rows.next().map_err(store_error)? else {
            return Ok(None);
        };
        let envelope = envelope_from_row(row)?;
        match row.get::<_, i64>(7).map_err(corrupted)? {
            0 => Ok(None),
            1 => {
                let content: Vec<u8> = row.get(8).map_err(corrupted)?;
                MessageContent::new(content)
                    .map_err(|_error| MailboxStoreError::Corrupted)
                    .map(|content| Some(Message::new(envelope, content)))
            }
            _ => Err(MailboxStoreError::Corrupted),
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct FileIdentity {
        device: u64,
        inode: u64,
        owner: u32,
        mode: fs::RawMode,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct DirectoryIdentity {
        device: u64,
        inode: u64,
        owner: u32,
        mode: fs::RawMode,
    }

    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    struct RecoveryStageLeaves {
        main: Option<FileIdentity>,
        wal: Option<FileIdentity>,
        shm: Option<FileIdentity>,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum RecoveryLeafKind {
        MainDatabase,
        WriteAheadLog,
    }

    impl RecoveryLeafKind {
        fn accepts_size(self, size: i64) -> bool {
            match self {
                Self::MainDatabase => size >= 512,
                Self::WriteAheadLog => size == 0 || size >= 32,
            }
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct RecoveryLeafExpectation {
        identity: FileIdentity,
        kind: RecoveryLeafKind,
    }

    impl RecoveryLeafExpectation {
        const fn main_database(identity: FileIdentity) -> Self {
            Self {
                identity,
                kind: RecoveryLeafKind::MainDatabase,
            }
        }

        const fn write_ahead_log(identity: FileIdentity) -> Self {
            Self {
                identity,
                kind: RecoveryLeafKind::WriteAheadLog,
            }
        }
    }

    const OWNER_ONLY_FILE_MODE: fs::RawMode = 0o600;

    /// Testable boundaries around fresh-leaf claiming, migration, and cleanup.
    ///
    /// The cleanup gaps are intentionally observable: a same-user process can
    /// insert after the snapshot or replace after final revalidation. macOS has
    /// no unlink-if-inode primitive, so those two cases are documented residuals.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum WriterHook {
        AfterSnapshot,
        BeforeFreshClaim,
        AfterFreshClaim,
        AfterOpen,
        BeforeFreshMigration,
        AfterFreshWalNormalization,
        AfterFreshMigration,
        CleanupBeforeRecord(usize),
        CleanupAfterRecord(usize),
        CleanupAfterRevalidate(usize),
        NormalizeAfterOpen(usize),
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct LeafSnapshot {
        main: Option<FileIdentity>,
        journal: Option<FileIdentity>,
        wal: Option<FileIdentity>,
        shm: Option<FileIdentity>,
    }

    impl LeafSnapshot {
        fn is_fresh(self) -> bool {
            self.main.is_none()
                && self.journal.is_none()
                && self.wal.is_none()
                && self.shm.is_none()
        }
    }

    /// Retains the validated account parent while a writer claims a fresh leaf.
    ///
    /// The `SQLite` opener remains pathname-based. This guard exists only for
    /// no-follow snapshots and bounded cleanup of files absent at preflight.
    struct LeafGuard {
        parent: OwnedFd,
        parent_owner: u32,
        names: [OsString; 4],
        snapshot: LeafSnapshot,
        fresh_main: Option<FileIdentity>,
        fresh_migration_succeeded: bool,
    }

    impl LeafGuard {
        fn open(path: &Path) -> Result<Self, OpenFailure> {
            let parent = path.parent().ok_or(OpenFailure::Storage)?;
            let name = path.file_name().ok_or(OpenFailure::Storage)?;
            let names = leaf_names(name);
            let parent = fs::openat(
                CWD,
                parent,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_error| OpenFailure::Storage)?;
            let parent_stat = fs::fstat(&parent).map_err(|_error| OpenFailure::Storage)?;
            if FileType::from_raw_mode(parent_stat.st_mode) != FileType::Directory {
                return Err(OpenFailure::Storage);
            }
            let parent_owner = parent_stat.st_uid;
            let snapshot = snapshot_leaf_entries(&parent, parent_owner, &names)?;
            // Existing writer-visible leaves are accepted only at the exact
            // owner-only mode. A pre-existing leaf has no creation provenance
            // from this opener and is never normalized or adopted.
            if [snapshot.main, snapshot.wal, snapshot.shm]
                .into_iter()
                .flatten()
                .any(|identity| identity.mode != OWNER_ONLY_FILE_MODE)
            {
                return Err(OpenFailure::Storage);
            }
            if snapshot.main.is_none()
                && (snapshot.journal.is_some() || snapshot.wal.is_some() || snapshot.shm.is_some())
            {
                return Err(OpenFailure::Corrupted);
            }
            Ok(Self {
                parent,
                parent_owner,
                names,
                snapshot,
                fresh_main: None,
                fresh_migration_succeeded: false,
            })
        }

        fn claim_fresh_main(&mut self) -> Result<(), OpenFailure> {
            let descriptor = fs::openat(
                &self.parent,
                &self.names[0],
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(OWNER_ONLY_FILE_MODE),
            )
            .map_err(|_error| OpenFailure::Storage)?;
            // O_CREAT's mode is filtered by umask.  This descriptor is still
            // exclusively ours, so normalize before exact-mode validation.
            fs::fchmod(&descriptor, Mode::from_raw_mode(OWNER_ONLY_FILE_MODE))
                .map_err(|_error| OpenFailure::Storage)?;
            let identity = restrictive_regular_identity(
                &fs::fstat(&descriptor).map_err(|_error| OpenFailure::Storage)?,
                self.parent_owner,
            )?;
            drop(descriptor);
            self.fresh_main = Some(identity);
            Ok(())
        }

        fn require_main_identity(&self) -> Result<(), OpenFailure> {
            let expected = self
                .fresh_main
                .or(self.snapshot.main)
                .ok_or(OpenFailure::Storage)?;
            let actual = leaf_entry(&self.parent, &self.names[0], self.parent_owner)?
                .ok_or(OpenFailure::Storage)?;
            (actual == expected)
                .then_some(())
                .ok_or(OpenFailure::Storage)
        }

        fn require_snapshot_unchanged(&self) -> Result<(), OpenFailure> {
            (snapshot_leaf_entries(&self.parent, self.parent_owner, &self.names)? == self.snapshot)
                .then_some(())
                .ok_or(OpenFailure::Storage)
        }

        fn require_existing_writer_state(
            &self,
            preflight: ExistingPreflight,
        ) -> Result<(), OpenFailure> {
            let actual = snapshot_leaf_entries(&self.parent, self.parent_owner, &self.names)?;
            let unchanged = actual.main == self.snapshot.main
                && actual.journal == self.snapshot.journal
                && match preflight {
                    ExistingPreflight::Stable | ExistingPreflight::FreshWal => {
                        actual.wal == self.snapshot.wal && actual.shm == self.snapshot.shm
                    }
                    ExistingPreflight::MainWithoutSidecars => {
                        actual.wal.is_some() && actual.shm.is_some()
                    }
                    ExistingPreflight::WalWithoutShm | ExistingPreflight::FreshWalWithoutShm => {
                        actual.wal == self.snapshot.wal && actual.shm.is_some()
                    }
                };
            let exact_owner_only_modes = [actual.main, actual.wal, actual.shm]
                .into_iter()
                .flatten()
                .all(|identity| identity.mode == OWNER_ONLY_FILE_MODE);
            (unchanged && exact_owner_only_modes)
                .then_some(())
                .ok_or(OpenFailure::Storage)
        }

        fn mark_fresh_migration_succeeded(&mut self) {
            self.fresh_migration_succeeded = true;
        }

        fn normalize_fresh_leaves(
            &mut self,
            hook: &mut dyn FnMut(WriterHook, &Path) -> Result<(), OpenFailure>,
            canonical_path: &Path,
        ) -> Result<(), OpenFailure> {
            let before = [
                self.snapshot.main,
                self.snapshot.journal,
                self.snapshot.wal,
                self.snapshot.shm,
            ];
            for (index, (name, prior)) in self.names.iter().zip(before).enumerate() {
                let Some(identity) = leaf_entry(&self.parent, name, self.parent_owner)? else {
                    continue;
                };
                if prior.is_none() {
                    if identity.mode != OWNER_ONLY_FILE_MODE {
                        // SQLite may create a sidecar as 0000 under a highly
                        // restrictive umask. Normalize through the retained
                        // parent before opening, then bind the descriptor to
                        // this pre-chmod identity and normalize it again.
                        chmod_no_follow_at(
                            &self.parent,
                            name,
                            Mode::from_raw_mode(OWNER_ONLY_FILE_MODE),
                        )
                        .map_err(|_error| OpenFailure::Storage)?;
                    }
                    let descriptor = fs::openat(
                        &self.parent,
                        name,
                        OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                        Mode::empty(),
                    )
                    .map_err(|_error| OpenFailure::Storage)?;
                    let opened = regular_identity(
                        &fs::fstat(&descriptor).map_err(|_error| OpenFailure::Storage)?,
                        self.parent_owner,
                    )?;
                    if opened.device != identity.device || opened.inode != identity.inode {
                        return Err(OpenFailure::Storage);
                    }
                    hook(WriterHook::NormalizeAfterOpen(index), canonical_path)?;
                    fs::fchmod(&descriptor, Mode::from_raw_mode(OWNER_ONLY_FILE_MODE))
                        .map_err(|_error| OpenFailure::Storage)?;
                    let normalized_descriptor = restrictive_regular_identity(
                        &fs::fstat(&descriptor).map_err(|_error| OpenFailure::Storage)?,
                        self.parent_owner,
                    )?;
                    if normalized_descriptor.device != identity.device
                        || normalized_descriptor.inode != identity.inode
                    {
                        return Err(OpenFailure::Storage);
                    }
                }
                let normalized = leaf_entry(&self.parent, name, self.parent_owner)?
                    .ok_or(OpenFailure::Storage)?;
                if normalized.device != identity.device
                    || normalized.inode != identity.inode
                    || normalized.mode != OWNER_ONLY_FILE_MODE
                {
                    return Err(OpenFailure::Storage);
                }
            }
            self.require_main_identity()
        }

        fn cleanup_fresh_candidates(
            &self,
            hook: &mut dyn FnMut(WriterHook, &Path) -> Result<(), OpenFailure>,
            canonical_path: &Path,
        ) {
            // Cleanup authority exists only after this opener proved authorship
            // of the main leaf with an exclusive create. A pre-existing or
            // racing main file never grants cleanup authority for itself or for
            // any sidecar.
            let Some(fresh_main) = self.fresh_main else {
                return;
            };
            if self.fresh_migration_succeeded {
                return;
            }
            // Sidecars are removed before the main leaf. Before every unlink,
            // the main name must still resolve to the exact O_EXCL-created
            // identity that granted this cleanup authority. A replacement,
            // deletion, or pre-existing main therefore preserves every
            // remaining leaf instead of being adopted for cleanup.
            for index in [3, 2, 1, 0] {
                if leaf_entry(&self.parent, &self.names[0], self.parent_owner)
                    .ok()
                    .flatten()
                    != Some(fresh_main)
                {
                    return;
                }
                let expected = (index == 0).then_some(fresh_main);
                if remove_unchanged_restrictive_leaf(
                    &self.parent,
                    &self.names[index],
                    self.parent_owner,
                    (index, expected),
                    (&self.names[0], fresh_main),
                    hook,
                    canonical_path,
                )
                .is_err()
                {
                    return;
                }
            }
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct ReadOnlyFileIdentities {
        main: FileIdentity,
        wal: FileIdentity,
        shm: FileIdentity,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ExistingPreflight {
        Stable,
        MainWithoutSidecars,
        WalWithoutShm,
        FreshWal,
        FreshWalWithoutShm,
    }

    impl ExistingPreflight {
        const fn permits_new_sidecars(self) -> bool {
            matches!(
                self,
                Self::MainWithoutSidecars | Self::WalWithoutShm | Self::FreshWalWithoutShm
            )
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum RecoveryHook {
        AfterDirectoryCreate,
        AfterDirectoryNormalize,
        AfterMainCopy,
        AfterWalCopy,
        BeforeReadOnlyOpen,
        AfterReadOnlyOpen,
        BeforeOriginalFinalRevalidate,
        BeforeCleanup,
    }

    fn canonical_database_path(path: &Path) -> Result<PathBuf, OpenFailure> {
        let file_name = path.file_name().ok_or(OpenFailure::Storage)?;
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let canonical_parent =
            std::fs::canonicalize(parent).map_err(|_error| OpenFailure::Storage)?;
        Ok(canonical_parent.join(file_name))
    }

    fn leaf_names(name: &OsStr) -> [OsString; 4] {
        let mut journal = name.to_os_string();
        journal.push("-journal");
        let mut wal = name.to_os_string();
        wal.push("-wal");
        let mut shm = name.to_os_string();
        shm.push("-shm");
        [name.to_os_string(), journal, wal, shm]
    }

    fn snapshot_leaf_entries(
        parent: &OwnedFd,
        parent_owner: u32,
        names: &[OsString; 4],
    ) -> Result<LeafSnapshot, OpenFailure> {
        Ok(LeafSnapshot {
            main: leaf_entry(parent, &names[0], parent_owner)?,
            journal: leaf_entry(parent, &names[1], parent_owner)?,
            wal: leaf_entry(parent, &names[2], parent_owner)?,
            shm: leaf_entry(parent, &names[3], parent_owner)?,
        })
    }

    fn leaf_entry(
        parent: &OwnedFd,
        name: &OsStr,
        parent_owner: u32,
    ) -> Result<Option<FileIdentity>, OpenFailure> {
        match fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => regular_identity(&stat, parent_owner).map(Some),
            Err(error) if error == rustix::io::Errno::NOENT => Ok(None),
            Err(_error) => Err(OpenFailure::Storage),
        }
    }

    fn regular_identity(stat: &fs::Stat, parent_owner: u32) -> Result<FileIdentity, OpenFailure> {
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
            || stat.st_uid != parent_owner
        {
            return Err(OpenFailure::Storage);
        }
        Ok(FileIdentity {
            device: device_number(stat.st_dev)?,
            inode: stat.st_ino,
            owner: stat.st_uid,
            mode: Mode::from_raw_mode(stat.st_mode).as_raw_mode(),
        })
    }

    fn restrictive_regular_identity(
        stat: &fs::Stat,
        parent_owner: u32,
    ) -> Result<FileIdentity, OpenFailure> {
        let identity = regular_identity(stat, parent_owner)?;
        (identity.mode == OWNER_ONLY_FILE_MODE)
            .then_some(identity)
            .ok_or(OpenFailure::Storage)
    }

    fn remove_unchanged_restrictive_leaf(
        parent: &OwnedFd,
        name: &OsStr,
        parent_owner: u32,
        candidate: (usize, Option<FileIdentity>),
        cleanup_authority: (&OsStr, FileIdentity),
        hook: &mut dyn FnMut(WriterHook, &Path) -> Result<(), OpenFailure>,
        canonical_path: &Path,
    ) -> Result<(), OpenFailure> {
        let (index, expected) = candidate;
        // A hook error only stops this best-effort cleanup; the caller retains
        // its original redacted failure class.
        hook(WriterHook::CleanupBeforeRecord(index), canonical_path)?;
        let Some(recorded) = leaf_entry(parent, name, parent_owner)? else {
            return Ok(());
        };
        if expected.is_some_and(|identity| identity != recorded) {
            return Err(OpenFailure::Storage);
        }
        hook(WriterHook::CleanupAfterRecord(index), canonical_path)?;
        let Some(revalidated) = leaf_entry(parent, name, parent_owner)? else {
            return Ok(());
        };
        if recorded != revalidated {
            return Err(OpenFailure::Storage);
        }
        if recorded.mode != OWNER_ONLY_FILE_MODE {
            return Err(OpenFailure::Storage);
        }
        hook(WriterHook::CleanupAfterRevalidate(index), canonical_path)?;
        if leaf_entry(parent, cleanup_authority.0, parent_owner)? != Some(cleanup_authority.1) {
            return Err(OpenFailure::Storage);
        }
        match fs::unlinkat(parent, name, AtFlags::empty()) {
            Ok(()) => Ok(()),
            Err(error) if error == rustix::io::Errno::NOENT => Ok(()),
            Err(_error) => Err(OpenFailure::Storage),
        }
    }

    #[cfg(test)]
    fn prepare_database_leaf(path: &Path) -> Result<LeafSnapshot, OpenFailure> {
        let mut leaf = LeafGuard::open(path)?;
        if leaf.snapshot.is_fresh() {
            leaf.claim_fresh_main()?;
        }
        Ok(leaf.snapshot)
    }

    fn file_identity(path: &Path) -> Result<FileIdentity, OpenFailure> {
        let metadata = std::fs::symlink_metadata(path).map_err(|_error| OpenFailure::Storage)?;
        if !metadata.file_type().is_file() {
            return Err(OpenFailure::Storage);
        }
        Ok(identity_from_metadata(&metadata))
    }

    fn restrictive_file_identity(
        path: &Path,
        parent_owner: u32,
    ) -> Result<FileIdentity, OpenFailure> {
        let identity = file_identity(path)?;
        (identity.owner == parent_owner && identity.mode == OWNER_ONLY_FILE_MODE)
            .then_some(identity)
            .ok_or(OpenFailure::Storage)
    }

    /// Changes the mode of `name` under `parent` without following a symlink.
    ///
    /// macOS supports `fchmodat(AT_SYMLINK_NOFOLLOW)` directly. Linux has no
    /// `lchmod` and only honors that flag through `fchmodat2` (kernel 6.6+), so
    /// the inode is pinned with `O_PATH | O_NOFOLLOW`, rejected if it is a
    /// symlink, and changed through its `/proc/self/fd` entry, as glibc does.
    /// On Linux this needs `/proc` mounted; without it, normalization fails
    /// closed as a storage error (relevant to minimal containers).
    #[cfg(not(target_os = "linux"))]
    fn chmod_no_follow_at(parent: &OwnedFd, name: &OsStr, mode: Mode) -> rustix::io::Result<()> {
        fs::chmodat(parent, name, mode, AtFlags::SYMLINK_NOFOLLOW)
    }

    #[cfg(target_os = "linux")]
    fn chmod_no_follow_at(parent: &OwnedFd, name: &OsStr, mode: Mode) -> rustix::io::Result<()> {
        use rustix::fd::AsRawFd;

        let pinned = fs::openat(
            parent,
            name,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        if FileType::from_raw_mode(fs::fstat(&pinned)?.st_mode) == FileType::Symlink {
            return Err(rustix::io::Errno::LOOP);
        }
        fs::chmod(format!("/proc/self/fd/{}", pinned.as_raw_fd()), mode)
    }

    fn sidecar_path(path: &Path, suffix: &str) -> PathBuf {
        let mut name = path.as_os_str().to_os_string();
        name.push(suffix);
        PathBuf::from(name)
    }

    fn create_recovery_stage(
        leaf: &LeafGuard,
        canonical_path: &Path,
        hook: &mut dyn FnMut(RecoveryHook, &Path) -> Result<(), OpenFailure>,
    ) -> Result<(OwnedFd, OsString, PathBuf, DirectoryIdentity), OpenFailure> {
        let parent_path = canonical_path.parent().ok_or(OpenFailure::Storage)?;
        for slot in 0..RECOVERY_STAGE_LIMIT {
            let name = OsString::from(format!(".tersa-wal-recovery-v1-{slot}"));
            let path = parent_path.join(&name);
            match fs::mkdirat(&leaf.parent, &name, Mode::from_raw_mode(0o700)) {
                Ok(()) => {
                    let initial = recovery_directory_identity_permissive(
                        &leaf.parent,
                        &name,
                        leaf.parent_owner,
                    )?;
                    let setup = (|| {
                        hook(RecoveryHook::AfterDirectoryCreate, &path)?;
                        chmod_no_follow_at(&leaf.parent, &name, Mode::from_raw_mode(0o700))
                            .map_err(|_error| OpenFailure::Storage)?;
                        let normalized =
                            recovery_directory_identity(&leaf.parent, &name, leaf.parent_owner)?;
                        if !same_directory_object(initial, normalized) {
                            return Err(OpenFailure::Storage);
                        }
                        hook(RecoveryHook::AfterDirectoryNormalize, &path)?;
                        let directory = fs::openat(
                            &leaf.parent,
                            &name,
                            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                            Mode::empty(),
                        )
                        .map_err(|_error| OpenFailure::Storage)?;
                        let opened = directory_identity_from_stat(
                            &fs::fstat(&directory).map_err(|_error| OpenFailure::Storage)?,
                            leaf.parent_owner,
                            true,
                        )?;
                        if opened != normalized {
                            return Err(OpenFailure::Storage);
                        }
                        Ok((directory, normalized))
                    })();
                    return match setup {
                        Ok((directory, identity)) => Ok((directory, name, path, identity)),
                        Err(error) => {
                            let _ = cleanup_created_empty_recovery_directory(leaf, &name, initial);
                            Err(error)
                        }
                    };
                }
                Err(error) if error == rustix::io::Errno::EXIST => {}
                Err(_error) => return Err(OpenFailure::Storage),
            }
        }
        Err(OpenFailure::Storage)
    }

    fn copy_recovery_leaf(
        source_parent: &OwnedFd,
        source_name: &OsStr,
        source_owner: u32,
        expected: RecoveryLeafExpectation,
        destination_parent: &OwnedFd,
        destination_name: &OsStr,
        created: &mut Option<FileIdentity>,
    ) -> Result<FileIdentity, OpenFailure> {
        let source = fs::openat(
            source_parent,
            source_name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_error| OpenFailure::Storage)?;
        let source_stat = fs::fstat(&source).map_err(|_error| OpenFailure::Storage)?;
        if !expected.kind.accepts_size(source_stat.st_size) {
            return Err(OpenFailure::Corrupted);
        }
        let source_identity = restrictive_regular_identity(&source_stat, source_owner)?;
        if source_identity != expected.identity {
            return Err(OpenFailure::Storage);
        }
        let destination = fs::openat(
            destination_parent,
            destination_name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(OWNER_ONLY_FILE_MODE),
        )
        .map_err(|_error| OpenFailure::Storage)?;
        fs::fchmod(&destination, Mode::from_raw_mode(OWNER_ONLY_FILE_MODE))
            .map_err(|_error| OpenFailure::Storage)?;
        let destination_identity = restrictive_regular_identity(
            &fs::fstat(&destination).map_err(|_error| OpenFailure::Storage)?,
            source_owner,
        )?;
        *created = Some(destination_identity);

        let mut source_file = std::fs::File::from(source);
        let mut destination_file = std::fs::File::from(destination);
        io::copy(&mut source_file, &mut destination_file).map_err(|_error| OpenFailure::Storage)?;
        destination_file
            .sync_all()
            .map_err(|_error| OpenFailure::Storage)?;
        Ok(destination_identity)
    }

    fn directory_identity_from_stat(
        stat: &fs::Stat,
        owner: u32,
        exact_mode: bool,
    ) -> Result<DirectoryIdentity, OpenFailure> {
        let mode = Mode::from_raw_mode(stat.st_mode).as_raw_mode();
        if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
            || stat.st_uid != owner
            || if exact_mode {
                mode != 0o700
            } else {
                mode & !0o700 != 0
            }
        {
            return Err(OpenFailure::Storage);
        }
        Ok(DirectoryIdentity {
            device: device_number(stat.st_dev)?,
            inode: stat.st_ino,
            owner: stat.st_uid,
            mode,
        })
    }

    const fn same_directory_object(left: DirectoryIdentity, right: DirectoryIdentity) -> bool {
        left.device == right.device && left.inode == right.inode && left.owner == right.owner
    }

    fn recovery_directory_identity_permissive(
        parent: &OwnedFd,
        name: &OsStr,
        owner: u32,
    ) -> Result<DirectoryIdentity, OpenFailure> {
        let stat = fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_error| OpenFailure::Storage)?;
        directory_identity_from_stat(&stat, owner, false)
    }

    fn recovery_directory_identity(
        parent: &OwnedFd,
        name: &OsStr,
        owner: u32,
    ) -> Result<DirectoryIdentity, OpenFailure> {
        let stat = fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_error| OpenFailure::Storage)?;
        directory_identity_from_stat(&stat, owner, true)
    }

    fn cleanup_created_empty_recovery_directory(
        leaf: &LeafGuard,
        name: &OsStr,
        expected: DirectoryIdentity,
    ) -> Result<(), OpenFailure> {
        let actual = recovery_directory_identity_permissive(&leaf.parent, name, leaf.parent_owner)?;
        if !same_directory_object(actual, expected) {
            return Err(OpenFailure::Storage);
        }
        fs::unlinkat(&leaf.parent, name, AtFlags::REMOVEDIR).map_err(|_error| OpenFailure::Storage)
    }

    fn recovery_stage_has_only_expected_names(
        directory: &OwnedFd,
        leaf: &LeafGuard,
        expected: RecoveryStageLeaves,
    ) -> Result<(), OpenFailure> {
        let expected_names = [
            expected.main.is_some().then_some(&leaf.names[0]),
            None,
            expected.wal.is_some().then_some(&leaf.names[2]),
            expected.shm.is_some().then_some(&leaf.names[3]),
        ];
        let entries = fs::Dir::read_from(directory).map_err(|_error| OpenFailure::Storage)?;
        for entry in entries {
            let entry = entry.map_err(|_error| OpenFailure::Storage)?;
            let name = entry.file_name().to_bytes();
            if matches!(name, b"." | b"..") {
                continue;
            }
            if !expected_names
                .iter()
                .flatten()
                .any(|expected_name| expected_name.as_os_str().as_encoded_bytes() == name)
            {
                return Err(OpenFailure::Storage);
            }
        }
        Ok(())
    }

    fn cleanup_recovery_stage(
        leaf: &LeafGuard,
        directory: &OwnedFd,
        name: &OsStr,
        expected_directory: DirectoryIdentity,
        expected_leaves: RecoveryStageLeaves,
    ) -> Result<(), OpenFailure> {
        if recovery_directory_identity(&leaf.parent, name, leaf.parent_owner)? != expected_directory
            || directory_identity_from_stat(
                &fs::fstat(directory).map_err(|_error| OpenFailure::Storage)?,
                leaf.parent_owner,
                true,
            )? != expected_directory
        {
            return Err(OpenFailure::Storage);
        }
        recovery_stage_has_only_expected_names(directory, leaf, expected_leaves)?;

        let expected = [
            expected_leaves.main,
            None,
            expected_leaves.wal,
            expected_leaves.shm,
        ];
        for (leaf_name, expected_identity) in leaf.names.iter().zip(expected) {
            if leaf_entry(directory, leaf_name, leaf.parent_owner)? != expected_identity {
                return Err(OpenFailure::Storage);
            }
        }
        for (leaf_name, expected_identity) in leaf.names.iter().zip(expected).rev() {
            if let Some(expected_identity) = expected_identity {
                if leaf_entry(directory, leaf_name, leaf.parent_owner)? != Some(expected_identity) {
                    return Err(OpenFailure::Storage);
                }
                fs::unlinkat(directory, leaf_name, AtFlags::empty())
                    .map_err(|_error| OpenFailure::Storage)?;
            }
        }
        if recovery_directory_identity(&leaf.parent, name, leaf.parent_owner)? != expected_directory
        {
            return Err(OpenFailure::Storage);
        }
        fs::unlinkat(&leaf.parent, name, AtFlags::REMOVEDIR).map_err(|_error| OpenFailure::Storage)
    }

    fn verify_recovery_stage(
        leaf: &LeafGuard,
        directory: &OwnedFd,
        name: &OsStr,
        expected_directory: DirectoryIdentity,
        expected_main: FileIdentity,
        expected_wal: FileIdentity,
        expected_shm: FileIdentity,
    ) -> Result<(), OpenFailure> {
        if recovery_directory_identity(&leaf.parent, name, leaf.parent_owner)? != expected_directory
            || directory_identity_from_stat(
                &fs::fstat(directory).map_err(|_error| OpenFailure::Storage)?,
                leaf.parent_owner,
                true,
            )? != expected_directory
            || leaf_entry(directory, &leaf.names[0], leaf.parent_owner)? != Some(expected_main)
            || leaf_entry(directory, &leaf.names[2], leaf.parent_owner)? != Some(expected_wal)
            || leaf_entry(directory, &leaf.names[3], leaf.parent_owner)? != Some(expected_shm)
        {
            return Err(OpenFailure::Storage);
        }
        Ok(())
    }

    fn finish_recovery_validation(
        validation: Result<bool, OpenFailure>,
        cleanup_hook: Result<(), OpenFailure>,
        cleanup: Result<(), OpenFailure>,
    ) -> Result<bool, OpenFailure> {
        match validation {
            Err(error) => Err(error),
            Ok(fresh) => cleanup_hook.and(cleanup).map(|()| fresh),
        }
    }

    fn validate_wal_without_shm_from_private_copy(
        canonical_path: &Path,
        account: &AccountId,
        key: &[u8; 32],
        leaf: &LeafGuard,
    ) -> Result<bool, OpenFailure> {
        validate_wal_without_shm_from_private_copy_with_hook(
            canonical_path,
            account,
            key,
            leaf,
            &mut |_point, _path| Ok(()),
        )
    }

    fn validate_wal_without_shm_from_private_copy_with_hook(
        canonical_path: &Path,
        account: &AccountId,
        key: &[u8; 32],
        leaf: &LeafGuard,
        hook: &mut dyn FnMut(RecoveryHook, &Path) -> Result<(), OpenFailure>,
    ) -> Result<bool, OpenFailure> {
        let main = leaf.snapshot.main.ok_or(OpenFailure::Storage)?;
        let wal = leaf.snapshot.wal.ok_or(OpenFailure::Storage)?;
        let (directory, stage_name, stage_path, directory_identity) =
            create_recovery_stage(leaf, canonical_path, hook)?;
        let mut created_leaves = RecoveryStageLeaves::default();
        let validation = (|| {
            let copied_main = copy_recovery_leaf(
                &leaf.parent,
                &leaf.names[0],
                leaf.parent_owner,
                RecoveryLeafExpectation::main_database(main),
                &directory,
                &leaf.names[0],
                &mut created_leaves.main,
            )?;
            hook(RecoveryHook::AfterMainCopy, &stage_path)?;
            let copied_wal = copy_recovery_leaf(
                &leaf.parent,
                &leaf.names[2],
                leaf.parent_owner,
                RecoveryLeafExpectation::write_ahead_log(wal),
                &directory,
                &leaf.names[2],
                &mut created_leaves.wal,
            )?;
            hook(RecoveryHook::AfterWalCopy, &stage_path)?;
            let shm = fs::openat(
                &directory,
                &leaf.names[3],
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(OWNER_ONLY_FILE_MODE),
            )
            .map_err(|_error| OpenFailure::Storage)?;
            fs::fchmod(&shm, Mode::from_raw_mode(OWNER_ONLY_FILE_MODE))
                .map_err(|_error| OpenFailure::Storage)?;
            let copied_shm = restrictive_regular_identity(
                &fs::fstat(&shm).map_err(|_error| OpenFailure::Storage)?,
                leaf.parent_owner,
            )?;
            created_leaves.shm = Some(copied_shm);
            drop(shm);
            leaf.require_snapshot_unchanged()?;
            verify_recovery_stage(
                leaf,
                &directory,
                &stage_name,
                directory_identity,
                copied_main,
                copied_wal,
                copied_shm,
            )?;
            hook(RecoveryHook::BeforeReadOnlyOpen, &stage_path)?;
            let connection = open_read_only_connection(&stage_path.join(&leaf.names[0]))?;
            disable_and_verify_checkpoint_on_close(&connection)?;
            opened_file_has_moved(&connection)?;
            verify_recovery_stage(
                leaf,
                &directory,
                &stage_name,
                directory_identity,
                copied_main,
                copied_wal,
                copied_shm,
            )?;
            hook(RecoveryHook::AfterReadOnlyOpen, &stage_path)?;
            verify_recovery_stage(
                leaf,
                &directory,
                &stage_name,
                directory_identity,
                copied_main,
                copied_wal,
                copied_shm,
            )?;
            let fresh =
                validate_recovery_read_only(&connection, account, key, IntegrityScan::Full)?;
            verify_recovery_stage(
                leaf,
                &directory,
                &stage_name,
                directory_identity,
                copied_main,
                copied_wal,
                copied_shm,
            )?;
            drop(connection);
            hook(RecoveryHook::BeforeOriginalFinalRevalidate, &stage_path)?;
            leaf.require_snapshot_unchanged()?;
            Ok(fresh)
        })();
        let cleanup_hook = hook(RecoveryHook::BeforeCleanup, &stage_path);
        let cleanup = cleanup_recovery_stage(
            leaf,
            &directory,
            &stage_name,
            directory_identity,
            created_leaves,
        );
        finish_recovery_validation(validation, cleanup_hook, cleanup)
    }

    fn preflight_read_only_files(path: &Path) -> Result<ReadOnlyFileIdentities, OpenFailure> {
        let parent = path.parent().ok_or(OpenFailure::Storage)?;
        let parent_metadata =
            std::fs::symlink_metadata(parent).map_err(|_error| OpenFailure::Storage)?;
        if !parent_metadata.file_type().is_dir() {
            return Err(OpenFailure::Storage);
        }
        let parent_owner = parent_metadata.uid();
        let main_metadata =
            std::fs::symlink_metadata(path).map_err(|_error| OpenFailure::Storage)?;
        if !main_metadata.file_type().is_file() || main_metadata.len() < 512 {
            return Err(OpenFailure::Storage);
        }
        let main = identity_from_metadata(&main_metadata);
        if main.owner != parent_owner || main.mode != OWNER_ONLY_FILE_MODE {
            return Err(OpenFailure::Storage);
        }
        match std::fs::symlink_metadata(sidecar_path(path, "-journal")) {
            Ok(_metadata) => return Err(OpenFailure::Storage),
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(_error) => return Err(OpenFailure::Storage),
        }
        Ok(ReadOnlyFileIdentities {
            main,
            wal: restrictive_file_identity(&sidecar_path(path, "-wal"), parent_owner)?,
            shm: restrictive_file_identity(&sidecar_path(path, "-shm"), parent_owner)?,
        })
    }

    fn verify_read_only_file_identities(
        path: &Path,
        expected: ReadOnlyFileIdentities,
    ) -> Result<(), OpenFailure> {
        let parent_owner = expected.main.owner;
        let actual = ReadOnlyFileIdentities {
            main: restrictive_file_identity(path, parent_owner)?,
            wal: restrictive_file_identity(&sidecar_path(path, "-wal"), parent_owner)?,
            shm: restrictive_file_identity(&sidecar_path(path, "-shm"), parent_owner)?,
        };
        (actual == expected)
            .then_some(())
            .ok_or(OpenFailure::Storage)
    }

    /// Widens a platform `dev_t` (`i32` on macOS, `u64` on Linux) to `u64`.
    fn device_number<T: TryInto<u64>>(raw: T) -> Result<u64, OpenFailure> {
        raw.try_into().map_err(|_error| OpenFailure::Storage)
    }

    fn identity_from_metadata(metadata: &std::fs::Metadata) -> FileIdentity {
        FileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
            owner: metadata.uid(),
            mode: fs::RawMode::try_from(metadata.mode() & 0o7777).unwrap_or_default(),
        }
    }

    fn open_connection(path: &Path) -> Result<Connection, OpenFailure> {
        let base_flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let connection =
            Connection::open_with_flags(path, base_flags | OpenFlags::SQLITE_OPEN_NOFOLLOW)
                .map_err(|_error| OpenFailure::Storage)?;
        disable_and_verify_checkpoint_on_close(&connection)?;
        Ok(connection)
    }

    fn open_read_only_connection(path: &Path) -> Result<Connection, OpenFailure> {
        let flags = OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        Connection::open_with_flags(path, flags).map_err(|_error| OpenFailure::Storage)
    }

    fn disable_and_verify_checkpoint_on_close(connection: &Connection) -> Result<(), OpenFailure> {
        let config = DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE;
        if !connection
            .set_db_config(config, true)
            .map_err(|_error| OpenFailure::Storage)?
            || !connection
                .db_config(config)
                .map_err(|_error| OpenFailure::Storage)?
        {
            return Err(OpenFailure::Storage);
        }
        Ok(())
    }

    #[expect(
        unsafe_code,
        reason = "SQLite requires a mutable integer pointer for SQLITE_FCNTL_HAS_MOVED"
    )]
    fn opened_file_has_moved(connection: &Connection) -> Result<(), OpenFailure> {
        let mut has_moved = 0;
        // SAFETY: `connection.handle()` remains valid for this synchronous call;
        // `main` is a static NUL-terminated database name; and `has_moved` is a
        // writable `i32` whose address remains valid until SQLite returns.
        let result = unsafe {
            rusqlite::ffi::sqlite3_file_control(
                connection.handle(),
                c"main".as_ptr(),
                rusqlite::ffi::SQLITE_FCNTL_HAS_MOVED,
                (&raw mut has_moved).cast::<std::ffi::c_void>(),
            )
        };
        if result == rusqlite::ffi::SQLITE_OK && has_moved == 0 {
            Ok(())
        } else {
            // Unsupported file controls, unexpected VFS results, and a moved
            // opened file all fail closed before the key or database is read.
            Err(OpenFailure::Storage)
        }
    }

    fn preflight_existing(
        path: &Path,
        account: &AccountId,
        key: &[u8; 32],
        leaf: &LeafGuard,
        scan: IntegrityScan,
    ) -> Result<ExistingPreflight, OpenFailure> {
        let snapshot = leaf.snapshot;
        if snapshot.journal.is_some() || (snapshot.wal.is_none() && snapshot.shm.is_some()) {
            return Err(OpenFailure::Corrupted);
        }
        if snapshot.wal.is_some() && snapshot.shm.is_none() {
            // SQLite rejects both immutable and normal read-only opens for a
            // WAL without its shared-memory index. Validate encrypted copies
            // in a private, identity-bound staging directory. The original
            // main/WAL pair remains read-only and is revalidated before and
            // after logical key, account, schema, and health checks.
            let fresh = validate_wal_without_shm_from_private_copy(path, account, key, leaf)?;
            return Ok(if fresh {
                ExistingPreflight::FreshWalWithoutShm
            } else {
                ExistingPreflight::WalWithoutShm
            });
        }

        let uri = immutable_file_uri(path);
        let flags = OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let main_connection = Connection::open_with_flags(PathBuf::from(uri), flags)
            .map_err(|_error| OpenFailure::Storage)?;
        apply_key(&main_connection, key).map_err(classify_key)?;
        let _main_is_fresh = validate_identity(&main_connection, account)?;
        let Some(_wal) = snapshot.wal else {
            return Ok(ExistingPreflight::MainWithoutSidecars);
        };

        // `immutable=1` deliberately ignores WAL. When an otherwise fresh main
        // has a WAL, validate the logical database through a non-checkpointing
        // read-only connection so an abrupt first-migration exit can recover
        // without granting write, repair, or cleanup authority. If SHM is
        // missing, a private encrypted-copy path above performs validation
        // without modifying the original leaf set.
        let wal_connection = open_read_only_connection(path)?;
        disable_and_verify_checkpoint_on_close(&wal_connection)?;
        opened_file_has_moved(&wal_connection)?;
        let fresh = validate_recovery_read_only(&wal_connection, account, key, scan)?;
        Ok(if fresh {
            ExistingPreflight::FreshWal
        } else {
            ExistingPreflight::Stable
        })
    }

    fn immutable_file_uri(path: &Path) -> OsString {
        file_uri(path, b"?immutable=1")
    }

    fn file_uri(path: &Path, query: &[u8]) -> OsString {
        let mut uri =
            Vec::with_capacity(path.as_os_str().as_encoded_bytes().len() + query.len() + 8);
        uri.extend_from_slice(b"file:");
        for byte in path.as_os_str().as_encoded_bytes() {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'/') {
                uri.push(*byte);
            } else {
                uri.push(b'%');
                uri.push(hex_digit(byte >> 4));
                uri.push(hex_digit(byte & 0x0f));
            }
        }
        uri.extend_from_slice(query);
        OsString::from_vec(uri)
    }

    const fn hex_digit(value: u8) -> u8 {
        match value {
            0..=9 => b'0' + value,
            _ => b'A' + (value - 10),
        }
    }

    fn list_envelopes(
        connection: &mut Connection,
        thread: Option<&ThreadId>,
        limit: StoreLimit,
    ) -> Result<Vec<MessageEnvelope>, MailboxStoreError> {
        let sql = if thread.is_some() {
            "SELECT CASE WHEN typeof(message_id) = 'text' AND length(CAST(message_id AS BLOB)) <= 256 THEN message_id END, CASE WHEN typeof(thread_id) = 'text' AND length(CAST(thread_id AS BLOB)) <= 256 THEN thread_id END, CASE WHEN typeof(sender) = 'text' AND length(CAST(sender AS BLOB)) <= 1024 THEN sender END, CASE WHEN typeof(subject) = 'text' AND length(CAST(subject AS BLOB)) <= 1024 THEN subject END, CASE WHEN typeof(preview) = 'text' AND length(CAST(preview AS BLOB)) <= 1024 THEN preview END, CASE WHEN typeof(received_at) = 'integer' THEN received_at END, CASE WHEN typeof(unread) = 'integer' THEN unread END FROM messages WHERE thread_id = ?1 ORDER BY received_at ASC, message_id ASC LIMIT ?2"
        } else {
            "SELECT CASE WHEN typeof(message_id) = 'text' AND length(CAST(message_id AS BLOB)) <= 256 THEN message_id END, CASE WHEN typeof(thread_id) = 'text' AND length(CAST(thread_id AS BLOB)) <= 256 THEN thread_id END, CASE WHEN typeof(sender) = 'text' AND length(CAST(sender AS BLOB)) <= 1024 THEN sender END, CASE WHEN typeof(subject) = 'text' AND length(CAST(subject AS BLOB)) <= 1024 THEN subject END, CASE WHEN typeof(preview) = 'text' AND length(CAST(preview AS BLOB)) <= 1024 THEN preview END, CASE WHEN typeof(received_at) = 'integer' THEN received_at END, CASE WHEN typeof(unread) = 'integer' THEN unread END FROM messages ORDER BY received_at DESC, message_id ASC LIMIT ?1"
        };
        let mut statement = connection.prepare(sql).map_err(store_error)?;
        let mut rows = match thread {
            Some(thread_id) => statement.query(params![thread_id.as_str(), i64::from(limit.get())]),
            None => statement.query(params![i64::from(limit.get())]),
        }
        .map_err(store_error)?;
        let mut result = Vec::new();
        while let Some(row) = rows.next().map_err(store_error)? {
            result.push(envelope_from_row(row)?);
        }
        Ok(result)
    }

    /// The envelopes after a cursor, in listing order. The `<=` bound lets the
    /// `messages_list_order` index seek; the rest breaks ties.
    const ENVELOPES_AFTER_SQL: &str = "SELECT CASE WHEN typeof(message_id) = 'text' AND length(CAST(message_id AS BLOB)) <= 256 THEN message_id END, CASE WHEN typeof(thread_id) = 'text' AND length(CAST(thread_id AS BLOB)) <= 256 THEN thread_id END, CASE WHEN typeof(sender) = 'text' AND length(CAST(sender AS BLOB)) <= 1024 THEN sender END, CASE WHEN typeof(subject) = 'text' AND length(CAST(subject AS BLOB)) <= 1024 THEN subject END, CASE WHEN typeof(preview) = 'text' AND length(CAST(preview AS BLOB)) <= 1024 THEN preview END, CASE WHEN typeof(received_at) = 'integer' THEN received_at END, CASE WHEN typeof(unread) = 'integer' THEN unread END FROM messages WHERE received_at <= ?1 AND (received_at < ?1 OR message_id > ?2) ORDER BY received_at DESC, message_id ASC LIMIT ?3";

    /// Lists up to `limit` envelopes after `after`, seeking through the
    /// `messages_list_order` index rather than skipping rows.
    fn list_envelopes_after(
        connection: &Connection,
        after: Option<&EnvelopeCursor>,
        limit: StoreLimit,
    ) -> Result<Vec<MessageEnvelope>, MailboxStoreError> {
        let mut result = Vec::new();
        let limit = i64::from(limit.get());
        let mut push_rows = |rows: &mut rusqlite::Rows<'_>| -> Result<(), MailboxStoreError> {
            while let Some(row) = rows.next().map_err(store_error)? {
                result.push(envelope_from_row(row)?);
            }
            Ok(())
        };
        match after {
            None => {
                let mut statement = connection
                    .prepare("SELECT CASE WHEN typeof(message_id) = 'text' AND length(CAST(message_id AS BLOB)) <= 256 THEN message_id END, CASE WHEN typeof(thread_id) = 'text' AND length(CAST(thread_id AS BLOB)) <= 256 THEN thread_id END, CASE WHEN typeof(sender) = 'text' AND length(CAST(sender AS BLOB)) <= 1024 THEN sender END, CASE WHEN typeof(subject) = 'text' AND length(CAST(subject AS BLOB)) <= 1024 THEN subject END, CASE WHEN typeof(preview) = 'text' AND length(CAST(preview AS BLOB)) <= 1024 THEN preview END, CASE WHEN typeof(received_at) = 'integer' THEN received_at END, CASE WHEN typeof(unread) = 'integer' THEN unread END FROM messages ORDER BY received_at DESC, message_id ASC LIMIT ?1")
                    .map_err(store_error)?;
                push_rows(&mut statement.query(params![limit]).map_err(store_error)?)?;
            }
            Some(cursor) => {
                let mut statement = connection
                    .prepare(ENVELOPES_AFTER_SQL)
                    .map_err(store_error)?;
                push_rows(
                    &mut statement
                        .query(params![
                            cursor.received_at().as_millis(),
                            cursor.message_id().as_str(),
                            limit
                        ])
                        .map_err(store_error)?,
                )?;
            }
        }
        Ok(result)
    }

    impl MailboxStore for SqlCipherMailboxStore {
        fn mark_message_read<'a>(
            &'a self,
            account: &'a AccountId,
            message_id: &'a MessageId,
        ) -> BoxFuture<'a, Result<(), MailboxStoreError>> {
            Box::pin(async move {
                self.checked_account(account)?;
                self.mark_one_message_read(message_id)
            })
        }
        fn mark_thread_read<'a>(
            &'a self,
            account: &'a AccountId,
            thread_id: &'a ThreadId,
        ) -> BoxFuture<'a, Result<(), MailboxStoreError>> {
            Box::pin(async move {
                self.checked_account(account)?;
                self.mark_one_thread_read(thread_id)
            })
        }
        fn upsert_envelopes<'a>(
            &'a self,
            account: &'a AccountId,
            envelopes: &'a [MessageEnvelope],
        ) -> BoxFuture<'a, Result<(), MailboxStoreError>> {
            Box::pin(async move {
                self.checked_account(account)?;
                self.upsert(envelopes)
            })
        }
        fn put_message<'a>(
            &'a self,
            account: &'a AccountId,
            message: &'a Message,
        ) -> BoxFuture<'a, Result<(), MailboxStoreError>> {
            Box::pin(async move {
                self.checked_account(account)?;
                self.put(message)
            })
        }
        fn reconcile_recent_envelopes<'a>(
            &'a self,
            account: &'a AccountId,
            envelopes: &'a [MessageEnvelope],
            keep_limit: StoreLimit,
            fence: &'a IdentityHash,
        ) -> BoxFuture<'a, Result<Vec<MessageId>, MailboxStoreError>> {
            Box::pin(async move {
                self.checked_account(account)?;
                self.reconcile(account, envelopes, keep_limit, fence)
            })
        }
        fn cache_message_if_present<'a>(
            &'a self,
            account: &'a AccountId,
            message: &'a Message,
            fence: &'a IdentityHash,
        ) -> BoxFuture<'a, Result<bool, MailboxStoreError>> {
            Box::pin(async move {
                self.checked_account(account)?;
                self.cache_if_present(account, message, fence)
            })
        }
        fn message<'a>(
            &'a self,
            account: &'a AccountId,
            message_id: &'a MessageId,
        ) -> BoxFuture<'a, Result<Option<Message>, MailboxStoreError>> {
            Box::pin(async move {
                self.checked_account(account)?;
                self.load_complete_message(message_id)
            })
        }
    }

    impl AccountIdentityStore for SqlCipherMailboxStore {
        fn load_identity<'a>(
            &'a self,
            account: &'a AccountId,
        ) -> BoxFuture<'a, Result<Option<IdentityHash>, MailboxStoreError>> {
            Box::pin(async move {
                self.checked_account(account)?;
                Ok(self
                    .read_identity_hash(account)?
                    .map(IdentityHash::from_bytes))
            })
        }

        fn reconcile_identity<'a>(
            &'a self,
            account: &'a AccountId,
            fresh: &'a IdentityHash,
            action: IdentityReconcile,
            expected: Option<&'a IdentityHash>,
        ) -> BoxFuture<'a, Result<(), MailboxStoreError>> {
            Box::pin(async move {
                self.checked_account(account)?;
                let clear_mailbox = matches!(action, IdentityReconcile::ClearMailboxAndRecord);
                self.write_identity_hash(
                    account,
                    fresh.as_bytes(),
                    clear_mailbox,
                    expected.map(IdentityHash::as_bytes),
                )
            })
        }
    }

    impl AccountPurgeStore for SqlCipherMailboxStore {
        fn purge_account<'a>(
            &'a self,
            account: &'a AccountId,
        ) -> BoxFuture<'a, Result<(), MailboxStoreError>> {
            Box::pin(async move {
                self.checked_account(account)?;
                self.purge(account)
            })
        }
    }

    impl AccountLifecycleStore for SqlCipherMailboxStore {
        fn lifecycle_metadata<'a>(
            &'a self,
            account: &'a AccountId,
        ) -> BoxFuture<'a, Result<AccountLifecycleMetadata, MailboxStoreError>> {
            Box::pin(async move {
                self.checked_account(account)?;
                self.read_lifecycle_metadata()
            })
        }

        fn mark_disconnect_started<'a>(
            &'a self,
            account: &'a AccountId,
        ) -> BoxFuture<'a, Result<(), MailboxStoreError>> {
            Box::pin(async move {
                self.checked_account(account)?;
                self.update_recovery(Some(DisconnectRecoveryState::IncompleteTeardown))
            })
        }

        fn mark_revoke_unconfirmed<'a>(
            &'a self,
            account: &'a AccountId,
        ) -> BoxFuture<'a, Result<(), MailboxStoreError>> {
            Box::pin(async move {
                self.checked_account(account)?;
                self.update_recovery(Some(DisconnectRecoveryState::RevokeUnconfirmed))
            })
        }

        fn clear_disconnect_recovery<'a>(
            &'a self,
            account: &'a AccountId,
        ) -> BoxFuture<'a, Result<(), MailboxStoreError>> {
            Box::pin(async move {
                self.checked_account(account)?;
                self.update_recovery(None)
            })
        }

        fn record_successful_sync<'a>(
            &'a self,
            account: &'a AccountId,
            unix_millis: i64,
        ) -> BoxFuture<'a, Result<(), MailboxStoreError>> {
            Box::pin(async move {
                self.checked_account(account)?;
                self.record_successful_sync_at(unix_millis)
            })
        }
    }

    impl MailboxReader for SqlCipherMailboxStore {
        fn list_envelopes<'a>(
            &'a self,
            account: &'a AccountId,
            limit: StoreLimit,
        ) -> BoxFuture<'a, Result<Vec<MessageEnvelope>, MailboxStoreError>> {
            Box::pin(async move {
                self.checked_account(account)?;
                self.list(None, limit)
            })
        }

        fn get_message<'a>(
            &'a self,
            account: &'a AccountId,
            message_id: &'a MessageId,
        ) -> BoxFuture<'a, Result<Option<Message>, MailboxStoreError>> {
            Box::pin(async move {
                self.checked_account(account)?;
                self.load_complete_message(message_id)
            })
        }
        fn uncached_message_ids<'a>(
            &'a self,
            account: &'a AccountId,
            message_ids: &'a [MessageId],
        ) -> BoxFuture<'a, Result<Vec<MessageId>, MailboxStoreError>> {
            Box::pin(async move {
                self.checked_account(account)?;
                self.with_connection(|connection| uncached_ids(connection, message_ids))
            })
        }
        fn list_envelopes_after<'a>(
            &'a self,
            account: &'a AccountId,
            after: Option<&'a EnvelopeCursor>,
            limit: StoreLimit,
        ) -> BoxFuture<'a, Result<Vec<MessageEnvelope>, MailboxStoreError>> {
            Box::pin(async move {
                self.checked_account(account)?;
                self.with_connection(|connection| list_envelopes_after(connection, after, limit))
            })
        }
        fn thread_envelopes<'a>(
            &'a self,
            account: &'a AccountId,
            thread_id: &'a ThreadId,
            limit: StoreLimit,
        ) -> BoxFuture<'a, Result<Vec<MessageEnvelope>, MailboxStoreError>> {
            Box::pin(async move {
                self.checked_account(account)?;
                self.list(Some(thread_id), limit)
            })
        }
    }

    /// The identifiers without a cached body, without reading any body.
    fn uncached_ids(
        connection: &Connection,
        ids: &[MessageId],
    ) -> Result<Vec<MessageId>, MailboxStoreError> {
        let mut statement = connection
            .prepare("SELECT 1 FROM messages WHERE message_id = ?1 AND content IS NOT NULL")
            .map_err(store_error)?;
        let mut uncached = Vec::new();
        for id in ids {
            if !statement
                .exists(params![id.as_str()])
                .map_err(store_error)?
            {
                uncached.push(id.clone());
            }
        }
        Ok(uncached)
    }

    impl MailboxReader for SqlCipherMailboxReader {
        fn list_envelopes<'a>(
            &'a self,
            account: &'a AccountId,
            limit: StoreLimit,
        ) -> BoxFuture<'a, Result<Vec<MessageEnvelope>, MailboxStoreError>> {
            Box::pin(async move {
                self.checked_account(account)?;
                self.list(None, limit)
            })
        }

        fn get_message<'a>(
            &'a self,
            account: &'a AccountId,
            message_id: &'a MessageId,
        ) -> BoxFuture<'a, Result<Option<Message>, MailboxStoreError>> {
            Box::pin(async move {
                self.checked_account(account)?;
                self.load_complete_message(message_id)
            })
        }

        fn list_envelopes_after<'a>(
            &'a self,
            account: &'a AccountId,
            after: Option<&'a EnvelopeCursor>,
            limit: StoreLimit,
        ) -> BoxFuture<'a, Result<Vec<MessageEnvelope>, MailboxStoreError>> {
            Box::pin(async move {
                self.checked_account(account)?;
                let connection = self
                    .connection
                    .lock()
                    .map_err(|_poison| MailboxStoreError::Storage)?;
                list_envelopes_after(&connection, after, limit)
            })
        }

        fn thread_envelopes<'a>(
            &'a self,
            account: &'a AccountId,
            thread_id: &'a ThreadId,
            limit: StoreLimit,
        ) -> BoxFuture<'a, Result<Vec<MessageEnvelope>, MailboxStoreError>> {
            Box::pin(async move {
                self.checked_account(account)?;
                self.list(Some(thread_id), limit)
            })
        }
    }

    /// The in-transaction identity fence: aborts the enclosing write unless the
    /// slot's recorded identity still equals `fence`.
    ///
    /// Fails closed on every anomaly, but with two distinct categories so the
    /// caller (and the sync failure surface) can tell them apart:
    /// - a missing row or a hash that no longer equals `fence` means the identity
    ///   changed (or was torn down by a concurrent disconnect) between the gate's
    ///   decision and this write — [`MailboxStoreError::IdentityChanged`];
    /// - a version-incompatible row, or a NULL / wrong-length / wrong-typeof
    ///   `identity_hash`/`algo_version` (filtered by the `CASE … typeof/length`
    ///   projection), is an unreadable identity, not a known account change —
    ///   [`MailboxStoreError::Corrupted`], matching the store's general rule that a
    ///   present-but-unreadable identity row never degrades to "no identity yet".
    ///
    /// Either category aborts the write; neither ever re-baselines or commits. The
    /// hash is compared in constant time via [`IdentityHash`]'s equality.
    fn assert_identity_unchanged(
        transaction: &Transaction<'_>,
        account: &AccountId,
        fence: &IdentityHash,
    ) -> Result<(), MailboxStoreError> {
        match read_recorded_identity(transaction, account)? {
            Some(current) if IdentityHash::from_bytes(current) == *fence => Ok(()),
            // A present-but-different hash, or a vanished row, both mean the identity
            // changed (or was torn down by a concurrent disconnect) since the gate.
            Some(_) | None => Err(MailboxStoreError::IdentityChanged),
        }
    }

    /// The gate's compare-and-set precondition, read inside the write transaction:
    /// the recorded identity must still equal what the gate's `decide` observed
    /// (`expected`), else a concurrent cycle recorded a different identity and this
    /// stale decision must abort with [`MailboxStoreError::IdentityRaced`] so the
    /// caller re-decides against the new state. A `None` expected requires the row to
    /// still be absent (first connect); a `Some` expected requires the recorded hash
    /// to still match it exactly.
    fn assert_identity_matches_expected(
        transaction: &Transaction<'_>,
        account: &AccountId,
        expected: Option<&[u8; 32]>,
    ) -> Result<(), MailboxStoreError> {
        match (read_recorded_identity(transaction, account)?, expected) {
            (None, None) => Ok(()),
            (Some(current), Some(expected)) if current == *expected => Ok(()),
            // Absent-vs-present, present-vs-absent, or a moved hash: a racing cycle
            // changed the recorded identity between the gate's read and this write.
            _ => Err(MailboxStoreError::IdentityRaced),
        }
    }

    /// Reads the recorded identity hash for `account` inside an open transaction —
    /// the single fail-closed reader shared by the fence and the compare-and-set
    /// gate precondition.
    ///
    /// Returns `Ok(None)` only when the row is genuinely absent. A present but
    /// unreadable or version-incompatible row (filtered by the `CASE … typeof/
    /// length` projection) is `Err(`[`MailboxStoreError::Corrupted`]`)` — never a
    /// silent "no identity yet", matching the store's rule that a present-but-
    /// unreadable identity always fails closed.
    fn read_recorded_identity(
        transaction: &Transaction<'_>,
        account: &AccountId,
    ) -> Result<Option<[u8; 32]>, MailboxStoreError> {
        let row = transaction.query_row(
            "SELECT CASE WHEN typeof(identity_hash) = 'blob' AND length(identity_hash) = 32 THEN identity_hash END, CASE WHEN typeof(algo_version) = 'integer' THEN algo_version END FROM account_identity WHERE account_id = ?1",
            params![account.as_str()],
            |row| {
                let hash: Option<Vec<u8>> = row.get(0)?;
                let version: Option<i64> = row.get(1)?;
                Ok((hash, version))
            },
        );
        match row {
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) => Err(store_error(error)),
            Ok((Some(hash), Some(version))) if version == IDENTITY_ALGO_VERSION => {
                let bytes: [u8; 32] = hash
                    .try_into()
                    .map_err(|_length| MailboxStoreError::Corrupted)?;
                Ok(Some(bytes))
            }
            // A present-but-unreadable or version-incompatible row must fail closed,
            // never degrade to "no identity yet".
            Ok(_) => Err(MailboxStoreError::Corrupted),
        }
    }

    fn write_envelope(
        transaction: &Transaction<'_>,
        envelope: &MessageEnvelope,
        content: Option<&[u8]>,
    ) -> Result<(), MailboxStoreError> {
        match content {
            // Sticky local read: once unread is 0, a later remote UNREAD snapshot
            // must not reopen the message (gmail.readonly cannot clear server labels).
            Some(content) => transaction.execute("INSERT INTO messages (message_id, thread_id, sender, subject, preview, received_at, unread, content) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) ON CONFLICT(message_id) DO UPDATE SET thread_id = excluded.thread_id, sender = excluded.sender, subject = excluded.subject, preview = excluded.preview, received_at = excluded.received_at, unread = CASE WHEN messages.unread = 0 THEN 0 ELSE excluded.unread END, content = excluded.content", params![envelope.message_id().as_str(), envelope.thread_id().as_str(), envelope.from().as_str(), envelope.subject().as_str(), envelope.preview().as_str(), envelope.received_at().as_millis(), i64::from(envelope.is_unread()), content]).map_err(store_error)?,
            None => transaction.execute("INSERT INTO messages (message_id, thread_id, sender, subject, preview, received_at, unread, content) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL) ON CONFLICT(message_id) DO UPDATE SET thread_id = excluded.thread_id, sender = excluded.sender, subject = excluded.subject, preview = excluded.preview, received_at = excluded.received_at, unread = CASE WHEN messages.unread = 0 THEN 0 ELSE excluded.unread END", params![envelope.message_id().as_str(), envelope.thread_id().as_str(), envelope.from().as_str(), envelope.subject().as_str(), envelope.preview().as_str(), envelope.received_at().as_millis(), i64::from(envelope.is_unread())]).map_err(store_error)?,
        };
        Ok(())
    }

    fn envelope_from_row(row: &rusqlite::Row<'_>) -> Result<MessageEnvelope, MailboxStoreError> {
        let message_id: String = row.get(0).map_err(corrupted)?;
        let thread_id: String = row.get(1).map_err(corrupted)?;
        let sender: String = row.get(2).map_err(corrupted)?;
        let subject: String = row.get(3).map_err(corrupted)?;
        let preview: String = row.get(4).map_err(corrupted)?;
        let received_at: i64 = row.get(5).map_err(corrupted)?;
        let unread: i64 = row.get(6).map_err(corrupted)?;
        let unread = match unread {
            0 => false,
            1 => true,
            _ => return Err(MailboxStoreError::Corrupted),
        };
        Ok(MessageEnvelope::new(
            MessageId::new(message_id).map_err(|_error| MailboxStoreError::Corrupted)?,
            ThreadId::new(thread_id).map_err(|_error| MailboxStoreError::Corrupted)?,
            HeaderText::new(sender).map_err(|_error| MailboxStoreError::Corrupted)?,
            HeaderText::new(subject).map_err(|_error| MailboxStoreError::Corrupted)?,
            HeaderText::new(preview).map_err(|_error| MailboxStoreError::Corrupted)?,
            UnixTimestampMillis::new(received_at).map_err(|_error| MailboxStoreError::Corrupted)?,
            unread,
        ))
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum OpenFailure {
        Corrupted,
        Storage,
    }
    fn configure_storage(
        connection: &Connection,
        account: &AccountId,
        key: &[u8; 32],
    ) -> Result<bool, OpenFailure> {
        apply_key(connection, key).map_err(classify_key)?;
        connection
            .busy_timeout(BUSY_TIMEOUT)
            .map_err(|_error| OpenFailure::Storage)?;
        connection
            .execute_batch(
                "PRAGMA cipher_memory_security = ON;
                 PRAGMA foreign_keys = ON;
                 PRAGMA temp_store = MEMORY;",
            )
            .map_err(classify_open)?;
        let fresh = validate_identity(connection, account)?;
        configure_owned_storage(connection)?;
        upgrade_schema_v1(connection)?;
        Ok(fresh)
    }

    fn migrate_fresh(connection: &Connection, account: &AccountId) -> Result<(), OpenFailure> {
        let transaction = connection
            .unchecked_transaction()
            .map_err(|_error| OpenFailure::Storage)?;
        transaction
            .execute_batch(MIGRATION)
            .map_err(classify_open)?;
        transaction
            .execute_batch(MIGRATION_V2_ACCOUNT_EMAIL)
            .map_err(classify_open)?;
        transaction
            .execute(
                "INSERT INTO account_binding (singleton, account_id) VALUES (1, ?1)",
                params![account.as_str()],
            )
            .map_err(classify_open)?;
        transaction
            .pragma_update(None, "application_id", APPLICATION_ID)
            .map_err(classify_open)?;
        transaction
            .pragma_update(None, "user_version", VERSION)
            .map_err(classify_open)?;
        transaction.commit().map_err(classify_open)
    }

    fn materialize_fresh_wal(connection: &Connection) -> Result<(), OpenFailure> {
        connection
            .execute_batch("BEGIN IMMEDIATE; PRAGMA user_version = 0; COMMIT;")
            .map_err(classify_open)
    }

    // Upgrades a shipped version-1 store to the current schema: it adds the
    // account email column and bumps the stored version in one
    // `BEGIN IMMEDIATE` transaction, so a crash can never leave a
    // half-upgraded store behind. A store already on the current version is
    // left alone; the caller validated the old schema before this runs and
    // the current one after.
    fn upgrade_schema_v1(connection: &Connection) -> Result<(), OpenFailure> {
        let user_version: i64 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(classify_open)?;
        if user_version != SCHEMA_VERSION_1 {
            return Ok(());
        }
        connection
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(classify_open)?;
        let outcome = (|| {
            connection
                .execute_batch(MIGRATION_V2_ACCOUNT_EMAIL)
                .map_err(classify_open)?;
            connection
                .pragma_update(None, "user_version", VERSION)
                .map_err(classify_open)?;
            let schema = schema(connection).map_err(classify_open)?;
            (schema == canonical_schema())
                .then_some(())
                .ok_or(OpenFailure::Corrupted)
        })();
        match outcome {
            Ok(()) => connection.execute_batch("COMMIT").map_err(classify_open),
            Err(error) => {
                let _ = connection.execute_batch("ROLLBACK");
                Err(error)
            }
        }
    }

    fn configure_read_only(
        connection: &Connection,
        account: &AccountId,
        key: &[u8; 32],
    ) -> Result<(), OpenFailure> {
        if validate_recovery_read_only(connection, account, key, IntegrityScan::Full)? {
            return Err(OpenFailure::Corrupted);
        }
        Ok(())
    }

    fn validate_recovery_read_only(
        connection: &Connection,
        account: &AccountId,
        key: &[u8; 32],
        scan: IntegrityScan,
    ) -> Result<bool, OpenFailure> {
        apply_key(connection, key).map_err(classify_key)?;
        connection
            .busy_timeout(BUSY_TIMEOUT)
            .map_err(|_error| OpenFailure::Storage)?;
        connection
            .execute_batch(
                "PRAGMA cipher_memory_security = ON;
                 PRAGMA foreign_keys = ON;
                 PRAGMA temp_store = MEMORY;",
            )
            .map_err(classify_open)?;
        let journal_size_limit: i64 = connection
            .query_row("PRAGMA journal_size_limit", [], |row| row.get(0))
            .map_err(classify_open)?;
        if journal_size_limit != -1 {
            return Err(OpenFailure::Corrupted);
        }

        connection.execute_batch("BEGIN;").map_err(classify_open)?;
        let validation = (|| {
            let fresh = validate_identity(connection, account)?;
            validate_health(connection, scan)?;
            Ok(fresh)
        })();
        if validation.is_ok() {
            connection.execute_batch("COMMIT;").map_err(classify_open)?;
        } else {
            let _ = connection.execute_batch("ROLLBACK;");
        }
        validation
    }

    #[expect(
        unsafe_code,
        reason = "SQLite PERSIST_WAL file control accepts a mutable integer pointer"
    )]
    fn persistent_wal_control(connection: &Connection, value: &mut i32) -> Result<(), OpenFailure> {
        // SAFETY: `connection.handle()` remains valid for this synchronous call;
        // `main` is a static NUL-terminated database name; and `value` is a
        // writable `i32` whose address remains valid until SQLite returns.
        let result = unsafe {
            rusqlite::ffi::sqlite3_file_control(
                connection.handle(),
                c"main".as_ptr(),
                rusqlite::ffi::SQLITE_FCNTL_PERSIST_WAL,
                std::ptr::from_mut(value).cast::<std::ffi::c_void>(),
            )
        };
        if result == rusqlite::ffi::SQLITE_OK {
            Ok(())
        } else {
            Err(OpenFailure::Storage)
        }
    }

    fn set_and_verify_persistent_wal(connection: &Connection) -> Result<(), OpenFailure> {
        let mut enabled = 1;
        persistent_wal_control(connection, &mut enabled)?;
        let mut current = -1;
        persistent_wal_control(connection, &mut current)?;
        (current == 1).then_some(()).ok_or(OpenFailure::Storage)
    }

    fn validate_identity(
        connection: &Connection,
        account: &AccountId,
    ) -> Result<bool, OpenFailure> {
        let cipher_version: String = connection
            .query_row("PRAGMA cipher_version", [], |row| row.get(0))
            .map_err(classify_open)?;
        if cipher_version.is_empty() {
            return Err(OpenFailure::Corrupted);
        }
        let application_id: i64 = connection
            .query_row("PRAGMA application_id", [], |row| row.get(0))
            .map_err(classify_open)?;
        let user_version: i64 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(classify_open)?;
        let schema = schema(connection).map_err(classify_open)?;
        let fresh = application_id == 0 && user_version == 0 && schema.is_empty();
        if fresh {
            return Ok(true);
        }
        // A shipped store is either the current version or the previous one,
        // each with exactly its own canonical objects. A newer version, a
        // foreign application id, or a mismatched object set fails closed and
        // is never rewritten here.
        let expected = match user_version {
            VERSION => canonical_schema(),
            SCHEMA_VERSION_1 => canonical_schema_v1(),
            _ => return Err(OpenFailure::Corrupted),
        };
        if application_id != APPLICATION_ID || schema != expected {
            return Err(OpenFailure::Corrupted);
        }
        let owner: String = connection
            .query_row(
                "SELECT CASE WHEN typeof(account_id) = 'text' AND length(CAST(account_id AS BLOB)) <= 256 THEN account_id END FROM account_binding WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .map_err(classify_open)?;
        if AccountId::new(owner).ok().as_ref() != Some(account) {
            return Err(OpenFailure::Corrupted);
        }
        Ok(false)
    }

    fn configure_owned_storage(connection: &Connection) -> Result<(), OpenFailure> {
        connection
            .execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA secure_delete = ON;",
            )
            .map_err(classify_open)
    }

    fn validate_health(connection: &Connection, scan: IntegrityScan) -> Result<(), OpenFailure> {
        let foreign_keys: i64 = connection
            .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
            .map_err(classify_open)?;
        let temp_store: i64 = connection
            .query_row("PRAGMA temp_store", [], |row| row.get(0))
            .map_err(classify_open)?;
        let secure_delete: i64 = connection
            .query_row("PRAGMA secure_delete", [], |row| row.get(0))
            .map_err(classify_open)?;
        let journal: String = connection
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .map_err(classify_open)?;
        let foreign_key_failure = connection
            .prepare("PRAGMA foreign_key_check")
            .and_then(|mut statement| statement.query([])?.next().map(|row| row.is_some()))
            .map_err(classify_open)?;
        let (integrity, cipher_failure) = match scan {
            IntegrityScan::Full => (
                connection
                    .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
                    .map_err(classify_open)?,
                connection
                    .prepare("PRAGMA cipher_integrity_check")
                    .and_then(|mut statement| statement.query([])?.next().map(|row| row.is_some()))
                    .map_err(classify_open)?,
            ),
            IntegrityScan::Skip => ("ok".to_owned(), false),
        };
        if foreign_keys != 1
            || temp_store != 2
            || secure_delete != 1
            || journal != "wal"
            || integrity != "ok"
            || foreign_key_failure
            || cipher_failure
        {
            return Err(OpenFailure::Corrupted);
        }
        Ok(())
    }

    fn classify_open(error: rusqlite::Error) -> OpenFailure {
        match error {
            rusqlite::Error::SqliteFailure(sqlite, _)
                if matches!(
                    sqlite.code,
                    ErrorCode::DatabaseCorrupt | ErrorCode::NotADatabase
                ) =>
            {
                OpenFailure::Corrupted
            }
            rusqlite::Error::FromSqlConversionFailure(..)
            | rusqlite::Error::IntegralValueOutOfRange(..)
            | rusqlite::Error::InvalidColumnType(..)
            | rusqlite::Error::InvalidQuery
            | rusqlite::Error::QueryReturnedNoRows
            | rusqlite::Error::Utf8Error(..) => OpenFailure::Corrupted,
            other => {
                report_storage_failure(&other);
                OpenFailure::Storage
            }
        }
    }

    /// The length of `SQLCipher`'s raw-key literal: `x'`, 64 hex digits, `'`.
    const RAW_KEY_LITERAL_LEN: usize = 2 + 64 + 1;

    #[expect(
        unsafe_code,
        reason = "SQLCipher's raw-key API avoids copying the key into an ordinary SQL string"
    )]
    pub(crate) fn apply_key(connection: &Connection, key: &[u8; 32]) -> rusqlite::Result<()> {
        // The key is already 256 uniformly random bits from HKDF, so it is
        // passed in SQLCipher's raw-key form, `x'<64 hex digits>'`. A plain
        // 32-byte buffer would be treated as a passphrase and stretched with
        // the default PBKDF2 (256,000 iterations) on every open, which costs
        // more than the whole first-frame budget.
        let mut literal = Zeroizing::new([0_u8; RAW_KEY_LITERAL_LEN]);
        literal[0] = b'x';
        literal[1] = b'\'';
        for (index, byte) in key.iter().enumerate() {
            literal[2 + 2 * index] = hex_digit(byte >> 4);
            literal[3 + 2 * index] = hex_digit(byte & 0x0f);
        }
        literal[RAW_KEY_LITERAL_LEN - 1] = b'\'';
        let key_length =
            i32::try_from(literal.len()).map_err(|_error| rusqlite::Error::InvalidQuery)?;
        // SAFETY: `connection.handle()` remains valid for this call, SQLCipher
        // copies exactly `key_length` bytes before returning, and the borrowed
        // literal buffer remains alive and immutable for the complete call.
        let result = unsafe {
            rusqlite::ffi::sqlite3_key(
                connection.handle(),
                literal.as_ptr().cast::<std::ffi::c_void>(),
                key_length,
            )
        };
        key_result(result)
    }

    fn key_result(result: i32) -> rusqlite::Result<()> {
        if result == rusqlite::ffi::SQLITE_OK {
            Ok(())
        } else {
            Err(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(result),
                None,
            ))
        }
    }

    fn classify_key(_error: rusqlite::Error) -> OpenFailure {
        // Wrong keys are accepted by `sqlite3_key` and surface as corruption on
        // the first database read. A non-OK keying result is therefore an
        // operational setup failure, most notably `SQLITE_NOMEM`.
        OpenFailure::Storage
    }
    fn mailbox_open_error(kind: OpenFailure) -> MailboxStoreError {
        match kind {
            OpenFailure::Corrupted => MailboxStoreError::Corrupted,
            OpenFailure::Storage => MailboxStoreError::Storage,
        }
    }
    fn schema(connection: &Connection) -> rusqlite::Result<Vec<(String, String, String)>> {
        let mut statement = connection.prepare(
            "SELECT
                CASE WHEN typeof(type) = 'text' AND length(CAST(type AS BLOB)) <= ?1 THEN type END,
                CASE WHEN typeof(name) = 'text' AND length(CAST(name AS BLOB)) <= ?2 THEN name END,
                CASE
                    WHEN sql IS NULL THEN ''
                    WHEN typeof(sql) = 'text' AND length(CAST(sql AS BLOB)) <= ?3 THEN sql
                END
             FROM sqlite_schema
             WHERE name NOT GLOB 'sqlite_*'
             ORDER BY type, name
             LIMIT ?4",
        )?;
        let row_limit = i64::try_from(CANONICAL_SCHEMA_OBJECT_COUNT + 1)
            .map_err(|_error| rusqlite::Error::InvalidQuery)?;
        let mut rows = statement.query(params![
            MAX_SCHEMA_KIND_LEN,
            MAX_SCHEMA_NAME_LEN,
            MAX_SCHEMA_SQL_LEN,
            row_limit
        ])?;
        let mut objects = Vec::with_capacity(CANONICAL_SCHEMA_OBJECT_COUNT);
        while let Some(row) = rows.next()? {
            if objects.len() == CANONICAL_SCHEMA_OBJECT_COUNT {
                return Err(rusqlite::Error::InvalidQuery);
            }
            objects.push((
                row.get(0)?,
                row.get(1)?,
                normalize(&row.get::<_, String>(2)?),
            ));
        }
        Ok(objects)
    }
    fn canonical_schema() -> Vec<(String, String, String)> {
        canonical_objects(normalize(
            "CREATE TABLE account_binding ( singleton INTEGER PRIMARY KEY CHECK (singleton = 1), account_id TEXT NOT NULL, broker_subject TEXT NULL CHECK (broker_subject IS NULL OR (length(CAST(broker_subject AS BLOB)) BETWEEN 1 AND 255)), refresh_token TEXT NULL CHECK (refresh_token IS NULL OR (length(CAST(refresh_token AS BLOB)) BETWEEN 1 AND 4096)) , email_address TEXT NULL CHECK (email_address IS NULL OR (length(CAST(email_address AS BLOB)) BETWEEN 3 AND 320)))",
        ))
    }
    // The previously shipped version-1 binding row, without the account email
    // column. A version-1 store must match exactly this object set so a
    // writable open can upgrade it and a read-only open can read it.
    fn canonical_schema_v1() -> Vec<(String, String, String)> {
        canonical_objects(normalize(
            "CREATE TABLE account_binding ( singleton INTEGER PRIMARY KEY CHECK (singleton = 1), account_id TEXT NOT NULL, broker_subject TEXT NULL CHECK (broker_subject IS NULL OR (length(CAST(broker_subject AS BLOB)) BETWEEN 1 AND 255)), refresh_token TEXT NULL CHECK (refresh_token IS NULL OR (length(CAST(refresh_token AS BLOB)) BETWEEN 1 AND 4096)) )",
        ))
    }
    fn canonical_objects(account_binding: String) -> Vec<(String, String, String)> {
        vec![
            (
                "index".into(),
                "messages_list_order".into(),
                normalize(
                    "CREATE INDEX messages_list_order ON messages (received_at DESC, message_id ASC)",
                ),
            ),
            (
                "index".into(),
                "messages_thread_order".into(),
                normalize(
                    "CREATE INDEX messages_thread_order ON messages (thread_id ASC, received_at ASC, message_id ASC)",
                ),
            ),
            ("table".into(), "account_binding".into(), account_binding),
            (
                "table".into(),
                "account_identity".into(),
                normalize(
                    "CREATE TABLE account_identity ( account_id TEXT PRIMARY KEY, identity_hash BLOB NOT NULL, algo_version INTEGER NOT NULL )",
                ),
            ),
            (
                "table".into(),
                "account_lifecycle".into(),
                normalize(
                    "CREATE TABLE account_lifecycle ( singleton INTEGER PRIMARY KEY CHECK (singleton = 1), disconnect_recovery INTEGER NULL CHECK (disconnect_recovery IN (1, 2)), last_successful_sync_unix_millis INTEGER NULL CHECK (last_successful_sync_unix_millis >= 0) )",
                ),
            ),
            (
                "table".into(),
                "messages".into(),
                normalize(
                    "CREATE TABLE messages ( message_id TEXT PRIMARY KEY, thread_id TEXT NOT NULL, sender TEXT NOT NULL, subject TEXT NOT NULL, preview TEXT NOT NULL, received_at INTEGER NOT NULL, unread INTEGER NOT NULL CHECK (unread IN (0, 1)), content BLOB NULL )",
                ),
            ),
        ]
    }
    fn normalize(sql: &str) -> String {
        sql.trim_end_matches(';')
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }
    // A broker subject is 1..=255 bytes of printable non-space ASCII. This
    // matches the `account_binding.broker_subject` column CHECK bound and
    // keeps the routing key free of whitespace and control bytes.
    fn is_valid_broker_subject(subject: &str) -> bool {
        let bytes = subject.as_bytes();
        (1..=255).contains(&bytes.len()) && bytes.iter().all(|byte| (0x21..=0x7e).contains(byte))
    }
    // A refresh token is 1..=4096 bytes of printable non-space ASCII, matching
    // the `account_binding.refresh_token` column CHECK bound.
    fn is_valid_refresh_token(token: &str) -> bool {
        let bytes = token.as_bytes();
        (1..=4096).contains(&bytes.len()) && bytes.iter().all(|byte| (0x21..=0x7e).contains(byte))
    }
    fn store_error(error: rusqlite::Error) -> MailboxStoreError {
        match error {
            rusqlite::Error::SqliteFailure(sqlite, _)
                if matches!(
                    sqlite.code,
                    ErrorCode::DatabaseCorrupt | ErrorCode::NotADatabase
                ) =>
            {
                MailboxStoreError::Corrupted
            }
            other => {
                report_storage_failure(&other);
                MailboxStoreError::Storage
            }
        }
    }

    /// In tests, prints why `SQLite` failed, with its extended result code, so
    /// an intermittent `Storage` failure shows its cause; the test harness
    /// shows the output of failing tests only. Release builds print nothing,
    /// because messages can name paths and mailbox content never belongs in
    /// logs.
    #[cfg(test)]
    fn report_storage_failure(error: &rusqlite::Error) {
        if let rusqlite::Error::SqliteFailure(sqlite, message) = error {
            eprintln!(
                "SQLite storage failure: extended code {} ({:?}): {}",
                sqlite.extended_code,
                sqlite.code,
                message.as_deref().unwrap_or("no message")
            );
        } else {
            eprintln!("SQLite storage failure: {error}");
        }
    }

    #[cfg(not(test))]
    const fn report_storage_failure(_error: &rusqlite::Error) {}
    fn corrupted(_error: rusqlite::Error) -> MailboxStoreError {
        MailboxStoreError::Corrupted
    }

    #[cfg(test)]
    mod tests {
        #![expect(clippy::unwrap_used, reason = "tests construct valid fixtures")]

        use std::fs;
        use std::os::unix::fs::PermissionsExt;
        use std::panic::{AssertUnwindSafe, catch_unwind};
        use std::pin::pin;
        use std::process::{Command, Stdio};
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::task::{Context, Poll, Waker};
        use std::thread;
        use std::time::Instant;

        use super::*;

        static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(0);

        struct TestDatabase {
            directory: std::path::PathBuf,
            path: std::path::PathBuf,
        }

        impl TestDatabase {
            fn new(label: &str) -> Self {
                let sequence = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
                let directory = std::env::temp_dir().join(format!(
                    "tersa-store-{label}-{}-{sequence}",
                    std::process::id()
                ));
                fs::create_dir(&directory).unwrap();
                let path = directory.join("mail.sqlite3");
                Self { directory, path }
            }

            fn path(&self) -> &Path {
                &self.path
            }

            fn files(&self) -> Vec<std::path::PathBuf> {
                let mut files = fs::read_dir(&self.directory)
                    .unwrap()
                    .map(|entry| entry.unwrap().path())
                    .filter(|path| path.is_file())
                    .collect::<Vec<_>>();
                files.sort();
                files
            }
        }

        impl Drop for TestDatabase {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.directory);
            }
        }

        fn account() -> AccountId {
            AccountId::new("account-a").unwrap()
        }
        fn key(byte: u8) -> DatabaseKey {
            DatabaseKey::new([byte; 32])
        }
        fn envelope(id: &str, thread: &str, received_at: i64) -> MessageEnvelope {
            MessageEnvelope::new(
                MessageId::new(id).unwrap(),
                ThreadId::new(thread).unwrap(),
                HeaderText::new("from").unwrap(),
                HeaderText::new("subject").unwrap(),
                HeaderText::new("preview").unwrap(),
                UnixTimestampMillis::new(received_at).unwrap(),
                true,
            )
        }
        fn run<T>(future: impl Future<Output = T>) -> T {
            let waker = Waker::noop();
            let mut context = Context::from_waker(waker);
            let mut future = pin!(future);
            match future.as_mut().poll(&mut context) {
                Poll::Ready(value) => value,
                Poll::Pending => panic!("store future must complete synchronously"),
            }
        }
        fn accepts_reader<T: MailboxReader>(_reader: &T) {}
        fn open(name: &str) -> (TestDatabase, SqlCipherMailboxStore) {
            let database = TestDatabase::new(name);
            let store = SqlCipherMailboxStore::open(account(), database.path(), key(7)).unwrap();
            (database, store)
        }

        fn fence() -> IdentityHash {
            IdentityHash::from_bytes([9; 32])
        }

        /// Records the baseline account identity a fenced write expects, mirroring
        /// what the gate persists before the first reconcile of a cycle in
        /// production. A reconcile or cache write whose commit reaches the fence
        /// assert requires this row to exist and match [`fence`].
        fn record_fence(store: &SqlCipherMailboxStore) {
            run(store.reconcile_identity(
                &account(),
                &fence(),
                IdentityReconcile::RecordOnly,
                None,
            ))
            .unwrap();
        }

        #[test]
        fn keys_are_applied_in_raw_form_without_key_stretching() {
            let (database, store) = open("raw-key");
            record_fence(&store);
            drop(store);
            let connection = raw_existing_connection(&database);
            let hex = "07".repeat(32);
            connection
                .pragma_update(None, "key", format!("x'{hex}'"))
                .unwrap();
            let tables: i64 = connection
                .query_row("SELECT count(*) FROM sqlite_schema", [], |row| row.get(0))
                .unwrap();
            assert!(tables > 0, "the raw-form key opens the database");

            let stretched = raw_existing_connection(&database);
            stretched.pragma_update(None, "key", hex).unwrap();
            assert!(
                stretched
                    .query_row("SELECT count(*) FROM sqlite_schema", [], |row| row
                        .get::<_, i64>(0))
                    .is_err(),
                "the same bytes as a passphrase do not"
            );
        }

        #[test]
        fn every_hex_digit_of_a_raw_key_round_trips() {
            let database = TestDatabase::new("raw-key-digits");
            let bytes: [u8; 32] =
                std::array::from_fn(|index| u8::try_from(index * 17 % 256).unwrap());
            let writer = Connection::open(database.path()).unwrap();
            apply_key(&writer, &bytes).unwrap();
            writer.execute_batch("CREATE TABLE t (x)").unwrap();
            drop(writer);
            let lower: String = bytes
                .iter()
                .flat_map(|byte| [byte >> 4, byte & 0x0f])
                .map(|digit| char::from_digit(u32::from(digit), 16).unwrap())
                .collect();
            for literal in [lower.clone(), lower.to_uppercase()] {
                let reader = Connection::open(database.path()).unwrap();
                reader
                    .pragma_update(None, "key", format!("x'{literal}'"))
                    .unwrap();
                let tables: i64 = reader
                    .query_row("SELECT count(*) FROM sqlite_schema", [], |row| row.get(0))
                    .unwrap();
                assert_eq!(tables, 1, "{literal}");
            }
        }

        fn crash_store_at(database: &TestDatabase, point: &str) {
            let status = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "store::tests::wal_resident_first_migration_crash_child",
                    "--ignored",
                    "--nocapture",
                ])
                .env("TERSA_STORE_CRASH_DATABASE", database.path())
                .env("TERSA_STORE_CRASH_POINT", point)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap();
            assert_eq!(status.code(), Some(73));
        }

        fn recovery_stage_paths(database: &TestDatabase) -> Vec<PathBuf> {
            (0..RECOVERY_STAGE_LIMIT)
                .map(|slot| {
                    database
                        .directory
                        .join(format!(".tersa-wal-recovery-v1-{slot}"))
                })
                .collect()
        }

        fn assert_no_recovery_stages(database: &TestDatabase) {
            assert!(
                recovery_stage_paths(database)
                    .into_iter()
                    .all(|path| !path.exists())
            );
        }

        fn open_existing_under_umask(database: &TestDatabase, mask: &str) {
            let status = Command::new("/bin/sh")
                .arg("-c")
                .arg("umask \"$1\"; shift; exec \"$@\"")
                .arg("tersa-existing-umask")
                .arg(mask)
                .arg(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "store::tests::restrictive_umask_existing_store_child",
                    "--ignored",
                    "--nocapture",
                ])
                .env("TERSA_STORE_EXISTING_DATABASE", database.path())
                .stdin(Stdio::null())
                .status()
                .unwrap();
            assert!(
                status.success(),
                "existing store helper failed for umask {mask}"
            );
        }

        fn validate_missing_shm_under_umask(database: &TestDatabase, mask: &str) {
            let status = Command::new("/bin/sh")
                .arg("-c")
                .arg("umask \"$1\"; shift; exec \"$@\"")
                .arg("tersa-recovery-umask")
                .arg(mask)
                .arg(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "store::tests::restrictive_umask_existing_store_child",
                    "--ignored",
                    "--nocapture",
                ])
                .env("TERSA_STORE_EXISTING_DATABASE", database.path())
                .env("TERSA_STORE_RECOVERY_ONLY", "1")
                .stdin(Stdio::null())
                .status()
                .unwrap();
            assert!(status.success(), "recovery helper failed for umask {mask}");
        }

        fn raw_connection(database: &TestDatabase) -> Connection {
            let path = canonical_database_path(database.path()).unwrap();
            assert!(prepare_database_leaf(&path).unwrap().is_fresh());
            open_connection(&path).unwrap()
        }

        fn raw_existing_connection(database: &TestDatabase) -> Connection {
            let path = canonical_database_path(database.path()).unwrap();
            open_connection(&path).unwrap()
        }

        fn journal_path(database: &TestDatabase) -> PathBuf {
            sidecar_path(database.path(), "-journal")
        }

        fn wal_path(database: &TestDatabase) -> PathBuf {
            sidecar_path(database.path(), "-wal")
        }

        fn shm_path(database: &TestDatabase) -> PathBuf {
            sidecar_path(database.path(), "-shm")
        }

        fn fixed_leaf_path(database: &TestDatabase, index: usize) -> PathBuf {
            match index {
                0 => database.path().to_path_buf(),
                1 => journal_path(database),
                2 => wal_path(database),
                3 => shm_path(database),
                _ => panic!("fixed leaf index must be in range"),
            }
        }

        fn write_restrictive(path: &Path, bytes: &[u8]) {
            fs::write(path, bytes).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }

        fn leave_foreign_hot_journal(database: &TestDatabase) {
            let connection = raw_connection(database);
            apply_key(&connection, &key(7).0).unwrap();
            connection
                .execute_batch(
                    "PRAGMA journal_mode = DELETE;
                     PRAGMA synchronous = FULL;
                     CREATE TABLE foreign_owner (value BLOB NOT NULL);
                     INSERT INTO foreign_owner (value) VALUES (zeroblob(4096));",
                )
                .unwrap();
            drop(connection);

            let ready = database.directory.join("hot-journal-ready");
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "store::tests::foreign_hot_journal_child",
                    "--ignored",
                    "--nocapture",
                ])
                .env("TERSA_STORE_HOT_JOURNAL_DATABASE", database.path())
                .env("TERSA_STORE_HOT_JOURNAL_READY", &ready)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            while !ready.exists() && Instant::now() < deadline {
                assert!(child.try_wait().unwrap().is_none());
                thread::sleep(Duration::from_millis(10));
            }
            assert!(
                ready.exists(),
                "hot-journal child did not reach its checkpoint"
            );
            child.kill().unwrap();
            assert!(!child.wait().unwrap().success());
            assert!(journal_path(database).exists());
        }

        fn schema_state(
            store: &SqlCipherMailboxStore,
        ) -> (i64, i64, Vec<(String, String, String)>) {
            let connection = store.connection.lock().unwrap();
            (
                connection
                    .query_row("PRAGMA application_id", [], |row| row.get(0))
                    .unwrap(),
                connection
                    .query_row("PRAGMA user_version", [], |row| row.get(0))
                    .unwrap(),
                schema(&connection).unwrap(),
            )
        }

        #[expect(
            clippy::needless_pass_by_value,
            reason = "the assertion owns and drops any unexpected opened store"
        )]
        fn assert_corrupted(result: Result<SqlCipherMailboxStore, MailboxStoreError>) {
            assert!(matches!(result, Err(MailboxStoreError::Corrupted)));
        }

        #[test]
        fn the_read_only_reader_pages_past_the_newest_store_limit() {
            let (database, store) = open("reader-pages");
            let total = usize::from(StoreLimit::MAX) + 1;
            let envelopes: Vec<_> = (0..total)
                .map(|index| {
                    envelope(
                        &format!("m{index:05}"),
                        "thread",
                        i64::try_from(total - index).unwrap(),
                    )
                })
                .collect();
            run(store.upsert_envelopes(&account(), &envelopes)).unwrap();
            let reader =
                SqlCipherMailboxReader::open_read_only(account(), database.path(), key(7)).unwrap();
            let cursor = EnvelopeCursor::after(&envelopes[total - 2]);
            let page = run(reader.list_envelopes_after(
                &account(),
                Some(&cursor),
                StoreLimit::new(10).unwrap(),
            ))
            .unwrap();
            let ids: Vec<&str> = page.iter().map(|item| item.message_id().as_str()).collect();
            assert_eq!(
                ids,
                ["m10000"],
                "the oldest, past the newest StoreLimit::MAX"
            );
        }

        #[test]
        fn keyset_pages_list_every_envelope_once_in_order() {
            fn paged(reader: &impl MailboxReader) -> Vec<String> {
                let mut paged = Vec::new();
                let mut cursor = None;
                loop {
                    let page = run(reader.list_envelopes_after(
                        &account(),
                        cursor.as_ref(),
                        StoreLimit::new(4).unwrap(),
                    ))
                    .unwrap();
                    let Some(last) = page.last() else { break };
                    cursor = Some(EnvelopeCursor::after(last));
                    paged.extend(
                        page.iter()
                            .map(|item| item.message_id().as_str().to_owned()),
                    );
                }
                paged
            }

            let (_database, store) = open("pages");
            let envelopes: Vec<_> = (0..23)
                .map(|index| envelope(&format!("m{index:02}"), "thread", i64::from(index / 3)))
                .collect();
            run(store.upsert_envelopes(&account(), &envelopes)).unwrap();
            let expected: Vec<_> =
                run(store.list_envelopes(&account(), StoreLimit::new(100).unwrap()))
                    .unwrap()
                    .iter()
                    .map(|item| item.message_id().as_str().to_owned())
                    .collect();
            assert_eq!(
                paged(&store),
                expected,
                "ties on the received time are broken by identifier"
            );
            assert_eq!(expected.len(), 23);

            let connection = store.connection.lock().unwrap();
            let plan: Vec<String> = connection
                .prepare(&format!("EXPLAIN QUERY PLAN {ENVELOPES_AFTER_SQL}"))
                .unwrap()
                .query_map(params![5, "m", 4], |row| row.get::<_, String>(3))
                .unwrap()
                .map(Result::unwrap)
                .collect();
            assert_eq!(plan.len(), 1, "one step, no sort: {plan:?}");
            assert!(
                plan[0]
                    .starts_with("SEARCH messages USING INDEX messages_list_order (received_at<?)"),
                "the listing query seeks the index: {plan:?}"
            );
        }

        #[test]
        fn a_skipped_scan_still_fails_reads_of_a_damaged_page() {
            let database = TestDatabase::new("scan");
            {
                let store =
                    SqlCipherMailboxStore::open(account(), database.path(), key(7)).unwrap();
                let big = envelope("big", "thread", 10);
                run(store.upsert_envelopes(&account(), std::slice::from_ref(&big))).unwrap();
                let body = Message::new(big, MessageContent::new(vec![b'x'; 256 * 1024]).unwrap());
                run(store.put_message(&account(), &body)).unwrap();
                store
                    .connection
                    .lock()
                    .unwrap()
                    .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
                    .unwrap();
            }
            // The body's overflow pages now fill most of the main file.
            // Damage one in the middle.
            let mut bytes = fs::read(database.path()).unwrap();
            assert!(bytes.len() > 256 * 1024, "the body is in the main file");
            let at = bytes.len() / 2;
            bytes[at] ^= 0xff;
            fs::write(database.path(), &bytes).unwrap();

            assert_corrupted(SqlCipherMailboxStore::open_with_scan(
                account(),
                database.path(),
                key(7),
                IntegrityScan::Full,
            ));
            let store = SqlCipherMailboxStore::open_with_scan(
                account(),
                database.path(),
                key(7),
                IntegrityScan::Skip,
            )
            .unwrap();
            assert!(
                run(store.get_message(&account(), &MessageId::new("big").unwrap())).is_err(),
                "SQLCipher authenticates the page when the body is read"
            );
        }

        #[test]
        fn fresh_create_converges_reopen_is_noop_and_wrong_key_is_rejected() {
            assert_eq!(
                key_result(rusqlite::ffi::SQLITE_NOMEM).map_err(classify_key),
                Err(OpenFailure::Storage)
            );
            let database = TestDatabase::new("reopen");
            let store = SqlCipherMailboxStore::open(account(), database.path(), key(7)).unwrap();
            let expected_state = (APPLICATION_ID, VERSION, canonical_schema());
            assert_eq!(schema_state(&store), expected_state);
            drop(store);
            let reopened = SqlCipherMailboxStore::open(account(), database.path(), key(7)).unwrap();
            assert_eq!(schema_state(&reopened), expected_state);
            drop(reopened);
            assert_corrupted(SqlCipherMailboxStore::open(
                account(),
                database.path(),
                key(8),
            ));

            let existing_empty = TestDatabase::new("existing empty ?#%");
            fs::File::create(existing_empty.path()).unwrap();
            fs::set_permissions(existing_empty.path(), fs::Permissions::from_mode(0o600)).unwrap();
            let existing_store =
                SqlCipherMailboxStore::open(account(), existing_empty.path(), key(7)).unwrap();
            assert_eq!(
                schema_state(&existing_store),
                (APPLICATION_ID, VERSION, canonical_schema())
            );
            drop(existing_store);
            let reopened_special =
                SqlCipherMailboxStore::open(account(), existing_empty.path(), key(7)).unwrap();
            assert_eq!(
                schema_state(&reopened_special),
                (APPLICATION_ID, VERSION, canonical_schema())
            );

            let unsafe_empty = TestDatabase::new("unsafe-existing-empty");
            fs::File::create(unsafe_empty.path()).unwrap();
            fs::set_permissions(unsafe_empty.path(), fs::Permissions::from_mode(0o644)).unwrap();
            assert!(matches!(
                SqlCipherMailboxStore::open(account(), unsafe_empty.path(), key(7)),
                Err(MailboxStoreError::Storage)
            ));
            assert_eq!(
                fs::metadata(unsafe_empty.path()).unwrap().mode() & 0o777,
                0o644
            );

            let empty_with_sidecar = TestDatabase::new("empty-with-sidecar");
            fs::File::create(empty_with_sidecar.path()).unwrap();
            fs::set_permissions(empty_with_sidecar.path(), fs::Permissions::from_mode(0o600))
                .unwrap();
            let mut journal_name = empty_with_sidecar.path().as_os_str().to_os_string();
            journal_name.push("-journal");
            let existing_journal_path = PathBuf::from(journal_name);
            fs::write(&existing_journal_path, b"foreign-sidecar").unwrap();
            assert_corrupted(SqlCipherMailboxStore::open(
                account(),
                empty_with_sidecar.path(),
                key(7),
            ));
            assert_eq!(fs::read(existing_journal_path).unwrap(), b"foreign-sidecar");

            let absent_with_sidecar = TestDatabase::new("absent-with-sidecar");
            let absent_journal = journal_path(&absent_with_sidecar);
            fs::write(&absent_journal, b"orphan-foreign-sidecar").unwrap();
            assert_corrupted(SqlCipherMailboxStore::open(
                account(),
                absent_with_sidecar.path(),
                key(7),
            ));
            assert!(!absent_with_sidecar.path().exists());
            assert_eq!(fs::read(absent_journal).unwrap(), b"orphan-foreign-sidecar");
        }

        #[test]
        fn writer_leaf_snapshot_accepts_existing_combinations_and_rejects_orphans() {
            for sidecars in 0_u8..8 {
                let existing = TestDatabase::new(&format!("existing-sidecars-{sidecars}"));
                write_restrictive(existing.path(), b"existing-main");
                for (index, suffix) in ["-journal", "-wal", "-shm"].into_iter().enumerate() {
                    if sidecars & (1 << index) != 0 {
                        write_restrictive(
                            &sidecar_path(existing.path(), suffix),
                            b"existing-sidecar",
                        );
                    }
                }
                let guard = LeafGuard::open(existing.path()).unwrap();
                assert!(guard.snapshot.main.is_some());
                assert!(!guard.snapshot.is_fresh());
                assert_corrupted(SqlCipherMailboxStore::open(
                    account(),
                    existing.path(),
                    key(7),
                ));
                assert!(existing.path().exists());
                assert!(existing.directory.exists());

                let orphan = TestDatabase::new(&format!("orphan-sidecars-{sidecars}"));
                if sidecars == 0 {
                    assert!(LeafGuard::open(orphan.path()).unwrap().snapshot.is_fresh());
                } else {
                    for (index, suffix) in ["-journal", "-wal", "-shm"].into_iter().enumerate() {
                        if sidecars & (1 << index) != 0 {
                            write_restrictive(
                                &sidecar_path(orphan.path(), suffix),
                                b"orphan-sidecar",
                            );
                        }
                    }
                    assert!(matches!(
                        LeafGuard::open(orphan.path()),
                        Err(OpenFailure::Corrupted)
                    ));
                    // Orphan sidecars fail before SQLite opens and are never
                    // granted fresh-cleanup authority.
                    assert_corrupted(SqlCipherMailboxStore::open(
                        account(),
                        orphan.path(),
                        key(7),
                    ));
                    assert!(!orphan.path().exists());
                    assert!(orphan.directory.exists());
                }
            }
        }

        #[test]
        fn fresh_failure_boundaries_keep_only_post_migration_state() {
            for point in [
                WriterHook::BeforeFreshClaim,
                WriterHook::AfterFreshClaim,
                WriterHook::AfterFreshWalNormalization,
                WriterHook::BeforeFreshMigration,
                WriterHook::AfterFreshMigration,
            ] {
                let database = TestDatabase::new(&format!("fresh-boundary-{point:?}"));
                let mut fired = false;
                let result = SqlCipherMailboxStore::open_inner_with_writer_hook(
                    account(),
                    database.path(),
                    key(7),
                    &mut |observed, _path| {
                        if observed == point {
                            fired = true;
                            return Err(OpenFailure::Storage);
                        }
                        Ok(())
                    },
                );
                assert!(fired);
                assert!(matches!(result, Err(MailboxStoreError::Storage)));
                if point == WriterHook::AfterFreshMigration {
                    assert!(database.path().exists());
                } else {
                    assert!(database.files().is_empty());
                }
                assert!(database.directory.exists());
            }
        }

        #[test]
        fn preexisting_empty_main_failure_preserves_main_then_retries() {
            use std::os::unix::fs::MetadataExt;

            let database = TestDatabase::new("preexisting-empty-main");
            write_restrictive(database.path(), b"");
            let main_before = fs::metadata(database.path()).unwrap();
            let mut fired = false;
            let mut cleanup_observed = false;
            let result = SqlCipherMailboxStore::open_inner_with_writer_hook(
                account(),
                database.path(),
                key(7),
                &mut |point, _path| {
                    if point == WriterHook::AfterFreshWalNormalization {
                        fired = true;
                        return Err(OpenFailure::Storage);
                    }
                    if matches!(
                        point,
                        WriterHook::CleanupBeforeRecord(_)
                            | WriterHook::CleanupAfterRecord(_)
                            | WriterHook::CleanupAfterRevalidate(_)
                    ) {
                        cleanup_observed = true;
                    }
                    Ok(())
                },
            );
            assert!(fired);
            assert!(matches!(result, Err(MailboxStoreError::Storage)));
            assert!(!cleanup_observed);
            let main_after = fs::metadata(database.path()).unwrap();
            assert_eq!(main_after.dev(), main_before.dev());
            assert_eq!(main_after.ino(), main_before.ino());
            assert_eq!(main_after.mode() & 0o777, 0o600);

            let store = SqlCipherMailboxStore::open(account(), database.path(), key(7)).unwrap();
            assert_eq!(
                schema_state(&store),
                (APPLICATION_ID, VERSION, canonical_schema())
            );
        }

        fn crashed_missing_shm(label: &str) -> TestDatabase {
            let database = TestDatabase::new(label);
            crash_store_at(&database, "after-migration");
            fs::remove_file(shm_path(&database)).unwrap();
            database
        }

        fn canonical_pair_state(
            database: &TestDatabase,
        ) -> (Vec<u8>, Vec<u8>, FileIdentity, FileIdentity) {
            (
                fs::read(database.path()).unwrap(),
                fs::read(wal_path(database)).unwrap(),
                file_identity(database.path()).unwrap(),
                file_identity(&wal_path(database)).unwrap(),
            )
        }

        fn validate_missing_shm_with_hook(
            database: &TestDatabase,
            key_byte: u8,
            hook: &mut dyn FnMut(RecoveryHook, &Path) -> Result<(), OpenFailure>,
        ) -> Result<bool, OpenFailure> {
            let canonical_path = canonical_database_path(database.path()).unwrap();
            let leaf = LeafGuard::open(&canonical_path).unwrap();
            let database_key = key(key_byte);
            validate_wal_without_shm_from_private_copy_with_hook(
                &canonical_path,
                &account(),
                &database_key.0,
                &leaf,
                hook,
            )
        }

        #[test]
        fn existing_canonical_main_without_sidecars_rebuilds_owner_only_wal_state() {
            let (source, store) = open("canonical-main-source");
            store
                .connection
                .lock()
                .unwrap()
                .execute_batch("PRAGMA wal_checkpoint(FULL);")
                .unwrap();
            drop(store);

            let database = TestDatabase::new("canonical-main-without-sidecars");
            fs::copy(source.path(), database.path()).unwrap();
            fs::set_permissions(database.path(), fs::Permissions::from_mode(0o600)).unwrap();
            assert!(!wal_path(&database).exists());
            assert!(!shm_path(&database).exists());

            let store = SqlCipherMailboxStore::open(account(), database.path(), key(7)).unwrap();
            assert_eq!(
                schema_state(&store),
                (APPLICATION_ID, VERSION, canonical_schema())
            );
            for path in [database.path(), &wal_path(&database), &shm_path(&database)] {
                assert_eq!(fs::metadata(path).unwrap().mode() & 0o777, 0o600);
            }
        }

        #[test]
        fn existing_canonical_main_with_empty_wal_recovers_without_shm() {
            let (source, store) = open("empty-wal-source");
            store
                .connection
                .lock()
                .unwrap()
                .execute_batch("PRAGMA wal_checkpoint(FULL);")
                .unwrap();
            drop(store);

            let database = TestDatabase::new("canonical-main-empty-wal");
            fs::copy(source.path(), database.path()).unwrap();
            fs::set_permissions(database.path(), fs::Permissions::from_mode(0o600)).unwrap();
            let canonical_path = canonical_database_path(database.path()).unwrap();
            let main_only = LeafGuard::open(&canonical_path).unwrap();
            assert_eq!(
                preflight_existing(
                    &canonical_path,
                    &account(),
                    &key(7).0,
                    &main_only,
                    IntegrityScan::Full
                ),
                Ok(ExistingPreflight::MainWithoutSidecars)
            );

            write_restrictive(&wal_path(&database), b"");
            assert!(!shm_path(&database).exists());
            let main_before = fs::read(database.path()).unwrap();
            let main_identity_before = file_identity(database.path()).unwrap();
            let wal_identity_before = file_identity(&wal_path(&database)).unwrap();
            let missing_shm = LeafGuard::open(&canonical_path).unwrap();
            assert_eq!(
                preflight_existing(
                    &canonical_path,
                    &account(),
                    &key(7).0,
                    &missing_shm,
                    IntegrityScan::Full
                ),
                Ok(ExistingPreflight::WalWithoutShm)
            );
            assert_eq!(fs::read(database.path()).unwrap(), main_before);
            assert_eq!(fs::read(wal_path(&database)).unwrap(), b"");
            assert_eq!(
                file_identity(database.path()).unwrap(),
                main_identity_before
            );
            assert_eq!(
                file_identity(&wal_path(&database)).unwrap(),
                wal_identity_before
            );
            assert!(!shm_path(&database).exists());
            assert_no_recovery_stages(&database);

            let store = SqlCipherMailboxStore::open(account(), database.path(), key(7)).unwrap();
            assert_eq!(
                schema_state(&store),
                (APPLICATION_ID, VERSION, canonical_schema())
            );
            assert!(wal_path(&database).is_file());
            assert!(shm_path(&database).is_file());
            assert_no_recovery_stages(&database);
        }

        #[test]
        fn writer_failure_after_open_does_not_checkpoint_existing_wal() {
            let (database, store) = open("writer-open-failure-no-checkpoint");
            run(store.upsert_envelopes(&account(), &[envelope("wal-resident", "thread", 1)]))
                .unwrap();
            drop(store);

            let files_before = database.files();
            let main_before = fs::read(database.path()).unwrap();
            let wal_before = fs::read(wal_path(&database)).unwrap();
            assert!(wal_before.len() >= 32);
            let identities_before = [
                file_identity(database.path()).unwrap(),
                file_identity(&wal_path(&database)).unwrap(),
                file_identity(&shm_path(&database)).unwrap(),
            ];
            let mut failed_after_open = false;
            let result = SqlCipherMailboxStore::open_inner_with_writer_hook(
                account(),
                database.path(),
                key(7),
                &mut |point, _path| {
                    if point == WriterHook::AfterOpen {
                        failed_after_open = true;
                        return Err(OpenFailure::Storage);
                    }
                    Ok(())
                },
            );

            assert!(failed_after_open);
            assert!(matches!(result, Err(MailboxStoreError::Storage)));
            assert_eq!(database.files(), files_before);
            assert_eq!(fs::read(database.path()).unwrap(), main_before);
            assert_eq!(fs::read(wal_path(&database)).unwrap(), wal_before);
            assert_eq!(
                [
                    file_identity(database.path()).unwrap(),
                    file_identity(&wal_path(&database)).unwrap(),
                    file_identity(&shm_path(&database)).unwrap(),
                ],
                identities_before
            );
        }

        #[test]
        fn fresh_claim_eexist_preserves_the_racing_database_and_sidecars() {
            let database = TestDatabase::new("fresh-claim-eexist");
            let mut inserted = false;
            let result = SqlCipherMailboxStore::open_inner_with_writer_hook(
                account(),
                database.path(),
                key(7),
                &mut |point, _path| {
                    if point == WriterHook::BeforeFreshClaim {
                        write_restrictive(database.path(), b"racing-owner");
                        write_restrictive(&wal_path(&database), b"racing-wal");
                        write_restrictive(&shm_path(&database), b"racing-shm");
                        inserted = true;
                    }
                    Ok(())
                },
            );
            assert!(inserted);
            assert!(matches!(result, Err(MailboxStoreError::Storage)));
            assert_eq!(fs::read(database.path()).unwrap(), b"racing-owner");
            assert_eq!(fs::read(wal_path(&database)).unwrap(), b"racing-wal");
            assert_eq!(fs::read(shm_path(&database)).unwrap(), b"racing-shm");
            assert_eq!(fs::metadata(database.path()).unwrap().mode() & 0o777, 0o600);
        }

        #[test]
        fn wal_resident_first_migration_reopens_after_abrupt_exit() {
            let database = TestDatabase::new("wal-resident-first-migration");
            crash_store_at(&database, "after-migration");
            assert!(database.path().is_file());
            assert!(wal_path(&database).is_file());
            assert!(shm_path(&database).is_file());
            fs::remove_file(shm_path(&database)).unwrap();
            let main_before = fs::read(database.path()).unwrap();
            let wal_before = fs::read(wal_path(&database)).unwrap();
            let main_identity_before = file_identity(database.path()).unwrap();
            let wal_identity_before = file_identity(&wal_path(&database)).unwrap();
            let canonical_path = canonical_database_path(database.path()).unwrap();
            let leaf = LeafGuard::open(&canonical_path).unwrap();
            assert_eq!(
                preflight_existing(
                    &canonical_path,
                    &account(),
                    &key(7).0,
                    &leaf,
                    IntegrityScan::Full
                ),
                Ok(ExistingPreflight::WalWithoutShm)
            );
            assert!(!shm_path(&database).exists());
            assert_eq!(fs::read(database.path()).unwrap(), main_before);
            assert_eq!(fs::read(wal_path(&database)).unwrap(), wal_before);
            assert_eq!(
                file_identity(database.path()).unwrap(),
                main_identity_before
            );
            assert_eq!(
                file_identity(&wal_path(&database)).unwrap(),
                wal_identity_before
            );
            assert!(fs::read_dir(&database.directory).unwrap().all(|entry| {
                !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".tersa-wal-recovery-")
            }));

            let store = SqlCipherMailboxStore::open(account(), database.path(), key(7)).unwrap();
            assert_eq!(
                schema_state(&store),
                (APPLICATION_ID, VERSION, canonical_schema())
            );
            assert_eq!(fs::read(database.path()).unwrap(), main_before);
            assert_eq!(fs::read(wal_path(&database)).unwrap(), wal_before);
            assert!(shm_path(&database).is_file());
        }

        #[test]
        fn fresh_wal_crash_before_migration_converges_with_or_without_shm() {
            for point in ["after-wal-normalization", "before-migration"] {
                for missing_shm in [false, true] {
                    let database = TestDatabase::new(&format!(
                        "fresh-wal-{point}-{}",
                        if missing_shm {
                            "missing-shm"
                        } else {
                            "complete"
                        }
                    ));
                    crash_store_at(&database, point);
                    if missing_shm {
                        fs::remove_file(shm_path(&database)).unwrap();
                    }
                    let canonical_path = canonical_database_path(database.path()).unwrap();
                    let leaf = LeafGuard::open(&canonical_path).unwrap();
                    let expected = if missing_shm {
                        ExistingPreflight::FreshWalWithoutShm
                    } else {
                        ExistingPreflight::FreshWal
                    };
                    assert_eq!(
                        preflight_existing(
                            &canonical_path,
                            &account(),
                            &key(7).0,
                            &leaf,
                            IntegrityScan::Full
                        ),
                        Ok(expected)
                    );
                    let mut cleanup_observed = false;
                    let store = SqlCipherMailboxStore::open_inner_with_writer_hook(
                        account(),
                        database.path(),
                        key(7),
                        &mut |observed, _path| {
                            if matches!(
                                observed,
                                WriterHook::CleanupBeforeRecord(_)
                                    | WriterHook::CleanupAfterRecord(_)
                                    | WriterHook::CleanupAfterRevalidate(_)
                            ) {
                                cleanup_observed = true;
                            }
                            Ok(())
                        },
                    )
                    .unwrap();
                    assert!(!cleanup_observed);
                    assert_eq!(
                        schema_state(&store),
                        (APPLICATION_ID, VERSION, canonical_schema())
                    );
                    assert_no_recovery_stages(&database);
                }
            }
        }

        #[test]
        fn missing_shm_recovery_normalizes_private_stage_under_restrictive_umasks() {
            for mask in ["0777", "0577", "0377"] {
                let database = TestDatabase::new(&format!("recovery-umask-{mask}"));
                crash_store_at(&database, "after-migration");
                fs::remove_file(shm_path(&database)).unwrap();
                let main_before = fs::read(database.path()).unwrap();
                let wal_before = fs::read(wal_path(&database)).unwrap();
                let main_identity = file_identity(database.path()).unwrap();
                let wal_identity = file_identity(&wal_path(&database)).unwrap();

                validate_missing_shm_under_umask(&database, mask);

                assert_eq!(fs::read(database.path()).unwrap(), main_before);
                assert_eq!(fs::read(wal_path(&database)).unwrap(), wal_before);
                assert_eq!(file_identity(database.path()).unwrap(), main_identity);
                assert_eq!(file_identity(&wal_path(&database)).unwrap(), wal_identity);
                assert_no_recovery_stages(&database);
            }
        }

        #[test]
        fn canonical_main_without_sidecars_normalizes_new_pair_under_restrictive_umasks() {
            let (source, store) = open("canonical-main-umask-source");
            store
                .connection
                .lock()
                .unwrap()
                .execute_batch("PRAGMA wal_checkpoint(FULL);")
                .unwrap();
            drop(store);

            for mask in ["0777", "0577", "0377"] {
                let database = TestDatabase::new(&format!("canonical-main-umask-{mask}"));
                fs::copy(source.path(), database.path()).unwrap();
                fs::set_permissions(database.path(), fs::Permissions::from_mode(0o600)).unwrap();
                open_existing_under_umask(&database, mask);
                for path in [database.path(), &wal_path(&database), &shm_path(&database)] {
                    assert_eq!(fs::metadata(path).unwrap().mode() & 0o777, 0o600);
                }
                assert_no_recovery_stages(&database);
            }
        }

        #[test]
        fn missing_shm_recovery_normal_errors_clean_the_bounded_stage() {
            let wrong_key = crashed_missing_shm("recovery-wrong-key");
            let wrong_key_before = canonical_pair_state(&wrong_key);
            assert_eq!(
                validate_missing_shm_with_hook(&wrong_key, 8, &mut |_point, _path| Ok(())),
                Err(OpenFailure::Corrupted)
            );
            assert_eq!(canonical_pair_state(&wrong_key), wrong_key_before);
            assert_no_recovery_stages(&wrong_key);

            let corrupt_wal = crashed_missing_shm("recovery-corrupt-wal");
            fs::write(wal_path(&corrupt_wal), b"corrupt-encrypted-wal").unwrap();
            let corrupt_wal_before = canonical_pair_state(&corrupt_wal);
            assert!(
                validate_missing_shm_with_hook(&corrupt_wal, 7, &mut |_point, _path| Ok(()))
                    .is_err()
            );
            assert_eq!(canonical_pair_state(&corrupt_wal), corrupt_wal_before);
            assert_no_recovery_stages(&corrupt_wal);

            for failure_point in [
                RecoveryHook::AfterDirectoryCreate,
                RecoveryHook::AfterDirectoryNormalize,
                RecoveryHook::AfterMainCopy,
                RecoveryHook::AfterWalCopy,
                RecoveryHook::BeforeReadOnlyOpen,
                RecoveryHook::AfterReadOnlyOpen,
                RecoveryHook::BeforeOriginalFinalRevalidate,
                RecoveryHook::BeforeCleanup,
            ] {
                let database = crashed_missing_shm(&format!("recovery-boundary-{failure_point:?}"));
                let before = canonical_pair_state(&database);
                let result = validate_missing_shm_with_hook(&database, 7, &mut |point, _path| {
                    if point == failure_point {
                        return Err(OpenFailure::Storage);
                    }
                    Ok(())
                });
                assert_eq!(result, Err(OpenFailure::Storage));
                assert_eq!(canonical_pair_state(&database), before);
                assert_no_recovery_stages(&database);
            }
        }

        #[test]
        fn missing_shm_recovery_preserves_validation_classification_when_cleanup_fails() {
            let database = crashed_missing_shm("recovery-corrupted-with-tampered-stage");
            let before = canonical_pair_state(&database);
            let mut tampered_stage = None;
            let result = validate_missing_shm_with_hook(&database, 8, &mut |point, stage| {
                if point == RecoveryHook::BeforeCleanup {
                    write_restrictive(&stage.join("mail.sqlite3-journal"), b"unexpected-journal");
                    tampered_stage = Some(stage.to_path_buf());
                }
                Ok(())
            });

            assert_eq!(result, Err(OpenFailure::Corrupted));
            assert_eq!(canonical_pair_state(&database), before);
            let tampered_stage = tampered_stage.unwrap();
            assert!(tampered_stage.join("mail.sqlite3").is_file());
            assert!(tampered_stage.join("mail.sqlite3-wal").is_file());
            assert!(tampered_stage.join("mail.sqlite3-shm").is_file());
            let unexpected_journal = tampered_stage.join("mail.sqlite3-journal");
            assert!(unexpected_journal.is_file());
            assert_eq!(
                fs::metadata(unexpected_journal).unwrap().mode() & 0o777,
                0o600
            );
        }

        #[test]
        fn missing_shm_recovery_original_drift_fails_closed_and_cleans_its_stage() {
            let database = crashed_missing_shm("recovery-original-drift");
            let replacement = database.directory.join("replacement-wal");
            write_restrictive(&replacement, b"replacement-wal");
            let original = database.directory.join("original-wal");
            let mut drifted = false;
            let result = validate_missing_shm_with_hook(&database, 7, &mut |point, _path| {
                if point == RecoveryHook::AfterWalCopy {
                    fs::rename(wal_path(&database), &original).unwrap();
                    fs::rename(&replacement, wal_path(&database)).unwrap();
                    drifted = true;
                }
                Ok(())
            });
            assert!(drifted);
            assert_eq!(result, Err(OpenFailure::Storage));
            assert_eq!(fs::read(wal_path(&database)).unwrap(), b"replacement-wal");
            assert!(original.is_file());
            assert_no_recovery_stages(&database);
        }

        #[test]
        fn missing_shm_recovery_preserves_tampered_stage_residue_fail_closed() {
            let mode_database = crashed_missing_shm("recovery-stage-mode-tamper");
            let mut mode_stage = None;
            let mode_result =
                validate_missing_shm_with_hook(&mode_database, 7, &mut |point, stage| {
                    if point == RecoveryHook::AfterReadOnlyOpen {
                        fs::set_permissions(
                            stage.join("mail.sqlite3-wal"),
                            fs::Permissions::from_mode(0o640),
                        )
                        .unwrap();
                        mode_stage = Some(stage.to_path_buf());
                    }
                    Ok(())
                });
            assert_eq!(mode_result, Err(OpenFailure::Storage));
            let mode_stage = mode_stage.unwrap();
            assert_eq!(
                fs::metadata(mode_stage.join("mail.sqlite3-wal"))
                    .unwrap()
                    .mode()
                    & 0o777,
                0o640
            );

            let directory_database = crashed_missing_shm("recovery-stage-directory-tamper");
            let mut moved_stage = None;
            let directory_result =
                validate_missing_shm_with_hook(&directory_database, 7, &mut |point, stage| {
                    if point == RecoveryHook::AfterWalCopy {
                        let moved = directory_database.directory.join("moved-recovery-stage");
                        fs::rename(stage, &moved).unwrap();
                        fs::create_dir(stage).unwrap();
                        fs::set_permissions(stage, fs::Permissions::from_mode(0o700)).unwrap();
                        moved_stage = Some((stage.to_path_buf(), moved));
                    }
                    Ok(())
                });
            assert_eq!(directory_result, Err(OpenFailure::Storage));
            let (replacement_stage, moved_stage) = moved_stage.unwrap();
            assert!(replacement_stage.is_dir());
            assert!(moved_stage.is_dir());
        }

        #[test]
        fn missing_shm_recovery_preserves_exact_mode_replacements_and_unknown_files() {
            let replacement_database = crashed_missing_shm("recovery-stage-inode-tamper");
            let captured_main = replacement_database.directory.join("captured-stage-main");
            let mut replacement_stage = None;
            let replacement_result =
                validate_missing_shm_with_hook(&replacement_database, 7, &mut |point, stage| {
                    if point == RecoveryHook::BeforeCleanup {
                        fs::rename(stage.join("mail.sqlite3"), &captured_main).unwrap();
                        write_restrictive(&stage.join("mail.sqlite3"), b"exact-mode-replacement");
                        replacement_stage = Some(stage.to_path_buf());
                    }
                    Ok(())
                });
            assert_eq!(replacement_result, Err(OpenFailure::Storage));
            let replacement_stage = replacement_stage.unwrap();
            assert!(captured_main.is_file());
            assert_eq!(
                fs::metadata(replacement_stage.join("mail.sqlite3"))
                    .unwrap()
                    .mode()
                    & 0o777,
                0o600
            );

            let journal_database = crashed_missing_shm("recovery-stage-journal-tamper");
            let mut journal_stage = None;
            let journal_result =
                validate_missing_shm_with_hook(&journal_database, 7, &mut |point, stage| {
                    if point == RecoveryHook::BeforeCleanup {
                        write_restrictive(
                            &stage.join("mail.sqlite3-journal"),
                            b"unexpected-journal",
                        );
                        journal_stage = Some(stage.to_path_buf());
                    }
                    Ok(())
                });
            assert_eq!(journal_result, Err(OpenFailure::Storage));
            let journal_stage = journal_stage.unwrap();
            assert!(journal_stage.join("mail.sqlite3").is_file());
            assert!(journal_stage.join("mail.sqlite3-wal").is_file());
            assert!(journal_stage.join("mail.sqlite3-shm").is_file());
            assert!(journal_stage.join("mail.sqlite3-journal").is_file());
        }

        #[test]
        fn missing_shm_recovery_stage_attempts_are_strictly_bounded() {
            let database = crashed_missing_shm("recovery-stage-exhaustion");
            let stages = recovery_stage_paths(&database);
            for stage in &stages {
                fs::create_dir(stage).unwrap();
                fs::set_permissions(stage, fs::Permissions::from_mode(0o700)).unwrap();
            }
            let before = canonical_pair_state(&database);
            assert_eq!(
                validate_missing_shm_with_hook(&database, 7, &mut |_point, _path| Ok(())),
                Err(OpenFailure::Storage)
            );
            assert_eq!(canonical_pair_state(&database), before);
            assert!(stages.iter().all(|stage| stage.is_dir()));
            assert_eq!(
                fs::read_dir(&database.directory)
                    .unwrap()
                    .filter_map(Result::ok)
                    .filter(|entry| {
                        entry
                            .file_name()
                            .to_string_lossy()
                            .starts_with(".tersa-wal-recovery-v1-")
                    })
                    .count(),
                RECOVERY_STAGE_LIMIT
            );
        }

        #[test]
        fn restrictive_umasks_cleanup_then_retry_with_owner_only_leaves() {
            let executable = std::env::current_exe().unwrap();
            for (label, mask) in [("zero", "0777"), ("write", "0577"), ("read", "0377")] {
                let database = TestDatabase::new(&format!("umask-{label}"));
                let status = Command::new("/bin/sh")
                    .arg("-c")
                    .arg("umask \"$1\"; shift; exec \"$@\"")
                    .arg("tersa-umask")
                    .arg(mask)
                    .arg(&executable)
                    .args([
                        "--exact",
                        "store::tests::restrictive_umask_store_child",
                        "--ignored",
                        "--nocapture",
                    ])
                    .env("TERSA_STORE_UMASK_DATABASE", database.path())
                    .stdin(Stdio::null())
                    .status()
                    .unwrap();
                assert!(status.success(), "store helper failed for umask {mask}");
            }
        }

        #[test]
        fn restrictive_umask_sidecar_refusal_preserves_main_for_retries() {
            let database = TestDatabase::new("cleanup-refused-umask");
            let status = Command::new("/bin/sh")
                .arg("-c")
                .arg("umask \"$1\"; shift; exec \"$@\"")
                .arg("tersa-cleanup-refused-umask")
                .arg("0777")
                .arg(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "store::tests::restrictive_umask_sidecar_refusal_child",
                    "--ignored",
                    "--nocapture",
                ])
                .env("TERSA_STORE_CLEANUP_REFUSED_DATABASE", database.path())
                .stdin(Stdio::null())
                .status()
                .unwrap();
            assert!(status.success(), "restrictive-umask cleanup helper failed");
        }

        #[test]
        fn absent_journal_is_benign_during_fresh_cleanup() {
            let database = TestDatabase::new("cleanup-absent-journal");
            let mut injected = false;
            let result = SqlCipherMailboxStore::open_inner_with_writer_hook(
                account(),
                database.path(),
                key(7),
                &mut |point, _path| {
                    if point == WriterHook::AfterFreshClaim {
                        write_restrictive(&wal_path(&database), b"candidate-wal");
                        write_restrictive(&shm_path(&database), b"candidate-shm");
                        injected = true;
                        return Err(OpenFailure::Storage);
                    }
                    Ok(())
                },
            );
            assert!(injected);
            assert!(matches!(result, Err(MailboxStoreError::Storage)));
            assert!(database.files().is_empty());
        }

        #[test]
        fn fresh_leaf_normalization_is_bound_to_the_opened_descriptor() {
            use std::os::unix::fs::MetadataExt;

            let database = TestDatabase::new("normalize-replacement");
            let backup = database.directory.join("opened-main");
            let mut replaced = false;
            let result = SqlCipherMailboxStore::open_inner_with_writer_hook(
                account(),
                database.path(),
                key(7),
                &mut |point, canonical_path| {
                    if point == WriterHook::NormalizeAfterOpen(0) {
                        fs::rename(canonical_path, &backup).unwrap();
                        write_restrictive(canonical_path, b"same-user-replacement");
                        replaced = true;
                    }
                    Ok(())
                },
            );
            assert!(replaced);
            assert!(matches!(result, Err(MailboxStoreError::Storage)));
            assert_eq!(fs::metadata(&backup).unwrap().mode() & 0o777, 0o600);
            assert_eq!(fs::read(database.path()).unwrap(), b"same-user-replacement");
        }

        #[test]
        fn cleanup_hooks_require_an_exclusively_created_main() {
            // Sidecar cleanup is authorized only after this opener has proved
            // main-leaf authorship through O_EXCL. These cases exercise the
            // remaining mutable-name gaps after that proof.
            for index in 1..4 {
                let inserted = TestDatabase::new(&format!("cleanup-insert-{index}"));
                let inserted_path = fixed_leaf_path(&inserted, index);
                let mut injected = false;
                let result = SqlCipherMailboxStore::open_inner_with_writer_hook(
                    account(),
                    inserted.path(),
                    key(7),
                    &mut |point, _path| {
                        if point == WriterHook::AfterFreshClaim {
                            write_restrictive(&inserted_path, b"inserted-after-snapshot");
                            injected = true;
                            return Err(OpenFailure::Storage);
                        }
                        Ok(())
                    },
                );
                assert!(injected);
                assert!(matches!(result, Err(MailboxStoreError::Storage)));
                // Sidecars absent at snapshot remain cleanup candidates.
                assert!(!inserted_path.exists());

                let replaced = TestDatabase::new(&format!("cleanup-middle-replace-{index}"));
                let replaced_path = fixed_leaf_path(&replaced, index);
                let backup = replaced.directory.join("recorded-before-replace");
                let mut replacement_done = false;
                let result = SqlCipherMailboxStore::open_inner_with_writer_hook(
                    account(),
                    replaced.path(),
                    key(7),
                    &mut |point, _path| {
                        if point == WriterHook::AfterFreshClaim {
                            write_restrictive(&replaced_path, b"recorded");
                            return Err(OpenFailure::Storage);
                        }
                        if point == WriterHook::CleanupAfterRecord(index) {
                            fs::rename(&replaced_path, &backup).unwrap();
                            write_restrictive(&replaced_path, b"replacement-preserved");
                            replacement_done = true;
                        }
                        Ok(())
                    },
                );
                assert!(replacement_done);
                assert!(matches!(result, Err(MailboxStoreError::Storage)));
                // The middle revalidation observes the identity change and
                // stops before deleting the cleanup-authority main.
                assert_eq!(fs::read(&replaced_path).unwrap(), b"replacement-preserved");
                let main_before_retry = file_identity(replaced.path()).unwrap();
                let files_before_retry = replaced.files();
                assert_corrupted(SqlCipherMailboxStore::open(
                    account(),
                    replaced.path(),
                    key(7),
                ));
                assert_eq!(file_identity(replaced.path()).unwrap(), main_before_retry);
                assert_eq!(replaced.files(), files_before_retry);

                let final_gap = TestDatabase::new(&format!("cleanup-final-gap-{index}"));
                let final_path = fixed_leaf_path(&final_gap, index);
                let final_backup = final_gap.directory.join("revalidated-before-unlink");
                let mut final_replacement = false;
                let result = SqlCipherMailboxStore::open_inner_with_writer_hook(
                    account(),
                    final_gap.path(),
                    key(7),
                    &mut |point, _path| {
                        if point == WriterHook::AfterFreshClaim {
                            write_restrictive(&final_path, b"revalidated");
                            return Err(OpenFailure::Storage);
                        }
                        if point == WriterHook::CleanupAfterRevalidate(index) {
                            fs::rename(&final_path, &final_backup).unwrap();
                            write_restrictive(&final_path, b"replacement-in-final-gap");
                            final_replacement = true;
                        }
                        Ok(())
                    },
                );
                assert!(final_replacement);
                assert!(matches!(result, Err(MailboxStoreError::Storage)));
                // Accepted residual: unlinkat cannot bind deletion to the
                // revalidated inode, so this final-gap replacement is removed.
                assert!(!final_path.exists());
            }
        }

        #[test]
        fn cleanup_refuses_an_unowned_symlink_and_preserves_main_for_retries() {
            let database = TestDatabase::new("cleanup-unowned-symlink");
            let foreign = database.directory.join("foreign-sidecar-target");
            let candidate = shm_path(&database);
            let mut injected = false;
            let result = SqlCipherMailboxStore::open_inner_with_writer_hook(
                account(),
                database.path(),
                key(7),
                &mut |point, _path| {
                    if point == WriterHook::AfterFreshClaim {
                        write_restrictive(&foreign, b"foreign-sidecar");
                        std::os::unix::fs::symlink(&foreign, &candidate).unwrap();
                        injected = true;
                        return Err(OpenFailure::Storage);
                    }
                    Ok(())
                },
            );
            assert!(injected);
            assert!(matches!(result, Err(MailboxStoreError::Storage)));
            let main_before_retry = file_identity(database.path()).unwrap();
            assert!(
                fs::symlink_metadata(&candidate)
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );
            assert_eq!(fs::read(&foreign).unwrap(), b"foreign-sidecar");

            for _ in 0..2 {
                assert!(matches!(
                    SqlCipherMailboxStore::open(account(), database.path(), key(7)),
                    Err(MailboxStoreError::Storage)
                ));
                assert_eq!(file_identity(database.path()).unwrap(), main_before_retry);
                assert!(
                    fs::symlink_metadata(&candidate)
                        .unwrap()
                        .file_type()
                        .is_symlink()
                );
                assert_eq!(fs::read(&foreign).unwrap(), b"foreign-sidecar");
            }
        }

        #[test]
        fn cleanup_stops_when_fresh_main_authority_is_replaced() {
            let database = TestDatabase::new("cleanup-main-authority-race");
            let original_main = database.directory.join("original-fresh-main");
            let mut replaced_main = false;
            let result = SqlCipherMailboxStore::open_inner_with_writer_hook(
                account(),
                database.path(),
                key(7),
                &mut |point, canonical_path| {
                    if point == WriterHook::AfterFreshClaim {
                        write_restrictive(&wal_path(&database), b"candidate-wal");
                        write_restrictive(&shm_path(&database), b"candidate-shm");
                        return Err(OpenFailure::Storage);
                    }
                    if point == WriterHook::CleanupAfterRevalidate(3) {
                        fs::rename(canonical_path, &original_main).unwrap();
                        write_restrictive(canonical_path, b"replacement-main");
                        replaced_main = true;
                    }
                    Ok(())
                },
            );
            assert!(replaced_main);
            assert!(matches!(result, Err(MailboxStoreError::Storage)));
            assert_eq!(fs::read(database.path()).unwrap(), b"replacement-main");
            assert_eq!(fs::read(wal_path(&database)).unwrap(), b"candidate-wal");
            assert_eq!(fs::read(shm_path(&database)).unwrap(), b"candidate-shm");
        }

        #[test]
        fn every_nonempty_residual_retries_through_the_state_matrix() {
            for subset in 1_u8..16 {
                let database = TestDatabase::new(&format!("residual-subset-{subset}"));
                for index in 0..4 {
                    if subset & (1 << index) != 0 {
                        write_restrictive(&fixed_leaf_path(&database, index), b"residual");
                    }
                }
                let result = SqlCipherMailboxStore::open(account(), database.path(), key(7));
                assert_corrupted(result);
                for index in 0..4 {
                    let present = subset & (1 << index) != 0;
                    assert_eq!(fixed_leaf_path(&database, index).exists(), present);
                }
                assert!(database.directory.exists());
            }
        }

        #[test]
        fn identity_queries_classify_operational_sqlite_failures_as_storage() {
            let memory = Connection::open_in_memory().unwrap();
            assert_eq!(
                set_and_verify_persistent_wal(&memory),
                Err(OpenFailure::Storage)
            );
            for code in [
                rusqlite::ffi::SQLITE_NOMEM,
                rusqlite::ffi::SQLITE_IOERR,
                rusqlite::ffi::SQLITE_BUSY,
                rusqlite::ffi::SQLITE_FULL,
                rusqlite::ffi::SQLITE_CANTOPEN,
            ] {
                assert_eq!(
                    classify_open(rusqlite::Error::SqliteFailure(
                        rusqlite::ffi::Error::new(code),
                        None,
                    )),
                    OpenFailure::Storage
                );
            }
            assert_eq!(
                classify_open(rusqlite::Error::QueryReturnedNoRows),
                OpenFailure::Corrupted
            );
            assert_eq!(
                classify_open(rusqlite::Error::InvalidColumnType(
                    0,
                    "cipher_version".into(),
                    rusqlite::types::Type::Integer,
                )),
                OpenFailure::Corrupted
            );
            assert_eq!(
                classify_open(rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_NOTADB),
                    None,
                )),
                OpenFailure::Corrupted
            );

            let (database, store) = open("invalid-owner-utf8");
            store
                .connection
                .lock()
                .unwrap()
                .execute_batch(
                    "UPDATE account_binding SET account_id = CAST(X'80' AS TEXT) WHERE singleton = 1;",
                )
                .unwrap();
            drop(store);
            assert_corrupted(SqlCipherMailboxStore::open(
                account(),
                database.path(),
                key(7),
            ));
        }

        #[test]
        fn unknown_noncanonical_and_future_schemas_are_rejected() {
            let unknown = TestDatabase::new("unknown-owner");
            let connection = raw_connection(&unknown);
            apply_key(&connection, &key(7).0).unwrap();
            connection
                .execute_batch("CREATE TABLE sqliteX (value TEXT NOT NULL);")
                .unwrap();
            let unknown_schema = schema(&connection).unwrap();
            let unknown_journal: String = connection
                .query_row("PRAGMA journal_mode", [], |row| row.get(0))
                .unwrap();
            drop(connection);
            assert_corrupted(SqlCipherMailboxStore::open(
                account(),
                unknown.path(),
                key(7),
            ));
            let unchanged = raw_existing_connection(&unknown);
            apply_key(&unchanged, &key(7).0).unwrap();
            assert_eq!(schema(&unchanged).unwrap(), unknown_schema);
            assert_eq!(
                unchanged
                    .query_row::<String, _, _>("PRAGMA journal_mode", [], |row| row.get(0))
                    .unwrap(),
                unknown_journal
            );
            drop(unchanged);

            let (hidden_extra_database, hidden_extra) = open("hidden-extra-schema");
            hidden_extra
                .connection
                .lock()
                .unwrap()
                .execute_batch("CREATE TABLE sqliteX (value TEXT NOT NULL);")
                .unwrap();
            drop(hidden_extra);
            assert_corrupted(SqlCipherMailboxStore::open(
                account(),
                hidden_extra_database.path(),
                key(7),
            ));

            let excessive = TestDatabase::new("excessive-schema");
            let excessive_connection = raw_connection(&excessive);
            apply_key(&excessive_connection, &key(7).0).unwrap();
            excessive_connection
                .execute_batch(
                    "CREATE TABLE one (value TEXT);
                     CREATE TABLE two (value TEXT);
                     CREATE TABLE three (value TEXT);
                     CREATE TABLE four (value TEXT);
                     CREATE TABLE five (value TEXT);",
                )
                .unwrap();
            drop(excessive_connection);
            assert_corrupted(SqlCipherMailboxStore::open(
                account(),
                excessive.path(),
                key(7),
            ));

            let oversized = TestDatabase::new("oversized-schema");
            let oversized_connection = raw_connection(&oversized);
            apply_key(&oversized_connection, &key(7).0).unwrap();
            oversized_connection
                .execute_batch(&format!(
                    "CREATE TABLE oversized_sql (value TEXT CHECK (value != '{}'));",
                    "x".repeat(usize::try_from(MAX_SCHEMA_SQL_LEN).unwrap() + 1)
                ))
                .unwrap();
            drop(oversized_connection);
            assert_corrupted(SqlCipherMailboxStore::open(
                account(),
                oversized.path(),
                key(7),
            ));

            let (modified_database, modified) = open("modified-schema");
            modified
                .connection
                .lock()
                .unwrap()
                .execute_batch("ALTER TABLE messages ADD COLUMN unexpected TEXT;")
                .unwrap();
            drop(modified);
            assert_corrupted(SqlCipherMailboxStore::open(
                account(),
                modified_database.path(),
                key(7),
            ));

            let (future_database, future) = open("future-schema");
            future
                .connection
                .lock()
                .unwrap()
                .pragma_update(None, "user_version", VERSION + 1)
                .unwrap();
            drop(future);
            assert_corrupted(SqlCipherMailboxStore::open(
                account(),
                future_database.path(),
                key(7),
            ));
        }

        #[test]
        fn foreign_hot_journal_is_rejected_without_recovery_or_mutation() {
            let database = TestDatabase::new("foreign-hot-journal");
            leave_foreign_hot_journal(&database);
            let journal_path = journal_path(&database);
            let database_before = fs::read(database.path()).unwrap();
            let journal_before = fs::read(&journal_path).unwrap();

            assert_corrupted(SqlCipherMailboxStore::open(
                account(),
                database.path(),
                key(7),
            ));
            assert_eq!(fs::read(database.path()).unwrap(), database_before);
            assert_eq!(fs::read(journal_path).unwrap(), journal_before);
        }

        #[test]
        fn replacement_between_preflight_and_reopen_is_rejected_before_database_reads() {
            let original = TestDatabase::new("preflight-original");
            let store = SqlCipherMailboxStore::open(account(), original.path(), key(7)).unwrap();
            drop(store);
            let replacement = TestDatabase::new("preflight-replacement");
            leave_foreign_hot_journal(&replacement);
            let replacement_database = fs::read(replacement.path()).unwrap();
            let replacement_journal_path = journal_path(&replacement);
            let replacement_journal = fs::read(&replacement_journal_path).unwrap();
            let original_backup = original.directory.join("owned-backup.sqlite3");
            let original_journal_path = journal_path(&original);

            let result = SqlCipherMailboxStore::open_inner(
                account(),
                original.path(),
                key(7),
                |_canonical_path| {
                    fs::rename(original.path(), &original_backup).unwrap();
                    fs::rename(replacement.path(), original.path()).unwrap();
                    fs::rename(&replacement_journal_path, &original_journal_path).unwrap();
                },
            );
            assert!(matches!(result, Err(MailboxStoreError::Storage)));
            assert_eq!(fs::read(original.path()).unwrap(), replacement_database);
            assert_eq!(
                fs::read(original_journal_path).unwrap(),
                replacement_journal
            );
        }

        #[test]
        fn moved_opened_file_is_rejected_before_key_or_database_reads() {
            let original = TestDatabase::new("moved-opened-original");
            let store = SqlCipherMailboxStore::open(account(), original.path(), key(7)).unwrap();
            drop(store);
            let original_bytes = fs::read(original.path()).unwrap();

            let replacement = TestDatabase::new("moved-opened-replacement");
            fs::write(replacement.path(), b"replacement remains unchanged").unwrap();
            let replacement_bytes = fs::read(replacement.path()).unwrap();
            let original_backup = original.directory.join("original-backup.sqlite3");
            let replacement_backup = replacement.directory.join("replacement-backup.sqlite3");

            let result = SqlCipherMailboxStore::open_inner_with_hooks(
                account(),
                original.path(),
                key(7),
                |_canonical_path| {
                    fs::rename(original.path(), &original_backup).unwrap();
                    fs::rename(replacement.path(), original.path()).unwrap();
                },
                |_canonical_path| {
                    fs::rename(original.path(), &replacement_backup).unwrap();
                    fs::rename(&original_backup, original.path()).unwrap();
                },
            );

            assert!(matches!(result, Err(MailboxStoreError::Storage)));
            assert_eq!(fs::read(original.path()).unwrap(), original_bytes);
            assert_eq!(fs::read(&replacement_backup).unwrap(), replacement_bytes);
        }

        #[test]
        #[ignore = "subprocess helper for the foreign hot-journal regression"]
        fn foreign_hot_journal_child() {
            let Some(database) = std::env::var_os("TERSA_STORE_HOT_JOURNAL_DATABASE") else {
                return;
            };
            let Some(ready) = std::env::var_os("TERSA_STORE_HOT_JOURNAL_READY") else {
                return;
            };
            let path = canonical_database_path(Path::new(&database)).unwrap();
            let connection = open_connection(&path).unwrap();
            apply_key(&connection, &key(7).0).unwrap();
            connection
                .execute_batch(
                    "PRAGMA journal_mode = DELETE;
                     PRAGMA synchronous = FULL;
                     PRAGMA cache_size = 1;
                     BEGIN IMMEDIATE;
                     UPDATE foreign_owner SET value = zeroblob(1048576);",
                )
                .unwrap();
            fs::write(ready, b"ready").unwrap();
            loop {
                thread::park();
            }
        }

        #[test]
        #[ignore = "subprocess helper for WAL-resident first-migration recovery"]
        #[expect(
            clippy::exit,
            reason = "the helper must terminate without running destructors to model a crash"
        )]
        fn wal_resident_first_migration_crash_child() {
            let Some(database) = std::env::var_os("TERSA_STORE_CRASH_DATABASE") else {
                return;
            };
            let Some(crash_point) = std::env::var_os("TERSA_STORE_CRASH_POINT") else {
                return;
            };
            let database = PathBuf::from(database);
            let crash_point = crash_point.to_string_lossy();
            let result = SqlCipherMailboxStore::open_inner_with_writer_hook(
                account(),
                &database,
                key(7),
                &mut |point, _path| {
                    let should_crash = matches!(
                        (crash_point.as_ref(), point),
                        (
                            "after-wal-normalization",
                            WriterHook::AfterFreshWalNormalization
                        ) | ("before-migration", WriterHook::BeforeFreshMigration)
                            | ("after-migration", WriterHook::AfterFreshMigration)
                    );
                    if should_crash {
                        assert!(database.is_file());
                        assert!(sidecar_path(&database, "-wal").is_file());
                        assert!(sidecar_path(&database, "-shm").is_file());
                        std::process::exit(73);
                    }
                    Ok(())
                },
            );
            panic!("crash boundary was not reached: {result:?}");
        }

        #[test]
        #[ignore = "subprocess helper for restrictive-umask existing-store recovery"]
        fn restrictive_umask_existing_store_child() {
            let Some(database) = std::env::var_os("TERSA_STORE_EXISTING_DATABASE") else {
                return;
            };
            let database = PathBuf::from(database);
            if std::env::var_os("TERSA_STORE_RECOVERY_ONLY").is_some() {
                let canonical_path = canonical_database_path(&database).unwrap();
                let leaf = LeafGuard::open(&canonical_path).unwrap();
                assert!(
                    !validate_wal_without_shm_from_private_copy(
                        &canonical_path,
                        &account(),
                        &key(7).0,
                        &leaf,
                    )
                    .unwrap()
                );
                assert!(
                    (0..RECOVERY_STAGE_LIMIT)
                        .map(|slot| database
                            .parent()
                            .unwrap()
                            .join(format!(".tersa-wal-recovery-v1-{slot}")))
                        .all(|path| !path.exists())
                );
                return;
            }
            let store = SqlCipherMailboxStore::open(account(), &database, key(7)).unwrap();
            assert_eq!(
                schema_state(&store),
                (APPLICATION_ID, VERSION, canonical_schema())
            );
            for path in [
                database.clone(),
                sidecar_path(&database, "-wal"),
                sidecar_path(&database, "-shm"),
            ] {
                assert_eq!(fs::metadata(path).unwrap().mode() & 0o777, 0o600);
            }
            assert!(
                (0..RECOVERY_STAGE_LIMIT)
                    .map(|slot| {
                        database
                            .parent()
                            .unwrap()
                            .join(format!(".tersa-wal-recovery-v1-{slot}"))
                    })
                    .all(|path| !path.exists())
            );
        }

        #[test]
        #[ignore = "subprocess helper for process-global umask coverage"]
        fn restrictive_umask_store_child() {
            use std::os::unix::fs::MetadataExt;

            let Some(database) = std::env::var_os("TERSA_STORE_UMASK_DATABASE") else {
                return;
            };
            let database = PathBuf::from(database);
            let mut injected = false;
            let first = SqlCipherMailboxStore::open_inner_with_writer_hook(
                account(),
                &database,
                key(7),
                &mut |point, _path| {
                    if point == WriterHook::AfterFreshWalNormalization {
                        injected = true;
                        return Err(OpenFailure::Storage);
                    }
                    Ok(())
                },
            );
            assert!(injected);
            assert!(matches!(first, Err(MailboxStoreError::Storage)));
            assert!(
                fs::read_dir(database.parent().unwrap())
                    .unwrap()
                    .all(|entry| !entry.unwrap().path().is_file())
            );

            let store = SqlCipherMailboxStore::open(account(), &database, key(7)).unwrap();
            let wal = sidecar_path(&database, "-wal");
            let shm = sidecar_path(&database, "-shm");
            for path in [&database, &wal, &shm] {
                assert!(
                    path.exists(),
                    "expected live SQLite leaf {}",
                    path.display()
                );
                assert_eq!(fs::metadata(path).unwrap().mode() & 0o777, 0o600);
            }
            drop(store);
        }

        #[test]
        #[ignore = "subprocess helper for refused sidecar cleanup under a restrictive umask"]
        fn restrictive_umask_sidecar_refusal_child() {
            use std::os::unix::fs::MetadataExt;

            let Some(database) = std::env::var_os("TERSA_STORE_CLEANUP_REFUSED_DATABASE") else {
                return;
            };
            let database = PathBuf::from(database);
            let refused_sidecar = sidecar_path(&database, "-shm");
            let mut injected = false;
            let first = SqlCipherMailboxStore::open_inner_with_writer_hook(
                account(),
                &database,
                key(7),
                &mut |point, _path| {
                    if point == WriterHook::AfterFreshClaim {
                        fs::write(&refused_sidecar, b"refused-sidecar").unwrap();
                        injected = true;
                        return Err(OpenFailure::Storage);
                    }
                    Ok(())
                },
            );
            assert!(injected);
            assert!(matches!(first, Err(MailboxStoreError::Storage)));
            assert_eq!(fs::metadata(&database).unwrap().mode() & 0o777, 0o600);
            assert_eq!(
                fs::metadata(&refused_sidecar).unwrap().mode() & 0o777,
                0o000
            );
            let main_before_retry = file_identity(&database).unwrap();

            for _ in 0..2 {
                assert!(matches!(
                    SqlCipherMailboxStore::open(account(), &database, key(7)),
                    Err(MailboxStoreError::Storage)
                ));
                assert_eq!(file_identity(&database).unwrap(), main_before_retry);
                assert_eq!(
                    fs::metadata(&refused_sidecar).unwrap().mode() & 0o777,
                    0o000
                );
            }
        }

        #[test]
        fn envelope_upsert_preserves_content_and_put_replaces_every_field() {
            let (_database, store) = open("content");
            let initial = envelope("m1", "t1", 10);
            run(store.upsert_envelopes(&account(), std::slice::from_ref(&initial))).unwrap();
            assert!(
                run(store.message(&account(), initial.message_id()))
                    .unwrap()
                    .is_none()
            );
            let message = Message::new(
                initial.clone(),
                MessageContent::new(b"body one".to_vec()).unwrap(),
            );
            run(store.put_message(&account(), &message)).unwrap();
            run(store.put_message(&account(), &message)).unwrap();
            let changed = MessageEnvelope::new(
                MessageId::new("m1").unwrap(),
                ThreadId::new("t2").unwrap(),
                HeaderText::new("new from").unwrap(),
                HeaderText::new("new subject").unwrap(),
                HeaderText::new("new preview").unwrap(),
                UnixTimestampMillis::new(20).unwrap(),
                true,
            );
            run(store.upsert_envelopes(&account(), std::slice::from_ref(&changed))).unwrap();
            assert_eq!(
                run(store.list_envelopes(&account(), StoreLimit::new(10).unwrap())).unwrap(),
                vec![changed.clone()],
                "the upsert replaces the envelope's fields"
            );
            assert_eq!(
                run(store.message(&account(), changed.message_id()))
                    .unwrap()
                    .unwrap()
                    .content()
                    .as_bytes(),
                b"body one"
            );
            let replacement = Message::new(
                changed.clone(),
                MessageContent::new(b"body two".to_vec()).unwrap(),
            );
            run(store.put_message(&account(), &replacement)).unwrap();
            assert_eq!(
                run(store.message(&account(), changed.message_id()))
                    .unwrap()
                    .unwrap(),
                replacement
            );
            assert_eq!(
                run(store.list_envelopes(&account(), StoreLimit::new(10).unwrap()))
                    .unwrap()
                    .len(),
                1
            );
        }

        #[test]
        fn reconcile_prunes_in_exact_order_preserves_bodies_and_caches_conditionally() {
            let (_database, store) = open("reconcile");
            record_fence(&store);
            let retained = envelope("retained", "thread", 70);
            let displaced = envelope("displaced", "thread", 40);
            run(store.upsert_envelopes(&account(), &[retained.clone(), displaced.clone()]))
                .unwrap();
            let retained_message = Message::new(
                retained.clone(),
                MessageContent::new(b"retained body".to_vec()).unwrap(),
            );
            run(store.put_message(&account(), &retained_message)).unwrap();

            let input = [
                envelope("old", "thread", 10),
                retained.clone(),
                envelope("tie-b", "thread", 50),
                envelope("tie-a", "thread", 50),
            ];
            let survivors = run(store.reconcile_recent_envelopes(
                &account(),
                &input,
                StoreLimit::new(3).unwrap(),
                &fence(),
            ))
            .unwrap();
            assert_eq!(
                survivors.iter().map(MessageId::as_str).collect::<Vec<_>>(),
                ["retained", "tie-b", "tie-a"]
            );
            assert_eq!(
                run(store.list_envelopes(&account(), StoreLimit::new(10).unwrap()))
                    .unwrap()
                    .iter()
                    .map(|item| item.message_id().as_str())
                    .collect::<Vec<_>>(),
                ["retained", "tie-a", "tie-b"]
            );
            assert_eq!(
                run(store.message(&account(), retained.message_id()))
                    .unwrap()
                    .unwrap(),
                retained_message
            );

            let missing = Message::new(
                envelope("missing", "thread", 60),
                MessageContent::new(b"missing body".to_vec()).unwrap(),
            );
            assert!(!run(store.cache_message_if_present(&account(), &missing, &fence())).unwrap());
            let cached = Message::new(
                envelope("tie-a", "thread", 50),
                MessageContent::new(b"cached body".to_vec()).unwrap(),
            );
            assert!(run(store.cache_message_if_present(&account(), &cached, &fence())).unwrap());
            assert_eq!(
                run(store.message(&account(), cached.envelope().message_id()))
                    .unwrap()
                    .unwrap(),
                cached
            );
            // "retained" and "tie-a" hold bodies; "tie-b" is an envelope only,
            // and "missing" has no row.
            let asked =
                ["tie-b", "retained", "missing", "tie-a"].map(|id| MessageId::new(id).unwrap());
            assert_eq!(
                run(store.uncached_message_ids(&account(), &asked))
                    .unwrap()
                    .iter()
                    .map(MessageId::as_str)
                    .collect::<Vec<_>>(),
                ["tie-b", "missing"]
            );
            assert_eq!(
                run(store.list_envelopes(&account(), StoreLimit::new(10).unwrap()))
                    .unwrap()
                    .len(),
                3
            );
        }

        #[test]
        fn reconcile_rolls_back_on_failpoints_and_remains_exact_after_reopen() {
            let (database, store) = open("reconcile-rollback");
            let initial = envelope("initial", "thread", 10);
            run(store.upsert_envelopes(&account(), std::slice::from_ref(&initial))).unwrap();
            store.fail_next_mutation();
            assert_eq!(
                run(store.reconcile_recent_envelopes(
                    &account(),
                    &[envelope("new", "thread", 20)],
                    StoreLimit::new(1).unwrap(),
                    &fence(),
                )),
                Err(MailboxStoreError::Storage)
            );
            assert_eq!(
                run(store.list_envelopes(&account(), StoreLimit::new(10).unwrap())).unwrap(),
                vec![initial.clone()]
            );
            store.fail_next_mutation();
            assert_eq!(
                run(store.reconcile_recent_envelopes(
                    &account(),
                    &[],
                    StoreLimit::new(1).unwrap(),
                    &fence(),
                )),
                Err(MailboxStoreError::Storage)
            );
            drop(store);
            let reopened = SqlCipherMailboxStore::open(account(), database.path(), key(7)).unwrap();
            assert_eq!(
                run(reopened.list_envelopes(&account(), StoreLimit::new(10).unwrap())).unwrap(),
                vec![initial]
            );
        }

        #[test]
        fn identity_first_record_persists_and_reloads() {
            let (database, store) = open("identity-first-record");
            assert!(run(store.load_identity(&account())).unwrap().is_none());
            let hash = IdentityHash::from_bytes([1; 32]);
            run(store.reconcile_identity(&account(), &hash, IdentityReconcile::RecordOnly, None))
                .unwrap();
            assert_eq!(
                run(store.load_identity(&account())).unwrap(),
                Some(hash.clone())
            );
            drop(store);
            let reopened = SqlCipherMailboxStore::open(account(), database.path(), key(7)).unwrap();
            assert_eq!(run(reopened.load_identity(&account())).unwrap(), Some(hash));
        }

        #[test]
        fn a_stale_algorithm_version_row_reads_corrupted() {
            // A pre-existing v1 (email-scheme) row after the algo bump to v2 must
            // fail closed — never Ok(None) (which would re-baseline as first
            // connect) and never a value comparison (which could false-match).
            let (_database, store) = open("identity-stale-version");
            store
                .write_identity_hash_with_version(&account(), &[1; 32], IDENTITY_ALGO_VERSION - 1)
                .unwrap();
            assert_eq!(
                run(store.load_identity(&account())),
                Err(MailboxStoreError::Corrupted)
            );
        }

        #[test]
        fn identity_mismatch_clears_the_mailbox_but_keeps_the_new_hash() {
            let (database, store) = open("identity-mismatch-clear");
            // First account connects (records its identity on the empty slot), then a
            // snapshot is cached under it — the fence equals the just-recorded hash.
            let first = IdentityHash::from_bytes([1; 32]);
            run(store.reconcile_identity(&account(), &first, IdentityReconcile::RecordOnly, None))
                .unwrap();
            run(store.reconcile_recent_envelopes(
                &account(),
                &[envelope("m1", "thread", 10), envelope("m2", "thread", 20)],
                StoreLimit::new(5).unwrap(),
                &first,
            ))
            .unwrap();
            run(store.record_successful_sync(&account(), 1_000)).unwrap();
            // A different account connects: clear the cached mailbox and record the
            // new hash in one transaction, compare-and-set against the prior identity.
            let second = IdentityHash::from_bytes([2; 32]);
            run(store.reconcile_identity(
                &account(),
                &second,
                IdentityReconcile::ClearMailboxAndRecord,
                Some(&first),
            ))
            .unwrap();
            assert!(
                run(store.list_envelopes(&account(), StoreLimit::new(10).unwrap()))
                    .unwrap()
                    .is_empty()
            );
            // The clear deletes messages; the just-recorded hash must survive it.
            assert_eq!(
                run(store.load_identity(&account())).unwrap(),
                Some(second.clone())
            );
            assert_eq!(
                run(store.lifecycle_metadata(&account()))
                    .unwrap()
                    .last_successful_sync_unix_millis(),
                None
            );
            // The new identity can record freshness only after its own later
            // successful sync.
            run(store.record_successful_sync(&account(), 2_000)).unwrap();
            assert_eq!(
                run(store.lifecycle_metadata(&account()))
                    .unwrap()
                    .last_successful_sync_unix_millis(),
                Some(2_000)
            );
            drop(store);
            let reopened = SqlCipherMailboxStore::open(account(), database.path(), key(7)).unwrap();
            assert!(
                run(reopened.list_envelopes(&account(), StoreLimit::new(10).unwrap()))
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(
                run(reopened.load_identity(&account())).unwrap(),
                Some(second)
            );
            assert_eq!(
                run(reopened.lifecycle_metadata(&account()))
                    .unwrap()
                    .last_successful_sync_unix_millis(),
                Some(2_000)
            );
        }

        #[test]
        fn an_identity_mismatch_clears_the_stored_email_address() {
            // The address belongs to the mailbox's identity: the clear that
            // wipes a replaced identity's mail must not leave the previous
            // account's Gmail address in the binding row for `account list`
            // and the interface to keep showing.
            let (database, store) = open("identity-mismatch-clear-email");
            let first = IdentityHash::from_bytes([1; 32]);
            run(store.reconcile_identity(&account(), &first, IdentityReconcile::RecordOnly, None))
                .unwrap();
            let email = AccountEmail::new("user@example.invalid").unwrap();
            store.store_email_address(&account(), &email).unwrap();
            let second = IdentityHash::from_bytes([2; 32]);
            run(store.reconcile_identity(
                &account(),
                &second,
                IdentityReconcile::ClearMailboxAndRecord,
                Some(&first),
            ))
            .unwrap();
            assert!(store.load_email_address(&account()).unwrap().is_none());
            drop(store);
            let reopened = SqlCipherMailboxStore::open(account(), database.path(), key(7)).unwrap();
            assert!(reopened.load_email_address(&account()).unwrap().is_none());
        }

        #[test]
        fn identity_reconcile_rolls_back_the_clear_and_the_record_together() {
            let (database, store) = open("identity-reconcile-rollback");
            let recorded = IdentityHash::from_bytes([1; 32]);
            run(store.reconcile_identity(
                &account(),
                &recorded,
                IdentityReconcile::RecordOnly,
                None,
            ))
            .unwrap();
            let seeded = envelope("seeded", "thread", 10);
            run(store.reconcile_recent_envelopes(
                &account(),
                std::slice::from_ref(&seeded),
                StoreLimit::new(5).unwrap(),
                &recorded,
            ))
            .unwrap();
            let email = AccountEmail::new("user@example.invalid").unwrap();
            store.store_email_address(&account(), &email).unwrap();
            let replacement = IdentityHash::from_bytes([2; 32]);
            run(store.record_successful_sync(&account(), 1_000)).unwrap();
            // The clear path has four transaction checkpoints: after mailbox
            // deletion, lifecycle freshness clear, binding address clear, and
            // identity record. Each failure must restore all four old-state
            // components together.
            for checkpoint in 1..=4 {
                store.fail_mutation_at(checkpoint);
                assert_eq!(
                    run(store.reconcile_identity(
                        &account(),
                        &replacement,
                        IdentityReconcile::ClearMailboxAndRecord,
                        Some(&recorded),
                    )),
                    Err(MailboxStoreError::Storage)
                );
                assert_eq!(
                    run(store.list_envelopes(&account(), StoreLimit::new(10).unwrap())).unwrap(),
                    vec![seeded.clone()]
                );
                assert_eq!(
                    run(store.load_identity(&account())).unwrap(),
                    Some(recorded.clone())
                );
                assert_eq!(
                    run(store.lifecycle_metadata(&account()))
                        .unwrap()
                        .last_successful_sync_unix_millis(),
                    Some(1_000)
                );
                assert_eq!(
                    store.load_email_address(&account()).unwrap().as_ref(),
                    Some(&email),
                    "the recorded identity's address survives the failed clear"
                );
            }
            drop(store);
            let reopened = SqlCipherMailboxStore::open(account(), database.path(), key(7)).unwrap();
            assert_eq!(
                run(reopened.list_envelopes(&account(), StoreLimit::new(10).unwrap())).unwrap(),
                vec![seeded]
            );
            assert_eq!(
                run(reopened.load_identity(&account())).unwrap(),
                Some(recorded)
            );
            assert_eq!(
                run(reopened.lifecycle_metadata(&account()))
                    .unwrap()
                    .last_successful_sync_unix_millis(),
                Some(1_000)
            );
            assert_eq!(
                reopened.load_email_address(&account()).unwrap().as_ref(),
                Some(&email)
            );
        }

        #[test]
        fn identity_record_only_rolls_back_the_hash_on_failpoint() {
            // A RecordOnly reconcile skips the DELETE, so the single armed
            // failpoint fires at the checkpoint AFTER the UPSERT — proving the
            // record itself rolls back, the boundary the clear-path test cannot
            // reach.
            let (database, store) = open("identity-record-only-rollback");
            store.fail_next_mutation();
            let recorded = IdentityHash::from_bytes([1; 32]);
            assert_eq!(
                run(store.reconcile_identity(
                    &account(),
                    &recorded,
                    IdentityReconcile::RecordOnly,
                    None,
                )),
                Err(MailboxStoreError::Storage)
            );
            assert!(run(store.load_identity(&account())).unwrap().is_none());
            drop(store);
            let reopened = SqlCipherMailboxStore::open(account(), database.path(), key(7)).unwrap();
            assert!(run(reopened.load_identity(&account())).unwrap().is_none());
        }

        #[test]
        fn two_racing_first_connects_leave_exactly_one_accounts_mail_via_compare_and_set() {
            // Cycle A first-connects, records [1;32], caches its mail. Cycle B started
            // from the same empty read, so it still holds a stale first-connect
            // decision; its compare-and-set must lose (the row is now [1;32], not
            // absent). Re-deciding against the new state yields a clear-and-record
            // that wipes A's mail before B writes — so exactly one account's mail ever
            // coexists with the recorded identity. This is the gate's cross-process
            // backstop the whole-cycle permit cannot provide.
            let (_database, store) = open("two-racing-first-connects");
            let a = IdentityHash::from_bytes([1; 32]);
            let b = IdentityHash::from_bytes([2; 32]);
            run(store.reconcile_identity(&account(), &a, IdentityReconcile::RecordOnly, None))
                .unwrap();
            run(store.reconcile_recent_envelopes(
                &account(),
                &[envelope("a-mail", "thread", 10)],
                StoreLimit::new(5).unwrap(),
                &a,
            ))
            .unwrap();
            // Cycle B's stale first-connect loses: the row is no longer absent.
            assert_eq!(
                run(store.reconcile_identity(&account(), &b, IdentityReconcile::RecordOnly, None,)),
                Err(MailboxStoreError::IdentityRaced)
            );
            // A's mail and identity are untouched by the aborted stale write.
            assert_eq!(
                run(store.list_envelopes(&account(), StoreLimit::new(10).unwrap()))
                    .unwrap()
                    .iter()
                    .map(|value| value.message_id().as_str())
                    .collect::<Vec<_>>(),
                ["a-mail"]
            );
            assert_eq!(
                run(store.load_identity(&account())).unwrap(),
                Some(a.clone())
            );
            // B re-decides against the new state (clear-and-record) and only then writes.
            run(store.reconcile_identity(
                &account(),
                &b,
                IdentityReconcile::ClearMailboxAndRecord,
                Some(&a),
            ))
            .unwrap();
            run(store.reconcile_recent_envelopes(
                &account(),
                &[envelope("b-mail", "thread", 20)],
                StoreLimit::new(5).unwrap(),
                &b,
            ))
            .unwrap();
            // Exactly one account's mail survives: A's was cleared, only B's remains.
            assert_eq!(
                run(store.list_envelopes(&account(), StoreLimit::new(10).unwrap()))
                    .unwrap()
                    .iter()
                    .map(|value| value.message_id().as_str())
                    .collect::<Vec<_>>(),
                ["b-mail"]
            );
            assert_eq!(run(store.load_identity(&account())).unwrap(), Some(b));
        }

        #[test]
        fn a_stale_clear_and_record_loses_the_compare_and_set_when_the_prior_hash_moved() {
            // A cycle observed [1;32] and decided clear-and-record, but a concurrent
            // cycle already moved the recorded identity to [2;32]. The stale
            // clear-and-record must abort rather than wipe a mailbox and record over
            // an identity it never observed.
            let (_database, store) = open("stale-clear-loses-cas");
            let recorded = IdentityHash::from_bytes([2; 32]);
            run(store.reconcile_identity(
                &account(),
                &recorded,
                IdentityReconcile::RecordOnly,
                None,
            ))
            .unwrap();
            run(store.reconcile_recent_envelopes(
                &account(),
                &[envelope("kept", "thread", 10)],
                StoreLimit::new(5).unwrap(),
                &recorded,
            ))
            .unwrap();
            let stale_prior = IdentityHash::from_bytes([1; 32]);
            let fresh = IdentityHash::from_bytes([3; 32]);
            assert_eq!(
                run(store.reconcile_identity(
                    &account(),
                    &fresh,
                    IdentityReconcile::ClearMailboxAndRecord,
                    Some(&stale_prior),
                )),
                Err(MailboxStoreError::IdentityRaced)
            );
            // Neither the clear nor the record took effect.
            assert_eq!(
                run(store.list_envelopes(&account(), StoreLimit::new(10).unwrap()))
                    .unwrap()
                    .len(),
                1
            );
            assert_eq!(
                run(store.load_identity(&account())).unwrap(),
                Some(recorded)
            );
        }

        #[test]
        fn a_reconcile_aborts_and_rolls_back_when_the_recorded_identity_moved_past_the_fence() {
            // Models an identity change between the gate (which produced the fence)
            // and this commit: the recorded identity no longer matches the fence the
            // stale cycle carries, so the envelope write must roll back rather than
            // land under a different account's mailbox.
            let (_database, store) = open("reconcile-stale-fence");
            let changed = IdentityHash::from_bytes([7; 32]);
            run(store.reconcile_identity(
                &account(),
                &changed,
                IdentityReconcile::RecordOnly,
                None,
            ))
            .unwrap();
            assert_eq!(
                run(store.reconcile_recent_envelopes(
                    &account(),
                    &[envelope("stale", "thread", 10)],
                    StoreLimit::new(3).unwrap(),
                    &fence(),
                )),
                Err(MailboxStoreError::IdentityChanged)
            );
            // Nothing persisted, and the recorded identity itself is untouched.
            assert!(
                run(store.list_envelopes(&account(), StoreLimit::new(10).unwrap()))
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(run(store.load_identity(&account())).unwrap(), Some(changed));
        }

        #[test]
        fn a_reconcile_aborts_and_rolls_back_when_the_identity_row_is_absent() {
            // No recorded identity at all is treated as "changed", never as a silent
            // first-connect re-baseline — the write fails closed.
            let (_database, store) = open("reconcile-absent-identity");
            assert_eq!(
                run(store.reconcile_recent_envelopes(
                    &account(),
                    &[envelope("orphan", "thread", 10)],
                    StoreLimit::new(3).unwrap(),
                    &fence(),
                )),
                Err(MailboxStoreError::IdentityChanged)
            );
            assert!(
                run(store.list_envelopes(&account(), StoreLimit::new(10).unwrap()))
                    .unwrap()
                    .is_empty()
            );
        }

        #[test]
        fn a_body_cache_carrying_a_stale_fence_aborts_and_leaves_the_envelope_bodyless() {
            // The body write is fenced too: `messages` is keyed by message_id alone,
            // and Gmail IDs are not distinct across accounts, so a stale body-fetch
            // must not overwrite a colliding row once the identity has moved on.
            let (_database, store) = open("cache-stale-fence");
            let present = envelope("present", "thread", 20);
            run(store.upsert_envelopes(&account(), std::slice::from_ref(&present))).unwrap();
            let changed = IdentityHash::from_bytes([7; 32]);
            run(store.reconcile_identity(
                &account(),
                &changed,
                IdentityReconcile::RecordOnly,
                None,
            ))
            .unwrap();
            let body = Message::new(
                present.clone(),
                MessageContent::new(b"secret body".to_vec()).unwrap(),
            );
            assert_eq!(
                run(store.cache_message_if_present(&account(), &body, &fence())),
                Err(MailboxStoreError::IdentityChanged)
            );
            // The body write rolled back: the envelope remains bodyless.
            assert!(
                run(store.message(&account(), present.message_id()))
                    .unwrap()
                    .is_none()
            );
        }

        #[test]
        fn conditional_cache_rolls_back_and_never_reinserts_a_missing_row() {
            let (database, store) = open("conditional-cache-rollback");
            let present = envelope("present", "thread", 20);
            run(store.upsert_envelopes(&account(), std::slice::from_ref(&present))).unwrap();
            let body = Message::new(
                present.clone(),
                MessageContent::new(b"sensitive body".to_vec()).unwrap(),
            );
            store.fail_next_mutation();
            assert_eq!(
                run(store.cache_message_if_present(&account(), &body, &fence())),
                Err(MailboxStoreError::Storage)
            );
            drop(store);

            let reopened = SqlCipherMailboxStore::open(account(), database.path(), key(7)).unwrap();
            record_fence(&reopened);
            assert!(
                run(reopened.message(&account(), present.message_id()))
                    .unwrap()
                    .is_none()
            );
            run(reopened.reconcile_recent_envelopes(
                &account(),
                &[envelope("newer", "thread", 30)],
                StoreLimit::new(1).unwrap(),
                &fence(),
            ))
            .unwrap();
            assert!(!run(reopened.cache_message_if_present(&account(), &body, &fence())).unwrap());
            assert_eq!(
                run(reopened.list_envelopes(&account(), StoreLimit::new(10).unwrap()))
                    .unwrap()
                    .iter()
                    .map(|value| value.message_id().as_str())
                    .collect::<Vec<_>>(),
                ["newer"]
            );
        }

        #[test]
        fn reconcile_rejects_a_null_primary_key_without_mutating_the_database() {
            let (_database, store) = open("null-primary-key");
            store
                .connection
                .lock()
                .unwrap()
                .execute(
                    "INSERT INTO messages (message_id, thread_id, sender, subject, preview, received_at, unread, content) VALUES (NULL, 'thread', 'sender', 'subject', 'preview', 50, 0, NULL)",
                    [],
                )
                .unwrap();

            assert_eq!(
                run(store.reconcile_recent_envelopes(
                    &account(),
                    &[envelope("new", "thread", 100)],
                    StoreLimit::new(1).unwrap(),
                    &fence(),
                )),
                Err(MailboxStoreError::Corrupted)
            );
            let (row_count, inserted_count): (i64, i64) = store
                .connection
                .lock()
                .unwrap()
                .query_row(
                    "SELECT COUNT(*), COUNT(CASE WHEN message_id = 'new' THEN 1 END) FROM messages",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            assert_eq!(row_count, 1);
            assert_eq!(inserted_count, 0);
        }

        #[test]
        fn ordering_limits_rollback_and_unpolled_cancellation_are_exact() {
            let (_database, store) = open("order");
            let values = [
                envelope("b", "thread", 10),
                envelope("a", "thread", 10),
                envelope("c", "other", 20),
            ];
            let local_account = account();
            let cancelled = store.upsert_envelopes(&local_account, &values);
            drop(cancelled);
            assert!(
                run(store.list_envelopes(&account(), StoreLimit::new(10).unwrap()))
                    .unwrap()
                    .is_empty()
            );
            run(store.upsert_envelopes(&account(), &values)).unwrap();
            let listed =
                run(store.list_envelopes(&account(), StoreLimit::new(2).unwrap())).unwrap();
            assert_eq!(
                listed
                    .iter()
                    .map(|value| value.message_id().as_str())
                    .collect::<Vec<_>>(),
                vec!["c", "a"]
            );
            let threaded = run(store.thread_envelopes(
                &account(),
                values[0].thread_id(),
                StoreLimit::new(2).unwrap(),
            ))
            .unwrap();
            assert_eq!(
                threaded
                    .iter()
                    .map(|value| value.message_id().as_str())
                    .collect::<Vec<_>>(),
                vec!["a", "b"]
            );
            run(store.upsert_envelopes(
                &account(),
                &[
                    envelope("early", "thread", 5),
                    envelope("older", "other", 1),
                ],
            ))
            .unwrap();
            let threaded = run(store.thread_envelopes(
                &account(),
                values[0].thread_id(),
                StoreLimit::new(2).unwrap(),
            ))
            .unwrap();
            assert_eq!(
                threaded
                    .iter()
                    .map(|value| value.message_id().as_str())
                    .collect::<Vec<_>>(),
                vec!["early", "a"],
                "a thread lists only its rows, oldest first, and the limit drops the newest"
            );
            store.fail_next_mutation();
            assert_eq!(
                run(store
                    .upsert_envelopes(&account(), &[envelope("d", "t", 1), envelope("e", "t", 2)])),
                Err(MailboxStoreError::Storage)
            );
            assert!(
                run(store.message(&account(), &MessageId::new("d").unwrap()))
                    .unwrap()
                    .is_none()
            );
            assert!(
                run(store.message(&account(), &MessageId::new("e").unwrap()))
                    .unwrap()
                    .is_none()
            );
            assert_eq!(
                run(store.list_envelopes(&account(), StoreLimit::new(10).unwrap()))
                    .unwrap()
                    .len(),
                5
            );
        }

        #[test]
        fn account_binding_and_method_mismatch_fail_closed_without_database_work() {
            let (database, store) = open("mismatch");
            let foreign = AccountId::new("account-b").unwrap();
            let changes_before = store.connection.lock().unwrap().total_changes();
            let error =
                run(store.list_envelopes(&foreign, StoreLimit::new(1).unwrap())).unwrap_err();
            assert_eq!(error, MailboxStoreError::Storage);
            assert_eq!(
                store.connection.lock().unwrap().total_changes(),
                changes_before
            );
            assert!(!format!("{store:?}").contains("account-a"));
            assert!(!error.to_string().contains("account-a"));
            drop(store);
            assert_corrupted(SqlCipherMailboxStore::open(
                foreign,
                database.path(),
                key(7),
            ));
        }

        /// Counts the rows of one table through the store's own connection, for
        /// purge assertions.
        fn row_count(store: &SqlCipherMailboxStore, table: &str) -> i64 {
            store
                .connection
                .lock()
                .unwrap()
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap()
        }

        #[test]
        fn purge_clears_the_mailbox_and_identity_and_keeps_the_binding() {
            let (database, store) = open("purge");
            record_fence(&store);
            run(store.upsert_envelopes(
                &account(),
                &[envelope("m1", "t1", 100), envelope("m2", "t1", 200)],
            ))
            .unwrap();
            assert_eq!(row_count(&store, "messages"), 2);
            assert_eq!(row_count(&store, "account_identity"), 1);

            run(store.purge_account(&account())).unwrap();

            // The mailbox rows AND the identity row die in the one purge...
            assert_eq!(row_count(&store, "messages"), 0);
            assert_eq!(row_count(&store, "account_identity"), 0);
            // ...but the account_binding singleton survives: the file stays
            // bound to its account, so a re-connect passes the open-time
            // binding check instead of reading as an unknown owner.
            assert_eq!(row_count(&store, "account_binding"), 1);
            // The teardown is idempotent: a second purge is a no-op success.
            run(store.purge_account(&account())).unwrap();
            drop(store);
            // A clean re-connect: the store reopens under the same account and
            // reads as a first connect (no identity recorded).
            let reopened = SqlCipherMailboxStore::open(account(), database.path(), key(7)).unwrap();
            assert!(reopened.read_identity_hash(&account()).unwrap().is_none());
        }

        #[test]
        fn broker_subject_round_trips_and_survives_reopen() {
            let (database, store) = open("broker-subject-round-trip");
            store
                .store_broker_subject(&account(), "google-subject-123")
                .unwrap();
            assert_eq!(
                store
                    .load_broker_subject(&account())
                    .unwrap()
                    .map(|subject| subject.to_string()),
                Some("google-subject-123".to_string())
            );
            drop(store);

            let reopened = SqlCipherMailboxStore::open(account(), database.path(), key(7)).unwrap();
            assert_eq!(
                reopened
                    .load_broker_subject(&account())
                    .unwrap()
                    .map(|subject| subject.to_string()),
                Some("google-subject-123".to_string())
            );
        }

        /// Builds a shipped version-1 store: the 0001 migration, the binding
        /// row, the ownership marker, and `user_version` 1, in WAL mode as
        /// every shipped open leaves it. Two messages are committed before any
        /// upgrade — one with a cached body, one envelope-only — and never
        /// checkpointed: the WAL grows, so the upgrade tests prove mail that
        /// lives only in the WAL survives. The returned connection stays open
        /// holding the WAL and its shared-memory index, like the process that
        /// owns the store while another one opens it.
        fn version_1_store(name: &str) -> (TestDatabase, Connection) {
            let database = TestDatabase::new(name);
            let connection = raw_connection(&database);
            apply_key(&connection, &key(7).0).unwrap();
            connection.execute_batch(MIGRATION).unwrap();
            connection
                .execute(
                    "INSERT INTO account_binding (singleton, account_id) VALUES (1, ?1)",
                    rusqlite::params![account().as_str()],
                )
                .unwrap();
            connection
                .pragma_update(None, "application_id", APPLICATION_ID)
                .unwrap();
            connection
                .pragma_update(None, "user_version", SCHEMA_VERSION_1)
                .unwrap();
            connection
                .execute_batch("PRAGMA journal_mode = WAL;")
                .unwrap();
            // Pre-upgrade mail, committed into the WAL and never checkpointed.
            let wal_before_mail = fs::metadata(wal_path(&database))
                .map(|metadata| metadata.len())
                .unwrap_or(0);
            let mail = [
                ("m1", 20, Some(b"cached body".as_slice())),
                ("m0", 10, None),
            ];
            for (id, received_at, content) in mail {
                connection
                    .execute(
                        "INSERT INTO messages (message_id, thread_id, sender, subject, preview, received_at, unread, content) VALUES (?1, 'thread', 'from', 'subject', 'preview', ?2, 1, ?3)",
                        rusqlite::params![id, received_at, content],
                    )
                    .unwrap();
            }
            assert!(
                fs::metadata(wal_path(&database)).unwrap().len() > wal_before_mail,
                "the pre-upgrade mail is committed into the WAL, not the main file"
            );
            // The ownership modes every shipped open leaves, which both open
            // paths require of pre-existing leaves.
            fs::set_permissions(wal_path(&database), fs::Permissions::from_mode(0o600)).unwrap();
            fs::set_permissions(shm_path(&database), fs::Permissions::from_mode(0o600)).unwrap();
            (database, connection)
        }

        #[test]
        fn a_version_one_store_upgrades_on_a_writable_open() {
            let (database, anchor) = version_1_store("version-one-upgrade");
            {
                let connection = raw_existing_connection(&database);
                apply_key(&connection, &key(7).0).unwrap();
                connection
                    .execute(
                        "UPDATE account_binding SET broker_subject = ?1, refresh_token = ?2 WHERE singleton = 1",
                        rusqlite::params!["google-subject-123", "refresh-token-xyz"],
                    )
                    .unwrap();
            }
            let store = SqlCipherMailboxStore::open(account(), database.path(), key(7)).unwrap();
            let (application_id, user_version, objects) = schema_state(&store);
            assert_eq!((application_id, user_version), (APPLICATION_ID, VERSION));
            assert_eq!(objects, canonical_schema());
            assert_eq!(
                store
                    .load_broker_subject(&account())
                    .unwrap()
                    .map(|subject| subject.to_string()),
                Some("google-subject-123".to_string())
            );
            assert_eq!(
                store
                    .load_refresh_token(&account())
                    .unwrap()
                    .map(|token| token.to_string()),
                Some("refresh-token-xyz".to_string())
            );
            assert!(store.load_email_address(&account()).unwrap().is_none());
            // Every message written before the upgrade survives it, the last
            // of them still only in the WAL, envelope and cached content
            // alike.
            assert_eq!(
                run(store.list_envelopes(&account(), StoreLimit::new(10).unwrap())).unwrap(),
                vec![envelope("m1", "thread", 20), envelope("m0", "thread", 10)]
            );
            assert_eq!(
                run(store.message(&account(), &MessageId::new("m1").unwrap()))
                    .unwrap()
                    .unwrap()
                    .content()
                    .as_bytes(),
                b"cached body"
            );
            assert!(
                run(store.message(&account(), &MessageId::new("m0").unwrap()))
                    .unwrap()
                    .is_none(),
                "the envelope-only row stays envelope-only"
            );
            let email = AccountEmail::new("user@example.invalid").unwrap();
            store.store_email_address(&account(), &email).unwrap();
            drop(store);
            drop(anchor);
            let reopened = SqlCipherMailboxStore::open(account(), database.path(), key(7)).unwrap();
            assert_eq!(
                reopened.load_email_address(&account()).unwrap().as_ref(),
                Some(&email)
            );
            assert_eq!(
                run(reopened.list_envelopes(&account(), StoreLimit::new(10).unwrap()))
                    .unwrap()
                    .iter()
                    .map(|value| value.message_id().as_str())
                    .collect::<Vec<_>>(),
                ["m1", "m0"]
            );
        }

        #[test]
        fn a_version_one_store_opens_read_only_and_stays_version_one() {
            let (database, anchor) = version_1_store("version-one-read-only");
            let reader =
                SqlCipherMailboxReader::open_read_only(account(), database.path(), key(7)).unwrap();
            // The reader holds the sidecars now, so the writer connection can
            // go, and the pre-upgrade mail stays readable on version 1.
            drop(anchor);
            assert_eq!(
                run(reader.list_envelopes(&account(), StoreLimit::new(10).unwrap()))
                    .unwrap()
                    .iter()
                    .map(|value| value.message_id().as_str())
                    .collect::<Vec<_>>(),
                ["m1", "m0"]
            );
            drop(reader);
            let connection = raw_existing_connection(&database);
            apply_key(&connection, &key(7).0).unwrap();
            let version: i64 = connection
                .query_row("PRAGMA user_version", [], |row| row.get(0))
                .unwrap();
            assert_eq!(version, SCHEMA_VERSION_1);
        }

        #[test]
        fn a_read_only_reader_keeps_reading_through_a_writable_upgrade() {
            // SQLite's WAL locking admits one writer alongside any number of
            // readers: the upgrade's BEGIN IMMEDIATE excludes only other
            // writers, and a reader's shared-memory read marks merely limit
            // checkpoints, which the open path never runs. So the upgrade
            // succeeds with the reader held open (only a second WRITER would
            // block it into the busy timeout and fail closed as storage), the
            // reader keeps reading its mail either way, and a fresh open sees
            // the upgraded store.
            let (database, anchor) = version_1_store("version-one-reader-upgrade");
            let reader =
                SqlCipherMailboxReader::open_read_only(account(), database.path(), key(7)).unwrap();
            // The reader holds the sidecars now, so the writer connection can
            // go.
            drop(anchor);
            assert_eq!(
                run(reader.list_envelopes(&account(), StoreLimit::new(10).unwrap()))
                    .unwrap()
                    .iter()
                    .map(|value| value.message_id().as_str())
                    .collect::<Vec<_>>(),
                ["m1", "m0"]
            );
            let store = SqlCipherMailboxStore::open(account(), database.path(), key(7)).unwrap();
            assert_eq!(
                schema_state(&store),
                (APPLICATION_ID, VERSION, canonical_schema())
            );
            assert_eq!(
                run(reader.list_envelopes(&account(), StoreLimit::new(10).unwrap()))
                    .unwrap()
                    .iter()
                    .map(|value| value.message_id().as_str())
                    .collect::<Vec<_>>(),
                ["m1", "m0"],
                "the held reader still reads its mail"
            );
            drop(reader);
            drop(store);
            let reopened =
                SqlCipherMailboxReader::open_read_only(account(), database.path(), key(7)).unwrap();
            let version: i64 = reopened
                .connection
                .lock()
                .unwrap()
                .query_row("PRAGMA user_version", [], |row| row.get(0))
                .unwrap();
            assert_eq!(version, VERSION);
            assert_eq!(
                run(reopened.list_envelopes(&account(), StoreLimit::new(10).unwrap()))
                    .unwrap()
                    .iter()
                    .map(|value| value.message_id().as_str())
                    .collect::<Vec<_>>(),
                ["m1", "m0"]
            );
        }

        #[test]
        fn account_email_round_trips_survives_reopen_and_purge() {
            let (database, store) = open("account-email-round-trip");
            let email = AccountEmail::new("user@example.invalid").unwrap();
            store.store_email_address(&account(), &email).unwrap();
            assert_eq!(
                store.load_email_address(&account()).unwrap().as_ref(),
                Some(&email)
            );
            drop(store);
            let reopened = SqlCipherMailboxStore::open(account(), database.path(), key(7)).unwrap();
            assert_eq!(
                reopened.load_email_address(&account()).unwrap().as_ref(),
                Some(&email)
            );
            run(reopened.purge_account(&account())).unwrap();
            assert_eq!(
                reopened.load_email_address(&account()).unwrap().as_ref(),
                Some(&email)
            );
            assert!(reopened.load_broker_subject(&account()).unwrap().is_none());
        }

        #[test]
        fn account_email_rejects_out_of_bound_direct_storage() {
            let (_database, store) = open("account-email-check");
            {
                let connection = store.connection.lock().unwrap();
                let invalid = "a".repeat(AccountEmail::MAX_LEN + 1);
                assert!(matches!(
                    connection.execute(
                        "UPDATE account_binding SET email_address = ?1 WHERE singleton = 1",
                        rusqlite::params![invalid],
                    ),
                    Err(rusqlite::Error::SqliteFailure(_, _))
                ));
            }
            assert!(store.load_email_address(&account()).unwrap().is_none());
        }

        #[test]
        fn account_email_rejects_invalid_text_storage() {
            let (_database, store) = open("account-email-corrupt");
            {
                let connection = store.connection.lock().unwrap();
                connection
                    .execute(
                        "UPDATE account_binding SET email_address = ?1 WHERE singleton = 1",
                        rusqlite::params!["not-an-address"],
                    )
                    .unwrap();
            }
            assert_eq!(
                store.load_email_address(&account()),
                Err(MailboxStoreError::Corrupted)
            );
        }

        #[test]
        fn fresh_stores_create_the_version_two_schema_with_no_email() {
            let (_database, store) = open("fresh-version-two");
            let (application_id, user_version, objects) = schema_state(&store);
            assert_eq!((application_id, user_version), (APPLICATION_ID, VERSION));
            assert_eq!(objects, canonical_schema());
            assert!(store.load_email_address(&account()).unwrap().is_none());
        }

        #[test]
        fn refresh_token_round_trips_clears_and_survives_reopen() {
            let (database, store) = open("refresh-token-round-trip");
            assert!(store.load_refresh_token(&account()).unwrap().is_none());
            store
                .store_refresh_token(&account(), "1//refresh-token-value")
                .unwrap();
            drop(store);

            let reopened = SqlCipherMailboxStore::open(account(), database.path(), key(7)).unwrap();
            assert_eq!(
                reopened
                    .load_refresh_token(&account())
                    .unwrap()
                    .map(|token| token.to_string()),
                Some("1//refresh-token-value".to_string())
            );
            reopened.clear_refresh_token(&account()).unwrap();
            assert!(reopened.load_refresh_token(&account()).unwrap().is_none());
        }

        #[test]
        fn refresh_token_rejects_bad_shapes_and_foreign_accounts() {
            let (_database, store) = open("refresh-token-shape");
            for bad in ["", "has space", "line\nbreak", &"x".repeat(4097)] {
                assert!(matches!(
                    store.store_refresh_token(&account(), bad),
                    Err(MailboxStoreError::Storage)
                ));
            }
            let foreign = AccountId::new("account-b").unwrap();
            assert!(matches!(
                store.store_refresh_token(&foreign, "token"),
                Err(MailboxStoreError::Storage)
            ));
            assert!(matches!(
                store.load_refresh_token(&foreign),
                Err(MailboxStoreError::Storage)
            ));
        }

        #[test]
        fn purge_clears_the_refresh_token() {
            let (_database, store) = open("refresh-token-purge");
            store.store_refresh_token(&account(), "token").unwrap();
            run(AccountPurgeStore::purge_account(&store, &account())).unwrap();
            assert!(store.load_refresh_token(&account()).unwrap().is_none());
        }

        #[test]
        fn broker_subject_rejects_wrong_account_without_database_work() {
            let (_database, store) = open("broker-subject-mismatch");
            store
                .store_broker_subject(&account(), "google-subject-123")
                .unwrap();
            let foreign = AccountId::new("account-b").unwrap();
            let changes_before = store.connection.lock().unwrap().total_changes();

            assert!(matches!(
                store.store_broker_subject(&foreign, "google-subject-123"),
                Err(MailboxStoreError::Storage)
            ));
            assert!(matches!(
                store.load_broker_subject(&foreign),
                Err(MailboxStoreError::Storage)
            ));

            assert_eq!(
                store.connection.lock().unwrap().total_changes(),
                changes_before,
                "a wrong-account broker subject operation must not mutate the database"
            );
            assert_eq!(
                store
                    .load_broker_subject(&account())
                    .unwrap()
                    .map(|subject| subject.to_string()),
                Some("google-subject-123".to_string())
            );
        }

        #[test]
        fn broker_subject_rejects_non_text_storage() {
            let (_database, store) = open("broker-subject-non-text");
            store
                .connection
                .lock()
                .unwrap()
                .execute(
                    "UPDATE account_binding SET broker_subject = X'00' WHERE singleton = 1",
                    [],
                )
                .unwrap();

            assert!(matches!(
                store.load_broker_subject(&account()),
                Err(MailboxStoreError::Corrupted)
            ));
        }

        #[test]
        fn broker_subject_rejects_invalid_text_storage() {
            let (_database, store) = open("broker-subject-invalid-text");
            let invalid_subjects = [
                String::new(),
                "a".repeat(256),
                "contains space".to_string(),
                "contains\nnewline".to_string(),
                "é".to_string(),
            ];

            for invalid in invalid_subjects {
                let connection = store.connection.lock().unwrap();
                connection
                    .execute_batch("PRAGMA ignore_check_constraints = ON;")
                    .unwrap();
                connection
                    .execute(
                        "UPDATE account_binding SET broker_subject = ?1 WHERE singleton = 1",
                        params![invalid],
                    )
                    .unwrap();
                connection
                    .execute_batch("PRAGMA ignore_check_constraints = OFF;")
                    .unwrap();
                drop(connection);

                assert!(matches!(
                    store.load_broker_subject(&account()),
                    Err(MailboxStoreError::Corrupted)
                ));
            }
        }

        #[test]
        fn purge_clears_broker_subject_and_keeps_binding() {
            let (_database, store) = open("purge-broker-subject");
            store
                .store_broker_subject(&account(), "google-subject-123")
                .unwrap();
            run(store.purge_account(&account())).unwrap();
            assert!(store.load_broker_subject(&account()).unwrap().is_none());
            // The binding singleton itself survives the purge: only the broker
            // routing subject on it is cleared.
            assert_eq!(row_count(&store, "account_binding"), 1);
        }

        #[test]
        fn lifecycle_recovery_transitions_survive_reopen_and_purge_preserves_marker() {
            let (database, store) = open("lifecycle-recovery");
            assert_eq!(
                run(store.lifecycle_metadata(&account())).unwrap(),
                AccountLifecycleMetadata::default()
            );
            run(store.mark_disconnect_started(&account())).unwrap();
            assert_eq!(
                run(store.lifecycle_metadata(&account()))
                    .unwrap()
                    .recovery(),
                Some(DisconnectRecoveryState::IncompleteTeardown)
            );
            drop(store);

            let reopened = SqlCipherMailboxStore::open(account(), database.path(), key(7)).unwrap();
            assert_eq!(
                run(reopened.lifecycle_metadata(&account()))
                    .unwrap()
                    .recovery(),
                Some(DisconnectRecoveryState::IncompleteTeardown),
                "a crash/relaunch must retain the incomplete-teardown fence"
            );
            run(reopened.mark_revoke_unconfirmed(&account())).unwrap();
            run(reopened.purge_account(&account())).unwrap();
            assert_eq!(
                run(reopened.lifecycle_metadata(&account()))
                    .unwrap()
                    .recovery(),
                Some(DisconnectRecoveryState::RevokeUnconfirmed)
            );
            run(reopened.clear_disconnect_recovery(&account())).unwrap();
            assert_eq!(
                run(reopened.lifecycle_metadata(&account()))
                    .unwrap()
                    .recovery(),
                None
            );
        }

        #[test]
        fn lifecycle_freshness_updates_only_on_success_and_purge_clears_it() {
            let (database, store) = open("lifecycle-freshness");
            run(store.record_successful_sync(&account(), 1_000)).unwrap();
            assert_eq!(
                run(store.lifecycle_metadata(&account()))
                    .unwrap()
                    .last_successful_sync_unix_millis(),
                Some(1_000)
            );
            // A failed sync does not invoke record_successful_sync; its prior
            // confirmed freshness remains available for offline presentation.
            assert_eq!(
                run(store.lifecycle_metadata(&account()))
                    .unwrap()
                    .last_successful_sync_unix_millis(),
                Some(1_000)
            );
            drop(store);
            let reopened = SqlCipherMailboxStore::open(account(), database.path(), key(7)).unwrap();
            assert_eq!(
                run(reopened.lifecycle_metadata(&account()))
                    .unwrap()
                    .last_successful_sync_unix_millis(),
                Some(1_000)
            );
            run(reopened.record_successful_sync(&account(), 3_000)).unwrap();
            run(reopened.purge_account(&account())).unwrap();
            assert_eq!(
                run(reopened.lifecycle_metadata(&account()))
                    .unwrap()
                    .last_successful_sync_unix_millis(),
                None
            );
        }

        #[test]
        fn lifecycle_rejects_a_negative_freshness_timestamp() {
            let (_database, store) = open("lifecycle-negative-freshness");
            assert_eq!(
                run(store.record_successful_sync(&account(), -1)),
                Err(MailboxStoreError::Corrupted)
            );
            assert_eq!(
                run(store.lifecycle_metadata(&account()))
                    .unwrap()
                    .last_successful_sync_unix_millis(),
                None
            );
        }

        #[test]
        fn lifecycle_rejects_injected_non_null_recovery_corruption() {
            let (_database, store) = open("lifecycle-recovery-corruption");
            let connection = store.connection.lock().unwrap();
            connection
                .execute_batch("PRAGMA ignore_check_constraints = ON;")
                .unwrap();
            connection
                .execute(
                    "INSERT INTO account_lifecycle (singleton, disconnect_recovery, last_successful_sync_unix_millis) VALUES (1, 99, NULL)",
                    [],
                )
                .unwrap();
            connection
                .execute_batch("PRAGMA ignore_check_constraints = OFF;")
                .unwrap();
            drop(connection);
            assert_eq!(
                run(store.lifecycle_metadata(&account())),
                Err(MailboxStoreError::Corrupted)
            );

            let (_database, typed_store) = open("lifecycle-recovery-type-corruption");
            let connection = typed_store.connection.lock().unwrap();
            connection
                .execute_batch("PRAGMA ignore_check_constraints = ON;")
                .unwrap();
            connection
                .execute(
                    "INSERT INTO account_lifecycle (singleton, disconnect_recovery, last_successful_sync_unix_millis) VALUES (1, 'invalid', NULL)",
                    [],
                )
                .unwrap();
            connection
                .execute_batch("PRAGMA ignore_check_constraints = OFF;")
                .unwrap();
            drop(connection);
            assert_eq!(
                run(typed_store.lifecycle_metadata(&account())),
                Err(MailboxStoreError::Corrupted)
            );

            let (_database, freshness_store) = open("lifecycle-freshness-type-corruption");
            let connection = freshness_store.connection.lock().unwrap();
            connection
                .execute_batch("PRAGMA ignore_check_constraints = ON;")
                .unwrap();
            connection
                .execute(
                    "INSERT INTO account_lifecycle (singleton, disconnect_recovery, last_successful_sync_unix_millis) VALUES (1, NULL, 'invalid')",
                    [],
                )
                .unwrap();
            connection
                .execute_batch("PRAGMA ignore_check_constraints = OFF;")
                .unwrap();
            drop(connection);
            assert_eq!(
                run(freshness_store.lifecycle_metadata(&account())),
                Err(MailboxStoreError::Corrupted)
            );
        }

        #[test]
        fn purge_rolls_back_atomically_on_a_failpoint() {
            let (_database, store) = open("purge-rollback");
            record_fence(&store);
            run(store.upsert_envelopes(&account(), &[envelope("m1", "t1", 100)])).unwrap();
            store
                .store_broker_subject(&account(), "google-subject-123")
                .unwrap();
            store.fail_next_mutation();
            assert_eq!(
                run(store.purge_account(&account())),
                Err(MailboxStoreError::Storage)
            );
            // Messages, identity, and the broker subject roll back together: a
            // mid-purge fault never leaves a half-torn-down account (mailbox
            // cleared but identity or broker subject kept, or the reverse).
            assert_eq!(row_count(&store, "messages"), 1);
            assert_eq!(row_count(&store, "account_identity"), 1);
            assert_eq!(row_count(&store, "account_binding"), 1);
            assert_eq!(
                store
                    .load_broker_subject(&account())
                    .unwrap()
                    .map(|subject| subject.to_string()),
                Some("google-subject-123".to_string())
            );
        }

        #[test]
        fn purge_rejects_a_wrong_account_without_database_work() {
            let (_database, store) = open("purge-mismatch");
            record_fence(&store);
            let foreign = AccountId::new("account-b").unwrap();
            let changes_before = store.connection.lock().unwrap().total_changes();
            assert_eq!(
                run(store.purge_account(&foreign)),
                Err(MailboxStoreError::Storage)
            );
            assert_eq!(
                store.connection.lock().unwrap().total_changes(),
                changes_before,
                "a wrong-account purge must not mutate the database"
            );
        }

        #[test]
        fn open_existing_on_an_absent_database_is_none_and_creates_nothing() {
            let database = TestDatabase::new("open-existing-absent");
            let opened =
                SqlCipherMailboxStore::open_existing(account(), database.path(), key(7)).unwrap();
            assert!(
                opened.is_none(),
                "an absent database is a no-op success for the disconnect purge"
            );
            assert!(
                database.files().is_empty(),
                "disconnect must never create artifacts for a never-connected account"
            );
        }

        #[test]
        fn open_existing_on_a_present_database_opens_it() {
            let database = TestDatabase::new("open-existing-present");
            let store = SqlCipherMailboxStore::open(account(), database.path(), key(7)).unwrap();
            drop(store);
            let opened =
                SqlCipherMailboxStore::open_existing(account(), database.path(), key(7)).unwrap();
            assert!(opened.is_some(), "a present database opens for the purge");
        }

        #[test]
        fn invalid_stored_values_are_corruption_without_large_body_allocation() {
            let (_database, store) = open("corrupt-row");
            let value = envelope("m1", "thread", 1);
            run(store.upsert_envelopes(&account(), std::slice::from_ref(&value))).unwrap();
            store
                .connection
                .lock()
                .unwrap()
                .execute(
                    "UPDATE messages SET subject = ?1, content = CAST(?2 AS TEXT) WHERE message_id = ?3",
                    params!["x".repeat(1_025), "not-a-blob", value.message_id().as_str()],
                )
                .unwrap();
            assert_eq!(
                run(store.list_envelopes(&account(), StoreLimit::new(10).unwrap())),
                Err(MailboxStoreError::Corrupted)
            );
            store
                .connection
                .lock()
                .unwrap()
                .execute(
                    "UPDATE messages SET subject = ?1 WHERE message_id = ?2",
                    params!["valid", value.message_id().as_str()],
                )
                .unwrap();
            assert_eq!(
                run(store.message(&account(), value.message_id())),
                Err(MailboxStoreError::Corrupted)
            );
        }

        #[test]
        fn encrypted_database_and_sidecars_contain_no_plaintext_sentinel() {
            let database = TestDatabase::new("plaintext-control");
            let secret_account = AccountId::new("account-plaintext-sentinel").unwrap();
            let store =
                SqlCipherMailboxStore::open(secret_account.clone(), database.path(), key(17))
                    .unwrap();
            let value = Message::new(
                MessageEnvelope::new(
                    MessageId::new("message-plaintext-sentinel").unwrap(),
                    ThreadId::new("thread-plaintext-sentinel").unwrap(),
                    HeaderText::new("from-plaintext-sentinel").unwrap(),
                    HeaderText::new("subject-plaintext-sentinel").unwrap(),
                    HeaderText::new("preview-plaintext-sentinel").unwrap(),
                    UnixTimestampMillis::new(1).unwrap(),
                    true,
                ),
                MessageContent::new(b"body-plaintext-sentinel".to_vec()).unwrap(),
            );
            run(store.put_message(&secret_account, &value)).unwrap();
            store
                .connection
                .lock()
                .unwrap()
                .execute_batch("PRAGMA wal_checkpoint(FULL);")
                .unwrap();
            let files = database.files();
            assert!(!files.is_empty());
            for path in files {
                let bytes = fs::read(path).unwrap();
                assert!(!contains_bytes(&bytes, b"plaintext-sentinel"));
            }
            let key_debug = format!("{:?}", key(17));
            let store_debug = format!("{store:?}");
            assert!(!key_debug.contains("17"));
            assert!(!store_debug.contains("plaintext"));
        }

        #[test]
        fn persistent_writer_supports_a_clean_standalone_metadata_reader() {
            let (database, store) = open("standalone-reader");
            let values = [envelope("new", "thread", 20), envelope("old", "thread", 10)];
            run(store.upsert_envelopes(&account(), &values)).unwrap();
            let mut persistent_wal = -1;
            persistent_wal_control(&store.connection.lock().unwrap(), &mut persistent_wal).unwrap();
            assert_eq!(persistent_wal, 1);
            drop(store);
            assert!(wal_path(&database).is_file());
            assert!(shm_path(&database).is_file());

            let files_before = database.files();
            let identities_before = ReadOnlyFileIdentities {
                main: file_identity(database.path()).unwrap(),
                wal: file_identity(&wal_path(&database)).unwrap(),
                shm: file_identity(&shm_path(&database)).unwrap(),
            };
            let main_before = fs::read(database.path()).unwrap();
            let wal_before = fs::read(wal_path(&database)).unwrap();
            let reader =
                SqlCipherMailboxReader::open_read_only(account(), database.path(), key(7)).unwrap();
            accepts_reader(&reader);
            assert_eq!(
                run(reader.list_envelopes(&account(), StoreLimit::new(10).unwrap()))
                    .unwrap()
                    .iter()
                    .map(|value| value.message_id().as_str())
                    .collect::<Vec<_>>(),
                ["new", "old"]
            );
            assert_eq!(
                run(reader.thread_envelopes(
                    &account(),
                    values[0].thread_id(),
                    StoreLimit::new(10).unwrap(),
                ))
                .unwrap()
                .len(),
                2
            );
            assert_eq!(
                reader
                    .connection
                    .lock()
                    .unwrap()
                    .query_row("PRAGMA journal_size_limit", [], |row| row.get::<_, i64>(0))
                    .unwrap(),
                -1
            );
            assert!(
                reader
                    .connection
                    .lock()
                    .unwrap()
                    .db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE)
                    .unwrap()
            );
            let foreign_account = AccountId::new("foreign-account").unwrap();
            assert_eq!(
                run(reader.list_envelopes(&foreign_account, StoreLimit::new(10).unwrap(),)),
                Err(MailboxStoreError::Storage)
            );
            assert!(!format!("{reader:?}").contains("account"));
            drop(reader);
            assert_eq!(database.files(), files_before);
            assert_eq!(
                ReadOnlyFileIdentities {
                    main: file_identity(database.path()).unwrap(),
                    wal: file_identity(&wal_path(&database)).unwrap(),
                    shm: file_identity(&shm_path(&database)).unwrap(),
                },
                identities_before
            );
            assert_eq!(fs::read(database.path()).unwrap(), main_before);
            assert_eq!(fs::read(wal_path(&database)).unwrap(), wal_before);
        }

        #[test]
        fn read_only_reader_coexists_with_wal_resident_writer_commits() {
            let (database, store) = open("live-reader");
            let first = envelope("first", "thread", 10);
            run(store.upsert_envelopes(&account(), std::slice::from_ref(&first))).unwrap();
            let wal_before = fs::read(wal_path(&database)).unwrap();
            let second = envelope("second", "thread", 20);
            run(store.upsert_envelopes(&account(), std::slice::from_ref(&second))).unwrap();
            let wal_after = fs::read(wal_path(&database)).unwrap();
            assert!(wal_after.len() > wal_before.len());

            let reader =
                SqlCipherMailboxReader::open_read_only(account(), database.path(), key(7)).unwrap();
            assert_eq!(
                run(reader.list_envelopes(&account(), StoreLimit::new(10).unwrap()))
                    .unwrap()
                    .iter()
                    .map(|value| value.message_id().as_str())
                    .collect::<Vec<_>>(),
                ["second", "first"]
            );
            assert_eq!(fs::read(wal_path(&database)).unwrap(), wal_after);
            drop(reader);
            drop(store);
            assert!(wal_path(&database).exists());
            assert!(shm_path(&database).exists());
        }

        #[test]
        fn read_only_open_requires_nonempty_main_and_both_existing_sidecars() {
            let absent = TestDatabase::new("reader-absent");
            let absent_before = absent.files();
            assert!(matches!(
                SqlCipherMailboxReader::open_read_only(account(), absent.path(), key(7)),
                Err(MailboxStoreError::Storage)
            ));
            assert_eq!(absent.files(), absent_before);

            let fresh = TestDatabase::new("reader-fresh");
            fs::File::create(fresh.path()).unwrap();
            fs::write(wal_path(&fresh), b"existing-wal").unwrap();
            fs::write(shm_path(&fresh), b"existing-shm").unwrap();
            let before = fresh.files();
            assert!(matches!(
                SqlCipherMailboxReader::open_read_only(account(), fresh.path(), key(7)),
                Err(MailboxStoreError::Storage)
            ));
            assert_eq!(fresh.files(), before);
            assert_eq!(fs::read(wal_path(&fresh)).unwrap(), b"existing-wal");
            assert_eq!(fs::read(shm_path(&fresh)).unwrap(), b"existing-shm");

            for suffix in ["-wal", "-shm"] {
                let (database, store) = open(&format!("reader-missing{suffix}"));
                run(store.upsert_envelopes(&account(), &[envelope("one", "thread", 1)])).unwrap();
                drop(store);
                fs::remove_file(sidecar_path(database.path(), suffix)).unwrap();
                let files_before = database.files();
                let main_before = fs::read(database.path()).unwrap();
                assert!(matches!(
                    SqlCipherMailboxReader::open_read_only(account(), database.path(), key(7)),
                    Err(MailboxStoreError::Storage)
                ));
                assert_eq!(database.files(), files_before);
                assert_eq!(fs::read(database.path()).unwrap(), main_before);
            }
        }

        #[test]
        fn read_only_open_rejects_rollback_journal_and_nonregular_sidecars_unchanged() {
            let (journal_database, journal_store) = open("reader-journal");
            drop(journal_store);
            fs::write(journal_path(&journal_database), b"foreign-journal").unwrap();
            let journal_files = journal_database.files();
            assert!(matches!(
                SqlCipherMailboxReader::open_read_only(account(), journal_database.path(), key(7),),
                Err(MailboxStoreError::Storage)
            ));
            assert_eq!(journal_database.files(), journal_files);
            assert_eq!(
                fs::read(journal_path(&journal_database)).unwrap(),
                b"foreign-journal"
            );

            let (symlink_database, symlink_store) = open("reader-symlink-wal");
            drop(symlink_store);
            let original_wal = symlink_database.directory.join("original-wal");
            fs::rename(wal_path(&symlink_database), &original_wal).unwrap();
            std::os::unix::fs::symlink(&original_wal, wal_path(&symlink_database)).unwrap();
            assert!(matches!(
                SqlCipherMailboxReader::open_read_only(account(), symlink_database.path(), key(7),),
                Err(MailboxStoreError::Storage)
            ));
            assert!(
                fs::symlink_metadata(wal_path(&symlink_database))
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );
            assert!(original_wal.is_file());

            let (directory_database, directory_store) = open("reader-directory-shm");
            drop(directory_store);
            fs::remove_file(shm_path(&directory_database)).unwrap();
            fs::create_dir(shm_path(&directory_database)).unwrap();
            assert!(matches!(
                SqlCipherMailboxReader::open_read_only(
                    account(),
                    directory_database.path(),
                    key(7),
                ),
                Err(MailboxStoreError::Storage)
            ));
            assert!(shm_path(&directory_database).is_dir());
        }

        #[test]
        fn read_only_open_requires_owner_only_modes_for_every_fixed_file() {
            for index in [0, 2, 3] {
                let (database, store) = open(&format!("reader-mode-{index}"));
                drop(store);
                let target = fixed_leaf_path(&database, index);
                let files_before = database.files();
                let main_before = fs::read(database.path()).unwrap();
                let wal_before = fs::read(wal_path(&database)).unwrap();
                fs::set_permissions(&target, fs::Permissions::from_mode(0o640)).unwrap();

                assert!(matches!(
                    SqlCipherMailboxReader::open_read_only(account(), database.path(), key(7),),
                    Err(MailboxStoreError::Storage)
                ));
                assert_eq!(database.files(), files_before);
                assert_eq!(fs::read(database.path()).unwrap(), main_before);
                assert_eq!(fs::read(wal_path(&database)).unwrap(), wal_before);
                assert_eq!(fs::metadata(target).unwrap().mode() & 0o777, 0o640);
            }
        }

        #[test]
        fn writer_requires_owner_only_modes_for_main_wal_and_shm() {
            for index in [0, 2, 3] {
                let (database, store) = open(&format!("writer-mode-{index}"));
                drop(store);
                let target = fixed_leaf_path(&database, index);
                let files_before = database.files();
                let main_before = fs::read(database.path()).unwrap();
                let wal_before = fs::read(wal_path(&database)).unwrap();
                fs::set_permissions(&target, fs::Permissions::from_mode(0o640)).unwrap();

                assert!(matches!(
                    SqlCipherMailboxStore::open(account(), database.path(), key(7)),
                    Err(MailboxStoreError::Storage)
                ));
                assert_eq!(database.files(), files_before);
                assert_eq!(fs::read(database.path()).unwrap(), main_before);
                assert_eq!(fs::read(wal_path(&database)).unwrap(), wal_before);
                assert_eq!(fs::metadata(target).unwrap().mode() & 0o777, 0o640);
            }
        }

        #[test]
        fn writer_leaf_mode_race_after_open_fails_closed() {
            for index in [0, 2, 3] {
                let (database, store) = open(&format!("writer-mode-race-{index}"));
                drop(store);
                let target = fixed_leaf_path(&database, index);
                let identity_before = file_identity(&target).unwrap();
                let mut raced = false;
                let result = SqlCipherMailboxStore::open_inner_with_writer_hook(
                    account(),
                    database.path(),
                    key(7),
                    &mut |point, _path| {
                        if point == WriterHook::AfterOpen {
                            fs::set_permissions(&target, fs::Permissions::from_mode(0o640))
                                .unwrap();
                            raced = true;
                        }
                        Ok(())
                    },
                );
                assert!(raced);
                assert!(matches!(result, Err(MailboxStoreError::Storage)));
                let identity_after = file_identity(&target).unwrap();
                assert_eq!(identity_after.device, identity_before.device);
                assert_eq!(identity_after.inode, identity_before.inode);
                assert_eq!(identity_after.mode, 0o640);
            }
        }

        #[test]
        fn read_only_open_rejects_wrong_key_owner_schema_and_invalid_rows_redacted() {
            let (database, store) = open("reader-validation");
            run(store.upsert_envelopes(&account(), &[envelope("one", "thread", 1)])).unwrap();
            drop(store);
            assert!(matches!(
                SqlCipherMailboxReader::open_read_only(account(), database.path(), key(8)),
                Err(MailboxStoreError::Corrupted)
            ));
            let foreign = AccountId::new("foreign-account").unwrap();
            assert!(matches!(
                SqlCipherMailboxReader::open_read_only(foreign, database.path(), key(7)),
                Err(MailboxStoreError::Corrupted)
            ));

            let (integrity_database, integrity_store) = open("reader-integrity");
            run(integrity_store.upsert_envelopes(
                &account(),
                &[envelope("integrity", "thread", 1)],
            ))
            .unwrap();
            integrity_store
                .connection
                .lock()
                .unwrap()
                .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
                .unwrap();
            drop(integrity_store);
            let mut corrupted_bytes = fs::read(integrity_database.path()).unwrap();
            assert!(corrupted_bytes.len() > 100);
            corrupted_bytes[100] ^= 0x80;
            fs::write(integrity_database.path(), corrupted_bytes).unwrap();
            assert!(matches!(
                SqlCipherMailboxReader::open_read_only(
                    account(),
                    integrity_database.path(),
                    key(7),
                ),
                Err(MailboxStoreError::Corrupted)
            ));

            let writer = SqlCipherMailboxStore::open(account(), database.path(), key(7)).unwrap();
            writer
                .connection
                .lock()
                .unwrap()
                .execute(
                    "UPDATE messages SET subject = ?1",
                    params!["x".repeat(1_025)],
                )
                .unwrap();
            drop(writer);
            let reader =
                SqlCipherMailboxReader::open_read_only(account(), database.path(), key(7)).unwrap();
            let error =
                run(reader.list_envelopes(&account(), StoreLimit::new(10).unwrap())).unwrap_err();
            assert_eq!(error, MailboxStoreError::Corrupted);
            assert!(!error.to_string().contains("account"));
            drop(reader);

            let writer = SqlCipherMailboxStore::open(account(), database.path(), key(7)).unwrap();
            writer
                .connection
                .lock()
                .unwrap()
                .execute("UPDATE messages SET subject = 'valid'", [])
                .unwrap();
            writer
                .connection
                .lock()
                .unwrap()
                .execute("CREATE TABLE unexpected(value INTEGER)", [])
                .unwrap();
            drop(writer);
            assert!(matches!(
                SqlCipherMailboxReader::open_read_only(account(), database.path(), key(7)),
                Err(MailboxStoreError::Corrupted)
            ));
        }

        #[test]
        fn read_only_open_detects_observable_sidecar_replacement() {
            let (database, store) = open("reader-sidecar-replacement");
            run(store.upsert_envelopes(&account(), &[envelope("one", "thread", 1)])).unwrap();
            drop(store);
            let replacement = database.directory.join("replacement-shm");
            fs::copy(shm_path(&database), &replacement).unwrap();
            let original = database.directory.join("original-shm");
            let result = SqlCipherMailboxReader::open_read_only_with_hooks(
                account(),
                database.path(),
                key(7),
                |_path| {
                    fs::rename(shm_path(&database), &original).unwrap();
                    fs::rename(&replacement, shm_path(&database)).unwrap();
                },
                |_path| {},
                |_path| {},
            );
            assert!(matches!(result, Err(MailboxStoreError::Storage)));

            let (main_database, main_store) = open("reader-main-replacement");
            drop(main_store);
            let (foreign_database, foreign_store) = open("reader-main-foreign");
            drop(foreign_store);
            let original_main = main_database.directory.join("original-main");
            let result = SqlCipherMailboxReader::open_read_only_with_hooks(
                account(),
                main_database.path(),
                key(7),
                |_path| {
                    fs::rename(main_database.path(), &original_main).unwrap();
                    fs::copy(foreign_database.path(), main_database.path()).unwrap();
                },
                |_path| {},
                |_path| {},
            );
            assert!(matches!(result, Err(MailboxStoreError::Storage)));
        }

        #[test]
        fn read_only_sidecar_swap_in_open_swap_back_is_an_accepted_residual() {
            let (database, store) = open("reader-sidecar-race");
            run(store.upsert_envelopes(&account(), &[envelope("one", "thread", 1)])).unwrap();
            drop(store);
            let replacement = database.directory.join("replacement-shm");
            fs::copy(shm_path(&database), &replacement).unwrap();
            let original = database.directory.join("original-shm");
            let reader = SqlCipherMailboxReader::open_read_only_with_hooks(
                account(),
                database.path(),
                key(7),
                |_path| {},
                |_path| {
                    fs::rename(shm_path(&database), &original).unwrap();
                    fs::rename(&replacement, shm_path(&database)).unwrap();
                },
                |_path| {
                    fs::remove_file(shm_path(&database)).unwrap();
                    fs::rename(&original, shm_path(&database)).unwrap();
                },
            )
            .unwrap();
            assert_eq!(
                run(reader.list_envelopes(&account(), StoreLimit::new(1).unwrap()))
                    .unwrap()
                    .len(),
                1
            );
        }

        #[test]
        fn read_only_sidecar_delete_recreate_is_an_accepted_residual() {
            let (database, store) = open("reader-sidecar-delete-race");
            run(store.upsert_envelopes(&account(), &[envelope("one", "thread", 1)])).unwrap();
            store
                .connection
                .lock()
                .unwrap()
                .execute_batch("PRAGMA wal_checkpoint(FULL);")
                .unwrap();
            drop(store);
            let original_wal = file_identity(&wal_path(&database)).unwrap();
            let result = SqlCipherMailboxReader::open_read_only_with_hooks(
                account(),
                database.path(),
                key(7),
                |_path| {},
                |_path| fs::remove_file(wal_path(&database)).unwrap(),
                |_path| {},
            );
            assert!(wal_path(&database).is_file());
            match result {
                Err(MailboxStoreError::Storage) => {
                    assert_ne!(file_identity(&wal_path(&database)).unwrap(), original_wal);
                }
                // Linux filesystems such as ext4 can hand the deleted WAL's
                // inode straight to the recreated file, so the identity check
                // cannot see the swap. The WAL was checkpointed first, so the
                // accepted residual is benign: the data is intact.
                Ok(reader) => assert_eq!(
                    run(reader.list_envelopes(&account(), StoreLimit::new(1).unwrap()))
                        .unwrap()
                        .len(),
                    1
                ),
                Err(other) => panic!("unexpected reader failure: {other:?}"),
            }
        }

        #[test]
        fn dropping_an_unpolled_reader_future_performs_no_query() {
            let (database, store) = open("reader-unpolled");
            run(store.upsert_envelopes(&account(), &[envelope("one", "thread", 1)])).unwrap();
            drop(store);
            let reader =
                SqlCipherMailboxReader::open_read_only(account(), database.path(), key(7)).unwrap();
            let local_account = account();
            let future = reader.list_envelopes(&local_account, StoreLimit::new(1).unwrap());
            drop(future);
            assert_eq!(
                run(reader.list_envelopes(&account(), StoreLimit::new(1).unwrap()))
                    .unwrap()
                    .len(),
                1
            );
        }

        #[test]
        fn symlink_leaf_and_poisoned_connection_are_opaque_storage_failures() {
            let target_database = TestDatabase::new("symlink-target");
            let target =
                SqlCipherMailboxStore::open(account(), target_database.path(), key(7)).unwrap();
            drop(target);
            let link_database = TestDatabase::new("symlink-link");
            std::os::unix::fs::symlink(target_database.path(), link_database.path()).unwrap();
            assert!(matches!(
                SqlCipherMailboxStore::open(account(), link_database.path(), key(7)),
                Err(MailboxStoreError::Storage)
            ));

            let (_database, poisoned) = open("poisoned");
            let panic = catch_unwind(AssertUnwindSafe(|| {
                let _guard = poisoned.connection.lock().unwrap();
                panic!("intentional mutex poison");
            }));
            assert!(panic.is_err());
            assert_eq!(
                run(poisoned.list_envelopes(&account(), StoreLimit::new(1).unwrap())),
                Err(MailboxStoreError::Storage)
            );
        }

        fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
            haystack
                .windows(needle.len())
                .any(|window| window == needle)
        }
    }
}

pub mod registry;

pub use store::{
    DatabaseKey, IntegrityScan, ReadOnlyMailboxOpenFailure, SqlCipherMailboxReader,
    SqlCipherMailboxStore,
};
