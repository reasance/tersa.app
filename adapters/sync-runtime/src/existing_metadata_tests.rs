// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Isolated, vault-free tests of the pre-confirmation boundary.

use std::collections::BTreeMap;
use std::os::unix::fs::symlink;
use std::sync::atomic::{AtomicU64, Ordering};

use super::*;

struct Directory(PathBuf);
impl Directory {
    fn absent() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        Self(std::env::temp_dir().join(format!(
            "tersa-existing-metadata-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )))
    }
    fn private() -> Self {
        let directory = Self::absent();
        private_dir(&directory.0);
        directory
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn root() -> RootKey {
    RootKey::from_bytes(Zeroizing::new([7; 32]))
}
fn private_dir(path: &Path) {
    fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .expect("private fixture directory");
}
fn write_private(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).expect("fixture bytes");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("fixture mode");
}
fn subject(value: &str) -> ValidatedSubject {
    ValidatedSubject::new(value).expect("synthetic subject")
}
fn register(installation: &Arc<Installation>, name: &str) -> AccountId {
    InstallationTokens(Arc::clone(installation))
        .store(
            &subject(name),
            &Zeroizing::new("synthetic-token".to_owned()),
        )
        .expect("fixture account");
    installation
        .account_for_subject(name)
        .expect("lookup")
        .expect("registered")
}

// Compare durable bytes and entry identities/modes, allowing native SQLite SHM
// bookkeeping and the explicitly permitted coordination lock. No account or
// registry journal/WAL/main changes are excluded.
fn durable_tree(path: &Path) -> BTreeMap<PathBuf, (u64, u32, Vec<u8>)> {
    fn visit(root: &Path, path: &Path, out: &mut BTreeMap<PathBuf, (u64, u32, Vec<u8>)>) {
        let metadata = fs::symlink_metadata(path).expect("fixture metadata");
        let name = path.file_name().expect("leaf").to_string_lossy();
        if name == LOCK_FILE || name.ends_with("-shm") {
            return;
        }
        let bytes = if metadata.is_file() {
            fs::read(path).expect("fixture bytes")
        } else if metadata.is_symlink() {
            fs::read_link(path)
                .expect("link")
                .as_os_str()
                .as_encoded_bytes()
                .to_vec()
        } else {
            Vec::new()
        };
        out.insert(
            path.strip_prefix(root).expect("relative").to_owned(),
            (metadata.ino(), metadata.mode(), bytes),
        );
        if metadata.is_dir() {
            for entry in fs::read_dir(path).expect("fixture entries") {
                visit(root, &entry.expect("entry").path(), out);
            }
        }
    }
    let mut out = BTreeMap::new();
    visit(path, path, &mut out);
    out
}

#[test]
fn existing_lock_requires_private_real_directory_without_hardening() {
    let directory = Directory::absent();
    assert!(matches!(
        InstallationLock::acquire_existing(&directory.0),
        Err(LockError::Directory)
    ));
    assert!(!directory.0.exists());
    private_dir(&directory.0);
    fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o755)).expect("insecure fixture");
    let before = durable_tree(&directory.0);
    assert!(InstallationLock::acquire_existing(&directory.0).is_err());
    assert_eq!(durable_tree(&directory.0), before);
    assert!(!directory.0.join(LOCK_FILE).exists());
    let link = Directory::absent();
    symlink(&directory.0, &link.0).expect("directory link");
    assert!(InstallationLock::acquire_existing(&link.0).is_err());
    fs::remove_file(&link.0).expect("remove link");
}

#[test]
fn existing_lock_refuses_unsafe_leaves_and_never_repairs_them() {
    for kind in ["public", "symlink", "directory", "fifo"] {
        let directory = Directory::private();
        let lock = directory.0.join(LOCK_FILE);
        match kind {
            "public" => {
                fs::write(&lock, b"keep").expect("lock bytes");
                fs::set_permissions(&lock, fs::Permissions::from_mode(0o644)).expect("mode");
            }
            "symlink" => {
                write_private(&directory.0.join("target"), b"keep");
                symlink("target", &lock).expect("lock link");
            }
            "directory" => private_dir(&lock),
            "fifo" => {
                assert!(
                    std::process::Command::new("mkfifo")
                        .arg("-m")
                        .arg("600")
                        .arg(&lock)
                        .status()
                        .expect("fixture FIFO command")
                        .success()
                );
            }
            _ => unreachable!(),
        }
        let before = fs::symlink_metadata(&lock).expect("lock metadata");
        assert!(
            matches!(
                InstallationLock::acquire_existing(&directory.0),
                Err(LockError::Directory)
            ),
            "{kind}"
        );
        let after = fs::symlink_metadata(&lock).expect("unchanged leaf");
        assert_eq!(file_identity(&before), file_identity(&after));
        if kind == "public" || kind == "symlink" {
            assert_eq!(fs::read(&lock).expect("unchanged contents"), b"keep");
        }
    }
}

#[test]
fn existing_lock_only_creates_coordination_and_excludes_until_drop() {
    let directory = Directory::private();
    let lock = InstallationLock::acquire_existing(&directory.0).expect("new coordination leaf");
    assert_eq!(fs::read_dir(&directory.0).expect("entries").count(), 1);
    let metadata = fs::metadata(directory.0.join(LOCK_FILE)).expect("lock metadata");
    assert!(private_lock_metadata(
        &metadata,
        rustix::process::geteuid().as_raw()
    ));
    assert!(matches!(
        InstallationLock::acquire_existing(&directory.0),
        Err(LockError::Busy)
    ));
    assert!(matches!(
        InstallationLock::acquire(&directory.0),
        Err(LockError::Busy)
    ));
    drop(lock);
    InstallationLock::acquire_existing(&directory.0).expect("released");
}

#[test]
fn ownership_predicates_refuse_foreign_uids_without_privileged_chown() {
    let directory = Directory::private();
    let metadata = fs::symlink_metadata(&directory.0).expect("directory metadata");
    assert!(!private_directory_metadata(
        &metadata,
        metadata.uid().wrapping_add(1)
    ));
    write_private(&directory.0.join(LOCK_FILE), b"");
    let metadata = fs::symlink_metadata(directory.0.join(LOCK_FILE)).expect("lock metadata");
    assert!(!private_lock_metadata(
        &metadata,
        metadata.uid().wrapping_add(1)
    ));
}

#[test]
fn existing_installation_missing_paths_and_unclaimed_registry_never_bootstrap() {
    let directory = Directory::absent();
    assert!(Installation::open_existing(&directory.0, root()).is_err());
    assert!(!directory.0.exists());
    private_dir(&directory.0);
    let before = durable_tree(&directory.0);
    assert!(Installation::open_existing(&directory.0, root()).is_err());
    assert_eq!(durable_tree(&directory.0), before);
    private_dir(&directory.0.join(ACCOUNTS_DIR));
    let before = durable_tree(&directory.0);
    assert!(Installation::open_existing(&directory.0, root()).is_err());
    assert_eq!(durable_tree(&directory.0), before);
    for bytes in [
        Vec::new(),
        vec![0; 8192],
        include_bytes!("../tests/fixtures/unclaimed-registry.bin").to_vec(),
    ] {
        write_private(&directory.0.join(REGISTRY_FILE), &bytes);
        let before = durable_tree(&directory.0);
        assert!(Installation::open_existing(&directory.0, root()).is_err());
        assert_eq!(durable_tree(&directory.0), before);
    }
}

#[test]
fn existing_installation_refuses_insecure_or_linked_directories_without_repair() {
    for leaf in ["", ACCOUNTS_DIR] {
        let directory = Directory::private();
        drop(Installation::open(&directory.0, root()).expect("fixture"));
        let path = directory.0.join(leaf);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("fixture mode");
        let before = durable_tree(&directory.0);
        assert!(Installation::open_existing(&directory.0, root()).is_err());
        assert_eq!(durable_tree(&directory.0), before);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("fixture restore");
        let moved = directory.0.join("moved-accounts");
        if leaf == ACCOUNTS_DIR {
            fs::rename(&path, &moved).expect("move");
            symlink(&moved, &path).expect("link");
            let before = durable_tree(&directory.0);
            assert!(Installation::open_existing(&directory.0, root()).is_err());
            assert_eq!(durable_tree(&directory.0), before);
        } else {
            let link = Directory::absent();
            symlink(&directory.0, &link.0).expect("link");
            assert!(Installation::open_existing(&link.0, root()).is_err());
            fs::remove_file(&link.0).expect("remove link");
        }
    }
}

#[test]
fn preview_keeps_duplicate_addresses_nulls_and_exact_ids_distinct_without_writes() {
    let directory = Directory::private();
    let setup = Arc::new(Installation::open(&directory.0, root()).expect("fixture"));
    let accounts = ["first", "second", "null"].map(|name| register(&setup, name));
    let email = AccountEmail::new("same@example.test").expect("email");
    for account in &accounts[..2] {
        setup
            .open_store(account)
            .expect("fixture store")
            .store_email_address(account, &email)
            .expect("fixture email");
    }
    drop(setup);
    let before = durable_tree(&directory.0);
    let lock = InstallationLock::acquire_existing(&directory.0).expect("lock");
    let preview = Installation::open_existing(&directory.0, root()).expect("preview");
    assert_eq!(preview.accounts().expect("accounts"), accounts);
    assert_eq!(
        preview.account_for_subject("first").expect("dedup"),
        Some(accounts[0].clone())
    );
    assert_eq!(
        preview
            .account_for_subject("unknown")
            .expect("unknown subject"),
        None
    );
    let results: Vec<_> = preview
        .accounts()
        .expect("accounts")
        .iter()
        .map(|account| preview.account_email_existing(account))
        .collect::<Result<_, _>>()
        .expect("all authenticated");
    assert_eq!(results, vec![Some(email.clone()), Some(email), None]);
    assert_eq!(
        results.iter().filter(|email| email.is_some()).count(),
        2,
        "resolver must keep both matches ambiguous"
    );
    let unknown = AccountId::new("acct_00000000000000000000000000000000").expect("unknown ID");
    assert!(matches!(
        preview.account_email_existing(&unknown),
        Err(InstallationError::UnknownAccount)
    ));
    drop(preview);
    drop(lock);
    assert_eq!(
        durable_tree(&directory.0),
        before,
        "dropped unused preview is not a writer"
    );
}

#[test]
fn wrong_registry_key_fails_before_accessing_a_missing_account_directory() {
    let directory = Directory::private();
    let setup = Arc::new(Installation::open(&directory.0, root()).expect("fixture"));
    let account = register(&setup, "first");
    let path = setup.account_dir(&account);
    drop(setup);
    fs::remove_dir_all(&path).expect("missing account fixture");
    let before = durable_tree(&directory.0);
    assert!(matches!(
        Installation::open_existing(&directory.0, RootKey::from_bytes(Zeroizing::new([8; 32]))),
        Err(InstallationError::Registry(_))
    ));
    assert_eq!(durable_tree(&directory.0), before);
    assert!(!path.exists());
}

#[test]
fn preview_unreadable_peer_is_an_error_and_never_a_false_unique_match() {
    for damage in [
        "directory-missing",
        "directory-public",
        "directory-link",
        "file-missing",
        "empty",
        "unclaimed",
        "file-link",
        "wrong-key",
    ] {
        let directory = Directory::private();
        let setup = Arc::new(Installation::open(&directory.0, root()).expect("fixture"));
        let a = register(&setup, "first");
        let b = register(&setup, "second");
        setup
            .open_store(&a)
            .expect("store")
            .store_email_address(&a, &AccountEmail::new("one@example.test").expect("email"))
            .expect("email");
        let account_dir = setup.account_dir(&b);
        let file = account_dir.join(MAIL_FILE);
        drop(setup);
        match damage {
            "directory-missing" => fs::remove_dir_all(&account_dir).expect("remove"),
            "directory-public" => {
                fs::set_permissions(&account_dir, fs::Permissions::from_mode(0o755)).expect("mode");
            }
            "directory-link" => {
                let target = directory.0.join("moved");
                fs::rename(&account_dir, &target).expect("move");
                symlink(target, &account_dir).expect("link");
            }
            "file-missing" => fs::remove_file(&file).expect("remove"),
            "empty" => write_private(&file, b""),
            "unclaimed" => write_private(&file, &[0; 8192]),
            "file-link" => {
                let target = account_dir.join("moved");
                fs::rename(&file, &target).expect("move");
                symlink(target, &file).expect("link");
            }
            "wrong-key" => {
                for suffix in ["", "-wal", "-shm"] {
                    fs::remove_file(PathBuf::from(format!("{}{suffix}", file.display())))
                        .expect("remove fixture file");
                }
                drop(
                    SqlCipherMailboxStore::open(b.clone(), &file, DatabaseKey::new([99; 32]))
                        .expect("wrong-key fixture"),
                );
            }
            _ => unreachable!(),
        }
        let before = durable_tree(&directory.0);
        let preview =
            Installation::open_existing(&directory.0, root()).expect("registry is still readable");
        assert!(
            preview
                .account_email_existing(&a)
                .expect("good peer")
                .is_some()
        );
        assert!(preview.account_email_existing(&b).is_err(), "{damage}");
        let all = preview
            .accounts()
            .expect("accounts")
            .iter()
            .map(|account| preview.account_email_existing(account))
            .collect::<Result<Vec<_>, _>>();
        assert!(
            all.is_err(),
            "must fail closed rather than skip a peer: {damage}"
        );
        drop(preview);
        assert_eq!(durable_tree(&directory.0), before, "{damage}");
    }
}

#[test]
fn real_v1_preview_has_no_address_and_does_not_upgrade() {
    let directory = Directory::private();
    let setup = Installation::open(&directory.0, root()).expect("fixture");
    let account = AccountId::new("acct_00000000000000000000000000000001").expect("v1 ID");
    let tag = registry_dedup_tag(&root(), b"v1-preview-subject").expect("tag");
    setup
        .registry
        .register(&account, &tag)
        .expect("fixture registration");
    let account_dir = setup.account_dir(&account);
    private_dir(&account_dir);
    let file = account_dir.join(MAIL_FILE);
    write_private(&file, include_bytes!("../tests/fixtures/v1-mail.bin"));
    // The fixture main is fully checkpointed in WAL mode. Existing native SHM
    // bookkeeping is allowed; no sidecar is minted by preview.
    write_private(&account_dir.join("mail.sqlite3-wal"), b"");
    write_private(&account_dir.join("mail.sqlite3-shm"), &vec![0; 32768]);
    drop(setup);
    let before = durable_tree(&directory.0);
    let preview = Installation::open_existing(&directory.0, root()).expect("preview");
    assert_eq!(
        preview
            .account_email_existing(&account)
            .expect("authenticated v1"),
        None
    );
    drop(preview);
    assert_eq!(
        durable_tree(&directory.0),
        before,
        "v1 schema/main/WAL unchanged"
    );
    // Ordinary open remains a migrating writer after the preview is gone.
    let ordinary = Installation::open(&directory.0, root()).expect("ordinary writer");
    let email = AccountEmail::new("upgraded@example.test").expect("email");
    ordinary
        .open_store(&account)
        .expect("ordinary upgrade")
        .store_email_address(&account, &email)
        .expect("v2 field available");
    assert_eq!(
        ordinary.account_email(&account).expect("ordinary getter"),
        Some(email)
    );
}

#[test]
fn encrypted_unclaimed_mailbox_remains_unclaimed_after_preview_refusal() {
    let directory = Directory::private();
    let setup = Installation::open(&directory.0, root()).expect("fixture");
    let account = AccountId::new("acct_00000000000000000000000000000001").expect("fixture ID");
    setup
        .registry
        .register(
            &account,
            &registry_dedup_tag(&root(), b"synthetic-unclaimed").expect("tag"),
        )
        .expect("register");
    let account_dir = setup.account_dir(&account);
    private_dir(&account_dir);
    write_private(
        &account_dir.join(MAIL_FILE),
        include_bytes!("../tests/fixtures/unclaimed-mailbox.bin"),
    );
    write_private(&account_dir.join("mail.sqlite3-wal"), b"");
    write_private(&account_dir.join("mail.sqlite3-shm"), &vec![0; 32768]);
    drop(setup);
    let before = durable_tree(&directory.0);
    let preview =
        Installation::open_existing(&directory.0, root()).expect("authenticated registry");
    assert!(preview.account_email_existing(&account).is_err());
    drop(preview);
    assert_eq!(durable_tree(&directory.0), before);
}
