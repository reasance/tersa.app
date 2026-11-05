// This Source Code Form is subject to the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Fixed, explicitly provisioned synthetic accounts for application integration tests.
use std::{
    fs,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tersa_application::{
    AccountCapability,
    identity::{AccountIdentityHasher, AccountIdentityStore, IdentityReconcile, normalize_subject},
    lifecycle::AccountLifecycleStore,
    mailbox::AccountId,
    token::AccountSubject,
};
use tersa_keys::{
    AccountKeyPurpose, InstallationKeyPurpose, RootKey, derive_account_key,
    derive_installation_key, registry_dedup_tag,
};
use tersa_store_sqlcipher::{
    DatabaseKey, SqlCipherMailboxStore, StoreCredential, registry::SqlCipherRegistry,
};
use tersa_sync_runtime::{Installation, InstallationHasher, InstallationLock};
use zeroize::Zeroizing;
fn root() -> RootKey {
    RootKey::from_bytes(Zeroizing::new([7; 32]))
}
pub(crate) struct LocalFixture {
    pub path: PathBuf,
    pub installation: Arc<Installation>,
    pub accounts: Vec<AccountId>,
    _lock: InstallationLock,
}
impl LocalFixture {
    pub fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "tersa-p9a-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let lock = InstallationLock::acquire(&path).expect("lock");
        let installation = Arc::new(Installation::open(&path, root()).expect("installation"));
        let key = derive_installation_key(&root(), InstallationKeyPurpose::RegistryDatabaseV1)
            .expect("key")
            .into_bytes();
        let registry =
            SqlCipherRegistry::open(&path.join("registry.sqlite3"), &key).expect("registry");
        let executor = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("executor");
        // SHA256 of the exact fixed account ID UTF-8 strings, without newline.
        let mut accounts = Vec::new();
        for (subject, id, directory) in [
            (
                "synthetic-a",
                "acct_00000000000000000000000000000001",
                "4f4b5f23e8fe1bc7c70aac651d808a2118a2eaf69145f174181b7b48329d812a",
            ),
            (
                "synthetic-b",
                "acct_00000000000000000000000000000002",
                "3120152975130f54133b7dab0053d79e08fda1e89eb3306653a734fc853ceda1",
            ),
        ] {
            accounts.push(provision(
                &path,
                &installation,
                &registry,
                &executor,
                subject,
                id,
                directory,
            ));
        }
        drop(registry);
        Self {
            path,
            installation,
            accounts,
            _lock: lock,
        }
    }
}
impl Drop for LocalFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
fn provision(
    path: &std::path::Path,
    installation: &Arc<Installation>,
    registry: &SqlCipherRegistry,
    executor: &tokio::runtime::Runtime,
    subject: &str,
    id: &str,
    directory: &str,
) -> AccountId {
    use std::os::unix::fs::DirBuilderExt;
    let account = AccountId::new(id).expect("account");
    registry
        .register(
            &account,
            &registry_dedup_tag(&root(), subject.as_bytes()).expect("tag"),
        )
        .expect("register");
    let directory = path.join("accounts").join(directory);
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .expect("directory");
    let key =
        derive_account_key(&root(), &account, AccountKeyPurpose::SqlCipherDatabaseV1).expect("key");
    let fresh = SqlCipherMailboxStore::open(
        account.clone(),
        directory.join("mail.sqlite3"),
        DatabaseKey::from_zeroizing(key.into_bytes()),
    )
    .expect("fixture store");
    fresh
        .store_broker_subject(&account, subject)
        .expect("subject");
    drop(fresh);
    let store = installation.open_store(&account).expect("store");
    let expected = store.load_credential_snapshot(&account).expect("snapshot");
    store
        .replace_credential_snapshot(
            &expected,
            AccountCapability::Modify,
            &StoreCredential::Active(Zeroizing::new("synthetic-modify".to_owned())),
        )
        .expect("Modify fixture");
    store
        .delete_credential_snapshot(&store.load_credential_snapshot(&account).expect("snapshot"))
        .expect("no usable token");
    let hash = InstallationHasher(Arc::clone(installation))
        .hash(
            &account,
            &normalize_subject(
                &AccountSubject::from_broker_validated(Zeroizing::new(subject.to_owned()))
                    .expect("subject"),
            ),
        )
        .expect("hash");
    executor
        .block_on(store.reconcile_identity(&account, &hash, IdentityReconcile::RecordOnly, None))
        .expect("identity");
    executor
        .block_on(store.record_successful_sync(&account, 1))
        .expect("lifecycle");
    account
}
