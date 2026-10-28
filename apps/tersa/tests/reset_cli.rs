// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Compiled-product negative checks: no shared keyring, credentials or provider.

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output, Stdio};
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Fixture {
        directory: PathBuf,
        data: PathBuf,
        config: PathBuf,
    }
    impl Fixture {
        fn new(client: bool) -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let directory = std::env::temp_dir().join(format!(
                "tersa-reset-compiled-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            assert!(directory.is_absolute());
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&directory)
                .expect("test directory");
            let config = directory.join("config");
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&config)
                .expect("config directory");
            let content = if client {
                "[google]\nclient_id = \"synthetic-client\"\n[vault]\nbackend = \"file\"\n"
            } else {
                "[vault]\nbackend = \"file\"\n"
            };
            fs::write(config.join("config.toml"), content).expect("explicit isolated file backend");
            let data = directory.join("data");
            Self {
                directory,
                data,
                config,
            }
        }
        fn run(&self, args: &[&str], input: &[u8]) -> Output {
            assert!(self.data.is_absolute() && self.config.is_absolute());
            let mut child = Command::new(env!("CARGO_BIN_EXE_tersa"))
                .args(args)
                .env("TERSA_CONFIG_DIR", &self.config)
                .env("TERSA_DATA_DIR", &self.data)
                .env_remove("TERSA_GOOGLE_CLIENT_ID")
                .env_remove("TERSA_GOOGLE_CLIENT_SECRET")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("isolated product process");
            let mut stdin = child.stdin.take().expect("child input");
            // The command may reject non-TTY before consuming its pipe.
            let _ = stdin.write_all(input);
            drop(stdin);
            child.wait_with_output().expect("product output")
        }
        fn private_data(&self) {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&self.data)
                .expect("data fixture");
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }
    fn stderr(output: &Output) -> String {
        String::from_utf8_lossy(&output.stderr).into_owned()
    }
    fn snapshot(path: &Path) -> BTreeMap<PathBuf, (u32, Vec<u8>)> {
        let mut out = BTreeMap::new();
        for entry in fs::read_dir(path).expect("data directory") {
            let path = entry.expect("entry").path();
            let metadata = fs::symlink_metadata(&path).expect("metadata");
            if path.file_name().expect("leaf") == ".lock"
                || path.to_string_lossy().ends_with("-shm")
            {
                continue;
            }
            let bytes = if metadata.is_dir() {
                out.extend(snapshot(&path));
                Vec::new()
            } else if metadata.is_symlink() {
                fs::read_link(&path)
                    .expect("target")
                    .as_os_str()
                    .as_encoded_bytes()
                    .to_vec()
            } else {
                fs::read(&path).expect("data bytes")
            };
            out.insert(path, (metadata.permissions().mode(), bytes));
        }
        out
    }

    struct Registered {
        fixture: Fixture,
        accounts: [tersa_application::mailbox::AccountId; 2],
        stores: Vec<PathBuf>,
    }
    impl Registered {
        fn new() -> Self {
            use tersa_application::mailbox::AccountId;
            use tersa_keys::{
                InstallationKeyPurpose, RootKey, derive_installation_key, registry_dedup_tag,
            };
            use tersa_store_sqlcipher::registry::SqlCipherRegistry;
            use tersa_sync_runtime::Installation;
            use zeroize::Zeroizing;

            let fixture = Fixture::new(true);
            let root = || RootKey::from_bytes(Zeroizing::new([7; 32]));
            drop(Installation::open(&fixture.data, root()).expect("fixture bootstrap"));
            let accounts = [
                "acct_00000000000000000000000000000001",
                "acct_00000000000000000000000000000002",
            ]
            .map(|id| AccountId::new(id).expect("fixture ID"));
            let key = derive_installation_key(&root(), InstallationKeyPurpose::RegistryDatabaseV1)
                .expect("registry key")
                .into_bytes();
            let registry = SqlCipherRegistry::open(&fixture.data.join("registry.sqlite3"), &key)
                .expect("fixture registry");
            for (index, account) in accounts.iter().enumerate() {
                registry
                    .register(
                        account,
                        &registry_dedup_tag(
                            &root(),
                            format!("synthetic-subject-{index}").as_bytes(),
                        )
                        .expect("tag"),
                    )
                    .expect("registration");
            }
            drop(registry);
            let installation =
                Installation::open(&fixture.data, root()).expect("fixture installation");
            let mut stores = Vec::new();
            for (index, account) in accounts.iter().enumerate() {
                let directories = fixture.data.join("accounts");
                let before: Vec<_> = fs::read_dir(&directories)
                    .expect("directories")
                    .map(|entry| entry.expect("entry").path())
                    .collect();
                let store = installation.open_store(account).expect("fixture account");
                stores.push(
                    fs::read_dir(directories)
                        .expect("directories")
                        .map(|entry| entry.expect("entry").path())
                        .find(|path| !before.contains(path))
                        .expect("created fixture directory")
                        .join("mail.sqlite3"),
                );
                store
                    .store_email_address(
                        account,
                        &tersa_application::mailbox::AccountEmail::new(format!(
                            "person{index}@example.test"
                        ))
                        .expect("email"),
                    )
                    .expect("fixture email");
            }
            drop(installation);
            // A public synthetic P-tag root exercises the existing unprotected
            // key decoder through the explicit file backend without touching
            // a keyring or needing a controlling terminal/passphrase. This is
            // test-only encoding; production file-vault creation wraps roots.
            let mut encoded = vec![b'P'];
            encoded.extend_from_slice(&[7; 32]);
            fs::write(fixture.data.join("root-key.wrapped"), encoded).expect("synthetic root slot");
            fs::set_permissions(
                fixture.data.join("root-key.wrapped"),
                fs::Permissions::from_mode(0o600),
            )
            .expect("private slot");
            Self {
                fixture,
                accounts,
                stores,
            }
        }
    }

    #[test]
    fn compiled_unlocked_preview_resolution_and_real_preclear_refusal_are_non_destructive() {
        let registered = Registered::new();
        let fixture = &registered.fixture;
        let before = snapshot(&fixture.data);
        for (raw, expected) in [
            ("unknown", "no account matches"),
            ("acct_", "matches more than one"),
            ("absent@example.test", "no account matches"),
            (registered.accounts[0].as_str(), "refused before clearing"),
            (
                "hostile\u{1b}[2J\u{202e}@example.test",
                "no account matches",
            ),
        ] {
            let output = fixture.run(&["account", "reset", raw, "--yes"], b"");
            assert_eq!(output.status.code(), Some(1));
            assert!(stderr(&output).contains(expected), "{}", stderr(&output));
            assert!(!stderr(&output).contains('\x1b') && !stderr(&output).contains('\u{202e}'));
            assert_eq!(snapshot(&fixture.data), before);
        }
        fs::remove_file(&registered.stores[1]).expect("missing peer");
        let before = snapshot(&fixture.data);
        for raw in [registered.accounts[1].as_str(), "person0@example.test"] {
            let output = fixture.run(&["account", "reset", raw, "--yes"], b"");
            assert_eq!(output.status.code(), Some(1));
            assert!(!stderr(&output).contains("cache clear committed"));
            assert_eq!(snapshot(&fixture.data), before);
            assert!(!registered.stores[1].exists());
        }
    }

    #[test]
    fn compiled_help_and_invalid_reset_arguments_do_not_open_storage() {
        let fixture = Fixture::new(true);
        let output = fixture.run(&["help"], b"");
        assert!(output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("account reset <account> [--yes]")
        );
        for args in [
            vec!["account", "reset"],
            vec!["account", "reset", "--yes"],
            vec!["account", "reset", ""],
            vec!["account", "reset", " \t"],
            vec!["account", "reset", "a", "b"],
            vec!["account", "reset", "a", "--yes", "--yes"],
            vec!["account", "reset", "a", "--force"],
        ] {
            let output = fixture.run(&args, b"");
            assert_eq!(
                output.status.code(),
                Some(2),
                "{args:?}: {}",
                stderr(&output)
            );
            assert!(!fixture.data.exists());
        }
    }

    #[test]
    fn compiled_piped_yes_without_override_refuses_before_vault_or_lock() {
        let fixture = Fixture::new(true);
        for answer in [b"".as_slice(), b"yes\n"] {
            let output = fixture.run(&["account", "reset", "acct_1"], answer);
            assert_eq!(output.status.code(), Some(1));
            assert!(stderr(&output).contains("requires interactive input or explicit --yes"));
            assert!(!fixture.data.exists());
        }
    }

    #[test]
    fn compiled_yes_validates_config_and_missing_directory_without_creating_it() {
        for client in [false, true] {
            let fixture = Fixture::new(client);
            let output = fixture.run(&["account", "reset", "acct_1", "--yes"], b"");
            assert_eq!(output.status.code(), Some(1));
            assert!(stderr(&output).contains(if client {
                "data directory is unusable"
            } else {
                "no Google OAuth client configured"
            }));
            assert!(!fixture.data.exists());
        }
    }

    #[test]
    fn compiled_existing_empty_and_unclaimed_data_never_mint_a_key_or_bootstrap() {
        let fixture = Fixture::new(true);
        fixture.private_data();
        for bytes in [None, Some(Vec::new()), Some(vec![0; 8192])] {
            if let Some(bytes) = bytes {
                fs::write(fixture.data.join("registry.sqlite3"), bytes).expect("unclaimed fixture");
                fs::set_permissions(
                    fixture.data.join("registry.sqlite3"),
                    fs::Permissions::from_mode(0o600),
                )
                .expect("mode");
            }
            let before = snapshot(&fixture.data);
            let output = fixture.run(&["account", "reset", "acct_1", "--yes"], b"");
            assert_eq!(output.status.code(), Some(1));
            assert!(stderr(&output).contains("no existing installation key is available"));
            assert_eq!(snapshot(&fixture.data), before);
            assert!(!fixture.data.join("root-key.wrapped").exists());
            assert!(!fixture.data.join("accounts").exists());
        }
    }

    #[test]
    fn compiled_unsafe_directory_and_lock_refuse_without_hardening_or_vault_access() {
        let fixture = Fixture::new(true);
        fixture.private_data();
        fs::set_permissions(&fixture.data, fs::Permissions::from_mode(0o755))
            .expect("insecure mode");
        let output = fixture.run(&["account", "reset", "acct_1", "--yes"], b"");
        assert_eq!(output.status.code(), Some(1));
        assert!(stderr(&output).contains("data directory is unusable"));
        assert_eq!(
            fs::metadata(&fixture.data)
                .expect("mode")
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
        assert!(!fixture.data.join(".lock").exists());
        fs::set_permissions(&fixture.data, fs::Permissions::from_mode(0o700))
            .expect("fixture mode");
        let target = fixture.directory.join("sentinel");
        fs::write(&target, b"keep").expect("sentinel");
        symlink(&target, fixture.data.join(".lock")).expect("unsafe lock");
        let output = fixture.run(&["account", "reset", "acct_1", "--yes"], b"");
        assert_eq!(output.status.code(), Some(1));
        assert!(stderr(&output).contains("data directory is unusable"));
        assert_eq!(fs::read(target).expect("unchanged sentinel"), b"keep");
        assert!(!fixture.data.join("root-key.wrapped").exists());
    }
}
