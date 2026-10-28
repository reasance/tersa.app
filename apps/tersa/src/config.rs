// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Paths and the user configuration file.
//!
//! Both platforms use XDG locations so terminal users find files where they
//! expect them: `$XDG_CONFIG_HOME/tersa/config.toml` (default
//! `~/.config/tersa`) and `$XDG_DATA_HOME/tersa` (default `~/.local/share/tersa`).
//! `TERSA_CONFIG_DIR` and `TERSA_DATA_DIR` override them.

use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use tersa_sync_runtime::OAuthClient;
use tersa_vault::BackendChoice;
use zeroize::Zeroizing;

const CONFIG_FILE: &str = "config.toml";
const CONFIG_LIMIT: u64 = 64 * 1024;

#[derive(Debug)]
pub struct Paths {
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
}

impl Paths {
    pub fn discover() -> Result<Self, String> {
        Ok(Self {
            config_dir: resolve("TERSA_CONFIG_DIR", "XDG_CONFIG_HOME", ".config")?,
            data_dir: resolve("TERSA_DATA_DIR", "XDG_DATA_HOME", ".local/share")?,
        })
    }

    pub fn config_file(&self) -> PathBuf {
        self.config_dir.join(CONFIG_FILE)
    }
}

fn resolve(override_var: &str, xdg_var: &str, home_relative: &str) -> Result<PathBuf, String> {
    if let Some(path) = absolute_env(override_var) {
        return Ok(path);
    }
    if let Some(base) = absolute_env(xdg_var) {
        return Ok(base.join("tersa"));
    }
    let home = absolute_env("HOME").ok_or("HOME is not set to an absolute path")?;
    Ok(home.join(home_relative).join("tersa"))
}

/// The XDG spec says relative values must be ignored.
fn absolute_env(name: &str) -> Option<PathBuf> {
    env::var_os(name)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    #[serde(default)]
    google: GoogleSection,
    #[serde(default)]
    vault: VaultSection,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct GoogleSection {
    client_id: Option<String>,
    client_secret: Option<String>,
}

impl std::fmt::Debug for GoogleSection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("GoogleSection([REDACTED])")
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct VaultSection {
    backend: Option<String>,
    passphrase: Option<bool>,
}

pub struct Config {
    pub client_id: Option<String>,
    client_secret: Option<Zeroizing<String>>,
    pub backend: BackendChoice,
    pub passphrase: bool,
    pub file_found: bool,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Config")
            .field("client_id_set", &self.client_id.is_some())
            .field("client_secret_set", &self.client_secret.is_some())
            .field("backend", &self.backend)
            .field("passphrase", &self.passphrase)
            .field("file_found", &self.file_found)
            .finish()
    }
}

impl Config {
    /// Synthetic configuration without reading inherited credential variables.
    #[cfg(test)]
    pub fn for_test(client_id: Option<&str>) -> Self {
        Self {
            client_id: client_id.map(str::to_owned),
            client_secret: None,
            backend: BackendChoice::File,
            passphrase: false,
            file_found: true,
        }
    }

    /// Loads `config.toml` if present, then applies `TERSA_GOOGLE_CLIENT_ID`
    /// and `TERSA_GOOGLE_CLIENT_SECRET`.
    pub fn load(path: &Path) -> Result<Self, String> {
        let (file, file_found) = match read_bounded(path) {
            Ok(text) => (
                toml::from_str::<FileConfig>(&text)
                    .map_err(|error| format!("{}: {}", path.display(), error.message()))?,
                true,
            ),
            Err(error) if error.kind() == io::ErrorKind::NotFound => (FileConfig::default(), false),
            Err(error) => return Err(format!("{}: {error}", path.display())),
        };
        let backend = match file.vault.backend.as_deref() {
            None | Some("auto") => BackendChoice::Auto,
            Some("keyring") => BackendChoice::Keyring,
            Some("file") => BackendChoice::File,
            Some(other) => {
                return Err(format!(
                    "{}: vault.backend must be \"auto\", \"keyring\", or \"file\", not {other:?}",
                    path.display()
                ));
            }
        };
        let client_id = env::var("TERSA_GOOGLE_CLIENT_ID")
            .ok()
            .or(file.google.client_id)
            .filter(|value| !value.trim().is_empty());
        let client_secret = env::var("TERSA_GOOGLE_CLIENT_SECRET")
            .ok()
            .or(file.google.client_secret)
            .filter(|value| !value.trim().is_empty())
            .map(Zeroizing::new);
        Ok(Self {
            client_id,
            client_secret,
            backend,
            passphrase: file.vault.passphrase.unwrap_or(false),
            file_found,
        })
    }

    pub fn has_client_secret(&self) -> bool {
        self.client_secret.is_some()
    }

    pub fn oauth_client(&self, path: &Path) -> Result<OAuthClient, String> {
        let client_id = self.client_id.clone().ok_or_else(|| {
            format!(
                "no Google OAuth client configured. Create a \"Desktop app\" OAuth client in \
                 Google Cloud Console (Gmail API enabled), then add to {}:\n\n\
                 [google]\nclient_id = \"….apps.googleusercontent.com\"\n\
                 client_secret = \"…\"",
                path.display()
            )
        })?;
        Ok(OAuthClient {
            client_id,
            client_secret: self.client_secret.clone(),
        })
    }
}

fn read_bounded(path: &Path) -> io::Result<String> {
    let metadata = fs::metadata(path)?;
    if metadata.len() > CONFIG_LIMIT {
        return Err(io::Error::other("the configuration file is too large"));
    }
    fs::read_to_string(path)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use tersa_vault::BackendChoice;

    use super::Config;

    fn temp_file(name: &str, contents: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("tersa-config-{name}-{}.toml", std::process::id()));
        fs::write(&path, contents).expect("write");
        path
    }

    #[test]
    fn reads_google_and_vault_sections() {
        let path = temp_file(
            "full",
            "[google]\nclient_id = \"id.apps.googleusercontent.com\"\nclient_secret = \"s\"\n\
             [vault]\nbackend = \"file\"\npassphrase = true\n",
        );
        let config = Config::load(&path).expect("load");
        fs::remove_file(&path).expect("cleanup");
        assert!(config.file_found);
        assert_eq!(config.backend, BackendChoice::File);
        assert!(config.passphrase);
        assert!(config.has_client_secret());
        assert!(!format!("{config:?}").contains("\"s\""));
    }

    #[test]
    fn rejects_unknown_keys_and_backends() {
        let path = temp_file("unknown", "[google]\nclient = \"x\"\n");
        assert!(Config::load(&path).is_err());
        fs::write(&path, "[vault]\nbackend = \"cloud\"\n").expect("write");
        assert!(Config::load(&path).is_err());
        fs::remove_file(&path).expect("cleanup");
    }

    #[test]
    fn a_missing_file_is_not_an_error() {
        let config = Config::load(&PathBuf::from("/nonexistent/tersa/config.toml")).expect("load");
        assert!(!config.file_found);
        assert_eq!(config.backend, BackendChoice::Auto);
    }
}
