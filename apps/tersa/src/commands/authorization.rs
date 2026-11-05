// This Source Code Form is subject to the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Selected-account CLI consent; durable grant success is separate from follow-up mail work.
use super::{Context, executor, require_installation};
use std::io::Write;
use tersa_application::mailbox::AccountId;
use tersa_presentation::terminal::SafeText;
use tersa_sync_runtime::{AddedAccount, Installation, Runtime};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Mode {
    Upgrade,
    Reconnect,
}
pub fn account_upgrade(context: &Context, raw: &str) -> Result<(), String> {
    run(context, raw, Mode::Upgrade)
}
pub fn account_reconnect(context: &Context, raw: &str) -> Result<(), String> {
    run(context, raw, Mode::Reconnect)
}

fn selected<T>(
    installation: &Installation,
    raw: &str,
    run: impl FnOnce(AccountId) -> Result<T, String>,
) -> Result<T, String> {
    let account = super::reset::resolve_existing(installation, raw)
        .map_err(|message| SafeText::single_line(&message).to_string())?;
    // Authenticate this exact existing profile before entering browser consent.
    installation
        .account_email_existing(&account)
        .map_err(|error| error.to_string())?;
    run(account)
}
async fn authorize(
    runtime: &Runtime,
    account: &AccountId,
    mode: Mode,
    browser: impl FnOnce(&str),
) -> Result<AddedAccount, String> {
    match mode {
        Mode::Upgrade => runtime.upgrade_account(account, browser).await,
        Mode::Reconnect => runtime.reconnect_account(account, browser).await,
    }
    .map_err(|error| error.to_string())
}
fn run(context: &Context, raw: &str, mode: Mode) -> Result<(), String> {
    if raw.trim().is_empty() {
        return Err("an existing account is required".to_owned());
    }
    context.config.oauth_client(&context.paths.config_file())?;
    let locked = require_installation(context)?;
    selected(&locked.installation, raw, |account| {
        let runtime = super::runtime(context, std::sync::Arc::clone(&locked.installation))?;
        let executor = executor()?;
        let added = executor.block_on(authorize(&runtime, &account, mode, super::open_browser))?;
        let followup = added.first_sync.is_ok();
        finish(&mut std::io::stdout().lock(), &account, mode, added)?;
        if followup {
            match executor.block_on(super::history::cycle(&runtime, &account)) {
                Ok(notice) => println!("{notice}"),
                Err(notice) => eprintln!(
                    "Grant remains saved. {notice} Use `tersa sync {}` to resume mail work.",
                    SafeText::single_line(account.as_str())
                ),
            }
        }
        Ok(())
    })
}
fn finish(
    output: &mut impl Write,
    selected: &AccountId,
    mode: Mode,
    added: AddedAccount,
) -> Result<(), String> {
    if &added.account != selected {
        return Err("unexpected authorization binding; reload account status".to_owned());
    }
    let account = SafeText::single_line(selected.as_str());
    let action = match mode {
        Mode::Upgrade => "Modify grant saved",
        Mode::Reconnect => "Grant reconnected with its stored capability",
    };
    writeln!(output, "{account}: {action}.").map_err(|_error| {
        "grant saved, but its result could not be displayed; reload account status".to_owned()
    })?;
    let notice = match added.first_sync {
        Ok(report) => format!(
            "Compatibility snapshot: {}. Bounded History follow-up runs separately.",
            super::describe_report(report)
        ),
        Err(error) => format!(
            "Grant saved; follow-up snapshot failed: {error}. Use `tersa sync {account}` to resume mail work."
        ),
    };
    writeln!(output, "{}", SafeText::single_line(&notice))
        .map_err(|_error| "grant saved, but follow-up status could not be displayed".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::LocalFixture;
    use std::{cell::Cell, sync::Arc};
    #[test]
    fn existing_selection_precedes_consent_and_both_modes_preserve_grant_on_missing_config() {
        let fixture = LocalFixture::new();
        let calls = Cell::new(0);
        for raw in ["", "acct_", "unknown"] {
            assert!(
                selected(&fixture.installation, raw, |_| {
                    calls.set(calls.get() + 1);
                    Ok(())
                })
                .is_err()
            );
        }
        assert_eq!(calls.get(), 0);
        let executor = executor().expect("executor");
        let runtime = Runtime::local(Arc::clone(&fixture.installation));
        for mode in [Mode::Upgrade, Mode::Reconnect] {
            let before = fixture
                .installation
                .open_store(&fixture.accounts[0])
                .expect("store")
                .load_credential_snapshot(&fixture.accounts[0])
                .expect("snapshot");
            selected(
                &fixture.installation,
                fixture.accounts[0].as_str(),
                |account| {
                    assert_eq!(account, fixture.accounts[0]);
                    assert!(
                        executor
                            .block_on(
                                authorize(&runtime, &account, mode, |_| calls.set(calls.get() + 1))
                            )
                            .is_err()
                    );
                    Ok(())
                },
            )
            .expect("selected account");
            assert_eq!(
                fixture
                    .installation
                    .open_store(&fixture.accounts[0])
                    .expect("store")
                    .load_credential_snapshot(&fixture.accounts[0])
                    .expect("snapshot"),
                before
            );
        }
        assert_eq!(calls.get(), 0, "missing OAuth must never launch a browser");
    }
    #[test]
    fn committed_selected_grant_and_followup_failure_have_distinct_cli_outcomes() {
        let fixture = LocalFixture::new();
        let account = &fixture.accounts[0];
        let store = fixture.installation.open_store(account).expect("store");
        let before = store.load_credential_snapshot(account).expect("snapshot");
        store
            .replace_credential_snapshot(
                &before,
                tersa_application::AccountCapability::Modify,
                &tersa_store_sqlcipher::StoreCredential::Active(zeroize::Zeroizing::new(
                    "synthetic-reconnected".to_owned(),
                )),
            )
            .expect("actual synthetic grant commit");
        let committed = store.load_credential_snapshot(account).expect("committed");
        let mut output = Vec::new();
        finish(
            &mut output,
            account,
            Mode::Reconnect,
            AddedAccount {
                account: account.clone(),
                already_present: true,
                first_sync: Err(tersa_sync_runtime::FlowError::Configuration),
            },
        )
        .expect("grant remains successful");
        let text = String::from_utf8(output).expect("text");
        assert!(text.contains("Grant reconnected with its stored capability"));
        assert!(text.contains("Grant saved; follow-up snapshot failed"));
        assert!(text.contains(&format!("tersa sync {}", account.as_str())));
        assert_eq!(
            store
                .load_credential_snapshot(account)
                .expect("after report"),
            committed
        );
    }
}
