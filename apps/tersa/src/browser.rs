// This Source Code Form is subject to the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Optional external browser launch, independent of account-task cancellation.
//!
//! xdg-open may remain the desktop application for a long time (its manual's
//! EXIT CODES section). Never kill or wait for it when consent finishes or an
//! account future is cancelled. Keep at most five immediate child handles and
//! reap finished launchers nonblocking on UI ticks/launch. A full/unavailable
//! launcher registry leaves the already-published sanitized URL as fallback.
//! Running external applications may outlive tersa; descendants are not owned.
//! No account, credential, callback task or installation lock is retained here.

use std::{
    process::{Child, Command, Stdio},
    sync::Mutex,
};
const MAX_LAUNCHERS: usize = 5;
static LAUNCHERS: Mutex<Launchers> = Mutex::new(Launchers {
    children: Vec::new(),
});
struct Launchers {
    children: Vec<Child>,
}
impl Launchers {
    fn reap(&mut self) {
        self.children
            .retain_mut(|child| !matches!(child.try_wait(), Ok(Some(_))));
    }
    fn launch(&mut self, mut command: Command) -> bool {
        self.reap();
        if self.children.len() >= MAX_LAUNCHERS {
            return false;
        }
        match command.spawn() {
            Ok(child) => {
                self.children.push(child);
                true
            }
            Err(_error) => false,
        }
    }
}
// Child::drop neither waits nor kills. In particular, do not add a cancellation
// Drop implementation: the immediate PID itself can be the user's application.
pub(crate) fn command(url: &str) -> Command {
    let mut command = Command::new(if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    });
    command
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}
pub(crate) fn launch(url: &str) -> bool {
    LAUNCHERS
        .lock()
        .is_ok_and(|mut launchers| launchers.launch(command(url)))
}
pub(crate) fn reap() {
    if let Ok(mut launchers) = LAUNCHERS.lock() {
        launchers.reap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn provider_text_is_one_argv_value_without_a_shell() {
        let url = "https://accounts.google.com/o/oauth2/auth?state=$(not-a-command);anything";
        let command = command(url);
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            vec![std::ffi::OsStr::new(url)]
        );
        assert!(matches!(
            command.get_program().to_str(),
            Some("open" | "xdg-open")
        ));
    }
    #[test]
    fn external_application_survives_registry_drop_and_is_not_waited_on() {
        // Only a task-owned native helper is launched, never a browser. Reaping
        // after drop proves drop neither killed the helper nor waited/reaped it.
        let child = Command::new("/bin/sleep")
            .arg("0.03")
            .spawn()
            .expect("synthetic external helper");
        let pid = rustix::process::Pid::from_raw(i32::try_from(child.id()).expect("pid fits"))
            .expect("child pid");
        let registry = Launchers {
            children: vec![child],
        };
        drop(registry);
        let status = rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::empty())
            .expect("drop did not reap child")
            .expect("child exited")
            .1;
        assert_eq!(
            status.exit_status(),
            Some(0),
            "drop did not kill the external application"
        );
    }
}
