# Roadmap

tersa is a terminal Gmail client for macOS and Linux. The baseline is
[ADR 0031](architecture/adr-0031-tui-only-pivot.md). Earlier plans remain in
Git history.

Every milestone ships as reviewed pull requests that pass `cargo xtask verify`
on Linux and macOS. A failed milestone check changes the plan; it is not
accepted as temporary debt.

T1 through T7 are validated manually on macOS only. Linux keeps full CI
coverage on every pull request that changes code, but real-consent runs,
Linux release binaries, and Linux packaging are deferred to T8 so that the
product is finished on one platform first. T8 also revisits the `deny.toml` ignores for the zbus 5
unmaintained notices (RUSTSEC-2026-0370, -0371, -0372).

| Milestone | Scope | Done when |
|---|---|---|
| T0 — Terminal baseline | ADR 0031; portable workspace, minimal `xtask`, terminal architecture docs | Workspace verifies on Linux and macOS |
| T1 — Portable foundation | Adapters made portable and renamed; TLS and SQLCipher crypto from the OS on macOS and from one static vendored OpenSSL on Linux; `crates/keys`; `adapters/vault` (keyring, optional passphrase, passphrase-only fallback); XDG paths; Rust loopback OAuth; in-process token service; BYO OAuth client config | `tersa account add` and `tersa inbox` work against a real Google account on macOS |
| T2 — Read-only TUI | `ratatui` shell; paged inbox; thread view; sanitized text; HTML to text; search; offline reopen; background sync with status; first performance harness | Hostile fixtures render safely; budgets measured in the PR |
| T3 — Multi-account | Encrypted registry; add/remove; cache-only reset; independent account sync; All/single-account inbox views | Two real accounts sync and display on macOS without cross-account leakage, including offline reopen |
| T4 — Triage | `history.list` incremental sync; archive, read state, labels, trash, undo with pending actions | Offline actions reconcile after reconnect |
| T5 — Composition | `$EDITOR` flow; MIME building; local-first drafts synced to Gmail; reply, forward, attachments; idempotent outbox | Killing tersa mid-send never produces a duplicate |
| T6 — Cache and lock | Encrypted cache budget and eviction; `:lock` and idle lock | Budget holds under a large mailbox |
| T7 — macOS distribution | Release workflow for macOS (aarch64, x86_64); Homebrew tap; release-signing decision for stable Keychain access | `brew install` works from a clean Mac |
| T8 — Linux | Real consent on a Secret Service desktop and on headless Linux with the passphrase-only vault; Linux release binaries (x86_64, aarch64) with the vendored OpenSSL; Homebrew on Linux formula; OpenSSL advisory rebuild procedure | `brew install` and `tersa account add` work on a clean Linux desktop and a headless host |

## T3 delivery status

Source implementation and automated coverage are delivered for the encrypted
registry, application-layer unified query (200-row global pages), unified
inbox, independent per-account sync/status, and Tab / Shift-Tab account views.
View changes clear search and return to a fresh inbox query; manual sync follows
the selected view while automatic scheduling continues for every account.

`tersa account reset <account> [--yes]` is delivered with existing-only readonly
preview and explicit confirmation. It clears local messages and freshness for
the resolved account, then runs normal bounded recent-mail sync with the same
registration and ordinary credential lifecycle. It is not the deferred
incompatible-schema/new-ID/quarantine protocol in
[ADR 0026](architecture/adr-0026-multi-account-and-unified-mailbox.md).

**T3 manual acceptance is pending.** Two real accounts must demonstrate macOS
isolation, independent sync, All/single-account display and offline reopen.
No candidate-specific two-account evidence has been recorded here; fixtures,
independent code review and CI do not close the table's done-when condition.
Capability upgrade, account-local FTS, drafts/outbox, app lock and T4–T8 remain
planned; this source delivery does not complete the entire ADR or MVP.

## Initial performance budgets

From ADR 0031, measured on a warm cache of at least 10,000 messages: first
frame under 100 ms, top-50 list query under 20 ms, idle resident memory under
50 MiB, stripped release binary under 15 MB.

## MVP exclusions

Full-mailbox offline, AI, MCP, OpenPGP, IMAP/SMTP, non-Gmail accounts, Google
Contacts, send-as aliases, snooze synchronization, server-side send-later,
Windows, and graphical clients.
