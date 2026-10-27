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
| T3 — Multi-account | Encrypted registry; add, remove, reset; per-account sync workers; unified inbox | Two real accounts sync and display without cross-account leakage |
| T4 — Triage | `history.list` incremental sync; archive, read state, labels, trash, undo with pending actions | Offline actions reconcile after reconnect |
| T5 — Composition | `$EDITOR` flow; MIME building; local-first drafts synced to Gmail; reply, forward, attachments; idempotent outbox | Killing tersa mid-send never produces a duplicate |
| T6 — Cache and lock | Encrypted cache budget and eviction; `:lock` and idle lock | Budget holds under a large mailbox |
| T7 — macOS distribution | Release workflow for macOS (aarch64, x86_64); Homebrew tap; release-signing decision for stable Keychain access | `brew install` works from a clean Mac |
| T8 — Linux | Real consent on a Secret Service desktop and on headless Linux with the passphrase-only vault; Linux release binaries (x86_64, aarch64) with the vendored OpenSSL; Homebrew on Linux formula; OpenSSL advisory rebuild procedure | `brew install` and `tersa account add` work on a clean Linux desktop and a headless host |

## Initial performance budgets

From ADR 0031, measured on a warm cache of at least 10,000 messages: first
frame under 100 ms, top-50 list query under 20 ms, idle resident memory under
50 MiB, stripped release binary under 15 MB.

## MVP exclusions

Full-mailbox offline, AI, MCP, OpenPGP, IMAP/SMTP, non-Gmail accounts, Google
Contacts, send-as aliases, snooze synchronization, server-side send-later,
Windows, and graphical clients.
