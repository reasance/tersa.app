<!--
This Source Code Form is subject to the terms of the Mozilla Public License,
v. 2.0. If a copy of the MPL was not distributed with this file, You can obtain
one at https://mozilla.org/MPL/2.0/.
-->

# ADR 0031: Terminal-only product pivot

- Status: Accepted
- Date: 2026-10-04

## Context

The product owner decided on 2026-10-03 that tersa is a **terminal (TUI)
client only**, built around portable Rust domain invariants, mailbox ports,
PKCE/token lifecycle, identity gating, bounded sync, metadata search, the Gmail
REST adapter, and SQLCipher. macOS and Linux remain supported.

Earlier architecture and removed implementation records remain in Git history
and at the `pre-tui-pivot` tag. This ADR defines the current architecture;
accepted future work is distinguished from implementation in the
[roadmap](../roadmap.md) and [security data flow](../security/data-flow.md).

## Decision

### Product

- tersa is one Rust binary, `tersa`, that runs a full-screen terminal UI.
  Non-interactive subcommands (`account add|list|remove`, `sync`, `doctor`)
  share the same core.
- Supported platforms are **macOS and Linux** (x86_64 and aarch64). Windows
  and graphical clients are out of scope.
- The MVP is a full client: multi-account with a unified inbox, reading,
  search, offline reopen, triage (archive, read state, labels, trash, undo),
  and composition (local-first drafts, reply, forward, attachments, and an
  idempotent outbox). Composition uses `$EDITOR`.
- Planned distribution is a Homebrew tap with prebuilt terminal binaries.
- Gmail access remains the official Gmail API with OAuth 2.0 PKCE and a
  loopback redirect. Users configure their own Google Cloud "Desktop app"
  OAuth client until the project has a Google-verified client.

### Retained constraints

ADR 0006 A3 (no project-operated backend) and A4 (OSI-approved production
licensing) remain in force. Encrypted local persistence, bounded sync and
cache, the official Gmail API, and performance as a primary constraint
(ADR 0022) remain in force.

### Secrets and storage

- One random 32-byte installation root key. Purpose-separated keys (registry
  SQLCipher key, per-account SQLCipher keys, registry dedup HMAC key) are
  derived from it with HKDF, reusing the ADR 0019 and ADR 0026 framing.
- The root key is held by the operating-system keyring (macOS login
  Keychain, Linux Secret Service). An optional passphrase wraps the root key
  with Argon2id and an AEAD before it is stored. When no keyring is available,
  a passphrase-wrapped file is the fallback.
- OAuth refresh tokens are stored inside the owning account's SQLCipher
  database, not as separate keyring items.
- Paths follow XDG on both platforms (`$XDG_CONFIG_HOME/tersa`,
  `$XDG_DATA_HOME/tersa`).

Accepted residual: without separately signed processes there is no runtime
barrier between the refresh token and the root key inside one user account.
Same-user code that can read the keyring item, or capture the passphrase, can
decrypt local data. Linux Secret Service has no per-application access
control. These are the current token-custody residuals recorded in ADR 0024.

### TLS and native crypto

- macOS uses the system TLS (Security.framework through `native-tls`) and
  CommonCrypto for SQLCipher.
- Linux release binaries statically link one vendored OpenSSL, shared by
  `reqwest` (`native-tls-vendored`) and SQLCipher
  (`bundled-sqlcipher-vendored-openssl`), so they do not depend on the host's
  libssl or libcrypto. rustls was considered and rejected because SQLCipher
  needs OpenSSL on Linux anyway; one crypto library keeps the binary smaller.
- Consequence: the vendored OpenSSL receives no operating-system security
  updates. Every OpenSSL advisory that affects the linked version requires
  bumping `openssl-src` and publishing new Linux binaries; the RustSec
  advisory check in `cargo deny` and release checks must track it.

### Hostile content in a terminal

- Every provider-derived string is sanitized before it reaches the terminal.
  The removal set is: C0 controls except newline and tab (including ESC, which
  starts ANSI, OSC, and DCS sequences), DEL, C1 controls (U+0080–U+009F);
  bidirectional embeddings, overrides, and isolates (U+202A–U+202E,
  U+2066–U+2069) and marks (U+200E, U+200F, U+061C); zero-width and invisible
  formatting characters (U+200B–U+200D, U+2060, U+FEFF); and the Tag block
  (U+E0000–U+E007F). The TUI renders only the sanitized type.
- HTML bodies are converted to text in Rust with size and depth limits. No
  remote resource is ever fetched. Links become a numbered list and open only
  on an explicit keypress after the URL is shown.
- Outbound, tersa never writes OSC 8 hyperlinks, OSC 52 clipboard writes, or
  window-title sequences. A future "copy" action uses the OS clipboard command
  (`pbcopy`, `wl-copy`, or `xclip`) through an argument vector, only on an
  explicit keypress.
- Attachments are saved with sanitized names and never opened automatically.
- MIME parsing, HTML-to-text conversion, and the sanitizer get fuzz targets.

### Governance

- `cargo xtask verify` (format, Clippy with warnings denied, tests, doc tests,
  rustdoc, a default-feature check, and a layering check) on Linux and
  macOS, plus `cargo deny` (including RustSec advisories) and `typos`, are
  the merge checks. CI stays minimal: fast and cheap is a requirement.
- The layering check enforces only durable rules: core crates under
  `crates/` forbid `unsafe` and depend only on the core and external crates
  allowlisted for each of them (computation crates only, plus `getrandom` for
  the system CSPRNG); nothing depends on `apps/` or `xtask`.
- DCO sign-offs are checked on pull requests and on pushes to `main`.
- ADRs are written only for decisions that change architecture, security
  boundaries, or the data model.

### Retained decisions

ADR numbers are stable; removed documents are not renumbered. Retired-only
planning and diagnostic records live in Git history rather than current guidance.

| ADR | Current decision |
| --- | --- |
| 0006 | No project-operated backend; OSI-approved production dependencies. |
| 0015–0018 | Portable mailbox contracts, Gmail REST, SQLCipher, bounded snapshot sync. |
| 0019 | Purpose-separated HKDF, trusted provisioning, strict read-only store access and filesystem residuals. |
| 0022 | Performance as a primary, continuously measured constraint. |
| 0023–0024 | Rust loopback OAuth, immutable subject identity gate, in-process lifecycle, encrypted token custody and recovery residuals. |
| 0026 | Account isolation and registry decisions; bounded unified-query and reset/FTS plans. |
| 0027–0028 | Future capability-gated History/commands, durable drafts and reconciled outbox. |
| 0029 | Sanitized terminal content, no remote resource fetch, validated editor/MIME boundary. |
| 0030 | Future encrypted blob publication/recovery, allocated-byte budget and vault-authenticated lock. |

### Initial TUI performance budgets

Measured on the developer's reference machines with a warm cache of at least
10,000 messages: first frame under 100 ms, top-50 list query under 20 ms,
idle resident memory under 50 MiB, and a stripped release binary under
15 MB. A budget breach blocks the slice that introduced it unless an accepted
ADR changes the budget.

## Delivery

| Milestone | Scope |
| --- | --- |
| T0 | Terminal architecture baseline, portable workspace boundaries, minimal `xtask`. |
| T1 | Portable adapters, `crates/keys`, `adapters/vault`, Rust loopback OAuth, in-process token service, `tersa account add`. |
| T2 | Read-only TUI: inbox, thread, search, offline reopen, background sync, sanitizer, HTML to text. |
| T3 | Multi-account registry and unified inbox. |
| T4 | Triage with history sync and pending actions. |
| T5 | Composition, drafts, and the idempotent outbox. |
| T6 | Encrypted cache budget, eviction, and lock. |
| T7 | macOS release workflow, Homebrew tap, and release signing. |
| T8 | Linux validation with real consent (desktop and headless), Linux release binaries, and Homebrew on Linux. |

T1 through T7 are validated manually on macOS; Linux keeps CI coverage on
every pull request and gets its manual validation and packaging in T8.

## Consequences

- Core crates retain pure contracts; platform/network/storage behavior belongs
  to adapters, composed by the terminal app and account runtime.
- The current tree contains the terminal product and its applicable decisions;
  Git history and tags retain removed implementation records.
- On macOS, keyring access control is tied to the binary's code signature.
  Unstably signed builds re-prompt for Keychain access; T7 decides the
  release-signing approach.

## Non-claims

This ADR implements no TUI, keyring, or passphrase code. It does not claim
that the residuals above are acceptable for every threat model, and it does
not claim Google restricted-scope verification.
