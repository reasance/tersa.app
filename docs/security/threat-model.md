# Threat model

## Scope and security objective

tersa is a terminal Gmail client for macOS and Linux
([ADR 0031](../architecture/adr-0031-tui-only-pivot.md)). It is a
consumer/prosumer tool, not a regulated archive or e-discovery system. The
objective is to keep mailbox content, credentials, cryptographic material, and
behavioral metadata inside their intended trust boundary unless the user acts
explicitly.

## Protected assets

| Asset | Required protection |
|---|---|
| OAuth authorization codes, refresh tokens, and access tokens | PKCE; refresh tokens only inside the encrypted account database; access tokens in memory only; never in logs, process arguments, or repository files |
| Gmail messages, headers, addresses, labels, drafts, and pending actions | TLS to Google; encrypted local persistence; per-account isolation; bounded retention |
| Root and derived encryption keys | CSPRNG generation; OS keyring or passphrase-wrapped storage; HKDF domain separation; zeroization; no export or diagnostics |
| SQLCipher databases, WAL/journals, cached bodies, and attachments | Encryption at rest; owner-only file modes; integrity checks; logical deletion does not guarantee secure erasure |
| Rendered text in the terminal | Sanitized against terminal control sequences before display |
| Composition temp files | Owner-only directory under the data directory; removed after the editor exits |
| Logs and crash output | No content, addresses, queries, tokens, or stable user identifiers |
| Release artifacts and dependency graph | Locked dependencies; license and advisory review; checksums published with releases |

## Trust boundaries

1. Google OAuth and the Gmail API are external trusted services; their
   responses remain untrusted input until protocol validation succeeds.
2. The operating system, its keyring service, the terminal emulator, the
   user's `$EDITOR`, and the system browser are platform boundaries outside
   the project's control.
3. The Rust core owns domain invariants. Adapters own OS capabilities and may
   not leak OS types into core crates (enforced by `cargo xtask architecture`).
4. Each account database is an isolation boundary; unified views read through
   application use cases, never across account keys.
5. Provider content crosses into a narrower representation before display:
   sanitized text only. No HTML engine and no remote fetch exist.

## Attacker capabilities

In scope: a remote sender crafting malicious MIME, HTML, links, filenames, or
attachments, including terminal escape and bidirectional-text payloads; a local
unprivileged process from another user, or one racing the loopback OAuth
listener; a stolen powered-off device; a malicious or compromised dependency;
malformed Gmail history and ambiguous send outcomes; accidental disclosure by
logs or temp files.

The attacker does not initially hold the user's login session, keyring
unlock, passphrase, or Google credentials.

## Threats, controls, and residual risk

| Threat | Controls | Residual risk / status |
|---|---|---|
| OAuth interception or callback forgery | Authorization Code with PKCE S256, exact state and redirect validation, IPv4 loopback listener bound to an ephemeral port, single-use session | Implemented (T1): the listener accepts only the matching `state` |
| Token or key disclosure on a stolen device | Root key in OS keyring or passphrase-wrapped; refresh tokens inside SQLCipher; owner-only file modes | Implemented (T1). Keyring items are readable by same-user code once unlocked |
| Same-user malware | None beyond OS keyring prompts on macOS | **Accepted residual** (ADR 0031): no process isolation between token and root key; Linux Secret Service has no per-app ACL. Passphrase mode narrows at-rest exposure only |
| Terminal escape injection (ANSI/OSC/DCS, title or clipboard writes, cursor tricks) | All provider-derived strings pass a sanitizer that strips C0 except newline/tab, C1, ESC, DEL; TUI renders only the sanitized type; tersa itself never emits OSC 8, OSC 52, or title sequences; fuzzing | Implemented (T2a–T2b) with deterministic randomized tests over HTML and MIME fragments and hostile-render tests of every message part; fuzz targets are not built yet |
| Bidirectional-text, invisible-character, and homoglyph spoofing | Bidi embeddings, overrides, isolates, and marks; zero-width and invisible formatting characters; and Tag-block characters are removed; the message view shows each address next to its display name, and the inbox list shows the address instead of a display name that contains `@` or its fullwidth or small forms | Homoglyphs and confusable scripts remain a residual |
| Malicious HTML, tracking pixels | HTML converted to text with size and depth limits; no remote resource is ever fetched; links listed and opened only on explicit keypress after showing the URL | Conversion implemented (T2a): linear, capped, no fetch. Opening links is not implemented yet |
| Malicious attachment or decompression bomb | Fetch on demand, size limits, sanitized filenames, never auto-opened | Planned (T5–T6) |
| Sync replay, ambiguity, or duplicate send | Transactional history cursor, idempotent desired state, bounded retries, client-generated Message-ID, reconciliation after ambiguous outcomes | Planned (T4–T5) |
| Cross-account access | `(AccountId, MessageId)` routing, per-account database/key/session, application-level 200-row unified query, independent sync workers, fresh scoped views and stale-result rejection | Implemented in source with automated isolation tests. Two-real-account macOS isolation/offline acceptance remains pending |
| Accidental cache reset or unsafe preview | Exact account resolution; existing-only private lock/readonly registry and profile; unreadable peers fail email resolution; completed `yes` line or explicit `--yes`; same lock/installation through transactional clear and bounded sync | Implemented. Missing/unclaimed/unsafe state is not provisioned or repaired. A committed clear can be followed by failed sync and partial new cache; the command fails nonzero and distinguishes that phase |
| Worker shutdown releases secrets or storage owners prematurely | Restore terminal, signal all workers, cancel owned futures, retain and join native-call owners before releasing installation lock | Implemented. Native calls can delay exit beyond the cooperative grace period; no forced abort. Already-dispatched DNS may finish detached without store state |
| Composition temp-file exposure | Owner-only directory, removal after editor exit | Plaintext exists on disk while the editor runs; editor swap/backup files are outside tersa's control |
| Dependency or release compromise | `Cargo.lock`, `cargo deny` (licenses, sources, RustSec advisories), DCO, review, published checksums | Upstream compromise and reproducibility gaps remain |
| Stale vendored OpenSSL on Linux | Linux binaries statically link `openssl-src`; `cargo deny` RustSec advisory check on every PR that changes code; an OpenSSL advisory triggers a dependency bump and a new release | Users stay exposed until they update tersa; the OS cannot patch it |

## Cache reset limits and remaining work

`tersa account reset <account> [--yes]` clears only local messages and sync
freshness for the resolved existing account, then performs the normal bounded
recent-mail sync. The clear preserves account setup and credentials; the sync
retains ordinary token rotation and revoked-token deletion. Continued
authorization and restoration of every old cached message are not guaranteed.
No secure erasure or incompatible-schema repair is claimed. The separate
new-ID/consent/quarantine protocol in
[ADR 0026](../architecture/adr-0026-multi-account-and-unified-mailbox.md) remains
planned.

Readonly pre-confirmation APIs do not make every installation method readonly.
Generic store openers remain create-capable; reset preview excludes them, and
normal writer access follows a successful existing-only clear. The lock is
advisory coordination between cooperating processes, not a defense against
compromised same-user code replacing paths. An owner-only coordination lock may
be created and existing SQLite SHM bookkeeping may change during preview.

Capability upgrade, account-local FTS, drafts/outbox, app lock and later roadmap
milestones remain planned. Source review, automated fixtures and CI do not close
the pending two-real-account macOS isolation and offline acceptance gate or
establish full ADR/MVP completion.

## Explicit exclusions

No protection is claimed against root/privileged malware, a compromised user
session while tersa is unlocked, a compromised terminal emulator or editor,
or hardware attacks on a running machine. tersa does not protect the Google
account after Google credentials are compromised, provide metadata anonymity,
or keep user-saved attachments encrypted.

AI, MCP, OpenPGP, and relay features are closed boundaries; each requires a
data-flow update and security review before code may reach them.

## Review triggers

Revisit this model when a persistence surface, network egress path, renderer,
external process invocation, or secret-storage mode is added or changed.
