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
| Sync replay or ambiguous triage writes | Record-atomic History prefix/cursor, durable desired state and pre-dispatch evidence, per-item reconciliation, bounded redispatch and lifecycle guards | T4 prerequisite contract below; source implementation pending |
| Duplicate send | Client-generated Message-ID and reconciled outbox | Planned (T5), outside T4 |
| Cross-account access | `(AccountId, MessageId)` routing, per-account database/key/session, application-level 200-row unified query, independent sync workers, fresh scoped views and stale-result rejection | Implemented in source with automated isolation tests. Independent Grok 4.7 review accepted the bounded sampled macOS manual gate for `06a7e0f`; see the [redacted report](../development/t3-live-acceptance-2026-11-04.md). Six samples do not establish exhaustive isolation |
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
milestones remain planned. Source review, automated fixtures and CI alone do
not establish live acceptance. Independent Grok 4.7 review accepted closure of
the bounded sampled two-real-account macOS isolation/offline manual gate for
`06a7e0f`, as recorded in the [redacted report](../development/t3-live-acceptance-2026-11-04.md).
This does not establish exhaustive security proof, live cache-reset validation,
full ADR/MVP completion or release readiness.

## T4 threat controls and residuals

The following is the T4 prerequisite contract; source implementation and live
acceptance remain pending. Its exact contract/budgets are in
[ADR 0027](../architecture/adr-0027-gmail-modify-history-and-mailbox-commands.md),
its migration ownership in
[ADR 0017](../architecture/adr-0017-production-account-store.md#t4-account-schema-v3-prerequisite-contract)
and its sensitive-state inventory in [data flow](data-flow.md#t4-persistence-and-deletion).
T3 acceptance and the implemented reset limits above remain unchanged.

| Threat | Planned T4 control | Residual / failure behavior |
| --- | --- | --- |
| Consent confusion, implicit promotion or wrong-account upgrade | Immutable requested capability and selected-account/expected-subject intent; atomic token/capability commit; account permit and generation fences; duplicate Connect cannot overwrite a grant | Absent scope inherits only the bound request/stored capability; explicit insufficient/cross-capability responses provide no usable access. Refresh never promotes ReadOnly. Current readonly APIs remain compatible during staging. |
| Stale credential or action after upgrade | Persisted Modify plus current Modify-accepted access/generation required for mutation; invalidate sessions under account permit | Generation is process-local, not a schema column. Restart drops sessions and durable Dispatching is Ambiguous. No SQL transaction/mutex spans HTTP. Broker subject permits/sole custody remain; stale completions fail closed. Same-user code is still inside the custody boundary. |
| Malformed/oversized History or skipped progress | Canonical 1-32 digit IDs, one complete record/data/cursor transaction, 500 records/page, 4 pages/2,000 records, 1,000 unique IDs/record, local 10,000-reference/page processing budget and 2 MiB JSON cap | Reserve whole-record metadata within 1,000 lookups/cycle. Local truncation returns contiguous whole-record progress and an explicit local indicator, never a provider token/response-head checkpoint. Invalid envelopes fail before application; over-limit/undecidable record stays unapplied. No-progress RecoveryRequired permits explicit retry or guarded reset after pending resolution/abandon; never automatic non-404 fallback. |
| Expired History erases intent or misses concurrent changes | Capture baseline before bounded snapshot; metadata/baseline commit together; keep pending evidence and independently reconcile it | Only absent cursor/History-cursor 404 takes fallback. Truncated keep-100 is valid recent-cache coverage; snapshot absence never settles commands. Optional 25 bodies follow commit and may fail separately. |
| Crash, cancellation or lost response repeats writes | Queued has no mailbox mutation attempted (read-only preflight/network is possible); durable Dispatching precedes mutation; restart treats it as Ambiguous; FIFO recovery blocks later writes | Successful empty batchModify is acknowledgement, not failure, and still needs per-item observation. Read retry helper never handles writes. No distributed atomicity or provider idempotency is assumed. |
| Queue/evidence exhaustion | Atomic quotas of 32 nonterminal commands/4,096 references/account; 1,000 targets/command; pin unresolved/undo targets; 1,000 minimal GETs/pass, at most 3 total automatic dispatch attempts including initial, with fresh unmet observation before further automatic attempts | Refuse admission rather than evict unresolved evidence. NeedsAttention retains recovery. Compact terminal item rows; retain at most 128 summaries plus one undo candidate. Unknown/expired replay ID cannot dispatch. |
| Partial membership or guessed label identity | Complete observed membership up to 512 labels or fail closed; catalog up to 500; exact encrypted names 1-1,024 UTF-8 bytes; validated account-bound User IDs | No omitted membership is assumed absent. Catalog overflow disables catalog-dependent reconciliation. Ambiguous create adopts exactly one observed match; zero/multiple matches never permit automatic recreation. A fresh complete zero-match catalog requires explicit duplicate-risk confirmation for one user-authorized create; multiple matches never retry creation. No read-after-write guarantee is claimed. |
| Recovery has no legal exit or abandonment falsely claims success | Complete/fully resolved Partial (including TargetMissing, even with zero successes) are terminal; only Complete message-state qualifies for undo. Ambiguous/NeedsAttention allow fresh-reconciliation Retry or explicit Abandon | Retry authorizes at most one guarded dispatch without resetting automatic budgets; satisfied state settles without mutation and failed reconciliation stays NeedsAttention. Abandon warns Gmail may already have applied the operation and automatic recovery stops; retain terminal Abandoned before releasing FIFO/pins/quota/reset/remove guards. No retry/requeue of abandoned IDs; no success/rollback claim. |
| Scope permits unintended API operations | Separate Modify component, closed endpoint/payload and desired-field maps; readonly negative guards; no arbitrary system-label/path mutation | Provider scope is broader than the product surface. No classification labels, permanent message delete, mute, compose/send/draft/watch or dedicated trash/untrash route is exposed. |
| Undo overwrites another device's changes, falsely claims offline eligibility or blocks itself | Last Complete message-state command only; admission refuses pre-existing nonterminal commands. Offline admission persists conditional compensation/expected post-state without mutation/eligibility claim. The admitted undo is Queued; do not reapply the admission gate to itself or later queued work at dispatch; FIFO prevents overtaking/self-deadlock | After reconnect and before any dispatch, fresh reconciliation validates the entire target set/required User labels and touched expected-post-state fields. Any mismatch refuses all compensation without writes; a pass restores touched pre-state only. Provider changes after comparison remain a no-CAS residual. No label-CRUD/Partial/Ambiguous undo, provider rollback or cross-account atomicity. |
| Reset, removal, identity change or pruning destroys recovery | Every nonterminal command, including Queued, blocks reset/remove; cancel Queued, settle or explicitly abandon first; guard release requires terminal summary commit. Identity replacement refuses destructive change; pin pending/undo targets | Guarded reset clears cursor/terminal/undo/membership but preserves capability/grant/identity/recovery. Removal/purge deletes T4 rows only after guard. Abandon is explicit retained disposition, not silent cleanup. These protections are future T4 work, not current reset behavior. |
| Format rollback destroys the only readable state | Owned v1/v2-to-v3 writer transaction with complete canonical set; readonly v1/v2/v3 do not migrate; registry v1/identity algorithm 2 unchanged | Old binaries reject v3. No implicit downgrade/reset/quarantine or plaintext backup. Existing SQLCipher path/sidecar/identity residuals remain. |

Provider labels, local-read presentation and pending desired state stay distinct;
only provider observations settle commands. Recent remains the default view;
Unknown membership remains accessible there and is excluded from observed-label
filters. Sanitized, bounded terminal documents carry no raw scopes, tokens or
provider responses. Opening a message adds no provider write.

Retain ADR 0024's stranded under-scoped-grant residual: rejected completion has
no validated revocation handle, persists/revokes nothing and requires manual
Google Account revocation guidance. Valid rejected-refresh rotation may be kept
only as a revocation handle, never usable access. Google grant-wide revocation
can affect another installation; no unconditional revoke is introduced.
Signature-unverified identity decoding remains restricted to the hardened token
back channel with issuer/audience/subject/freshness validation, not a new token
source. Same-user root-key/token co-residence and Linux Secret Service's lack
of per-app ACL remain accepted residuals.

New T4 state stays in account SQLCipher and encrypted WAL/journals with existing
owner-only/no-follow checks. No plaintext sidecar, content/identity diagnostic,
backup/export surface or app-lock behavior is introduced. External backups can
retain sensitive encrypted records; logical deletion promises no secure erase
or removal from backups. Source rollback cannot undo committed provider writes.
Deterministic fixtures/CI prove bounded contracts, not live provider success;
candidate-bound authorized macOS acceptance remains separate from Linux
consent, release or exhaustive isolation proof.

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
