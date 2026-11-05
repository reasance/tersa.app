<!--
This Source Code Form is subject to the terms of the Mozilla Public License,
v. 2.0. If a copy of the MPL was not distributed with this file, You can obtain
one at https://mozilla.org/MPL/2.0/.
-->

# ADR 0017: Production account store

- Status: Accepted
- T4 v3 schema: implemented on candidate `771bacbf19766ffa3d4cbb29b981489607283c89`; live Modify acceptance is separate and has not been run
- Amended by: [ADR 0031](adr-0031-tui-only-pivot.md): portable store for macOS and Linux
- Date: 2026-07-16

## Context

The mailbox contract needs a production local implementation without widening
the shared application or domain layers. Account data must be encrypted at rest,
bound to one local account, and reject unknown schema ownership.

## Decision

`tersa-store-sqlcipher` implements `MailboxStore` for exactly one
`AccountId` and one caller-selected SQLCipher file. It accepts a zeroizing
32-byte database key, applies it through SQLCipher's raw-key FFI before schema
access, and uses WAL, foreign keys, in-memory temporary storage, secure
deletion, a bounded busy timeout, canonical schema validation, `SQLite` and `SQLCipher` integrity
checks, and no-follow opening of the canonicalized database leaf.
`IntegrityScan::Full` runs `PRAGMA integrity_check`, `PRAGMA cipher_integrity_check`,
and `PRAGMA foreign_key_check`. `IntegrityScan::Skip` omits all three walks.
Every open still sets and requires foreign-key enforcement (`PRAGMA foreign_keys = 1`),
together with the temp-store, secure-delete, and WAL checks. Enforcement does
not walk existing rows. `Skip`, including a writable display open from
`Installation::open_store_for_display`, can leave a damaged unread page or an
existing orphan row latent until a `Full` scan or until a later access reads
that page or validates that relationship. SQLCipher still authenticates each
page it reads. Bounded singleton metadata validation still runs on `Skip`.
A recognized v1 or v2 migration runs `Full` before it changes format, even
when the caller requested `Skip`.
`Installation::open_store` runs `Full` on the first successful open of that
account through the installation handle and `Skip` afterward.
`open_store_for_display` always requests `Skip` and does not record a `Full` scan.
An existing file is first inspected through an immutable read-only SQLite URI,
so rollback-journal recovery cannot modify it before ownership is established.
An empty candidate with any SQLite sidecar is rejected rather than claimed.
Only then is the canonical path reopened read-write. Before key application or
database reads, `SQLITE_FCNTL_HAS_MOVED` is issued for SQLite's `main`
database; on the bundled Unix VFS, this compares SQLite's held file with the
current pathname. A moved result, unsupported control, or control failure is a
storage failure. The pathname device/inode comparison remains defense in depth.
This closes the deterministic swap-in/open/swap-back gap without claiming that
all later path races are eliminated. Connection-local safeguards are applied
before the second ownership check, but durable WAL and secure-delete
configuration occurs only after a fresh or already-owned canonical store has
been established; a foreign file is rejected unchanged. The adapter's only
`unsafe` blocks are documented calls to `sqlite3_key` and
`sqlite3_file_control`; each borrows the live rusqlite handle only for its
synchronous call. Raw keying avoids the non-zeroizing SQL builder that a key
PRAGMA would otherwise use.

The adapter also implements the envelope-only `MailboxReader` port through
`SqlCipherMailboxReader::open_read_only`. This type opens only an existing
regular main database with existing regular `-wal` and `-shm` sidecars, uses
SQLite read-only/no-mutex/no-follow flags, and has no mutation capability.
It can read a complete cached message. Its open uses `IntegrityScan::Full`, including
`foreign_key_check`, plus exact key, owner, schema, account, bounded-decode,
and pre/post pathname-identity checks. A later read transaction on that reader
uses `Skip` for the three whole-database scans and still rechecks identity,
canonical schema, foreign-key enforcement, and bounded metadata. That reader
is not the writable display opener. Production inbox and message display use
`open_store_for_display` (`Skip`). `Installation::account_email_existing` uses
this readonly reader, so that address read does run `Full`.
The reader disables and verifies checkpoint-on-close and exposes no
creation, claim, migration, repair, checkpoint, or journal-mode operation. It
does not use `immutable=1` or a private copy. `MessageEnvelope` still contains
the existing body-derived preview; callers must treat that preview as sensitive content.

Every validated writer sets and reads back `SQLITE_FCNTL_PERSIST_WAL = 1` only
after ownership is established. The reader independently sets and reads back
the same connection-local flag before validation and requires
`journal_size_limit = -1`. This prevents a clean writer close or reader close
from deleting the sidecar pair. Missing or observably replaced sidecars fail
closed. SQLite may update coordination bytes in the existing `-shm`; tests
prove that metadata reads do not change main-database or WAL bytes.

The adapter is synchronous internally but returns lazy, runtime-free futures.
Later orchestration must poll it on a bounded blocking executor; it must not be
run on a latency-sensitive async executor thread. Each write is one SQLCipher
transaction, and a dropped unpolled future has no effect.

The implemented account schema is v3. It includes the v1 singleton binding,
messages with nullable RFC 5322 content, identity and lifecycle rows, the
nullable account email from `0002_account_email.sql`, and the complete v3
triage objects. Writable opens upgrade a recognized v1 or v2 store to v3 in
one transaction, including the email upgrade when it is still required.
Readonly opens of v1, v2, and v3 do not migrate. The separate registry is
schema v1 and the identity-hash algorithm is version 2. Only an exactly empty
database may be claimed. Ownership,
version, schema, integrity, missing identity rows, invalid SQLite types or
conversions, empty cipher versions, and decoded domain values are revalidated
and map to opaque corruption errors. SQLite operational failures, including
`NOMEM`, `IOERR`, `BUSY`, `FULL`, and `CANTOPEN`, map to opaque storage errors,
including when they occur while reading `cipher_version` or the account binding.
This includes non-OK raw-key setup results such as `SQLITE_NOMEM`; a wrong key
instead succeeds at setup and maps to corruption when the first read fails.
An envelope without content is a valid partial cache entry, so `message`
returns `None` until complete content is stored. Reads preflight SQLite types
and byte lengths before materializing user-controlled text or message bytes.
Schema inspection likewise reads at most the canonical object count plus one
and bounds every schema field before allocation. Only SQLite's literal
`sqlite_` internal-object prefix is excluded from the canonical comparison.

Blob and attachment encryption are deferred to the planned production protocol
in [ADR 0030](adr-0030-encrypted-blobs-storage-budget-and-app-lock.md).
Production store crash and integrity behavior is owned by this adapter and its
tests; no removed feasibility program supplies production evidence.

Deterministic adapter tests cover exact schema convergence and no-op reopen,
wrong-key and foreign/future/noncanonical schema rejection, orphan-sidecar and
foreign hot-journal non-mutation, preflight/reopen replacement rejection, an
opened-file swap-in/open/swap-back rejection before keying, transaction
rollback, lazy cancellation, corrupted row rejection, mutex poisoning, symlink
denial, and absence of plaintext sentinels from the database and sidecars. A
broader process-crash harness is deferred until the store adds a commit protocol
beyond one SQLCipher transaction.

Reader tests additionally cover clean standalone use, coexistence with a live
writer and WAL-resident commits, missing, non-regular, symlinked, and ordinarily
replaced sidecars, rollback journals, fresh/zero-length candidates, wrong keys
and owners, unknown schemas, invalid row values, redacted failures,
journal-size policy, unpolled futures, unchanged main/WAL bytes, and stable
main/WAL/SHM pathname identities. The bundled Unix VFS cannot descriptor-bind
the internally opened `-shm` inode to the preflight pathname and internally
opens WAL/SHM with create-capable flags. Deterministic fixtures record the
accepted same-user swap-in/open/swap-back non-detection and deletion/recreation
residual instead of claiming prevention. An absent sidecar at preflight still
fails without creation; deletion after preflight can be recreated by the VFS
before the post-read identity check fails closed.

## T4 account schema v3 prerequisite contract

This section is the v3 store contract implemented with
[ADR 0027](adr-0027-gmail-modify-history-and-mailbox-commands.md). Live Modify
acceptance is a separate record and is not claimed here.
`tersa-store-sqlcipher` remains the sole schema and
transaction owner; runtime composition does not issue SQL or migrate stores.

Recognized owned v1/v2 account stores migrate to v3 in **one writer transaction**:
include the existing email upgrade when needed, create the complete v3 object
set, update the version and canonically revalidate before commit. Preserve
binding, identity, credentials, email, lifecycle and cached messages. Existing
grants default to ReadOnly; cursor is null, queue empty and provider membership
Unknown. Registry stays v1 and identity algorithm stays 2. Foreign, unknown,
noncanonical or corrupt formats remain unwritten; failure rolls back the
migration, never resets or quarantines the only readable copy.

The first schema slice defines every v3 canonical object, including dormant
later History/command tables. The data model must hold account capability
alongside broker routing/credential state; History cursor;
provider labels and complete observed membership separate from local-read
presentation; command aggregates, full bounded targets, desired patches and
dispatch/reconciliation evidence; retained terminal summaries and the one undo
candidate's touched-field pre/post-state and a queued conditional compensation's
expected post-state. Concrete SQL definitions and bounded
decoders belong to that source slice. Subsequent method slices may not add
canonical objects under v3; layout changes require separately reviewed version
policy. Credential generation is process-local, not a v3 column; restart drops
access sessions and treats durable Dispatching as Ambiguous. Existing
`AccountProfile` remains the application identity trait, not
the name of a replacement store/identity API.

Readonly opens support recognized v1/v2/v3 without migration. Known-version
decoding must remain valid around a writable upgrade or fail closed before
returning incompatible data; no permission to repair or migrate a readonly open
is added. Preserve path, key, owner, account, sidecar, type/length, integrity and
identity-fence checks, including the filesystem residuals described above.
Baseline binaries reject v3; source rollback does not restore readability.
There is no implicit downgrade, reset, quarantine, key export or plaintext copy.

The store supplies these atomic boundaries:

- Read token plus capability consistently. Bind upgrade to the existing account
  and expected immutable subject; replace token plus capability together, with
  process-local credential-generation fencing in runtime composition. Two
  independent successful writes are not an
  atomic implementation. Broker retains sole token custody.
- Apply one complete, fully decided History record and that record ID in one
  transaction. Successive commits may form a contiguous decided prefix; never
  advance past an undecided record or commit a subset of one. The decoder's
  local reference budget truncates at a whole-record boundary with an explicit
  local indicator, not a fabricated provider token. Resume from the last record
  cursor; a locally truncated page cannot install response `historyId`. Invalid
  page envelopes fail before application; an over-limit/undecidable next record
  stays unapplied. Validate final-page current-mailbox cursor rules before commit.
  Network lookups happen outside SQL transactions; optional body writes follow
  metadata/cursor commit.
- Commit collected bounded snapshot metadata plus the retained pre-snapshot
  baseline in one transaction. Failure preserves the prior cursor and pending
  commands; snapshot absence never settles a command.
- Admit Queued desired state, command ID and full target set while checking both
  account quotas (32 nonterminal commands, 4,096 target references). Queued means
  no mailbox mutation attempted; read-only preflight/network remains possible.
  Before a mailbox mutation, commit Dispatching and reconciled undo pre-state.
  Persist item reconciliation
  and account aggregate status without fabricating success from cache rows.
- Store full observed membership up to 512 labels/message, or fail the
  record/command closed. Partial sets are never stored as complete observations.
  Names remain exact encrypted bytes for equality and sanitized only for display.
- Retain at most 128 terminal aggregate summaries plus one undo candidate.
  Compact terminal item rows except that candidate; never evict nonterminal
  evidence for quota. Replay lookup is distinct from admission: expired/unknown
  command IDs cannot create new work.
- Complete is terminal success; Partial is terminal when all items resolve and
  at least one fails, including TargetMissing, even with zero successes. These
  release FIFO without creating an undo candidate except Complete message-state.
  Ambiguous/NeedsAttention stay nonterminal. Explicit Retry reconciles first,
  authorizes at most one guarded dispatch and never resets the automatic budget.
  That automatic budget is three total attempts, including the initial attempt.
  Failed reconciliation cannot dispatch. Label-create zero-match retry requires
  explicit duplicate-risk confirmation; multiple matches never permit creation.
- Explicit Abandon atomically retains a terminal Abandoned summary before
  releasing FIFO/pins/quota or reset/remove guards. Its confirmation warns that
  Gmail may already have applied the operation and automatic recovery stops;
  it claims neither success nor rollback. The abandoned ID never retries or
  reenqueues; bounded terminal retention applies.
- Offline undo admission persists conditional compensation and expected
  post-state through the ordinary queue, refusing admission if a pre-existing
  account command is nonterminal, without claiming provider eligibility or
  performing a mutation. The admitted undo is itself Queued: do not reapply that
  admission-only gate at dispatch to itself or later queued commands. FIFO
  prevents later work from overtaking it or causing self-deadlock.
  After reconnect and before any dispatch, fresh
  reconciliation must validate the entire target set/required User labels and
  touched expected-post-state fields. Any mismatch refuses the whole compensation
  without writes; only a passing check permits touched-pre-state restoration.

Pruning pins all nonterminal targets and the undo candidate, even outside the
normal keep-100 recent set. Local-read overlay never supplies provider evidence.
Reset/removal refuse every nonterminal command, including Queued; cancellation
of Queued work, settlement or explicit terminal abandonment is required first.
Only a committed terminal disposition releases unresolved-evidence guards.
Identity replacement also refuses destructive
change while nonterminal evidence exists. A guarded successful cache clear
removes cursor, terminal summaries, undo and cached membership while retaining
registration, capability, grant, identity and disconnect recovery. Guarded
removal/purge deletes all T4 rows in its account-local transaction. These
guards are part of the v3 store and the existing-only reset path. They were
not v2 reset behavior. History
RecoveryRequired offers later explicit retry or guarded cache reset after all
nonterminal commands are cancelled, settled or abandoned. Reset clears cursor
and captures a new baseline; failures/budget exhaustion never cause automatic
non-404 snapshot fallback.

Migration/reopen, token/capability and cursor/data rollback, whole-record boundaries,
quota admission, complete membership, pins and lifecycle refusal need adapter
evidence against actual SQLCipher. No network wait holds a SQL transaction; lazy
unpolled futures still have no effect. Committed Dispatching survives
cancellation for reconciliation, not blind retry. Abandoned-summary commit must
precede evidence/guard release, with failure rollback preserving the old guard.
Secure deletion remains a
logical policy without a secure-erasure or backup-removal guarantee.

## Consequences

The account-store adapter supports macOS and Linux and has no keyring,
cross-account mailbox, retry, pool, or sync-orchestration behavior. The separate
encrypted registry component is described in ADR 0026. Its path, key, account,
headers, identifiers, and message bodies are never included in errors or debug
output.
