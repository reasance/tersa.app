<!--
This Source Code Form is subject to the terms of the Mozilla Public License,
v. 2.0. If a copy of the MPL was not distributed with this file, You can obtain
one at https://mozilla.org/MPL/2.0/.
-->

# ADR 0017: Production account store

- Status: Accepted
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
(Amended in T2c: the `integrity_check` and `cipher_integrity_check` scans read
the whole database, so they run on the first open of each database in a
process. Later opens and the interface's first read skip them; every other open
check still runs, and SQLCipher authenticates each page it reads.)
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
SQLite read-only/no-mutex/no-follow flags, and has no complete-message-body or
mutation capability. It performs exact key, owner, schema, SQLCipher, integrity,
account, bounded-decode, and pre/post pathname-identity checks inside a live
read transaction. It disables and verifies checkpoint-on-close and exposes no
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

Schema v1 owns a singleton account binding and message envelopes with nullable
RFC 5322 content. Only an exactly empty database may be claimed. Ownership,
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

## Consequences

The account-store adapter supports macOS and Linux and has no keyring,
cross-account mailbox, retry, pool, or sync-orchestration behavior. The separate
encrypted registry component is described in ADR 0026. Its path, key, account,
headers, identifiers, and message bodies are never included in errors or debug
output.
