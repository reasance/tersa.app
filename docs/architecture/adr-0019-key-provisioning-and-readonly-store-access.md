<!--
This Source Code Form is subject to the terms of the Mozilla Public License,
v. 2.0. If a copy of the MPL was not distributed with this file, You can obtain
one at https://mozilla.org/MPL/2.0/.
-->

# ADR 0019: Key provisioning and read-only store access

- Status: Accepted; amended by [ADR 0031](adr-0031-tui-only-pivot.md)
- Date: 2026-07-16

## Current key boundary

One random 32-byte installation root key is held by `tersa-vault` in the OS
keyring or a passphrase-wrapped file. XDG configuration and data paths apply on
macOS and Linux. Provisioning, retrieval, wrapping, and account composition are
Rust responsibilities. No key is accepted through process arguments or emitted
to logs, JSON, diagnostics, or terminal output. Keys pass only through trusted
in-process composition into secret storage, derivation, and database opening.
The current key types expose bytes for those operations; this is a capability
boundary and does not claim compiler-enforced secrecy from the containing
process. Existing profile state must not be silently replaced by a new root
when its key is missing or unreadable.

`tersa-keys` implements HKDF-SHA256 with salt `tersa/root-key/v1` and disjoint
account and installation prefixes:

- `tersa/hkdf-sha256/account/v1`, followed by two-byte big-endian length-framed
  validated AccountId bytes and purpose bytes;
- `tersa/hkdf-sha256/installation/v1`, followed only by length-framed purpose
  bytes, with no account identifier.

Account database purpose `sqlcipher/account-database/v1`, account identity
purpose `account-subject/v1`, registry purpose `sqlcipher/registry/v1`, and
registry dedup purpose `registry-subject-dedup/v1` remain separate. Purposes
are closed and versioned; framing changes need reviewed compatibility decisions.
Root and derived key buffers use best-effort zeroization and redacted Debug.
Internal cryptographic-library state and transient allocator copies remain
outside the explicit-buffer zeroization guarantee.

Passphrase wrapping uses Argon2id and XChaCha20-Poly1305 with authenticated
parameters, fresh salt and nonce, and bounded decode/cost checks. This existing
wrapping capability does not establish a production blob or draft-bundle format.
Root-key rotation and recovery require separately reviewed protocols.

## Store and filesystem ownership

The SQLCipher adapter remains the sole owner of database creation, claim,
migration, validation, transactions, and leaf cleanup. Account identity selects
the derived key and account directory; an address or arbitrary provider string
cannot select a local store. No caller may bypass validation by supplying a key
or by opening a database through a second engine.

The following storage invariants survive independently of any packaging:

- Validate expected owner, type, restrictive directory permissions, and exact
  `0600` database/sidecar modes; reject symlinks and observable identity changes.
- Serialize cooperative bootstrap operations through their final outcome.
  Contention must be bounded; malformed lock entries, poisoned locks, and
  operational failures must not be mislabeled as ordinary contention. Locks
  protecting local store setup or transactions are never held over network I/O.
- If the main file is absent and any journal/WAL/SHM exists, preserve all entries
  and fail before open. A present main is existing state regardless of sidecars;
  it never receives fresh-failure cleanup authority. Only absence of all four
  entries followed by a successful exclusive main-file claim permits cleanup.
- Cleanup removes only objects proven created by that attempt, under a retained
  validated parent descriptor, with no-follow identity checks immediately before
  removal. Never recursively remove profile content or clean snapshot-present
  entries. Directory cleanup is reverse-order, empty-only, identity-bound, and
  permitted only before invoking the store opener.
- Existing valid WAL state belongs to the owning writer. WAL-only crash recovery
  validates encrypted copies in at most eight fixed owner-only staging slots;
  it never adopts or deletes a pre-existing staging slot. Identity drift preserves
  unknown residue. Exhaustion fails closed rather than creating unbounded names.

Any future cooperative bootstrap lock preserves the bounded acquisition contract:
one monotonic 30-second deadline across process mutex, file validation, and
advisory-lock acquisition, nonblocking attempts with 10-millisecond backoff capped
by the remaining budget, and EINTR within that budget. Keep acquired guards through
root retrieval, absent-root checks, directory setup, store claim/migration, identity
checks, cleanup, and final status construction. Lock entries are permanent,
same-user regular files at exact `0600`; only missing owner read/write bits may
be normalized after identity validation. Reject execute/group/other bits. This
records a storage constraint, not a claim that a particular bootstrap worker or
cross-process lock is present in the terminal runtime.

Descriptor-relative cleanup does not make pathname-based SQLite opening
end-to-end descriptor-bound. Same-user replacement between identity checks,
sidecar insertion after an exclusive claim but before recording, and replacement
between final validation and unlink remain accepted residuals. Cooperative
locks do not constrain hostile same-user code. Permission normalization also
names a mutable entry: replacement between stat, chmod, and final descriptor
validation can affect a replacement before identity drift is detected. Fixtures
must distinguish
observable replacement rejection from non-prevention of swap-back races.

## Strict read-only contract

`SqlCipherMailboxReader::open_read_only` opens an existing regular database with
existing regular WAL and SHM sidecars. It validates key, owner, account, schema,
integrity, bounded decode, and path identities inside a live read transaction.
It has no create, claim, migrate, repair, body-fetch, or write capability and
never falls back to read-write. It uses read-only/no-mutex/no-follow flags,
never `immutable=1` for a live WAL store and never a private copy.

Writers establish persistent WAL after ownership validation. Readers separately
set and verify `SQLITE_FCNTL_PERSIST_WAL`, disable checkpoint-on-close, and require
`journal_size_limit = -1`. Missing or observably replaced sidecars fail closed.
SHM coordination bytes may change while main/WAL contents remain unchanged.
SQLite's Unix VFS can recreate a sidecar deleted after preflight and cannot
bind its internally opened SHM inode to the caller's descriptor. These are
recorded residuals, not prevention claims; see
[ADR 0017](adr-0017-production-account-store.md).

## Consequences and non-claims

Read-only store access remains a distinct capability within the terminal app.
The app also has explicit account and sync commands; it is not globally a
retrieval-only executable. Display/export is user-directed declassification,
with sanitized terminal text and no sensitive error payloads. Redirected output,
editor backup files, and downstream consumers are outside encrypted storage.

This ADR does not prove keyring runtime behavior, filesystem crash safety on
all platforms, live OAuth, recovery, or release signing. The current release
signing decision remains T7 in the [roadmap](../roadmap.md).
