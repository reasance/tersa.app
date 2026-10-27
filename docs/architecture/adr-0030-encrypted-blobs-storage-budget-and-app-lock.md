<!--
This Source Code Form is subject to the terms of the Mozilla Public License,
v. 2.0. If a copy of the MPL was not distributed with this file, You can obtain
one at https://mozilla.org/MPL/2.0/.
-->

# ADR 0030: encrypted blobs, storage budget, and app lock

- Status: Accepted
- Amended by: [ADR 0031](adr-0031-tui-only-pivot.md) (terminal-only pivot)
- Date: 2026-08-29

## Implementation status and context

Blob storage, allocated-byte cache budgets, and app-lock lifecycle are accepted
future T6 work. SQLCipher storage and root-key passphrase wrapping are implemented;
neither establishes this blob protocol. The terminal app must support bounded
attachment storage without plaintext temporary caches and preserve local intent
when recoverable cache is evicted.

Lock must close stores, quiesce work, evict keys/models, and require fresh vault
authentication before reopening, not merely cover the terminal view. It cannot
protect content already exposed to a compromised unlocked process.

## Prerequisite decision and policy slices

Before new blob/budget/lock code, independently review exact dependency versions,
features, targets, and owners; a narrow account-bound blob capability; the blob
key purpose and trusted composition; descriptor-relative no-replace publication;
and security data-flow/threat-model changes for backup, rotation, deletion,
allocated-byte accounting, authentication, lock, and diagnostics. Existing
Argon2id/XChaCha20 root wrapping does not authorize blob or draft-bundle formats.
The separate bundle policy in ADR 0028 still owns its format and recovery gates.
No version, new adapter path, or dependency permission is invented by this ADR.

## Decision

### Per-account encrypted blobs

The domain layer adds `BlobId`, `BlobRef`, `BlobKind`, `BlobManifestV1`, and
`StorageClass`. `BlobRef` always carries `AccountId`; `StorageClass` is either
recoverable cache data or non-evictable local intent. The application adds
`SecureBlobStore` and `StorageBudgetStore` ports. The future blob adapter owns
only account-bound encryption, filesystem staging,
and authenticated publication. Trusted runtime composition supplies derived keys
and returns only a narrow `SecureBlobStore` capability; it adds no public key
callback or display/export channel.

The trusted key-derivation boundary gains the closed
`blob/account-content/v1` derivation purpose. It derives a 32-byte per-account
blob key without exposing root or derived bytes to callers. A blob receives a
random 128-bit `BlobId`, a separate random 24-byte XChaCha20 nonce for every
1 MiB plaintext chunk, and a further independent random 24-byte nonce for its
encrypted/authenticated manifest. The adapter rejects every nonce collision
within a blob before encryption or publication. Nonces are nonsecret and are
stored beside their ciphertext in fixed versioned record headers. Each chunk's
associated data begins with the literal `tersa.app/blob-chunk/v1` and binds
format version, `AccountId`, `BlobId`, chunk index, and plaintext length. The
manifest's associated data begins with the disjoint literal
`tersa.app/blob-manifest/v1` and binds the same account/blob/version context,
chunk count/order, total length, `BlobKind`, and storage class. A chunk or
manifest from a different account, blob, index, record kind, or format must not
decrypt.

The adapter writes only ciphertext plus nonsecret fixed framing and nonce
metadata to a validated owner-only staging directory under the account's
`blobs/` directory. It synchronizes every chunk and manifest file, then
synchronizes the staging directory after all entries exist. Only then
may it use the verified Rustix 1.1.4 primitive
`rustix::fs::renameat_with(..., RenameFlags::NOREPLACE)`, which maps on macOS to
`renameatx_np` with `RENAME_EXCL`, to publish the complete staging directory,
followed by synchronization of the account `blobs/` parent directory. Every
file, staging-directory, rename, or parent-directory synchronization failure
fails closed and never falls back to overwrite/replace. Directories are `0700`;
files are `0600`; all traversal is descriptor-relative and no-follow. It does
not create plaintext files, replace an existing final blob, recursively clean
unowned data, or claim power-loss atomicity beyond this staged publication
protocol. A failed write cleans only files/directories proven created by that
attempt and otherwise preserves redacted residue for recovery. This requires no
libc or unsafe amendment.

A separate `policy-xtask` slice owns any dependency/owner-policy amendment;
this documentation changes no manifest or dependency permission. Existing key
wrapping and removed feasibility work supply no production blob evidence.

### Budget and eviction

The planned per-account default budget is 10 GiB with a 50 GiB installation
aggregate; a user may lower an account budget, but
never below 1 GiB. Accounting uses allocated file bytes, not semantic SQLite
row sizes: it includes each account database, WAL, SHM, FTS files, blob
ciphertext/manifests, render/image cache, and registry metadata where allocated
to that account. A write preflights pessimistic allocated size, attempts bounded
eviction, and fails before partial publication when either budget remains
insufficient. Accounting divergence or a non-measurable allocated size preserves
data and fails closed; it never deletes protected content merely to repair a
counter.

Eviction is deterministic least-recently-used across recoverable message bodies,
received attachments, inline images, and derived render cache. It may evict
only data that Gmail can retrieve again. It never evicts drafts, outbox entries,
pending mailbox actions, account registry/profile/binding data, configured
budget, or a blob referenced by local intent. Downloaded attachments remain
on-demand; Save/Open is an explicit user-directed declassification and beta
does not preview hostile documents in-app.

Backup, key rotation, file permissions, deletion, and diagnostics require
security documentation before implementation: backup copies remain encrypted,
but databases without their root key are unreadable on another device; the beta
performs no key rotation; a future rotation requires a separate re-encryption/
atomic-cutover ADR; neither platform gains an unsupported filesystem protection
claim beyond owner-only files, encryption, and the planned lock lifecycle;
deletion is validated descriptor-relative unlink plus reference removal, not
SSD secure erase; and diagnostics may record only aggregate sizes, versions,
and redacted outcome classes, never paths, BlobIds, account IDs, content, or
keys.

### Blob commit and recovery state machine

The application-layer `BlobCommitCoordinator` is the sole owner of the ordered
operation across the SQLCipher store and blob adapter. The SQLCipher store is
the durable transaction authority; the blob adapter receives only one
account-bound prepared/published operation at a time and returns opaque status
and authenticated manifest/accounting facts, never a path or key.

Creation follows this exact order:

1. After pessimistic budget preflight, one SQLCipher transaction inserts a
   `PendingBlobCommit` containing the validated `AccountId`, `BlobId`,
   `BlobKind`, storage class, and reserved upper-bound allocated bytes. It is not
   a reachable `BlobRef` and cannot be opened, attached, or displayed.
2. The blob adapter stages and publishes ciphertext using the file/directory
   synchronization and no-replace order above. Only successful parent-directory
   synchronization returns `PublishedBlob`, containing the same account/blob
   identity, authenticated manifest summary, and measured allocated bytes.
3. A second SQLCipher transaction verifies the pending/published identity and
   size, atomically replaces the pending row with the reachable `BlobRef`, and
   commits actual allocated-byte accounting. No reachable reference can commit
   before durable filesystem publication.
4. A pre-publication failure may cancel the pending row only after the adapter
   proves that no final was published and completes or safely defers cleanup of
   its proven stage. An ambiguous result retains the pending row and exposes no
   `BlobRef` until recovery resolves it.

Startup and explicit recovery perform a bounded descriptor-relative join of
SQLCipher pending/reachable state and the account blob inventory:

- A pending row with neither a stage nor a final is cancelled only after one
  bounded descriptor-relative no-follow inventory proves both names absent under
  the expected account/blob identity. Failure, an unbounded result, or ambiguity
  retains the reservation and keeps it unavailable. This same transition handles
  a crash after validated stage cleanup but before pending-row cancellation.
- A pending row plus a validated stage and no final cleans only an authenticated,
  identity-bound stage before running the same bounded double-absence proof and
  cancelling the pending row; any mismatch preserves both and fails closed.
- A pending row plus a final authenticates the manifest, requires exact
  account/blob/kind/storage-class agreement, measures allocated bytes, and then
  must successfully synchronize the account `blobs/` parent directory. Only
  that successful recovery synchronization reconstructs the equivalent of
  `PublishedBlob` and permits the finalizing SQLCipher transaction. A sync or
  identity mismatch retains the pending row and final as unavailable without
  deletion.
- An authenticated final with no pending or reachable row is never silently
  adopted. Recoverable cache data may be removed only by a bounded validated
  cleanup transaction. Non-evictable local intent is preserved, charged at its
  measured allocated bytes through an `OrphanedProtectedBlob` recovery record,
  and requires explicit recovery; it is never auto-deleted.
- A reachable reference with a missing, invalid, or mismatched final becomes
  `BlobUnavailable`. Protected intent and its reference remain durable and block
  dependent send/export; no counter repair infers deletion. A recoverable-cache
  reference may be removed only by the normal store transaction after the
  missing-final state is confirmed.
- An unbounded inventory, unauthenticated entry, accounting mismatch, or
  ambiguous ownership makes that account's blob subsystem unavailable and
  authorizes neither eviction nor cleanup.

### App-lock lifecycle

App lock is planned as opt-in terminal `:lock` and idle lock. Unlock requires
fresh vault authentication; the exact keyring/passphrase interaction on macOS
and Linux must be reviewed before implementation. No biometric template,
authentication secret, or reusable success token is stored by the app. The
planned `AppLockPolicy` has `Immediate`, `OneMinute`, `FiveMinutes`, and
`FifteenMinutes`; default `FiveMinutes`. Sleep-trigger support requires explicit
platform validation, not an assumed terminal capability.

The application `AppLockCoordinator` consumes an abstract authenticated/not-
authenticated result, not OS framework types. When lock is enabled it:

1. locks on explicit `:lock`, the selected inactivity timeout, and supported
   platform sleep events;
2. prevents new sync, render, blob, draft, and outbox work;
3. cancels/quiesces active workers, closes SQLCipher handles, clears UI models,
   and zeroizes or evicts application-held derived key material;
4. increments a lock generation that every asynchronous completion must match
   before it can publish state; and
5. requires a fresh successful vault authentication before deriving keys,
   reopening stores, or returning any mailbox document.

An already-dispatched Gmail operation may remain externally ambiguous; its
durable desired/outbox state survives and is reconciled after unlock. The lock
is not a second encryption root, does not revoke tokens, and does not claim to
protect content already available to a compromised unlocked process.

Lock closes every account store and registry-backed reader before it reports a
locked state. Any single-account or unified fan-out query returns only the
closed top-level `Locked` outcome while locked: it must not display rows from an
already-open account or report a partial-account result. Unlock starts a fresh
routed query after authentication and generation validation.

### Invariants and data flow

```text
Account-scoped attachment/image bytes
  -> SQLCipher PendingBlobCommit budget reservation (not reachable)
  -> SecureBlobStore staging ciphertext + authenticated manifest
  -> file sync -> staging-directory sync -> NOREPLACE publish -> parent sync
  -> SQLCipher atomic BlobRef + actual accounting finalize
  -> explicit open/save declassification only

Explicit terminal lock / idle timeout / supported sleep event
  -> AppLockCoordinator generation fence
  -> stop work, close stores, evict keys/models
  -> vault authentication -> authorized reopen
```

- No blob, manifest, usage record, or key can be routed without a validated
  `AccountId`. Lock state carries no account identity and gates every account.
- The SQLCipher store is the durable transaction authority for pending/final
  `BlobRef` reachability, budget accounting, protected-orphan recovery,
  drafts/outbox protection, and eviction selection. The application
  `BlobCommitCoordinator` alone orders cross-adapter transitions; the blob
  adapter owns only ciphertext files, authenticated inventory facts, and verified
  publication/removal.
- A plaintext attachment exists only in bounded memory while explicitly opened,
  saved, composed, or parsed. The operation cannot silently export it.
- Lock generation fences apply to TUI models, adapter completions, and
  Rust workers; an old unlocked completion cannot repopulate a locked view.
- Locked fan-out is all-or-nothing: stores are closed and no partial account
  display is permitted until fresh authentication completes.

### Implementation decomposition

Sequence security/architecture documentation and dependency policy before domain
values, application commit/budget/lock coordinators, one blob/store adapter at a
time, trusted key/runtime composition, and TUI settings/lock/save recovery. Use
the current [change classes](../development/agent-playbook.md); adding a new path
requires an explicit ownership decision before code. Models carry no raw key,
filesystem path, or store-handle capability to the terminal.

## Failure handling

Manifest/tag/nonce/order validation failure marks the blob unavailable and
retains no decrypted output. Disk-full, quota, permission, file/directory sync,
exclusive-rename, parent-sync, or SQL finalization failure follows the commit
state machine above and never exposes a reachable partial blob. An orphaned
encrypted stage is never adopted blindly; recovery validates and identity-binds
it before cleanup. A published-but-unreferenced final is reconciled only through
its matching pending row, bounded recoverable-cache cleanup, or a preserved
`OrphanedProtectedBlob` record. A missing final never makes protected intent look
deleted. A corrupted usage record, allocated-byte accounting divergence, or
unbounded/ambiguous inventory fails closed rather than evicting protected intent
or repairing a counter by inference.

Authentication cancellation/failure leaves the app locked. Worker cancellation
on lock preserves durable sync/outbox intent but prevents stale result delivery.
If a store cannot close or a worker cannot quiesce within its bounded shutdown
contract, the process remains locked and does not reopen content. Locking never
falls back to a UI-only mask or a plaintext cache, and a locked fan-out never
falls back to partial rows.

## Test and evidence gates

- Cryptographic tests cover wrong account/blob/key/nonce/index, chunk-versus-
  manifest associated-data separation, chunk/manifest nonce collision rejection,
  manifest and chunk tampering, truncation, reordered chunks, malformed staging
  entries, and absence of plaintext sentinels from finals, stages, logs, and
  diagnostics.
- Crash and fault-injection tests stop after every chunk/manifest file sync,
  staging-directory sync, no-replace rename, parent-directory sync,
  pending-reservation transaction, and finalizing transaction. They cover every
  pending/stage/final/reference recovery matrix row, including pending with neither
  stage nor final, cleanup-before-pending-cancel crashes, recovery parent-sync
  failure, published-but-unreferenced cache and protected-intent outcomes,
  missing finals, exclusive-rename failure, disk-full, concurrent writers,
  allocated-byte divergence, quota eviction, protected-intent preservation, and
  bounded post-crash inventory handling.
- Cross-account tests prove a `BlobRef` cannot be read, evicted, or attached
  through another account. Budget tests cover default, 1 GiB minimum, and LRU
  behavior without evicting drafts/outbox/pending actions.
- Lifecycle tests cover timeout, sleep, failed authentication, all-store close,
  top-level locked fan-out/no partial rows, key/store/model eviction, and stale
  completion rejection for sync, worker, and TUI paths.
- Candidate-specific platform checks must exercise lock/unlock, supported sleep
  behavior, save warnings, authentication, and accessibility. Source tests do not
  establish real keyring authentication or release behavior on either platform.

## Non-claims

This ADR does not implement or approve any prerequisite slice, guarantee secure
deletion from SSD wear-leveling, add cloud backup/synchronization, preview or
execute attachments, claim lock protection against a compromised unlocked
process, change token-service ownership, or pass release-signing evidence. It
does not turn an accepted storage design into implemented code or invent
dependency versions.

## Consequences

The beta gains a single accountable encrypted attachment/cache path and a
storage budget that protects local intent before recoverable cache. App lock
becomes a lifecycle boundary with explicit residual limits, rather than a
cosmetic screen overlay.
