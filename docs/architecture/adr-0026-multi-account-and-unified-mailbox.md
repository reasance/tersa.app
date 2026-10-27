<!--
This Source Code Form is subject to the terms of the Mozilla Public License,
v. 2.0. If a copy of the MPL was not distributed with this file, You can obtain
one at https://mozilla.org/MPL/2.0/.
-->

# ADR 0026: Multi-account and unified mailbox

- Status: Accepted
- Amended by: [ADR 0031](adr-0031-tui-only-pivot.md) (terminal-only pivot)
- Date: 2026-08-29

## Implementation status

Accepted design for T3, amended for the terminal architecture by ADR 0031.
Opaque account IDs, purpose-separated keys, and an encrypted registry exist in
source. Unified queries, capability upgrade, reset/quarantine, and account-local
FTS described below remain plans; this ADR does not certify their completion.

## Context

The terminal client needs isolated Google accounts and a bounded unified inbox.
An address cannot be a local routing key, a plaintext global index would defeat
account isolation, and unknown schemas must never be silently claimed or reset.
The in-process token service owns credential lifecycle (ADR 0024), while the
SQLCipher adapter owns account persistence and schema migration (ADR 0017).
Keys and paths follow ADRs 0019 and 0031.

## Decision

### Account identity, registry, and storage

Each added account receives a locally generated, opaque `AccountId`: 128 bits
from the platform CSPRNG, encoded as `acct_` followed by 32 lowercase hexadecimal
characters. It is not derived from, and never displays, an email address or
Google identifier. A collision is retried before any provider or store write.
The beta registry admits at most five accounts and rejects a sixth before OAuth
or any local write.

The accepted model requires these redacted, validated values:

- `AccountCapability`, initially `ReadOnly` or `Modify`;
- `AccountProfile`, containing the Gmail profile fields required by the UI; and
- `RegistryDedupTag`, which is never constructed from a caller-supplied key; and
- `UnifiedMailboxRow` / `UnifiedMailboxDocument`, whose every row carries its
  originating `AccountId`.

`AccountProfile` and the validated broker subject are persisted only in the
corresponding account's SQLCipher database. `IdentityHash` remains
account-bound and is not reused for cross-account duplicate detection.

Trusted Rust composition derives one account-independent HMAC
key under `InstallationKeyPurpose::RegistrySubjectDedupV1` and computes a redacted
`RegistryDedupTag` from a broker-validated subject. It also derives the distinct
`InstallationKeyPurpose::RegistryDatabaseV1` registry SQLCipher key. The current
framing is defined in ADR 0019: a disjoint installation prefix
plus length-framed purpose, omitting account-ID bytes. Keys and raw subjects
stay within trusted composition and are never displayed or logged.

The registry component of `tersa-store-sqlcipher` uses a distinct SQLCipher key
and stores only `(AccountId, RegistryDedupTag, position)` for ordering and
duplicate rejection. It has no messages, profiles, raw subjects, tokens, labels,
queries, or blob data. Preferences may contain only opaque ordering/selection
metadata, never tags, addresses, subjects, tokens, profiles, or mailbox data.

The encrypted tag is deliberately a same-install equality oracle: code that can
decrypt the registry metadata can learn that two attempted subjects are equal,
and the record reveals that a deduplicated account is resident on this install.
It is not portable across installations, is never exposed to UI/CLI/logs,
and does not reveal the subject without an infeasible HMAC preimage attack. This
limited residency/equality leakage is an accepted residual requiring independent
security review; it is not a claim that the registry is identity-free.

The terminal layout uses the XDG data directory on both platforms, with a
separate encrypted registry and per-account database directories. Future blobs
must use a separate account namespace. No account database may contain another
account's messages, profile, subject, search index, drafts, pending actions, or
blobs. A planned schema reset is not permission to replace existing stores.

### Prerequisite decision and policy slices

Before each new T3 persistence or query surface, independently review its domain
and port contracts, dependency ownership, schema/version/reset policy, and
security data-flow/threat-model amendments. The current registry and key purposes
do not authorize an additional format or plaintext index. Absent-root checks must
recognize every supported registry/account entry without unsafe provisioning.
FTS requires target-specific compile-option evidence and reviewed account-local
schema ownership before implementation. Budget policy belongs to ADR 0030.
Legacy data may not be reset or quarantined until a supported read path and
explicit recovery protocol exist; preserve the only readable copy.

### Add, remove, reset, and unified reading

Adding an account begins OAuth through the broker. Only after the broker has a
valid grant and subject does private composition derive a `RegistryDedupTag` and
reject an existing tag. It then creates the account registry entry, profile
directory, and encrypted store, and obtains the Gmail profile for that account.
It rolls back only objects proven created by that attempt on failure before
registry commit. An existing account can remain readable while a different
account is added.

Removing an account uses the existing broker revoke/delete then local-purge
ordering for that `AccountId`; only a completed local purge removes the opaque
registry entry. An unconfirmed revoke or incomplete token deletion remains a
content-free recovery entry and is not shown as a clean removal. If the removed
account was selected, the registry selects its next ordered account or no
account when none remain.

A planned incompatible schema reset requires explicit user confirmation and a
new opaque account ID/consent flow; it is not an automatic migration. Under the
owning application lock, inspect old state without a write-open or migration,
then quarantine the fixed legacy directory using descriptor-relative no-follow
identity checks and an exclusive no-replace rename. An occupied destination,
identity drift, or rename failure preserves all state. Revoke/delete the old
grant and retain a visible recovery state if either step is unconfirmed. Never
copy the old database into the new identity, recursively delete the old tree,
or silently reuse its grant. Quarantine remains until a separately reviewed
bounded, descriptor-relative, identity-checked purge protocol is implemented;
that protocol must define a fixed traversal budget.

`UnifiedMailboxQuery` is an application use case, not a global store. It adds
a bounded `UnifiedMailboxContinuation` and a global page cap of 200 rows. For
an All Accounts inbox or search it requests only enough account-local rows to
fill that global cap, merges by `received_at DESC, account_id ASC, message_id
ASC`, and returns bounded per-account continuations for the next page. It never
issues an `N * 10,000` fan-out payload. Threads, drafts, actions, and settings
remain account-scoped even when the inbox is unified.

When unlocked, an account-local failure produces
`UnavailableAccount { account_id, state }`, where `state` is only
`AuthorizationRequired` or `StoreUnavailable`; it contributes no rows. The
document may show available-account rows plus these opaque availability states.
When app lock is active, all stores are closed and `UnifiedMailboxQuery` returns
only the top-level `Locked` state without account identity: it performs no
fan-out and displays no partial rows. After unlock, it restarts the query from
its supplied continuation rather than reusing a locked in-memory result.

Each future FTS-enabled account schema owns an encrypted FTS5 index only after
reviewed policy has recorded target-specific compile-option evidence. The future
`LocalMailboxSearch` port indexes subject, sender, recipient, plain body,
sanitized-render text, and attachment filenames only in that account's store.
It does not extract document text in this beta and does not create an index
outside SQLCipher. It introduces no global search database. This is a future
account-local FTS extension, not the current in-memory sanitized-row filter.

### Invariants and data flow

```text
Terminal account intent (opaque AccountId)
  -> application AccountRegistry / UnifiedMailboxQuery
  -> one account-scoped SQLCipher store and one account-scoped adapter session
  -> versioned document with AccountId on every returned row
```

- Every mutating or reading route validates `AccountId` before selecting a
  store, key derivation, token-broker session, Gmail client, blob namespace, or
  returned document.
- A broker subject is a private binding input. The account-independent registry
  HMAC creates the only cross-account equality tag; it is never displayed,
  placed in preferences, logged, or exposed in a presentation payload.
- The broker returns only an access token and validated subject for the selected
  account. Refresh-token persistence remains broker-only.
- A unified view is a capped, paginated merge of isolated account results. It
  has no cross-account mailbox transaction, cache, FTS table, or worker.
- Terminal models carry bounded, sanitized data and opaque account routing;
  keys, store handles, tokens, and raw subjects never become display values.

### Implementation decomposition

Use the current [change classes](../development/agent-playbook.md) in separate
slices: domain values, application registry/unified-query contracts, SQLCipher
registry/account persistence, trusted runtime/key composition, and terminal
account/recovery states. Any new dependency or schema policy precedes its
implementation; no new class or removed adapter is implicitly authorized.

## Failure handling

An account-add failure before registry commit leaves no usable registered
account. A duplicate dedup tag, corrupt registry metadata, missing account key, or
ambiguous profile identity fails closed for that account and never falls back to
another account. A selected-account preference that names no registered account
is cleared to an empty selection, not treated as an authorization request.

After a broker grant but before registry commit, setup failure invokes broker
revoke/delete. If confirmation fails, `AccountRegistry` retains only an opaque
setup-recovery route until the user resolves it; it never treats the grant as a
normal account or persists its subject/profile in preferences.

Legacy reset errors preserve the original or quarantined identity without a
recursive delete and do not retry provider revoke automatically. Store corruption
or quota failure in one account yields its closed unavailable state; it cannot
cross-populate the unified view. A locked app returns top-level `Locked`, never
rows from another account. Search and inbox cancellation drops unfinished
fan-out work and returns no partial durable mutation.

## Test and evidence gates

- Domain and application tests cover ID generation/validation, five-account cap,
  private dedup-tag equality, paginated 200-row merge, continuation bounds,
  unavailable/locked semantics, and no raw subject in preferences/documents.
- Registry/store/key tests cover registry SQLCipher tag residency,
  registry-purpose framing, v2 schema and compile-proven FTS isolation,
  absent-root enumeration, no-write legacy detection, quarantine identity drift
  preservation, and the later bounded purge contract.
- Runtime/TUI tests cover private subject handling, opaque routing, sanitized
  output, account switching, and retained setup/teardown recovery.
- Candidate-specific manual evidence must exercise add, switch, remove, offline
  reopen, locked unified inbox, and 200-row continuation with accessibility checks.
  Local source tests do not establish live consent or release readiness.

## Non-claims

This accepted design is not a completion claim for T3, FTS, quarantine, app
lock, live consent, performance, or release validation. It adds no account-sharing
backend, cross-account labels/threads, automatic legacy migration, or recursive
legacy deletion. The same-install equality/residency oracle remains explicit.

## Consequences

If the prerequisites are independently accepted and implemented, the beta gains
a capped, page-bounded account boundary before mailbox mutation, draft, outbox,
blob, or rich-content work. It preserves legacy data in a verified quarantine
rather than claiming deletion safety, and it makes the registry's narrow
cross-account equality linkage explicit.
