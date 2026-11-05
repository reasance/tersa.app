# Account schema v3: storage handoff

P5a owns schema and credential transactions; P5b and P5c implement the History
and command methods described below. Runtime activation remains P7 work. No broker adapter dependency is introduced. Registry schema
remains v1 and identity hashing remains algorithm 2. Old binaries reject v3;
source rollback does not downgrade its format.

## Canonical inventory

There are 19 named canonical objects (SQLite autoindexes are excluded): the six
inherited objects, ten new tables and three new indexes. The schema reader admits
at most 19 objects plus one rejection sentinel, names up to 256 bytes, kinds up to
16 bytes and SQL definitions up to 16 KiB. Exact normalized SQL is checked for
each recognized v1, v2 or v3 layout. The first two migration files retain their
historical meaning.

| Object | State represented |
| --- | --- |
| `account_binding` | Original account/subject/token/email, plus capability and explicit credential purpose; historical token storage remains 4,096 bytes |
| `account_identity`, `account_lifecycle`, `messages` and two message indexes | Preserved existing identity, lifecycle, body cache and sticky local-read `unread` |
| `mailbox_checkpoint` | Nullable History cursor, RecoveryRequired, separate catalog-known bit and monotonic FIFO allocator |
| `provider_labels` | Exact ID/name/kind catalog; no row is a guessed definition |
| `provider_messages` | Missing versus completely observed membership; no row means Unknown |
| `provider_memberships` | Full observed label IDs, independent of sticky local-read state and catalog lifetime |
| `mailbox_commands`, `mailbox_commands_fifo` | Immutable intent family/label inputs, revision, FIFO, status, automatic budget, explicit retry ticket, duplicate-risk confirmation, dispatch and reconciliation evidence, undo ancestry |
| `command_items`, `command_items_message` | Complete targets, per-item outcomes, observation kind and last dispatch selection |
| `command_item_memberships` | Full per-target reconciliation observation, independent of cache/catalog pruning |
| `command_fields` | Per-target touched field mask and desired, actual pre-state, observed post-state, conditional expected-post-state |
| `terminal_commands`, `terminal_commands_fifo` | Compacted terminal stamp/category/counts/FIFO summaries, separate from active intent |
| `mailbox_undo` | One retained Complete message-state command; its full targets and touched evidence live in command tables |

New tables are STRICT. Names are exact 1–1,024 UTF-8 bytes, including permitted
controls and NUL; no normalization or terminal sanitization occurs in storage.
Message IDs retain their existing printable-ASCII contract, distinct from the
label/command segment contract and canonical decimal History IDs. Revisions and
retry/dispatch/guard/source stamps use exactly eight big-endian bytes, supporting
the application's full `u64` range without signed integer narrowing. FIFO uses
positive SQLite integers; later methods must fail on allocator exhaustion.

Later method slices must check their transaction quotas before insertion and
bound/type-check projections before allocating domain values: 500 catalog rows,
512 memberships per message/item, 1,000 targets per command, 32 nonterminal
commands, 4,096 nonterminal target references, 128 terminal summaries and one undo
candidate. Full command bodies remain only for nonterminal work and that candidate.
Summary expiry never expands a lookup into admission; no tombstone table or
unbounded retention is introduced. Domain constructors still validate touched
masks, User-label classification, exact coverage and terminal semantics. P5a does
not claim those later transaction methods are implemented by SQL CHECK clauses.

Foreign-key cascades run only from observed-message rows to their membership,
and from explicitly removed command bodies/items to their owned evidence. No
command/undo row references cached `messages` or `provider_labels`. Their pruning
cannot cascade away pending/undo evidence. The undo slot prevents removal of its
referenced command until the slot is deliberately changed in a transaction.

## Durable dispatch and compensation markers

P5c must commit these in the pre-dispatch transaction, before any provider write:

- `dispatch_started = 1`, `dispatch_revision` and `dispatch_authorization`
  (0 automatic, 1 explicit). They identify possible dispatch independently of
  `automatic_attempts`, current aggregate revision/status and retry-ticket state.
  An explicit-only dispatch can have zero automatic attempts. A NULL
  `dispatch_fact` after this marker means no recorded result, including a crash
  before `record_dispatch`; it never means no possible dispatch.
- `compensation_guard_revision` records the first successful fresh whole-target
  expected-post-state check for an admitted compensation. It survives partial
  progress and subsequent revisions. Recovery reconciles remaining targets using
  retained evidence; it must not reapply the original pre-compensation whole-set
  guard against already compensated targets. A not-yet-dispatched compensation
  with no marker still requires that original guard before its first dispatch.
- `dispatch_fact` and its separate `dispatch_label_id/name` retain the last remote
  result independently of later `observed_label_id/name`, `label_observation`,
  `create_matches`, `reconciliation_failure` and current revision. A reconciliation
  failure/status change must not clear the dispatch marker, selected targets,
  pre-state, guard marker or dispatch result. A later authorized dispatch replaces
  the last-dispatch stamp/result/selection atomically, retaining original touched
  pre-state and settled item evidence needed for undo/recovery.

Dispatch fact codes are batch acknowledgement 0, created-label acknowledgement 1,
label-definition acknowledgement 2, ambiguity 3, authorization rejection 4,
rate-limit rejection 5, definitive rejection 6. Reconciliation failures are read
unavailable 0, invalid evidence 1, compensation refused 2. Label progress is pending
0, complete 1, failed 2. Create matches is NULL unknown, 0 zero, 1 exactly one, 2
multiple; the adopted immutable ID is stored separately. Category is message 0,
compensation 1, label definition 2. Other closed mappings are documented in the
migration. These are storage encodings, not network/command orchestration.

The SQL fixture covers explicit dispatch with zero automatic attempts, no recorded
result, a later NeedsAttention revision/failure and partial compensation progress.
Reopen preserves the distinct dispatch/guard stamps and touched/item evidence.
This proves representability/persistence, not correct P5c transition behavior.

## Migration and read boundaries

Recognized v1/v2 migration uses one immediate writer transaction. It rechecks
canonical ownership, fully authenticates old pages even for a Skip caller,
validates legacy row types/lengths and bounded metadata,
adds the v1 email column if needed, creates all v3 objects, sets v3, revalidates
canonical objects/singletons, and commits. Body validation uses SQL type/length,
never a body-value result. Failure rolls back objects, email, version and data.
Existing grants become ReadOnly and Active if a token exists, otherwise Missing;
cursor/catalog/queue/undo remain empty and old memberships remain Unknown.

Routine ownership validation reads canonical objects and bounded singleton
metadata only. It does not query message bodies, catalog, membership or item rows.
The existing first-open Full policy still scans page integrity, cipher integrity
and foreign keys, including new table pages. `IntegrityScan::Skip`, for stores
already scanned by the process, now also skips the potentially large foreign-key
walk. Foreign-key enforcement remains enabled for writes. Later row-consuming
methods must fail closed on their bounded row decodes, as existing mailbox reads
do. Strict readonly open retains Full scans; it never migrates, creates, repairs
or checkpoints. Readonly email revalidates version/schema/metadata in one read
transaction, so a concurrent writer migration gives a known complete snapshot
or a closed failure. Existing path/key/owner/held-file/sidecar checks are retained.

A SQLCipher page-damage regression proves that repeated metadata/envelope reads
and Skip writer opens do not visit a damaged membership page; a direct membership
read and Full open reject the same page. The existing body-overflow damage test
continues to distinguish Full from Skip. There is no new unconditional mailbox
scan on reopen. First Full integrity work grows with actual stored pages; v3 also
adds bounded canonical-object/singleton work. An isolated one-envelope/one-membership fixture measured 2.59 ms for readonly
Full open, 3.69 ms for three metadata/envelope passes and 7.50 ms for Skip writer
open on this host. These are current-candidate observations, not a baseline
comparison, representative large-cache benchmark or latency guarantee.

## Credential bridge boundary

`load_credential_snapshot`, `replace_credential_snapshot` and
`delete_credential_snapshot` use store-local redacted/zeroizing types. Snapshot
state includes the actual account, immutable routing subject, capability,
Missing/Active/RevocationOnly credential and optional algorithm-2 identity hash.
An unfinished binding can have no subject; it cannot be replaced through the new
API until bound. No new account is provisioned. A recorded subject cannot be
changed through the legacy subject setter.

Replacement acquires an immediate transaction, compares the full expected
snapshot (including absent identity), updates token/capability/purpose in one SQL
statement, checks the resulting pair and commits. Deletion preserves capability.
Fresh snapshots are required after any successful change; stale writes/deletes
fail without overwriting. Runtime later bridges broker-specific operations and
must serialize account operations plus invalidate process-local sessions.
There is no credential-generation column.

New typed and legacy usable accesses enforce 1–1,024 credential bytes. Migration
preserves historical values through 4,096 bytes without truncation; unsupported
occupied reads fail instead of reporting absence. Legacy token-only reads/writes
accept only ReadOnly Active/Missing state and cannot expose, overwrite, clear or
downgrade Modify/revocation-only state. New capability-aware APIs retain exact
bounded UTF-8 credential bytes; legacy APIs retain their printable-ASCII rule.
No credential enters display/log/error text. SQL CASE type/byte-length projections
precede Rust materialization; the bounded token/subject are immediately zeroizing.

Real deferred foreign-key commit failures cover rollback after migration work
and after token/capability/purpose replacement, including deletion and rejected
rotation retention. These use test-local temporary SQL objects, with no production
failpoint or test-only exported API.

## Interim legacy destructive operations

Until P5c implements detailed pins/guards, legacy reset, purge, identity-clear
and reconcile/prune refuse **any retained command body or undo slot**, including
a Complete undo candidate. Refusal is an opaque storage failure in the old ports;
P5c must replace it with the intended typed eligibility/guard/pin behavior. This
is deliberately conservative and can block readonly pruning while T4 evidence
exists. No pending/undo evidence is silently discarded.

With no command bodies/undo slot, successful reset/identity-clear/purge atomically
clear History/recovery/catalog-known metadata, provider catalog/membership and
terminal summaries together with their existing cache operation. Reset retains
binding/capability/credential/identity/disconnect recovery. Purge clears the grant
and resets capability/purpose with the existing subject/identity teardown. Legacy
reset/prune rollback tests remain intact. No T4 runtime, History transaction,
queue method, provider call, retention algorithm or live acceptance is claimed.

## P5b History and cached-read implementation

P5b implements `HistoryCursorStore` on `SqlCipherMailboxStore` using the fixed
v3 layout. No canonical SQL, version, migration, registry or credential behavior
changes. P5c command admission/transitions/settlement/retention and P7 runtime
activation remain pending. Directly seeded command rows in P5b fixtures prove
History retention/relationship behavior, not successful P5c admission.

Each write takes one immediate transaction, checks existing ownership and actual
algorithm-2 identity against `AccountFence`, compares the expected cursor, then
commits every decision plus exactly the record ID, or all snapshot metadata plus
the retained captured baseline. A later failed record preserves the prior
committed prefix. The terminal-head method accepts the approved
`TerminalHistoryCheckpoint` document and requires its final-record predecessor
already durable; a stale or skipped predecessor cannot advance it. These methods
do not reinterpret provider events, synthesize continuation/checkpoint values,
require Modify capability or load a usable credential. Runtime still owns
provider authorization, provenance, complete-chain acquisition, account-operation
serialization and recovery policy. No network work occurs in these transactions.

`classify_record` reads bounded cache/pin presence without bodies. Application
classification is planning evidence: `apply_record` rechecks each Irrelevant key
against actual cache/pins under the writer lock. Newly pinned/cached targets
reject the whole record, including earlier attempted writes. An exact accessed
provider parent/child inconsistency also fails instead of becoming Unknown.
Metadata-only updates preserve existing bodies and sticky `messages.unread`.
Complete provider membership remains independent of that local-read display.

New metadata competes with retained metadata for the first 100 messages ordered
by `received_at DESC, message_id ASC`; all pending and undo targets remain pinned
in addition to those recent survivors. Snapshot omission does not delete pinned
metadata, synthesize Missing, or settle command items. An exact observed Missing
may delete the cached envelope/body, but command/item/touched/undo evidence is
untouched. Missing observations persist for pinned targets. Once a target has
neither a cached envelope nor a pin, its observations are discarded and reads
return Unknown; there is no unbounded outside-cache missing/tombstone log.
Snapshot metadata joins the same deterministic recent competition, rather than
interpreting omitted list entries as exact-key deletions.

Pin derivation validates at most 33 command bodies, one undo slot, 5,096 target
references and 10,192 touched-field rows, using one extra rejection sentinel at
each bound. It checks command IDs/status/kind/revision/attempt/FIFO shape,
label-intent shape, each target's owning aggregate, nonempty message-command
coverage, per-command and account target bounds, undo's Complete message-command
ancestry, and each touched-state footprint/required retained pre/post state.
Orphan item/field/undo relationships are errors; no inner join silently drops
those references. This does not walk per-item reconciliation membership (which
P5c must validate when consuming it), implement queue transitions or inspect
terminal summary payloads. New History pruning reads only bounded envelope
identity/time and provider-parent identities, with at most 6,196 transient rows:
4,096 pending references + 1,000 undo targets + 100 recent + 1,000 new record
candidates. An over-bound or malformed accessed row fails and rolls back, rather
than silently truncating. Exact provider membership is validated before replacing
or discarding an accessed observation. Legacy reset/purge/identity-clear and
legacy reconcile/prune keep their P5a conservative refusals; only the new History
path performs pin-aware pruning.

`cached_provider_state` and `cached_provider_states` read one exact key or at
most 200 unique requested IDs, retaining request order and explicit account/key
pairing. They distinguish Unknown, observed Missing and Known (including empty).
Each exact membership query admits at most 512 labels plus one rejection row,
checks type/byte length before Rust allocation, validates label IDs and checks
children even when the parent is absent. It never loads bodies or performs a
global membership scan. Unrelated membership is not read as a side effect.
`cached_label_catalog` distinguishes Unknown from complete empty, and rejects
overflow/malformed definitions or catalog rows under an unknown marker. Catalog
replacement compares actual identity and atomically replaces a complete typed
catalog of at most 500 labels, leaving message membership untouched. Names retain
exact UTF-8/control/NUL bytes. None of these cached values proves fresh command
reconciliation, continued User classification or provider eligibility.

Both store and readonly reader implement `AccountMetadataReader`. Known accounts
may legitimately have no email; another requested account returns None without
provisioning. Upgrade bindings contain the bounded immutable subject and reject
unreadable/foreign identity rows or missing/invalid subject, rather than claiming
unknown account. A missing identity is valid interrupted registration; a supplied
History fence still requires an actual matching identity. Legacy readonly v1/v2
return ReadOnly capability and Unknown provider state/catalog without migration.
A reader held over a legitimate writer migration uses one coherent version in
its new read transaction, or fails closed.

The new readonly cached/profile/binding entrypoints strengthen the previous
constructor-only file boundary: a narrow helper locks once, checks the retained
main/WAL/SHM identities and modes plus held-main movement, disables/verifies
checkpoint-on-close and confirms readonly connection authority, then validates
canonical ownership/singleton metadata and readonly health flags in a deferred
transaction. It repeats movement/leaf checks after the transaction before
returning data. It uses Skip health, without repeating full page/FK walks.
Original constructor checks and all legacy read methods are unchanged. These are
observable pre/post checks, not continuous filesystem custody: same-user
swap-and-restore races can remain undetected, and SQLite/VFS sidecar bookkeeping
residuals from the constructor still apply. The helper does not migrate, create,
checkpoint, repair permissions or return a cached success after observed drift.

SQLCipher tests cover attempted-write and deferred-commit rollback (including
snapshot pruning), predecessor/identity/owner refusal, preserved committed prefix,
Irrelevant-to-pinned/cached races, deterministic retention with seeded pending and
undo pins, Missing versus snapshot omission, the full 1,000-target record path,
500-label catalog and 512-membership successful bounds, malformed/overflow/orphan
reads, readonly v1/v2/v3 no-write reads and migration coexistence, new read-time
main/sidecar refusals, and damaged-body/unrelated-membership noninterference.
They make no live provider, runtime, recovery-coordinator or P5c completion claim.


## P5c durable command implementation

`MailboxCommandStore` is implemented by `SqlCipherMailboxStore` without changing
canonical v3 SQL, migrations, dependencies or registry format. Private bounded
codecs reconstruct named message actions, classified User IDs and touched states
through domain constructors. Raw SQLite types and byte lengths are checked before
Rust allocation. Accessed item, membership, field and undo-source relationships
reject corruption or orphans; routine open still does not walk these tables.
Full membership decoding is bounded to 512 IDs per accessed command item.

Every semantic mutation takes an immediate transaction and checks actual owning
account, algorithm-2 identity, command revision and applicable FIFO conditions.
Fresh admission and dispatch require persisted Modify and no disconnect recovery;
usable credentials are not loaded. Retained admission IDs return saved state.
Lookup is separate: unknown/expired replay does not admit intent. Fresh compensation
is admitted only through the current undo candidate and its admission-only empty
nonterminal-queue gate. Both 32-command and 4,096-full-target-reference limits,
FIFO allocation, Queued intent, fields and pins commit together. Revision and FIFO
exhaustion fail without wrap or partial writes.

Preparation compares fresh whole-command evidence against the actual snapshot,
selects only unsettled unmet targets, captures actual touched pre-state for all
known targets (including initial already-satisfied targets), and commits selected
IDs, Dispatching, dispatch revision/authorization and attempt/ticket consumption
before returning a receipt. Original touched pre-state and possible-dispatch
markers survive later failures and revisions. Interrupted Dispatching recovers as
Ambiguous, including an explicit-only attempt with zero automatic attempts and no
recorded transport result. Acknowledgements do not settle commands; stale outcomes
and retry tickets cannot overwrite later revisions. Three automatic attempts are
separate from each single-use explicit retry permission, and reconciliation moves
an unused ticket to the new revision. Failed reads invalidate the ticket.

Settlement derives item outcomes from complete same-account exact-key observations.
All missing is terminal Partial with zero successes. Unknown/failed reads retain
uncertainty and pins. An ordinary Remove User label can complete without a write
when membership already lacks that exact ID, even if the definition is missing;
Apply and dispatch still need the actual User definition. Create adopts exactly
one complete-catalog match; zero/multiple never permit automatic recreation after
possible dispatch. A further explicit create requires fresh zero matches and the
duplicate-risk confirmation. Rename/delete use observed known-ID name/absence.

The first compensation settlement or dispatch must freshly validate the entire
target set, required User label and touched expected post-state. Generic desired
state matching cannot bypass that comparison. The admission-only queue gate is
not repeated for the undo itself or later queued work. First dispatch persists the
guard marker, allowing partial recovery against remaining targets without
reapplying the original condition to targets already restored. This is local SQL
atomicity, without provider CAS or distributed rollback.

Terminal disposition and bounded summaries commit before FIFO/quota/pin release.
Only Complete original message-state work replaces the undo slot. Label CRUD and
compensation preserve it; its full body can outlive the 128-summary window. Cache
pruning retains every nonterminal/undo target, including through the existing
legacy 10,000-envelope reconciliation API. Terminal release prunes observations
that no longer have a cache row or pin. No nonterminal evidence is evicted.

Reset, purge and identity replacement refuse all nonterminal work. The existing
`mark_disconnect_started` operation now checks this guard in the same transaction
before recording the pre-revocation marker. Recording a post-attempt unconfirmed
revoke and local cancellation/settlement/Abandon remain possible after grant loss.
Warned Abandon retains a terminal summary before releasing guards in the same
commit. After safe disposition, reset clears terminal/undo/History/catalog/cache
metadata while preserving binding, grant, identity and existing disconnect rules;
purge performs its existing grant/identity teardown atomically. The old cache-reset
identity/subject/credential/recovery eligibility checks remain in force.

SQLCipher tests use production admission, preparation and settlement, competing
connections and real deferred foreign-key commit failures. They cover rollback,
FIFO/account/identity/revision guards, replay, automatic/explicit budgets, restart
ambiguity, label ambiguity, full-target pre-state, whole-set undo refusal and
partial recovery, bounded membership, retention, pins, lifecycle guards and
Abandon commit failure. No owner receipt is fabricated to claim persistence.
P6 orchestration, P7 runtime composition, independent approval, full-host checks,
provider freshness/provenance, process-local generation fencing and live account
acceptance remain separate responsibilities and claims.


## P7b cached triage read prerequisites

`CachedMailboxFilter` is closed to Recent, Inbox, Trash, Spam and an account-bound
User-label ID. `list_filtered_envelopes_after` is available on both the store and
readonly reader. It applies complete observed membership in SQL before LIMIT,
using the existing `received_at DESC, message_id ASC` keyset order. Pending desired
intent and label names do not enter the predicate. Recent keeps all cached rows,
including Unknown, Missing and known-empty provider metadata; only actual complete
observed membership matches the other filters. Returned envelope unread display
values retain their existing sticky local-read semantics.

Pages are limited to 1 through 201 envelopes, supporting the existing 200-row
unified query plus its continuation probe. Larger StoreLimits and foreign
accounts/User labels fail through the existing closed mailbox errors. Envelope
projections retain bounded type/byte checks, and each returned current-schema
key's complete provider observation is validated within the existing 512-label
bound. Unrelated candidate envelopes and memberships are not materialized. The
existing ordering and primary-key indexes are used without adding a canonical
object; sparse filters can require scanning more ordered index entries, so this
is a materialization bound rather than a constant SQL-work or latency guarantee.
Legacy v1/v2 readers return useful Recent pages and empty observed-filter pages:
the old format has no observed membership, and these reads never migrate it.

`pending_commands(&AccountFence)` is also available on both types. One readonly
transaction checks actual ownership and the identity fence, then uses P5c's real
bounded queue/item/field/observation/undo reconstruction for every nonterminal
snapshot in FIFO order. It rejects overflow or accessed corruption rather than
truncating: at most 32 nonterminal commands and 4,096 full target references are
returned. Terminal summaries and the retained Complete undo source are excluded.
Persisted Dispatching remains Dispatching; no recovery transition, usable token
or access session is required. A valid identity-fenced legacy store has an empty
queue; absent, foreign or invalid identity still fails the existing fence check.

Both read surfaces use the existing cached-read transaction boundary, including
readonly pre/post file identity, movement, permission, sidecar, schema and Skip
health checks. They never select message bodies, perform a global integrity/FK
walk, load credentials, alter command transitions or dispatch, or write data.
Tests cover late matching pages and equal-time continuation, unavailable versus
observed membership, exact User IDs/account routing, pending-intent exclusion,
legacy non-mutation, damaged body-page avoidance, established readonly path
faults, real admitted queues across reopen, uncertainty/terminal exclusion and
full quota/relationship/fence failures. Runtime composition, host verification,
independent approval and live/provider acceptance remain separate claims.
