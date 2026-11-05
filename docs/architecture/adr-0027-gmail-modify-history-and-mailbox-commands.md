<!--
This Source Code Form is subject to the terms of the Mozilla Public License,
v. 2.0. If a copy of the MPL was not distributed with this file, You can obtain
one at https://mozilla.org/MPL/2.0/.
-->

# ADR 0027: Gmail modify, History, and mailbox commands

- Status: implemented on candidate `771bacbf19766ffa3d4cbb29b981489607283c89` (tree `e6caedd32cea7d13309ef356897c12e1a0acef8c`); live Modify acceptance has not been run; T4 is not complete
- Amended by: [ADR 0031](adr-0031-tui-only-pivot.md) (terminal-only pivot)
- Date: 2026-08-29
- T4 prerequisite contract: 2026-11-04

## Implementation status and accepted boundary

History, Modify capability and the closed mailbox-command set are implemented
in the candidate above. Baseline `a00b825` had fixed ReadOnly OAuth, a GET-only
`GmailMailbox`, account schema v2, and no History or command store. That
baseline is historical. `application::identity::AccountProfile` remains a
validated subject trait. Persisted capability and email are store fields and
do not replace that trait. ReadOnly accounts keep the readonly path.

The implemented requirements are: official Gmail API access, broker-only token
custody, account-local encrypted persistence, transactional History/cursor
application, durable desired state before dispatch, per-message reconciliation
of ambiguous batches, bounded sanitized status and the closed triage command
set. The contract below is that implemented behavior. It is not live Gmail
Modify acceptance.
See the [execution plan](../development/t4-execution-plan.md) for slice merges
and the [live protocol](../development/t4-live-acceptance-protocol.md) for the
unrun provider gate.

The closed command set is read/unread, star/unstar, archive, trash/restore,
spam/clear spam, user-label create/rename/delete/apply/remove, and account-local
message-state batches of at most 1,000 IDs. No permanent message delete, mute,
send/drafts, push/relay, MCP or T5-T8 feature is authorized. The accepted
[ADR 0018](adr-0018-bounded-sync-and-cache.md) recent-cache boundary remains;
T4 does not promise lossless full-mailbox synchronization.

## T4 prerequisite contract

This section is the contract implemented on the candidate. Live acceptance has
not been run. Provider facts still do not guarantee local atomicity,
label-create idempotency or read-after-write consistency.

### Capability and grant custody

`AccountCapability` is closed to `ReadOnly` and `Modify`. Requests contain only
`openid` and the selected Gmail scope: `gmail.readonly` or `gmail.modify` under
`https://www.googleapis.com/auth/`. Existing constructors remain explicitly
ReadOnly compatibility entry points until consumers migrate. Capability-aware
begin binds an immutable requested capability; transport returns bounded closed
scope facts and application policy decides acceptance, never the old readonly
boolean alone.

An absent scope field inherits the immutable requested capability for callback
and exchange; an explicitly present scope set lacking that capability's required
Gmail scope is rejected. An explicit ReadOnly result containing `gmail.modify`
is a mismatch. Modify may include readonly too. New grants containing
`gmail.send` or `https://mail.google.com/` are rejected. This separates absent
scope from explicit reduction, consistent with token-response and refresh scope
semantics in [RFC 6749 sections 3.3, 5.1 and 6](https://www.rfc-editor.org/rfc/rfc6749).
Callback acceptance is the product's capability-bound predicate, not an RFC
claim about Google's callback fields.

Refresh atomically reads stored token plus capability, validates the same
immutable subject, never changes capability and never promotes ReadOnly. An
absent refresh scope inherits the stored grant capability. Explicit scope
rejection exposes no usable access token; retaining a valid rotation solely as
a revocation handle remains the separate failure path in
[ADR 0024](adr-0024-token-lifecycle-and-custody.md). Mutation requires persisted
Modify plus a current access token accepted for Modify at the current credential
generation.

Connect and selected-account Upgrade/reconnect are distinct bound flows:

- Connect validates a new subject before admission. A new binding may initially
  have no token and ReadOnly, but success requires one transaction persisting
  token plus requested capability. Duplicate Connect never overwrites or
  downgrades an existing grant; direct the user to explicit same-account
  reconnect/upgrade. The explicit readonly compatibility API retains its
  established reconsent behavior until migrated.
- Upgrade captures selected `AccountId` and expected stored immutable subject
  before browser launch. Another subject causes no registration, write or
  revoke. A validated same-subject grant replaces token plus capability in one
  owning-account transaction; separate successful writes cannot emulate this.
  Denial, mismatch or insufficient scope preserves the old grant.
- One account operation permit serializes grant replacement, History, commands,
  reset/remove and identity-changing writes. Broker subject permits and sole
  credential custody remain. Hold no mutex or SQL transaction across network
  awaits. After successful upgrade, invalidate cached access sessions while
  holding the account permit; generation fences reject stale access/command
  completions. Credential generation is process-local, not a v3 column. Restart
  drops all access sessions; durable Dispatching still recovers as Ambiguous.

Scope rejection precedes validated identity at completion. An explicitly
under-scoped first-connect/upgrade response persists and revokes nothing in-app;
manual Google Account revocation guidance remains necessary. Do not erase that
[ADR 0024 residual](adr-0024-token-lifecycle-and-custody.md) or the grant-wide
revocation risk to another installation. Refresh-time `invalid_grant` still
requires confirmed credential deletion before reporting reconnect; cached mail
is preserved. Identity failure is not permission for grant cleanup.

### Values, ports and storage ownership

Domain values include bounded redacted `HistoryCursor`, `MailboxCommandId`,
`MailboxCommand`, `DesiredMailboxState`, `LabelDefinition` and a validated label
ID. History record IDs/cursors are canonical nonnegative ASCII decimal strings
of 1-32 digits, compared by magnitude without arithmetic or lexical ordering of
unequal-length strings. This decimal rule does not apply to `MessageId`.

Application extension ports are `GmailHistoryFeed`/`HistoryPage`,
`RemoteMailboxCommands`, `HistoryCursorStore` and `MailboxCommandStore`;
`HistorySync` and `MailboxCommandCoordinator` orchestrate them. Ports remain
runtime-free with closed provider-data-free failures. They extend rather than
weaken `RemoteMailbox`/`MailboxStore`. Trusted runtime composition owns routing;
SQLCipher owns all migrations and atomic transactions, with no raw SQL, keys or
tokens exposed to the coordinator or TUI.

The [ADR 0017 v3 prerequisite contract](adr-0017-production-account-store.md#t4-account-schema-v3-prerequisite-contract)
retains account identity/binding/grants and migrates recognized v1/v2 in one
writer transaction. Registry schema stays v1; identity algorithm stays 2. No
unknown-schema reset, quarantine or downgrade is implied.

### Closed endpoint and desired-field map

Keep GET-only `GmailMailbox` and OAuth token transport separate from the new
account-bound Modify component. History GET, profile baseline GET, message
metadata/minimal GET and label catalog/label GET support reads; existing bounded
message list/raw reads remain. ReadOnly may use approved reads but cannot
construct or dispatch a mailbox write. The write allowlist is exactly:

| Method and resource under `users/me` | Allowed request fields |
| --- | --- |
| POST `messages/batchModify` | `ids`, `addLabelIds`, `removeLabelIds` only |
| POST `labels` | `name` only |
| PATCH `labels/{validatedUserLabelId}` | `name` only |
| DELETE `labels/{validatedUserLabelId}` | No body |

Google documents the [batch POST](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/batchModify),
[label create POST](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.labels/create),
[rename-capable PATCH](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.labels/patch)
and [label DELETE](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.labels/delete).
The narrow payloads and exclusive method selection above are product rules.
Label deletion removes that label and assignments, not the messages.

No arbitrary user resource/path, PUT rename, dedicated trash/untrash route,
classification-label fields, permanent message DELETE, mute, send/draft/watch
endpoint or broader requested scope is exposed. Validate owner and IDs before
URL construction or local query. Retain HTTPS-only/no-redirect/no-proxy policy,
bounded responses and redacted failures.

Each message-state desired patch touches only the following memberships:

| Action | Required observed desired fields |
| --- | --- |
| Read / unread | `UNREAD=false` / `UNREAD=true` |
| Star / unstar | `STARRED=true` / `STARRED=false` |
| Archive | `INBOX=false` |
| Trash | `TRASH=true`, `INBOX=false` |
| Restore | `TRASH=false`, `INBOX=true` |
| Spam | `SPAM=true`, `INBOX=false` |
| Clear spam | `SPAM=false`, `INBOX=true` |
| Apply / remove User label | That validated account-bound User-label membership only |

Untouched fields remain outside the patch; Complete requires observation of all
touched fields. Restore explicitly means return to Inbox, whereas undo restores
actual recorded pre-state. Never silently include `IMPORTANT`, `SENT`, `DRAFT`
or other system labels. Google's [label guide](https://developers.google.com/workspace/gmail/api/guides/labels)
distinguishes manually applicable labels; this product exposes only the map
above, not arbitrary system-label operations.

### Finite work and retention budgets

These are product bounds, not provider capacity or convergence guarantees.

| Resource | Bound and exhaustion behavior |
| --- | --- |
| History | 500 records/page; 4 pages and 2,000 records/cycle. Checkpoint only fully decided progress; remaining work resumes later. |
| Decoded History events | At most 1,000 unique affected message IDs/record; local processing budget 10,000 affected references/page within the existing 2 MiB JSON response cap. Expose only a contiguous whole-record prefix that fits, with an explicit local-truncation indicator. A single over-limit/undecidable record remains unapplied and reports RecoveryRequired. |
| History metadata | 1,000 lookups/cycle. Reserve the entire next record's requirement before starting its lookups; if it cannot fit after earlier work, stop before it and resume from the committed prefix. A supported 1,000-target record fits a fresh cycle. |
| Body hydration | Optional, at most 25/cycle after metadata/cursor commit; failures reported separately. |
| Snapshot fallback | Existing 4 pages of 25, keep 100; optional 25 bodies after metadata/baseline commit. Truncation is a valid recent-cache snapshot, not a full-mailbox result. |
| Command queue | At most 32 nonterminal commands and 4,096 total nonterminal target references/account. Check both quotas in the admission transaction; label-only commands consume a command slot. |
| Command/batch | At most 1,000 distinct message IDs, partitioned by account before admission. |
| Command reconciliation | At most 1,000 minimal GETs/pass; unresolved work remains pending. |
| Automatic dispatch attempts | At most 3 total/command, including the initial attempt; further automatic attempts require fresh observation of unmet idempotent desired state. At exhaustion retain NeedsAttention. Ambiguous label create is never automatically recreated. |
| Label catalog/name | At most 500 labels; names 1-1,024 UTF-8 bytes, exact encrypted provider bytes for equality and sanitized only for display. Catalog overflow disables catalog-dependent create/name reconciliation. |
| Message membership | At most 512 label IDs, with full observed membership or failure. Overflow fails the record/command closed; never persist partial membership or infer omitted labels absent. |
| Terminal retention/undo | At most 128 terminal aggregate summaries plus one undo candidate/account. Compact terminal per-item rows except the active undo record. Never evict nonterminal evidence to meet a quota. |

### Record-atomic History and snapshot baseline

[History list](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.history/list)
returns increasing non-contiguous IDs, limits pages to 500, and identifies the
response `historyId` as current mailbox history. Store that response cursor only
when the whole chain is decided and `nextPageToken` is absent. Specific event
arrays can overlap the generic message array; apply specific events once and do
not double-apply generic duplicates. Validate ordering, duplicate/conflicting
records, ownership and response/continuation bounds before commit.

Collect network data outside SQL transactions. **One complete, fully decided
record is the atomic application unit:** its transaction applies all relevant
data and commits that record ID. A run may commit contiguous decided records;
earlier commits survive failure of the next record, but no subset of a record,
invalid application, cancellation or storage failure advances that record's
cursor. Protocol-invalid page envelopes fail before application; a malformed or
oversized next record stops before that record.

Walk the page in order within its local reference-processing budget. The bounded
decoder/coordinator may expose only the contiguous whole-record prefix that
fits, marking local truncation explicitly. Do not reject an otherwise valid
whole page merely because later records exceed that processing budget. Commit
decided records and resume later from the last committed record cursor; never
fabricate a provider continuation token or install a locally truncated page's
response `historyId`.

On the final page, a valid nonregressing response `historyId` may be committed
only after every record in the chain is decided, no local truncation exists and
no provider continuation remains. An empty final page with a valid cursor is
valid. Empty intermediate pages may follow fresh tokens within the cycle
budget; repeated tokens are errors. Budget exhaustion with no durable progress
reports RecoveryRequired, not completion or an automatic busy loop. A single
over-limit or undecidable record remains unapplied. Recovery permits later
explicit retry, or cache reset after every nonterminal command has been
cancelled (Queued), settled or explicitly abandoned. Reset clears the cursor
and captures a new baseline through the defined path. No non-404 failure or
budget exhaustion triggers automatic snapshot fallback or promises convergence.

Hydrate new `messageAdded` IDs as bounded recent candidates, then deterministically
compete for keep-100. Reconcile existing cached/pinned IDs. Old label/deletion
IDs outside the cache and pins may be decided no-ops; that decision does not
claim full-mailbox convergence. Preserve pending targets and undo pins while
pruning. Provider observations are never derived from a local-read overlay.

No cursor, or specifically a History-cursor `404`, captures
`GET users/me/profile?fields=historyId` **before** collecting the bounded
snapshot. [Profile GET](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users/getProfile)
provides current mailbox history. Commit successfully collected snapshot metadata
plus that retained baseline in one transaction, then hydrate optional bodies.
This refines the [recent-cache/full-sync guidance](https://developers.google.com/workspace/gmail/api/guides/sync)
with the product's baseline-before-snapshot ordering. Baseline/collection failure
preserves old cursor and all pending commands. Message `404` and every other
non-History-cursor-404 error do not trigger snapshot fallback. Pending commands
need their own fresh reconciliation; snapshot absence cannot settle them.
History remains in-process foreground/manual/resume work, without push, relay
or execution while tersa is not running.

### Durable commands and reconciliation

Admission atomically persists account, command ID, full bounded targets and
desired state as `Queued`. No mailbox-mutation attempt has happened in that
state; read-only preflight/network is possible and local cancellation is allowed.
Before a mailbox mutation, atomically persist `Dispatching`
and reconciled pre-state needed for undo. Crash, cancellation or restart from
Dispatching is `Ambiguous` even if no socket write actually occurred. There is
no post-send marker that can make a missing acknowledgement safe to repeat.

A successful empty batchModify response is the documented acknowledgement,
not a failed bodyless transport. It still requires per-item reconciliation
before Complete. Timeout, connection loss or a bodyless transport failure after
possible dispatch remains ambiguous. Never use the read-only `retry_rejected`
helper for writes or assume a batch timeout is atomic.

Dispatch/recovery is FIFO and single-flight per account. Unresolved possible
dispatch on the oldest command blocks later writes; cached reads and bounded
read-only synchronization remain available. Admission/cancellation use the same
account/store coordination. A replayed retained command ID returns saved status;
an expired or unknown replay ID cannot enqueue or dispatch new work. Fresh
admission is distinct from replay lookup.

Inspect History, then bounded minimal GET where History is insufficient. Settle
an item only from same-account observation of desired state. For message-state
commands, observed target absence is terminal `TargetMissing`, not fabricated
success. Already settled items are not redispatched. `Complete`, `Partial` and
`Ambiguous` are account-level aggregate statuses with bounded counts, distinct
from item outcomes. Complete is terminal success. Partial is terminal once all
items are resolved and at least one is a known failure, including TargetMissing,
even if no item succeeded. These terminal outcomes do not block FIFO; only
Complete message-state commands qualify for undo. Ambiguous and NeedsAttention
remain nonterminal. The automatic budget is three total dispatch attempts per
command, including the initial attempt; further automatic attempts require fresh
unmet-state evidence. NeedsAttention retains unresolved
evidence and is not success or permission to evict possible-dispatch state.
Missing/corrupt state fails closed; local rows or omitted batch results never
supply success evidence.

### Label ambiguity

[Label IDs](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.labels)
are immutable; names are display values, and system definitions cannot be
created, renamed or deleted. Validate an account-bound User label before any
CRUD/apply/remove use. Catalog overflow does not permit guessed IDs; applying
or deleting a previously validated User label still requires fresh target
verification. Membership must be fully observed within its bound.

After an ambiguous CREATE, reconcile a complete bounded catalog. Exactly one
matching User label may be adopted by its observed provider ID. Zero or multiple
matches remain Ambiguous/NeedsAttention. Even a negative list result never
permits an automatic second create: provider idempotency/read-after-write
consistency was not established. After a fresh complete catalog still has zero
matches, the user may authorize one new attempt with explicit confirmation of
possible duplicate-label risk. This consumes one explicit retry authorization,
never an automatic retry. Multiple matches never permit another create.
Rename uses the known ID and name-only PATCH;
reconcile that ID/name before retry. Delete settles only after observed absence
of the known User-label ID. Never guess or replace provider identity.

### Explicit recovery exits

Ambiguous/NeedsAttention offer **Retry** and **Abandon**. Retry first performs
fresh bounded reconciliation: satisfied state settles without a write;
otherwise it authorizes at most one new dispatch after identity, capability and
normal guards are rechecked. It does not reset or loop the automatic retry
budget. Failed pre-dispatch reconciliation returns NeedsAttention without any
mailbox mutation. Label-create zero-match retry additionally requires the
duplicate-risk confirmation above; multiple matches never authorize creation.

Abandon atomically writes a retained terminal `Abandoned` summary before
releasing FIFO, pins and quota. Confirmation explains that Gmail may already
have applied the operation and automatic recovery will stop. This is not success,
provider rollback, cache reset or silent evidence deletion. Later writes, reset
or removal become eligible only after the terminal summary commits. Bounded
terminal retention applies; the abandoned ID can never be retried or reenqueued.
A newly selected user intent is a new operation, not hidden replay. This explicit
disposition also makes History cache-reset recovery possible after unresolved
commands have been abandoned.

### Views, undo and lifecycle

Provider label state is separate from legacy local-read presentation. Migrated
membership is `Unknown`, never guessed. ReadOnly retains established local-read
display; Modify uses observed provider state with visibly pending desired-state
overlay. Opening a message introduces no provider mutation.

Name the default view **Recent** (all cached), preserving offline rows. Explicit
Inbox, Trash, Spam and User-label filters operate within existing All/single-account
scopes and use observed membership only. Unknown rows remain accessible in Recent,
with missing label metadata disclosed. Retain global 200-row application query
caps and `(AccountId, MessageId)` pairing; these are bounded cache views.

One undo slot holds the last Complete per-account message-state command; label
CRUD does not replace it. Cancel Queued intent locally rather than call that
undo. At undo admission, refuse if any pre-existing account command is
nonterminal. This admission-only gate is not reapplied at dispatch to the undo
itself, which is now Queued, or to later queued commands. Dispatch remains FIFO:
later commands cannot overtake the undo or cause it to block itself. Offline undo
admission stores a **conditional compensation** and the original expected
post-state in the ordinary durable queue; it claims neither current eligibility
nor a provider mutation. After reconnect, before any compensation dispatch,
fresh reconciliation must validate every target, required User label and touched
post-state field across the entire target set. Any missing target/label or
inequality refuses the whole compensation without writes. Only a successful
whole-set check permits dispatch through the same durable path, restoring only
touched fields to recorded pre-state. No label-CRUD, Partial or Ambiguous undo;
no provider rollback or cross-account atomicity. A provider change after the
pre-dispatch comparison remains an explicit no-CAS residual.

Prune pins cover all nonterminal targets and the one undo candidate. Reset and
removal refuse **every nonterminal command, including Queued**; users may cancel
Queued commands first, settle work or explicitly abandon unresolved commands.
Only committed terminal disposition releases the guard. Never erase
possible-dispatch evidence as implicit cleanup.
Successful cache reset clears cursor, terminal summaries, undo state and cached
membership while retaining registration, capability, grant, identity and
disconnect recovery. Guarded removal/purge deletes all T4 account rows in the
existing account-local transaction. Identity mismatch/replacement likewise
refuses destructive change while nonterminal evidence exists, preserving a
recoverable state. These guards are implemented in the v3 store and the
existing-only reset path. They were not v2 reset behavior.

## Test and evidence gates

The [plan's test-owner matrix](../development/t4-execution-plan.md#test-owner-matrix)
assigns pure protocol/desired-state tests to application, wire tests to Gmail,
transaction/migration evidence to SQLCipher, custody to broker, composition to
runtime and sanitized affordances to presentation/TUI. Cover boundary bounds,
1,000-target record progress, one-record atomicity and local whole-record
truncation without fake tokens/response-head checkpoints, complete-or-fail
membership, empty successful batch acknowledgement, terminal Partial/TargetMissing,
three total automatic attempts including initial, single explicit Retry and
warned durable Abandon before guard release, confirmed
zero-match label retry versus multiple-match refusal, all-nonterminal lifecycle
guards and offline conditional undo with an admission-only pre-existing-command
gate, FIFO progress despite its own/later Queued commands, whole-set fresh
equality before dispatch and no writes on any mismatch. Preserve
readonly behavior during additive staging; no fake atomic defaults or duplicate
implementation-mirroring tests.

Scoped preflights applied while editing, and full `cargo xtask verify` applied
at source slice boundaries and before independent review, with no new CI
job, tool or dependency. The candidate's recorded results are in the
[acceptance report](../development/t4-live-acceptance-report.md). Separately
authorized macOS evidence, specified in the
[live protocol](../development/t4-live-acceptance-protocol.md), still has to
demonstrate same-account upgrade, command/History convergence and offline
intent after reconnect. That run has not happened. Fixtures do not prove
provider writes, keyring behavior or release acceptance. T3 acceptance remains
unchanged.

## Non-claims and consequences

The candidate implements the ports, v3 migration, durable commands and closed
Modify transport covered by automated fixtures and CLI/TUI wiring. It claims
no live Google verification, full-mailbox replay, secure erasure, app lock or
release readiness. Unknown schemas remain preserved; old binaries cannot read
v3 and no implicit downgrade/reset/quarantine exists. Stranded under-scoped
grants, same-user token/key co-residence, grant-wide revocation effects and
the filesystem residuals in ADRs 0017/0024/0031 remain.

The delivered source result is account-scoped recoverable desired state with
Gmail as authority after reconciliation. The bounded recovery path keeps
unresolved work visible. Live exercise of that path is recorded only in the
acceptance report, which currently has no observations.
