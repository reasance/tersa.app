# T4 execution plan

Status: **T4 prerequisite contract; source implementation pending**.
Contract date: 2026-11-04. Baseline:
`a00b8257945ce2dcc08f175f91aa314633ab9fca`.

This plan records the T4 prerequisite contract and its implementation order.
Source slices require reviewed and integrated prerequisites. The lead owns
decisions, verification and protected-branch integration. Baseline facts and
future design requirements remain distinct; no T4 behavior is implemented yet.

## Outcome and scope

Deliver the closed triage command set in
[ADR 0027](../architecture/adr-0027-gmail-modify-history-and-mailbox-commands.md)
and the [T4 roadmap condition](../roadmap.md): durable offline actions reconcile
after reconnect. Preserve account isolation, encrypted local persistence,
sanitized terminal output, bounded work and Gmail authority after reconciliation.

The accepted command set covers read/unread, star/unstar, archive, trash/restore,
spam/clear spam, user-label create/rename/delete/apply/remove, and account-local
message-state batches of at most 1,000 IDs. Permanent message deletion, mute,
composition/send/drafts, push/relay services, app lock and other T5-T8 work remain
outside T4. Classification-label and domain-wide-delegation surfaces are not
part of this contract.

T3 acceptance remains delivered under its
[candidate-bound report](t3-live-acceptance-2026-11-04.md). This plan neither
reopens that gate nor extends its evidence to T4 provider writes.

## Baseline implementation constraints

The code inventory for the baseline establishes these implementation facts:

| Surface | Existing owner and constraint |
| --- | --- |
| Domain and identity | `crates/domain/src/mailbox.rs` has bounded message/account values. `crates/application/src/identity.rs::AccountProfile` is a subject-bearing trait, not a persisted account-profile value. T4 capability, History, label and command values/ports are absent. |
| OAuth/token policy | `crates/application/src/oauth.rs` requests fixed readonly scope. `token.rs` and `adapters/gmail-rest/src/lib.rs::parse_token_response` reduce scope to a readonly boolean; absent token-response scope currently inherits readonly semantics. |
| Broker and account routing | `adapters/token-broker-core/src/ports.rs::RefreshTokenStore` is subject-keyed and token-only. `adapters/sync-runtime/src/installation.rs::InstallationTokens` can register the returned subject. Existing account-add completion is not a selected-account upgrade API. |
| Gmail reads | `adapters/gmail-rest/src/lib.rs::GmailMailbox` is GET-only. Profile retrieval retains email only; message labels become only `unread`. The recent-list request has no `INBOX` filter. |
| Persistence | `adapters/store-sqlcipher/src/lib.rs` owns account schema v2 and the existing transactional v1 upgrade; readonly v1 opens do not migrate. `registry.rs` independently owns registry schema v1. Unknown/future/noncanonical schemas fail closed. |
| Snapshot | `crates/application/src/sync.rs::SyncCoordinator::sync_recent` commits reconciled envelopes before optional body fetches. The SQLCipher reconciliation prunes deterministically and preserves sticky local-read state. A wrapper cannot turn these separate steps into atomic snapshot-plus-baseline persistence. |
| Runtime | `flows.rs`, `gate.rs` and `session_cache.rs` in `adapters/sync-runtime/src/` compose refresh, identity checks and fenced writes. Existing cached-token retry applies to reads; refresh sharing and TUI sync admission do not serialize every future command/History operation. |
| TUI/presentation | `apps/tersa/src/tui/{app,mod,worker,view}.rs` owns scoped views, account workers, download generations and sync status. It has no triage, pending-action or undo intents. `crates/presentation/src/terminal.rs::SafeText` remains the display boundary. |
| Architecture | `xtask/src/main.rs::CORE_POLICY` and `check_architecture` enforce layering/core dependencies, not endpoint or scope allowlists. |

The retained contracts are documented in
[ADR 0017](../architecture/adr-0017-production-account-store.md),
[ADR 0018](../architecture/adr-0018-bounded-sync-and-cache.md),
[ADR 0023](../architecture/adr-0023-step3-oauth-and-bounded-sync.md),
[ADR 0024](../architecture/adr-0024-token-lifecycle-and-custody.md),
[ADR 0026](../architecture/adr-0026-multi-account-and-unified-mailbox.md) and
[ADR 0031](../architecture/adr-0031-tui-only-pivot.md).

## Provider constraints

Official references checked on 2026-11-04 constrain the transport; they do not
choose local recovery, checkpoint or undo policy.

- [History list](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.history/list)
  returns increasing, non-contiguous History IDs and permits at most 500 records
  per page. Its response `historyId` denotes current mailbox history. The
  documented future checkpoint is usable when `nextPageToken` is absent; do not
  treat a paginated response's current-mailbox ID as fully applied progress.
  Specific event arrays can overlap the generic changed-message array.
- [Client synchronization](https://developers.google.com/workspace/gmail/api/guides/sync)
  permits caching recent messages for the client's purpose. Unavailable History
  ranges require full synchronization; retention is not a fixed replay window.
  ADR 0027 additionally requires baseline capture before the bounded fallback
  snapshot and atomic snapshot/cursor persistence.
- [Batch modify](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/batchModify)
  uses POST, accepts at most 1,000 message IDs and returns an empty success body.
  This does not establish atomic timeout behavior. T4 retains ADR 0027's
  per-message ambiguity reconciliation and its `gmail.modify` scope boundary.
- [Labels](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.labels)
  have immutable IDs and display names. User labels support modification;
  system-label definitions cannot be created, renamed or deleted. Only some
  system labels can be applied/removed. Endpoint and label-ID allowlists must
  enforce the approved command set rather than accept arbitrary labels.

## T4 prerequisite contract

This prerequisite contract defines the source implementation requirements.
Source implementation and live acceptance remain pending. The detailed contract is
[ADR 0027](../architecture/adr-0027-gmail-modify-history-and-mailbox-commands.md#t4-prerequisite-contract);
[ADR 0017](../architecture/adr-0017-production-account-store.md#t4-account-schema-v3-prerequisite-contract)
owns schema/transaction policy and the security documents record custody and
residuals. Provider facts do not establish atomic writes, label idempotency or
read-after-write consistency.

| ID | Prerequisite contract |
| --- | --- |
| D1: values/APIs | Closed ReadOnly/Modify capability and bounded redacted History/command/label values; separate extension ports; preserve old readonly constructors and the subject-bearing `AccountProfile` trait. The persisted profile/capability model does not replace that identity trait. No sequential-write atomic default. |
| D2: grant custody | Bind requested capability at begin. Absent scope inherits that immutable request; explicit lacking required scope rejects; explicit ReadOnly plus Modify rejects; Modify may include readonly. New send/mail.google.com grants reject. Refresh atomically reads token/capability, inherits only stored capability on omission and never promotes; rejected-scope rotation solely for revocation remains separate. Connect admits new subjects only; duplicate Connect cannot overwrite/downgrade. Selected-account Upgrade/reconnect binds expected account/subject before browser; mismatch registers/writes/revokes nothing. Successful token/capability replacement is atomic; account permit plus process-local generation fencing and cached-session invalidation prevent stale access. Generation is not a v3 column; restart drops sessions and Dispatching recovers as Ambiguous. |
| D3: schema | One recognized owned v1/v2-to-v3 writer transaction, including email upgrade and complete canonical objects/revalidation. Preserve existing data; default old grants ReadOnly, cursor null, queue empty and provider membership Unknown. Registry v1 and identity algorithm 2 stay. Readonly v1/v2/v3 never migrate. First schema slice includes dormant later tables; method slices cannot add objects under v3. Old binaries reject v3; unknown formats remain unwritten; no downgrade/reset/quarantine. |
| D4: transport/patch | Keep GET mailbox and token transport separate from Modify. Writes are only POST message batchModify (`ids`/`addLabelIds`/`removeLabelIds`), name-only POST labels, name-only PATCH known User-label ID, no-body DELETE known User-label ID. Enforce ADR 0027's exact field map: UNREAD, STARRED, INBOX, TRASH, SPAM or validated User membership only; complete requires observing every touched field. Restore means return to Inbox; undo uses recorded pre-state. No permanent message delete, PUT rename, trash/untrash endpoint, arbitrary path/system label, classification label, send/draft/watch or broader scope. |
| D5: History | Canonical nonnegative ASCII decimal record/cursor IDs, 1-32 digits, magnitude comparison without arithmetic; distinct MessageId validation. Apply specific events once. One complete decided record/data/cursor transaction is atomic; successive commits form contiguous progress. Local page-reference processing truncates at whole-record boundaries with an explicit local indicator, never a fabricated provider token. Invalid envelopes fail before application; over-limit/undecidable next record remains unapplied. Final response cursor requires every record decided, no local truncation/continuation and nonregression. RecoveryRequired permits explicit retry or cache reset after pending cancellation/settlement/abandon; no automatic non-404 fallback. Only no cursor or History-cursor 404 captures baseline before snapshot, then atomic metadata/baseline commit; optional bodies follow. |
| D6: durable queue | Admission persists Queued plus full targets/desired patch; no mailbox mutation has been attempted, but read-only preflight/network is possible. Commit Dispatching/pre-state before mutation; crash/drop/restart is Ambiguous. Empty successful batchModify is acknowledgement requiring reconciliation, not transport failure. Complete is terminal success; Partial is terminal when all items resolve with at least one known failure, including TargetMissing even with zero successes. Terminal failures release FIFO without undo. Ambiguous/NeedsAttention remain nonterminal: explicit Retry freshly reconciles, then permits at most one guarded dispatch without resetting automatic budgets; failed reconciliation cannot write. Abandon warns of possible prior provider application and commits retained terminal Abandoned before FIFO/pins/quota/reset/remove release. Abandoned/unknown/expired replay IDs cannot dispatch or reenroll work. |
| D7: labels/undo | Full membership or fail closed. Ambiguous create reconciles a complete bounded catalog: adopt exactly one matching observed User ID; zero/multiple matches never authorize automatic recreation. Fresh zero-match retry needs duplicate-risk confirmation for one user-authorized create; multiple matches never create. Rename reconciles known ID/name; delete observes known-ID absence. One last-Complete message-state undo slot; label CRUD does not replace it. Undo admission alone refuses pre-existing nonterminal account commands. The admitted undo is Queued: do not reapply that gate at dispatch to itself or later queued work; FIFO prevents overtaking/self-deadlock. Offline admission stores conditional compensation/expected post-state without eligibility or provider-write claims. After reconnect and before dispatch, freshly reconcile the whole target set/required User labels/touched expected post-state; any mismatch refuses the entire compensation without writes. Passing compensation restores touched pre-state through the normal queue; no label-CRUD/Partial/Ambiguous undo. Later provider change is a no-CAS residual. |
| D8: cache/views | Hydrate new messageAdded IDs as bounded recent candidates competing for keep-100; reconcile cached/pinned IDs. Old unpinned/out-of-cache label/deletion events may be decided no-ops without a full-mailbox claim. Provider state, legacy local-read display and pending projection stay distinct. ReadOnly keeps its display behavior; Modify uses observed state with visible pending overlay. Opening does not mutate. Recent/all-cached remains default; observed-membership Inbox/Trash/Spam/User filters keep Unknown rows accessible in Recent and disclose missing metadata, under existing All/single scopes and global 200-row cap. |
| D9: lifecycle/privacy | Pin all nonterminal targets and undo candidate. Every nonterminal command, including Queued, blocks reset/remove; cancel Queued, settle or explicitly abandon first, releasing guards only after terminal disposition commits. Identity replacement refuses destructive change while unresolved evidence exists. Guarded reset clears cursor, terminal summaries, undo and membership while preserving registration/capability/grant/identity/disconnect recovery. Abandoned retains bounded terminal evidence, claims no success/rollback and cannot retry/requeue its ID. Guarded purge removes all T4 account rows atomically. Exact label bytes/evidence stay encrypted, not logged/exported; existing residuals remain, no app-lock claim. |

| Budget | Selected bound and exhaustion |
| --- | --- |
| History | 500 records/page; 4 pages/2,000 records/cycle; 1,000 unique affected IDs/record; local 10,000-reference/page processing budget; existing 2 MiB JSON cap. Commit complete records that fit with local-truncation indicator, not a fake token/response-head checkpoint. Single over-limit/undecidable record remains unapplied; explicit recovery, no non-404 automatic fallback. |
| Metadata/body work | 1,000 metadata lookups/cycle with whole-next-record reservation, so a 1,000-target record fits a fresh cycle; stop before a record that cannot fit remaining budget. Optional 25 bodies after metadata/cursor commit, separately reported. |
| Snapshot fallback | Baseline first; 4 pages of 25, keep 100; metadata/baseline transaction, then up to 25 bodies. Bounded/truncated snapshot is valid recent coverage, not full mailbox; absence cannot settle pending commands. |
| Queue | 32 nonterminal commands plus 4,096 nonterminal target references/account; 1,000 distinct IDs/command. Both quotas checked atomically; label-only commands use a command slot. Never evict nonterminal evidence. |
| Recovery/retry | 1,000 minimal GETs/pass; at most 3 total automatic dispatch attempts/command, including the initial attempt; further automatic attempts need fresh unmet observation, then exhaustion retains nonterminal NeedsAttention. Explicit Retry freshly reconciles and permits at most one guarded dispatch, never resetting the automatic budget. No automatic second ambiguous label create; zero-match explicit retry needs duplicate-risk confirmation, multiple matches never create. Abandon commits warned terminal summary before releasing guards. |
| Labels | Catalog 500; exact names 1-1,024 UTF-8 bytes; full membership up to 512 IDs/message or fail closed. Catalog-dependent reconciliation becomes unavailable on overflow; fresh verified known User IDs are not guessed. |
| Terminal/undo | 128 terminal aggregate summaries plus one undo candidate/account; compact terminal item rows except the candidate. Saved-status replay differs from new admission; no resurrection of expired IDs. |

The complete endpoint/desired-field maps and whole-record/snapshot semantics in
ADR 0027 are required acceptance criteria, not choices delegated to later
implementers. The selected budgets do not add a tool, dependency or CI job.

## Ordered implementation slices

These are implementation slices, not dispatch authorization. Each slice owns
exactly one [change class](agent-playbook.md); files named below are existing
touchpoints or explicitly planned new modules. The implementer owns only that
row's paths. The lead freezes dependencies and acceptance checks before dispatch.

All source slices require reviewed and integrated P0 and the build-preserving
rules below. Tests stay with the owning class; no concurrent writers share files.

P1 covers `AccountCapability`, `HistoryCursor`, `MailboxCommandId`,
`MailboxCommand`, `DesiredMailboxState`, `LabelDefinition` and a validated label
ID. P2 covers `HistoryPage`, `GmailHistoryFeed`, `RemoteMailboxCommands`,
`HistoryCursorStore`, `MailboxCommandStore` and the profile/upgrade contracts.
P6 supplies `HistorySync` and `MailboxCommandCoordinator` over those ports.

| Slice / class | Owned files and responsibility | Depends on / exit condition | Minimum loop |
| --- | --- | --- | --- |
| P0 / `docs-only` | Exactly this plan, ADRs 0017/0027, `docs/security/{data-flow,threat-model}.md` and a concise `docs/roadmap.md` status pointer. | Concrete D1-D9 contract and budgets, custody/residuals and test map; reviewed and integrated prerequisites before source work. No implementation claim. | `typos` on changed files; whitespace, link and redaction checks. |
| P1 / `domain` | `crates/domain/src/lib.rs`, `mailbox.rs`, planned account/History/command/label value modules. Pure validated values, no I/O or new dependencies. | P0; reject invalid/oversized values and keep debug output redacted. Existing constructors remain usable. | `cargo xtask preflight domain` |
| P2 / `application` | `crates/application/src/{lib,oauth,token,mailbox}.rs`; planned History/command/profile port modules. Capability-aware OAuth/token contracts and separate extension ports. | P1; exact capability predicates and atomic persistence/application contracts exist without changing readonly call sites. | `cargo xtask preflight application` |
| P3 / `adapter-rust` | Only `adapters/token-broker-core/**`: `broker.rs`, `ports.rs`, `registry.rs`, `permits.rs` as required. Bound upgrade sessions and atomic credential/capability port support. | P2; same-subject validation precedes replacement, old grant survives rejected upgrade, legacy broker path compiles. No runtime activation. | `cargo xtask preflight adapter --package tersa-token-broker-core` |
| P4 / `adapter-rust` | Only `adapters/gmail-rest/**`: current `src/lib.rs`, planned History/modify modules. Capability-aware token parsing, bounded History/baseline reads and separate enumerated write transport. | P2; exact wire fixtures and readonly/wrong-account/endpoint denial; existing GET path preserved. | `cargo xtask preflight adapter --package tersa-gmail-rest` |
| P5a / `adapter-rust` | Only `adapters/store-sqlcipher/**`: complete v3 schema/migration (including dormant later objects), validation and concrete atomic token/capability methods. Registry stays v1. | P2/P3 contract; reviewed D3 migration preserves old data and rejects unknown schemas unchanged. No runtime activation. | `cargo xtask preflight adapter --package tersa-store-sqlcipher` |
| P5b / `adapter-rust` | Same SQLCipher owner: provider state, atomic History data/cursor and fallback metadata/baseline transactions. | P5a and D5/D8; rollback/fence evidence covers every transaction boundary. | Same SQLCipher preflight. |
| P5c / `adapter-rust` | Same SQLCipher owner: durable command/items, dispatch evidence, settlement, offline conditional compensation/expected post-state and approved undo retention; cache/lifecycle protection methods. | P5b and D6/D7/D9; restart state survives; warned terminal Abandoned commits before guard release, and pruning/reset cannot erase unresolved dispatch evidence. | Same SQLCipher preflight. |
| P6a / `application` | Only `crates/application/**`: planned History coordinator module and bounded snapshot collection/commit contracts. | P2; implement reviewed D5/D8 over ports. Check against P4/P5b contracts; no SQL/network/runtime dependencies. | `cargo xtask preflight application` |
| P6b / `application` | Same application owner: planned `MailboxCommandCoordinator`, queue/recovery/undo orchestration and closed operation documents. | P6a; implement reviewed D6/D7/D9, including terminal failure versus uncertainty, explicit Retry/Abandon and label ambiguity. | Same application preflight. |
| P7 / `adapter-rust` | Only `adapters/sync-runtime/**`: `flows.rs`, `installation.rs`, `session.rs`, `session_cache.rs`, `gate.rs`, `cache_reset.rs` and focused new modules. Compose upgrade, process-local generation, stores/transports, serialization, restart reconciliation and lifecycle guards. | P3/P4/P5c/P6b; capability and account remain bound across refresh, restart and recovery; no UI bypass or unsafe read-retry reuse for writes. | `cargo xtask preflight adapter --package tersa-sync-runtime` |
| P8 / `presentation` | Only `crates/presentation/**`: sanitized capability/action/recovery documents and bounded closed display statuses. | P1/P2/P6b; pending projection and authoritative state remain distinguishable; provider strings enter `SafeText`. | `cargo xtask preflight presentation` |
| P9 / `tui` | Only `apps/**`: `commands.rs`, `cli.rs` if required, `tui/{app,mod,worker,view}.rs`. Explicit upgrade, account-partitioned actions, batches, labels, Retry/Abandon with uncertainty/duplicate-risk confirmations, pending recovery and offline conditional undo with pre-dispatch validation. | P7/P8; preserve account routing/view generations and owned shutdown; all writes pass through the coordinator. Offline intent survives reopen and converges through the runtime. | `cargo xtask preflight tui` |
| P10 / `docs-only` | This plan, roadmap/source-delivery status and a candidate-bound T4 acceptance protocol/report under `docs/development/`. | Reviewed source candidate; document automated results separately from authorized macOS provider observations. Protocol can precede the run; results follow observations only. | Documentation checks as P0. |

P4 and P5 do not depend on each other's concrete implementation. P6 uses ports,
not adapter imports; its placement after storage makes transaction assumptions
reviewable without introducing a reverse dependency. Keep P8 after P7 in this
sequence. P5a defines all v3 objects. P5b/P5c add methods, not canonical objects;
any later layout amendment needs separately reviewed version policy. A large row
may be divided into successive slices of the same class with separately stated
acceptance checks.

If a reviewed contract needs a new dependency or architecture/tooling rule, insert
a separate `policy-xtask` slice first, owning only `xtask/**`, permitted policy/CI
configuration or scripts. Run `cargo xtask preflight policy` then full
`cargo xtask verify`. Do not add source-regex policing or new CI jobs merely to
check an endpoint list. Keep the existing Linux/macOS/CI-gate topology and budget.

### Build-preserving transitions

- Introduce extension traits and explicit capability-aware entry points before
  wiring consumers. Preserve old readonly constructors and forwarding methods
  until their callers migrate; never make compatibility imply Modify access.
- Required-method changes to `RemoteMailbox`, `MailboxStore`,
  `RefreshTokenStore` or TUI `Remote` break concrete implementations and fakes.
  Do not stage such a break across independently reviewed slices. A separate
  atomic upgrade contract must fail closed, not emulate atomicity with two writes.
- `TokenResponse::new`/`into_parts`, OAuth/broker signatures,
  `MessageEnvelope::new` and public status enums have downstream consumers.
  Stage new constructors/accessors/types while preserving existing behavior.
  Keep the subject-bearing `AccountProfile` trait distinct from the profile value.
- Build compatibility does not imply database compatibility. No API wrapper can
  make the baseline binary read a new canonical schema. Record supported formats
  and rollback limits before enabling migration or writes.

## Test-owner matrix

The inventory identifies existing test owners, not T4 passing results. Planned
modules below acquire the corresponding new contract tests. Give each observable
contract one primary owner; other layers cover distinct wire, SQL or lifecycle
risks rather than duplicate coordinator assertions. Name the failure being
prevented before adding a test; use real ports/fakes without test-only production
exports or seams.

| Contract | Primary owner / existing anchor | Distinct boundary evidence |
| --- | --- | --- |
| Values and redaction | Domain value-module tests; existing `domain/src/mailbox.rs` | Numeric History-ID magnitude/bounds without applying that rule to MessageId; invalid labels/targets, closed command set and redacted formatting. |
| Capability predicates | `application/src/{oauth,token}.rs` | Absent versus explicit insufficient scope, readonly-plus-modify rejection, Modify-plus-readonly acceptance, send/mail.google.com rejection and refresh non-promotion. Gmail tests own scope wire parsing, not a second policy implementation. |
| Upgrade lifecycle | `token-broker-core/src/broker.rs` | Connect versus bound Upgrade/reconnect, duplicate Connect non-overwrite, same-subject before replacement, rejected-grant preservation, rotation/delete failures and cancellation permits. SQLCipher owns real token-plus-capability transaction rollback. |
| Provider requests | `gmail-rest/src/lib.rs` and planned transport modules | Exact allowlisted endpoint/body/desired fields; readonly/owner/ID denial; empty successful batch acknowledgement distinct from failed transport; bounded replies and complete label observations. No permanent-delete/mute/send route. |
| History protocol | Planned application History tests; existing `application/src/sync.rs` snapshot anchors | One-record atomicity/contiguous progress, local reference truncation at whole-record boundary without fake token/response-head checkpoint, 1,000-target reservation/progress, invalid envelope versus undecidable record, explicit retry/guarded-reset recovery and baseline/final-cursor rules. |
| Durable storage | `store-sqlcipher/src/lib.rs` | One v1/v2-to-v3 transaction/complete objects, readonly v1/v2/v3, rollback and unknown-schema non-mutation, token/capability and data/cursor atomicity, both admission quotas, 512-label complete-or-fail membership, terminal retention/pins, Abandoned-summary rollback before guard release and every nonterminal lifecycle guard. Generation is not a schema column. |
| Desired state and undo | Planned application command-coordinator tests | Exact patches, terminal Partial/TargetMissing (including zero successes), FIFO, 3 total automatic attempts including initial versus single explicit Retry after reconciliation, failed reconciliation/no write, warned durable Abandon with no replay, no automatic label recreation, confirmed single zero-match retry versus multiple-match refusal, and offline conditional compensation with admission-only pre-existing-command checks, FIFO dispatch despite its own/later Queued work, whole-set fresh expected-post-state equality before dispatch and zero writes on mismatch. |
| Runtime composition | `sync-runtime/src/{flows,gate,installation,session_cache,cache_reset}.rs` | Actual wiring, account-permit/process-local generation fencing and restart session loss, upgrade invalidation, Queued read-only preflight versus mailbox mutation, Dispatching restart/drop ambiguity, explicit recovery and guard release only after terminal commit. Preserve existing identity-gate evidence. |
| Unified UI/recovery | `application/src/unified_mailbox.rs`, app `commands.rs`, `tui/{app,mod,worker,view}.rs` | Recent default/Unknown rows versus observed filters, exact `(AccountId, MessageId)` routes/200-row cap, account partitions, stale-view completions, independent status, cancellation/shutdown, terminal-versus-uncertain status and concrete Retry/Abandon/duplicate-risk affordances and offline conditional undo without an eligibility claim. |
| Sanitized display | `presentation/src/{terminal,message}.rs`, new recovery documents | Hostile label/status text is sanitized, payloads bounded and secrets absent. TUI tests prove safe rendering and usable action/status distinctions. |
| Architecture | `xtask/src/main.rs`, only if policy changes | Durable layering/dependency rules; this check does not certify provider endpoint safety. |

Use each row's scoped preflight during source editing. At each source slice
boundary and before independent review, run full `cargo xtask verify`; retain
`cargo deny` and `typos` as separate required checks. Record exits and relevant
timings, including any measured CI/performance cost change. Documentation-only
work uses spelling/whitespace/link/redaction checks and does not require a build.
An independent review must report zero unresolved actionable findings on the
frozen candidate; subsequent edits invalidate approval. Integration remains the
lead's separate protected-branch workflow, not implementer authority.

## Rollback and non-claims

Before runtime activation, additive contracts leave the existing readonly path
usable. After migration, reverting code does not restore old-format readability;
after dispatch, reverting code does not undo provider writes. Owned migration
failures roll back atomically; v3 stores stay preserved on old-binary refusal.
Stop further dispatch on unresolved recovery rather than pretend code rollback
compensates provider state.
Do not downgrade/reset a store, discard unresolved intent, delete credentials or
replay writes as an implicit rollback. Explicit Abandon warns that Gmail may
already have applied the operation and automatic recovery stops; its retained
terminal summary must commit before releasing guards. It is not success or
provider rollback, and its command ID can never be retried/reenqueued. Preserve evidence needed to reconcile
possible dispatch and expose a closed recovery state. Do not copy or publish
private stores as rollback artifacts.

Local transaction rollback evidence belongs to SQLCipher tests. Provider recovery
requires observation/reconciliation; an undo is not a distributed transaction.
The plan claims neither lossless full-mailbox replay nor permanent History
availability, Google scope verification, live keyring/provider behavior, release
readiness, Linux consent acceptance or T5-T8 completion.

## Separate live acceptance

Automated source delivery and live acceptance are separate records. After source
checks and independent review, the lead must select a frozen candidate and obtain
explicit authorization for the account, message/label targets and concrete actions
before any live modify call. This document authorizes no mailbox mutation.

The planned macOS acceptance protocol should demonstrate same-account capability
upgrade, an approved command followed by History convergence, and offline intent
surviving reopen and reconciling after reconnect. Include approved undo and
multi-account routing observations where applicable; record selections and limits
without publishing account identities or message content. Denied consent,
malformed responses, expired History, ambiguous transport and crash ordering stay
primarily under deterministic fixtures; do not induce arbitrary failures in a real
mailbox to manufacture evidence.

P10 records exact candidate/check results, observed versus unexercised cases and
redacted evidence. Offline/fake/CI success cannot stand in for provider writes;
T3 observations cannot close T4 acceptance. macOS T4 evidence does not certify
Linux consent, packaging or release readiness.
