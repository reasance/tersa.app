<!--
This Source Code Form is subject to the terms of the Mozilla Public License,
v. 2.0. If a copy of the MPL was not distributed with this file, You can obtain
one at https://mozilla.org/MPL/2.0/.
-->

# ADR 0028: drafts, outbox, and idempotent send

- Status: Accepted
- Amended by: [ADR 0031](adr-0031-tui-only-pivot.md) (terminal-only pivot)
- Date: 2026-08-29

## Implementation status and context

Drafts, composition, attachments, and send are accepted future T5 work. The
terminal editing surface is `$EDITOR` under ADR 0031; the durable outbox remains
a Rust-owned state machine. A provider timeout after accepting a message makes
blind retry capable of mailing a duplicate.

This plan depends on account isolation in
[ADR 0026](adr-0026-multi-account-and-unified-mailbox.md), capability and History
in [ADR 0027](adr-0027-gmail-modify-history-and-mailbox-commands.md), safe content
and composition boundaries in
[ADR 0029](adr-0029-safe-content-and-composition.md), and encrypted blobs in
[ADR 0030](adr-0030-encrypted-blobs-storage-budget-and-app-lock.md).

## Prerequisite decision and policy slices

No draft, send, attachment, or export implementation may start until the
ADRs 0026–0030 and their prerequisite policies are independently
accepted. A dedicated `docs-only` security ADR must additionally define an
importable encrypted draft-bundle format, explicit passphrase UI, versioning,
verification, import conflict behavior, and recovery. A separate `policy-xtask`
slice, coordinated with ADR 0030 dependency policy, must select/pin the
Argon2id/XChaCha20-Poly1305 dependency path and add the required redaction and format
fixtures before bundle code is eligible.

Before draft/outbox persistence or Gmail send egress, **security
documentation** must amend the security data flow and threat model for encrypted
drafts/outbox, file-permission posture, backup/export/import, deletion,
app-lock behavior, diagnostics, stable identifiers, and ambiguous-send recovery.

## Decision

### Local-first drafts

The domain layer adds `DraftId`, `OutboxItemId`, `GmailDraftId`,
`RfcMessageId`, `MimeDigest`, `DraftCreateAttempt`, `DraftSyncState`,
`ConflictCopy`, `PossibleDuplicateTombstone`, and the closed `OutboxState` set:
`Queued`, `Preparing`, `DraftUploading`, `ReadyToSend`, `Sending`,
`AwaitingDraftReconciliation`, `AwaitingSendReconciliation`, `Sent`,
`RetryableFailure`, `PermanentFailure`, `Cancelled`, and
`AbandonedAmbiguous`. `DraftId` and `OutboxItemId` are opaque local CSPRNG
identifiers. `RfcMessageId` is generated exactly once when an item enters the
outbox and is formatted as
`<outbox-<OutboxItemId>@tersa.app>`; it is never regenerated during retry,
restart, or reconciliation. `MimeDigest` is a redacted fixed-size digest of the
complete transfer-encoded MIME bytes and never exposes content in debug or
diagnostics. A `PreparedMimeRef` is an account-bound ADR-0030 `BlobRef` with
non-evictable local-intent storage class. A `DraftCreateAttempt` is bound to one
account/outbox item and persists the selected revision, prepared-MIME reference,
stable message ID, MIME digest, encoded length, and closed phase `Prepared` or
`Dispatched`; it contains no token and no plaintext MIME.

`DraftStore` persists each account-scoped edit transactionally before the UI
reports it saved. It stores the validated editor text, recipients,
references, attachment `BlobRef`s, local draft ID, optional replaceable Gmail
draft ID, and the last observed remote draft revision. There is no in-memory-only draft path after implementation.

`GmailDraftTransport` synchronizes a local saved draft only when the account is
online and has `Modify` capability. A local dirty draft always wins over an
unseen remote update: when its recorded remote revision differs from the
current Gmail draft, the transport retains the local draft and creates a second
local `ConflictCopy` from the remote content. It does not overwrite either
version or silently upload a winner. Before a server ID exists, the durable
`DraftCreateAttempt` is the sole remote-create route. Once adopted,
`GmailDraftId` is replaceable but is the primary remote draft/send handle;
stable `DraftId` remains the local user route.

### Rust-owned outbox and send transport

The application layer adds `DraftStore`, `OutboxStore`, `GmailDraftTransport`,
`GmailSendTransport`, and `OutboxCoordinator` as runtime-neutral ports/use
cases. The coordinator is the sole production owner of state transitions and
runs on a bounded Rust worker; the TUI observes bounded sanitized state and
submits intents only.

Sending transitions are exact:

1. `Queued` records the immutable `RfcMessageId` and selected draft revision.
2. `Preparing` reads the encrypted selected revision and attachment `BlobRef`s,
   validates the saved editor document and builds
   the complete transfer-encoded MIME source deterministically. The 20 MiB cap is
   checked before any provider request; an over-limit item remains an editable
   local draft and creates no provider-side attempt. The bounded MIME bytes are
   then committed through ADR 0030's `BlobCommitCoordinator` as a non-evictable
   local-intent `PreparedMimeRef`; one account SQLCipher outbox transaction binds
   that reference, its `MimeDigest`, encoded length, and selected revision before
   the item can advance.
3. `DraftUploading` reads and verifies those already persisted complete MIME
   bytes by `PreparedMimeRef`. If a `GmailDraftId` exists, it updates only that
   draft. For a local-only draft, the coordinator first persists a
   `DraftCreateAttempt` in phase `Prepared`, then
   atomically stamps it `Dispatched` immediately before invoking
   `drafts.create`. Encoded MIME over 5 MiB uses resumable upload; smaller sources
   may use simple upload. The provider receives no partial or unchecked MIME.
4. A successful draft create/update persists the returned `GmailDraftId` and
   remote revision, clears any pre-ID attempt, and moves to `ReadyToSend`. A
   timeout, connection loss, crash after draft dispatch, or incomplete create
   response moves to `AwaitingDraftReconciliation`; it never dispatches send or
   a second create.
5. Draft reconciliation with a persisted `GmailDraftId` fetches and validates
   only that draft. A pre-ID create attempt instead performs a bounded
   account-scoped drafts query for the exact stable RFC `Message-ID`, fetches the
   candidates, and adopts a `GmailDraftId` only when exactly one draft carries
   that exact message ID and matches the persisted attempt. Zero, multiple, or
   invalid matches remain `AwaitingDraftReconciliation`; they never make the
   same attempt retryable. The user may abandon the attempt with its encrypted
   possible-duplicate tombstone, but no automatic or manual path issues a second
   `drafts.create` for that outbox item.
6. `ReadyToSend` is reachable only with a persisted `GmailDraftId` bound to the
   immutable selected revision and prepared MIME digest. `Sending` dispatches
   `drafts.send` by that ID; it never uploads a newly rebuilt MIME source.
7. A confirmed or ambiguous send response persists every returned provider
   identity when present and moves to `AwaitingSendReconciliation`, never
   directly to `Sent` and never to an immediate retry.
8. Send reconciliation resolves the persisted `GmailDraftId` first and uses the
   stable RFC `Message-ID` only as secondary evidence in bounded Gmail
   search/History. It marks `Sent` only when one matching accepted message is
   found. A bounded negative result may move to `RetryableFailure` only when it
   also proves the persisted Gmail draft remains unsent; otherwise the item
   stays `AwaitingSendReconciliation`.
9. User cancellation is allowed only before provider dispatch. Once a draft or
   send request may have reached Gmail, cancellation waits for the corresponding
   reconciliation. A permanently rejected message becomes `PermanentFailure`
   with a redacted, closed reason.
10. After an offline or provider-unavailable ambiguous outcome, the user may
    explicitly acknowledge possible duplication. The coordinator then writes
    an encrypted `PossibleDuplicateTombstone` and moves the item to terminal
    `AbandonedAmbiguous`; it is never retried automatically or manually as the
    same draft-create or send attempt.

The terminal MVP compiles validated plain editor text and attachment references
into deterministic MIME; multipart framing is used when attachments require it.
Any future structured compose model must deterministically generate plain/allowed
HTML from a closed AST, never accept arbitrary editor HTML as trusted markup.
Such an extension requires its own reviewed scope decision under ADR 0029.
There is no blind second send, mutable message ID, or provider retry outside the
state machine. Durable outbox work resumes only while tersa runs with connectivity;
there is no scheduling/delivery guarantee while the host sleeps or is off.

Disconnect is blocked when an account has a nonterminal draft/outbox obligation.
The user must explicitly send it, delete it, complete a verified encrypted
draft-bundle export, or acknowledge `AbandonedAmbiguous`. The future bundle is
importable through the separately approved versioned format and explicit
passphrase UI; verified export checks its manifest/authentication before
disconnect can proceed. Only after one of those resolutions can broker
revoke/delete and local account purge proceed.

### Invariants and data flow

```text
$EDITOR text validated by Rust
  -> DraftStore transaction in the account SQLCipher store
  -> deterministic complete MIME + 20 MiB check
  -> ADR-0030 non-evictable PreparedMimeRef
  -> durable pre-ID DraftCreateAttempt -> Gmail draft transport
  -> persisted GmailDraftId -> Gmail send transport
  -> History/message-ID reconciliation
  -> closed sanitized state back to the TUI
```

- Drafts, outbox entries, attachments, remote draft IDs, and message-ID
  reconciliation are bound to one `AccountId`; a unified inbox never merges
  them.
- `OutboxStore` commits every transition atomically. A dropped future may leave
  an external outcome unknown but may not leave a partial local transition.
- A pre-ID `DraftCreateAttempt` is the sole durable primary handle until exactly
  one matching Gmail draft is adopted; after that, the persisted Gmail draft ID
  is the primary remote send handle. RFC `Message-ID` is secondary correlation
  evidence and is never assumed to be a provider idempotency key. No outbox item
  may issue a second create while its pre-ID attempt is `Dispatched` or awaiting
  reconciliation.
- `PreparedMimeRef`, its digest, encoded length, selected revision, and every
  attachment reference are account-bound non-evictable local intent. The bytes
  sent to Gmail must verify against that persisted digest; they are never rebuilt
  after dispatch from a newer draft revision.
- The broker continues to provide only transient access tokens. Tokens, keys,
  raw MIME, recipients, subject, and message IDs never appear in diagnostics or
  terminal error text.
- The 20 MiB limit measures the complete transfer-encoded MIME source, not
  only attachment files, and is checked before `drafts.create`, `drafts.update`,
  or send dispatch. Over-limit items remain editable local drafts and produce no
  provider upload or partial remote draft.
- The TUI submits intents through application use cases and never sends directly.
  Persistence, preparation, dispatch, and reconciliation remain distinct and tested.

### Implementation decomposition

Sequence the importable bundle/security decisions and dependency policy before
domain states, application coordinator, one SQLCipher/Gmail adapter at a time,
runtime composition, and TUI/editor recovery. Use the current
[change classes](../development/agent-playbook.md). No new provider endpoint or
persistence format is authorized by incidental UI wiring.

## Failure handling

Blob/key/store failures leave the draft and outbox state durable and redacted;
they never substitute an attachment with plaintext or silently drop it. A
provider rejection classified as permanent does not destroy the draft. Ambiguous
draft-create/update or send results consume no automatic retry budget until their
corresponding reconciliation completes. If Gmail cannot be queried, the item
remains `AwaitingDraftReconciliation` or `AwaitingSendReconciliation` and the
user may force neither a second create nor a send. They may only acknowledge
`AbandonedAmbiguous`, which creates the possible-duplicate tombstone and permits
account disconnect without reusing that outbox item's create or send attempt.

Draft synchronization failures retain the local draft. A remote conflict makes
two recoverable local copies, not an overwrite. An upload that exceeds the
limit, loses permission, or loses its account route returns a closed failure
and cannot cross to another account. Disconnect recovery persists until all
obligations are explicitly resolved.

## Test and evidence gates

- Domain/application tests cover every legal and illegal state transition,
  `ConflictCopy`, stable Message-ID generation, `PreparedMimeRef` digest/length
  binding, pre-ID `Prepared`/`Dispatched` persistence, no second create, separate
  draft/send reconciliation, tombstone creation, cancellation at every boundary,
  and no retry before negative send reconciliation.
- Store/blob crash-injection tests stop before/during/after prepared-MIME
  publication/binding, pre-ID attempt persistence and dispatch stamp, Gmail ID
  adoption, ready-to-send transition, send dispatch, and tombstone commit. They
  verify either the old or the complete new state, never a partial one, and never
  evict prepared MIME local intent.
- Adapter fakes cover Gmail draft replacement, conflict copy, simple/resumable
  upload selection, encoded-size rejection before any request, successful and
  ambiguous initial create, bounded exact-Message-ID draft adoption, zero/multiple
  pre-ID matches remaining unresolved, no second create, send success with lost
  response, and draft-ID-first/Message-ID-secondary send reconciliation.
- TUI/editor tests cover durable saving, accessible conflict/send recovery, blocked
  disconnect, and no direct network send path.
- A live Gmail send merge gate requires a separate owner authorization for one
  exact attempt that proves persisted-draft send, Message-ID round trip, and
  Gmail searchability/retrieval. If that evidence is absent or negative, an
  ambiguous send never receives a blind retry; it remains reconciling or may be
  abandoned with its possible-duplicate tombstone.

## Non-claims

This ADR does not implement sending, approve the bundle/security prerequisite,
grant `gmail.send`, guarantee delivery when the app is absent, support scheduled
send, aliases, permanent delete, unbounded attachments, plaintext export,
an MCP path, or release evidence. It does not claim that
Gmail offers an idempotency key; duplicate prevention is the application's
reconciliation protocol and retains documented ambiguity until resolved or
explicitly abandoned.

## Consequences

Sending becomes recoverable local intent with a strict durability and
reconciliation cost, rather than a fast but duplicate-prone UI action. The
product gains conflict-visible Gmail-synced drafts and an honest limitation:
offline delivery resumes only while the app can run.
