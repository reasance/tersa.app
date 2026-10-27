<!--
This Source Code Form is subject to the terms of the Mozilla Public License,
v. 2.0. If a copy of the MPL was not distributed with this file, You can obtain
one at https://mozilla.org/MPL/2.0/.
-->

# ADR 0023: OAuth and bounded Gmail synchronization

- Status: Accepted; amended by [ADR 0031](adr-0031-tui-only-pivot.md)
- Date: 2026-07-20

## Context and implementation boundary

The terminal client uses the official Gmail API, portable PKCE/token lifecycle
code, the Gmail REST adapter, an in-process token service, and SQLCipher.
Bounded snapshot sync and the account-identity gate are implemented. History,
mailbox mutation, and send remain plans under ADRs 0027–0028. Earlier runtime
results do not certify the current terminal workflow or a release.

## OAuth and client configuration

Users configure their own Google **Desktop app** OAuth client. The Rust listener
binds an ephemeral literal IPv4 loopback redirect. PKCE S256, exact redirect and
state validation, a bounded session lifetime, and one-shot callback consumption
are required. Browser authorization requests offline access and explicit consent
when a new refresh credential is needed.

An installed application's issued client secret is non-confidential. If the
client requires it, send it only to the token endpoint alongside the client ID,
hold runtime copies in zeroizing memory, and never commit or log it. Configuration
is user-supplied, as described in the [README](../../README.md).

The read capability requests `openid` and `gmail.readonly`. The token response
and callback reject an explicitly reduced scope before granting mailbox access;
an absent token-response scope field follows OAuth semantics. The separately
bounded token POST/revoke component is distinct from GET-only `GmailMailbox`
([ADR 0016](adr-0016-gmail-rest-adapter.md)). No raw provider body or secret
appears in errors. Temporary HTTP-library buffers remain a zeroization residual.

## Token custody and failure semantics

Refresh tokens are persisted only in the owning account's SQLCipher database.
The in-process lifecycle core owns exchange, refresh, rotation, revoke, and local
token deletion over narrow ports; access tokens remain memory-only and zeroizing.
Rotation is persistence-first and atomic, never delete-then-add. Account work is
serialized before refresh as well as before gate/write, so concurrent cycles
cannot overwrite a rotated credential.

An exchange-time `invalid_grant` means the sign-in lapsed and is non-destructive.
A refresh-time `invalid_grant` deletes the dead stored credential before reporting
reconnect, preserving cached mail. A deletion failure remains a persistence
failure; it cannot masquerade as a completed reconnect transition. Unverified or
mismatched identity is non-destructive. Explicit under-scope and stranded-grant
cleanup follow the accepted residuals in
[ADR 0024](adr-0024-token-lifecycle-and-custody.md).

Disconnect preserves the ordering: durable account-scoped teardown marker,
provider revoke, confirmed local token deletion, owning-writer mailbox purge,
marker clear. Unconfirmed revoke or deletion preserves recovery state and cannot
report clean teardown. Planned local draft/outbox obligations add the resolution
gate in ADR 0028 before this sequence.

## Identity source

The gate uses the immutable Google OIDC `sub`, never mutable or reusable email
addresses. Identity is hashed with account- and installation-bound derivation;
no raw subject is displayed or logged. The narrow token result carries validated
subject input only to trusted composition.

`id_token` decoding is signature-unverified only because the token comes directly
from the hardened TLS token-endpoint back channel. The private decoder checks
Google issuer, audience equal to client ID, and bounded nonempty subject. The
composition checks `exp` and `iat` against a wall clock, with a fixed two-minute
skew, before using the subject on every exchange/refresh cycle. A fresh session
must be constructed for each cycle; a long-lived validated session would bypass
freshness checks. Any future front-channel/non-back-channel token source requires
signature verification and `exp`/`iat`/`nonce` validation at acceptance.

## Gate-to-write serialization

Before every sync or on-demand body-cache write, compare the current subject hash
with the account slot's recorded identity. A match preserves cached mail; a
mismatch clears the old mailbox and records the new hash atomically before new
mail writes. Read/hash/store failure blocks the write. Present-but-unreadable
identity data is corruption, never an absent identity.

Three requirements work together:

1. One whole-cycle account permit covers refresh, identity read/decision/record,
   and sync. Busy begins do not spawn or enqueue a competing cycle. Cancellation
   releases permits and drops in-flight work without detached retries.
2. Identity recording is compare-and-set in `BEGIN IMMEDIATE`: first record
   requires absence; replacement requires the previously observed hash. A race
   aborts and re-runs read/decide/record within a finite bound. This prevents two
   concurrent first-connect decisions from preserving different principals' mail.
3. Each envelope reconciliation and conditional body-cache write carries the
   fresh cycle's identity fence and checks it in its own write transaction.
   Missing or mismatched identity aborts; corrupt identity fails as corruption.
   Both paths are fenced because provider message IDs may collide across accounts.

A transaction fence alone cannot serialize the gate's read-decide-record step.
The permit protects cooperative in-process cycles; transactional compare-and-set
protects against stale cross-process decisions. Two-gate interleaving tests must
prove that only one principal's mail survives.

The runtime composes adapters; it is not a second SQL or migration owner.
Blocking SQLCipher work belongs on a bounded blocking executor. Local transaction
locks are never held across network I/O. Fetch bounded bodies before taking a
short write lock. Status output is closed and redacted, not an identity oracle.
The bounded snapshot rules in [ADR 0018](adr-0018-bounded-sync-and-cache.md)
remain binding. The TUI's startup, periodic, manual, and on-demand body paths all
use the identity gate while the process runs.

## Evidence and non-claims

Deterministic tests must cover malformed callbacks, missing scope, identity
freshness, rotation, refresh failure, incomplete teardown, cancellation, and the
permit/CAS/fence interleavings. Live provider and packaging claims require
separate candidate-bound evidence and owner authorization. This ADR does not
grant Google verification, implement History or provider writes, or certify
performance, Linux consent, or release signing.
