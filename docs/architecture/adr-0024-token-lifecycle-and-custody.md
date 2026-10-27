<!--
This Source Code Form is subject to the terms of the Mozilla Public License,
v. 2.0. If a copy of the MPL was not distributed with this file, You can obtain
one at https://mozilla.org/MPL/2.0/.
-->

# ADR 0024: Token lifecycle and custody

- Status: Accepted lifecycle decisions; custody amended by
  [ADR 0031](adr-0031-tui-only-pivot.md)
- Date: 2026-08-02

## Current architecture

`tersa-token-broker-core` is an in-process, runtime-agnostic service over generic
ports. It owns OAuth code exchange, refresh, refresh-token persistence, rotation,
provider revoke, and local deletion. `tersa-sync-runtime` supplies the loopback,
Google transport, account routing, and SQLCipher credential-store composition.
The core contains no OS keyring implementation or interprocess protocol.

The begin operation receives only the exact root-form IPv4 loopback redirect
with an explicit non-privileged port. The core retains PKCE verifier/state in a
bounded TTL session registry and returns an authorization URL and opaque handle.
Each callback atomically claims its session before validation, so replay cannot
reuse a failed attempt. Registry handles are zeroizing; poison fails closed and
wipes state. No live session is evicted to admit another.

Mutation serializes per validated subject through bounded single-flight permits
released by RAII, without holding a mutex over an await. Successful results expose
only a bounded zeroizing short-lived access token, validated zeroizing subject,
and positive expiry to trusted composition. No refresh token, authorization code,
state, or PKCE verifier crosses the public result API. The credential-store port
is subject-keyed; it is not a generic secret-store interface.

Refresh tokens reside in the account SQLCipher database. The root resides in the
OS keyring or passphrase-wrapped slot. These are logical capabilities inside one
process; they provide no runtime isolation from same-user code able to read the
keyring or capture the passphrase. Linux Secret Service has no per-app ACL.
This accepted residual is explicit in ADR 0031 and the
[threat model](../security/threat-model.md).

## Cleanup, identity, and accepted residuals

A granted completion snapshots stored credentials under its subject permit
before replacement. Only a definitively empty snapshot permits best-effort
stranded-grant revocation. An unreadable snapshot fails as `PersistenceFailed`
before any write or revoke. Unknown/malformed identity never becomes a fabricated
store key or cleanup input.

Google revocation is grant-wide across tokens for one user/client. An empty local
snapshot cannot detect another installation holding the same grant; cleanup can
invalidate that installation's credential. This is an accepted residual of
best-effort cleanup, not permission for unconditional revoke after every failure.

An explicitly under-scoped completion has no validated subject because scope is
decided before identity validation, and begin supplies no account identity. It
persists nothing and revokes nothing. A first-connect under-scoped grant can
therefore remain active at Google. This API has no retained token or validated
subject to revoke it in-app. Recovery must preserve any prior working connection,
offer retain-or-retry, and direct the user to Google Account permissions for
external manual revocation.

The hard provider refresh-token bound is 1,024 bytes; Google specifies no maximum.
Oversized rotation fails as `MalformedResponse` before persistence or revoke,
never truncates, and requires a reviewed bound change if provider behavior changes.
A granted refresh validates the exact stored subject before persisting rotation;
a mismatch retains the old credential and drops the access token. An explicitly
under-scoped refresh cannot validate identity and intentionally persists a valid
rotation only as a local revocation handle before reporting scope failure.

## Closed failures and disconnect

`AuthorizationCodeRejected` is exchange-time `invalid_grant`: sign in again,
without deleting stored state. It remains distinct from `ProviderRejected` and
refresh-time `ConsentRevoked`. On refresh-time `invalid_grant`, deletion must
succeed before reconnect is reported; deletion failure is `PersistenceFailed`.
Missing refresh token also requires reconnect. `IdentityUnverified` and
`IdentityMismatch` are non-destructive. All errors carry closed categories and
no raw input, provider body, subject, or secret.

Revoke and local token deletion are separate operations. `RevokeUnconfirmed`,
revoke-time persistence failure, and delete-time persistence failure cannot be
mapped to a clean disconnect. The owning runtime must preserve durable teardown
recovery in this order: intent marker, provider revoke, confirmed token delete,
account mailbox purge, marker clear. Cache purge never erases evidence needed
to resolve unconfirmed consent withdrawal. See
[ADR 0023](adr-0023-step3-oauth-and-bounded-sync.md).

## Evidence and non-claims

Core tests establish deterministic lifecycle contracts over fake ports. They do
not establish live provider behavior, keyring interoperability, isolation from
same-user code, or release signing. Recovery presentation must preserve the
closed failure distinctions; documentation alone does not establish that every
recovery flow is implemented in the terminal interface.
