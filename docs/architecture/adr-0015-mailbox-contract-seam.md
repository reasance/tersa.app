# ADR 0015: mailbox contract seam

- Status: Accepted
- Date: 2026-07-16

## Context

The terminal client needs portable mailbox contracts shared by the Gmail
transport and SQLCipher-backed store. The contracts must avoid selecting
an async runtime or exposing user-controlled data in diagnostics.

## Decision

`tersa-domain` defines bounded, provider-neutral mailbox values. Opaque decoded
message content has a defensive maximum of 64 MiB. Identifiers use visible
non-whitespace ASCII (`!` through `~`); locally assigned `AccountId` values also
reject email-shaped input. Identifiers, header text, content, page tokens, and
pages use manual redacted or metadata-only `Debug` output; user content is never
displayed.

`tersa-application` defines two separate inward ports: `RemoteMailbox` for
provider retrieval and `MailboxStore` for local persistence. Both are object
safe and return standard-library boxed futures, so this seam adds no Tokio,
`async-trait`, futures crate, or runtime dependency. Dropping a returned future
is the caller's cancellation request and releases future-owned state. Adapters
should stop before dispatch or commit when possible. An operation already
dispatched or made irreversible may finish once, but must not start retries or
unbounded detached work after drop. Store mutations are atomic and
all-or-nothing: after drop the outcome may be unknown, but partial durable state
is forbidden and callers may reconcile by re-reading.

Remote `PageSize` is only a provider pagination size (1 through 500). Local
`StoreLimit` is a separate result limit (1 through 10,000). Remote listing
preserves provider page order; global and equal-time ordering is provider-defined
or unspecified, so it is not a lossless sync snapshot. Local listings use stable
total orders: newest-first by received time then message ID, and thread listings
oldest-first by received time then message ID. Both local listing operations
require a `StoreLimit`, including thread listings, so no local query contract
returns an unbounded envelope collection.

Each concrete adapter must provide its own cancellation, atomicity, and contract
conformance tests. Reusable cross-crate test support is deferred.

No revision, history, or checkpoint API is introduced. Any later revision
acquisition must be atomic with listing, never a separate post-list getter,
and belongs to a reviewed sync protocol.

## Consequences

Adapters implement these ports inward. The contract seam adds no transport,
storage engine, runtime, renderer, or platform types. Sync, mutation, search,
and cache behavior require their own reviewed contracts.
