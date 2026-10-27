# ADR 0018: bounded sync and cache

- Status: Accepted
- Date: 2026-07-16

## Context

The terminal client needs an offline recent inbox without making a lossless mailbox-sync,
background-refresh, or cache-budget claim. The Gmail adapter can return an
empty page with a fresh continuation token when all attempted message hydrations
were 404, so bounded pagination must permit that case without risking a loop.

## Decision

`tersa-application::sync` owns a runtime-free recent-snapshot coordinator. A
validated policy uses the existing provider `PageSize` cap of 500, a finite cap
of 1,000 pages, an existing `StoreLimit` keep cap of 10,000, and a full-message
cap no greater than the keep cap. The coordinator is lazy and single-flight per
account; its drop-owned claim is released on cancellation, it holds no mutex
guard across an await, creates no detached work, and retries nothing.

It collects and validates the complete bounded snapshot before any store
mutation. Pages larger than requested, repeated continuation tokens, and
conflicting duplicate message identifiers fail. Exact duplicates deduplicate in
provider encounter order. Collection stops at the keep limit and reports
truncation. A zero-item page with a fresh token is valid.

One store transaction reconciles snapshot envelopes, preserving already cached
bodies and retaining only the deterministic `received_at DESC, message_id ASC`
keep set. It returns only snapshot identifiers that survived, in duplicate-free
provider encounter order. The coordinator fetches bodies sequentially only for
those survivors and only up to the full-message cap. `NotFound` and a vanished
conditional-cache row are counted as skipped; every other remote, protocol, or
store failure stops immediately. The coordinator never calls general-purpose
`put_message`.

Reports and failures contain only counts, source categories, progress, and
truncation flags. Their manual formatting does not expose identifiers, tokens,
headers, or bodies.

## Non-claims

This is bounded recent-snapshot bootstrap/refresh only. It adds no Gmail
History/cursor, deletion reconciliation, retry, background work,
mutations/outbox/labels, blob/search/CLI/UI, real credentials/network tests,
platform-runtime evidence. Older or deleted remote rows may
remain locally until deterministic pruning displaces them. Cache budgets remain
constraints, not evidence.

## Consequences

The local store remains responsible for atomic reconcile and conditional cache
writes. Adapters continue to own their transaction and cancellation evidence;
the application layer stays independent of runtimes, transports, storage
engines, OS APIs, and terminal frameworks.
