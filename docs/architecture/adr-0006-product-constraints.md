# ADR 0006: Product constraints

- Status: Accepted; amended by [ADR 0031](adr-0031-tui-only-pivot.md)

## Decisions

- **A3 — service boundary.** MVP has no required or project-operated backend.
  A user-operated, open-source relay may be considered in vNext, but can never
  be an MVP dependency.
- **A4 — production licensing.** Production dependencies must be OSI-approved
  unless a separate accepted legal ADR authorizes a narrow exception.

Encrypted local persistence, the official Gmail API, and bounded synchronization
remain product requirements. Current platform, cache, and performance decisions
are in [ADR 0031](adr-0031-tui-only-pivot.md) and
[ADR 0030](adr-0030-encrypted-blobs-storage-budget-and-app-lock.md).

## Evidence

A constraint or accepted plan is not an implementation or acceptance result.
Runtime, accessibility, security, and release evidence must identify the exact
candidate and measurement conditions and receive independent review. Local
source tests cannot establish live-provider or release behavior.

The removed diagnostic gate program imposes no current milestone or toolkit
gate. Earlier versions of these decisions remain in Git history.
