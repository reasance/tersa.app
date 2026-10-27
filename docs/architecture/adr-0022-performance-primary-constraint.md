<!--
This Source Code Form is subject to the terms of the Mozilla Public License,
v. 2.0. If a copy of the MPL was not distributed with this file, You can obtain
one at https://mozilla.org/MPL/2.0/.
-->

# ADR 0022: Performance as a primary constraint

- Status: Accepted; amended by [ADR 0031](adr-0031-tui-only-pivot.md)
- Date: 2026-07-19

## Decision

Performance and lightweightness are primary product constraints. Measure each
slice as soon as its relevant behavior exists; do not defer all measurement to
release acceptance. Record candidate, build mode, machine, dataset, cache state,
and measurement conditions with results. A source check or unmeasurable metric
is not a runtime performance pass.

[ADR 0031](adr-0031-tui-only-pivot.md) owns the current terminal budgets: first
frame, list-query latency, idle resident memory, and stripped binary size.
[ADR 0030](adr-0030-encrypted-blobs-storage-budget-and-app-lock.md) owns the
planned allocated-byte cache budget. Neither document is evidence that a budget
has been met.

A budget breach blocks the introducing slice unless an accepted ADR changes
the budget. Size growth and measurement limitations need explicit independent
review; an implementer cannot waive their own result. Local macOS measurements
do not establish Linux or release-candidate performance.

## Consequences

Each slice carries the measurements it enables. Release validation remains
candidate-specific; early development measurements do not certify a release.
