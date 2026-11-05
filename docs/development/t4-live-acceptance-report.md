# T4 live acceptance report

Candidate: `771bacbf19766ffa3d4cbb29b981489607283c89`.
Tree: `e6caedd32cea7d13309ef356897c12e1a0acef8c`, the same tree as reviewed
commit `ea594784394067173d24c6123612dcc4d8721add`.
Lineage ends at [pull request 170](https://github.com/reasance/tersa.app/pull/170).
Protocol: [t4-live-acceptance-protocol.md](t4-live-acceptance-protocol.md).

No live Gmail Modify acceptance was performed. This report has no live
observations. T3 OAuth and mailbox observations in
[the T3 report](t3-live-acceptance-2026-11-04.md) are not this gate.
The selections required by the protocol have not been supplied.

## Automated checks

These are the recorded candidate checks. This documentation slice did not
re-run them. They are controlled-port, SQLCipher, HTTP-adapter, and
production-wiring evidence. They are not live Google results.

| Check | Recorded result |
| --- | --- |
| `cargo xtask verify` on the candidate host | Exit 0, 30.260 s |
| `cargo deny --locked check` | Exit 0 |
| Application and CLI tests | 137 passed, plus 6 compiled CLI tests; 3 pre-existing performance cases ignored |
| Pull request 170 CI | Linux 137 s, macOS 175 s, CI gate 2 s, success |
| `main` CI at `771bacb` | Success |

The 137 passing tests and the compiled CLI tests exercise fakes, SQLCipher,
and the wired CLI/TUI. Ignored performance cases were not run. CI success
does not include a Gmail Modify call.

## Independent source approval

Independent Grok review accepted the tree above with zero unresolved
findings. That approval is source acceptance of `e6caedd`. It is not live
acceptance, and it does not approve a later change to the tree.

## Source delivery

Pull requests 146 through 170 are merged on the candidate. The
[execution plan](t4-execution-plan.md) lists the slice for each merge.
Delivered source includes ReadOnly account add, selected Modify upgrade,
bounded History sync, the closed message actions, user-label
create/rename/apply/remove/delete, the durable queue, conditional Undo,
queued cancel, explicit Retry, warned Abandon, and the TUI keys in the
protocol. Schema v3, foreign-key enforcement on every open, and `Full`
versus `Skip` scans are implemented as [ADR 0017](../architecture/adr-0017-production-account-store.md)
states.

CLI and TUI wiring is part of this source delivery. It is a separate fact
from a sampled live observation: the commands exist and are tested without a
live mailbox. `tersa help` and the `?` help list are the command and key
surfaces. This report does not claim they were exercised on Google.

## Sampled live acceptance

Binary identity was not recorded for a live run. No alias, message, label,
or OAuth consent was selected.

| Case | Result | Observation |
| --- | --- | --- |
| Binary identity matches the candidate | NOT_RUN | None |
| ReadOnly add and ReadOnly refusal | NOT_RUN | None |
| Selected upgrade to Modify | NOT_RUN | None |
| Second-account isolation | NOT_RUN | None |
| Allowed message action and observed reconciliation | NOT_RUN | None |
| Label create, rename, apply, remove, and delete | NOT_RUN | None |
| Conditional Undo | NOT_RUN | None |
| Cancel of still-Queued local intent | NOT_RUN | None |
| Restart with queued intent | NOT_RUN | None |
| Process-local offline intent, then online reconciliation | NOT_RUN | None |
| Post-commit online failure | NOT_RUN | None |
| Bounded History progress and a further page | NOT_RUN | None |
| Stale view after scope or filter change | NOT_RUN | None |
| Explicit Retry | NOT_RUN | None |
| Warned Abandon | NOT_RUN | None |

The following failures were not injected into a live mailbox. Their evidence
remains the automated suites named above, which do not observe Google:

- Crash or cancel after Dispatching.
- Dropped or forged HTTP responses.
- Forged History expiry, History `404`, or a malformed History page.
- Planted orphan rows or damaged database pages.
- Scripted consent denial, insufficient scope, or a mismatched account.

## Release readiness

Release readiness is not claimed. There is no live Modify run, no Linux
consent acceptance, and no packaging decision. macOS source CI on pull
request 170 does not change that.

## Non-claims

- No live Gmail Modify acceptance.
- No claim that T3 token exchanges or T3 mailbox reads exercised Modify,
  History writes, labels, Undo, or Abandon.
- No claim that tests, mocks, or the candidate hash contacted Google.
- No full-mailbox copy. History caught-up and a 200-row page are bounded
  cache results. A full page reads at most 201 rows from each ready account.
- No secure erasure, app lock, send, draft, watch, classification label, or
  permanent delete.
- No ownership of browser descendants. The launcher bound and the
  nonblocking reap are source behavior, not a live observation in this
  report.
- T4 is not complete.
