# T3 live acceptance observations — 2026-11-04

Candidate: `06a7e0fdc1a677ea5eb284f8e56ff0f1cbae3130`, macOS development build.
This report summarizes observations from November 2 and November 4, 2026 for
the T3 two-real-account manual gate in the [roadmap](../roadmap.md) and
[ADR 0026](../architecture/adr-0026-multi-account-and-unified-mailbox.md).
Independent Grok 4.7 review (xhigh effort, 500k context) accepted closure of
that bounded candidate-specific gate as sampled macOS acceptance.

## Observed results

Accounts are labeled A and B. Two distinct registrations were verified.

| Check | Candidate-specific observation |
|---|---|
| Add/sync, November 2 | Both accounts showed 100 messages and synced status. B's add reported 100 messages and 25 cached bodies; the checkpoint does not record A's body count. |
| Online views, November 2 | All accounts showed 200 messages; each scoped view showed 100. Independent per-account sync/status was observed. |
| Offline reopen, November 2 | After exit to shell, the TUI reopened with process-local network denial. Cached All/scoped views showed 200/100/100 messages; both account sync endpoints were unreachable. |
| Removal, November 2 | B removal exited successfully and its account directory was deleted. A remained registered with its directory present, synced 100 messages with two newly cached bodies, and the TUI showed 100 messages. |
| Offline isolation, November 4 | The final isolation record reports PASS for six samples, three per account, with CLI cache counts of 100/100. Every sample had one own-account search match, zero other-account matches and one unified match, a matching account header and a rendered cached body. The first 30 compared pane lines matched between scoped and unified views, including message headers and the beginning of the body. All accounts showed 200 cached rows. |

## Method and evidence

The isolation verifier used a scoped CLI cache reference and the actual TUI
through Herdr. It selected six messages from the first 25 CLI cache rows per
account. The CLI prefilter kept a subject only when its words matched one
own-account row and no other-account rows. Subject-word collisions were
excluded, and those prefilter exclusions are not counted in the PASS record.
Selected samples also required a unique actual own-account TUI result.
The other-account TUI check used word search over sender, subject and preview;
it was not exact-subject enumeration or a full-cache comparison.

This compares local cache routing and rendered views; there was no independent
Gmail API export. Equality was checked only for the first 30 pane lines after
removing the top/bottom bars and sync-failure lines. Those lines include message
headers and the beginning of the body, not 30 body lines or necessarily the
entire message.

Offline runs used `sandbox-exec` with `(deny network*)` for the Tersa process.
Host connectivity remained available; this was not physical host disconnection.
No repository code changes were made for verification.

The source records are private local `checkpoint.json` and
`removal-checkpoint.json` from November 2 and the final `isolation.json` from
November 4. All three checkpoints bind to the candidate above. Preserved
incomplete harness attempts document the corrections below. The independent
evidence verdict accepting the bounded gate is retained locally.
Earlier pending entries describe intermediate states; the later removal and
isolation records supply the subsequent observations. Raw records, account
identifiers, addresses, message content, subject/rendered hashes, credentials
and private paths are omitted from this repository report and remain local.

## Harness corrections

The first readiness-timeout record reports that the offline TUI failed to
initialize, with no samples and no recorded diagnosis. A second command-error
record diagnoses a missing closing quote in the external verifier command and
states that Tersa had not started in that attempt. Command construction was
corrected with `shlex.join`.

Preserved ambiguous attempts stopped at four scoped matches and excluded the
candidate as non-unique. They do not establish which fields produced the extra
matches. The final PASS record retains a skipped four-match candidate; the six
accepted samples each had a unique actual own-account TUI result. These
incomplete attempts and selection corrections are retained as harness limits;
no repository code changes were made for verification.

## Limits and non-claims

- Six selected messages are bounded evidence, not exhaustive cross-account
  isolation or security proof. Row counts alone do not prove content isolation.
- Live cache reset was not exercised. Its evidence remains the existing
  automated coverage; successful removal is not a cache-reset test.
- Successful local removal does not establish confirmed Google-side revocation.
- Independent per-account sync/status was observed, without a five-minute
  timing test or teardown stress test.
- These macOS development-build observations do not establish Linux live
  acceptance, performance budgets, distribution or release readiness, whole-ADR
  completion or MVP completion.
- Capability upgrade, account-local FTS, drafts/outbox, app lock and the deferred
  incompatible-schema/new-ID/quarantine protocol remain planned. This report
  does not expand T3 or the roadmap scope.
