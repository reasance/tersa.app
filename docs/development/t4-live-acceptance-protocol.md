# T4 live acceptance protocol

Candidate: `771bacbf19766ffa3d4cbb29b981489607283c89`.
Tree: `e6caedd32cea7d13309ef356897c12e1a0acef8c`, the same tree as reviewed
commit `ea594784394067173d24c6123612dcc4d8721add`.
Lineage ends at [pull request 170](https://github.com/reasance/tersa.app/pull/170).

This protocol is the macOS manual gate for that candidate. It authorizes no
run by itself. The [report](t4-live-acceptance-report.md) stays free of
observations until a later slice records a run that used the selections below.
T3 acceptance in [its report](t3-live-acceptance-2026-11-04.md) is a different
gate.

## Proof classes

Keep these records separate:

| Record | What it can show |
| --- | --- |
| Controlled-port, SQLCipher, and HTTP-adapter tests | Closed contracts against fakes, fixtures, and the local database |
| CLI and TUI production wiring | The real command parser, interface keys, and runtime calls in the candidate |
| Sampled live observation | What this protocol records on a user-selected mailbox |
| Release readiness | Packaging, Linux consent, and a decision to ship |

Automated tests, mocks, and the candidate hash do not establish a live Google
result. A wired command that has not been used on the selected account stays
unobserved.

## Binary identity

Before any account command, from a clean tree at the candidate:

1. Record `git rev-parse HEAD` and `git rev-parse 'HEAD^{tree}'`. Both must
   match the commit and tree above. Stop if they differ.
2. Build the `tersa` binary that will be used. Record its absolute path,
   `tersa --version`, and the SHA-256 of that file.
3. Use that same binary for every case. Rebuilding, or any commit change,
   ends the run.

The version string alone is not identity. The repository copy of the report
stores the commit, tree, version, and binary hash. It does not store the
binary path if that path identifies a home directory.

## Evidence rules

Accounts are aliases such as A and B. Messages are aliases such as M1.
The disposable User label is L1. The repository record may contain the alias,
the closed action name, the closed command status, numeric counts from tersa's
own notices, and the words Read-only or Modify.

Do not commit access tokens, refresh tokens, OAuth `state`, authorization
URLs, raw message bodies, raw subjects, raw label names, addresses, account
identifiers, key material, or private paths. `tersa account list` output stays
out of the repository; copy only the stored-access word onto the alias.

A count that ends in `+` means another cached page is available. Each merged
query page holds at most 200 rows. A 200-row page probes 201 source rows so
another page can follow. Do not record 200 as the size of the mailbox or of
the view.

## Allowed actions

Use only disposable messages and one disposable User label that the user
named in the selection. On those messages the allowed actions are Read,
Unread, Star, Unstar, Archive, Trash, Restore to Inbox, Spam, and Clear Spam
to Inbox. On L1 the allowed actions are create, rename, apply, remove, and
delete. Delete removes the label definition and its assignments. It does not
delete messages.

Also allowed, on commands this run created:

- Cancel a command that is still Queued, before dispatch.
- Queue conditional Undo of the last Complete message-state command.
- Explicit Retry only when Q already shows Ambiguous or Needs attention for
  that command.
- Warned Abandon only when Q already shows a nonterminal command and the user
  chooses that exit. Abandon is not success and not rollback.

`tersa account add` requests ReadOnly. Modify is only
`tersa account upgrade <account>` or A → Upgrade for that selected account.
`tersa account reconnect <account>` repeats consent for the stored capability.
`tersa sync [<account>]` is one bounded History cycle and, when pending
commands exist, one command pass.

## Forbidden actions

Do not send mail, create or edit drafts, call watch, apply classification
labels, permanently delete messages, or request `gmail.send`,
`https://mail.google.com/`, or any scope beyond the selected ReadOnly or
Modify grant. Do not delete messages the user did not name. Do not change
host networking, DNS, proxy, firewall, or another account's data. Do not
stop unrelated processes.

Process-local network denial for the tersa process, as in the T3 offline
reopen, is the only offline method. Host connectivity stays available.

## Browser and consent

Upgrade and reconnect open the system browser. The launcher keeps at most
five child handles, reaps finished launchers without blocking, and does not
kill or wait for the browser when consent finishes or the account task is
cancelled. Descendants are not owned. Closing tersa cancels tersa's account
work; the external browser application may remain open. Leave it. Do not
copy the authorization link into the report.

## Interface path

Bare `tersa` opens cached Recent mail. `?` is the help list and any key
closes it. The production keys used here are:

| Key | Use |
| --- | --- |
| `j` / `k` | Move in the list |
| `m` | Desired actions for the current row, or for the `v` / `V` batch |
| `i` | Observed state and pending intent |
| `F` | Recent, observed Inbox, Trash, Spam, or a User label |
| `Q` | Queue, cancel, retry, abandon, conditional Undo |
| `L` | Create, rename, and delete User labels |
| `A` | Account status, upgrade, reconnect, one observe pass, one drive pass |
| `v` / `V` / `X` | Select one, select the shown page, clear the batch |
| Tab / Shift-Tab | All accounts or one account, when two or more are registered |
| Ctrl-R | Sync the current view. Automatic sync still covers every account |

Message actions open "Explicit desired action", then a confirmation whose
default is Cancel. The confirm choice is "Confirm this exact captured
action". A ReadOnly account shows "ReadOnly: no command admitted. Use A →
Upgrade for this account." and admits nothing.

Q distinguishes observed provider state from pending desired intent. Status
words to copy are the closed ones tersa shows, including Queued, Dispatching,
Complete, Partial, Cancelled, Abandoned, Ambiguous, and Needs attention.
"History caught up for the retained cache; this is not full-mailbox coverage."
and "Bounded History progress saved; cached views may still be stale." are
progress notices, not a claim that the mailbox was fully copied.

## Cases

Run the cases in order. Skip a case whose selection is missing and leave it
not run. Do not invent a stand-in target.

1. **Identity.** Record the binary identity above. Do not start consent until
   it matches.
2. **ReadOnly add.** If alias A is not already connected, `tersa account add`
   and complete the ReadOnly consent. Record that the stored access for A is
   Read-only. Attempt one message action before upgrade and record the
   ReadOnly refusal.
3. **Selected upgrade.** Upgrade only the selected account, from
   `tersa account upgrade` or A → Upgrade. Complete that separate Modify
   consent. Record that stored access for A is Modify. A second account, if
   selected, stays ReadOnly unless the user also selected it for upgrade.
4. **Isolation.** Requires aliases A and B. Admit one allowed action on a
   message owned by A. In B's scoped view and in B's queue, record that the
   command is absent. One account leaves this case not run. Automated
   isolation tests remain the other evidence, and they are not this case.
5. **Message action and reconciliation.** On M1, confirm one allowed action.
   Record the queued or later status from Q. Run `tersa sync` for that
   account, or Ctrl-R on its view. Record the History notice and the command
   notice, including whether observation is still required. Then `i` on M1
   and record only the closed observed word for the field that action
   changed, such as read, starred, Inbox, Trash, or Spam.
6. **Labels.** Create L1, rename it once, apply it to M1, remove it from M1,
   and delete it. Use L for create, rename, and delete, and `m` for apply and
   remove. Record each closed status. Deletion's confirmation says messages
   are not deleted; confirm M1 is still listed afterward.
7. **Conditional Undo.** After a Complete message-state command, choose
   "Conditional Undo of last Complete message command…" from A or Q. The
   warning says eligibility is checked after reconnect and that queuing does
   not confirm completion. Confirm the queue. If no Complete message-state
   command exists, leave the case not run. Label create, rename, and delete
   do not supply Undo.
8. **Queued cancel.** Admit one allowed action and cancel it from Q while
   the status is still Queued, using "Cancel still-Queued local intent".
   Record Cancelled. If the command has already left Queued, do not cancel
   it; leave this case not run and keep the later status on its own case.
9. **Restart.** With a Queued command or a queued conditional Undo present,
   quit to the shell and open `tersa` again. Record that the same account's
   Q still shows that intent. Then continue with sync.
10. **Offline intent.** With process-local `(deny network*)` around tersa
    only, admit one allowed action or leave the queued intent from the
    previous case. Record that Q shows queued intent and that sync for that
    account is unreachable. Quit. Reopen online and run `tersa sync` for
    that account. Record the command notice and the observed field. Do not
    change global networking.
11. **Post-commit online failure.** If, after a durable receipt is shown, a
    later sync or command pass fails while tersa reports that existing intent
    is retained, record the closed notice and the status still in Q. Do not
    inject a dropped response, a killed connection, or a proxy change to
    force it. If it does not occur, the case stays not run. Automated
    Dispatching and Ambiguous coverage remains the evidence for lost
    responses.
12. **History progress.** Record one `tersa sync` notice. If it says bounded
    progress, run sync again and record whether another bounded step or
    caught-up is shown. Caught-up still says it is not full-mailbox coverage.
    In the interface, if the count ends in `+`, page further and record that
    another page loaded. Do not treat the first page as the whole view.
13. **Stale view.** Start an action confirmation, then switch account scope
    or press `F` before confirming. A changed view says to reopen the action
    and that nothing was submitted. Reopen `m` on the new view and confirm
    the targets belong to that view. Complete one action, switch scope, and
    record that Q for the owning account still holds the command.
14. **Recovery and Abandon.** Only if Q already shows Ambiguous or Needs
    attention, record one explicit Retry. The label-create retry additionally
    requires the duplicate-risk confirmation; do not create that situation on
    purpose. Only if the user chooses to stop a real nonterminal command,
    open "Warned Abandon of this command…", record that the warning says
    Gmail may already have applied it, and record Abandoned after
    confirmation. Otherwise leave both paths not run.

## Failure injection that stays on fixtures

Do not perform these against the selected mailbox. Each one already has
automated coverage, and that coverage is not a live observation:

- Crash or cancel after Dispatching, to force Ambiguous.
- Drop or forge the HTTP response, including an empty-body success versus a
  transport failure.
- Forge History expiry, a History `404`, or a malformed History page.
- Plant orphan rows or damaged database pages to distinguish `Full` and
  `Skip` scans.
- Deny consent, return an insufficient scope, or present the wrong account
  in the browser. If the user independently refuses consent, record only
  "consent refused" for that alias and stop that account. Do not retry with
  a broader scope.

## Selection required

The user supplies these before a live slice. This protocol does not choose
them.

| Selection | What to name |
| --- | --- |
| Account or accounts | Alias A, and alias B when isolation should run. Say which alias is upgraded to Modify. The other stays ReadOnly. |
| Message or messages | Disposable messages, with aliases. State which allowed reversible actions may be used on each. |
| Label | One disposable User-label name, recorded in the report only as L1. The run may create, rename, apply, remove, and delete it. |
| OAuth consent | Consent for a ReadOnly add when the account is not connected, and a separate consent for the selected Modify upgrade. The user completes consent in the external browser. |

Until those selections exist, every live case stays not run.
