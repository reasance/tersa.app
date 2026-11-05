# tersa

tersa is a privacy-first, open-source Gmail client for the terminal, for
macOS and Linux.

It is in early development. Source builds include read-only browsing,
multi-account views, and account-bound triage: History sync, labels, and
durable mailbox commands. There are no published builds. Live Gmail Modify
acceptance has not been run, so T4 is not complete.

## Product boundaries

- one Rust binary with a full-screen terminal UI
- macOS and Linux (x86_64 and aarch64)
- Gmail through the official Gmail API, with your own Google OAuth client
- encrypted local storage, with keys held by the OS keyring or a passphrase
- no project-operated backend
- message content rendered as sanitized text; no remote content is fetched

## Trying it

tersa has no releases yet. From a checkout:

1. In Google Cloud Console, create a project, enable the Gmail API, and create
   an OAuth client of type **Desktop app**. Add yourself as a test user.
2. Put the client in `~/.config/tersa/config.toml`:

   ```toml
   [google]
   client_id = "….apps.googleusercontent.com"
   client_secret = "…"

   # Optional. "auto" uses the system keyring and falls back to a
   # passphrase-protected key file; set passphrase = true to require a
   # passphrase even with a keyring.
   [vault]
   backend = "auto"
   passphrase = false
   ```

3. Run `cargo run -p tersa -- account add`, then `cargo run -p tersa` to open
   the interface (`?` lists the keys) or `cargo run -p tersa -- inbox` for
   plain cached output. `tersa doctor` shows where files live and what is
   configured.

`tersa account add` requests ReadOnly access. Modify is a separate selected
upgrade, `tersa account upgrade <account>`, or A → Upgrade in the interface.
`tersa account reconnect <account>` repeats consent for the capability already
stored. `tersa sync [<account>]` runs one bounded History cycle and, when
pending commands exist, one command pass. With no arguments, `tersa` opens
cached Recent mail. The interface help is the key list: `m` actions, `F`
filters, `Q` queue, `L` labels, `A` account, `v` / `V` / `X` selection, and
`?` help. `tersa help` prints the command list.

## Accounts and cache reset

The inbox combines up to five accounts. With multiple accounts, Tab / Shift-Tab
cycles between All accounts and one account. A real view change returns to the
inbox, clears search, and starts a fresh scoped query. Automatic sync continues for every
account; Ctrl-R syncs the current view. Accounts have independent sync workers
and status. Search filters loaded, sanitized rows in memory; it is not a
full-mailbox index.

```text
tersa account reset <account>
tersa account reset <account> --yes
```

The target can be an exact account ID, an unambiguous ID prefix, or a stored
address. Unknown or ambiguous targets fail; unreadable accounts cannot be
skipped to claim a unique address match. The interactive prompt shows the
address when available and the opaque ID. Enter the complete word `yes` and
press Enter to confirm (case-insensitive, surrounding whitespace allowed).
Empty input, EOF, or another answer cancels. Non-interactive use requires
`--yes`, which skips only confirmation; key unlock and validation still apply.

Reset deletes local cached messages and clears sync freshness, then runs the
normal bounded recent-mail sync: up to four pages of 25, keeping 100 envelopes
and caching up to 25 bodies. A successful clear also removes the History
cursor, terminal command summaries, undo state, and cached provider membership.
It keeps the same account registration, capability, grant, identity, and
disconnect recovery. The clear preserves credentials; subsequent sync follows
the normal token lifecycle, including rotation or deletion of a revoked refresh
token. This command does not guarantee restoration of all previous mail, secure
erasure, or repair of an incompatible schema.

A nonterminal command, including one that is still queued, refuses the clear
before it starts. The command reports that the local cache is not eligible and
leaves it intact. Cancel that queued intent, let the work settle, or explicitly
Abandon it in the interface before retrying reset. Any other pre-clear refusal
also leaves the cache intact. If the clear commits but sync fails, the command
exits unsuccessfully and says so; partial new cache data may exist. Run
`tersa sync <account>` to retry. If sign-in is required, run
`tersa account reconnect <account>`. Reset does not retry or start reconsent
automatically. After a committed clear, the CLI also runs one History cycle.
If that follow-up fails, the clear stays committed and the command says to
resume with `tersa sync`.

## Project status

Multi-account source implementation and automated coverage are delivered.
Two-real-account macOS observations on candidate `06a7e0f` cover add/sync,
All/single-account views, offline reopen, removal and six content-isolation
samples. The [redacted acceptance report](docs/development/t3-live-acceptance-2026-11-04.md)
records the candidate, method and limits. Independent Grok 4.7 review accepted
closure of this bounded sampled manual gate. These observations do not establish
exhaustive isolation, whole-ADR, MVP or release readiness. Cache reset has automated
coverage but was not exercised live.

T4 triage source is on candidate `771bacb` (tree `e6caedd`). Automated checks
and independent source approval are in the
[acceptance report](docs/development/t4-live-acceptance-report.md). No live
Gmail Modify acceptance has been run. The T3 observations above are not that
gate.

See the [roadmap](docs/roadmap.md) and
[ADR 0031](docs/architecture/adr-0031-tui-only-pivot.md) for the terminal
architecture. Security boundaries are in
the [threat model](docs/security/threat-model.md) and
[data flow](docs/security/data-flow.md).

## Development

The workspace pins Rust 1.91.1. Run the verification suite with:

```sh
cargo xtask verify
```

See [Development](docs/development.md) for the contributor workflow.

## Contributing and security

- Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.
- Report vulnerabilities through the process in [SECURITY.md](SECURITY.md).
- Repository artifacts follow the [English language policy](docs/governance/language-policy.md).
- Source code is licensed under the [Mozilla Public License 2.0](LICENSE).
