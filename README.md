# tersa

tersa is a privacy-first, open-source Gmail client for the terminal, for
macOS and Linux.

It is in early development, with read-only mail browsing and multi-account
support available from source. There are no published builds.

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
   the interface (`?` lists the keys) or `… -- inbox` for plain output.
   `tersa doctor` shows where files live and what is configured.

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
and caching up to 25 bodies. It keeps the same account registration and setup.
The clear preserves credentials; subsequent sync follows the normal token
lifecycle, including rotation or deletion of a revoked refresh token. This
command does not guarantee restoration of all previous mail, secure erasure,
or repair of an incompatible schema.

A pre-clear refusal leaves the cache intact. If the clear commits but sync
fails, the command exits unsuccessfully and says so; partial new cache data
may exist. Run `tersa sync <account>` to retry, or `tersa account add` if sign-in
is required. Reset does not retry or start reconsent automatically.

## Project status

Multi-account source implementation and automated coverage are delivered.
Two-real-account macOS isolation and offline acceptance remain pending; fixtures
and CI do not establish that manual gate or MVP completion.

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
