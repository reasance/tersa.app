# tersa

tersa is a privacy-first, open-source Gmail client for the terminal, for
macOS and Linux.

It is in early development and not yet usable as an email client. There are
no published builds.

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

## Project status

See the [roadmap](docs/roadmap.md) and
[ADR 0031](docs/architecture/adr-0031-tui-only-pivot.md), which moved tersa
from a native Apple client to a terminal client. Security boundaries are in
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
