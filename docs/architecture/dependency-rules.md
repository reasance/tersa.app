# Dependency rules

Current dependency boundaries follow [ADR 0031](adr-0031-tui-only-pivot.md),
`CORE_POLICY` in `xtask/src/main.rs`, and `cargo deny`.

## Layers

| Layer | Location | May depend on |
|---|---|---|
| core | `crates/*` | other core crates listed in `CORE_POLICY` (`xtask/src/main.rs`) |
| adapter | `adapters/*` | core crates and other adapters |
| app | `apps/*` | core crates and adapters |
| tool | `xtask` | external crates only |

Nothing may depend on an app or on `xtask`.

## Core purity

Core crates hold domain types, ports, and pure policy. They must:

- declare `#![forbid(unsafe_code)]` on a line of its own at the crate root;
- be listed in `CORE_POLICY` (`xtask/src/main.rs`) with an explicit allowlist
  of both the core crates and the external crates they may depend on.

The external allowlist admits only computation crates. I/O, runtime,
terminal, and OS crates belong to adapters and apps; `getrandom` is the single
OS-backed exception because it only reads the system CSPRNG. The check covers
direct dependencies, so adding an external crate to a core crate is always a
visible, reviewed change to `CORE_POLICY`.

`cargo xtask architecture` enforces these rules; `cargo xtask verify` runs it
first.

## Supply chain

`deny.toml` restricts the shipped graph to the macOS and Linux targets,
allows only OSI-approved licenses (ADR 0006 A4), denies yanked crates and
wildcard versions, and keeps retired UI runtimes out of the graph.
`cargo deny check` also applies the RustSec advisory database on every pull
request that changes code. A new production dependency needs a justification in its pull
request: why it is needed, its license, and its maintenance status.
