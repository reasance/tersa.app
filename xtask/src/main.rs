// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Repository automation for tersa.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::error::Error;
use std::fs;
use std::io;
use std::process::{Command, ExitCode};

use cargo_metadata::camino::Utf8Path;
use cargo_metadata::{DependencyKind, Metadata, MetadataCommand, Package};

type TaskResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

/// One core crate and every dependency it may declare.
struct CorePolicy {
    name: &'static str,
    /// Allowed workspace (core) dependencies.
    workspace: &'static [&'static str],
    /// Allowed external dependencies. Core crates hold domain types, ports,
    /// and pure policy, so only computation crates belong here; I/O, runtime,
    /// terminal, and OS crates belong to adapters and apps. `getrandom` is the
    /// one OS-backed exception: it only reads the system CSPRNG.
    external: &'static [&'static str],
}

/// Every crate under `crates/` must be listed here before it builds in CI.
/// Adding an external dependency to a core crate is a reviewed policy change.
const CORE_POLICY: [CorePolicy; 4] = [
    CorePolicy {
        name: "tersa-domain",
        workspace: &[],
        external: &[],
    },
    CorePolicy {
        name: "tersa-keys",
        workspace: &["tersa-domain"],
        external: &[
            "argon2",
            "chacha20poly1305",
            "getrandom",
            "hkdf",
            "hmac",
            "sha2",
            "zeroize",
        ],
    },
    CorePolicy {
        name: "tersa-application",
        workspace: &["tersa-domain"],
        external: &["base64", "getrandom", "sha2", "subtle", "url", "zeroize"],
    },
    CorePolicy {
        name: "tersa-presentation",
        workspace: &["tersa-domain", "tersa-application"],
        external: &["mail-parser", "unicode-segmentation", "unicode-width"],
    },
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Layer {
    Core,
    Adapter,
    App,
    Tool,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> TaskResult {
    let mut arguments = env::args().skip(1);
    match arguments.next().as_deref() {
        Some("architecture") => {
            reject_extra_arguments(arguments)?;
            check_architecture()
        }
        Some("verify") => {
            reject_extra_arguments(arguments)?;
            verify()
        }
        Some("check-pkg") => {
            let package = required_argument(&mut arguments, "package name")?;
            reject_extra_arguments(arguments)?;
            check_pkg(&package)
        }
        Some("test-pkg") => {
            let package = required_argument(&mut arguments, "package name")?;
            reject_extra_arguments(arguments)?;
            test_pkg(&package)
        }
        Some("clippy-pkg") => {
            let package = required_argument(&mut arguments, "package name")?;
            reject_extra_arguments(arguments)?;
            clippy_pkg(&package)
        }
        Some("preflight") => {
            let class = required_argument(&mut arguments, "preflight class")?;
            let package = optional_package_flag(&mut arguments)?;
            reject_extra_arguments(arguments)?;
            preflight(&class, package.as_deref())
        }
        Some("help") | None => {
            print_help();
            Ok(())
        }
        Some(command) => Err(io::Error::other(format!(
            "unknown command `{command}`; run `cargo xtask help`"
        ))
        .into()),
    }
}

fn required_argument(
    arguments: &mut impl Iterator<Item = String>,
    description: &str,
) -> TaskResult<String> {
    arguments.next().ok_or_else(|| {
        io::Error::other(format!("missing {description}; run `cargo xtask help`")).into()
    })
}

fn reject_extra_arguments(mut arguments: impl Iterator<Item = String>) -> TaskResult {
    if let Some(argument) = arguments.next() {
        return Err(io::Error::other(format!("unexpected argument `{argument}`")).into());
    }
    Ok(())
}

fn optional_package_flag(
    arguments: &mut impl Iterator<Item = String>,
) -> TaskResult<Option<String>> {
    let Some(first) = arguments.next() else {
        return Ok(None);
    };
    if first == "--package" || first == "-p" {
        return Ok(Some(required_argument(arguments, "package name")?));
    }
    if let Some(package) = first.strip_prefix("--package=") {
        return Ok(Some(package.to_owned()));
    }
    Err(io::Error::other(format!(
        "unexpected argument `{first}`; expected --package <crate> or no further arguments"
    ))
    .into())
}

fn print_help() {
    println!(
        "\
Repository automation for tersa

Usage:
  cargo xtask verify                    Run the full verification suite (merge quality)
  cargo xtask architecture              Check workspace layering and core purity
  cargo xtask check-pkg <package>       cargo check  -p <package> --all-targets (locked)
  cargo xtask test-pkg <package>        cargo test   -p <package> --all-targets (locked)
  cargo xtask clippy-pkg <package>      cargo clippy -p <package> --all-targets -D warnings
  cargo xtask preflight <class> [--package <crate>]
                                        Change-class minimum loop (see agent playbook)
  cargo xtask help                      Show this help

preflight classes: domain, application, presentation, adapter (needs --package),
  tui, policy, docs"
    );
}

// --- Cargo helpers -------------------------------------------------------

fn cargo(arguments: &[&str]) -> Command {
    let mut command = Command::new("cargo");
    command.args(arguments);
    command
}

fn run_command(label: &str, mut command: Command) -> TaskResult {
    println!("Running {label}...");
    let status = command.status()?;
    if status.success() {
        return Ok(());
    }
    Err(io::Error::other(format!("{label} exited with status {status}")).into())
}

fn workspace_metadata(no_deps: bool) -> TaskResult<Metadata> {
    let mut command = MetadataCommand::new();
    if no_deps {
        command.no_deps();
    }
    command
        .other_options(vec!["--locked".to_owned()])
        .exec()
        .map_err(|error| io::Error::other(format!("cargo metadata failed: {error}")).into())
}

fn require_workspace_package(package: &str) -> TaskResult {
    let metadata = workspace_metadata(true)?;
    let names = metadata
        .workspace_packages()
        .into_iter()
        .map(|candidate| candidate.name.to_string())
        .collect::<BTreeSet<_>>();
    if names.contains(package) {
        return Ok(());
    }
    Err(io::Error::other(format!(
        "unknown package `{package}`; workspace packages: {}",
        names.into_iter().collect::<Vec<_>>().join(", ")
    ))
    .into())
}

fn check_pkg(package: &str) -> TaskResult {
    require_workspace_package(package)?;
    run_command(
        &format!("check {package}"),
        cargo(&["check", "--locked", "-p", package, "--all-targets"]),
    )
}

fn test_pkg(package: &str) -> TaskResult {
    require_workspace_package(package)?;
    run_command(
        &format!("tests {package}"),
        cargo(&["test", "--locked", "-p", package, "--all-targets"]),
    )
}

fn clippy_pkg(package: &str) -> TaskResult {
    require_workspace_package(package)?;
    run_command(
        &format!("Clippy {package}"),
        cargo(&[
            "clippy",
            "--locked",
            "-p",
            package,
            "--all-targets",
            "--",
            "--deny",
            "warnings",
        ]),
    )
}

// --- verify --------------------------------------------------------------

fn verify() -> TaskResult {
    check_architecture()?;
    run_command("format check", cargo(&["fmt", "--all", "--check"]))?;
    run_command(
        "Clippy",
        cargo(&[
            "clippy",
            "--locked",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--",
            "--deny",
            "warnings",
        ]),
    )?;
    // Tests and Clippy enable every feature; this checks exactly what ships,
    // the `tersa` binary with its production feature set.
    run_command(
        "default-feature check",
        cargo(&["check", "--locked", "--package", "tersa"]),
    )?;
    run_command(
        "tests",
        cargo(&[
            "test",
            "--locked",
            "--workspace",
            "--all-targets",
            "--all-features",
        ]),
    )?;
    run_command(
        "documentation tests",
        cargo(&["test", "--locked", "--workspace", "--doc", "--all-features"]),
    )?;
    let mut documentation = cargo(&[
        "doc",
        "--locked",
        "--workspace",
        "--no-deps",
        "--all-features",
    ]);
    documentation.env("RUSTDOCFLAGS", "--deny warnings");
    run_command("documentation", documentation)?;

    println!("Verification passed.");
    Ok(())
}

// --- preflight -----------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PreflightClass {
    Domain,
    Application,
    Presentation,
    Adapter,
    Tui,
    Policy,
    Docs,
}

fn parse_preflight_class(raw: &str) -> Option<PreflightClass> {
    match raw {
        "domain" => Some(PreflightClass::Domain),
        "application" => Some(PreflightClass::Application),
        "presentation" => Some(PreflightClass::Presentation),
        "adapter" | "adapter-rust" => Some(PreflightClass::Adapter),
        "tui" => Some(PreflightClass::Tui),
        "policy" | "policy-xtask" => Some(PreflightClass::Policy),
        "docs" | "docs-only" => Some(PreflightClass::Docs),
        _ => None,
    }
}

fn preflight(class_raw: &str, package: Option<&str>) -> TaskResult {
    let class = parse_preflight_class(class_raw).ok_or_else(|| {
        io::Error::other(format!(
            "unknown preflight class `{class_raw}`; run `cargo xtask help`"
        ))
    })?;
    match class {
        PreflightClass::Domain => test_pkg("tersa-domain"),
        PreflightClass::Application => test_pkg("tersa-application"),
        PreflightClass::Presentation => test_pkg("tersa-presentation"),
        PreflightClass::Adapter => {
            let package = package
                .ok_or_else(|| io::Error::other("preflight adapter requires --package <crate>"))?;
            test_pkg(package)
        }
        PreflightClass::Tui => {
            let metadata = workspace_metadata(true)?;
            for app in metadata
                .workspace_packages()
                .into_iter()
                .filter(|candidate| {
                    package_layer(candidate, &metadata.workspace_root) == Some(Layer::App)
                })
            {
                clippy_pkg(app.name.as_str())?;
                test_pkg(app.name.as_str())?;
            }
            Ok(())
        }
        PreflightClass::Policy => {
            check_architecture()?;
            test_pkg("xtask")
        }
        PreflightClass::Docs => {
            println!("preflight docs: no cargo suite; run `typos` if installed");
            Ok(())
        }
    }
}

// --- architecture --------------------------------------------------------

/// Classifies a package by the first component of its manifest path relative
/// to the workspace root, so the checkout location cannot affect the result.
fn package_layer(package: &Package, workspace_root: &Utf8Path) -> Option<Layer> {
    layer_for(package.manifest_path.strip_prefix(workspace_root).ok()?)
}

/// Classifies a manifest path relative to the workspace root.
fn layer_for(relative: &Utf8Path) -> Option<Layer> {
    let components = relative
        .components()
        .map(|component| component.as_str())
        .collect::<Vec<_>>();
    match components.as_slice() {
        ["crates", _, "Cargo.toml"] => Some(Layer::Core),
        ["adapters", _, "Cargo.toml"] => Some(Layer::Adapter),
        ["apps", _, "Cargo.toml"] => Some(Layer::App),
        ["xtask", "Cargo.toml"] => Some(Layer::Tool),
        _ => None,
    }
}

/// One workspace crate as seen by the layering rules.
#[derive(Debug)]
struct CrateFacts<'a> {
    name: &'a str,
    layer: Layer,
    /// Normal (shipped) dependencies on other workspace crates.
    workspace_dependencies: BTreeSet<&'a str>,
    /// Normal (shipped) dependencies on external crates.
    external_dependencies: BTreeSet<&'a str>,
}

fn layering_violations(crates: &[CrateFacts<'_>]) -> Vec<String> {
    let layers = crates
        .iter()
        .map(|facts| (facts.name, facts.layer))
        .collect::<BTreeMap<_, _>>();
    let core_policy = CORE_POLICY
        .iter()
        .map(|policy| (policy.name, policy))
        .collect::<BTreeMap<_, _>>();
    let mut violations = Vec::new();

    for facts in crates {
        for dependency in &facts.workspace_dependencies {
            match layers.get(dependency) {
                Some(Layer::App | Layer::Tool) => violations.push(format!(
                    "{} -> {dependency}: apps and xtask are leaves; nothing may depend on them",
                    facts.name
                )),
                Some(Layer::Adapter) if facts.layer == Layer::Core => violations.push(format!(
                    "{} -> {dependency}: core crates must not depend on adapters",
                    facts.name
                )),
                _ => {}
            }
        }

        if facts.layer != Layer::Core {
            continue;
        }
        match core_policy.get(facts.name) {
            None => violations.push(format!(
                "{}: core crate is missing from CORE_POLICY in xtask",
                facts.name
            )),
            Some(policy) => {
                for dependency in &facts.workspace_dependencies {
                    if !policy.workspace.contains(dependency) {
                        violations.push(format!(
                            "{} -> {dependency}: not allowed by CORE_POLICY",
                            facts.name
                        ));
                    }
                }
                for dependency in &facts.external_dependencies {
                    if !policy.external.contains(dependency) {
                        violations.push(format!(
                            "{} -> {dependency}: external dependency not allowed by CORE_POLICY \
                             (core crates stay free of I/O and OS crates)",
                            facts.name
                        ));
                    }
                }
            }
        }
    }
    violations
}

fn check_architecture() -> TaskResult {
    let metadata = workspace_metadata(true)?;
    let workspace_names = metadata
        .workspace_packages()
        .into_iter()
        .map(|package| package.name.as_str())
        .collect::<BTreeSet<_>>();

    let mut violations = Vec::new();
    let mut crates = Vec::new();
    for package in metadata.workspace_packages() {
        let Some(layer) = package_layer(package, &metadata.workspace_root) else {
            violations.push(format!(
                "{}: workspace crate lives outside crates/, adapters/, apps/, or xtask/",
                package.name
            ));
            continue;
        };
        let (workspace_dependencies, external_dependencies) = package
            .dependencies
            .iter()
            .filter(|dependency| dependency.kind == DependencyKind::Normal)
            .map(|dependency| dependency.name.as_str())
            .partition(|name| workspace_names.contains(name));
        if layer == Layer::Core {
            violations.extend(core_unsafe_violation(package)?);
        }
        crates.push(CrateFacts {
            name: package.name.as_str(),
            layer,
            workspace_dependencies,
            external_dependencies,
        });
    }
    violations.extend(layering_violations(&crates));

    if violations.is_empty() {
        println!("Architecture check passed.");
        return Ok(());
    }
    for violation in &violations {
        eprintln!("architecture: {violation}");
    }
    Err(io::Error::other(format!(
        "{} architecture violation(s) found",
        violations.len()
    ))
    .into())
}

fn core_unsafe_violation(package: &Package) -> TaskResult<Option<String>> {
    for target in &package.targets {
        if !target.is_lib() {
            continue;
        }
        let source = fs::read_to_string(&target.src_path)?;
        // Require the attribute as a line of its own, so a comment or a doc
        // example that mentions it does not count.
        if !source
            .lines()
            .any(|line| line.trim() == "#![forbid(unsafe_code)]")
        {
            return Ok(Some(format!(
                "{}: core crate root must declare #![forbid(unsafe_code)]",
                package.name
            )));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use cargo_metadata::camino::Utf8Path;

    use super::{
        CrateFacts, Layer, PreflightClass, layer_for, layering_violations, parse_preflight_class,
    };

    #[test]
    fn classifies_layers_from_workspace_relative_paths() {
        let layer = |path: &str| layer_for(Utf8Path::new(path));
        assert_eq!(layer("crates/domain/Cargo.toml"), Some(Layer::Core));
        assert_eq!(layer("adapters/vault/Cargo.toml"), Some(Layer::Adapter));
        assert_eq!(layer("apps/tersa/Cargo.toml"), Some(Layer::App));
        assert_eq!(layer("xtask/Cargo.toml"), Some(Layer::Tool));
        assert_eq!(layer("crates/a/b/Cargo.toml"), None);
        assert_eq!(layer("tools/x/Cargo.toml"), None);
        assert_eq!(layer("Cargo.toml"), None);
    }

    fn facts<'a>(
        name: &'a str,
        layer: Layer,
        workspace: &[&'a str],
        external: &[&'a str],
    ) -> CrateFacts<'a> {
        CrateFacts {
            name,
            layer,
            workspace_dependencies: workspace.iter().copied().collect::<BTreeSet<_>>(),
            external_dependencies: external.iter().copied().collect::<BTreeSet<_>>(),
        }
    }

    #[test]
    fn accepts_current_layering() {
        let crates = [
            facts("tersa-domain", Layer::Core, &[], &[]),
            facts(
                "tersa-application",
                Layer::Core,
                &["tersa-domain"],
                &["url"],
            ),
            facts(
                "tersa-store",
                Layer::Adapter,
                &["tersa-application"],
                &["rusqlite"],
            ),
            facts(
                "tersa",
                Layer::App,
                &["tersa-store", "tersa-domain"],
                &["ratatui"],
            ),
        ];
        assert!(layering_violations(&crates).is_empty());
    }

    #[test]
    fn rejects_core_io_and_upward_dependencies() {
        let crates = [
            facts("tersa-domain", Layer::Core, &["tersa-store"], &["tokio"]),
            facts("tersa-store", Layer::Adapter, &["tersa"], &[]),
            facts("tersa", Layer::App, &[], &[]),
            facts("tersa-new-core", Layer::Core, &[], &[]),
        ];
        let violations = layering_violations(&crates);
        assert!(
            violations
                .iter()
                .any(|v| v.contains("must not depend on adapters"))
        );
        assert!(
            violations
                .iter()
                .any(|v| v.contains("not allowed by CORE_POLICY"))
        );
        assert!(violations.iter().any(|v| v.contains("free of I/O")));
        assert!(violations.iter().any(|v| v.contains("leaves")));
        assert!(
            violations
                .iter()
                .any(|v| v.contains("missing from CORE_POLICY"))
        );
    }

    #[test]
    fn parses_preflight_aliases() {
        assert_eq!(
            parse_preflight_class("adapter-rust"),
            Some(PreflightClass::Adapter)
        );
        assert_eq!(parse_preflight_class("tui"), Some(PreflightClass::Tui));
        assert_eq!(
            parse_preflight_class("policy-xtask"),
            Some(PreflightClass::Policy)
        );
        assert_eq!(parse_preflight_class("swift-ui"), None);
    }

    #[test]
    fn rejects_unlisted_core_external_dependencies() {
        // Not on the denylist of obvious I/O crates, but still not allowed:
        // the allowlist catches what a denylist would miss.
        let crates = [facts(
            "tersa-application",
            Layer::Core,
            &["tersa-domain"],
            &["url", "ureq"],
        )];
        let violations = layering_violations(&crates);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("ureq"));
    }
}
