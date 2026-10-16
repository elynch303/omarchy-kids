//! `omarchy-kids-install-helper` — the actual target of `pkexec` for an
//! allow-listed package install (see `agentd/src/handlers.rs`'s
//! `spawn_install_package`). Reached via the
//! `net.omarchykids.agent.install-package` polkit action
//! (`packaging/polkit/`), which is deliberately `allow_active: yes` — no
//! password prompt at all, unlike the PIN/override path's `auth_admin` —
//! because the actual gate here isn't a live human, it's the parent-curated
//! allow-list file this binary re-reads and re-checks itself, as root,
//! before doing anything. agentd already checked the same things once, but
//! this process is the one about to gain root, so it trusts nothing agentd
//! claimed and starts over: re-validate the name, re-load the allow-list,
//! re-confirm the package is real and non-AUR, *then* install it.
//!
//! `pkexec` runs this with no `--user` (unlike `override-helper`) — it
//! genuinely needs to run as root to call `pacman -S`. It sanitizes the
//! environment first, so `HOME` doesn't survive; the caller passes it
//! explicitly (same convention as `override-helper`), since that's where the
//! child's `installable.toml` lives.

use clap::Parser;
use omarchy_kids_common::install_validate::validate_install_name;
use omarchy_kids_common::{installable, paths};
use std::process::{Command, ExitCode};

#[derive(Parser)]
struct Cli {
    /// The package name to install — always a bare name, never a path or
    /// shell fragment (enforced by `validate_install_name`, same rules
    /// `agentd` already applied once).
    name: String,
    #[arg(long)]
    home: String,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    std::env::set_var("HOME", &cli.home);

    if let Err(e) = validate_install_name(&cli.name) {
        eprintln!("omarchy-kids-install-helper: {e}");
        return ExitCode::FAILURE;
    }

    let allowlist = installable::load(&paths::installable_path());
    if !allowlist.packages.iter().any(|p| p == &cli.name) {
        eprintln!(
            "omarchy-kids-install-helper: '{}' is not on the parent's allow-list \
             ({}) — refusing",
            cli.name,
            paths::installable_path().display()
        );
        return ExitCode::FAILURE;
    }

    // Re-confirm it's a real, synced, non-AUR package — never trust that
    // agentd's own earlier lookup is still accurate or was even genuine.
    let si = Command::new("pacman")
        .env("LC_ALL", "C")
        .args(["-Si", "--", &cli.name])
        .status();
    match si {
        Ok(status) if status.success() => {}
        Ok(status) => {
            eprintln!(
                "omarchy-kids-install-helper: '{}' is not in the synced repositories (pacman -Si: {status})",
                cli.name
            );
            return ExitCode::FAILURE;
        }
        Err(e) => {
            eprintln!("omarchy-kids-install-helper: could not run pacman -Si: {e}");
            return ExitCode::FAILURE;
        }
    }

    let install = Command::new("pacman")
        .args(["-S", "--noconfirm", "--needed", "--", &cli.name])
        .status();
    match install {
        Ok(status) if status.success() => {
            println!("Installed '{}'.", cli.name);
            ExitCode::SUCCESS
        }
        Ok(status) => {
            eprintln!("omarchy-kids-install-helper: pacman -S failed ({status})");
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("omarchy-kids-install-helper: could not run pacman -S: {e}");
            ExitCode::FAILURE
        }
    }
}
