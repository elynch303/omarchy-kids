//! Install requests (see `Request::InstallRequest`): the two pacman lookups
//! for the `Package` kind. Name/note validation lives in
//! `omarchy_kids_common::install_validate`, shared with the root-run
//! `install-helper` (see `handlers::handle_install_request`).
//!
//! Nothing here installs anything by itself for a *pending* request — that
//! still waits on a parent. An allow-listed request is different: see
//! `handlers::handle_install_request` and `installable.rs`.

use std::process::Command;

/// Requests waiting for a decision at once — enough for a child to ask for a
/// few things, low enough that they can't bury a parent in requests.
pub const MAX_PENDING_REQUESTS: u32 = 10;

/// What `pacman -Si` says about one package.
#[derive(Debug, PartialEq, Eq)]
pub struct RepoPackage {
    pub repo: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub download_size: String,
}

/// Parses the first block of `pacman -Si` output (run with `LC_ALL=C`, so the
/// field names are English). Returns `None` if the essentials are missing.
pub fn parse_pacman_si(output: &str) -> Option<RepoPackage> {
    let mut repo = None;
    let mut name = None;
    let mut version = None;
    let mut description = None;
    let mut download_size = None;

    for line in output.lines() {
        if line.trim().is_empty() {
            if repo.is_some() {
                break; // a blank line ends the first package's block
            }
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim().to_string();
        match key.trim() {
            "Repository" => repo = Some(value),
            "Name" => name = Some(value),
            "Version" => version = Some(value),
            "Description" => description = Some(value),
            "Download Size" => download_size = Some(value),
            _ => {}
        }
    }

    Some(RepoPackage {
        repo: repo?,
        name: name?,
        version: version?,
        description: description.unwrap_or_default(),
        download_size: download_size.unwrap_or_default(),
    })
}

/// Looks the package up in the synced pacman repositories. `Err` carries a
/// message that is safe to show the child.
///
/// AUR packages are not in those repositories, so they can never be found
/// here — that is the point: an AUR package runs an unreviewed build script.
pub fn lookup_package(name: &str) -> Result<RepoPackage, String> {
    let output = Command::new("pacman")
        .env("LC_ALL", "C")
        .args(["-Si", "--", name])
        .output()
        .map_err(|e| format!("could not run pacman: {e}"))?;

    if output.status.success() {
        if let Some(pkg) = parse_pacman_si(&String::from_utf8_lossy(&output.stdout)) {
            return Ok(pkg);
        }
    }
    Err(format!(
        "'{name}' was not found in the official or Omarchy repositories \
         (packages from the AUR can't be requested)"
    ))
}

/// Whether the package is already installed (`pacman -Q`).
pub fn is_installed(name: &str) -> bool {
    Command::new("pacman")
        .env("LC_ALL", "C")
        .args(["-Q", "--", name])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SI_SAMPLE: &str = "\
Repository      : extra
Name            : gimp
Version         : 3.0.4-1
Description     : GNU Image Manipulation Program: a raster editor
Architecture    : x86_64
Download Size   : 34.20 MiB
Installed Size  : 120.00 MiB

Repository      : community
Name            : gimp
Version         : 9.9-1
Description     : A second block that must be ignored
Download Size   : 1.00 MiB
";

    #[test]
    fn pacman_si_output_is_parsed_from_its_first_block_only() {
        let pkg = parse_pacman_si(SI_SAMPLE).unwrap();
        assert_eq!(pkg.repo, "extra");
        assert_eq!(pkg.name, "gimp");
        assert_eq!(pkg.version, "3.0.4-1");
        // A colon inside the value must not truncate it.
        assert_eq!(pkg.description, "GNU Image Manipulation Program: a raster editor");
        assert_eq!(pkg.download_size, "34.20 MiB");
    }

    #[test]
    fn output_without_the_essentials_is_not_a_package() {
        assert_eq!(parse_pacman_si(""), None);
        assert_eq!(parse_pacman_si("error: package 'x' was not found\n"), None);
        assert_eq!(parse_pacman_si("Description : no repo or name\n"), None);
    }
}
