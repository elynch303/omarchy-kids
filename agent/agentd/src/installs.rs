//! Install requests (see `Request::InstallRequest`): package-name validation,
//! cleaning the child's free-text note, and the two pacman lookups.
//!
//! Nothing here installs anything. agentd runs as the child, which has no
//! admin rights; a request is only a record for a parent to act on.

use std::process::Command;

/// Requests waiting for a decision at once — enough for a child to ask for a
/// few things, low enough that they can't bury a parent in requests.
pub const MAX_PENDING_REQUESTS: u32 = 10;

const MAX_PACKAGE_NAME_LEN: usize = 100;
const MAX_NOTE_CHARS: usize = 200;

/// Arch package names use lowercase letters, digits and `@ . _ + -`, and
/// don't start with `-` or `.`. Enforced strictly because the name is handed
/// to pacman (as a plain argument, never through a shell) and displayed to a
/// parent; anything else is refused up front.
pub fn validate_package_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("no package name given".into());
    }
    if name.len() > MAX_PACKAGE_NAME_LEN {
        return Err("that package name is too long".into());
    }
    let first = name.chars().next().unwrap_or(' ');
    if first == '-' || first == '.' {
        return Err(format!("'{name}' is not a valid package name"));
    }
    let ok = name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "@._+-".contains(c));
    if !ok {
        return Err(format!(
            "'{name}' is not a valid package name (use lowercase letters, digits and @ . _ + - only)"
        ));
    }
    Ok(())
}

/// The child's free-text note: control characters dropped (a terminal or
/// notification must not be able to interpret them), length capped, and
/// `None` if nothing is left.
pub fn sanitize_note(note: &str) -> Option<String> {
    let cleaned: String = note
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_NOTE_CHARS)
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

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

    #[test]
    fn ordinary_arch_package_names_are_accepted() {
        for name in ["gimp", "minecraft-launcher", "lib32-glibc", "python-numpy", "g++", "gtk4", "a"] {
            assert!(validate_package_name(name).is_ok(), "{name} should be valid");
        }
    }

    #[test]
    fn names_that_could_be_options_or_shell_tricks_are_refused() {
        for name in [
            "", "-S", "--sysupgrade", ".hidden", "UPPER", "with space", "a;b", "a&&b", "$(id)", "a`b`",
            "a/b", "../x", "naïve", "tab\there", "new\nline",
        ] {
            assert!(validate_package_name(name).is_err(), "{name:?} should be refused");
        }
        assert!(validate_package_name(&"a".repeat(101)).is_err());
    }

    #[test]
    fn notes_lose_control_characters_and_are_capped() {
        assert_eq!(sanitize_note("  for art class  ").as_deref(), Some("for art class"));
        assert_eq!(sanitize_note("a\u{1b}[31mred\u{7}\nb").as_deref(), Some("a[31mredb"));
        assert_eq!(sanitize_note("   \n\t ").as_deref(), None);
        assert_eq!(sanitize_note("x").as_deref(), Some("x"));
        assert_eq!(sanitize_note(&"y".repeat(500)).unwrap().chars().count(), 200);
    }

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
