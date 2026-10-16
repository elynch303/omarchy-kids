//! Parent-curated allow-list of what an `InstallRequest` may install right
//! away, with no pending/approve step (see `InstallRequest`'s doc comment
//! and `agentd`'s `handlers::handle_install_request`). Shared between
//! `agentd` (decides whether to auto-approve a fresh request) and the
//! root-run `omarchy-kids-install-helper` (re-checks the same list itself
//! before actually installing a package — see that crate's doc comment for
//! why it doesn't just trust agentd's decision) — one parser, so the two
//! can't drift apart on what counts as allow-listed.
//!
//! Same convention as `allowlist.rs`'s `unlockable-apps.toml`: an absent or
//! empty file means nothing is allow-listed (secure default), and this file
//! is meant to be authored by the parent (by hand today; a future Control
//! Center control is the intended path) — agentd only ever reads it, never
//! writes it in response to any `Request`. It lives in the child's own
//! `~/.config/omarchy-kids/`, so it inherits the same accepted residual risk
//! already documented for `unlockable-apps.toml` and `config.toml` in
//! `docs/security-threat-model.md`: a malicious *local, same-uid* process
//! could edit it directly. That's an existing, out-of-scope gap for this
//! whole trust boundary, not something new to this file.
//!
//! Packages are a plain name list, checked against pacman's synced
//! repositories at request time (see `installs::lookup_package`) — the name
//! alone is enough to resolve a trustworthy source.
//!
//! Themes and plugins are different: Omarchy's own `omarchy-theme-install`
//! takes an arbitrary git URL and clones it — there is no catalog or
//! signing, the same "runs whatever's in the repo" risk class as the AUR.
//! So a theme/plugin entry here maps a short name to one specific,
//! parent-chosen URL; the child can only ever ask by name, never supply a
//! URL themselves, and agentd only ever passes the *pinned* URL to
//! `omarchy-theme-install`/`git clone`, never anything the child typed.

use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Default, Deserialize)]
struct RawInstallable {
    #[serde(default)]
    packages: Vec<String>,
    #[serde(default)]
    themes: HashMap<String, String>,
    #[serde(default)]
    plugins: HashMap<String, String>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Installable {
    pub packages: Vec<String>,
    pub themes: HashMap<String, String>,
    pub plugins: HashMap<String, String>,
}

/// An absent file means an empty allow-list (secure default), not an error.
pub fn load(path: &Path) -> Installable {
    let raw = match std::fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(_) => return Installable::default(),
    };
    match toml::from_str::<RawInstallable>(&raw) {
        Ok(list) => Installable {
            packages: list.packages,
            themes: list.themes,
            plugins: list.plugins,
        },
        Err(e) => {
            eprintln!(
                "agentd: {} is malformed, treating as empty allow-list: {e:#}",
                path.display()
            );
            Installable::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn missing_file_is_an_empty_allowlist() {
        assert_eq!(load(Path::new("/nonexistent/installable.toml")), Installable::default());
    }

    #[test]
    fn parses_a_real_file() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            f,
            r#"
packages = ["gimp", "inkscape"]

[themes]
bubblegum = "https://github.com/example/omarchy-bubblegum-theme.git"

[plugins]
mini-launcher = "https://github.com/example/omarchy-kids-launcher.git"
"#
        )
        .unwrap();
        let list = load(f.path());
        assert_eq!(list.packages, vec!["gimp".to_string(), "inkscape".to_string()]);
        assert_eq!(
            list.themes.get("bubblegum").map(String::as_str),
            Some("https://github.com/example/omarchy-bubblegum-theme.git")
        );
        assert_eq!(list.plugins.len(), 1);
    }

    #[test]
    fn malformed_file_is_an_empty_allowlist_not_a_crash() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "not valid toml {{{{").unwrap();
        assert_eq!(load(f.path()), Installable::default());
    }
}
