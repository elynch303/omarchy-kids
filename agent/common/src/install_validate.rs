//! Name/note validation shared between `agentd` (records an `InstallRequest`)
//! and `omarchy-kids-install-helper` (the root-run helper that actually
//! performs an allow-listed install — see `agentd/src/handlers.rs` and
//! `install-helper/src/main.rs`). The helper re-validates independently
//! rather than trusting whatever agentd already checked, since it runs as
//! root off a name that ultimately originated with the child; using the
//! exact same rules here (not a re-implementation of them) is what makes
//! that re-check meaningful.

const MAX_NAME_LEN: usize = 100;
const MAX_NOTE_CHARS: usize = 200;

/// Package/theme/plugin names: lowercase letters, digits and `@ . _ + -`,
/// never starting with `-` or `.`. Strict on purpose — the name is handed to
/// `pacman`/`omarchy-theme-install` as a plain argument (never through a
/// shell) and displayed to a parent, so anything else is refused up front.
pub fn validate_install_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("no name given".into());
    }
    if name.len() > MAX_NAME_LEN {
        return Err("that name is too long".into());
    }
    let first = name.chars().next().unwrap_or(' ');
    if first == '-' || first == '.' {
        return Err(format!("'{name}' is not a valid name"));
    }
    let ok = name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "@._+-".contains(c));
    if !ok {
        return Err(format!(
            "'{name}' is not a valid name (use lowercase letters, digits and @ . _ + - only)"
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_names_are_accepted() {
        for name in ["gimp", "minecraft-launcher", "lib32-glibc", "python-numpy", "g++", "gtk4", "a", "bubblegum"] {
            assert!(validate_install_name(name).is_ok(), "{name} should be valid");
        }
    }

    #[test]
    fn names_that_could_be_options_or_shell_tricks_are_refused() {
        for name in [
            "", "-S", "--sysupgrade", ".hidden", "UPPER", "with space", "a;b", "a&&b", "$(id)", "a`b`",
            "a/b", "../x", "naïve", "tab\there", "new\nline",
        ] {
            assert!(validate_install_name(name).is_err(), "{name:?} should be refused");
        }
        assert!(validate_install_name(&"a".repeat(101)).is_err());
    }

    #[test]
    fn notes_lose_control_characters_and_are_capped() {
        assert_eq!(sanitize_note("  for art class  ").as_deref(), Some("for art class"));
        assert_eq!(sanitize_note("a\u{1b}[31mred\u{7}\nb").as_deref(), Some("a[31mredb"));
        assert_eq!(sanitize_note("   \n\t ").as_deref(), None);
        assert_eq!(sanitize_note("x").as_deref(), Some("x"));
        assert_eq!(sanitize_note(&"y".repeat(500)).unwrap().chars().count(), 200);
    }
}
