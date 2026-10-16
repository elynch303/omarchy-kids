-- Omarchy Kids: Tier maxi (11-13, normal desktop) first-run replacement.
-- Installed by omarchy-kids-set-tier as a full replacement for
-- ~/.config/hypr/autostart.lua — edit tiers/maxi/hypr/autostart.lua in the
-- omarchy-kids repo, not this file directly. The original is backed up as
-- autostart.lua.pre-omarchy-kids.
--
-- Same reasoning as the mini tier's version (issue #30): Omarchy's own
-- first-login sequence is almost entirely prompts aimed at an administrator
-- ("Update System", "Setup Wi-Fi", post-update invitations, ...), and this
-- account has no admin rights, so every one of them would only lead to a
-- refused action. omarchy-kids-set-tier marks Omarchy's own "first-run-user"
-- done-marker so its handler exits immediately, and this handler replicates
-- just the four silent, non-prompt setup steps, gated by our own once-only
-- done-marker.

-- Redirect the native Omarchy menu's Install/Remove entries (SUPER+SPACE)
-- through the request-approval flow, without editing Omarchy's own
-- omarchy-menu.jsonc at all — see docs/security-threat-model.md's boundary
-- on allow-listed installs, and the `menu-wrappers/` scripts this installs
-- (packaging: `tiers/packaging/PKGBUILD`).
--
-- Every menu action Quickshell runs (whether a direct exec like
-- omarchy-theme-bg-install, or one spawned inside a floating terminal via
-- xdg-terminal-exec/omarchy-launch-floating-terminal-with-presentation)
-- resolves the command by name against whatever PATH the *Hyprland process
-- itself* was started with — not a later shell's `.bashrc`, not
-- `~/.config/environment.d` (confirmed empirically on a real device: neither
-- reaches it). Omarchy's own default/hypr/envs.lua sets that PATH via
-- `hl.env`, Hyprland's own env mechanism, evaluated once per config
-- load/reload; this file loads after it (see ~/.config/hypr/hyprland.lua's
-- require order), so extending it the same way here reaches every one of
-- those invocation paths reliably, real terminal or not.
--
-- Must go *before* $OMARCHY_PATH/bin, not just anywhere ahead of /usr/bin:
-- the real omarchy-pkg-install etc. live at
-- /usr/share/omarchy/bin/omarchy-pkg-install, and envs.lua puts that
-- directory on PATH directly (not only via the /usr/bin symlink). envs.lua
-- keeps itself first the same way, on every reload — a plain "prepend if not
-- already present anywhere" (this file's first attempt, confirmed broken on
-- a real device 2026-09-23) loses that race the moment envs.lua re-runs
-- after this file already ran once: it finds our entry already present
-- further back and skips re-fixing its position. So this always strips any
-- existing occurrence and reinserts at position 0, every reload, the same
-- technique envs.lua uses for itself — never a one-time "if missing" check.
local wrapper_dir = "/usr/lib/omarchy-kids/menu-wrappers"
local kept = {}
for entry in (os.getenv("PATH") or "/usr/local/bin:/usr/bin"):gmatch("[^:]+") do
  if entry ~= wrapper_dir then table.insert(kept, entry) end
end
table.insert(kept, 1, wrapper_dir)
hl.env("PATH", table.concat(kept, ":"))

hl.on("hyprland.start", function()
  hl.exec_cmd(
    "omarchy_path=${OMARCHY_PATH:-/usr/share/omarchy}; " ..
    "omarchy-done ensure omarchy-kids-maxi-first-run && { " ..
    "bash \"$omarchy_path/install/user/first-run/enable-user-units.sh\"; " ..
    "bash \"$omarchy_path/install/user/first-run/gnome-theme.sh\"; " ..
    "bash \"$omarchy_path/install/user/first-run/gtk-primary-paste.sh\"; " ..
    "bash \"$omarchy_path/install/user/first-run/audio-tuning.sh\"; }"
  )
end)
