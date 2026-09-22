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
