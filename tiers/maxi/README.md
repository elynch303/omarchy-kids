# tier: maxi (11-13)

A regular Omarchy desktop with guardrails — **not** a kiosk.

What the child gets: the normal Quickshell bar, the normal Omarchy menu and key bindings, a browser, a terminal, and whatever apps the parent installs.

What keeps it safe is not the UI:

- **No admin rights.** The child account is not in `wheel` and has no sudo rule (the bootstrap removes the one Omarchy's installer creates). Installing or removing system packages, installing services, and changing system settings are refused. The Omarchy menu still *shows* its Install entries; they just fail. Per-user things that need no root (web apps, per-user tools) are not blocked by this tier.
- **Autonomous updates.** `systemd/` installs a daily `omarchy-update -y`, since the child cannot run updates themselves and Omarchy's update prompt is hidden.
- **First-run prompts hidden.** `hypr/autostart.lua` keeps the adult-facing first-login prompts (update, Wi-Fi, invitations) from appearing.

What this tier deliberately does **not** do (yet):

- **Screen-time limits.** The agent enforces time budgets only for apps launched through its wrapper (`omarchy-kids-run`). Apps started from the normal Omarchy menu bypass it, so no budget applies here. `omarchy-kids-agent`/the Control Center still report status.
- **Content filtering.** Not part of this tier (see the DNS-filter work).
- **Hide or trim the menu's Install entries.** Possible later through `~/.config/omarchy/extensions/menu.sh`.

Switching *to* this tier from `mini` undoes the kiosk (Hyprland config, launcher plugin, console masks) — see `omarchy-kids-set-tier`.
