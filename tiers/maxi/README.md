# tier: maxi (11-13)

A regular Omarchy desktop with guardrails — **not** a kiosk.

What the child gets: the normal Quickshell bar, the normal Omarchy menu and key bindings, a browser, a terminal, and whatever apps the parent installs.

What keeps it safe is not the UI:

- **No admin rights.** The child account is not in `wheel` and has no sudo rule (the bootstrap removes the one Omarchy's installer creates). Installing or removing system packages, installing services, and changing system settings are refused. The Omarchy menu's `Package`/`AUR`/`Theme`/`TUI` Install entries are redirected to the request-approval flow below (see "Installs" below) — everything else under Install (the ~80 named one-click app/service/dev-env shortcuts, e.g. Steam, VSCode, Spotify) and all of Remove still just dead-end at a sudo prompt they can't answer, same as before this tier's install-request feature existed. Per-user things that need no root (web apps, per-user tools) are not blocked by this tier.
- **Autonomous updates.** `systemd/` installs a daily `omarchy-update -y`, since the child cannot run updates themselves and Omarchy's update prompt is hidden.
- **First-run prompts hidden.** `hypr/autostart.lua` keeps the adult-facing first-login prompts (update, Wi-Fi, invitations) from appearing.

What this tier deliberately does **not** do (yet):

- **Screen-time limits.** The agent enforces time budgets only for apps launched through its wrapper (`omarchy-kids-run`). Apps started from the normal Omarchy menu bypass it, so no budget applies here. `omarchy-kids-agent`/the Control Center still report status.
- **Content filtering.** Not part of this tier (see the DNS-filter work).

Installs are not simply refused, though: `omarchy-kids-request-install` (also reachable directly as a terminal command) lets the child ask a parent to approve installing an official/Omarchy-repo package, an Omarchy theme, or a plugin — see the agent's generalized `InstallRequest`/`DecideInstallRequest` messages (`kind`: package/theme/plugin) and the Control Center's "Install requests" panel. AUR packages, and any theme/plugin source URL the child supplies themselves, can never be requested — see `docs/security-threat-model.md`'s boundary 5.

A parent can also pre-approve specific packages/themes/plugins via `~/.config/omarchy-kids/installable.toml` (today: hand-edited; a Control Center control is the intended path, not yet built) — a request that matches installs immediately with no pending step and no password prompt of any kind, the "training wheels come off for this one thing" path. Themes/plugins are keyed by name to one specific, parent-pinned source URL, never a URL the child provides (see boundary 5's reasoning: Omarchy's own theme installer clones an arbitrary URL with no catalog, the same risk class as the AUR).

**How the native menu is reached, without editing it.** An earlier approach (an `~/.config/omarchy/extensions/menu.sh` override replacing the Install entry) never worked on Omarchy 4.0.4 — that version's menu is Quickshell/QML, driven by JSONC config (`/usr/share/omarchy/default/omarchy/omarchy-menu.jsonc`), not a bash case-statement, and the override was inert. The actual fix doesn't touch that JSONC at all: `tiers/maxi/hypr/autostart.lua` prepends `menu-wrappers/` onto `PATH` via Hyprland's own `hl.env` (the same mechanism Omarchy's own `default/hypr/envs.lua` uses to set `PATH` in the first place — confirmed empirically that neither `~/.bashrc` nor `~/.config/environment.d` reaches the process tree Quickshell spawns menu actions in, only this does). The menu still runs the same command names it always has (`omarchy-pkg-install`, `omarchy-pkg-aur-install`, `omarchy-theme-install`, `omarchy-tui-install`); this account's `PATH` just resolves them to `menu-wrappers/`'s scripts first, which redirect into `omarchy-kids-request-install` (AUR: a flat refusal, no request possible — see boundary 5). Update-safe, since nothing Omarchy ships is ever modified.

Not yet wrapped: the ~80 named one-click installers under Install (Steam, VSCode, Spotify, ...) and Remove — each is its own distinct command name, and wrapping all of them individually doesn't scale; they still just dead-end at a sudo prompt today, same as before this feature existed, not a new gap. Also open: a bar-button/launcher-style entry point for reaching `omarchy-kids-request-install` without going through the native menu at all.

`themes/`: `standard` (default, calm dark blue) plus five ages-11-12/9-12 themes (`bubblegum`, `kinetic-zine`, `night-transit`, `pocket-arcade`, `signal-garden`) pulled from upstream Omarchy PR [#12488](https://github.com/omacom/omarchy/pull/12488) ("Add Omarchy Kids theme collection", OldJobobo, draft) — see each theme's own `ATTRIBUTION.md`/`LICENSE` (MIT).

Switching *to* this tier from `mini` undoes the kiosk (Hyprland config, launcher plugin, console masks) — see `omarchy-kids-set-tier`.
