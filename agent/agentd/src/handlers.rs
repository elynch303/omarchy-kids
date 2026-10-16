use crate::{allowlist, budget, db, installs, launcher, security};
use crate::state::{ActiveSession, State};
use chrono::{Datelike, Duration as ChronoDuration, Local, Utc};
use omarchy_kids_common::config::UnlockedApp;
use omarchy_kids_common::desktop;
use omarchy_kids_common::install_validate::{sanitize_note, validate_install_name};
use omarchy_kids_common::installable;
use omarchy_kids_common::paths;
use omarchy_kids_common::protocol::{
    AllowedPayload, AppUsage, DEFAULT_UNLOCK_MINUTES, InstallKind, InstallRequestInfo,
    InstallRequestsPayload, Request, Response, ReportPayload, SecurityEventSummary, StatusPayload,
};
use std::process::Command;
use std::sync::{Arc, Mutex};

/// Path baked into the polkit action's `org.freedesktop.policykit.exec.path`
/// annotation (`packaging/polkit/net.omarchykids.agent.policy`) — the only
/// thing that action is allowed to run.
const INSTALL_HELPER_PATH: &str = "/usr/lib/omarchy-kids/omarchy-kids-install-helper";

/// Failed override attempts for the same app within a 5-minute window before
/// the event escalates from "routine" to "severe" (issue #10's open
/// threshold question — 3 chosen to match a typical "wrong PIN" lockout
/// convention without being so low that a genuine typo trips it).
const SEVERE_OVERRIDE_FAILURE_THRESHOLD: u32 = 3;
const OVERRIDE_FAILURE_WINDOW_MINUTES: i64 = 5;

/// Tiers agentd will accept for `SetTier` (issue #32). `SetTier`'s only real
/// caller (`omarchy-kids-set-tier`, invoked via `sudo -u <child>` — see
/// `setup-wizard/bootstrap/lib/branding-tier.sh`) runs at the child's own
/// uid, same as any other local process, so the socket can't distinguish a
/// legitimate tier switch from a malicious one by caller identity alone.
/// This enumeration plus the per-tile validation below is the accepted
/// mitigation: content is validated, the caller isn't. Matches CLAUDE.md's
/// "Current focus" — extend this when a second tier actually ships.
const KNOWN_TIERS: &[&str] = &["mini", "maxi"];

pub fn dispatch(state: &Arc<Mutex<State>>, req: Request) -> Response {
    match req {
        Request::Ping => Response::ok_empty(),
        Request::Status => handle_status(state),
        Request::SetTier { tier, apps } => handle_set_tier(state, tier, apps),
        Request::Unlock { app, minutes } => handle_unlock(state, app, minutes, false),
        Request::Override { app, minutes } => handle_unlock(state, app, minutes, true),
        Request::OverrideFailed { app } => handle_override_failed(state, app),
        Request::Report { week } => handle_report(state, week),
        Request::WrapperAuthorize { app } => handle_wrapper_authorize(state, app),
        Request::WrapperStart { app, pid } => handle_wrapper_start(state, app, pid),
        Request::WrapperStop {
            app,
            pid,
            exit_code: _,
        } => handle_wrapper_stop(state, app, pid),
        Request::WrapperPoll { app, pid } => handle_wrapper_poll(state, app, pid),
        Request::PushContent { .. } => {
            Response::err("push-content is reserved but not implemented yet (see issue #13)")
        }
        Request::InstallRequest { kind, name, note } => {
            handle_install_request(state, kind, name, note)
        }
        Request::ListInstallRequests { status } => handle_list_install_requests(state, status),
        Request::DecideInstallRequest { id, decision } => {
            handle_decide_install_request(state, id, decision)
        }
    }
}

fn install_request_info(row: db::InstallRequestRow) -> InstallRequestInfo {
    InstallRequestInfo {
        id: row.id,
        kind: row.kind.parse().unwrap_or(InstallKind::Package),
        name: row.name,
        repo: row.repo,
        version: row.version,
        description: row.description,
        download_size: row.download_size,
        note: row.note,
        status: row.status,
        auto_approved: row.auto_approved,
        requested_at: row.requested_at,
        decided_at: row.decided_at,
    }
}

/// Records a child's request to install a package, theme, or plugin — and,
/// if `name` is already on the parent's allow-list
/// (`paths::installable_path()`), installs it immediately instead of queuing
/// it for a parent's decision. See `InstallRequest`'s doc comment for the
/// full split between the three kinds and why themes/plugins (unlike
/// packages) are refused outright, not queued, when not allow-listed: there
/// is no safe, unprivileged way to look up what an arbitrary theme/plugin
/// name *is* without a parent-vetted source URL already in hand.
fn handle_install_request(
    state: &Arc<Mutex<State>>,
    kind: InstallKind,
    name: String,
    note: Option<String>,
) -> Response {
    let name = name.trim().to_string();
    if let Err(e) = validate_install_name(&name) {
        return Response::err(e);
    }
    let note = note.as_deref().and_then(sanitize_note);
    let installable = installable::load(&paths::installable_path());

    let (repo, version, description, download_size, auto_approved, source_url) = match kind {
        InstallKind::Package => {
            let found = match installs::lookup_package(&name) {
                Ok(found) => found,
                Err(e) => return Response::err(e),
            };
            if installs::is_installed(&name) {
                return Response::err(format!("'{name}' is already installed"));
            }
            let auto = installable.packages.iter().any(|p| p == &name);
            (found.repo, found.version, found.description, found.download_size, auto, None)
        }
        InstallKind::Theme | InstallKind::Plugin => {
            let map = if kind == InstallKind::Theme { &installable.themes } else { &installable.plugins };
            let Some(url) = map.get(&name) else {
                return Response::err(format!(
                    "'{name}' isn't on the allow-list yet — ask a parent to add it \
                     (with its source) before you can install a {kind}"
                ));
            };
            if target_dir_exists(kind, &name) {
                return Response::err(format!("'{name}' is already installed"));
            }
            (String::new(), String::new(), format!("from {url}"), String::new(), true, Some(url.clone()))
        }
    };

    let state = state.lock().unwrap();
    match db::pending_install_request_id(&state.db, &kind.to_string(), &name) {
        Ok(Some(id)) => {
            return Response::err(format!(
                "'{name}' is already waiting for approval (request #{id})"
            ))
        }
        Ok(None) => {}
        Err(e) => return Response::err(format!("failed to check existing requests: {e:#}")),
    }
    if !auto_approved {
        match db::pending_install_request_count(&state.db) {
            Ok(n) if n >= installs::MAX_PENDING_REQUESTS => {
                return Response::err(format!(
                    "there are already {n} requests waiting; ask a parent to look at them first"
                ))
            }
            Ok(_) => {}
            Err(e) => return Response::err(format!("failed to count requests: {e:#}")),
        }
    }

    let new = db::NewInstallRequest {
        kind: &kind.to_string(),
        name: &name,
        repo: &repo,
        version: &version,
        description: &description,
        download_size: &download_size,
        note: note.as_deref(),
        auto_approved,
    };
    let id = match db::insert_install_request(&state.db, &new, Utc::now()) {
        Ok(id) => id,
        Err(e) => return Response::err(format!("failed to record the request: {e:#}")),
    };

    if auto_approved {
        match kind {
            InstallKind::Package => spawn_install_package(&name),
            InstallKind::Theme => spawn_install_theme(&name, &source_url.unwrap()),
            InstallKind::Plugin => spawn_install_plugin(&name, &source_url.unwrap()),
        }
    }

    match db::install_request_by_id(&state.db, id) {
        Ok(Some(row)) => Response::ok_with(install_request_info(row)),
        Ok(None) => Response::err("the request was recorded but could not be read back"),
        Err(e) => Response::err(format!("failed to read the request back: {e:#}")),
    }
}

fn target_dir_exists(kind: InstallKind, name: &str) -> bool {
    theme_or_plugin_dir(kind, name).map(|p| p.exists()).unwrap_or(false)
}

fn theme_or_plugin_dir(kind: InstallKind, name: &str) -> Option<std::path::PathBuf> {
    let home = std::env::var_os("HOME")?;
    let sub = match kind {
        InstallKind::Theme => "themes",
        InstallKind::Plugin => "plugins",
        InstallKind::Package => return None,
    };
    Some(std::path::PathBuf::from(home).join(".config/omarchy").join(sub).join(name))
}

/// Kicks off the actual, privileged install for an allow-listed package and
/// returns immediately — `pacman -S` can take a while, and nothing here
/// should block the socket-handling thread or the child's CLI (which has its
/// own short timeout). `net.omarchykids.agent.install-package`
/// (`packaging/polkit/`) is a zero-prompt polkit action (`allow_active:
/// yes`): the helper it runs re-validates the name and the allow-list itself
/// before touching pacman, since it's the one actually gaining root, not
/// this process. Progress is picked up the same way an existing manual
/// install already was: `handle_list_install_requests`'s `pacman -Q`
/// catch-up below.
fn spawn_install_package(name: &str) {
    let name = name.to_string();
    // `pkexec` (no `--user`) sanitizes the environment before running the
    // helper as root, so `HOME` doesn't survive — pass it explicitly, same
    // convention as `run_override` in `agent/src/main.rs`.
    let home = std::env::var("HOME").unwrap_or_default();
    std::thread::spawn(move || {
        let result = Command::new("pkexec")
            .arg(INSTALL_HELPER_PATH)
            .arg("--home")
            .arg(&home)
            .arg("--")
            .arg(&name)
            .status();
        if let Err(e) = result {
            eprintln!("omarchy-kids-agentd: failed to launch install-helper for '{name}': {e}");
        }
    });
}

/// Clones an allow-listed theme's *pinned* URL (never anything the child
/// supplied) straight into a directory named for the allow-list key, then
/// applies it — no root needed, themes live under the child's own
/// `~/.config/omarchy/`. Deliberately does not shell out to
/// `omarchy-theme-install` itself: that script derives the theme's directory
/// name from the URL, which for the allow-list's own naming (parent picks
/// the name, not the URL) could disagree with the name the child asked for.
fn spawn_install_theme(name: &str, url: &str) {
    let Some(target) = theme_or_plugin_dir(InstallKind::Theme, name) else { return };
    let name = name.to_string();
    let url = url.to_string();
    std::thread::spawn(move || {
        if !git_clone_checked(InstallKind::Theme, &name, &url, &target) {
            return;
        }
        if let Err(e) = Command::new("omarchy-theme-set").arg(&name).status() {
            eprintln!("omarchy-kids-agentd: 'omarchy-theme-set {name}' failed: {e}");
        }
    });
}

/// Same idea as `spawn_install_theme`, for plugins — clones into
/// `~/.config/omarchy/plugins/<name>`, then registers it the same way
/// `omarchy-kids-set-tier` registers its own launcher plugin: into
/// `shell.json`'s top-level `plugins[]` array (dropping the directory alone
/// does nothing — Omarchy plugins are opt-in, see that script's own comment)
/// and a Quickshell restart, the same reload-reliability step it also takes.
/// Refuses to register anything without a `manifest.json` — not a real
/// Omarchy Quickshell plugin, whatever else the repo might contain.
fn spawn_install_plugin(name: &str, url: &str) {
    let Some(target) = theme_or_plugin_dir(InstallKind::Plugin, name) else { return };
    let name = name.to_string();
    let url = url.to_string();
    std::thread::spawn(move || {
        if !git_clone_checked(InstallKind::Plugin, &name, &url, &target) {
            return;
        }
        if !target.join("manifest.json").is_file() {
            eprintln!(
                "omarchy-kids-agentd: '{name}' has no manifest.json, not a valid Omarchy plugin — removing"
            );
            let _ = std::fs::remove_dir_all(&target);
            return;
        }
        if let Err(e) = register_plugin_in_shell_json(&name) {
            eprintln!("omarchy-kids-agentd: failed to register plugin '{name}' in shell.json: {e}");
            return;
        }
        let _ = Command::new("pkill").args(["-f", "quickshell -n -p"]).status();
    });
}

/// `omarchy-git-url-check` is Omarchy's own guard against a URL that's
/// actually a git option/transport-helper invocation (the same check
/// `omarchy-theme-install` itself runs); reused here rather than
/// reimplemented. Returns whether the clone landed in `target`.
fn git_clone_checked(kind: InstallKind, name: &str, url: &str, target: &std::path::Path) -> bool {
    match Command::new("omarchy-git-url-check").arg(url).status() {
        Ok(status) if status.success() => {}
        Ok(status) => {
            eprintln!("omarchy-kids-agentd: refusing {kind} '{name}': url check failed ({status})");
            return false;
        }
        Err(e) => {
            eprintln!("omarchy-kids-agentd: could not run omarchy-git-url-check: {e}");
            return false;
        }
    }
    match Command::new("git").args(["clone", "--"]).arg(url).arg(target).status() {
        Ok(status) if status.success() => true,
        Ok(status) => {
            eprintln!("omarchy-kids-agentd: failed to clone {kind} '{name}' ({status})");
            false
        }
        Err(e) => {
            eprintln!("omarchy-kids-agentd: failed to clone {kind} '{name}': {e}");
            false
        }
    }
}

/// Adds `{"id": name}` to `~/.config/omarchy/shell.json`'s top-level
/// `plugins[]` array (creating the file if absent), the exact jq expression
/// `omarchy-kids-set-tier` already uses for the same purpose — kept as its
/// own small, dependency-free implementation here rather than shelling out
/// to `jq` from a systemd service on a config file a parent might be mid-edit
/// of elsewhere.
fn register_plugin_in_shell_json(id: &str) -> Result<(), String> {
    let home = std::env::var("HOME").map_err(|_| "HOME is not set".to_string())?;
    let path = std::path::PathBuf::from(home).join(".config/omarchy/shell.json");
    let mut doc: serde_json::Value = match std::fs::read_to_string(&path) {
        Ok(raw) => serde_json::from_str(&raw).map_err(|e| e.to_string())?,
        Err(_) => serde_json::json!({}),
    };
    let obj = doc.as_object_mut().ok_or("shell.json's top level is not an object")?;
    let plugins = obj.entry("plugins").or_insert_with(|| serde_json::json!([]));
    let arr = plugins.as_array_mut().ok_or("shell.json's 'plugins' is not an array")?;
    let already = arr.iter().any(|p| p.get("id").and_then(|v| v.as_str()) == Some(id));
    if !already {
        arr.push(serde_json::json!({ "id": id }));
    }
    let text = serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())?;
    std::fs::write(&path, text).map_err(|e| e.to_string())
}

fn handle_list_install_requests(state: &Arc<Mutex<State>>, status: Option<String>) -> Response {
    if let Some(s) = &status {
        if !db::INSTALL_STATUSES.contains(&s.as_str()) {
            return Response::err(format!(
                "unknown status '{s}' (use one of: {})",
                db::INSTALL_STATUSES.join(", ")
            ));
        }
    }

    // An approved request whose target has since actually shown up (package
    // in pacman's local database; theme/plugin directory on disk) has been
    // installed: record that, so the parent's list and the child's answer
    // catch up without `spawn_install_*` (fire-and-forget, since none of
    // them should block this socket) reporting back itself. These lookups
    // run outside the lock.
    let approved = {
        let state = state.lock().unwrap();
        db::list_install_requests(&state.db, Some("approved"), 50).unwrap_or_default()
    };
    for row in approved {
        let kind: InstallKind = row.kind.parse().unwrap_or(InstallKind::Package);
        let done = match kind {
            InstallKind::Package => installs::is_installed(&row.name),
            InstallKind::Theme | InstallKind::Plugin => target_dir_exists(kind, &row.name),
        };
        if done {
            let state = state.lock().unwrap();
            let _ = db::mark_install_request_installed(&state.db, row.id, Utc::now());
        }
    }

    let state = state.lock().unwrap();
    match db::list_install_requests(&state.db, status.as_deref(), 50) {
        Ok(rows) => Response::ok_with(InstallRequestsPayload {
            requests: rows.into_iter().map(install_request_info).collect(),
        }),
        Err(e) => Response::err(format!("failed to read install requests: {e:#}")),
    }
}

fn handle_decide_install_request(
    state: &Arc<Mutex<State>>,
    id: i64,
    decision: String,
) -> Response {
    let new_status = match decision.as_str() {
        "approve" => "approved",
        "deny" => "denied",
        _ => return Response::err("decision must be 'approve' or 'deny'"),
    };
    let state = state.lock().unwrap();
    match db::decide_pending_install_request(&state.db, id, new_status, Utc::now()) {
        Ok(true) => Response::ok_empty(),
        Ok(false) => Response::err(format!("there is no pending install request #{id}")),
        Err(e) => Response::err(format!("failed to record the decision: {e:#}")),
    }
}

fn handle_status(state: &Arc<Mutex<State>>) -> Response {
    let state = state.lock().unwrap();
    let now_local = Local::now();
    let now_utc = Utc::now();
    let midnight = budget::local_midnight_utc(now_local);

    let used = budget::compute_daily_used_minutes(&state.db, &state.active, midnight, now_utc)
        .unwrap_or(0);
    let budget_minutes = state
        .config
        .daily_total_minutes_today(now_local.weekday())
        .unwrap_or(0);
    let remaining = budget_minutes.saturating_sub(used);
    let active_app = state.active.values().next().map(|s| s.app.clone());
    let unlocked_apps = state
        .config
        .effective_launcher_tiles()
        .into_iter()
        .map(|t| t.desktop_id)
        .collect();

    Response::ok_with(StatusPayload {
        tier: state.config.tier.current.clone(),
        unlocked_apps,
        daily_budget_minutes: budget_minutes,
        daily_used_minutes: used,
        daily_remaining_minutes: remaining,
        in_blocked_window: budget::in_blocked_window(&state.config, now_local),
        active_app,
    })
}

fn handle_set_tier(
    state: &Arc<Mutex<State>>,
    tier: String,
    apps: Option<Vec<omarchy_kids_common::config::AppTile>>,
) -> Response {
    if !KNOWN_TIERS.contains(&tier.as_str()) {
        return Response::err(format!("unknown tier '{tier}'"));
    }
    if let Some(apps) = &apps {
        for tile in apps {
            if desktop::find_desktop_file(&tile.desktop_id).is_none() {
                return Response::err(format!(
                    "refusing to set tier: '{}' does not resolve to an installed application",
                    tile.desktop_id
                ));
            }
        }
    }

    let mut state = state.lock().unwrap();
    state.config.tier.current = tier;
    if let Some(apps) = apps {
        state.config.apps.base = apps;
    }

    if let Err(e) = state.config.save(&state.config_path) {
        return Response::err(format!("failed to save config: {e:#}"));
    }
    if let Err(e) = launcher::render(&state.config) {
        return Response::err(format!("failed to render launcher tiles: {e:#}"));
    }
    Response::ok_empty()
}

/// Looks up a nicer label/icon for a temporarily-unlocked app from its
/// `.desktop` entry; falls back to the raw id if it can't be found (still a
/// usable tile, just less pretty).
fn tile_metadata_for(desktop_id: &str) -> (String, String, String) {
    const FALLBACK_SWATCH: &str = "#94A3B8";
    if let Some(path) = desktop::find_desktop_file(desktop_id) {
        if let Ok(entry) = desktop::parse_desktop_entry(&path) {
            return (entry.name, entry.icon, FALLBACK_SWATCH.to_string());
        }
    }
    (
        desktop_id.to_string(),
        desktop_id.to_string(),
        FALLBACK_SWATCH.to_string(),
    )
}

/// `Unlock` (unauthenticated at the socket layer) may only grant an app on
/// the parent-curated allow-list; `Override` is exempt because it's only
/// ever sent after a live polkit admin authentication has already happened
/// (see `agent/agent/src/main.rs`'s `run_override`) — a stronger, in-the-
/// moment authorization the allow-list doesn't need to duplicate.
fn unlock_is_permitted(app: &str, via_override: bool, allowlist: &[String]) -> bool {
    via_override || allowlist.iter().any(|a| a == app)
}

fn handle_unlock(
    state: &Arc<Mutex<State>>,
    app: String,
    minutes: Option<u32>,
    via_override: bool,
) -> Response {
    let allowed_apps = allowlist::load(&paths::unlockable_apps_path());
    if !unlock_is_permitted(&app, via_override, &allowed_apps) {
        return Response::err(format!(
            "'{app}' is not on the parent-curated unlockable-apps list ({})",
            paths::unlockable_apps_path().display()
        ));
    }

    let minutes = minutes.unwrap_or(DEFAULT_UNLOCK_MINUTES);
    let (label, icon, swatch) = tile_metadata_for(&app);

    let mut state = state.lock().unwrap();
    let now = Utc::now();
    let expires_at = now + ChronoDuration::minutes(minutes as i64);

    state.config.apps.unlocked.retain(|u| u.desktop_id != app);
    state.config.apps.unlocked.push(UnlockedApp {
        desktop_id: app.clone(),
        label,
        icon,
        swatch,
        expires_at,
        via_override,
    });

    if let Err(e) = state.config.save(&state.config_path) {
        return Response::err(format!("failed to save config: {e:#}"));
    }
    if let Err(e) = launcher::render(&state.config) {
        return Response::err(format!("failed to render launcher tiles: {e:#}"));
    }
    if via_override {
        if let Err(e) = db::insert_pin_override(&state.db, &app, minutes, now) {
            eprintln!("agentd: failed to log pin override: {e:#}");
        }
    }
    Response::ok_empty()
}

fn handle_override_failed(state: &Arc<Mutex<State>>, app: String) -> Response {
    let state = state.lock().unwrap();
    let now = Utc::now();
    let window_start = now - ChronoDuration::minutes(OVERRIDE_FAILURE_WINDOW_MINUTES);

    let recent = db::recent_override_failure_count(&state.db, &app, window_start).unwrap_or(0);
    let severity = if recent + 1 >= SEVERE_OVERRIDE_FAILURE_THRESHOLD {
        "severe"
    } else {
        "routine"
    };

    if let Err(e) = db::insert_security_event(&state.db, "override_failed", severity, Some(&app), now) {
        return Response::err(format!("failed to log security event: {e:#}"));
    }
    if severity == "severe" {
        security::notify_severe(&format!(
            "Repeated failed unlock attempts for '{app}' ({} in the last {OVERRIDE_FAILURE_WINDOW_MINUTES} min)",
            recent + 1
        ));
    }
    Response::ok_empty()
}

fn handle_wrapper_start(state: &Arc<Mutex<State>>, app: String, pid: u32) -> Response {
    let mut state = state.lock().unwrap();
    let now = Utc::now();

    if !state.config.is_app_allowed(&app) {
        // Not fatal — still record the session for transparency in the
        // report; the next WrapperPoll (within POLL_INTERVAL) will tell the
        // wrapper to terminate it.
        let _ = db::insert_security_event(
            &state.db,
            "wrapper_started_disallowed_app",
            "routine",
            Some(&app),
            now,
        );
    }

    if let Err(e) = db::start_session(&state.db, &app, pid, now) {
        return Response::err(format!("failed to log session start: {e:#}"));
    }
    state.active.insert(
        pid,
        ActiveSession {
            app,
            started_at: now,
            warned: false,
        },
    );
    Response::ok_empty()
}

fn handle_wrapper_stop(state: &Arc<Mutex<State>>, app: String, pid: u32) -> Response {
    let mut state = state.lock().unwrap();
    let now = Utc::now();
    state.active.remove(&pid);
    if let Err(e) = db::end_session(&state.db, &app, pid, now) {
        return Response::err(format!("failed to log session stop: {e:#}"));
    }
    Response::ok_empty()
}

/// Shared by `WrapperAuthorize` (checked *before* a launch, issue #35) and
/// `WrapperPoll` (checked periodically while already running) — same
/// allow-list/budget/window rules apply either way, only the pid-keyed
/// session accounting differs (and neither of these actually needs the pid).
fn check_allowed(state: &State, app: &str) -> AllowedPayload {
    let now_utc = Utc::now();
    let now_local = Local::now();

    let disallow = |reason: &str| AllowedPayload {
        allowed: false,
        reason: Some(reason.to_string()),
    };

    if !state.config.is_app_allowed(app) {
        return disallow("app is not (or no longer) unlocked");
    }
    if budget::in_blocked_window(&state.config, now_local) {
        // Time windows get no grace buffer — hard cutoff, per design note.
        return disallow("currently inside a blocked time window");
    }

    let midnight = budget::local_midnight_utc(now_local);
    if let Some(limit) = state
        .config
        .daily_total_minutes_today(now_local.weekday())
    {
        let used =
            budget::compute_daily_used_minutes(&state.db, &state.active, midnight, now_utc)
                .unwrap_or(0);
        if used > limit + budget::GRACE_MINUTES {
            return disallow("daily time budget exhausted");
        }
    }
    if let Some(limit) = state.config.per_app_minutes_today(app, now_local.weekday()) {
        let used =
            budget::compute_app_used_minutes(&state.db, &state.active, app, midnight, now_utc)
                .unwrap_or(0);
        if used > limit + budget::GRACE_MINUTES {
            return disallow("per-app time budget exhausted");
        }
    }

    AllowedPayload {
        allowed: true,
        reason: None,
    }
}

fn handle_wrapper_authorize(state: &Arc<Mutex<State>>, app: String) -> Response {
    let state = state.lock().unwrap();
    Response::ok_with(check_allowed(&state, &app))
}

fn handle_wrapper_poll(state: &Arc<Mutex<State>>, app: String, _pid: u32) -> Response {
    let state = state.lock().unwrap();
    Response::ok_with(check_allowed(&state, &app))
}

fn handle_report(state: &Arc<Mutex<State>>, week: bool) -> Response {
    let state = state.lock().unwrap();
    let range_days: i64 = if week { 7 } else { 1 };
    let now = Utc::now();
    let since = now - ChronoDuration::days(range_days);
    let prev_since = now - ChronoDuration::days(range_days * 2);

    let per_app_rows = match db::usage_by_app_since(&state.db, since) {
        Ok(v) => v,
        Err(e) => return Response::err(format!("failed to read usage: {e:#}")),
    };
    let per_app: Vec<AppUsage> = per_app_rows
        .into_iter()
        .map(|r| AppUsage {
            app: r.app,
            minutes: (r.seconds / 60) as u32,
        })
        .collect();

    let total_this = match db::used_seconds_since(&state.db, None, since) {
        Ok(v) => (v / 60) as u32,
        Err(e) => return Response::err(format!("failed to sum usage: {e:#}")),
    };
    let total_incl_previous = match db::used_seconds_since(&state.db, None, prev_since) {
        Ok(v) => (v / 60) as u32,
        Err(e) => return Response::err(format!("failed to sum usage: {e:#}")),
    };
    let total_previous = total_incl_previous.saturating_sub(total_this);

    let pin_override_count = db::pin_override_count_since(&state.db, since).unwrap_or(0);
    let security_events = db::recent_security_events(&state.db, since)
        .unwrap_or_default()
        .into_iter()
        .map(|r| SecurityEventSummary {
            occurred_at: r.occurred_at,
            event_type: r.event_type,
            severity: r.severity,
            detail: r.detail,
        })
        .collect();

    Response::ok_with(ReportPayload {
        range_days: range_days as u32,
        per_app,
        total_minutes_this_period: total_this,
        total_minutes_previous_period: total_previous,
        pin_override_count,
        security_events,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unlock_rejects_apps_not_on_the_allowlist() {
        let allowed = vec!["org.kde.gcompris".to_string()];
        assert!(!unlock_is_permitted("org.gnome.Terminal", false, &allowed));
        assert!(!unlock_is_permitted("org.gnome.Terminal", false, &[]));
    }

    #[test]
    fn unlock_permits_apps_on_the_allowlist() {
        let allowed = vec!["org.kde.gcompris".to_string()];
        assert!(unlock_is_permitted("org.kde.gcompris", false, &allowed));
    }

    #[test]
    fn override_bypasses_the_allowlist() {
        // Override is only ever sent after a live polkit admin
        // authentication (see run_override in agent/agent/src/main.rs) — a
        // stronger, in-the-moment check the allow-list doesn't need to gate.
        assert!(unlock_is_permitted("anything", true, &[]));
    }

    #[test]
    fn known_tiers_rejects_unrecognized_names() {
        assert!(!KNOWN_TIERS.contains(&"midi"));
        assert!(KNOWN_TIERS.contains(&"mini"));
        assert!(KNOWN_TIERS.contains(&"maxi"));
    }
}
