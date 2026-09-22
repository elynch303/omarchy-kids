//! SQLite usage log (issue #12). Unlimited retention — see design note
//! "Omarchy Kids - Parental Controls und Bildschirmzeit"; deletion, if ever
//! added, is a Control Center feature, not agentd's.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;

pub fn open(path: &Path) -> Result<Connection> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let conn = Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS usage_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            app_id TEXT NOT NULL,
            pid INTEGER NOT NULL,
            started_at TEXT NOT NULL,
            ended_at TEXT,
            duration_seconds INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_usage_sessions_started_at ON usage_sessions(started_at);
        CREATE INDEX IF NOT EXISTS idx_usage_sessions_open ON usage_sessions(app_id, pid, ended_at);

        CREATE TABLE IF NOT EXISTS pin_overrides (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            occurred_at TEXT NOT NULL,
            app_id TEXT NOT NULL,
            minutes INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            occurred_at TEXT NOT NULL,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            detail TEXT
        );

        CREATE TABLE IF NOT EXISTS install_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            package TEXT NOT NULL,
            repo TEXT NOT NULL,
            version TEXT NOT NULL,
            description TEXT NOT NULL,
            download_size TEXT NOT NULL,
            note TEXT,
            status TEXT NOT NULL,
            requested_at TEXT NOT NULL,
            decided_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_install_requests_status ON install_requests(status);
        ",
    )
    .context("creating schema")?;
    Ok(conn)
}

pub fn start_session(conn: &Connection, app: &str, pid: u32, started_at: DateTime<Utc>) -> Result<()> {
    conn.execute(
        "INSERT INTO usage_sessions (app_id, pid, started_at) VALUES (?1, ?2, ?3)",
        params![app, pid, started_at.to_rfc3339()],
    )?;
    Ok(())
}

/// Closes the most recent still-open session for (app, pid). If none exists
/// (e.g. agentd restarted mid-session and lost its in-memory `active` map),
/// records a zero-duration entry so the stop event isn't silently dropped.
pub fn end_session(conn: &Connection, app: &str, pid: u32, ended_at: DateTime<Utc>) -> Result<()> {
    let open_started_at: Option<String> = conn
        .query_row(
            "SELECT started_at FROM usage_sessions
             WHERE app_id = ?1 AND pid = ?2 AND ended_at IS NULL
             ORDER BY id DESC LIMIT 1",
            params![app, pid],
            |row| row.get(0),
        )
        .optional()?;

    let Some(started_at) = open_started_at else {
        conn.execute(
            "INSERT INTO usage_sessions (app_id, pid, started_at, ended_at, duration_seconds)
             VALUES (?1, ?2, ?3, ?3, 0)",
            params![app, pid, ended_at.to_rfc3339()],
        )?;
        return Ok(());
    };

    let started: DateTime<Utc> = DateTime::parse_from_rfc3339(&started_at)
        .context("parsing stored started_at")?
        .with_timezone(&Utc);
    let duration = (ended_at - started).num_seconds().max(0);

    conn.execute(
        "UPDATE usage_sessions SET ended_at = ?1, duration_seconds = ?2
         WHERE app_id = ?3 AND pid = ?4 AND ended_at IS NULL",
        params![ended_at.to_rfc3339(), duration, app, pid],
    )?;
    Ok(())
}

/// Sum of completed sessions' durations since `since`, optionally filtered
/// to one app. Deliberately excludes still-open sessions — the caller adds
/// their live elapsed time on top (see `budget::compute_*_used_minutes`).
pub fn used_seconds_since(conn: &Connection, app: Option<&str>, since: DateTime<Utc>) -> Result<i64> {
    let seconds = match app {
        Some(app) => conn.query_row(
            "SELECT COALESCE(SUM(duration_seconds), 0) FROM usage_sessions
             WHERE started_at >= ?1 AND ended_at IS NOT NULL AND app_id = ?2",
            params![since.to_rfc3339(), app],
            |row| row.get(0),
        )?,
        None => conn.query_row(
            "SELECT COALESCE(SUM(duration_seconds), 0) FROM usage_sessions
             WHERE started_at >= ?1 AND ended_at IS NOT NULL",
            params![since.to_rfc3339()],
            |row| row.get(0),
        )?,
    };
    Ok(seconds)
}

pub struct AppUsageRow {
    pub app: String,
    pub seconds: i64,
}

pub fn usage_by_app_since(conn: &Connection, since: DateTime<Utc>) -> Result<Vec<AppUsageRow>> {
    let mut stmt = conn.prepare(
        "SELECT app_id, COALESCE(SUM(duration_seconds), 0) FROM usage_sessions
         WHERE started_at >= ?1 AND ended_at IS NOT NULL
         GROUP BY app_id ORDER BY 2 DESC",
    )?;
    let rows = stmt.query_map(params![since.to_rfc3339()], |row| {
        Ok(AppUsageRow {
            app: row.get(0)?,
            seconds: row.get(1)?,
        })
    })?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .context("reading usage_by_app_since")
}

pub fn insert_pin_override(conn: &Connection, app: &str, minutes: u32, occurred_at: DateTime<Utc>) -> Result<()> {
    conn.execute(
        "INSERT INTO pin_overrides (occurred_at, app_id, minutes) VALUES (?1, ?2, ?3)",
        params![occurred_at.to_rfc3339(), app, minutes],
    )?;
    Ok(())
}

pub fn pin_override_count_since(conn: &Connection, since: DateTime<Utc>) -> Result<u32> {
    conn.query_row(
        "SELECT COUNT(*) FROM pin_overrides WHERE occurred_at >= ?1",
        params![since.to_rfc3339()],
        |row| row.get(0),
    )
    .context("counting pin overrides")
}

pub fn insert_security_event(
    conn: &Connection,
    event_type: &str,
    severity: &str,
    detail: Option<&str>,
    occurred_at: DateTime<Utc>,
) -> Result<()> {
    conn.execute(
        "INSERT INTO security_events (occurred_at, event_type, severity, detail) VALUES (?1, ?2, ?3, ?4)",
        params![occurred_at.to_rfc3339(), event_type, severity, detail],
    )?;
    Ok(())
}

pub struct SecurityEventRow {
    pub occurred_at: String,
    pub event_type: String,
    pub severity: String,
    pub detail: Option<String>,
}

pub fn recent_security_events(conn: &Connection, since: DateTime<Utc>) -> Result<Vec<SecurityEventRow>> {
    let mut stmt = conn.prepare(
        "SELECT occurred_at, event_type, severity, detail FROM security_events
         WHERE occurred_at >= ?1 ORDER BY occurred_at DESC",
    )?;
    let rows = stmt.query_map(params![since.to_rfc3339()], |row| {
        Ok(SecurityEventRow {
            occurred_at: row.get(0)?,
            event_type: row.get(1)?,
            severity: row.get(2)?,
            detail: row.get(3)?,
        })
    })?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .context("reading recent_security_events")
}

/// Failed-override attempts for one app within a trailing window — feeds the
/// "gehäufte PIN-Fehlversuche" severity threshold (issue #10).
pub fn recent_override_failure_count(conn: &Connection, app: &str, since: DateTime<Utc>) -> Result<u32> {
    conn.query_row(
        "SELECT COUNT(*) FROM security_events
         WHERE event_type = 'override_failed' AND detail = ?1 AND occurred_at >= ?2",
        params![app, since.to_rfc3339()],
        |row| row.get(0),
    )
    .context("counting recent override failures")
}

// --- install requests (see `Request::InstallRequest`) ---------------------

pub const INSTALL_STATUSES: &[&str] = &["pending", "approved", "denied", "installed"];

pub struct NewInstallRequest<'a> {
    pub package: &'a str,
    pub repo: &'a str,
    pub version: &'a str,
    pub description: &'a str,
    pub download_size: &'a str,
    pub note: Option<&'a str>,
}

pub struct InstallRequestRow {
    pub id: i64,
    pub package: String,
    pub repo: String,
    pub version: String,
    pub description: String,
    pub download_size: String,
    pub note: Option<String>,
    pub status: String,
    pub requested_at: String,
    pub decided_at: Option<String>,
}

const INSTALL_REQUEST_COLUMNS: &str =
    "id, package, repo, version, description, download_size, note, status, requested_at, decided_at";

fn install_request_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<InstallRequestRow> {
    Ok(InstallRequestRow {
        id: row.get(0)?,
        package: row.get(1)?,
        repo: row.get(2)?,
        version: row.get(3)?,
        description: row.get(4)?,
        download_size: row.get(5)?,
        note: row.get(6)?,
        status: row.get(7)?,
        requested_at: row.get(8)?,
        decided_at: row.get(9)?,
    })
}

/// Records a new request as `pending` and returns its id.
pub fn insert_install_request(
    conn: &Connection,
    new: &NewInstallRequest<'_>,
    requested_at: DateTime<Utc>,
) -> Result<i64> {
    conn.execute(
        "INSERT INTO install_requests
            (package, repo, version, description, download_size, note, status, requested_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending', ?7)",
        params![
            new.package,
            new.repo,
            new.version,
            new.description,
            new.download_size,
            new.note,
            requested_at.to_rfc3339()
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn install_request_by_id(conn: &Connection, id: i64) -> Result<Option<InstallRequestRow>> {
    conn.query_row(
        &format!("SELECT {INSTALL_REQUEST_COLUMNS} FROM install_requests WHERE id = ?1"),
        params![id],
        install_request_from_row,
    )
    .optional()
    .context("reading an install request")
}

/// The id of a still-pending request for this exact package, if any.
pub fn pending_install_request_id(conn: &Connection, package: &str) -> Result<Option<i64>> {
    conn.query_row(
        "SELECT id FROM install_requests WHERE package = ?1 AND status = 'pending' LIMIT 1",
        params![package],
        |row| row.get(0),
    )
    .optional()
    .context("looking for a pending install request")
}

pub fn pending_install_request_count(conn: &Connection) -> Result<u32> {
    conn.query_row(
        "SELECT COUNT(*) FROM install_requests WHERE status = 'pending'",
        [],
        |row| row.get(0),
    )
    .context("counting pending install requests")
}

/// Newest first. `status = None` returns every status.
pub fn list_install_requests(
    conn: &Connection,
    status: Option<&str>,
    limit: u32,
) -> Result<Vec<InstallRequestRow>> {
    let sql = format!(
        "SELECT {INSTALL_REQUEST_COLUMNS} FROM install_requests
         WHERE (?1 IS NULL OR status = ?1) ORDER BY id DESC LIMIT ?2"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params![status, limit], install_request_from_row)?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .context("reading install requests")
}

/// Moves a request from `pending` to `new_status` (`approved` or `denied`).
/// Returns false, changing nothing, if the request isn't pending (unknown id,
/// or already decided) so a decision can't be silently overwritten.
pub fn decide_pending_install_request(
    conn: &Connection,
    id: i64,
    new_status: &str,
    decided_at: DateTime<Utc>,
) -> Result<bool> {
    let changed = conn.execute(
        "UPDATE install_requests SET status = ?2, decided_at = ?3
         WHERE id = ?1 AND status = 'pending'",
        params![id, new_status, decided_at.to_rfc3339()],
    )?;
    Ok(changed == 1)
}

/// `approved` -> `installed`, once the package shows up in pacman's local DB.
pub fn mark_install_request_installed(conn: &Connection, id: i64, at: DateTime<Utc>) -> Result<()> {
    conn.execute(
        "UPDATE install_requests SET status = 'installed', decided_at = COALESCE(decided_at, ?2)
         WHERE id = ?1 AND status = 'approved'",
        params![id, at.to_rfc3339()],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_db() -> (tempfile::TempDir, Connection) {
        let dir = tempfile::tempdir().unwrap();
        let conn = open(&dir.path().join("usage.db")).unwrap();
        (dir, conn)
    }

    fn sample<'a>(package: &'a str, note: Option<&'a str>) -> NewInstallRequest<'a> {
        NewInstallRequest {
            package,
            repo: "extra",
            version: "1.0-1",
            description: "A test package",
            download_size: "1.00 MiB",
            note,
        }
    }

    #[test]
    fn a_new_request_is_pending_and_can_be_read_back() {
        let (_dir, conn) = temp_db();
        let id = insert_install_request(&conn, &sample("gimp", Some("for art class")), Utc::now()).unwrap();

        let row = install_request_by_id(&conn, id).unwrap().unwrap();
        assert_eq!(row.package, "gimp");
        assert_eq!(row.status, "pending");
        assert_eq!(row.note.as_deref(), Some("for art class"));
        assert!(row.decided_at.is_none());
        assert_eq!(pending_install_request_id(&conn, "gimp").unwrap(), Some(id));
        assert_eq!(pending_install_request_count(&conn).unwrap(), 1);
    }

    #[test]
    fn deciding_moves_a_pending_request_once_and_only_once() {
        let (_dir, conn) = temp_db();
        let id = insert_install_request(&conn, &sample("gimp", None), Utc::now()).unwrap();

        assert!(decide_pending_install_request(&conn, id, "approved", Utc::now()).unwrap());
        // Already decided: a second decision must not overwrite the first.
        assert!(!decide_pending_install_request(&conn, id, "denied", Utc::now()).unwrap());
        assert_eq!(install_request_by_id(&conn, id).unwrap().unwrap().status, "approved");
        assert!(!decide_pending_install_request(&conn, 9999, "denied", Utc::now()).unwrap());
        // No longer pending, so no longer counted or matched as pending.
        assert_eq!(pending_install_request_count(&conn).unwrap(), 0);
        assert_eq!(pending_install_request_id(&conn, "gimp").unwrap(), None);
    }

    #[test]
    fn only_an_approved_request_can_become_installed() {
        let (_dir, conn) = temp_db();
        let pending = insert_install_request(&conn, &sample("a", None), Utc::now()).unwrap();
        let approved = insert_install_request(&conn, &sample("b", None), Utc::now()).unwrap();
        decide_pending_install_request(&conn, approved, "approved", Utc::now()).unwrap();

        mark_install_request_installed(&conn, pending, Utc::now()).unwrap();
        mark_install_request_installed(&conn, approved, Utc::now()).unwrap();

        assert_eq!(install_request_by_id(&conn, pending).unwrap().unwrap().status, "pending");
        assert_eq!(install_request_by_id(&conn, approved).unwrap().unwrap().status, "installed");
    }

    #[test]
    fn listing_is_newest_first_and_filters_by_status() {
        let (_dir, conn) = temp_db();
        let first = insert_install_request(&conn, &sample("first", None), Utc::now()).unwrap();
        let second = insert_install_request(&conn, &sample("second", None), Utc::now()).unwrap();
        decide_pending_install_request(&conn, first, "denied", Utc::now()).unwrap();

        let all = list_install_requests(&conn, None, 50).unwrap();
        assert_eq!(all.iter().map(|r| r.id).collect::<Vec<_>>(), vec![second, first]);

        let pending = list_install_requests(&conn, Some("pending"), 50).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].package, "second");
        assert_eq!(list_install_requests(&conn, Some("denied"), 50).unwrap().len(), 1);
    }
}
