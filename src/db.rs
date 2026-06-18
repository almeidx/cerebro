//! SQLite persistence for the audit log, configuration snapshots and firewall backups.
//!
//! Timestamps are stored as RFC3339 text and enums as their [`std::fmt::Display`]
//! representation, so the on-disk schema stays human-readable and self-describing.

use std::path::Path;

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};

use crate::error::{Error, Result};
use crate::model::{ActionTier, AuditEntry, Snapshot, SnapshotKind};

/// A configuration snapshot awaiting persistence (the `taken_at` timestamp is
/// assigned by [`Store::save_snapshot`]).
#[derive(Debug, Clone)]
pub struct NewSnapshot {
    pub host: String,
    pub kind: SnapshotKind,
    pub payload: String,
}

/// Owns the SQLite connection and exposes the persistence operations Cerebro needs.
pub struct Store {
    conn: Connection,
}

impl Store {
    /// Open (creating if necessary) the database at `path` and run migrations.
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        let store = Self { conn };
        store.migrate()?;
        Ok(store)
    }

    /// Open a throwaway in-memory database, primarily for tests.
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let store = Self { conn };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> Result<()> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                host TEXT NOT NULL,
                action TEXT NOT NULL,
                tier TEXT NOT NULL,
                command TEXT NOT NULL,
                diff TEXT,
                result TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host TEXT NOT NULL,
                taken_at TEXT NOT NULL,
                kind TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS fw_backups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host TEXT NOT NULL,
                taken_at TEXT NOT NULL,
                ruleset TEXT NOT NULL
            );",
        )?;
        Ok(())
    }

    /// Append an audit entry, returning its new row id.
    pub fn record_audit(&self, e: &AuditEntry) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO audit_log (ts, host, action, tier, command, diff, result)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                e.ts.to_rfc3339(),
                e.host,
                e.action,
                e.tier.to_string(),
                e.command,
                e.diff,
                e.result,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Return up to `limit` audit entries, most recent first.
    pub fn recent_audit(&self, limit: usize) -> Result<Vec<AuditEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT ts, host, action, tier, command, diff, result
             FROM audit_log
             ORDER BY id DESC
             LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, String>(6)?,
            ))
        })?;

        let mut entries = Vec::new();
        for row in rows {
            let (ts, host, action, tier, command, diff, result) = row?;
            entries.push(AuditEntry {
                ts: parse_ts(&ts)?,
                host,
                action,
                tier: parse_tier(&tier)?,
                command,
                diff,
                result,
            });
        }
        Ok(entries)
    }

    /// Persist a snapshot, stamping it with the current time. Returns the row id.
    pub fn save_snapshot(&self, s: &NewSnapshot) -> Result<i64> {
        let taken_at = Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT INTO snapshots (host, taken_at, kind, payload)
             VALUES (?1, ?2, ?3, ?4)",
            params![s.host, taken_at, s.kind.to_string(), s.payload],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Return the most recent snapshot for `host`/`kind`, if any.
    pub fn latest_snapshot(&self, host: &str, kind: SnapshotKind) -> Result<Option<Snapshot>> {
        let row = self
            .conn
            .query_row(
                "SELECT id, host, taken_at, kind, payload
                 FROM snapshots
                 WHERE host = ?1 AND kind = ?2
                 ORDER BY id DESC
                 LIMIT 1",
                params![host, kind.to_string()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                },
            )
            .optional()?;

        let Some((id, host, taken_at, kind, payload)) = row else {
            return Ok(None);
        };
        Ok(Some(Snapshot {
            id,
            host,
            taken_at: parse_ts(&taken_at)?,
            kind: parse_kind(&kind)?,
            payload,
        }))
    }

    /// Store a firewall ruleset backup, stamping it with the current time. Returns the row id.
    pub fn save_fw_backup(&self, host: &str, ruleset: &str) -> Result<i64> {
        let taken_at = Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT INTO fw_backups (host, taken_at, ruleset)
             VALUES (?1, ?2, ?3)",
            params![host, taken_at, ruleset],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Return the ruleset of the most recent firewall backup for `host`, if any.
    pub fn latest_fw_backup(&self, host: &str) -> Result<Option<String>> {
        let ruleset = self
            .conn
            .query_row(
                "SELECT ruleset
                 FROM fw_backups
                 WHERE host = ?1
                 ORDER BY id DESC
                 LIMIT 1",
                params![host],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        Ok(ruleset)
    }
}

fn parse_ts(s: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| Error::parse("timestamp", e))
}

fn parse_tier(s: &str) -> Result<ActionTier> {
    match s {
        "read" => Ok(ActionTier::Read),
        "safe-write" => Ok(ActionTier::SafeWrite),
        "destructive" => Ok(ActionTier::Destructive),
        other => Err(Error::parse(
            "action tier",
            format!("unknown tier `{other}`"),
        )),
    }
}

fn parse_kind(s: &str) -> Result<SnapshotKind> {
    match s {
        "firewall" => Ok(SnapshotKind::Firewall),
        "docker_daemon" => Ok(SnapshotKind::DockerDaemon),
        "cron" => Ok(SnapshotKind::Cron),
        "packages" => Ok(SnapshotKind::Packages),
        "sockets" => Ok(SnapshotKind::Sockets),
        other => Err(Error::parse(
            "snapshot kind",
            format!("unknown kind `{other}`"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry() -> AuditEntry {
        AuditEntry {
            ts: Utc::now(),
            host: "web-01".to_string(),
            action: "firewall.add-port".to_string(),
            tier: ActionTier::SafeWrite,
            command: "firewall-cmd --add-port=8443/tcp".to_string(),
            diff: Some("+ 8443/tcp".to_string()),
            result: "ok".to_string(),
        }
    }

    #[test]
    fn opens_in_memory_and_migrates() {
        let store = Store::open_in_memory().unwrap();
        assert!(store.recent_audit(10).unwrap().is_empty());
    }

    #[test]
    fn records_and_reads_back_audit_entry() {
        let store = Store::open_in_memory().unwrap();
        let entry = sample_entry();
        let id = store.record_audit(&entry).unwrap();
        assert_eq!(id, 1);

        let recent = store.recent_audit(10).unwrap();
        assert_eq!(recent.len(), 1);
        let got = &recent[0];
        assert_eq!(got.host, "web-01");
        assert_eq!(got.action, "firewall.add-port");
        assert_eq!(got.tier, ActionTier::SafeWrite);
        assert_eq!(got.diff.as_deref(), Some("+ 8443/tcp"));
        assert_eq!(got.result, "ok");
    }

    #[test]
    fn audit_entry_with_no_diff_roundtrips() {
        let store = Store::open_in_memory().unwrap();
        let mut entry = sample_entry();
        entry.tier = ActionTier::Read;
        entry.diff = None;
        store.record_audit(&entry).unwrap();

        let recent = store.recent_audit(10).unwrap();
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].tier, ActionTier::Read);
        assert!(recent[0].diff.is_none());
    }

    #[test]
    fn recent_audit_is_newest_first_and_honours_limit() {
        let store = Store::open_in_memory().unwrap();
        for action in ["a", "b", "c"] {
            let mut entry = sample_entry();
            entry.action = action.to_string();
            store.record_audit(&entry).unwrap();
        }
        let recent = store.recent_audit(2).unwrap();
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].action, "c");
        assert_eq!(recent[1].action, "b");
    }

    #[test]
    fn saves_and_loads_latest_snapshot() {
        let store = Store::open_in_memory().unwrap();
        let snap = NewSnapshot {
            host: "web-01".to_string(),
            kind: SnapshotKind::Firewall,
            payload: "zone=public ports=22/tcp".to_string(),
        };
        let id = store.save_snapshot(&snap).unwrap();
        assert_eq!(id, 1);

        let latest = store
            .latest_snapshot("web-01", SnapshotKind::Firewall)
            .unwrap()
            .expect("snapshot should exist");
        assert_eq!(latest.id, 1);
        assert_eq!(latest.host, "web-01");
        assert_eq!(latest.kind, SnapshotKind::Firewall);
        assert_eq!(latest.payload, "zone=public ports=22/tcp");
    }

    #[test]
    fn latest_snapshot_for_unknown_host_is_none() {
        let store = Store::open_in_memory().unwrap();
        let latest = store
            .latest_snapshot("nope", SnapshotKind::Firewall)
            .unwrap();
        assert!(latest.is_none());
    }

    #[test]
    fn latest_snapshot_returns_most_recent_for_same_host_and_kind() {
        let store = Store::open_in_memory().unwrap();
        let host = "web-01";
        store
            .save_snapshot(&NewSnapshot {
                host: host.to_string(),
                kind: SnapshotKind::Cron,
                payload: "first".to_string(),
            })
            .unwrap();
        store
            .save_snapshot(&NewSnapshot {
                host: host.to_string(),
                kind: SnapshotKind::Cron,
                payload: "second".to_string(),
            })
            .unwrap();

        let latest = store
            .latest_snapshot(host, SnapshotKind::Cron)
            .unwrap()
            .expect("snapshot should exist");
        assert_eq!(latest.payload, "second");
    }

    #[test]
    fn snapshot_kind_filter_is_respected() {
        let store = Store::open_in_memory().unwrap();
        store
            .save_snapshot(&NewSnapshot {
                host: "web-01".to_string(),
                kind: SnapshotKind::Packages,
                payload: "pkgs".to_string(),
            })
            .unwrap();
        let other = store
            .latest_snapshot("web-01", SnapshotKind::Sockets)
            .unwrap();
        assert!(other.is_none());
    }

    #[test]
    fn firewall_backup_roundtrips() {
        let store = Store::open_in_memory().unwrap();
        assert!(store.latest_fw_backup("web-01").unwrap().is_none());

        let id = store.save_fw_backup("web-01", "ruleset-v1").unwrap();
        assert_eq!(id, 1);
        assert_eq!(
            store.latest_fw_backup("web-01").unwrap().as_deref(),
            Some("ruleset-v1")
        );

        store.save_fw_backup("web-01", "ruleset-v2").unwrap();
        assert_eq!(
            store.latest_fw_backup("web-01").unwrap().as_deref(),
            Some("ruleset-v2")
        );
    }

    #[test]
    fn parse_tier_rejects_unknown() {
        assert!(parse_tier("bogus").is_err());
        assert_eq!(parse_tier("destructive").unwrap(), ActionTier::Destructive);
    }

    #[test]
    fn parse_kind_rejects_unknown() {
        assert!(parse_kind("bogus").is_err());
        assert_eq!(
            parse_kind("docker_daemon").unwrap(),
            SnapshotKind::DockerDaemon
        );
    }
}
