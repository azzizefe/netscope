use std::path::Path;

use tokio::sync::Mutex;

pub struct OfflineBuffer {
    conn: Mutex<rusqlite::Connection>,
    max_bytes: u64,
}

impl OfflineBuffer {
    pub fn new(db_path: &Path, max_disk_mb: u64) -> anyhow::Result<Self> {
        let conn = rusqlite::Connection::open(db_path)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS event_queue (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 sensor_id TEXT NOT NULL,
                 event_type TEXT NOT NULL,
                 severity TEXT NOT NULL,
                 title TEXT NOT NULL,
                 description TEXT,
                 source_ip TEXT,
                 dest_ip TEXT,
                 protocol TEXT,
                 port INTEGER,
                 raw_data TEXT,
                 created_at TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_event_queue_created ON event_queue(created_at);",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
            max_bytes: max_disk_mb.saturating_mul(1024 * 1024),
        })
    }

    pub async fn push(&self, event: &OfflineEvent) -> anyhow::Result<()> {
        let conn = self.conn.lock().await;
        // Trim until the queue is back under the cap, not once. A single
        // 100-row delete could leave it still over, and because the check ran
        // again on the next push the buffer then dropped another 100 rows for
        // every single event appended — a queue that had touched its cap once
        // stayed permanently near-empty, silently discarding the events it
        // exists to preserve. Bounded so a cap smaller than one batch cannot
        // spin here.
        for _ in 0..MAX_TRIM_ROUNDS {
            if Self::used_bytes(&conn)? < self.max_bytes {
                break;
            }
            let removed = conn.execute(
                "DELETE FROM event_queue WHERE id IN (SELECT id FROM event_queue ORDER BY id ASC LIMIT 100)",
                [],
            )?;
            if removed == 0 {
                break;
            }
        }
        conn.execute(
            "INSERT INTO event_queue (sensor_id, event_type, severity, title, description,
             source_ip, dest_ip, protocol, port, raw_data, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            rusqlite::params![
                event.sensor_id,
                event.event_type,
                event.severity,
                event.title,
                event.description,
                event.source_ip,
                event.dest_ip,
                event.protocol,
                event.port,
                event.raw_data,
                event.created_at,
            ],
        )?;
        Ok(())
    }

    pub async fn pop_batch(&self, limit: usize) -> anyhow::Result<Vec<OfflineEvent>> {
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare(
            "SELECT id, sensor_id, event_type, severity, title, description,
             source_ip, dest_ip, protocol, port, raw_data, created_at
             FROM event_queue ORDER BY id ASC LIMIT ?1",
        )?;
        let rows = stmt.query_map(rusqlite::params![limit as i64], |row| {
            Ok(OfflineEvent {
                id: Some(row.get(0)?),
                sensor_id: row.get(1)?,
                event_type: row.get(2)?,
                severity: row.get(3)?,
                title: row.get(4)?,
                description: row.get(5)?,
                source_ip: row.get(6)?,
                dest_ip: row.get(7)?,
                protocol: row.get(8)?,
                port: row.get(9)?,
                raw_data: row.get(10)?,
                created_at: row.get(11)?,
            })
        })?;

        let mut events = Vec::new();
        for row in rows {
            events.push(row?);
        }
        Ok(events)
    }

    pub async fn delete_batch(&self, ids: &[i64]) -> anyhow::Result<()> {
        if ids.is_empty() {
            return Ok(());
        }
        let conn = self.conn.lock().await;
        let placeholders: Vec<String> = ids.iter().map(|_| "?".to_string()).collect();
        let sql = format!(
            "DELETE FROM event_queue WHERE id IN ({})",
            placeholders.join(",")
        );
        let mut stmt = conn.prepare(&sql)?;
        let params: Vec<rusqlite::types::Value> = ids
            .iter()
            .map(|id| rusqlite::types::Value::Integer(*id))
            .collect();
        let refs: Vec<&dyn rusqlite::types::ToSql> = params
            .iter()
            .map(|p| p as &dyn rusqlite::types::ToSql)
            .collect();
        stmt.execute(refs.as_slice())?;
        Ok(())
    }

    pub async fn count(&self) -> anyhow::Result<i64> {
        let conn = self.conn.lock().await;
        Ok(conn.query_row("SELECT COUNT(*) FROM event_queue", [], |r| r.get(0))?)
    }

    /// Bytes the queue actually occupies, from SQLite's own page accounting.
    ///
    /// This used to stat the database file, which was wrong twice over. Under
    /// `journal_mode=WAL` recent inserts live in the sidecar `-wal` file, so
    /// the main file under-reported the queue until a checkpoint; and deleting
    /// rows moves pages to the freelist without shrinking the file, so the
    /// measurement never came back down after a trim. Counting the pages in
    /// use excludes the freelist, which is what makes the trim above converge
    /// — freed pages are reused by the next insert, so the file stops growing
    /// even though it never gets smaller.
    fn used_bytes(conn: &rusqlite::Connection) -> anyhow::Result<u64> {
        let page_size: i64 = conn.query_row("PRAGMA page_size", [], |r| r.get(0))?;
        let page_count: i64 = conn.query_row("PRAGMA page_count", [], |r| r.get(0))?;
        let free_pages: i64 = conn.query_row("PRAGMA freelist_count", [], |r| r.get(0))?;
        Ok((page_count - free_pages).max(0) as u64 * page_size.max(0) as u64)
    }
}

/// Enough rounds to trim 100k events out of an oversized queue in one push,
/// and a hard stop so a `max_disk_mb` smaller than SQLite's own page overhead
/// cannot turn this into an infinite loop.
const MAX_TRIM_ROUNDS: usize = 1000;

#[cfg(test)]
mod tests {
    use super::*;

    fn buffer(max_disk_mb: u64) -> (OfflineBuffer, tempdir::Dir) {
        let dir = tempdir::Dir::new();
        let buf =
            OfflineBuffer::new(&dir.path().join("queue.db"), max_disk_mb).expect("open the queue");
        (buf, dir)
    }

    fn event(title: &str) -> OfflineEvent {
        OfflineEvent {
            id: None,
            sensor_id: "11111111-1111-1111-1111-111111111111".into(),
            event_type: "detection".into(),
            severity: "high".into(),
            title: title.into(),
            description: Some("described".into()),
            source_ip: Some("10.0.0.1".into()),
            dest_ip: Some("10.0.0.2".into()),
            protocol: Some("modbus".into()),
            port: Some(502),
            raw_data: Some("{}".into()),
            created_at: "2026-07-28T12:00:00Z".into(),
        }
    }

    /// The buffer exists so an outage does not lose events, which means what
    /// comes back out has to be what went in — every column, not just the title.
    #[tokio::test]
    async fn an_event_survives_the_round_trip_intact() {
        let (buf, _dir) = buffer(4096);
        buf.push(&event("cheese")).await.unwrap();

        let popped = buf.pop_batch(10).await.unwrap();
        assert_eq!(popped.len(), 1);
        let got = &popped[0];
        assert_eq!(got.title, "cheese");
        assert_eq!(got.severity, "high");
        assert_eq!(got.source_ip.as_deref(), Some("10.0.0.1"));
        assert_eq!(got.port, Some(502));
        assert_eq!(got.created_at, "2026-07-28T12:00:00Z");
        assert!(got.id.is_some(), "the id is what delete_batch is given");
    }

    /// Events replay in the order they happened. `pop_batch` orders by id and
    /// the flush deletes exactly what it sent, so a partial flush must leave
    /// the remainder — and leave it in order.
    #[tokio::test]
    async fn a_partial_flush_leaves_the_rest_in_order() {
        let (buf, _dir) = buffer(4096);
        for n in 0..5 {
            buf.push(&event(&format!("event-{n}"))).await.unwrap();
        }

        let first = buf.pop_batch(2).await.unwrap();
        assert_eq!(
            first.iter().map(|e| e.title.as_str()).collect::<Vec<_>>(),
            ["event-0", "event-1"],
        );

        let ids: Vec<i64> = first.iter().filter_map(|e| e.id).collect();
        buf.delete_batch(&ids).await.unwrap();
        assert_eq!(buf.count().await.unwrap(), 3);

        let rest = buf.pop_batch(10).await.unwrap();
        assert_eq!(
            rest.iter().map(|e| e.title.as_str()).collect::<Vec<_>>(),
            ["event-2", "event-3", "event-4"],
        );
    }

    /// `pop_batch` is a peek, not a take: an event stays queued until the
    /// server has acknowledged it and `delete_batch` removes it. Popping twice
    /// without deleting must return the same event, or a failed upload would
    /// lose it.
    #[tokio::test]
    async fn popping_does_not_remove() {
        let (buf, _dir) = buffer(4096);
        buf.push(&event("still here")).await.unwrap();

        assert_eq!(buf.pop_batch(10).await.unwrap().len(), 1);
        assert_eq!(buf.pop_batch(10).await.unwrap().len(), 1);
        assert_eq!(buf.count().await.unwrap(), 1);
    }

    /// Deleting nothing is not deleting everything. `delete_batch` builds its
    /// `IN (...)` list from the ids it is given, and an empty list would make
    /// that `IN ()` — so the early return is load-bearing.
    #[tokio::test]
    async fn deleting_an_empty_batch_keeps_the_queue() {
        let (buf, _dir) = buffer(4096);
        buf.push(&event("keep me")).await.unwrap();

        buf.delete_batch(&[]).await.unwrap();
        assert_eq!(buf.count().await.unwrap(), 1);
    }

    /// The disk cap has to bound the queue without emptying it.
    ///
    /// This is the regression: the cap was measured with `fs::metadata` on the
    /// database file. Deleting rows moves pages to SQLite's freelist and never
    /// shrinks the file, so once the queue touched its cap the measurement
    /// stayed over it forever and every subsequent push dropped another 100
    /// events. A sensor's buffer collapsed to nearly empty and stayed there.
    #[tokio::test]
    async fn the_disk_cap_trims_the_oldest_without_emptying_the_queue() {
        // 1 MB is the smallest cap the config can express. Padding each event
        // to ~1 KB puts roughly 900 of them in that budget — comfortably more
        // than the 100-row trim step, so a correct trim leaves most of the
        // queue standing and the assertions below can tell "trimmed" apart
        // from "emptied".
        let (buf, _dir) = buffer(1);
        let padding = "x".repeat(1024);
        for n in 0..1500 {
            let mut ev = event(&format!("event-{n}"));
            ev.raw_data = Some(padding.clone());
            buf.push(&ev).await.unwrap();
        }

        let remaining = buf.count().await.unwrap();
        assert!(
            remaining < 1500,
            "the cap never engaged: all {remaining} events are still queued",
        );
        assert!(
            remaining > 500,
            "the cap emptied the queue instead of trimming it: {remaining} left",
        );

        // What survives is the newest, because the trim deletes by ascending
        // id — the recent events are the ones worth keeping.
        let head = buf.pop_batch(1).await.unwrap();
        let oldest_kept: u32 = head[0]
            .title
            .strip_prefix("event-")
            .and_then(|n| n.parse().ok())
            .expect("the title carries its ordinal");
        assert!(
            oldest_kept > 0,
            "nothing was trimmed, so the cap never engaged",
        );
    }

    /// A queue well under its cap is never trimmed.
    #[tokio::test]
    async fn a_small_queue_is_left_alone() {
        let (buf, _dir) = buffer(4096);
        for n in 0..200 {
            buf.push(&event(&format!("event-{n}"))).await.unwrap();
        }
        assert_eq!(buf.count().await.unwrap(), 200);
    }

    /// A scratch directory that removes itself, so the tests do not need a
    /// dev-dependency to hold one temporary SQLite file.
    mod tempdir {
        use std::path::{Path, PathBuf};
        use std::sync::atomic::{AtomicU32, Ordering};

        static COUNTER: AtomicU32 = AtomicU32::new(0);

        pub struct Dir(PathBuf);

        impl Dir {
            pub fn new() -> Self {
                let n = COUNTER.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "netscope-agent-offline-{}-{}",
                    std::process::id(),
                    n,
                ));
                std::fs::create_dir_all(&path).expect("create the scratch directory");
                Dir(path)
            }

            pub fn path(&self) -> &Path {
                &self.0
            }
        }

        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OfflineEvent {
    #[serde(skip)]
    pub id: Option<i64>,
    pub sensor_id: String,
    pub event_type: String,
    pub severity: String,
    pub title: String,
    pub description: Option<String>,
    pub source_ip: Option<String>,
    pub dest_ip: Option<String>,
    pub protocol: Option<String>,
    pub port: Option<i32>,
    pub raw_data: Option<String>,
    pub created_at: String,
}
