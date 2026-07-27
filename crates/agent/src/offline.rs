use std::path::PathBuf;

use rusqlite::Connection;

pub struct OfflineBuffer {
    conn: Connection,
    max_bytes: u64,
    db_path: PathBuf,
}

impl OfflineBuffer {
    pub fn new(db_path: PathBuf, max_disk_mb: u64) -> anyhow::Result<Self> {
        let conn = Connection::open(&db_path)?;
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
                 payload BLOB,
                 created_at TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_event_queue_created ON event_queue(created_at);
             CREATE TABLE IF NOT EXISTS meta (
                 key TEXT PRIMARY KEY,
                 value TEXT NOT NULL
             );"
        )?;
        Ok(Self { conn, max_bytes: max_disk_mb * 1024 * 1024, db_path })
    }

    pub fn push(&self, event: &OfflineEvent) -> anyhow::Result<()> {
        if self.current_bytes()? >= self.max_bytes {
            self.prune_oldest()?;
        }
        self.conn.execute(
            "INSERT INTO event_queue (sensor_id, event_type, severity, title, description,
             source_ip, dest_ip, protocol, port, raw_data, payload, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            rusqlite::params![
                event.sensor_id, event.event_type, event.severity, event.title,
                event.description, event.source_ip, event.dest_ip,
                event.protocol, event.port, event.raw_data, event.payload,
                event.created_at,
            ],
        )?;
        Ok(())
    }

    pub fn pop_batch(&self, limit: usize) -> anyhow::Result<Vec<OfflineEvent>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, sensor_id, event_type, severity, title, description,
             source_ip, dest_ip, protocol, port, raw_data, payload, created_at
             FROM event_queue ORDER BY id ASC LIMIT ?1"
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
                payload: row.get(11)?,
                created_at: row.get(12)?,
            })
        })?;

        let mut events = Vec::new();
        for row in rows {
            events.push(row?);
        }
        Ok(events)
    }

    pub fn delete_batch(&self, ids: &[i64]) -> anyhow::Result<()> {
        if ids.is_empty() {
            return Ok(());
        }
        let placeholders: Vec<String> = ids.iter().map(|_| "?".to_string()).collect();
        let sql = format!(
            "DELETE FROM event_queue WHERE id IN ({})",
            placeholders.join(",")
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let params: Vec<rusqlite::types::Value> = ids
            .iter()
            .map(|id| rusqlite::types::Value::Integer(*id))
            .collect();
        let refs: Vec<&dyn rusqlite::types::ToSql> = params.iter().map(|p| p as &dyn rusqlite::types::ToSql).collect();
        stmt.execute(refs.as_slice())?;
        Ok(())
    }

    pub fn count(&self) -> anyhow::Result<i64> {
        Ok(self.conn.query_row("SELECT COUNT(*) FROM event_queue", [], |r| r.get(0))?)
    }

    pub fn is_empty(&self) -> bool {
        self.count().unwrap_or(0) == 0
    }

    fn current_bytes(&self) -> anyhow::Result<u64> {
        Ok(std::fs::metadata(&self.db_path)
            .map(|m| m.len())
            .unwrap_or(0))
    }

    fn prune_oldest(&self) -> anyhow::Result<()> {
        self.conn.execute(
            "DELETE FROM event_queue WHERE id IN (
                SELECT id FROM event_queue ORDER BY id ASC LIMIT 100
            )",
            [],
        )?;
        self.conn.execute("VACUUM", [])?;
        Ok(())
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
    #[serde(skip)]
    pub payload: Option<Vec<u8>>,
    pub created_at: String,
}
