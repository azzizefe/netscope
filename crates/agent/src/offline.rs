use std::path::Path;

use tokio::sync::Mutex;

pub struct OfflineBuffer {
    conn: Mutex<rusqlite::Connection>,
    max_bytes: u64,
    db_path: std::path::PathBuf,
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
             CREATE INDEX IF NOT EXISTS idx_event_queue_created ON event_queue(created_at);"
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
            max_bytes: max_disk_mb * 1024 * 1024,
            db_path: db_path.to_path_buf(),
        })
    }

    pub async fn push(&self, event: &OfflineEvent) -> anyhow::Result<()> {
        let conn = self.conn.lock().await;
        if self.current_bytes() >= self.max_bytes {
            conn.execute(
                "DELETE FROM event_queue WHERE id IN (SELECT id FROM event_queue ORDER BY id ASC LIMIT 100)",
                [],
            )?;
        }
        conn.execute(
            "INSERT INTO event_queue (sensor_id, event_type, severity, title, description,
             source_ip, dest_ip, protocol, port, raw_data, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            rusqlite::params![
                event.sensor_id, event.event_type, event.severity, event.title,
                event.description, event.source_ip, event.dest_ip,
                event.protocol, event.port, event.raw_data, event.created_at,
            ],
        )?;
        Ok(())
    }

    pub async fn pop_batch(&self, limit: usize) -> anyhow::Result<Vec<OfflineEvent>> {
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare(
            "SELECT id, sensor_id, event_type, severity, title, description,
             source_ip, dest_ip, protocol, port, raw_data, created_at
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
        let refs: Vec<&dyn rusqlite::types::ToSql> = params.iter().map(|p| p as &dyn rusqlite::types::ToSql).collect();
        stmt.execute(refs.as_slice())?;
        Ok(())
    }

    pub async fn count(&self) -> anyhow::Result<i64> {
        let conn = self.conn.lock().await;
        Ok(conn.query_row("SELECT COUNT(*) FROM event_queue", [], |r| r.get(0))?)
    }

    pub async fn is_empty(&self) -> bool {
        self.count().await.unwrap_or(0) == 0
    }

    fn current_bytes(&self) -> u64 {
        std::fs::metadata(&self.db_path)
            .map(|m| m.len())
            .unwrap_or(0)
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
