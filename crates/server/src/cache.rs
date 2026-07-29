use anyhow::Result;
use redis::aio::ConnectionManager;
use redis::AsyncCommands;

/// A thin Redis wrapper holding only the operations that have a caller.
///
/// It used to carry `set`/`delete`/`exists`/`publish`/`incr`/`expire` as well,
/// none of which anything called, and every method took `&mut self` — which
/// made the whole layer unreachable in practice, because `ApiState` holds it
/// as an `Arc<CacheLayer>` and an `Arc` hands out shared references only.
/// `ConnectionManager` is a cheap handle and clones into an owned one, so the
/// methods take `&self` and clone; the earlier signatures were the reason the
/// cache was configured, connected, logged — and never once used.
pub struct CacheLayer {
    con: ConnectionManager,
}

impl CacheLayer {
    pub async fn new(url: &str) -> Result<Self> {
        let client = redis::Client::open(url)?;
        let con = ConnectionManager::new(client).await?;
        Ok(CacheLayer { con })
    }

    pub async fn get<T: redis::FromRedisValue>(&self, key: &str) -> Result<Option<T>> {
        let mut con = self.con.clone();
        let val: Option<T> = con.get(key).await?;
        Ok(val)
    }

    pub async fn set_ttl<T: redis::ToRedisArgs + Send + Sync>(
        &self,
        key: &str,
        value: T,
        ttl_secs: u64,
    ) -> Result<()> {
        let mut con = self.con.clone();
        let _: () = redis::cmd("SETEX")
            .arg(key)
            .arg(ttl_secs)
            .arg(value)
            .query_async(&mut con)
            .await?;
        Ok(())
    }

    pub async fn incr(&self, key: &str) -> Result<i64> {
        let mut con = self.con.clone();
        let val: i64 = redis::cmd("INCR").arg(key).query_async(&mut con).await?;
        Ok(val)
    }

    pub async fn expire(&self, key: &str, secs: i64) -> Result<bool> {
        let mut con = self.con.clone();
        let val: bool = redis::cmd("EXPIRE")
            .arg(key)
            .arg(secs)
            .query_async(&mut con)
            .await?;
        Ok(val)
    }

    pub async fn set_nx_ttl(&self, key: &str, value: &str, ttl_secs: u64) -> Result<bool> {
        let mut con = self.con.clone();
        let val: Option<String> = redis::cmd("SET")
            .arg(key)
            .arg(value)
            .arg("EX")
            .arg(ttl_secs)
            .arg("NX")
            .query_async(&mut con)
            .await?;
        Ok(val.is_some())
    }
}
