use std::time::Duration;

use anyhow::Result;
use redis::aio::ConnectionManager;
use redis::AsyncCommands;

pub struct CacheLayer {
    con: ConnectionManager,
    default_ttl: Duration,
}

impl CacheLayer {
    pub async fn new(url: &str) -> Result<Self> {
        let client = redis::Client::open(url)?;
        let con = ConnectionManager::new(client).await?;
        Ok(CacheLayer {
            con,
            default_ttl: Duration::from_secs(300),
        })
    }

    pub async fn get<T: redis::FromRedisValue>(&mut self, key: &str) -> Result<Option<T>> {
        let val: Option<T> = self.con.get(key).await?;
        Ok(val)
    }

    pub async fn set<T: redis::ToRedisArgs + Send + Sync>(
        &mut self,
        key: &str,
        value: T,
    ) -> Result<()> {
        let _: () = redis::cmd("SETEX")
            .arg(key)
            .arg(self.default_ttl.as_secs())
            .arg(value)
            .query_async(&mut self.con)
            .await?;
        Ok(())
    }

    pub async fn set_ttl<T: redis::ToRedisArgs + Send + Sync>(
        &mut self,
        key: &str,
        value: T,
        ttl_secs: u64,
    ) -> Result<()> {
        let _: () = redis::cmd("SETEX")
            .arg(key)
            .arg(ttl_secs)
            .arg(value)
            .query_async(&mut self.con)
            .await?;
        Ok(())
    }

    pub async fn delete(&mut self, key: &str) -> Result<()> {
        let _: () = redis::cmd("DEL").arg(key).query_async(&mut self.con).await?;
        Ok(())
    }

    pub async fn exists(&mut self, key: &str) -> Result<bool> {
        let val: bool = redis::cmd("EXISTS").arg(key).query_async(&mut self.con).await?;
        Ok(val)
    }

    pub async fn publish(&mut self, channel: &str, message: &str) -> Result<()> {
        let _: () = redis::cmd("PUBLISH").arg(channel).arg(message).query_async(&mut self.con).await?;
        Ok(())
    }

    pub async fn incr(&mut self, key: &str) -> Result<i64> {
        let val: i64 = redis::cmd("INCR").arg(key).query_async(&mut self.con).await?;
        Ok(val)
    }

    pub async fn expire(&mut self, key: &str, ttl_secs: i64) -> Result<()> {
        let _: () = redis::cmd("EXPIRE").arg(key).arg(ttl_secs).query_async(&mut self.con).await?;
        Ok(())
    }
}
