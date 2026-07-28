pub mod models;
pub mod queries;

use anyhow::Result;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

pub async fn create_pool(url: &str, max_connections: u32) -> Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(max_connections)
        .connect(url)
        .await?;
    Ok(pool)
}

pub async fn run_migrations(pool: &PgPool) -> Result<()> {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let m = sqlx::migrate::Migrator::new(manifest.join("migrations")).await?;
    m.run(pool).await?;
    tracing::info!("Database migrations applied successfully");
    Ok(())
}
