use sqlx::{PgPool, postgres::PgPoolOptions};
use testcontainers::{ContainerAsync, runners::AsyncRunner};
use testcontainers_modules::postgres::Postgres;
use std::time::Duration;

#[allow(dead_code)]
pub struct TestDb {
    pub pool: PgPool,
    pub host: String,
    pub port: u16,
    _container: ContainerAsync<Postgres>,
}

impl TestDb {
    pub async fn new() -> Self {
        println!("\n  ┌─────────────────────────────────────────────────────────┐");
        println!("  │  Starting EPHEMERAL PostgreSQL (testcontainers)         │");
        println!("  └─────────────────────────────────────────────────────────┘");
        
        let container = Postgres::default()
            .start()
            .await
            .expect("Failed to start postgres container");

        let host = container.get_host().await.expect("Failed to get host");
        let port = container.get_host_port_ipv4(5432).await.expect("Failed to get port");

        println!("  → Container: {}:{}", host, port);

        let database_url = format!(
            "postgres://postgres:postgres@{}:{}/postgres",
            host, port
        );

        let pool = PgPoolOptions::new()
            .max_connections(5)
            .acquire_timeout(Duration::from_secs(30))
            .connect(&database_url)
            .await
            .expect("Failed to connect");

        println!("  → Running migrations...");

        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("Failed to run migrations");

        println!("  ✓ Ready\n");

        Self {
            pool,
            host: host.to_string(),
            port,
            _container: container,
        }
    }
}
