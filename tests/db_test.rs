//! Database tests
//!
//! Ephemeral (testcontainers):
//!   cargo test test_db -- --nocapture
//!
//! Production connection (docker-compose):
//!   cargo test test_production -- --nocapture
//!
//! Interactive:
//!   cargo test test_interactive -- --nocapture --ignored

mod common;

use common::TestDb;
use sqlx::Row;

// =============================================================================
// PRODUCTION CONNECTION TEST (docker-compose)
// =============================================================================

#[tokio::test]
async fn test_production_connection() {
    // Skip in CI
    if std::env::var("CI").is_ok() {
        println!("Skipping production DB test in CI");
        return;
    }

    use sqlx::postgres::PgPoolOptions;
    use std::time::Duration;

    println!("\n============================================================");
    println!("TEST: Production database connection");
    println!("============================================================");

    // Read password from .env
    let password = std::fs::read_to_string(".env")
        .expect(".env not found")
        .lines()
        .find(|l| l.starts_with("DB_PASSWORD="))
        .map(|l| l.trim_start_matches("DB_PASSWORD=").to_string())
        .expect("DB_PASSWORD not in .env");

    let database_url = format!(
        "postgres://docsend_user:{}@localhost:5432/docsend",
        password
    );

    println!("  → Connecting to production database...");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&database_url)
        .await
        .expect("Failed to connect. Is docker-compose up?");

    // Verify connection
    let result: (i32,) = sqlx::query_as("SELECT 1")
        .fetch_one(&pool)
        .await
        .expect("Query failed");
    assert_eq!(result.0, 1);
    println!("  ✓ Connected");

    // Check postgres version
    let version: (String,) = sqlx::query_as("SELECT version()")
        .fetch_one(&pool)
        .await
        .expect("Version query failed");
    println!("  ✓ {}", version.0.split_whitespace().take(2).collect::<Vec<_>>().join(" "));

    println!("  ✓ Production connection test passed\n");
}

// =============================================================================
// EPHEMERAL TESTS (testcontainers)
// =============================================================================

#[tokio::test]
async fn test_db_setup_migrate_teardown() {
    println!("\n============================================================");
    println!("TEST: Setup, migrate, teardown");
    println!("============================================================");

    let db = TestDb::new().await;

    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT table_name::text FROM information_schema.tables WHERE table_schema = 'public' ORDER BY table_name"
    )
    .fetch_all(&db.pool)
    .await
    .expect("Failed to query tables");

    println!("  Tables: {:?}", tables);
    assert!(tables.contains(&"admins".to_string()));
    assert!(tables.contains(&"documents".to_string()));
    assert!(tables.contains(&"links".to_string()));
    assert!(tables.contains(&"access_tokens".to_string()));
    assert!(tables.contains(&"views".to_string()));
    assert!(tables.contains(&"custom_blocklist".to_string()));

    println!("  ✓ All 6 tables verified\n");
}

#[tokio::test]
async fn test_db_crud() {
    println!("\n============================================================");
    println!("TEST: CRUD operations");
    println!("============================================================");

    let db = TestDb::new().await;

    // Create document
    let doc_id = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO documents (id, name, filename, storage_path, size_bytes) VALUES ($1, $2, $3, $4, $5)")
        .bind(doc_id)
        .bind("Test Doc")
        .bind("test.pdf")
        .bind("/tmp/test.pdf")
        .bind(1000_i64)
        .execute(&db.pool)
        .await
        .unwrap();
    println!("  ✓ Create document");

    // Read document
    let row: (String,) = sqlx::query_as("SELECT name FROM documents WHERE id = $1")
        .bind(doc_id)
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(row.0, "Test Doc");
    println!("  ✓ Read document");

    // Update document
    sqlx::query("UPDATE documents SET name = $1 WHERE id = $2")
        .bind("Updated Doc")
        .bind(doc_id)
        .execute(&db.pool)
        .await
        .unwrap();
    let row: (String,) = sqlx::query_as("SELECT name FROM documents WHERE id = $1")
        .bind(doc_id)
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(row.0, "Updated Doc");
    println!("  ✓ Update document");

    // Delete document
    sqlx::query("DELETE FROM documents WHERE id = $1")
        .bind(doc_id)
        .execute(&db.pool)
        .await
        .unwrap();
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM documents WHERE id = $1")
        .bind(doc_id)
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(count.0, 0);
    println!("  ✓ Delete document");

    println!("\n  ✓ CRUD test passed\n");
}

#[tokio::test]
async fn test_db_full_workflow() {
    println!("\n============================================================");
    println!("TEST: Full workflow (document → link → token → view)");
    println!("============================================================");

    let db = TestDb::new().await;

    // Admin
    let admin_id = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO admins (id, email, password_hash) VALUES ($1, $2, $3)")
        .bind(admin_id)
        .bind("admin@company.com")
        .bind("$argon2id$hash")
        .execute(&db.pool)
        .await
        .unwrap();
    println!("  1. ✓ Admin");

    // Document
    let doc_id = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO documents (id, name, filename, storage_path, size_bytes) VALUES ($1, $2, $3, $4, $5)")
        .bind(doc_id)
        .bind("Deck")
        .bind("deck.pdf")
        .bind("uploads/deck.pdf")
        .bind(5000_i64)
        .execute(&db.pool)
        .await
        .unwrap();
    println!("  2. ✓ Document");

    // Link
    let link_id = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO links (id, document_id, short_code, expires_at) VALUES ($1, $2, $3, $4)")
        .bind(link_id)
        .bind(doc_id)
        .bind("test123")
        .bind(chrono::Utc::now() + chrono::Duration::days(7))
        .execute(&db.pool)
        .await
        .unwrap();
    println!("  3. ✓ Link");

    // Token
    let token_id = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO access_tokens (id, link_id, email, token, expires_at, request_ip) VALUES ($1, $2, $3, $4, $5, $6)")
        .bind(token_id)
        .bind(link_id)
        .bind("test@vc.com")
        .bind("magic123")
        .bind(chrono::Utc::now() + chrono::Duration::hours(1))
        .bind("1.2.3.4")
        .execute(&db.pool)
        .await
        .unwrap();
    println!("  4. ✓ Token");

    // View
    sqlx::query("INSERT INTO views (id, access_token_id, email, ip, duration_secs, pages_viewed) VALUES ($1, $2, $3, $4, $5, $6)")
        .bind(uuid::Uuid::new_v4())
        .bind(token_id)
        .bind("test@vc.com")
        .bind("1.2.3.4")
        .bind(120)
        .bind(vec![1, 2, 3])
        .execute(&db.pool)
        .await
        .unwrap();
    println!("  5. ✓ View");

    // Query chain
    let row = sqlx::query(
        "SELECT d.name, l.short_code, v.duration_secs FROM views v
         JOIN access_tokens at ON v.access_token_id = at.id
         JOIN links l ON at.link_id = l.id
         JOIN documents d ON l.document_id = d.id"
    )
        .fetch_one(&db.pool)
        .await
        .unwrap();

    let name: String = row.get("name");
    let code: String = row.get("short_code");
    let dur: i32 = row.get("duration_secs");
    println!("  6. ✓ Query: doc={}, link={}, duration={}s", name, code, dur);

    assert_eq!(name, "Deck");
    assert_eq!(code, "test123");
    println!("\n  ✓ Full workflow passed\n");
}

/// Interactive: keeps container up 60 seconds for manual inspection
/// Run: cargo test test_interactive -- --nocapture --ignored
#[tokio::test]
#[ignore]
async fn test_interactive() {
    println!("\n============================================================");
    println!("INTERACTIVE: 60 second inspection window");
    println!("============================================================");

    let db = TestDb::new().await;
    println!("Connect to: postgres://postgres:postgres@{}:{}/postgres", db.host, db.port);
    println!("Sleeping 60 seconds...");
    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    println!("Done.");
}
