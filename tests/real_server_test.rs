//! Real Integration Tests - Spawns Actual Binary
//!
//! These tests:
//! 1. Start real PostgreSQL via testcontainers
//! 2. Spawn the actual docsend binary as a subprocess
//! 3. Make HTTP requests via reqwest
//! 4. Kill the server when done
//!
//! Run: cargo test --test real_server_test -- --nocapture --test-threads=1

mod common;

use common::TestDb;
use docsend::db;
use reqwest::Client;
use serde_json::{json, Value};
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::SaltString;

struct TestServer {
    child: Child,
    base_url: String,
    #[allow(dead_code)]
    test_db: TestDb,
}

impl TestServer {
    async fn start() -> Self {
        // Start ephemeral PostgreSQL
        let test_db = TestDb::new().await;

        // Read the real config.toml to get all required fields
        let real_config = std::fs::read_to_string("config.toml").expect("config.toml not found");
        
        // Replace database section with test DB settings
        let test_config = real_config
            .lines()
            .map(|line| {
                if line.starts_with("host = ") && real_config[..real_config.find(line).unwrap()].ends_with("[database]\n") {
                    format!("host = \"{}\"", test_db.host)
                } else if line.starts_with("port = ") && real_config[..real_config.find(line).unwrap()].contains("[database]") {
                    format!("port = {}", test_db.port)
                } else if line.starts_with("user = ") {
                    "user = \"postgres\"".to_string()
                } else if line.starts_with("database = ") {
                    "database = \"postgres\"".to_string()
                } else if line.starts_with("port = 8080") {
                    "port = 19080".to_string()
                } else if line.starts_with("upload_dir = ") {
                    "upload_dir = \"/tmp/docsend_test_uploads\"".to_string()
                } else {
                    line.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n");

        let config_path = "/tmp/docsend_test_config.toml";
        std::fs::write(config_path, test_config).expect("Failed to write test config");

        // Create upload dir
        let _ = std::fs::create_dir_all("/tmp/docsend_test_uploads");

        // Build the binary first
        println!("  → Building binary...");
        let build_status = Command::new("cargo")
            .args(["build", "--bin", "docsend"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("Failed to build");

        if !build_status.success() {
            panic!("Failed to build docsend binary");
        }

        // Spawn the actual binary
        println!("  → Starting server...");
        let child = Command::new("cargo")
            .args(["run", "--bin", "docsend"])
            .env("CONFIG_PATH", config_path)
            .env("DB_PASSWORD", "postgres")
            .env("JWT_SECRET", "test_jwt_secret_key_for_testing_12345")
            .env("RESEND_API_KEY", "test_resend_api_key")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("Failed to spawn server");

        let base_url = "http://127.0.0.1:19080".to_string();

        // Poll health endpoint until server is ready
        let client = Client::new();
        for i in 0..50 {
            tokio::time::sleep(Duration::from_millis(200)).await;
            if let Ok(resp) = client.get(format!("{}/health", base_url))
                .timeout(Duration::from_millis(500))
                .send()
                .await
            {
                if resp.status().is_success() {
                    println!("  ✓ Server ready at {} (took {}ms)", base_url, (i + 1) * 200);
                    return Self { child, base_url, test_db };
                }
            }
        }

        panic!("Server failed to start after 10 seconds");
    }

    fn pool(&self) -> &sqlx::PgPool {
        &self.test_db.pool
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        println!("  → Stopping server...");
        let _ = self.child.kill();
        let _ = self.child.wait();
        println!("  ✓ Server stopped");
    }
}

fn hash_password(password: &str) -> String {
    let salt = SaltString::generate(&mut rand::thread_rng());
    let argon2 = Argon2::default();
    argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string()
}

// ============================================================================
// Tests
// ============================================================================

#[tokio::test]
async fn test_real_server_health() {
    println!("\n=== test_real_server_health ===");
    let server = TestServer::start().await;

    let client = Client::new();
    let resp = client.get(format!("{}/health", server.base_url))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "ok");
    println!("  ✓ GET /health returns 200");
}

#[tokio::test]
async fn test_real_server_admin_login() {
    println!("\n=== test_real_server_admin_login ===");
    let server = TestServer::start().await;

    // Create admin in database
    let password = "test_password_123";
    let hash = hash_password(password);
    db::create_admin(server.pool(), "admin@test.com", &hash).await.unwrap();
    println!("  ✓ Created admin in DB");

    let client = Client::new();

    // Test successful login
    let resp = client.post(format!("{}/api/admin/login", server.base_url))
        .json(&json!({
            "email": "admin@test.com",
            "password": password
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["token"].as_str().is_some());
    println!("  ✓ POST /api/admin/login returns token");

    // Test failed login
    let resp = client.post(format!("{}/api/admin/login", server.base_url))
        .json(&json!({
            "email": "admin@test.com",
            "password": "wrong_password"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
    println!("  ✓ POST /api/admin/login with wrong password returns 401");
}

#[tokio::test]
async fn test_real_server_documents_crud() {
    println!("\n=== test_real_server_documents_crud ===");
    let server = TestServer::start().await;

    // Create admin and login
    let password = "test_password_123";
    let hash = hash_password(password);
    db::create_admin(server.pool(), "admin@test.com", &hash).await.unwrap();

    let client = Client::new();
    let resp = client.post(format!("{}/api/admin/login", server.base_url))
        .json(&json!({"email": "admin@test.com", "password": password}))
        .send()
        .await
        .unwrap();
    let token = resp.json::<Value>().await.unwrap()["token"].as_str().unwrap().to_string();
    println!("  ✓ Logged in");

    // List documents (empty)
    let resp = client.get(format!("{}/api/admin/documents", server.base_url))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let docs: Vec<Value> = resp.json().await.unwrap();
    assert_eq!(docs.len(), 0);
    println!("  ✓ GET /api/admin/documents returns empty list");

    // Upload document
    let form = reqwest::multipart::Form::new()
        .text("name", "Test Document")
        .part("file", reqwest::multipart::Part::bytes(b"PDF content here".to_vec())
            .file_name("test.pdf")
            .mime_str("application/pdf").unwrap());

    let resp = client.post(format!("{}/api/admin/documents", server.base_url))
        .header("Authorization", format!("Bearer {}", token))
        .multipart(form)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let doc: Value = resp.json().await.unwrap();
    let doc_id = doc["id"].as_str().unwrap();
    println!("  ✓ POST /api/admin/documents uploads document: {}", doc_id);

    // List documents (one)
    let resp = client.get(format!("{}/api/admin/documents", server.base_url))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();
    let docs: Vec<Value> = resp.json().await.unwrap();
    assert_eq!(docs.len(), 1);
    println!("  ✓ GET /api/admin/documents returns 1 document");

    // Delete document
    let resp = client.delete(format!("{}/api/admin/documents/{}", server.base_url, doc_id))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    println!("  ✓ DELETE /api/admin/documents/{} succeeds", doc_id);
}

#[tokio::test]
async fn test_real_server_links_crud() {
    println!("\n=== test_real_server_links_crud ===");
    let server = TestServer::start().await;

    // Setup
    let password = "test_password_123";
    let hash = hash_password(password);
    db::create_admin(server.pool(), "admin@test.com", &hash).await.unwrap();
    let doc = db::create_document(server.pool(), "Test Doc", "test.pdf", "/test.pdf", 100).await.unwrap();

    let client = Client::new();
    let resp = client.post(format!("{}/api/admin/login", server.base_url))
        .json(&json!({"email": "admin@test.com", "password": password}))
        .send()
        .await
        .unwrap();
    let token = resp.json::<Value>().await.unwrap()["token"].as_str().unwrap().to_string();
    println!("  ✓ Logged in");

    // Create link
    let resp = client.post(format!("{}/api/admin/links", server.base_url))
        .header("Authorization", format!("Bearer {}", token))
        .json(&json!({
            "document_id": doc.id.to_string(),
            "expires_in_days": 7
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let link: Value = resp.json().await.unwrap();
    let link_id = link["id"].as_str().unwrap();
    println!("  ✓ POST /api/admin/links creates link: {}", link_id);

    // List links
    let resp = client.get(format!("{}/api/admin/links", server.base_url))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();
    let links: Vec<Value> = resp.json().await.unwrap();
    assert_eq!(links.len(), 1);
    println!("  ✓ GET /api/admin/links returns 1 link");

    // Revoke link
    let resp = client.post(format!("{}/api/admin/links/{}/revoke", server.base_url, link_id))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    println!("  ✓ POST /api/admin/links/{}/revoke succeeds", link_id);
}

#[tokio::test]
async fn test_real_server_stats() {
    println!("\n=== test_real_server_stats ===");
    let server = TestServer::start().await;

    // Setup
    let password = "test_password_123";
    let hash = hash_password(password);
    db::create_admin(server.pool(), "admin@test.com", &hash).await.unwrap();

    let client = Client::new();
    let resp = client.post(format!("{}/api/admin/login", server.base_url))
        .json(&json!({"email": "admin@test.com", "password": password}))
        .send()
        .await
        .unwrap();
    let token = resp.json::<Value>().await.unwrap()["token"].as_str().unwrap().to_string();

    // Get stats (empty)
    let resp = client.get(format!("{}/api/admin/stats", server.base_url))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let stats: Value = resp.json().await.unwrap();
    assert_eq!(stats["total_docs"], 0);
    println!("  ✓ GET /api/admin/stats returns zeros");

    // Add document
    db::create_document(server.pool(), "Test", "test.pdf", "/test.pdf", 100).await.unwrap();

    // Get stats again
    let resp = client.get(format!("{}/api/admin/stats", server.base_url))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();
    let stats: Value = resp.json().await.unwrap();
    assert_eq!(stats["total_docs"], 1);
    println!("  ✓ GET /api/admin/stats shows 1 document");
}

#[tokio::test]
async fn test_real_server_views_endpoint() {
    println!("\n=== test_real_server_views_endpoint ===");
    let server = TestServer::start().await;

    // Setup
    let password = "test_password_123";
    let hash = hash_password(password);
    db::create_admin(server.pool(), "admin@test.com", &hash).await.unwrap();

    let client = Client::new();
    let resp = client.post(format!("{}/api/admin/login", server.base_url))
        .json(&json!({"email": "admin@test.com", "password": password}))
        .send()
        .await
        .unwrap();
    let token = resp.json::<Value>().await.unwrap()["token"].as_str().unwrap().to_string();

    // List views (empty)
    let resp = client.get(format!("{}/api/admin/views", server.base_url))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let views: Vec<Value> = resp.json().await.unwrap();
    assert_eq!(views.len(), 0);
    println!("  ✓ GET /api/admin/views returns empty list");
}

#[tokio::test]
async fn test_real_server_admin_login_invalid() {
    println!("\n=== test_real_server_admin_login_invalid ===");
    let server = TestServer::start().await;

    let client = Client::new();

    // Non-existent user
    let resp = client.post(format!("{}/api/admin/login", server.base_url))
        .json(&json!({
            "email": "nobody@test.com",
            "password": "whatever"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    println!("  ✓ POST /api/admin/login with non-existent user returns 401");

    // Create admin but use wrong password
    let password = "correct_password";
    let hash = hash_password(password);
    db::create_admin(server.pool(), "admin@test.com", &hash).await.unwrap();

    let resp = client.post(format!("{}/api/admin/login", server.base_url))
        .json(&json!({
            "email": "admin@test.com",
            "password": "wrong_password"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    println!("  ✓ POST /api/admin/login with wrong password returns 401");
}

#[tokio::test]
async fn test_real_server_blocklist_crud() {
    println!("\n=== test_real_server_blocklist_crud ===");
    let server = TestServer::start().await;

    // Setup
    let password = "test_password_123";
    let hash = hash_password(password);
    db::create_admin(server.pool(), "admin@test.com", &hash).await.unwrap();

    let client = Client::new();
    let resp = client.post(format!("{}/api/admin/login", server.base_url))
        .json(&json!({"email": "admin@test.com", "password": password}))
        .send()
        .await
        .unwrap();
    let token = resp.json::<Value>().await.unwrap()["token"].as_str().unwrap().to_string();

    // Add to blocklist
    let resp = client.post(format!("{}/api/admin/blocklist", server.base_url))
        .header("Authorization", format!("Bearer {}", token))
        .json(&json!({"domain": "blocked.com"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    println!("  ✓ POST /api/admin/blocklist adds domain");

    // List blocklist
    let resp = client.get(format!("{}/api/admin/blocklist", server.base_url))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();
    let entries: Vec<Value> = resp.json().await.unwrap();
    assert_eq!(entries.len(), 1);
    println!("  ✓ GET /api/admin/blocklist returns 1 entry");

    // Remove from blocklist
    let resp = client.delete(format!("{}/api/admin/blocklist/blocked.com", server.base_url))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    println!("  ✓ DELETE /api/admin/blocklist/blocked.com succeeds");
}

#[tokio::test]
async fn test_real_server_unauthorized() {
    println!("\n=== test_real_server_unauthorized ===");
    let server = TestServer::start().await;

    let client = Client::new();

    // No auth header
    let resp = client.get(format!("{}/api/admin/documents", server.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    println!("  ✓ GET /api/admin/documents without auth returns 401");

    // Bad token
    let resp = client.get(format!("{}/api/admin/documents", server.base_url))
        .header("Authorization", "Bearer invalid_token")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    println!("  ✓ GET /api/admin/documents with bad token returns 401");
}

#[tokio::test]
async fn test_real_server_full_workflow() {
    println!("\n=== test_real_server_full_workflow ===");
    let server = TestServer::start().await;

    // Setup admin
    let password = "admin_password_123";
    let hash = hash_password(password);
    db::create_admin(server.pool(), "admin@company.com", &hash).await.unwrap();

    let client = Client::new();

    println!("  Step 1: Admin logs in");
    let resp = client.post(format!("{}/api/admin/login", server.base_url))
        .json(&json!({"email": "admin@company.com", "password": password}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let token = resp.json::<Value>().await.unwrap()["token"].as_str().unwrap().to_string();
    println!("    ✓ Got auth token");

    println!("  Step 2: Admin uploads pitch deck");
    let form = reqwest::multipart::Form::new()
        .text("name", "Q4 Pitch Deck")
        .part("file", reqwest::multipart::Part::bytes(b"PDF content".to_vec())
            .file_name("pitch.pdf")
            .mime_str("application/pdf").unwrap());

    let resp = client.post(format!("{}/api/admin/documents", server.base_url))
        .header("Authorization", format!("Bearer {}", token))
        .multipart(form)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let doc: Value = resp.json().await.unwrap();
    let doc_id = doc["id"].as_str().unwrap();
    println!("    ✓ Uploaded document: {}", doc_id);

    println!("  Step 3: Admin creates shareable link");
    let resp = client.post(format!("{}/api/admin/links", server.base_url))
        .header("Authorization", format!("Bearer {}", token))
        .json(&json!({
            "document_id": doc_id,
            "expires_in_days": 30
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let link: Value = resp.json().await.unwrap();
    let link_id = link["id"].as_str().unwrap();
    let short_code = link["short_code"].as_str().unwrap();
    println!("    ✓ Created link: /d/{}", short_code);

    println!("  Step 4: Admin checks stats");
    let resp = client.get(format!("{}/api/admin/stats", server.base_url))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();
    let stats: Value = resp.json().await.unwrap();
    assert_eq!(stats["total_docs"], 1);
    assert_eq!(stats["total_links"], 1);
    println!("    ✓ Stats: {} doc, {} link", stats["total_docs"], stats["total_links"]);

    println!("  Step 5: Admin blocks competitor domain");
    let resp = client.post(format!("{}/api/admin/blocklist", server.base_url))
        .header("Authorization", format!("Bearer {}", token))
        .json(&json!({"domain": "competitor.com"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    println!("    ✓ Blocked competitor.com");

    println!("  Step 6: Admin revokes link");
    let resp = client.post(format!("{}/api/admin/links/{}/revoke", server.base_url, link_id))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    println!("    ✓ Link revoked");

    println!("\n  ✓ Full workflow completed with REAL server!\n");
}
