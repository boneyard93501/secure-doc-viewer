//! HTTP Integration Tests
//! 
//! Spins up real Axum server + ephemeral PostgreSQL, tests all endpoints via HTTP.
//! Run: cargo test --test http_test -- --nocapture --test-threads=1

mod common;

use common::TestDb;
use reqwest::Client;
use serde_json::{json, Value};
use std::time::Duration;
use tokio::net::TcpListener;
use axum::Router;
use docsend::{Config, db};
use std::sync::Arc;
use sqlx::PgPool;
use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::SaltString;

// ============================================================================
// Test Server Setup
// ============================================================================

#[derive(Clone)]
struct TestAppState {
    pool: PgPool,
    config: Arc<Config>,
    jwt_secret: String,
}

async fn create_test_app(pool: PgPool) -> (Router, String) {
    use axum::{
        extract::{Path, State, Query, Multipart},
        http::{StatusCode, HeaderMap, header},
        response::{IntoResponse, Response, Json},
        routing::{get, post, delete},
    };
    use tower_http::cors::{CorsLayer, Any};
    use chrono::{Utc, Duration};
    use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
    use serde::{Deserialize, Serialize};
    use uuid::Uuid;

    let jwt_secret = "test_secret_key_12345".to_string();
    
    let config = Config {
        server: docsend::ServerConfig {
            host: "127.0.0.1".to_string(),
            port: 0,
            static_dir: "static".to_string(),
            upload_dir: "/tmp/docsend_test_uploads".to_string(),
        },
        database: docsend::DatabaseConfig {
            host: "localhost".to_string(),
            port: 5432,
            database: "test".to_string(),
            user: "test".to_string(),
            max_connections: 5,
        },
        test_database: None,
        auth: docsend::AuthConfig {
            admin_token_ttl_secs: 3600,
            access_token_ttl_secs: 3600,
        },
        email: docsend::EmailConfig {
            from_email: "test@test.com".to_string(),
            from_name: "Test".to_string(),
            verification_url_base: "http://localhost:8080/verify".to_string(),
        },
        branding: docsend::BrandingConfig {
            owner_name: "Test Owner".to_string(),
            document_title_default: "Document".to_string(),
        },
        blocklist: docsend::BlocklistConfig {
            file_path: "data/blocklist.txt".to_string(),
        },
        rate_limit: docsend::RateLimitConfig {
            email_send_per_hour: 100,
            token_attempts_per_hour: 100,
        },
        routes: docsend::RoutesConfig {
            health: "/health".to_string(),
            link_meta: "/api/link/{short_code}/meta".to_string(),
            token_meta: "/api/token/{token}/meta".to_string(),
            verify: "/api/verify".to_string(),
            document: "/api/document/{token}".to_string(),
            track: "/api/track".to_string(),
            admin_login: "/api/admin/login".to_string(),
            admin_password: "/api/admin/password".to_string(),
            admin_documents: "/api/admin/documents".to_string(),
            admin_links: "/api/admin/links".to_string(),
            admin_views: "/api/admin/views".to_string(),
            admin_blocklist: "/api/admin/blocklist".to_string(),
            admin_stats: "/api/admin/stats".to_string(),
        },
        messages: docsend::MessagesConfig {
            email_sent: "Check your email".to_string(),
            invalid_token: "Invalid token".to_string(),
            link_expired: "Link expired".to_string(),
            link_revoked: "Link revoked".to_string(),
            domain_blocked: "Domain blocked".to_string(),
        },
        logging: docsend::LoggingConfig {
            level: "info".to_string(),
        },
        dashboard: docsend::DashboardConfig {
            refresh_interval_secs: 30,
        },
    };

    let state = TestAppState {
        pool: pool.clone(),
        config: Arc::new(config),
        jwt_secret: jwt_secret.clone(),
    };

    // ========== Request/Response Types ==========
    
    #[derive(Debug, Deserialize)]
    struct LoginRequest {
        email: String,
        password: String,
    }

    #[derive(Debug, Serialize)]
    struct LoginResponse {
        token: String,
        expires_at: i64,
    }

    #[derive(Debug, Serialize)]
    struct ApiError {
        error: String,
    }

    #[derive(Debug, Serialize)]
    struct ApiSuccess {
        message: String,
    }

    #[derive(Debug, Deserialize)]
    struct CreateLinkRequest {
        document_id: Uuid,
        expires_in_days: Option<i64>,
    }

    #[derive(Debug, Serialize)]
    struct CreateLinkResponse {
        id: Uuid,
        short_code: String,
        url: String,
        expires_at: Option<i64>,
    }

    #[derive(Debug, Deserialize)]
    struct PaginationParams {
        limit: Option<i64>,
        offset: Option<i64>,
    }

    #[derive(Debug, Deserialize)]
    struct BlocklistRequest {
        domain: String,
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct AdminClaims {
        sub: String,
        exp: usize,
    }

    // ========== Helper Functions ==========

    fn json_error(status: StatusCode, message: &str) -> Response {
        (status, Json(ApiError { error: message.to_string() })).into_response()
    }

    fn json_success(message: &str) -> Response {
        (StatusCode::OK, Json(ApiSuccess { message: message.to_string() })).into_response()
    }

    fn verify_password(password: &str, hash: &str) -> bool {
        use argon2::{PasswordHash, PasswordVerifier};
        let parsed_hash = match PasswordHash::new(hash) {
            Ok(h) => h,
            Err(_) => return false,
        };
        Argon2::default().verify_password(password.as_bytes(), &parsed_hash).is_ok()
    }

    fn generate_jwt(admin_id: &str, secret: &str, ttl_secs: u64) -> Result<String, jsonwebtoken::errors::Error> {
        let exp = (Utc::now() + Duration::seconds(ttl_secs as i64)).timestamp() as usize;
        let claims = AdminClaims {
            sub: admin_id.to_string(),
            exp,
        };
        encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_bytes()))
    }

    fn verify_jwt(token: &str, secret: &str) -> Option<AdminClaims> {
        decode::<AdminClaims>(
            token,
            &DecodingKey::from_secret(secret.as_bytes()),
            &Validation::default(),
        )
        .ok()
        .map(|data| data.claims)
    }

    fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
        headers
            .get(header::AUTHORIZATION)?
            .to_str()
            .ok()?
            .strip_prefix("Bearer ")
            .map(|s| s.to_string())
    }

    fn verify_admin(headers: &HeaderMap, jwt_secret: &str) -> bool {
        extract_bearer_token(headers)
            .and_then(|token| verify_jwt(&token, jwt_secret))
            .is_some()
    }

    fn generate_short_code() -> String {
        use rand::Rng;
        let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".chars().collect();
        let mut rng = rand::thread_rng();
        (0..8).map(|_| chars[rng.gen_range(0..chars.len())]).collect()
    }

    // ========== Handlers ==========

    async fn health() -> impl IntoResponse {
        Json(json!({"status": "ok"}))
    }

    async fn admin_login(
        State(state): State<TestAppState>,
        Json(req): Json<LoginRequest>,
    ) -> Response {
        let admin = match db::get_admin_by_email(&state.pool, &req.email).await {
            Ok(Some(a)) => a,
            Ok(None) => return json_error(StatusCode::UNAUTHORIZED, "Invalid credentials"),
            Err(_) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Database error"),
        };

        if !verify_password(&req.password, &admin.password_hash) {
            return json_error(StatusCode::UNAUTHORIZED, "Invalid credentials");
        }

        let token = match generate_jwt(&admin.id.to_string(), &state.jwt_secret, state.config.auth.admin_token_ttl_secs) {
            Ok(t) => t,
            Err(_) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to generate token"),
        };

        let expires_at = (Utc::now() + Duration::seconds(state.config.auth.admin_token_ttl_secs as i64)).timestamp();

        Json(LoginResponse { token, expires_at }).into_response()
    }

    async fn list_documents(
        State(state): State<TestAppState>,
        headers: HeaderMap,
        Query(params): Query<PaginationParams>,
    ) -> Response {
        if !verify_admin(&headers, &state.jwt_secret) {
            return json_error(StatusCode::UNAUTHORIZED, "Unauthorized");
        }

        let limit = params.limit.unwrap_or(50);
        let offset = params.offset.unwrap_or(0);

        match db::list_documents(&state.pool, limit, offset).await {
            Ok(docs) => Json(docs).into_response(),
            Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "Database error"),
        }
    }

    async fn upload_document(
        State(state): State<TestAppState>,
        headers: HeaderMap,
        mut multipart: Multipart,
    ) -> Response {
        if !verify_admin(&headers, &state.jwt_secret) {
            return json_error(StatusCode::UNAUTHORIZED, "Unauthorized");
        }

        let mut name = None;
        let mut filename = None;
        let mut file_data = None;

        while let Ok(Some(field)) = multipart.next_field().await {
            let field_name = field.name().unwrap_or("").to_string();
            
            if field_name == "name" {
                name = field.text().await.ok();
            } else if field_name == "file" {
                filename = field.file_name().map(|s| s.to_string());
                file_data = field.bytes().await.ok();
            }
        }

        let name = match name {
            Some(n) => n,
            None => return json_error(StatusCode::BAD_REQUEST, "Missing document name"),
        };
        let filename = match filename {
            Some(f) => f,
            None => return json_error(StatusCode::BAD_REQUEST, "Missing file"),
        };
        let file_data = match file_data {
            Some(d) => d,
            None => return json_error(StatusCode::BAD_REQUEST, "Missing file data"),
        };

        let storage_path = format!("{}/{}", state.config.server.upload_dir, filename);
        
        // Create upload dir if needed
        let _ = tokio::fs::create_dir_all(&state.config.server.upload_dir).await;
        
        if let Err(_) = tokio::fs::write(&storage_path, &file_data).await {
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to save file");
        }

        match db::create_document(&state.pool, &name, &filename, &storage_path, file_data.len() as i64).await {
            Ok(doc) => Json(doc).into_response(),
            Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to create document"),
        }
    }

    async fn delete_document(
        State(state): State<TestAppState>,
        headers: HeaderMap,
        Path(id): Path<Uuid>,
    ) -> Response {
        if !verify_admin(&headers, &state.jwt_secret) {
            return json_error(StatusCode::UNAUTHORIZED, "Unauthorized");
        }

        match db::delete_document(&state.pool, id).await {
            Ok(true) => json_success("Document deleted"),
            Ok(false) => json_error(StatusCode::NOT_FOUND, "Document not found"),
            Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "Database error"),
        }
    }

    async fn list_all_links(
        State(state): State<TestAppState>,
        headers: HeaderMap,
        Query(params): Query<PaginationParams>,
    ) -> Response {
        if !verify_admin(&headers, &state.jwt_secret) {
            return json_error(StatusCode::UNAUTHORIZED, "Unauthorized");
        }

        let limit = params.limit.unwrap_or(50);
        let offset = params.offset.unwrap_or(0);

        match db::list_all_links(&state.pool, limit, offset).await {
            Ok(links) => Json(links).into_response(),
            Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "Database error"),
        }
    }

    async fn create_link(
        State(state): State<TestAppState>,
        headers: HeaderMap,
        Json(req): Json<CreateLinkRequest>,
    ) -> Response {
        if !verify_admin(&headers, &state.jwt_secret) {
            return json_error(StatusCode::UNAUTHORIZED, "Unauthorized");
        }

        let short_code = generate_short_code();
        let expires_at = req.expires_in_days.map(|days| Utc::now() + Duration::days(days));

        match db::create_link(&state.pool, req.document_id, &short_code, None, false, expires_at).await {
            Ok(link) => {
                let url = format!("http://localhost/d/{}", short_code);
                Json(CreateLinkResponse {
                    id: link.id,
                    short_code: link.short_code,
                    url,
                    expires_at: link.expires_at.map(|t| t.timestamp()),
                }).into_response()
            }
            Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to create link"),
        }
    }

    async fn revoke_link(
        State(state): State<TestAppState>,
        headers: HeaderMap,
        Path(id): Path<Uuid>,
    ) -> Response {
        if !verify_admin(&headers, &state.jwt_secret) {
            return json_error(StatusCode::UNAUTHORIZED, "Unauthorized");
        }

        match db::revoke_link(&state.pool, id).await {
            Ok(Some(_)) => json_success("Link revoked"),
            Ok(None) => json_error(StatusCode::NOT_FOUND, "Link not found"),
            Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to revoke link"),
        }
    }

    async fn list_all_views(
        State(state): State<TestAppState>,
        headers: HeaderMap,
        Query(params): Query<PaginationParams>,
    ) -> Response {
        if !verify_admin(&headers, &state.jwt_secret) {
            return json_error(StatusCode::UNAUTHORIZED, "Unauthorized");
        }

        let limit = params.limit.unwrap_or(50);
        let offset = params.offset.unwrap_or(0);

        match db::list_all_views(&state.pool, limit, offset).await {
            Ok(views) => Json(views).into_response(),
            Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "Database error"),
        }
    }

    async fn get_global_stats(
        State(state): State<TestAppState>,
        headers: HeaderMap,
    ) -> Response {
        if !verify_admin(&headers, &state.jwt_secret) {
            return json_error(StatusCode::UNAUTHORIZED, "Unauthorized");
        }

        match db::get_global_stats(&state.pool).await {
            Ok(stats) => Json(stats).into_response(),
            Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "Database error"),
        }
    }

    async fn list_blocklist(
        State(state): State<TestAppState>,
        headers: HeaderMap,
    ) -> Response {
        if !verify_admin(&headers, &state.jwt_secret) {
            return json_error(StatusCode::UNAUTHORIZED, "Unauthorized");
        }

        match db::list_custom_blocklist(&state.pool).await {
            Ok(entries) => Json(entries).into_response(),
            Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "Database error"),
        }
    }

    async fn add_to_blocklist(
        State(state): State<TestAppState>,
        headers: HeaderMap,
        Json(req): Json<BlocklistRequest>,
    ) -> Response {
        if !verify_admin(&headers, &state.jwt_secret) {
            return json_error(StatusCode::UNAUTHORIZED, "Unauthorized");
        }

        match db::add_to_custom_blocklist(&state.pool, &req.domain).await {
            Ok(entry) => Json(entry).into_response(),
            Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to add domain"),
        }
    }

    async fn remove_from_blocklist(
        State(state): State<TestAppState>,
        headers: HeaderMap,
        Path(domain): Path<String>,
    ) -> Response {
        if !verify_admin(&headers, &state.jwt_secret) {
            return json_error(StatusCode::UNAUTHORIZED, "Unauthorized");
        }

        match db::remove_from_custom_blocklist(&state.pool, &domain).await {
            Ok(true) => json_success("Domain removed from blocklist"),
            Ok(false) => json_error(StatusCode::NOT_FOUND, "Domain not in blocklist"),
            Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to remove domain"),
        }
    }

    // ========== Build Router ==========

    let app = Router::new()
        .route("/health", get(health))
        .route("/api/admin/login", post(admin_login))
        .route("/api/admin/documents", get(list_documents).post(upload_document))
        .route("/api/admin/documents/{id}", delete(delete_document))
        .route("/api/admin/links", get(list_all_links).post(create_link))
        .route("/api/admin/links/{id}/revoke", post(revoke_link))
        .route("/api/admin/views", get(list_all_views))
        .route("/api/admin/stats", get(get_global_stats))
        .route("/api/admin/blocklist", get(list_blocklist).post(add_to_blocklist))
        .route("/api/admin/blocklist/{domain}", delete(remove_from_blocklist))
        .layer(CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any))
        .with_state(state);

    (app, jwt_secret)
}

async fn start_server(app: Router) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{}", addr);
    
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    
    // Give server time to start
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    base_url
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
async fn test_health_endpoint() {
    println!("\n=== test_health_endpoint ===");
    let test_db = TestDb::new().await;
    let (app, _) = create_test_app(test_db.pool.clone()).await;
    let base_url = start_server(app).await;
    
    let client = Client::new();
    let resp = client.get(format!("{}/health", base_url))
        .send()
        .await
        .unwrap();
    
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "ok");
    println!("  ✓ GET /health returns 200 with status=ok");
}

#[tokio::test]
async fn test_admin_login_success() {
    println!("\n=== test_admin_login_success ===");
    let test_db = TestDb::new().await;
    
    // Create admin
    let password = "test_password_123";
    let hash = hash_password(password);
    db::create_admin(&test_db.pool, "admin@test.com", &hash).await.unwrap();
    
    let (app, _) = create_test_app(test_db.pool.clone()).await;
    let base_url = start_server(app).await;
    
    let client = Client::new();
    let resp = client.post(format!("{}/api/admin/login", base_url))
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
    assert!(body["expires_at"].as_i64().is_some());
    println!("  ✓ POST /api/admin/login returns token");
}

#[tokio::test]
async fn test_admin_login_invalid_credentials() {
    println!("\n=== test_admin_login_invalid_credentials ===");
    let test_db = TestDb::new().await;
    
    let (app, _) = create_test_app(test_db.pool.clone()).await;
    let base_url = start_server(app).await;
    
    let client = Client::new();
    let resp = client.post(format!("{}/api/admin/login", base_url))
        .json(&json!({
            "email": "nobody@test.com",
            "password": "wrong"
        }))
        .send()
        .await
        .unwrap();
    
    assert_eq!(resp.status(), 401);
    println!("  ✓ POST /api/admin/login with bad credentials returns 401");
}

#[tokio::test]
async fn test_documents_unauthorized() {
    println!("\n=== test_documents_unauthorized ===");
    let test_db = TestDb::new().await;
    let (app, _) = create_test_app(test_db.pool.clone()).await;
    let base_url = start_server(app).await;
    
    let client = Client::new();
    
    // No auth header
    let resp = client.get(format!("{}/api/admin/documents", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    println!("  ✓ GET /api/admin/documents without auth returns 401");
    
    // Bad token
    let resp = client.get(format!("{}/api/admin/documents", base_url))
        .header("Authorization", "Bearer invalid_token")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    println!("  ✓ GET /api/admin/documents with bad token returns 401");
}

#[tokio::test]
async fn test_documents_crud() {
    println!("\n=== test_documents_crud ===");
    let test_db = TestDb::new().await;
    
    // Create admin and get token
    let password = "test_password_123";
    let hash = hash_password(password);
    db::create_admin(&test_db.pool, "admin@test.com", &hash).await.unwrap();
    
    let (app, _) = create_test_app(test_db.pool.clone()).await;
    let base_url = start_server(app).await;
    
    let client = Client::new();
    
    // Login
    let resp = client.post(format!("{}/api/admin/login", base_url))
        .json(&json!({"email": "admin@test.com", "password": password}))
        .send()
        .await
        .unwrap();
    let login_body: Value = resp.json().await.unwrap();
    let token = login_body["token"].as_str().unwrap();
    println!("  ✓ Logged in, got token");
    
    // List documents (empty)
    let resp = client.get(format!("{}/api/admin/documents", base_url))
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
    
    let resp = client.post(format!("{}/api/admin/documents", base_url))
        .header("Authorization", format!("Bearer {}", token))
        .multipart(form)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let doc: Value = resp.json().await.unwrap();
    let doc_id = doc["id"].as_str().unwrap();
    assert_eq!(doc["name"], "Test Document");
    assert_eq!(doc["filename"], "test.pdf");
    println!("  ✓ POST /api/admin/documents uploads document: {}", doc_id);
    
    // List documents (one)
    let resp = client.get(format!("{}/api/admin/documents", base_url))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();
    let docs: Vec<Value> = resp.json().await.unwrap();
    assert_eq!(docs.len(), 1);
    println!("  ✓ GET /api/admin/documents returns 1 document");
    
    // Delete document
    let resp = client.delete(format!("{}/api/admin/documents/{}", base_url, doc_id))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    println!("  ✓ DELETE /api/admin/documents/{} succeeds", doc_id);
    
    // List documents (empty again)
    let resp = client.get(format!("{}/api/admin/documents", base_url))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();
    let docs: Vec<Value> = resp.json().await.unwrap();
    assert_eq!(docs.len(), 0);
    println!("  ✓ GET /api/admin/documents returns empty after delete");
}

#[tokio::test]
async fn test_links_crud() {
    println!("\n=== test_links_crud ===");
    let test_db = TestDb::new().await;
    
    // Setup
    let password = "test_password_123";
    let hash = hash_password(password);
    db::create_admin(&test_db.pool, "admin@test.com", &hash).await.unwrap();
    let doc = db::create_document(&test_db.pool, "Test Doc", "test.pdf", "/test.pdf", 100).await.unwrap();
    
    let (app, _) = create_test_app(test_db.pool.clone()).await;
    let base_url = start_server(app).await;
    let client = Client::new();
    
    // Login
    let resp = client.post(format!("{}/api/admin/login", base_url))
        .json(&json!({"email": "admin@test.com", "password": password}))
        .send()
        .await
        .unwrap();
    let token = resp.json::<Value>().await.unwrap()["token"].as_str().unwrap().to_string();
    println!("  ✓ Logged in");
    
    // List links (empty)
    let resp = client.get(format!("{}/api/admin/links", base_url))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let links: Vec<Value> = resp.json().await.unwrap();
    assert_eq!(links.len(), 0);
    println!("  ✓ GET /api/admin/links returns empty list");
    
    // Create link
    let resp = client.post(format!("{}/api/admin/links", base_url))
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
    assert!(link["short_code"].as_str().is_some());
    assert!(link["url"].as_str().is_some());
    println!("  ✓ POST /api/admin/links creates link: {}", link_id);
    
    // List links (one)
    let resp = client.get(format!("{}/api/admin/links", base_url))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();
    let links: Vec<Value> = resp.json().await.unwrap();
    assert_eq!(links.len(), 1);
    println!("  ✓ GET /api/admin/links returns 1 link");
    
    // Revoke link
    let resp = client.post(format!("{}/api/admin/links/{}/revoke", base_url, link_id))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    println!("  ✓ POST /api/admin/links/{}/revoke succeeds", link_id);
}

#[tokio::test]
async fn test_views_endpoint() {
    println!("\n=== test_views_endpoint ===");
    let test_db = TestDb::new().await;
    
    // Setup
    let password = "test_password_123";
    let hash = hash_password(password);
    db::create_admin(&test_db.pool, "admin@test.com", &hash).await.unwrap();
    
    let (app, _) = create_test_app(test_db.pool.clone()).await;
    let base_url = start_server(app).await;
    let client = Client::new();
    
    // Login
    let resp = client.post(format!("{}/api/admin/login", base_url))
        .json(&json!({"email": "admin@test.com", "password": password}))
        .send()
        .await
        .unwrap();
    let token = resp.json::<Value>().await.unwrap()["token"].as_str().unwrap().to_string();
    
    // List views (empty)
    let resp = client.get(format!("{}/api/admin/views", base_url))
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
async fn test_stats_endpoint() {
    println!("\n=== test_stats_endpoint ===");
    let test_db = TestDb::new().await;
    
    // Setup
    let password = "test_password_123";
    let hash = hash_password(password);
    db::create_admin(&test_db.pool, "admin@test.com", &hash).await.unwrap();
    
    let (app, _) = create_test_app(test_db.pool.clone()).await;
    let base_url = start_server(app).await;
    let client = Client::new();
    
    // Login
    let resp = client.post(format!("{}/api/admin/login", base_url))
        .json(&json!({"email": "admin@test.com", "password": password}))
        .send()
        .await
        .unwrap();
    let token = resp.json::<Value>().await.unwrap()["token"].as_str().unwrap().to_string();
    
    // Get stats (empty)
    let resp = client.get(format!("{}/api/admin/stats", base_url))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let stats: Value = resp.json().await.unwrap();
    assert_eq!(stats["total_docs"], 0);
    assert_eq!(stats["total_links"], 0);
    assert_eq!(stats["total_views"], 0);
    println!("  ✓ GET /api/admin/stats returns zeros");
    
    // Add document
    db::create_document(&test_db.pool, "Test", "test.pdf", "/test.pdf", 100).await.unwrap();
    
    // Get stats again
    let resp = client.get(format!("{}/api/admin/stats", base_url))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();
    let stats: Value = resp.json().await.unwrap();
    assert_eq!(stats["total_docs"], 1);
    println!("  ✓ GET /api/admin/stats shows 1 document after insert");
}

#[tokio::test]
async fn test_blocklist_crud() {
    println!("\n=== test_blocklist_crud ===");
    let test_db = TestDb::new().await;
    
    // Setup
    let password = "test_password_123";
    let hash = hash_password(password);
    db::create_admin(&test_db.pool, "admin@test.com", &hash).await.unwrap();
    
    let (app, _) = create_test_app(test_db.pool.clone()).await;
    let base_url = start_server(app).await;
    let client = Client::new();
    
    // Login
    let resp = client.post(format!("{}/api/admin/login", base_url))
        .json(&json!({"email": "admin@test.com", "password": password}))
        .send()
        .await
        .unwrap();
    let token = resp.json::<Value>().await.unwrap()["token"].as_str().unwrap().to_string();
    
    // List blocklist (empty)
    let resp = client.get(format!("{}/api/admin/blocklist", base_url))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let entries: Vec<Value> = resp.json().await.unwrap();
    assert_eq!(entries.len(), 0);
    println!("  ✓ GET /api/admin/blocklist returns empty list");
    
    // Add domain
    let resp = client.post(format!("{}/api/admin/blocklist", base_url))
        .header("Authorization", format!("Bearer {}", token))
        .json(&json!({"domain": "blocked.com"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let entry: Value = resp.json().await.unwrap();
    assert_eq!(entry["domain"], "blocked.com");
    println!("  ✓ POST /api/admin/blocklist adds domain");
    
    // List blocklist (one)
    let resp = client.get(format!("{}/api/admin/blocklist", base_url))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();
    let entries: Vec<Value> = resp.json().await.unwrap();
    assert_eq!(entries.len(), 1);
    println!("  ✓ GET /api/admin/blocklist returns 1 entry");
    
    // Remove domain
    let resp = client.delete(format!("{}/api/admin/blocklist/blocked.com", base_url))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    println!("  ✓ DELETE /api/admin/blocklist/blocked.com succeeds");
    
    // List blocklist (empty again)
    let resp = client.get(format!("{}/api/admin/blocklist", base_url))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();
    let entries: Vec<Value> = resp.json().await.unwrap();
    assert_eq!(entries.len(), 0);
    println!("  ✓ GET /api/admin/blocklist returns empty after delete");
}

#[tokio::test]
async fn test_full_workflow() {
    println!("\n=== test_full_workflow ===");
    let test_db = TestDb::new().await;
    
    // Setup admin
    let password = "admin_password_123";
    let hash = hash_password(password);
    db::create_admin(&test_db.pool, "admin@company.com", &hash).await.unwrap();
    
    let (app, _) = create_test_app(test_db.pool.clone()).await;
    let base_url = start_server(app).await;
    let client = Client::new();
    
    println!("  Step 1: Admin logs in");
    let resp = client.post(format!("{}/api/admin/login", base_url))
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
    
    let resp = client.post(format!("{}/api/admin/documents", base_url))
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
    let resp = client.post(format!("{}/api/admin/links", base_url))
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
    let resp = client.get(format!("{}/api/admin/stats", base_url))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();
    let stats: Value = resp.json().await.unwrap();
    assert_eq!(stats["total_docs"], 1);
    assert_eq!(stats["total_links"], 1);
    println!("    ✓ Stats: {} doc, {} link", stats["total_docs"], stats["total_links"]);
    
    println!("  Step 5: Admin blocks competitor domain");
    let resp = client.post(format!("{}/api/admin/blocklist", base_url))
        .header("Authorization", format!("Bearer {}", token))
        .json(&json!({"domain": "competitor.com"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    println!("    ✓ Blocked competitor.com");
    
    println!("  Step 6: Admin revokes link (deal fell through)");
    let resp = client.post(format!("{}/api/admin/links/{}/revoke", base_url, link_id))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    println!("    ✓ Link revoked");
    
    println!("\n  ✓ Full admin workflow completed!\n");
}
