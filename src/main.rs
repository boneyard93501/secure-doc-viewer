use axum::{
    extract::{Path, State, Multipart, Query, ConnectInfo},
    http::{StatusCode, HeaderMap, header},
    response::{IntoResponse, Response, Json},
    routing::{get, post, put, delete},
    Router,
};
use docsend::{Config, db, blocklist};
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::sync::Arc;
use tower_http::cors::{CorsLayer, Any};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;
use chrono::{Utc, Duration};
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
use argon2::{Argon2, PasswordHash, PasswordVerifier, PasswordHasher};
use argon2::password_hash::SaltString;

// ============================================================================
// App State
// ============================================================================

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub config: Arc<Config>,
    pub jwt_secret: String,
    pub resend_api_key: Option<String>,
}

// ============================================================================
// Build App (used by main and tests)
// ============================================================================

pub fn build_app(state: AppState, static_dir: &str) -> Router {
    Router::new()
        // Public routes
        .route("/health", get(health))
        .route("/d/{short_code}", get(serve_document_form))
        .route("/api/link/{short_code}/meta", get(get_link_meta))
        .route("/api/link/{short_code}/access", post(request_access))
        .route("/api/verify", post(verify_token))
        .route("/api/track", post(track_view))
        .route("/api/document/{token}", get(serve_document_file))
        // Admin routes
        .route("/api/admin/login", post(admin_login))
        .route("/api/admin/password", put(admin_change_password))
        .route("/api/admin/documents", get(list_documents).post(upload_document))
        .route("/api/admin/documents/{id}", delete(delete_document))
        .route("/api/admin/documents/{id}/links", get(list_links))
        .route("/api/admin/documents/{id}/views", get(list_views))
        .route("/api/admin/documents/{id}/stats", get(get_document_stats))
        .route("/api/admin/links", get(list_all_links).post(create_link))
        .route("/api/admin/links/{id}/revoke", post(revoke_link))
        .route("/api/admin/views", get(list_all_views))
        .route("/api/admin/attempts", get(list_access_attempts))
        .route("/api/admin/stats", get(get_global_stats))
        .route("/api/admin/blocklist", get(list_blocklist).post(add_to_blocklist))
        .route("/api/admin/blocklist/{domain}", delete(remove_from_blocklist))
        // CSV exports
        .route("/api/admin/export/documents", get(export_documents_csv))
        .route("/api/admin/export/links", get(export_links_csv))
        .route("/api/admin/export/views", get(export_views_csv))
        .route("/api/admin/export/attempts", get(export_attempts_csv))
        // Admin (single route - handles login + dashboard)
        .route("/admin", get(serve_admin))
        // Viewer (token verification from email link)
        .route("/view", get(serve_viewer))
        // Static files
        .nest_service("/static", ServeDir::new(static_dir))
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any))
        .layer(RequestBodyLimitLayer::new(100 * 1024 * 1024)) // 100MB limit
        .with_state(state)
}

// ============================================================================
// JWT Claims
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
struct AdminClaims {
    sub: String,  // admin id
    exp: usize,
}

// ============================================================================
// Request/Response Types
// ============================================================================

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

#[derive(Debug, Deserialize)]
struct ChangePasswordRequest {
    current_password: String,
    new_password: String,
}

#[derive(Debug, Deserialize)]
struct RequestAccessRequest {
    email: String,
}

#[derive(Debug, Serialize)]
struct LinkMetaResponse {
    document_name: String,
    owner_name: String,
    requires_email: bool,
}

#[derive(Debug, Deserialize)]
struct VerifyRequest {
    token: String,
}

#[derive(Debug, Deserialize)]
struct TrackRequest {
    view_id: Uuid,
    duration_secs: Option<i32>,
    pages_viewed: Option<Vec<i32>>,
}

#[derive(Debug, Deserialize)]
struct CreateLinkRequest {
    document_id: Uuid,
    expires_in_days: Option<i64>,
    note: Option<String>,
    one_time_only: Option<bool>,
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

#[derive(Debug, Serialize)]
struct ApiError {
    error: String,
}

#[derive(Debug, Serialize)]
struct ApiSuccess {
    message: String,
}

// ============================================================================
// Error Handling
// ============================================================================

fn json_error(status: StatusCode, message: &str) -> Response {
    (status, Json(ApiError { error: message.to_string() })).into_response()
}

fn json_success(message: &str) -> Response {
    (StatusCode::OK, Json(ApiSuccess { message: message.to_string() })).into_response()
}

// ============================================================================
// Auth Helpers
// ============================================================================

pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut rand::thread_rng());
    let argon2 = Argon2::default();
    let hash = argon2.hash_password(password.as_bytes(), &salt)?;
    Ok(hash.to_string())
}

fn verify_password(password: &str, hash: &str) -> bool {
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

fn generate_short_code() -> String {
    use rand::Rng;
    let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".chars().collect();
    let mut rng = rand::thread_rng();
    (0..8).map(|_| chars[rng.gen_range(0..chars.len())]).collect()
}

fn generate_access_token() -> String {
    use rand::Rng;
    let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".chars().collect();
    let mut rng = rand::thread_rng();
    (0..32).map(|_| chars[rng.gen_range(0..chars.len())]).collect()
}

// ============================================================================
// Public Handlers
// ============================================================================

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({"status": "ok"}))
}

// Admin page handler - serves combined login/dashboard
async fn serve_admin(State(state): State<AppState>) -> Response {
    use axum::response::Html;
    match std::fs::read_to_string("static/admin.html") {
        Ok(content) => {
            let html = content
                .replace("{{REFRESH_INTERVAL_MS}}", &(state.config.dashboard.refresh_interval_secs * 1000).to_string());
            Html(html).into_response()
        }
        Err(_) => (StatusCode::NOT_FOUND, "Page not found").into_response(),
    }
}

// Viewer page handler - verifies token from email and serves document viewer
#[derive(Debug, Deserialize)]
struct ViewerQuery {
    token: String,
}

async fn serve_viewer(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<ViewerQuery>,
) -> Response {
    use axum::response::Html;
    
    // Get and validate access token
    let access_token = match db::get_valid_access_token(&state.pool, &query.token).await {
        Ok(Some(t)) => t,
        Ok(None) => {
            // Invalid/expired token - show error page
            let html = r#"<!DOCTYPE html><html><head><title>Error</title><style>body{font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;background:#f5f7fa;}.box{background:white;padding:40px;border-radius:12px;text-align:center;}</style></head><body><div class="box"><h1>⏰ Link Expired</h1><p>This verification link has expired or is invalid.</p><p>Please request a new link.</p></div></body></html>"#;
            return Html(html).into_response();
        }
        Err(_) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response();
        }
    };
    
    // Get link info
    let link = match db::get_link_by_id(&state.pool, access_token.link_id).await {
        Ok(Some(l)) => l,
        Ok(None) => return (StatusCode::NOT_FOUND, "Link not found").into_response(),
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response(),
    };
    
    // Check if one-time link has already been used
    if link.one_time_only.unwrap_or(false) && access_token.used.unwrap_or(false) {
        let html = r#"<!DOCTYPE html><html><head><title>Error</title><style>body{font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;background:#f5f7fa;}.box{background:white;padding:40px;border-radius:12px;text-align:center;}</style></head><body><div class="box"><h1>🔒 One-Time Link</h1><p>This link can only be viewed once and has already been used.</p><p>Please request a new link from the sender.</p></div></body></html>"#;
        return Html(html).into_response();
    }
    
    // Get document info
    let doc = match db::get_document_by_id(&state.pool, link.document_id).await {
        Ok(Some(d)) => d,
        Ok(None) => return (StatusCode::NOT_FOUND, "Document not found").into_response(),
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response(),
    };
    
    // Get IP: prefer proxy headers, fallback to connection IP
    let verified_ip = headers.get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or(s).trim().to_string())
        .or_else(|| headers.get("x-real-ip")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()))
        .unwrap_or_else(|| addr.ip().to_string());
    let verified_ua = headers.get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    
    let _ = db::mark_access_token_used(
        &state.pool,
        access_token.id,
        Some(&verified_ip),
        verified_ua.as_deref(),
    ).await;
    
    // Create view record
    let view = match db::create_view(
        &state.pool,
        Some(access_token.id),
        &access_token.email,
        Some(&verified_ip),
    ).await {
        Ok(v) => v,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to create view").into_response(),
    };
    
    // Serve viewer with document info
    let viewer_html = match std::fs::read_to_string("static/viewer.html") {
        Ok(html) => html,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to load viewer").into_response(),
    };
    
    let html = viewer_html
        .replace("{{DOCUMENT_NAME}}", &doc.name)
        .replace("{{DOCUMENT_PATH}}", &format!("/api/document/{}", query.token))
        .replace("{{VIEW_ID}}", &view.id.to_string())
        .replace("{{TOKEN}}", &query.token);
    
    Html(html).into_response()
}

async fn serve_static_html(path: &str) -> Response {
    use axum::response::Html;
    match std::fs::read_to_string(path) {
        Ok(content) => Html(content).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "Page not found").into_response(),
    }
}

// Serve PDF document (requires valid token)
async fn serve_document_file(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> Response {
    // Validate token (allow used tokens - they can view multiple times)
    let access_token = match db::get_access_token_by_token(&state.pool, &token).await {
        Ok(Some(t)) => t,
        Ok(None) => return json_error(StatusCode::UNAUTHORIZED, "Invalid token"),
        Err(_) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Database error"),
    };
    
    // Check if token is expired
    if access_token.expires_at < Utc::now() {
        return json_error(StatusCode::UNAUTHORIZED, "Token expired");
    }
    
    // Get link and document
    let link = match db::get_link_by_id(&state.pool, access_token.link_id).await {
        Ok(Some(l)) => l,
        Ok(None) => return json_error(StatusCode::NOT_FOUND, "Link not found"),
        Err(_) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Database error"),
    };
    
    let doc = match db::get_document_by_id(&state.pool, link.document_id).await {
        Ok(Some(d)) => d,
        Ok(None) => return json_error(StatusCode::NOT_FOUND, "Document not found"),
        Err(_) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Database error"),
    };
    
    // Read and serve the PDF file
    match tokio::fs::read(&doc.storage_path).await {
        Ok(contents) => {
            (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, "application/pdf"),
                    (header::CONTENT_DISPOSITION, &format!("inline; filename=\"{}\"", doc.filename)),
                ],
                contents,
            ).into_response()
        }
        Err(_) => json_error(StatusCode::NOT_FOUND, "File not found"),
    }
}

async fn serve_document_form(
    State(state): State<AppState>,
    Path(short_code): Path<String>,
) -> Response {
    use axum::response::Html;
    
    // Read form template
    let form_html = match std::fs::read_to_string("static/form.html") {
        Ok(html) => html,
        Err(_) => {
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to load form");
        }
    };
    
    // Check if link exists and is valid
    let link = match db::get_link_with_document(&state.pool, &short_code).await {
        Ok(Some(l)) => l,
        Ok(None) => {
            // Link doesn't exist - serve form with expired state
            let html = form_html
                .replace("{{SHORT_CODE}}", &short_code)
                .replace("{{DOCUMENT_NAME}}", "Document")
                .replace("{{OWNER_NAME}}", &state.config.branding.owner_name)
                .replace("class=\"view active\" id=\"formView\"", "class=\"view\" id=\"formView\"")
                .replace("class=\"view\" id=\"expiredView\"", "class=\"view active\" id=\"expiredView\"");
            return Html(html).into_response();
        }
        Err(_) => {
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Database error");
        }
    };

    // Check if revoked or expired
    let is_expired = link.revoked.unwrap_or(false) || 
        link.expires_at.map(|exp| exp < Utc::now()).unwrap_or(false);
    
    if is_expired {
        let html = form_html
            .replace("{{SHORT_CODE}}", &short_code)
            .replace("{{DOCUMENT_NAME}}", &link.document_name)
            .replace("{{OWNER_NAME}}", &state.config.branding.owner_name)
            .replace("class=\"view active\" id=\"formView\"", "class=\"view\" id=\"formView\"")
            .replace("class=\"view\" id=\"expiredView\"", "class=\"view active\" id=\"expiredView\"");
        return Html(html).into_response();
    }

    // Valid link - serve normal form
    let html = form_html
        .replace("{{SHORT_CODE}}", &short_code)
        .replace("{{DOCUMENT_NAME}}", &link.document_name)
        .replace("{{OWNER_NAME}}", &state.config.branding.owner_name);
    
    Html(html).into_response()
}

async fn get_link_meta(
    State(state): State<AppState>,
    Path(short_code): Path<String>,
) -> Response {
    let link = match db::get_link_with_document(&state.pool, &short_code).await {
        Ok(Some(l)) => l,
        Ok(None) => return json_error(StatusCode::NOT_FOUND, "Link not found"),
        Err(_) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Database error"),
    };

    // Check if link is valid
    if link.revoked.unwrap_or(false) {
        return json_error(StatusCode::GONE, &state.config.messages.link_revoked);
    }
    if let Some(exp) = link.expires_at {
        if exp < Utc::now() {
            return json_error(StatusCode::GONE, &state.config.messages.link_expired);
        }
    }

    Json(LinkMetaResponse {
        document_name: link.document_name,
        owner_name: state.config.branding.owner_name.clone(),
        requires_email: true,
    }).into_response()
}

async fn request_access(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    Path(short_code): Path<String>,
    headers: HeaderMap,
    Json(req): Json<RequestAccessRequest>,
) -> Response {
    // Get IP: prefer proxy headers, fallback to connection IP
    let request_ip = headers.get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or(s).trim().to_string())
        .or_else(|| headers.get("x-real-ip")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()))
        .unwrap_or_else(|| addr.ip().to_string());
    let request_ua = headers.get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Validate email format
    if !blocklist::is_valid_email_format(&req.email) {
        let _ = db::log_access_attempt(
            &state.pool, &short_code, &req.email,
            Some(&request_ip), request_ua.as_deref(),
            false, Some("invalid_format")
        ).await;
        return json_error(StatusCode::BAD_REQUEST, "Invalid email format");
    }

    // Check blocklist
    match blocklist::validate_email(&state.pool, &req.email).await {
        Err(blocklist::EmailValidationError::InvalidFormat) => {
            let _ = db::log_access_attempt(
                &state.pool, &short_code, &req.email,
                Some(&request_ip), request_ua.as_deref(),
                false, Some("invalid_format")
            ).await;
            return json_error(StatusCode::BAD_REQUEST, "Invalid email format");
        }
        Err(blocklist::EmailValidationError::BlockedDomain(domain)) => {
            let _ = db::log_access_attempt(
                &state.pool, &short_code, &req.email,
                Some(&request_ip), request_ua.as_deref(),
                false, Some(&format!("blocked_domain:{}", domain))
            ).await;
            return json_error(StatusCode::FORBIDDEN, &state.config.messages.domain_blocked);
        }
        Err(blocklist::EmailValidationError::CustomBlockedDomain(domain)) => {
            let _ = db::log_access_attempt(
                &state.pool, &short_code, &req.email,
                Some(&request_ip), request_ua.as_deref(),
                false, Some(&format!("custom_blocked:{}", domain))
            ).await;
            return json_error(StatusCode::FORBIDDEN, &state.config.messages.domain_blocked);
        }
        Ok(()) => {}
    }

    // Get link with document info
    let link = match db::get_link_with_document(&state.pool, &short_code).await {
        Ok(Some(l)) => l,
        Ok(None) => {
            let _ = db::log_access_attempt(
                &state.pool, &short_code, &req.email,
                Some(&request_ip), request_ua.as_deref(),
                false, Some("link_not_found")
            ).await;
            return json_error(StatusCode::NOT_FOUND, "Link not found or expired");
        }
        Err(_) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Database error"),
    };
    
    // Check if revoked
    if link.revoked.unwrap_or(false) {
        let _ = db::log_access_attempt(
            &state.pool, &short_code, &req.email,
            Some(&request_ip), request_ua.as_deref(),
            false, Some("link_revoked")
        ).await;
        return json_error(StatusCode::GONE, &state.config.messages.link_revoked);
    }
    
    // Check if expired
    if let Some(exp) = link.expires_at {
        if exp < Utc::now() {
            let _ = db::log_access_attempt(
                &state.pool, &short_code, &req.email,
                Some(&request_ip), request_ua.as_deref(),
                false, Some("link_expired")
            ).await;
            return json_error(StatusCode::GONE, &state.config.messages.link_expired);
        }
    }

    // Generate access token
    let token = generate_access_token();
    let expires_at = Utc::now() + Duration::seconds(state.config.auth.access_token_ttl_secs as i64);

    if let Err(_) = db::create_access_token(
        &state.pool,
        link.link_id,
        &req.email,
        &token,
        expires_at,
        Some(&request_ip),
        request_ua.as_deref(),
    ).await {
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to create access token");
    }

    // Log successful attempt
    let _ = db::log_access_attempt(
        &state.pool, &short_code, &req.email,
        Some(&request_ip), request_ua.as_deref(),
        true, None
    ).await;

    // Send email via Resend
    if let Some(ref api_key) = state.resend_api_key {
        tracing::info!(email = %req.email, "Attempting to send verification email via Resend");
        
        let verify_url = format!("{}?token={}", 
            state.config.email.verification_url_base,
            token
        );
        
        let from = format!("{} <{}>", 
            state.config.email.from_name, 
            state.config.email.from_email
        );
        
        let subject = format!("Access {} - {}", 
            link.document_name,
            state.config.branding.owner_name
        );
        
        let body = format!(
            r#"<p>Click the link below to view the document:</p>
<p><a href="{}" style="display:inline-block;background:#667eea;color:white;padding:12px 24px;text-decoration:none;border-radius:6px;">View Document</a></p>
<p>Or copy this link: {}</p>
<p>This link expires in {} minutes.</p>
<p style="color:#666;font-size:12px;">Sent by {}</p>"#,
            verify_url,
            verify_url,
            state.config.auth.access_token_ttl_secs / 60,
            state.config.branding.owner_name
        );
        
        tracing::info!(from = %from, to = %req.email, subject = %subject, "Sending email");
        
        // Send via Resend API
        let client = reqwest::Client::new();
        let send_result = client
            .post("https://api.resend.com/emails")
            .header("Authorization", format!("Bearer {}", api_key))
            .json(&serde_json::json!({
                "from": from,
                "to": [&req.email],
                "subject": subject,
                "html": body
            }))
            .send()
            .await;
            
        match send_result {
            Ok(resp) if resp.status().is_success() => {
                tracing::info!(email = %req.email, "Verification email sent successfully");
            }
            Ok(resp) => {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                tracing::error!(email = %req.email, status = %status, body = %body, "Failed to send email - API error");
            }
            Err(e) => {
                tracing::error!(email = %req.email, error = %e, "Failed to send email - request error");
            }
        }
    } else {
        tracing::warn!(email = %req.email, token = %token, "No RESEND_API_KEY set - email not sent");
    }

    json_success(&state.config.messages.email_sent)
}

async fn verify_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<VerifyRequest>,
) -> Response {
    let access_token = match db::get_valid_access_token(&state.pool, &req.token).await {
        Ok(Some(t)) => t,
        Ok(None) => return json_error(StatusCode::UNAUTHORIZED, &state.config.messages.invalid_token),
        Err(_) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Database error"),
    };

    // Get link and document info
    let link = match db::get_link_by_id(&state.pool, access_token.link_id).await {
        Ok(Some(l)) => l,
        Ok(None) => return json_error(StatusCode::NOT_FOUND, "Link not found"),
        Err(_) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Database error"),
    };

    let doc = match db::get_document_by_id(&state.pool, link.document_id).await {
        Ok(Some(d)) => d,
        Ok(None) => return json_error(StatusCode::NOT_FOUND, "Document not found"),
        Err(_) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Database error"),
    };

    // Mark token as used
    let verified_ip = headers.get("x-forwarded-for")
        .and_then(|v| v.to_str().ok());
    let verified_ua = headers.get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok());

    if let Err(_) = db::mark_access_token_used(&state.pool, access_token.id, verified_ip, verified_ua).await {
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to verify token");
    }

    // Create view record
    let view = match db::create_view(
        &state.pool,
        Some(access_token.id),
        &access_token.email,
        verified_ip,
    ).await {
        Ok(v) => v,
        Err(_) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to create view"),
    };

    Json(serde_json::json!({
        "view_id": view.id,
        "document_name": doc.name,
        "filename": doc.filename,
        "storage_path": doc.storage_path,
    })).into_response()
}

async fn track_view(
    State(state): State<AppState>,
    Json(req): Json<TrackRequest>,
) -> Response {
    match db::update_view(&state.pool, req.view_id, req.duration_secs, req.pages_viewed).await {
        Ok(_) => json_success("View updated"),
        Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to update view"),
    }
}

// ============================================================================
// Admin Handlers
// ============================================================================

async fn admin_login(
    State(state): State<AppState>,
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

async fn admin_change_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ChangePasswordRequest>,
) -> Response {
    let token = match extract_bearer_token(&headers) {
        Some(t) => t,
        None => return json_error(StatusCode::UNAUTHORIZED, "Missing authorization"),
    };

    let claims = match verify_jwt(&token, &state.jwt_secret) {
        Some(c) => c,
        None => return json_error(StatusCode::UNAUTHORIZED, "Invalid token"),
    };

    let admin_id: Uuid = match claims.sub.parse() {
        Ok(id) => id,
        Err(_) => return json_error(StatusCode::UNAUTHORIZED, "Invalid token"),
    };

    let admin = match db::get_admin_by_id(&state.pool, admin_id).await {
        Ok(Some(a)) => a,
        Ok(None) => return json_error(StatusCode::NOT_FOUND, "Admin not found"),
        Err(_) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Database error"),
    };

    if !verify_password(&req.current_password, &admin.password_hash) {
        return json_error(StatusCode::UNAUTHORIZED, "Current password is incorrect");
    }

    let new_hash = match hash_password(&req.new_password) {
        Ok(h) => h,
        Err(_) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to hash password"),
    };

    match db::update_admin_password(&state.pool, admin_id, &new_hash).await {
        Ok(_) => json_success("Password updated"),
        Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to update password"),
    }
}

async fn list_documents(
    State(state): State<AppState>,
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
    State(state): State<AppState>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Response {
    if !verify_admin(&headers, &state.jwt_secret) {
        return json_error(StatusCode::UNAUTHORIZED, "Unauthorized");
    }

    let mut name: Option<String> = None;
    let mut file_data: Option<Vec<u8>> = None;
    let mut filename: Option<String> = None;

    while let Ok(Some(field)) = multipart.next_field().await {
        let field_name = field.name().unwrap_or("").to_string();
        
        match field_name.as_str() {
            "name" => {
                name = field.text().await.ok();
            }
            "file" => {
                filename = field.file_name().map(|s| s.to_string());
                file_data = field.bytes().await.ok().map(|b| b.to_vec());
            }
            _ => {}
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

    // Generate storage path
    let storage_filename = format!("{}_{}", Uuid::new_v4(), filename);
    let storage_path = format!("{}/{}", state.config.server.upload_dir, storage_filename);

    // Save file
    if let Err(_) = tokio::fs::write(&storage_path, &file_data).await {
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to save file");
    }

    // Create database record
    match db::create_document(&state.pool, &name, &filename, &storage_path, file_data.len() as i64).await {
        Ok(doc) => Json(doc).into_response(),
        Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to create document"),
    }
}

async fn delete_document(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Response {
    if !verify_admin(&headers, &state.jwt_secret) {
        return json_error(StatusCode::UNAUTHORIZED, "Unauthorized");
    }

    // Get document to delete file
    if let Ok(Some(doc)) = db::get_document_by_id(&state.pool, id).await {
        let _ = tokio::fs::remove_file(&doc.storage_path).await;
    }

    match db::delete_document(&state.pool, id).await {
        Ok(true) => json_success("Document deleted"),
        Ok(false) => json_error(StatusCode::NOT_FOUND, "Document not found"),
        Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to delete document"),
    }
}

async fn create_link(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateLinkRequest>,
) -> Response {
    if !verify_admin(&headers, &state.jwt_secret) {
        return json_error(StatusCode::UNAUTHORIZED, "Unauthorized");
    }

    // Verify document exists
    if let Ok(None) = db::get_document_by_id(&state.pool, req.document_id).await {
        return json_error(StatusCode::NOT_FOUND, "Document not found");
    }

    let short_code = generate_short_code();
    let expires_at = req.expires_in_days.map(|days| Utc::now() + Duration::days(days));
    let one_time_only = req.one_time_only.unwrap_or(false);

    match db::create_link(
        &state.pool, 
        req.document_id, 
        &short_code, 
        req.note.as_deref(),
        one_time_only,
        expires_at
    ).await {
        Ok(link) => {
            let url = format!("{}/d/{}", state.config.email.verification_url_base, short_code);
            Json(CreateLinkResponse {
                id: link.id,
                short_code: link.short_code,
                url,
                expires_at: link.expires_at.map(|e| e.timestamp()),
            }).into_response()
        }
        Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to create link"),
    }
}

async fn list_links(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(document_id): Path<Uuid>,
) -> Response {
    if !verify_admin(&headers, &state.jwt_secret) {
        return json_error(StatusCode::UNAUTHORIZED, "Unauthorized");
    }

    match db::list_links_for_document(&state.pool, document_id).await {
        Ok(links) => Json(links).into_response(),
        Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "Database error"),
    }
}

async fn list_all_links(
    State(state): State<AppState>,
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

async fn revoke_link(
    State(state): State<AppState>,
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

async fn list_views(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(document_id): Path<Uuid>,
    Query(params): Query<PaginationParams>,
) -> Response {
    if !verify_admin(&headers, &state.jwt_secret) {
        return json_error(StatusCode::UNAUTHORIZED, "Unauthorized");
    }

    let limit = params.limit.unwrap_or(50);
    let offset = params.offset.unwrap_or(0);

    match db::list_views_for_document(&state.pool, document_id, limit, offset).await {
        Ok(views) => Json(views).into_response(),
        Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "Database error"),
    }
}

async fn list_all_views(
    State(state): State<AppState>,
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
    State(state): State<AppState>,
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

async fn get_document_stats(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(document_id): Path<Uuid>,
) -> Response {
    if !verify_admin(&headers, &state.jwt_secret) {
        return json_error(StatusCode::UNAUTHORIZED, "Unauthorized");
    }

    match db::get_document_stats(&state.pool, document_id).await {
        Ok(stats) => Json(stats).into_response(),
        Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "Database error"),
    }
}

async fn list_blocklist(
    State(state): State<AppState>,
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
    State(state): State<AppState>,
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
    State(state): State<AppState>,
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

async fn list_access_attempts(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<PaginationParams>,
) -> Response {
    if !verify_admin(&headers, &state.jwt_secret) {
        return json_error(StatusCode::UNAUTHORIZED, "Unauthorized");
    }

    let limit = params.limit.unwrap_or(100);
    let offset = params.offset.unwrap_or(0);

    match db::list_access_attempts(&state.pool, limit, offset).await {
        Ok(attempts) => Json(attempts).into_response(),
        Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "Database error"),
    }
}

// ============================================================================
// CSV Export Handlers
// ============================================================================

fn csv_response(filename: &str, content: String) -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8"),
            (header::CONTENT_DISPOSITION, &format!("attachment; filename=\"{}\"", filename)),
        ],
        content,
    ).into_response()
}

async fn export_documents_csv(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    if !verify_admin(&headers, &state.jwt_secret) {
        return json_error(StatusCode::UNAUTHORIZED, "Unauthorized");
    }

    let docs = match db::list_documents(&state.pool, 10000, 0).await {
        Ok(d) => d,
        Err(_) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Database error"),
    };

    let mut csv = String::from("id,name,filename,size_bytes,created_at\n");
    for doc in docs {
        csv.push_str(&format!(
            "{},{},{},{},{}\n",
            doc.id,
            escape_csv(&doc.name),
            escape_csv(&doc.filename),
            doc.size_bytes,
            doc.created_at.map(|t| t.to_rfc3339()).unwrap_or_default()
        ));
    }

    csv_response("documents.csv", csv)
}

async fn export_links_csv(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    if !verify_admin(&headers, &state.jwt_secret) {
        return json_error(StatusCode::UNAUTHORIZED, "Unauthorized");
    }

    let links = match db::list_all_links(&state.pool, 10000, 0).await {
        Ok(l) => l,
        Err(_) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Database error"),
    };

    let mut csv = String::from("id,document_id,document_name,short_code,note,one_time_only,expires_at,revoked,view_count,created_at\n");
    for link in links {
        csv.push_str(&format!(
            "{},{},{},{},{},{},{},{},{},{}\n",
            link.id,
            link.document_id,
            escape_csv(&link.document_name),
            link.short_code,
            escape_csv(&link.note.unwrap_or_default()),
            link.one_time_only.unwrap_or(false),
            link.expires_at.map(|t| t.to_rfc3339()).unwrap_or_default(),
            link.revoked.unwrap_or(false),
            link.view_count,
            link.created_at.map(|t| t.to_rfc3339()).unwrap_or_default()
        ));
    }

    csv_response("links.csv", csv)
}

async fn export_views_csv(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    if !verify_admin(&headers, &state.jwt_secret) {
        return json_error(StatusCode::UNAUTHORIZED, "Unauthorized");
    }

    let views = match db::list_all_views(&state.pool, 10000, 0).await {
        Ok(v) => v,
        Err(_) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Database error"),
    };

    let mut csv = String::from("id,email,document_name,ip,started_at,duration_secs,pages_viewed\n");
    for view in views {
        let pages = view.pages_viewed
            .map(|p| p.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(";"))
            .unwrap_or_default();
        csv.push_str(&format!(
            "{},{},{},{},{},{},{}\n",
            view.id,
            escape_csv(&view.email),
            escape_csv(&view.document_name),
            view.ip.as_deref().unwrap_or(""),
            view.started_at.map(|t| t.to_rfc3339()).unwrap_or_default(),
            view.duration_secs.unwrap_or(0),
            pages
        ));
    }

    csv_response("views.csv", csv)
}

async fn export_attempts_csv(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    if !verify_admin(&headers, &state.jwt_secret) {
        return json_error(StatusCode::UNAUTHORIZED, "Unauthorized");
    }

    let attempts = match db::list_access_attempts(&state.pool, 10000, 0).await {
        Ok(a) => a,
        Err(_) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Database error"),
    };

    let mut csv = String::from("id,short_code,document_name,email,ip,success,failure_reason,created_at\n");
    for attempt in attempts {
        csv.push_str(&format!(
            "{},{},{},{},{},{},{},{}\n",
            attempt.id,
            attempt.short_code,
            escape_csv(&attempt.document_name.unwrap_or_default()),
            escape_csv(&attempt.email),
            attempt.ip.as_deref().unwrap_or(""),
            attempt.success,
            escape_csv(&attempt.failure_reason.unwrap_or_default()),
            attempt.created_at.map(|t| t.to_rfc3339()).unwrap_or_default()
        ));
    }

    csv_response("access_attempts.csv", csv)
}

fn escape_csv(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn verify_admin(headers: &HeaderMap, jwt_secret: &str) -> bool {
    extract_bearer_token(headers)
        .and_then(|token| verify_jwt(&token, jwt_secret))
        .is_some()
}

// ============================================================================
// Main
// ============================================================================

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load .env file
    dotenvy::dotenv().ok();
    
    // Load config
    let config_path = std::env::var("CONFIG_PATH").unwrap_or_else(|_| "config.toml".to_string());
    let config = Config::load(&config_path)?;

    // Setup logging
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new(&config.logging.level)))
        .init();

    // Load blocklist
    blocklist::load_blocklist();
    tracing::info!("Loaded {} domains into blocklist", blocklist::load_blocklist().len());

    // Database connection
    let db_password = std::env::var("DB_PASSWORD").expect("DB_PASSWORD must be set");
    let database_url = config.database.connection_string(&db_password);
    
    let pool = PgPoolOptions::new()
        .max_connections(config.database.max_connections)
        .connect(&database_url)
        .await?;

    tracing::info!("Connected to database");

    // Create uploads directory
    tokio::fs::create_dir_all(&config.server.upload_dir).await?;

    // App state
    let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    let resend_api_key = std::env::var("RESEND_API_KEY").ok();
    
    let state = AppState {
        pool,
        config: Arc::new(config.clone()),
        jwt_secret,
        resend_api_key,
    };

    // Build router using shared function
    let app = build_app(state, &config.server.static_dir);

    // Run server
    let addr = format!("{}:{}", config.server.host, config.server.port);
    tracing::info!("Starting server on {}", addr);
    
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(
        listener, 
        app.into_make_service_with_connect_info::<std::net::SocketAddr>()
    ).await?;

    Ok(())
}
