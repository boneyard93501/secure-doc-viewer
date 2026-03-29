use axum::extract::{Path, State, Multipart, Query};
use axum::http::{StatusCode, HeaderMap};
use axum::response::{IntoResponse, Response, Json};
use chrono::{Utc, Duration};
use uuid::Uuid;

use docsend::db;
use crate::AppState;
use crate::auth::{verify_password, hash_password, generate_jwt, verify_jwt, extract_bearer_token, verify_admin, generate_short_code};
use crate::types::*;

pub async fn admin_login(
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

pub async fn admin_change_password(
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

pub async fn list_documents(
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

pub async fn upload_document(
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

    let storage_filename = format!("{}_{}", Uuid::new_v4(), filename);
    let storage_path = format!("{}/{}", state.config.server.upload_dir, storage_filename);

    if let Err(_) = tokio::fs::write(&storage_path, &file_data).await {
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to save file");
    }

    match db::create_document(&state.pool, &name, &filename, &storage_path, file_data.len() as i64).await {
        Ok(doc) => Json(doc).into_response(),
        Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to create document"),
    }
}

pub async fn delete_document(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Response {
    if !verify_admin(&headers, &state.jwt_secret) {
        return json_error(StatusCode::UNAUTHORIZED, "Unauthorized");
    }

    if let Ok(Some(doc)) = db::get_document_by_id(&state.pool, id).await {
        let _ = tokio::fs::remove_file(&doc.storage_path).await;
    }

    match db::delete_document(&state.pool, id).await {
        Ok(true) => json_success("Document deleted"),
        Ok(false) => json_error(StatusCode::NOT_FOUND, "Document not found"),
        Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to delete document"),
    }
}

pub async fn create_link(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateLinkRequest>,
) -> Response {
    if !verify_admin(&headers, &state.jwt_secret) {
        return json_error(StatusCode::UNAUTHORIZED, "Unauthorized");
    }

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

pub async fn list_links(
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

pub async fn list_all_links(
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

pub async fn revoke_link(
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

pub async fn list_views(
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

pub async fn list_all_views(
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

pub async fn get_global_stats(
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

pub async fn get_document_stats(
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

pub async fn list_blocklist(
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

pub async fn add_to_blocklist(
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

pub async fn remove_from_blocklist(
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

pub async fn list_access_attempts(
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
