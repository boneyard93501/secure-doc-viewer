use axum::extract::{Path, State, Query, ConnectInfo};
use axum::http::{StatusCode, HeaderMap, header};
use axum::response::{IntoResponse, Response, Json, Html};
use chrono::{Utc, Duration};

use docsend::{db, blocklist};
use crate::AppState;
use crate::auth::generate_access_token;
use crate::types::*;

pub async fn health() -> impl IntoResponse {
    Json(serde_json::json!({"status": "ok"}))
}

pub async fn root_redirect() -> axum::response::Redirect {
    axum::response::Redirect::permanent("/admin")
}

pub async fn serve_admin(State(state): State<AppState>) -> Response {
    match std::fs::read_to_string("static/admin.html") {
        Ok(content) => {
            let html = content
                .replace("{{REFRESH_INTERVAL_MS}}", &(state.config.dashboard.refresh_interval_secs * 1000).to_string());
            Html(html).into_response()
        }
        Err(_) => (StatusCode::NOT_FOUND, "Page not found").into_response(),
    }
}

pub async fn serve_viewer(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<ViewerQuery>,
) -> Response {
    let access_token = match db::get_valid_access_token(&state.pool, &query.token).await {
        Ok(Some(t)) => t,
        Ok(None) => {
            let html = r#"<!DOCTYPE html><html><head><title>Error</title><style>body{font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;background:#f5f7fa;}.box{background:white;padding:40px;border-radius:12px;text-align:center;}</style></head><body><div class="box"><h1>⏰ Link Expired</h1><p>This verification link has expired or is invalid.</p><p>Please request a new link.</p></div></body></html>"#;
            return Html(html).into_response();
        }
        Err(_) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response();
        }
    };

    let link = match db::get_link_by_id(&state.pool, access_token.link_id).await {
        Ok(Some(l)) => l,
        Ok(None) => return (StatusCode::NOT_FOUND, "Link not found").into_response(),
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response(),
    };

    if link.one_time_only.unwrap_or(false) && access_token.used.unwrap_or(false) {
        let html = r#"<!DOCTYPE html><html><head><title>Error</title><style>body{font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;background:#f5f7fa;}.box{background:white;padding:40px;border-radius:12px;text-align:center;}</style></head><body><div class="box"><h1>🔒 One-Time Link</h1><p>This link can only be viewed once and has already been used.</p><p>Please request a new link from the sender.</p></div></body></html>"#;
        return Html(html).into_response();
    }

    let doc = match db::get_document_by_id(&state.pool, link.document_id).await {
        Ok(Some(d)) => d,
        Ok(None) => return (StatusCode::NOT_FOUND, "Document not found").into_response(),
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response(),
    };

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

    let view = match db::create_view(
        &state.pool,
        Some(access_token.id),
        &access_token.email,
        Some(&verified_ip),
    ).await {
        Ok(v) => v,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to create view").into_response(),
    };

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

pub async fn serve_document_file(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> Response {
    let access_token = match db::get_access_token_by_token(&state.pool, &token).await {
        Ok(Some(t)) => t,
        Ok(None) => return json_error(StatusCode::UNAUTHORIZED, "Invalid token"),
        Err(_) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Database error"),
    };

    if access_token.expires_at < Utc::now() {
        return json_error(StatusCode::UNAUTHORIZED, "Token expired");
    }

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

pub async fn serve_document_form(
    State(state): State<AppState>,
    Path(short_code): Path<String>,
) -> Response {
    let form_html = match std::fs::read_to_string("static/form.html") {
        Ok(html) => html,
        Err(_) => {
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to load form");
        }
    };

    let link = match db::get_link_with_document(&state.pool, &short_code).await {
        Ok(Some(l)) => l,
        Ok(None) => {
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

    let html = form_html
        .replace("{{SHORT_CODE}}", &short_code)
        .replace("{{DOCUMENT_NAME}}", &link.document_name)
        .replace("{{OWNER_NAME}}", &state.config.branding.owner_name);

    Html(html).into_response()
}

pub async fn get_link_meta(
    State(state): State<AppState>,
    Path(short_code): Path<String>,
) -> Response {
    let link = match db::get_link_with_document(&state.pool, &short_code).await {
        Ok(Some(l)) => l,
        Ok(None) => return json_error(StatusCode::NOT_FOUND, "Link not found"),
        Err(_) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Database error"),
    };

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

pub async fn request_access(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    Path(short_code): Path<String>,
    headers: HeaderMap,
    Json(req): Json<RequestAccessRequest>,
) -> Response {
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

    if !blocklist::is_valid_email_format(&req.email) {
        let _ = db::log_access_attempt(
            &state.pool, &short_code, &req.email,
            Some(&request_ip), request_ua.as_deref(),
            false, Some("invalid_format")
        ).await;
        return json_error(StatusCode::BAD_REQUEST, "Invalid email format");
    }

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

    if link.revoked.unwrap_or(false) {
        let _ = db::log_access_attempt(
            &state.pool, &short_code, &req.email,
            Some(&request_ip), request_ua.as_deref(),
            false, Some("link_revoked")
        ).await;
        return json_error(StatusCode::GONE, &state.config.messages.link_revoked);
    }

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

    let _ = db::log_access_attempt(
        &state.pool, &short_code, &req.email,
        Some(&request_ip), request_ua.as_deref(),
        true, None
    ).await;

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

pub async fn verify_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<VerifyRequest>,
) -> Response {
    let access_token = match db::get_valid_access_token(&state.pool, &req.token).await {
        Ok(Some(t)) => t,
        Ok(None) => return json_error(StatusCode::UNAUTHORIZED, &state.config.messages.invalid_token),
        Err(_) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Database error"),
    };

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

    let verified_ip = headers.get("x-forwarded-for")
        .and_then(|v| v.to_str().ok());
    let verified_ua = headers.get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok());

    if let Err(_) = db::mark_access_token_used(&state.pool, access_token.id, verified_ip, verified_ua).await {
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to verify token");
    }

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

pub async fn track_view(
    State(state): State<AppState>,
    Json(req): Json<TrackRequest>,
) -> Response {
    tracing::info!(view_id = %req.view_id, duration = ?req.duration_secs, pages = ?req.pages_viewed, "Tracking view");
    match db::update_view(&state.pool, req.view_id, req.duration_secs, req.pages_viewed).await {
        Ok(_) => {
            tracing::info!(view_id = %req.view_id, "View updated successfully");
            json_success("View updated")
        }
        Err(e) => {
            tracing::error!(view_id = %req.view_id, error = %e, "Failed to update view");
            json_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to update view")
        }
    }
}
