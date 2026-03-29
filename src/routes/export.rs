use axum::extract::State;
use axum::http::{StatusCode, HeaderMap, header};
use axum::response::{IntoResponse, Response};

use docsend::db;
use crate::AppState;
use crate::auth::verify_admin;
use crate::types::json_error;

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

fn escape_csv(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

pub async fn export_documents_csv(
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

pub async fn export_links_csv(
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

pub async fn export_views_csv(
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

pub async fn export_attempts_csv(
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
