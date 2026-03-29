use axum::http::StatusCode;
use axum::response::{IntoResponse, Response, Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct AdminClaims {
    pub sub: String,
    pub exp: usize,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub expires_at: i64,
}

#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Debug, Deserialize)]
pub struct RequestAccessRequest {
    pub email: String,
}

#[derive(Debug, Serialize)]
pub struct LinkMetaResponse {
    pub document_name: String,
    pub owner_name: String,
    pub requires_email: bool,
}

#[derive(Debug, Deserialize)]
pub struct VerifyRequest {
    pub token: String,
}

#[derive(Debug, Deserialize)]
pub struct TrackRequest {
    pub view_id: Uuid,
    pub duration_secs: Option<i32>,
    pub pages_viewed: Option<Vec<i32>>,
}

#[derive(Debug, Deserialize)]
pub struct CreateLinkRequest {
    pub document_id: Uuid,
    pub expires_in_days: Option<i64>,
    pub note: Option<String>,
    pub one_time_only: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct CreateLinkResponse {
    pub id: Uuid,
    pub short_code: String,
    pub url: String,
    pub expires_at: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct PaginationParams {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct BlocklistRequest {
    pub domain: String,
}

#[derive(Debug, Deserialize)]
pub struct ViewerQuery {
    pub token: String,
}

#[derive(Debug, Serialize)]
pub struct ApiError {
    pub error: String,
}

#[derive(Debug, Serialize)]
pub struct ApiSuccess {
    pub message: String,
}

pub fn json_error(status: StatusCode, message: &str) -> Response {
    (status, Json(ApiError { error: message.to_string() })).into_response()
}

pub fn json_success(message: &str) -> Response {
    (StatusCode::OK, Json(ApiSuccess { message: message.to_string() })).into_response()
}
