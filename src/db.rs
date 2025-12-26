use sqlx::PgPool;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use serde::Serialize;

// ============================================================================
// Types
// ============================================================================

#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct Admin {
    pub id: Uuid,
    pub email: String,
    #[serde(skip)]
    pub password_hash: String,
    pub password_changed_at: Option<DateTime<Utc>>,
    pub created_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct Document {
    pub id: Uuid,
    pub name: String,
    pub filename: String,
    pub storage_path: String,
    pub size_bytes: i64,
    pub created_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct Link {
    pub id: Uuid,
    pub document_id: Uuid,
    pub short_code: String,
    pub note: Option<String>,
    pub one_time_only: Option<bool>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked: Option<bool>,
    pub created_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct AccessToken {
    pub id: Uuid,
    pub link_id: Uuid,
    pub email: String,
    #[serde(skip)]
    pub token: String,
    pub expires_at: DateTime<Utc>,
    pub used: Option<bool>,
    pub request_ip: Option<String>,
    pub request_ua: Option<String>,
    pub verified_ip: Option<String>,
    pub verified_ua: Option<String>,
    pub verified_at: Option<DateTime<Utc>>,
    pub created_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct View {
    pub id: Uuid,
    pub access_token_id: Option<Uuid>,
    pub email: String,
    pub ip: Option<String>,
    pub started_at: Option<DateTime<Utc>>,
    pub duration_secs: Option<i32>,
    pub pages_viewed: Option<Vec<i32>>,
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct CustomBlocklistEntry {
    pub id: Uuid,
    pub domain: String,
    pub created_at: Option<DateTime<Utc>>,
}

// ============================================================================
// Admins
// ============================================================================

pub async fn create_admin(
    pool: &PgPool,
    email: &str,
    password_hash: &str,
) -> Result<Admin, sqlx::Error> {
    sqlx::query_as::<_, Admin>(
        r#"
        INSERT INTO admins (email, password_hash)
        VALUES ($1, $2)
        RETURNING *
        "#,
    )
    .bind(email)
    .bind(password_hash)
    .fetch_one(pool)
    .await
}

pub async fn get_admin_by_email(pool: &PgPool, email: &str) -> Result<Option<Admin>, sqlx::Error> {
    sqlx::query_as::<_, Admin>("SELECT * FROM admins WHERE email = $1")
        .bind(email)
        .fetch_optional(pool)
        .await
}

pub async fn get_admin_by_id(pool: &PgPool, id: Uuid) -> Result<Option<Admin>, sqlx::Error> {
    sqlx::query_as::<_, Admin>("SELECT * FROM admins WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
}

pub async fn update_admin_password(
    pool: &PgPool,
    id: Uuid,
    password_hash: &str,
) -> Result<Admin, sqlx::Error> {
    sqlx::query_as::<_, Admin>(
        r#"
        UPDATE admins
        SET password_hash = $2, password_changed_at = now()
        WHERE id = $1
        RETURNING *
        "#,
    )
    .bind(id)
    .bind(password_hash)
    .fetch_one(pool)
    .await
}

// ============================================================================
// Documents
// ============================================================================

pub async fn create_document(
    pool: &PgPool,
    name: &str,
    filename: &str,
    storage_path: &str,
    size_bytes: i64,
) -> Result<Document, sqlx::Error> {
    sqlx::query_as::<_, Document>(
        r#"
        INSERT INTO documents (name, filename, storage_path, size_bytes)
        VALUES ($1, $2, $3, $4)
        RETURNING *
        "#,
    )
    .bind(name)
    .bind(filename)
    .bind(storage_path)
    .bind(size_bytes)
    .fetch_one(pool)
    .await
}

pub async fn get_document_by_id(pool: &PgPool, id: Uuid) -> Result<Option<Document>, sqlx::Error> {
    sqlx::query_as::<_, Document>("SELECT * FROM documents WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
}

pub async fn list_documents(pool: &PgPool, limit: i64, offset: i64) -> Result<Vec<Document>, sqlx::Error> {
    sqlx::query_as::<_, Document>(
        "SELECT * FROM documents ORDER BY created_at DESC LIMIT $1 OFFSET $2",
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
}

pub async fn delete_document(pool: &PgPool, id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM documents WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn update_document_name(
    pool: &PgPool,
    id: Uuid,
    name: &str,
) -> Result<Option<Document>, sqlx::Error> {
    sqlx::query_as::<_, Document>(
        r#"
        UPDATE documents SET name = $2 WHERE id = $1
        RETURNING *
        "#,
    )
    .bind(id)
    .bind(name)
    .fetch_optional(pool)
    .await
}

// ============================================================================
// Links
// ============================================================================

pub async fn create_link(
    pool: &PgPool,
    document_id: Uuid,
    short_code: &str,
    note: Option<&str>,
    one_time_only: bool,
    expires_at: Option<DateTime<Utc>>,
) -> Result<Link, sqlx::Error> {
    sqlx::query_as::<_, Link>(
        r#"
        INSERT INTO links (document_id, short_code, note, one_time_only, expires_at)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING *
        "#,
    )
    .bind(document_id)
    .bind(short_code)
    .bind(note)
    .bind(one_time_only)
    .bind(expires_at)
    .fetch_one(pool)
    .await
}

pub async fn get_link_by_short_code(pool: &PgPool, short_code: &str) -> Result<Option<Link>, sqlx::Error> {
    sqlx::query_as::<_, Link>("SELECT * FROM links WHERE short_code = $1")
        .bind(short_code)
        .fetch_optional(pool)
        .await
}

pub async fn get_link_by_id(pool: &PgPool, id: Uuid) -> Result<Option<Link>, sqlx::Error> {
    sqlx::query_as::<_, Link>("SELECT * FROM links WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
}

pub async fn list_links_for_document(pool: &PgPool, document_id: Uuid) -> Result<Vec<Link>, sqlx::Error> {
    sqlx::query_as::<_, Link>(
        "SELECT * FROM links WHERE document_id = $1 ORDER BY created_at DESC",
    )
    .bind(document_id)
    .fetch_all(pool)
    .await
}

pub async fn revoke_link(pool: &PgPool, id: Uuid) -> Result<Option<Link>, sqlx::Error> {
    sqlx::query_as::<_, Link>(
        r#"
        UPDATE links SET revoked = TRUE WHERE id = $1
        RETURNING *
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await
}

pub async fn delete_link(pool: &PgPool, id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM links WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

/// Check if a link is valid (not revoked, not expired)
pub async fn get_valid_link_by_short_code(
    pool: &PgPool,
    short_code: &str,
) -> Result<Option<Link>, sqlx::Error> {
    sqlx::query_as::<_, Link>(
        r#"
        SELECT * FROM links
        WHERE short_code = $1
          AND (revoked IS NULL OR revoked = FALSE)
          AND (expires_at IS NULL OR expires_at > now())
        "#,
    )
    .bind(short_code)
    .fetch_optional(pool)
    .await
}

/// List all links with document info
#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct LinkWithStats {
    pub id: Uuid,
    pub document_id: Uuid,
    pub document_name: String,
    pub short_code: String,
    pub note: Option<String>,
    pub one_time_only: Option<bool>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked: Option<bool>,
    pub created_at: Option<DateTime<Utc>>,
    pub view_count: i64,
}

pub async fn list_all_links(pool: &PgPool, limit: i64, offset: i64) -> Result<Vec<LinkWithStats>, sqlx::Error> {
    sqlx::query_as::<_, LinkWithStats>(
        r#"
        SELECT 
            l.id, l.document_id, d.name as document_name, l.short_code, 
            l.note, l.one_time_only, l.expires_at, l.revoked, l.created_at,
            (SELECT COUNT(*) FROM views v 
             JOIN access_tokens at ON v.access_token_id = at.id 
             WHERE at.link_id = l.id) as view_count
        FROM links l
        JOIN documents d ON l.document_id = d.id
        ORDER BY l.created_at DESC
        LIMIT $1 OFFSET $2
        "#,
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
}

// ============================================================================
// Access Tokens
// ============================================================================

pub async fn create_access_token(
    pool: &PgPool,
    link_id: Uuid,
    email: &str,
    token: &str,
    expires_at: DateTime<Utc>,
    request_ip: Option<&str>,
    request_ua: Option<&str>,
) -> Result<AccessToken, sqlx::Error> {
    sqlx::query_as::<_, AccessToken>(
        r#"
        INSERT INTO access_tokens (link_id, email, token, expires_at, request_ip, request_ua)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING *
        "#,
    )
    .bind(link_id)
    .bind(email)
    .bind(token)
    .bind(expires_at)
    .bind(request_ip)
    .bind(request_ua)
    .fetch_one(pool)
    .await
}

pub async fn get_access_token_by_token(
    pool: &PgPool,
    token: &str,
) -> Result<Option<AccessToken>, sqlx::Error> {
    sqlx::query_as::<_, AccessToken>("SELECT * FROM access_tokens WHERE token = $1")
        .bind(token)
        .fetch_optional(pool)
        .await
}

pub async fn get_valid_access_token(
    pool: &PgPool,
    token: &str,
) -> Result<Option<AccessToken>, sqlx::Error> {
    sqlx::query_as::<_, AccessToken>(
        r#"
        SELECT * FROM access_tokens
        WHERE token = $1
          AND (used IS NULL OR used = FALSE)
          AND expires_at > now()
        "#,
    )
    .bind(token)
    .fetch_optional(pool)
    .await
}

pub async fn mark_access_token_used(
    pool: &PgPool,
    id: Uuid,
    verified_ip: Option<&str>,
    verified_ua: Option<&str>,
) -> Result<AccessToken, sqlx::Error> {
    sqlx::query_as::<_, AccessToken>(
        r#"
        UPDATE access_tokens
        SET used = TRUE, verified_at = now(), verified_ip = $2, verified_ua = $3
        WHERE id = $1
        RETURNING *
        "#,
    )
    .bind(id)
    .bind(verified_ip)
    .bind(verified_ua)
    .fetch_one(pool)
    .await
}

pub async fn list_access_tokens_for_link(
    pool: &PgPool,
    link_id: Uuid,
) -> Result<Vec<AccessToken>, sqlx::Error> {
    sqlx::query_as::<_, AccessToken>(
        "SELECT * FROM access_tokens WHERE link_id = $1 ORDER BY created_at DESC",
    )
    .bind(link_id)
    .fetch_all(pool)
    .await
}

// ============================================================================
// Views
// ============================================================================

pub async fn create_view(
    pool: &PgPool,
    access_token_id: Option<Uuid>,
    email: &str,
    ip: Option<&str>,
) -> Result<View, sqlx::Error> {
    sqlx::query_as::<_, View>(
        r#"
        INSERT INTO views (access_token_id, email, ip)
        VALUES ($1, $2, $3)
        RETURNING *
        "#,
    )
    .bind(access_token_id)
    .bind(email)
    .bind(ip)
    .fetch_one(pool)
    .await
}

pub async fn update_view(
    pool: &PgPool,
    id: Uuid,
    duration_secs: Option<i32>,
    pages_viewed: Option<Vec<i32>>,
) -> Result<View, sqlx::Error> {
    sqlx::query_as::<_, View>(
        r#"
        UPDATE views
        SET duration_secs = COALESCE($2, duration_secs),
            pages_viewed = COALESCE($3, pages_viewed)
        WHERE id = $1
        RETURNING *
        "#,
    )
    .bind(id)
    .bind(duration_secs)
    .bind(pages_viewed)
    .fetch_one(pool)
    .await
}

pub async fn get_view_by_id(pool: &PgPool, id: Uuid) -> Result<Option<View>, sqlx::Error> {
    sqlx::query_as::<_, View>("SELECT * FROM views WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
}

pub async fn list_views_for_document(
    pool: &PgPool,
    document_id: Uuid,
    limit: i64,
    offset: i64,
) -> Result<Vec<View>, sqlx::Error> {
    sqlx::query_as::<_, View>(
        r#"
        SELECT v.* FROM views v
        JOIN access_tokens at ON v.access_token_id = at.id
        JOIN links l ON at.link_id = l.id
        WHERE l.document_id = $1
        ORDER BY v.started_at DESC
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(document_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
}

pub async fn list_views_by_email(
    pool: &PgPool,
    email: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<View>, sqlx::Error> {
    sqlx::query_as::<_, View>(
        "SELECT * FROM views WHERE email = $1 ORDER BY started_at DESC LIMIT $2 OFFSET $3",
    )
    .bind(email)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct ViewWithDocument {
    pub id: Uuid,
    pub email: String,
    pub document_name: String,
    pub ip: Option<String>,
    pub started_at: Option<DateTime<Utc>>,
    pub duration_secs: Option<i32>,
    pub pages_viewed: Option<Vec<i32>>,
}

pub async fn list_all_views(pool: &PgPool, limit: i64, offset: i64) -> Result<Vec<ViewWithDocument>, sqlx::Error> {
    sqlx::query_as::<_, ViewWithDocument>(
        r#"
        SELECT 
            v.id, v.email, d.name as document_name, v.ip,
            v.started_at, v.duration_secs, v.pages_viewed
        FROM views v
        JOIN access_tokens at ON v.access_token_id = at.id
        JOIN links l ON at.link_id = l.id
        JOIN documents d ON l.document_id = d.id
        ORDER BY v.started_at DESC
        LIMIT $1 OFFSET $2
        "#,
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct GlobalStats {
    pub total_docs: i64,
    pub total_links: i64,
    pub total_views: i64,
    pub active_links: i64,
}

pub async fn get_global_stats(pool: &PgPool) -> Result<GlobalStats, sqlx::Error> {
    sqlx::query_as::<_, GlobalStats>(
        r#"
        SELECT
            (SELECT COUNT(*) FROM documents) as total_docs,
            (SELECT COUNT(*) FROM links) as total_links,
            (SELECT COUNT(*) FROM views) as total_views,
            (SELECT COUNT(*) FROM links 
             WHERE (revoked IS NULL OR revoked = FALSE)
               AND (expires_at IS NULL OR expires_at > now())) as active_links
        "#,
    )
    .fetch_one(pool)
    .await
}

// ============================================================================
// Custom Blocklist
// ============================================================================

pub async fn add_to_custom_blocklist(
    pool: &PgPool,
    domain: &str,
) -> Result<CustomBlocklistEntry, sqlx::Error> {
    sqlx::query_as::<_, CustomBlocklistEntry>(
        r#"
        INSERT INTO custom_blocklist (domain)
        VALUES ($1)
        ON CONFLICT (domain) DO UPDATE SET domain = EXCLUDED.domain
        RETURNING *
        "#,
    )
    .bind(domain.to_lowercase())
    .fetch_one(pool)
    .await
}

pub async fn remove_from_custom_blocklist(pool: &PgPool, domain: &str) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM custom_blocklist WHERE domain = $1")
        .bind(domain.to_lowercase())
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn is_domain_in_custom_blocklist(pool: &PgPool, domain: &str) -> Result<bool, sqlx::Error> {
    let result = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM custom_blocklist WHERE domain = $1",
    )
    .bind(domain.to_lowercase())
    .fetch_one(pool)
    .await?;
    Ok(result > 0)
}

pub async fn list_custom_blocklist(pool: &PgPool) -> Result<Vec<CustomBlocklistEntry>, sqlx::Error> {
    sqlx::query_as::<_, CustomBlocklistEntry>(
        "SELECT * FROM custom_blocklist ORDER BY domain",
    )
    .fetch_all(pool)
    .await
}

// ============================================================================
// Analytics / Stats
// ============================================================================

#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct DocumentStats {
    pub document_id: Uuid,
    pub total_views: i64,
    pub unique_viewers: i64,
    pub total_links: i64,
    pub active_links: i64,
}

pub async fn get_document_stats(pool: &PgPool, document_id: Uuid) -> Result<DocumentStats, sqlx::Error> {
    sqlx::query_as::<_, DocumentStats>(
        r#"
        SELECT
            $1::uuid as document_id,
            (SELECT COUNT(*) FROM views v
             JOIN access_tokens at ON v.access_token_id = at.id
             JOIN links l ON at.link_id = l.id
             WHERE l.document_id = $1) as total_views,
            (SELECT COUNT(DISTINCT v.email) FROM views v
             JOIN access_tokens at ON v.access_token_id = at.id
             JOIN links l ON at.link_id = l.id
             WHERE l.document_id = $1) as unique_viewers,
            (SELECT COUNT(*) FROM links WHERE document_id = $1) as total_links,
            (SELECT COUNT(*) FROM links
             WHERE document_id = $1
               AND (revoked IS NULL OR revoked = FALSE)
               AND (expires_at IS NULL OR expires_at > now())) as active_links
        "#,
    )
    .bind(document_id)
    .fetch_one(pool)
    .await
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct LinkWithDocument {
    pub link_id: Uuid,
    pub short_code: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked: Option<bool>,
    pub link_created_at: Option<DateTime<Utc>>,
    pub document_id: Uuid,
    pub document_name: String,
    pub filename: String,
}

pub async fn get_link_with_document(
    pool: &PgPool,
    short_code: &str,
) -> Result<Option<LinkWithDocument>, sqlx::Error> {
    sqlx::query_as::<_, LinkWithDocument>(
        r#"
        SELECT
            l.id as link_id,
            l.short_code,
            l.expires_at,
            l.revoked,
            l.created_at as link_created_at,
            d.id as document_id,
            d.name as document_name,
            d.filename
        FROM links l
        JOIN documents d ON l.document_id = d.id
        WHERE l.short_code = $1
        "#,
    )
    .bind(short_code)
    .fetch_optional(pool)
    .await
}

// ============================================================================
// Access Attempts
// ============================================================================

#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct AccessAttempt {
    pub id: Uuid,
    pub short_code: String,
    pub email: String,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub success: bool,
    pub failure_reason: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct AccessAttemptWithDocument {
    pub id: Uuid,
    pub short_code: String,
    pub email: String,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub success: bool,
    pub failure_reason: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub document_name: Option<String>,
}

pub async fn log_access_attempt(
    pool: &PgPool,
    short_code: &str,
    email: &str,
    ip: Option<&str>,
    user_agent: Option<&str>,
    success: bool,
    failure_reason: Option<&str>,
) -> Result<AccessAttempt, sqlx::Error> {
    sqlx::query_as::<_, AccessAttempt>(
        r#"
        INSERT INTO access_attempts (short_code, email, ip, user_agent, success, failure_reason)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING *
        "#,
    )
    .bind(short_code)
    .bind(email)
    .bind(ip)
    .bind(user_agent)
    .bind(success)
    .bind(failure_reason)
    .fetch_one(pool)
    .await
}

pub async fn list_access_attempts(
    pool: &PgPool,
    limit: i64,
    offset: i64,
) -> Result<Vec<AccessAttemptWithDocument>, sqlx::Error> {
    sqlx::query_as::<_, AccessAttemptWithDocument>(
        r#"
        SELECT
            a.id,
            a.short_code,
            a.email,
            a.ip,
            a.user_agent,
            a.success,
            a.failure_reason,
            a.created_at,
            d.name as document_name
        FROM access_attempts a
        LEFT JOIN links l ON a.short_code = l.short_code
        LEFT JOIN documents d ON l.document_id = d.id
        ORDER BY a.created_at DESC
        LIMIT $1 OFFSET $2
        "#,
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
}

pub async fn list_failed_attempts(
    pool: &PgPool,
    limit: i64,
    offset: i64,
) -> Result<Vec<AccessAttemptWithDocument>, sqlx::Error> {
    sqlx::query_as::<_, AccessAttemptWithDocument>(
        r#"
        SELECT
            a.id,
            a.short_code,
            a.email,
            a.ip,
            a.user_agent,
            a.success,
            a.failure_reason,
            a.created_at,
            d.name as document_name
        FROM access_attempts a
        LEFT JOIN links l ON a.short_code = l.short_code
        LEFT JOIN documents d ON l.document_id = d.id
        WHERE a.success = FALSE
        ORDER BY a.created_at DESC
        LIMIT $1 OFFSET $2
        "#,
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
}
