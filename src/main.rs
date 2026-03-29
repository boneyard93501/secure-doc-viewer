mod types;
mod auth;
mod routes;

use axum::routing::{get, post, put, delete};
use axum::Router;
use docsend::{Config, blocklist};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::sync::Arc;
use tower_http::cors::{CorsLayer, Any};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

use routes::{public, admin, export};

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub config: Arc<Config>,
    pub jwt_secret: String,
    pub resend_api_key: Option<String>,
}

pub fn build_app(state: AppState, static_dir: &str) -> Router {
    Router::new()
        .route("/", get(public::root_redirect))
        .route("/health", get(public::health))
        .route("/d/{short_code}", get(public::serve_document_form))
        .route("/api/link/{short_code}/meta", get(public::get_link_meta))
        .route("/api/link/{short_code}/access", post(public::request_access))
        .route("/api/verify", post(public::verify_token))
        .route("/api/track", post(public::track_view))
        .route("/api/document/{token}", get(public::serve_document_file))
        .route("/api/admin/login", post(admin::admin_login))
        .route("/api/admin/password", put(admin::admin_change_password))
        .route("/api/admin/documents", get(admin::list_documents).post(admin::upload_document))
        .route("/api/admin/documents/{id}", delete(admin::delete_document))
        .route("/api/admin/documents/{id}/links", get(admin::list_links))
        .route("/api/admin/documents/{id}/views", get(admin::list_views))
        .route("/api/admin/documents/{id}/stats", get(admin::get_document_stats))
        .route("/api/admin/links", get(admin::list_all_links).post(admin::create_link))
        .route("/api/admin/links/{id}/revoke", post(admin::revoke_link))
        .route("/api/admin/views", get(admin::list_all_views))
        .route("/api/admin/attempts", get(admin::list_access_attempts))
        .route("/api/admin/stats", get(admin::get_global_stats))
        .route("/api/admin/blocklist", get(admin::list_blocklist).post(admin::add_to_blocklist))
        .route("/api/admin/blocklist/{domain}", delete(admin::remove_from_blocklist))
        .route("/api/admin/export/documents", get(export::export_documents_csv))
        .route("/api/admin/export/links", get(export::export_links_csv))
        .route("/api/admin/export/views", get(export::export_views_csv))
        .route("/api/admin/export/attempts", get(export::export_attempts_csv))
        .route("/admin", get(public::serve_admin))
        .route("/view", get(public::serve_viewer))
        .nest_service("/static", ServeDir::new(static_dir))
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any))
        .layer(RequestBodyLimitLayer::new(100 * 1024 * 1024))
        .with_state(state)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();

    let config_path = std::env::var("CONFIG_PATH").unwrap_or_else(|_| "config.toml".to_string());
    let config = Config::load(&config_path)?;

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new(&config.logging.level)))
        .init();

    blocklist::load_blocklist();
    tracing::info!("Loaded {} domains into blocklist", blocklist::load_blocklist().len());

    let db_password = std::env::var("DB_PASSWORD").expect("DB_PASSWORD must be set");
    let database_url = config.database.connection_string(&db_password);

    let pool = PgPoolOptions::new()
        .max_connections(config.database.max_connections)
        .connect(&database_url)
        .await?;

    tracing::info!("Connected to database");

    tokio::fs::create_dir_all(&config.server.upload_dir).await?;

    let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    let resend_api_key = std::env::var("RESEND_API_KEY").ok();

    let state = AppState {
        pool,
        config: Arc::new(config.clone()),
        jwt_secret,
        resend_api_key,
    };

    let app = build_app(state, &config.server.static_dir);

    let addr = format!("{}:{}", config.server.host, config.server.port);
    tracing::info!("Starting server on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>()
    ).await?;

    Ok(())
}
