pub mod db;
pub mod blocklist;

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub branding: BrandingConfig,
    pub database: DatabaseConfig,
    pub test_database: Option<DatabaseConfig>,
    pub auth: AuthConfig,
    pub email: EmailConfig,
    pub blocklist: BlocklistConfig,
    pub rate_limit: RateLimitConfig,
    pub logging: LoggingConfig,
    pub routes: RoutesConfig,
    pub messages: MessagesConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub static_dir: String,
    pub upload_dir: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BrandingConfig {
    pub owner_name: String,
    pub document_title_default: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub database: String,
    pub max_connections: u32,
}

impl DatabaseConfig {
    pub fn connection_string(&self, password: &str) -> String {
        format!(
            "postgres://{}:{}@{}:{}/{}",
            self.user, password, self.host, self.port, self.database
        )
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthConfig {
    pub admin_token_ttl_secs: u64,
    pub access_token_ttl_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EmailConfig {
    pub from_email: String,
    pub from_name: String,
    pub verification_url_base: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BlocklistConfig {
    pub file_path: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RateLimitConfig {
    pub email_send_per_hour: u32,
    pub token_attempts_per_hour: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RoutesConfig {
    pub health: String,
    pub link_meta: String,
    pub token_meta: String,
    pub verify: String,
    pub document: String,
    pub track: String,
    pub admin_login: String,
    pub admin_password: String,
    pub admin_documents: String,
    pub admin_links: String,
    pub admin_views: String,
    pub admin_blocklist: String,
    pub admin_stats: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MessagesConfig {
    pub email_sent: String,
    pub domain_blocked: String,
    pub link_expired: String,
    pub link_revoked: String,
    pub invalid_token: String,
}

impl Config {
    pub fn load(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }
}
