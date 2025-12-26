use std::collections::HashSet;
use std::sync::OnceLock;
use sqlx::PgPool;

static BLOCKLIST: OnceLock<HashSet<String>> = OnceLock::new();

/// Load the blocklist from the embedded file at startup
pub fn load_blocklist() -> &'static HashSet<String> {
    BLOCKLIST.get_or_init(|| {
        let content = include_str!("../data/blocklist.txt");
        content
            .lines()
            .map(|line| line.trim().to_lowercase())
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect()
    })
}

/// Extract domain from email address
pub fn extract_domain(email: &str) -> Option<&str> {
    email.split('@').nth(1)
}

/// Check if an email domain is in the static blocklist
pub fn is_blocked_domain(domain: &str) -> bool {
    let blocklist = load_blocklist();
    blocklist.contains(&domain.to_lowercase())
}

/// Check if an email address uses a blocked domain
pub fn is_blocked_email(email: &str) -> bool {
    match extract_domain(email) {
        Some(domain) => is_blocked_domain(domain),
        None => false,
    }
}

/// Check if domain is in custom blocklist (database)
pub async fn is_custom_blocked(pool: &PgPool, domain: &str) -> Result<bool, sqlx::Error> {
    crate::db::is_domain_in_custom_blocklist(pool, domain).await
}

/// Full validation: check both static and custom blocklists
pub async fn is_email_allowed(pool: &PgPool, email: &str) -> Result<bool, sqlx::Error> {
    let domain = match extract_domain(email) {
        Some(d) => d.to_lowercase(),
        None => return Ok(false), // Invalid email format
    };

    // Check static blocklist first (fast, in-memory)
    if is_blocked_domain(&domain) {
        return Ok(false);
    }

    // Check custom blocklist (database)
    if is_custom_blocked(pool, &domain).await? {
        return Ok(false);
    }

    Ok(true)
}

/// Validate email format (basic check)
pub fn is_valid_email_format(email: &str) -> bool {
    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return false;
    }
    let local = parts[0];
    let domain = parts[1];
    
    // Basic validation
    !local.is_empty() 
        && !domain.is_empty() 
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
}

#[derive(Debug, Clone, PartialEq)]
pub enum EmailValidationError {
    InvalidFormat,
    BlockedDomain(String),
    CustomBlockedDomain(String),
}

impl std::fmt::Display for EmailValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EmailValidationError::InvalidFormat => write!(f, "Invalid email format"),
            EmailValidationError::BlockedDomain(d) => write!(f, "Email domain '{}' is not allowed", d),
            EmailValidationError::CustomBlockedDomain(d) => write!(f, "Email domain '{}' is blocked", d),
        }
    }
}

impl std::error::Error for EmailValidationError {}

/// Full email validation with detailed error
pub async fn validate_email(pool: &PgPool, email: &str) -> Result<(), EmailValidationError> {
    if !is_valid_email_format(email) {
        return Err(EmailValidationError::InvalidFormat);
    }

    let domain = extract_domain(email).unwrap().to_lowercase();

    if is_blocked_domain(&domain) {
        return Err(EmailValidationError::BlockedDomain(domain));
    }

    match is_custom_blocked(pool, &domain).await {
        Ok(true) => Err(EmailValidationError::CustomBlockedDomain(domain)),
        Ok(false) => Ok(()),
        Err(_) => Ok(()), // On DB error, allow (fail open for availability)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_domain() {
        assert_eq!(extract_domain("user@example.com"), Some("example.com"));
        assert_eq!(extract_domain("user@sub.example.com"), Some("sub.example.com"));
        assert_eq!(extract_domain("invalid"), None);
    }

    #[test]
    fn test_is_valid_email_format() {
        assert!(is_valid_email_format("user@example.com"));
        assert!(is_valid_email_format("user.name@example.co.uk"));
        assert!(!is_valid_email_format("invalid"));
        assert!(!is_valid_email_format("@example.com"));
        assert!(!is_valid_email_format("user@"));
        assert!(!is_valid_email_format("user@.com"));
    }

    #[test]
    fn test_blocked_domains() {
        load_blocklist(); // Initialize
        
        // Common free email providers should be blocked
        assert!(is_blocked_email("user@gmail.com"));
        assert!(is_blocked_email("user@yahoo.com"));
        assert!(is_blocked_email("user@hotmail.com"));
        assert!(is_blocked_email("user@outlook.com"));
        assert!(is_blocked_email("user@protonmail.com"));
        assert!(is_blocked_email("user@tuta.io"));
        
        // Case insensitive
        assert!(is_blocked_email("user@GMAIL.COM"));
        assert!(is_blocked_email("user@Gmail.Com"));
        
        // Non-blocked domains
        assert!(!is_blocked_email("user@company.com"));
        assert!(!is_blocked_email("user@anthropic.com"));
    }

    #[test]
    fn test_blocklist_loaded() {
        let blocklist = load_blocklist();
        assert!(blocklist.len() > 1000); // Should have thousands of domains
        assert!(blocklist.contains("gmail.com"));
        assert!(blocklist.contains("yahoo.com"));
    }
}
