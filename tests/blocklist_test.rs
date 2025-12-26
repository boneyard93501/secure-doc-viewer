//! Tests for blocklist module
//!
//! Run: cargo test test_blocklist -- --nocapture

mod common;

use common::TestDb;
use docsend::blocklist;

#[test]
fn test_blocklist_loads() {
    println!("\n============================================================");
    println!("TEST: Blocklist loads from file");
    println!("============================================================");

    let blocklist = blocklist::load_blocklist();
    
    println!("  Loaded {} domains", blocklist.len());
    assert!(blocklist.len() > 3000, "Expected 3000+ domains, got {}", blocklist.len());
    println!("  ✓ Blocklist has {} domains", blocklist.len());

    // Verify some known domains
    assert!(blocklist.contains("gmail.com"));
    assert!(blocklist.contains("yahoo.com"));
    assert!(blocklist.contains("hotmail.com"));
    assert!(blocklist.contains("protonmail.com"));
    assert!(blocklist.contains("tuta.io"));
    println!("  ✓ Contains known free email domains");

    println!("\n  ✓ Blocklist load test passed\n");
}

#[test]
fn test_extract_domain() {
    println!("\n============================================================");
    println!("TEST: Extract domain from email");
    println!("============================================================");

    assert_eq!(blocklist::extract_domain("user@example.com"), Some("example.com"));
    assert_eq!(blocklist::extract_domain("user@sub.example.com"), Some("sub.example.com"));
    assert_eq!(blocklist::extract_domain("user.name@company.co.uk"), Some("company.co.uk"));
    assert_eq!(blocklist::extract_domain("invalid"), None);
    assert_eq!(blocklist::extract_domain("also@invalid@email"), Some("invalid@email")); // weird but expected
    
    println!("  ✓ Domain extraction works");
    println!("\n  ✓ Extract domain test passed\n");
}

#[test]
fn test_email_format_validation() {
    println!("\n============================================================");
    println!("TEST: Email format validation");
    println!("============================================================");

    // Valid emails
    assert!(blocklist::is_valid_email_format("user@example.com"));
    assert!(blocklist::is_valid_email_format("user.name@example.com"));
    assert!(blocklist::is_valid_email_format("user+tag@example.com"));
    assert!(blocklist::is_valid_email_format("user@sub.example.com"));
    assert!(blocklist::is_valid_email_format("a@b.co"));
    println!("  ✓ Valid emails pass");

    // Invalid emails
    assert!(!blocklist::is_valid_email_format("invalid"));
    assert!(!blocklist::is_valid_email_format("@example.com"));
    assert!(!blocklist::is_valid_email_format("user@"));
    assert!(!blocklist::is_valid_email_format("user@.com"));
    assert!(!blocklist::is_valid_email_format("user@com."));
    assert!(!blocklist::is_valid_email_format("user@nodot"));
    assert!(!blocklist::is_valid_email_format(""));
    println!("  ✓ Invalid emails fail");

    println!("\n  ✓ Email format validation test passed\n");
}

#[test]
fn test_static_blocklist_check() {
    println!("\n============================================================");
    println!("TEST: Static blocklist domain check");
    println!("============================================================");

    // Initialize blocklist
    blocklist::load_blocklist();

    // Blocked domains
    assert!(blocklist::is_blocked_domain("gmail.com"));
    assert!(blocklist::is_blocked_domain("yahoo.com"));
    assert!(blocklist::is_blocked_domain("hotmail.com"));
    assert!(blocklist::is_blocked_domain("outlook.com"));
    assert!(blocklist::is_blocked_domain("protonmail.com"));
    assert!(blocklist::is_blocked_domain("tuta.io"));
    assert!(blocklist::is_blocked_domain("icloud.com"));
    assert!(blocklist::is_blocked_domain("aol.com"));
    println!("  ✓ Known free email domains blocked");

    // Case insensitive
    assert!(blocklist::is_blocked_domain("GMAIL.COM"));
    assert!(blocklist::is_blocked_domain("Gmail.Com"));
    assert!(blocklist::is_blocked_domain("YaHoO.cOm"));
    println!("  ✓ Case insensitive matching");

    // Not blocked (business domains)
    assert!(!blocklist::is_blocked_domain("company.com"));
    assert!(!blocklist::is_blocked_domain("anthropic.com"));
    assert!(!blocklist::is_blocked_domain("sequoiacap.com"));
    assert!(!blocklist::is_blocked_domain("a16z.com"));
    println!("  ✓ Business domains not blocked");

    println!("\n  ✓ Static blocklist check test passed\n");
}

#[test]
fn test_blocked_email_check() {
    println!("\n============================================================");
    println!("TEST: Email blocklist check");
    println!("============================================================");

    blocklist::load_blocklist();

    // Blocked emails
    assert!(blocklist::is_blocked_email("user@gmail.com"));
    assert!(blocklist::is_blocked_email("john.doe@yahoo.com"));
    assert!(blocklist::is_blocked_email("test@protonmail.com"));
    assert!(blocklist::is_blocked_email("secure@tuta.io"));
    println!("  ✓ Blocked emails detected");

    // Case insensitive
    assert!(blocklist::is_blocked_email("user@GMAIL.COM"));
    assert!(blocklist::is_blocked_email("user@Gmail.Com"));
    println!("  ✓ Case insensitive");

    // Not blocked
    assert!(!blocklist::is_blocked_email("user@company.com"));
    assert!(!blocklist::is_blocked_email("investor@sequoiacap.com"));
    println!("  ✓ Business emails not blocked");

    // Invalid format
    assert!(!blocklist::is_blocked_email("invalid")); // false because can't extract domain
    println!("  ✓ Invalid emails return false");

    println!("\n  ✓ Blocked email check test passed\n");
}

#[tokio::test]
async fn test_custom_blocklist_integration() {
    println!("\n============================================================");
    println!("TEST: Custom blocklist with database");
    println!("============================================================");

    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Add to custom blocklist
    docsend::db::add_to_custom_blocklist(pool, "competitor.com")
        .await
        .expect("Failed to add");
    println!("  ✓ Added competitor.com to custom blocklist");

    // Check custom blocked
    let blocked = blocklist::is_custom_blocked(pool, "competitor.com")
        .await
        .expect("Query failed");
    assert!(blocked);
    println!("  ✓ Custom blocked domain detected");

    // Check not custom blocked
    let not_blocked = blocklist::is_custom_blocked(pool, "allowed.com")
        .await
        .expect("Query failed");
    assert!(!not_blocked);
    println!("  ✓ Non-blocked domain passes");

    println!("\n  ✓ Custom blocklist integration test passed\n");
}

#[tokio::test]
async fn test_full_email_validation() {
    println!("\n============================================================");
    println!("TEST: Full email validation (static + custom)");
    println!("============================================================");

    let test_db = TestDb::new().await;
    let pool = &test_db.pool;
    blocklist::load_blocklist();

    // Add custom blocked domain
    docsend::db::add_to_custom_blocklist(pool, "customblocked.com")
        .await
        .expect("Failed to add");

    // Test validate_email function
    
    // Invalid format
    let result = blocklist::validate_email(pool, "invalid").await;
    assert!(matches!(result, Err(blocklist::EmailValidationError::InvalidFormat)));
    println!("  ✓ Invalid format detected");

    // Static blocklist
    let result = blocklist::validate_email(pool, "user@gmail.com").await;
    assert!(matches!(result, Err(blocklist::EmailValidationError::BlockedDomain(_))));
    println!("  ✓ Static blocked domain detected");

    // Custom blocklist
    let result = blocklist::validate_email(pool, "user@customblocked.com").await;
    assert!(matches!(result, Err(blocklist::EmailValidationError::CustomBlockedDomain(_))));
    println!("  ✓ Custom blocked domain detected");

    // Valid email
    let result = blocklist::validate_email(pool, "user@legitimate-company.com").await;
    assert!(result.is_ok());
    println!("  ✓ Valid business email passes");

    // Test is_email_allowed function
    let allowed = blocklist::is_email_allowed(pool, "user@company.com")
        .await
        .expect("Query failed");
    assert!(allowed);
    println!("  ✓ is_email_allowed returns true for valid");

    let not_allowed = blocklist::is_email_allowed(pool, "user@gmail.com")
        .await
        .expect("Query failed");
    assert!(!not_allowed);
    println!("  ✓ is_email_allowed returns false for blocked");

    println!("\n  ✓ Full email validation test passed\n");
}

#[test]
fn test_error_display() {
    println!("\n============================================================");
    println!("TEST: Error message formatting");
    println!("============================================================");

    let err1 = blocklist::EmailValidationError::InvalidFormat;
    assert_eq!(format!("{}", err1), "Invalid email format");
    println!("  ✓ InvalidFormat: {}", err1);

    let err2 = blocklist::EmailValidationError::BlockedDomain("gmail.com".to_string());
    assert!(format!("{}", err2).contains("gmail.com"));
    println!("  ✓ BlockedDomain: {}", err2);

    let err3 = blocklist::EmailValidationError::CustomBlockedDomain("competitor.com".to_string());
    assert!(format!("{}", err3).contains("competitor.com"));
    println!("  ✓ CustomBlockedDomain: {}", err3);

    println!("\n  ✓ Error display test passed\n");
}

#[test]
fn test_privacy_providers_blocked() {
    println!("\n============================================================");
    println!("TEST: Privacy-focused providers blocked");
    println!("============================================================");

    blocklist::load_blocklist();

    // Tutanota variants
    assert!(blocklist::is_blocked_domain("tuta.io"));
    assert!(blocklist::is_blocked_domain("tuta.com"));
    assert!(blocklist::is_blocked_domain("tutamail.com"));
    assert!(blocklist::is_blocked_domain("tutanota.com"));
    assert!(blocklist::is_blocked_domain("tutanota.de"));
    println!("  ✓ Tutanota variants blocked");

    // ProtonMail variants
    assert!(blocklist::is_blocked_domain("protonmail.com"));
    assert!(blocklist::is_blocked_domain("protonmail.ch"));
    assert!(blocklist::is_blocked_domain("proton.me"));
    assert!(blocklist::is_blocked_domain("pm.me"));
    println!("  ✓ ProtonMail variants blocked");

    // SimpleLogin
    assert!(blocklist::is_blocked_domain("simplelogin.co"));
    assert!(blocklist::is_blocked_domain("simplelogin.com"));
    println!("  ✓ SimpleLogin blocked");

    // Other privacy providers
    assert!(blocklist::is_blocked_domain("mailfence.com"));
    assert!(blocklist::is_blocked_domain("mailbox.org"));
    assert!(blocklist::is_blocked_domain("startmail.com"));
    assert!(blocklist::is_blocked_domain("posteo.de"));
    println!("  ✓ Other privacy providers blocked");

    println!("\n  ✓ Privacy providers test passed\n");
}

#[test]
fn test_disposable_providers_blocked() {
    println!("\n============================================================");
    println!("TEST: Disposable email providers blocked");
    println!("============================================================");

    blocklist::load_blocklist();

    // Guerrilla Mail
    assert!(blocklist::is_blocked_domain("guerrillamail.com"));
    assert!(blocklist::is_blocked_domain("guerrillamail.org"));
    assert!(blocklist::is_blocked_domain("sharklasers.com"));
    println!("  ✓ Guerrilla Mail blocked");

    // 10 Minute Mail and similar
    assert!(blocklist::is_blocked_domain("10minutemail.com"));
    println!("  ✓ 10 Minute Mail blocked");

    // Temp mail providers
    assert!(blocklist::is_blocked_domain("tempmail.com"));
    assert!(blocklist::is_blocked_domain("throwawaymail.com"));
    println!("  ✓ Temp mail providers blocked");

    println!("\n  ✓ Disposable providers test passed\n");
}
