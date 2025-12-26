//! API Integration Tests
//!
//! Run: cargo test test_api -- --nocapture
//!
//! Note: These tests verify the handler logic by calling functions directly.
//! For full HTTP testing, use a tool like `reqwest` with a running server.

mod common;

use common::TestDb;
use docsend::{db, blocklist};
use chrono::{Utc, Duration};

/// Test the full access request workflow
#[tokio::test]
async fn test_access_request_workflow() {
    println!("\n============================================================");
    println!("TEST: Access Request Workflow");
    println!("============================================================");

    let test_db = TestDb::new().await;
    let pool = &test_db.pool;
    blocklist::load_blocklist();

    // Setup: Create document and link
    let doc = db::create_document(pool, "Pitch Deck", "deck.pdf", "/uploads/deck.pdf", 5000)
        .await
        .expect("Failed to create document");
    println!("  1. ✓ Created document: {}", doc.name);

    let link = db::create_link(pool, doc.id, "pitch123", None, false, None)
        .await
        .expect("Failed to create link");
    println!("  2. ✓ Created link: {}", link.short_code);

    // Step 1: Viewer requests access
    let email = "investor@sequoiacap.com";
    
    // Validate email first
    assert!(blocklist::is_valid_email_format(email));
    assert!(blocklist::is_email_allowed(pool, email).await.unwrap());
    println!("  3. ✓ Email validated: {}", email);

    // Create access token
    let token_str = "test_magic_token_12345";
    let expires_at = Utc::now() + Duration::hours(1);
    let access_token = db::create_access_token(
        pool,
        link.id,
        email,
        token_str,
        expires_at,
        Some("203.0.113.1"),
        Some("Mozilla/5.0"),
    )
        .await
        .expect("Failed to create token");
    println!("  4. ✓ Access token created (would email to user)");

    // Step 2: Viewer clicks magic link
    let valid_token = db::get_valid_access_token(pool, token_str)
        .await
        .expect("Query failed")
        .expect("Token should be valid");
    assert_eq!(valid_token.id, access_token.id);
    println!("  5. ✓ Token verified");

    // Mark token as used
    let used_token = db::mark_access_token_used(
        pool,
        access_token.id,
        Some("203.0.113.1"),
        Some("Mozilla/5.0"),
    )
        .await
        .expect("Failed to mark used");
    assert!(used_token.verified_at.is_some());
    println!("  6. ✓ Token marked as used");

    // Create view record
    let view = db::create_view(pool, Some(access_token.id), email, Some("203.0.113.1"))
        .await
        .expect("Failed to create view");
    println!("  7. ✓ View record created: {}", view.id);

    // Step 3: Track viewing activity
    let updated_view = db::update_view(pool, view.id, Some(120), Some(vec![1, 2, 3, 4, 5]))
        .await
        .expect("Failed to update view");
    assert_eq!(updated_view.duration_secs, Some(120));
    assert_eq!(updated_view.pages_viewed, Some(vec![1, 2, 3, 4, 5]));
    println!("  8. ✓ View tracking updated (120s, 5 pages)");

    // Verify stats
    let stats = db::get_document_stats(pool, doc.id)
        .await
        .expect("Failed to get stats");
    assert_eq!(stats.total_views, 1);
    assert_eq!(stats.unique_viewers, 1);
    println!("  9. ✓ Document stats: {} views, {} unique viewers", 
        stats.total_views, stats.unique_viewers);

    println!("\n  ✓ Access request workflow passed\n");
}

/// Test blocked email rejection
#[tokio::test]
async fn test_blocked_email_rejection() {
    println!("\n============================================================");
    println!("TEST: Blocked Email Rejection");
    println!("============================================================");

    let test_db = TestDb::new().await;
    let pool = &test_db.pool;
    blocklist::load_blocklist();

    // Gmail should be blocked
    let result = blocklist::validate_email(pool, "user@gmail.com").await;
    assert!(result.is_err());
    println!("  ✓ gmail.com blocked");

    // Yahoo should be blocked
    let result = blocklist::validate_email(pool, "user@yahoo.com").await;
    assert!(result.is_err());
    println!("  ✓ yahoo.com blocked");

    // Tutanota should be blocked
    let result = blocklist::validate_email(pool, "user@tuta.io").await;
    assert!(result.is_err());
    println!("  ✓ tuta.io blocked");

    // Add custom blocklist entry
    db::add_to_custom_blocklist(pool, "competitor.vc").await.unwrap();
    let result = blocklist::validate_email(pool, "partner@competitor.vc").await;
    assert!(matches!(result, Err(blocklist::EmailValidationError::CustomBlockedDomain(_))));
    println!("  ✓ Custom blocked domain rejected");

    println!("\n  ✓ Blocked email rejection test passed\n");
}

/// Test link expiration
#[tokio::test]
async fn test_link_expiration() {
    println!("\n============================================================");
    println!("TEST: Link Expiration");
    println!("============================================================");

    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    let doc = db::create_document(pool, "Expiry Test", "test.pdf", "/path", 1000)
        .await.unwrap();

    // Create expired link
    let expired = Utc::now() - Duration::hours(1);
    let _link = db::create_link(pool, doc.id, "expired123", None, false, Some(expired))
        .await.unwrap();
    println!("  1. ✓ Created expired link");

    // get_valid_link_by_short_code should not return expired links
    let result = db::get_valid_link_by_short_code(pool, "expired123")
        .await
        .expect("Query failed");
    assert!(result.is_none());
    println!("  2. ✓ Expired link not returned by valid query");

    // Regular get should still return it
    let result = db::get_link_by_short_code(pool, "expired123")
        .await
        .expect("Query failed");
    assert!(result.is_some());
    println!("  3. ✓ Expired link still exists in database");

    println!("\n  ✓ Link expiration test passed\n");
}

/// Test link revocation
#[tokio::test]
async fn test_link_revocation() {
    println!("\n============================================================");
    println!("TEST: Link Revocation");
    println!("============================================================");

    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    let doc = db::create_document(pool, "Revoke Test", "test.pdf", "/path", 1000)
        .await.unwrap();

    let link = db::create_link(pool, doc.id, "revoke123", None, false, None)
        .await.unwrap();
    println!("  1. ✓ Created link");

    // Link is valid initially
    let valid = db::get_valid_link_by_short_code(pool, "revoke123")
        .await
        .expect("Query failed");
    assert!(valid.is_some());
    println!("  2. ✓ Link is valid");

    // Revoke link
    db::revoke_link(pool, link.id).await.unwrap();
    println!("  3. ✓ Link revoked");

    // Link is no longer valid
    let valid = db::get_valid_link_by_short_code(pool, "revoke123")
        .await
        .expect("Query failed");
    assert!(valid.is_none());
    println!("  4. ✓ Revoked link not returned by valid query");

    println!("\n  ✓ Link revocation test passed\n");
}

/// Test token expiration
#[tokio::test]
async fn test_token_expiration() {
    println!("\n============================================================");
    println!("TEST: Token Expiration");
    println!("============================================================");

    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    let doc = db::create_document(pool, "Token Exp Test", "test.pdf", "/path", 1000)
        .await.unwrap();
    let link = db::create_link(pool, doc.id, "tokexp123", None, false, None)
        .await.unwrap();

    // Create expired token
    let expired = Utc::now() - Duration::minutes(30);
    db::create_access_token(pool, link.id, "user@corp.com", "expiredtoken", expired, None, None)
        .await.unwrap();
    println!("  1. ✓ Created expired token");

    // get_valid_access_token should not return expired tokens
    let result = db::get_valid_access_token(pool, "expiredtoken")
        .await
        .expect("Query failed");
    assert!(result.is_none());
    println!("  2. ✓ Expired token not returned by valid query");

    println!("\n  ✓ Token expiration test passed\n");
}

/// Test token single-use
#[tokio::test]
async fn test_token_single_use() {
    println!("\n============================================================");
    println!("TEST: Token Single Use");
    println!("============================================================");

    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    let doc = db::create_document(pool, "Single Use Test", "test.pdf", "/path", 1000)
        .await.unwrap();
    let link = db::create_link(pool, doc.id, "single123", None, false, None)
        .await.unwrap();

    let expires = Utc::now() + Duration::hours(1);
    let token = db::create_access_token(pool, link.id, "user@corp.com", "singleuse", expires, None, None)
        .await.unwrap();
    println!("  1. ✓ Created token");

    // Token is valid
    let valid = db::get_valid_access_token(pool, "singleuse")
        .await
        .expect("Query failed");
    assert!(valid.is_some());
    println!("  2. ✓ Token is valid");

    // Use the token
    db::mark_access_token_used(pool, token.id, None, None)
        .await.unwrap();
    println!("  3. ✓ Token marked as used");

    // Token is no longer valid
    let valid = db::get_valid_access_token(pool, "singleuse")
        .await
        .expect("Query failed");
    assert!(valid.is_none());
    println!("  4. ✓ Used token not returned by valid query");

    println!("\n  ✓ Token single use test passed\n");
}

/// Test admin authentication flow
#[tokio::test]
async fn test_admin_auth_flow() {
    println!("\n============================================================");
    println!("TEST: Admin Authentication Flow");
    println!("============================================================");

    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Create admin with hashed password
    // In real code, we'd use the hash_password function from main.rs
    let fake_hash = "$argon2id$v=19$m=19456,t=2,p=1$somesalt$somehash";
    let admin = db::create_admin(pool, "admin@company.com", fake_hash)
        .await
        .expect("Failed to create admin");
    println!("  1. ✓ Created admin: {}", admin.email);

    // Look up by email (login flow)
    let found = db::get_admin_by_email(pool, "admin@company.com")
        .await
        .expect("Query failed")
        .expect("Admin not found");
    assert_eq!(found.id, admin.id);
    println!("  2. ✓ Found admin by email");

    // Wrong email returns None
    let not_found = db::get_admin_by_email(pool, "wrong@company.com")
        .await
        .expect("Query failed");
    assert!(not_found.is_none());
    println!("  3. ✓ Wrong email returns None");

    // Change password
    let new_hash = "$argon2id$v=19$m=19456,t=2,p=1$newsalt$newhash";
    let updated = db::update_admin_password(pool, admin.id, new_hash)
        .await
        .expect("Failed to update");
    assert!(updated.password_changed_at.is_some());
    assert_eq!(updated.password_hash, new_hash);
    println!("  4. ✓ Password updated");

    println!("\n  ✓ Admin auth flow test passed\n");
}

/// Test document cascade delete
#[tokio::test]
async fn test_document_cascade_delete() {
    println!("\n============================================================");
    println!("TEST: Document Cascade Delete");
    println!("============================================================");

    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Create document with links, tokens, and views
    let doc = db::create_document(pool, "Cascade Test", "test.pdf", "/path", 1000)
        .await.unwrap();
    let link = db::create_link(pool, doc.id, "cascade123", None, false, None)
        .await.unwrap();
    let expires = Utc::now() + Duration::hours(1);
    let token = db::create_access_token(pool, link.id, "user@corp.com", "cascadetok", expires, None, None)
        .await.unwrap();
    db::create_view(pool, Some(token.id), "user@corp.com", None)
        .await.unwrap();
    println!("  1. ✓ Created document with link, token, view");

    // Delete document
    let deleted = db::delete_document(pool, doc.id).await.unwrap();
    assert!(deleted);
    println!("  2. ✓ Document deleted");

    // Link should be gone (CASCADE)
    let link_gone = db::get_link_by_id(pool, link.id)
        .await
        .expect("Query failed");
    assert!(link_gone.is_none());
    println!("  3. ✓ Link cascade deleted");

    // Token should be gone (CASCADE)
    let token_gone = db::get_access_token_by_token(pool, "cascadetok")
        .await
        .expect("Query failed");
    assert!(token_gone.is_none());
    println!("  4. ✓ Token cascade deleted");

    println!("\n  ✓ Document cascade delete test passed\n");
}
