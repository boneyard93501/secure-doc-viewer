//! Integration tests using ephemeral PostgreSQL via testcontainers
//! 
//! Run: cargo test --test integration_test -- --nocapture --test-threads=1

mod common;

use common::TestDb;
use docsend::db;
use chrono::{Utc, Duration};

// ============================================================================
// Database Function Tests
// ============================================================================

#[tokio::test]
async fn test_admin_crud() {
    println!("\n=== test_admin_crud ===");
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Create admin
    let admin = db::create_admin(pool, "admin@test.com", "hashed_password_123")
        .await
        .expect("Failed to create admin");
    
    assert_eq!(admin.email, "admin@test.com");
    println!("  ✓ Created admin: {}", admin.id);

    // Get by email
    let found = db::get_admin_by_email(pool, "admin@test.com")
        .await
        .expect("Query failed")
        .expect("Admin not found");
    
    assert_eq!(found.id, admin.id);
    println!("  ✓ Found admin by email");

    // Get by ID
    let found = db::get_admin_by_id(pool, admin.id)
        .await
        .expect("Query failed")
        .expect("Admin not found");
    
    assert_eq!(found.email, "admin@test.com");
    println!("  ✓ Found admin by ID");

    // Update password
    let updated = db::update_admin_password(pool, admin.id, "new_hash_456")
        .await
        .expect("Failed to update password");
    
    assert_eq!(updated.password_hash, "new_hash_456");
    println!("  ✓ Updated password");

    // Not found case
    let not_found = db::get_admin_by_email(pool, "nobody@test.com")
        .await
        .expect("Query failed");
    
    assert!(not_found.is_none());
    println!("  ✓ Not found returns None");
}

#[tokio::test]
async fn test_document_crud() {
    println!("\n=== test_document_crud ===");
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Create document
    let doc = db::create_document(pool, "Test Doc", "test.pdf", "/uploads/test.pdf", 1024)
        .await
        .expect("Failed to create document");
    
    assert_eq!(doc.name, "Test Doc");
    assert_eq!(doc.filename, "test.pdf");
    assert_eq!(doc.size_bytes, 1024);
    println!("  ✓ Created document: {}", doc.id);

    // Get by ID
    let found = db::get_document_by_id(pool, doc.id)
        .await
        .expect("Query failed")
        .expect("Document not found");
    
    assert_eq!(found.name, "Test Doc");
    println!("  ✓ Found document by ID");

    // Update name
    let updated = db::update_document_name(pool, doc.id, "Updated Doc")
        .await
        .expect("Failed to update")
        .expect("Not found");
    
    assert_eq!(updated.name, "Updated Doc");
    println!("  ✓ Updated document name");

    // List documents
    let docs = db::list_documents(pool, 10, 0)
        .await
        .expect("Failed to list");
    
    assert_eq!(docs.len(), 1);
    println!("  ✓ Listed 1 document");

    // Delete
    let deleted = db::delete_document(pool, doc.id)
        .await
        .expect("Failed to delete");
    
    assert!(deleted);
    println!("  ✓ Deleted document");

    // Verify deleted
    let not_found = db::get_document_by_id(pool, doc.id)
        .await
        .expect("Query failed");
    
    assert!(not_found.is_none());
    println!("  ✓ Verified deletion");
}

#[tokio::test]
async fn test_link_crud() {
    println!("\n=== test_link_crud ===");
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Setup: create document
    let doc = db::create_document(pool, "Link Test", "test.pdf", "/test.pdf", 100)
        .await
        .unwrap();

    // Create link without expiry
    let link1 = db::create_link(pool, doc.id, "abc123", None, false, None)
        .await
        .expect("Failed to create link");
    
    assert_eq!(link1.short_code, "abc123");
    assert!(link1.expires_at.is_none());
    println!("  ✓ Created link without expiry: {}", link1.id);

    // Create link with expiry
    let expires = Utc::now() + Duration::days(7);
    let link2 = db::create_link(pool, doc.id, "def456", None, false, Some(expires))
        .await
        .expect("Failed to create link");
    
    assert!(link2.expires_at.is_some());
    println!("  ✓ Created link with expiry");

    // Get by short_code
    let found = db::get_link_by_short_code(pool, "abc123")
        .await
        .expect("Query failed")
        .expect("Link not found");
    
    assert_eq!(found.id, link1.id);
    println!("  ✓ Found link by short_code");

    // Get valid link
    let valid = db::get_valid_link_by_short_code(pool, "abc123")
        .await
        .expect("Query failed")
        .expect("Valid link not found");
    
    assert_eq!(valid.id, link1.id);
    println!("  ✓ Got valid link");

    // List for document
    let links = db::list_links_for_document(pool, doc.id)
        .await
        .expect("Failed to list");
    
    assert_eq!(links.len(), 2);
    println!("  ✓ Listed 2 links for document");

    // Revoke link
    let revoked = db::revoke_link(pool, link1.id)
        .await
        .expect("Failed to revoke")
        .expect("Link not found");
    
    assert_eq!(revoked.revoked, Some(true));
    println!("  ✓ Revoked link");

    // Revoked link should not be valid
    let not_valid = db::get_valid_link_by_short_code(pool, "abc123")
        .await
        .expect("Query failed");
    
    assert!(not_valid.is_none());
    println!("  ✓ Revoked link not returned as valid");

    // Get link with document info
    let with_doc = db::get_link_with_document(pool, "def456")
        .await
        .expect("Query failed")
        .expect("Not found");
    
    assert_eq!(with_doc.document_name, "Link Test");
    println!("  ✓ Got link with document info");
}

#[tokio::test]
async fn test_access_token_crud() {
    println!("\n=== test_access_token_crud ===");
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Setup
    let doc = db::create_document(pool, "Token Test", "test.pdf", "/test.pdf", 100)
        .await.unwrap();
    let link = db::create_link(pool, doc.id, "tok123", None, false, None)
        .await.unwrap();

    let expires = Utc::now() + Duration::hours(1);
    
    // Create token
    let token = db::create_access_token(
        pool, link.id, "user@test.com", "magic_token_abc",
        expires, Some("1.2.3.4"), Some("Mozilla/5.0")
    ).await.expect("Failed to create token");
    
    assert_eq!(token.email, "user@test.com");
    assert_eq!(token.token, "magic_token_abc");
    assert_eq!(token.used, Some(false));
    println!("  ✓ Created access token: {}", token.id);

    // Get by token string
    let found = db::get_access_token_by_token(pool, "magic_token_abc")
        .await
        .expect("Query failed")
        .expect("Token not found");
    
    assert_eq!(found.id, token.id);
    println!("  ✓ Found token by string");

    // Get valid token
    let valid = db::get_valid_access_token(pool, "magic_token_abc")
        .await
        .expect("Query failed")
        .expect("Valid token not found");
    
    assert_eq!(valid.id, token.id);
    println!("  ✓ Got valid token");

    // Mark as used
    let used = db::mark_access_token_used(pool, token.id, Some("5.6.7.8"), Some("Chrome"))
        .await
        .expect("Failed to mark used");
    
    assert_eq!(used.used, Some(true));
    assert!(used.verified_at.is_some());
    println!("  ✓ Marked token as used");

    // Used token should not be valid
    let not_valid = db::get_valid_access_token(pool, "magic_token_abc")
        .await
        .expect("Query failed");
    
    assert!(not_valid.is_none());
    println!("  ✓ Used token not returned as valid");

    // List tokens for link
    let tokens = db::list_access_tokens_for_link(pool, link.id)
        .await
        .expect("Failed to list");
    
    assert_eq!(tokens.len(), 1);
    println!("  ✓ Listed tokens for link");
}

#[tokio::test]
async fn test_view_crud() {
    println!("\n=== test_view_crud ===");
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Setup
    let doc = db::create_document(pool, "View Test", "test.pdf", "/test.pdf", 100)
        .await.unwrap();
    let link = db::create_link(pool, doc.id, "view123", None, false, None)
        .await.unwrap();
    let token = db::create_access_token(
        pool, link.id, "viewer@test.com", "viewtoken",
        Utc::now() + Duration::hours(1), None, None
    ).await.unwrap();

    // Create view
    let view = db::create_view(pool, Some(token.id), "viewer@test.com", Some("1.2.3.4"))
        .await
        .expect("Failed to create view");
    
    assert_eq!(view.email, "viewer@test.com");
    println!("  ✓ Created view: {}", view.id);

    // Get by ID
    let found = db::get_view_by_id(pool, view.id)
        .await
        .expect("Query failed")
        .expect("View not found");
    
    assert_eq!(found.email, "viewer@test.com");
    println!("  ✓ Found view by ID");

    // Update view
    let updated = db::update_view(pool, view.id, Some(120), Some(vec![1, 2, 3]))
        .await
        .expect("Failed to update");
    
    assert_eq!(updated.duration_secs, Some(120));
    assert_eq!(updated.pages_viewed, Some(vec![1, 2, 3]));
    println!("  ✓ Updated view with duration and pages");

    // List by email
    let views = db::list_views_by_email(pool, "viewer@test.com", 10, 0)
        .await
        .expect("Failed to list");
    
    assert_eq!(views.len(), 1);
    println!("  ✓ Listed views by email");

    // List for document
    let views = db::list_views_for_document(pool, doc.id, 10, 0)
        .await
        .expect("Failed to list");
    
    assert_eq!(views.len(), 1);
    println!("  ✓ Listed views for document");
}

#[tokio::test]
async fn test_custom_blocklist() {
    println!("\n=== test_custom_blocklist ===");
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Add domain
    let entry = db::add_to_custom_blocklist(pool, "blocked.com")
        .await
        .expect("Failed to add");
    
    assert_eq!(entry.domain, "blocked.com");
    println!("  ✓ Added domain to blocklist: {}", entry.id);

    // Check if blocked
    let is_blocked = db::is_domain_in_custom_blocklist(pool, "blocked.com")
        .await
        .expect("Query failed");
    
    assert!(is_blocked);
    println!("  ✓ Domain is blocked");

    // Check non-blocked
    let is_blocked = db::is_domain_in_custom_blocklist(pool, "allowed.com")
        .await
        .expect("Query failed");
    
    assert!(!is_blocked);
    println!("  ✓ Non-blocked domain returns false");

    // List blocklist
    let list = db::list_custom_blocklist(pool)
        .await
        .expect("Failed to list");
    
    assert_eq!(list.len(), 1);
    println!("  ✓ Listed 1 blocked domain");

    // Remove domain
    let removed = db::remove_from_custom_blocklist(pool, "blocked.com")
        .await
        .expect("Failed to remove");
    
    assert!(removed);
    println!("  ✓ Removed domain");

    // Verify removed
    let is_blocked = db::is_domain_in_custom_blocklist(pool, "blocked.com")
        .await
        .expect("Query failed");
    
    assert!(!is_blocked);
    println!("  ✓ Verified removal");
}

#[tokio::test]
async fn test_document_stats() {
    println!("\n=== test_document_stats ===");
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Create document with links and views
    let doc = db::create_document(pool, "Stats Test", "test.pdf", "/test.pdf", 100)
        .await.unwrap();
    
    // Active link
    let link1 = db::create_link(pool, doc.id, "stat1", None, false, None)
        .await.unwrap();
    
    // Expired link
    let _link2 = db::create_link(pool, doc.id, "stat2", None, false, Some(Utc::now() - Duration::days(1)))
        .await.unwrap();

    // Create views
    let token = db::create_access_token(
        pool, link1.id, "viewer1@test.com", "stattoken1",
        Utc::now() + Duration::hours(1), None, None
    ).await.unwrap();
    
    db::create_view(pool, Some(token.id), "viewer1@test.com", None)
        .await.unwrap();
    
    let token2 = db::create_access_token(
        pool, link1.id, "viewer2@test.com", "stattoken2",
        Utc::now() + Duration::hours(1), None, None
    ).await.unwrap();
    
    db::create_view(pool, Some(token2.id), "viewer2@test.com", None)
        .await.unwrap();

    // Get stats
    let stats = db::get_document_stats(pool, doc.id)
        .await
        .expect("Failed to get stats");
    
    assert_eq!(stats.total_views, 2);
    assert_eq!(stats.unique_viewers, 2);
    assert_eq!(stats.total_links, 2);
    assert_eq!(stats.active_links, 1); // 1 expired
    println!("  ✓ Document stats: {} views, {} unique, {} links, {} active",
        stats.total_views, stats.unique_viewers, stats.total_links, stats.active_links);
}

#[tokio::test]
async fn test_global_stats() {
    println!("\n=== test_global_stats ===");
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Empty stats
    let stats = db::get_global_stats(pool).await.expect("Failed to get stats");
    assert_eq!(stats.total_docs, 0);
    assert_eq!(stats.total_links, 0);
    assert_eq!(stats.total_views, 0);
    println!("  ✓ Empty stats: all zeros");

    // Add data
    let doc = db::create_document(pool, "Global Test", "test.pdf", "/test.pdf", 100)
        .await.unwrap();
    let link = db::create_link(pool, doc.id, "global1", None, false, None)
        .await.unwrap();
    let token = db::create_access_token(
        pool, link.id, "viewer@test.com", "globaltoken",
        Utc::now() + Duration::hours(1), None, None
    ).await.unwrap();
    db::create_view(pool, Some(token.id), "viewer@test.com", None)
        .await.unwrap();

    // Check stats
    let stats = db::get_global_stats(pool).await.expect("Failed to get stats");
    assert_eq!(stats.total_docs, 1);
    assert_eq!(stats.total_links, 1);
    assert_eq!(stats.total_views, 1);
    assert_eq!(stats.active_links, 1);
    println!("  ✓ Stats: {} docs, {} links, {} views, {} active",
        stats.total_docs, stats.total_links, stats.total_views, stats.active_links);
}

#[tokio::test]
async fn test_list_all_links() {
    println!("\n=== test_list_all_links ===");
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Create documents and links
    let doc1 = db::create_document(pool, "Doc 1", "doc1.pdf", "/doc1.pdf", 100)
        .await.unwrap();
    let doc2 = db::create_document(pool, "Doc 2", "doc2.pdf", "/doc2.pdf", 200)
        .await.unwrap();

    db::create_link(pool, doc1.id, "link1", None, false, None).await.unwrap();
    db::create_link(pool, doc1.id, "link2", None, false, None).await.unwrap();
    db::create_link(pool, doc2.id, "link3", None, false, None).await.unwrap();

    // List all links
    let links = db::list_all_links(pool, 10, 0)
        .await
        .expect("Failed to list");
    
    assert_eq!(links.len(), 3);
    println!("  ✓ Listed {} links across all documents", links.len());

    // Check link has document_name
    assert!(links.iter().any(|l| l.document_name == "Doc 1"));
    assert!(links.iter().any(|l| l.document_name == "Doc 2"));
    println!("  ✓ Links have document names attached");
}

#[tokio::test]
async fn test_list_all_views() {
    println!("\n=== test_list_all_views ===");
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Setup
    let doc = db::create_document(pool, "View All Test", "test.pdf", "/test.pdf", 100)
        .await.unwrap();
    let link = db::create_link(pool, doc.id, "viewall", None, false, None)
        .await.unwrap();

    // Create multiple views
    for i in 0..3 {
        let token = db::create_access_token(
            pool, link.id, &format!("viewer{}@test.com", i), &format!("token{}", i),
            Utc::now() + Duration::hours(1), None, None
        ).await.unwrap();
        db::create_view(pool, Some(token.id), &format!("viewer{}@test.com", i), None)
            .await.unwrap();
    }

    // List all views
    let views = db::list_all_views(pool, 10, 0)
        .await
        .expect("Failed to list");
    
    assert_eq!(views.len(), 3);
    println!("  ✓ Listed {} views", views.len());

    // Check view has document_name
    assert!(views.iter().all(|v| v.document_name == "View All Test"));
    println!("  ✓ Views have document names attached");
}

#[tokio::test]
async fn test_cascade_delete() {
    println!("\n=== test_cascade_delete ===");
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Create document with link, token, and view
    let doc = db::create_document(pool, "Cascade Test", "test.pdf", "/test.pdf", 100)
        .await.unwrap();
    let link = db::create_link(pool, doc.id, "cascade1", None, false, None)
        .await.unwrap();
    let token = db::create_access_token(
        pool, link.id, "cascade@test.com", "cascadetoken",
        Utc::now() + Duration::hours(1), None, None
    ).await.unwrap();
    let view = db::create_view(pool, Some(token.id), "cascade@test.com", None)
        .await.unwrap();

    println!("  ✓ Created: doc={}, link={}, token={}, view={}", 
        doc.id, link.id, token.id, view.id);

    // Delete document
    db::delete_document(pool, doc.id).await.expect("Failed to delete");
    println!("  ✓ Deleted document");

    // Verify cascade: link should be gone
    let link_check = db::get_link_by_id(pool, link.id).await.expect("Query failed");
    assert!(link_check.is_none());
    println!("  ✓ Link deleted (cascade)");

    // Verify cascade: token should be gone
    let token_check = db::get_access_token_by_token(pool, "cascadetoken").await.expect("Query failed");
    assert!(token_check.is_none());
    println!("  ✓ Token deleted (cascade)");

    // Verify cascade: view should be gone
    let view_check = db::get_view_by_id(pool, view.id).await.expect("Query failed");
    assert!(view_check.is_none());
    println!("  ✓ View deleted (cascade)");
}

#[tokio::test]
async fn test_expired_link_not_valid() {
    println!("\n=== test_expired_link_not_valid ===");
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    let doc = db::create_document(pool, "Expired Test", "test.pdf", "/test.pdf", 100)
        .await.unwrap();
    
    // Create expired link
    let expired = Utc::now() - Duration::hours(1);
    let link = db::create_link(pool, doc.id, "expired1", None, false, Some(expired))
        .await.unwrap();
    println!("  ✓ Created expired link: {}", link.id);

    // Should not be returned as valid
    let valid = db::get_valid_link_by_short_code(pool, "expired1")
        .await
        .expect("Query failed");
    
    assert!(valid.is_none());
    println!("  ✓ Expired link not returned by get_valid");
}

#[tokio::test]
async fn test_expired_token_not_valid() {
    println!("\n=== test_expired_token_not_valid ===");
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    let doc = db::create_document(pool, "Token Expiry Test", "test.pdf", "/test.pdf", 100)
        .await.unwrap();
    let link = db::create_link(pool, doc.id, "tokenexp", None, false, None)
        .await.unwrap();
    
    // Create expired token
    let expired = Utc::now() - Duration::hours(1);
    let token = db::create_access_token(
        pool, link.id, "expiry@test.com", "expiredtoken",
        expired, None, None
    ).await.unwrap();
    println!("  ✓ Created expired token: {}", token.id);

    // Should not be returned as valid
    let valid = db::get_valid_access_token(pool, "expiredtoken")
        .await
        .expect("Query failed");
    
    assert!(valid.is_none());
    println!("  ✓ Expired token not returned by get_valid");
}

// ============================================================================
// Full Workflow Test
// ============================================================================

#[tokio::test]
async fn test_full_document_sharing_workflow() {
    println!("\n=== test_full_document_sharing_workflow ===");
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    println!("  Step 1: Admin uploads document");
    let doc = db::create_document(pool, "Q4 Pitch Deck", "pitch.pdf", "/uploads/pitch.pdf", 2048000)
        .await.unwrap();
    println!("    ✓ Document created: {}", doc.id);

    println!("  Step 2: Admin creates shareable link");
    let link = db::create_link(pool, doc.id, "pitch2024", None, false, Some(Utc::now() + Duration::days(30)))
        .await.unwrap();
    println!("    ✓ Link created: /d/{}", link.short_code);

    println!("  Step 3: Investor requests access");
    let token = db::create_access_token(
        pool, link.id, "partner@sequoia.com", "magic_link_token",
        Utc::now() + Duration::hours(1), Some("203.0.113.1"), Some("Mozilla/5.0")
    ).await.unwrap();
    println!("    ✓ Access token created for partner@sequoia.com");

    println!("  Step 4: Investor clicks email link, token verified");
    let _ = db::mark_access_token_used(pool, token.id, Some("203.0.113.1"), Some("Mozilla/5.0"))
        .await.unwrap();
    println!("    ✓ Token marked as used");

    println!("  Step 5: View session started");
    let view = db::create_view(pool, Some(token.id), "partner@sequoia.com", Some("203.0.113.1"))
        .await.unwrap();
    println!("    ✓ View session created: {}", view.id);

    println!("  Step 6: Investor views document, tracking sent");
    let updated = db::update_view(pool, view.id, Some(180), Some(vec![1, 2, 3, 4, 5, 6]))
        .await.unwrap();
    println!("    ✓ Tracked: {}s viewing pages {:?}", 
        updated.duration_secs.unwrap(), updated.pages_viewed.unwrap());

    println!("  Step 7: Admin checks stats");
    let stats = db::get_document_stats(pool, doc.id).await.unwrap();
    assert_eq!(stats.total_views, 1);
    assert_eq!(stats.unique_viewers, 1);
    println!("    ✓ Stats: {} total views, {} unique viewers", 
        stats.total_views, stats.unique_viewers);

    println!("\n  ✓ Full workflow completed successfully!\n");
}
