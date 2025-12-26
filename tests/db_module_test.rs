//! Tests for db module functions
//!
//! Run: cargo test test_db_module -- --nocapture

mod common;

use common::TestDb;
use docsend::db;
use chrono::{Utc, Duration};

#[tokio::test]
async fn test_admin_crud() {
    println!("\n============================================================");
    println!("TEST: Admin CRUD (db module)");
    println!("============================================================");

    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Create
    let admin = db::create_admin(pool, "admin@test.com", "$argon2id$fakehash")
        .await
        .expect("Failed to create admin");
    println!("  ✓ Created admin: {}", admin.id);
    assert_eq!(admin.email, "admin@test.com");

    // Get by email
    let found = db::get_admin_by_email(pool, "admin@test.com")
        .await
        .expect("Query failed")
        .expect("Admin not found");
    assert_eq!(found.id, admin.id);
    println!("  ✓ Found by email");

    // Get by id
    let found = db::get_admin_by_id(pool, admin.id)
        .await
        .expect("Query failed")
        .expect("Admin not found");
    assert_eq!(found.email, "admin@test.com");
    println!("  ✓ Found by id");

    // Update password
    let updated = db::update_admin_password(pool, admin.id, "$argon2id$newhash")
        .await
        .expect("Failed to update password");
    assert!(updated.password_changed_at.is_some());
    println!("  ✓ Updated password");

    // Not found
    let not_found = db::get_admin_by_email(pool, "nobody@test.com")
        .await
        .expect("Query failed");
    assert!(not_found.is_none());
    println!("  ✓ Not found returns None");

    println!("\n  ✓ Admin CRUD passed\n");
}

#[tokio::test]
async fn test_document_crud() {
    println!("\n============================================================");
    println!("TEST: Document CRUD (db module)");
    println!("============================================================");

    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Create
    let doc = db::create_document(pool, "Test Doc", "test.pdf", "/uploads/test.pdf", 1024)
        .await
        .expect("Failed to create document");
    println!("  ✓ Created document: {}", doc.id);
    assert_eq!(doc.name, "Test Doc");
    assert_eq!(doc.filename, "test.pdf");
    assert_eq!(doc.size_bytes, 1024);

    // Get by id
    let found = db::get_document_by_id(pool, doc.id)
        .await
        .expect("Query failed")
        .expect("Document not found");
    assert_eq!(found.name, "Test Doc");
    println!("  ✓ Found by id");

    // Update name
    let updated = db::update_document_name(pool, doc.id, "Renamed Doc")
        .await
        .expect("Failed to update")
        .expect("Document not found");
    assert_eq!(updated.name, "Renamed Doc");
    println!("  ✓ Updated name");

    // List
    let docs = db::list_documents(pool, 10, 0)
        .await
        .expect("Failed to list");
    assert_eq!(docs.len(), 1);
    println!("  ✓ Listed documents");

    // Delete
    let deleted = db::delete_document(pool, doc.id)
        .await
        .expect("Failed to delete");
    assert!(deleted);
    println!("  ✓ Deleted document");

    // Verify deleted
    let gone = db::get_document_by_id(pool, doc.id)
        .await
        .expect("Query failed");
    assert!(gone.is_none());
    println!("  ✓ Verified deletion");

    println!("\n  ✓ Document CRUD passed\n");
}

#[tokio::test]
async fn test_link_crud() {
    println!("\n============================================================");
    println!("TEST: Link CRUD (db module)");
    println!("============================================================");

    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Setup: create document
    let doc = db::create_document(pool, "Link Test", "test.pdf", "/uploads/test.pdf", 1024)
        .await
        .expect("Failed to create document");

    // Create link (no expiry)
    let link1 = db::create_link(pool, doc.id, "abc123", None, false, None)
        .await
        .expect("Failed to create link");
    println!("  ✓ Created link: {}", link1.short_code);
    assert_eq!(link1.short_code, "abc123");
    assert!(link1.expires_at.is_none());

    // Create link (with expiry)
    let expires = Utc::now() + Duration::days(7);
    let link2 = db::create_link(pool, doc.id, "xyz789", None, false, Some(expires))
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
    println!("  ✓ Found by short_code");

    // Get valid link
    let valid = db::get_valid_link_by_short_code(pool, "abc123")
        .await
        .expect("Query failed")
        .expect("Valid link not found");
    assert_eq!(valid.id, link1.id);
    println!("  ✓ Valid link query works");

    // List for document
    let links = db::list_links_for_document(pool, doc.id)
        .await
        .expect("Failed to list");
    assert_eq!(links.len(), 2);
    println!("  ✓ Listed {} links", links.len());

    // Revoke
    let revoked = db::revoke_link(pool, link1.id)
        .await
        .expect("Failed to revoke")
        .expect("Link not found");
    assert_eq!(revoked.revoked, Some(true));
    println!("  ✓ Revoked link");

    // Revoked link not valid
    let not_valid = db::get_valid_link_by_short_code(pool, "abc123")
        .await
        .expect("Query failed");
    assert!(not_valid.is_none());
    println!("  ✓ Revoked link not returned by valid query");

    // Get link with document
    let with_doc = db::get_link_with_document(pool, "xyz789")
        .await
        .expect("Query failed")
        .expect("Not found");
    assert_eq!(with_doc.document_name, "Link Test");
    assert_eq!(with_doc.short_code, "xyz789");
    println!("  ✓ Link with document join works");

    println!("\n  ✓ Link CRUD passed\n");
}

#[tokio::test]
async fn test_access_token_crud() {
    println!("\n============================================================");
    println!("TEST: Access Token CRUD (db module)");
    println!("============================================================");

    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Setup
    let doc = db::create_document(pool, "Token Test", "test.pdf", "/path", 1024)
        .await.unwrap();
    let link = db::create_link(pool, doc.id, "tok123", None, false, None)
        .await.unwrap();

    // Create token
    let expires = Utc::now() + Duration::hours(1);
    let token = db::create_access_token(
        pool,
        link.id,
        "user@company.com",
        "magictoken123",
        expires,
        Some("1.2.3.4"),
        Some("Mozilla/5.0"),
    )
        .await
        .expect("Failed to create token");
    println!("  ✓ Created token: {}", token.token);
    assert_eq!(token.email, "user@company.com");
    assert_eq!(token.used, Some(false));

    // Get by token
    let found = db::get_access_token_by_token(pool, "magictoken123")
        .await
        .expect("Query failed")
        .expect("Token not found");
    assert_eq!(found.id, token.id);
    println!("  ✓ Found by token");

    // Get valid token
    let valid = db::get_valid_access_token(pool, "magictoken123")
        .await
        .expect("Query failed")
        .expect("Valid token not found");
    assert_eq!(valid.id, token.id);
    println!("  ✓ Valid token query works");

    // Mark used
    let used = db::mark_access_token_used(pool, token.id, Some("5.6.7.8"), Some("Chrome"))
        .await
        .expect("Failed to mark used");
    assert_eq!(used.used, Some(true));
    assert!(used.verified_at.is_some());
    assert_eq!(used.verified_ip, Some("5.6.7.8".to_string()));
    println!("  ✓ Marked as used");

    // Used token not valid
    let not_valid = db::get_valid_access_token(pool, "magictoken123")
        .await
        .expect("Query failed");
    assert!(not_valid.is_none());
    println!("  ✓ Used token not returned by valid query");

    // List for link
    let tokens = db::list_access_tokens_for_link(pool, link.id)
        .await
        .expect("Failed to list");
    assert_eq!(tokens.len(), 1);
    println!("  ✓ Listed tokens");

    println!("\n  ✓ Access Token CRUD passed\n");
}

#[tokio::test]
async fn test_view_crud() {
    println!("\n============================================================");
    println!("TEST: View CRUD (db module)");
    println!("============================================================");

    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Setup
    let doc = db::create_document(pool, "View Test", "test.pdf", "/path", 1024)
        .await.unwrap();
    let link = db::create_link(pool, doc.id, "view123", None, false, None)
        .await.unwrap();
    let expires = Utc::now() + Duration::hours(1);
    let token = db::create_access_token(pool, link.id, "viewer@corp.com", "viewtok", expires, None, None)
        .await.unwrap();

    // Create view
    let view = db::create_view(pool, Some(token.id), "viewer@corp.com", Some("9.8.7.6"))
        .await
        .expect("Failed to create view");
    println!("  ✓ Created view: {}", view.id);
    assert_eq!(view.email, "viewer@corp.com");

    // Get by id
    let found = db::get_view_by_id(pool, view.id)
        .await
        .expect("Query failed")
        .expect("View not found");
    assert_eq!(found.id, view.id);
    println!("  ✓ Found by id");

    // Update view
    let updated = db::update_view(pool, view.id, Some(180), Some(vec![1, 2, 3, 4]))
        .await
        .expect("Failed to update");
    assert_eq!(updated.duration_secs, Some(180));
    assert_eq!(updated.pages_viewed, Some(vec![1, 2, 3, 4]));
    println!("  ✓ Updated view (duration=180s, pages=[1,2,3,4])");

    // List by document
    let views = db::list_views_for_document(pool, doc.id, 10, 0)
        .await
        .expect("Failed to list");
    assert_eq!(views.len(), 1);
    println!("  ✓ Listed views for document");

    // List by email
    let views = db::list_views_by_email(pool, "viewer@corp.com", 10, 0)
        .await
        .expect("Failed to list");
    assert_eq!(views.len(), 1);
    println!("  ✓ Listed views by email");

    println!("\n  ✓ View CRUD passed\n");
}

#[tokio::test]
async fn test_custom_blocklist() {
    println!("\n============================================================");
    println!("TEST: Custom Blocklist (db module)");
    println!("============================================================");

    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Add domain
    let entry = db::add_to_custom_blocklist(pool, "blocked.com")
        .await
        .expect("Failed to add");
    assert_eq!(entry.domain, "blocked.com");
    println!("  ✓ Added blocked.com");

    // Check exists
    let exists = db::is_domain_in_custom_blocklist(pool, "blocked.com")
        .await
        .expect("Query failed");
    assert!(exists);
    println!("  ✓ Domain found in blocklist");

    // Check not exists
    let not_exists = db::is_domain_in_custom_blocklist(pool, "allowed.com")
        .await
        .expect("Query failed");
    assert!(!not_exists);
    println!("  ✓ Non-blocked domain not found");

    // List
    let list = db::list_custom_blocklist(pool)
        .await
        .expect("Failed to list");
    assert_eq!(list.len(), 1);
    println!("  ✓ Listed blocklist");

    // Upsert (add same domain)
    let _ = db::add_to_custom_blocklist(pool, "BLOCKED.COM")
        .await
        .expect("Failed to upsert");
    let list = db::list_custom_blocklist(pool)
        .await
        .expect("Failed to list");
    assert_eq!(list.len(), 1); // Still 1, not 2
    println!("  ✓ Upsert works (case-insensitive)");

    // Remove
    let removed = db::remove_from_custom_blocklist(pool, "blocked.com")
        .await
        .expect("Failed to remove");
    assert!(removed);
    println!("  ✓ Removed domain");

    // Verify removed
    let exists = db::is_domain_in_custom_blocklist(pool, "blocked.com")
        .await
        .expect("Query failed");
    assert!(!exists);
    println!("  ✓ Verified removal");

    println!("\n  ✓ Custom Blocklist passed\n");
}

#[tokio::test]
async fn test_document_stats() {
    println!("\n============================================================");
    println!("TEST: Document Stats (db module)");
    println!("============================================================");

    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Setup: doc with 2 links, 3 views from 2 unique emails
    let doc = db::create_document(pool, "Stats Test", "test.pdf", "/path", 1024)
        .await.unwrap();
    
    let link1 = db::create_link(pool, doc.id, "stat1", None, false, None).await.unwrap();
    let _link2 = db::create_link(pool, doc.id, "stat2", None, false, Some(Utc::now() - Duration::days(1))).await.unwrap(); // expired
    
    let expires = Utc::now() + Duration::hours(1);
    let tok1 = db::create_access_token(pool, link1.id, "a@corp.com", "t1", expires, None, None).await.unwrap();
    let tok2 = db::create_access_token(pool, link1.id, "a@corp.com", "t2", expires, None, None).await.unwrap();
    let tok3 = db::create_access_token(pool, link1.id, "b@corp.com", "t3", expires, None, None).await.unwrap();

    db::create_view(pool, Some(tok1.id), "a@corp.com", None).await.unwrap();
    db::create_view(pool, Some(tok2.id), "a@corp.com", None).await.unwrap();
    db::create_view(pool, Some(tok3.id), "b@corp.com", None).await.unwrap();

    // Get stats
    let stats = db::get_document_stats(pool, doc.id)
        .await
        .expect("Failed to get stats");

    println!("  Stats: total_views={}, unique_viewers={}, total_links={}, active_links={}",
        stats.total_views, stats.unique_viewers, stats.total_links, stats.active_links);

    assert_eq!(stats.total_views, 3);
    assert_eq!(stats.unique_viewers, 2);
    assert_eq!(stats.total_links, 2);
    assert_eq!(stats.active_links, 1); // link2 is expired
    println!("  ✓ All stats correct");

    println!("\n  ✓ Document Stats passed\n");
}
