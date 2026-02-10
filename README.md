# DocSend

A self-hosted document sharing platform with email verification, view tracking, and domain blocking. Built for sharing pitch decks with investors while maintaining control over who accesses your documents.

## Features

- **Document Management**: Upload, list, and delete PDF documents
- **Shareable Links**: Generate unique short links with optional expiration, notes, and one-time view
- **Email Verification**: Visitors must verify their email before viewing (via Resend API)
- **Domain Blocking**: Block personal email domains (gmail, yahoo, etc.) + custom blocklist
- **View Analytics**: Track who viewed documents, when, for how long, and which pages
- **Access Attempts**: Log all access attempts with IP addresses (successful and blocked)
- **CSV Exports**: Export documents, links, views, and attempts data
- **Admin Dashboard**: Web UI with auto-refresh to manage everything

## Tech Stack

- **Backend**: Rust + Axum
- **Database**: PostgreSQL
- **Auth**: JWT tokens (admin), magic links (viewers)
- **Email**: Resend API

## Quick Start

```bash
# 1. Copy environment file
cp .env.example .env

# 2. Edit .env with your values (see below)

# 3. Start database and run migrations
make reset

# 4. Create admin account
make create-admin

# 5. Run server
make run
```

Then open: `http://localhost:8080/admin`

## Environment Variables (.env)

```bash
# Database
DB_PASSWORD=docsend_dev_pass
POSTGRES_USER=docsend_user
POSTGRES_DB=docsend

# Test Database
DOCSEND_TEST_USER_PASS=docsend_test_pass
POSTGRES_TEST_USER=docsend_user
POSTGRES_TEST_DB=docsend_test

# Auth
JWT_SECRET=your_jwt_secret_min_32_bytes_long!

# Email (get from resend.com)
RESEND_API_KEY=re_xxxxxxxxxxxx
```

## Project Structure

```
docsend/
├── src/
│   ├── main.rs        # Server, routes, handlers
│   ├── lib.rs         # Config structs
│   ├── db.rs          # Database queries
│   ├── blocklist.rs   # Domain blocking logic
│   └── bin/
│       └── create_admin.rs
├── static/
│   ├── admin.html     # Admin dashboard (login + dashboard combined)
│   ├── form.html      # Email form (all states inline: form, blocked, expired, check-email)
│   └── viewer.html    # PDF viewer
├── migrations/
│   └── 001_init.sql   # Database schema
├── data/
│   └── blocklist.txt  # Default blocked domains (3,500+)
├── tests/
├── config.toml        # Server configuration
├── docker-compose.yml # PostgreSQL setup
└── Makefile           # Common commands
```

## Database Schema

- **admins**: Admin accounts (email, password_hash)
- **documents**: Uploaded PDFs (name, filename, storage_path, size)
- **links**: Shareable links (document_id, short_code, note, one_time_only, expires_at, revoked)
- **access_tokens**: Email verification tokens (link_id, email, token, used)
- **views**: View tracking (access_token_id, email, ip, duration, pages_viewed)
- **access_attempts**: All access attempts with IP, success/failure, reason
- **custom_blocklist**: Additional blocked domains

## API Endpoints

### Public
- `GET /health` - Health check
- `GET /d/{short_code}` - Document access form
- `GET /view?token=xxx` - Verify email and view document
- `GET /api/document/{token}` - Serve PDF file
- `GET /api/link/{short_code}/meta` - Get link metadata
- `POST /api/link/{short_code}/access` - Request access (send verification email)
- `POST /api/verify` - Verify email token
- `POST /api/track` - Track page views

### Admin (requires JWT)
- `POST /api/admin/login` - Login
- `PUT /api/admin/password` - Change password
- `GET/POST /api/admin/documents` - List/upload documents
- `DELETE /api/admin/documents/{id}` - Delete document
- `GET/POST /api/admin/links` - List/create links
- `POST /api/admin/links/{id}/revoke` - Revoke link
- `GET /api/admin/views` - List all views
- `GET /api/admin/attempts` - List access attempts
- `GET /api/admin/stats` - Global statistics
- `GET/POST /api/admin/blocklist` - List/add blocked domains
- `DELETE /api/admin/blocklist/{domain}` - Remove from blocklist
- `GET /api/admin/export/{type}` - CSV export (documents, links, views, attempts)

## Make Commands

```bash
make up           # Start database containers
make down         # Stop containers
make reset        # Reset database (destroy + migrate)
make migrate      # Run migrations only
make build        # Build release binary
make run          # Run server
make create-admin # Create admin account
make psql         # Connect to production db
make psql-test    # Connect to test db
make tables       # Show tables
make logs         # Show container logs
make test         # Run all tests
```

## Configuration (config.toml)

```toml
[server]
host = "0.0.0.0"
port = 8080
static_dir = "static"
upload_dir = "uploads"

[database]
host = "localhost"
port = 5432
user = "docsend_user"
database = "docsend"

[auth]
admin_token_ttl_secs = 86400   # 24 hours
access_token_ttl_secs = 3600   # 1 hour

[email]
from_email = "noreply@yourdomain.com"
from_name = "Your Company"
verification_url_base = "https://yourdomain.com"

[branding]
owner_name = "Your Company"

[messages]
email_sent = "Check your email for the access link"
domain_blocked = "Please use a work email address"
link_expired = "This link has expired"
link_revoked = "This link has been revoked"
invalid_token = "Invalid or expired token"
```

## Viewer Flow

1. Admin uploads document, creates shareable link (with optional note, expiration, one-time)
2. Admin sends link to investor: `https://yourdomain.com/d/abc123`
3. Investor clicks link, sees email form
4. Investor enters business email (personal domains blocked)
5. System sends magic link via Resend
6. Investor clicks magic link, views PDF
7. System tracks: email, IP, duration, pages viewed
8. Admin sees analytics in dashboard (auto-refreshes every 30s)

