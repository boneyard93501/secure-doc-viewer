-- 001_init.sql

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Admins
CREATE TABLE admins (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email               TEXT UNIQUE NOT NULL,
    password_hash       TEXT NOT NULL,
    password_changed_at TIMESTAMPTZ,
    created_at          TIMESTAMPTZ DEFAULT now()
);

-- Documents
CREATE TABLE documents (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL,
    filename        TEXT NOT NULL,
    storage_path    TEXT NOT NULL,
    size_bytes      BIGINT NOT NULL,
    created_at      TIMESTAMPTZ DEFAULT now()
);

-- Links
CREATE TABLE links (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id     UUID NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    short_code      TEXT UNIQUE NOT NULL,
    note            TEXT,
    one_time_only   BOOLEAN DEFAULT FALSE,
    expires_at      TIMESTAMPTZ,
    revoked         BOOLEAN DEFAULT FALSE,
    created_at      TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX idx_links_short_code ON links(short_code);

-- Access tokens (magic links)
CREATE TABLE access_tokens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    link_id         UUID NOT NULL REFERENCES links(id) ON DELETE CASCADE,
    email           TEXT NOT NULL,
    token           TEXT UNIQUE NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    used            BOOLEAN DEFAULT FALSE,
    request_ip      TEXT,
    request_ua      TEXT,
    verified_ip     TEXT,
    verified_ua     TEXT,
    verified_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX idx_access_tokens_token ON access_tokens(token);

-- Views
CREATE TABLE views (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    access_token_id UUID REFERENCES access_tokens(id),
    email           TEXT NOT NULL,
    ip              TEXT,
    started_at      TIMESTAMPTZ DEFAULT now(),
    duration_secs   INTEGER,
    pages_viewed    INTEGER[]
);

CREATE INDEX idx_views_email ON views(email);
CREATE INDEX idx_views_started_at ON views(started_at DESC);

-- Custom blocklist
CREATE TABLE custom_blocklist (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain          TEXT UNIQUE NOT NULL,
    created_at      TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX idx_blocklist_domain ON custom_blocklist(domain);

-- Access attempts (failed and successful)
CREATE TABLE access_attempts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    short_code      TEXT NOT NULL,
    email           TEXT NOT NULL,
    ip              TEXT,
    user_agent      TEXT,
    success         BOOLEAN NOT NULL,
    failure_reason  TEXT,  -- 'blocked_domain', 'invalid_format', 'link_expired', 'link_revoked', 'link_not_found'
    created_at      TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX idx_access_attempts_created_at ON access_attempts(created_at DESC);
CREATE INDEX idx_access_attempts_email ON access_attempts(email);
CREATE INDEX idx_access_attempts_ip ON access_attempts(ip);
