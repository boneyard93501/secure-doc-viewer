.PHONY: help up down migrate reset build run create-admin test test-db test-production test-db-interactive psql psql-test logs tables

help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Production (docker-compose):"
	@echo "  up              Start production containers"
	@echo "  down            Stop production containers"
	@echo "  migrate         Run database migrations"
	@echo "  reset           Destroy + restart (fresh db + migrate)"
	@echo "  build           Build release binary"
	@echo "  run             Run server (starts db if needed)"
	@echo "  create-admin    Create admin user (interactive)"
	@echo "  logs            Show container logs (Ctrl+C to exit)"
	@echo "  psql            Connect to production db"
	@echo "  psql-test       Connect to test db"
	@echo "  tables          Show tables in production db"
	@echo ""
	@echo "Tests:"
	@echo "  test            Run all tests"
	@echo "  test-db         Run ephemeral db tests (testcontainers)"
	@echo "  test-production Run production connection test (docker-compose)"
	@echo "  test-db-interactive Run interactive db test (60s)"

# =============================================================================
# PRODUCTION (docker-compose)
# =============================================================================

up:
	docker-compose up -d

down:
	docker-compose down

reset:
	docker-compose down -v
	docker-compose up -d
	@sleep 5
	@$(MAKE) migrate

migrate: up
	@sleep 3
	@. ./.env && PGPASSWORD=$$DB_PASSWORD psql -h localhost -U docsend_user -d docsend < migrations/001_init.sql

build:
	cargo build --release

run: up
	@. ./.env && \
	JWT_SECRET=$${JWT_SECRET:-$$(openssl rand -hex 32)} \
	./target/release/docsend

create-admin: build
	@. ./.env && \
	./target/release/docsend-admin

logs: up
	docker-compose logs -f

psql: up
	@sleep 2
	@. ./.env && PGPASSWORD=$$DB_PASSWORD psql -h localhost -U docsend_user -d docsend

psql-test: up
	@sleep 2
	@. ./.env && PGPASSWORD=$$DOCSEND_TEST_USER_PASS psql -h localhost -p 5433 -U docsend_user -d docsend_test

tables: up
	@sleep 2
	@. ./.env && PGPASSWORD=$$DB_PASSWORD psql -h localhost -U docsend_user -d docsend -c "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public';"

# =============================================================================
# TESTS
# =============================================================================

test:
	cargo test -- --nocapture

test-db:
	cargo test test_db -- --nocapture

test-production:
	cargo test test_production -- --nocapture

test-db-interactive:
	cargo test test_interactive -- --nocapture --ignored
