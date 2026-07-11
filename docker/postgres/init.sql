-- VulnInt PostgreSQL initialization
-- Runs only on first cluster init (from POSTGRES_INITDB env)

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
CREATE EXTENSION IF NOT EXISTS "btree_gin";

-- pg_trgm enables fast LIKE-based search; trigram indexes are created
-- per-table by Alembic migrations as needed.

-- Reasonable timezone default for an international ops team
ALTER DATABASE CURRENT SET timezone TO 'UTC';

-- Statement timeout safety (per-session; overridable):
-- prevents runaway queries from a misbehaving worker.
ALTER DATABASE CURRENT SET statement_timeout TO '120s';
