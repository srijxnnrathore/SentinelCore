import asyncio
from sqlalchemy.ext.asyncio import create_async_engine

ADMIN_URL = "postgresql+asyncpg://postgres:postgrespassword@localhost:5432/sentinelcore"

INIT_SQL = """
-- 1. Create a restricted application role (if it does not exist)
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'sentinel_app') THEN
        CREATE ROLE sentinel_app WITH LOGIN PASSWORD 'app_secure_password';
    END IF;
END
$$;

-- 2. Create the tenants table
CREATE TABLE IF NOT EXISTS tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 3. Create the documents table
CREATE TABLE IF NOT EXISTS documents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 4. Create the append-only audit_logs table
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE SET NULL,
    actor_id VARCHAR(100) NOT NULL,
    action VARCHAR(50) NOT NULL,
    resource_id VARCHAR(100),
    status VARCHAR(20) NOT NULL,
    ip_address VARCHAR(45),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 5. Grant restricted DML privileges to sentinel_app
GRANT CONNECT ON DATABASE sentinelcore TO sentinel_app;
GRANT USAGE ON SCHEMA public TO sentinel_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO sentinel_app;

-- Revoke UPDATE and DELETE on audit_logs to enforce append-only immutability
REVOKE UPDATE, DELETE ON audit_logs FROM sentinel_app;

ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO sentinel_app;

-- 6. Enable and FORCE Row-Level Security on documents
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE documents FORCE ROW LEVEL SECURITY;

-- 7. Define the RLS policy for documents
DROP POLICY IF EXISTS tenant_isolation_policy ON documents;
CREATE POLICY tenant_isolation_policy ON documents
    FOR ALL
    TO sentinel_app
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);
"""

async def run_init():
    engine = create_async_engine(ADMIN_URL, isolation_level="AUTOCOMMIT")
    async with engine.connect() as conn:
        print("Provisioning database schema, roles, and RLS policies...")
        raw_conn = await conn.get_raw_connection()
        await raw_conn.driver_connection.execute(INIT_SQL)
        print("Database provisioning completed successfully.")
    await engine.dispose()

if __name__ == "__main__":
    asyncio.run(run_init())