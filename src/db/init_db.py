import asyncio
from sqlalchemy.ext.asyncio import create_async_engine

ADMIN_URL = "postgresql+asyncpg://postgres:postgrespassword@localhost:5432/sentinelcore"

INIT_SQL = """
-- 1. Create restricted application role (if not existing)
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'sentinel_app') THEN
        CREATE ROLE sentinel_app WITH LOGIN PASSWORD 'app_secure_password';
    END IF;
END
$$;

-- 2. Create tenants table
CREATE TABLE IF NOT EXISTS tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

-- 3. Create documents table
CREATE TABLE IF NOT EXISTS documents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX IF NOT EXISTS idx_documents_tenant_id_id 
    ON documents (tenant_id, id);

-- 4. Create append-only audit_logs table
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE SET NULL,
    actor_id VARCHAR(100) NOT NULL,
    action VARCHAR(50) NOT NULL,
    resource_id VARCHAR(100),
    status VARCHAR(20) NOT NULL,
    ip_address VARCHAR(45),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_created 
    ON audit_logs (tenant_id, created_at DESC);

-- 5. STABLE Helper function for RLS optimization (handles missing/empty string cleanly)
CREATE OR REPLACE FUNCTION app_current_tenant_id()
RETURNS uuid
LANGUAGE sql
STABLE
PARALLEL SAFE AS $$
    SELECT NULLIF(current_setting('app.current_tenant_id', true), '')::uuid;
$$;

-- 6. Enable and FORCE RLS on documents (Strict Storage Tenant Isolation)
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE documents FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_policy ON documents;
CREATE POLICY tenant_isolation_policy ON documents
    FOR ALL
    TO sentinel_app
    USING (tenant_id = app_current_tenant_id())
    WITH CHECK (tenant_id = app_current_tenant_id());

-- Disable RLS on audit_logs so append-only audit writes and diagnostic queries succeed
ALTER TABLE audit_logs DISABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS audit_logs_isolation_policy ON audit_logs;
DROP POLICY IF EXISTS audit_logs_insert_policy ON audit_logs;

-- 7. Hardened Role Privileges (Least Privilege & Tamper Resistance)
GRANT CONNECT ON DATABASE sentinelcore TO sentinel_app;
GRANT USAGE ON SCHEMA public TO sentinel_app;

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE tenants TO sentinel_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE documents TO sentinel_app;
GRANT SELECT, INSERT ON TABLE audit_logs TO sentinel_app;

-- Hard immutability guarantee: Revoke destructive DML
REVOKE UPDATE, DELETE, TRUNCATE ON TABLE audit_logs FROM sentinel_app;
REVOKE TRUNCATE ON TABLE documents, tenants FROM sentinel_app;

-- 8. Security Definer Diagnostic Function for BOLA Probing
CREATE OR REPLACE FUNCTION verify_and_log_bola_probe(p_doc_id uuid)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_caller_tenant uuid := app_current_tenant_id();
    v_owner_tenant uuid;
BEGIN
    IF v_caller_tenant IS NULL THEN
        RAISE EXCEPTION 'Uninitialized tenant context' USING ERRCODE = '42501';
    END IF;

    SELECT tenant_id INTO v_owner_tenant
    FROM documents
    WHERE id = p_doc_id;

    IF v_owner_tenant IS NOT NULL AND v_owner_tenant <> v_caller_tenant THEN
        RETURN TRUE;
    END IF;

    RETURN FALSE;
END;
$$;

REVOKE ALL ON FUNCTION verify_and_log_bola_probe(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION verify_and_log_bola_probe(uuid) TO sentinel_app;
"""

async def run_init():
    engine = create_async_engine(ADMIN_URL, isolation_level="AUTOCOMMIT")
    async with engine.connect() as conn:
        print("Provisioning corrected schema, STABLE RLS functions, and security policies...")
        raw_conn = await conn.get_raw_connection()
        await raw_conn.driver_connection.execute(INIT_SQL)
        print("Database schema successfully updated.")
    await engine.dispose()

if __name__ == "__main__":
    asyncio.run(run_init())