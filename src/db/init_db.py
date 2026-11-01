import asyncio
from sqlalchemy.ext.asyncio import create_async_engine

ADMIN_URL = "postgresql+asyncpg://postgres:postgrespassword@localhost:5432/sentinelcore"

INIT_SQL = """
-- 1. Create unprivileged application role & security definer role
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sentinel_app') THEN
        CREATE ROLE sentinel_app WITH LOGIN PASSWORD 'app_secure_password';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sentinel_definer') THEN
        CREATE ROLE sentinel_definer NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
    END IF;
END $$;

-- 2. Core tables
CREATE TABLE IF NOT EXISTS tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE IF NOT EXISTS documents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

-- Leading index for composite RLS query pushdown
CREATE INDEX IF NOT EXISTS idx_documents_tenant_id_id 
    ON documents (tenant_id, id);

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

-- 3. Non-inlined STABLE context resolver (PL/pgSQL prevents function inlining)
CREATE OR REPLACE FUNCTION public.app_current_tenant_id()
RETURNS uuid
LANGUAGE plpgsql
STABLE
PARALLEL SAFE
COST 1 AS $$
BEGIN
    RETURN NULLIF(current_setting('app.current_tenant_id', true), '')::uuid;
END;
$$;

-- 4. Storage boundary enforcement on documents
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE documents FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_policy ON documents;
CREATE POLICY tenant_isolation_policy ON documents
    FOR ALL
    TO sentinel_app
    USING (tenant_id = public.app_current_tenant_id())
    WITH CHECK (tenant_id = public.app_current_tenant_id());

-- 5. Hard disable RLS on audit_logs (Append-only immutability enforced via DML revocations)
ALTER TABLE audit_logs DISABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs NO FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS audit_logs_isolation_policy ON audit_logs;
DROP POLICY IF EXISTS audit_logs_insert_policy ON audit_logs;

-- 6. Scope Definer probe function
CREATE OR REPLACE FUNCTION public.check_cross_tenant_probe(p_doc_id uuid)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_caller_tenant uuid := public.app_current_tenant_id();
    v_owner_tenant uuid;
BEGIN
    IF v_caller_tenant IS NULL THEN
        RAISE EXCEPTION 'Missing tenant context' USING ERRCODE = '42501';
    END IF;

    SELECT tenant_id INTO v_owner_tenant
    FROM public.documents
    WHERE id = p_doc_id;

    RETURN (v_owner_tenant IS NOT NULL AND v_owner_tenant <> v_caller_tenant);
END;
$$;

ALTER FUNCTION public.check_cross_tenant_probe(uuid) OWNER TO sentinel_definer;

-- 7. Role grants and privilege boundaries
GRANT CONNECT ON DATABASE sentinelcore TO sentinel_app;
GRANT USAGE ON SCHEMA public TO sentinel_app, sentinel_definer;

GRANT SELECT, INSERT ON TABLE tenants TO sentinel_app;
REVOKE UPDATE, DELETE, TRUNCATE ON TABLE tenants FROM sentinel_app;

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE documents TO sentinel_app;
GRANT SELECT, INSERT ON TABLE audit_logs TO sentinel_app;

-- Revoke destructive and table-level locking vectors
REVOKE UPDATE, DELETE, TRUNCATE ON TABLE audit_logs FROM sentinel_app;
REVOKE TRUNCATE ON TABLE documents, tenants FROM sentinel_app;

-- Grant sentinel_definer read-only access to (id, tenant_id)
GRANT SELECT (id, tenant_id) ON public.documents TO sentinel_definer;

DROP POLICY IF EXISTS definer_probe_read_policy ON public.documents;
CREATE POLICY definer_probe_read_policy ON public.documents
    FOR SELECT
    TO sentinel_definer
    USING (true);

REVOKE ALL ON FUNCTION public.check_cross_tenant_probe(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.check_cross_tenant_probe(uuid) TO sentinel_app;
"""

async def run_init():
    engine = create_async_engine(ADMIN_URL, isolation_level="AUTOCOMMIT")
    async with engine.connect() as conn:
        print("Provisioning non-inlined PL/pgSQL functions and definer boundaries...")
        raw_conn = await conn.get_raw_connection()
        await raw_conn.driver_connection.execute(INIT_SQL)
        print("Database schema successfully hardened.")
    await engine.dispose()

if __name__ == "__main__":
    asyncio.run(run_init())
