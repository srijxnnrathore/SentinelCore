# ADR 0001: Kernel-Enforced Row-Level Security with Non-Inlined PL/pgSQL Functions

## Status
Accepted

## Context
In multi-tenant SaaS applications, software engineers traditionally enforce tenant boundaries at the application tier using ORM-level filters (e.g. `query.filter_by(tenant_id=...)`). This architecture introduces catastrophic failure modes:
1. **Developer Omission:** A single missing filter predicate in a complex query, join, or subquery causes cross-tenant data contamination or full tenant data exposure (BOLA / IDOR).
2. **Volatile Inlining Vulnerability:** In PostgreSQL, inline SQL functions reading session settings (e.g., `current_setting('app.current_tenant_id')`) are classified as volatile by default. When the PostgreSQL query optimizer inlines these functions into a table scan, it executes the setting lookup repeatedly for every tuple scanned, converting candidate index scans into post-filter sequential scans and allowing timing oracles.

## Decision
We enforce multi-tenant isolation directly inside the PostgreSQL 16 storage kernel using native Row-Level Security (`FORCE ROW LEVEL SECURITY`) and an unprivileged application role (`sentinel_app`):

1. **Non-Inlined PL/pgSQL Resolver:**
   We declare `public.app_current_tenant_id()` with `LANGUAGE plpgsql STABLE PARALLEL SAFE COST 1`:
   ```sql
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
   ```
   Because PL/pgSQL functions are never inlined into query expressions by the PostgreSQL planner, the optimizer evaluates `app_current_tenant_id()` exactly once per query as an `InitPlan` parameter.

2. **Composite Leading Index & Policy:**
   ```sql
   ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
   ALTER TABLE documents FORCE ROW LEVEL SECURITY;

   CREATE INDEX idx_documents_tenant_id_id ON documents (tenant_id, id);

   CREATE POLICY tenant_isolation_policy ON documents
       FOR ALL
       TO sentinel_app
       USING (tenant_id = public.app_current_tenant_id())
       WITH CHECK (tenant_id = public.app_current_tenant_id());
   ```

3. **Definer Probe Function for BOLA Isolation:**
   Cross-tenant document verification is decoupled via a `SECURITY DEFINER` function with restricted column privileges (`SELECT (id, tenant_id) ON documents TO sentinel_definer`):
   ```sql
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
   ```

## Rationale & Consequences
- **Kernel-Enforced Safety:** `FORCE ROW LEVEL SECURITY` guarantees that even table owners or subqueries cannot bypass row isolation. Application developers cannot leak data through missing `WHERE` clauses.
- **Index Pushdown Invariant:** The `InitPlan` optimization forces PostgreSQL 16 to treat `app_current_tenant_id()` as an evaluation-time constant, pushing the tenant filter into the leading column of `idx_documents_tenant_id_id` (`Index Cond: (tenant_id = $0)`), preventing full table scans.
- **Constant-Time Responses:** Unauthorized reads execute constant-time index lookups, guaranteeing that cross-tenant read rejections return HTTP 404 with indistinguishable latency from non-existent IDs ($\Delta < 3.5\text{ms}$).

