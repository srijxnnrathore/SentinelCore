# SentinelCore

A security-hardened, multi-tenant backend architecture built with FastAPI, PostgreSQL 16, and Redis 7. Enforces storage-layer tenant boundary isolation via Row-Level Security (RLS), asymmetric RFC 7517/8725 JWKS authentication, atomic abuse mitigation, automated threat containment, and tamper-evident audit logging.

---

## Architectural Threat Model & Mitigations

### 1. Broken Object Level Authorization (BOLA / IDOR)
* **Threat:** An authenticated tenant manipulates resource identifiers to read or mutate another tenant's records.
* **Mitigation:** Native PostgreSQL 16 Row-Level Security (`FORCE ROW LEVEL SECURITY`) coupled with an unprivileged database role (`sentinel_app`). The tenant identity context is dynamically set per-transaction via `SET LOCAL app.current_tenant_id`. Application queries do not require manual `WHERE tenant_id = ...` predicates; the storage engine kernel enforces row filtering automatically.
* **Adversarial Guarantee:** Unauthorized queries return `404 Not Found` rather than `403 Forbidden`, preventing resource enumeration or metadata leakage.

### 2. Identity Decoupling & Key Rotation (RFC 8725)
* **Threat:** Shared symmetric secrets (`HS256`) allow any compromised service to forge tokens. Uncached key resolution causes outbound Denial of Service (DoS) during Key ID (`kid`) flooding attacks.
* **Mitigation:** Asymmetric `RS256` verification backed by an in-memory `JWKSManager`. Features thread-safe double-checked locking (`asyncio.Lock`) and a cooldown window to stop outbound cache-stampede and amplification attacks against Identity Providers. Tokens forged via algorithm confusion (`HS256` / `none`) are rejected at the edge.

### 3. Automated Threat Detection & Tenant Quarantine
* **Threat:** Distributed enumeration sweeps scanning for accessible object UUIDs.
* **Mitigation:** Runtime violation tracking via an atomic Redis Lua circuit breaker. Tenants exceeding 3 unauthorized read attempts (`DOCUMENT_READ_DENIED`) within a 30-second sliding window are automatically quarantined. Subsequent requests are rejected with immediate `HTTP 403 Forbidden` responses at the dependency boundary, bypassing database execution entirely.

### 4. Distributed Resource Exhaustion (Noisy-Neighbor Problem)
* **Threat:** High-volume bursts from a single tenant starving shared connection pools and compute capacity.
* **Mitigation:** Distributed fixed-window rate limiter powered by Redis 7 executing an atomic Lua script (`EVALSHA`) combining `INCR` and conditional `EXPIRE`. Prevents key race conditions and orphan memory allocations.

### 5. Forensic Log Tampering
* **Threat:** An attacker compromising the application attempts to clear or rewrite access trails.
* **Mitigation:** Database-level privilege lockdown (`REVOKE UPDATE, DELETE ON audit_logs FROM sentinel_app`). Ensures append-only forensic telemetry.

---

## Tech Stack

* **Runtime:** Python 3.12+ / 3.14+
* **Framework:** FastAPI (ASGI)
* **Storage Engine:** PostgreSQL 16 (Alpine)
* **Cache & State Broker:** Redis 7 (Alpine)
* **ORM / Database Driver:** SQLAlchemy 2.0 (Async) + `asyncpg`
* **Cryptography:** PyJWT + Cryptography
* **CI/CD:** GitHub Actions (Automated Postgres/Redis containers, SAST with `bandit`, `pytest`)

---

## Verification & Test Suite

The test suite runs 13 automated integration and adversarial regression test cases.

```powershell
# 1. Start backing services
docker compose up -d

# 2. Provision database schema, roles, and RLS policies
python src/db/init_db.py

# 3. Execute full regression suite
python -m pytest -v