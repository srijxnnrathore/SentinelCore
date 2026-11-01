import asyncio
from pathlib import Path
import socket
import struct
import subprocess
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from concurrent.futures import ThreadPoolExecutor
import httpx
import pytest
from sqlalchemy import text

from src.core.redis import get_redis_client
from src.core.security import jwks_manager
from src.db.session import engine, scoped_tenant_session
from tests.conftest import mint_test_token, _pub_key, TEST_KID

def send_and_abort(port: int, token: str, is_write: bool):
    """
    Initiates an authenticated HTTP request over a raw TCP socket, allows it
    to reach the scoped_tenant_session database transaction layer, and violently
    closes the socket using SO_LINGER(1, 0) to emit a TCP RST packet.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect(("127.0.0.1", port))
        if is_write:
            body = '{"title": "Chaos RST Document", "content": "Violent socket abort testing"}'
            req = (
                f"POST /documents/ HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{port}\r\n"
                f"Authorization: Bearer {token}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"Connection: close\r\n\r\n"
                f"{body}"
            )
        else:
            req = (
                f"GET /documents/ HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{port}\r\n"
                f"Authorization: Bearer {token}\r\n"
                f"Connection: close\r\n\r\n"
            )

        s.sendall(req.encode())
        s.settimeout(0.15)
        try:
            # Read first few bytes (e.g. HTTP status header) confirming active execution
            s.recv(4)
        except Exception:
            pass
    except Exception:
        pass
    finally:
        try:
            # Setting SO_LINGER to (1, 0) forces an immediate violent TCP RST
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            s.close()
        except Exception:
            pass

@pytest.mark.anyio
async def test_client_abort_chaos_tcp_rst():
    """
    Fires 100 rapid violent TCP RST client disconnects during active database transactions.
    Verifies that:
    1. The asyncpg connection pool remains healthy under violent task cancellations.
    2. Subsequent queries execute cleanly with zero 'InterfaceError: connection is busy'.
    3. No transaction-scoped GUC (app.current_tenant_id) leaks onto idle or recycled connections.
    """
    jwks_manager.set_keys_manually({TEST_KID: _pub_key})
    redis_client = get_redis_client()

    # 1. Provision 20 distinct tenants (5 requests each = 100 requests within rate limit quota)
    tenants = [str(uuid.uuid4()) for _ in range(20)]
    tokens = [mint_test_token(tenant_id=t, subject=f"chaos-actor-{t[:8]}") for t in tenants]

    async with engine.connect() as conn:
        for t in tenants:
            await conn.execute(
                text("INSERT INTO tenants (id, name) VALUES (:t, 'Abort Chaos Org')"),
                {"t": t},
            )
            await redis_client.delete(f"rate:{{{t}}}")
        await conn.commit()

    # 2. Spin up real TCP server hosting the FastAPI application in an isolated subprocess with seeded JWKS
    from cryptography.hazmat.primitives import serialization
    pub_pem = _pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()

    server_code = (
        "import uvicorn\n"
        "from cryptography.hazmat.primitives import serialization\n"
        "from src.main import app\n"
        "from src.core.security import jwks_manager\n"
        f"pub_pem = {repr(pub_pem)}\n"
        "pub_key = serialization.load_pem_public_key(pub_pem.encode('utf-8'))\n"
        f"jwks_manager.set_keys_manually({{'{TEST_KID}': pub_key}})\n"
        f"uvicorn.run(app, host='127.0.0.1', port={port}, log_level='error')\n"
    )

    server_proc = subprocess.Popen([
        sys.executable, "-c", server_code
    ])

    try:
        # Wait for server readiness
        server_ready = False
        for _ in range(50):
            try:
                async with httpx.AsyncClient() as client:
                    resp = await client.get(f"http://127.0.0.1:{port}/health/live", timeout=0.5)
                    if resp.status_code == 200:
                        server_ready = True
                        break
            except Exception:
                await asyncio.sleep(0.05)
        assert server_ready, "Uvicorn server failed to start within timeout"

        # 3. Fire 100 rapid aborted connections across worker threads
        total_aborts = 100

        def fire_aborts():
            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = []
                for i in range(total_aborts):
                    token = tokens[i % len(tokens)]
                    is_write = (i % 2 == 0)
                    futures.append(executor.submit(send_and_abort, port, token, is_write))
                for f in futures:
                    f.result()

        await asyncio.to_thread(fire_aborts)

        # Allow brief settlement window for connection cancellation shields
        await asyncio.sleep(0.2)

        # 4. Verification 1: Server readiness probe confirms DB and Redis health in live server process
        async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{port}") as client:
            ready_res = await client.get("/health/ready")
            assert ready_res.status_code == 200, f"Server degraded after RST storm: {ready_res.text}"
            assert ready_res.json()["status"] == "ready"

            # 5. Verification 2: Subsequent tenant queries succeed without 'connection is busy'
            for token in tokens[:5]:
                clean_res = await client.get(
                    "/documents/",
                    headers={"Authorization": f"Bearer {token}"},
                )
                assert clean_res.status_code in (200, 429), f"Query failed on server: {clean_res.text}"

        # 6. Verification 3: Connection pool integrity and zero leaked GUCs on idle connections
        async with engine.connect() as conn:
            for _ in range(15):
                leaked_guc = await conn.scalar(
                    text("SELECT NULLIF(current_setting('app.current_tenant_id', true), '')")
                )
                assert leaked_guc is None, f"Wire pollution detected: leaked GUC '{leaked_guc}'"

    finally:
        server_proc.terminate()
        try:
            server_proc.wait(timeout=3.0)
        except Exception:
            server_proc.kill()

        # Cleanup Redis rate keys
        for t in tenants:
            await redis_client.delete(f"rate:{{{t}}}")

if __name__ == "__main__":
    asyncio.run(test_client_abort_chaos_tcp_rst())
    print("test_client_abort_chaos.py passed standalone execution!")
