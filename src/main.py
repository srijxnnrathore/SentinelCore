from fastapi import FastAPI
from contextlib import asynccontextmanager
import json
from jwt.algorithms import RSAAlgorithm
from cryptography.hazmat.primitives.asymmetric import rsa

from src.api.documents import router as documents_router
from src.core.security import jwks_manager
from src.core.config import settings

# Ephemeral RSA keypair generated for local demo mode
_demo_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
_demo_public_key = _demo_private_key.public_key()
DEMO_KID = "sentinelcore-demo-key-2026"

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Register the local public key into the in-memory cache on startup
    jwks_manager.set_keys_manually({DEMO_KID: _demo_public_key})
    yield

app = FastAPI(
    title="SentinelCore",
    version="1.0.0",
    description="Security-Hardened Multi-Tenant Backend with RLS, RS256 JWKS, and Automated Threat Defense",
    lifespan=lifespan
)

app.include_router(documents_router)

@app.get("/health", tags=["System"])
@app.get("/health/live", tags=["System"])
def health_check():
    return {"status": "alive"}

@app.get("/.well-known/jwks.json", tags=["Auth / IdP Simulation"])
def get_jwks():
    """
    Exposes RFC 7517 JSON Web Key Set containing active public keys.
    In enterprise deployments, this endpoint is hosted externally by Okta/Keycloak.
    """
    jwk_dict = json.loads(RSAAlgorithm.to_jwk(_demo_public_key))
    jwk_dict["kid"] = DEMO_KID
    jwk_dict["use"] = "sig"
    jwk_dict["alg"] = "RS256"
    return {"keys": [jwk_dict]}