import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from src.core.security import jwks_manager, create_access_token_rs256

TEST_KID = "sentinelcore-test-key-1"

# Generate in-memory RSA keypair once for the test run
_priv_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
_pub_key = _priv_key.public_key()

@pytest.fixture(scope="session", autouse=True)
def seed_test_jwks():
    """Seeds the in-memory test public key into the global jwks_manager."""
    jwks_manager.set_keys_manually({TEST_KID: _pub_key})

@pytest.fixture
def test_private_key():
    return _priv_key

@pytest.fixture
def anyio_backend():
    return "asyncio"


def mint_test_token(tenant_id: str, subject: str = "test-subject") -> str:
    return create_access_token_rs256(
        tenant_id=tenant_id,
        subject=subject,
        private_key=_priv_key,
        kid=TEST_KID
    )