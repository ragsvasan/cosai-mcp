"""T1: Session-bound identity, DPoP (RFC 9449), JTI replay cache."""
from __future__ import annotations

import base64
import threading
import time
import uuid
import warnings
from collections import OrderedDict

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

try:
    from joserfc import jwt as _jose_jwt
    from joserfc.jwk import OKPKey as _OKPKey
    _JOSERFC_AVAILABLE = True
except ImportError:
    _JOSERFC_AVAILABLE = False


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class JtiCache:
    """Thread-safe replay-detection cache with TTL expiry.

    Each entry is stored with an expiry timestamp (now + ttl_seconds).
    On each check_and_add:
      1. Expired entries are swept first to free space.
      2. JTI already present → False (replay detected).
      3. Cache full with non-expired entries → False (fail-safe: deny rather than
         evict a live entry, which would allow an attacker to replay the evicted JTI).
      4. Otherwise add and return True.
    """

    def __init__(self, maxsize: int = 10_000, ttl_seconds: float = 300.0) -> None:
        self._maxsize = maxsize
        self._ttl = ttl_seconds
        self._cache: OrderedDict[str, float] = OrderedDict()  # jti -> expiry_time
        self._lock = threading.Lock()

    def check_and_add(self, jti: str) -> bool:
        """Return True if *jti* is new (first use). Return False if already seen (replay)
        or if the cache is full with non-expired entries (fail-safe)."""
        now = time.monotonic()
        with self._lock:
            # Sweep expired entries so they don't consume cache capacity.
            expired = [k for k, exp in self._cache.items() if exp <= now]
            for k in expired:
                del self._cache[k]

            if jti in self._cache:
                return False  # replay

            if len(self._cache) >= self._maxsize:
                # All remaining entries are within their TTL window.
                # Evicting one would allow replay of the evicted JTI before its
                # window closes — deny the new entry instead (fail-safe).
                return False

            self._cache[jti] = now + self._ttl
            return True


class SessionBoundIdentity:
    """Generate DPoP proofs (RFC 9449) for the scanner's outbound requests.

    Protects the scanner's own HTTP calls — not a probe of the target server.

    Each instance holds an ephemeral Ed25519 keypair for the session lifetime.
    The JtiCache prevents the scanner from inadvertently replaying its own proofs.
    """

    def __init__(self) -> None:
        self._private_key = Ed25519PrivateKey.generate()
        self._jti_cache = JtiCache()

    def generate_dpop_proof(
        self,
        method: str,
        url: str,
        nonce: str | None = None,
    ) -> str:
        """Generate a DPoP proof JWT for the given HTTP method and URL.

        Per RFC 9449 §4.2: the proof includes `htm` (HTTP method), `htu` (HTTP URI),
        `iat` (issued-at), `jti` (unique token ID), and optionally `nonce`.

        The `jwk` header claim carries the ephemeral public key so the server can
        verify the proof is bound to this key pair.

        Returns a compact-serialized JWT string.
        """
        if not _JOSERFC_AVAILABLE:
            raise RuntimeError(
                "joserfc is required for DPoP proof generation. "
                "Install with: pip install joserfc"
            )

        jti = str(uuid.uuid4())
        self._jti_cache.check_and_add(jti)

        priv_bytes = self._private_key.private_bytes_raw()
        pub_bytes = self._private_key.public_key().public_bytes_raw()

        key = _OKPKey.import_key({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": _b64url(pub_bytes),
            "d": _b64url(priv_bytes),
        })

        pub_jwk = {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": _b64url(pub_bytes),
        }

        header: dict = {
            "alg": "EdDSA",
            "typ": "dpop+jwt",
            "jwk": pub_jwk,
        }

        payload: dict = {
            "htm": method.upper(),
            "htu": url,
            "iat": int(time.time()),
            "jti": jti,
        }
        if nonce is not None:
            payload["nonce"] = nonce

        # EdDSA is flagged as "not recommended" by joserfc due to RFC 9864 ambiguity,
        # but DPoP (RFC 9449) explicitly supports EdDSA via OKP keys — suppress the warning.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            token: str = _jose_jwt.encode(header, payload, key, algorithms=["EdDSA"])

        return token

    @property
    def jti_cache(self) -> JtiCache:
        return self._jti_cache
