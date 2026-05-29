"""T7: Cryptographic session binding — server-generated IDs, JWT validation, DPoP verification."""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
import warnings
from dataclasses import dataclass
from typing import Any

try:
    from joserfc import jwt as _jose_jwt
    from joserfc.jwk import OKPKey as _OKPKey
    _JOSERFC_AVAILABLE = True
except ImportError:
    _JOSERFC_AVAILABLE = False

from cosai_mcp.middleware.auth import JtiCache


def _b64url_decode(s: str) -> bytes:
    """Decode a base64url string, adding padding as needed."""
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    return base64.urlsafe_b64decode(s)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


@dataclass(frozen=True)
class SessionClaims:
    """Validated claims extracted from a bearer JWT."""
    subject: str
    issuer: str
    audience: str
    jti: str
    expires_at: float
    issued_at: float
    extra: tuple    # tuple[tuple[str, Any], ...] — additional verified claims


class SessionValidationError(Exception):
    """Raised when a session token or DPoP proof fails validation."""


class DPoP_ProofError(SessionValidationError):
    """Raised when a DPoP proof (RFC 9449) fails verification."""


class SessionManager:
    """Server-side session management with cryptographic binding.

    Session IDs are generated with CSPRNG (128-bit minimum).
    Client-supplied session IDs are never accepted — the server owns session state.

    JWT validation pins the algorithm, validates iss/aud/exp/nbf claims, and
    maintains a JTI replay cache to prevent token replay attacks.

    DPoP proof verification (RFC 9449 §4.3) confirms the caller holds the
    private key matching the ``jwk`` embedded in the proof header.
    """

    def __init__(
        self,
        expected_issuer: str,
        expected_audience: str,
        allowed_algorithms: tuple[str, ...] = ("RS256", "RS384", "RS512", "EdDSA"),
        jti_cache_size: int = 10_000,
        jti_cache_ttl: float = 300.0,
        clock_skew_seconds: float = 30.0,
    ) -> None:
        self._expected_issuer = expected_issuer
        self._expected_audience = expected_audience
        self._allowed_algorithms: frozenset[str] = frozenset(allowed_algorithms)
        # Shared JTI cache for bearer tokens and DPoP proofs (namespaced by prefix).
        self._jti_cache = JtiCache(maxsize=jti_cache_size, ttl_seconds=jti_cache_ttl)
        self._clock_skew = clock_skew_seconds

    # -------------------------------------------------------------------------
    # Session ID generation
    # -------------------------------------------------------------------------

    def create_session_id(self) -> str:
        """Generate a cryptographically random session ID (128-bit, hex-encoded).

        Server-generated only — never accept a client-supplied value.
        Must not appear in URL query parameters (leaks via Referer header and logs).
        """
        return secrets.token_hex(16)  # 128 bits

    # -------------------------------------------------------------------------
    # JWT bearer token validation
    # -------------------------------------------------------------------------

    def validate_token(
        self,
        token: str,
        keyset: Any,
    ) -> SessionClaims:
        """Validate a bearer JWT and return its claims.

        Raises ``SessionValidationError`` on any failure:
        - Algorithm not in allowed set (prevents downgrade / ``alg:none`` attack)
        - Issuer or audience mismatch
        - Token expired or not-yet-valid (with clock_skew allowance)
        - JTI replay detected
        - Missing required claims (iss, aud, exp, nbf, jti, sub)
        """
        if not _JOSERFC_AVAILABLE:
            raise RuntimeError(
                "joserfc is required for JWT validation. "
                "Install with: pip install joserfc"
            )

        try:
            with warnings.catch_warnings():
                # Suppress joserfc's RFC 9864 EdDSA recommendation warning only.
                warnings.filterwarnings("ignore", message=".*not recommended.*")
                warnings.filterwarnings("ignore", message=".*EdDSA.*")
                token_obj = _jose_jwt.decode(
                    token,
                    keyset,
                    algorithms=list(self._allowed_algorithms),
                )
        except Exception as exc:
            raise SessionValidationError(f"JWT decode failed: {exc}") from exc

        header = token_obj.header
        claims = token_obj.claims

        # Algorithm pinning — reject none and any non-allowlisted alg.
        alg = header.get("alg", "")
        if not alg or alg == "none" or alg not in self._allowed_algorithms:
            raise SessionValidationError(
                f"Algorithm '{alg}' not in allowed set {sorted(self._allowed_algorithms)}"
            )

        # Required claim presence.
        for claim in ("iss", "aud", "exp", "nbf", "jti", "sub"):
            if claim not in claims:
                raise SessionValidationError(f"Missing required claim: '{claim}'")

        now = time.time()

        if claims["iss"] != self._expected_issuer:
            raise SessionValidationError(
                f"Issuer mismatch: expected '{self._expected_issuer}', "
                f"got '{claims['iss']}'"
            )

        # aud may be a string or a list per RFC 7519.
        aud = claims["aud"]
        aud_set = {aud} if isinstance(aud, str) else set(aud)
        if self._expected_audience not in aud_set:
            raise SessionValidationError(
                f"Audience mismatch: expected '{self._expected_audience}', "
                f"got '{aud}'"
            )

        if now > claims["exp"] + self._clock_skew:
            raise SessionValidationError("Token has expired")

        if now < claims["nbf"] - self._clock_skew:
            raise SessionValidationError("Token is not yet valid (nbf)")

        jti = str(claims["jti"])
        if not self._jti_cache.check_and_add(f"bearer:{jti}"):
            raise SessionValidationError(f"JTI replay detected: '{jti}'")

        extra = tuple(
            (k, v) for k, v in claims.items()
            if k not in ("iss", "aud", "exp", "nbf", "jti", "sub", "iat")
        )

        return SessionClaims(
            subject=str(claims["sub"]),
            issuer=str(claims["iss"]),
            audience=self._expected_audience,
            jti=jti,
            expires_at=float(claims["exp"]),
            issued_at=float(claims.get("iat", 0.0)),
            extra=extra,
        )

    # -------------------------------------------------------------------------
    # DPoP proof verification (RFC 9449)
    # -------------------------------------------------------------------------

    def verify_dpop_proof(
        self,
        proof: str,
        expected_method: str,
        expected_url: str,
        bound_access_token: str | None = None,
        max_age_seconds: float = 60.0,
    ) -> None:
        """Verify a DPoP proof JWT (RFC 9449 §4.3).

        Checks:
        - ``typ`` header is ``dpop+jwt``
        - ``alg`` is not ``none``
        - ``jwk`` header contains the sender's OKP public key
        - ``htm`` claim matches *expected_method* (case-insensitive)
        - ``htu`` claim matches *expected_url*
        - ``iat`` is within *max_age_seconds* of now
        - ``jti`` has not been seen before (replay protection)
        - If *bound_access_token* provided, ``ath`` equals BASE64URL(SHA-256(token))

        Raises ``DPoP_ProofError`` on any check failure.
        """
        if not _JOSERFC_AVAILABLE:
            raise RuntimeError(
                "joserfc is required for DPoP verification. "
                "Install with: pip install joserfc"
            )

        parts = proof.split(".")
        if len(parts) != 3:
            raise DPoP_ProofError("DPoP proof is not a valid compact JWT")

        try:
            header: dict[str, Any] = json.loads(_b64url_decode(parts[0]))
        except Exception as exc:
            raise DPoP_ProofError(f"Cannot decode DPoP proof header: {exc}") from exc

        if header.get("typ") != "dpop+jwt":
            raise DPoP_ProofError(
                f"DPoP proof typ must be 'dpop+jwt', got '{header.get('typ')}'"
            )

        alg = header.get("alg", "")
        if not alg or alg == "none":
            raise DPoP_ProofError(f"DPoP proof alg must not be 'none', got '{alg!r}'")

        jwk_dict = header.get("jwk")
        if not isinstance(jwk_dict, dict):
            raise DPoP_ProofError("DPoP proof header missing or invalid 'jwk' claim")

        # Verify the signature using the embedded public key.
        try:
            if jwk_dict.get("kty") == "OKP":
                key = _OKPKey.import_key(jwk_dict)
            else:
                raise DPoP_ProofError(
                    f"DPoP jwk kty '{jwk_dict.get('kty')}' not supported; expected 'OKP'"
                )

            with warnings.catch_warnings():
                # Suppress joserfc's RFC 9864 EdDSA recommendation warning only.
                warnings.filterwarnings("ignore", message=".*not recommended.*")
                warnings.filterwarnings("ignore", message=".*EdDSA.*")
                token_obj = _jose_jwt.decode(proof, key, algorithms=[alg])
        except DPoP_ProofError:
            raise
        except Exception as exc:
            raise DPoP_ProofError(f"DPoP proof signature invalid: {exc}") from exc

        claims = token_obj.claims
        now = time.time()

        if claims.get("htm", "").upper() != expected_method.upper():
            raise DPoP_ProofError(
                f"DPoP htm mismatch: expected '{expected_method.upper()}', "
                f"got '{claims.get('htm')}'"
            )

        if claims.get("htu") != expected_url:
            raise DPoP_ProofError(
                f"DPoP htu mismatch: expected '{expected_url}', "
                f"got '{claims.get('htu')}'"
            )

        iat = claims.get("iat")
        if iat is None:
            raise DPoP_ProofError("DPoP proof missing 'iat' claim")
        if abs(now - float(iat)) > max_age_seconds:
            raise DPoP_ProofError(
                f"DPoP proof stale: iat={iat}, now={now:.0f}, max_age={max_age_seconds}s"
            )

        jti = str(claims.get("jti", ""))
        if not jti:
            raise DPoP_ProofError("DPoP proof missing 'jti' claim")
        if not self._jti_cache.check_and_add(f"dpop:{jti}"):
            raise DPoP_ProofError(f"DPoP proof jti replay detected: '{jti}'")

        if bound_access_token is not None:
            expected_ath = _b64url(
                hashlib.sha256(bound_access_token.encode("ascii")).digest()
            )
            if claims.get("ath") != expected_ath:
                raise DPoP_ProofError(
                    "DPoP proof 'ath' claim does not match the bound access token"
                )
