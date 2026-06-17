"""Tests for T1 middleware: JtiCache and SessionBoundIdentity (DPoP)."""
from __future__ import annotations

import base64
import json
import threading
import time

from cosai_mcp.middleware.auth import JtiCache, SessionBoundIdentity

# ===========================================================================
# JtiCache — replay detection
# ===========================================================================

class TestJtiCache:

    def test_jti_cache_first_use_allowed(self):
        cache = JtiCache()
        assert cache.check_and_add("jti-001") is True

    def test_jti_cache_replay_rejected(self):
        cache = JtiCache()
        cache.check_and_add("jti-001")
        assert cache.check_and_add("jti-001") is False

    def test_jti_cache_different_jti_allowed(self):
        cache = JtiCache()
        cache.check_and_add("jti-001")
        assert cache.check_and_add("jti-002") is True

    def test_regression_jti_eviction_replay_blocked(self):
        """Full cache with non-expired entries denies new JTIs (fail-safe).

        Old behaviour: evicted the oldest entry on overflow, letting an attacker
        replay the evicted JTI before its TTL closed. New behaviour: deny the
        incoming entry instead — never evict a live JTI.
        """
        cache = JtiCache(maxsize=3, ttl_seconds=300)
        cache.check_and_add("a")
        cache.check_and_add("b")
        cache.check_and_add("c")
        # Cache full with non-expired entries — new entry is denied (fail-safe).
        assert cache.check_and_add("d") is False
        # "a" was NOT evicted and is still blocked.
        assert cache.check_and_add("a") is False

    def test_jti_cache_expired_entries_freed(self):
        """After TTL expires, entries are swept and space is freed for new JTIs."""
        cache = JtiCache(maxsize=2, ttl_seconds=0.01)
        assert cache.check_and_add("x") is True
        assert cache.check_and_add("y") is True
        time.sleep(0.02)  # let both entries expire
        # Sweep removes expired entries; new entry is accepted.
        assert cache.check_and_add("z") is True

    def test_jti_cache_empty_allows(self):
        cache = JtiCache()
        assert cache.check_and_add("fresh") is True

    def test_jti_cache_thread_safe(self):
        """Concurrent check_and_add with the same JTI — exactly one True."""
        cache = JtiCache()
        results: list[bool] = []
        lock = threading.Lock()

        def worker():
            result = cache.check_and_add("shared-jti")
            with lock:
                results.append(result)

        threads = [threading.Thread(target=worker) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        true_count = sum(1 for r in results if r is True)
        assert true_count == 1

    def test_jti_cache_large_maxsize(self):
        cache = JtiCache(maxsize=10_000)
        for i in range(1000):
            assert cache.check_and_add(f"jti-{i}") is True
        assert cache.check_and_add("jti-0") is False


# ===========================================================================
# SessionBoundIdentity — DPoP proof generation
# ===========================================================================

class TestSessionBoundIdentity:

    def _identity(self) -> SessionBoundIdentity:
        return SessionBoundIdentity()

    def _decode_token(self, token: str) -> tuple[dict, dict]:
        """Decode a JWT without verification (for claim inspection in tests)."""
        parts = token.split(".")
        assert len(parts) == 3, "Expected compact JWT with 3 parts"

        def decode_part(s: str) -> dict:
            # Add padding
            s += "=" * (-len(s) % 4)
            return json.loads(base64.urlsafe_b64decode(s))

        header = decode_part(parts[0])
        payload = decode_part(parts[1])
        return header, payload

    def test_dpop_proof_has_required_claims(self):
        identity = self._identity()
        token = identity.generate_dpop_proof("POST", "https://example.com/mcp")
        header, payload = self._decode_token(token)
        assert payload["htm"] == "POST"
        assert payload["htu"] == "https://example.com/mcp"
        assert "iat" in payload
        assert "jti" in payload

    def test_dpop_proof_alg_is_eddsa(self):
        identity = self._identity()
        token = identity.generate_dpop_proof("GET", "https://example.com")
        header, _ = self._decode_token(token)
        assert header["alg"] == "EdDSA"

    def test_dpop_proof_typ_is_dpop(self):
        identity = self._identity()
        token = identity.generate_dpop_proof("GET", "https://example.com")
        header, _ = self._decode_token(token)
        assert header["typ"] == "dpop+jwt"

    def test_dpop_proof_jwk_header_present(self):
        identity = self._identity()
        token = identity.generate_dpop_proof("GET", "https://example.com")
        header, _ = self._decode_token(token)
        assert "jwk" in header
        jwk = header["jwk"]
        assert jwk["kty"] == "OKP"
        assert jwk["crv"] == "Ed25519"
        assert "x" in jwk
        # Public key must not include private component
        assert "d" not in jwk

    def test_dpop_proof_htm_uppercased(self):
        identity = self._identity()
        token = identity.generate_dpop_proof("get", "https://example.com")
        _, payload = self._decode_token(token)
        assert payload["htm"] == "GET"

    def test_dpop_proof_nonce_included_when_provided(self):
        identity = self._identity()
        token = identity.generate_dpop_proof(
            "POST", "https://example.com", nonce="server-nonce-xyz"
        )
        _, payload = self._decode_token(token)
        assert payload.get("nonce") == "server-nonce-xyz"

    def test_dpop_proof_nonce_absent_when_not_provided(self):
        identity = self._identity()
        token = identity.generate_dpop_proof("POST", "https://example.com")
        _, payload = self._decode_token(token)
        assert "nonce" not in payload

    def test_dpop_proof_jti_unique_per_call(self):
        identity = self._identity()
        t1 = identity.generate_dpop_proof("GET", "https://example.com")
        t2 = identity.generate_dpop_proof("GET", "https://example.com")
        _, p1 = self._decode_token(t1)
        _, p2 = self._decode_token(t2)
        assert p1["jti"] != p2["jti"]

    def test_dpop_proof_iat_is_recent(self):
        identity = self._identity()
        token = identity.generate_dpop_proof("POST", "https://example.com")
        _, payload = self._decode_token(token)
        now = int(time.time())
        assert abs(payload["iat"] - now) <= 5

    def test_dpop_jti_cache_tracks_generated_proofs(self):
        identity = self._identity()
        token = identity.generate_dpop_proof("GET", "https://example.com")
        _, payload = self._decode_token(token)
        jti = payload["jti"]
        # The JTI was registered during generation
        assert identity.jti_cache.check_and_add(jti) is False

    def test_different_identities_have_different_keys(self):
        i1 = SessionBoundIdentity()
        i2 = SessionBoundIdentity()
        t1 = i1.generate_dpop_proof("GET", "https://example.com")
        t2 = i2.generate_dpop_proof("GET", "https://example.com")
        h1, _ = self._decode_token(t1)
        h2, _ = self._decode_token(t2)
        assert h1["jwk"]["x"] != h2["jwk"]["x"]
