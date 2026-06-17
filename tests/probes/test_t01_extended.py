"""Tests for T01-003 (token replay) and T01-004 (malformed auth) probes."""
from __future__ import annotations

from pathlib import Path

import pytest

from cosai_mcp.harness.mock_server import MockMCPServer
from tests.probes.conftest import error_response, ok_response, run_probe


# ===========================================================================
# T01-003 catalog and probe tests
# ===========================================================================

class TestT01003CatalogLoads:

    def test_t01_003_catalog_loads(self, catalog):
        t = catalog.load_file(Path("official/T01-003.json"))
        assert t.id == "T01-003"
        assert t.category == "T1"
        assert len(t.probes) == 2

    def test_t01_003_probes_assert_error(self, catalog):
        t = catalog.load_file(Path("official/T01-003.json"))
        for probe in t.probes:
            assert any(
                a.target == "response.error" for a in probe.assertions
            )

    def test_regression_t01_003_probes_are_distinct(self, catalog):
        """T01-003 probes must differ in method or assertion value.

        FIX 6: The original two probes were identical (same method, payload, and
        assertion) — the second probe provided zero additional coverage and would
        never catch a vulnerability the first probe missed.
        """
        t = catalog.load_file(Path("official/T01-003.json"))
        p1, p2 = t.probes
        assert (p1.method, p1.assertions) != (p2.method, p2.assertions), (
            "T01-003 probes must not be identical"
        )


class TestT01003Probes:

    @pytest.mark.asyncio
    async def test_t01_003_server_rejects_replay(self, catalog):
        """Secure server rejects replayed token → response.error=true → probe passes."""
        t = catalog.load_file(Path("official/T01-003.json"))
        probe = t.probes[0]

        with MockMCPServer(tools_call_response=error_response(-32001, "Token replayed")) as server:
            server.wait_ready()
            result = await run_probe(probe, t, server)

        assert result.passed is True

    @pytest.mark.asyncio
    async def test_t01_003_server_accepts_replay(self, catalog):
        """Vulnerable server accepts replayed token → response.error=false → probe fails."""
        t = catalog.load_file(Path("official/T01-003.json"))
        probe = t.probes[0]

        with MockMCPServer(tools_call_response=ok_response("data")) as server:
            server.wait_ready()
            result = await run_probe(probe, t, server)

        assert result.passed is False


# A JWT carrying a fixed ``jti`` claim — replaying it (sending it twice) is the
# canonical token-replay attack a JTI cache must defeat.
_REPLAY_TOKEN = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiJ1IiwiaXNzIjoiaHR0cHM6Ly9pZHAuZXhhbXBsZSIsImF1ZCI6Im1jcC1zZXJ2"
    "ZXIiLCJleHAiOjQxMDI0NDQ4MDAsImp0aSI6InJlcGxheS10ZXN0LWp0aS0wMDEifQ.ZmFrZXNpZw"
)
# A second, well-formed JWT identical to _REPLAY_TOKEN except for a DIFFERENT
# jti claim (replay-test-jti-002). Used to prove the server keys the replay cache
# on the jti, not on "any second call".
_REPLAY_TOKEN_2 = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiJ1IiwiaXNzIjoiaHR0cHM6Ly9pZHAuZXhhbXBsZSIsImF1ZCI6Im1jcC1zZXJ2"
    "ZXIiLCJleHAiOjQxMDI0NDQ4MDAsImp0aSI6InJlcGxheS10ZXN0LWp0aS0wMDIifQ.ZmFrZXNpZw"
)


class TestT01003RealReplay:
    """WG-89 item 9: a real replay sends the SAME request TWICE and asserts the
    SECOND is rejected. A single one-shot call cannot demonstrate replay at all —
    these tests exercise the two-call sequence against the JTI-cache contract.
    """

    @pytest.mark.asyncio
    async def test_real_replay_second_call_rejected(self, catalog):
        """JTI-cache server: first presentation served, identical second rejected."""
        t = catalog.load_file(Path("official/T01-003.json"))
        probe = t.probes[0]  # asserts response.error == true

        headers = {"Authorization": f"Bearer {_REPLAY_TOKEN}"}
        with MockMCPServer(reject_replayed_tokens=True) as server:
            server.wait_ready()
            first = await run_probe(probe, t, server, base_headers=headers)
            second = await run_probe(probe, t, server, base_headers=headers)

        # First call is served (no error) → the rejection-assertion probe "fails".
        # Second identical call is rejected (response.error) → the probe "passes".
        # The contract under test is the server's behavior, not the probe verdict:
        assert first.passed is False, "first presentation of a fresh token must be served"
        assert second.passed is True, "replayed (second) presentation must be rejected"

    @pytest.mark.asyncio
    async def test_vulnerable_server_accepts_both_presentations(self, catalog):
        """A server with no JTI cache serves the replayed token every time (T1 finding)."""
        t = catalog.load_file(Path("official/T01-003.json"))
        probe = t.probes[0]

        headers = {"Authorization": f"Bearer {_REPLAY_TOKEN}"}
        with MockMCPServer(reject_replayed_tokens=False) as server:
            server.wait_ready()
            first = await run_probe(probe, t, server, base_headers=headers)
            second = await run_probe(probe, t, server, base_headers=headers)

        # Neither call is rejected → both "fail" the rejection-assertion probe,
        # which is exactly the vulnerable signal (replay accepted).
        assert first.passed is False
        assert second.passed is False

    @pytest.mark.asyncio
    async def test_regression_valid_different_jti_not_treated_as_replay(self, catalog):
        """A second, WELL-FORMED JWT with a different jti is not a replay → served.

        Guards against the cache keying on "any second call" instead of the jti:
        both tokens are valid JWTs differing only in their jti claim, so a correct
        JTI cache serves both.
        """
        t = catalog.load_file(Path("official/T01-003.json"))
        probe = t.probes[0]

        with MockMCPServer(reject_replayed_tokens=True) as server:
            server.wait_ready()
            first = await run_probe(
                probe, t, server, base_headers={"Authorization": f"Bearer {_REPLAY_TOKEN}"}
            )
            second = await run_probe(
                probe, t, server, base_headers={"Authorization": f"Bearer {_REPLAY_TOKEN_2}"}
            )

        # Distinct jti values → both served (no rejection), so both probe verdicts
        # are False (the rejection-assertion probe "fails" because nothing erred).
        assert first.passed is False
        assert second.passed is False


# ===========================================================================
# T01-006 — distinct JWT-validation probes (WG-89 item 9)
# ===========================================================================

class TestT01006CatalogLoads:

    def test_t01_006_catalog_loads(self, catalog):
        t = catalog.load_file(Path("official/T01-006.json"))
        assert t.id == "T01-006"
        assert t.category == "T1"
        assert len(t.probes) == 6

    def test_t01_006_every_probe_asserts_rejection(self, catalog):
        """Each probe asserts the server REJECTS the crafted token (response.error)."""
        t = catalog.load_file(Path("official/T01-006.json"))
        for probe in t.probes:
            err = [a for a in probe.assertions if a.target == "response.error"]
            assert err, f"{probe.id} must assert response.error"
            assert err[0].value is True

    def test_t01_006_every_probe_carries_a_distinct_crafted_token(self, catalog):
        """Each probe must send its own Authorization header (a distinct attack token)."""
        t = catalog.load_file(Path("official/T01-006.json"))
        for probe in t.probes:
            assert probe.probe_headers is not None
            assert "Authorization" in probe.probe_headers

    def test_regression_t01_006_probes_are_distinct(self, catalog):
        """WG-89 item 9: every probe must exercise a DISTINCT failure mode.

        The original T01-003 'replay' coverage was a single probe. Distinctness
        is enforced here across (payload, Authorization token, corroboration):
        no two probes may be byte-identical, so each adds real coverage
        (alg=none, iss, aud, exp, scope-narrowing, DPoP-binding).
        """
        t = catalog.load_file(Path("official/T01-006.json"))
        signatures = [
            (
                tuple(sorted(p.payload.get("arguments", {}).items())),
                p.probe_headers.get("Authorization") if p.probe_headers else None,
            )
            for p in t.probes
        ]
        assert len(signatures) == len(set(signatures)), (
            "T01-006 probes must each carry a distinct payload+token"
        )
        # Every Authorization token must be unique (no copy-paste duplication).
        tokens = [s[1] for s in signatures]
        assert len(tokens) == len(set(tokens)) == 6


class TestT01006Probes:

    @pytest.mark.asyncio
    async def test_t01_006_secure_server_rejects_all(self, catalog):
        """A server that rejects every crafted token → every probe passes."""
        t = catalog.load_file(Path("official/T01-006.json"))
        with MockMCPServer(tools_call_response=error_response(-32001, "Invalid token")) as server:
            server.wait_ready()
            for probe in t.probes:
                result = await run_probe(probe, t, server)
                assert result.passed is True, f"{probe.id} should pass against a rejecting server"

    @pytest.mark.asyncio
    async def test_t01_006_permissive_server_fails_each(self, catalog):
        """A server that accepts every crafted token → every probe reports a finding."""
        t = catalog.load_file(Path("official/T01-006.json"))
        with MockMCPServer(tools_call_response=ok_response("served")) as server:
            server.wait_ready()
            for probe in t.probes:
                result = await run_probe(probe, t, server)
                assert result.passed is False, f"{probe.id} should fail against a permissive server"
                assert result.inconclusive_reason is None, (
                    f"{probe.id} finding must be corroborated, not inconclusive"
                )


# ===========================================================================
# T01-004 catalog and probe tests
# ===========================================================================

class TestT01004CatalogLoads:

    def test_t01_004_catalog_loads(self, catalog):
        t = catalog.load_file(Path("official/T01-004.json"))
        assert t.id == "T01-004"
        assert t.category == "T1"
        assert len(t.probes) == 2

    def test_t01_004_probes_assert_error(self, catalog):
        t = catalog.load_file(Path("official/T01-004.json"))
        for probe in t.probes:
            assert any(
                a.target == "response.error" for a in probe.assertions
            )

    def test_regression_t01_004_probes_are_distinct(self, catalog):
        """T01-004 probes must differ in method or assertion value — see FIX 6."""
        t = catalog.load_file(Path("official/T01-004.json"))
        p1, p2 = t.probes
        assert (p1.method, p1.assertions) != (p2.method, p2.assertions), (
            "T01-004 probes must not be identical"
        )


class TestT01004Probes:

    @pytest.mark.asyncio
    async def test_t01_004_malformed_auth_rejected(self, catalog):
        """Secure server rejects malformed auth → response.error=true → probe passes."""
        t = catalog.load_file(Path("official/T01-004.json"))
        probe = t.probes[0]

        with MockMCPServer(tools_call_response=error_response(-32001, "Bad auth format")) as server:
            server.wait_ready()
            result = await run_probe(probe, t, server)

        assert result.passed is True

    @pytest.mark.asyncio
    async def test_t01_004_malformed_auth_accepted_fails(self, catalog):
        """Vulnerable server accepts malformed auth → probe fails."""
        t = catalog.load_file(Path("official/T01-004.json"))
        probe = t.probes[0]

        with MockMCPServer(tools_call_response=ok_response("data")) as server:
            server.wait_ready()
            result = await run_probe(probe, t, server)

        assert result.passed is False
