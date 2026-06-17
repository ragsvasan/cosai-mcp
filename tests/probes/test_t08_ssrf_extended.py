"""Black-box probes for T8 — Extended cloud-metadata + scheme SSRF coverage.

T08-004: GCP metadata endpoint (metadata.google.internal)
T08-005: Azure IMDS (169.254.169.254/metadata)
T08-006: AWS IMDSv2 token endpoint (169.254.169.254/latest/api/token)
T08-007: Alibaba Cloud ECS metadata (100.100.100.200)
T08-008: file:// scheme leaking local filesystem
T08-009: IPv6 ULA/link-local rejection (fd00::1, fe80::1)
"""
from __future__ import annotations

from pathlib import Path

import pytest

from cosai_mcp.harness.mock_server import MockMCPServer
from tests.probes.conftest import error_response, ok_response, run_probe


# ---------------------------------------------------------------------------
# Catalog load tests
# ---------------------------------------------------------------------------

class TestT08ExtendedCatalogLoads:

    def test_t08_004_loads(self, catalog):
        t = catalog.load_file(Path("official/T08-004.json"))
        assert t.id == "T08-004"
        assert t.category == "T8"
        assert len(t.probes) == 1
        assert t.probes[0].method == "tools/call"
        assert "metadata.google.internal" in t.probes[0].payload["arguments"]["url"]

    def test_t08_005_loads(self, catalog):
        t = catalog.load_file(Path("official/T08-005.json"))
        assert t.id == "T08-005"
        assert t.category == "T8"
        assert len(t.probes) == 1
        assert "metadata/instance" in t.probes[0].payload["arguments"]["url"]

    def test_t08_006_loads(self, catalog):
        t = catalog.load_file(Path("official/T08-006.json"))
        assert t.id == "T08-006"
        assert t.category == "T8"
        assert len(t.probes) == 1
        assert "/latest/api/token" in t.probes[0].payload["arguments"]["url"]

    def test_t08_007_loads(self, catalog):
        t = catalog.load_file(Path("official/T08-007.json"))
        assert t.id == "T08-007"
        assert t.category == "T8"
        assert len(t.probes) == 1
        assert "100.100.100.200" in t.probes[0].payload["arguments"]["url"]

    def test_t08_008_loads(self, catalog):
        t = catalog.load_file(Path("official/T08-008.json"))
        assert t.id == "T08-008"
        assert t.category == "T8"
        assert len(t.probes) == 1
        assert t.probes[0].payload["arguments"]["url"] == "file:///etc/passwd"

    def test_t08_009_loads(self, catalog):
        t = catalog.load_file(Path("official/T08-009.json"))
        assert t.id == "T08-009"
        assert t.category == "T8"
        assert len(t.probes) == 2
        urls = [p.payload["arguments"]["url"] for p in t.probes]
        assert any("fd00" in u for u in urls)
        assert any("fe80" in u for u in urls)

    def test_t08_009_protocol_error_is_expected(self, catalog):
        """Both T08-009 probes use protocol_error_is_expected=True — rejection IS the secure outcome."""
        t = catalog.load_file(Path("official/T08-009.json"))
        for probe in t.probes:
            assert probe.protocol_error_is_expected is True


# ---------------------------------------------------------------------------
# T08-004 — GCP metadata
# ---------------------------------------------------------------------------

class TestT08004GCPMetadata:

    @pytest.mark.asyncio
    async def test_secure_server_passes_gcp_metadata_probe(self, catalog):
        """Secure server rejects GCP metadata URL at application layer → probe is inconclusive
        (COV-08: a -32602 rejection cannot prove the tool even fetches URLs, so it is
        not a vacuous pass either; the probe is INCONCLUSIVE rather than a finding)."""
        t = catalog.load_file(Path("official/T08-004.json"))
        probe = t.probes[0]

        with MockMCPServer(tools_call_response=error_response(-32602, "URL scheme/host not allowed")) as server:
            server.wait_ready()
            result = await run_probe(probe, t, server)

        # -32602 → inconclusive (can't prove tool fetches URLs); not a finding
        assert result.passed is False
        assert result.inconclusive_reason is not None

    @pytest.mark.asyncio
    async def test_vulnerable_server_returns_gcp_metadata(self, catalog):
        """Vulnerable server fetches GCP metadata and returns body → probe fails."""
        t = catalog.load_file(Path("official/T08-004.json"))
        probe = t.probes[0]

        body = '{"kind":"compute#metadata","items":[{"key":"numericProjectId","value":"123456789"}]}'
        with MockMCPServer(tools_call_response=ok_response(body)) as server:
            server.wait_ready()
            result = await run_probe(probe, t, server)

        assert result.passed is False

    @pytest.mark.asyncio
    async def test_vulnerable_server_returns_computemetadata_signature(self, catalog):
        """Vulnerable server leaks computeMetadata path in response body → probe fails."""
        t = catalog.load_file(Path("official/T08-004.json"))
        probe = t.probes[0]

        body = "computeMetadata/v1/instance/zone: projects/123/zones/us-central1-a"
        with MockMCPServer(tools_call_response=ok_response(body)) as server:
            server.wait_ready()
            result = await run_probe(probe, t, server)

        assert result.passed is False


# ---------------------------------------------------------------------------
# T08-005 — Azure IMDS
# ---------------------------------------------------------------------------

class TestT08005AzureIMDS:

    @pytest.mark.asyncio
    async def test_secure_server_passes_azure_imds_probe(self, catalog):
        """Secure server rejects Azure IMDS URL → probe inconclusive (COV-08).
        -32602 cannot prove the tool fetches URLs; it is INCONCLUSIVE, not a finding."""
        t = catalog.load_file(Path("official/T08-005.json"))
        probe = t.probes[0]

        with MockMCPServer(tools_call_response=error_response(-32602, "Private address blocked")) as server:
            server.wait_ready()
            result = await run_probe(probe, t, server)

        assert result.passed is False
        assert result.inconclusive_reason is not None

    @pytest.mark.asyncio
    async def test_vulnerable_server_returns_azure_environment(self, catalog):
        """Vulnerable server leaks azEnvironment in response body → probe fails."""
        t = catalog.load_file(Path("official/T08-005.json"))
        probe = t.probes[0]

        body = '{"compute":{"azEnvironment":"AzurePublicCloud","vmId":"abc-123"}}'
        with MockMCPServer(tools_call_response=ok_response(body)) as server:
            server.wait_ready()
            result = await run_probe(probe, t, server)

        assert result.passed is False

    @pytest.mark.asyncio
    async def test_vulnerable_server_returns_vm_id(self, catalog):
        """Vulnerable server leaks vmId in response body → probe fails."""
        t = catalog.load_file(Path("official/T08-005.json"))
        probe = t.probes[0]

        body = '{"compute":{"location":"eastus","vmId":"deadbeef-0000-0000-0000-000000000001"}}'
        with MockMCPServer(tools_call_response=ok_response(body)) as server:
            server.wait_ready()
            result = await run_probe(probe, t, server)

        assert result.passed is False


# ---------------------------------------------------------------------------
# T08-006 — AWS IMDSv2 token endpoint
# ---------------------------------------------------------------------------

class TestT08006AWSIMDSv2:

    @pytest.mark.asyncio
    async def test_secure_server_passes_imdsv2_token_probe(self, catalog):
        """Secure server rejects IMDSv2 token URL → probe inconclusive (COV-08).
        -32602 cannot prove the tool fetches URLs; it is INCONCLUSIVE, not a finding."""
        t = catalog.load_file(Path("official/T08-006.json"))
        probe = t.probes[0]

        with MockMCPServer(tools_call_response=error_response(-32602, "Link-local address denied")) as server:
            server.wait_ready()
            result = await run_probe(probe, t, server)

        assert result.passed is False
        assert result.inconclusive_reason is not None

    @pytest.mark.asyncio
    async def test_vulnerable_server_returns_imdsv2_token(self, catalog):
        """Vulnerable server fetches IMDSv2 and returns token → probe fails."""
        t = catalog.load_file(Path("official/T08-006.json"))
        probe = t.probes[0]

        # IMDSv2 tokens begin with AQAEA
        body = "AQAEABcX9vGcCCmHJ5cTd_example_token_value_here"
        with MockMCPServer(tools_call_response=ok_response(body)) as server:
            server.wait_ready()
            result = await run_probe(probe, t, server)

        assert result.passed is False


# ---------------------------------------------------------------------------
# T08-007 — Alibaba Cloud ECS metadata
# ---------------------------------------------------------------------------

class TestT08007AlibabaMetadata:

    @pytest.mark.asyncio
    async def test_secure_server_passes_alibaba_metadata_probe(self, catalog):
        """Secure server rejects Alibaba metadata URL → probe inconclusive (COV-08).
        -32602 cannot prove the tool fetches URLs; it is INCONCLUSIVE, not a finding."""
        t = catalog.load_file(Path("official/T08-007.json"))
        probe = t.probes[0]

        with MockMCPServer(tools_call_response=error_response(-32602, "Host not permitted")) as server:
            server.wait_ready()
            result = await run_probe(probe, t, server)

        assert result.passed is False
        assert result.inconclusive_reason is not None

    @pytest.mark.asyncio
    async def test_vulnerable_server_returns_instance_id(self, catalog):
        """Vulnerable server leaks instance-id from Alibaba metadata → probe fails."""
        t = catalog.load_file(Path("official/T08-007.json"))
        probe = t.probes[0]

        body = "instance-id\nvpc-id\nregion-id"
        with MockMCPServer(tools_call_response=ok_response(body)) as server:
            server.wait_ready()
            result = await run_probe(probe, t, server)

        assert result.passed is False


# ---------------------------------------------------------------------------
# T08-008 — file:// scheme
# ---------------------------------------------------------------------------

class TestT08008FileScheme:

    @pytest.mark.asyncio
    async def test_secure_server_passes_file_scheme_probe(self, catalog):
        """Secure server rejects file:// URL → probe inconclusive (COV-08).
        -32602 cannot prove the tool reads files; it is INCONCLUSIVE, not a finding."""
        t = catalog.load_file(Path("official/T08-008.json"))
        probe = t.probes[0]

        with MockMCPServer(tools_call_response=error_response(-32602, "Unsupported URL scheme: file")) as server:
            server.wait_ready()
            result = await run_probe(probe, t, server)

        assert result.passed is False
        assert result.inconclusive_reason is not None

    @pytest.mark.asyncio
    async def test_vulnerable_server_leaks_passwd(self, catalog):
        """Vulnerable server reads /etc/passwd via file:// and returns content → probe fails."""
        t = catalog.load_file(Path("official/T08-008.json"))
        probe = t.probes[0]

        body = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
        with MockMCPServer(tools_call_response=ok_response(body)) as server:
            server.wait_ready()
            result = await run_probe(probe, t, server)

        assert result.passed is False


# ---------------------------------------------------------------------------
# T08-009 — IPv6 ULA / link-local rejection
# ---------------------------------------------------------------------------

class TestT08009IPv6Private:

    @pytest.mark.asyncio
    async def test_secure_server_rejects_ipv6_ula(self, catalog):
        """Secure server rejects IPv6 ULA address with application error → probe inconclusive (COV-08).
        -32602 cannot prove the tool fetches IPv6 addresses; it is INCONCLUSIVE, not a finding.
        An application-level error (non-protocol code) would be a genuine PASS."""
        t = catalog.load_file(Path("official/T08-009.json"))
        probe_ula = t.probes[0]  # fd00::1

        with MockMCPServer(tools_call_response=error_response(-32602, "IPv6 ULA address blocked")) as server:
            server.wait_ready()
            result = await run_probe(probe_ula, t, server)

        assert result.passed is False
        assert result.inconclusive_reason is not None

    @pytest.mark.asyncio
    async def test_secure_server_rejects_ipv6_link_local(self, catalog):
        """Secure server rejects IPv6 link-local address with application error → probe inconclusive (COV-08).
        -32602 cannot prove the tool fetches IPv6 addresses; it is INCONCLUSIVE, not a finding."""
        t = catalog.load_file(Path("official/T08-009.json"))
        probe_ll = t.probes[1]  # fe80::1

        with MockMCPServer(tools_call_response=error_response(-32602, "IPv6 link-local address blocked")) as server:
            server.wait_ready()
            result = await run_probe(probe_ll, t, server)

        assert result.passed is False
        assert result.inconclusive_reason is not None

    @pytest.mark.asyncio
    async def test_secure_server_rejects_ipv6_ula_with_app_error(self, catalog):
        """Secure server rejects IPv6 ULA with a non-protocol error (application layer) → probe PASSES."""
        t = catalog.load_file(Path("official/T08-009.json"))
        probe_ula = t.probes[0]  # fd00::1

        # Application-level error (not a JSON-RPC protocol code) → not inconclusive
        with MockMCPServer(tools_call_response=error_response(-32001, "IPv6 private address blocked")) as server:
            server.wait_ready()
            result = await run_probe(probe_ula, t, server)

        # response.error == True → assertion passes; not a protocol code → not inconclusive
        assert result.passed is True

    @pytest.mark.asyncio
    async def test_vulnerable_server_fetches_ipv6_ula(self, catalog):
        """Vulnerable server fetches IPv6 ULA address (returns ok_response) → probe fails."""
        t = catalog.load_file(Path("official/T08-009.json"))
        probe_ula = t.probes[0]

        with MockMCPServer(tools_call_response=ok_response("internal service response")) as server:
            server.wait_ready()
            result = await run_probe(probe_ula, t, server)

        # response.error == False → assertion "eq True" fails → probe fails
        assert result.passed is False

    @pytest.mark.asyncio
    async def test_vulnerable_server_fetches_ipv6_link_local(self, catalog):
        """Vulnerable server fetches IPv6 link-local address (returns ok_response) → probe fails."""
        t = catalog.load_file(Path("official/T08-009.json"))
        probe_ll = t.probes[1]

        with MockMCPServer(tools_call_response=ok_response("link-local service response")) as server:
            server.wait_ready()
            result = await run_probe(probe_ll, t, server)

        assert result.passed is False
