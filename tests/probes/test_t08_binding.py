"""Tests for T8-003 — operator-supplied bind-config validation + TLS inspection.

Scope note (WG-89 item 12): ``BindAddressValidator`` validates the host:port the
OPERATOR declares the server is bound to; it does not perform active shadow-
server discovery (interface enumeration / port scanning), which is out of scope
for this non-adversarial scanner. ``TransportSecurityInspector`` adds optional,
best-effort TLS posture inspection (SAN / cipher / mTLS) of the connected
transport — also observation, not discovery.
"""
from __future__ import annotations

import socket
import threading
from pathlib import Path

import pytest

from cosai_mcp.middleware.network import (
    BindAddressValidator,
    BindCheckResult,
    TLSInspectionResult,
    TransportSecurityInspector,
)


CATALOG_ROOT = Path(__file__).parent.parent.parent / "catalog"


# ===========================================================================
# T8-003 catalog loads
# ===========================================================================

class TestT08003CatalogLoads:

    def test_t08_003_catalog_loads(self, catalog):
        t = catalog.load_file(Path("official/T08-003.json"))
        assert t.id == "T08-003"
        assert t.category == "T8"
        assert len(t.probes) >= 1
        probe = t.probes[0]
        assert any(a.target == "response.error" for a in probe.assertions)

    def test_regression_t08_003_assertion_not_inverted(self, catalog):
        """T08-003-p1 must assert response.error == False (server should accept initialize).

        FIX 5: The original assertion was response.error eq true, which always
        failed against a clean server (initialize succeeds → response.error=false).
        A false-positive on every clean server defeats the probe's purpose.
        """
        t = catalog.load_file(Path("official/T08-003.json"))
        probe = t.probes[0]
        error_assertions = [
            a for a in probe.assertions if a.target == "response.error"
        ]
        assert len(error_assertions) == 1
        assert error_assertions[0].value is False, (
            "T08-003-p1 response.error assertion must be False (not inverted)"
        )


# ===========================================================================
# BindAddressValidator — unit tests
# ===========================================================================

class TestBindAddressValidator:

    def test_bind_address_validator_loopback_ipv4(self):
        v = BindAddressValidator()
        assert v.is_loopback_only("127.0.0.1") is True

    def test_bind_address_validator_loopback_localhost(self):
        v = BindAddressValidator()
        assert v.is_loopback_only("localhost") is True

    def test_bind_address_validator_nonloopback_all_interfaces(self):
        v = BindAddressValidator()
        # 0.0.0.0 is not loopback
        assert v.is_loopback_only("0.0.0.0") is False

    def test_bind_address_validator_nonloopback_public_ip(self):
        v = BindAddressValidator()
        # 8.8.8.8 is public
        assert v.is_loopback_only("8.8.8.8") is False

    def test_bind_check_result_loopback_only_true(self):
        v = BindAddressValidator()
        result = v.check_bind_address("127.0.0.1", 8000)
        assert result.is_loopback_only is True
        assert result.host == "127.0.0.1"
        assert result.port == 8000

    def test_bind_check_result_nonloopback(self):
        v = BindAddressValidator()
        result = v.check_bind_address("0.0.0.0", 8000)
        assert result.is_loopback_only is False

    def test_bind_check_result_is_frozen(self):
        result = BindCheckResult(
            host="127.0.0.1", port=8000, is_loopback_only=True, resolved_ips=("127.0.0.1",)
        )
        with pytest.raises((AttributeError, TypeError)):
            result.host = "mutated"  # type: ignore[misc]

    def test_loopback_bound_server_passes(self):
        """A server that only responds on 127.0.0.1 is classified as loopback-only."""
        v = BindAddressValidator()
        result = v.check_bind_address("127.0.0.1", 9999)
        assert result.is_loopback_only is True

    def test_exposed_server_fails(self):
        """0.0.0.0 bind address is classified as exposed (not loopback-only)."""
        v = BindAddressValidator()
        result = v.check_bind_address("0.0.0.0", 9999)
        assert result.is_loopback_only is False

    def test_unreachable_host_returns_error(self):
        v = BindAddressValidator()
        result = v.check_bind_address("this.host.does.not.exist.invalid", 8000)
        assert result.error is not None
        assert result.is_loopback_only is False


# ===========================================================================
# All T08 probes load correctly
# ===========================================================================

class TestAllT08ProbesCatalogLoad:

    def test_all_t08_probes_load(self, catalog):
        for name in ("T08-001.json", "T08-002.json", "T08-003.json"):
            t = catalog.load_file(Path(f"official/{name}"))
            assert t.category == "T8"


# ===========================================================================
# Scope-honesty: validator docstring is reframed as operator-supplied config
# ===========================================================================

class TestBindValidatorScopeIsHonest:

    def test_docstring_disclaims_active_discovery(self):
        """WG-89 item 12: the validator must not claim shadow-server discovery."""
        doc = (BindAddressValidator.__doc__ or "").lower()
        assert "operator" in doc
        assert "out of scope" in doc or "no active discovery" in doc

    def test_module_docstring_disclaims_interface_enumeration(self):
        import cosai_mcp.middleware.network as net
        doc = (net.__doc__ or "").lower()
        assert "shadow-server discovery" in doc or "interface" in doc
        assert "out of scope" in doc


# ===========================================================================
# TransportSecurityInspector — TLS posture inspection (optional)
# ===========================================================================

class TestSummarizeCertificate:
    """Pure-function cert summary — no network."""

    _CERT = {
        "subject": ((("commonName", "mcp.example.com"),),),
        "subjectAltName": (
            ("DNS", "mcp.example.com"),
            ("DNS", "api.example.com"),
            ("IP Address", "127.0.0.1"),
        ),
        "notAfter": "Dec 31 23:59:59 2027 GMT",
    }

    def test_extracts_subject_cn(self):
        out = TransportSecurityInspector.summarize_certificate(self._CERT)
        assert out["subject_cn"] == "mcp.example.com"

    def test_extracts_all_sans(self):
        out = TransportSecurityInspector.summarize_certificate(self._CERT)
        assert out["san"] == ("DNS:mcp.example.com", "DNS:api.example.com", "IP Address:127.0.0.1")

    def test_extracts_not_after(self):
        out = TransportSecurityInspector.summarize_certificate(self._CERT)
        assert out["not_after"] == "Dec 31 23:59:59 2027 GMT"

    def test_extracts_cipher_and_protocol(self):
        out = TransportSecurityInspector.summarize_certificate(
            self._CERT, cipher=("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        )
        assert out["cipher"] == "TLS_AES_256_GCM_SHA384"
        assert out["protocol"] == "TLSv1.3"

    def test_explicit_protocol_overrides_cipher_tuple(self):
        out = TransportSecurityInspector.summarize_certificate(
            self._CERT, cipher=("X", "TLSv1.2", 128), protocol="TLSv1.3"
        )
        assert out["protocol"] == "TLSv1.3"

    def test_empty_cert_is_safe(self):
        out = TransportSecurityInspector.summarize_certificate(None)
        assert out["subject_cn"] is None
        assert out["san"] == ()


class TestTransportInspectErrorPath:
    """inspect() must never raise — failures surface via .error."""

    def test_connection_refused_returns_error_result(self):
        inspector = TransportSecurityInspector()
        # Port 9 (discard) on loopback is almost always closed → fast refusal.
        result = inspector.inspect("127.0.0.1", 9, timeout=1.0)
        assert isinstance(result, TLSInspectionResult)
        assert result.tls is False
        assert result.error is not None

    def test_plaintext_endpoint_returns_error_not_exception(self):
        """A non-TLS HTTP server triggers an SSLError, surfaced (not raised)."""
        from cosai_mcp.harness.mock_server import MockMCPServer
        with MockMCPServer() as server:
            server.wait_ready()
            result = TransportSecurityInspector().inspect("127.0.0.1", server.port, timeout=2.0)
        assert result.tls is False
        assert result.error is not None
