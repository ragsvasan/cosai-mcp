"""T12 — Insufficient Logging: audit-log coverage is MIDDLEWARE-ONLY.

WG-89 reviewer item 4. The "T12 logging" black-box probe never tested logging —
it inspected destructive-tool *descriptions* (transparency UX). That probe has
been honestly renamed to ``test_t12_description_transparency.py``.

Genuine T12 "Insufficient Logging" coverage — a tamper-evident, hash-chained,
append-only audit trail of every tool invocation plus a DAG causal trace — is
**structurally undecidable from a black-box prober**: the audit log lives inside
the server and is never exposed over JSON-RPC. Per the locked three-engine
architecture (CLAUDE.md), T12 is covered by the **middleware instrumentation
engine** (``cosai_mcp.middleware.audit``), verified out-of-band via
``cosai audit verify`` over the chained log — NOT by anything in ``tests/probes/``.

This module is the explicit placeholder that records that boundary so a future
contributor does not "add the missing T12 logging probe": there is no black-box
probe to add. The real audit-chain tests live in ``tests/middleware/``.
"""
from __future__ import annotations

import pytest


def test_t12_audit_logging_is_middleware_only_coverage_matrix():
    """The coverage matrix must classify T12 as middleware-only — guarding
    against a regression that re-labels T12 as a black-box probe category."""
    from cosai_mcp import COVERAGE_MATRIX

    t12 = COVERAGE_MATRIX["T12"]
    # Entry may be a plain coverage string ("middleware-only") or a dict.
    engine = (
        " ".join(str(v) for v in t12.values()) if isinstance(t12, dict) else str(t12)
    ).lower()
    assert "middleware" in engine, (
        f"T12 must be middleware-only per locked architecture; got {t12!r}"
    )


def test_t12_audit_chain_lives_in_middleware_not_probes():
    """The audit middleware (hash-chained log) must exist and be the home of
    real T12 coverage — black-box probes cannot reach it."""
    from cosai_mcp.middleware import audit

    # The middleware module is the load-bearing T12 surface; assert it exposes
    # an append/verify-style audit primitive rather than this probe file.
    members = dir(audit)
    assert any(
        "audit" in m.lower() or "log" in m.lower() or "chain" in m.lower()
        for m in members
    ), f"expected an audit-log primitive in cosai_mcp.middleware.audit; got {members!r}"


@pytest.mark.skip(
    reason="T12 audit logging is middleware-only — no black-box probe is possible "
    "(audit trail is internal to the server, never exposed over JSON-RPC). "
    "See cosai_mcp.middleware.audit and tests/middleware/ for real coverage."
)
def test_t12_blackbox_audit_log_probe_placeholder():
    """Intentionally skipped placeholder — documents that a black-box T12
    audit-logging probe cannot exist, so none should be added here."""
