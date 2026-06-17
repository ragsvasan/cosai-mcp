"""TelemetryEmitter — protocol and concrete implementations.

Concrete emitters:
* NullEmitter   — silently discards all events (default, no-op)
* HttpEmitter   — POSTs OCSF events to a SIEM/SOAR webhook endpoint

Usage::

    emitter = HttpEmitter("https://siem.example.com/webhook/cosai",
                          auth_header="Bearer <token>")
    result = emitter.emit(ocsf_event)
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class EmitResult:
    """Outcome of one telemetry emit call."""

    success: bool
    status_code: int | None  # HTTP status, or None for NullEmitter / pre-send errors
    error: str | None        # description if success is False


@runtime_checkable
class TelemetryEmitter(Protocol):
    """Protocol that all telemetry backends must implement."""

    def emit(self, event: dict[str, Any]) -> EmitResult:
        """Send one OCSF event dict to the backend.

        Must never raise — return EmitResult(success=False, ...) on failure.
        """
        ...

    def emit_batch(self, events: list[dict[str, Any]]) -> list[EmitResult]:
        """Send multiple events.

        Default implementation calls emit() per event; backends may override
        for efficiency (bulk insert, batched HTTP, etc.).
        """
        ...


class NullEmitter:
    """No-op emitter — discards all events.  Default when no --emit-to is set."""

    def emit(self, event: dict[str, Any]) -> EmitResult:
        return EmitResult(success=True, status_code=None, error=None)

    def emit_batch(self, events: list[dict[str, Any]]) -> list[EmitResult]:
        return [EmitResult(success=True, status_code=None, error=None) for _ in events]


class HttpEmitter:
    """POST OCSF events to a SIEM/SOAR webhook over HTTPS.

    Parameters
    ----------
    endpoint:
        Full URL of the SIEM webhook endpoint.
    auth_header:
        Optional value for the ``Authorization`` header (e.g. ``"Bearer tok"``).
    timeout:
        Per-request timeout in seconds (default 10).
    verify_tls:
        Whether to verify TLS certificates (default True — never disable in prod).
    """

    def __init__(
        self,
        endpoint: str,
        auth_header: str | None = None,
        timeout: float = 10.0,
        verify_tls: bool = True,
    ) -> None:
        if not endpoint.startswith(("http://", "https://")):
            raise ValueError(
                f"HttpEmitter endpoint must start with http:// or https://: {endpoint!r}"
            )
        self._endpoint = endpoint
        self._auth_header = auth_header
        import httpx
        self._client = httpx.Client(
            timeout=timeout,
            verify=verify_tls,
            follow_redirects=False,
            trust_env=False,  # blocks HTTP_PROXY injection per locked architecture §3
        )

    @property
    def endpoint(self) -> str:
        return self._endpoint

    def _headers(self) -> dict[str, str]:
        h = {"Content-Type": "application/json"}
        if self._auth_header:
            h["Authorization"] = self._auth_header
        return h

    def emit(self, event: dict[str, Any]) -> EmitResult:
        """POST a single OCSF event to the configured endpoint."""
        try:
            body = json.dumps(event).encode()
            resp = self._client.post(
                self._endpoint,
                content=body,
                headers=self._headers(),
            )
            success = 200 <= resp.status_code < 300
            if not success:
                log.warning(
                    "TelemetryEmitter: SIEM webhook returned %s for probe %s",
                    resp.status_code,
                    event.get("finding", {}).get("uid", "?"),
                )
            return EmitResult(
                success=success,
                status_code=resp.status_code,
                error=None if success else f"HTTP {resp.status_code}",
            )
        except Exception as exc:
            log.warning("TelemetryEmitter: failed to emit event: %s", type(exc).__name__)
            return EmitResult(
                success=False,
                status_code=None,
                error=f"connection error ({type(exc).__name__})",
            )

    def emit_batch(self, events: list[dict[str, Any]]) -> list[EmitResult]:
        """POST each event individually (sequential).

        Override in a subclass to bulk-insert into specific SIEM APIs.
        """
        return [self.emit(e) for e in events]

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> HttpEmitter:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
