"""CatalogLoader — Ed25519 verification, provenance, path confinement."""
from __future__ import annotations

import base64
import json
import types
from pathlib import Path
from typing import Any

import warnings as _warnings

try:
    import re2  # google-re2
except ImportError:  # pragma: no cover
    import re as re2  # type: ignore[no-redef]
    _warnings.warn(
        "google-re2 not available; falling back to stdlib re for catalog pattern validation. "
        "Production deployments must use google-re2 (pip install google-re2) "
        "to prevent ReDoS via malicious catalog entries.",
        RuntimeWarning,
        stacklevel=1,
    )

from cosai_mcp.catalog.models import (
    Assertion,
    Operator,
    Probe,
    Provenance,
    Severity,
    ThreatDefinition,
)
from cosai_mcp.catalog.schema import validate_threat_json
from cosai_mcp.exceptions import (
    PathTraversalError,
    SchemaValidationError,
    SignatureVerificationError,
    UnsafePatternError,
)
from cosai_mcp.keys import verify_catalog_signature


def _assert_no_mutable_containers(obj: Any, path: str = "") -> None:
    """Walk the dataclass tree and assert no list or dict instances remain."""
    if isinstance(obj, list):
        raise TypeError(
            f"Mutable list found at {path!r} — all list fields must be converted to tuple."
        )
    if isinstance(obj, dict):
        raise TypeError(
            f"Mutable dict found at {path!r} — all dict fields must be converted to MappingProxyType."
        )
    if hasattr(obj, "__dataclass_fields__"):
        for field_name in obj.__dataclass_fields__:  # type: ignore[union-attr]
            _assert_no_mutable_containers(getattr(obj, field_name), f"{path}.{field_name}")
    if isinstance(obj, tuple):
        for i, item in enumerate(obj):
            _assert_no_mutable_containers(item, f"{path}[{i}]")
    if isinstance(obj, types.MappingProxyType):
        for k, v in obj.items():
            _assert_no_mutable_containers(v, f"{path}[{k!r}]")


def _make_mapping_proxy(d: Any) -> Any:
    """Recursively convert dicts to MappingProxyType and lists to tuples."""
    if isinstance(d, dict):
        return types.MappingProxyType({k: _make_mapping_proxy(v) for k, v in d.items()})
    if isinstance(d, list):
        return tuple(_make_mapping_proxy(item) for item in d)
    return d


def _parse_assertion(
    raw: dict,
    is_custom: bool,
    allow_regex_in_custom: bool,
) -> Assertion:
    operator = Operator(raw["operator"])
    value = raw["value"]

    compiled_pattern: object = None
    if operator == Operator.MATCHES_REGEX:
        if is_custom and not allow_regex_in_custom:
            raise UnsafePatternError(
                "matches_regex operator is disabled in custom catalog files "
                "unless allow_regex_in_custom=True is passed to CatalogLoader."
            )
        pattern_str = str(value)
        try:
            compiled_pattern = re2.compile(pattern_str)
        except re2.error as exc:
            raise UnsafePatternError(
                f"RE2 rejected pattern {pattern_str!r}: {exc}"
            ) from exc

    # Convert list values (e.g. for status_in / error_code_in) to tuples
    if isinstance(value, list):
        value = tuple(value)

    return Assertion(
        target=raw["target"],
        operator=operator,
        value=value,
        compiled_pattern=compiled_pattern,
    )


def _parse_probe(
    raw: dict,
    is_custom: bool,
    allow_regex_in_custom: bool,
) -> Probe:
    assertions = tuple(
        _parse_assertion(a, is_custom, allow_regex_in_custom)
        for a in raw["assertions"]
    )
    payload = _make_mapping_proxy(raw["payload"])
    if not isinstance(payload, types.MappingProxyType):
        payload = types.MappingProxyType({})
    raw_headers = raw.get("probe_headers")
    probe_headers = _make_mapping_proxy(raw_headers) if raw_headers else None
    return Probe(
        id=raw["id"],
        transport=raw["transport"],
        method=raw["method"],
        payload=payload,
        assertions=assertions,
        probe_token=raw.get("probe_token"),
        probe_count=raw.get("probe_count", 1),
        probe_headers=probe_headers,
    )


def _parse_threat(
    data: dict,
    provenance: Provenance,
    is_custom: bool,
    allow_regex_in_custom: bool,
) -> ThreatDefinition:
    probes = tuple(
        _parse_probe(p, is_custom, allow_regex_in_custom)
        for p in data["probes"]
    )
    threat = ThreatDefinition(
        schema_version=data["schema_version"],
        id=data["id"],
        category=data["category"],
        severity=Severity(data["severity"]),
        cosai_ref=data["cosai_ref"],
        owasp_ref=data["owasp_ref"],
        cwe=tuple(data["cwe"]),
        probes=probes,
        remediation=data["remediation"],
        references=tuple(data["references"]),
        provenance=provenance,
        mode=data.get("mode", "read-only"),
    )
    _assert_no_mutable_containers(threat, threat.id)
    return threat


def _resolve_safe(path: Path, catalog_root: Path) -> Path:
    """Resolve path and verify it is within catalog_root.

    Raises PathTraversalError for absolute paths, ``..`` escapes, or symlinks
    that escape the catalog directory.
    """
    if path.is_absolute():
        raise PathTraversalError(
            f"Absolute catalog paths are rejected: {path}"
        )
    try:
        resolved = (catalog_root / path).resolve()
        catalog_resolved = catalog_root.resolve()
    except OSError as exc:
        raise PathTraversalError(f"Cannot resolve path {path}: {exc}") from exc

    # strict=False: path may not exist yet (checked by caller)
    # Use is_relative_to (Python 3.9+) instead of startswith — the string
    # comparison fails for paths like /catalog_root_extra/file.json which
    # share a prefix with /catalog_root/ but are outside it.
    if not resolved.is_relative_to(catalog_resolved):
        raise PathTraversalError(
            f"Path {path} resolves outside catalog root {catalog_root}."
        )
    return resolved


class CatalogLoader:
    """Load and validate threat definitions from the catalog directory.

    Parameters
    ----------
    catalog_root:
        Absolute path to the ``catalog/`` directory.
    allow_custom:
        If False (default), files under ``catalog/custom/`` are silently skipped.
    allow_regex_in_custom:
        If True, ``matches_regex`` assertions in custom catalog files are compiled.
        Requires ``allow_custom=True`` to have any effect.
    """

    def __init__(
        self,
        catalog_root: Path,
        allow_custom: bool = False,
        allow_regex_in_custom: bool = False,
        allow_adversarial: bool = False,
    ) -> None:
        self._root = catalog_root.resolve()
        self._allow_custom = allow_custom
        self._allow_regex_in_custom = allow_regex_in_custom
        self._allow_adversarial = allow_adversarial

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load_all(self) -> list[ThreatDefinition]:
        """Load all threat definitions: official/ (always) + adversarial/ and custom/ (if allowed)."""
        threats: list[ThreatDefinition] = []

        official_dir = self._root / "official"
        if official_dir.is_dir():
            for json_file in sorted(official_dir.glob("*.json")):
                threats.append(self._load_official(json_file))

        if self._allow_adversarial:
            adv_dir = self._root / "official" / "adversarial"
            if adv_dir.is_dir():
                for json_file in sorted(adv_dir.glob("*.json")):
                    resolved = _resolve_safe(json_file.relative_to(self._root), self._root)
                    threats.append(self._load_adversarial(resolved))

        if self._allow_custom:
            custom_dir = self._root / "custom"
            if custom_dir.is_dir():
                for json_file in sorted(custom_dir.glob("*.json")):
                    threats.append(self._load_custom(json_file))

        return threats

    def load_file(self, path: Path) -> ThreatDefinition:
        """Load a single threat definition file.

        Parameters
        ----------
        path:
            Relative path from ``catalog_root``.  Absolute paths are rejected.

        Raises
        ------
        PathTraversalError
            If ``path`` is absolute or resolves outside ``catalog_root``.
        SignatureVerificationError
            If an official file has a missing or invalid signature.
        SchemaValidationError
            If the JSON does not conform to the meta-schema.
        UnsafePatternError
            If a regex pattern is rejected by RE2.
        """
        resolved = _resolve_safe(path, self._root)
        provenance, is_custom = self._classify(resolved)
        if is_custom and not self._allow_custom:
            raise PermissionError(
                f"Custom catalog is disabled. Pass allow_custom=True to CatalogLoader. "
                f"File: {path}"
            )
        if is_custom:
            return self._load_custom(resolved)
        return self._load_official(resolved)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _classify(self, resolved: Path) -> tuple[Provenance, bool]:
        """Return (Provenance, is_custom) for a resolved path."""
        try:
            relative = resolved.relative_to(self._root)
        except ValueError as exc:
            raise PathTraversalError(
                f"{resolved} is outside catalog root {self._root}"
            ) from exc

        parts = relative.parts
        if parts and parts[0] == "official":
            return Provenance.OFFICIAL, False
        if parts and parts[0] == "custom":
            return Provenance.CUSTOM, True
        # Treat unknown subdirectory as custom (no signature expected)
        return Provenance.CUSTOM, True

    def _load_official(self, json_path: Path) -> ThreatDefinition:
        """Load and verify an official catalog file (must have .sig sidecar)."""
        sig_path = json_path.with_suffix(".json.sig")
        if not sig_path.exists():
            raise SignatureVerificationError(
                f"Missing signature sidecar for official catalog file: {json_path}. "
                f"Expected: {sig_path}"
            )

        raw_bytes = json_path.read_bytes()
        sig_bytes = base64.b64decode(sig_path.read_bytes().strip())

        verify_catalog_signature(raw_bytes, sig_bytes)  # raises on failure

        data = json.loads(raw_bytes)
        validate_threat_json(data)
        return _parse_threat(data, Provenance.OFFICIAL, is_custom=False, allow_regex_in_custom=False)

    def _load_adversarial(self, json_path: Path) -> ThreatDefinition:
        """Load an adversarial catalog file with full Ed25519 verification.

        Adversarial files are official files stored under official/adversarial/.
        They require signed .sig sidecars just like any other official file —
        dual opt-in (--adversarial + --i-own-this-target) is not a substitute
        for catalog integrity verification.
        """
        return self._load_official(json_path)

    def _load_custom(self, json_path: Path) -> ThreatDefinition:
        """Load a custom catalog file (no signature required, marked UNTRUSTED)."""
        raw_bytes = json_path.read_bytes()
        data = json.loads(raw_bytes)
        validate_threat_json(data)
        return _parse_threat(
            data,
            Provenance.CUSTOM,
            is_custom=True,
            allow_regex_in_custom=self._allow_regex_in_custom,
        )
