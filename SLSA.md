# SLSA Provenance — cosai-mcp

## Build Integrity

cosai-mcp releases are built via GitHub Actions and attested using [Sigstore](https://sigstore.dev) per [PEP 740](https://peps.python.org/pep-0740/).

Every PyPI release includes a provenance attestation verifiable with:

```bash
pip download cosai-mcp==<version> --no-deps -d /tmp/cosai
python -m pip_attestations verify /tmp/cosai/cosai_mcp-<version>-*.whl \
  --publisher pypi --source-repository cosai-mcp/cosai-mcp
```

## Catalog Integrity

Official catalog entries (`catalog/official/`) are signed with the project Ed25519 keypair. The public key is hardcoded as a bytes literal in `cosai_mcp/keys.py` and published via Sigstore/PEP 740 attestation — it cannot be silently substituted.

To verify a catalog entry manually:

```bash
cosai audit verify --catalog catalog/official/T01-001.json
```

## Dependency Pinning

All dependencies are pinned in `requirements-lock.txt` (generated from `pyproject.toml` via `pip-compile`). The Docker image uses the pinned lockfile, not floating version ranges.

## Reproducible Builds

The Docker image is built from a pinned base (`python:3.12-slim@sha256:<digest>` in CI) and a locked dependency set. Build logs are retained as GitHub Actions artifacts for 90 days.

## Threat Model

- **PyPI account compromise**: Sigstore attestation binds the release to the GitHub Actions workflow SHA. A compromised PyPI account cannot publish a verifiable attestation for a build that did not run in the project's CI.
- **Dependency confusion**: All first-party packages use scoped names. Dependencies are SCA-scanned on every PR via `pip-audit`.
- **Catalog tampering**: Ed25519 signatures on `catalog/official/` entries; scanner refuses unsigned files. Custom catalog requires explicit `--allow-custom-catalog` flag.
