# Release Handoff — EFF-01 (and EFF-08/09/10)

This file lists the **credentialed / human-only** steps the audit-fix work
deliberately stopped short of. Everything here requires secrets, an org account,
or a key-management decision that must not be made unilaterally by an agent.

Status of what IS done in-repo:
- `pyproject.toml` is PyPI-ready (hatchling build, name `cosai-mcp`, deps, console
  script `cosai = cosai_mcp.cli:cli`). A local `python -m build` produces a wheel.
- Catalog is Ed25519-signed and verifies against the hardcoded public key.

---

## EFF-01 — Publish the package and the scan-action (HUMAN STEPS)

These cannot be done from here (no PyPI/GitHub credentials, must not create the org).

1. **Create the GitHub org + repos** (`github.com/cosai-mcp`):
   - `cosai-mcp/cosai-mcp` — mirror of this repo (or transfer it).
   - `cosai-mcp/scan-action` — holds `action.yml` (composite action wrapping
     `uvx cosai-mcp scan` / the published wheel). Tag it `v1` and record the
     commit SHA so downstream workflows can pin `uses: cosai-mcp/scan-action@<sha>`.

2. **Publish to PyPI** (Trusted Publishing recommended — no long-lived token):
   - Configure PyPI Trusted Publisher for `cosai-mcp` pointing at the release
     workflow in `cosai-mcp/cosai-mcp`.
   - `python -m build && twine check dist/*` locally first.
   - Tag `v0.1.0`; let the release workflow publish. Verify
     `https://pypi.org/pypi/cosai-mcp/json` returns 200.

3. **Release workflow** (add `.github/workflows/release.yml`, tag-triggered):
   - `on: push: tags: ['v*']`, `permissions: id-token: write` (Trusted Publishing),
     `concurrency: { group: release-${{ github.ref }}, cancel-in-progress: false }`
     (do NOT cancel an in-flight publish).
   - Steps: checkout → `python -m build` → `twine check` → `pypa/gh-action-pypi-publish`.

4. **Fix the install/reference docs once published** (they currently advertise paths
   that 404 until the above is done — until then, the from-source path is the only
   working one):
   - `README.md:13,16` — `uvx cosai-mcp` / `pip install cosai-mcp[pytest]`
   - `cosai-gate.yml:49` — `uses: cosai-mcp/scan-action@<sha>` (pin the real SHA)
   - `GETTING_STARTED.md`, `PLATFORM_GUIDE.md:306`, `VALUE_PROP.md:127,270`,
     `VISION.md:88` — same install lines.
   - **Interim honest fix (safe to do now, no publish needed):** prefix each install
     snippet with "from source until the first PyPI release:
     `pip install git+https://github.com/cosai-mcp/cosai-mcp`" so no doc advertises a
     path that 404s.

---

## EFF-10 — Signer identity / key distribution (DESIGN DECISION — do not pick unilaterally)

The catalog/scorecard signing key is currently a committed deterministic dev seed
(`cosai_mcp/signing.py:_DEV_SIGNING_SEED`) with the public key hardcoded in
`cosai_mcp/keys.py`. Production needs a real signer identity and rotation story.
Two viable paths — the project owner must choose:

- **X.509 / managed PKI** — bind the signing key to an org cert; publish a key
  directory; rotation via cert chain. Heavier, enterprise-familiar.
- **Sigstore / Fulcio + PEP 740 attestation** — keyless signing tied to an OIDC
  identity; transparency-log backed. Lighter ops, modern supply-chain standard,
  aligns with the PyPI Trusted Publishing above.

Recommendation to evaluate (not a decision): Sigstore/PEP 740, because it composes
with Trusted Publishing and avoids long-lived key custody. Requires a short ADR
before implementation.

---

## EFF-08 / EFF-09 — Enterprise scale (scoped, not blocked, but larger than this pass)

- **EFF-08 auth plugin** — RFC 8693 token-exchange + DPoP (RFC 9449) + a
  secret-resolver hook so tokens come from a secrets manager, never `/tmp`. New
  `cosai_mcp/identity/` surface; design for a pluggable `TokenProvider`.
- **EFF-09 fleet mode** — `--targets <file>` running N servers with bounded
  concurrency and an aggregated scorecard/SARIF. Mind per-target rate limits
  (mnemo aggressively rate-limits a single scanner; a fleet must back off per host).
