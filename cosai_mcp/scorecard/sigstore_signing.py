"""Sigstore/Fulcio keyless signing and verification for Scorecard artifacts.

ENT-P0-2 (docs/ENTERPRISE_REQUIREMENTS_2026-07-01.md): replaces "a keypair
whose private seed ships in the repo" trust model with signatures bound to
an *organizational OIDC identity*. The scanner never holds a long-lived
signing secret: Fulcio issues a short-lived certificate (~10 minutes) bound
to the CI workflow's OIDC token, sigstore-python signs with a fresh
ephemeral key, and the signature + certificate + a Rekor transparency-log
inclusion proof are bundled together. A verifier checks the bundle against
an EXPECTED identity (e.g. "this GitHub Actions workflow, this repo") —
never "any Sigstore signature," which would authenticate nothing (the same
fail-closed principle the existing Ed25519 trust-anchor check already
applies — see scorecard/signing.py's H-1 contract).

Key rotation: this is a keyless mechanism — there is no long-lived private
key to rotate. Every signing operation generates a fresh ephemeral key and
a fresh short-lived Fulcio certificate. The operational equivalent of "key
rotation" is *trust-policy* rotation: updating which identity/issuer a
verifier accepts, e.g. when a CI workflow moves to a new repository. The
`identity`/`issuer` parameters below are supplied by the verifying caller
at verify time — never baked into the artifact — so a policy change never
requires re-signing historical artifacts.

Requires the optional `sigstore` extra: `pip install cosai-mcp[sigstore]`.
Deliberately NOT a core dependency: sigstore-python pulls in a newer
`cryptography` floor than some sibling CoSAI-ecosystem tools pin (verified
in this repo's own dev environment: installing `sigstore` produced
`mcp-armor 1.1.0 requires cryptography<46,>=41.0, but you have cryptography
48.0.1`) — forcing every cosai-mcp install through that would break the
zero-config local-scan path for users who never touch Sigstore signing.

Environment limitation, documented rather than hidden: signing (not
verification) requires a real ambient OIDC identity token — GitHub Actions
with `permissions: id-token: write`, GitLab CI, or an interactive OIDC
login. No such identity is obtainable in an offline/sandboxed dev
environment, so `sign_scorecard_sigstore` cannot be exercised end-to-end
outside a real CI run. It is tested here by mocking sigstore-python's
Signer/SigningContext at the boundary — proving this module's own
integration logic (canonical-bytes construction, bundle serialization,
fail-closed error handling) is correct. sigstore-python's own cryptographic
protocol correctness is that project's test suite's responsibility, not
re-verified here. The API calls below were confirmed against the real
installed sigstore 4.3.0 package by introspection (inspect.signature),
not assumed from training data.

Known trust_env exception, documented rather than hidden (supply-chain-pass
finding, ENT-P0-2 review): every other outbound HTTP client in this
codebase hard-codes `trust_env=False` (see e.g. transport/streamable_http.py,
ir/containment.py, telemetry/emitter.py) so proxy env vars can never MITM a
scan, per CLAUDE.md's "Network — SSRF Prevention" rule. This module makes
NO httpx calls itself — signing and verification are delegated entirely to
sigstore-python's own `SigningContext`/`Verifier`, which perform their own
network calls to Fulcio, Rekor, and the TUF trust-root repository using
sigstore-python's own HTTP client. That client does NOT disable
`trust_env`, and sigstore-python exposes no override for this. A
`HTTPS_PROXY`/`REQUESTS_CA_BUNDLE` set in the ambient environment (e.g. a
compromised prior CI step) is honored during those calls — unlike every
other network path in this codebase. Accepted as an upstream sigstore-python
limitation, not fixable at this layer; flagged here so a future auditor
does not assume the house `trust_env=False` convention applies to this
module's (indirect) network calls.
"""
from __future__ import annotations

import json
from typing import Any

from cosai_mcp.scorecard.models import Scorecard
from cosai_mcp.scorecard.signing import _canonical_bytes, _signable_dict


class SigstoreUnavailableError(RuntimeError):
    """The optional `sigstore` package is not installed."""


class SigstoreSigningError(RuntimeError):
    """Sigstore signing failed (no ambient OIDC identity, network error, etc.)."""


class SigstoreVerificationError(RuntimeError):
    """Sigstore verification failed — callers must never treat this as a pass."""


def _require_sigstore() -> None:
    try:
        import sigstore  # noqa: F401
    except ImportError as exc:
        raise SigstoreUnavailableError(
            "Sigstore signing/verification requires the optional 'sigstore' "
            "package: pip install cosai-mcp[sigstore]"
        ) from exc


def sign_scorecard_sigstore(scorecard: Scorecard, *, staging: bool = False) -> dict[str, Any]:
    """Sign *scorecard*'s canonical bytes with Sigstore keyless signing.

    Requires an ambient OIDC identity, auto-detected via sigstore-python's
    `detect_credential()`. Raises SigstoreSigningError if none is found —
    this must never silently fall back to an unsigned or weaker artifact;
    that decision belongs to the caller (e.g. "sign with Ed25519 only, but
    say so"), not to this function.

    Returns the Sigstore bundle as a plain JSON-serializable dict — the
    caller writes it as a sidecar file next to the scorecard, the same
    pattern already used for the Ed25519 report signature (.sig.json).

    *staging* selects Sigstore's public staging instance instead of
    production — for testing this integration against real Sigstore
    infrastructure without producing artifacts under the production trust
    root.
    """
    _require_sigstore()
    from sigstore.models import ClientTrustConfig
    from sigstore.oidc import IdentityToken, detect_credential
    from sigstore.sign import SigningContext

    raw_token = detect_credential()
    if raw_token is None:
        raise SigstoreSigningError(
            "No ambient OIDC identity token found. Sigstore signing requires "
            "running in an environment that provides one — e.g. GitHub "
            "Actions with `permissions: id-token: write`, GitLab CI, or an "
            "interactive OIDC login."
        )
    identity_token = IdentityToken(raw_token)

    trust_config = ClientTrustConfig.staging() if staging else ClientTrustConfig.production()
    signing_ctx = SigningContext.from_trust_config(trust_config)

    payload = _canonical_bytes(_signable_dict(scorecard))
    with signing_ctx.signer(identity_token) as signer:
        bundle = signer.sign_artifact(payload)

    result: dict[str, Any] = json.loads(bundle.to_json())
    return result


def verify_scorecard_sigstore(
    scorecard: Scorecard,
    bundle_dict: dict[str, Any],
    *,
    identity: str,
    issuer: str | None = None,
    staging: bool = False,
) -> None:
    """Verify *scorecard* against a Sigstore *bundle_dict*.

    Requires the signer's OIDC identity to match *identity* (and *issuer*,
    if given) — the identity policy IS the security boundary. A bundle
    that merely carries *a* valid Sigstore signature from *some* identity
    proves nothing about who signed it; this mirrors why the existing
    Ed25519 path refuses signature-only verification with no trust anchor.

    Raises SigstoreVerificationError on any failure: a malformed bundle, a
    certificate chain that doesn't lead to Fulcio's root, an invalid Rekor
    inclusion proof, a signature that doesn't match, a signer identity that
    doesn't match what the caller expects, OR an infrastructure failure
    (TUF trust-root refresh over the network, Rekor lookup) while
    constructing the verifier itself. Returns normally (None) only when
    every check passes.

    Adversary-pass EXPLOIT 1 (ENT-P0-2 review): `Verifier.production()` /
    `.staging()` performs its own network TUF trust-root refresh and can
    raise exceptions outside `sigstore.errors.Error` (connection errors,
    TUF metadata errors). Left unguarded, those escaped this function as
    unhandled exceptions — callers (see cli.py's `_verify_sigstore_bundle_
    or_exit`) only catch `SigstoreVerificationError`, so an unhandled
    exception here previously surfaced as a raw traceback instead of a
    clean fail-closed verdict. Every exception from verifier construction
    through `verify_artifact` is now normalized to SigstoreVerificationError.
    """
    _require_sigstore()
    from sigstore.errors import Error as SigstoreLibraryError
    from sigstore.models import Bundle
    from sigstore.verify import Verifier
    from sigstore.verify import policy as sigstore_policy

    try:
        bundle = Bundle.from_json(json.dumps(bundle_dict))
    except Exception as exc:
        raise SigstoreVerificationError(f"Malformed Sigstore bundle: {exc}") from exc

    try:
        verifier = Verifier.staging() if staging else Verifier.production()
        identity_policy = sigstore_policy.Identity(identity=identity, issuer=issuer)
        payload = _canonical_bytes(_signable_dict(scorecard))
        verifier.verify_artifact(payload, bundle, identity_policy)
    except SigstoreLibraryError as exc:
        raise SigstoreVerificationError(f"Sigstore verification failed: {exc}") from exc
    except Exception as exc:
        raise SigstoreVerificationError(
            f"Sigstore verification failed (infrastructure error): {exc}"
        ) from exc
