"""ENT-P0-2 — Sigstore/Fulcio keyless signer identity
(docs/ENTERPRISE_REQUIREMENTS_2026-07-01.md).

"As GRC, I need the signed scorecard to be verifiable against an
*organizational* identity ... not a keypair whose private seed ships in
the repo, so that a conformance claim means 'org X's scanner asserted
this,' not 'anyone who cloned the repo could have.'"

Signing requires a real ambient OIDC identity token that does not exist in
this test environment — sigstore-python's Signer/SigningContext/Verifier
are mocked at the boundary throughout. This proves cosai-mcp's own
integration logic (canonical-bytes construction, fail-closed error
handling, identity-policy construction) is correct; it does not re-verify
sigstore-python's own cryptographic protocol, which is that project's
test suite's responsibility.
"""
from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

import pytest

from cosai_mcp.scorecard.models import CategoryResult, ConformanceLevel, Grade, Scorecard
from cosai_mcp.scorecard.sigstore_signing import (
    SigstoreSigningError,
    SigstoreUnavailableError,
    SigstoreVerificationError,
    sign_scorecard_sigstore,
    verify_scorecard_sigstore,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_scorecard() -> Scorecard:
    return Scorecard(
        scan_id="test-scan-123",
        target_url="http://target.example.com:8000",
        scan_timestamp="2026-07-02T00:00:00Z",
        catalog_hash="abc123",
        tool_version="0.1.0",
        categories=(
            CategoryResult(
                category="T1", grade=Grade.PASS, probe_count=2, finding_count=0,
                critical_count=0, high_count=0, coverage_engine="black_box_prober",
            ),
        ),
        conformance_level=ConformanceLevel.FULL_CONFORMANCE,
        public_key="",
        signature="",
    )


# ---------------------------------------------------------------------------
# Package-not-installed fail-closed behavior
# ---------------------------------------------------------------------------

class TestSigstoreUnavailable:
    def test_sign_raises_clear_error_when_package_missing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setitem(sys.modules, "sigstore", None)
        with pytest.raises(SigstoreUnavailableError, match="cosai-mcp\\[sigstore\\]"):
            sign_scorecard_sigstore(_make_scorecard())

    def test_verify_raises_clear_error_when_package_missing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setitem(sys.modules, "sigstore", None)
        with pytest.raises(SigstoreUnavailableError, match="cosai-mcp\\[sigstore\\]"):
            verify_scorecard_sigstore(
                _make_scorecard(), {}, identity="signer@example.com"
            )


# ---------------------------------------------------------------------------
# Signing — no ambient identity must fail closed, never fall back silently
# ---------------------------------------------------------------------------

class TestSignScorecardSigstore:
    def test_raises_when_no_ambient_identity(self) -> None:
        with patch("sigstore.oidc.detect_credential", return_value=None):
            with pytest.raises(SigstoreSigningError, match="No ambient OIDC identity"):
                sign_scorecard_sigstore(_make_scorecard())

    def test_signs_with_detected_identity_and_returns_bundle_dict(self) -> None:
        fake_bundle = MagicMock()
        fake_bundle.to_json.return_value = '{"mediaType": "fake-bundle", "signed": true}'

        fake_signer = MagicMock()
        fake_signer.sign_artifact.return_value = fake_bundle

        fake_signing_ctx = MagicMock()
        fake_signing_ctx.signer.return_value.__enter__.return_value = fake_signer
        fake_signing_ctx.signer.return_value.__exit__.return_value = False

        with (
            patch("sigstore.oidc.detect_credential", return_value="fake.jwt.token"),
            patch("sigstore.oidc.IdentityToken") as mock_token_cls,
            patch("sigstore.sign.SigningContext.from_trust_config", return_value=fake_signing_ctx),
            patch("sigstore.models.ClientTrustConfig.production"),
        ):
            result = sign_scorecard_sigstore(_make_scorecard())

        assert result == {"mediaType": "fake-bundle", "signed": True}
        mock_token_cls.assert_called_once_with("fake.jwt.token")
        fake_signer.sign_artifact.assert_called_once()
        # the payload signed must be the canonical bytes of the scorecard,
        # not e.g. a re-serialized/different-order JSON blob
        signed_payload = fake_signer.sign_artifact.call_args.args[0]
        assert isinstance(signed_payload, bytes)
        assert b'"scan_id":"test-scan-123"' in signed_payload

    def test_staging_uses_staging_trust_config(self) -> None:
        fake_bundle = MagicMock()
        fake_bundle.to_json.return_value = "{}"
        fake_signer = MagicMock()
        fake_signer.sign_artifact.return_value = fake_bundle
        fake_signing_ctx = MagicMock()
        fake_signing_ctx.signer.return_value.__enter__.return_value = fake_signer
        fake_signing_ctx.signer.return_value.__exit__.return_value = False

        with (
            patch("sigstore.oidc.detect_credential", return_value="fake.jwt.token"),
            patch("sigstore.oidc.IdentityToken"),
            patch("sigstore.sign.SigningContext.from_trust_config", return_value=fake_signing_ctx),
            patch("sigstore.models.ClientTrustConfig.production") as mock_prod,
            patch("sigstore.models.ClientTrustConfig.staging") as mock_staging,
        ):
            sign_scorecard_sigstore(_make_scorecard(), staging=True)

        mock_staging.assert_called_once()
        mock_prod.assert_not_called()


# ---------------------------------------------------------------------------
# Verification — identity policy is the actual security boundary
# ---------------------------------------------------------------------------

class TestVerifyScorecardSigstore:
    def test_malformed_bundle_raises_verification_error(self) -> None:
        with patch("sigstore.models.Bundle.from_json", side_effect=ValueError("bad json")):
            with pytest.raises(SigstoreVerificationError, match="Malformed Sigstore bundle"):
                verify_scorecard_sigstore(
                    _make_scorecard(), {"not": "a real bundle"}, identity="signer@example.com"
                )

    def test_verification_failure_from_library_is_wrapped(self) -> None:
        from sigstore.errors import Error as SigstoreLibraryError

        fake_bundle = MagicMock()
        fake_verifier = MagicMock()
        fake_verifier.verify_artifact.side_effect = SigstoreLibraryError("identity mismatch")

        with (
            patch("sigstore.models.Bundle.from_json", return_value=fake_bundle),
            patch("sigstore.verify.Verifier.production", return_value=fake_verifier),
        ):
            with pytest.raises(SigstoreVerificationError, match="identity mismatch"):
                verify_scorecard_sigstore(
                    _make_scorecard(), {"fake": "bundle"}, identity="attacker@evil.com"
                )

    def test_success_calls_verifier_with_expected_identity_policy(self) -> None:
        fake_bundle = MagicMock()
        fake_verifier = MagicMock()
        fake_verifier.verify_artifact.return_value = None

        with (
            patch("sigstore.models.Bundle.from_json", return_value=fake_bundle),
            patch("sigstore.verify.Verifier.production", return_value=fake_verifier),
            patch("sigstore.verify.policy.Identity") as mock_identity_cls,
        ):
            verify_scorecard_sigstore(
                _make_scorecard(), {"fake": "bundle"},
                identity="ci@github-actions.example", issuer="https://token.actions.githubusercontent.com",
            )

        mock_identity_cls.assert_called_once_with(
            identity="ci@github-actions.example",
            issuer="https://token.actions.githubusercontent.com",
        )
        fake_verifier.verify_artifact.assert_called_once()

    def test_staging_uses_staging_verifier(self) -> None:
        fake_bundle = MagicMock()
        fake_verifier = MagicMock()
        fake_verifier.verify_artifact.return_value = None

        with (
            patch("sigstore.models.Bundle.from_json", return_value=fake_bundle),
            patch("sigstore.verify.Verifier.production") as mock_prod,
            patch("sigstore.verify.Verifier.staging", return_value=fake_verifier) as mock_staging,
        ):
            verify_scorecard_sigstore(
                _make_scorecard(), {"fake": "bundle"}, identity="x", staging=True
            )

        mock_staging.assert_called_once()
        mock_prod.assert_not_called()

    # -------------------------------------------------------------------
    # Adversary-pass EXPLOIT 1 (ENT-P0-2 review): Verifier.production()/
    # .staging() performs its own network TUF trust-root refresh and can
    # raise exceptions outside sigstore.errors.Error (e.g. a connection
    # error). Left unguarded, these escaped as unhandled exceptions
    # instead of the documented "raises SigstoreVerificationError on any
    # failure" contract — a caller catching only SigstoreVerificationError
    # (see cli.py's _verify_sigstore_bundle_or_exit) would see a raw
    # traceback instead of a clean fail-closed verdict.
    # -------------------------------------------------------------------

    def test_verifier_construction_error_maps_to_verification_error(self) -> None:
        with (
            patch("sigstore.models.Bundle.from_json", return_value=MagicMock()),
            patch(
                "sigstore.verify.Verifier.production",
                side_effect=ConnectionError("TUF trust-root refresh failed"),
            ),
        ):
            with pytest.raises(SigstoreVerificationError, match="infrastructure error"):
                verify_scorecard_sigstore(
                    _make_scorecard(), {"fake": "bundle"}, identity="ci@example.com"
                )

    def test_verify_artifact_non_library_error_maps_to_verification_error(self) -> None:
        fake_bundle = MagicMock()
        fake_verifier = MagicMock()
        fake_verifier.verify_artifact.side_effect = TypeError("unexpected bundle shape")

        with (
            patch("sigstore.models.Bundle.from_json", return_value=fake_bundle),
            patch("sigstore.verify.Verifier.production", return_value=fake_verifier),
        ):
            with pytest.raises(SigstoreVerificationError, match="infrastructure error"):
                verify_scorecard_sigstore(
                    _make_scorecard(), {"fake": "bundle"}, identity="ci@example.com"
                )


class TestTrustEnvExceptionDocumented:
    """Supply-chain-pass finding (ENT-P0-2 review): unlike every other HTTP
    client in this codebase, sigstore-python's own Fulcio/Rekor/TUF calls
    honor ambient proxy env vars (trust_env) — an accepted, upstream-owned
    limitation this project cannot fix at this layer. This must stay
    documented in the module docstring; if a future refactor drops the
    note without replacing it with an actual mitigation, this test fails
    so the gap doesn't silently become undocumented."""

    def test_module_docstring_documents_trust_env_exception(self) -> None:
        import cosai_mcp.scorecard.sigstore_signing as mod

        assert mod.__doc__ is not None
        assert "trust_env" in mod.__doc__
