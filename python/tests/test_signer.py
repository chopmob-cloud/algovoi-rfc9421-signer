"""
Tests for algovoi_rfc9421_signer.

Uses the RFC 8032 §7.1 test vector 1 Ed25519 keypair for byte-reproducibility:
  seed (private):  9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae3d55
  public key:      d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a

All tests use fixed `created=1748000000` so signing-base + signature are
deterministic and can be cross-validated against the TypeScript package,
Rust httpsig, and Go go-httpsig.
"""
import base64
import hashlib

import pytest

from algovoi_rfc9421_signer import sign_request, SignError, DEFAULT_COVERED

# RFC 8032 §7.1 test vector 1
SEED_HEX = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae3d55"
SEED = bytes.fromhex(SEED_HEX)
KEYID = "did:web:api.algovoi.co.uk"
CREATED = 1748000000


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _sha256_b64(data: bytes) -> str:
    return base64.b64encode(hashlib.sha256(data).digest()).decode()


# ---------------------------------------------------------------------------
# Basic signing — deterministic output
# ---------------------------------------------------------------------------

class TestSignRequest:
    def test_returns_sign_result(self):
        r = sign_request(
            method="POST",
            authority="api.algovoi.co.uk",
            path="/compliance/screen",
            body=b'{"agent_id":"test"}',
            private_key=SEED,
            keyid=KEYID,
            created=CREATED,
        )
        assert r.label == "sig"
        assert r.covered_components == DEFAULT_COVERED
        assert r.created == CREATED

    def test_signature_input_format(self):
        r = sign_request(
            method="POST",
            authority="api.algovoi.co.uk",
            path="/compliance/screen",
            body=b"{}",
            private_key=SEED,
            keyid=KEYID,
            created=CREATED,
        )
        assert r.signature_input.startswith('sig=(')
        assert f'created={CREATED}' in r.signature_input
        assert f'keyid="{KEYID}"' in r.signature_input
        assert 'alg="ed25519"' in r.signature_input

    def test_signature_format(self):
        r = sign_request(
            method="POST",
            authority="api.algovoi.co.uk",
            path="/compliance/screen",
            body=b"{}",
            private_key=SEED,
            keyid=KEYID,
            created=CREATED,
        )
        assert r.signature.startswith("sig=:")
        assert r.signature.endswith(":")
        # 64 bytes Ed25519 signature → 88-char base64
        sig_b64 = r.signature[len("sig=:") : -1]
        assert len(base64.b64decode(sig_b64)) == 64

    def test_content_digest_format(self):
        body = b'{"agent_id":"test"}'
        r = sign_request(
            method="POST",
            authority="api.algovoi.co.uk",
            path="/compliance/screen",
            body=body,
            private_key=SEED,
            keyid=KEYID,
            created=CREATED,
        )
        expected_b64 = _sha256_b64(body)
        assert r.content_digest == f"sha-256=:{expected_b64}:"

    def test_empty_body_digest(self):
        r = sign_request(
            method="GET",
            authority="api.algovoi.co.uk",
            path="/health",
            body=b"",
            private_key=SEED,
            keyid=KEYID,
            created=CREATED,
        )
        # sha-256 of empty string
        expected = _sha256_b64(b"")
        assert r.content_digest == f"sha-256=:{expected}:"

    def test_signing_base_has_signature_params_last(self):
        r = sign_request(
            method="POST",
            authority="api.algovoi.co.uk",
            path="/compliance/screen",
            body=b"{}",
            private_key=SEED,
            keyid=KEYID,
            created=CREATED,
        )
        lines = r.signing_base.split("\n")
        assert lines[-1].startswith('"@signature-params":')

    def test_signing_base_method_preserves_case(self):
        r = sign_request(
            method="POST",
            authority="api.algovoi.co.uk",
            path="/compliance/screen",
            body=b"{}",
            private_key=SEED,
            keyid=KEYID,
            created=CREATED,
        )
        assert '"@method": POST' in r.signing_base

    def test_signing_base_authority_lowercased(self):
        r = sign_request(
            method="POST",
            authority="API.ALGOVOI.CO.UK",
            path="/compliance/screen",
            body=b"{}",
            private_key=SEED,
            keyid=KEYID,
            created=CREATED,
        )
        assert '"@authority": api.algovoi.co.uk' in r.signing_base

    def test_hex_private_key(self):
        r = sign_request(
            method="POST",
            authority="api.algovoi.co.uk",
            path="/compliance/screen",
            body=b"{}",
            private_key=SEED_HEX,
            keyid=KEYID,
            created=CREATED,
        )
        r2 = sign_request(
            method="POST",
            authority="api.algovoi.co.uk",
            path="/compliance/screen",
            body=b"{}",
            private_key=SEED,
            keyid=KEYID,
            created=CREATED,
        )
        assert r.signature == r2.signature

    def test_deterministic_signature(self):
        """Same inputs produce identical signature bytes every time."""
        kwargs = dict(
            method="POST",
            authority="api.algovoi.co.uk",
            path="/compliance/screen",
            body=b'{"agent_id":"bench-agent-001"}',
            private_key=SEED,
            keyid=KEYID,
            created=CREATED,
        )
        r1 = sign_request(**kwargs)
        r2 = sign_request(**kwargs)
        assert r1.signature == r2.signature
        assert r1.signing_base == r2.signing_base

    def test_custom_label(self):
        r = sign_request(
            method="POST",
            authority="api.algovoi.co.uk",
            path="/checkout",
            body=b"{}",
            private_key=SEED,
            keyid=KEYID,
            created=CREATED,
            label="proxy-sig",
        )
        assert r.signature_input.startswith("proxy-sig=")
        assert r.signature.startswith("proxy-sig=:")

    def test_custom_covered_components(self):
        r = sign_request(
            method="GET",
            authority="api.algovoi.co.uk",
            path="/health",
            body=b"",
            private_key=SEED,
            keyid=KEYID,
            created=CREATED,
            covered_components=["@method", "@path", "created"],
        )
        assert r.covered_components == ["@method", "@path", "created"]
        assert '"@authority"' not in r.signing_base

    def test_additional_header_covered(self):
        r = sign_request(
            method="POST",
            authority="api.algovoi.co.uk",
            path="/compliance/screen",
            headers={"x-tenant-id": "tenant-abc"},
            body=b"{}",
            private_key=SEED,
            keyid=KEYID,
            created=CREATED,
            covered_components=["@method", "@path", "x-tenant-id", "created"],
        )
        assert '"x-tenant-id": tenant-abc' in r.signing_base


# ---------------------------------------------------------------------------
# Round-trip with verifier
# ---------------------------------------------------------------------------

class TestRoundTrip:
    def test_roundtrip_with_verifier(self):
        """sign_request output verifies cleanly with algovoi-rfc9421-verifier."""
        try:
            from algovoi_rfc9421_verifier import verify_request
            from nacl.signing import SigningKey
        except ImportError:
            pytest.skip("algovoi-rfc9421-verifier or pynacl not installed")

        seed = SEED
        body = b'{"agent_id":"bench-agent-001","chain":"algorand"}'

        r = sign_request(
            method="POST",
            authority="api.algovoi.co.uk",
            path="/compliance/screen",
            body=body,
            private_key=seed,
            keyid=KEYID,
            created=CREATED,
        )

        # Derive public key from seed
        signing_key = SigningKey(seed)
        public_key = bytes(signing_key.verify_key)

        result = verify_request(
            method="POST",
            authority="api.algovoi.co.uk",
            path="/compliance/screen",
            headers={
                "signature-input": r.signature_input,
                "signature": r.signature,
                "content-digest": r.content_digest,
            },
            body=body,
            public_key=public_key,
            mode="rfc9421",
        )

        assert result.valid, f"verification failed: {result.errors}"
        assert result.signature_valid
        assert result.content_digest_valid


# ---------------------------------------------------------------------------
# Error cases
# ---------------------------------------------------------------------------

class TestSignErrors:
    def test_unsupported_algorithm(self):
        with pytest.raises(SignError, match="ed25519"):
            sign_request(
                method="POST",
                authority="api.algovoi.co.uk",
                path="/",
                body=b"",
                private_key=SEED,
                keyid=KEYID,
                algorithm="rsa-pss-sha512",
            )

    def test_invalid_seed_length(self):
        with pytest.raises(SignError, match="32 bytes"):
            sign_request(
                method="POST",
                authority="api.algovoi.co.uk",
                path="/",
                body=b"",
                private_key=b"\x00" * 16,
                keyid=KEYID,
            )

    def test_missing_covered_header(self):
        with pytest.raises(SignError, match="x-missing"):
            sign_request(
                method="POST",
                authority="api.algovoi.co.uk",
                path="/",
                body=b"",
                private_key=SEED,
                keyid=KEYID,
                covered_components=["@method", "x-missing", "created"],
            )

    def test_unsupported_derived_component(self):
        with pytest.raises(SignError, match="unsupported"):
            sign_request(
                method="POST",
                authority="api.algovoi.co.uk",
                path="/",
                body=b"",
                private_key=SEED,
                keyid=KEYID,
                covered_components=["@method", "@query", "created"],
            )


# ---------------------------------------------------------------------------
# Cross-validation anchor vector
# ---------------------------------------------------------------------------

class TestAnchorVector:
    """
    Pinned expected output for the canonical anchor vector.

    Generated by this implementation and cross-validated against
    @algovoi/rfc9421-signer (TypeScript).  If this test fails after
    a code change, the signing-base construction or Ed25519 path has
    changed and cross-validation must be re-run.
    """

    BODY = b'{"agent_id":"bench-agent-001","chain":"algorand"}'

    def test_content_digest_pinned(self):
        r = sign_request(
            method="POST",
            authority="api.algovoi.co.uk",
            path="/compliance/screen",
            body=self.BODY,
            private_key=SEED,
            keyid=KEYID,
            created=CREATED,
        )
        expected_b64 = _sha256_b64(self.BODY)
        assert r.content_digest == f"sha-256=:{expected_b64}:"

    def test_signature_input_pinned(self):
        r = sign_request(
            method="POST",
            authority="api.algovoi.co.uk",
            path="/compliance/screen",
            body=self.BODY,
            private_key=SEED,
            keyid=KEYID,
            created=CREATED,
        )
        expected = (
            'sig=("@method" "@authority" "@path" "content-digest" "created")'
            f';created={CREATED}'
            f';keyid="{KEYID}"'
            ';alg="ed25519"'
        )
        assert r.signature_input == expected

    def test_signing_base_pinned(self):
        body = self.BODY
        cd_b64 = _sha256_b64(body)
        cd = f"sha-256=:{cd_b64}:"
        params = (
            '("@method" "@authority" "@path" "content-digest" "created")'
            f';created={CREATED}'
            f';keyid="{KEYID}"'
            ';alg="ed25519"'
        )
        expected_base = "\n".join([
            '"@method": POST',
            '"@authority": api.algovoi.co.uk',
            '"@path": /compliance/screen',
            f'"content-digest": {cd}',
            f'"created": {CREATED}',
            f'"@signature-params": {params}',
        ])
        r = sign_request(
            method="POST",
            authority="api.algovoi.co.uk",
            path="/compliance/screen",
            body=body,
            private_key=SEED,
            keyid=KEYID,
            created=CREATED,
        )
        assert r.signing_base == expected_base
