"""
RFC 9421 (HTTP Message Signatures) + RFC 9530 (Content-Digest) signing.

Produces the three headers required by the rfc9421-x402-binding-v1 extension:

  Signature-Input: sig=("@method" "@authority" "@path" "content-digest"
                         "created");created=<unix>;keyid="<keyid>";alg="ed25519"
  Signature:       sig=:<base64(64-byte Ed25519 signature)>:
  Content-Digest:  sha-256=:<base64(sha-256(body))>:

Ed25519 only (RFC 8032 §7.1 deterministic — byte-reproducible across
Python, TypeScript, Rust, and Go implementations from the same seed).

Designed for byte-for-byte parity with @algovoi/rfc9421-signer (TypeScript).
"""
from __future__ import annotations

import base64
import hashlib
import time
from dataclasses import dataclass
from typing import Union

PrivateKey = Union[bytes, str]
"""Ed25519 seed: 32 raw bytes or a 64-char hex string (with or without 0x)."""

DEFAULT_COVERED: list[str] = [
    "@method",
    "@authority",
    "@path",
    "content-digest",
    "created",
]
"""Default covered-component set for x402 requests per rfc9421-x402-binding-v1."""


class SignError(ValueError):
    """Raised when signing setup is invalid."""


@dataclass
class SignResult:
    """Output of sign_request().

    Attach all three headers to the outbound request.  The receiver
    uses algovoi-rfc9421-verifier (or any RFC 9421-compliant verifier)
    to validate them.
    """
    signature_input: str
    """Value for the Signature-Input header."""
    signature: str
    """Value for the Signature header."""
    content_digest: str
    """Value for the Content-Digest header."""
    signing_base: str
    """The signing base as defined by RFC 9421 §2.5 (for debugging)."""
    label: str
    covered_components: list[str]
    created: int


def _seed_bytes(private_key: PrivateKey) -> bytes:
    if isinstance(private_key, bytes):
        if len(private_key) != 32:
            raise SignError(
                f"Ed25519 seed must be 32 bytes, got {len(private_key)}"
            )
        return private_key
    if isinstance(private_key, str):
        hex_key = private_key.removeprefix("0x")
        try:
            kb = bytes.fromhex(hex_key)
        except ValueError as e:
            raise SignError(f"private_key hex is invalid: {e}") from e
        if len(kb) != 32:
            raise SignError(
                f"Ed25519 seed hex must decode to 32 bytes, got {len(kb)}"
            )
        return kb
    raise SignError(
        f"private_key must be bytes or hex str, got {type(private_key).__name__}"
    )


def _content_digest_value(body: bytes) -> str:
    """RFC 9530 sha-256 Content-Digest header value."""
    digest = hashlib.sha256(body).digest()
    b64 = base64.b64encode(digest).decode("ascii")
    return f"sha-256=:{b64}:"


def _params_block(
    covered: list[str],
    *,
    created: int,
    keyid: str,
    algorithm: str,
) -> str:
    """Build the Signature-Input Inner List + parameters string.

    This string appears after the label in Signature-Input and is also
    the value of the @signature-params line in the signing base.

    Example output:
        ("@method" "@authority" "@path" "content-digest" "created")
        ;created=1748000000;keyid="did:web:api.algovoi.co.uk";alg="ed25519"
    """
    inner = " ".join(f'"{c}"' for c in covered)
    return (
        f'({inner})'
        f';created={created}'
        f';keyid="{keyid}"'
        f';alg="{algorithm}"'
    )


def sign_request(
    *,
    method: str,
    authority: str,
    path: str,
    headers: dict[str, str] | None = None,
    body: bytes = b"",
    private_key: PrivateKey,
    keyid: str,
    covered_components: list[str] | None = None,
    created: int | None = None,
    label: str = "sig",
    algorithm: str = "ed25519",
) -> SignResult:
    """Sign an HTTP request per RFC 9421 + RFC 9530.

    Returns a SignResult.  The caller MUST attach all three headers
    (Signature-Input, Signature, Content-Digest) to the outbound request.

    Args:
        method:             HTTP method (e.g. "POST").  RFC 9421 §2.2.1
                            preserves case; HTTP convention is uppercase.
        authority:          Authority component (Host), typically lowercase.
        path:               URL path (e.g. "/compliance/screen").
        headers:            Additional request headers.  Any header named in
                            covered_components that is not a @-derived component
                            must be present here.
        body:               Request body bytes.  Used to compute Content-Digest.
        private_key:        Ed25519 seed — 32 bytes or hex string.
        keyid:              Stable key identifier: DID (did:web:…) or HTTPS URL.
        covered_components: Ordered covered-component list.  Defaults to
                            DEFAULT_COVERED.
        created:            Unix timestamp (seconds).  Defaults to now.
        label:              Signature label.  Defaults to "sig".
        algorithm:          Signing algorithm.  Only "ed25519" is supported.

    Raises:
        SignError: on invalid inputs.
        ImportError: if PyNaCl is not installed.
    """
    if algorithm.lower() != "ed25519":
        raise SignError(f"Only 'ed25519' is supported; got {algorithm!r}")

    covered = covered_components if covered_components is not None else list(DEFAULT_COVERED)
    ts = created if created is not None else int(time.time())
    norm_headers = {k.lower(): v for k, v in (headers or {}).items()}
    seed = _seed_bytes(private_key)

    # 1. Compute Content-Digest and inject into header map so it can be
    #    covered if "content-digest" appears in covered_components.
    cd_value = _content_digest_value(body)
    norm_headers["content-digest"] = cd_value

    # 2. Build the params block — shared between Signature-Input value
    #    and the @signature-params line in the signing base.
    params = _params_block(covered, created=ts, keyid=keyid, algorithm=algorithm)

    # 3. Build the signing base per RFC 9421 §2.5 (rfc9421 mode).
    #    One line per covered component, then @signature-params last.
    lines: list[str] = []
    for comp in covered:
        c = comp.lower()
        if c == "@method":
            lines.append(f'"@method": {method}')
        elif c == "@authority":
            lines.append(f'"@authority": {authority.lower()}')
        elif c == "@path":
            lines.append(f'"@path": {path}')
        elif c == "@scheme":
            lines.append('"@scheme": https')
        elif c == "@target-uri":
            raise SignError(
                "@target-uri requires the full URI; pass it via headers as a "
                "pre-built component or use @authority + @path instead."
            )
        elif c == "content-digest":
            lines.append(f'"content-digest": {cd_value}')
        elif c == "created":
            lines.append(f'"created": {ts}')
        elif c == "expires":
            raise SignError(
                "'expires' component requires an 'expires' param; "
                "pass it via covered_components only when you set expires in params."
            )
        elif c.startswith("@"):
            raise SignError(f"unsupported derived component: {comp!r}")
        else:
            val = norm_headers.get(c)
            if val is None:
                raise SignError(
                    f"covered header {comp!r} not present in supplied headers"
                )
            lines.append(f'"{c}": {val}')

    lines.append(f'"@signature-params": {params}')
    signing_base = "\n".join(lines)

    # 4. Ed25519 sign (deterministic per RFC 8032 §7.1).
    try:
        from nacl.signing import SigningKey
    except ImportError as exc:
        raise ImportError(
            "PyNaCl is required for Ed25519 signing: pip install pynacl"
        ) from exc

    signing_key = SigningKey(seed)
    signed = signing_key.sign(signing_base.encode("utf-8"))
    sig_b64 = base64.b64encode(signed.signature).decode("ascii")

    return SignResult(
        signature_input=f"{label}={params}",
        signature=f"{label}=:{sig_b64}:",
        content_digest=cd_value,
        signing_base=signing_base,
        label=label,
        covered_components=covered,
        created=ts,
    )
