# algovoi-rfc9421-signer

RFC 9421 (HTTP Message Signatures) + RFC 9530 (Content-Digest) **signer** — Python and TypeScript, byte-for-byte identical output from the same Ed25519 seed.

Pair with [`algovoi-rfc9421-verifier`](https://github.com/chopmob-cloud/algovoi-rfc9421-verifier) for a complete sign/verify substrate.

## Packages

| Language | Package | Registry |
|----------|---------|----------|
| Python | `algovoi-rfc9421-signer` | PyPI |
| TypeScript / Node.js | `@algovoi/rfc9421-signer` | npm |

## Quick start

### Python

```python
from algovoi_rfc9421_signer import sign_request

result = sign_request(
    method="POST",
    authority="api.algovoi.co.uk",
    path="/compliance/screen",
    body=b'{"agent_id":"bench-agent-001"}',
    private_key=bytes.fromhex("9d61b19d..."),  # 32-byte Ed25519 seed
    keyid="did:web:api.algovoi.co.uk",
)

# Attach to your request:
# Signature-Input: {result.signature_input}
# Signature:       {result.signature}
# Content-Digest:  {result.content_digest}
```

### TypeScript / Node.js

```typescript
import { signRequest } from "@algovoi/rfc9421-signer";

const result = await signRequest({
  method: "POST",
  authority: "api.algovoi.co.uk",
  path: "/compliance/screen",
  body: Buffer.from('{"agent_id":"bench-agent-001"}'),
  privateKey: "9d61b19d...",  // 32-byte hex seed
  keyid: "did:web:api.algovoi.co.uk",
});

// result.signatureInput, result.signature, result.contentDigest
```

## Cross-language parity

Both implementations produce byte-for-byte identical `Signature`, `Signature-Input`, and `Content-Digest` headers from the same Ed25519 seed and covered-component inputs, verified against the RFC 8032 §7.1 test vector 1 keypair.

## Covered components (default)

`@method`, `@authority`, `@path`, `content-digest`, `created`

## License

Apache-2.0 — AlgoVoi
