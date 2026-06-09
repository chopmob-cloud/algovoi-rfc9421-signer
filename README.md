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
## Verify your output

Use [`algovoi-rfc9421-verifier`](https://github.com/chopmob-cloud/algovoi-rfc9421-verifier)
to verify locally, or POST to the hosted endpoint at
[`verify.algovoi.co.uk/rfc9421`](https://verify.algovoi.co.uk/rfc9421)
without any installation — pass the three output headers (`Signature-Input`,
`Signature`, `Content-Digest`) and get back a full verification result.


## Covered components (default)

`@method`, `@authority`, `@path`, `content-digest`, `created`

## License

Apache-2.0 — AlgoVoi
## Attribution

This package is Apache-2.0. Use it freely and build whatever you are building on top of it. The only ask is the one the licence already makes: keep the NOTICE, and name who authored the substrate. To attribute it in your own product, add this to your NOTICE file:

```
This product includes the AlgoVoi substrate,
authored by Christopher Hopley / AlgoVoi (chopmob-cloud), Apache-2.0.
https://docs.algovoi.co.uk/canonicalisation-substrate
```

The full invitation is at https://docs.algovoi.co.uk/canonicalisation-substrate#adopt-the-substrate
