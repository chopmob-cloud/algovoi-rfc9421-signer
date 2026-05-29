/**
 * RFC 9421 (HTTP Message Signatures) + RFC 9530 (Content-Digest) signing.
 *
 * Mirror of algovoi_rfc9421_signer (Python). Produces byte-for-byte identical
 * Signature-Input, Signature, and Content-Digest headers from the same Ed25519
 * seed and covered-component inputs.
 *
 * Uses @noble/ed25519 (deterministic Ed25519, RFC 8032 §7.1).
 */

import * as ed25519 from "@noble/ed25519";
import { createHash } from "node:crypto";

// @noble/ed25519 v2 requires SHA-512 to be wired in Node.js environments.
ed25519.etc.sha512Sync = (...msgs: Uint8Array[]) => {
  const hash = createHash("sha512");
  for (const msg of msgs) hash.update(msg);
  return new Uint8Array(hash.digest());
};

export type PrivateKey = Uint8Array | string;
/** Ed25519 seed: 32 raw bytes or 64-char hex (with or without 0x prefix). */

export const DEFAULT_COVERED: readonly string[] = [
  "@method",
  "@authority",
  "@path",
  "content-digest",
  "created",
];

export class SignError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SignError";
  }
}

export interface SignResult {
  /** Value for the Signature-Input header. */
  signatureInput: string;
  /** Value for the Signature header. */
  signature: string;
  /** Value for the Content-Digest header. */
  contentDigest: string;
  /** The signing base as defined by RFC 9421 §2.5 (for debugging). */
  signingBase: string;
  label: string;
  coveredComponents: string[];
  created: number;
}

export interface SignRequestInput {
  method: string;
  authority: string;
  path: string;
  headers?: Record<string, string>;
  body?: Uint8Array | Buffer | string;
  privateKey: PrivateKey;
  keyid: string;
  coveredComponents?: string[];
  created?: number;
  label?: string;
  algorithm?: string;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function seedBytes(privateKey: PrivateKey): Uint8Array {
  if (typeof privateKey === "string") {
    const hex = privateKey.startsWith("0x")
      ? privateKey.slice(2)
      : privateKey;
    if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
      throw new SignError(
        `Ed25519 seed hex must be 64 hex chars (32 bytes), got ${hex.length} chars`
      );
    }
    return Uint8Array.from(Buffer.from(hex, "hex"));
  }
  if (privateKey instanceof Uint8Array || Buffer.isBuffer(privateKey)) {
    if (privateKey.length !== 32) {
      throw new SignError(
        `Ed25519 seed must be 32 bytes, got ${privateKey.length}`
      );
    }
    return privateKey instanceof Uint8Array
      ? privateKey
      : new Uint8Array(privateKey);
  }
  throw new SignError(`privateKey must be Uint8Array or hex string`);
}

function bodyBytes(body: Uint8Array | Buffer | string | undefined): Uint8Array {
  if (body === undefined || (typeof body === "string" && body === "")) {
    return new Uint8Array(0);
  }
  if (typeof body === "string") {
    return new TextEncoder().encode(body);
  }
  return body instanceof Uint8Array ? body : new Uint8Array(body);
}

function contentDigestValue(body: Uint8Array): string {
  const hash = createHash("sha256").update(body).digest("base64");
  return `sha-256=:${hash}:`;
}

function paramsBlock(
  covered: string[],
  created: number,
  keyid: string,
  algorithm: string
): string {
  const inner = covered.map((c) => `"${c}"`).join(" ");
  return `(${inner});created=${created};keyid="${keyid}";alg="${algorithm}"`;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Sign an HTTP request per RFC 9421 + RFC 9530.
 *
 * Returns a {@link SignResult} with the three headers to attach to the request.
 * The calling code MUST include Signature-Input, Signature, and Content-Digest.
 *
 * Byte-for-byte compatible with algovoi_rfc9421_signer (Python) on identical
 * inputs (same seed, same covered-component order, same created timestamp).
 */
export async function signRequest(
  input: SignRequestInput
): Promise<SignResult> {
  const {
    method,
    authority,
    path,
    headers = {},
    privateKey,
    keyid,
    coveredComponents,
    label = "sig",
  } = input;

  const algorithm = (input.algorithm ?? "ed25519").toLowerCase();
  if (algorithm !== "ed25519") {
    throw new SignError(`Only 'ed25519' is supported; got '${algorithm}'`);
  }

  const covered: string[] =
    coveredComponents !== undefined
      ? [...coveredComponents]
      : [...DEFAULT_COVERED];

  const created =
    input.created !== undefined ? input.created : Math.floor(Date.now() / 1000);

  const seed = seedBytes(privateKey);
  const rawBody = bodyBytes(input.body);
  const normHeaders: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    normHeaders[k.toLowerCase()] = v;
  }

  // 1. Content-Digest
  const cdValue = contentDigestValue(rawBody);
  normHeaders["content-digest"] = cdValue;

  // 2. Params block (shared)
  const params = paramsBlock(covered, created, keyid, algorithm);

  // 3. Signing base
  const lines: string[] = [];
  for (const comp of covered) {
    const c = comp.toLowerCase();
    if (c === "@method") {
      lines.push(`"@method": ${method}`);
    } else if (c === "@authority") {
      lines.push(`"@authority": ${authority.toLowerCase()}`);
    } else if (c === "@path") {
      lines.push(`"@path": ${path}`);
    } else if (c === "@scheme") {
      lines.push(`"@scheme": https`);
    } else if (c === "content-digest") {
      lines.push(`"content-digest": ${cdValue}`);
    } else if (c === "created") {
      lines.push(`"created": ${created}`);
    } else if (c.startsWith("@")) {
      throw new SignError(`unsupported derived component: ${comp}`);
    } else {
      const val = normHeaders[c];
      if (val === undefined) {
        throw new SignError(
          `covered header '${comp}' not present in supplied headers`
        );
      }
      lines.push(`"${c}": ${val}`);
    }
  }
  lines.push(`"@signature-params": ${params}`);
  const signingBase = lines.join("\n");

  // 4. Ed25519 sign (deterministic)
  const sigBytes = await ed25519.sign(
    new TextEncoder().encode(signingBase),
    seed
  );
  const sigB64 = Buffer.from(sigBytes).toString("base64");

  return {
    signatureInput: `${label}=${params}`,
    signature: `${label}=:${sigB64}:`,
    contentDigest: cdValue,
    signingBase,
    label,
    coveredComponents: covered,
    created,
  };
}
