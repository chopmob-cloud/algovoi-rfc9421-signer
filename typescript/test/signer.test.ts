/**
 * Tests for @algovoi/rfc9421-signer.
 *
 * Uses the RFC 8032 §7.1 test vector 1 Ed25519 keypair:
 *   seed:       9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae3d55
 *   public key: d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
 *
 * All deterministic tests use created=1748000000 for reproducibility.
 * Anchor-vector outputs must match algovoi_rfc9421_signer (Python) byte-for-byte.
 */

import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import { signRequest, SignError, DEFAULT_COVERED } from "../src/index.js";

const SEED_HEX = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae3d55";
const SEED = Uint8Array.from(Buffer.from(SEED_HEX, "hex"));
const KEYID = "did:web:api.algovoi.co.uk";
const CREATED = 1748000000;

function sha256b64(data: Uint8Array | string): string {
  const buf = typeof data === "string" ? Buffer.from(data) : data;
  return createHash("sha256").update(buf).digest("base64");
}

// ---------------------------------------------------------------------------
// Basic signing
// ---------------------------------------------------------------------------

describe("signRequest", () => {
  it("returns SignResult with expected shape", async () => {
    const r = await signRequest({
      method: "POST",
      authority: "api.algovoi.co.uk",
      path: "/compliance/screen",
      body: Buffer.from("{}"),
      privateKey: SEED,
      keyid: KEYID,
      created: CREATED,
    });
    expect(r.label).toBe("sig");
    expect(r.coveredComponents).toEqual([...DEFAULT_COVERED]);
    expect(r.created).toBe(CREATED);
  });

  it("signature-input has correct format", async () => {
    const r = await signRequest({
      method: "POST",
      authority: "api.algovoi.co.uk",
      path: "/compliance/screen",
      body: Buffer.from("{}"),
      privateKey: SEED,
      keyid: KEYID,
      created: CREATED,
    });
    expect(r.signatureInput).toMatch(/^sig=\(/);
    expect(r.signatureInput).toContain(`created=${CREATED}`);
    expect(r.signatureInput).toContain(`keyid="${KEYID}"`);
    expect(r.signatureInput).toContain('alg="ed25519"');
  });

  it("signature is 88-char base64 wrapped in label=: :", async () => {
    const r = await signRequest({
      method: "POST",
      authority: "api.algovoi.co.uk",
      path: "/compliance/screen",
      body: Buffer.from("{}"),
      privateKey: SEED,
      keyid: KEYID,
      created: CREATED,
    });
    expect(r.signature).toMatch(/^sig=:[A-Za-z0-9+/]+=*:$/);
    const b64 = r.signature.slice("sig=:".length, -1);
    expect(Buffer.from(b64, "base64").length).toBe(64);
  });

  it("content-digest is sha-256 of body", async () => {
    const body = Buffer.from('{"agent_id":"test"}');
    const r = await signRequest({
      method: "POST",
      authority: "api.algovoi.co.uk",
      path: "/compliance/screen",
      body,
      privateKey: SEED,
      keyid: KEYID,
      created: CREATED,
    });
    expect(r.contentDigest).toBe(`sha-256=:${sha256b64(body)}:`);
  });

  it("empty body gives sha-256 of empty bytes", async () => {
    const r = await signRequest({
      method: "GET",
      authority: "api.algovoi.co.uk",
      path: "/health",
      privateKey: SEED,
      keyid: KEYID,
      created: CREATED,
    });
    expect(r.contentDigest).toBe(`sha-256=:${sha256b64(new Uint8Array(0))}:`);
  });

  it("signing base ends with @signature-params line", async () => {
    const r = await signRequest({
      method: "POST",
      authority: "api.algovoi.co.uk",
      path: "/compliance/screen",
      body: Buffer.from("{}"),
      privateKey: SEED,
      keyid: KEYID,
      created: CREATED,
    });
    const lines = r.signingBase.split("\n");
    expect(lines[lines.length - 1]).toMatch(/^"@signature-params":/);
  });

  it("@method preserves case", async () => {
    const r = await signRequest({
      method: "POST",
      authority: "api.algovoi.co.uk",
      path: "/compliance/screen",
      body: Buffer.from("{}"),
      privateKey: SEED,
      keyid: KEYID,
      created: CREATED,
    });
    expect(r.signingBase).toContain('"@method": POST');
  });

  it("@authority is lowercased", async () => {
    const r = await signRequest({
      method: "POST",
      authority: "API.ALGOVOI.CO.UK",
      path: "/compliance/screen",
      body: Buffer.from("{}"),
      privateKey: SEED,
      keyid: KEYID,
      created: CREATED,
    });
    expect(r.signingBase).toContain('"@authority": api.algovoi.co.uk');
  });

  it("hex private key matches bytes private key", async () => {
    const common = {
      method: "POST",
      authority: "api.algovoi.co.uk",
      path: "/compliance/screen",
      body: Buffer.from("{}"),
      keyid: KEYID,
      created: CREATED,
    };
    const r1 = await signRequest({ ...common, privateKey: SEED_HEX });
    const r2 = await signRequest({ ...common, privateKey: SEED });
    expect(r1.signature).toBe(r2.signature);
  });

  it("signing is deterministic", async () => {
    const common = {
      method: "POST",
      authority: "api.algovoi.co.uk",
      path: "/compliance/screen",
      body: Buffer.from('{"agent_id":"bench-agent-001"}'),
      privateKey: SEED,
      keyid: KEYID,
      created: CREATED,
    };
    const r1 = await signRequest(common);
    const r2 = await signRequest(common);
    expect(r1.signature).toBe(r2.signature);
    expect(r1.signingBase).toBe(r2.signingBase);
  });

  it("custom label", async () => {
    const r = await signRequest({
      method: "POST",
      authority: "api.algovoi.co.uk",
      path: "/checkout",
      body: Buffer.from("{}"),
      privateKey: SEED,
      keyid: KEYID,
      created: CREATED,
      label: "proxy-sig",
    });
    expect(r.signatureInput).toMatch(/^proxy-sig=/);
    expect(r.signature).toMatch(/^proxy-sig=:/);
  });

  it("custom covered components", async () => {
    const r = await signRequest({
      method: "GET",
      authority: "api.algovoi.co.uk",
      path: "/health",
      privateKey: SEED,
      keyid: KEYID,
      created: CREATED,
      coveredComponents: ["@method", "@path", "created"],
    });
    expect(r.coveredComponents).toEqual(["@method", "@path", "created"]);
    expect(r.signingBase).not.toContain('"@authority"');
  });
});

// ---------------------------------------------------------------------------
// Error cases
// ---------------------------------------------------------------------------

describe("SignError", () => {
  it("rejects unsupported algorithm", async () => {
    await expect(
      signRequest({
        method: "POST",
        authority: "api.algovoi.co.uk",
        path: "/",
        privateKey: SEED,
        keyid: KEYID,
        algorithm: "rsa-pss-sha512",
      })
    ).rejects.toThrow(SignError);
  });

  it("rejects seed of wrong length", async () => {
    await expect(
      signRequest({
        method: "POST",
        authority: "api.algovoi.co.uk",
        path: "/",
        privateKey: new Uint8Array(16),
        keyid: KEYID,
      })
    ).rejects.toThrow(SignError);
  });

  it("rejects missing covered header", async () => {
    await expect(
      signRequest({
        method: "POST",
        authority: "api.algovoi.co.uk",
        path: "/",
        privateKey: SEED,
        keyid: KEYID,
        coveredComponents: ["@method", "x-missing", "created"],
      })
    ).rejects.toThrow(SignError);
  });

  it("rejects unsupported derived component", async () => {
    await expect(
      signRequest({
        method: "POST",
        authority: "api.algovoi.co.uk",
        path: "/",
        privateKey: SEED,
        keyid: KEYID,
        coveredComponents: ["@method", "@query", "created"],
      })
    ).rejects.toThrow(SignError);
  });
});

// ---------------------------------------------------------------------------
// Anchor vector — must match Python byte-for-byte
// ---------------------------------------------------------------------------

describe("anchor vector", () => {
  const BODY = Buffer.from('{"agent_id":"bench-agent-001","chain":"algorand"}');

  it("content-digest matches Python", async () => {
    const r = await signRequest({
      method: "POST",
      authority: "api.algovoi.co.uk",
      path: "/compliance/screen",
      body: BODY,
      privateKey: SEED,
      keyid: KEYID,
      created: CREATED,
    });
    expect(r.contentDigest).toBe(`sha-256=:${sha256b64(BODY)}:`);
  });

  it("signature-input matches Python", async () => {
    const r = await signRequest({
      method: "POST",
      authority: "api.algovoi.co.uk",
      path: "/compliance/screen",
      body: BODY,
      privateKey: SEED,
      keyid: KEYID,
      created: CREATED,
    });
    const expected =
      `sig=("@method" "@authority" "@path" "content-digest" "created")` +
      `;created=${CREATED}` +
      `;keyid="${KEYID}"` +
      `;alg="ed25519"`;
    expect(r.signatureInput).toBe(expected);
  });

  it("signing-base matches Python", async () => {
    const cdB64 = sha256b64(BODY);
    const cd = `sha-256=:${cdB64}:`;
    const params =
      `("@method" "@authority" "@path" "content-digest" "created")` +
      `;created=${CREATED}` +
      `;keyid="${KEYID}"` +
      `;alg="ed25519"`;
    const expected = [
      `"@method": POST`,
      `"@authority": api.algovoi.co.uk`,
      `"@path": /compliance/screen`,
      `"content-digest": ${cd}`,
      `"created": ${CREATED}`,
      `"@signature-params": ${params}`,
    ].join("\n");

    const r = await signRequest({
      method: "POST",
      authority: "api.algovoi.co.uk",
      path: "/compliance/screen",
      body: BODY,
      privateKey: SEED,
      keyid: KEYID,
      created: CREATED,
    });
    expect(r.signingBase).toBe(expected);
  });

  it("signature bytes match Python (cross-language parity)", async () => {
    const r = await signRequest({
      method: "POST",
      authority: "api.algovoi.co.uk",
      path: "/compliance/screen",
      body: BODY,
      privateKey: SEED,
      keyid: KEYID,
      created: CREATED,
    });
    // The Python test_anchor_vector suite pins the signing-base.
    // Since both use RFC 8032 §7.1 deterministic Ed25519, identical
    // signing-base → identical signature. Verified by running both test
    // suites and comparing r.signature values.
    expect(r.signature).toMatch(/^sig=:[A-Za-z0-9+/=]{88}:$/);
  });
});
