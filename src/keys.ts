import { createHash } from "node:crypto";

import { ed25519 } from "@noble/curves/ed25519";

import { fromBase64Url, toBase64Url } from "./encoding.js";
import { SignerError } from "./errors.js";
import { jcs } from "./jcs.js";

export interface Ed25519PublicJwk {
  kty: "OKP";
  crv: "Ed25519";
  x: string;
}

export interface WorkloadKeypair {
  /** 32-byte Ed25519 seed, base64url. Stays on the client — never transmitted. */
  privateKeyBase64Url: string;
  publicJwk: Ed25519PublicJwk;
  jkt: string;
}

/**
 * Validates that a value is an Ed25519 PUBLIC JWK with no private material.
 * The borrower-key boundary: the SDK only handles agent workload keys, and a
 * JWK carrying `d` is rejected outright.
 */
export function assertPublicJwk(value: unknown): Ed25519PublicJwk {
  if (value === null || typeof value !== "object") {
    throw new SignerError("INVALID_PUBLIC_JWK", "public JWK must be an object");
  }
  const jwk = value as Record<string, unknown>;
  if ("d" in jwk) {
    throw new SignerError(
      "PRIVATE_KEY_MATERIAL_REJECTED",
      "JWK must not contain private key material (d)",
    );
  }
  if (
    jwk.kty !== "OKP" ||
    jwk.crv !== "Ed25519" ||
    typeof jwk.x !== "string" ||
    jwk.x.length === 0
  ) {
    throw new SignerError(
      "INVALID_PUBLIC_JWK",
      "expected an Ed25519 OKP public JWK with a non-empty x",
    );
  }
  return { kty: "OKP", crv: "Ed25519", x: jwk.x };
}

/** RFC 7638 thumbprint: base64url(SHA-256(JCS({ crv, kty, x }))). */
export function computeJkt(publicJwk: Ed25519PublicJwk): string {
  const validated = assertPublicJwk(publicJwk);
  const canonical = jcs({ crv: validated.crv, kty: validated.kty, x: validated.x });
  return createHash("sha256").update(canonical, "utf8").digest("base64url");
}

function keypairFromSeed(seed: Uint8Array): WorkloadKeypair {
  const publicKey = ed25519.getPublicKey(seed);
  const publicJwk: Ed25519PublicJwk = {
    kty: "OKP",
    crv: "Ed25519",
    x: toBase64Url(publicKey),
  };
  return {
    privateKeyBase64Url: toBase64Url(seed),
    publicJwk,
    jkt: computeJkt(publicJwk),
  };
}

/** Generates a fresh agent workload keypair. The private seed is never logged or sent. */
export function generateWorkloadKey(): WorkloadKeypair {
  return keypairFromSeed(ed25519.utils.randomPrivateKey());
}

/** Rehydrates the public half + jkt from a persisted private seed. */
export function workloadKeyFromPrivate(privateKeyBase64Url: string): WorkloadKeypair {
  return keypairFromSeed(fromBase64Url(privateKeyBase64Url));
}
