import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import { VOUCHER_DOMAIN_TAG } from "../src/constants.js";
import { toHex } from "../src/encoding.js";
import { buildPaymentSignatureHeader } from "../src/envelope.js";
import { SignerError } from "../src/errors.js";
import { computeJkt } from "../src/keys.js";
import { buildPopChallengeMessage, signPoP } from "../src/pop.js";
import {
  buildVoucherSignedBytes,
  computePaymentId,
  signVoucher,
  type AgentPaymentVoucher,
} from "../src/voucher.js";

const here = dirname(fileURLToPath(import.meta.url));

/**
 * Resolve the parity vectors from, in order:
 *   1. the published @sohopay/signer-vectors package (once it is a dependency),
 *   2. an explicit SIGNER_VECTORS_PATH,
 *   3. the sibling backend checkout (local dev).
 * Returns undefined when none is available (e.g. CI before the dep is published),
 * in which case the parity tests skip instead of failing to load.
 */
async function loadVectorsDoc(): Promise<unknown | undefined> {
  // Non-literal specifier: don't make tsc resolve an optional, not-yet-added dep.
  const pkg = "@sohopay/signer-vectors";
  try {
    const mod = (await import(pkg)) as { loadVectors?: () => unknown };
    if (typeof mod.loadVectors === "function") {
      return mod.loadVectors();
    }
  } catch {
    // package not installed yet — fall through to a path.
  }
  const explicit = process.env.SIGNER_VECTORS_PATH;
  const sibling = join(
    here,
    "..",
    "..",
    "sohopay-backend",
    "packages",
    "signer-vectors",
    "vectors",
    "index.json",
  );
  const path = explicit ?? (existsSync(sibling) ? sibling : undefined);
  return path ? JSON.parse(readFileSync(path, "utf8")) : undefined;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const doc: any = await loadVectorsDoc();
const skip = doc ? false : "parity vectors unavailable (publish @sohopay/signer-vectors or set SIGNER_VECTORS_PATH)";
const testKey = doc?.testKeys?.[0];

test("contract matches SDK constants + exact canonicalize pin", { skip }, () => {
  assert.equal(doc.contract.voucherDomainTag, VOUCHER_DOMAIN_TAG);
  assert.equal(doc.contract.canonicalize, "2.1.0");
});

test("jkt vectors reproduce", { skip }, () => {
  for (const v of doc.vectors.jkt) {
    assert.equal(computeJkt(v.input.publicJwk), v.expected.jkt, v.id);
  }
});

test("pop vectors reproduce (message bytes + signature)", { skip }, () => {
  for (const v of doc.vectors.pop) {
    assert.equal(toHex(buildPopChallengeMessage(v.input.fields)), v.expected.messageUtf8Hex, `${v.id} message`);
    assert.equal(signPoP(v.input.fields, testKey.seedB64Url).pop_signature, v.expected.popSignature, `${v.id} sig`);
  }
});

test("voucher paymentId vectors reproduce", { skip }, () => {
  for (const v of doc.vectors.voucherPaymentId) {
    assert.equal(computePaymentId(v.input.core), v.expected.paymentId, v.id);
  }
});

test("voucher signature vectors reproduce (preimage + signature)", { skip }, () => {
  for (const v of doc.vectors.voucherSignature) {
    const voucher = v.input.voucher as AgentPaymentVoucher;
    assert.equal(toHex(buildVoucherSignedBytes(voucher)), v.expected.preimageHex, `${v.id} preimage`);
    const { signature } = signVoucher({
      voucher,
      privateKeyBase64Url: testKey.seedB64Url,
      signing: v.input.signing,
      publicJwk: testKey.publicJwk,
    });
    assert.equal(signature, v.expected.signature, `${v.id} sig`);
  }
});

test("envelope vectors reproduce (decoded deep-equal)", { skip }, () => {
  for (const v of doc.vectors.envelope) {
    const { headerName, headerValue } = buildPaymentSignatureHeader(
      v.input.prepareResponse,
      v.input.signature,
    );
    assert.equal(headerName, v.expected.headerName, `${v.id} name`);
    const decoded = JSON.parse(Buffer.from(headerValue, "base64").toString("utf8"));
    assert.deepEqual(decoded, v.expected.decodedEnvelope, `${v.id} decoded`);
  }
});

test("negative guard vectors throw their code", { skip }, () => {
  const code = (e: unknown, expected: string): boolean =>
    e instanceof SignerError && e.code === expected;

  for (const v of doc.negative) {
    switch (v.id) {
      case "neg-voucher-field-number":
        assert.throws(() => computePaymentId(v.input.core), (e) => code(e, v.expectError), v.id);
        break;
      case "neg-pop-iat-float":
        assert.throws(() => buildPopChallengeMessage(v.input.fields), (e) => code(e, v.expectError), v.id);
        break;
      case "neg-downgrade-algorithm": {
        const voucher = doc.vectors.voucherSignature[0].input.voucher as AgentPaymentVoucher;
        assert.throws(
          () => signVoucher({ voucher, privateKeyBase64Url: testKey.seedB64Url, signing: v.input.signing }),
          (e) => code(e, v.expectError),
          v.id,
        );
        break;
      }
      case "neg-public-jwk-has-private-d":
        assert.throws(() => computeJkt(v.input.publicJwk), (e) => code(e, v.expectError), v.id);
        break;
      default:
        // cross-replay negatives are backend verify-only invariants.
        break;
    }
  }
});
