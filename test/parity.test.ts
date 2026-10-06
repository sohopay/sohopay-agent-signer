import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
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

/**
 * Single-source consumption during dev: the committed vectors live in the
 * backend repo. The publish cutover (last step) swaps this for the
 * `@sohopay/signer-vectors` package. Override with SIGNER_VECTORS_PATH.
 */
const here = dirname(fileURLToPath(import.meta.url));
const VECTORS_PATH =
  process.env.SIGNER_VECTORS_PATH ??
  join(here, "..", "..", "sohopay-backend", "test", "signer-vectors", "vectors", "index.json");

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const doc: any = JSON.parse(readFileSync(VECTORS_PATH, "utf8"));
const testKey = doc.testKeys[0];

test("contract matches SDK constants + exact canonicalize pin", () => {
  assert.equal(doc.contract.voucherDomainTag, VOUCHER_DOMAIN_TAG);
  assert.equal(doc.contract.canonicalize, "2.1.0");
});

test("jkt vectors reproduce", () => {
  for (const v of doc.vectors.jkt) {
    assert.equal(computeJkt(v.input.publicJwk), v.expected.jkt, v.id);
  }
});

test("pop vectors reproduce (message bytes + signature)", () => {
  for (const v of doc.vectors.pop) {
    assert.equal(toHex(buildPopChallengeMessage(v.input.fields)), v.expected.messageUtf8Hex, `${v.id} message`);
    assert.equal(signPoP(v.input.fields, testKey.seedB64Url).pop_signature, v.expected.popSignature, `${v.id} sig`);
  }
});

test("voucher paymentId vectors reproduce", () => {
  for (const v of doc.vectors.voucherPaymentId) {
    assert.equal(computePaymentId(v.input.core), v.expected.paymentId, v.id);
  }
});

test("voucher signature vectors reproduce (preimage + signature)", () => {
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

test("envelope vectors reproduce (decoded deep-equal)", () => {
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

test("negative guard vectors throw their code", () => {
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
        // cross-replay negatives are backend verify-only invariants (proven in
        // the vectors); the SDK is a signer and does not verify, so skip them.
        break;
    }
  }
});
