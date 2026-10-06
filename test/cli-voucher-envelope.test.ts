import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { loadVectors } from "@sohopay/signer-vectors";
import { run } from "../src/cli/run.js";

const doc = loadVectors();
const testKey = doc.testKeys[0];
const vector = doc.vectors.voucherSignature[0] as {
  input: { voucher: Record<string, unknown>; signing?: unknown };
  expected: { signature: string };
};

/** The full prepare_x402_payment response the skill writes to a temp file. */
function prepareResponse(voucher: Record<string, unknown>) {
  return {
    voucher,
    signing: vector.input.signing,
    envelope: {
      x402Version: 2,
      paymentPayload: { payload: { voucher, signature: null } },
    },
    header_name: "PAYMENT-SIGNATURE",
  };
}

function key() {
  return { private_key_base64url: testKey.seedB64Url, public_jwk: testKey.publicJwk };
}

test("voucher sign --envelope fills only the signature and returns the completed header", () => {
  const stdin = JSON.stringify({ ...prepareResponse(vector.input.voucher), key: key() });
  const r = run(["voucher", "sign", "--envelope", "--input", "-", "--output", "json"], stdin);
  assert.equal(r.exitCode, 0, r.stderr);
  const out = JSON.parse(r.stdout);

  // Same crypto outputs as the default mode / the vector.
  assert.equal(out.signer_protocol, "sohopay-signer/1");
  assert.equal(out.signature, vector.expected.signature);
  assert.equal(out.payment_id, vector.input.voucher.paymentId);
  assert.equal(out.agent_key_jkt, vector.input.voucher.agentKeyJkt);

  // header_name passed through; header_value decodes to the input envelope with ONLY the signature filled.
  assert.equal(out.header_name, "PAYMENT-SIGNATURE");
  const decoded = JSON.parse(Buffer.from(out.header_value, "base64").toString("utf8"));
  const expectedEnvelope = {
    x402Version: 2,
    paymentPayload: { payload: { voucher: vector.input.voucher, signature: out.signature } },
  };
  assert.deepEqual(decoded, expectedEnvelope);
  // And nulling the signature reproduces the input envelope byte-for-byte.
  const reNulled = JSON.parse(JSON.stringify(decoded));
  reNulled.paymentPayload.payload.signature = null;
  assert.deepEqual(reNulled, prepareResponse(vector.input.voucher).envelope);
  assert.deepEqual(out.envelope, expectedEnvelope);
});

test("an input envelope that already carries a signature is MALFORMED_ENVELOPE", () => {
  const prep = prepareResponse(vector.input.voucher);
  prep.envelope.paymentPayload.payload.signature = "already-here" as never;
  const stdin = JSON.stringify({ ...prep, key: key() });
  const r = run(["voucher", "sign", "--envelope", "--input", "-", "--output", "json"], stdin);
  assert.equal(r.exitCode, 1);
  assert.equal(JSON.parse(r.stderr).error.code, "MALFORMED_ENVELOPE");
  assert.ok(!r.stderr.includes(testKey.seedB64Url), "stderr must not contain the private seed");
});

test("an input envelope missing paymentPayload.payload is MALFORMED_ENVELOPE (no crash)", () => {
  const prep = prepareResponse(vector.input.voucher) as Record<string, unknown>;
  prep.envelope = { x402Version: 2 }; // no paymentPayload
  const stdin = JSON.stringify({ ...prep, key: key() });
  const r = run(["voucher", "sign", "--envelope", "--input", "-", "--output", "json"], stdin);
  assert.equal(r.exitCode, 1);
  assert.equal(JSON.parse(r.stderr).error.code, "MALFORMED_ENVELOPE");
});

test("a missing header_name is MALFORMED_ENVELOPE (never a guessed header)", () => {
  const prep = prepareResponse(vector.input.voucher) as Record<string, unknown>;
  delete prep.header_name;
  const stdin = JSON.stringify({ ...prep, key: key() });
  const r = run(["voucher", "sign", "--envelope", "--input", "-", "--output", "json"], stdin);
  assert.equal(r.exitCode, 1);
  assert.equal(JSON.parse(r.stderr).error.code, "MALFORMED_ENVELOPE");
});

test("the envelope's embedded voucher with a different paymentId is PAYMENT_ID_MISMATCH", () => {
  const prep = prepareResponse(vector.input.voucher) as Record<string, unknown>;
  // Keep the top-level voucher valid; make the embedded one disagree.
  prep.envelope = {
    x402Version: 2,
    paymentPayload: {
      payload: {
        voucher: { ...vector.input.voucher, paymentId: `0x${"00".repeat(32)}` },
        signature: null,
      },
    },
  };
  const stdin = JSON.stringify({ ...prep, key: key() });
  const r = run(["voucher", "sign", "--envelope", "--input", "-", "--output", "json"], stdin);
  assert.equal(r.exitCode, 1);
  assert.equal(JSON.parse(r.stderr).error.code, "PAYMENT_ID_MISMATCH");
  assert.ok(!r.stderr.includes(testKey.seedB64Url), "stderr must not contain the private seed");
});

test("--envelope on a non-voucher-sign command is a usage error (exit 2)", () => {
  const r = run(["capabilities", "--envelope"], "");
  assert.equal(r.exitCode, 2);
  assert.doesNotMatch(r.stderr, /"error"/);
});

test("--write-header without --envelope is a usage error (exit 2)", () => {
  const stdin = JSON.stringify({ ...prepareResponse(vector.input.voucher), key: key() });
  const r = run(["voucher", "sign", "--write-header", "/tmp/h.txt", "--input", "-"], stdin);
  assert.equal(r.exitCode, 2);
  assert.doesNotMatch(r.stderr, /"error"/);
});

test("--write-header writes a curl-ready `<name>: <value>` header line", () => {
  const dir = mkdtempSync(join(tmpdir(), "sohopay-cli-hdr-"));
  const headerPath = join(dir, "header.txt");
  const stdin = JSON.stringify({ ...prepareResponse(vector.input.voucher), key: key() });
  const r = run(
    ["voucher", "sign", "--envelope", "--write-header", headerPath, "--input", "-", "--output", "json"],
    stdin,
  );
  assert.equal(r.exitCode, 0, r.stderr);
  const out = JSON.parse(r.stdout);
  const fileBytes = readFileSync(headerPath, "utf8");
  // Exactly one header line, terminated by \n, so `curl -H @<file>` replays it
  // without the value ever entering a shell argument or the model's context.
  assert.equal(fileBytes, `${out.header_name}: ${out.header_value}\n`);
});

test("an unwritable --write-header path is MALFORMED_ENVELOPE with no stdout", () => {
  const stdin = JSON.stringify({ ...prepareResponse(vector.input.voucher), key: key() });
  const r = run(
    [
      "voucher",
      "sign",
      "--envelope",
      "--write-header",
      "/no-such-dir-sohopay/header.txt",
      "--input",
      "-",
      "--output",
      "json",
    ],
    stdin,
  );
  assert.equal(r.exitCode, 1);
  assert.equal(r.stdout, "");
  assert.equal(JSON.parse(r.stderr).error.code, "MALFORMED_ENVELOPE");
});
