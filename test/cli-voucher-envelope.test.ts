import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { loadVectors } from "@sohopay/signer-vectors";
import { run } from "../src/cli/run.js";
import { withKeyFile } from "./key-home-fixture.js";

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

const keyContent = { private_key_base64url: testKey.seedB64Url, public_jwk: testKey.publicJwk };

/** Runs the CLI with the signing key supplied as a 0600 --key file under a temp key root. */
function runWithKey(args: string[], stdinObj: unknown) {
  return withKeyFile(keyContent, (keyPath) => run([...args, "--key", keyPath], JSON.stringify(stdinObj)));
}

test("voucher sign --envelope fills only the signature and returns the completed header", () => {
  const stdin = prepareResponse(vector.input.voucher);
  const r = runWithKey(["voucher", "sign", "--envelope", "--input", "-", "--output", "json"], stdin);
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
  const stdin = prep;
  const r = runWithKey(["voucher", "sign", "--envelope", "--input", "-", "--output", "json"], stdin);
  assert.equal(r.exitCode, 1);
  assert.equal(JSON.parse(r.stderr).error.code, "MALFORMED_ENVELOPE");
  assert.ok(!r.stderr.includes(testKey.seedB64Url), "stderr must not contain the private seed");
});

test("an input envelope missing paymentPayload.payload is MALFORMED_ENVELOPE (no crash)", () => {
  const prep = prepareResponse(vector.input.voucher) as Record<string, unknown>;
  prep.envelope = { x402Version: 2 }; // no paymentPayload
  const stdin = prep;
  const r = runWithKey(["voucher", "sign", "--envelope", "--input", "-", "--output", "json"], stdin);
  assert.equal(r.exitCode, 1);
  assert.equal(JSON.parse(r.stderr).error.code, "MALFORMED_ENVELOPE");
});

test("a missing header_name is MALFORMED_ENVELOPE (never a guessed header)", () => {
  const prep = prepareResponse(vector.input.voucher) as Record<string, unknown>;
  delete prep.header_name;
  const stdin = prep;
  const r = runWithKey(["voucher", "sign", "--envelope", "--input", "-", "--output", "json"], stdin);
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
  const stdin = prep;
  const r = runWithKey(["voucher", "sign", "--envelope", "--input", "-", "--output", "json"], stdin);
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
  const stdin = prepareResponse(vector.input.voucher);
  const r = runWithKey(["voucher", "sign", "--write-header", "/tmp/h.txt", "--input", "-"], stdin);
  assert.equal(r.exitCode, 2);
  assert.doesNotMatch(r.stderr, /"error"/);
});

test("--write-header writes a curl-ready `<name>: <value>` header line", () => {
  const dir = mkdtempSync(join(tmpdir(), "sohopay-cli-hdr-"));
  const headerPath = join(dir, "header.txt");
  const stdin = prepareResponse(vector.input.voucher);
  const noFlag = runWithKey(["voucher", "sign", "--envelope", "--input", "-", "--output", "json"], stdin);
  const r = runWithKey(["voucher", "sign", "--envelope", "--write-header", headerPath, "--input", "-", "--output", "json"], stdin);
  assert.equal(r.exitCode, 0, r.stderr);
  // Exactly one header line, terminated by \n, so `curl -H @<file>` replays it
  // without the value ever entering a shell argument or the model's context.
  const expected = JSON.parse(noFlag.stdout);
  assert.equal(readFileSync(headerPath, "utf8"), `${expected.header_name}: ${expected.header_value}\n`);
});

/** Every substring of `secret` with length >= `min`, checked against `haystack`. */
function leakedSubstring(secret: string, haystack: string, min = 16): string | undefined {
  for (let i = 0; i + min <= secret.length; i++) {
    const chunk = secret.slice(i, i + min);
    if (haystack.includes(chunk)) return chunk;
  }
  return undefined;
}

for (const output of ["json", "human"] as const) {
  test(`INV-1: --write-header keeps header_value out of stdout and stderr (--output ${output})`, () => {
    const dir = mkdtempSync(join(tmpdir(), "sohopay-cli-hdr-"));
    const headerPath = join(dir, "header.txt");
    const stdin = prepareResponse(vector.input.voucher);
    const baseline = JSON.parse(
      runWithKey(["voucher", "sign", "--envelope", "--input", "-", "--output", "json"], stdin).stdout,
    );
    const r = runWithKey(
      ["voucher", "sign", "--envelope", "--write-header", headerPath, "--input", "-", "--output", output],
      stdin,
    );
    assert.equal(r.exitCode, 0, r.stderr);
    const value: string = baseline.header_value;
    assert.ok(value.length >= 16);
    // The credential reaches the file only.
    assert.ok(readFileSync(headerPath, "utf8").includes(value));
    for (const stream of [r.stdout, r.stderr]) {
      assert.ok(!stream.includes(value), "full header_value leaked");
      assert.equal(leakedSubstring(value, stream), undefined, "header_value substring leaked");
      assert.ok(!stream.includes("header_value"), "header_value key present");
      // The completed envelope and signature are the same credential in decomposed form.
      assert.ok(!stream.includes(baseline.signature), "signature leaked");
    }
    // Non-secret metadata and the file path stay reported.
    assert.ok(r.stdout.includes(headerPath));
    assert.ok(r.stdout.includes(baseline.payment_id));
  });
}

test("INV-1: an unwritable --write-header path leaks no header_value on any stream", () => {
  const stdin = prepareResponse(vector.input.voucher);
  const baseline = JSON.parse(
    runWithKey(["voucher", "sign", "--envelope", "--input", "-", "--output", "json"], stdin).stdout,
  );
  const r = runWithKey(
    ["voucher", "sign", "--envelope", "--write-header", "/no-such-dir-sohopay/h.txt", "--input", "-", "--output", "json"],
    stdin,
  );
  assert.equal(r.exitCode, 1);
  for (const stream of [r.stdout, r.stderr]) {
    assert.equal(leakedSubstring(baseline.header_value, stream), undefined);
  }
});

test("without --write-header the envelope result is unchanged (header_value still on stdout)", () => {
  const stdin = prepareResponse(vector.input.voucher);
  const r = runWithKey(["voucher", "sign", "--envelope", "--input", "-", "--output", "json"], stdin);
  assert.equal(r.exitCode, 0, r.stderr);
  const out = JSON.parse(r.stdout);
  assert.deepEqual(
    Object.keys(out).sort(),
    ["agent_key_jkt", "algorithm", "envelope", "header_name", "header_value", "implementation", "implementation_version", "payment_id", "signature", "signer_protocol"].sort(),
  );
  assert.equal(typeof out.header_value, "string");
  assert.equal(out.header_file, undefined);
});

test("an unwritable --write-header path is MALFORMED_ENVELOPE with no stdout", () => {
  const stdin = prepareResponse(vector.input.voucher);
  const r = runWithKey([
      "voucher",
      "sign",
      "--envelope",
      "--write-header",
      "/no-such-dir-sohopay/header.txt",
      "--input",
      "-",
      "--output",
      "json",
    ], stdin);
  assert.equal(r.exitCode, 1);
  assert.equal(r.stdout, "");
  assert.equal(JSON.parse(r.stderr).error.code, "MALFORMED_ENVELOPE");
});

test("a header_name with CRLF (injection attempt) is MALFORMED_ENVELOPE", () => {
  const prep = prepareResponse(vector.input.voucher) as Record<string, unknown>;
  prep.header_name = "PAYMENT-SIGNATURE\r\nX-Injected: evil";
  const stdin = prep;
  const r = runWithKey(["voucher", "sign", "--envelope", "--input", "-", "--output", "json"], stdin);
  assert.equal(r.exitCode, 1);
  assert.equal(JSON.parse(r.stderr).error.code, "MALFORMED_ENVELOPE");
});

test("--write-header creates the file with mode 0600", () => {
  const dir = mkdtempSync(join(tmpdir(), "sohopay-cli-hdr-"));
  const headerPath = join(dir, "header.txt");
  const stdin = prepareResponse(vector.input.voucher);
  const r = runWithKey(["voucher", "sign", "--envelope", "--write-header", headerPath, "--input", "-", "--output", "json"], stdin);
  assert.equal(r.exitCode, 0, r.stderr);
  // Low 9 permission bits must be owner-only read/write (0o600).
  assert.equal(statSync(headerPath).mode & 0o777, 0o600);
});
