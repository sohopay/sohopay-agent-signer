# SP2 Amendment A — `voucher sign --envelope` + normative header serialization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the entire `PAYMENT-SIGNATURE` header deterministic and vector-pinned by moving envelope-fill + header construction into the `sohopay-signer` CLI (`voucher sign --envelope`) and pinning the serialization in the shared conformance vectors.

**Architecture:** Two repos. In **sohopay-agent-signer** (`@sohopay/agent-signer`) add a new mode on the existing `voucher sign` command that takes the full `prepare_x402_payment` response, signs the voucher with the existing fail-closed guards, fills **only** `paymentPayload.payload.signature` via the SDK's existing `buildPaymentSignatureHeader`, and returns the completed `envelope` + `header_name` + `header_value`. In **sohopay-backend** (`@sohopay/signer-vectors`) extend the `envelope` vector category with the normative `headerValue` and cut a minor version. The CLI's `verify-vectors` then asserts `header_value` too. The new published vectors version is required before the CLI's `verify-vectors` assertion can go green, so publishing is an explicit human-gated step between the two repos.

**Tech Stack:** TypeScript (ESM NodeNext, strict + `noUncheckedIndexedAccess`); `node:test` + `tsx` (signer repo); Jest + `ts-node` (backend vectors generator); `@noble/curves`, `@noble/hashes`, `canonicalize@2.1.0`; GitHub Packages for `@sohopay/signer-vectors`.

**Spec:** `docs/superpowers/specs/2026-10-06-portable-agent-signing-design.md` — section **"Amendment A — `voucher sign --envelope` + normative header serialization"** (lines 219–312).

## Global Constraints

- Machine I/O is **snake_case**; camelCase appears only at the SDK call boundary. Output object key order matches the existing `voucher sign` result, with `envelope`, `header_name`, `header_value` appended.
- `header_value` = **standard base64 WITH `=` padding** (`Buffer.from(json,"utf8").toString("base64")`), explicitly **NOT** base64url. base64url is only the inner Ed25519 voucher signature.
- The **completed envelope** is the input `envelope` with **exactly one** field set — `paymentPayload.payload.signature` — nothing else added, removed, or re-ordered. It is serialized with **compact** `JSON.stringify` (no inserted whitespace), UTF-8.
- `header_name` is **passed through from the prepare response unchanged** (`input.header_name`).
- Operational failures → exit 1 with `{"error":{"code","message"}}` on stderr (codes from `SignerErrorCode`). Usage errors → exit 2, plain stderr line, no `error` envelope.
- The agent private seed MUST NEVER appear in stderr on any path. `header_value` carries no key material.
- The default `voucher sign` mode (no `--envelope`) and `pop sign` / `payment-id` / `key jkt` / `capabilities` are **unchanged**.
- No key generation or storage is added (SP2 decision 3 stands).
- `@sohopay/signer-vectors` gets a **minor** bump `0.1.0` → `0.2.0`. `canonicalize` stays exact-pinned at `2.1.0`; do not touch it.
- Backend repo rule: never commit to `develop`/`main` directly — Task 1 lands on a `feat/` branch via PR. Publishing the package is a human action (tag `signer-vectors-v0.2.0` or the manual `publish-signer-vectors.yml` dispatch).
- No `console.*` in product code.

## Review Focus

- **Input `envelope` missing `paymentPayload.payload`** (or `paymentPayload`) → must be `MALFORMED_ENVELOPE` (exit 1), never a `TypeError`/crash. Pinned in Task 3, Step 6.
- **`--envelope` on a non-`voucher sign` command, or `--write-header` without `--envelope`** → usage error (exit 2), not a silent no-op. Pinned in Task 3, Step 7.
- **`--write-header` target unwritable** (bad directory / EACCES) → `MALFORMED_ENVELOPE` (exit 1) and **no** stdout emitted (the file is written before stdout). Pinned in Task 3, Step 9.
- **`header_value` byte-identity** between stdout and the `--write-header` file — the file must hold exactly the bytes, **no trailing newline**, so a shell retry pastes an identical header. Pinned in Task 3, Step 8.
- **`header_name` missing or non-string in the input** → `MALFORMED_ENVELOPE`, never a guessed/defaulted header name. Pinned in Task 3, Step 6.

---

### Task 1: Extend the `envelope` vectors with the normative `header_value` + minor version bump (repo: sohopay-backend)

Normatively pin the completed-envelope byte string in the shared conformance vectors so every runtime (CLI, future bundle, Python) is held to one canonical `header_value`.

**Repo:** `sohopay-backend` (branch `feat/signer-vectors-envelope-header-value` off `develop`).

**Files:**
- Modify: `test/signer-vectors/gen-signer-vectors.ts` — `buildEnvelopeVectors` (lines 324–365)
- Modify (regenerated, do not hand-edit): `packages/signer-vectors/vectors/index.json`
- Modify: `packages/signer-vectors/package.json:3` (version)
- Test: `test/signer-vectors/gen-signer-vectors.spec.ts` (existing regen guard — unchanged, used as the gate)

**Interfaces:**
- Consumes: the backend verifier helpers already imported by the generator (`buildAgentPaymentVoucher`, `canonicalizeJcs`, etc.) — no new imports.
- Produces: the published `@sohopay/signer-vectors@0.2.0` whose `vectors.envelope[0].expected` now carries `headerValue: string` (standard base64 of the compact completed-envelope JSON) alongside `headerName` and `decodedEnvelope`. Consumed by Task 4.

- [ ] **Step 1: Replace `buildEnvelopeVectors` so `expected.headerValue` is the normative string**

Replace the body of `buildEnvelopeVectors` (currently lines 324–365) with:

```ts
/** Category: envelope — the normative PAYMENT-SIGNATURE header_value (byte-exact) + decode assertion. */
function buildEnvelopeVectors(
  voucher: VoucherSigResult["voucher"],
  signature: string,
): unknown[] {
  // The input envelope the prepare response carries, with the signature slot empty.
  const prepareResponse = {
    x402Version: 2,
    paymentPayload: { payload: { voucher, signature: null } },
  };
  // The completed envelope: the input with ONLY paymentPayload.payload.signature set.
  // Same key order as prepareResponse, so compact JSON.stringify is the canonical bytes.
  const decodedEnvelope = {
    x402Version: 2,
    paymentPayload: { payload: { voucher, signature } },
  };
  // header_value = standard base64 (WITH '=' padding) of the compact completed-envelope JSON.
  const headerValue = Buffer.from(
    JSON.stringify(decodedEnvelope),
    "utf8",
  ).toString("base64");

  const roundTrip = JSON.parse(
    Buffer.from(headerValue, "base64").toString("utf8"),
  );
  assert(
    JSON.stringify(roundTrip) === JSON.stringify(decodedEnvelope),
    "header_value must base64-decode → JSON-parse → deep-equal the completed envelope",
  );

  return [
    {
      id: "envelope-key-A-basic",
      description:
        "header_value is the normative canonical bytes; also decode → JSON → deep-equal decodedEnvelope",
      input: {
        prepareResponse,
        signature,
      },
      expected: {
        headerName: "PAYMENT-SIGNATURE",
        decodedEnvelope,
        headerValue,
      },
    },
  ];
}
```

This renames the old non-normative `referenceHeaderValueBase64` to the normative `headerValue` and tightens the self-check to deep-equality after decode.

- [ ] **Step 2: Run the regen guard and confirm it now FAILS against the committed file**

Run: `npm run test:signer-vectors`
Expected: FAIL — the committed `packages/signer-vectors/vectors/index.json` still has `referenceHeaderValueBase64` and no `headerValue`, so the fresh-vs-committed diff differs under `vectors.envelope[0].expected`.

- [ ] **Step 3: Regenerate the committed vectors**

Run: `npm run gen:signer-vectors`
Expected: prints `Wrote .../packages/signer-vectors/vectors/index.json`. Confirm with `git diff --stat packages/signer-vectors/vectors/index.json` that only that file changed and the `envelope` category's `expected` now shows `headerValue` (and no `referenceHeaderValueBase64`).

- [ ] **Step 4: Run the regen guard and confirm it PASSES**

Run: `npm run test:signer-vectors`
Expected: PASS (both specs — fresh matches committed, and `canonicalize` is still pinned to `2.1.0`).

- [ ] **Step 5: Bump the package minor version**

Edit `packages/signer-vectors/package.json` line 3: `"version": "0.1.0"` → `"version": "0.2.0"`.

- [ ] **Step 6: Build the package to confirm it still compiles**

Run: `npm run build --workspace=packages/signer-vectors`
Expected: tsc exits 0; `packages/signer-vectors/dist/` is produced.

- [ ] **Step 7: Commit**

```bash
git add test/signer-vectors/gen-signer-vectors.ts packages/signer-vectors/vectors/index.json packages/signer-vectors/package.json
git commit -m "feat(signer-vectors): pin normative header_value in the envelope vectors (0.2.0)"
```

---

### Task 2: Publish `@sohopay/signer-vectors@0.2.0` (HUMAN-GATED — executor stops here)

Publishing to GitHub Packages is an outward-facing release. Per subagent-driven-development, a publish is one of the actions that stops the executor: **do not run the publish**. Open the PR for Task 1, and hand the publish steps to the human partner. Task 4 cannot go green until `0.2.0` is live.

**Files:** none (release action).

- [ ] **Step 1: Push Task 1's branch and open a PR into `develop`**

```bash
git push -u origin feat/signer-vectors-envelope-header-value
gh pr create --base develop --title "[FEAT] signer-vectors: normative header_value (0.2.0)" \
  --body "Adds the normative PAYMENT-SIGNATURE header_value to the envelope conformance vectors and bumps @sohopay/signer-vectors to 0.2.0. Required before the sohopay-agent-signer verify-vectors header_value assertion (SP2 Amendment A)."
```

- [ ] **Step 2: STOP and hand off the publish to the human partner**

State to the human partner that the release is theirs to perform, and give them the exact sequence:
1. Review + merge the PR into `develop`.
2. Publish `0.2.0` by either tagging `git tag signer-vectors-v0.2.0 <merge-commit> && git push origin signer-vectors-v0.2.0`, or running the `Publish @sohopay/signer-vectors` workflow (`workflow_dispatch`, version `0.2.0`) from `develop`/`main`.
3. Confirm `@sohopay/signer-vectors@0.2.0` resolves from GitHub Packages.

Do not proceed to Task 4 until the human partner confirms `0.2.0` is published.

---

### Task 3: Add the `voucher sign --envelope` mode (repo: sohopay-agent-signer)

Expose envelope-fill + header construction through the CLI with all existing signing guards plus the two new guards, and the optional `--write-header`. Independent of the new vectors — its tests build their own prepare response — so it can be implemented before Task 2's publish completes.

**Repo:** `sohopay-agent-signer` (branch `feat/sp2-amendment-a-envelope` off `main`).

**Files:**
- Modify: `src/cli/args.ts` (`ParsedArgs`, `parseArgs`)
- Modify: `src/cli/commands.ts` (add `voucherSignEnvelopeResult`)
- Modify: `src/cli/run.ts` (routing, flag validation, `--write-header`)
- Test: `test/cli-voucher-envelope.test.ts` (new)

**Interfaces:**
- Consumes: `buildPaymentSignatureHeader(prepareResponse: unknown, signature: string): { headerName, headerValue, envelope }` from `../envelope.js`; `signVoucher`, `workloadKeyFromPrivate`, `resolveSigningKey`, `SIGNER_PROTOCOL`, `IMPLEMENTATION`, `SUPPORTED_SIGNING`, `implementationVersion`.
- Produces: `voucherSignEnvelopeResult(input: unknown, keyFileSource: string | undefined, stdin: string): Record<string, unknown>` returning `{ signer_protocol, implementation, implementation_version, payment_id, agent_key_jkt, signature, algorithm, envelope, header_name, header_value }`. `ParsedArgs` gains `envelope: boolean` and `writeHeader?: string`.

- [ ] **Step 1: Extend `ParsedArgs` and `parseArgs` for `--envelope` and `--write-header`**

In `src/cli/args.ts`, change the `ParsedArgs` interface to add the two fields:

```ts
/** Parsed CLI invocation. `input`/`key` are a path or "-" (stdin); undefined = absent. */
export interface ParsedArgs {
  command: string;
  input?: string;
  key?: string;
  output: "json" | "human";
  envelope: boolean;
  writeHeader?: string;
}
```

In `parseArgs`, add the two locals alongside the existing ones:

```ts
  let output: "json" | "human" = "human";
  let envelope = false;
  let writeHeader: string | undefined;
```

Add two branches to the flag `if/else` chain, before the final `else { throw new UsageError(`unknown flag: ${name}`); }`:

```ts
      } else if (name === "--envelope") {
        envelope = true; // boolean flag; any inline value is ignored
      } else if (name === "--write-header") {
        writeHeader = valueOf("--write-header");
      } else {
```

And return them:

```ts
  return { command, input, key, output, envelope, writeHeader };
```

- [ ] **Step 2: Write the failing happy-path test**

Create `test/cli-voucher-envelope.test.ts`:

```ts
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
```

- [ ] **Step 3: Run the happy-path test to verify it fails**

Run: `npm test -- test/cli-voucher-envelope.test.ts` (or `node --import tsx --test test/cli-voucher-envelope.test.ts`)
Expected: FAIL — `--envelope` is not yet routed, so `run` dispatches the default `voucher sign` and the output has no `header_value`.

- [ ] **Step 4: Implement `voucherSignEnvelopeResult` and wire it in `run`**

In `src/cli/commands.ts`, add the import for `buildPaymentSignatureHeader` at the top alongside the other local imports:

```ts
import { buildPaymentSignatureHeader } from "../envelope.js";
```

Add this function after `voucherSignResult`:

```ts
/**
 * `--envelope`: `{ voucher, signing?, envelope, header_name, key? } (+ optional --key)`
 * → signed result plus the completed x402 envelope and PAYMENT-SIGNATURE header.
 * Fills ONLY paymentPayload.payload.signature; never re-signs a filled envelope.
 */
export function voucherSignEnvelopeResult(
  input: unknown,
  keyFileSource: string | undefined,
  stdin: string,
): Record<string, unknown> {
  const record = (input ?? {}) as Record<string, unknown>;

  const voucher = record.voucher as AgentPaymentVoucher | undefined;
  if (voucher === null || typeof voucher !== "object") {
    throw new SignerError("MALFORMED_ENVELOPE", "voucher sign --envelope requires a `voucher` object");
  }

  const prepareEnvelope = record.envelope;
  if (prepareEnvelope === null || typeof prepareEnvelope !== "object") {
    throw new SignerError("MALFORMED_ENVELOPE", "voucher sign --envelope requires an `envelope` object");
  }

  const headerName = record.header_name;
  if (typeof headerName !== "string" || headerName.length === 0) {
    throw new SignerError(
      "MALFORMED_ENVELOPE",
      "voucher sign --envelope requires a non-empty string `header_name`",
    );
  }

  const payload = (prepareEnvelope as {
    paymentPayload?: { payload?: { signature?: unknown; voucher?: { paymentId?: unknown } } };
  }).paymentPayload?.payload;
  if (payload === null || typeof payload !== "object") {
    throw new SignerError(
      "MALFORMED_ENVELOPE",
      "input envelope is missing paymentPayload.payload",
    );
  }

  // Guard: never re-sign an already-filled envelope.
  if (payload.signature !== undefined && payload.signature !== null) {
    throw new SignerError("MALFORMED_ENVELOPE", "input envelope already carries a signature");
  }

  // Guard: the voucher embedded in the envelope must be the voucher we sign (payment_id cross-check).
  const embeddedPaymentId = payload.voucher?.paymentId;
  if (typeof embeddedPaymentId !== "string") {
    throw new SignerError(
      "MALFORMED_ENVELOPE",
      "input envelope is missing paymentPayload.payload.voucher.paymentId",
    );
  }
  if (embeddedPaymentId !== voucher.paymentId) {
    throw new SignerError(
      "PAYMENT_ID_MISMATCH",
      "voucher paymentId does not match the envelope's embedded voucher",
    );
  }

  const key = resolveSigningKey(record, keyFileSource, stdin);
  if (!key.privateKeyBase64Url) {
    throw new SignerError("MALFORMED_ENVELOPE", "signing key is missing private_key_base64url");
  }

  const { signature } = signVoucher({
    voucher,
    privateKeyBase64Url: key.privateKeyBase64Url,
    signing: record.signing as never,
    // Derive the public key from the seed when absent so the jkt-binding guard always runs.
    publicJwk: key.publicJwk ?? workloadKeyFromPrivate(key.privateKeyBase64Url).publicJwk,
  });

  const { headerValue, envelope } = buildPaymentSignatureHeader(prepareEnvelope, signature);

  return {
    signer_protocol: SIGNER_PROTOCOL,
    implementation: IMPLEMENTATION,
    implementation_version: implementationVersion(),
    payment_id: voucher.paymentId,
    agent_key_jkt: voucher.agentKeyJkt,
    signature,
    algorithm: SUPPORTED_SIGNING.algorithm,
    envelope,
    header_name: headerName,
    header_value: headerValue,
  };
}
```

Then in `src/cli/run.ts`, add the `node:fs` import at the top:

```ts
import { writeFileSync } from "node:fs";
```

Add `voucherSignEnvelopeResult` to the existing `./commands.js` import. After the existing stdin check inside `run`'s `try`, add the flag-combo validation:

```ts
    if ((parsed.envelope || parsed.writeHeader !== undefined) && parsed.command !== "voucher sign") {
      throw new UsageError("--envelope and --write-header are only valid for `voucher sign`");
    }
    if (parsed.writeHeader !== undefined && !parsed.envelope) {
      throw new UsageError("--write-header requires --envelope");
    }
```

Replace the `case "voucher sign":` body with:

```ts
      case "voucher sign":
        if (parsed.envelope) {
          result = voucherSignEnvelopeResult(readInput(parsed.input, stdin), parsed.key, stdin);
          if (parsed.writeHeader !== undefined) {
            const headerValue = result.header_value;
            if (typeof headerValue !== "string") {
              throw new SignerError("MALFORMED_ENVELOPE", "internal: header_value missing");
            }
            // Write the exact header bytes (no trailing newline) BEFORE stdout, so a
            // failed write never leaves a mismatched stdout behind.
            try {
              writeFileSync(parsed.writeHeader, headerValue, "utf8");
            } catch {
              throw new SignerError("MALFORMED_ENVELOPE", `cannot write header file: ${parsed.writeHeader}`);
            }
          }
        } else {
          result = voucherSignResult(readInput(parsed.input, stdin), parsed.key, stdin);
        }
        break;
```

- [ ] **Step 5: Run the happy-path test to verify it now passes**

Run: `npm test -- test/cli-voucher-envelope.test.ts`
Expected: PASS for the happy-path case.

- [ ] **Step 6: Add the `MALFORMED_ENVELOPE` guard tests (already-filled, missing payload, missing header_name) and run them**

Append to `test/cli-voucher-envelope.test.ts`:

```ts
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
```

Run: `npm test -- test/cli-voucher-envelope.test.ts`
Expected: PASS for all cases so far.

- [ ] **Step 7: Add the `PAYMENT_ID_MISMATCH` and flag-combo usage-error tests and run them**

Append:

```ts
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
```

Run: `npm test -- test/cli-voucher-envelope.test.ts`
Expected: PASS.

- [ ] **Step 8: Add the `--write-header` byte-identity test and run it**

Append:

```ts
test("--write-header writes exactly the stdout header_value bytes (no newline)", () => {
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
  assert.equal(fileBytes, out.header_value);
  assert.ok(!fileBytes.endsWith("\n"), "header file must not have a trailing newline");
});
```

Run: `npm test -- test/cli-voucher-envelope.test.ts`
Expected: PASS.

- [ ] **Step 9: Add the unwritable `--write-header` test and run it**

Append:

```ts
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
```

Run: `npm test -- test/cli-voucher-envelope.test.ts`
Expected: PASS.

- [ ] **Step 10: Run the full check (default mode must be untouched)**

Run: `npm run check`
Expected: tsc clean; all suites pass (the pre-existing `cli-voucher.test.ts` default-mode cases still pass unchanged). If `@sohopay/signer-vectors` is not yet installed, run `NODE_AUTH_TOKEN=$(gh auth token) npm install` first (the `0.1.0` dep is fine for this task).

- [ ] **Step 11: Commit**

```bash
git add src/cli/args.ts src/cli/commands.ts src/cli/run.ts test/cli-voucher-envelope.test.ts
git commit -m "feat(cli): add voucher sign --envelope mode with fill/paymentId guards and --write-header"
```

---

### Task 4: `verify-vectors` asserts `header_value` + bump the vectors dependency (repo: sohopay-agent-signer)

Close the loop so a divergent serializer is caught by the in-process self-check. **Depends on Task 2** — the `headerValue` expectation only exists in `@sohopay/signer-vectors@0.2.0`.

**Repo:** `sohopay-agent-signer` (same branch `feat/sp2-amendment-a-envelope`).

**Files:**
- Modify: `package.json` (`@sohopay/signer-vectors` dependency `^0.1.0` → `^0.2.0`)
- Modify: `src/cli/verify-vectors.ts` (envelope loop, lines 94–102)
- Test: `test/cli-verify-vectors.test.ts` (existing — stays green)

**Interfaces:**
- Consumes: `@sohopay/signer-vectors@0.2.0` `vectors.envelope[0].expected.headerValue: string` (produced by Task 1).
- Produces: a `verify-vectors` run that additionally `===`-asserts `header_value`; exit 0 iff every vector (incl. the new one) passes.

- [ ] **Step 1: Bump the dependency and install `0.2.0`**

Edit `package.json`: `"@sohopay/signer-vectors": "^0.1.0"` → `"@sohopay/signer-vectors": "^0.2.0"`.

Run: `NODE_AUTH_TOKEN=$(gh auth token) npm install`
Expected: `node_modules/@sohopay/signer-vectors` resolves to `0.2.0`. Confirm: `node -e "console.log(require('@sohopay/signer-vectors/package.json').version)"` prints `0.2.0`.

- [ ] **Step 2: Add the failing `header_value` assertion to the envelope loop**

In `src/cli/verify-vectors.ts`, replace the `for (const v of doc.vectors.envelope) { ... }` block (lines 94–102) with:

```ts
  for (const v of doc.vectors.envelope) {
    const { headerName, headerValue } = buildPaymentSignatureHeader(v.input.prepareResponse, v.input.signature);
    check(`env-name:${v.id}`, headerName, v.expected.headerName);
    // Normative byte-exact header_value (standard base64 of the compact completed envelope).
    check(`env-value:${v.id}`, headerValue, v.expected.headerValue);
    check(
      `env-decoded:${v.id}`,
      JSON.parse(Buffer.from(headerValue, "base64").toString("utf8")),
      v.expected.decodedEnvelope,
    );
  }
```

- [ ] **Step 3: Run `verify-vectors` and confirm it passes with the new assertion**

Run: `node --import tsx -e "import('./src/cli/run.js').then(m => { const r = m.run(['verify-vectors','--output','json'], ''); console.log(r.stdout, 'exit', r.exitCode); process.exit(r.exitCode); })"`
Expected: exit 0; `failed: 0`; `passed`/`total` one higher than before (the new `env-value` check). If it reports `env-value:...:no-expected`, `0.2.0` was not installed — re-run Step 1.

- [ ] **Step 4: Run the full check**

Run: `npm run check`
Expected: tsc clean; all suites pass including `test/cli-verify-vectors.test.ts`.

- [ ] **Step 5: Commit**

```bash
git add package.json package-lock.json src/cli/verify-vectors.ts
git commit -m "feat(cli): verify-vectors asserts the normative header_value; depend on signer-vectors 0.2.0"
```

---

## Notes for the executor

- **Cross-repo ordering:** Task 1 → Task 2 (human-gated publish) → Task 4. Task 3 is independent of the publish and may be done any time after the plan starts (it runs green against the installed `0.1.0`). The executor runs Tasks 1 and 3, then **stops at Task 2** for the human to publish, then runs Task 4.
- **Two working directories:** Task 1 is in `sohopay-backend`; Tasks 3–4 are in `sohopay-agent-signer`. Confirm the repo before each task.
- **Auth for installs:** the private scoped package needs `NODE_AUTH_TOKEN=$(gh auth token) npm install` locally.
- **Finish:** after Task 4 is green, use superpowers:finishing-a-development-branch for the `sohopay-agent-signer` branch (merge/PR to `main`). The SP5 voucher recipe merge waits on both the published `0.2.0` and this branch.
