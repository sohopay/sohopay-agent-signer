# SP2 — Node CLI Signer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a thin `sohopay-signer` CLI over the existing `@sohopay/agent-signer` SDK that gives skills a stable, language-agnostic execution protocol for V2 voucher/PoP signing.

**Architecture:** The CLI adds no crypto, no network, and no business logic. A pure `run(argv, stdin) → { stdout, stderr, exitCode }` orchestrator parses arguments, reads JSON from stdin or a file, dispatches to a command handler that calls one SDK primitive, and formats the result as a single JSON object (machine mode) or readable lines (human mode). A thin `index.ts` process wrapper is the only impure layer. All command I/O is snake_case; the CLI translates to the SDK's camelCase at the boundary.

**Tech Stack:** TypeScript (ES2022 / NodeNext ESM), `node:test` + `tsx`, Node `node:fs`/`node:child_process` only. No new runtime dependency except promoting `@sohopay/signer-vectors` from devDependency to dependency (needed by `verify-vectors` in the shipped CLI).

**Spec:** `docs/superpowers/specs/2026-10-06-portable-agent-signing-design.md` (SP1 contract + SP2 CLI). Executors read both.

## Global Constraints

Every task's requirements implicitly include this section. Values are copied verbatim from the spec/SDK.

- **Protocol identifier:** `sohopay-signer/1`, stamped into machine output as `signer_protocol` (spec SP1 §Protocol version).
- **Implementation identifier:** `@sohopay/agent-signer`; `implementation_version` is read from `package.json` at runtime (currently `0.1.0`).
- **Algorithm:** `Ed25519` only (`SUPPORTED_SIGNING.algorithm`).
- **Machine interface:** `--input -` reads JSON from **stdin**; `--output json` emits one JSON object to **stdout** and nothing decorative; `stderr` is diagnostics only; **non-zero exit = failure** (spec SP2 §Machine interface).
- **Error envelope (machine):** operational failures emit `{ "error": { "code", "message" } }` to **stderr** with exit `1`. `code` is a `SignerErrorCode` (`src/errors.ts`). Usage errors (unknown command/flag, missing required `--input`, bad `--output`) print a plain human line to stderr with exit `2` — they are not operation failures and get no JSON envelope.
- **Encoding:** JSON canonicalization RFC 8785 via `canonicalize@2.1.0` (pinned, already an SDK dep); `payment_id` is `0x`-prefixed keccak256 hex; signatures / `jkt` are base64url.
- **Key boundary:** the CLI handles agent workload keys only. A key block carrying private material where a public JWK is expected is rejected by the SDK (`PRIVATE_KEY_MATERIAL_REJECTED`). The private seed MUST never appear in stderr diagnostics.
- **Module system:** ESM, `NodeNext`; every relative import carries a `.js` extension. `strict` + `noUncheckedIndexedAccess` are on — index access yields `T | undefined` and must be guarded.
- **No `console.*`:** write through `process.stdout.write` / `process.stderr.write` only (project logging rule + SP2 "nothing decorative" on stdout).
- **Tests:** `node --test` under the existing `npm test` script; no new runner.

## Review Focus

Spec-implied inputs that no happy-path task exercises, most likely to bite a user first. Each has its test added to the owning task.

- **Non-JSON / malformed stdin** → must return `MALFORMED_ENVELOPE` + exit 1, never a raw stack trace. (Task 2)
- **Key supplied both inline and via `--key`** → mutually exclusive per spec; must fail `MALFORMED_ENVELOPE`, not silently pick one. (Task 3)
- **`--key` file is group/world-readable** → SDK refuses with `INSECURE_KEY_PERMISSIONS`; the CLI must surface that code, not crash. (Task 3)
- **Unknown command / missing required `--input`** → usage error, exit 2, plain stderr line, no JSON envelope. (Task 1 unknown command; Task 2 missing input)
- **A signing failure must not echo the private seed to stderr** → assert the seed substring is absent from stderr on an induced failure. (Task 3)

---

## File Structure

New files, all under the SDK repo:

- `src/cli/args.ts` — argument parsing: `parseArgs(argv) → ParsedArgs`; `UsageError`.
- `src/cli/io.ts` — input/key reading + shape coercion: `readInput`, `resolveKeyBlock`.
- `src/cli/commands.ts` — one handler per command, each returning a plain result object; no I/O beyond what `io.ts` provides.
- `src/cli/verify-vectors.ts` — in-process full vector run using `@sohopay/signer-vectors` + SDK primitives.
- `src/cli/run.ts` — `run(argv, stdin) → CliResult` orchestrator (parse → dispatch → format → error mapping). Pure and synchronous.
- `src/cli/index.ts` — shebang + real-process wrapper: read stdin, call `run`, write streams, set exit code.

Modified:

- `src/constants.ts` — add `SIGNER_PROTOCOL`, `IMPLEMENTATION`.
- `src/storage.ts` — export a `loadKeyFile(path)` helper (permission-checked read at an explicit path).
- `package.json` — add `bin`, promote `@sohopay/signer-vectors` to `dependencies`.

New tests:

- `test/cli-capabilities.test.ts`, `test/cli-readonly.test.ts`, `test/cli-voucher.test.ts`, `test/cli-pop.test.ts`, `test/cli-verify-vectors.test.ts`.

---

## Task 1: CLI scaffold + `capabilities`

The whole pipe end-to-end on the simplest command (no input, no key): arg parse → dispatch → format → emit. Establishes `run()`, the process wrapper, and the `bin`.

**Files:**
- Modify: `src/constants.ts`
- Create: `src/cli/args.ts`
- Create: `src/cli/commands.ts`
- Create: `src/cli/run.ts`
- Create: `src/cli/index.ts`
- Modify: `package.json`
- Test: `test/cli-capabilities.test.ts`

**Interfaces:**
- Produces:
  - `SIGNER_PROTOCOL = "sohopay-signer/1"`, `IMPLEMENTATION = "@sohopay/agent-signer"` (constants).
  - `parseArgs(argv: string[]): ParsedArgs` where `ParsedArgs = { command: string; input?: string; key?: string; output: "json" | "human" }`; throws `UsageError`.
  - `class UsageError extends Error`.
  - `capabilitiesResult(): Record<string, unknown>` and `implementationVersion(): string` (commands.ts).
  - `run(argv: string[], stdin: string): CliResult` where `CliResult = { stdout: string; stderr: string; exitCode: number }`.
- Consumes: SDK `SUPPORTED_SIGNING` from `src/constants.ts`.

- [ ] **Step 1: Add protocol constants**

In `src/constants.ts`, append:

```typescript
/** SP1 protocol identifier — advertised by every conformant executable. */
export const SIGNER_PROTOCOL = "sohopay-signer/1";

/** This implementation's package name, stamped into machine output. */
export const IMPLEMENTATION = "@sohopay/agent-signer";
```

- [ ] **Step 2: Write the failing test for `parseArgs` + `capabilities`**

Create `test/cli-capabilities.test.ts`:

```typescript
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { test } from "node:test";

import { parseArgs, UsageError } from "../src/cli/args.js";
import { run } from "../src/cli/run.js";

test("parseArgs reads a two-token command plus flags", () => {
  const p = parseArgs(["voucher", "sign", "--input", "-", "--output", "json"]);
  assert.equal(p.command, "voucher sign");
  assert.equal(p.input, "-");
  assert.equal(p.output, "json");
});

test("parseArgs defaults output to human and recognizes single-token commands", () => {
  const p = parseArgs(["capabilities"]);
  assert.equal(p.command, "capabilities");
  assert.equal(p.output, "human");
});

test("parseArgs throws UsageError on an unknown flag", () => {
  assert.throws(() => parseArgs(["capabilities", "--nope"]), UsageError);
});

test("parseArgs throws UsageError when a flag is missing its value", () => {
  assert.throws(() => parseArgs(["capabilities", "--output"]), UsageError);
});

test("capabilities (json) reports sohopay-signer/1 and the command set", () => {
  const r = run(["capabilities", "--output", "json"], "");
  assert.equal(r.exitCode, 0);
  assert.equal(r.stderr, "");
  const out = JSON.parse(r.stdout);
  assert.equal(out.signer_protocol, "sohopay-signer/1");
  assert.equal(out.implementation, "@sohopay/agent-signer");
  assert.deepEqual(out.algorithms, ["Ed25519"]);
  assert.ok(out.commands.includes("voucher sign"));
  assert.ok(out.commands.includes("verify-vectors"));
  assert.match(out.implementation_version, /^\d+\.\d+\.\d+/);
});

test("an unknown command is a usage error: exit 2, plain stderr, no JSON envelope", () => {
  const r = run(["frobnicate"], "");
  assert.equal(r.exitCode, 2);
  assert.equal(r.stdout, "");
  assert.ok(r.stderr.length > 0);
  assert.doesNotMatch(r.stderr, /"error"/);
});

test("the real bin pipes capabilities over stdio (subprocess smoke)", () => {
  const r = spawnSync("node", ["--import", "tsx", "src/cli/index.ts", "capabilities", "--output", "json"], {
    input: "",
    encoding: "utf8",
    cwd: process.cwd(),
  });
  assert.equal(r.status, 0);
  assert.equal(JSON.parse(r.stdout).signer_protocol, "sohopay-signer/1");
});
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `npm test -- test/cli-capabilities.test.ts` (or `node --import tsx --test test/cli-capabilities.test.ts`)
Expected: FAIL — `src/cli/args.js` / `src/cli/run.js` do not exist.

- [ ] **Step 4: Implement `src/cli/args.ts`**

```typescript
/** Parsed CLI invocation. `input`/`key` are a path or "-" (stdin); undefined = absent. */
export interface ParsedArgs {
  command: string;
  input?: string;
  key?: string;
  output: "json" | "human";
}

/** A caller mistake (unknown command/flag, missing value). Mapped to exit 2. */
export class UsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UsageError";
  }
}

const KNOWN_COMMANDS = new Set([
  "voucher sign",
  "payment-id",
  "key jkt",
  "pop sign",
  "verify-vectors",
  "capabilities",
]);

function requireValue(argv: string[], index: number, flag: string): string {
  const value = argv[index];
  if (value === undefined) {
    throw new UsageError(`${flag} requires a value`);
  }
  return value;
}

/** Splits argv into a known command (1–2 leading tokens) plus flags. */
export function parseArgs(argv: string[]): ParsedArgs {
  const positionals: string[] = [];
  let input: string | undefined;
  let key: string | undefined;
  let output: "json" | "human" = "human";

  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    if (token === "--input") {
      input = requireValue(argv, ++i, "--input");
    } else if (token === "--key") {
      key = requireValue(argv, ++i, "--key");
    } else if (token === "--output") {
      const value = requireValue(argv, ++i, "--output");
      if (value !== "json" && value !== "human") {
        throw new UsageError(`--output must be "json" or "human", got "${value}"`);
      }
      output = value;
    } else if (token !== undefined && token.startsWith("--")) {
      throw new UsageError(`unknown flag: ${token}`);
    } else if (token !== undefined) {
      positionals.push(token);
    }
  }

  const twoToken = positionals.slice(0, 2).join(" ");
  const oneToken = positionals[0] ?? "";
  let command: string;
  if (KNOWN_COMMANDS.has(twoToken)) {
    command = twoToken;
  } else if (KNOWN_COMMANDS.has(oneToken)) {
    command = oneToken;
  } else {
    throw new UsageError(`unknown command: ${positionals.join(" ") || "(none)"}`);
  }

  return { command, input, key, output };
}
```

- [ ] **Step 5: Implement `src/cli/commands.ts` (capabilities only for now)**

```typescript
import { readFileSync } from "node:fs";

import { IMPLEMENTATION, SIGNER_PROTOCOL, SUPPORTED_SIGNING } from "../constants.js";

/** Reads this package's version from package.json, relative to the module. */
export function implementationVersion(): string {
  const pkg = JSON.parse(
    readFileSync(new URL("../../package.json", import.meta.url), "utf8"),
  ) as { version?: string };
  return pkg.version ?? "0.0.0";
}

const COMMANDS = ["voucher sign", "payment-id", "key jkt", "pop sign", "verify-vectors", "capabilities"];

/** Static advertisement SP5 routing probes to confirm a usable signer. */
export function capabilitiesResult(): Record<string, unknown> {
  return {
    signer_protocol: SIGNER_PROTOCOL,
    implementation: IMPLEMENTATION,
    implementation_version: implementationVersion(),
    algorithms: [SUPPORTED_SIGNING.algorithm],
    commands: COMMANDS,
  };
}
```

- [ ] **Step 6: Implement `src/cli/run.ts`**

```typescript
import { parseArgs, UsageError } from "./args.js";
import { capabilitiesResult } from "./commands.js";
import { SignerError } from "../errors.js";

export interface CliResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

/** Renders a result object as human-readable `key: value` lines (never secrets). */
function toHuman(result: Record<string, unknown>): string {
  return (
    Object.entries(result)
      .map(([k, v]) => `${k}: ${typeof v === "string" ? v : JSON.stringify(v)}`)
      .join("\n") + "\n"
  );
}

function format(result: Record<string, unknown>, output: "json" | "human"): string {
  return output === "json" ? JSON.stringify(result) : toHuman(result);
}

/**
 * Pure orchestrator: parse → dispatch → format. Never throws; every failure is
 * mapped to a CliResult. Usage errors exit 2 (plain stderr); SignerError and
 * other operational failures exit 1 with a machine error envelope on stderr.
 */
export function run(argv: string[], _stdin: string): CliResult {
  let output: "json" | "human" = "human";
  try {
    const parsed = parseArgs(argv);
    output = parsed.output;

    let result: Record<string, unknown>;
    switch (parsed.command) {
      case "capabilities":
        result = capabilitiesResult();
        break;
      default:
        // Later tasks add the signing/read commands here.
        throw new UsageError(`command not implemented: ${parsed.command}`);
    }

    return { stdout: format(result, output), stderr: "", exitCode: 0 };
  } catch (error) {
    if (error instanceof UsageError) {
      return { stdout: "", stderr: `${error.message}\n`, exitCode: 2 };
    }
    const code = error instanceof SignerError ? error.code : "MALFORMED_ENVELOPE";
    const message = error instanceof Error ? error.message : String(error);
    return {
      stdout: "",
      stderr: `${JSON.stringify({ error: { code, message } })}\n`,
      exitCode: 1,
    };
  }
}
```

- [ ] **Step 7: Implement `src/cli/index.ts` (process wrapper)**

```typescript
#!/usr/bin/env node
import { readFileSync } from "node:fs";

import { run } from "./run.js";

/** Reads all of stdin synchronously (fd 0). Empty string when nothing is piped. */
function readStdin(): string {
  try {
    return readFileSync(0, "utf8");
  } catch {
    return "";
  }
}

const result = run(process.argv.slice(2), readStdin());
if (result.stdout) {
  process.stdout.write(result.stdout);
}
if (result.stderr) {
  process.stderr.write(result.stderr);
}
process.exitCode = result.exitCode;
```

- [ ] **Step 8: Wire `package.json`**

Add a `bin` entry (TypeScript preserves the `#!` shebang on emit, so `dist/cli/index.js` stays executable as a bin):

```json
{
  "bin": {
    "sohopay-signer": "dist/cli/index.js"
  }
}
```

Move `"@sohopay/signer-vectors": "^0.1.0"` from `devDependencies` to `dependencies` (the CLI's `verify-vectors` ships with it). Run `npm install --package-lock-only` so the lockfile reflects the move, then `npm install` to sync `node_modules`.

- [ ] **Step 9: Run the test to verify it passes**

Run: `npm test -- test/cli-capabilities.test.ts`
Expected: PASS (all cases, including the subprocess smoke).

- [ ] **Step 10: Run the full build + suite**

Run: `npm run check`
Expected: `tsc --noEmit` clean and every test green.

- [ ] **Step 11: Commit**

```bash
git add src/constants.ts src/cli package.json package-lock.json test/cli-capabilities.test.ts
git commit -m "feat(cli): scaffold sohopay-signer CLI with capabilities command"
```

---

## Task 2: Read-only commands — `payment-id` and `key jkt`

Input-reading commands with no private key. Exercises stdin/file input and the malformed-input path.

**Files:**
- Create: `src/cli/io.ts`
- Modify: `src/cli/commands.ts`
- Modify: `src/cli/run.ts`
- Test: `test/cli-readonly.test.ts`

**Interfaces:**
- Produces:
  - `readInput(source: string | undefined, stdin: string): unknown` (io.ts) — `source` is a path, `"-"` for stdin, or `undefined` (→ `UsageError`).
  - `resolveKeyBlock(block: unknown): ResolvedKey` where `ResolvedKey = { privateKeyBase64Url?: string; publicJwk?: Ed25519PublicJwk }` (io.ts).
  - `paymentIdResult(input: unknown): Record<string, unknown>` and `keyJktResult(input: unknown): Record<string, unknown>` (commands.ts).
- Consumes: `computePaymentId`, `AgentPaymentVoucherCore` (`src/voucher.ts`), `computeJkt`, `workloadKeyFromPrivate`, `assertPublicJwk`, `Ed25519PublicJwk` (`src/keys.ts`), `SignerError` (`src/errors.ts`), `UsageError` (`src/cli/args.ts`).

- [ ] **Step 1: Write the failing test**

Create `test/cli-readonly.test.ts`:

```typescript
import assert from "node:assert/strict";
import { test } from "node:test";

import { generateWorkloadKey } from "../src/keys.js";
import { computePaymentId } from "../src/voucher.js";
import { run } from "../src/cli/run.js";

const key = generateWorkloadKey();
const core = {
  agentId: "agent-1",
  merchantId: `0x${"5f".repeat(32)}`,
  asset: `0x${"ab".repeat(20)}`,
  chainId: "8453",
  amount: "1000000",
  feeAmount: "5000",
  orderRef: `0x${"9d".repeat(32)}`,
  nonce: "1",
  deadline: "4102444800",
};

test("payment-id over stdin returns the SDK's keccak paymentId", () => {
  const r = run(["payment-id", "--input", "-", "--output", "json"], JSON.stringify({ core }));
  assert.equal(r.exitCode, 0);
  assert.equal(JSON.parse(r.stdout).payment_id, computePaymentId(core));
});

test("key jkt from a public_jwk reproduces computeJkt", () => {
  const r = run(["key", "jkt", "--input", "-", "--output", "json"], JSON.stringify({ public_jwk: key.publicJwk }));
  assert.equal(r.exitCode, 0);
  assert.equal(JSON.parse(r.stdout).agent_key_jkt, key.jkt);
});

test("key jkt from a private seed derives the same jkt", () => {
  const r = run(
    ["key", "jkt", "--input", "-", "--output", "json"],
    JSON.stringify({ key: { private_key_base64url: key.privateKeyBase64Url } }),
  );
  assert.equal(r.exitCode, 0);
  assert.equal(JSON.parse(r.stdout).agent_key_jkt, key.jkt);
});

test("non-JSON stdin fails MALFORMED_ENVELOPE with exit 1 and no stack trace", () => {
  const r = run(["payment-id", "--input", "-", "--output", "json"], "not json {");
  assert.equal(r.exitCode, 1);
  assert.equal(r.stdout, "");
  assert.equal(JSON.parse(r.stderr).error.code, "MALFORMED_ENVELOPE");
  assert.doesNotMatch(r.stderr, /\bat \//);
});

test("missing --input on an input command is a usage error (exit 2)", () => {
  const r = run(["payment-id", "--output", "json"], "");
  assert.equal(r.exitCode, 2);
  assert.doesNotMatch(r.stderr, /"error"/);
});

test("a voucher field that is a number surfaces VOUCHER_FIELD_NOT_STRING", () => {
  const bad = { ...core, amount: 1000000 };
  const r = run(["payment-id", "--input", "-", "--output", "json"], JSON.stringify({ core: bad }));
  assert.equal(r.exitCode, 1);
  assert.equal(JSON.parse(r.stderr).error.code, "VOUCHER_FIELD_NOT_STRING");
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm test -- test/cli-readonly.test.ts`
Expected: FAIL — `payment-id` / `key jkt` are not dispatched (Task 1 `run` throws "not implemented").

- [ ] **Step 3: Implement `src/cli/io.ts`**

```typescript
import { readFileSync } from "node:fs";

import { UsageError } from "./args.js";
import { SignerError } from "../errors.js";
import { assertPublicJwk, type Ed25519PublicJwk } from "../keys.js";

/** A key block coerced to the SDK's camelCase argument names. */
export interface ResolvedKey {
  privateKeyBase64Url?: string;
  publicJwk?: Ed25519PublicJwk;
}

/** Reads and JSON-parses the --input source. Absence is a usage error (exit 2). */
export function readInput(source: string | undefined, stdin: string): unknown {
  if (source === undefined) {
    throw new UsageError("this command requires --input <file|->");
  }
  let raw: string;
  if (source === "-") {
    raw = stdin;
  } else {
    try {
      raw = readFileSync(source, "utf8");
    } catch {
      throw new SignerError("MALFORMED_ENVELOPE", `cannot read input file: ${source}`);
    }
  }
  try {
    return JSON.parse(raw);
  } catch {
    throw new SignerError("MALFORMED_ENVELOPE", "input is not valid JSON");
  }
}

/**
 * Coerces an on-wire key block ({ private_key_base64url?, public_jwk? }) to the
 * SDK's camelCase names. `public_jwk` is validated by the SDK (rejects `d`).
 */
export function resolveKeyBlock(block: unknown): ResolvedKey {
  if (block === null || typeof block !== "object") {
    throw new SignerError("MALFORMED_ENVELOPE", "key block must be an object");
  }
  const record = block as Record<string, unknown>;
  const resolved: ResolvedKey = {};

  const priv = record.private_key_base64url;
  if (priv !== undefined) {
    if (typeof priv !== "string") {
      throw new SignerError("MALFORMED_ENVELOPE", "private_key_base64url must be a string");
    }
    resolved.privateKeyBase64Url = priv;
  }
  if (record.public_jwk !== undefined) {
    resolved.publicJwk = assertPublicJwk(record.public_jwk);
  }
  return resolved;
}
```

- [ ] **Step 4: Add handlers to `src/cli/commands.ts`**

Add imports and two handlers (extend the existing `../constants.js` import line rather than duplicating):

```typescript
import { resolveKeyBlock } from "./io.js";
import { SignerError } from "../errors.js";
import { computeJkt, workloadKeyFromPrivate } from "../keys.js";
import { computePaymentId, type AgentPaymentVoucherCore } from "../voucher.js";

/** `{ core } → { payment_id }`. */
export function paymentIdResult(input: unknown): Record<string, unknown> {
  const core = (input as { core?: unknown })?.core;
  if (core === null || typeof core !== "object") {
    throw new SignerError("MALFORMED_ENVELOPE", "payment-id requires a `core` object");
  }
  return { payment_id: computePaymentId(core as AgentPaymentVoucherCore) };
}

/** `{ public_jwk } | { key: { public_jwk | private_key_base64url } } → { agent_key_jkt }`. */
export function keyJktResult(input: unknown): Record<string, unknown> {
  const record = (input ?? {}) as Record<string, unknown>;
  const block = record.public_jwk !== undefined ? { public_jwk: record.public_jwk } : record.key;
  const key = resolveKeyBlock(block);
  if (key.publicJwk) {
    return { agent_key_jkt: computeJkt(key.publicJwk) };
  }
  if (key.privateKeyBase64Url) {
    return { agent_key_jkt: workloadKeyFromPrivate(key.privateKeyBase64Url).jkt };
  }
  throw new SignerError("MALFORMED_ENVELOPE", "key jkt requires public_jwk or a key with private/public material");
}
```

- [ ] **Step 5: Dispatch the new commands in `src/cli/run.ts`**

Add the imports and cases; `readInput` is called once per input command:

```typescript
import { readInput } from "./io.js";
import { keyJktResult, paymentIdResult } from "./commands.js";
```

Inside the `switch (parsed.command)`:

```typescript
      case "payment-id":
        result = paymentIdResult(readInput(parsed.input, _stdin));
        break;
      case "key jkt":
        result = keyJktResult(readInput(parsed.input, _stdin));
        break;
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `npm test -- test/cli-readonly.test.ts`
Expected: PASS.

- [ ] **Step 7: Run the full build + suite**

Run: `npm run check`
Expected: clean.

- [ ] **Step 8: Commit**

```bash
git add src/cli/io.ts src/cli/commands.ts src/cli/run.ts test/cli-readonly.test.ts
git commit -m "feat(cli): add payment-id and key jkt read commands"
```

---

## Task 3: `voucher sign`

The core signing command. Key comes from inline `input.key` or `--key <file>` (exactly one). Fail-closed SDK guards surface as machine error codes.

**Files:**
- Modify: `src/cli/io.ts`
- Modify: `src/storage.ts`
- Modify: `src/cli/commands.ts`
- Modify: `src/cli/run.ts`
- Test: `test/cli-voucher.test.ts`

**Interfaces:**
- Produces:
  - `loadKeyFile(path: string): unknown` (storage.ts) — permission-checked read at an explicit path.
  - `readKeyFile(source: string, stdin: string): ResolvedKey` (io.ts) — reads a key JSON file (or `"-"` for stdin) and coerces it.
  - `voucherSignResult(input: unknown, keyFileSource: string | undefined, stdin: string): Record<string, unknown>` (commands.ts).
  - `resolveSigningKey(input: Record<string, unknown>, keyFileSource: string | undefined, stdin: string): ResolvedKey` (commands.ts, reused by Task 4).
- Consumes: `signVoucher`, `AgentPaymentVoucher` (`src/voucher.ts`); `resolveKeyBlock`, `ResolvedKey` (io.ts); `SignerError` (`src/errors.ts`).

- [ ] **Step 1: Write the failing test (parity against vectors + guards + secret-safety)**

Create `test/cli-voucher.test.ts`:

```typescript
import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { loadVectors } from "@sohopay/signer-vectors";
import { generateWorkloadKey } from "../src/keys.js";
import { computePaymentId } from "../src/voucher.js";
import { run } from "../src/cli/run.js";

const doc = loadVectors();
const testKey = doc.testKeys[0];
const vector = doc.vectors.voucherSignature[0] as {
  input: { voucher: Record<string, unknown>; signing?: unknown };
  expected: { signature: string };
};

test("voucher sign (inline key) reproduces the vector signature + payment_id + jkt", () => {
  const stdin = JSON.stringify({
    voucher: vector.input.voucher,
    signing: vector.input.signing,
    key: { private_key_base64url: testKey.seedB64Url, public_jwk: testKey.publicJwk },
  });
  const r = run(["voucher", "sign", "--input", "-", "--output", "json"], stdin);
  assert.equal(r.exitCode, 0, r.stderr);
  const out = JSON.parse(r.stdout);
  assert.equal(out.signer_protocol, "sohopay-signer/1");
  assert.equal(out.algorithm, "Ed25519");
  assert.equal(out.signature, vector.expected.signature);
  assert.equal(out.payment_id, vector.input.voucher.paymentId);
  assert.equal(out.agent_key_jkt, vector.input.voucher.agentKeyJkt);
});

test("voucher sign reads the key from --key file (stdin carries only the voucher)", () => {
  const dir = mkdtempSync(join(tmpdir(), "sohopay-cli-"));
  const keyPath = join(dir, "secret.json");
  writeFileSync(
    keyPath,
    JSON.stringify({ private_key_base64url: testKey.seedB64Url, public_jwk: testKey.publicJwk }),
    { mode: 0o600 },
  );
  chmodSync(keyPath, 0o600);
  const stdin = JSON.stringify({ voucher: vector.input.voucher, signing: vector.input.signing });
  const r = run(["voucher", "sign", "--input", "-", "--key", keyPath, "--output", "json"], stdin);
  assert.equal(r.exitCode, 0, r.stderr);
  assert.equal(JSON.parse(r.stdout).signature, vector.expected.signature);
});

test("key supplied both inline and via --key is MALFORMED_ENVELOPE", () => {
  const stdin = JSON.stringify({
    voucher: vector.input.voucher,
    key: { private_key_base64url: testKey.seedB64Url },
  });
  const r = run(["voucher", "sign", "--input", "-", "--key", "/tmp/whatever.json", "--output", "json"], stdin);
  assert.equal(r.exitCode, 1);
  assert.equal(JSON.parse(r.stderr).error.code, "MALFORMED_ENVELOPE");
});

test("a group/world-readable --key file is refused with INSECURE_KEY_PERMISSIONS", () => {
  const dir = mkdtempSync(join(tmpdir(), "sohopay-cli-"));
  const keyPath = join(dir, "secret.json");
  writeFileSync(keyPath, JSON.stringify({ private_key_base64url: testKey.seedB64Url, public_jwk: testKey.publicJwk }));
  chmodSync(keyPath, 0o644);
  const stdin = JSON.stringify({ voucher: vector.input.voucher });
  const r = run(["voucher", "sign", "--input", "-", "--key", keyPath, "--output", "json"], stdin);
  assert.equal(r.exitCode, 1);
  assert.equal(JSON.parse(r.stderr).error.code, "INSECURE_KEY_PERMISSIONS");
});

test("a tampered paymentId fails PAYMENT_ID_MISMATCH without echoing the seed", () => {
  const tampered = { ...vector.input.voucher, paymentId: `0x${"00".repeat(32)}` };
  const stdin = JSON.stringify({
    voucher: tampered,
    key: { private_key_base64url: testKey.seedB64Url, public_jwk: testKey.publicJwk },
  });
  const r = run(["voucher", "sign", "--input", "-", "--output", "json"], stdin);
  assert.equal(r.exitCode, 1);
  assert.equal(JSON.parse(r.stderr).error.code, "PAYMENT_ID_MISMATCH");
  assert.ok(!r.stderr.includes(testKey.seedB64Url), "stderr must not contain the private seed");
});

test("a jkt that does not match the signing key fails AGENT_KEY_JKT_MISMATCH", () => {
  const otherJkt = generateWorkloadKey().jkt;
  const voucher = { ...vector.input.voucher, agentKeyJkt: otherJkt } as Record<string, unknown>;
  // recompute paymentId so only the jkt guard trips, not PAYMENT_ID_MISMATCH.
  const { paymentId: _p, agentKeyJkt: _j, ...core } = voucher;
  const rebuilt = { ...voucher, paymentId: computePaymentId(core as never) };
  const stdin = JSON.stringify({
    voucher: rebuilt,
    key: { private_key_base64url: testKey.seedB64Url, public_jwk: testKey.publicJwk },
  });
  const r = run(["voucher", "sign", "--input", "-", "--output", "json"], stdin);
  assert.equal(r.exitCode, 1);
  assert.equal(JSON.parse(r.stderr).error.code, "AGENT_KEY_JKT_MISMATCH");
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm test -- test/cli-voucher.test.ts`
Expected: FAIL — `voucher sign` not dispatched.

- [ ] **Step 3: Export `loadKeyFile` from `src/storage.ts`**

`src/storage.ts` already has the private `assertSecurePermissions(path)` helper and imports `readFileSync` + `SignerError`. Add an exported reader for an arbitrary path (the CLI's `--key` is not borrower-scoped):

```typescript
/** Reads and parses a key file at an explicit path, refusing group/world-readable files. */
export function loadKeyFile(path: string): unknown {
  const raw = readFileSync(path, "utf8");
  assertSecurePermissions(path);
  try {
    return JSON.parse(raw);
  } catch {
    throw new SignerError("STORED_KEY_CORRUPT", `${path} is not valid JSON`);
  }
}
```

- [ ] **Step 4: Add `readKeyFile` to `src/cli/io.ts`**

```typescript
import { loadKeyFile } from "../storage.js";

/** Reads a key JSON file (or "-" = stdin) into a ResolvedKey. */
export function readKeyFile(source: string, stdin: string): ResolvedKey {
  if (source === "-") {
    try {
      return resolveKeyBlock(JSON.parse(stdin));
    } catch (error) {
      if (error instanceof SignerError) {
        throw error;
      }
      throw new SignerError("MALFORMED_ENVELOPE", "key file is not valid JSON");
    }
  }
  // Delegates to the SDK's permission-checked read so a loosened file is refused.
  return resolveKeyBlock(loadKeyFile(source));
}
```

- [ ] **Step 5: Add `resolveSigningKey` + `voucherSignResult` to `src/cli/commands.ts`**

```typescript
import { readKeyFile, resolveKeyBlock, type ResolvedKey } from "./io.js";
import { signVoucher, type AgentPaymentVoucher } from "../voucher.js";
// SIGNER_PROTOCOL, IMPLEMENTATION, SUPPORTED_SIGNING already imported from "../constants.js" (Task 1).

/** Resolves the signing key from exactly one source: inline `input.key` or --key. */
export function resolveSigningKey(
  input: Record<string, unknown>,
  keyFileSource: string | undefined,
  stdin: string,
): ResolvedKey {
  const inline = input.key;
  if (inline !== undefined && keyFileSource !== undefined) {
    throw new SignerError("MALFORMED_ENVELOPE", "provide the key inline OR via --key, not both");
  }
  if (keyFileSource !== undefined) {
    return readKeyFile(keyFileSource, stdin);
  }
  if (inline !== undefined) {
    return resolveKeyBlock(inline);
  }
  throw new SignerError("MALFORMED_ENVELOPE", "signing requires a key (inline `key` or --key)");
}

/** `{ voucher, signing?, key? } (+ optional --key) → signed result`. */
export function voucherSignResult(
  input: unknown,
  keyFileSource: string | undefined,
  stdin: string,
): Record<string, unknown> {
  const record = (input ?? {}) as Record<string, unknown>;
  const voucher = record.voucher as AgentPaymentVoucher | undefined;
  if (voucher === null || typeof voucher !== "object") {
    throw new SignerError("MALFORMED_ENVELOPE", "voucher sign requires a `voucher` object");
  }
  const key = resolveSigningKey(record, keyFileSource, stdin);
  if (!key.privateKeyBase64Url) {
    throw new SignerError("MALFORMED_ENVELOPE", "signing key is missing private_key_base64url");
  }

  const { signature } = signVoucher({
    voucher,
    privateKeyBase64Url: key.privateKeyBase64Url,
    signing: record.signing as never,
    publicJwk: key.publicJwk,
  });

  return {
    signer_protocol: SIGNER_PROTOCOL,
    implementation: IMPLEMENTATION,
    implementation_version: implementationVersion(),
    payment_id: voucher.paymentId,
    agent_key_jkt: voucher.agentKeyJkt,
    signature,
    algorithm: SUPPORTED_SIGNING.algorithm,
  };
}
```

- [ ] **Step 6: Guard the stdin double-read and dispatch in `src/cli/run.ts`**

Before the `switch`, reject the impossible double-stdin case:

```typescript
    if (parsed.input === "-" && parsed.key === "-") {
      throw new UsageError("--input and --key cannot both read stdin");
    }
```

Add the dispatch case (import `voucherSignResult`):

```typescript
      case "voucher sign":
        result = voucherSignResult(readInput(parsed.input, _stdin), parsed.key, _stdin);
        break;
```

- [ ] **Step 7: Run the test to verify it passes**

Run: `npm test -- test/cli-voucher.test.ts`
Expected: PASS (all six cases).

- [ ] **Step 8: Run the full build + suite**

Run: `npm run check`
Expected: clean.

- [ ] **Step 9: Commit**

```bash
git add src/cli/io.ts src/cli/commands.ts src/cli/run.ts src/storage.ts test/cli-voucher.test.ts
git commit -m "feat(cli): add voucher sign with inline/file key resolution"
```

---

## Task 4: `pop sign`

Onboarding PoP signatures (spec decision 1: `pop sign` is in SP2). Untagged preimage, `iat` the only numeric field.

**Files:**
- Modify: `src/cli/commands.ts`
- Modify: `src/cli/run.ts`
- Test: `test/cli-pop.test.ts`

**Interfaces:**
- Produces: `popSignResult(input: unknown, keyFileSource: string | undefined, stdin: string): Record<string, unknown>` (commands.ts).
- Consumes: `signPoP`, `PopChallengeFields` (`src/pop.ts`); `resolveSigningKey` (commands.ts, Task 3).

- [ ] **Step 1: Write the failing test**

Create `test/cli-pop.test.ts`:

```typescript
import assert from "node:assert/strict";
import { test } from "node:test";

import { loadVectors } from "@sohopay/signer-vectors";
import { run } from "../src/cli/run.js";

const doc = loadVectors();
const testKey = doc.testKeys[0];
const vector = doc.vectors.pop[0] as {
  input: { fields: Record<string, unknown> };
  expected: { popSignature: string };
};

test("pop sign reproduces the vector pop_signature", () => {
  const stdin = JSON.stringify({
    fields: vector.input.fields,
    key: { private_key_base64url: testKey.seedB64Url },
  });
  const r = run(["pop", "sign", "--input", "-", "--output", "json"], stdin);
  assert.equal(r.exitCode, 0, r.stderr);
  const out = JSON.parse(r.stdout);
  assert.equal(out.signer_protocol, "sohopay-signer/1");
  assert.equal(out.algorithm, "Ed25519");
  assert.equal(out.pop_signature, vector.expected.popSignature);
});

test("a non-integer iat fails POP_IAT_NOT_INTEGER", () => {
  const fields = { ...vector.input.fields, iat: 1.5 };
  const stdin = JSON.stringify({ fields, key: { private_key_base64url: testKey.seedB64Url } });
  const r = run(["pop", "sign", "--input", "-", "--output", "json"], stdin);
  assert.equal(r.exitCode, 1);
  assert.equal(JSON.parse(r.stderr).error.code, "POP_IAT_NOT_INTEGER");
});

test("pop sign with no key is MALFORMED_ENVELOPE", () => {
  const stdin = JSON.stringify({ fields: vector.input.fields });
  const r = run(["pop", "sign", "--input", "-", "--output", "json"], stdin);
  assert.equal(r.exitCode, 1);
  assert.equal(JSON.parse(r.stderr).error.code, "MALFORMED_ENVELOPE");
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm test -- test/cli-pop.test.ts`
Expected: FAIL — `pop sign` not dispatched.

- [ ] **Step 3: Add `popSignResult` to `src/cli/commands.ts`**

```typescript
import { signPoP, type PopChallengeFields } from "../pop.js";

/** `{ fields, key? } (+ optional --key) → { pop_signature }`. */
export function popSignResult(
  input: unknown,
  keyFileSource: string | undefined,
  stdin: string,
): Record<string, unknown> {
  const record = (input ?? {}) as Record<string, unknown>;
  const fields = record.fields;
  if (fields === null || typeof fields !== "object") {
    throw new SignerError("MALFORMED_ENVELOPE", "pop sign requires a `fields` object");
  }
  const key = resolveSigningKey(record, keyFileSource, stdin);
  if (!key.privateKeyBase64Url) {
    throw new SignerError("MALFORMED_ENVELOPE", "signing key is missing private_key_base64url");
  }
  const { pop_signature } = signPoP(fields as PopChallengeFields, key.privateKeyBase64Url);
  return {
    signer_protocol: SIGNER_PROTOCOL,
    implementation: IMPLEMENTATION,
    implementation_version: implementationVersion(),
    pop_signature,
    algorithm: SUPPORTED_SIGNING.algorithm,
  };
}
```

- [ ] **Step 4: Dispatch in `src/cli/run.ts`**

Import `popSignResult` and add:

```typescript
      case "pop sign":
        result = popSignResult(readInput(parsed.input, _stdin), parsed.key, _stdin);
        break;
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `npm test -- test/cli-pop.test.ts`
Expected: PASS.

- [ ] **Step 6: Run the full build + suite**

Run: `npm run check`
Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add src/cli/commands.ts src/cli/run.ts test/cli-pop.test.ts
git commit -m "feat(cli): add pop sign command"
```

---

## Task 5: `verify-vectors`

In-process conformance self-check: run the full `@sohopay/signer-vectors` set with the SDK primitives. Exit 0 iff every vector passes.

**Files:**
- Create: `src/cli/verify-vectors.ts`
- Modify: `src/cli/commands.ts`
- Modify: `src/cli/run.ts`
- Test: `test/cli-verify-vectors.test.ts`

**Interfaces:**
- Produces:
  - `verifyVectors(): VerifySummary` where `VerifySummary = { passed: number; failed: number; total: number; failures: string[] }` (verify-vectors.ts).
  - `verifyVectorsResult(): { result: Record<string, unknown>; ok: boolean }` (commands.ts).
- Consumes: `loadVectors` (`@sohopay/signer-vectors`); `computeJkt`, `buildPopChallengeMessage`, `signPoP`, `computePaymentId`, `buildVoucherSignedBytes`, `signVoucher`, `buildPaymentSignatureHeader`, `toHex` (SDK).

- [ ] **Step 1: Write the failing test**

Create `test/cli-verify-vectors.test.ts`:

```typescript
import assert from "node:assert/strict";
import { test } from "node:test";

import { run } from "../src/cli/run.js";
import { verifyVectors } from "../src/cli/verify-vectors.js";

test("verifyVectors passes every vector with zero failures", () => {
  const summary = verifyVectors();
  assert.equal(summary.failed, 0, summary.failures.join("; "));
  assert.ok(summary.total > 0);
  assert.equal(summary.passed, summary.total);
});

test("verify-vectors (json) exits 0 and summarizes pass/fail/total", () => {
  const r = run(["verify-vectors", "--output", "json"], "");
  assert.equal(r.exitCode, 0, r.stderr);
  const out = JSON.parse(r.stdout);
  assert.equal(out.failed, 0);
  assert.equal(out.passed, out.total);
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm test -- test/cli-verify-vectors.test.ts`
Expected: FAIL — `src/cli/verify-vectors.js` does not exist.

- [ ] **Step 3: Implement `src/cli/verify-vectors.ts`**

Mirrors `test/parity.test.ts` as a counting function (same checks, no `node:test`):

```typescript
import { loadVectors } from "@sohopay/signer-vectors";

import { toHex } from "../encoding.js";
import { buildPaymentSignatureHeader } from "../envelope.js";
import { computeJkt } from "../keys.js";
import { buildPopChallengeMessage, signPoP } from "../pop.js";
import {
  buildVoucherSignedBytes,
  computePaymentId,
  signVoucher,
  type AgentPaymentVoucher,
} from "../voucher.js";

export interface VerifySummary {
  passed: number;
  failed: number;
  total: number;
  failures: string[];
}

/** Runs the full known-answer set in-process. A host calls this to self-certify. */
export function verifyVectors(): VerifySummary {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const doc = loadVectors() as any;
  const testKey = doc.testKeys[0];
  const failures: string[] = [];
  let passed = 0;

  const check = (id: string, actual: unknown, expected: unknown): void => {
    if (JSON.stringify(actual) === JSON.stringify(expected)) {
      passed += 1;
    } else {
      failures.push(id);
    }
  };

  for (const v of doc.vectors.jkt) {
    check(`jkt:${v.id}`, computeJkt(v.input.publicJwk), v.expected.jkt);
  }
  for (const v of doc.vectors.pop) {
    check(`pop-msg:${v.id}`, toHex(buildPopChallengeMessage(v.input.fields)), v.expected.messageUtf8Hex);
    check(`pop-sig:${v.id}`, signPoP(v.input.fields, testKey.seedB64Url).pop_signature, v.expected.popSignature);
  }
  for (const v of doc.vectors.voucherPaymentId) {
    check(`pid:${v.id}`, computePaymentId(v.input.core), v.expected.paymentId);
  }
  for (const v of doc.vectors.voucherSignature) {
    const voucher = v.input.voucher as AgentPaymentVoucher;
    check(`vsig-pre:${v.id}`, toHex(buildVoucherSignedBytes(voucher)), v.expected.preimageHex);
    check(
      `vsig:${v.id}`,
      signVoucher({
        voucher,
        privateKeyBase64Url: testKey.seedB64Url,
        signing: v.input.signing,
        publicJwk: testKey.publicJwk,
      }).signature,
      v.expected.signature,
    );
  }
  for (const v of doc.vectors.envelope) {
    const { headerName, headerValue } = buildPaymentSignatureHeader(v.input.prepareResponse, v.input.signature);
    check(`env-name:${v.id}`, headerName, v.expected.headerName);
    check(
      `env-decoded:${v.id}`,
      JSON.parse(Buffer.from(headerValue, "base64").toString("utf8")),
      v.expected.decodedEnvelope,
    );
  }

  return { passed, failed: failures.length, total: passed + failures.length, failures };
}
```

- [ ] **Step 4: Add `verifyVectorsResult` to `src/cli/commands.ts`**

```typescript
import { verifyVectors } from "./verify-vectors.js";

/** `verify-vectors → ({ passed, failed, total }, ok)`; ok drives the exit code. */
export function verifyVectorsResult(): { result: Record<string, unknown>; ok: boolean } {
  const summary = verifyVectors();
  return {
    result: { passed: summary.passed, failed: summary.failed, total: summary.total },
    ok: summary.failed === 0,
  };
}
```

- [ ] **Step 5: Dispatch in `src/cli/run.ts` (exit 0 iff all pass)**

`verify-vectors` is special — a non-zero `failed` count is a reported result, not a thrown error, but the process must exit non-zero. Handle it in the `switch` and short-circuit the shared success return (import `verifyVectorsResult`):

```typescript
      case "verify-vectors": {
        const { result: summary, ok } = verifyVectorsResult();
        return { stdout: format(summary, output), stderr: "", exitCode: ok ? 0 : 1 };
      }
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `npm test -- test/cli-verify-vectors.test.ts`
Expected: PASS.

- [ ] **Step 7: Run the full build + suite**

Run: `npm run check`
Expected: clean.

- [ ] **Step 8: Commit**

```bash
git add src/cli/verify-vectors.ts src/cli/commands.ts src/cli/run.ts test/cli-verify-vectors.test.ts
git commit -m "feat(cli): add verify-vectors self-check command"
```

---

## Task 6: README usage + full-suite verification

Document the CLI surface and prove the whole thing builds, installs as a bin, and passes end-to-end.

**Files:**
- Modify: `README.md`
- Test: (manual verification steps; no new automated test)

- [ ] **Step 1: Add a CLI section to `README.md`**

Append a `## CLI (sohopay-signer)` section documenting: the machine interface (stdin JSON, `--output json`, non-zero exit = failure), each command with a one-line stdin/stdout example (`voucher sign`, `payment-id`, `key jkt`, `pop sign`, `verify-vectors`, `capabilities`), the error-envelope shape (`{ "error": { "code", "message" } }`), and that the CLI holds agent workload keys only. Use the exact output shapes from the spec SP2 §Machine interface.

- [ ] **Step 2: Build and verify the bin runs from `dist`**

```bash
npm run build
echo '{}' | node dist/cli/index.js capabilities --output json
```

Expected: a JSON object with `"signer_protocol":"sohopay-signer/1"`. Confirm `dist/cli/index.js` begins with `#!/usr/bin/env node` (shebang preserved by tsc).

- [ ] **Step 3: Verify `verify-vectors` from the built bin**

```bash
node dist/cli/index.js verify-vectors --output json
echo "exit: $?"
```

Expected: `{"passed":N,"failed":0,"total":N}` and `exit: 0`.

- [ ] **Step 4: Run the whole suite + typecheck**

Run: `npm run check`
Expected: `tsc --noEmit` clean; every test green (new CLI tests + existing parity/flow/storage/etc.).

- [ ] **Step 5: Commit**

```bash
git add README.md
git commit -m "docs(cli): document the sohopay-signer command surface"
```

---

## Self-Review

**1. Spec coverage** (SP2 section of the design doc):
- Packaging (`bin: sohopay-signer`, `npx`, bundles signer-vectors) → Task 1 Step 8.
- Commands `voucher sign`, `payment-id`, `key jkt`, `pop sign`, `verify-vectors`, `capabilities` → Tasks 1–5.
- Machine interface (`--input -` stdin, `--output json` single object, stderr diagnostics, non-zero exit) → Task 1 (`run`/`index`), reinforced each task.
- `voucher sign` stdin/stdout shapes → Task 3.
- `--key` mutually exclusive with inline, `--key` preferred so the seed avoids the command line → Task 3 (both sources; file read).
- `capabilities` stdout shape → Task 1.
- `verify-vectors` exits 0 iff all pass, `--output json` summary → Task 5.
- Security (seed never logged; permission posture reused) → Task 3 (secret-safety test + `loadKeyFile` permission check).
- Testing (subprocess happy path; each negative guard returns the right code; `verify-vectors` exits 0; `capabilities` reports protocol) → distributed across tasks; subprocess smoke in Task 1.
- Out of scope (key gen/storage lifecycle, host routing, bundling) → honored; none added.
- SP1 protocol id surfaced as `signer_protocol` → Task 1 constants + every signed/capabilities output.

**2. Placeholder scan:** No "TBD"/"handle errors appropriately"/"similar to Task N"; every code step carries full code. ✓

**3. Type consistency:** `CliResult { stdout, stderr, exitCode }`, `ParsedArgs { command, input?, key?, output }`, `ResolvedKey { privateKeyBase64Url?, publicJwk? }`, `VerifySummary { passed, failed, total, failures }`, `implementationVersion()`, `resolveSigningKey(...)`, `verifyVectors()`, `verifyVectorsResult()` are each defined once and consumed with matching names/signatures. SDK names (`signVoucher`, `signPoP`, `computePaymentId`, `computeJkt`, `workloadKeyFromPrivate`, `buildVoucherSignedBytes`, `buildPaymentSignatureHeader`, `assertPublicJwk`, `toHex`, `loadVectors`) match `src/*.ts` / the vectors package exactly. ✓

**4. Review Focus:** all five lines have an owning test — malformed stdin (Task 2), dual key source (Task 3), insecure perms (Task 3), unknown command / missing input (Task 1 / Task 2), seed-not-in-stderr (Task 3). ✓
