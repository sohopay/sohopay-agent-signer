# SP5 Amendment B — Workload-Key Generation Interface Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a signer-owned `key generate` command (generation + persistence) and make all key input reference-only, so onboarding can route every workload-key cryptographic operation through the signer without the private key ever crossing the signer boundary.

**Architecture:** Track 1 of SP5-complete, in the `sohopay-agent-signer` repo. A new `key generate` command generates + persists the Ed25519 workload key at an explicit, validated path and emits only public material. A shared key-path validator gates every key path (generate + `pop sign`/`voucher sign` reads). `pop sign` now mints its own CSPRNG nonce/`iat`. The inline raw-key input form is removed. Strict input+output JSON schemas (INV-ioschema) and error-leak canaries (INV-errleak) enforce the boundary. No signing wire bytes change — the protocol stays `sohopay-signer/1`; capabilities gain an additive `command_contracts` map.

**Tech Stack:** TypeScript (ESM, NodeNext), `node --test` + tsx, `@noble/curves` (Ed25519), existing SDK (`generateWorkloadKey`, `computeJkt`, `workloadKeyFromPrivate`, `signPoP`, JCS), `node:crypto` (`randomBytes`), `node:fs`.

**Spec:** `docs/superpowers/specs/2026-10-07-sp5-complete-workload-keygen-and-onboard-routing-design.md` (approved SHA `0a70d56`)

## Global Constraints

- **INV-1 (key never crosses the boundary):** the private key appears in no stdout/stderr, argv, stdin, env var, log, or error message; no debug/verbose flag unlocks it.
- **INV-2 (signer owns gen + persist):** `key generate` writes `secret.json` (0600, atomic) and emits only `{ public_jwk, jkt, borrower_id, terminal_id, created }`.
- **INV-3 (reference-only key input):** key material enters ONLY via a validated `--key <path>`; the inline `private_key_base64url`-in-stdin form is removed (`INLINE_KEY_REJECTED`, checked before generic schema rejection). Public `public_jwk` inline for `key jkt` is still allowed (public material).
- **INV-4 (shared path validator):** one module validates every key path — allowed roots from a **compiled default (`~/.agents/sohopay-agent-workload`) + config file `~/.config/sohopay-signer/config.json` (owner==uid, 0600, no symlinks, parent 0700)**; env `SOHOPAY_SIGNER_KEY_ROOTS` may **only narrow** (intersection, never widen); `realpath` each configured root once at load, then `lstat` every component below it (reject symlinks + `..`); leaf basename must be `secret.json`; parent 0700 + owner==uid; read mode file 0600 + owner==uid; **ensure mode: never overwrite, never regenerate — create (`O_CREAT|O_EXCL`) only when absent**.
- **INV-ioschema:** every command validates BOTH stdin and stdout against a strict `additionalProperties:false` schema. `pop sign` input = exactly `{ fields: { borrowerId, terminalId, jkt } }` (a client `nonce`/`iat` ⇒ `MALFORMED_INPUT`); `key generate` input = exactly `{ borrower_id, terminal_id }`. Outputs are strict allowlists (see tasks).
- **INV-errleak:** a corrupted `secret.json` carrying a canary, run against every command, never surfaces the canary in stdout/stderr/exit payload; includes an inline-key canary.
- **INV-noseed:** no `--seed`/test-RNG flag or env var exists; test determinism is injected at the in-process SDK level only.
- **Capabilities:** `commands` stays a string array; add a sibling `command_contracts` map with `"key generate": "workload-keygen/1"`, `"pop sign": "pop-sign/1"`. `signer_protocol` stays `"sohopay-signer/1"`.
- **Output envelope preserved:** `pop sign` keeps its existing metadata envelope (`signer_protocol`, `implementation`, `implementation_version`, `algorithm`) and ADDS `nonce` + `iat` — the strict output allowlist is those plus `pop_signature` (the spec's shorthand "exactly `{pop_signature, nonce, iat}`" means the signing fields; the shared metadata envelope is kept for cross-command consistency).
- **`key generate` is non-deterministic** → NOT added to the conformance vectors.
- **Commits carry NO attribution / co-author / "Generated with" trailer** (repo owner's global git rule).
- **Branch:** `feat/sp5-amendment-b-workload-keygen` off `develop` @ `70712cd` (already checked out). This branch does NOT contain SP3 (PR #3); `implementationVersion()` here still has the `?? "0.0.0"` form — leave it (SP3 owns that fix).

## Review Focus

- **Symlinked `--out`/`--key` path** → the validator must reject a symlink at any component below the root (not just the leaf), else INV-1 is bypassed. Pinned in Task 3 (symlink-below-root test).
- **Env root-widening** (`SOHOPAY_SIGNER_KEY_ROOTS=/tmp`) → must fail `KEY_PATH_INVALID`, never widen. Pinned in Task 2 (env-widen-rejected) + Task 3 (INV-rootenv).
- **Client-supplied PoP `nonce`/`iat`** → must be rejected `MALFORMED_INPUT`, never used (precompute/replay). Pinned in Task 8 (client-nonce-rejected) + Task 5 (input schema).
- **Corrupted `secret.json` echoed in an error** → a JSON parse/validation failure must not quote file contents. Pinned in Task 10 (INV-errleak canary).
- **`key generate` overwriting a live key** → ensure mode must never regenerate/overwrite a same-borrower key (orphaning the registered key). Pinned in Task 6 (same-borrower→created:false, byte-identical file).

---

### Task 1: New error codes

**Files:**
- Modify: `src/errors.ts:2-17`
- Test: `test/errors-codes.test.ts` (Create)

**Interfaces:**
- Produces: the `SignerErrorCode` union gains `"KEY_PATH_INVALID" | "CROSS_BORROWER_KEY" | "TERMINAL_MISMATCH" | "KEY_INTEGRITY_FAILED" | "KEY_PERSIST_FAILED" | "INLINE_KEY_REJECTED" | "MALFORMED_INPUT"`.

- [ ] **Step 1: Write the failing test**

```ts
// test/errors-codes.test.ts
import assert from "node:assert/strict";
import test from "node:test";
import { SignerError, type SignerErrorCode } from "../src/errors.js";

test("new SP5-complete error codes construct and carry their code", () => {
  const codes: SignerErrorCode[] = [
    "KEY_PATH_INVALID", "CROSS_BORROWER_KEY", "TERMINAL_MISMATCH",
    "KEY_INTEGRITY_FAILED", "KEY_PERSIST_FAILED", "INLINE_KEY_REJECTED", "MALFORMED_INPUT",
  ];
  for (const c of codes) {
    assert.equal(new SignerError(c, "msg").code, c);
  }
});
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `node --import tsx --test test/errors-codes.test.ts`
Expected: FAIL — tsc/type error: the literals are not assignable to `SignerErrorCode`.

- [ ] **Step 3: Add the codes**

In `src/errors.ts`, extend the `SignerErrorCode` union (append to the existing literals, before the closing `;` on the `OPERATION_NOT_FOUND` line):

```ts
  | "KEY_PATH_INVALID"
  | "CROSS_BORROWER_KEY"
  | "TERMINAL_MISMATCH"
  | "KEY_INTEGRITY_FAILED"
  | "KEY_PERSIST_FAILED"
  | "INLINE_KEY_REJECTED"
  | "MALFORMED_INPUT";
```

- [ ] **Step 4: Run tests + typecheck**

Run: `npx tsc --noEmit && node --import tsx --test test/errors-codes.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/errors.ts test/errors-codes.test.ts
git commit -m "feat(signer): add SP5-complete error codes (key path/binding/integrity/inline/input)"
```

---

### Task 2: Signer config + resolved key roots

**Files:**
- Create: `src/cli/signer-config.ts`
- Test: `test/signer-config.test.ts` (Create)

**Interfaces:**
- Produces: `resolveKeyRoots(opts?: { homeDir?: string; env?: NodeJS.ProcessEnv }): string[]` — returns the **realpath-resolved** absolute allowed roots: the compiled default (`<home>/.agents/sohopay-agent-workload`) plus any roots from `<home>/.config/sohopay-signer/config.json` (`{ "keyRoots": string[] }`), intersected (narrowed) with `env.SOHOPAY_SIGNER_KEY_ROOTS` (colon-separated) when set. `homeDir`/`env` are injectable for tests (pure config inputs, NOT a product RNG/path seam). Throws `SignerError("KEY_PATH_INVALID", …)` when the config file exists but fails its guards (owner/mode/symlink/parent) or when the env would widen beyond the configured set.

- [ ] **Step 1: Write the failing test**

```ts
// test/signer-config.test.ts
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";
import test from "node:test";
import { resolveKeyRoots } from "../src/cli/signer-config.js";

function home(): string { return mkdtempSync(join(tmpdir(), "sc-home-")); }

test("default root is the compiled ~/.agents/sohopay-agent-workload", () => {
  const h = home();
  try {
    const roots = resolveKeyRoots({ homeDir: h, env: {} });
    assert.ok(roots.some((r) => r.endsWith("/.agents/sohopay-agent-workload")));
  } finally { rmSync(h, { recursive: true, force: true }); }
});

test("config file adds a root (0600, owner)", () => {
  const h = home();
  try {
    mkdirSync(join(h, ".config", "sohopay-signer"), { recursive: true });
    const extra = join(h, "custom-store"); mkdirSync(extra);
    const cfg = join(h, ".config", "sohopay-signer", "config.json");
    writeFileSync(cfg, JSON.stringify({ keyRoots: [extra] }), { mode: 0o600 });
    chmodSync(cfg, 0o600);
    const roots = resolveKeyRoots({ homeDir: h, env: {} });
    assert.ok(roots.some((r) => r.endsWith("/custom-store")));
  } finally { rmSync(h, { recursive: true, force: true }); }
});

test("env narrows to the intersection, never widens", () => {
  const h = home();
  try {
    const def = join(h, ".agents", "sohopay-agent-workload"); mkdirSync(def, { recursive: true });
    const narrowed = resolveKeyRoots({ homeDir: h, env: { SOHOPAY_SIGNER_KEY_ROOTS: def } });
    assert.ok(narrowed.every((r) => r.endsWith("/.agents/sohopay-agent-workload")));
    assert.throws(
      () => resolveKeyRoots({ homeDir: h, env: { SOHOPAY_SIGNER_KEY_ROOTS: "/tmp" } }),
      (e: { code?: string }) => e.code === "KEY_PATH_INVALID",
    );
  } finally { rmSync(h, { recursive: true, force: true }); }
});

test("a group/world-readable config file is refused", () => {
  const h = home();
  try {
    mkdirSync(join(h, ".config", "sohopay-signer"), { recursive: true });
    const cfg = join(h, ".config", "sohopay-signer", "config.json");
    writeFileSync(cfg, JSON.stringify({ keyRoots: [] }), { mode: 0o644 });
    chmodSync(cfg, 0o644);
    assert.throws(
      () => resolveKeyRoots({ homeDir: h, env: {} }),
      (e: { code?: string }) => e.code === "KEY_PATH_INVALID",
    );
  } finally { rmSync(h, { recursive: true, force: true }); }
});
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `node --import tsx --test test/signer-config.test.ts`
Expected: FAIL — `signer-config.js` does not exist.

- [ ] **Step 3: Implement `src/cli/signer-config.ts`**

```ts
import { lstatSync, readFileSync, realpathSync, statSync } from "node:fs";
import { homedir, platform, userInfo } from "node:os";
import { join } from "node:path";

import { SignerError } from "../errors.js";

const DEFAULT_SUBDIR = [".agents", "sohopay-agent-workload"];
const CONFIG_REL = [".config", "sohopay-signer", "config.json"];

function invalid(message: string): never {
  throw new SignerError("KEY_PATH_INVALID", message);
}

/** Owner==uid, 0600, not a symlink, parent 0700 — the config file is a trusted input. */
function assertConfigFileSecure(path: string): void {
  if (platform() === "win32") return; // ACL-governed; POSIX mode bits not meaningful
  const l = lstatSync(path);
  if (l.isSymbolicLink()) invalid(`${path} is a symlink`);
  const st = statSync(path);
  if (st.uid !== userInfo().uid) invalid(`${path} is not owned by the current user`);
  if ((st.mode & 0o077) !== 0) invalid(`${path} must be 0600`);
  const parent = statSync(join(path, ".."));
  if ((parent.mode & 0o077) !== 0) invalid(`${path} parent dir must be 0700`);
}

function realOrNull(p: string): string | null {
  try { return realpathSync(p); } catch { return null; }
}

/** Resolve the allowed key roots: compiled default + config file, narrowed by env. */
export function resolveKeyRoots(opts: { homeDir?: string; env?: NodeJS.ProcessEnv } = {}): string[] {
  const home = opts.homeDir ?? homedir();
  const env = opts.env ?? process.env;

  const configured = new Set<string>();
  const def = join(home, ...DEFAULT_SUBDIR);
  configured.add(realOrNull(def) ?? def);

  const cfgPath = join(home, ...CONFIG_REL);
  if (realOrNull(cfgPath) !== null) {
    assertConfigFileSecure(cfgPath);
    let parsed: { keyRoots?: unknown };
    try {
      parsed = JSON.parse(readFileSync(cfgPath, "utf8")) as { keyRoots?: unknown };
    } catch {
      invalid(`${cfgPath} is not valid JSON`);
    }
    const roots = parsed.keyRoots;
    if (roots !== undefined) {
      if (!Array.isArray(roots) || roots.some((r) => typeof r !== "string")) {
        invalid(`${cfgPath} keyRoots must be an array of strings`);
      }
      for (const r of roots as string[]) configured.add(realOrNull(r) ?? r);
    }
  }

  const envRaw = env.SOHOPAY_SIGNER_KEY_ROOTS;
  if (envRaw === undefined || envRaw.length === 0) {
    return [...configured];
  }
  const envRoots = envRaw.split(":").filter((s) => s.length > 0).map((r) => realOrNull(r) ?? r);
  const narrowed: string[] = [];
  for (const er of envRoots) {
    const ok = [...configured].some((cr) => er === cr || er.startsWith(cr + "/"));
    if (!ok) invalid(`SOHOPAY_SIGNER_KEY_ROOTS entry ${er} is not within a configured root`);
    narrowed.push(er);
  }
  return narrowed;
}
```

- [ ] **Step 4: Run tests + typecheck**

Run: `npx tsc --noEmit && node --import tsx --test test/signer-config.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/cli/signer-config.ts test/signer-config.test.ts
git commit -m "feat(signer): config-file + compiled key roots, env narrow-only (INV-4 roots)"
```

---

### Task 3: Shared key-path validator (INV-4)

**Files:**
- Create: `src/cli/key-path.ts`
- Test: `test/key-path.test.ts` (Create)

**Interfaces:**
- Consumes: `resolveKeyRoots` (Task 2).
- Produces: `validateKeyPath(path: string, mode: "read" | "ensure", opts?: { homeDir?: string; env?: NodeJS.ProcessEnv }): string` — returns the validated absolute path. Throws `SignerError("KEY_PATH_INVALID", …)` on: path not under any resolved root, any symlink component below the root, any `..`, leaf basename ≠ `secret.json`, parent dir not 0700/owner, (read) file absent or not 0600/owner, (ensure) file already exists.

- [ ] **Step 1: Write the failing test**

```ts
// test/key-path.test.ts
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, chmodSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";
import test from "node:test";
import { validateKeyPath } from "../src/cli/key-path.js";

function fixture(): { home: string; root: string } {
  const home = mkdtempSync(join(tmpdir(), "kp-home-"));
  const root = join(home, ".agents", "sohopay-agent-workload");
  mkdirSync(root, { recursive: true, mode: 0o700 });
  return { home, root };
}
const code = (e: { code?: string }) => e.code === "KEY_PATH_INVALID";

test("ensure mode accepts an absent secret.json under the root", () => {
  const { home, root } = fixture();
  try {
    const p = validateKeyPath(join(root, "secret.json"), "ensure", { homeDir: home, env: {} });
    assert.ok(p.endsWith("/secret.json"));
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("ensure mode refuses an existing file (never overwrite)", () => {
  const { home, root } = fixture();
  try {
    const p = join(root, "secret.json");
    writeFileSync(p, "{}", { mode: 0o600 }); chmodSync(p, 0o600);
    assert.throws(() => validateKeyPath(p, "ensure", { homeDir: home, env: {} }), code);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("read mode refuses a loosened (0644) file", () => {
  const { home, root } = fixture();
  try {
    const p = join(root, "secret.json");
    writeFileSync(p, "{}", { mode: 0o644 }); chmodSync(p, 0o644);
    assert.throws(() => validateKeyPath(p, "read", { homeDir: home, env: {} }), code);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("a wrong leaf basename is refused", () => {
  const { home, root } = fixture();
  try {
    assert.throws(() => validateKeyPath(join(root, "key.json"), "ensure", { homeDir: home, env: {} }), code);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("a symlinked component below the root is refused", () => {
  const { home, root } = fixture();
  try {
    const realDir = join(home, "elsewhere"); mkdirSync(realDir, { mode: 0o700 });
    const linked = join(root, "sub"); symlinkSync(realDir, linked);
    assert.throws(() => validateKeyPath(join(linked, "secret.json"), "ensure", { homeDir: home, env: {} }), code);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("a path outside every root is refused", () => {
  const { home } = fixture();
  try {
    const out = mkdtempSync(join(tmpdir(), "kp-out-"));
    try {
      assert.throws(() => validateKeyPath(join(out, "secret.json"), "ensure", { homeDir: home, env: {} }), code);
    } finally { rmSync(out, { recursive: true, force: true }); }
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("INV-rootenv: env root outside configured roots fails KEY_PATH_INVALID", () => {
  const { home, root } = fixture();
  try {
    assert.throws(
      () => validateKeyPath(join(root, "secret.json"), "ensure",
        { homeDir: home, env: { SOHOPAY_SIGNER_KEY_ROOTS: "/tmp" } }), code);
  } finally { rmSync(home, { recursive: true, force: true }); }
});
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `node --import tsx --test test/key-path.test.ts`
Expected: FAIL — `key-path.js` does not exist.

- [ ] **Step 3: Implement `src/cli/key-path.ts`**

```ts
import { existsSync, lstatSync, statSync } from "node:fs";
import { platform, userInfo } from "node:os";
import { basename, dirname, resolve, sep } from "node:path";

import { SignerError } from "../errors.js";
import { resolveKeyRoots } from "./signer-config.js";

function invalid(message: string): never {
  throw new SignerError("KEY_PATH_INVALID", message);
}

/** No symlink and no `..` from the root down to the target (existing components only). */
function assertNoSymlinkBelow(root: string, target: string): void {
  if (platform() === "win32") return;
  if (target !== root && !target.startsWith(root + sep)) invalid(`${target} is not under ${root}`);
  const rest = target.slice(root.length).split(sep).filter((s) => s.length > 0);
  let cur = root;
  for (const seg of rest) {
    if (seg === "..") invalid("path must not contain ..");
    cur = cur + sep + seg;
    if (existsSync(cur) && lstatSync(cur).isSymbolicLink()) invalid(`${cur} is a symlink`);
  }
}

function assertOwnerMode(path: string, denyMask: number): void {
  if (platform() === "win32") return;
  const st = statSync(path);
  if (st.uid !== userInfo().uid) invalid(`${path} is not owned by the current user`);
  if ((st.mode & denyMask) !== 0) invalid(`${path} has too-permissive mode`);
}

/** Validate a key path for `read` or `ensure`, returning the absolute path. */
export function validateKeyPath(
  path: string,
  mode: "read" | "ensure",
  opts: { homeDir?: string; env?: NodeJS.ProcessEnv } = {},
): string {
  const abs = resolve(path);
  if (basename(abs) !== "secret.json") invalid("key file must be named secret.json");

  const roots = resolveKeyRoots(opts);
  const root = roots.find((r) => abs === r || abs.startsWith(r + sep));
  if (!root) invalid(`${abs} is not under an allowed key root`);

  assertNoSymlinkBelow(root, abs);
  assertOwnerMode(dirname(abs), 0o077); // parent dir 0700, owner

  if (mode === "read") {
    if (!existsSync(abs)) invalid(`${abs} does not exist`);
    assertOwnerMode(abs, 0o077); // file 0600, owner
  } else if (existsSync(abs)) {
    invalid(`${abs} already exists (ensure mode never overwrites)`);
  }
  return abs;
}
```

- [ ] **Step 4: Run tests + typecheck**

Run: `npx tsc --noEmit && node --import tsx --test test/key-path.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/cli/key-path.ts test/key-path.test.ts
git commit -m "feat(signer): shared key-path validator — roots, symlink/.., leaf, modes, read/ensure (INV-4)"
```

---

### Task 4: Capabilities `command_contracts` + `key generate` registration + `--out`

**Files:**
- Modify: `src/cli/commands.ts:25-36`
- Modify: `src/cli/args.ts:1-9` (ParsedArgs), `:19-26` (KNOWN_COMMANDS), `:37-98` (`--out`)
- Test: `test/cli-command-contracts.test.ts` (Create)

**Interfaces:**
- Produces: `capabilitiesResult()` gains `command_contracts: { "key generate": "workload-keygen/1", "pop sign": "pop-sign/1" }`; `"key generate"` added to `COMMANDS` and `KNOWN_COMMANDS`; `ParsedArgs` gains `out?: string`.

- [ ] **Step 1: Write the failing test**

```ts
// test/cli-command-contracts.test.ts
import assert from "node:assert/strict";
import test from "node:test";
import { capabilitiesResult } from "../src/cli/commands.js";
import { parseArgs } from "../src/cli/args.js";

test("capabilities advertises the workload-keygen/1 and pop-sign/1 contracts", () => {
  const caps = capabilitiesResult() as { commands: string[]; command_contracts: Record<string, string> };
  assert.ok(caps.commands.includes("key generate"));
  assert.equal(caps.command_contracts["key generate"], "workload-keygen/1");
  assert.equal(caps.command_contracts["pop sign"], "pop-sign/1");
});

test("args parses `key generate --out <path>`", () => {
  const parsed = parseArgs(["key", "generate", "--out", "/x/secret.json", "--input", "-"]);
  assert.equal(parsed.command, "key generate");
  assert.equal(parsed.out, "/x/secret.json");
});
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `node --import tsx --test test/cli-command-contracts.test.ts`
Expected: FAIL — `command_contracts` undefined; `parseArgs` throws "unknown command: key generate".

- [ ] **Step 3: Implement**

In `src/cli/commands.ts` replace lines 25-36 with:

```ts
const COMMANDS = ["voucher sign", "payment-id", "key jkt", "key generate", "pop sign", "verify-vectors", "capabilities"];

const COMMAND_CONTRACTS: Record<string, string> = {
  "key generate": "workload-keygen/1",
  "pop sign": "pop-sign/1",
};

/** Static advertisement SP5 routing probes to confirm a usable signer. */
export function capabilitiesResult(): Record<string, unknown> {
  return {
    signer_protocol: SIGNER_PROTOCOL,
    implementation: IMPLEMENTATION,
    implementation_version: implementationVersion(),
    algorithms: [SUPPORTED_SIGNING.algorithm],
    commands: COMMANDS,
    command_contracts: COMMAND_CONTRACTS,
  };
}
```

In `src/cli/args.ts`: add `"key generate"` to the `KNOWN_COMMANDS` set; add `out?: string;` to `ParsedArgs`; declare `let out: string | undefined;` beside the other flag vars; add `} else if (name === "--out") { out = valueOf("--out"); }` in the flag loop (after the `--key` branch); and add `out` to the returned object.

- [ ] **Step 4: Run tests + typecheck**

Run: `npx tsc --noEmit && node --import tsx --test test/cli-command-contracts.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/cli/commands.ts src/cli/args.ts test/cli-command-contracts.test.ts
git commit -m "feat(signer): advertise command_contracts (workload-keygen/1, pop-sign/1); register key generate + --out"
```

---

### Task 5: Strict I/O schemas (INV-ioschema)

**Files:**
- Create: `src/cli/io-schema.ts`
- Test: `test/io-schema.test.ts` (Create)

**Interfaces:**
- Produces:
  - `assertInputSchema(command: string, input: unknown): void` — throws `SignerError("MALFORMED_INPUT", …)` on any key outside the command's input allowlist. `"pop sign"` → top `["fields"]`, `fields` exactly `["borrowerId","terminalId","jkt"]`; `"key generate"` → top `["borrower_id","terminal_id"]`.
  - `assertOutputSchema(command: string, output: Record<string, unknown>): void` — throws a plain `Error` (mapped to exit 1) on any key outside the command's output allowlist. `"key generate"` → `["public_jwk","jkt","borrower_id","terminal_id","created"]`; `"pop sign"` → `["signer_protocol","implementation","implementation_version","pop_signature","nonce","iat","algorithm"]`.

- [ ] **Step 1: Write the failing test**

```ts
// test/io-schema.test.ts
import assert from "node:assert/strict";
import test from "node:test";
import { assertInputSchema, assertOutputSchema } from "../src/cli/io-schema.js";

test("pop sign input rejects a client-supplied nonce", () => {
  assert.throws(
    () => assertInputSchema("pop sign", { fields: { borrowerId: "b", terminalId: "t", jkt: "j", nonce: "x" } }),
    (e: { code?: string }) => e.code === "MALFORMED_INPUT",
  );
  assert.doesNotThrow(() => assertInputSchema("pop sign", { fields: { borrowerId: "b", terminalId: "t", jkt: "j" } }));
});

test("key generate input rejects extra keys", () => {
  assert.throws(
    () => assertInputSchema("key generate", { borrower_id: "b", terminal_id: "t", extra: 1 }),
    (e: { code?: string }) => e.code === "MALFORMED_INPUT",
  );
});

test("output schema rejects a leaked field", () => {
  assert.throws(() => assertOutputSchema("key generate",
    { public_jwk: {}, jkt: "j", borrower_id: "b", terminal_id: "t", created: true, private_key_base64url: "LEAK" }));
});
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `node --import tsx --test test/io-schema.test.ts`
Expected: FAIL — `io-schema.js` does not exist.

- [ ] **Step 3: Implement `src/cli/io-schema.ts`**

```ts
import { SignerError } from "../errors.js";

const INPUT_ALLOW: Record<string, { top: string[]; fields?: string[] }> = {
  "pop sign": { top: ["fields"], fields: ["borrowerId", "terminalId", "jkt"] },
  "key generate": { top: ["borrower_id", "terminal_id"] },
};

const OUTPUT_ALLOW: Record<string, string[]> = {
  "key generate": ["public_jwk", "jkt", "borrower_id", "terminal_id", "created"],
  "pop sign": ["signer_protocol", "implementation", "implementation_version", "pop_signature", "nonce", "iat", "algorithm"],
};

function keysOutside(obj: Record<string, unknown>, allow: string[]): string[] {
  return Object.keys(obj).filter((k) => !allow.includes(k));
}

export function assertInputSchema(command: string, input: unknown): void {
  const spec = INPUT_ALLOW[command];
  if (!spec) return;
  if (input === null || typeof input !== "object") {
    throw new SignerError("MALFORMED_INPUT", `${command} input must be an object`);
  }
  const rec = input as Record<string, unknown>;
  const extraTop = keysOutside(rec, spec.top);
  if (extraTop.length > 0) {
    throw new SignerError("MALFORMED_INPUT", `${command}: unexpected input field(s): ${extraTop.join(", ")}`);
  }
  if (spec.fields) {
    const fields = rec.fields;
    if (fields === null || typeof fields !== "object") {
      throw new SignerError("MALFORMED_INPUT", `${command} requires a \`fields\` object`);
    }
    const extra = keysOutside(fields as Record<string, unknown>, spec.fields);
    if (extra.length > 0) {
      throw new SignerError("MALFORMED_INPUT", `${command}: unexpected field(s): ${extra.join(", ")}`);
    }
  }
}

export function assertOutputSchema(command: string, output: Record<string, unknown>): void {
  const allow = OUTPUT_ALLOW[command];
  if (!allow) return;
  const extra = keysOutside(output, allow);
  if (extra.length > 0) {
    throw new Error(`internal: ${command} output leaked field(s): ${extra.join(", ")}`);
  }
}
```

- [ ] **Step 4: Run tests + typecheck**

Run: `npx tsc --noEmit && node --import tsx --test test/io-schema.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/cli/io-schema.ts test/io-schema.test.ts
git commit -m "feat(signer): strict input/output JSON schemas (INV-ioschema)"
```

---

### Task 6: `key generate` ensure-mode command

**Files:**
- Modify: `src/storage.ts` (factor out `writeSecretFileAtPath`)
- Create: `src/cli/key-generate.ts`
- Test: `test/key-generate.test.ts` (Create)

**Interfaces:**
- Consumes: `validateKeyPath` (Task 3); SDK `generateWorkloadKey`/`workloadKeyFromPrivate` + `Ed25519PublicJwk` (`src/keys.js`); `loadKeyFile`, `writeSecretFileAtPath`, `StoredWorkloadKey` (`src/storage.js`).
- Produces: `keyGenerateResult(input: unknown, outPath: string | undefined, opts?: { homeDir?: string; env?: NodeJS.ProcessEnv }): Record<string, unknown>` returning exactly `{ public_jwk, jkt, borrower_id, terminal_id, created }` per the ensure-mode branch table.

**Persistence note:** `saveWorkloadKey` in `storage.ts` computes a borrower-scoped path internally; `key generate` uses an explicit `--out` path. Factor the atomic-write body into `writeSecretFileAtPath(path, key)` and have `saveWorkloadKey` call it.

- [ ] **Step 1: Write the failing test**

```ts
// test/key-generate.test.ts
import { mkdtempSync, mkdirSync, readFileSync, statSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";
import test from "node:test";
import { keyGenerateResult } from "../src/cli/key-generate.js";

function env() {
  const home = mkdtempSync(join(tmpdir(), "kg-home-"));
  const root = join(home, ".agents", "sohopay-agent-workload");
  mkdirSync(root, { recursive: true, mode: 0o700 });
  return { home, out: join(root, "secret.json"), opts: { homeDir: home, env: {} as NodeJS.ProcessEnv } };
}

test("absent → generates, writes 0600, returns created:true and only public material", () => {
  const { home, out, opts } = env();
  try {
    const r = keyGenerateResult({ borrower_id: "b1", terminal_id: "t1" }, out, opts) as Record<string, unknown>;
    assert.equal(r.created, true);
    assert.equal(r.borrower_id, "b1");
    assert.ok((r.public_jwk as { x?: string }).x);
    assert.equal((r as { private_key_base64url?: unknown }).private_key_base64url, undefined);
    assert.equal(statSync(out).mode & 0o777, 0o600);
    assert.ok(JSON.parse(readFileSync(out, "utf8")).private_key_base64url);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("same borrower + same terminal → created:false, same jkt, byte-identical file", () => {
  const { home, out, opts } = env();
  try {
    const first = keyGenerateResult({ borrower_id: "b1", terminal_id: "t1" }, out, opts) as Record<string, unknown>;
    const before = readFileSync(out, "utf8");
    const second = keyGenerateResult({ borrower_id: "b1", terminal_id: "t1" }, out, opts) as Record<string, unknown>;
    assert.equal(second.created, false);
    assert.equal(second.jkt, first.jkt);
    assert.equal(readFileSync(out, "utf8"), before);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("same borrower + different terminal → TERMINAL_MISMATCH", () => {
  const { home, out, opts } = env();
  try {
    keyGenerateResult({ borrower_id: "b1", terminal_id: "t1" }, out, opts);
    assert.throws(() => keyGenerateResult({ borrower_id: "b1", terminal_id: "t2" }, out, opts),
      (e: { code?: string }) => e.code === "TERMINAL_MISMATCH");
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("different borrower at the same path → CROSS_BORROWER_KEY", () => {
  const { home, out, opts } = env();
  try {
    keyGenerateResult({ borrower_id: "b1", terminal_id: "t1" }, out, opts);
    assert.throws(() => keyGenerateResult({ borrower_id: "b2", terminal_id: "t1" }, out, opts),
      (e: { code?: string }) => e.code === "CROSS_BORROWER_KEY");
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("stored public ≠ derived → KEY_INTEGRITY_FAILED", () => {
  const { home, out, opts } = env();
  try {
    keyGenerateResult({ borrower_id: "b1", terminal_id: "t1" }, out, opts);
    const raw = JSON.parse(readFileSync(out, "utf8"));
    raw.public_jwk.x = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    writeFileSync(out, JSON.stringify(raw), { mode: 0o600 });
    assert.throws(() => keyGenerateResult({ borrower_id: "b1", terminal_id: "t1" }, out, opts),
      (e: { code?: string }) => e.code === "KEY_INTEGRITY_FAILED");
  } finally { rmSync(home, { recursive: true, force: true }); }
});
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `node --import tsx --test test/key-generate.test.ts`
Expected: FAIL — `key-generate.js` does not exist.

- [ ] **Step 3: Implement**

In `src/storage.ts`, add `writeSecretFileAtPath` (and refactor `saveWorkloadKey` to call it with its computed `secretPath(...)`):

```ts
/** Atomically writes a StoredWorkloadKey at an explicit path (0600, temp→fsync→rename). */
export function writeSecretFileAtPath(path: string, key: StoredWorkloadKey): void {
  const dir = dirname(path);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const tmp = join(dir, `.secret.${process.pid}.${Date.now()}.tmp`);
  const fd = openSync(tmp, "w", 0o600);
  try {
    writeFileSync(fd, `${JSON.stringify(key, null, 2)}\n`);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  chmodSync(tmp, 0o600);
  renameSync(tmp, path);
}
```

Then `src/cli/key-generate.ts`:

```ts
import { closeSync, openSync } from "node:fs";

import { SignerError } from "../errors.js";
import { generateWorkloadKey, workloadKeyFromPrivate, type Ed25519PublicJwk } from "../keys.js";
import { loadKeyFile, writeSecretFileAtPath, type StoredWorkloadKey } from "../storage.js";
import { validateKeyPath } from "./key-path.js";

function str(rec: Record<string, unknown>, k: string): string {
  const v = rec[k];
  if (typeof v !== "string" || v.length === 0) {
    throw new SignerError("MALFORMED_INPUT", `key generate requires a non-empty string \`${k}\``);
  }
  return v;
}

function publicMaterial(stored: StoredWorkloadKey): Record<string, unknown> {
  return { public_jwk: stored.public_jwk, jkt: stored.jkt, borrower_id: stored.borrower_id, terminal_id: stored.terminal_id };
}

export function keyGenerateResult(
  input: unknown,
  outPath: string | undefined,
  opts: { homeDir?: string; env?: NodeJS.ProcessEnv } = {},
): Record<string, unknown> {
  if (outPath === undefined) {
    throw new SignerError("MALFORMED_INPUT", "key generate requires --out <path>");
  }
  const rec = (input ?? {}) as Record<string, unknown>;
  const borrowerId = str(rec, "borrower_id");
  const terminalId = str(rec, "terminal_id");

  // Probe existence via a read-mode validation (throws KEY_PATH_INVALID when absent).
  let existing: StoredWorkloadKey | undefined;
  try {
    existing = loadKeyFile(validateKeyPath(outPath, "read", opts)) as StoredWorkloadKey;
  } catch (e) {
    if ((e as { code?: string }).code !== "KEY_PATH_INVALID") throw e;
    existing = undefined;
  }

  if (existing) {
    if (existing.borrower_id !== borrowerId) {
      throw new SignerError("CROSS_BORROWER_KEY", "a key for a different borrower exists at this path");
    }
    if (existing.terminal_id !== terminalId) {
      throw new SignerError("TERMINAL_MISMATCH", "the stored key is bound to a different terminal");
    }
    const derived = workloadKeyFromPrivate(existing.private_key_base64url);
    if (derived.jkt !== existing.jkt || derived.publicJwk.x !== (existing.public_jwk as Ed25519PublicJwk).x) {
      throw new SignerError("KEY_INTEGRITY_FAILED", "stored public material does not match the private key");
    }
    return { ...publicMaterial(existing), created: false };
  }

  const writePath = validateKeyPath(outPath, "ensure", opts); // re-checks nothing exists (race)
  const keypair = generateWorkloadKey();
  const stored: StoredWorkloadKey = {
    private_key_base64url: keypair.privateKeyBase64Url,
    public_jwk: keypair.publicJwk,
    jkt: keypair.jkt,
    terminal_id: terminalId,
    borrower_id: borrowerId,
  };
  try {
    // O_EXCL placeholder claims the path; a race loser re-enters the read branch.
    closeSync(openSync(writePath, "wx", 0o600));
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "EEXIST") {
      return keyGenerateResult(input, outPath, opts);
    }
    throw new SignerError("KEY_PERSIST_FAILED", `cannot create ${writePath}`);
  }
  try {
    writeSecretFileAtPath(writePath, stored); // atomic rename over the placeholder
  } catch {
    throw new SignerError("KEY_PERSIST_FAILED", "cannot persist the workload key");
  }
  return { ...publicMaterial(stored), created: true };
}
```

- [ ] **Step 4: Run tests + typecheck**

Run: `npx tsc --noEmit && node --import tsx --test test/key-generate.test.ts`
Expected: PASS — all five branches green.

- [ ] **Step 5: Commit**

```bash
git add src/cli/key-generate.ts src/storage.ts test/key-generate.test.ts
git commit -m "feat(signer): key generate — ensure-mode gen+persist, public-only output, integrity re-derive"
```

---

### Task 7: Parallel-generate race test

**Files:**
- Test: `test/key-generate-race.test.ts` (Create)

**Interfaces:** Consumes `keyGenerateResult` (Task 6).

- [ ] **Step 1: Write the test** (should PASS given Task 6's EEXIST fallthrough; it pins the race)

```ts
// test/key-generate-race.test.ts
import { mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";
import test from "node:test";
import { keyGenerateResult } from "../src/cli/key-generate.js";

test("two parallel generates yield one key; exactly one created:true, same jkt", async () => {
  const home = mkdtempSync(join(tmpdir(), "kg-race-"));
  const root = join(home, ".agents", "sohopay-agent-workload");
  mkdirSync(root, { recursive: true, mode: 0o700 });
  const out = join(root, "secret.json");
  const opts = { homeDir: home, env: {} as NodeJS.ProcessEnv };
  try {
    const [a, b] = (await Promise.all([
      Promise.resolve().then(() => keyGenerateResult({ borrower_id: "b1", terminal_id: "t1" }, out, opts)),
      Promise.resolve().then(() => keyGenerateResult({ borrower_id: "b1", terminal_id: "t1" }, out, opts)),
    ])) as Record<string, unknown>[];
    assert.equal([a.created, b.created].filter((c) => c === true).length, 1);
    assert.equal(a.jkt, b.jkt);
  } finally { rmSync(home, { recursive: true, force: true }); }
});
```

- [ ] **Step 2: Run it**

Run: `node --import tsx --test test/key-generate-race.test.ts`
Expected: PASS. If it FAILS, fix the race handling in `key-generate.ts` (Task 6), not the test.

- [ ] **Step 3: Commit**

```bash
git add test/key-generate-race.test.ts
git commit -m "test(signer): key generate concurrent-invocation race yields a single key"
```

---

### Task 8: `pop sign` — signer-minted nonce/iat + three-field binding

**Files:**
- Modify: `src/cli/commands.ts:219-242` (`popSignResult`) + imports
- Test: `test/cli-pop-binding.test.ts` (Create)

**Interfaces:**
- Consumes: `signPoP` (`src/pop.js`), `toBase64Url` (`src/encoding.js`), `randomBytes` (`node:crypto`), `validateKeyPath` (Task 3), `loadKeyFile`/`StoredWorkloadKey` (`src/storage.js`).
- Produces: `popSignResult(input, keyFileSource, stdin, opts?)` → `{ …envelope…, pop_signature, nonce, iat }`; mints a 32-byte CSPRNG `nonce` + clock `iat`; asserts `borrowerId`/`terminalId`/`jkt` against the key file.

- [ ] **Step 1: Write the failing test**

```ts
// test/cli-pop-binding.test.ts
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";
import test from "node:test";
import { popSignResult } from "../src/cli/commands.js";
import { generateWorkloadKey } from "../src/keys.js";

function keyFile(borrowerId: string, terminalId: string) {
  const home = mkdtempSync(join(tmpdir(), "pop-home-"));
  const root = join(home, ".agents", "sohopay-agent-workload");
  mkdirSync(root, { recursive: true, mode: 0o700 });
  const kp = generateWorkloadKey();
  const out = join(root, "secret.json");
  writeFileSync(out, JSON.stringify({ private_key_base64url: kp.privateKeyBase64Url, public_jwk: kp.publicJwk, jkt: kp.jkt, terminal_id: terminalId, borrower_id: borrowerId }), { mode: 0o600 });
  chmodSync(out, 0o600);
  return { home, out, jkt: kp.jkt, opts: { homeDir: home, env: {} as NodeJS.ProcessEnv } };
}

test("pop sign mints nonce+iat and returns them; signs with the file key", () => {
  const { home, out, jkt, opts } = keyFile("b1", "t1");
  try {
    const r = popSignResult({ fields: { borrowerId: "b1", terminalId: "t1", jkt } }, out, "", opts) as Record<string, unknown>;
    assert.ok(typeof r.pop_signature === "string" && (r.pop_signature as string).length > 0);
    assert.ok(typeof r.nonce === "string" && (r.nonce as string).length >= 43);
    assert.ok(Number.isSafeInteger(r.iat));
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("pop sign refuses a terminal mismatch and a borrower mismatch", () => {
  const { home, out, jkt, opts } = keyFile("b1", "t1");
  try {
    assert.throws(() => popSignResult({ fields: { borrowerId: "b1", terminalId: "tX", jkt } }, out, "", opts),
      (e: { code?: string }) => e.code === "TERMINAL_MISMATCH");
    assert.throws(() => popSignResult({ fields: { borrowerId: "bX", terminalId: "t1", jkt } }, out, "", opts),
      (e: { code?: string }) => e.code === "CROSS_BORROWER_KEY");
  } finally { rmSync(home, { recursive: true, force: true }); }
});
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `node --import tsx --test test/cli-pop-binding.test.ts`
Expected: FAIL — current `popSignResult(input, keyFileSource, stdin)` has no `opts`, signs caller-supplied `fields`, asserts no binding.

- [ ] **Step 3: Implement**

Add imports at the top of `src/cli/commands.ts`: `import { randomBytes } from "node:crypto";`, `import { toBase64Url } from "../encoding.js";`, `import { loadKeyFile, type StoredWorkloadKey } from "../storage.js";`, `import { validateKeyPath } from "./key-path.js";`. Replace `popSignResult` with:

```ts
/** `{ fields: { borrowerId, terminalId, jkt } } (+ --key <path>) → { …, pop_signature, nonce, iat }`. */
export function popSignResult(
  input: unknown,
  keyFileSource: string | undefined,
  _stdin: string,
  opts: { homeDir?: string; env?: NodeJS.ProcessEnv } = {},
): Record<string, unknown> {
  const record = (input ?? {}) as Record<string, unknown>;
  const fields = record.fields as { borrowerId?: unknown; terminalId?: unknown; jkt?: unknown } | undefined;
  if (fields === null || typeof fields !== "object") {
    throw new SignerError("MALFORMED_INPUT", "pop sign requires a `fields` object");
  }
  if (keyFileSource === undefined) {
    throw new SignerError("MALFORMED_INPUT", "pop sign requires --key <path>");
  }
  const { borrowerId, terminalId, jkt } = fields;
  if (typeof borrowerId !== "string" || typeof terminalId !== "string" || typeof jkt !== "string") {
    throw new SignerError("MALFORMED_INPUT", "pop sign fields require string borrowerId, terminalId, jkt");
  }

  const stored = loadKeyFile(validateKeyPath(keyFileSource, "read", opts)) as StoredWorkloadKey;
  if (stored.borrower_id !== borrowerId) throw new SignerError("CROSS_BORROWER_KEY", "fields.borrowerId does not match the key file");
  if (stored.terminal_id !== terminalId) throw new SignerError("TERMINAL_MISMATCH", "fields.terminalId does not match the key file");
  if (stored.jkt !== jkt) throw new SignerError("AGENT_KEY_JKT_MISMATCH", "fields.jkt does not match the key file");

  const nonce = toBase64Url(randomBytes(32));
  const iat = Math.floor(Date.now() / 1000);
  const { pop_signature } = signPoP({ borrowerId, terminalId, jkt, nonce, iat }, stored.private_key_base64url);
  return {
    signer_protocol: SIGNER_PROTOCOL,
    implementation: IMPLEMENTATION,
    implementation_version: implementationVersion(),
    pop_signature,
    nonce,
    iat,
    algorithm: SUPPORTED_SIGNING.algorithm,
  };
}
```

- [ ] **Step 4: Run tests + typecheck**

Run: `npx tsc --noEmit && node --import tsx --test test/cli-pop-binding.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/cli/commands.ts test/cli-pop-binding.test.ts
git commit -m "feat(signer): pop sign mints CSPRNG nonce/iat + asserts borrower/terminal/jkt binding"
```

---

### Task 9: Remove the inline raw-key form (INV-3); wire `key generate` + INV-ioschema in run.ts

**Files:**
- Modify: `src/cli/commands.ts` (`resolveSigningKey`, `keyJktResult`)
- Modify: `src/cli/io.ts` (`readKeyFile` validates the path)
- Modify: `src/cli/run.ts` (dispatch `key generate`; `assertInputSchema`/`assertOutputSchema`; pass `--out`)
- Test: `test/cli-inline-key-rejected.test.ts` (Create); migrate inline cases in `test/cli-pop.test.ts`, `test/cli-voucher.test.ts`, `test/cli-voucher-envelope.test.ts`

**Interfaces:**
- Produces: inline `key`/`private_key_base64url` ⇒ `SignerError("INLINE_KEY_REJECTED", …)` (checked BEFORE the strict schema); `readKeyFile(source, _stdin, opts?)` validates the path (no `"-"`/stdin key); `run.ts` dispatches `key generate` and wraps INV-ioschema commands.

- [ ] **Step 1: Write the failing test**

```ts
// test/cli-inline-key-rejected.test.ts
import assert from "node:assert/strict";
import test from "node:test";
import { run } from "../src/cli/run.js";

test("pop sign with an inline private key is INLINE_KEY_REJECTED", () => {
  const stdin = JSON.stringify({ fields: { borrowerId: "b", terminalId: "t", jkt: "j" }, key: { private_key_base64url: "AAAA" } });
  const r = run(["pop", "sign", "--input", "-", "--output", "json"], stdin);
  assert.equal(r.exitCode, 1);
  assert.match(r.stderr, /INLINE_KEY_REJECTED|MALFORMED_INPUT/); // schema may also reject `key`; inline check runs first
});

test("voucher sign with an inline private key is INLINE_KEY_REJECTED", () => {
  const stdin = JSON.stringify({ voucher: {}, key: { private_key_base64url: "AAAA" } });
  const r = run(["voucher", "sign", "--input", "-", "--output", "json"], stdin);
  assert.equal(r.exitCode, 1);
  assert.match(r.stderr, /INLINE_KEY_REJECTED/);
});
```

(Note: `pop sign` has a strict input schema that also forbids a top-level `key`; the inline check in `resolveSigningKey` is not reached for pop because pop no longer calls `resolveSigningKey`. So for pop, the rejection is `MALFORMED_INPUT` from the schema; for voucher sign — which still uses `resolveSigningKey` and has no strict input schema — it is `INLINE_KEY_REJECTED`. The test accepts either for pop and requires `INLINE_KEY_REJECTED` for voucher.)

- [ ] **Step 2: Run it to make sure it fails**

Run: `node --import tsx --test test/cli-inline-key-rejected.test.ts`
Expected: FAIL — inline keys currently accepted.

- [ ] **Step 3: Implement**

In `src/cli/commands.ts`, make `resolveSigningKey` reject inline first and route through the validator:

```ts
export function resolveSigningKey(
  input: Record<string, unknown>,
  keyFileSource: string | undefined,
  stdin: string,
  opts: { homeDir?: string; env?: NodeJS.ProcessEnv } = {},
): ResolvedKey {
  if (input.key !== undefined) {
    throw new SignerError("INLINE_KEY_REJECTED", "inline key material is not accepted; use --key <path>");
  }
  if (keyFileSource === undefined) {
    throw new SignerError("MALFORMED_INPUT", "signing requires --key <path>");
  }
  const key = readKeyFile(keyFileSource, stdin, opts);
  if (key.privateKeyBase64Url !== undefined) decodeWorkloadSeed(key.privateKeyBase64Url);
  return key;
}
```

Update the two `resolveSigningKey(record, keyFileSource, stdin)` call sites in `voucherSignResult`/`voucherSignEnvelopeResult` to pass an `opts` arg through (add `opts` params to those two functions with a default `{}`, and thread from `run.ts`). In `keyJktResult`, reject a private inline block (keep `public_jwk`):

```ts
  const block = record.public_jwk !== undefined ? { public_jwk: record.public_jwk } : record.key;
  if (block && typeof block === "object" && (block as Record<string, unknown>).private_key_base64url !== undefined) {
    throw new SignerError("INLINE_KEY_REJECTED", "key jkt does not accept inline private key material; pass public_jwk");
  }
```

In `src/cli/io.ts`, validate the `--key` path (drop the `"-"`/stdin branch):

```ts
import { validateKeyPath } from "./key-path.js";
import { loadKeyFile } from "../storage.js";

export function readKeyFile(source: string, _stdin: string, opts: { homeDir?: string; env?: NodeJS.ProcessEnv } = {}): ResolvedKey {
  return resolveKeyBlock(loadKeyFile(validateKeyPath(source, "read", opts)));
}
```

In `src/cli/run.ts`: import `assertInputSchema, assertOutputSchema` from `./io-schema.js` and `keyGenerateResult` from `./key-generate.js`. Replace the `pop sign` case and add the `key generate` case:

```ts
      case "key generate": {
        const input = readInput(parsed.input, stdin);
        assertInputSchema("key generate", input);
        result = keyGenerateResult(input, parsed.out);
        assertOutputSchema("key generate", result);
        break;
      }
      case "pop sign": {
        const input = readInput(parsed.input, stdin);
        assertInputSchema("pop sign", input);
        result = popSignResult(input, parsed.key, stdin);
        assertOutputSchema("pop sign", result);
        break;
      }
```

Migrate the inline-key cases in `test/cli-pop.test.ts`, `test/cli-voucher.test.ts`, `test/cli-voucher-envelope.test.ts` to write a 0600 `secret.json` under a temp root (set `process.env.SOHOPAY_SIGNER_KEY_ROOTS` to that root for the test, restore in `finally`) and pass `--key <path>`; any case asserting the inline form *succeeds* becomes an assertion of `INLINE_KEY_REJECTED` (voucher) / `MALFORMED_INPUT` (pop).

- [ ] **Step 4: Run the full suite + typecheck**

Run: `npx tsc --noEmit && npm test`
Expected: PASS — inline rejections green; migrated voucher/pop cases green; nothing else regressed.

- [ ] **Step 5: Commit**

```bash
git add src/cli/commands.ts src/cli/io.ts src/cli/run.ts test/cli-inline-key-rejected.test.ts test/cli-pop.test.ts test/cli-voucher.test.ts test/cli-voucher-envelope.test.ts
git commit -m "feat(signer): reference-only key input (INLINE_KEY_REJECTED), validated --key, key generate dispatch + INV-ioschema"
```

---

### Task 10: INV-errleak — corrupted-secret + inline-key canary across every command

**Files:**
- Test: `test/inv-errleak.test.ts` (Create)

**Interfaces:** Consumes `run` (`src/cli/run.js`).

- [ ] **Step 1: Write the test**

```ts
// test/inv-errleak.test.ts
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";
import test from "node:test";
import { run } from "../src/cli/run.js";

const CANARY = "CANARY_SECRET_a1b2c3d4";
const INLINE = "INLINE_KEY_aaaaaaaaaaaaaaaa";

test("a corrupted secret.json never surfaces its contents in any command's output", () => {
  const home = mkdtempSync(join(tmpdir(), "leak-home-"));
  const root = join(home, ".agents", "sohopay-agent-workload");
  mkdirSync(root, { recursive: true, mode: 0o700 });
  const out = join(root, "secret.json");
  writeFileSync(out, `{ not json ${CANARY}`, { mode: 0o600 }); chmodSync(out, 0o600);
  const prev = process.env.SOHOPAY_SIGNER_KEY_ROOTS; process.env.SOHOPAY_SIGNER_KEY_ROOTS = root;
  try {
    for (const argv of [
      ["pop", "sign", "--key", out, "--input", "-", "--output", "json"],
      ["key", "generate", "--out", out, "--input", "-", "--output", "json"],
    ]) {
      const stdin = argv[0] === "pop"
        ? JSON.stringify({ fields: { borrowerId: "b", terminalId: "t", jkt: "j" } })
        : JSON.stringify({ borrower_id: "b", terminal_id: "t" });
      const r = run(argv, stdin);
      assert.ok(!r.stdout.includes(CANARY) && !r.stderr.includes(CANARY), `leaked canary: ${r.stdout}${r.stderr}`);
    }
  } finally {
    if (prev === undefined) delete process.env.SOHOPAY_SIGNER_KEY_ROOTS; else process.env.SOHOPAY_SIGNER_KEY_ROOTS = prev;
    rmSync(home, { recursive: true, force: true });
  }
});

test("a rejected inline key never surfaces the key material", () => {
  const r = run(["voucher", "sign", "--input", "-", "--output", "json"],
    JSON.stringify({ voucher: {}, key: { private_key_base64url: INLINE } }));
  assert.ok(!r.stdout.includes(INLINE) && !r.stderr.includes(INLINE), "inline key leaked");
  assert.match(r.stderr, /INLINE_KEY_REJECTED/);
});
```

- [ ] **Step 2: Run it**

Run: `node --import tsx --test test/inv-errleak.test.ts`
Expected: PASS. If FAIL, fix the offending command's error path to stop quoting input — never the test.

- [ ] **Step 3: Commit**

```bash
git add test/inv-errleak.test.ts
git commit -m "test(signer): INV-errleak — corrupted-secret + inline-key canary across commands"
```

---

### Task 11: INV-noseed — no CLI RNG seam

**Files:**
- Test: `test/inv-noseed.test.ts` (Create)

**Interfaces:** Consumes `parseArgs` (`src/cli/args.js`) + the source tree.

- [ ] **Step 1: Write the test**

```ts
// test/inv-noseed.test.ts
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import assert from "node:assert/strict";
import test from "node:test";
import { parseArgs } from "../src/cli/args.js";

test("--seed is an unknown flag (no CLI RNG seam)", () => {
  assert.throws(() => parseArgs(["key", "generate", "--seed", "0", "--out", "/x/secret.json", "--input", "-"]),
    /unknown flag: --seed/);
});

test("no source file references a seed/test-RNG env or flag", () => {
  const offenders: string[] = [];
  const walk = (d: string) => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      const p = join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.name.endsWith(".ts") && /--seed|SOHOPAY_SIGNER_SEED|TEST_RNG|deterministicKeygen/.test(readFileSync(p, "utf8"))) {
        offenders.push(p);
      }
    }
  };
  walk(join(process.cwd(), "src"));
  assert.deepEqual(offenders, [], `RNG seam found in: ${offenders.join(", ")}`);
});
```

- [ ] **Step 2: Run it**

Run: `node --import tsx --test test/inv-noseed.test.ts`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add test/inv-noseed.test.ts
git commit -m "test(signer): INV-noseed — no CLI RNG seam / test-seed flag in release builds"
```

---

### Task 12: Acceptance-change regression + README + full-suite gate

**Files:**
- Test: `test/cli-voucher-key-path.test.ts` (Create)
- Modify: `README.md`

**Interfaces:** none new.

- [ ] **Step 1: Write the regression test**

```ts
// test/cli-voucher-key-path.test.ts
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";
import test from "node:test";
import { run } from "../src/cli/run.js";
import { generateWorkloadKey } from "../src/keys.js";

test("voucher sign --key rejects a wrong-leaf path but validates the documented secret.json", () => {
  const home = mkdtempSync(join(tmpdir(), "vk-home-"));
  const root = join(home, ".agents", "sohopay-agent-workload");
  mkdirSync(root, { recursive: true, mode: 0o700 });
  const kp = generateWorkloadKey();
  const good = join(root, "secret.json");
  writeFileSync(good, JSON.stringify({ private_key_base64url: kp.privateKeyBase64Url, public_jwk: kp.publicJwk, jkt: kp.jkt, terminal_id: "t", borrower_id: "b" }), { mode: 0o600 });
  chmodSync(good, 0o600);
  const wrong = join(root, "key.json");
  writeFileSync(wrong, "{}", { mode: 0o600 }); chmodSync(wrong, 0o600);
  const prev = process.env.SOHOPAY_SIGNER_KEY_ROOTS; process.env.SOHOPAY_SIGNER_KEY_ROOTS = root;
  try {
    const voucher = JSON.stringify({ voucher: { paymentId: "0x", agentKeyJkt: kp.jkt } });
    const bad = run(["voucher", "sign", "--key", wrong, "--input", "-", "--output", "json"], voucher);
    assert.equal(bad.exitCode, 1);
    assert.match(bad.stderr, /KEY_PATH_INVALID/);
    const okPath = run(["voucher", "sign", "--key", good, "--input", "-", "--output", "json"], voucher);
    assert.doesNotMatch(okPath.stderr, /KEY_PATH_INVALID/); // validates; any later error is about voucher shape
  } finally {
    if (prev === undefined) delete process.env.SOHOPAY_SIGNER_KEY_ROOTS; else process.env.SOHOPAY_SIGNER_KEY_ROOTS = prev;
    rmSync(home, { recursive: true, force: true });
  }
});
```

- [ ] **Step 2: Run it**

Run: `node --import tsx --test test/cli-voucher-key-path.test.ts`
Expected: PASS.

- [ ] **Step 3: Update `README.md`**

Add a `key generate` section (input `{ borrower_id, terminal_id }` + `--out <path>`; emits `{ public_jwk, jkt, borrower_id, terminal_id, created }`; the private key is written to `secret.json` 0600 and never printed) and a "key input is reference-only" note documenting the two acceptance changes: `--key`/`--out` must be a `secret.json` under an allowed root (0600, no symlinks); inline key material is rejected `INLINE_KEY_REJECTED`.

- [ ] **Step 4: Run the whole suite + typecheck**

Run: `npx tsc --noEmit && npm test`
Expected: PASS — full suite green end-to-end.

- [ ] **Step 5: Commit**

```bash
git add test/cli-voucher-key-path.test.ts README.md
git commit -m "test+docs(signer): key-path acceptance-change regression; document key generate + reference-only key input"
```

---

## Notes for the executor

- **Version bump:** this plan does NOT bump `package.json`. At release time pick the next minor (e.g. `0.3.0`); that pinned version is the merge-gate artifact and feeds Track 2's `signer.md` pin + INV-pin-sync.
- **Order dependency:** Tasks 1→3 are foundational (errors → config → validator). Task 6 (`key generate`) and Tasks 8/9 (pop binding + inline removal) all consume the validator; Task 9 threads `opts` + the schema asserts through `run.ts`.
- **INV-codes-registered (signer half):** every `SignerError(code, …)` added here is one of the Task-1 codes; the cross-repo registry check lives in Track 2's `validate-skills`. Do not add a code outside the Task-1 union.
- **Fix code, not tests:** INV-errleak, the race test, and the acceptance-change regression are acceptance surfaces; a failure is a real defect, not a test to relax.
