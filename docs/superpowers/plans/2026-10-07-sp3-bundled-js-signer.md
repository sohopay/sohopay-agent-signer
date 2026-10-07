# SP3 — Portable Bundled JS Signer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce a single self-contained `sohopay-signer.mjs` (all deps + the `@sohopay/signer-vectors` JSON inlined, no `node_modules`, no network) so SP5 routing resolves a conformant `sohopay-signer/1` signer without npx.

**Architecture:** One implementation → two packaging forms. An esbuild build (`scripts/bundle.mjs`) bundles the existing `src/cli/index.ts` entry into `dist-bundle/sohopay-signer.mjs`; the CLI source, command surface, contract, and crypto are untouched except two shared tweaks (build-injectable version; a bundle-only vectors shim) and one new shared runtime Node-floor guard. Distribution is a tag-driven GitHub Release with build-provenance attestation; the repo goes public so the asset and attestation need no token.

**Tech Stack:** TypeScript (ESM, NodeNext), esbuild, Node ≥ 18, `node --test` + tsx, GitHub Actions, `@sohopay/signer-vectors`, `@noble/*`, `canonicalize`.

**Spec:** `docs/superpowers/specs/2026-10-07-sp3-bundled-js-signer-design.md`

## Global Constraints

- **Invariant:** one implementation → two packaging forms; the bundle is built from `src/cli/index.ts`; **no parallel CLI implementation**. Anything that makes the bundle behave differently from the npm CLI is a defect.
- **Output:** `dist-bundle/sohopay-signer.mjs` + `dist-bundle/sohopay-signer.mjs.sha256` + `dist-bundle/sohopay-signer.mjs.LEGAL.txt`; `dist-bundle/` is **git-ignored**, never confused with `dist/`.
- **esbuild options (exact):** `format:"esm"`, `platform:"node"`, `bundle:true`, `target:"node18"`, `banner:{js:"#!/usr/bin/env node"}`, `sourcemap:false`, `legalComments:"external"`.
- **Version:** read `package.json`, **assert `version` is a non-empty string else throw and fail the build**; `define:{ __SIGNER_IMPL_VERSION__: JSON.stringify(version) }`. Neither form may ever emit `"0.0.0"` or `"unknown"` — unresolved is a throw.
- **Identity identical:** `capabilities` reports `signer_protocol:"sohopay-signer/1"`, `implementation:"@sohopay/agent-signer"`, same `implementation_version`.
- **Node floor ≥ 18:** runtime guard exits non-zero with coded `NODE_VERSION_UNSUPPORTED`.
- **Checksum format:** `<sha256>  sohopay-signer.mjs` (two spaces; `sha256sum -c` compatible).
- **Vectors shim import:** the package's `exports` map **blocks** `@sohopay/signer-vectors/vectors/index.json` (`ERR_PACKAGE_PATH_NOT_EXPORTED`); the shim MUST import the JSON by a **filesystem-relative path** into `node_modules`.
- **Test-harness default:** `SOHOPAY_SIGNER_BIN` unset ⇒ the existing `node --import tsx src/cli/index.ts` source form (not `dist/cli/index.js` — that would force a build before `npm test`). Set it to the bundle for the parity pass.
- **Determinism:** pinned esbuild, no sourcemap, fixed banner, external legal comments, no timestamps/abs paths/env metadata embedded; proven by building **twice into two separate clean dirs** and diffing for byte-identity.
- **Release:** `js-bundle-v<version>` tag (version mirrors `package.json`); workflow perms **exactly** `contents: write`, `id-token: write`, `attestations: write`; assert built version == tag version; `actions/attest-build-provenance`; attach the 3 assets; compare release SHA to a second clean build of the same commit.
- **Install doc:** pin an **exact version**, never `latest`; `gh attestation verify` online; out-of-release hash offline; the downloaded `.sha256` is convenience, not the trust anchor.
- **Prerequisite (human/ops, not code):** the `sohopay-agent-signer` repo is made **public** before the release workflow is used; immutable releases + `js-bundle-v*` tag protection enabled.
- **Signer stays network-free** — no download path is added into the signer.
- **Commits carry no attribution/co-author line** (user's global git rule disables it).

## Review Focus

- **Vectors silently dropped** (shim import path wrong) → `verify-vectors` must report the real non-zero count, not 0/empty. Pinned in Task 3 (deep-equal) + Task 6 (clean-room `total > 0` assertion).
- **Version drift** — a build that injects nothing would report `0.0.0`/`unknown` → Task 6 asserts bundle `implementation_version` equals `package.json` exactly.
- **Hidden `node_modules` runtime read** (an un-inlined dep) → Task 6 clean-room run with no `node_modules`; Task 7 adds no-network (`unshare`).
- **License notices stripped** by a future esbuild config → Task 4 asserts `*.LEGAL.txt` contains expected headers.
- **Extensionless copy on PATH runs oddly** instead of failing → Task 6 asserts the extensionless-copy invocation exits non-zero loudly.

---

### Task 1: Build-injectable `implementationVersion()` (source tweak #1)

**Files:**
- Modify: `src/cli/commands.ts:17-23`
- Test: `test/cli-version.test.ts` (Create)

**Interfaces:**
- Consumes: nothing new.
- Produces: `implementationVersion(): string` — unchanged signature; now prefers an esbuild-injected `__SIGNER_IMPL_VERSION__`, else reads `package.json`, and **throws** if unresolved (never returns `"0.0.0"`).

- [ ] **Step 1: Write the failing test**

```ts
// test/cli-version.test.ts
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import test from "node:test";
import { implementationVersion } from "../src/cli/commands.js";

test("implementationVersion returns package.json version, never the 0.0.0 fallback", () => {
  const pkg = JSON.parse(
    readFileSync(fileURLToPath(new URL("../package.json", import.meta.url)), "utf8"),
  ) as { version?: string };
  const v = implementationVersion();
  assert.equal(v, pkg.version);
  assert.notEqual(v, "0.0.0");
});
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `node --import tsx --test test/cli-version.test.ts`
Expected: FAIL — the file does not exist yet (and the current `?? "0.0.0"` would mask an unresolved version the new test forbids).

- [ ] **Step 3: Implement the change**

Replace `src/cli/commands.ts:17-23` with:

```ts
// ambient — esbuild `define` replaces this literal in the bundle; undefined in the tsc/tsx path
declare const __SIGNER_IMPL_VERSION__: string | undefined;

/** The signer's implementation version: build-injected in the bundle, else from package.json. */
export function implementationVersion(): string {
  if (typeof __SIGNER_IMPL_VERSION__ !== "undefined" && __SIGNER_IMPL_VERSION__) {
    return __SIGNER_IMPL_VERSION__;
  }
  const pkg = JSON.parse(
    readFileSync(new URL("../../package.json", import.meta.url), "utf8"),
  ) as { version?: string };
  if (!pkg.version) {
    throw new Error("implementation_version could not be resolved from package.json");
  }
  return pkg.version;
}
```

(`typeof X` on an undeclared identifier is the one reference form that never throws — safe under tsx/dist where no `define` applies.)

- [ ] **Step 4: Run tests + typecheck**

Run: `npx tsc --noEmit && node --import tsx --test test/cli-version.test.ts`
Expected: PASS; tsc clean (the `declare const` satisfies it).

- [ ] **Step 5: Commit**

```bash
git add src/cli/commands.ts test/cli-version.test.ts
git commit -m "feat(cli): make implementation_version build-injectable; throw instead of 0.0.0 fallback"
```

---

### Task 2: Runtime Node-floor guard (new shared component)

**Files:**
- Create: `src/cli/node-floor.ts`
- Modify: `src/cli/index.ts` (restructure to guard-then-dynamic-import)
- Test: `test/cli-node-floor.test.ts` (Create)

**Interfaces:**
- Produces: `MIN_NODE_MAJOR: number`; `assertNodeFloor(nodeVersion: string): void` — throws an `Error` with `.code === "NODE_VERSION_UNSUPPORTED"` when the major is below the floor.

- [ ] **Step 1: Write the failing test**

```ts
// test/cli-node-floor.test.ts
import assert from "node:assert/strict";
import test from "node:test";
import { assertNodeFloor, MIN_NODE_MAJOR } from "../src/cli/node-floor.js";

test("assertNodeFloor rejects below the floor with a coded error", () => {
  assert.equal(MIN_NODE_MAJOR, 18);
  const err = assert.throws(() => assertNodeFloor("16.20.2")) as { code?: string };
  assert.equal(err.code, "NODE_VERSION_UNSUPPORTED");
  assert.throws(() => assertNodeFloor("not-a-version"));
});

test("assertNodeFloor accepts the floor and above", () => {
  assert.doesNotThrow(() => assertNodeFloor("18.0.0"));
  assert.doesNotThrow(() => assertNodeFloor("20.11.1"));
});
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `node --import tsx --test test/cli-node-floor.test.ts`
Expected: FAIL — `node-floor.js` does not exist.

- [ ] **Step 3: Implement `src/cli/node-floor.ts`**

```ts
/** Minimum Node major this signer runs on. Mirrors package.json "engines". */
export const MIN_NODE_MAJOR = 18;

/** Throws a coded error if the runtime Node major is below the floor. */
export function assertNodeFloor(nodeVersion: string): void {
  const major = Number.parseInt((nodeVersion.split(".")[0] ?? "").trim(), 10);
  if (!Number.isFinite(major) || major < MIN_NODE_MAJOR) {
    const err = new Error(`sohopay-signer requires Node >= ${MIN_NODE_MAJOR}`);
    (err as { code?: string }).code = "NODE_VERSION_UNSUPPORTED";
    throw err;
  }
}
```

- [ ] **Step 4: Restructure `src/cli/index.ts`**

The guard must run before the heavy modules evaluate. ESM hoists static imports, so import only `node-floor` statically and load the rest via dynamic import after the guard:

```ts
#!/usr/bin/env node
import { assertNodeFloor } from "./node-floor.js";

try {
  assertNodeFloor(process.versions.node);
} catch (e) {
  const code = (e as { code?: string }).code ?? "NODE_VERSION_UNSUPPORTED";
  process.stderr.write(JSON.stringify({ error: { code, message: (e as Error).message } }) + "\n");
  process.exit(1);
}

const { readFileSync } = await import("node:fs");
const { needsStdin } = await import("./args.js");
const { run } = await import("./run.js");

/** Reads all of stdin synchronously (fd 0). Empty string when nothing is piped. */
function readStdin(): string {
  try {
    return readFileSync(0, "utf8");
  } catch {
    return "";
  }
}

const argv = process.argv.slice(2);
const stdin = needsStdin(argv) ? readStdin() : "";
const result = run(argv, stdin);
if (result.stdout) process.stdout.write(result.stdout);
if (result.stderr) process.stderr.write(result.stderr);
process.exitCode = result.exitCode;
```

- [ ] **Step 5: Run the full suite + typecheck (entry behavior unchanged on current Node)**

Run: `npx tsc --noEmit && npm test`
Expected: PASS — existing CLI subprocess tests still pass (we run on Node ≥ 18, so the guard is a no-op; dynamic imports resolve under tsx and after `npm run build`).

- [ ] **Step 6: Commit**

```bash
git add src/cli/node-floor.ts src/cli/index.ts test/cli-node-floor.test.ts
git commit -m "feat(cli): coded Node>=18 runtime floor guard before command dispatch"
```

---

### Task 3: Bundle-only vectors shim + parity test (source tweak #2)

**Files:**
- Create: `scripts/bundle-vectors-shim.mjs`
- Test: `test/bundle-vectors-shim.test.ts` (Create)

**Interfaces:**
- Produces: `scripts/bundle-vectors-shim.mjs` exporting `loadVectors(): unknown` returning the statically-imported vectors payload. Used ONLY via the esbuild `alias` in Task 4; the `dist/` path keeps the real `@sohopay/signer-vectors`.

- [ ] **Step 1: Write the failing test**

```ts
// test/bundle-vectors-shim.test.ts
import assert from "node:assert/strict";
import test from "node:test";
import { loadVectors as realLoad } from "@sohopay/signer-vectors";
// @ts-expect-error — plain .mjs shim, no types
import { loadVectors as shimLoad } from "../scripts/bundle-vectors-shim.mjs";

test("vectors shim returns byte-identical payload to the package (same IDs/count/content)", () => {
  assert.deepStrictEqual(shimLoad(), realLoad());
});
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `node --import tsx --test test/bundle-vectors-shim.test.ts`
Expected: FAIL — the shim file does not exist.

- [ ] **Step 3: Implement the shim**

```js
// scripts/bundle-vectors-shim.mjs
// Build-time replacement for @sohopay/signer-vectors in the bundle. The real package reads
// vectors/index.json from disk at runtime (esbuild cannot see through that), so the bundle
// would break offline. This statically imports the SAME JSON so esbuild inlines it.
// NOTE: the package `exports` map blocks the subpath "@sohopay/signer-vectors/vectors/index.json"
// (ERR_PACKAGE_PATH_NOT_EXPORTED), so we import by a filesystem-relative path into node_modules.
import vectors from "../node_modules/@sohopay/signer-vectors/vectors/index.json" with { type: "json" };

export function loadVectors() {
  return vectors;
}
```

(If a toolchain rejects the `with { type: "json" }` attribute, drop it — esbuild and modern Node infer JSON from the extension; the relative path is the load-bearing part.)

- [ ] **Step 4: Run the test**

Run: `node --import tsx --test test/bundle-vectors-shim.test.ts`
Expected: PASS — deep-equal holds.

- [ ] **Step 5: Commit**

```bash
git add scripts/bundle-vectors-shim.mjs test/bundle-vectors-shim.test.ts
git commit -m "feat(bundle): vectors shim that inlines the vectors JSON for offline verify-vectors"
```

---

### Task 4: esbuild bundle build (`scripts/bundle.mjs`) + packaging wiring + build-output test

**Files:**
- Modify: `package.json` (add `esbuild` devDep pinned exact; add `"bundle"` script)
- Modify: `.gitignore` (add `dist-bundle/`)
- Create: `scripts/bundle.mjs`
- Test: `test/bundle-build.test.ts` (Create)

**Interfaces:**
- Consumes: `src/cli/index.ts` (entry), `scripts/bundle-vectors-shim.mjs` (Task 3), `__SIGNER_IMPL_VERSION__` define (Task 1).
- Produces: `dist-bundle/sohopay-signer.mjs` (shebang, mode 0755), `…/.mjs.sha256` (`<sha256>  sohopay-signer.mjs`), `…/.mjs.LEGAL.txt`.

- [ ] **Step 1: Add esbuild + script + gitignore**

In `package.json` `devDependencies` add the exact version `npm install --save-dev --save-exact esbuild` resolves (e.g. `"esbuild": "0.24.0"`). Add to `scripts`: `"bundle": "node scripts/bundle.mjs"`. Append `dist-bundle/` to `.gitignore`.

Run: `npm install --save-dev --save-exact esbuild`

- [ ] **Step 2: Write the failing test**

```ts
// test/bundle-build.test.ts
import { spawnSync } from "node:child_process";
import { readFileSync, existsSync, statSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";
import test, { before } from "node:test";

const OUT = "dist-bundle/sohopay-signer.mjs";

before(() => {
  const r = spawnSync("npm", ["run", "bundle"], { encoding: "utf8" });
  assert.equal(r.status, 0, `bundle failed:\n${r.stdout}\n${r.stderr}`);
});

test("bundle emits an executable .mjs with a node shebang", () => {
  assert.ok(existsSync(OUT));
  assert.ok(readFileSync(OUT, "utf8").startsWith("#!/usr/bin/env node"));
  assert.ok((statSync(OUT).mode & 0o111) !== 0, "not executable");
});

test("checksum file uses the conventional sha256sum format", () => {
  const line = readFileSync(`${OUT}.sha256`, "utf8").trim();
  assert.match(line, /^[0-9a-f]{64}  sohopay-signer\.mjs$/);
});

test("license notices survive (LEGAL.txt non-empty, names a bundled dep)", () => {
  const legal = readFileSync(`${OUT}.LEGAL.txt`, "utf8");
  assert.ok(legal.length > 0);
  assert.match(legal, /noble|canonicalize/i);
});

test("build is reproducible across two separate clean output dirs", () => {
  const build = (dir: string) => {
    const r = spawnSync("node", ["scripts/bundle.mjs"], {
      encoding: "utf8",
      env: { ...process.env, SOHOPAY_BUNDLE_OUTDIR: dir },
    });
    assert.equal(r.status, 0, `${r.stdout}\n${r.stderr}`);
    return readFileSync(join(dir, "sohopay-signer.mjs"));
  };
  const a = mkdtempSync(join(tmpdir(), "bnd-a-"));
  const b = mkdtempSync(join(tmpdir(), "bnd-b-"));
  try {
    assert.ok(build(a).equals(build(b)), "two clean builds differ");
  } finally {
    rmSync(a, { recursive: true, force: true });
    rmSync(b, { recursive: true, force: true });
  }
});
```

- [ ] **Step 3: Run it to make sure it fails**

Run: `node --import tsx --test test/bundle-build.test.ts`
Expected: FAIL — `scripts/bundle.mjs` does not exist, `npm run bundle` errors.

- [ ] **Step 4: Implement `scripts/bundle.mjs`**

```js
// scripts/bundle.mjs
import { build } from "esbuild";
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const outDir = process.env.SOHOPAY_BUNDLE_OUTDIR ?? join(root, "dist-bundle");
const outFile = join(outDir, "sohopay-signer.mjs");

const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
if (typeof pkg.version !== "string" || pkg.version.length === 0) {
  throw new Error("cannot resolve a non-empty package.json version for the bundle");
}

mkdirSync(outDir, { recursive: true });

await build({
  entryPoints: [join(root, "src/cli/index.ts")],
  outfile: outFile,
  bundle: true,
  format: "esm",
  platform: "node",
  target: "node18",
  sourcemap: false,
  legalComments: "external", // writes <outfile>.LEGAL.txt
  banner: { js: "#!/usr/bin/env node" },
  define: { __SIGNER_IMPL_VERSION__: JSON.stringify(pkg.version) },
  alias: { "@sohopay/signer-vectors": join(here, "bundle-vectors-shim.mjs") },
});

chmodSync(outFile, 0o755);

const bytes = readFileSync(outFile);
const sha = createHash("sha256").update(bytes).digest("hex");
writeFileSync(`${outFile}.sha256`, `${sha}  sohopay-signer.mjs\n`);

process.stderr.write(`bundled ${outFile} (sha256 ${sha}, version ${pkg.version})\n`);
```

- [ ] **Step 5: Run the test + typecheck**

Run: `npx tsc --noEmit && node --import tsx --test test/bundle-build.test.ts`
Expected: PASS — all four tests green. (`legalComments:"external"` writes `<outfile>.LEGAL.txt` next to each output, including under `SOHOPAY_BUNDLE_OUTDIR`; the reproducibility test reads only the `.mjs`.)

- [ ] **Step 6: Commit**

```bash
git add package.json package-lock.json .gitignore scripts/bundle.mjs test/bundle-build.test.ts
git commit -m "feat(bundle): esbuild single-file build with shebang, sha256, external legal notices"
```

---

### Task 5: Parameterize the CLI test harness (`SOHOPAY_SIGNER_BIN`)

**Files:**
- Create: `test/helpers/cli-bin.ts`
- Modify: `test/cli-capabilities.test.ts`, `test/cli-pop.test.ts`, `test/cli-readonly.test.ts`, `test/cli-verify-vectors.test.ts`, `test/cli-voucher-envelope.test.ts`, `test/cli-voucher.test.ts` (route each `spawnSync` through the helper)

**Interfaces:**
- Produces: `cliInvocation(): { cmd: string; prefix: string[] }` — `SOHOPAY_SIGNER_BIN` set ⇒ `{ cmd:"node", prefix:[bin] }`; unset ⇒ `{ cmd:"node", prefix:["--import","tsx","src/cli/index.ts"] }`.

- [ ] **Step 1: Write the helper**

```ts
// test/helpers/cli-bin.ts
/**
 * How the CLI tests spawn the signer. Default: the source via tsx (no build needed, matches
 * the existing suite). SOHOPAY_SIGNER_BIN=<path> runs that file with node instead (the bundle
 * parity pass points it at dist-bundle/sohopay-signer.mjs).
 */
export function cliInvocation(): { cmd: string; prefix: string[] } {
  const bin = process.env.SOHOPAY_SIGNER_BIN;
  if (bin && bin.length > 0) return { cmd: "node", prefix: [bin] };
  return { cmd: "node", prefix: ["--import", "tsx", "src/cli/index.ts"] };
}
```

- [ ] **Step 2: Route one test through it and confirm it still passes (refactor, stays green)**

In `test/cli-capabilities.test.ts`, replace the hardcoded spawn:

```ts
// before:
// const r = spawnSync("node", ["--import", "tsx", "src/cli/index.ts", "capabilities", "--output", "json"], {...});
// after:
import { cliInvocation } from "./helpers/cli-bin.js";
const { cmd, prefix } = cliInvocation();
const r = spawnSync(cmd, [...prefix, "capabilities", "--output", "json"], { /* same opts */ });
```

Run: `node --import tsx --test test/cli-capabilities.test.ts`
Expected: PASS (default path unchanged).

- [ ] **Step 3: Route the remaining cli-*.test.ts files the same way**

Apply the identical substitution to every `spawnSync("node", ["--import","tsx","src/cli/index.ts", …], …)` in `cli-pop`, `cli-readonly`, `cli-verify-vectors`, `cli-voucher-envelope`, `cli-voucher`. Keep every other spawn option (cwd, input, env) exactly as-is.

- [ ] **Step 4: Run the whole suite (default path green)**

Run: `npm test`
Expected: PASS — no behavior change with `SOHOPAY_SIGNER_BIN` unset.

- [ ] **Step 5: Smoke the override against the bundle**

Run: `npm run bundle && SOHOPAY_SIGNER_BIN="$PWD/dist-bundle/sohopay-signer.mjs" node --import tsx --test test/cli-*.test.ts`
Expected: PASS — the same CLI suite runs against the bundle. (If a test hardcodes a cwd that breaks the absolute bin path, fix that test to honor the absolute `SOHOPAY_SIGNER_BIN`.)

- [ ] **Step 6: Commit**

```bash
git add test/helpers/cli-bin.ts test/cli-capabilities.test.ts test/cli-pop.test.ts test/cli-readonly.test.ts test/cli-verify-vectors.test.ts test/cli-voucher-envelope.test.ts test/cli-voucher.test.ts
git commit -m "test(cli): route CLI subprocess tests through SOHOPAY_SIGNER_BIN for bundle parity"
```

---

### Task 6: Bundle-behavior test — clean room, invocation forms, parity

**Files:**
- Test: `test/bundle-behavior.test.ts` (Create)

**Interfaces:**
- Consumes: `npm run bundle` output (Task 4).

- [ ] **Step 1: Write the failing test**

```ts
// test/bundle-behavior.test.ts
import { spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, rmSync, symlinkSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";
import test, { before } from "node:test";

const BUNDLE = join(process.cwd(), "dist-bundle/sohopay-signer.mjs");

before(() => {
  const r = spawnSync("npm", ["run", "bundle"], { encoding: "utf8" });
  assert.equal(r.status, 0, `${r.stdout}\n${r.stderr}`);
});

function cleanRoom(): string {
  const dir = mkdtempSync(join(tmpdir(), "signer-cleanroom-"));
  cpSync(BUNDLE, join(dir, "sohopay-signer.mjs")); // ONLY the bundle; no node_modules
  return dir;
}

test("runs capabilities with no node_modules present", () => {
  const dir = cleanRoom();
  try {
    const r = spawnSync("node", ["sohopay-signer.mjs", "capabilities", "--output", "json"], {
      cwd: dir, encoding: "utf8",
    });
    assert.equal(r.status, 0, r.stderr);
    const caps = JSON.parse(r.stdout);
    assert.equal(caps.signer_protocol, "sohopay-signer/1");
    assert.equal(caps.implementation, "@sohopay/agent-signer");
    const pkg = JSON.parse(readFileSync(join(process.cwd(), "package.json"), "utf8"));
    assert.equal(caps.implementation_version, pkg.version); // no 0.0.0 drift
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("verify-vectors passes offline with the real (non-zero) vector count", () => {
  const dir = cleanRoom();
  try {
    const r = spawnSync("node", ["sohopay-signer.mjs", "verify-vectors", "--output", "json"], {
      cwd: dir, encoding: "utf8",
    });
    assert.equal(r.status, 0, r.stderr);
    const s = JSON.parse(r.stdout);
    assert.ok(s.total > 0 && s.failed === 0, `unexpected summary ${r.stdout}`);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("direct exec (shebang) works", () => {
  const dir = cleanRoom();
  try {
    const r = spawnSync("./sohopay-signer.mjs", ["capabilities"], { cwd: dir, encoding: "utf8" });
    assert.equal(r.status, 0, r.stderr);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("symlink named 'sohopay-signer' on PATH resolves (SP5 route 2)", () => {
  const dir = cleanRoom();
  try {
    symlinkSync(join(dir, "sohopay-signer.mjs"), join(dir, "sohopay-signer"));
    const r = spawnSync("sohopay-signer", ["capabilities"], {
      cwd: dir, encoding: "utf8", env: { ...process.env, PATH: `${dir}:${process.env.PATH}` },
    });
    assert.equal(r.status, 0, r.stderr);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("extensionless COPY (not symlink) fails loudly, not oddly", () => {
  const dir = cleanRoom();
  try {
    cpSync(join(dir, "sohopay-signer.mjs"), join(dir, "sohopay-signer")); // real copy, no .mjs
    const r = spawnSync("node", ["sohopay-signer", "capabilities"], { cwd: dir, encoding: "utf8" });
    assert.notEqual(r.status, 0, "extensionless copy must fail");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("capabilities is semantically identical between source and bundle", () => {
  const src = spawnSync("node", ["--import", "tsx", "src/cli/index.ts", "capabilities", "--output", "json"], { encoding: "utf8" });
  const bnd = spawnSync("node", [BUNDLE, "capabilities", "--output", "json"], { encoding: "utf8" });
  assert.equal(src.status, 0); assert.equal(bnd.status, 0);
  assert.deepStrictEqual(JSON.parse(bnd.stdout), JSON.parse(src.stdout));
});
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `node --import tsx --test test/bundle-behavior.test.ts`
Expected: FAIL if the bundle has a real defect (or before Task 4's build exists). These are the acceptance tests.

- [ ] **Step 3: Make them pass**

Resolve any failure in `scripts/bundle.mjs` / the shim / the entry — **not** in the test. Re-run until green.

- [ ] **Step 4: Run the test**

Run: `node --import tsx --test test/bundle-behavior.test.ts`
Expected: PASS — all behavior + parity assertions green.

- [ ] **Step 5: Commit**

```bash
git add test/bundle-behavior.test.ts
git commit -m "test(bundle): clean-room, invocation forms, and capabilities parity for the bundle"
```

---

### Task 7: CI — build, clean-room (network-off), Node matrix, full-suite parity, reproducibility

**Files:**
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: `npm run bundle`, `SOHOPAY_SIGNER_BIN` (Task 5), the bundle tests (Tasks 4/6).

- [ ] **Step 1: Add a bundle matrix job to `ci.yml`**

Append (keep the existing `build-test` job unchanged):

```yaml
  bundle:
    name: bundle (node ${{ matrix.node }})
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        node: [18, 22] # floor + current LTS
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: ${{ matrix.node }}
          cache: npm
          registry-url: https://npm.pkg.github.com
          scope: "@sohopay"
      - run: npm ci
        env:
          NODE_AUTH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      - name: Build bundle
        run: npm run bundle
      - name: Bundle build + shim + behavior tests
        run: node --import tsx --test test/bundle-build.test.ts test/bundle-vectors-shim.test.ts test/bundle-behavior.test.ts
      - name: Full CLI suite against the bundle (parity)
        run: SOHOPAY_SIGNER_BIN="$PWD/dist-bundle/sohopay-signer.mjs" node --import tsx --test test/cli-capabilities.test.ts test/cli-pop.test.ts test/cli-readonly.test.ts test/cli-verify-vectors.test.ts test/cli-voucher-envelope.test.ts test/cli-voucher.test.ts
      - name: Clean-room with NO node_modules and NO network
        run: |
          set -euo pipefail
          work="$(mktemp -d)"
          cp dist-bundle/sohopay-signer.mjs "$work/"
          ( cd "$work" && unshare -rn node sohopay-signer.mjs capabilities --output json )
          ( cd "$work" && unshare -rn node sohopay-signer.mjs verify-vectors --output json )
      - name: Reproducibility (two clean dirs, byte-identical)
        run: |
          set -euo pipefail
          a="$(mktemp -d)"; b="$(mktemp -d)"
          SOHOPAY_BUNDLE_OUTDIR="$a" node scripts/bundle.mjs
          SOHOPAY_BUNDLE_OUTDIR="$b" node scripts/bundle.mjs
          diff "$a/sohopay-signer.mjs" "$b/sohopay-signer.mjs"
          ( cd "$a" && sha256sum -c sohopay-signer.mjs.sha256 )
```

(If `unshare -rn` is unavailable on the runner image, use `sudo unshare -n` or a `--network none` container step; the invariant is a clean-room run with no `node_modules` and no network.)

- [ ] **Step 2: Add the Node-16 floor negative (separate job)**

```yaml
  node-floor:
    name: node-16 floor guard
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
          cache: npm
          registry-url: https://npm.pkg.github.com
          scope: "@sohopay"
      - run: npm ci
        env:
          NODE_AUTH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      - run: npm run bundle
      - uses: actions/setup-node@v4
        with:
          node-version: 16
      - name: bundle refuses Node 16 with a coded error
        run: |
          set +e
          out="$(node dist-bundle/sohopay-signer.mjs capabilities 2>&1)"; code=$?
          set -e
          echo "$out"
          test "$code" -ne 0
          echo "$out" | grep -q "NODE_VERSION_UNSUPPORTED"
```

- [ ] **Step 3: Validate the workflow**

Run (locally): `actionlint .github/workflows/ci.yml` if available; otherwise re-run the exact shell blocks locally (Tasks 4/6 already prove `npm run bundle`, the clean-room, parity, and reproducibility commands succeed on Node ≥ 18; reproduce the Node-16 block with an nvm Node 16 if available).
Expected: no lint errors; local command blocks behave as the YAML asserts.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: build bundle, clean-room (no node_modules/no network), node matrix, parity, reproducibility"
```

---

### Task 8: Release workflow — `release-bundle.yml` with attestation

**Files:**
- Create: `.github/workflows/release-bundle.yml`

**Interfaces:**
- Consumes: `npm run bundle`, the bundle tests; the `js-bundle-v<version>` tag.

- [ ] **Step 1: Create the workflow**

```yaml
name: Release bundle

on:
  push:
    tags: ["js-bundle-v*"]
  workflow_dispatch:
    inputs:
      tag:
        description: "js-bundle-v<version> tag to release"
        required: true

permissions:
  contents: write
  id-token: write
  attestations: write

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
          cache: npm
          registry-url: https://npm.pkg.github.com
          scope: "@sohopay"
      - run: npm ci
        env:
          NODE_AUTH_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - name: Assert built version == tag version
        run: |
          set -euo pipefail
          ref="${{ github.event.inputs.tag || github.ref_name }}"
          tag_version="${ref#js-bundle-v}"
          pkg_version="$(node -p "require('./package.json').version")"
          echo "tag=$tag_version pkg=$pkg_version"
          test "$tag_version" = "$pkg_version"

      - name: Build + verify bundle
        run: |
          npm run bundle
          node --import tsx --test test/bundle-build.test.ts test/bundle-behavior.test.ts

      - name: Cross-runner reproducibility (compare to a second clean build)
        run: |
          set -euo pipefail
          other="$(mktemp -d)"
          SOHOPAY_BUNDLE_OUTDIR="$other" node scripts/bundle.mjs
          diff dist-bundle/sohopay-signer.mjs "$other/sohopay-signer.mjs"

      - name: Attest build provenance
        uses: actions/attest-build-provenance@v1
        with:
          subject-path: dist-bundle/sohopay-signer.mjs

      - name: Create release with assets
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          ref="${{ github.event.inputs.tag || github.ref_name }}"
          gh release create "$ref" \
            dist-bundle/sohopay-signer.mjs \
            dist-bundle/sohopay-signer.mjs.sha256 \
            dist-bundle/sohopay-signer.mjs.LEGAL.txt \
            --title "$ref" \
            --notes "Portable bundled JS signer ($ref). Verify: gh attestation verify sohopay-signer.mjs --repo sohopay/sohopay-agent-signer"
```

- [ ] **Step 2: Validate the workflow**

Run (locally): `actionlint .github/workflows/release-bundle.yml` if available; dry-check the version-assert and build blocks by running their shell locally with `ref="js-bundle-v$(node -p "require('./package.json').version")"`.
Expected: no lint errors; the version-assert passes when the tag matches `package.json`, and fails on a mismatched tag.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/release-bundle.yml
git commit -m "ci(release): tag-driven bundle release with build-provenance attestation and version/repro gates"
```

---

### Task 9: README install doc + public-repo & hardening notes

**Files:**
- Modify: `README.md`

**Interfaces:** none (documentation).

- [ ] **Step 1: Add the install section to `README.md`**

```markdown
## Install-free bundle (no npm registry required)

A single self-contained `sohopay-signer.mjs` runs on any host with Node >= 18 — no
`node_modules`, no network. Download it from the matching `js-bundle-v<version>` GitHub
Release, **verify**, then point `$SOHOPAY_SIGNER` at it.

1. Download the exact version you want (never `latest`):

       V=0.2.0   # the js-bundle-v<version> you intend to run
       gh release download "js-bundle-v$V" --repo sohopay/sohopay-agent-signer \
         --pattern 'sohopay-signer.mjs' --pattern 'sohopay-signer.mjs.sha256'

2. Verify. **Online (preferred)** — ties the file to the build workflow + commit:

       gh attestation verify sohopay-signer.mjs --repo sohopay/sohopay-agent-signer

   **Offline / air-gapped** — compare against the expected hash for that exact version
   published in the table below (updated per release), NOT only the downloaded `.sha256`
   (a compromised release could swap both files):

       sha256sum sohopay-signer.mjs   # compare to the table below

3. Install:

       chmod +x sohopay-signer.mjs
       export SOHOPAY_SIGNER="$PWD/sohopay-signer.mjs"
       sohopay-signer capabilities    # expect signer_protocol: sohopay-signer/1
       sohopay-signer verify-vectors  # expect exit 0

### Expected hashes (trust anchor, out-of-release)

| Version | sha256 of `sohopay-signer.mjs` |
|---------|--------------------------------|
| _(add a row per release)_ | _(the hash from the release build)_ |
```

- [ ] **Step 2: Add the maintainer notes**

Add a short "Releasing the bundle" subsection: the repo is **public** (required for token-free asset download + `gh attestation verify`); cut a release by tagging `js-bundle-v<version>` where `<version>` equals `package.json`; **immutable releases** and `js-bundle-v*` **tag protection** are enabled so a published asset cannot be replaced; after a release, add the new row to the Expected-hashes table on `main`.

- [ ] **Step 3: Verify the doc**

Run: `npx tsc --noEmit && npm test` (doc-only change must not break anything); eyeball the rendered Markdown.
Expected: PASS; the install block reads correctly.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs(readme): install-free bundle verification + release/hardening notes"
```

---

## Notes for the executor

- **Prerequisite outside this plan:** making the repo public and enabling immutable releases / `js-bundle-v*` tag protection are human/ops actions in GitHub settings — the release workflow assumes them but no task can perform them. Surface this at finish.
- **Order matters for Task 4:** it depends on Tasks 1–3 (version `define`, Node-floor entry restructure, vectors shim) to produce a correct bundle; and Tasks 6/7/8 depend on Task 4's `npm run bundle`.
- **Fix code, not tests:** the Task 6 behavior tests are the acceptance surface; a failure there is a real gap, not a test to relax.
