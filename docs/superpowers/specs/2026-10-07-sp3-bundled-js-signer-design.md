# SP3 — Portable Bundled JS Signer — Design

Status: approved in brainstorming 2026-10-07. Part of the **SohoPay Portable Agent
Signing** epic (`docs/superpowers/specs/2026-10-06-portable-agent-signing-design.md`).
Depends on SP2 (node CLI) + Amendment A (shipped, `@sohopay/agent-signer@0.2.0`,
merged to `develop`). Consumed by SP5 routing (shipped) and, later, SP5-complete.

## The invariant

**One implementation → two packaging forms.** Not "npm signer + portable signer." SP3
adds a *packaging* path alongside the existing `tsc → dist/` path; the CLI source, the
command surface, the signer contract, and the crypto are untouched. The bundle is the
same code built from the same `src/cli/index.ts` entrypoint — there is no parallel CLI
implementation. This framing governs every section below: anything that would make the
bundle behave differently from the npm CLI is a defect, not a feature.

## Goal

Remove the resolution cliff in SP5 routing. SP5 resolves a signer via
`$SOHOPAY_SIGNER → sohopay-signer on PATH → npx @sohopay/agent-signer`. The first two
require a signer already installed; the `npx` fallback needs npm, a reachable registry,
and read access to the private `@sohopay` scope. On a host with Node but no registry
access, **nothing resolves → `SIGNER_UNAVAILABLE`**, and every V2 pay fails closed.

SP3 produces a single self-contained `sohopay-signer.mjs` that runs on bare
`node sohopay-signer.mjs …` — every dependency (`@noble/curves`, `@noble/hashes`,
`canonicalize`, **and** the `@sohopay/signer-vectors` JSON) inlined, no `node_modules`,
no network. A host drops one file, points `$SOHOPAY_SIGNER` at it (or symlinks it onto
`PATH`), and SP5 routing resolves it unchanged.

**Definition of done.** `npm run bundle` produces the executable `.mjs` plus a
conventional `.sha256` (and a license-notices file), from a clean checkout,
reproducibly, with **no runtime dependency on `node_modules`**, preserving the same CLI
and vector semantics as the normal `dist/` build.

## Prerequisite — repository visibility

The `sohopay-agent-signer` repo **must be public** before the release channel works.
Because the npm package stays `private`, the GitHub Release asset is the primary JS
distribution; a private repo would gate the asset (and `gh attestation verify`) behind a
GitHub token, which reintroduces exactly the cliff SP3 removes. Making the repo public is
safe: the signer holds **no secrets and no keys** — it is deterministic crypto routing
that signs with a key the caller supplies by path. Publishing the code is an org decision,
taken (2026-10-07). The release workflow and the install doc both assume public
visibility.

---

## Architecture

- **Output:** a single file `dist-bundle/sohopay-signer.mjs` — ESM, `platform=node`,
  built by **esbuild** from `src/cli/index.ts`, everything inlined. `dist-bundle/` is a
  **separate, git-ignored** directory, never confused with the package build output
  `dist/`.
- **Shebang + exec bit:** esbuild banner `#!/usr/bin/env node`; output `chmod 0755`. Both
  SP5 routes then work from one file:
  - `$SOHOPAY_SIGNER="/abs/path/sohopay-signer.mjs"` (direct exec, route 1), **and**
  - a symlink `sohopay-signer → /abs/path/sohopay-signer.mjs` on `PATH` (route 2); Node's
    default realpath resolution sees the `.mjs` target, so ESM loads correctly.
- **Identity is deliberately identical** to the npm CLI: `capabilities` reports
  `signer_protocol: "sohopay-signer/1"`, `implementation: "@sohopay/agent-signer"`, and
  the **same** `implementation_version` (from `package.json`, injected at build). SP5's
  existing `implementation_version >= 0.2.0` gate therefore applies to the bundle with
  **zero SP5 change**.
- **Runtime floor:** Node `>= 18` (matches `engines`). Documented, and enforced by a
  minimal runtime floor guard (below) that fails cleanly — not "version negotiation."

### Runtime Node-floor guard (new, minimal)

There is no runtime Node check today. SP3 adds one at the very top of the CLI entry,
written in syntax safe on Node ≥ 14, that runs before any Node-18-only API: if
`process.versions.node`'s major is `< 18`, write a coded error to stderr
(`{"error":{"code":"NODE_VERSION_UNSUPPORTED","message":"sohopay-signer requires Node >= 18"}}`)
and exit non-zero. This gives a clear coded failure on an old runtime instead of a
cryptic crash, and both packaging forms get it (it is in the shared entry). This is a
clean floor guard, not runtime version negotiation.

---

## Components & the build

- **New devDep:** `esbuild`, pinned exact.
- **Build script:** `scripts/bundle.mjs` — the esbuild **JS API** (not the CLI) for
  control over `define`, `alias`, banner, and post-write steps.
- **npm script:** `"bundle": "node scripts/bundle.mjs"`.
- **Output:** `dist-bundle/sohopay-signer.mjs`, `dist-bundle/sohopay-signer.mjs.sha256`,
  `dist-bundle/sohopay-signer.mjs.LEGAL.txt`.

`scripts/bundle.mjs`:

- entry `src/cli/index.ts`; `format:"esm"`, `platform:"node"`, `bundle:true`,
  `target:"node18"`, `banner:{js:"#!/usr/bin/env node"}`, `sourcemap:false`,
  `legalComments:"external"` (writes `*.LEGAL.txt` — license notices MUST survive;
  see below).
- **Version injection:** read `package.json`; **assert `version` is a non-empty string,
  else throw and fail the build**; `define:{ __SIGNER_IMPL_VERSION__: JSON.stringify(version) }`.
- **Vector inlining:** `alias:{ "@sohopay/signer-vectors": <bundle vectors shim> }`.
- Post-write: `chmod 0755` the `.mjs`; compute SHA-256; write the checksum file in the
  conventional `sha256sum`-compatible format (below).

### Two source tweaks (shared by both forms — the invariant holds)

1. **`implementationVersion()`** (currently reads `../../package.json` relative to the
   module, with a silent `?? "0.0.0"` fallback — which breaks in a bundle where that path
   does not exist). Change to: prefer an injected constant, else read `package.json`, and
   **throw** if the version is unresolved. Declare the injected global explicitly so
   `tsc` and editors stay clean:

   ```ts
   declare const __SIGNER_IMPL_VERSION__: string | undefined; // ambient; esbuild define replaces in the bundle
   ```

   The `dist/` path keeps the `package.json` read; the bundle path uses the injected
   literal. Neither form can emit `"0.0.0"` or `"unknown"` — an unresolved version is a
   hard failure in both.

2. **Vectors shim** (bundle-only). `@sohopay/signer-vectors`'s `loadVectors()` does a
   runtime `readFileSync` of a path relative to its own `dist` — esbuild cannot see
   through it, so the bundle would break offline. The shim is **as thin as possible**: it
   statically `import`s the same `vectors/index.json` payload the package exposes and
   implements **only** the runtime export surface the signer consumes (`loadVectors`). It
   is not a second vector-loader implementation. esbuild embeds the JSON into the output.
   The `dist/` path is untouched — it still uses the real `@sohopay/signer-vectors`.

### Checksum file format

Conventional, so operators verify with stock tooling (`sha256sum -c`), no custom parsing:

```text
<sha256>  sohopay-signer.mjs
```

(two spaces between hash and filename).

### License notices

`legalComments:"external"` emits `sohopay-signer.mjs.LEGAL.txt` carrying the bundled
dependencies' license headers (`@noble/*`, `canonicalize`, …). This file is attached to
the release, and a test asserts it contains the expected headers — so a future esbuild
config change cannot silently strip notices.

### Determinism / reproducibility

Pinned esbuild, no sourcemap, fixed banner, external (not inline-interleaved) legal
comments, no timestamps / absolute paths / environment-specific metadata embedded. Proven
by building **twice into two separate clean directories** and diffing the two `.mjs` for
byte-identity (not rebuilding over the same output, which could hide a dependency on prior
output or filesystem state).

---

## CI, release & testing

### CI (extend `.github/workflows/ci.yml`, same hosted-ubuntu job, after `npm ci → tsc → build → test`)

- `npm run bundle`.
- **Clean-room self-containment (load-bearing):** copy *only* `sohopay-signer.mjs` into a
  fresh temp dir with **no `node_modules`**, then run `capabilities`, `verify-vectors`,
  `voucher sign --envelope`, and `pop sign` there. Passing with no deps present is the
  proof of "install-free."
- **Network-free, mechanically:** run the clean-room steps under `unshare -n` (or a
  `--network none` container). The signer makes no network calls; a no-network run turns
  "by construction" into an enforced invariant the security model can lean on.
- **Node matrix for the clean room:** Node **18** (the floor) and **current LTS**, both
  green. Plus a **Node 16 negative case** asserting the runtime floor guard exits non-zero
  with `NODE_VERSION_UNSUPPORTED`.
- **Invocation forms SP5 actually uses:**
  - `node sohopay-signer.mjs capabilities` (route 1, `node <file>`),
  - direct `./sohopay-signer.mjs capabilities` (shebang + `0755`),
  - a **symlink named `sohopay-signer` on `PATH`** → `capabilities` (route 2),
  - a **copy to an extensionless name** (`sohopay-signer`, no `.mjs`, not a symlink) must
    **fail loudly** (clear error), not behave oddly — Node treats an extensionless file as
    CommonJS and the ESM bundle must error clearly. The supported forms (`.mjs` name, or a
    symlink to it) are documented; the unsupported copy is a tested loud failure.
- **Full-suite parity, not reduced:** the SP2 subprocess CLI tests gain a
  `SOHOPAY_SIGNER_BIN` env (default `node dist/cli/index.js`); a second CI pass sets it to
  `node dist-bundle/sohopay-signer.mjs` and runs the **same** suite. The bundle gets the
  full suite, never a subset.
- **Semantic parity checks:** `capabilities` JSON (`signer_protocol`, `implementation`,
  `implementation_version`, `algorithms`, `commands`) equal across both forms; and
  `verify-vectors` sees identical vector **IDs / count / content** through both loaders
  (real package vs shim).
- **Reproducibility:** build twice into two separate clean dirs, diff `.mjs` → identical;
  confirm `.sha256` matches; `sha256sum -c` the checksum file.

### Release (`js-bundle-v<version>` tag; version mirrors `package.json`; human-dispatched)

Matches the signer-vectors publish-by-tag pattern. `.github/workflows/release-bundle.yml`,
**least-privilege permissions** (`contents: write`, `id-token: write`,
`attestations: write`, nothing else):

- checkout the tag → `npm ci` → `npm run bundle` → **assert built version == tag version**
  (fail on drift) → re-run the clean-room + parity gate (never release an unverified
  artifact).
- **Build-provenance attestation:** `actions/attest-build-provenance` over
  `sohopay-signer.mjs`, tying the asset to the workflow and commit.
- Create the GitHub Release attaching `sohopay-signer.mjs`, `sohopay-signer.mjs.sha256`,
  and `sohopay-signer.mjs.LEGAL.txt`.
- **Cross-runner reproducibility evidence (SHOULD):** compare the release-built SHA-256 to
  a CI build of the same commit; mismatch fails the release.

`js-bundle-v*` is distinct from any future `js-v*` / `py-v*` tags; the npm package stays
`private`, so the bundle release is the primary JS distribution.

**Release hardening (SHOULD):** enable immutable releases and protect `js-bundle-v*` tags,
so a published asset cannot be replaced after the fact.

### Install doc (the Scope-A deliverable, in `README.md`)

Pin an **exact version** in every command — never `latest`. Verify order:

1. **Online (preferred):**
   `gh attestation verify sohopay-signer.mjs --repo sohopay/sohopay-agent-signer` — ties
   the file to the workflow + commit.
2. **Offline / air-gapped:** compare the file's SHA-256 against the **expected hash for
   that exact version, published outside the release** — the `README` on `main`, updated
   per release (and later pinned in the SP5-complete skill). The downloaded `.sha256` is a
   **convenience against corruption, not the trust anchor** (a compromised release could
   swap both files).
3. Then `chmod +x sohopay-signer.mjs` → `export SOHOPAY_SIGNER=/abs/path/sohopay-signer.mjs`
   → confirm with `sohopay-signer capabilities` and `verify-vectors`.

---

## Scope boundary

**In SP3:** the esbuild bundle + build script, the two source tweaks, the runtime
floor guard, the CI parity/clean-room/network-free/matrix tests, the tag-driven release
workflow with attestation, and the README install doc. The repo goes public.

**Not in SP3 (SP5-complete):** skill-driven auto-fetch of the bundle, pinning the
expected hash inside a skill, and wiring `$SOHOPAY_SIGNER` from a skill. SP3 leaves a
clean seam: a verified artifact at a stable URL plus a documented manual install. The
signer stays **network-free** — no download path is added *into* the signer.

## Out of scope

- A no-Node native/standalone binary (SEA / `pkg` / `bun compile`). "Bundled JS" means
  Node remains the runtime.
- Any change to the signer contract, commands, crypto, or the `dist/` package path beyond
  the two shared tweaks above.
- Python (SP4) and the multi-host eval runner (SP6).
