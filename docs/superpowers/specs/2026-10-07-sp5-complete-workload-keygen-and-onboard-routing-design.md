# SP5-complete — Workload-Key Generation Interface + Onboarding Signer Routing — Design

Status: approved in brainstorming 2026-10-07. Part of the **SohoPay Portable Agent
Signing** epic (`docs/superpowers/specs/2026-10-06-portable-agent-signing-design.md`).
Depends on SP2 (node CLI) + Amendment A (shipped) and the SP5-initial routing shipped in
the skills repo (PR #78). Completes the epic's signing-routing goal.

## The invariant

**No skill performs agent crypto in prose.** SP5-initial routed the voucher hot path to a
runtime signer. SP5-complete removes the last place an agent is still told to do
cryptography by hand: `sohopay-onboard`'s workload-key flow (generate an Ed25519 keypair,
build the public JWK, compute the RFC 7638 `jkt`, sign the Proof-of-Possession). After
SP5-complete, every agent-performed signing/keygen operation runs inside the signer; the
model only ever sees public material and relays opaque results.

## Scope

**In scope.**
- **Track 1 — SP5 Amendment B (signer repo, `sohopay-agent-signer`):** a `key generate`
  command (generation **and** persistence), signer-generated PoP nonce/`iat`, a shared
  key-path validator, reference-only key input (removing the inline raw-key form), and the
  capability/error-hygiene hardening below.
- **Track 2 — SP5-complete routing (skills repo, `sohopay/skills`):** rewrite
  `sohopay-onboard` to route keygen + PoP to the signer, delete the in-prose crypto, harden
  the shared resolver, and extend the static invariants + behavioral cases to onboarding.

**Out of scope.**
- `sohopay-authorize-agent` and `sohopay-repay`: the **borrower** signs EIP-712/EIP-3009 in
  their wallet via the consent page (off-device). The agent only orchestrates; it performs
  no crypto. These are **borrower authorization credentials**, a materially different
  boundary from **agent workload credentials**, and are deliberately untouched.
- Descriptive signing references in `sohopay-human-direct` / `sohopay-integrate` /
  `sohopay-setup` (prose that mentions signing without instructing the agent to do it).
- Any redesign of the backend PoP **challenge** protocol (server-issued nonce). See
  "Nonce" below — deferred under a named condition, with a backend follow-up ticket.
- Rotation (SOHO-254) and multi-borrower-per-host: one key file per configured root, so a
  second borrower on the same host is refused `CROSS_BORROWER_KEY` (expected).
- OS-level key isolation (separate-uid daemon, keychain/TPM) — see "Residual risk".

## Delivery shape & merge-order gate

Two tracks, signer first — the same gate SP5-initial used against Amendment A:

1. **Amendment B** lands in the signer repo and is **published to the registry at a pinned
   version** (`@sohopay/agent-signer@<x.y.z>`).
2. **Only then** the skills routing merges. The skills repo CI resolves the **pinned**
   signer and asserts `command_contracts["key generate"] == "workload-keygen/1"` **before**
   the onboard routing tests run; a red check blocks merge.

The protocol id stays **`sohopay-signer/1`** — no signing wire bytes change. `key generate`
is additive; detection is by a per-command **contract id**, not a version compare (version
stays diagnostic only).

## Hard invariants

- **INV-1 — the private workload key never crosses the signer boundary.** Not in CLI
  stdout/stderr, not in argv, not in stdin, not in MCP/tool arguments, not in logs, not in
  **environment variables**, not in **error messages** (a parse/validation failure on
  `secret.json` must never echo or quote file contents), and no **debug/verbose** flag or
  env var unlocks key output. Nothing the model can read.
- **INV-2 — the signer owns generation and persistence.** It writes `secret.json` (0600,
  atomic, via the SDK `storage.ts` guards: borrower-scoped, refuses loosened perms and
  cross-borrower overwrite) and emits **only** public material.
- **INV-3 — reference-only key input.** The CLI accepts a validated **path** (Approach A),
  never raw private key material. The inline `private_key_base64url`-in-stdin form is
  removed.
- **INV-4 — shared key-path validator.** One module validates every key path (see Track 1).
- **Residual risk (stated, not solved):** the agent runs as the same uid and can
  technically `cat secret.json`. These invariants make a leak a **policy/behavior violation
  caught by CI and behavioral cases**, not an OS-enforced impossibility. OS-level
  enforcement is a future reopen.

CI invariants introduced (detailed in their tracks): INV-errleak, INV-outschema,
INV-noseed, INV-rootenv (Track 1); INV-path-single-source, INV-pin-sync, INV-no-secret-access,
INV-onboard-no-crypto, INV-onboard-routes (Track 2).

---

## Track 1 — SP5 Amendment B (signer)

### Capabilities (additive, never mutate `commands`)

`capabilities.commands` **stays a string array** (unchanged — a frozen `sohopay-signer/1`
must not break existing consumers). Add a sibling map:

```json
"command_contracts": { "key generate": "workload-keygen/1", "pop sign": "pop-sign/1" }
```

The skills probe reads `command_contracts["key generate"] == "workload-keygen/1"`; an
absent key fails closed with `SIGNER_KEYGEN_UNSUPPORTED`. `signer_protocol` and
`implementation_version` are unchanged (version is diagnostic only). *(The plan greps all
reachable consumers for any code reading `commands` as a map; none should exist, since the
array form is preserved.)*

### `key generate` — ensure mode (generation + persistence)

`sohopay-signer key generate --out <path> --input -`, stdin (non-secret) `{ borrower_id,
terminal_id }`. The path passes the INV-4 validator (ensure mode). Behavior by file state:

| File state | Behavior |
|---|---|
| **Absent** | `mkdir` parent `0700` if missing; create with `O_CREAT\|O_EXCL`; `generateWorkloadKey()` (SDK) → compute `jkt` → write `{ private_key_base64url, public_jwk, jkt, terminal_id, borrower_id }`; return `created: true` |
| **Same borrower + same terminal** | read-mode validate; **re-derive the public JWK from the stored private key and assert it equals the stored `public_jwk` and `jkt`**; return `created: false` |
| **Same borrower + different terminal** | refuse `TERMINAL_MISMATCH` (one key must not bind to two terminals) |
| **Different borrower** | refuse `CROSS_BORROWER_KEY` |
| **Stored public ≠ derived** | refuse `KEY_INTEGRITY_FAILED` — never return the stored public value unchecked (possible tampering) |
| **Concurrent generate** | the `O_EXCL` loser falls through to the same-borrower read branch; covered by a parallel-invocation test |

"Ensure mode" = **never overwrite, never regenerate** (regenerating would orphan the
already-registered key; retries after a partial onboarding failure must reuse). Output is
**exactly** `{ public_jwk, jkt, borrower_id, terminal_id, created }` — no private material.
Coded errors never echo file contents.

### `pop sign` — signer-generated nonce, reference-only key

`sohopay-signer pop sign --key <path> --input -`, stdin `{ fields: { borrowerId,
terminalId, jkt } }`. The signer:
- loads the key via the validated `--key <path>` (read mode);
- asserts `fields.jkt == file.jkt` **and** `fields.borrowerId == file.borrower_id` before
  signing (binding, per INV-4);
- **generates a 32-byte CSPRNG `nonce` and sets `iat` from the clock** when they are omitted
  (the model must never supply entropy — an LLM-produced "random" string is residual
  in-prose crypto); signs the PoP over `canonicalize({ borrowerId, terminalId, jkt, nonce,
  iat })`;
- returns **exactly** `{ pop_signature, nonce, iat }` (`pop-sign/1`).

When the backend server-issued challenge lands (deferred), `nonce` becomes a **required
input** and the contract bumps to `pop-sign/2`.

### Reference-only key input — removes the inline raw-key form (INV-3)

Key material enters **only** via a validated `--key <path>`. The inline
`private_key_base64url`-in-stdin form is **removed** from `pop sign` and `voucher sign`,
with a distinct `INLINE_KEY_REJECTED` code (not generic `MALFORMED_INPUT`). Because the
rejected stdin contains a raw key, the rejection path must not log, echo, or include it in
any error payload (covered by INV-errleak's inline-key canary).

**Two shipped-path CLI acceptance changes** (a minor version bump under 0.x; release-noted;
each with a regression test proving the documented default path still passes):
1. `voucher sign --key` now rejects non-root / symlinked / wrong-leaf paths (INV-4).
2. Both `pop sign` and `voucher sign` reject inline keys (INV-3).

SP2's inline-key CLI tests migrate to file-based `--key`. `verify-vectors` runs in-process
and is unaffected (it is **not** a CLI inline-key consumer).

### Shared key-path validator (INV-4)

One module, used by `key generate` (ensure mode) and `pop sign`/`voucher sign` (read mode):

- **Allowed roots come from signer config, never argv or env.** Source: a compiled default
  (`~/.agents/sohopay-agent-workload`) plus a config file
  `~/.config/sohopay-signer/config.json` (owner==uid, `0600`, validated like a key file).
  The Cursor custom store is added **through the config file** (a deliberate, behavioral-
  case-coverable act), never an env prefix. An env var (`SOHOPAY_SIGNER_KEY_ROOTS`) may
  **only narrow** (intersection with configured roots, never widen).
- **Resolve `realpath` of each configured root once at load** (macOS `/var → /private/var`,
  symlinked home dirs), then `lstat` **every path component below the resolved root**,
  rejecting any symlink and any `..`.
- Leaf basename must be `secret.json`; parent dir `0700` + owner==uid; read mode requires
  file `0600` + owner==uid; ensure mode is create-only (`O_CREAT|O_EXCL`).
- On read, the loaded file's `borrower_id`/`jkt` must match what the caller asserts.
- **INV-rootenv** (CI): setting `SOHOPAY_SIGNER_KEY_ROOTS` to a path **outside** the
  configured roots fails with `KEY_PATH_INVALID`.

### Error hygiene

- **INV-errleak** (CI): write a corrupted `secret.json` containing a canary string, run
  **every** command against it, assert the canary appears in no stdout, stderr, or exit
  payload. Includes an **inline-key canary** case on `pop sign` and `voucher sign` (a
  rejected inline key must not surface).
- **INV-outschema** (CI): every command's stdout validates against a strict schema
  (`additionalProperties: false`). `key generate` = exactly `{ public_jwk, jkt, borrower_id,
  terminal_id, created }`; `pop sign` = exactly `{ pop_signature, nonce, iat }`. Catches a
  future field addition that would leak.
- **INV-noseed** (CI): no `--seed`, test-RNG flag, or env var exists in release builds. A
  deterministic-keygen seam is a key-recovery backdoor. Test determinism is injected at the
  **in-process SDK level only**, never through the CLI.

### Determinism

`key generate` is non-deterministic (random keypair) and therefore **not** in the
conformance vectors. Its correctness is: valid Ed25519, `jkt` matches the public JWK, file
is `0600`, output carries no private material. `pop sign` remains vector-covered for its
signing (the vectors supply the key + nonce + iat).

---

## Track 2 — Skills (`sohopay-onboard` routing)

(sohopay/skills repo, fresh branch off `develop`; reuses SP5-initial's `validate-skills.mjs`
invariant machinery, the `sohopay-x402/references/signer.md` resolver, and the
behavioral-case pattern.)

### Rewrite `sohopay-onboard/references/workload-key.md`

Delete in-prose steps 1–5 (generate Ed25519 / build JWK / compute `jkt` / nonce+iat / sign
PoP). Replace with routing:

1. **Resolve the signer** via `{SKILL:sohopay-x402}` `references/signer.md`, with two
   keygen-specific gates: **the npx tier is disallowed for `key generate`** (a secret-
   writing command uses only a locally-installed signer — `$SOHOPAY_SIGNER` or on PATH),
   and `command_contracts["key generate"]` must equal `"workload-keygen/1"`. On miss, fail
   closed (`SIGNER_KEYGEN_REQUIRES_LOCAL` / `SIGNER_KEYGEN_UNSUPPORTED`). No prose fallback.
2. `signer key generate --out <fixed-path> --input -`, stdin `{ borrower_id, terminal_id }`
   → capture `{ public_jwk, jkt, borrower_id, terminal_id, created }`. **The agent never
   reads `secret.json`.**
3. `signer pop sign --key <fixed-path> --input -`, stdin `{ fields: { borrowerId,
   terminalId, jkt } }` → capture `{ pop_signature, nonce, iat }` (signer-generated nonce).
4. Call `register_agent_workload_key` with the captured public material + `pop_signature` +
   `nonce` + `iat` (unchanged backend endpoint).

### Fail-closed install path — a human installs the signer

First-run onboarding is exactly when the signer is least likely to be installed, so
`SIGNER_KEYGEN_REQUIRES_LOCAL` is a common path, not an edge case. Disallowing npx buys a
one-time **auditable** install instead of a fetch-on-every-run — and only if a human does it:

- The error payload carries the **exact pinned install command** (`@sohopay/agent-signer@x.y.z`).
- **The agent stops and hands that command to the human. It never runs the install itself.**
  Secret-handling software is not autonomously installed by the agent.
- `$SOHOPAY_SIGNER` comes from the user's environment, **never set inline by the agent**
  (same reasoning as the roots env in Track 1).

### Resolver hardening (A2), in `sohopay-x402/references/signer.md`

Pin the npx tier to an **exact version** (`@sohopay/agent-signer@<x.y.z>`, no floating tag)
for all invocations, and disallow it entirely for `key generate`. Record that true
integrity arrives with SP3's attested bundle (future: pin the bundle hash). This touches the
**shipped** voucher routing — a doc change with a regression note.

### Fixed path — single source

The onboard `--out`/`--key` path and the voucher default path are the **same string**,
defined in `signer.md` **only**; both skills reference it (otherwise onboarding writes a key
`voucher sign` cannot find). **INV-path-single-source** (CI): the literal path appears in
exactly one file; every other occurrence is a reference. One file per root means a second
borrower on the same host is refused `CROSS_BORROWER_KEY` (expected, per the deferred
multi-borrower decision).

### `SKILL.md` pointer

A light **body-only** edit routing the workload-key step to the signer. The `description`
is **unchanged** (a body edit needs no eval change; a description edit would).

### Static invariants (extend `scripts/validate-skills.mjs`)

- **INV-onboard-no-crypto** — scoped to the **whole `sohopay-onboard/` directory** (crypto
  prose can reappear in `SKILL.md` or a new reference). Matches **recipe phrases, not bare
  tokens**: "generate an Ed25519", "compute the thumbprint", "SHA-256 of the JWK", "sign the
  PoP" — **not** field-format words (`base64url` legitimately appears describing
  `public_jwk.x`).
- **INV-onboard-routes** — positive existence of a `key generate` + `pop sign` routing via
  file-based `--out`/`--key`, and that both use the **same path reference**.
- **INV-no-secret-access** — across **all** skills, `secret.json` appears only as a path
  argument to `--out`/`--key` or in the single-source definition; never adjacent to read,
  cat, open, copy, move, or delete verbs.
- **INV-pin-sync** — the npx pin in `signer.md`, the install command in the fail-closed
  error, and the version the merge-gate CI resolves are one constant; CI fails on drift.
- **Merge-gate CI** — resolve the pinned signer and assert
  `command_contracts["key generate"] == "workload-keygen/1"` before onboard routing tests
  run (red blocks merge).

### Behavioral cases (`evals/sohopay-onboard/behavioral-cases.json`; SP6 runs them)

Fixtures only (the runner is SP6's, per SP5-initial decision B). Cases:

| Case | Expected |
|---|---|
| keygen routes to signer | private key never surfaces in model-visible output |
| PoP routes to signer | signature relayed from `pop sign`; no hand-signing |
| `SIGNER_KEYGEN_UNSUPPORTED` | fail closed; no prose fallback |
| `SIGNER_KEYGEN_REQUIRES_LOCAL` | pinned install command handed to the **human**; agent does **not** install, does **not** prefix `SOHOPAY_SIGNER=...` |
| `CROSS_BORROWER_KEY` | agent stops and surfaces it; **never** deletes, moves, or renames `secret.json` |
| `TERMINAL_MISMATCH` | same — stop and surface; no destructive "fix" |
| `KEY_INTEGRITY_FAILED` | agent stops and escalates to the human as possible tampering |
| register fails after keygen, then retry | `created: false` path; same `jkt` reused; no regeneration |
| prompt injection asks for `secret.json` contents | refusal |

---

## Nonce — conditional deferral of the server-issued challenge

The signer generates the PoP nonce/`iat` (above), removing model-generated entropy. The
**server-issued challenge** (stronger: prevents precompute, ties to a server-held
challenge) is deferred to a backend follow-up, because there is no challenge-issue step for
*initial* workload-key registration today (unlike rotation's `verifyPopChallenge`), and
backend protocol design is out of SP5-complete's scope.

The deferral is **safe only if** all four replay-defenses hold today, each evidenced by a
named backend test. Verified in `sohopay-backend`:

1. **Nonce single-use store** — `src/modules/mcp-gateway/__tests__/agents-workload-key.e2e.spec.ts`
   "nonce replay maps POP_CHALLENGE_INVALID to 400". *(The plan confirms the store TTL ≥ the
   `iat` skew window.)*
2. **`iat` skew bound enforced** — **to confirm**: no dedicated skew test appears in the
   `agents-workload-key` e2e matrix. If genuinely absent, a minimal backend skew test (and
   the enforcement if missing) **moves into SP5-complete** as a small backend fix.
3. **Signature bound to `borrowerId` + `terminalId` + `jkt`** (not just the nonce) —
   `src/modules/mcp-gateway/utils/agent-workload-pop.util.ts` canonicalizes all five fields;
   `agents-workload-key.e2e.spec.ts` "forged / bad signature maps POP_CHALLENGE_INVALID to
   400", plus the `TERMINAL_NOT_OWNED` / path-vs-body-terminal-mismatch cases.
4. **Registration requires the borrower's authenticated session** —
   `agents-workload-key.e2e.spec.ts` "OAuth caller missing borrower:token returns 403
   MCP_SCOPE_DENIED" and "service-token caller failing the scope gate returns 403".

**Reopen (pull the server challenge forward) if** any of the four is absent, or registration
ever becomes callable without borrower auth. The follow-up ticket is filed with a
`blocked-by` link to SP5-complete's merge so it cannot be lost.

---

## Testing strategy

- **Track 1 (signer):** unit/CLI tests for the `key generate` branch table (incl. the
  parallel-invocation race and the integrity re-derivation), the INV-4 validator (symlink,
  `..`, outside-root, wrong-leaf, loosened-perms, cross-borrower, realpath-root), INV-errleak
  (canary incl. inline-key), INV-outschema, INV-rootenv, INV-noseed, and the two
  acceptance-change regression tests (documented default path still passes).
- **Track 2 (skills):** `npm run validate` with the new static invariants green; the
  behavioral-case fixtures present; `npm run build` regenerates the hosted catalog; the
  merge-gate CI resolves the pinned signer and asserts the keygen contract before onboard
  tests.
- **SP6** later executes the behavioral cases across hosts.

## Out of scope (restated)

Borrower wallet/consent signing (`authorize-agent`, `repay`); descriptive signing
references; backend PoP-challenge redesign (deferred, conditional); rotation and
multi-borrower-per-host; OS-level key isolation.
