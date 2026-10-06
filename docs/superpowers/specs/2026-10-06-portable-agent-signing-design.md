# Portable Agent Signing — Design (Epic + Phase 1: SP1 Contract, SP2 Node CLI)

Status: draft for review · 2026-10-06
Repos: `sohopay-agent-signer` (SP1–SP4), `sohopay/skills` (SP5–SP6)

## Problem

SohoPay Protocol V2 payments require an Ed25519 voucher signature and a PoP
signature over RFC 8785 (JCS) preimages. An LLM cannot compute these itself, so
today the agent skills instruct the model to "sign" via whatever ad-hoc execution
a host happens to have — brittle, host-specific, and the exact hand-rolled-crypto
problem we are eliminating. Agent hosts vary in execution capability: Node+npm
(Claude Code, Codex), a terminal possibly without npm (Cursor), a Python-only
sandbox (ChatGPT), or nothing.

## Goal

Make correct signing **portable**: define one normative signing contract, provide
runtime-specific *adapters* that all prove conformance against the same vectors,
and have skills **select** an available signer capability rather than implement
crypto. Where no executable capability exists, fail closed with
`SIGNER_UNAVAILABLE` — never fall back to prose crypto for V2.

## Principles

- **The contract is the center.** `@sohopay/agent-signer` defines canonical input,
  output, encoding, error taxonomy, key formats, and supported algorithms;
  `@sohopay/signer-vectors` is the normative interoperability contract. Runtimes
  are adapters around it.
- **Single source of truth.** Schemas, vectors, golden payloads, fixture
  generation, protocol semantics, and expected outputs are shared/generated from
  one source. Only the *crypto layer* is re-implemented per language.
- **Protocol version is independent of package version.** A signer advertises
  `sohopay-signer/1`; the npm, bundled-JS, Python, or future Rust implementations
  all speak `sohopay-signer/1` without impersonating the npm package.
- **Skills never do crypto.** They route to a capability; no prose signing for V2.

## Epic: SohoPay Portable Agent Signing

| ID | Sub-project | Repo | Notes |
|----|-------------|------|-------|
| SP1 | Signer interface & conformance contract | agent-signer | Formalize vectors, schemas, encoding, errors, protocol version, compatibility |
| SP2 | Node CLI signer | agent-signer | Canonical executable over the existing SDK (this phase) |
| SP3 | Portable bundled single-file JS | agent-signer | Install-free, same protocol, derived from the TS where possible |
| SP4 | Python signer | agent-signer `python/` | Independent crypto layer, vector-conformant; shares fixtures/vectors; separate `py-v*` tags |
| SP5 | Skill signer routing | skills | Remove recipe prose; capability-based selection |
| SP6 | Multi-host conformance evals | skills | Cryptographic equivalence + correct capability selection |

**Execution order:** SP1 → SP2 → SP5 (initial routing) → SP3 → SP4 → SP5 (complete) → SP6.
Each sub-project gets its own plan + implementation. This document specifies SP1
and SP2; later sub-projects get their own specs.

---

## SP1 — Signer interface & conformance contract

Formalizes what already exists (the `@sohopay/signer-vectors` known-answer set and
the SDK primitives) into a normative contract every implementation must satisfy.

### Protocol version

- Identifier: `sohopay-signer/1`.
- Any conformant executable, regardless of language/package, advertises this via
  `capabilities` (below) and stamps it into machine output as `signer_protocol`.
- Bumping the voucher domain tag or the canonicalization scheme is a new protocol
  version (`sohopay-signer/2`), not a patch.

### Canonical operations (the contract surface)

1. **voucher sign** — input `{ voucher, signing?, key }` → output `{ signer_protocol,
   payment_id, agent_key_jkt, signature, algorithm }`. Fail-closed guards
   (paymentId recompute, jkt match, signing-scheme allowlist, all-string voucher
   fields) per the SDK.
2. **payment-id** — input `{ core }` (9-field voucher core) → `{ payment_id }`.
3. **key jkt** — input `{ key | public_jwk }` → `{ agent_key_jkt }`.
4. **pop sign** — input `{ fields, key }` → `{ pop_signature }`. **In SP2**
   (onboarding needs it). Cross-domain non-interchangeability is required — see
   **Domain separation**.

### Encoding & formats (normative)

- JSON canonicalization: RFC 8785, `canonicalize@2.1.0` (pinned); voucher preimage
  is `utf8(tag) || 0x00 || JCS(value)`, PoP preimage is untagged `JCS(fields)`.
- `payment_id`: `0x`-prefixed keccak256 hex.
- Signatures / `jkt`: base64url. `agent_key_jkt`: RFC 7638 (SHA-256, base64url).
- Key file format: `{ private_key_base64url, public_jwk?, jkt?, terminal_id?,
  borrower_id? }` (the SDK's `StoredWorkloadKey`). A public JWK carrying `d` is
  rejected.
- Voucher core fields are all strings (no JSON numbers); PoP `iat` is the only
  numeric signed field (safe integer).

### Error taxonomy

The SDK's `SignerError` codes are normative, surfaced in machine mode as
`{ "error": { "code", "message" } }` on **stderr** with a non-zero exit:
`VOUCHER_FIELD_NOT_STRING`, `POP_IAT_NOT_INTEGER`, `SIGNING_SCHEME_NOT_ALLOWED`,
`PRIVATE_KEY_MATERIAL_REJECTED`, `INVALID_PUBLIC_JWK`, `PAYMENT_ID_MISMATCH`,
`AGENT_KEY_JKT_MISMATCH`, `MALFORMED_ENVELOPE`. Plus a routing-level
`SIGNER_UNAVAILABLE` (owned by SP5, not the CLI).

### Domain separation (voucher vs PoP)

A PoP signature must never verify as a voucher signature, nor vice versa — a hard
requirement, enforced in **both** directions by negative vectors
`neg-cross-replay-voucher-as-pop` and `neg-cross-replay-pop-as-voucher` (already in
`@sohopay/signer-vectors`).

Mechanism in `sohopay-signer/1` (matching the **deployed** backend verifier): the
voucher preimage is domain-tagged — `utf8("SohoPay:AgentPaymentVoucher:v2") ||
0x00 || JCS(...)` — while the PoP preimage is **untagged** `JCS({borrowerId,
terminalId, jkt, nonce, iat})` with a disjoint field set. Tag-vs-untagged plus
field-disjointness makes the two preimages unequal, so a signature over one can
never validate against the other.

Future hardening (NOT SP2): the PoP preimage is deliberately untagged and frozen
for deployed clients (SOHO-74). Giving PoP its own typed prefix would break the
backend `verifyPopChallenge` and every deployed signer, so symmetric typed
prefixes belong to a future `sohopay-signer/2` bump coordinated with the backend.
Until then, `sohopay-signer/1` MUST emit the untagged PoP, and cross-domain safety
is provided by the tag-asymmetry + field-disjointness above (vector-enforced both
ways).

### Conformance

An implementation is "SohoPay-compatible" only if it passes the full
`@sohopay/signer-vectors` set (all categories + negative guards). `verify-vectors`
(below) runs this in-process so any host can self-check.

---

## SP2 — Node CLI signer

A deliberately thin executable over the existing SDK — **no business logic**, no
network, no new crypto. It exists to give skills a stable execution protocol that
SP3 (bundled JS) and SP4 (Python) will mirror.

### Packaging

- `bin`: `sohopay-signer` → `@sohopay/agent-signer`.
- Runs via `npx @sohopay/agent-signer …` (or a global/local install).
- Bundles/imports `@sohopay/signer-vectors` for `verify-vectors` (already a devDep;
  promote to a dependency for the CLI path).

### Commands

```
sohopay-signer voucher sign   --input <file|-> [--key <file>] [--output json]
sohopay-signer payment-id     --input <file|->
sohopay-signer key jkt        --key <file|->
sohopay-signer pop sign       --input <file|-> [--key <file>]
sohopay-signer verify-vectors [--output json]
sohopay-signer capabilities   [--output json]
```

### Machine interface (the contract skills target)

- `--input -` reads JSON from **stdin**; `--output json` emits a single JSON object
  to **stdout** and nothing decorative.
- `stderr` is diagnostics only. **Non-zero exit = failure.**
- `voucher sign` stdin:
  ```json
  { "voucher": { … }, "signing": { … }, "key": { "private_key_base64url": "…", "public_jwk": { … } } }
  ```
  stdout:
  ```json
  { "signer_protocol": "sohopay-signer/1", "implementation": "@sohopay/agent-signer",
    "implementation_version": "0.x.y", "payment_id": "0x…", "agent_key_jkt": "…",
    "signature": "…", "algorithm": "Ed25519" }
  ```
- `key` may be supplied inline in stdin (as above) or via `--key <file>`; the two
  are mutually exclusive, and `--key` is preferred so the private seed never has to
  transit a command line or a shared stdin blob when a file exists.
- `capabilities` stdout: `{ "signer_protocol": "sohopay-signer/1", "implementation",
  "implementation_version", "algorithms": ["Ed25519"], "commands": [ … ] }` — what
  SP5 routing probes to confirm a usable signer.
- `verify-vectors`: exits 0 iff every vector passes; `--output json` summarizes
  `{ passed, failed, total }`.

### Security

- The private seed is read from a file or stdin and never logged (stderr
  diagnostics must never include key material). File reads reuse the SDK's
  permission posture where applicable.
- No `--output`-less decorative mode writes secrets; human mode prints only
  non-sensitive fields.

### Testing

- Unit/integration tests drive the CLI as a subprocess: happy `voucher sign` whose
  stdout `signature`/`payment_id` equal the `@sohopay/signer-vectors` expected
  values; each negative guard returns the right `error.code` + non-zero exit;
  `verify-vectors` exits 0; `capabilities` reports `sohopay-signer/1`.
- Runs in the SDK's existing `node --test` CI; no new runner.

### Out of scope (SP2)

- Key generation/storage lifecycle (already SDK primitives; the CLI signs with a
  provided key — a `key gen` command can come later if a host needs it).
- Any host detection / routing (SP5).
- Bundling for install-free use (SP3).

## Decisions (resolved)

1. **`pop sign` is in SP2.** Same thin wrapper; onboarding needs it on shell-capable
   hosts. Condition: cross-domain non-interchangeability (SP1 §Domain separation) —
   required and vector-enforced both directions. A symmetric *typed* PoP prefix is a
   future `sohopay-signer/2` item, not SP2 (it would break the frozen deployed PoP).
2. **Python signer lives in `python/` within `sohopay-agent-signer`.** Shared
   fixtures/vectors; a SINGLE vector commit gates BOTH the JS and Python
   implementations in the SAME CI run. Separate release tags (`js-v*`, `py-v*`) and
   separate publishing pipelines; `sohopay-signer/1` is the shared compatibility
   axis — package versions are not.
3. **`key gen` is out of SP2.** Keygen belongs with session-key provisioning, where
   custody is decided; a generic CLI keygen risks private keys landing in arbitrary
   places. The SDK retains programmatic keygen for provisioning flows.
