# @sohopay/agent-signer

Deterministic client-side signer for SohoPay **Protocol V2** agent payments.

This is the small, exact-by-construction piece that must run on the agent side: it
produces the Ed25519 **voucher** and **proof-of-possession** signatures, the
`paymentId`, and the RFC 7638 key thumbprint — byte-for-byte compatible with the
SohoPay backend verifier. It replaces the hand-executed "signing recipe" that
previously lived in prose inside the agent skills.

It is **not** an MCP client. The agent host already provides transport, OAuth,
and tool invocation; this library only owns the crypto and key handling those
hosts cannot safely do for you.

## Security boundary

- Holds the **agent workload key** only. It **never** touches a borrower key —
  borrower authorization is an EIP-712 signature made off-device in the
  borrower's own wallet.
- The server stays the authority for policy, idempotency, and settlement. This
  library only signs; it does not decide whether a payment is allowed.
- A JWK carrying private material (`d`) is rejected. The server's advertised
  `signing` block is validated against a compiled-in allowlist and never
  substituted — the SDK will not sign under a scheme it does not implement.

## Install

```bash
npm install @sohopay/agent-signer
```

## Usage

```ts
import {
  generateWorkloadKey,
  signPoP,
  computePaymentId,
  signVoucher,
  buildPaymentSignatureHeader,
} from "@sohopay/agent-signer";

// 1. Once per terminal: generate and persist the workload key (private seed stays local).
const key = generateWorkloadKey();

// 2. Register it: sign the proof-of-possession challenge.
const { pop_signature } = signPoP(
  { borrowerId, terminalId, jkt: key.jkt, nonce, iat: Math.floor(Date.now() / 1000) },
  key.privateKeyBase64Url,
);

// 3. On VOUCHER_ISSUED from prepare_x402_payment: sign the voucher.
const { signature } = signVoucher({
  voucher,                    // from the prepare response
  signing,                    // the prepare response's `signing` block (validated)
  privateKeyBase64Url: key.privateKeyBase64Url,
  publicJwk: key.publicJwk,   // optional: asserts voucher.agentKeyJkt matches this key
});

// 4. Build the merchant unlock header.
const { headerName, headerValue } = buildPaymentSignatureHeader(prepareResponse, signature);
```

All signing is fail-closed: `signVoucher` recomputes and checks the `paymentId`
and the key thumbprint before producing a signature, and every failure throws a
`SignerError` with a stable `code`.

## Parity testing

Correctness is defined by cross-language known-answer vectors generated from the
backend's own verifier. During development the test suite reads those vectors
from the backend repo; override the location with `SIGNER_VECTORS_PATH`.

```bash
npm test          # parity suite (node --test)
npm run build     # emit dist/
```

## Install-free bundle (no npm registry required)

A single self-contained `sohopay-signer.mjs` runs on any host with Node >= 18 — no
`node_modules`, no network. Download it from the matching `js-bundle-v<version>` GitHub
Release, **verify**, then point `$SOHOPAY_SIGNER` at it.

### Download and verify

1. Download the exact version you want (never `latest`):

       V=0.2.0   # the js-bundle-v<version> you intend to run
       gh release download "js-bundle-v$V" --repo sohopay/sohopay-agent-signer \
         --pattern 'sohopay-signer.mjs' --pattern 'sohopay-signer.mjs.sha256'

2. Verify. **Online (preferred)** — ties the file to the build workflow + commit:

       gh attestation verify sohopay-signer.mjs --repo sohopay/sohopay-agent-signer

   **Offline / air-gapped** — compare against the expected hash for that exact version
   published in the table below (updated per release). Note: the downloaded `.sha256` is
   a convenience against file corruption in transit, **not the trust anchor**; a
   compromised release could swap both files. Trust only the out-of-release table:

       sha256sum sohopay-signer.mjs   # compare to the table below

3. Install and verify:

       chmod +x sohopay-signer.mjs
       export SOHOPAY_SIGNER="$PWD/sohopay-signer.mjs"
       sohopay-signer capabilities    # expect signer_protocol: sohopay-signer/1
       sohopay-signer verify-vectors  # expect exit 0

### Expected hashes (trust anchor, out-of-release)

| Version | sha256 of `sohopay-signer.mjs` |
|---------|--------------------------------|
| _(add a row per release)_ | _(the hash from the release build)_ |

### Supported invocation forms

The bundle supports three ways to run:

- **`node sohopay-signer.mjs <command> [args]`** — explicit Node invocation; always works
- **`./sohopay-signer.mjs <command> [args]`** — direct execution after `chmod +x`; works with Node >= 18.13 and modern shebangs
- **Symlink on PATH** — `ln -s /path/to/sohopay-signer.mjs ~/bin/sohopay-signer` → `sohopay-signer <command>` (Node resolves the `.mjs` extension)

**Not supported:** copying to an extensionless name (e.g. `cp sohopay-signer.mjs sohopay-signer`). On older Node versions this fails (Node parses an extensionless file as CommonJS and the ESM bundle errors); on Node >= 22.7 it may run via module auto-detection, but the behavior is version-dependent. Use the `.mjs` name or a symlink to it instead.

### Releasing the bundle

**One-time repo setup (must be in place before the first release — these are the trust controls the install flow above relies on):**

- Make the repo **public** — required for token-free asset download and `gh attestation verify` support.
- Enable **immutable releases** and **`js-bundle-v*` tag protection** so published assets and tags cannot be replaced after the fact.

To release, once the above are enabled:

1. Tag the commit: `git tag "js-bundle-v<version>"` where `<version>` matches `package.json`
2. Push the tag: `git push origin "js-bundle-v<version>"` — GitHub Actions builds and publishes the release automatically
3. Add the new version row to the "Expected hashes" table above on the `main` branch to record the trust anchor for future verifications.

With immutable releases enabled, a published release is permanent — its assets cannot be swapped.

## CLI (sohopay-signer)

The package ships a `sohopay-signer` bin for shell-capable agent hosts. It is a
thin wrapper over the SDK above and is protocol-versioned as `sohopay-signer/1`.

```bash
npx @sohopay/agent-signer capabilities --output json
```

### Machine interface

- `--input -` reads a JSON object from **stdin**; `--output json` emits a single
  JSON object to **stdout** and nothing else.
- `stderr` is diagnostics only. **A non-zero exit means failure.**
- Operational failures exit `1` with an error envelope on stderr:
  ```json
  { "error": { "code": "MALFORMED_ENVELOPE", "message": "..." } }
  ```
  Usage errors (unknown command or flag, missing flag value) exit `2` with a
  plain one-line message.
- The CLI holds **agent workload keys only**; it never touches a borrower key,
  and the seed is never logged.

### Key input is reference-only

The signing key is supplied **by reference** with `--key <path>`; inline key
material in the stdin JSON (`"key": { ... }`) is rejected with
`INLINE_KEY_REJECTED`. Both `--key` and `--out` must name a file called
`secret.json` under an allowed key root (default `~/.agents/sohopay-agent-workload`;
`SOHOPAY_SIGNER_KEY_ROOTS` can only narrow it). The file must be mode `0600` and
may not be a symlink. Anything else fails with `KEY_PATH_INVALID`.

### Commands

`key generate`: creates a new Ed25519 workload key.

```bash
echo '{ "borrower_id": "...", "terminal_id": "..." }' \
  | sohopay-signer key generate --out ~/.agents/sohopay-agent-workload/secret.json --input - --output json
# {"public_jwk":{...},"jkt":"...","borrower_id":"...","terminal_id":"...","created":true}
```

The private key is written to `secret.json` with mode `0600` and is never
printed; stdout carries public material only.

`voucher sign`: signs the voucher issued by `prepare_x402_payment`.

```bash
echo '{ "voucher": { ... }, "signing": { ... } }' \
  | sohopay-signer voucher sign --key ~/.agents/sohopay-agent-workload/secret.json --input - --output json
# {"signer_protocol":"sohopay-signer/1","implementation":"@sohopay/agent-signer",
#  "implementation_version":"0.x.y","payment_id":"0x...","agent_key_jkt":"...",
#  "signature":"...","algorithm":"Ed25519"}
```

`payment-id`: recomputes the `paymentId` from a voucher core.

```bash
echo '{ "core": { ... } }' | sohopay-signer payment-id --input - --output json
# {"payment_id":"0x..."}
```

`key jkt`: RFC 7638 thumbprint of a public JWK (or of the key derived from a seed).

```bash
echo '{ "public_jwk": { ... } }' | sohopay-signer key jkt --input - --output json
# {"agent_key_jkt":"..."}
```

`pop sign`: signs the proof-of-possession challenge for key registration.

```bash
echo '{ "fields": { "borrowerId": "...", "terminalId": "...", "jkt": "...", "nonce": "...", "iat": 0 } }' \
  | sohopay-signer pop sign --input - --key ~/.agents/sohopay-agent-workload/secret.json --output json
# {"signer_protocol":"sohopay-signer/1","implementation":"@sohopay/agent-signer",
#  "implementation_version":"0.x.y","pop_signature":"...","algorithm":"Ed25519"}
```

`verify-vectors`: runs the bundled known-answer vectors; exits `0` only if all pass.

```bash
sohopay-signer verify-vectors --output json
# {"passed":N,"failed":0,"total":N}
```

`capabilities`: what host routing probes to confirm a usable signer.

```bash
sohopay-signer capabilities --output json
# {"signer_protocol":"sohopay-signer/1","implementation":"@sohopay/agent-signer",
#  "implementation_version":"0.x.y","algorithms":["Ed25519"],"commands":[...]}
```

## License

Proprietary — SohoPay. Not for distribution.
