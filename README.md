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
- The CLI holds **agent workload keys only**; it never touches a borrower key.
  The seed is never logged.

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
  | sohopay-signer pop sign --input - --key ./agent-key.json --output json
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
