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

## License

Proprietary — SohoPay. Not for distribution.
