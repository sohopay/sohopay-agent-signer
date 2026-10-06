import { buildPaymentSignatureHeader } from "./envelope.js";
import type { Ed25519PublicJwk } from "./keys.js";
import {
  advancePhase,
  beginOperation,
  recordPrepared,
  recoveryAction,
  resolveOperation,
  type OperationStore,
} from "./operations.js";
import { signVoucher, type AgentPaymentVoucher, type ServerSigningBlock } from "./voucher.js";

/**
 * S12 — optional reference orchestration of one x402 payment using the SDK.
 *
 * This is a convenience, not a required layer: a host may call the primitives
 * (`signVoucher`, the operation ledger, `recoveryAction`) directly. It exists to
 * show the canonical, recovery-aware sequence and to prove the pieces compose.
 * It performs NO I/O — every network call is delegated to {@link HostTransport},
 * which the host implements over its own MCP client / HTTP.
 */

/** `prepare_x402_payment` returned an unsigned voucher (Protocol V2). */
export interface PrepareVoucherResult {
  status: "VOUCHER_ISSUED";
  voucher: AgentPaymentVoucher;
  /** The server's advertised signing block, validated by signVoucher. */
  signing?: ServerSigningBlock;
  /** The prepare-response envelope to fill with the signature (paymentPayload wrapper). */
  prepareResponse: unknown;
}

/** Any non-voucher prepare outcome (e.g. a terminal FAILED, or legacy V1 COMPLETED). */
export interface PrepareTerminalResult {
  status: string;
}

export type PrepareResult = PrepareVoucherResult | PrepareTerminalResult;

export interface SettlementStatus {
  status: string;
  terminal: boolean;
}

/** The host-provided transport. The SDK never does I/O itself. */
export interface HostTransport {
  prepare(input: { borrowerId: string; orderRef: string; idempotencyKey: string }): Promise<PrepareResult>;
  submit(input: { paymentId: string; headerName: string; headerValue: string }): Promise<void>;
  getStatus(input: { borrowerId: string; paymentId: string }): Promise<SettlementStatus>;
}

export interface ExecutePaymentArgs {
  transport: HostTransport;
  store: OperationStore;
  borrowerId: string;
  orderRef: string;
  /** The agent workload private seed (base64url) used to sign the voucher. */
  privateKeyBase64Url: string;
  /** Optional: asserts the voucher's agentKeyJkt matches this signing key. */
  publicJwk?: Ed25519PublicJwk;
}

export interface ExecutePaymentResult {
  paymentId?: string;
  status: string;
  terminal: boolean;
}

function isVoucherResult(result: PrepareResult): result is PrepareVoucherResult {
  return (result as PrepareVoucherResult).status === "VOUCHER_ISSUED";
}

/**
 * Runs (or resumes) one payment. On resume it consults the operation ledger:
 * a terminal op returns immediately, an op that already has a voucher queries
 * authoritative status (never re-submits), and an op with no voucher yet re-
 * prepares under the same idempotency key. A fresh run prepares → signs →
 * submits → resolves.
 */
export async function executePayment(args: ExecutePaymentArgs): Promise<ExecutePaymentResult> {
  const { transport, store, borrowerId, orderRef } = args;
  const op = beginOperation({ store, borrowerId, orderRef });

  switch (recoveryAction(op)) {
    case "DONE":
      return { paymentId: op.paymentId, status: op.status ?? "RESOLVED", terminal: true };
    case "QUERY_STATUS": {
      const status = await transport.getStatus({ borrowerId, paymentId: op.paymentId! });
      if (status.terminal) {
        resolveOperation({ store, borrowerId, orderRef, status: status.status });
      }
      return { paymentId: op.paymentId, status: status.status, terminal: status.terminal };
    }
    case "RETRY_PREPARE":
      break;
  }

  const prepared = await transport.prepare({ borrowerId, orderRef, idempotencyKey: op.idempotencyKey });
  if (!isVoucherResult(prepared)) {
    resolveOperation({ store, borrowerId, orderRef, status: prepared.status });
    return { status: prepared.status, terminal: true };
  }

  recordPrepared({
    store,
    borrowerId,
    orderRef,
    paymentId: prepared.voucher.paymentId,
    agentKeyJkt: prepared.voucher.agentKeyJkt,
    voucherDeadline: prepared.voucher.deadline,
  });

  const { signature } = signVoucher({
    voucher: prepared.voucher,
    signing: prepared.signing,
    privateKeyBase64Url: args.privateKeyBase64Url,
    publicJwk: args.publicJwk,
  });
  advancePhase({ store, borrowerId, orderRef, phase: "SIGNED" });

  const header = buildPaymentSignatureHeader(prepared.prepareResponse, signature);
  await transport.submit({
    paymentId: prepared.voucher.paymentId,
    headerName: header.headerName,
    headerValue: header.headerValue,
  });
  advancePhase({ store, borrowerId, orderRef, phase: "SUBMITTED" });

  const status = await transport.getStatus({ borrowerId, paymentId: prepared.voucher.paymentId });
  if (status.terminal) {
    resolveOperation({ store, borrowerId, orderRef, status: status.status });
  }
  return { paymentId: prepared.voucher.paymentId, status: status.status, terminal: status.terminal };
}
