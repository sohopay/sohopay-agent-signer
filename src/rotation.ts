import type { OperationRecord, OperationStore } from "./operations.js";

/**
 * S10 — key-rotation drain gate.
 *
 * A voucher signed under the old workload key but not yet captured will fail at
 * capture once the key is rotated out (the backend verifies against the live key
 * at capture; SOHO-254 supersedes the old key atomically). So a rotation must not
 * be *activated* while such vouchers are still in flight. This assesses, from the
 * operation ledger (S9), whether rotation is safe and, if not, which operations
 * block it.
 *
 * An operation blocks when it is non-terminal, has produced a voucher
 * (`paymentId` known), is signed under the key being rotated out, and its voucher
 * deadline has not elapsed. A `STARTED` operation with no voucher does not block
 * (it simply re-prepares under the new key), and an elapsed-deadline voucher can
 * no longer be captured, so it is surfaced as expired rather than blocking.
 */
export interface RotationDrainAssessment {
  /** True when nothing is in flight that could capture under the rotating key. */
  ready: boolean;
  /** Non-terminal, unexpired vouchers that must resolve (or expire) before rotating. */
  blocking: OperationRecord[];
  /** Non-terminal vouchers whose deadline has passed — safe, reported for visibility. */
  expired: OperationRecord[];
}

export interface AssessRotationDrainArgs {
  operations: OperationRecord[];
  /** epoch ms; defaults to now. */
  now?: number;
  /** When set, only operations signed under this jkt are considered (the key being rotated out). */
  jkt?: string;
}

/** Assesses rotation safety from a list of operation records. */
export function assessRotationDrain(args: AssessRotationDrainArgs): RotationDrainAssessment {
  const nowSeconds = Math.floor((args.now ?? Date.now()) / 1000);
  const blocking: OperationRecord[] = [];
  const expired: OperationRecord[] = [];

  for (const op of args.operations) {
    if (op.terminal) {
      continue;
    }
    // Only a voucher (paymentId issued) can be captured under the old key.
    if (!op.paymentId) {
      continue;
    }
    // Scope to the key being rotated out, when known on both sides.
    if (args.jkt && op.agentKeyJkt && op.agentKeyJkt !== args.jkt) {
      continue;
    }
    if (op.voucherDeadline !== undefined && Number(op.voucherDeadline) < nowSeconds) {
      expired.push(op);
      continue;
    }
    blocking.push(op);
  }

  return { ready: blocking.length === 0, blocking, expired };
}

/** Convenience: assess drain for one borrower straight from an operation store. */
export function assessRotationDrainForBorrower(args: {
  store: OperationStore;
  borrowerId: string;
  now?: number;
  jkt?: string;
}): RotationDrainAssessment {
  return assessRotationDrain({
    operations: args.store.list(args.borrowerId),
    now: args.now,
    jkt: args.jkt,
  });
}
