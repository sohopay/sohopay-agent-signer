import { randomUUID } from "node:crypto";

import { SignerError } from "./errors.js";

/** A fresh UUID v4 idempotency key (what the backend's @Idempotent endpoints require). */
export function newIdempotencyKey(): string {
  return randomUUID();
}

export interface IdempotencyRecord {
  key: string;
  /** The client-computed paymentId this key is bound to, once known. */
  paymentId?: string;
}

/** Pluggable persistence for idempotency records. Default is in-memory. */
export interface IdempotencyStore {
  get(scope: string): IdempotencyRecord | undefined;
  set(scope: string, record: IdempotencyRecord): void;
}

/** Process-lifetime store. Swap for a persistent one to survive restarts. */
export class InMemoryIdempotencyStore implements IdempotencyStore {
  private readonly records = new Map<string, IdempotencyRecord>();

  get(scope: string): IdempotencyRecord | undefined {
    return this.records.get(scope);
  }

  set(scope: string, record: IdempotencyRecord): void {
    this.records.set(scope, record);
  }
}

const defaultStore = new InMemoryIdempotencyStore();

function scopeKey(borrowerId: string, orderRef: string): string {
  return `${borrowerId}\u0000${orderRef}`;
}

export interface ResolveIdempotencyKeyArgs {
  borrowerId: string;
  orderRef: string;
  /** When known, binds the key to this paymentId and guards against payload drift. */
  paymentId?: string;
  store?: IdempotencyStore;
}

/**
 * Returns a stable idempotency key for a logical payment `(borrowerId, orderRef)`,
 * minting one on first use and reusing it on retry. If the same order is retried
 * with a DIFFERENT `paymentId`, it throws rather than silently reusing the key —
 * a changed amount/payee is a new payment, not a retry.
 */
export function resolveIdempotencyKey(args: ResolveIdempotencyKeyArgs): string {
  const store = args.store ?? defaultStore;
  const scope = scopeKey(args.borrowerId, args.orderRef);

  const existing = store.get(scope);
  if (existing) {
    if (
      args.paymentId &&
      existing.paymentId &&
      existing.paymentId.toLowerCase() !== args.paymentId.toLowerCase()
    ) {
      throw new SignerError(
        "IDEMPOTENCY_PAYLOAD_MISMATCH",
        `orderRef "${args.orderRef}" was already used for a different paymentId`,
      );
    }
    if (args.paymentId && !existing.paymentId) {
      store.set(scope, { ...existing, paymentId: args.paymentId });
    }
    return existing.key;
  }

  const record: IdempotencyRecord = { key: newIdempotencyKey(), paymentId: args.paymentId };
  store.set(scope, record);
  return record.key;
}
