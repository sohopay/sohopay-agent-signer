import {
  chmodSync,
  closeSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";

import { SignerError } from "./errors.js";
import { newIdempotencyKey } from "./idempotency.js";
import { resolveDataDir } from "./terminal.js";

/**
 * S9 — client-side operation ledger for crash/timeout recovery. Tracks each
 * logical payment `(borrowerId, orderRef)` through its phases so that after an
 * interruption the client can decide whether to safely re-prepare (idempotent)
 * or query authoritative status — never blindly re-submit a money operation.
 *
 * The SDK does NOT make the status HTTP call (that is the host's transport); it
 * records state and recommends the next action via {@link recoveryAction}.
 */
export type OperationPhase = "STARTED" | "PREPARED" | "SIGNED" | "SUBMITTED" | "RESOLVED";

export interface OperationRecord {
  borrowerId: string;
  orderRef: string;
  /** The idempotency key bound to this logical payment (reused on every retry). */
  idempotencyKey: string;
  /** Set once prepare returns a voucher. */
  paymentId?: string;
  /** jkt the voucher was signed under — used by the rotation drain gate (S10). */
  agentKeyJkt?: string;
  /** Voucher validity, unix seconds (string) — an elapsed deadline is uncapturable. */
  voucherDeadline?: string;
  phase: OperationPhase;
  /** Last authoritative status the host observed (free-form, from the backend). */
  status?: string;
  terminal: boolean;
  attempts: number;
  /** epoch ms. */
  createdAt: number;
  updatedAt: number;
}

export interface OperationStore {
  get(borrowerId: string, orderRef: string): OperationRecord | undefined;
  put(record: OperationRecord): void;
  list(borrowerId: string): OperationRecord[];
}

const BORROWER_ID_PATTERN = /^[A-Za-z0-9._:@-]+$/;

function assertSafeId(borrowerId: string): string {
  if (!borrowerId || !BORROWER_ID_PATTERN.test(borrowerId)) {
    throw new SignerError(
      "INVALID_BORROWER_ID",
      "borrower_id must be safe as a path segment (letters, digits, . _ : @ -)",
    );
  }
  return borrowerId;
}

/** Process-lifetime store (does not survive restarts — use FileOperationStore for recovery). */
export class InMemoryOperationStore implements OperationStore {
  private readonly records = new Map<string, OperationRecord>();

  private key(borrowerId: string, orderRef: string): string {
    return `${borrowerId}\u0000${orderRef}`;
  }

  get(borrowerId: string, orderRef: string): OperationRecord | undefined {
    return this.records.get(this.key(borrowerId, orderRef));
  }

  put(record: OperationRecord): void {
    this.records.set(this.key(record.borrowerId, record.orderRef), record);
  }

  list(borrowerId: string): OperationRecord[] {
    return [...this.records.values()].filter((r) => r.borrowerId === borrowerId);
  }
}

/** Atomic JSON write (temp → fsync → rename), mode 0600. */
function atomicWriteJson(path: string, data: unknown): void {
  const dir = dirname(path);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const tmp = join(dir, `.op.${process.pid}.${Date.now()}.tmp`);
  const fd = openSync(tmp, "w", 0o600);
  try {
    writeFileSync(fd, `${JSON.stringify(data, null, 2)}\n`);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  chmodSync(tmp, 0o600);
  renameSync(tmp, path);
}

/** Durable store: one JSON file per borrower, so operations survive a restart. */
export class FileOperationStore implements OperationStore {
  constructor(private readonly options: { dataDir?: string } = {}) {}

  private file(borrowerId: string): string {
    return join(resolveDataDir(this.options.dataDir), "operations", `${assertSafeId(borrowerId)}.json`);
  }

  private readAll(borrowerId: string): Record<string, OperationRecord> {
    try {
      return JSON.parse(readFileSync(this.file(borrowerId), "utf8")) as Record<string, OperationRecord>;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") {
        return {};
      }
      throw error;
    }
  }

  get(borrowerId: string, orderRef: string): OperationRecord | undefined {
    return this.readAll(borrowerId)[orderRef];
  }

  list(borrowerId: string): OperationRecord[] {
    return Object.values(this.readAll(borrowerId));
  }

  put(record: OperationRecord): void {
    const all = this.readAll(record.borrowerId);
    all[record.orderRef] = record;
    atomicWriteJson(this.file(record.borrowerId), all);
  }
}

function requireOperation(store: OperationStore, borrowerId: string, orderRef: string): OperationRecord {
  const existing = store.get(borrowerId, orderRef);
  if (!existing) {
    throw new SignerError("OPERATION_NOT_FOUND", `no operation for (${borrowerId}, ${orderRef})`);
  }
  return existing;
}

export interface BeginOperationArgs {
  store: OperationStore;
  borrowerId: string;
  orderRef: string;
  /** Reuse an idempotency key (e.g. from resolveIdempotencyKey); minted if absent. */
  idempotencyKey?: string;
  now?: number;
}

/**
 * Starts or resumes an operation. A resume (existing, non-terminal) bumps the
 * attempt counter and keeps the same idempotency key; a terminal operation is
 * returned unchanged (its {@link recoveryAction} is `DONE`).
 */
export function beginOperation(args: BeginOperationArgs): OperationRecord {
  const now = args.now ?? Date.now();
  const existing = args.store.get(args.borrowerId, args.orderRef);
  if (existing) {
    if (existing.terminal) {
      return existing;
    }
    const resumed: OperationRecord = { ...existing, attempts: existing.attempts + 1, updatedAt: now };
    args.store.put(resumed);
    return resumed;
  }
  const record: OperationRecord = {
    borrowerId: args.borrowerId,
    orderRef: args.orderRef,
    idempotencyKey: args.idempotencyKey ?? newIdempotencyKey(),
    phase: "STARTED",
    terminal: false,
    attempts: 1,
    createdAt: now,
    updatedAt: now,
  };
  args.store.put(record);
  return record;
}

function update(
  store: OperationStore,
  borrowerId: string,
  orderRef: string,
  patch: Partial<OperationRecord>,
  now: number,
): OperationRecord {
  const existing = requireOperation(store, borrowerId, orderRef);
  const next: OperationRecord = { ...existing, ...patch, updatedAt: now };
  store.put(next);
  return next;
}

export interface RecordPreparedArgs {
  store: OperationStore;
  borrowerId: string;
  orderRef: string;
  paymentId: string;
  agentKeyJkt?: string;
  voucherDeadline?: string;
  now?: number;
}

/** Records that prepare returned a voucher (paymentId known). */
export function recordPrepared(args: RecordPreparedArgs): OperationRecord {
  return update(
    args.store,
    args.borrowerId,
    args.orderRef,
    {
      phase: "PREPARED",
      paymentId: args.paymentId,
      agentKeyJkt: args.agentKeyJkt,
      voucherDeadline: args.voucherDeadline,
    },
    args.now ?? Date.now(),
  );
}

/** Advances the phase (e.g. SIGNED after signing, SUBMITTED after handing to the merchant). */
export function advancePhase(args: {
  store: OperationStore;
  borrowerId: string;
  orderRef: string;
  phase: OperationPhase;
  now?: number;
}): OperationRecord {
  return update(args.store, args.borrowerId, args.orderRef, { phase: args.phase }, args.now ?? Date.now());
}

/** Marks the operation terminal with the authoritative status the host observed. */
export function resolveOperation(args: {
  store: OperationStore;
  borrowerId: string;
  orderRef: string;
  status?: string;
  now?: number;
}): OperationRecord {
  return update(
    args.store,
    args.borrowerId,
    args.orderRef,
    { phase: "RESOLVED", terminal: true, status: args.status },
    args.now ?? Date.now(),
  );
}

export function getOperation(
  store: OperationStore,
  borrowerId: string,
  orderRef: string,
): OperationRecord | undefined {
  return store.get(borrowerId, orderRef);
}

/** What the client should do next for an interrupted operation. */
export type RecoveryAction = "RETRY_PREPARE" | "QUERY_STATUS" | "DONE";

/**
 * - `DONE` — terminal, nothing to do.
 * - `RETRY_PREPARE` — no voucher was ever issued; safe to re-prepare with the
 *   same idempotency key.
 * - `QUERY_STATUS` — a voucher exists (paymentId known); ask the backend for the
 *   authoritative outcome rather than re-submitting.
 */
export function recoveryAction(op: OperationRecord): RecoveryAction {
  if (op.terminal) {
    return "DONE";
  }
  return op.paymentId ? "QUERY_STATUS" : "RETRY_PREPARE";
}
