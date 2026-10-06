import assert from "node:assert/strict";
import { test } from "node:test";

import { InMemoryOperationStore, type OperationRecord } from "../src/operations.js";
import { assessRotationDrain, assessRotationDrainForBorrower } from "../src/rotation.js";

const NOW = 1_760_000_000_000; // epoch ms
const nowSec = Math.floor(NOW / 1000);

function op(partial: Partial<OperationRecord>): OperationRecord {
  return {
    borrowerId: "b",
    orderRef: "o",
    idempotencyKey: "k",
    phase: "PREPARED",
    terminal: false,
    attempts: 1,
    createdAt: NOW,
    updatedAt: NOW,
    ...partial,
  };
}

test("no operations → ready", () => {
  assert.equal(assessRotationDrain({ operations: [], now: NOW }).ready, true);
});

test("a prepared, unexpired voucher blocks rotation", () => {
  const r = assessRotationDrain({
    operations: [op({ paymentId: "0x1", voucherDeadline: String(nowSec + 600) })],
    now: NOW,
  });
  assert.equal(r.ready, false);
  assert.equal(r.blocking.length, 1);
});

test("terminal operations never block", () => {
  const r = assessRotationDrain({ operations: [op({ paymentId: "0x1", terminal: true })], now: NOW });
  assert.equal(r.ready, true);
});

test("a STARTED operation with no voucher does not block", () => {
  const r = assessRotationDrain({ operations: [op({ phase: "STARTED" })], now: NOW });
  assert.equal(r.ready, true);
});

test("an elapsed-deadline voucher is expired, not blocking", () => {
  const r = assessRotationDrain({
    operations: [op({ paymentId: "0x1", voucherDeadline: String(nowSec - 1) })],
    now: NOW,
  });
  assert.equal(r.ready, true);
  assert.equal(r.expired.length, 1);
  assert.equal(r.blocking.length, 0);
});

test("jkt scope: a voucher under a different key does not block the rotating key", () => {
  const ops = [op({ paymentId: "0x1", agentKeyJkt: "OTHER", voucherDeadline: String(nowSec + 600) })];
  assert.equal(assessRotationDrain({ operations: ops, now: NOW, jkt: "ROTATING" }).ready, true);
  assert.equal(assessRotationDrain({ operations: ops, now: NOW, jkt: "OTHER" }).ready, false);
});

test("assessRotationDrainForBorrower reads the store", () => {
  const store = new InMemoryOperationStore();
  store.put(op({ paymentId: "0x1", voucherDeadline: String(nowSec + 600) }));
  assert.equal(assessRotationDrainForBorrower({ store, borrowerId: "b", now: NOW }).ready, false);
});
