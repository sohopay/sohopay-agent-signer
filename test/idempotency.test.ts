import assert from "node:assert/strict";
import { test } from "node:test";

import { SignerError } from "../src/errors.js";
import {
  InMemoryIdempotencyStore,
  newIdempotencyKey,
  resolveIdempotencyKey,
} from "../src/idempotency.js";

const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

test("newIdempotencyKey is a UUID v4", () => {
  assert.match(newIdempotencyKey(), UUID_V4);
});

test("stable per (borrowerId, orderRef)", () => {
  const store = new InMemoryIdempotencyStore();
  const k1 = resolveIdempotencyKey({ borrowerId: "b", orderRef: "o1", store });
  const k2 = resolveIdempotencyKey({ borrowerId: "b", orderRef: "o1", store });
  assert.equal(k1, k2);
});

test("different orderRef yields a different key", () => {
  const store = new InMemoryIdempotencyStore();
  const k1 = resolveIdempotencyKey({ borrowerId: "b", orderRef: "o1", store });
  const k2 = resolveIdempotencyKey({ borrowerId: "b", orderRef: "o2", store });
  assert.notEqual(k1, k2);
});

test("same orderRef with a different paymentId throws IDEMPOTENCY_PAYLOAD_MISMATCH", () => {
  const store = new InMemoryIdempotencyStore();
  resolveIdempotencyKey({ borrowerId: "b", orderRef: "o1", paymentId: "0xaaa", store });
  assert.throws(
    () => resolveIdempotencyKey({ borrowerId: "b", orderRef: "o1", paymentId: "0xbbb", store }),
    (e) => e instanceof SignerError && e.code === "IDEMPOTENCY_PAYLOAD_MISMATCH",
  );
});

test("reuse with the same paymentId returns the same key", () => {
  const store = new InMemoryIdempotencyStore();
  const k1 = resolveIdempotencyKey({ borrowerId: "b", orderRef: "o1", paymentId: "0xaaa", store });
  const k2 = resolveIdempotencyKey({ borrowerId: "b", orderRef: "o1", paymentId: "0xaaa", store });
  assert.equal(k1, k2);
});

test("backfills paymentId when first seen without one", () => {
  const store = new InMemoryIdempotencyStore();
  const k1 = resolveIdempotencyKey({ borrowerId: "b", orderRef: "o1", store });
  const k2 = resolveIdempotencyKey({ borrowerId: "b", orderRef: "o1", paymentId: "0xaaa", store });
  assert.equal(k1, k2);
  assert.throws(
    () => resolveIdempotencyKey({ borrowerId: "b", orderRef: "o1", paymentId: "0xbbb", store }),
    (e) => e instanceof SignerError && e.code === "IDEMPOTENCY_PAYLOAD_MISMATCH",
  );
});
