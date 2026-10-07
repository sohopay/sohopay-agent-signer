import { spawnSync } from "node:child_process";
import { readFileSync, existsSync, statSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";
import test, { before } from "node:test";

const OUT = "dist-bundle/sohopay-signer.mjs";

before(() => {
  const r = spawnSync("npm", ["run", "bundle"], { encoding: "utf8" });
  assert.equal(r.status, 0, `bundle failed:\n${r.stdout}\n${r.stderr}`);
});

test("bundle emits an executable .mjs with a node shebang", () => {
  assert.ok(existsSync(OUT));
  assert.ok(readFileSync(OUT, "utf8").startsWith("#!/usr/bin/env node"));
  assert.ok((statSync(OUT).mode & 0o111) !== 0, "not executable");
});

test("checksum file uses the conventional sha256sum format", () => {
  const line = readFileSync(`${OUT}.sha256`, "utf8").trim();
  assert.match(line, /^[0-9a-f]{64}  sohopay-signer\.mjs$/);
});

test("license notices survive (LEGAL.txt non-empty, names a bundled dep)", () => {
  const legal = readFileSync(`${OUT}.LEGAL.txt`, "utf8");
  assert.ok(legal.length > 0);
  assert.match(legal, /noble|canonicalize/i);
});

test("build is reproducible across two separate clean output dirs", () => {
  const build = (dir: string) => {
    const r = spawnSync("node", ["scripts/bundle.mjs"], {
      encoding: "utf8",
      env: { ...process.env, SOHOPAY_BUNDLE_OUTDIR: dir },
    });
    assert.equal(r.status, 0, `${r.stdout}\n${r.stderr}`);
    return readFileSync(join(dir, "sohopay-signer.mjs"));
  };
  const a = mkdtempSync(join(tmpdir(), "bnd-a-"));
  const b = mkdtempSync(join(tmpdir(), "bnd-b-"));
  try {
    assert.ok(build(a).equals(build(b)), "two clean builds differ");
  } finally {
    rmSync(a, { recursive: true, force: true });
    rmSync(b, { recursive: true, force: true });
  }
});
