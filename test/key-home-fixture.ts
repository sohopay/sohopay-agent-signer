import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/**
 * Runs `fn` with HOME pointed at a temp dir holding a 0600 secret.json under the
 * default key root. `run()` resolves roots via homedir(), so HOME is the only way
 * to place a test key inside an allowed root (env roots may only narrow, not widen).
 */
export function withKeyFile<T>(content: Record<string, unknown>, fn: (keyPath: string) => T): T {
  const home = mkdtempSync(join(tmpdir(), "sohopay-cli-home-"));
  const root = join(home, ".agents", "sohopay-agent-workload");
  mkdirSync(root, { recursive: true, mode: 0o700 });
  chmodSync(root, 0o700);
  const keyPath = join(root, "secret.json");
  writeFileSync(keyPath, JSON.stringify(content), { mode: 0o600 });
  chmodSync(keyPath, 0o600);
  const prevHome = process.env.HOME;
  const prevRoots = process.env.SOHOPAY_SIGNER_KEY_ROOTS;
  process.env.HOME = home;
  delete process.env.SOHOPAY_SIGNER_KEY_ROOTS;
  try {
    return fn(keyPath);
  } finally {
    if (prevHome === undefined) delete process.env.HOME;
    else process.env.HOME = prevHome;
    if (prevRoots !== undefined) process.env.SOHOPAY_SIGNER_KEY_ROOTS = prevRoots;
    rmSync(home, { recursive: true, force: true });
  }
}
