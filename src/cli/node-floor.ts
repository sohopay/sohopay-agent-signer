/** Minimum Node major this signer runs on. Mirrors package.json "engines". */
export const MIN_NODE_MAJOR = 18;

/** Throws a coded error if the runtime Node major is below the floor. */
export function assertNodeFloor(nodeVersion: string): void {
  const major = Number.parseInt((nodeVersion.split(".")[0] ?? "").trim(), 10);
  if (!Number.isFinite(major) || major < MIN_NODE_MAJOR) {
    const err = new Error(`sohopay-signer requires Node >= ${MIN_NODE_MAJOR}`);
    (err as { code?: string }).code = "NODE_VERSION_UNSUPPORTED";
    throw err;
  }
}
