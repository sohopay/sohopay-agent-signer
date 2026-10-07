import { lstatSync, realpathSync, statSync, type Stats } from "node:fs";
import { platform, userInfo } from "node:os";
import { basename, dirname, resolve, sep } from "node:path";

import { SignerError } from "../errors.js";
import { resolveKeyRoots } from "./signer-config.js";

function invalid(message: string): never {
  throw new SignerError("KEY_PATH_INVALID", message);
}

/** lstat never follows links, so a dangling symlink is still reported; only ENOENT means absent. */
function lstatOrNull(path: string): Stats | null {
  try {
    return lstatSync(path);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
    return invalid(`cannot inspect ${path}`);
  }
}

/** No symlink and no `..` from the root down to the target (existing components only). */
function assertNoSymlinkBelow(root: string, target: string): void {
  if (platform() === "win32") return;
  if (target !== root && !target.startsWith(root + sep)) invalid(`${target} is not under ${root}`);
  const rest = target.slice(root.length).split(sep).filter((s) => s.length > 0);
  let cur = root;
  for (const seg of rest) {
    if (seg === "..") invalid("path must not contain ..");
    cur = cur + sep + seg;
    const st = lstatOrNull(cur);
    if (st === null) return; // genuinely absent: nothing below it exists either
    if (st.isSymbolicLink()) invalid(`${cur} is a symlink`);
  }
}

function assertOwnerMode(path: string, denyMask: number): void {
  if (platform() === "win32") return;
  let st: Stats;
  try {
    st = statSync(path);
  } catch {
    return invalid(`${path} cannot be inspected (missing or unreadable)`);
  }
  if (st.uid !== userInfo().uid) invalid(`${path} is not owned by the current user`);
  if ((st.mode & denyMask) !== 0) invalid(`${path} has too-permissive mode`);
}

/**
 * Locate the allowed root containing `abs`. Roots are realpath-resolved, so the
 * lexical prefix of `abs` (e.g. macOS /var -> /private/var) is matched through its
 * realpath; the remainder below the root stays unresolved so symlinks there are caught.
 */
function locateRoot(abs: string, roots: readonly string[]): { root: string; canonical: string } | null {
  for (let anc = abs; ; anc = dirname(anc)) {
    let real: string | null = null;
    try { real = realpathSync(anc); } catch { real = null; }
    if (real !== null && roots.includes(real)) return { root: real, canonical: real + abs.slice(anc.length) };
    if (dirname(anc) === anc) return null;
  }
}

/** Validate a key path for `read` or `ensure`, returning the absolute path. */
export function validateKeyPath(
  path: string,
  mode: "read" | "ensure",
  opts: { homeDir?: string; env?: NodeJS.ProcessEnv } = {},
): string {
  const abs = resolve(path);
  if (basename(abs) !== "secret.json") invalid("key file must be named secret.json");

  const roots = resolveKeyRoots(opts);
  const found = locateRoot(abs, roots);
  if (!found) invalid(`${abs} is not under an allowed key root`);
  const { root } = found;
  const target = found.canonical;

  assertNoSymlinkBelow(root, target);
  assertOwnerMode(dirname(target), 0o077); // parent dir 0700, owner

  if (mode === "read") {
    if (lstatOrNull(target) === null) invalid(`${target} does not exist`);
    assertOwnerMode(target, 0o077); // file 0600, owner
  } else if (lstatOrNull(target) !== null) {
    invalid(`${target} already exists (ensure mode never overwrites)`);
  }
  return target;
}
