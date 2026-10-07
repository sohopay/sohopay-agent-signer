import { lstatSync, mkdirSync, realpathSync, statSync, type Stats } from "node:fs";
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

/** Realpath, or null when the path is absent or unreadable. */
function realOrNull(p: string): string | null {
  try {
    return realpathSync(p);
  } catch {
    return null;
  }
}

/**
 * Ensure-mode "mkdir parent 0700 if missing": create an absent allowed root (and any
 * missing ancestors) at 0700, owner-only. The deepest already-existing ancestor must be
 * a real directory, never a symlink; every component we create is made by us, so it
 * cannot be a symlink. Runs only after the path has been placed under an allowed root,
 * and never creates a subdirectory *below* the root (a missing nested dir still fails
 * the parent-mode check, as before).
 */
function ensureRootExists(root: string): void {
  if (platform() === "win32") {
    try {
      mkdirSync(root, { recursive: true });
    } catch {
      invalid(`cannot create ${root}`);
    }
    return;
  }
  if (lstatOrNull(root) !== null) return; // already present (symlinked-root handling is unchanged)
  const missing: string[] = [];
  let cur = root;
  while (lstatOrNull(cur) === null) {
    missing.unshift(cur);
    const parent = dirname(cur);
    if (parent === cur) break; // reached the filesystem root
    cur = parent;
  }
  const anchor = lstatOrNull(cur);
  if (anchor === null || anchor.isSymbolicLink() || !anchor.isDirectory()) {
    invalid(`${cur} is not a usable parent directory`);
  }
  for (const dir of missing) {
    try {
      mkdirSync(dir, { mode: 0o700 });
    } catch {
      invalid(`cannot create ${dir}`);
    }
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
    const real = realOrNull(anc);
    if (real !== null && roots.includes(real)) return { root: real, canonical: real + abs.slice(anc.length) };
    if (dirname(anc) === anc) break;
  }
  // Fallback for a configured root that does not yet exist on disk (fresh machine):
  // match lexically so ensure mode can create it. Only absent roots qualify, so this
  // never widens acceptance for an existing (possibly symlinked) root, which the
  // realpath walk above already resolves.
  for (const r of roots) {
    if (realOrNull(r) !== null) continue;
    if (abs === r || abs.startsWith(r + sep)) return { root: r, canonical: abs };
  }
  return null;
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

  // Ensure mode provisions an absent allowed root (never a nested subdir below it), so a
  // fresh machine can create its first key — the spec's "mkdir parent 0700 if missing".
  if (mode === "ensure") ensureRootExists(root);

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
