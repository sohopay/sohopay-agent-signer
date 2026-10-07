import { lstatSync, readFileSync, realpathSync, statSync } from "node:fs";
import { homedir, platform, userInfo } from "node:os";
import { isAbsolute, join, resolve, sep } from "node:path";

import { SignerError } from "../errors.js";

const DEFAULT_SUBDIR = [".agents", "sohopay-agent-workload"];
const CONFIG_REL = [".config", "sohopay-signer", "config.json"];

function invalid(message: string): never {
  throw new SignerError("KEY_PATH_INVALID", message);
}

/** Owner==uid, 0600, not a symlink, parent 0700 — the config file is a trusted input. */
function assertConfigFileSecure(path: string): void {
  if (platform() === "win32") return; // ACL-governed; POSIX mode bits not meaningful
  const l = lstatSync(path);
  if (l.isSymbolicLink()) invalid(`${path} is a symlink`);
  const st = statSync(path);
  if (st.uid !== userInfo().uid) invalid(`${path} is not owned by the current user`);
  if ((st.mode & 0o077) !== 0) invalid(`${path} must be 0600`);
  const parent = statSync(join(path, ".."));
  if ((parent.mode & 0o077) !== 0) invalid(`${path} parent dir must be 0700`);
}

function realOrNull(p: string): string | null {
  try { return realpathSync(p); } catch { return null; }
}

/** Reject relative or `..`-bearing entries so a lexical prefix can never escape a root (INV-4). */
function normalizeRootEntry(entry: string, source: string): string {
  if (!isAbsolute(entry) || entry.split(/[\\/]/).includes("..")) {
    invalid(`${source} entry ${entry} must be an absolute path without ".." segments`);
  }
  const abs = resolve(entry);
  return realOrNull(abs) ?? abs;
}

/** Resolve the allowed key roots: compiled default + config file, narrowed by env. */
export function resolveKeyRoots(opts: { homeDir?: string; env?: NodeJS.ProcessEnv } = {}): string[] {
  const home = opts.homeDir ?? homedir();
  const env = opts.env ?? process.env;

  const configured = new Set<string>();
  const def = join(home, ...DEFAULT_SUBDIR);
  configured.add(realOrNull(def) ?? def);

  const cfgPath = join(home, ...CONFIG_REL);
  if (realOrNull(cfgPath) !== null) {
    assertConfigFileSecure(cfgPath);
    let parsed: { keyRoots?: unknown };
    try {
      parsed = JSON.parse(readFileSync(cfgPath, "utf8")) as { keyRoots?: unknown };
    } catch {
      invalid(`${cfgPath} is not valid JSON`);
    }
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      invalid(`${cfgPath} must contain a JSON object`);
    }
    const roots = parsed.keyRoots;
    if (roots !== undefined) {
      if (!Array.isArray(roots) || roots.some((r) => typeof r !== "string")) {
        invalid(`${cfgPath} keyRoots must be an array of strings`);
      }
      for (const r of roots as string[]) configured.add(normalizeRootEntry(r, cfgPath));
    }
  }

  const envRaw = env.SOHOPAY_SIGNER_KEY_ROOTS;
  if (envRaw === undefined || envRaw.length === 0) {
    return [...configured];
  }
  const envRoots = envRaw.split(":").filter((s) => s.length > 0).map((r) => normalizeRootEntry(r, "SOHOPAY_SIGNER_KEY_ROOTS"));
  const narrowed: string[] = [];
  for (const er of envRoots) {
    const ok = [...configured].some((cr) => er === cr || er.startsWith(cr + sep));
    if (!ok) invalid(`SOHOPAY_SIGNER_KEY_ROOTS entry ${er} is not within a configured root`);
    narrowed.push(er);
  }
  return narrowed;
}
