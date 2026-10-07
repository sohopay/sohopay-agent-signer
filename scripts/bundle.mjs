// scripts/bundle.mjs
import { build } from "esbuild";
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const outDir = process.env.SOHOPAY_BUNDLE_OUTDIR ?? join(root, "dist-bundle");
const outFile = join(outDir, "sohopay-signer.mjs");

const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
if (typeof pkg.version !== "string" || pkg.version.length === 0) {
  throw new Error("cannot resolve a non-empty package.json version for the bundle");
}

mkdirSync(outDir, { recursive: true });

await build({
  entryPoints: [join(root, "src/cli/index.ts")],
  outfile: outFile,
  bundle: true,
  format: "esm",
  platform: "node",
  target: "node18",
  sourcemap: false,
  legalComments: "external", // writes <outfile>.LEGAL.txt
  // No banner: esbuild preserves the entry's own shebang (src/cli/index.ts line 1);
  // adding one here produced a duplicate "#!" line, an ESM SyntaxError.
  define: { __SIGNER_IMPL_VERSION__: JSON.stringify(pkg.version) },
  alias: { "@sohopay/signer-vectors": join(here, "bundle-vectors-shim.mjs") },
});

chmodSync(outFile, 0o755);

const bytes = readFileSync(outFile);
const sha = createHash("sha256").update(bytes).digest("hex");
writeFileSync(`${outFile}.sha256`, `${sha}  sohopay-signer.mjs\n`);

process.stderr.write(`bundled ${outFile} (sha256 ${sha}, version ${pkg.version})\n`);
