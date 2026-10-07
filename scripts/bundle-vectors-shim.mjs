// Build-time replacement for @sohopay/signer-vectors in the bundle. The real package reads
// vectors/index.json from disk at runtime (esbuild cannot see through that), so the bundle
// would break offline. This statically imports the SAME JSON so esbuild inlines it.
// NOTE: the package `exports` map blocks the subpath "@sohopay/signer-vectors/vectors/index.json"
// (ERR_PACKAGE_PATH_NOT_EXPORTED), so we import by a filesystem-relative path into node_modules.
import vectors from "../node_modules/@sohopay/signer-vectors/vectors/index.json" with { type: "json" };

export function loadVectors() {
  return vectors;
}
