/** `canonicalize@2` ships a bare CJS default export with no bundled types. */
declare module "canonicalize" {
  const canonicalize: (input: unknown) => string | undefined;
  export default canonicalize;
}
