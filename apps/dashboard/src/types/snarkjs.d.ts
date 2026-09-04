/**
 * Minimal ambient types for snarkjs, which ships none.
 *
 * Deliberately narrow: only groth16's two entry points are declared, so a
 * typo in a member name is still a compile error rather than being swallowed
 * by a blanket module declaration.
 */
declare module "snarkjs" {
  export namespace groth16 {
    function fullProve(
      input: Record<string, unknown>,
      wasm: Uint8Array | string,
      zkey: Uint8Array | string,
    ): Promise<{ proof: any; publicSignals: string[] }>;

    function verify(
      vkey: unknown,
      publicSignals: string[],
      proof: unknown,
    ): Promise<boolean>;
  }
}
