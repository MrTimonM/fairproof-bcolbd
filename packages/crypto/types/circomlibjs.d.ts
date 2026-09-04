/**
 * Minimal ambient types for circomlibjs, which ships none.
 *
 * Deliberately narrow: only the members this package actually uses are
 * declared, so a typo in a member name is still a compile error rather than
 * being swallowed by a blanket `any` module declaration.
 *
 * `F` is the field arithmetic object (ffjavascript's ZqField). Its values are
 * Montgomery-form byte arrays, NOT bigints, which is why every value crossing
 * this boundary goes through `F.toObject`. Treating an F element as a bigint
 * silently produces wrong hashes.
 */
declare module "circomlibjs" {
  export interface FField {
    p: bigint;
    e(v: bigint | number | string): unknown;
    toObject(v: unknown): bigint;
    toString(v: unknown, radix?: number): string;
    eq(a: unknown, b: unknown): boolean;
    zero: unknown;
    one: unknown;
  }

  export interface Poseidon {
    (inputs: (bigint | number | string)[]): unknown;
    F: FField;
  }

  export function buildPoseidon(): Promise<Poseidon>;

  export interface Eddsa {
    prv2pub(privateKey: Uint8Array): [unknown, unknown];
    signPoseidon(
      privateKey: Uint8Array,
      message: unknown,
    ): { R8: [unknown, unknown]; S: bigint };
    verifyPoseidon(
      message: unknown,
      signature: { R8: [unknown, unknown]; S: bigint },
      publicKey: [unknown, unknown],
    ): boolean;
    F: FField;
  }

  export function buildEddsa(): Promise<Eddsa>;

  export interface BabyJub {
    F: FField;
    Base8: [unknown, unknown];
    order: bigint;
    subOrder: bigint;
    addPoint(a: [unknown, unknown], b: [unknown, unknown]): [unknown, unknown];
    mulPointEscalar(p: [unknown, unknown], e: bigint): [unknown, unknown];
    inCurve(p: [unknown, unknown]): boolean;
  }

  export function buildBabyjub(): Promise<BabyJub>;
}
