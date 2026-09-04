/**
 * EdDSA-BabyJubjub signing over Poseidon, for issuer credential signatures.
 *
 * Whitepaper Section 5 clause 1: "issuerSig verifies over the credential
 * fields (EdDSA-BabyJubjub)". docs/field-encoding.md Section 8 pins the
 * message as `credDigest`, a single field element.
 *
 * Uses circomlibjs so the curve arithmetic and Poseidon constants are
 * byte-identical to circomlib's `eddsaposeidon.circom`. Never reimplement
 * this: a subtly different point encoding produces signatures that fail in
 * the circuit for reasons that look like a curve bug.
 */
import { buildEddsa } from "circomlibjs";
import { credDigest, type CredentialFields } from "./poseidon.js";
import { SAFE_MAX } from "./field.js";

type Eddsa = {
  prv2pub(prv: Uint8Array): [Uint8Array, Uint8Array];
  signPoseidon(prv: Uint8Array, msg: Uint8Array): {
    R8: [Uint8Array, Uint8Array];
    S: bigint;
  };
  verifyPoseidon(msg: Uint8Array, sig: unknown, pub: [Uint8Array, Uint8Array]): boolean;
  F: {
    e(v: bigint | string | number): Uint8Array;
    toObject(v: Uint8Array): bigint;
  };
  babyJub: { F: { toObject(v: Uint8Array): bigint } };
};

let eddsaInstance: Eddsa | undefined;

/** Initialise the EdDSA instance once. Must be awaited before signing. */
export async function initEddsa(): Promise<void> {
  if (!eddsaInstance) {
    eddsaInstance = (await buildEddsa()) as unknown as Eddsa;
  }
}

function instance(): Eddsa {
  if (!eddsaInstance) {
    throw new Error("eddsa: call await initEddsa() first");
  }
  return eddsaInstance;
}

/** An issuer's BabyJubjub public key, as the registry and circuit see it. */
export interface IssuerPublicKey {
  x: bigint;
  y: bigint;
}

/** An EdDSA-Poseidon signature in the form the circuit consumes. */
export interface EddsaSignature {
  R8x: bigint;
  R8y: bigint;
  S: bigint;
}

/**
 * Derive the public key from a 32-byte private key.
 *
 * The private key is arbitrary bytes, not a field element: circomlibjs hashes
 * it internally to derive the scalar.
 */
export function derivePublicKey(privateKey: Uint8Array): IssuerPublicKey {
  if (privateKey.length !== 32) {
    throw new Error("derivePublicKey: private key must be 32 bytes");
  }
  const e = instance();
  const pub = e.prv2pub(privateKey);
  return {
    x: e.babyJub.F.toObject(pub[0]),
    y: e.babyJub.F.toObject(pub[1]),
  };
}

/** Sign a single field element with EdDSA-Poseidon. */
export function signField(privateKey: Uint8Array, message: bigint): EddsaSignature {
  if (message > SAFE_MAX * 2n ** 6n) {
    // Not a hard field bound, just a guard against passing raw bytes.
    throw new Error("signField: message does not look like a field element");
  }
  const e = instance();
  const sig = e.signPoseidon(privateKey, e.F.e(message));
  return {
    R8x: e.babyJub.F.toObject(sig.R8[0]),
    R8y: e.babyJub.F.toObject(sig.R8[1]),
    S: sig.S,
  };
}

/** Verify an EdDSA-Poseidon signature. Mirrors the in-circuit check. */
export function verifyField(
  publicKey: IssuerPublicKey,
  message: bigint,
  signature: EddsaSignature,
): boolean {
  const e = instance();
  return e.verifyPoseidon(
    e.F.e(message),
    {
      R8: [e.F.e(signature.R8x), e.F.e(signature.R8y)],
      S: signature.S,
    },
    [e.F.e(publicKey.x), e.F.e(publicKey.y)],
  );
}

/**
 * Sign a credential: compute `credDigest` per spec Section 8 and sign it.
 *
 * This is the issuer's act, and it is the root of input authenticity. It is
 * what separates FairProof from a system that merely proves "someone typed a
 * number above the required threshold" (whitepaper Section 4).
 */
export function signCredential(
  privateKey: Uint8Array,
  fields: CredentialFields,
): { digest: bigint; signature: EddsaSignature } {
  const digest = credDigest(fields);
  return { digest, signature: signField(privateKey, digest) };
}
