/**
 * Poseidon hashing over BN254, and the fixed composite digests of
 * docs/field-encoding.md Sections 7-13.
 *
 * Uses circomlibjs so the constants are byte-identical to the circomlib
 * Circom templates and to generated Solidity. Never reimplement Poseidon.
 */
import { buildPoseidon } from "circomlibjs";
import {
  DOMAIN_BIDCOMMIT_V1,
  DOMAIN_CRED_V1,
  DOMAIN_LEAF_V1,
  DOMAIN_NULLIFIER_V1,
  DOMAIN_PADDING_V1,
  DOMAIN_SUBJECT_V1,
  BID_TREE_DEPTH,
} from "./domains.js";
import { assertUint } from "./field.js";

type PoseidonFn = {
  (inputs: (bigint | number | string)[]): Uint8Array;
  F: { toObject(x: Uint8Array): bigint };
};

let poseidonInstance: PoseidonFn | undefined;

/** Initialise the Poseidon instance once. Must be awaited before hashing. */
export async function initPoseidon(): Promise<void> {
  if (!poseidonInstance) {
    poseidonInstance = (await buildPoseidon()) as PoseidonFn;
  }
}

/**
 * Poseidon over 1..6 field elements. Spec Section 7 caps arity at 6;
 * more inputs must use a documented tree, never ad-hoc chaining.
 */
export function poseidon(inputs: bigint[]): bigint {
  if (!poseidonInstance) {
    throw new Error("poseidon: call await initPoseidon() first");
  }
  if (inputs.length < 1 || inputs.length > 6) {
    throw new Error(
      `poseidon: arity ${inputs.length} out of range; spec allows 1..6`,
    );
  }
  const digest = poseidonInstance(inputs);
  return poseidonInstance.F.toObject(digest);
}

/** subjectCommitment = Poseidon2(DOMAIN_SUBJECT_V1, subjectSecret). Spec 9. */
export function subjectCommitment(subjectSecret: bigint): bigint {
  return poseidon([DOMAIN_SUBJECT_V1, subjectSecret]);
}

/**
 * nullifier = Poseidon3(DOMAIN_NULLIFIER_V1, subjectSecret, tenderIdField).
 * Spec Section 9, whitepaper Section 5 clause 8.
 */
export function nullifier(subjectSecret: bigint, tenderIdField: bigint): bigint {
  return poseidon([DOMAIN_NULLIFIER_V1, subjectSecret, tenderIdField]);
}

/**
 * bidCommitment = Poseidon5(DOMAIN, bidAmount, bidNonce, tenderIdField, nullifier).
 * Spec Section 10, whitepaper Section 5 clause 9.
 *
 * bidNonce is what makes this hiding; without it Poseidon(7400000) is
 * grindable in seconds (whitepaper Table 4).
 */
export function bidCommitment(params: {
  bidAmount: bigint;
  bidNonce: bigint;
  tenderIdField: bigint;
  nullifier: bigint;
}): bigint {
  assertUint(params.bidAmount, 64, "bidAmount");
  return poseidon([
    DOMAIN_BIDCOMMIT_V1,
    params.bidAmount,
    params.bidNonce,
    params.tenderIdField,
    params.nullifier,
  ]);
}

/** Credential fields signed by the issuer. Spec Section 8. */
export interface CredentialFields {
  schemaVersion: bigint;
  subjectCommitment: bigint;
  annualTurnover: bigint;
  relevantExperience: bigint;
  certificationCode: bigint;
  certValidUntil: bigint;
  credentialValidUntil: bigint;
  credentialId: bigint;
  issuerEpoch: bigint;
  issuedAt: bigint;
}

/**
 * credDigest, the single field element the issuer signs with EdDSA-Poseidon.
 * Spec Section 8. THE FIELD ORDER IS CANONICAL - any reordering between this
 * function and the Circom template produces a signature failure that looks
 * like a curve bug.
 */
export function credDigest(c: CredentialFields): bigint {
  assertUint(c.annualTurnover, 64, "annualTurnover");
  assertUint(c.relevantExperience, 32, "relevantExperience");
  assertUint(c.certificationCode, 64, "certificationCode");
  assertUint(c.certValidUntil, 64, "certValidUntil");
  assertUint(c.credentialValidUntil, 64, "credentialValidUntil");
  assertUint(c.credentialId, 64, "credentialId");
  assertUint(c.issuerEpoch, 32, "issuerEpoch");
  assertUint(c.issuedAt, 64, "issuedAt");

  const h1 = poseidon([
    DOMAIN_CRED_V1,
    c.schemaVersion,
    c.subjectCommitment,
    c.annualTurnover,
    c.relevantExperience,
    c.certificationCode,
  ]);
  const h2 = poseidon([
    c.certValidUntil,
    c.credentialValidUntil,
    c.credentialId,
    c.issuerEpoch,
    c.issuedAt,
  ]);
  return poseidon([h1, h2]);
}

/**
 * Bid leaf. Spec Section 12, whitepaper Section 7.
 *
 * FOUR inputs plus the domain constant. storageReceiptRoot is deliberately
 * NOT part of the leaf - it is stored in the bid record and checked at
 * acceptance. An earlier draft of the development plan included it, which
 * would have made every on-chain root disagree with the published award
 * statement.
 */
export function bidLeaf(params: {
  nullifier: bigint;
  bidCommitment: bigint;
  ciphertextHashField: bigint;
  submissionIndex: number;
}): bigint {
  assertUint(BigInt(params.submissionIndex), 8, "submissionIndex");
  return poseidon([
    DOMAIN_LEAF_V1,
    params.nullifier,
    params.bidCommitment,
    params.ciphertextHashField,
    BigInt(params.submissionIndex),
  ]);
}

/**
 * Precomputed empty-subtree hashes for the bid-set tree. Spec Section 12.
 *
 * zero[0] is DOMAIN_PADDING_V1, NOT zero: a zero leaf is indistinguishable
 * from an empty subtree and invites a completeness bypass.
 */
export function zeroHashes(depth: number = BID_TREE_DEPTH): bigint[] {
  const zeros: bigint[] = [DOMAIN_PADDING_V1];
  for (let i = 1; i <= depth; i++) {
    zeros.push(poseidon([zeros[i - 1], zeros[i - 1]]));
  }
  return zeros;
}

/** Merkle parent of two nodes. Spec Section 12. */
export function merkleParent(left: bigint, right: bigint): bigint {
  return poseidon([left, right]);
}
