/**
 * Witness construction for the eligibility circuit.
 *
 * The private witness never leaves the bidder's device (whitepaper Figure 3),
 * so this module runs in the browser. It must not log, serialise or transmit
 * any field it receives.
 */
import { ISSUER_TREE_DEPTH, REVOCATION_TREE_DEPTH, SCHEMA_VERSION } from "./domains.js";
import { toLimbs } from "./field.js";
import { IncrementalMerkleTree, rootFromLeaves } from "./merkle.js";
import {
  bidCommitment,
  nullifier as computeNullifier,
  poseidon,
  subjectCommitment,
  type CredentialFields,
} from "./poseidon.js";
import type { EddsaSignature, IssuerPublicKey } from "./eddsa.js";

/** A signed credential as held by the bidder. */
export interface SignedCredential {
  fields: CredentialFields;
  signature: EddsaSignature;
  issuerPublicKey: IssuerPublicKey;
}

/** The tender's public rule parameters, as frozen on-chain. */
export interface TenderPublicInputs {
  tenderIdField: bigint;
  rulesHash: string;
  turnoverThreshold: bigint;
  experienceMonthsThreshold: bigint;
  requiredCertificationCode: bigint;
  deadline: bigint;
  issuerRegistryRoot: bigint;
  revocationRoot: bigint;
  credentialEpoch: bigint;
}

/** Merkle witnesses the bidder obtains from the registry's published state. */
export interface MerkleWitnesses {
  issuerPathElements: bigint[];
  issuerPathIndices: number[];
  revocationPathElements: bigint[];
}

/**
 * The issuer-registry leaf. Commits to BOTH coordinates, so a prover cannot
 * swap in a different curve point sharing one coordinate.
 */
export function issuerRegistryLeaf(key: IssuerPublicKey): bigint {
  return poseidon([key.x, key.y]);
}

/** Build the issuer registry root from the approved keys, in order. */
export function issuerRegistryRoot(keys: IssuerPublicKey[]): bigint {
  return rootFromLeaves(keys.map(issuerRegistryLeaf), ISSUER_TREE_DEPTH);
}

/**
 * Inclusion path for an issuer key in the registry tree.
 * Mirrors IncrementalMerkleTree.proof but over the padded key list.
 */
export function issuerRegistryPath(
  keys: IssuerPublicKey[],
  index: number,
): { pathElements: bigint[]; pathIndices: number[] } {
  const tree = new IncrementalMerkleTree(ISSUER_TREE_DEPTH);
  for (const k of keys) tree.insert(issuerRegistryLeaf(k));
  const proof = tree.proof(index);
  return { pathElements: proof.siblings, pathIndices: proof.pathIndices };
}

/**
 * An all-zero sparse revocation tree: no credential is revoked.
 *
 * Zero IS the correct empty value for this tree, unlike the bid tree. It is a
 * sparse tree keyed by credentialId, and whitepaper Section 5 specifies "a
 * zero-valued leaf proves non-revocation", so an all-zero subtree is the
 * expected default state rather than an ambiguity.
 */
export function emptyRevocationTree(depth: number = REVOCATION_TREE_DEPTH): {
  root: bigint;
  siblings: bigint[];
} {
  const siblings: bigint[] = [];
  let node = 0n;
  for (let i = 0; i < depth; i++) {
    siblings.push(node);
    node = poseidon([node, node]);
  }
  return { root: node, siblings };
}

/**
 * A sparse revocation tree with a single credential revoked.
 *
 * Returns the root, plus the sibling path for ANY other credential id (which
 * still proves non-revocation) and for the revoked one (which must fail).
 */
export function revocationTreeWith(
  revokedCredentialId: bigint,
  markerValue: bigint = 1n,
  depth: number = REVOCATION_TREE_DEPTH,
): { root: bigint; siblingsFor(credentialId: bigint): bigint[] } {
  // Path bits of the revoked id, least-significant first, matching Num2Bits.
  const revokedBits: number[] = [];
  for (let i = 0; i < depth; i++) {
    revokedBits.push(Number((revokedCredentialId >> BigInt(i)) & 1n));
  }

  // Empty-subtree hashes.
  const zeros: bigint[] = [];
  let z = 0n;
  for (let i = 0; i < depth; i++) {
    zeros.push(z);
    z = poseidon([z, z]);
  }

  // Nodes along the revoked path, from leaf upward.
  const pathNodes: bigint[] = [markerValue];
  for (let level = 0; level < depth; level++) {
    const node = pathNodes[level];
    const sibling = zeros[level];
    pathNodes.push(
      revokedBits[level] === 1 ? poseidon([sibling, node]) : poseidon([node, sibling]),
    );
  }
  const root = pathNodes[depth];

  return {
    root,
    /**
     * Siblings for `credentialId`.
     *
     * At level L the query node covers block `credentialId >> L`, and its
     * sibling covers `(credentialId >> L) ^ 1`. The revoked leaf is inside
     * that sibling block exactly when `revokedId >> L` equals it - and then
     * the sibling is the revoked path's node at that level. Everywhere else
     * the sibling is an empty subtree.
     *
     * The earlier version compared single bits and stopped at the first
     * difference, which is not the same predicate: two ids can differ at a
     * low bit while still sharing a subtree higher up, so it placed the
     * revoked subtree at the wrong level and produced a root that did not
     * match.
     */
    siblingsFor(credentialId: bigint): bigint[] {
      const siblings: bigint[] = [];
      for (let level = 0; level < depth; level++) {
        const queryBlock = credentialId >> BigInt(level);
        const siblingBlock = queryBlock ^ 1n;
        const revokedBlock = revokedCredentialId >> BigInt(level);
        siblings.push(revokedBlock === siblingBlock ? pathNodes[level] : zeros[level]);
      }
      return siblings;
    },
  };
}

/** All inputs the circuit needs, private and public. */
export interface EligibilityWitness {
  // private
  subjectSecret: bigint;
  annualTurnover: bigint;
  relevantExperience: bigint;
  certificationCode: bigint;
  certValidUntil: bigint;
  credentialValidUntil: bigint;
  credentialId: bigint;
  issuedAt: bigint;
  issuerPubKeyX: bigint;
  issuerPubKeyY: bigint;
  issuerSigR8x: bigint;
  issuerSigR8y: bigint;
  issuerSigS: bigint;
  issuerPathElements: bigint[];
  issuerPathIndices: number[];
  revocationPathElements: bigint[];
  bidAmount: bigint;
  bidNonce: bigint;
  // public
  tenderIdField: bigint;
  rulesHashHi: bigint;
  rulesHashLo: bigint;
  turnoverThreshold: bigint;
  experienceMonthsThreshold: bigint;
  requiredCertificationCode: bigint;
  deadline: bigint;
  issuerRegistryRoot: bigint;
  revocationRoot: bigint;
  credentialEpoch: bigint;
  nullifier: bigint;
  bidCommitment: bigint;
}

/**
 * Assemble the eligibility witness.
 *
 * The nullifier and bid commitment are DERIVED here rather than accepted as
 * inputs, so the caller cannot accidentally submit a public signal that
 * disagrees with the witness - the circuit would reject it, but far less
 * legibly than a mismatch caught in TypeScript.
 */
export function buildEligibilityWitness(params: {
  credential: SignedCredential;
  subjectSecret: bigint;
  bidAmount: bigint;
  bidNonce: bigint;
  tender: TenderPublicInputs;
  merkle: MerkleWitnesses;
}): EligibilityWitness {
  const { credential, subjectSecret, bidAmount, bidNonce, tender, merkle } = params;
  const f = credential.fields;

  // The credential must actually belong to this subject secret, or the
  // in-circuit clause 4 check fails.
  const expectedSubject = subjectCommitment(subjectSecret);
  if (f.subjectCommitment !== expectedSubject) {
    throw new Error(
      "buildEligibilityWitness: credential subjectCommitment does not match " +
        "the supplied subjectSecret (whitepaper clause 4 would fail)",
    );
  }
  if (f.schemaVersion !== SCHEMA_VERSION) {
    throw new Error(
      `buildEligibilityWitness: credential schemaVersion ${f.schemaVersion} ` +
        `!= supported ${SCHEMA_VERSION}`,
    );
  }

  const nul = computeNullifier(subjectSecret, tender.tenderIdField);
  const commitment = bidCommitment({
    bidAmount,
    bidNonce,
    tenderIdField: tender.tenderIdField,
    nullifier: nul,
  });
  const { hi, lo } = toLimbs(tender.rulesHash);

  return {
    subjectSecret,
    annualTurnover: f.annualTurnover,
    relevantExperience: f.relevantExperience,
    certificationCode: f.certificationCode,
    certValidUntil: f.certValidUntil,
    credentialValidUntil: f.credentialValidUntil,
    credentialId: f.credentialId,
    issuedAt: f.issuedAt,
    issuerPubKeyX: credential.issuerPublicKey.x,
    issuerPubKeyY: credential.issuerPublicKey.y,
    issuerSigR8x: credential.signature.R8x,
    issuerSigR8y: credential.signature.R8y,
    issuerSigS: credential.signature.S,
    issuerPathElements: merkle.issuerPathElements,
    issuerPathIndices: merkle.issuerPathIndices,
    revocationPathElements: merkle.revocationPathElements,
    bidAmount,
    bidNonce,
    tenderIdField: tender.tenderIdField,
    rulesHashHi: hi,
    rulesHashLo: lo,
    turnoverThreshold: tender.turnoverThreshold,
    experienceMonthsThreshold: tender.experienceMonthsThreshold,
    requiredCertificationCode: tender.requiredCertificationCode,
    deadline: tender.deadline,
    issuerRegistryRoot: tender.issuerRegistryRoot,
    revocationRoot: tender.revocationRoot,
    credentialEpoch: f.issuerEpoch,
    nullifier: nul,
    bidCommitment: commitment,
  };
}
