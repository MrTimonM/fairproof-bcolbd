/**
 * Domain separation constants. Spec Section 3.
 *
 * Every hash in the system gets a distinct domain constant, so a digest
 * computed for one purpose can never be reinterpreted as another
 * (development plan Section 21.2).
 *
 * Two forms are needed:
 *   - RAW_*   : the full 32-byte keccak digest, for byte concatenation
 *   - DOMAIN_*: the 248-bit field element, for use as a Poseidon input
 *
 * The values are DERIVED here and asserted against committed literals in
 * test/domains.test.ts, so they cannot drift silently.
 */
import { keccak256, toUtf8Bytes } from "ethers";
import { toField } from "./field.js";

function raw(label: string): string {
  return keccak256(toUtf8Bytes(label));
}

// Raw 32-byte digests, used as byte prefixes in concatenated preimages.
export const RAW_TENDER_ID_V1 = raw("FairProof:tenderId:v1");
export const RAW_CIPHERTEXT_V1 = raw("FairProof:ciphertext:v1");
export const RAW_RECEIPT_V1 = raw("FairProof:receipt:v1");
/** Key-derivation domain for the ElGamal-wrapped DEK. Spec Section 20. */
export const RAW_DEK_V1 = raw("FairProof:dek:v1");
/** Fiat-Shamir challenge domain for Chaum-Pedersen DLEQ. Spec Section 21. */
export const RAW_DLEQ_V1 = raw("FairProof:dleq:v1");
/**
 * Domain for the legal identity RECORD digest. Spec Section 23.
 *
 * Separate from DOMAIN_IDENTITY_V1 below: one separates the keccak over the
 * published record, the other the Poseidon commitment the circuit proves.
 * Sharing a constant between a keccak preimage and a Poseidon input is the
 * kind of reuse domain separation exists to prevent.
 */
export const RAW_IDENTITY_RECORD_V1 = raw("FairProof:identityRecord:v1");
/**
 * Signing domain for a storage receipt. Spec Section 22.
 *
 * Distinct from RAW_RECEIPT_V1, which domain-separates the receipt LEAF.
 * Reusing one constant for both would let a leaf preimage be presented as a
 * signature preimage.
 */
export const RAW_RECEIPT_SIG_V1 = raw("FairProof:receiptSig:v1");

// Field-element domains, used as the first input to a Poseidon call.
export const DOMAIN_CRED_V1 = toField(raw("FairProof:cred:v1"));
export const DOMAIN_LEAF_V1 = toField(raw("FairProof:leaf:v1"));
export const DOMAIN_PADDING_V1 = toField(raw("FairProof:padding:v1"));
export const DOMAIN_NULLIFIER_V1 = toField(raw("FairProof:nullifier:v1"));
export const DOMAIN_BIDCOMMIT_V1 = toField(raw("FairProof:bidCommitment:v1"));
export const DOMAIN_SUBJECT_V1 = toField(raw("FairProof:subject:v1"));
/** Winner identity binding. Spec Section 23. */
export const DOMAIN_IDENTITY_V1 = toField(raw("FairProof:identity:v1"));

/** Credential schema version for this release. Spec Section 8. */
export const SCHEMA_VERSION = 1n;

/** Protocol constants that must agree across all three languages. */
export const MAX_BIDS = 32;
export const BID_TREE_DEPTH = 5;
export const ISSUER_TREE_DEPTH = 4;
export const RECEIPT_TREE_DEPTH = 2;
export const REVOCATION_TREE_DEPTH = 32;

/** Opening committee threshold. Whitepaper Section 6: 3-of-5. */
export const COMMITTEE_THRESHOLD = 3;
export const COMMITTEE_SIZE = 5;

/** Ciphertext storage replication. Whitepaper Section 4: 2-of-3. */
export const STORAGE_QUORUM = 2;
export const STORAGE_REPLICAS = 3;

/** Governance council. Whitepaper Section 14: 3-of-4. */
export const COUNCIL_THRESHOLD = 3;
export const COUNCIL_SIZE = 4;
