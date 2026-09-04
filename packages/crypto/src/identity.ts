/**
 * Winner-identity witness construction. Spec Section 23, plan Section 9.7.
 *
 * The winner runs this AFTER the award, to publish who it is. Everything the
 * circuit needs is material the winner already holds: the credential, the
 * issuer signature, the registry path, and the opened bid values.
 */
import { getBytes, keccak256 } from "ethers";
import { DOMAIN_IDENTITY_V1, RAW_IDENTITY_RECORD_V1, SCHEMA_VERSION } from "./domains.js";
import { concatBytes, toField } from "./field.js";
import { jcsCanonicalize } from "./encoding.js";
import { bidCommitment, nullifier as computeNullifier, poseidon } from "./poseidon.js";
import type { SignedCredential } from "./witness.js";

/**
 * The record the winner publishes.
 *
 * `credentialId` is included deliberately: it is what lets the issuer that
 * signed the credential - and any auditor - confirm the declaration against
 * the firm it actually issued to. Without it the record would be an
 * unfalsifiable self-description.
 */
export interface LegalIdentityRecord {
  credentialId: number;
  legalName: string;
  registrationNumber: string;
  tradeLicence: string;
  vatBin: string;
}

/** toField(keccak256(RAW_IDENTITY_RECORD_V1 || JCS(record))). Spec Section 23. */
export function legalIdentityHash(canonicalRecord: string): bigint {
  return toField(
    keccak256(
      concatBytes(
        getBytes(RAW_IDENTITY_RECORD_V1),
        new TextEncoder().encode(canonicalRecord),
      ),
    ),
  );
}

/**
 * legalIdentityCommitment = Poseidon2(Poseidon2(DOMAIN_IDENTITY_V1,
 *                                               credentialId),
 *                                     legalIdentityHash)
 *
 * Two nested arity-2 hashes rather than one arity-3, so the contract needs
 * only the PoseidonT3 library it already links. The nesting order is fixed by
 * the specification, not a detail.
 */
export function legalIdentityCommitment(
  credentialId: bigint,
  identityHash: bigint,
): bigint {
  return poseidon([poseidon([DOMAIN_IDENTITY_V1, credentialId]), identityHash]);
}

export interface WinnerIdentityWitness {
  // private
  subjectSecret: bigint;
  annualTurnover: bigint;
  relevantExperience: bigint;
  certificationCode: bigint;
  certValidUntil: bigint;
  credentialValidUntil: bigint;
  credentialId: bigint;
  issuerEpoch: bigint;
  issuedAt: bigint;
  issuerPubKeyX: bigint;
  issuerPubKeyY: bigint;
  issuerSigR8x: bigint;
  issuerSigR8y: bigint;
  issuerSigS: bigint;
  issuerPathElements: bigint[];
  issuerPathIndices: number[];
  bidAmount: bigint;
  bidNonce: bigint;
  legalIdentityHash: bigint;
  // public
  tenderIdField: bigint;
  winnerCommitment: bigint;
  nullifier: bigint;
  legalIdentityCommitment: bigint;
  issuerRegistryRoot: bigint;
}

export function buildWinnerIdentityWitness(params: {
  credential: SignedCredential;
  subjectSecret: bigint;
  bidAmount: bigint;
  bidNonce: bigint;
  tenderIdField: bigint;
  issuerRegistryRoot: bigint;
  issuerPathElements: bigint[];
  issuerPathIndices: number[];
  record: LegalIdentityRecord;
}): WinnerIdentityWitness {
  const f = params.credential.fields;
  if (f.schemaVersion !== SCHEMA_VERSION) {
    throw new Error(
      `buildWinnerIdentityWitness: credential schemaVersion ${f.schemaVersion} ` +
        `!= supported ${SCHEMA_VERSION}`,
    );
  }
  if (BigInt(params.record.credentialId) !== f.credentialId) {
    throw new Error(
      `buildWinnerIdentityWitness: the record declares credentialId ` +
        `${params.record.credentialId} but the credential carries ${f.credentialId}. ` +
        `The contract recomputes the commitment from the record, so a mismatch ` +
        `would fail verification with no indication of which value was wrong.`,
    );
  }

  const canonical = jcsCanonicalize(params.record);
  const idHash = legalIdentityHash(canonical);
  const nul = computeNullifier(params.subjectSecret, params.tenderIdField);

  return {
    subjectSecret: params.subjectSecret,
    annualTurnover: f.annualTurnover,
    relevantExperience: f.relevantExperience,
    certificationCode: f.certificationCode,
    certValidUntil: f.certValidUntil,
    credentialValidUntil: f.credentialValidUntil,
    credentialId: f.credentialId,
    issuerEpoch: f.issuerEpoch,
    issuedAt: f.issuedAt,
    issuerPubKeyX: params.credential.issuerPublicKey.x,
    issuerPubKeyY: params.credential.issuerPublicKey.y,
    issuerSigR8x: params.credential.signature.R8x,
    issuerSigR8y: params.credential.signature.R8y,
    issuerSigS: params.credential.signature.S,
    issuerPathElements: [...params.issuerPathElements],
    issuerPathIndices: [...params.issuerPathIndices],
    bidAmount: params.bidAmount,
    bidNonce: params.bidNonce,
    legalIdentityHash: idHash,
    tenderIdField: params.tenderIdField,
    winnerCommitment: bidCommitment({
      bidAmount: params.bidAmount,
      bidNonce: params.bidNonce,
      tenderIdField: params.tenderIdField,
      nullifier: nul,
    }),
    nullifier: nul,
    legalIdentityCommitment: legalIdentityCommitment(f.credentialId, idHash),
    issuerRegistryRoot: params.issuerRegistryRoot,
  };
}

/** The circuit input object, all values as decimal strings. */
export function winnerIdentityCircuitInput(
  w: WinnerIdentityWitness,
): Record<string, string | string[]> {
  const s = (v: bigint) => v.toString();
  return {
    subjectSecret: s(w.subjectSecret),
    annualTurnover: s(w.annualTurnover),
    relevantExperience: s(w.relevantExperience),
    certificationCode: s(w.certificationCode),
    certValidUntil: s(w.certValidUntil),
    credentialValidUntil: s(w.credentialValidUntil),
    credentialId: s(w.credentialId),
    issuerEpoch: s(w.issuerEpoch),
    issuedAt: s(w.issuedAt),
    issuerPubKeyX: s(w.issuerPubKeyX),
    issuerPubKeyY: s(w.issuerPubKeyY),
    issuerSigR8x: s(w.issuerSigR8x),
    issuerSigR8y: s(w.issuerSigR8y),
    issuerSigS: s(w.issuerSigS),
    issuerPathElements: w.issuerPathElements.map(String),
    issuerPathIndices: w.issuerPathIndices.map(String),
    bidAmount: s(w.bidAmount),
    bidNonce: s(w.bidNonce),
    legalIdentityHash: s(w.legalIdentityHash),
    tenderIdField: s(w.tenderIdField),
    winnerCommitment: s(w.winnerCommitment),
    nullifier: s(w.nullifier),
    legalIdentityCommitment: s(w.legalIdentityCommitment),
    issuerRegistryRoot: s(w.issuerRegistryRoot),
  };
}

/** Public signals in the frozen order. Spec Section 18, as amended. */
export function winnerIdentityPublicSignals(w: WinnerIdentityWitness): bigint[] {
  return [
    w.tenderIdField,
    w.winnerCommitment,
    w.nullifier,
    w.legalIdentityCommitment,
    w.issuerRegistryRoot,
  ];
}
