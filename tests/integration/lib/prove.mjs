/**
 * Generate an eligibility proof at run time, for a tender created at run time.
 *
 * The committed fixtures use a deadline in 2096 so they never rot. That works
 * for unit tests, which can fast-forward the clock - but the live Besu chain
 * cannot be fast-forwarded, so a tender with a 2096 deadline can never CLOSE
 * and the opening ceremony could never be demonstrated against it.
 *
 * So the opening test builds its own credential, witness and proof for a
 * tender whose deadline is a couple of minutes away. It is slower (proving
 * takes tens of seconds) and it is the only honest way to show the full
 * lifecycle on a real chain.
 */
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import * as snarkjs from "snarkjs";
import {
  DISCLOSE_WINNING_PRICE,
  SCHEMA_VERSION,
  awardCircuitInput,
  awardPublicSignals,
  buildAwardWitness,
  buildEligibilityWitness,
  buildWinnerIdentityWitness,
  derivePublicKey,
  emptyRevocationTree,
  issuerRegistryPath,
  issuerRegistryRoot,
  signCredential,
  subjectCommitment,
  tenderIdField,
  winnerIdentityCircuitInput,
  winnerIdentityPublicSignals,
} from "@fairproof/crypto";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "../../..");
const circuits = join(repoRoot, "packages/circuits");
const wasm = join(circuits, "build/eligibility/eligibility_js/eligibility.wasm");
const zkey = join(circuits, "build/eligibility/eligibility_final.zkey");
const vkeyPath = join(circuits, "build/eligibility/eligibility_verification_key.json");
const awardWasm = join(circuits, "build/award/award_js/award.wasm");
const awardZkey = join(circuits, "build/award/award_final.zkey");
const awardVkeyPath = join(circuits, "build/award/award_verification_key.json");
const identityWasm = join(
  circuits, "build/winner_identity/winner_identity_js/winner_identity.wasm",
);
const identityZkey = join(circuits, "build/winner_identity/winner_identity_final.zkey");
const identityVkeyPath = join(
  circuits, "build/winner_identity/winner_identity_verification_key.json",
);

/** Solidity calldata form. snarkjs's pi_b has its coordinate pairs SWAPPED. */
function calldata(proof) {
  return {
    pA: [BigInt(proof.pi_a[0]), BigInt(proof.pi_a[1])],
    pB: [
      [BigInt(proof.pi_b[0][1]), BigInt(proof.pi_b[0][0])],
      [BigInt(proof.pi_b[1][1]), BigInt(proof.pi_b[1][0])],
    ],
    pC: [BigInt(proof.pi_c[0]), BigInt(proof.pi_c[1])],
  };
}

/** The issuer registry the proof will prove membership in. */
export function buildIssuerRegistry(privByte = 7, secondPrivByte = 3) {
  const issuerPriv = new Uint8Array(32).fill(privByte);
  const issuerKey = derivePublicKey(issuerPriv);
  const keys = [issuerKey, derivePublicKey(new Uint8Array(32).fill(secondPrivByte))];
  return {
    issuerPriv,
    issuerKey,
    keys,
    root: issuerRegistryRoot(keys),
    path: issuerRegistryPath(keys, 0),
    revocation: emptyRevocationTree(),
  };
}

/**
 * Prove eligibility for the given tender parameters.
 *
 * Asserts snarkjs's own public-signal order against the order frozen in
 * docs/field-encoding.md Section 16, so a reordered public list fails loudly
 * here rather than making the contract compare a deadline against a
 * threshold.
 */
export async function proveEligibility({
  registry,
  tenderIdString,
  rulesHash,
  turnoverThreshold,
  experienceMonthsThreshold,
  requiredCertificationCode,
  deadline,
  credentialEpoch,
  subjectSecret,
  bidAmount,
  bidNonce,
  credentialId,
  annualTurnover,
  relevantExperience,
  validUntil,
  issuedAt,
}) {
  const tf = tenderIdField(tenderIdString);

  const fields = {
    schemaVersion: SCHEMA_VERSION,
    subjectCommitment: subjectCommitment(subjectSecret),
    annualTurnover,
    relevantExperience,
    certificationCode: requiredCertificationCode,
    certValidUntil: validUntil,
    credentialValidUntil: validUntil,
    credentialId,
    issuerEpoch: credentialEpoch,
    issuedAt,
  };
  const { signature } = signCredential(registry.issuerPriv, fields);

  const witness = buildEligibilityWitness({
    credential: { fields, signature, issuerPublicKey: registry.issuerKey },
    subjectSecret,
    bidAmount,
    bidNonce,
    tender: {
      tenderIdField: tf,
      rulesHash,
      turnoverThreshold,
      experienceMonthsThreshold,
      requiredCertificationCode,
      deadline,
      issuerRegistryRoot: registry.root,
      revocationRoot: registry.revocation.root,
      credentialEpoch,
    },
    merkle: {
      // Copied, not aliased: a shared array reference here once let one
      // witness's tampering corrupt every later one.
      issuerPathElements: [...registry.path.pathElements],
      issuerPathIndices: [...registry.path.pathIndices],
      revocationPathElements: [...registry.revocation.siblings],
    },
  });

  const str = (v) => v.toString();
  const arr = (a) => a.map(String);
  const input = {
    subjectSecret: str(witness.subjectSecret),
    annualTurnover: str(witness.annualTurnover),
    relevantExperience: str(witness.relevantExperience),
    certificationCode: str(witness.certificationCode),
    certValidUntil: str(witness.certValidUntil),
    credentialValidUntil: str(witness.credentialValidUntil),
    credentialId: str(witness.credentialId),
    issuedAt: str(witness.issuedAt),
    issuerPubKeyX: str(witness.issuerPubKeyX),
    issuerPubKeyY: str(witness.issuerPubKeyY),
    issuerSigR8x: str(witness.issuerSigR8x),
    issuerSigR8y: str(witness.issuerSigR8y),
    issuerSigS: str(witness.issuerSigS),
    issuerPathElements: arr(witness.issuerPathElements),
    issuerPathIndices: arr(witness.issuerPathIndices),
    revocationPathElements: arr(witness.revocationPathElements),
    bidAmount: str(witness.bidAmount),
    bidNonce: str(witness.bidNonce),
    tenderIdField: str(witness.tenderIdField),
    rulesHashHi: str(witness.rulesHashHi),
    rulesHashLo: str(witness.rulesHashLo),
    turnoverThreshold: str(witness.turnoverThreshold),
    experienceMonthsThreshold: str(witness.experienceMonthsThreshold),
    requiredCertificationCode: str(witness.requiredCertificationCode),
    deadline: str(witness.deadline),
    issuerRegistryRoot: str(witness.issuerRegistryRoot),
    revocationRoot: str(witness.revocationRoot),
    credentialEpoch: str(witness.credentialEpoch),
    nullifier: str(witness.nullifier),
    bidCommitment: str(witness.bidCommitment),
  };

  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasm, zkey);

  const expected = [
    witness.tenderIdField, witness.rulesHashHi, witness.rulesHashLo,
    witness.turnoverThreshold, witness.experienceMonthsThreshold,
    witness.requiredCertificationCode, witness.deadline,
    witness.issuerRegistryRoot, witness.revocationRoot, witness.credentialEpoch,
    witness.nullifier, witness.bidCommitment,
  ].map(String);
  if (JSON.stringify(publicSignals) !== JSON.stringify(expected)) {
    throw new Error(
      "public signal order mismatch: docs/field-encoding.md Section 16 and " +
        "the circuit's public list have diverged",
    );
  }

  const vkey = JSON.parse(readFileSync(vkeyPath, "utf8"));
  if (!(await snarkjs.groth16.verify(vkey, publicSignals, proof))) {
    throw new Error("snarkjs rejected the proof it just produced");
  }

  return {
    witness,
    publicSignals: publicSignals.map(BigInt),
    // Solidity calldata order. snarkjs's pi_b has its coordinate pairs
    // SWAPPED relative to the generated verifier's expectation.
    pA: [BigInt(proof.pi_a[0]), BigInt(proof.pi_a[1])],
    pB: [
      [BigInt(proof.pi_b[0][1]), BigInt(proof.pi_b[0][0])],
      [BigInt(proof.pi_b[1][1]), BigInt(proof.pi_b[1][0])],
    ],
    pC: [BigInt(proof.pi_c[0]), BigInt(proof.pi_c[1])],
  };
}

/**
 * snarkjs leaves its WebAssembly curve worker pool running, so a script that
 * proves never exits. Call this at the end.
 */
export async function shutdownProver() {
  if (globalThis.curve_bn128) await globalThis.curve_bn128.terminate();
}

/**
 * Prove the award over a set of opened bids.
 *
 * The witness is built from the bids the AUTHORITY holds after the opening
 * ceremony - amounts and nonces only, never any subjectSecret - and the
 * bidSetRoot it produces must equal the root the chain accumulated. That
 * agreement is checked here rather than left to the contract, because a
 * mismatch discovered in a reverted transaction is far less informative.
 */
export async function proveAward({
  bids,
  tenderIdString,
  rulesHash,
  disclosurePolicy = DISCLOSE_WINNING_PRICE,
  expectedBidSetRoot,
}) {
  const w = buildAwardWitness({
    bids,
    tenderIdField: tenderIdField(tenderIdString),
    rulesHash,
    disclosurePolicy,
  });
  if (expectedBidSetRoot !== undefined && w.bidSetRoot !== expectedBidSetRoot) {
    throw new Error(
      `proveAward: the witness accumulates ${w.bidSetRoot} but the chain holds ` +
        `${expectedBidSetRoot}. The opened bid set does not match what was accepted.`,
    );
  }

  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    awardCircuitInput(w), awardWasm, awardZkey,
  );
  const expected = awardPublicSignals(w).map(String);
  if (JSON.stringify(publicSignals) !== JSON.stringify(expected)) {
    throw new Error("proveAward: public signal order mismatch (spec Section 17)");
  }
  const vkey = JSON.parse(readFileSync(awardVkeyPath, "utf8"));
  if (!(await snarkjs.groth16.verify(vkey, publicSignals, proof))) {
    throw new Error("proveAward: snarkjs rejected the proof it just produced");
  }
  return { witness: w, publicSignals: publicSignals.map(BigInt), ...calldata(proof) };
}

/** Prove the winner's ownership of the winning bid. */
export async function proveWinnerIdentity({
  registry,
  credential,
  subjectSecret,
  bidAmount,
  bidNonce,
  tenderIdString,
  record,
}) {
  const w = buildWinnerIdentityWitness({
    credential,
    subjectSecret,
    bidAmount,
    bidNonce,
    tenderIdField: tenderIdField(tenderIdString),
    issuerRegistryRoot: registry.root,
    issuerPathElements: registry.path.pathElements,
    issuerPathIndices: registry.path.pathIndices,
    record,
  });
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    winnerIdentityCircuitInput(w), identityWasm, identityZkey,
  );
  const expected = winnerIdentityPublicSignals(w).map(String);
  if (JSON.stringify(publicSignals) !== JSON.stringify(expected)) {
    throw new Error("proveWinnerIdentity: public signal order mismatch (spec Section 18)");
  }
  const vkey = JSON.parse(readFileSync(identityVkeyPath, "utf8"));
  if (!(await snarkjs.groth16.verify(vkey, publicSignals, proof))) {
    throw new Error("proveWinnerIdentity: snarkjs rejected the proof it just produced");
  }
  return { witness: w, publicSignals: publicSignals.map(BigInt), ...calldata(proof) };
}

/**
 * Build a signed credential the way the issuer would, so the identity proof
 * and the eligibility proof share one credential.
 */
export function issueCredential(registry, bidder) {
  const fields = {
    schemaVersion: SCHEMA_VERSION,
    subjectCommitment: subjectCommitment(bidder.subjectSecret),
    annualTurnover: bidder.annualTurnover,
    relevantExperience: bidder.relevantExperience,
    certificationCode: bidder.certificationCode,
    certValidUntil: bidder.validUntil,
    credentialValidUntil: bidder.validUntil,
    credentialId: bidder.credentialId,
    issuerEpoch: bidder.credentialEpoch,
    issuedAt: bidder.issuedAt,
  };
  const { signature } = signCredential(registry.issuerPriv, fields);
  return { fields, signature, issuerPublicKey: registry.issuerKey };
}
