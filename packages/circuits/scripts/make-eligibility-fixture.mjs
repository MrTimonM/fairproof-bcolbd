#!/usr/bin/env node
/**
 * Generate real Groth16 eligibility proofs for the contract tests.
 *
 * WHY A COMMITTED FIXTURE RATHER THAN PROVING INSIDE THE TEST.
 *
 * The adapter contract's job is to decide which public signals a proof must
 * carry. Testing that with a proof generated on the fly is circular: the same
 * code would compute the signals for the prover and for the expectation, so a
 * wrong signal order would agree with itself and every test would pass. A
 * fixture generated here, from the frozen spec, and consumed by a Solidity
 * test that independently derives the same values from on-chain tender state,
 * is a genuine cross-check between two implementations.
 *
 * It also keeps the contract suite fast, and makes the proofs inspectable.
 *
 * HOW THE FIXTURE AND THE CHAIN AGREE.
 *
 * `rulesHash` is keccak256 of the canonical rule document. Nobody can pick a
 * keccak preimage, so the document comes FIRST: it lives in
 * fixtures/eligibility.spec.json, this script hashes it to get the limbs, and
 * the contract test submits the same bytes to `setRuleDocument`, where the
 * contract hashes them itself. Both sides arrive at the same value without
 * either trusting the other.
 *
 * The bidding window uses far-future absolute timestamps. A fixture pinned to
 * "now + an hour" would pass on the day it was generated and fail every day
 * afterwards, which is a test that rots.
 *
 * FIXTURES PRODUCED
 *
 *   valid          - the qualified firm, matching the tender exactly.
 *   otherTender    - a proof for a DIFFERENT tenderIdField. Everything about
 *                    it is internally consistent and it verifies against the
 *                    raw Groth16 verifier; the adapter must still reject it.
 *   weakThresholds - a proof against thresholds the bidder chose (turnover 1,
 *                    experience 0). This is the attack the adapter exists to
 *                    stop, so there has to be an artifact that mounts it.
 *   secondBidder   - a different subject, hence a different nullifier, used
 *                    to show two distinct bidders on one tender.
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { keccak256, toUtf8Bytes } from "ethers";
import * as snarkjs from "snarkjs";
import {
  SCHEMA_VERSION,
  DISCLOSE_WINNING_PRICE,
  awardCircuitInput,
  awardPublicSignals,
  buildAwardWitness,
  buildWinnerIdentityWitness,
  combineInExponent,
  dealCommitteeKey,
  decryptionShare,
  initBabyjub,
  mulPoint,
  proveDleq,
  sealBid,
  verifyDleq,
  winnerIdentityCircuitInput,
  winnerIdentityPublicSignals,
  buildEligibilityWitness,
  derivePublicKey,
  emptyRevocationTree,
  revocationTreeWith,
  initEddsa,
  initPoseidon,
  jcsCanonicalize,
  issuerRegistryPath,
  issuerRegistryRoot,
  signCredential,
  subjectCommitment,
  tenderIdField,
  toField,
  toLimbs,
} from "@fairproof/crypto";

const here = dirname(fileURLToPath(import.meta.url));
const pkgRoot = resolve(here, "..");
const fixtureDir = join(pkgRoot, "fixtures");
const wasm = join(pkgRoot, "build/eligibility/eligibility_js/eligibility.wasm");
const zkey = join(pkgRoot, "build/eligibility/eligibility_final.zkey");
const vkeyPath = join(pkgRoot, "build/eligibility/eligibility_verification_key.json");

const spec = JSON.parse(readFileSync(join(fixtureDir, "eligibility.spec.json"), "utf8"));

/**
 * The canonical rule document, byte-for-byte as the contract will store it.
 *
 * Canonicalized here from the structured object in the spec, so the fixture
 * and the contract test cannot drift: there is one object, one JCS
 * implementation, and the resulting string is published in the fixture for
 * the Solidity test to submit verbatim.
 */
const ruleDocument = jcsCanonicalize(spec.ruleDocument);
const rulesHash = keccak256(toUtf8Bytes(ruleDocument));

const big = (v) => BigInt(v);

await initPoseidon();
await initEddsa();
await initBabyjub();

/**
 * A deterministic 3-of-5 committee dealing, and one sealed ciphertext per
 * bidder encrypted to it.
 *
 * The sealed bid belongs in this fixture rather than in the contract test
 * because `bidCommitment` must be the SAME value the proof carries as public
 * signal 11. Deriving it twice from one spec is what makes the agreement
 * between the proof, the ciphertext and the contract meaningful; computing it
 * in the test would make the test agree with itself.
 *
 * The ephemeral scalars are fixed so the ciphertext bytes - and therefore
 * `ciphertextHash` - are stable across regenerations. Production must never
 * fix them: two bids sharing `r` under one tender key share the wrapping key.
 */
const committee = dealCommitteeKey({
  secret: BigInt(spec.committee.secret),
  coefficients: spec.committee.coefficients.map(BigInt),
});

// --- issuer registry ------------------------------------------------------
// Two approved issuers. The credential is signed by the first; the second
// exists so the registry root is a real two-leaf tree rather than a
// degenerate single-leaf one that would hide a path-index bug.
const issuerPriv = new Uint8Array(32).fill(spec.issuer.privByte);
const secondIssuerPriv = new Uint8Array(32).fill(spec.issuer.secondPrivByte);
const issuerKey = derivePublicKey(issuerPriv);
const registryKeys = [issuerKey, derivePublicKey(secondIssuerPriv)];
const registryRoot = issuerRegistryRoot(registryKeys);
const issuerPath = issuerRegistryPath(registryKeys, 0);
const revocation = emptyRevocationTree();

/**
 * The revocation tree the tender's deadline root is pinned from.
 *
 * A DIFFERENT credential is revoked in it, so the deadline root differs from
 * the submission-time root while both bidders stay unrevoked. Were the two
 * roots equal, the original eligibility proof would double as a status proof
 * and the close-time check would be exercised only vacuously.
 */
const deadlineRevocation = revocationTreeWith(
  BigInt(spec.deadlineRevocation.revokedCredentialId),
);

function credential(bidder) {
  const fields = {
    schemaVersion: SCHEMA_VERSION,
    subjectCommitment: subjectCommitment(big(bidder.subjectSecret)),
    annualTurnover: big(bidder.annualTurnover),
    relevantExperience: big(bidder.relevantExperience),
    certificationCode: big(spec.tender.requiredCertificationCode),
    certValidUntil: big(bidder.certValidUntil),
    credentialValidUntil: big(bidder.credentialValidUntil),
    credentialId: big(bidder.credentialId),
    issuerEpoch: big(spec.tender.credentialEpoch),
    issuedAt: big(bidder.issuedAt),
  };
  const { signature } = signCredential(issuerPriv, fields);
  return { fields, signature, issuerPublicKey: issuerKey };
}

/**
 * A CLOSE-TIME STATUS witness: the same eligibility statement, re-evaluated
 * against the pinned deadline root.
 *
 * Only signal 8 changes, so the same circuit, the same ceremony and the same
 * verifier all apply - which is why there is no second trusted setup for
 * status proofs.
 */
function statusWitnessFor(bidder) {
  return buildEligibilityWitness({
    credential: credential(bidder),
    subjectSecret: big(bidder.subjectSecret),
    bidAmount: big(bidder.bidAmount),
    bidNonce: big(bidder.bidNonce),
    tender: {
      tenderIdField: tenderIdField(spec.tender.tenderIdString),
      rulesHash,
      turnoverThreshold: big(spec.tender.turnoverThreshold),
      experienceMonthsThreshold: big(spec.tender.experienceMonthsThreshold),
      requiredCertificationCode: big(spec.tender.requiredCertificationCode),
      deadline: big(spec.tender.deadline),
      issuerRegistryRoot: registryRoot,
      revocationRoot: deadlineRevocation.root,
      credentialEpoch: big(spec.tender.credentialEpoch),
    },
    merkle: {
      issuerPathElements: [...issuerPath.pathElements],
      issuerPathIndices: [...issuerPath.pathIndices],
      // The sibling path for THIS credential in the deadline tree. A zero
      // leaf at its position is what proves non-revocation.
      revocationPathElements: deadlineRevocation.siblingsFor(big(bidder.credentialId)),
    },
  });
}

/** Assemble a witness, optionally overriding the tender it binds to. */
function witnessFor(bidder, tenderOverrides = {}) {
  const tender = {
    tenderIdField: tenderIdField(spec.tender.tenderIdString),
    rulesHash,
    turnoverThreshold: big(spec.tender.turnoverThreshold),
    experienceMonthsThreshold: big(spec.tender.experienceMonthsThreshold),
    requiredCertificationCode: big(spec.tender.requiredCertificationCode),
    deadline: big(spec.tender.deadline),
    issuerRegistryRoot: registryRoot,
    revocationRoot: revocation.root,
    credentialEpoch: big(spec.tender.credentialEpoch),
    ...tenderOverrides,
  };
  return buildEligibilityWitness({
    credential: credential(bidder),
    subjectSecret: big(bidder.subjectSecret),
    bidAmount: big(bidder.bidAmount),
    bidNonce: big(bidder.bidNonce),
    tender,
    merkle: {
      // Copied, not aliased: a shared array reference here once let one
      // fixture's tampering corrupt every later one.
      issuerPathElements: [...issuerPath.pathElements],
      issuerPathIndices: [...issuerPath.pathIndices],
      revocationPathElements: [...revocation.siblings],
    },
  });
}

/** The circuit's input object. Every value is a decimal string. */
function circuitInput(w) {
  const s = (v) => v.toString();
  const arr = (a) => a.map((v) => v.toString());
  return {
    subjectSecret: s(w.subjectSecret),
    annualTurnover: s(w.annualTurnover),
    relevantExperience: s(w.relevantExperience),
    certificationCode: s(w.certificationCode),
    certValidUntil: s(w.certValidUntil),
    credentialValidUntil: s(w.credentialValidUntil),
    credentialId: s(w.credentialId),
    issuedAt: s(w.issuedAt),
    issuerPubKeyX: s(w.issuerPubKeyX),
    issuerPubKeyY: s(w.issuerPubKeyY),
    issuerSigR8x: s(w.issuerSigR8x),
    issuerSigR8y: s(w.issuerSigR8y),
    issuerSigS: s(w.issuerSigS),
    issuerPathElements: arr(w.issuerPathElements),
    issuerPathIndices: arr(w.issuerPathIndices),
    revocationPathElements: arr(w.revocationPathElements),
    bidAmount: s(w.bidAmount),
    bidNonce: s(w.bidNonce),
    tenderIdField: s(w.tenderIdField),
    rulesHashHi: s(w.rulesHashHi),
    rulesHashLo: s(w.rulesHashLo),
    turnoverThreshold: s(w.turnoverThreshold),
    experienceMonthsThreshold: s(w.experienceMonthsThreshold),
    requiredCertificationCode: s(w.requiredCertificationCode),
    deadline: s(w.deadline),
    issuerRegistryRoot: s(w.issuerRegistryRoot),
    revocationRoot: s(w.revocationRoot),
    credentialEpoch: s(w.credentialEpoch),
    nullifier: s(w.nullifier),
    bidCommitment: s(w.bidCommitment),
  };
}

/**
 * The twelve public signals in the frozen order (encoding spec Section 16).
 *
 * Asserted against snarkjs's own `publicSignals` below. snarkjs orders them
 * by the declaration order in `component main { public [...] }`, so if the
 * circuit's public list is ever reordered, this check fails loudly instead of
 * the contract quietly comparing the deadline against a threshold.
 */
function expectedSignalOrder(w) {
  return [
    w.tenderIdField,
    w.rulesHashHi,
    w.rulesHashLo,
    w.turnoverThreshold,
    w.experienceMonthsThreshold,
    w.requiredCertificationCode,
    w.deadline,
    w.issuerRegistryRoot,
    w.revocationRoot,
    w.credentialEpoch,
    w.nullifier,
    w.bidCommitment,
  ].map((v) => v.toString());
}

const vkey = JSON.parse(readFileSync(vkeyPath, "utf8"));

const awardWasm = join(pkgRoot, "build/award/award_js/award.wasm");
const awardZkey = join(pkgRoot, "build/award/award_final.zkey");
const awardVkeyPath = join(pkgRoot, "build/award/award_verification_key.json");
const identityWasm = join(
  pkgRoot, "build/winner_identity/winner_identity_js/winner_identity.wasm",
);
const identityZkey = join(pkgRoot, "build/winner_identity/winner_identity_final.zkey");
const identityVkeyPath = join(
  pkgRoot, "build/winner_identity/winner_identity_verification_key.json",
);

async function prove(label, w) {
  process.stdout.write(`proving ${label} ... `);
  const input = circuitInput(w);
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasm, zkey);

  const expected = expectedSignalOrder(w);
  if (JSON.stringify(publicSignals) !== JSON.stringify(expected)) {
    throw new Error(
      `public signal order mismatch for '${label}'.\n` +
        `snarkjs:  ${JSON.stringify(publicSignals)}\n` +
        `expected: ${JSON.stringify(expected)}\n` +
        `docs/field-encoding.md Section 16 and the circuit's public list have diverged.`,
    );
  }

  // Verify off-chain before committing the fixture. A fixture containing an
  // invalid proof would make every contract test that expects rejection pass
  // for the wrong reason.
  const ok = await snarkjs.groth16.verify(vkey, publicSignals, proof);
  if (!ok) throw new Error(`snarkjs rejected the '${label}' proof`);
  console.log("ok");

  return {
    // Solidity calldata order. snarkjs's pi_b has its two coordinates
    // SWAPPED relative to the generated verifier's expectation; the exported
    // verifier's own `verifyProof` signature is what defines the order, and
    // getting it wrong makes valid proofs fail with no useful message.
    pA: [proof.pi_a[0], proof.pi_a[1]],
    pB: [
      [proof.pi_b[0][1], proof.pi_b[0][0]],
      [proof.pi_b[1][1], proof.pi_b[1][0]],
    ],
    pC: [proof.pi_c[0], proof.pi_c[1]],
    publicSignals,
  };
}

const [primary, second] = spec.bidders;

const primaryWitness = witnessFor(primary);
const secondWitness = witnessFor(second);

const fixtures = {
  valid: await prove("valid", primaryWitness),
  secondBidder: await prove("secondBidder", secondWitness),
  statusValid: await prove("statusValid", statusWitnessFor(primary)),
  statusSecondBidder: await prove("statusSecondBidder", statusWitnessFor(second)),
  otherTender: await prove("otherTender", witnessFor(primary, {
    tenderIdField: tenderIdField(spec.otherTenderIdString),
  })),
  weakThresholds: await prove("weakThresholds", witnessFor(primary, {
    turnoverThreshold: 1n,
    experienceMonthsThreshold: 0n,
  })),
};

/** Seal a bid payload against the fixture committee key. */
async function sealFor(bidder, label, witness) {
  const payload = {
    tenderId: spec.tender.tenderIdString,
    amountMinorUnit: bidder.bidAmount,
    currency: "BDT",
    bidNonce: bidder.bidNonce,
    subjectCommitment: subjectCommitment(big(bidder.subjectSecret)).toString(),
    createdAt: "2026-09-02T10:00:00Z",
  };
  const sealed = await sealBid({
    payload,
    tenderPublicKey: committee.publicKey,
    tenderIdField: witness.tenderIdField,
    nullifier: witness.nullifier,
    ephemeralScalar: BigInt(spec.committee.ephemeralScalars[label]),
  });

  // The commitment the ciphertext binds MUST equal the proof's signal 11. If
  // these ever diverge, an accepted bid could not be opened to the value the
  // award was computed from.
  if (sealed.bidCommitment !== witness.bidCommitment) {
    throw new Error(
      `sealFor(${label}): bidCommitment disagrees with the proof's public signal ` +
        `(${sealed.bidCommitment} vs ${witness.bidCommitment})`,
    );
  }

  return {
    payload,
    ciphertextHash: sealed.ciphertextHash,
    ciphertextHashField: sealed.ciphertextHashField.toString(),
    byteLength: sealed.canonicalBytes.length,
    canonicalBytes: "0x" + Buffer.from(sealed.canonicalBytes).toString("hex"),
    ciphertext: {
      rX: sealed.ciphertext.rX.toString(),
      rY: sealed.ciphertext.rY.toString(),
      wrapped: "0x" + Buffer.from(sealed.ciphertext.wrapped).toString("hex"),
      iv: "0x" + Buffer.from(sealed.ciphertext.iv).toString("hex"),
      ct: "0x" + Buffer.from(sealed.ciphertext.ct).toString("hex"),
      tag: "0x" + Buffer.from(sealed.ciphertext.tag).toString("hex"),
    },
    bidCommitment: sealed.bidCommitment.toString(),
  };
}

const pt = (p) => ({ x: p.x.toString(), y: p.y.toString() });

/**
 * Every member's decryption share for one ciphertext, with a Chaum-Pedersen
 * proof, plus one deliberately forged share.
 *
 * The proofs are generated here rather than in the Solidity test because the
 * contract must be checked against proofs produced by an INDEPENDENT
 * implementation. A test that generated the proof with the same code the
 * contract verifies would only be checking that the code agrees with itself.
 *
 * DLEQ nonces are fixed so the fixture is stable across regenerations.
 * Production must never fix them: two proofs sharing a nonce reveal the
 * secret outright, since subtracting the responses gives (e1 - e2) * x_i.
 */
function openingFor(label, sealed) {
  const R = { x: BigInt(sealed.ciphertext.rX), y: BigInt(sealed.ciphertext.rY) };

  const shares = committee.shares.map((s, i) => {
    const D = decryptionShare(s.share, R);
    const proof = proveDleq({
      secret: s.share,
      ephemeral: R,
      nonce: BigInt(`${1000 + i * 7}${label.length}${"7".repeat(60)}`) % 2736030358979909402780800718157159386076813972158567259200215660948447373041n,
    });
    if (!verifyDleq({ publicShare: s.publicShare, ephemeral: R, decryptionShare: D, proof })) {
      throw new Error(`openingFor(${label}): member ${s.index}'s own proof does not verify`);
    }
    return {
      memberIndex: s.index,
      share: pt(D),
      proof: {
        aX: proof.a.x.toString(),
        aY: proof.a.y.toString(),
        bX: proof.b.x.toString(),
        bY: proof.b.y.toString(),
        z: proof.z.toString(),
      },
    };
  });

  // A forged share: a valid curve point, with member 4's honest proof
  // attached. This is exactly the attack the on-chain DLEQ check exists to
  // stop, so there has to be an artifact that mounts it.
  const honest4 = committee.shares[3];
  const forged = {
    memberIndex: 4,
    share: pt(mulPoint(R, honest4.share + 1n)),
    proof: shares[3].proof,
  };

  // What three shares must combine to, and what the payload must open to.
  const combined = combineInExponent(
    [0, 2, 4].map((i) => ({
      index: committee.shares[i].index,
      point: decryptionShare(committee.shares[i].share, R),
    })),
  );
  const expectedShared = mulPoint(R, BigInt(spec.committee.secret));
  if (combined.x !== expectedShared.x || combined.y !== expectedShared.y) {
    throw new Error(`openingFor(${label}): three shares do not combine to x*R`);
  }

  return {
    ephemeral: pt(R),
    threshold: committee.threshold,
    shares,
    forgedShare: forged,
    expectedShared: pt(expectedShared),
    combiningIndices: [1, 3, 5],
  };
}

const sealedValid = await sealFor(primary, "valid", primaryWitness);
const sealedSecond = await sealFor(second, "secondBidder", secondWitness);

/**
 * The award proof over the two-bid set the contract tests build.
 *
 * The bid amounts, nonces and nullifiers all come from the same spec the
 * eligibility proofs and the sealed ciphertexts came from, so the award's
 * `bidSetRoot` is the root the contract will already hold once both bids are
 * accepted. Nothing here is told to the chain; it is derived from the same
 * source twice and has to agree.
 */
async function proveAward(label, bids, disclosurePolicy) {
  const w = buildAwardWitness({
    bids,
    tenderIdField: tenderIdField(spec.tender.tenderIdString),
    rulesHash,
    disclosurePolicy,
  });

  process.stdout.write(`proving award/${label} ... `);
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    awardCircuitInput(w), awardWasm, awardZkey,
  );

  const expected = awardPublicSignals(w).map(String);
  if (JSON.stringify(publicSignals) !== JSON.stringify(expected)) {
    throw new Error(
      `award/${label}: public signal order mismatch.\n` +
        `snarkjs:  ${JSON.stringify(publicSignals)}\n` +
        `expected: ${JSON.stringify(expected)}\n` +
        `docs/field-encoding.md Section 17 and the circuit's public list have diverged.`,
    );
  }
  const awardVkey = JSON.parse(readFileSync(awardVkeyPath, "utf8"));
  if (!(await snarkjs.groth16.verify(awardVkey, publicSignals, proof))) {
    throw new Error(`snarkjs rejected the award/${label} proof`);
  }
  console.log("ok");

  return {
    winnerIndex: Number(w.winnerIndex),
    winnerCommitment: w.winnerCommitment.toString(),
    winningPrice: w.winningPrice.toString(),
    bidSetRoot: w.bidSetRoot.toString(),
    submissionCount: Number(w.submissionCount),
    disclosurePolicy: Number(w.disclosurePolicy),
    publicSignals,
    pA: [proof.pi_a[0], proof.pi_a[1]],
    pB: [
      [proof.pi_b[0][1], proof.pi_b[0][0]],
      [proof.pi_b[1][1], proof.pi_b[1][0]],
    ],
    pC: [proof.pi_c[0], proof.pi_c[1]],
  };
}

/** The two accepted bids, in submission order, as the authority holds them. */
const awardBids = [
  {
    submissionIndex: 0,
    nullifier: primaryWitness.nullifier,
    bidAmount: big(primary.bidAmount),
    bidNonce: big(primary.bidNonce),
    ciphertextHashField: toField(sealedValid.ciphertextHash),
  },
  {
    submissionIndex: 1,
    nullifier: secondWitness.nullifier,
    bidAmount: big(second.bidAmount),
    bidNonce: big(second.bidNonce),
    ciphertextHashField: toField(sealedSecond.ciphertextHash),
  },
];

const award = {
  // The demo policy: publish the winning price. Bidder A at BDT 74,00,000
  // beats bidder B at BDT 81,50,000, so slot 0 wins.
  disclosed: await proveAward("disclosed", awardBids, DISCLOSE_WINNING_PRICE),
  // The same set under a winner-only policy: winningPrice must be ZERO.
  concealed: await proveAward("concealed", awardBids, 2),
  // A single-bid set, for the contract test that awards one bid.
  singleBid: await proveAward("singleBid", [awardBids[0]], DISCLOSE_WINNING_PRICE),
};

/**
 * The winner's ownership proof.
 *
 * The identity records in the spec are SYNTHETIC. No real company's
 * registration, trade licence or VAT/BIN appears anywhere in this repository.
 */
async function proveIdentity(label, bidder) {
  const w = buildWinnerIdentityWitness({
    credential: credential(bidder),
    subjectSecret: big(bidder.subjectSecret),
    bidAmount: big(bidder.bidAmount),
    bidNonce: big(bidder.bidNonce),
    tenderIdField: tenderIdField(spec.tender.tenderIdString),
    issuerRegistryRoot: registryRoot,
    issuerPathElements: issuerPath.pathElements,
    issuerPathIndices: issuerPath.pathIndices,
    record: bidder.identityRecord,
  });

  process.stdout.write(`proving identity/${label} ... `);
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    winnerIdentityCircuitInput(w), identityWasm, identityZkey,
  );
  const expected = winnerIdentityPublicSignals(w).map(String);
  if (JSON.stringify(publicSignals) !== JSON.stringify(expected)) {
    throw new Error(
      `identity/${label}: public signal order mismatch.\n` +
        `snarkjs:  ${JSON.stringify(publicSignals)}\n` +
        `expected: ${JSON.stringify(expected)}`,
    );
  }
  const vk = JSON.parse(readFileSync(identityVkeyPath, "utf8"));
  if (!(await snarkjs.groth16.verify(vk, publicSignals, proof))) {
    throw new Error(`snarkjs rejected the identity/${label} proof`);
  }
  console.log("ok");

  return {
    credentialId: bidder.identityRecord.credentialId,
    record: bidder.identityRecord,
    canonicalRecord: jcsCanonicalize(bidder.identityRecord),
    legalIdentityHash: w.legalIdentityHash.toString(),
    legalIdentityCommitment: w.legalIdentityCommitment.toString(),
    publicSignals,
    pA: [proof.pi_a[0], proof.pi_a[1]],
    pB: [
      [proof.pi_b[0][1], proof.pi_b[0][0]],
      [proof.pi_b[1][1], proof.pi_b[1][0]],
    ],
    pC: [proof.pi_c[0], proof.pi_c[1]],
  };
}

const identity = {
  winner: await proveIdentity("winner", primary),
  loser: await proveIdentity("loser", second),
};

const out = {
  $comment:
    "Generated by `npm run fixtures:eligibility`. Real Groth16 proofs over the " +
    "ceremony zkey in packages/circuits/ceremony/eligibility.transcript.json. " +
    "Regenerate after any change to the circuit or the ceremony; a stale " +
    "fixture fails the sample-proof check at verifier registration.",
  generatedAt: new Date().toISOString(),
  vkeySha256Note: "see ceremony/eligibility.transcript.json -> verificationKey.sha256",
  nPublic: vkey.nPublic,
  chain: {
    canonicalRuleDocument: ruleDocument,
    rulesHash,
    rulesHashLimbs: (() => {
      const { hi, lo } = toLimbs(rulesHash);
      return { hi: hi.toString(), lo: lo.toString() };
    })(),
    tenderIdString: spec.tender.tenderIdString,
    tenderIdField: tenderIdField(spec.tender.tenderIdString).toString(),
    issuerRegistryRoot: "0x" + registryRoot.toString(16).padStart(64, "0"),
    revocationRoot: "0x" + revocation.root.toString(16).padStart(64, "0"),
    deadlineRevocationRoot:
      "0x" + deadlineRevocation.root.toString(16).padStart(64, "0"),
    deadlineRevokedCredentialId: spec.deadlineRevocation.revokedCredentialId,
  },
  tender: spec.tender,
  committee: {
    $warning:
      "TEST MATERIAL. The secret shares are published so the opening tests " +
      "are reproducible. Never reuse them.",
    threshold: committee.threshold,
    size: committee.size,
    publicKey: pt(committee.publicKey),
    commitments: committee.commitments.map(pt),
    shares: committee.shares.map((s) => ({
      index: s.index,
      share: s.share.toString(),
      publicShare: pt(s.publicShare),
    })),
  },
  sealed: {
    valid: sealedValid,
    secondBidder: sealedSecond,
  },
  opening: {
    valid: openingFor("valid", sealedValid),
    secondBidder: openingFor("secondBidder", sealedSecond),
  },
  award,
  identity,
  fixtures,
};

mkdirSync(fixtureDir, { recursive: true });
writeFileSync(
  join(fixtureDir, "eligibility.proof.json"),
  JSON.stringify(out, null, 2) + "\n",
);
console.log(`\nfixtures/eligibility.proof.json (${Object.keys(fixtures).length} proofs)`);
console.log(`rulesHash ${rulesHash}`);

// snarkjs starts a WebAssembly curve worker pool and does not tear it down,
// so the process hangs after the last proof. Terminating it explicitly is the
// documented workaround; without it this script never exits and a CI job that
// runs it waits for its timeout instead of failing or passing.
if (globalThis.curve_bn128) await globalThis.curve_bn128.terminate();
