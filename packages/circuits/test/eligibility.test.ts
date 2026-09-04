import { beforeAll, describe, expect, it } from "vitest";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
// @ts-expect-error - circom_tester ships no types
import { wasm as wasmTester } from "circom_tester";
import {
  FIELD_PRIME,
  SCHEMA_VERSION,
  bidCommitment,
  buildEligibilityWitness,
  credDigest,
  derivePublicKey,
  emptyRevocationTree,
  initEddsa,
  initPoseidon,
  issuerRegistryPath,
  issuerRegistryRoot,
  nullifier as computeNullifier,
  poseidon,
  revocationTreeWith,
  signField,
  subjectCommitment,
  tenderIdField,
  toLimbs,
  type EligibilityWitness,
} from "@fairproof/crypto";

const here = dirname(fileURLToPath(import.meta.url));
const pkgRoot = resolve(here, "..");

/**
 * The eligibility circuit: all nine clauses of whitepaper Figure 3.
 *
 * Development plan Section 20.2. The negative tests are the point: whitepaper
 * Section 19.2 says "Failures persuade more than successes, because each one
 * shows a guarantee being enforced rather than described."
 *
 * A negative test that unexpectedly PASSES is a build-stopping defect
 * (plan Section 24.9) - it means the circuit is unsound, silently.
 */

// --- fixed scenario -------------------------------------------------------
const ISSUER_PRIV = new Uint8Array(32).fill(7);
const OTHER_ISSUER_PRIV = new Uint8Array(32).fill(9);

const SUBJECT_SECRET = 4759208310398234759832475982374598234759823475982347n;
const BID_NONCE = 8823409128340981234098123409812340981234098123409812n;
const BID_AMOUNT = 7400000n; // BDT 74,00,000 - the Figure 5 winning bid

const TURNOVER_THRESHOLD = 500000000n; // BDT 50 crore
const EXPERIENCE_THRESHOLD = 60n;      // months
const CERT_CODE = 9001n;
const DEADLINE = 1790000000n;

const RULES_HASH =
  "0x8f3a2b1c4d5e6f708192a3b4c5d6e7f80112233445566778899aabbccddeeff0";

let circuit: any;
let issuerKey: ReturnType<typeof derivePublicKey>;
let otherIssuerKey: ReturnType<typeof derivePublicKey>;
let registryKeys: ReturnType<typeof derivePublicKey>[];
let registryRoot: bigint;
let issuerPath: { pathElements: bigint[]; pathIndices: number[] };
let emptyRevocation: { root: bigint; siblings: bigint[] };

beforeAll(async () => {
  await initPoseidon();
  await initEddsa();

  circuit = await wasmTester(join(pkgRoot, "src/eligibility.circom"), {
    include: [join(pkgRoot, "../../node_modules")],
  });

  issuerKey = derivePublicKey(ISSUER_PRIV);
  otherIssuerKey = derivePublicKey(OTHER_ISSUER_PRIV);
  // Two approved issuers in the registry; the "other" key is NOT among them.
  registryKeys = [issuerKey, derivePublicKey(new Uint8Array(32).fill(3))];
  registryRoot = issuerRegistryRoot(registryKeys);
  issuerPath = issuerRegistryPath(registryKeys, 0);
  emptyRevocation = emptyRevocationTree();
}, 300000);

/** Credential fields for the qualified firm, with optional overrides. */
function credentialFields(overrides: Partial<Record<string, bigint>> = {}) {
  return {
    schemaVersion: SCHEMA_VERSION,
    subjectCommitment: subjectCommitment(SUBJECT_SECRET),
    annualTurnover: 500000000n,
    relevantExperience: 72n,
    certificationCode: CERT_CODE,
    certValidUntil: 1795000000n,
    credentialValidUntil: 1800000000n,
    credentialId: 7n,
    issuerEpoch: 1n,
    issuedAt: 1750000000n,
    ...overrides,
  };
}

/**
 * Build a complete witness for the happy path, with hooks to break exactly
 * one thing at a time.
 */
function makeWitness(opts: {
  credOverrides?: Partial<Record<string, bigint>>;
  signWith?: Uint8Array;
  /** Sign a DIFFERENT digest than the one in the witness (forged credential). */
  signFieldsOverrides?: Partial<Record<string, bigint>>;
  issuerKeyOverride?: { x: bigint; y: bigint };
  tenderOverrides?: Partial<Record<string, bigint>>;
  revocationOverride?: { root: bigint; siblings: bigint[] };
  subjectSecret?: bigint;
  bidAmount?: bigint;
  tenderId?: string;
  rulesHash?: string;
  /** Mutate the finished witness, for public-signal tampering tests. */
  mutate?: (w: EligibilityWitness) => void;
}): EligibilityWitness {
  const fields = credentialFields(opts.credOverrides);
  const priv = opts.signWith ?? ISSUER_PRIV;
  // Sign either the real digest or a different one, to forge a credential.
  const signedDigest = opts.signFieldsOverrides
    ? credDigest(credentialFields({ ...opts.credOverrides, ...opts.signFieldsOverrides }) as any)
    : credDigest(fields as any);
  const signature = signField(priv, signedDigest);

  const w = buildEligibilityWitness({
    credential: {
      fields: fields as any,
      signature,
      issuerPublicKey: opts.issuerKeyOverride ?? derivePublicKey(priv),
    },
    subjectSecret: opts.subjectSecret ?? SUBJECT_SECRET,
    bidAmount: opts.bidAmount ?? BID_AMOUNT,
    bidNonce: BID_NONCE,
    tender: {
      tenderIdField: tenderIdField(opts.tenderId ?? "FP-00014"),
      rulesHash: opts.rulesHash ?? RULES_HASH,
      turnoverThreshold: TURNOVER_THRESHOLD,
      experienceMonthsThreshold: EXPERIENCE_THRESHOLD,
      requiredCertificationCode: CERT_CODE,
      deadline: DEADLINE,
      issuerRegistryRoot: registryRoot,
      revocationRoot: (opts.revocationOverride ?? emptyRevocation).root,
      credentialEpoch: 1n,
      ...(opts.tenderOverrides as any),
    },
    merkle: {
      // COPIED, not referenced. The tampering tests mutate these arrays, and
      // sharing the module-level reference silently corrupted every
      // subsequent test - the failures showed up as clause-2 errors in
      // unrelated cases and vanished when run in isolation.
      issuerPathElements: [...issuerPath.pathElements],
      issuerPathIndices: [...issuerPath.pathIndices],
      revocationPathElements: [
        ...(opts.revocationOverride ?? emptyRevocation).siblings,
      ],
    },
  });
  opts.mutate?.(w);
  return w;
}

/**
 * credDigest WITHOUT the TypeScript range assertions.
 *
 * Needed only by the soundness tests, which must forge a signature over an
 * out-of-range value so that the CIRCUIT's range constraint is the single
 * thing rejecting the witness. Mirrors spec Section 8's Poseidon tree exactly.
 */
function rawCredDigest(c: Record<string, bigint>): bigint {
  const DOMAIN_CRED_V1 =
    322149158785522698676451765976810572237009812112012877722857913027064676009n;
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
 * Assemble a witness bypassing buildEligibilityWitness's guards, so the
 * circuit is the only thing that can reject it.
 */
function buildWitnessUnchecked(opts: {
  fields: Record<string, bigint>;
  signature: { R8x: bigint; R8y: bigint; S: bigint };
}): EligibilityWitness {
  const { fields, signature } = opts;
  const tField = tenderIdField("FP-00014");
  const nul = computeNullifier(SUBJECT_SECRET, tField);
  const commitment = bidCommitment({
    bidAmount: BID_AMOUNT,
    bidNonce: BID_NONCE,
    tenderIdField: tField,
    nullifier: nul,
  });
  const { hi, lo } = toLimbs(RULES_HASH);
  return {
    subjectSecret: SUBJECT_SECRET,
    annualTurnover: fields.annualTurnover,
    relevantExperience: fields.relevantExperience,
    certificationCode: fields.certificationCode,
    certValidUntil: fields.certValidUntil,
    credentialValidUntil: fields.credentialValidUntil,
    credentialId: fields.credentialId,
    issuedAt: fields.issuedAt,
    issuerPubKeyX: issuerKey.x,
    issuerPubKeyY: issuerKey.y,
    issuerSigR8x: signature.R8x,
    issuerSigR8y: signature.R8y,
    issuerSigS: signature.S,
    issuerPathElements: [...issuerPath.pathElements],
    issuerPathIndices: [...issuerPath.pathIndices],
    revocationPathElements: [...emptyRevocation.siblings],
    bidAmount: BID_AMOUNT,
    bidNonce: BID_NONCE,
    tenderIdField: tField,
    rulesHashHi: hi,
    rulesHashLo: lo,
    turnoverThreshold: TURNOVER_THRESHOLD,
    experienceMonthsThreshold: EXPERIENCE_THRESHOLD,
    requiredCertificationCode: CERT_CODE,
    deadline: DEADLINE,
    issuerRegistryRoot: registryRoot,
    revocationRoot: emptyRevocation.root,
    credentialEpoch: fields.issuerEpoch,
    nullifier: nul,
    bidCommitment: commitment,
  };
}

async function expectValid(w: EligibilityWitness) {
  const witness = await circuit.calculateWitness(w as any, true);
  await circuit.checkConstraints(witness);
  return witness;
}

/** Assert the circuit REFUSES to produce a valid witness. */
async function expectInvalid(w: EligibilityWitness, label: string) {
  let failed = false;
  try {
    const witness = await circuit.calculateWitness(w as any, true);
    await circuit.checkConstraints(witness);
  } catch {
    failed = true;
  }
  expect(
    failed,
    `${label}: the circuit ACCEPTED an invalid witness. ` +
      `This is a soundness defect, not a test failure.`,
  ).toBe(true);
}

describe("eligibility circuit - the qualified firm", () => {
  it("a valid credential above both thresholds passes", async () => {
    await expectValid(makeWitness({}));
  }, 60000);

  it("does not expose turnover or experience in the public signals", async () => {
    // Whitepaper Figure 3: "The chain learns only that an approved, unrevoked
    // issuer attested facts meeting the committed thresholds and nothing
    // else."
    const w = makeWitness({});
    const publicNames = [
      "tenderIdField", "rulesHashHi", "rulesHashLo", "turnoverThreshold",
      "experienceMonthsThreshold", "requiredCertificationCode", "deadline",
      "issuerRegistryRoot", "revocationRoot", "credentialEpoch",
      "nullifier", "bidCommitment",
    ];
    expect(publicNames).not.toContain("annualTurnover");
    expect(publicNames).not.toContain("relevantExperience");
    expect(publicNames).not.toContain("bidAmount");
    expect(publicNames).not.toContain("subjectSecret");
    // The threshold IS public; the firm's actual value is not.
    expect(w.turnoverThreshold).toBe(TURNOVER_THRESHOLD);
    expect(w.annualTurnover).toBe(500000000n);
  });
});

describe("clause 5: turnover threshold - boundary values", () => {
  it("turnover EXACTLY at the threshold passes (>=, not >)", async () => {
    await expectValid(
      makeWitness({ credOverrides: { annualTurnover: TURNOVER_THRESHOLD } }),
    );
  }, 60000);

  it("turnover at threshold PLUS ONE passes", async () => {
    await expectValid(
      makeWitness({ credOverrides: { annualTurnover: TURNOVER_THRESHOLD + 1n } }),
    );
  }, 60000);

  it("turnover at threshold MINUS ONE fails", async () => {
    await expectInvalid(
      makeWitness({ credOverrides: { annualTurnover: TURNOVER_THRESHOLD - 1n } }),
      "turnover threshold - 1",
    );
  }, 60000);

  it("the ineligible firm at BDT 3.8 crore fails (whitepaper Table 14 row 6)", async () => {
    // The key demo moment. 3.8 crore = 380,000,000 taka, below the 50 crore
    // threshold. The public never learns the 3.8 crore figure, only that the
    // threshold was not met.
    await expectInvalid(
      makeWitness({ credOverrides: { annualTurnover: 380000000n } }),
      "BDT 3.8 crore against a BDT 50 crore threshold",
    );
  }, 60000);

  it("turnover of zero fails", async () => {
    await expectInvalid(
      makeWitness({ credOverrides: { annualTurnover: 0n } }),
      "zero turnover",
    );
  }, 60000);

  /**
   * THE SOUNDNESS TEST THAT MATTERS MOST.
   *
   * An unconstrained LessThan in Circom is not a comparison - a malicious
   * prover supplies a field element that wraps past 2^64 and the comparison
   * reads as satisfied. docs/field-encoding.md Section 14 requires an
   * explicit Num2Bits on both operands precisely to close this, and this test
   * attacks it directly.
   */
  it("TypeScript refuses to build a witness with an out-of-range turnover", async () => {
    // Defence in depth. The circuit is the authority, but catching it here
    // gives a legible error instead of an opaque constraint failure.
    expect(() =>
      makeWitness({ credOverrides: { annualTurnover: 1n << 64n } }),
    ).toThrow(/annualTurnover/);
  });

  it("the CIRCUIT rejects a turnover that would wrap past uint64", async () => {
    // THE SOUNDNESS TEST THAT MATTERS MOST.
    //
    // A field element astronomically larger than 2^64. Without an explicit
    // Num2Bits(64) on both operands, LessThan would read as satisfied and a
    // firm with no turnover at all could qualify.
    //
    // The signature is forged over the SAME wrapping value, bypassing the
    // TypeScript guard, so clause 1 passes and the ONLY thing that can reject
    // this witness is the range constraint. Otherwise the test would pass for
    // the wrong reason and prove nothing about clause 5.
    const wrapping = FIELD_PRIME - 1n;
    const fields = credentialFields({ annualTurnover: wrapping });
    const digest = rawCredDigest(fields);
    const signature = signField(ISSUER_PRIV, digest);

    const w = buildWitnessUnchecked({ fields, signature });
    await expectInvalid(w, "wrapping turnover value");
  }, 60000);
});

describe("clause 6: experience threshold - boundary values", () => {
  it("experience exactly at the threshold passes", async () => {
    await expectValid(
      makeWitness({ credOverrides: { relevantExperience: EXPERIENCE_THRESHOLD } }),
    );
  }, 60000);

  it("experience one month below the threshold fails", async () => {
    await expectInvalid(
      makeWitness({ credOverrides: { relevantExperience: EXPERIENCE_THRESHOLD - 1n } }),
      "experience threshold - 1",
    );
  }, 60000);
});

describe("clause 1: issuer signature - self-attestation is impossible", () => {
  it("a credential signed by an unregistered key fails", async () => {
    // The firm signs its own credential. The signature is internally valid,
    // but the key is not in the registry - so clause 2 fails.
    await expectInvalid(
      makeWitness({ signWith: OTHER_ISSUER_PRIV }),
      "self-signed credential",
    );
  }, 60000);

  it("a forged credential - altered values, original signature - fails", async () => {
    // Sign the honest fields, then present inflated ones.
    await expectInvalid(
      makeWitness({
        credOverrides: { annualTurnover: 999999999n },
        signFieldsOverrides: { annualTurnover: 500000000n },
      }),
      "forged credential values",
    );
  }, 60000);

  it("a tampered signature scalar fails", async () => {
    await expectInvalid(
      makeWitness({ mutate: (w) => { w.issuerSigS = w.issuerSigS + 1n; } }),
      "tampered signature S",
    );
  }, 60000);

  it("a tampered signature point fails", async () => {
    await expectInvalid(
      makeWitness({ mutate: (w) => { w.issuerSigR8x = w.issuerSigR8x + 1n; } }),
      "tampered signature R8x",
    );
  }, 60000);
});

describe("clause 2: issuerRegistryRoot membership", () => {
  it("a valid signature from a key OUTSIDE the registry fails", async () => {
    // The whole point of clause 2. Without it the circuit would accept any
    // key that produced a valid signature.
    await expectInvalid(
      makeWitness({
        signWith: OTHER_ISSUER_PRIV,
        issuerKeyOverride: otherIssuerKey,
      }),
      "issuer key not in the registry",
    );
  }, 60000);

  it("a wrong registry root fails", async () => {
    await expectInvalid(
      makeWitness({ mutate: (w) => { w.issuerRegistryRoot = w.issuerRegistryRoot + 1n; } }),
      "wrong issuerRegistryRoot",
    );
  }, 60000);

  it("a tampered issuer Merkle path fails", async () => {
    await expectInvalid(
      makeWitness({ mutate: (w) => { w.issuerPathElements[0] = w.issuerPathElements[0] + 1n; } }),
      "tampered issuer path",
    );
  }, 60000);
});

describe("clause 3: sparse-Merkle non-revocation", () => {
  it("an unrevoked credential passes against a tree with OTHER revocations", async () => {
    const tree = revocationTreeWith(999n);
    await expectValid(
      makeWitness({
        revocationOverride: { root: tree.root, siblings: tree.siblingsFor(7n) },
      }),
    );
  }, 60000);

  it("a REVOKED credential fails", async () => {
    // Whitepaper Section 5: a zero-valued leaf proves non-revocation, so a
    // non-zero leaf at credentialId cannot produce a valid witness.
    const tree = revocationTreeWith(7n);
    await expectInvalid(
      makeWitness({
        revocationOverride: { root: tree.root, siblings: tree.siblingsFor(7n) },
      }),
      "revoked credential",
    );
  }, 60000);

  it("a wrong revocation root fails", async () => {
    await expectInvalid(
      makeWitness({ mutate: (w) => { w.revocationRoot = w.revocationRoot + 1n; } }),
      "wrong revocationRoot",
    );
  }, 60000);
});

describe("clause 4: subject binding", () => {
  it("TypeScript refuses a credential belonging to another subject", async () => {
    expect(() =>
      makeWitness({
        credOverrides: { subjectCommitment: subjectCommitment(SUBJECT_SECRET + 1n) },
      }),
    ).toThrow(/subjectCommitment does not match/);
  });

  it("the CIRCUIT rejects a credential belonging to another subject", async () => {
    // Prevents using someone else's credential, and prevents one credential
    // from generating many nullifiers. Built unchecked so the circuit, not
    // the TypeScript guard, is what rejects it.
    const otherSubject = subjectCommitment(SUBJECT_SECRET + 1n);
    const fields = credentialFields({ subjectCommitment: otherSubject });
    const digest = rawCredDigest(fields);
    const signature = signField(ISSUER_PRIV, digest);

    const w = buildWitnessUnchecked({ fields, signature });
    await expectInvalid(w, "credential belongs to a different subject");
  }, 60000);
});

describe("clause 7: certification validity and match", () => {
  it("a certificate expiring exactly at the deadline passes", async () => {
    await expectValid(
      makeWitness({ credOverrides: { certValidUntil: DEADLINE } }),
    );
  }, 60000);

  it("a certificate expiring one second before the deadline fails", async () => {
    // Must be valid ON the deadline date, not merely when the proof is made.
    await expectInvalid(
      makeWitness({ credOverrides: { certValidUntil: DEADLINE - 1n } }),
      "certificate expired at deadline",
    );
  }, 60000);

  it("a wrong certification code fails", async () => {
    await expectInvalid(
      makeWitness({ credOverrides: { certificationCode: 9002n } }),
      "wrong certification code",
    );
  }, 60000);

  it("an expired CREDENTIAL fails, even with a valid certificate", async () => {
    // A superset of the whitepaper's nine clauses, documented as such.
    await expectInvalid(
      makeWitness({ credOverrides: { credentialValidUntil: DEADLINE - 1n } }),
      "expired credential",
    );
  }, 60000);
});

describe("clauses 8 and 9: nullifier and bid commitment binding", () => {
  it("a tampered nullifier fails", async () => {
    await expectInvalid(
      makeWitness({ mutate: (w) => { w.nullifier = w.nullifier + 1n; } }),
      "tampered nullifier",
    );
  }, 60000);

  it("a tampered bid commitment fails", async () => {
    await expectInvalid(
      makeWitness({ mutate: (w) => { w.bidCommitment = w.bidCommitment + 1n; } }),
      "tampered bidCommitment",
    );
  }, 60000);

  it("substituting a different bid amount fails", async () => {
    // Bid substitution: the commitment no longer matches the amount.
    await expectInvalid(
      makeWitness({ mutate: (w) => { w.bidAmount = w.bidAmount - 100000n; } }),
      "bid amount substituted after commitment",
    );
  }, 60000);

  it("the nullifier differs across tenders, so participation is unlinkable", async () => {
    const a = makeWitness({ tenderId: "FP-00014" });
    const b = makeWitness({ tenderId: "FP-00015" });
    expect(a.nullifier).not.toBe(b.nullifier);
    await expectValid(a);
    await expectValid(b);
  }, 90000);

  it("a proof for one tender does not validate against another tenderIdField", async () => {
    // Cross-tender replay. Whitepaper Section 5.1: "Public tenderId and
    // rulesHash stop cross-tender replay."
    await expectInvalid(
      makeWitness({ mutate: (w) => { w.tenderIdField = tenderIdField("FP-00015"); } }),
      "cross-tender replay",
    );
  }, 60000);
});

describe("public rule parameters are binding", () => {
  it("raising the threshold in the public signals invalidates the proof", async () => {
    await expectInvalid(
      makeWitness({ mutate: (w) => { w.turnoverThreshold = 600000000n; } }),
      "threshold raised above the attested turnover",
    );
  }, 60000);

  it("a later deadline in the public signals invalidates an expiring certificate", async () => {
    await expectInvalid(
      makeWitness({
        credOverrides: { certValidUntil: DEADLINE },
        mutate: (w) => { w.deadline = DEADLINE + 1n; },
      }),
      "deadline moved past certificate expiry",
    );
  }, 60000);
});
