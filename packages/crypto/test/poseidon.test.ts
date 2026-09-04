import { beforeAll, describe, expect, it } from "vitest";
import {
  FIELD_PRIME,
  bidCommitment,
  bidLeaf,
  credDigest,
  initPoseidon,
  nullifier,
  poseidon,
  subjectCommitment,
  tenderIdField,
  zeroHashes,
  DOMAIN_PADDING_V1,
  SCHEMA_VERSION,
} from "../src/index.js";

beforeAll(async () => {
  await initPoseidon();
});

describe("poseidon (spec Sections 7-12)", () => {
  it("matches the circomlib reference vector for Poseidon(1,2)", () => {
    // Canonical circomlibjs test vector; if this changes, the constants are
    // wrong and every hash in the system disagrees with the circuits.
    expect(poseidon([1n, 2n])).toBe(
      7853200120776062878684798364095072458815029376092732009249414926327459813530n,
    );
  });

  it("matches the circomlib reference vector for Poseidon(1)", () => {
    expect(poseidon([1n])).toBe(
      18586133768512220936620570745912940619677854269274689475585506675881198879027n,
    );
  });

  it("rejects arity outside 1..6", () => {
    expect(() => poseidon([])).toThrow(/arity 0/);
    expect(() => poseidon([1n, 2n, 3n, 4n, 5n, 6n, 7n])).toThrow(/arity 7/);
  });

  it("always returns a valid field element", () => {
    for (let i = 0n; i < 20n; i++) {
      expect(poseidon([i, i + 1n])).toBeLessThan(FIELD_PRIME);
    }
  });
});

describe("nullifier binding (whitepaper Section 5 clause 8)", () => {
  const secret = 12345678901234567890n;

  it("is deterministic for the same subject and tender", () => {
    const t = tenderIdField("FP-00014");
    expect(nullifier(secret, t)).toBe(nullifier(secret, t));
  });

  it("differs across tenders, preventing cross-tender linkage", () => {
    const a = nullifier(secret, tenderIdField("FP-00014"));
    const b = nullifier(secret, tenderIdField("FP-00015"));
    expect(a).not.toBe(b);
  });

  it("differs across subjects for the same tender", () => {
    const t = tenderIdField("FP-00014");
    expect(nullifier(secret, t)).not.toBe(nullifier(secret + 1n, t));
  });

  it("subjectCommitment is stable, so reissuance keeps one nullifier per firm", () => {
    expect(subjectCommitment(secret)).toBe(subjectCommitment(secret));
    expect(subjectCommitment(secret)).not.toBe(subjectCommitment(secret + 1n));
  });
});

describe("bidCommitment hiding and binding (whitepaper Table 4)", () => {
  const base = {
    bidAmount: 7400000n,
    bidNonce: 98765432109876543210n,
    tenderIdField: tenderIdField("FP-00014"),
    nullifier: 42n,
  };

  it("defeats the dictionary attack: same amount, different nonce", () => {
    const a = bidCommitment(base);
    const b = bidCommitment({ ...base, bidNonce: base.bidNonce + 1n });
    expect(a).not.toBe(b);
  });

  it("binds the amount", () => {
    expect(bidCommitment(base)).not.toBe(
      bidCommitment({ ...base, bidAmount: 7400001n }),
    );
  });

  it("binds the tender", () => {
    expect(bidCommitment(base)).not.toBe(
      bidCommitment({ ...base, tenderIdField: tenderIdField("FP-00015") }),
    );
  });

  it("binds the nullifier, preventing proof transfer", () => {
    expect(bidCommitment(base)).not.toBe(
      bidCommitment({ ...base, nullifier: 43n }),
    );
  });

  it("range-constrains bidAmount to uint64", () => {
    expect(() => bidCommitment({ ...base, bidAmount: 1n << 64n })).toThrow(
      /bidAmount/,
    );
  });
});

describe("credDigest (spec Section 8)", () => {
  const cred = {
    schemaVersion: SCHEMA_VERSION,
    subjectCommitment: 111n,
    annualTurnover: 500000000n,
    relevantExperience: 60n,
    certificationCode: 9001n,
    certValidUntil: 1790000000n,
    credentialValidUntil: 1800000000n,
    credentialId: 7n,
    issuerEpoch: 1n,
    issuedAt: 1750000000n,
  };

  it("is deterministic", () => {
    expect(credDigest(cred)).toBe(credDigest(cred));
  });

  it("changes when any signed field changes", () => {
    const baseline = credDigest(cred);
    const fields: (keyof typeof cred)[] = [
      "subjectCommitment",
      "annualTurnover",
      "relevantExperience",
      "certificationCode",
      "certValidUntil",
      "credentialValidUntil",
      "credentialId",
      "issuerEpoch",
      "issuedAt",
    ];
    for (const f of fields) {
      const mutated = { ...cred, [f]: cred[f] + 1n };
      expect(credDigest(mutated), `field ${f} is not bound`).not.toBe(baseline);
    }
  });

  it("enforces the declared numeric ranges", () => {
    expect(() =>
      credDigest({ ...cred, annualTurnover: 1n << 64n }),
    ).toThrow(/annualTurnover/);
    expect(() =>
      credDigest({ ...cred, relevantExperience: 1n << 32n }),
    ).toThrow(/relevantExperience/);
  });
});

describe("bid leaf and zero hashes (spec Section 12)", () => {
  const leafArgs = {
    nullifier: 42n,
    bidCommitment: 99n,
    ciphertextHashField: 1234n,
    submissionIndex: 0,
  };

  it("has four inputs plus the domain constant, per whitepaper Section 7", () => {
    // Sanity: changing any of the four changes the leaf.
    const baseline = bidLeaf(leafArgs);
    expect(bidLeaf({ ...leafArgs, nullifier: 43n })).not.toBe(baseline);
    expect(bidLeaf({ ...leafArgs, bidCommitment: 100n })).not.toBe(baseline);
    expect(bidLeaf({ ...leafArgs, ciphertextHashField: 1235n })).not.toBe(baseline);
    expect(bidLeaf({ ...leafArgs, submissionIndex: 1 })).not.toBe(baseline);
  });

  it("range-constrains submissionIndex to uint8", () => {
    expect(() => bidLeaf({ ...leafArgs, submissionIndex: 256 })).toThrow(
      /submissionIndex/,
    );
  });

  it("zero[0] is the padding domain, not zero", () => {
    const zeros = zeroHashes(5);
    expect(zeros[0]).toBe(DOMAIN_PADDING_V1);
    expect(zeros[0]).not.toBe(0n);
  });

  it("a padding leaf can never be confused with a real leaf", () => {
    const zeros = zeroHashes(5);
    expect(bidLeaf(leafArgs)).not.toBe(zeros[0]);
  });

  it("produces depth+1 zero hashes", () => {
    expect(zeroHashes(5)).toHaveLength(6);
  });
});
