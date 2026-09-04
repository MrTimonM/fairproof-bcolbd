import { beforeAll, describe, expect, it } from "vitest";
import {
  canonicalCiphertextBytes,
  ciphertextHash,
  ciphertextHashField,
  initPoseidon,
  jcsCanonicalize,
  receiptLeaf,
  rulesHash,
  tenderIdField,
  toLimbs,
  fromLimbs,
} from "../src/index.js";

beforeAll(async () => {
  await initPoseidon();
});

describe("tenderIdField (spec Section 5)", () => {
  it("is deterministic and distinct per tender", () => {
    expect(tenderIdField("FP-00014")).toBe(tenderIdField("FP-00014"));
    expect(tenderIdField("FP-00014")).not.toBe(tenderIdField("FP-00015"));
  });

  it("is a safe field element (248 bits)", () => {
    expect(tenderIdField("FP-00014")).toBeLessThan(1n << 248n);
  });

  it("is domain-separated, so it cannot collide with a bare keccak", () => {
    // A bare keccak of the id, truncated, must differ from the domained form.
    const { keccak256, toUtf8Bytes } = require("ethers");
    const bare = BigInt(keccak256(toUtf8Bytes("FP-00014"))) >> 8n;
    expect(tenderIdField("FP-00014")).not.toBe(bare);
  });
});

describe("JCS canonicalization (RFC 8785, whitepaper Section 4)", () => {
  it("sorts object keys", () => {
    expect(jcsCanonicalize({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
  });

  it("is insensitive to key insertion order", () => {
    const a = { tenderId: "FP-00014", deadline: 1790000000, schemaVersion: 1 };
    const b = { schemaVersion: 1, deadline: 1790000000, tenderId: "FP-00014" };
    expect(jcsCanonicalize(a)).toBe(jcsCanonicalize(b));
  });

  it("sorts nested object keys", () => {
    expect(jcsCanonicalize({ z: { y: 1, x: 2 } })).toBe('{"z":{"x":2,"y":1}}');
  });

  it("preserves array order, which is semantic", () => {
    expect(jcsCanonicalize([3, 1, 2])).toBe("[3,1,2]");
  });

  it("drops undefined but preserves null", () => {
    expect(jcsCanonicalize({ a: undefined, b: null })).toBe('{"b":null}');
  });

  it("serializes bigints as integers", () => {
    expect(jcsCanonicalize({ amount: 7400000n })).toBe('{"amount":7400000}');
  });

  it("rejects floating point, since the protocol forbids it", () => {
    expect(() => jcsCanonicalize({ amount: 74.5 })).toThrow(/floating point/);
  });

  it("rejects non-finite numbers", () => {
    expect(() => jcsCanonicalize({ x: Infinity })).toThrow(/non-finite/);
    expect(() => jcsCanonicalize({ x: NaN })).toThrow(/non-finite/);
  });

  it("escapes strings via JSON rules", () => {
    expect(jcsCanonicalize('a"b')).toBe('"a\\"b"');
  });
});

describe("rulesHash (whitepaper Section 4)", () => {
  const rules = {
    schemaVersion: 1,
    tenderId: "FP-00014",
    requirements: {
      turnoverThreshold: 500000000,
      experienceMonths: 60,
      certificationCode: 9001,
    },
    selectionRule: "LOWEST_QUALIFIED_PRICE",
    tieBreakRule: "SUBMISSION_SEQUENCE",
    biddingStart: 1790000000,
    deadline: 1790086400,
    disclosurePolicy: "WINNER_ONLY_POST_AWARD",
    issuerEpoch: 1,
    revocationPolicy: "DEADLINE_ROOT",
    contingencyPolicy: "CANCEL_AND_REISSUE",
    verifierVersion: 1,
  };

  it("is reproducible by any verifier from the canonical document", () => {
    expect(rulesHash(rules)).toBe(rulesHash(rules));
  });

  it("is independent of key order in the source document", () => {
    const reordered = Object.fromEntries(
      Object.entries(rules).reverse(),
    ) as typeof rules;
    expect(rulesHash(reordered)).toBe(rulesHash(rules));
  });

  it("changes when any rule field changes - this is the immutability claim", () => {
    const baseline = rulesHash(rules);
    expect(rulesHash({ ...rules, deadline: rules.deadline + 1 })).not.toBe(baseline);
    expect(
      rulesHash({
        ...rules,
        requirements: { ...rules.requirements, turnoverThreshold: 499999999 },
      }),
    ).not.toBe(baseline);
    expect(
      rulesHash({ ...rules, disclosurePolicy: "PUBLIC_AT_OPENING" }),
    ).not.toBe(baseline);
    expect(rulesHash({ ...rules, verifierVersion: 2 })).not.toBe(baseline);
  });

  it("round-trips through limbs, so the contract can reconstruct it", () => {
    const h = rulesHash(rules);
    const { hi, lo } = toLimbs(h);
    expect(fromLimbs(hi, lo)).toBe(h);
  });
});

describe("ciphertext encoding (spec Sections 6, 11)", () => {
  const parts = {
    rX: 111n,
    rY: 222n,
    wrapped: new Uint8Array(32).fill(7),
    iv: new Uint8Array(12).fill(3),
    ct: new Uint8Array(48).fill(9),
    tag: new Uint8Array(16).fill(1),
  };

  it("serializes to the fixed layout with a version byte", () => {
    const bytes = canonicalCiphertextBytes(parts);
    // 1 + 32 + 32 + 32 + 12 + 4 + 48 + 16
    expect(bytes.length).toBe(177);
    expect(bytes[0]).toBe(0x01);
  });

  it("length-prefixes the ciphertext big-endian", () => {
    const bytes = canonicalCiphertextBytes(parts);
    const lenOffset = 1 + 32 + 32 + 32 + 12;
    expect(Array.from(bytes.slice(lenOffset, lenOffset + 4))).toEqual([0, 0, 0, 48]);
  });

  it("binds every component of the ciphertext", () => {
    const baseline = ciphertextHash(parts);
    expect(ciphertextHash({ ...parts, rX: 112n })).not.toBe(baseline);
    expect(
      ciphertextHash({ ...parts, wrapped: new Uint8Array(32).fill(8) }),
    ).not.toBe(baseline);
    expect(ciphertextHash({ ...parts, iv: new Uint8Array(12).fill(4) })).not.toBe(
      baseline,
    );
    expect(ciphertextHash({ ...parts, ct: new Uint8Array(48).fill(10) })).not.toBe(
      baseline,
    );
    expect(ciphertextHash({ ...parts, tag: new Uint8Array(16).fill(2) })).not.toBe(
      baseline,
    );
  });

  it("rejects wrong fixed-field lengths", () => {
    expect(() =>
      canonicalCiphertextBytes({ ...parts, iv: new Uint8Array(16) }),
    ).toThrow(/iv must be 12 bytes/);
    expect(() =>
      canonicalCiphertextBytes({ ...parts, tag: new Uint8Array(12) }),
    ).toThrow(/tag must be 16 bytes/);
    expect(() =>
      canonicalCiphertextBytes({ ...parts, wrapped: new Uint8Array(16) }),
    ).toThrow(/wrapped must be 32 bytes/);
  });

  it("the field form is safe for Poseidon input", () => {
    expect(ciphertextHashField(parts)).toBeLessThan(1n << 248n);
  });
});

describe("storage receipts (spec Section 13)", () => {
  const receipt = {
    replicaId: 1,
    contentHash: "0x" + "ab".repeat(32),
    byteLength: 177,
    signature: "0x" + "cd".repeat(65),
  };

  it("binds replicaId, so one replica cannot forge another's receipt", () => {
    expect(receiptLeaf(receipt)).not.toBe(
      receiptLeaf({ ...receipt, replicaId: 2 }),
    );
  });

  it("binds the content hash and byte length", () => {
    const baseline = receiptLeaf(receipt);
    expect(
      receiptLeaf({ ...receipt, contentHash: "0x" + "ac".repeat(32) }),
    ).not.toBe(baseline);
    expect(receiptLeaf({ ...receipt, byteLength: 178 })).not.toBe(baseline);
  });

  it("requires a 65-byte signature", () => {
    expect(() =>
      receiptLeaf({ ...receipt, signature: "0x" + "cd".repeat(64) }),
    ).toThrow(/65 bytes/);
  });
});
