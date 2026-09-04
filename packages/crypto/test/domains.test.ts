import { beforeAll, describe, expect, it } from "vitest";
import {
  COMMITTEE_SIZE,
  COMMITTEE_THRESHOLD,
  COUNCIL_SIZE,
  COUNCIL_THRESHOLD,
  DOMAIN_BIDCOMMIT_V1,
  DOMAIN_CRED_V1,
  DOMAIN_LEAF_V1,
  DOMAIN_NULLIFIER_V1,
  DOMAIN_PADDING_V1,
  DOMAIN_SUBJECT_V1,
  BID_TREE_DEPTH,
  IncrementalMerkleTree,
  MAX_BIDS,
  RAW_CIPHERTEXT_V1,
  RAW_DEK_V1,
  RAW_DLEQ_V1,
  RAW_RECEIPT_SIG_V1,
  RAW_RECEIPT_V1,
  RAW_TENDER_ID_V1,
  STORAGE_QUORUM,
  STORAGE_REPLICAS,
  initPoseidon,
  tenderIdField,
} from "../src/index.js";

beforeAll(async () => {
  await initPoseidon();
});

/**
 * These literals are the frozen protocol constants. They are derived at
 * runtime in domains.ts and pinned here so that a change to a domain label,
 * to toField, or to the Poseidon constants fails loudly instead of silently
 * forking the protocol.
 *
 * If a test in this file fails, DO NOT update the literal to match the code.
 * Find out what changed - it is a breaking protocol change requiring a
 * version bump in docs/field-encoding.md.
 */
describe("frozen domain constants (spec Section 3)", () => {
  it("raw keccak domains are pinned", () => {
    expect(RAW_TENDER_ID_V1).toBe(
      "0x9eaa6dde8d74874da28e947eb1fe707365b7288bc291b6388e5a176d0b3719ac",
    );
    expect(RAW_CIPHERTEXT_V1).toBe(
      "0x6edc5e8537624c6e297a0e49274ec5a5e66270f9402ff011206b0c1793896729",
    );
    expect(RAW_RECEIPT_V1).toBe(
      "0x6f914b0c1addf20f03c49bb18eb568ad66529197270c1c525f3867fdef721325",
    );
    // Spec Sections 20-22, added for the sealed-bid stage.
    expect(RAW_DEK_V1).toBe(
      "0x4d81339f62c86b8e778c8291fde69866126f324c401be831dea3c355d885c48d",
    );
    expect(RAW_DLEQ_V1).toBe(
      "0x90fcb89fb43b96167b00efaf2bbe93dea466b042c0be602817027df1ed2a572c",
    );
    expect(RAW_RECEIPT_SIG_V1).toBe(
      "0xc3ffb182dd3ebfe5535def6710ba4562e2bf2416e6ac55e4ac25fc7e14433ea3",
    );
  });

  it("every raw domain is distinct", () => {
    // The point of domain separation: a digest computed for one purpose must
    // never be reinterpretable as another. RAW_RECEIPT_SIG_V1 and
    // RAW_RECEIPT_V1 are the pair most at risk, since both concern receipts.
    const all = [
      RAW_TENDER_ID_V1,
      RAW_CIPHERTEXT_V1,
      RAW_RECEIPT_V1,
      RAW_DEK_V1,
      RAW_DLEQ_V1,
      RAW_RECEIPT_SIG_V1,
    ];
    expect(new Set(all).size).toBe(all.length);
  });

  it("field-element domains are pinned", () => {
    expect(DOMAIN_CRED_V1).toBe(
      322149158785522698676451765976810572237009812112012877722857913027064676009n,
    );
    expect(DOMAIN_LEAF_V1).toBe(
      190845489973463437363397010865843301780418146225117113041917773882994065432n,
    );
    expect(DOMAIN_PADDING_V1).toBe(
      118794039896364772078121437224410514784736280784934280083252483328023231778n,
    );
    expect(DOMAIN_NULLIFIER_V1).toBe(
      332042671396993988458214105119834532491316109751507750077714947830527129332n,
    );
    expect(DOMAIN_BIDCOMMIT_V1).toBe(
      139370848049544989023910287186176558846770354377755241435164208878574711998n,
    );
    expect(DOMAIN_SUBJECT_V1).toBe(
      63384362855929274650512957064135432067752122244173505609908999325216133498n,
    );
  });

  it("all domain constants are distinct", () => {
    const all = [
      DOMAIN_CRED_V1,
      DOMAIN_LEAF_V1,
      DOMAIN_PADDING_V1,
      DOMAIN_NULLIFIER_V1,
      DOMAIN_BIDCOMMIT_V1,
      DOMAIN_SUBJECT_V1,
    ];
    expect(new Set(all.map(String)).size).toBe(all.length);
  });

  it("tenderIdField is pinned for the Figure 5 demo tender", () => {
    expect(tenderIdField("FP-00014")).toBe(
      345466083462855046233379317649602515757229700962688122897585307103576758497n,
    );
  });

  it("the empty bid-set root is pinned", () => {
    expect(IncrementalMerkleTree.emptyRoot(BID_TREE_DEPTH)).toBe(
      18232377929263394053032240335347245131877279331383963775401837732819763548351n,
    );
  });
});

describe("frozen protocol parameters", () => {
  it("MAX_BIDS is 32, per whitepaper Section 7", () => {
    expect(MAX_BIDS).toBe(32);
    expect(2 ** BID_TREE_DEPTH).toBe(MAX_BIDS);
  });

  it("the opening committee is 3-of-5, per whitepaper Section 6", () => {
    expect(COMMITTEE_THRESHOLD).toBe(3);
    expect(COMMITTEE_SIZE).toBe(5);
  });

  it("storage replication is 2-of-3, per whitepaper Section 4", () => {
    expect(STORAGE_QUORUM).toBe(2);
    expect(STORAGE_REPLICAS).toBe(3);
  });

  it("the two thresholds are genuinely different mechanisms", () => {
    // Guards against the misreading that conflated them: the opening key
    // threshold is 3-of-5, the storage receipt threshold is 2-of-3.
    expect([COMMITTEE_THRESHOLD, COMMITTEE_SIZE]).not.toEqual([
      STORAGE_QUORUM,
      STORAGE_REPLICAS,
    ]);
  });

  it("the governance council is 3-of-4, per whitepaper Section 14", () => {
    expect(COUNCIL_THRESHOLD).toBe(3);
    expect(COUNCIL_SIZE).toBe(4);
  });
});
