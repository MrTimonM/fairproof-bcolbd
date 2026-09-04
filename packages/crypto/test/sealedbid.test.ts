import { beforeAll, describe, expect, it } from "vitest";
import { Wallet, keccak256, recoverAddress } from "ethers";
import {
  DOMAIN_PADDING_V1,
  STORAGE_QUORUM,
  STORAGE_REPLICAS,
  aesGcmDecrypt,
  aesGcmEncrypt,
  bidCommitment,
  canonicalCiphertextBytes,
  ciphertextHash,
  combineInExponent,
  dealCommitteeKey,
  decryptionShare,
  deriveWrappingKey,
  dleqChallenge,
  encapsulate,
  generateDek,
  generateIv,
  hasStorageQuorum,
  initBabyjub,
  initPoseidon,
  jcsCanonicalize,
  mulBase,
  mulPoint,
  nullifier as computeNullifier,
  openSealedBid,
  pointsEqual,
  proveDleq,
  receiptLeaf,
  receiptSigDigest,
  sealBid,
  storageReceiptRoot,
  subjectCommitment,
  tenderIdField,
  unwrapDek,
  verifyDleq,
  type StorageReceipt,
} from "../src/index.js";

/**
 * The sealed-bid pipeline end to end: encrypt, encapsulate, store, open.
 *
 * Development plan Sections 12.3 to 12.6. The whole point of this stage is
 * that a bid is unreadable until three of five committee members act, and
 * that a bid cannot be accepted unless two of three replicas hold it. Both
 * numbers get negative tests, because a threshold that is described but not
 * enforced is worse than none.
 */

const SUBJECT_SECRET = 4759208310398234759832475982374598234759823475982347n;
const BID_NONCE = 8823409128340981234098123409812340981234098123409812n;
const BID_AMOUNT = 7400000n; // BDT 74,00,000 - the Figure 5 winning bid
const TENDER = "FP-00014";

beforeAll(async () => {
  await initPoseidon();
  await initBabyjub();
});

function payload(overrides: Record<string, string> = {}) {
  return {
    tenderId: TENDER,
    amountMinorUnit: BID_AMOUNT.toString(),
    currency: "BDT",
    bidNonce: BID_NONCE.toString(),
    subjectCommitment: subjectCommitment(SUBJECT_SECRET).toString(),
    createdAt: "2026-09-02T10:00:00Z",
    ...overrides,
  };
}

describe("ElGamal encapsulation to the tender key", () => {
  it("recovers the DEK from the shared secret", () => {
    const dealt = dealCommitteeKey();
    const dek = generateDek();
    const enc = encapsulate(dealt.publicKey, dek);
    expect(unwrapDek(enc.wrapped, enc.shared)).toEqual(dek);
  });

  it("the committee recovers the shared secret WITHOUT the tender secret", () => {
    // This is the property the whole design rests on. Three members publish
    // D_i = x_i * R; those interpolate in the exponent to x * R. The tender
    // secret is never reassembled.
    const dealt = dealCommitteeKey();
    const dek = generateDek();
    const enc = encapsulate(dealt.publicKey, dek);

    const parts = [0, 2, 4].map((i) => ({
      index: dealt.shares[i].index,
      point: decryptionShare(dealt.shares[i].share, enc.ephemeral),
    }));
    const shared = combineInExponent(parts);

    expect(pointsEqual(shared, enc.shared)).toBe(true);
    expect(unwrapDek(enc.wrapped, shared)).toEqual(dek);
  });

  it("TWO decryption shares do not recover the DEK", () => {
    const dealt = dealCommitteeKey();
    const dek = generateDek();
    const enc = encapsulate(dealt.publicKey, dek);
    const parts = [0, 1].map((i) => ({
      index: dealt.shares[i].index,
      point: decryptionShare(dealt.shares[i].share, enc.ephemeral),
    }));
    expect(unwrapDek(enc.wrapped, combineInExponent(parts))).not.toEqual(dek);
  });

  it("both coordinates of the shared secret enter the KDF", () => {
    // If only S.x were hashed, S and -S would derive the same key, and those
    // two points are distinguishable to an attacker who chooses points.
    const dealt = dealCommitteeKey();
    const enc = encapsulate(dealt.publicKey, generateDek());
    const negated = { x: enc.shared.x, y: 21888242871839275222246405745257275088548364400416034343698204186575808495617n - enc.shared.y };
    expect(deriveWrappingKey(enc.shared)).not.toEqual(deriveWrappingKey(negated));
  });

  it("refuses to encrypt to a key outside the prime-order subgroup", () => {
    const orderTwo = {
      x: 0n,
      y: 21888242871839275222246405745257275088548364400416034343698204186575808495616n,
    };
    expect(() => encapsulate(orderTwo, generateDek())).toThrow(/prime-order subgroup/);
  });

  it("rejects a DEK that is not 32 bytes", () => {
    const dealt = dealCommitteeKey();
    expect(() => encapsulate(dealt.publicKey, new Uint8Array(16))).toThrow(/32 bytes/);
  });

  it("two encapsulations of the same DEK differ", () => {
    // A fresh ephemeral scalar per bid. Reuse would let the XOR of two
    // `wrapped` values reveal the XOR of their DEKs.
    const dealt = dealCommitteeKey();
    const dek = generateDek();
    const a = encapsulate(dealt.publicKey, dek);
    const b = encapsulate(dealt.publicKey, dek);
    expect(a.wrapped).not.toEqual(b.wrapped);
    expect(pointsEqual(a.ephemeral, b.ephemeral)).toBe(false);
  });
});

describe("AES-256-GCM", () => {
  it("round-trips", async () => {
    const dek = generateDek();
    const iv = generateIv();
    const msg = new TextEncoder().encode("BDT 74,00,000");
    const { ct, tag } = await aesGcmEncrypt(dek, iv, msg);
    expect(tag.length).toBe(16);
    expect(await aesGcmDecrypt(dek, iv, ct, tag)).toEqual(msg);
  });

  it("a failed tag is a HARD failure, not a warning", async () => {
    // Plan Section 12.6 step 9. Treating a bad tag as recoverable would let a
    // tampered bid into the award witness.
    const dek = generateDek();
    const iv = generateIv();
    const { ct, tag } = await aesGcmEncrypt(dek, iv, new TextEncoder().encode("x"));
    const bad = new Uint8Array(tag);
    bad[0] ^= 1;
    await expect(aesGcmDecrypt(dek, iv, ct, bad)).rejects.toThrow(/authentication failed/);
  });

  it("a tampered ciphertext fails authentication", async () => {
    const dek = generateDek();
    const iv = generateIv();
    const { ct, tag } = await aesGcmEncrypt(dek, iv, new TextEncoder().encode("hello"));
    const bad = new Uint8Array(ct);
    bad[0] ^= 0xff;
    await expect(aesGcmDecrypt(dek, iv, bad, tag)).rejects.toThrow(/authentication failed/);
  });

  it("the wrong key fails authentication rather than returning garbage", async () => {
    const iv = generateIv();
    const { ct, tag } = await aesGcmEncrypt(generateDek(), iv, new TextEncoder().encode("hi"));
    await expect(aesGcmDecrypt(generateDek(), iv, ct, tag)).rejects.toThrow(/authentication failed/);
  });
});

describe("sealing and opening a bid", () => {
  const setup = () => {
    const dealt = dealCommitteeKey();
    const tf = tenderIdField(TENDER);
    const nul = computeNullifier(SUBJECT_SECRET, tf);
    return { dealt, tf, nul };
  };

  it("seals a bid and reproduces the on-chain commitment", async () => {
    const { dealt, tf, nul } = setup();
    const sealed = await sealBid({
      payload: payload(),
      tenderPublicKey: dealt.publicKey,
      tenderIdField: tf,
      nullifier: nul,
    });

    expect(sealed.bidCommitment).toBe(
      bidCommitment({ bidAmount: BID_AMOUNT, bidNonce: BID_NONCE, tenderIdField: tf, nullifier: nul }),
    );
    expect(sealed.ciphertextHash).toBe(ciphertextHash(sealed.ciphertext));
    expect(sealed.canonicalBytes).toEqual(canonicalCiphertextBytes(sealed.ciphertext));
  });

  it("the ciphertext reveals nothing recognisable about the amount", async () => {
    const { dealt, tf, nul } = setup();
    const sealed = await sealBid({
      payload: payload(),
      tenderPublicKey: dealt.publicKey,
      tenderIdField: tf,
      nullifier: nul,
    });
    const bytes = Buffer.from(sealed.canonicalBytes).toString("hex");
    // The amount as decimal ASCII and as hex must both be absent.
    expect(bytes).not.toContain(Buffer.from("7400000").toString("hex"));
    expect(bytes).not.toContain(BID_AMOUNT.toString(16));
  });

  it("three committee members open it; the amount comes back exactly", async () => {
    const { dealt, tf, nul } = setup();
    const sealed = await sealBid({
      payload: payload(),
      tenderPublicKey: dealt.publicKey,
      tenderIdField: tf,
      nullifier: nul,
    });

    const parts = [1, 2, 4].map((i) => ({
      index: dealt.shares[i].index,
      point: decryptionShare(dealt.shares[i].share, {
        x: sealed.ciphertext.rX,
        y: sealed.ciphertext.rY,
      }),
    }));

    const opened = await openSealedBid({
      ciphertext: sealed.ciphertext,
      shared: combineInExponent(parts),
      expectedCommitment: sealed.bidCommitment,
      tenderIdField: tf,
      nullifier: nul,
    });

    expect(opened.bidAmount).toBe(BID_AMOUNT);
    expect(opened.bidNonce).toBe(BID_NONCE);
    expect(opened.payload.currency).toBe("BDT");
  });

  it("TWO members cannot open it", async () => {
    const { dealt, tf, nul } = setup();
    const sealed = await sealBid({
      payload: payload(),
      tenderPublicKey: dealt.publicKey,
      tenderIdField: tf,
      nullifier: nul,
    });
    const parts = [0, 1].map((i) => ({
      index: dealt.shares[i].index,
      point: decryptionShare(dealt.shares[i].share, {
        x: sealed.ciphertext.rX,
        y: sealed.ciphertext.rY,
      }),
    }));
    await expect(
      openSealedBid({
        ciphertext: sealed.ciphertext,
        shared: combineInExponent(parts),
        expectedCommitment: sealed.bidCommitment,
        tenderIdField: tf,
        nullifier: nul,
      }),
    ).rejects.toThrow(/authentication failed/);
  });

  it("an opened payload that disagrees with the on-chain commitment is rejected", async () => {
    // Plan Section 12.6 step 10. Without this a committee that decrypted
    // correctly could still report a different amount, and the award would be
    // computed from a number nobody committed to.
    const { dealt, tf, nul } = setup();
    const sealed = await sealBid({
      payload: payload(),
      tenderPublicKey: dealt.publicKey,
      tenderIdField: tf,
      nullifier: nul,
    });
    const parts = [0, 1, 2].map((i) => ({
      index: dealt.shares[i].index,
      point: decryptionShare(dealt.shares[i].share, {
        x: sealed.ciphertext.rX,
        y: sealed.ciphertext.rY,
      }),
    }));
    await expect(
      openSealedBid({
        ciphertext: sealed.ciphertext,
        shared: combineInExponent(parts),
        expectedCommitment: sealed.bidCommitment + 1n,
        tenderIdField: tf,
        nullifier: nul,
      }),
    ).rejects.toThrow(/does not reproduce the on-chain/);
  });

  it("the payload is JCS-canonical, so it is byte-reproducible", () => {
    const canonical = jcsCanonicalize(payload());
    expect(canonical).toBe(jcsCanonicalize(JSON.parse(canonical)));
    // Keys sorted, so two clients producing the same payload agree.
    expect(canonical.indexOf('"amountMinorUnit"')).toBeLessThan(canonical.indexOf('"currency"'));
  });

  it("refuses a floating-point amount anywhere in the payload", () => {
    expect(() => jcsCanonicalize({ ...payload(), amount: 74000.5 })).toThrow(/floating point/);
  });
});

describe("Chaum-Pedersen DLEQ on decryption shares", () => {
  const ephemeral = () => mulBase(987654321n);

  it("a member's honest share verifies", () => {
    const dealt = dealCommitteeKey();
    const R = ephemeral();
    const s = dealt.shares[2];
    const proof = proveDleq({ secret: s.share, ephemeral: R });
    expect(
      verifyDleq({
        publicShare: s.publicShare,
        ephemeral: R,
        decryptionShare: decryptionShare(s.share, R),
        proof,
      }),
    ).toBe(true);
  });

  it("a forged share is rejected", () => {
    // Why the proof exists: without it a member could publish any point and
    // the combination would silently produce garbage, surfacing later as an
    // AES tag failure that looks like the bidder's fault.
    const dealt = dealCommitteeKey();
    const R = ephemeral();
    const s = dealt.shares[2];
    const proof = proveDleq({ secret: s.share, ephemeral: R });
    expect(
      verifyDleq({
        publicShare: s.publicShare,
        ephemeral: R,
        decryptionShare: mulPoint(R, s.share + 1n),
        proof,
      }),
    ).toBe(false);
  });

  it("a proof cannot be replayed against a different ciphertext", () => {
    // The challenge covers R and D_i, so a proof produced once cannot be
    // accepted for every bid in the tender.
    const dealt = dealCommitteeKey();
    const R1 = mulBase(111n);
    const R2 = mulBase(222n);
    const s = dealt.shares[0];
    const proof = proveDleq({ secret: s.share, ephemeral: R1 });
    expect(
      verifyDleq({
        publicShare: s.publicShare,
        ephemeral: R2,
        decryptionShare: decryptionShare(s.share, R2),
        proof,
      }),
    ).toBe(false);
  });

  it("a proof for one member is rejected under another member's public share", () => {
    const dealt = dealCommitteeKey();
    const R = ephemeral();
    const proof = proveDleq({ secret: dealt.shares[0].share, ephemeral: R });
    expect(
      verifyDleq({
        publicShare: dealt.shares[1].publicShare,
        ephemeral: R,
        decryptionShare: decryptionShare(dealt.shares[0].share, R),
        proof,
      }),
    ).toBe(false);
  });

  it("a tampered response is rejected", () => {
    const dealt = dealCommitteeKey();
    const R = ephemeral();
    const s = dealt.shares[3];
    const proof = proveDleq({ secret: s.share, ephemeral: R });
    expect(
      verifyDleq({
        publicShare: s.publicShare,
        ephemeral: R,
        decryptionShare: decryptionShare(s.share, R),
        proof: { ...proof, z: proof.z + 1n },
      }),
    ).toBe(false);
  });

  it("a non-point in the proof is rejected before any arithmetic", () => {
    const dealt = dealCommitteeKey();
    const R = ephemeral();
    const s = dealt.shares[1];
    const proof = proveDleq({ secret: s.share, ephemeral: R });
    expect(
      verifyDleq({
        publicShare: s.publicShare,
        ephemeral: R,
        decryptionShare: decryptionShare(s.share, R),
        proof: { ...proof, a: { x: 1n, y: 1n } },
      }),
    ).toBe(false);
  });

  it("the challenge changes if any statement element changes", () => {
    const dealt = dealCommitteeKey();
    const R = ephemeral();
    const s = dealt.shares[0];
    const D = decryptionShare(s.share, R);
    const A = mulBase(5n);
    const B = mulPoint(R, 5n);
    const base = dleqChallenge({
      publicShare: s.publicShare, ephemeral: R, decryptionShare: D,
      commitmentA: A, commitmentB: B,
    });
    const variants = [
      { publicShare: dealt.shares[1].publicShare, ephemeral: R, decryptionShare: D, commitmentA: A, commitmentB: B },
      { publicShare: s.publicShare, ephemeral: mulBase(7n), decryptionShare: D, commitmentA: A, commitmentB: B },
      { publicShare: s.publicShare, ephemeral: R, decryptionShare: mulBase(9n), commitmentA: A, commitmentB: B },
      { publicShare: s.publicShare, ephemeral: R, decryptionShare: D, commitmentA: mulBase(11n), commitmentB: B },
      { publicShare: s.publicShare, ephemeral: R, decryptionShare: D, commitmentA: A, commitmentB: mulBase(13n) },
    ];
    for (const v of variants) expect(dleqChallenge(v)).not.toBe(base);
  });
});

describe("storage receipts (the 2-of-3 quorum)", () => {
  /** A replica signs the digest with its own registered key. */
  async function sign(replicaId: number, contentHash: string, byteLength: number, key: string) {
    const digest = receiptSigDigest({ replicaId, contentHash, byteLength });
    const w = new Wallet(key);
    return { digest, signature: w.signingKey.sign(digest).serialized, address: w.address };
  }

  const KEYS = [
    "0x" + "11".repeat(32),
    "0x" + "22".repeat(32),
    "0x" + "33".repeat(32),
  ];
  const CONTENT = keccak256(new Uint8Array([1, 2, 3]));

  it("a receipt signature recovers the replica's registered address", async () => {
    const { digest, signature, address } = await sign(1, CONTENT, 512, KEYS[0]);
    expect(recoverAddress(digest, signature)).toBe(address);
  });

  it("the digest binds the replica id, the content hash and the length", () => {
    const base = receiptSigDigest({ replicaId: 1, contentHash: CONTENT, byteLength: 512 });
    expect(receiptSigDigest({ replicaId: 2, contentHash: CONTENT, byteLength: 512 })).not.toBe(base);
    expect(
      receiptSigDigest({ replicaId: 1, contentHash: keccak256(new Uint8Array([9])), byteLength: 512 }),
    ).not.toBe(base);
    expect(receiptSigDigest({ replicaId: 1, contentHash: CONTENT, byteLength: 513 })).not.toBe(base);
  });

  it("the root is independent of the order receipts arrive in", async () => {
    // Receipts are sorted by replicaId, so whichever replica answers first the
    // contract can still recompute the root.
    const rs: StorageReceipt[] = [];
    for (const [i, k] of KEYS.entries()) {
      const { signature } = await sign(i + 1, CONTENT, 512, k);
      rs.push({ replicaId: i + 1, contentHash: CONTENT, byteLength: 512, signature });
    }
    expect(storageReceiptRoot(rs)).toBe(storageReceiptRoot([...rs].reverse()));
  });

  it("a two-replica root differs from a three-replica root", async () => {
    const rs: StorageReceipt[] = [];
    for (const [i, k] of KEYS.entries()) {
      const { signature } = await sign(i + 1, CONTENT, 512, k);
      rs.push({ replicaId: i + 1, contentHash: CONTENT, byteLength: 512, signature });
    }
    expect(storageReceiptRoot(rs.slice(0, 2))).not.toBe(storageReceiptRoot(rs));
  });

  it("missing replicas are padded with DOMAIN_PADDING_V1, not zero", async () => {
    // A zero leaf is indistinguishable from an empty subtree.
    const { signature } = await sign(1, CONTENT, 512, KEYS[0]);
    const one: StorageReceipt[] = [
      { replicaId: 1, contentHash: CONTENT, byteLength: 512, signature },
    ];
    const root = storageReceiptRoot(one);
    expect(root).not.toBe(0n);
    expect(DOMAIN_PADDING_V1).not.toBe(0n);
  });

  it("enforces the 2-of-3 quorum, which is NOT the 3-of-5 opening threshold", async () => {
    expect(STORAGE_QUORUM).toBe(2);
    expect(STORAGE_REPLICAS).toBe(3);
    const rs: StorageReceipt[] = [];
    for (const [i, k] of KEYS.entries()) {
      const { signature } = await sign(i + 1, CONTENT, 512, k);
      rs.push({ replicaId: i + 1, contentHash: CONTENT, byteLength: 512, signature });
    }
    expect(hasStorageQuorum([])).toBe(false);
    expect(hasStorageQuorum(rs.slice(0, 1))).toBe(false);
    expect(hasStorageQuorum(rs.slice(0, 2))).toBe(true);
    expect(hasStorageQuorum(rs)).toBe(true);
  });

  it("rejects a duplicate replicaId", async () => {
    const { signature } = await sign(1, CONTENT, 512, KEYS[0]);
    const r: StorageReceipt = { replicaId: 1, contentHash: CONTENT, byteLength: 512, signature };
    // Two receipts from the same replica are not two acknowledgements.
    expect(() => storageReceiptRoot([r, { ...r }])).toThrow(/duplicate replicaId/);
    expect(hasStorageQuorum([r, { ...r }])).toBe(false);
  });

  it("rejects a signature that is not 65 bytes", () => {
    expect(() =>
      receiptLeaf({ replicaId: 1, contentHash: CONTENT, byteLength: 1, signature: "0x1234" }),
    ).toThrow(/65 bytes/);
  });
});
