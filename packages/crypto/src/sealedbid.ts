/**
 * The bidder's sealed-bid pipeline. Development plan Section 12.3.
 *
 * Runs in the browser. Nothing in this module may log, persist or transmit
 * the DEK, the bid amount, the bid nonce, or the subject secret. The only
 * values it hands back for publication are commitments and hashes.
 *
 * THE ORDER OF OPERATIONS MATTERS. A bid is submitted on-chain only after two
 * independent replicas have acknowledged the ciphertext, so a commitment can
 * never enter `bidSetRoot` without a retrievable payload behind it. That is
 * the mechanism behind the whitepaper's "missing ciphertext" row: the
 * completeness claim of the award proof depends on every accepted bid being
 * openable.
 */
import { getBytes, keccak256 } from "ethers";
import { type Point } from "./babyjub.js";
import {
  DOMAIN_PADDING_V1,
  RAW_RECEIPT_SIG_V1,
  RECEIPT_TREE_DEPTH,
  STORAGE_QUORUM,
  STORAGE_REPLICAS,
} from "./domains.js";
import { concatBytes, toBytes } from "./field.js";
import {
  canonicalCiphertextBytes,
  ciphertextHash,
  ciphertextHashField,
  jcsCanonicalize,
  receiptLeaf,
  type CiphertextParts,
  type StorageReceipt,
} from "./encoding.js";
import { encapsulate, unwrapDek } from "./elgamal.js";
import { bidCommitment } from "./poseidon.js";
import { rootFromLeaves } from "./merkle.js";

/** The plaintext bid payload. Integer minor units only. Plan Section 12.1. */
export interface BidPayload {
  tenderId: string;
  /** BDT, integer minor units. NEVER a float: spec Section 14 forbids them. */
  amountMinorUnit: string;
  currency: string;
  bidNonce: string;
  subjectCommitment: string;
  createdAt: string;
}

/** Everything the bidder needs after sealing, split by what may be published. */
export interface SealedBid {
  /** Safe to publish: this is what goes to the replicas and on-chain. */
  ciphertext: CiphertextParts;
  ciphertextHash: string;
  ciphertextHashField: bigint;
  canonicalBytes: Uint8Array;
  bidCommitment: bigint;
  /** SECRET. Held only until the on-chain submission succeeds, then cleared. */
  dek: Uint8Array;
}

const CIPHERTEXT_VERSION_NOTE =
  "canonicalCiphertextBytes fixes the field order and every length; see " +
  "docs/field-encoding.md Section 11.";
void CIPHERTEXT_VERSION_NOTE;

/**
 * Copy bytes into a plain ArrayBuffer for WebCrypto.
 *
 * TypeScript 5.7 distinguishes `Uint8Array<ArrayBuffer>` from
 * `Uint8Array<ArrayBufferLike>`, and WebCrypto's `BufferSource` accepts only
 * the former - a view onto a SharedArrayBuffer would be rejected at runtime.
 * Copying satisfies the type honestly rather than casting the problem away,
 * and WebCrypto copies its inputs regardless.
 */
function bufferSource(u: Uint8Array): ArrayBuffer {
  const out = new ArrayBuffer(u.length);
  new Uint8Array(out).set(u);
  return out;
}

/** A fresh 256-bit AES key from the platform CSPRNG. */
export function generateDek(): Uint8Array {
  const dek = new Uint8Array(32);
  crypto.getRandomValues(dek);
  return dek;
}

/** A fresh 96-bit AES-GCM IV. Never reuse one under the same key. */
export function generateIv(): Uint8Array {
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);
  return iv;
}

/**
 * AES-256-GCM encrypt, splitting the tag from the ciphertext.
 *
 * WebCrypto appends the 16-byte tag to the ciphertext; the canonical byte
 * layout carries them as separate fields, so they are split here rather than
 * leaving a caller to slice the buffer and get the boundary wrong.
 */
export async function aesGcmEncrypt(
  dek: Uint8Array,
  iv: Uint8Array,
  plaintext: Uint8Array,
): Promise<{ ct: Uint8Array; tag: Uint8Array }> {
  const key = await crypto.subtle.importKey(
    "raw",
    bufferSource(dek),
    "AES-GCM",
    false,
    ["encrypt"],
  );
  const sealed = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: bufferSource(iv), tagLength: 128 },
      key,
      bufferSource(plaintext),
    ),
  );
  return {
    ct: sealed.slice(0, sealed.length - 16),
    tag: sealed.slice(sealed.length - 16),
  };
}

/**
 * AES-256-GCM decrypt AND AUTHENTICATE.
 *
 * A failed tag throws. Plan Section 12.6 step 9 is explicit that this is "a
 * hard failure, not a warning": a payload whose tag does not verify has been
 * altered or was encrypted under a different key, and treating it as
 * recoverable would let a tampered bid into the award witness.
 */
export async function aesGcmDecrypt(
  dek: Uint8Array,
  iv: Uint8Array,
  ct: Uint8Array,
  tag: Uint8Array,
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    "raw",
    bufferSource(dek),
    "AES-GCM",
    false,
    ["decrypt"],
  );
  try {
    return new Uint8Array(
      await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: bufferSource(iv), tagLength: 128 },
        key,
        bufferSource(concatBytes(ct, tag)),
      ),
    );
  } catch {
    throw new Error(
      "aesGcmDecrypt: GCM authentication failed. The payload was altered or " +
        "the key is wrong. This is a hard failure (plan Section 12.6 step 9).",
    );
  }
}

/**
 * Seal a bid: canonicalize, encrypt, encapsulate the key, and compute the
 * commitment and hashes. Plan Section 12.3 steps 1-6.
 */
export async function sealBid(params: {
  payload: BidPayload;
  tenderPublicKey: Point;
  tenderIdField: bigint;
  nullifier: bigint;
  /** Test-only determinism hooks. Production must leave all three unset. */
  dek?: Uint8Array;
  iv?: Uint8Array;
  ephemeralScalar?: bigint;
}): Promise<SealedBid> {
  const { payload, tenderPublicKey, tenderIdField, nullifier } = params;

  // The same canonicalization the rule document uses, so a bid payload is
  // reproducible byte for byte by whoever opens it.
  const canonicalPayload = new TextEncoder().encode(jcsCanonicalize(payload));

  const dek = params.dek ?? generateDek();
  const iv = params.iv ?? generateIv();
  const { ct, tag } = await aesGcmEncrypt(dek, iv, canonicalPayload);

  const enc = encapsulate(tenderPublicKey, dek, params.ephemeralScalar);

  const ciphertext: CiphertextParts = {
    rX: enc.ephemeral.x,
    rY: enc.ephemeral.y,
    wrapped: enc.wrapped,
    iv,
    ct,
    tag,
  };

  const commitment = bidCommitment({
    bidAmount: BigInt(payload.amountMinorUnit),
    bidNonce: BigInt(payload.bidNonce),
    tenderIdField,
    nullifier,
  });

  return {
    ciphertext,
    ciphertextHash: ciphertextHash(ciphertext),
    ciphertextHashField: ciphertextHashField(ciphertext),
    canonicalBytes: canonicalCiphertextBytes(ciphertext),
    bidCommitment: commitment,
    dek,
  };
}

/**
 * Open a sealed bid using the committee's reconstructed shared secret.
 * Plan Section 12.6 steps 7-10.
 */
export async function openSealedBid(params: {
  ciphertext: CiphertextParts;
  /** S = x * R, from interpolating three decryption shares in the exponent. */
  shared: Point;
  /** On-chain values the opened payload must reproduce. */
  expectedCommitment: bigint;
  tenderIdField: bigint;
  nullifier: bigint;
}): Promise<{ payload: BidPayload; bidAmount: bigint; bidNonce: bigint }> {
  const { ciphertext, shared } = params;
  const dek = unwrapDek(ciphertext.wrapped, shared);
  const plaintext = await aesGcmDecrypt(dek, ciphertext.iv, ciphertext.ct, ciphertext.tag);
  const payload = JSON.parse(new TextDecoder().decode(plaintext)) as BidPayload;

  const bidAmount = BigInt(payload.amountMinorUnit);
  const bidNonce = BigInt(payload.bidNonce);

  // Recompute the commitment from the opened values and compare it to the
  // on-chain one. Plan Section 12.6 step 10: without this, a committee that
  // decrypted correctly could still report a different amount, and the award
  // would be computed from a number nobody committed to.
  const recomputed = bidCommitment({
    bidAmount,
    bidNonce,
    tenderIdField: params.tenderIdField,
    nullifier: params.nullifier,
  });
  if (recomputed !== params.expectedCommitment) {
    throw new Error(
      "openSealedBid: the opened payload does not reproduce the on-chain " +
        `bidCommitment (got ${recomputed}, expected ${params.expectedCommitment})`,
    );
  }

  return { payload, bidAmount, bidNonce };
}

// ------------------------------------------------------------- storage receipts

/**
 * The digest a replica signs. Spec Section 22.
 *
 * Binds the acknowledgement to the exact ciphertext bytes, because
 * `contentHash` is the `ciphertextHash` the bidder also submits on-chain.
 */
export function receiptSigDigest(params: {
  replicaId: number;
  contentHash: string;
  byteLength: number;
}): string {
  if (params.replicaId < 0 || params.replicaId > 255) {
    throw new Error("receiptSigDigest: replicaId must fit in a uint8");
  }
  return keccak256(
    concatBytes(
      getBytes(RAW_RECEIPT_SIG_V1),
      toBytes(BigInt(params.replicaId), 1),
      getBytes(params.contentHash),
      toBytes(BigInt(params.byteLength), 8),
    ),
  );
}

/**
 * The storage-receipt root. Spec Section 13.
 *
 * Receipts are ordered by `replicaId` ASCENDING and missing slots are filled
 * with `DOMAIN_PADDING_V1`. Both rules exist so the root is deterministic: an
 * unordered set of receipts would give a different root depending on which
 * replica answered first, and the contract could not recompute it.
 *
 * Depth 2, capacity 4: three replicas plus one padding slot.
 */
export function storageReceiptRoot(receipts: StorageReceipt[]): bigint {
  if (receipts.length > STORAGE_REPLICAS) {
    throw new Error(
      `storageReceiptRoot: at most ${STORAGE_REPLICAS} replicas, got ${receipts.length}`,
    );
  }
  const ids = receipts.map((r) => r.replicaId);
  if (new Set(ids).size !== ids.length) {
    throw new Error("storageReceiptRoot: duplicate replicaId");
  }
  const sorted = [...receipts].sort((a, b) => a.replicaId - b.replicaId);
  const leaves = sorted.map(receiptLeaf);
  while (leaves.length < 1 << RECEIPT_TREE_DEPTH) leaves.push(DOMAIN_PADDING_V1);
  return rootFromLeaves(leaves, RECEIPT_TREE_DEPTH);
}

/**
 * Whether enough distinct replicas acknowledged the ciphertext.
 *
 * Two of three. This is the STORAGE quorum and has nothing to do with the
 * 3-of-5 opening threshold: two replicas cannot open a bid, and three
 * committee members cannot make a ciphertext retrievable.
 */
export function hasStorageQuorum(receipts: StorageReceipt[]): boolean {
  return new Set(receipts.map((r) => r.replicaId)).size >= STORAGE_QUORUM;
}
