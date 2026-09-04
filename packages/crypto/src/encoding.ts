/**
 * Keccak-based encodings: tenderIdField, ciphertextHash, receipt leaves,
 * and JCS canonicalization for the rule document.
 * Spec Sections 5, 6, 11, 13.
 */
import { keccak256, toUtf8Bytes, getBytes } from "ethers";
import {
  RAW_CIPHERTEXT_V1,
  RAW_RECEIPT_V1,
  RAW_TENDER_ID_V1,
} from "./domains.js";
import { concatBytes, toBytes, toField } from "./field.js";

/**
 * tenderIdField = toField(keccak256(DOMAIN_TENDER_ID_V1 || utf8(tenderId))).
 * Spec Section 5.
 */
export function tenderIdField(tenderId: string): bigint {
  const preimage = concatBytes(
    getBytes(RAW_TENDER_ID_V1),
    toUtf8Bytes(tenderId),
  );
  return toField(keccak256(preimage));
}

/** Components of a sealed-bid ciphertext object. Spec Section 11. */
export interface CiphertextParts {
  /** ElGamal ephemeral point R = r*G */
  rX: bigint;
  rY: bigint;
  /** Wrapped AES-256 data-encryption key */
  wrapped: Uint8Array;
  /** AES-GCM IV, 12 bytes, unique per key */
  iv: Uint8Array;
  /** AES-256-GCM ciphertext */
  ct: Uint8Array;
  /** GCM authentication tag, 16 bytes */
  tag: Uint8Array;
}

export const CIPHERTEXT_VERSION = 0x01;

/**
 * Canonical byte serialization of a ciphertext object. Spec Section 11.
 * All lengths fixed; ct is length-prefixed.
 */
export function canonicalCiphertextBytes(parts: CiphertextParts): Uint8Array {
  if (parts.wrapped.length !== 32) {
    throw new Error("canonicalCiphertextBytes: wrapped must be 32 bytes");
  }
  if (parts.iv.length !== 12) {
    throw new Error("canonicalCiphertextBytes: iv must be 12 bytes");
  }
  if (parts.tag.length !== 16) {
    throw new Error("canonicalCiphertextBytes: tag must be 16 bytes");
  }
  return concatBytes(
    new Uint8Array([CIPHERTEXT_VERSION]),
    toBytes(parts.rX, 32),
    toBytes(parts.rY, 32),
    parts.wrapped,
    parts.iv,
    toBytes(BigInt(parts.ct.length), 4),
    parts.ct,
    parts.tag,
  );
}

/** ciphertextHash = keccak256(DOMAIN_CIPHERTEXT_V1 || canonicalBytes). Spec 6. */
export function ciphertextHash(parts: CiphertextParts): string {
  const preimage = concatBytes(
    getBytes(RAW_CIPHERTEXT_V1),
    canonicalCiphertextBytes(parts),
  );
  return keccak256(preimage);
}

/** Field form of ciphertextHash, for the bid leaf. Spec Section 6. */
export function ciphertextHashField(parts: CiphertextParts): bigint {
  return toField(ciphertextHash(parts));
}

/** A signed acknowledgement from one ciphertext-store replica. Spec 13. */
export interface StorageReceipt {
  replicaId: number;
  contentHash: string;
  byteLength: number;
  /** 65-byte secp256k1 signature over the receipt fields */
  signature: string;
}

/** Receipt leaf for the storage-receipt tree. Spec Section 13. */
export function receiptLeaf(receipt: StorageReceipt): bigint {
  const sig = getBytes(receipt.signature);
  if (sig.length !== 65) {
    throw new Error("receiptLeaf: signature must be 65 bytes");
  }
  const preimage = concatBytes(
    getBytes(RAW_RECEIPT_V1),
    toBytes(BigInt(receipt.replicaId), 1),
    getBytes(receipt.contentHash),
    toBytes(BigInt(receipt.byteLength), 8),
    sig,
  );
  return toField(keccak256(preimage));
}

/**
 * RFC 8785 JSON Canonicalization Scheme.
 *
 * The whitepaper commits to JCS for the rule document, so rulesHash is
 * reproducible by any verifier. Implemented directly rather than pulled in
 * as a dependency, because the subset the rule schema uses is small and a
 * mismatch here silently breaks the immutability claim.
 *
 * Supports: objects (keys sorted by UTF-16 code unit), arrays, strings,
 * integers, booleans, null. Rejects floats and non-finite numbers, since
 * the protocol forbids floating point entirely (spec Section 14).
 */
export function jcsCanonicalize(value: unknown): string {
  if (value === null) return "null";

  if (typeof value === "boolean") return value ? "true" : "false";

  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error("jcsCanonicalize: non-finite number");
    }
    if (!Number.isInteger(value)) {
      throw new Error(
        "jcsCanonicalize: non-integer number; the protocol forbids " +
          "floating point (use integer minor units)",
      );
    }
    return String(value);
  }

  if (typeof value === "bigint") return value.toString();

  if (typeof value === "string") return JSON.stringify(value);

  if (Array.isArray(value)) {
    return "[" + value.map(jcsCanonicalize).join(",") + "]";
  }

  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      // JCS sorts by UTF-16 code unit, which is what the default
      // comparison on JS strings already does.
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return (
      "{" +
      entries
        .map(([k, v]) => JSON.stringify(k) + ":" + jcsCanonicalize(v))
        .join(",") +
      "}"
    );
  }

  throw new Error(`jcsCanonicalize: unsupported type ${typeof value}`);
}

/**
 * rulesHash = keccak256(JCS(ruleDocument)). Whitepaper Section 4.
 * Travels through circuits as two 128-bit limbs (spec Section 4).
 */
export function rulesHash(ruleDocument: unknown): string {
  return keccak256(toUtf8Bytes(jcsCanonicalize(ruleDocument)));
}
