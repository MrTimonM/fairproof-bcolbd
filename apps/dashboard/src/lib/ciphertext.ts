/**
 * The inverse of `canonicalCiphertextBytes`.
 *
 * The committee opens a bid it did not seal, so it has to recover the
 * ciphertext's parts from the bytes a replica serves rather than from a
 * bidder's in-memory object. The layout is fixed by docs/field-encoding.md
 * Section 11, and every length is checked here — a ciphertext whose length
 * prefix disagrees with its own body is a corrupt object, not a short read,
 * and the difference matters when the next step is a decryption failure that
 * would otherwise look like a wrong key.
 */
import { CIPHERTEXT_VERSION, type CiphertextParts } from "@fairproof/crypto";

function beBigInt(b: Uint8Array): bigint {
  let v = 0n;
  for (const x of b) v = (v << 8n) | BigInt(x);
  return v;
}

export function parseCiphertextBytes(bytes: Uint8Array): CiphertextParts {
  // 1 version + 32 rX + 32 rY + 32 wrapped + 12 iv + 4 length + ct + 16 tag
  const FIXED = 1 + 32 + 32 + 32 + 12 + 4 + 16;
  if (bytes.length < FIXED) {
    throw new Error(
      `parseCiphertextBytes: ${bytes.length} bytes is shorter than the ${FIXED}-byte minimum`,
    );
  }
  if (bytes[0] !== CIPHERTEXT_VERSION) {
    throw new Error(
      `parseCiphertextBytes: version ${bytes[0]}, expected ${CIPHERTEXT_VERSION}`,
    );
  }

  let at = 1;
  const take = (n: number) => {
    const slice = bytes.subarray(at, at + n);
    at += n;
    return slice;
  };

  const rX = beBigInt(take(32));
  const rY = beBigInt(take(32));
  const wrapped = new Uint8Array(take(32));
  const iv = new Uint8Array(take(12));
  const ctLength = Number(beBigInt(take(4)));

  if (at + ctLength + 16 !== bytes.length) {
    throw new Error(
      `parseCiphertextBytes: the length prefix claims ${ctLength} ciphertext bytes, ` +
        `which does not account for the object's ${bytes.length} bytes`,
    );
  }

  const ct = new Uint8Array(take(ctLength));
  const tag = new Uint8Array(take(16));

  return { rX, rY, wrapped, iv, ct, tag };
}
