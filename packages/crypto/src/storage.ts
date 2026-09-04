/**
 * The bidder's client for the ciphertext-store replicas.
 *
 * Development plan Section 12.3 steps 7-9. Uses global `fetch`, so the same
 * code runs in the browser and in Node.
 *
 * THE QUORUM IS THE POINT. The bidder uploads to all three replicas in
 * parallel and requires at least TWO signed receipts. One replica may be
 * down - the plan says so explicitly, and there is a test that takes one
 * down. What must never happen is an on-chain submission whose ciphertext
 * only one replica holds, because then a single failure makes the bid
 * unopenable and the award proof's completeness claim false.
 *
 * RECEIPTS ARE VERIFIED HERE, BEFORE SUBMISSION. Every signature is recovered
 * and compared against the replica's registered address. `SealedBid` performs
 * the same check on-chain, but discovering a bad receipt in a reverted
 * transaction - possibly minutes before the deadline - is far worse than
 * discovering it here, where the bidder can retry against the other replicas.
 */
import { recoverAddress } from "ethers";
import { STORAGE_QUORUM } from "./domains.js";
import type { StorageReceipt } from "./encoding.js";
import { hasStorageQuorum, receiptSigDigest, storageReceiptRoot } from "./sealedbid.js";

/** A replica as registered on-chain. */
export interface ReplicaEndpoint {
  replicaId: number;
  /** Base URL, e.g. http://127.0.0.1:8101 */
  url: string;
  /** The address whose key signs this replica's receipts. */
  address: string;
}

export interface ReplicaOutcome {
  replicaId: number;
  ok: boolean;
  receipt?: StorageReceipt;
  /** Why this replica did not produce a usable receipt. */
  problem?: string;
}

export interface UploadResult {
  receipts: StorageReceipt[];
  storageReceiptRoot: bigint;
  outcomes: ReplicaOutcome[];
  quorumMet: boolean;
}

/** Validate one replica's response. Returns a problem string, or null. */
function validate(
  endpoint: ReplicaEndpoint,
  body: {
    replicaId?: number;
    contentHash?: string;
    byteLength?: number;
    signature?: string;
  },
  expected: { contentHash: string; byteLength: number },
): string | null {
  if (body.replicaId !== endpoint.replicaId) {
    return `replicaId ${body.replicaId} does not match the registered ${endpoint.replicaId}`;
  }
  if (!body.contentHash || body.contentHash.toLowerCase() !== expected.contentHash.toLowerCase()) {
    return `contentHash ${body.contentHash} does not match the submitted ciphertext`;
  }
  if (body.byteLength !== expected.byteLength) {
    return `byteLength ${body.byteLength} does not match the ${expected.byteLength} bytes uploaded`;
  }
  if (!body.signature) return "no signature";

  // Recover, do not trust. The replica reports its own signer address in the
  // response; using that would let a replica claim any identity it likes.
  const digest = receiptSigDigest({
    replicaId: endpoint.replicaId,
    contentHash: expected.contentHash,
    byteLength: expected.byteLength,
  });
  let recovered: string;
  try {
    recovered = recoverAddress(digest, body.signature);
  } catch (err) {
    return `signature does not recover: ${(err as Error).message}`;
  }
  if (recovered.toLowerCase() !== endpoint.address.toLowerCase()) {
    return `signature recovers to ${recovered}, not the registered ${endpoint.address}`;
  }
  return null;
}

/**
 * Upload the canonical ciphertext bytes to every replica in parallel and
 * collect verified receipts.
 *
 * Never throws on a replica failure; a down replica is an expected condition,
 * not an error. It throws only if the quorum cannot be met, because
 * submitting on-chain at that point would be worse than failing here.
 */
export async function uploadToReplicas(
  replicas: ReplicaEndpoint[],
  canonicalBytes: Uint8Array,
  contentHash: string,
  options: { timeoutMs?: number; requireQuorum?: boolean } = {},
): Promise<UploadResult> {
  const timeoutMs = options.timeoutMs ?? 5000;
  const expected = { contentHash, byteLength: canonicalBytes.length };

  const outcomes = await Promise.all(
    replicas.map(async (endpoint): Promise<ReplicaOutcome> => {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      try {
        const res = await fetch(
          `${endpoint.url}/objects?contentHash=${contentHash}`,
          {
            method: "PUT",
            // Copied into a plain ArrayBuffer: fetch's BodyInit does not
            // accept a view onto a SharedArrayBuffer, which is what
            // Uint8Array's default type parameter allows.
            body: canonicalBytes.slice().buffer as ArrayBuffer,
            headers: { "content-type": "application/octet-stream" },
            signal: controller.signal,
          },
        );
        const body = await res.json().catch(() => ({}));
        if (!res.ok) {
          return {
            replicaId: endpoint.replicaId,
            ok: false,
            problem: `HTTP ${res.status}: ${body.error ?? "no detail"}`,
          };
        }
        const problem = validate(endpoint, body, expected);
        if (problem) return { replicaId: endpoint.replicaId, ok: false, problem };
        return {
          replicaId: endpoint.replicaId,
          ok: true,
          receipt: {
            replicaId: endpoint.replicaId,
            contentHash: expected.contentHash,
            byteLength: expected.byteLength,
            signature: body.signature as string,
          },
        };
      } catch (err) {
        return {
          replicaId: endpoint.replicaId,
          ok: false,
          problem: (err as Error).name === "AbortError"
            ? `no response within ${timeoutMs}ms`
            : (err as Error).message,
        };
      } finally {
        clearTimeout(timer);
      }
    }),
  );

  const receipts = outcomes.flatMap((o) => (o.receipt ? [o.receipt] : []));
  const quorumMet = hasStorageQuorum(receipts);

  if (options.requireQuorum !== false && !quorumMet) {
    const detail = outcomes
      .filter((o) => !o.ok)
      .map((o) => `replica ${o.replicaId}: ${o.problem}`)
      .join("; ");
    throw new Error(
      `uploadToReplicas: only ${receipts.length} of ${replicas.length} replicas ` +
        `acknowledged; ${STORAGE_QUORUM} are required. ${detail}`,
    );
  }

  return {
    receipts,
    // Computed from whatever quorum was achieved, padded canonically, so the
    // root a two-replica submission produces is well defined and the contract
    // can recompute it.
    storageReceiptRoot: receipts.length ? storageReceiptRoot(receipts) : 0n,
    outcomes,
    quorumMet,
  };
}

/** Fetch a stored ciphertext from the first replica that has it. */
export async function fetchCiphertext(
  replicas: ReplicaEndpoint[],
  contentHash: string,
  options: { timeoutMs?: number } = {},
): Promise<{ bytes: Uint8Array; replicaId: number }> {
  const timeoutMs = options.timeoutMs ?? 5000;
  const problems: string[] = [];
  for (const endpoint of replicas) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetch(`${endpoint.url}/objects/${contentHash}`, {
        signal: controller.signal,
      });
      if (!res.ok) {
        problems.push(`replica ${endpoint.replicaId}: HTTP ${res.status}`);
        continue;
      }
      return {
        bytes: new Uint8Array(await res.arrayBuffer()),
        replicaId: endpoint.replicaId,
      };
    } catch (err) {
      problems.push(`replica ${endpoint.replicaId}: ${(err as Error).message}`);
    } finally {
      clearTimeout(timer);
    }
  }
  throw new Error(`fetchCiphertext: no replica served ${contentHash}. ${problems.join("; ")}`);
}
