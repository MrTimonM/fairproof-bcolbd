#!/usr/bin/env node
/**
 * One replica of the sealed-bid ciphertext store.
 *
 * Development plan Sections 12.3 and 12.5, whitepaper Section 4 and Figure 5.
 * Three of these run independently; a bid is accepted on-chain only once TWO
 * of them have acknowledged the ciphertext.
 *
 * WHAT A RECEIPT ACTUALLY CLAIMS. It claims that this replica, identified by
 * a key registered on-chain, holds bytes whose `ciphertextHash` is
 * `contentHash`. That is the entire content of the guarantee behind the
 * whitepaper's "missing ciphertext" row: a commitment cannot enter
 * `bidSetRoot` unless a retrievable payload was genuinely acknowledged by two
 * independent replicas.
 *
 * SO THE REPLICA RECOMPUTES THE HASH ITSELF.
 *
 * The content hash is derived from the uploaded bytes, never taken from the
 * request. A replica that signed a caller-supplied hash could be made to
 * vouch for bytes it does not hold - and the failure would only surface at
 * opening time, after the deadline, when nothing can be done about it. This
 * is the single most important line of code in the service.
 *
 * WHAT IT IS NOT. This is a prototype store: no authentication, no rate
 * limiting, no replication between replicas, no durability guarantees beyond
 * the filesystem. It demonstrates the receipt mechanism honestly; it is not
 * an availability solution. Whitepaper Table 11's "off-chain storage
 * dependency" row already says as much.
 */
import { createServer } from "node:http";
import { mkdirSync, readFileSync, writeFileSync, existsSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { keccak256, Wallet, getBytes, concat } from "ethers";

/** keccak256("FairProof:ciphertext:v1"), spec Section 3. */
const RAW_CIPHERTEXT_V1 =
  "0x6edc5e8537624c6e297a0e49274ec5a5e66270f9402ff011206b0c1793896729";
/** keccak256("FairProof:receiptSig:v1"), spec Section 22. */
const RAW_RECEIPT_SIG_V1 =
  "0xc3ffb182dd3ebfe5535def6710ba4562e2bf2416e6ac55e4ac25fc7e14433ea3";

/**
 * The service duplicates two constants and two hash definitions rather than
 * importing @fairproof/crypto.
 *
 * That is deliberate, and the reason is worth stating: a replica whose
 * receipt logic came from the same module as the bidder's would agree with
 * the bidder by construction. An independent implementation of
 * `ciphertextHash` and `receiptSigDigest` means the cross-check between them
 * is a real check. The constants are asserted against the crypto package in
 * the integration test, so a drift is caught rather than tolerated.
 */

const REPLICA_ID = Number(process.env.REPLICA_ID ?? 1);
const PORT = Number(process.env.PORT ?? 8100 + REPLICA_ID);
const PRIVATE_KEY = process.env.REPLICA_PRIVATE_KEY;
const DATA_DIR = resolve(process.env.DATA_DIR ?? `./data/replica-${REPLICA_ID}`);
/** Refuse an upload larger than this. A bid payload is a few hundred bytes. */
const MAX_BYTES = Number(process.env.MAX_BYTES ?? 65536);

if (!PRIVATE_KEY) {
  console.error("REPLICA_PRIVATE_KEY is required");
  process.exit(1);
}
if (!Number.isInteger(REPLICA_ID) || REPLICA_ID < 1 || REPLICA_ID > 255) {
  console.error("REPLICA_ID must be a uint8 >= 1 (0 is reserved)");
  process.exit(1);
}

const wallet = new Wallet(PRIVATE_KEY);
mkdirSync(DATA_DIR, { recursive: true });

const u8 = (n, bytes) => {
  const out = new Uint8Array(bytes);
  let v = BigInt(n);
  for (let i = bytes - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
};

/** ciphertextHash = keccak256(RAW_CIPHERTEXT_V1 || canonicalBytes). Spec 6. */
const contentHashOf = (bytes) =>
  keccak256(concat([getBytes(RAW_CIPHERTEXT_V1), bytes]));

/** Spec Section 22. */
const receiptSigDigest = (replicaId, contentHash, byteLength) =>
  keccak256(
    concat([
      getBytes(RAW_RECEIPT_SIG_V1),
      u8(replicaId, 1),
      getBytes(contentHash),
      u8(byteLength, 8),
    ]),
  );

const objectPath = (contentHash) => join(DATA_DIR, `${contentHash.slice(2)}.bin`);

/**
 * Permissive CORS, deliberately.
 *
 * A bidder seals and uploads a ciphertext from their own browser tab, so the
 * upload is a cross-origin request from the dashboard's origin to this
 * replica's. Nothing here is protected by origin: every write is content-
 * addressed and every read returns bytes whose hash the caller already knows,
 * so an origin check would restrict nothing an attacker could not do with
 * curl. What actually binds an object to a bid is the replica's signature over
 * the content hash, which a browser cannot forge.
 */
const CORS = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET, PUT, OPTIONS",
  "access-control-allow-headers": "content-type",
  "access-control-expose-headers": "x-fairproof-content-hash",
  "access-control-max-age": "86400",
};

function json(res, status, body) {
  const payload = JSON.stringify(body, null, 2);
  res.writeHead(status, {
    ...CORS,
    "content-type": "application/json",
    "content-length": Buffer.byteLength(payload),
  });
  res.end(payload);
}

async function readBody(req) {
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    // Bounded before buffering, not after: an unbounded read is a trivial
    // memory exhaustion in a service anyone can POST to.
    if (total > MAX_BYTES) {
      throw Object.assign(new Error(`body exceeds ${MAX_BYTES} bytes`), { status: 413 });
    }
    chunks.push(chunk);
  }
  return new Uint8Array(Buffer.concat(chunks));
}

const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://localhost:${PORT}`);

    if (req.method === "OPTIONS") {
      res.writeHead(204, { ...CORS, "content-length": 0 });
      return res.end();
    }

    if (req.method === "GET" && url.pathname === "/health") {
      return json(res, 200, {
        replicaId: REPLICA_ID,
        address: wallet.address,
        objects: readdirSync(DATA_DIR).filter((f) => f.endsWith(".bin")).length,
        maxBytes: MAX_BYTES,
      });
    }

    // Store a ciphertext and return a signed receipt.
    if (req.method === "PUT" && url.pathname === "/objects") {
      const bytes = await readBody(req);
      if (bytes.length === 0) return json(res, 400, { error: "empty body" });

      // THE hash is computed HERE, from the bytes received. Never from the
      // request. See the header comment.
      const contentHash = contentHashOf(bytes);

      // If the caller stated an expected hash, it must match what we computed.
      // This is a courtesy check that catches a transport corruption early; it
      // is not what the receipt rests on.
      const claimed = url.searchParams.get("contentHash");
      if (claimed && claimed.toLowerCase() !== contentHash.toLowerCase()) {
        return json(res, 400, {
          error: "contentHash mismatch",
          computed: contentHash,
          claimed,
          note: "the receipt covers the hash of the bytes received, never a supplied value",
        });
      }

      writeFileSync(objectPath(contentHash), bytes);

      const digest = receiptSigDigest(REPLICA_ID, contentHash, bytes.length);
      return json(res, 201, {
        replicaId: REPLICA_ID,
        contentHash,
        // Defined to EQUAL contentHash, so it carries no information the
        // signature does not cover (spec Section 22).
        objectId: contentHash,
        byteLength: bytes.length,
        storedAt: new Date().toISOString(),
        signature: wallet.signingKey.sign(digest).serialized,
        signer: wallet.address,
        digest,
      });
    }

    // Retrieve a stored ciphertext.
    if (req.method === "GET" && url.pathname.startsWith("/objects/")) {
      const contentHash = url.pathname.slice("/objects/".length).toLowerCase();
      if (!/^0x[0-9a-f]{64}$/.test(contentHash)) {
        return json(res, 400, { error: "contentHash must be a 32-byte hex string" });
      }
      const p = objectPath(contentHash);
      if (!existsSync(p)) return json(res, 404, { error: "not found", contentHash });
      const bytes = readFileSync(p);

      // Re-derive on the way out too. A corrupted file must be reported, not
      // served: the opening path would otherwise fail with an AES tag error
      // and look like the bidder's fault.
      const recomputed = contentHashOf(new Uint8Array(bytes));
      if (recomputed.toLowerCase() !== contentHash) {
        return json(res, 500, {
          error: "stored object is corrupt",
          expected: contentHash,
          computed: recomputed,
        });
      }
      res.writeHead(200, {
        ...CORS,
        "content-type": "application/octet-stream",
        "content-length": bytes.length,
        "x-fairproof-content-hash": contentHash,
      });
      return res.end(bytes);
    }

    return json(res, 404, { error: "no such route", method: req.method, path: url.pathname });
  } catch (err) {
    return json(res, err.status ?? 500, { error: err.message });
  }
});

server.listen(PORT, "127.0.0.1", () => {
  console.log(
    `ciphertext-store replica ${REPLICA_ID} on 127.0.0.1:${PORT}\n` +
      `  signer ${wallet.address}\n` +
      `  data   ${DATA_DIR}`,
  );
});

for (const sig of ["SIGINT", "SIGTERM"]) {
  process.on(sig, () => {
    server.close(() => process.exit(0));
  });
}
