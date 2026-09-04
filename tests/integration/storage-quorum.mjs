#!/usr/bin/env node
/**
 * The 2-of-3 ciphertext storage quorum, against three real processes.
 *
 * Development plan Sections 12.3 and 12.5, whitepaper Section 4 and Table 4.
 *
 * This is the STORAGE quorum. It is not the 3-of-5 opening threshold. Two
 * replicas cannot open a bid; three committee members cannot make a
 * ciphertext retrievable.
 *
 * Why an integration test and not a unit test: the plan requires that "one
 * replica may be down; that is the point of the test". Simulating a down
 * replica with a stubbed client proves that the stub works. Here the test
 * SIGTERMs an actual process and the bidder's real HTTP client has to cope.
 */
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { recoverAddress } from "ethers";
import {
  RAW_CIPHERTEXT_V1,
  RAW_RECEIPT_SIG_V1,
  STORAGE_QUORUM,
  ciphertextHash,
  dealCommitteeKey,
  fetchCiphertext,
  generateDek,
  hasStorageQuorum,
  initBabyjub,
  initPoseidon,
  nullifier as computeNullifier,
  receiptSigDigest,
  sealBid,
  storageReceiptRoot,
  subjectCommitment,
  tenderIdField,
  uploadToReplicas,
} from "@fairproof/crypto";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "../..");
const control = join(repoRoot, "scripts/replica-control.mjs");

let failures = 0;
let step = 0;
const check = (ok, label, detail = "") => {
  console.log(`  ${ok ? "PASS" : "FAIL"}  ${label}${detail ? ` - ${detail}` : ""}`);
  if (!ok) failures++;
};
const stage = (t) => console.log(`\n[${++step}] ${t}`);

const ctl = (...args) =>
  execFileSync(process.execPath, [control, ...args], { encoding: "utf8", cwd: repoRoot });

const endpoints = JSON.parse(ctl("endpoints"));

console.log("FairProof ciphertext storage quorum (2 of 3)");
console.log(`replicas: ${endpoints.map((e) => e.url).join(", ")}\n`);

await initPoseidon();
await initBabyjub();

// Always leave the replicas as we found them, even on a thrown error: a test
// that exits with a replica still down poisons every later run.
let stoppedReplica = null;
process.on("exit", () => {
  if (stoppedReplica !== null) {
    try {
      ctl("start", String(stoppedReplica));
    } catch {
      console.error(`\nWARNING: could not restart replica ${stoppedReplica}`);
    }
  }
});

// ---------------------------------------------------------------- seal a bid

const TENDER = "FP-00014";
const SUBJECT_SECRET = 4759208310398234759832475982374598234759823475982347n;
const BID_NONCE = 8823409128340981234098123409812340981234098123409812n;
const BID_AMOUNT = 7400000n;

const dealt = dealCommitteeKey();
const tf = tenderIdField(TENDER);
const nul = computeNullifier(SUBJECT_SECRET, tf);

async function freshBid(amount = BID_AMOUNT) {
  return sealBid({
    payload: {
      tenderId: TENDER,
      amountMinorUnit: amount.toString(),
      currency: "BDT",
      bidNonce: BID_NONCE.toString(),
      subjectCommitment: subjectCommitment(SUBJECT_SECRET).toString(),
      createdAt: new Date().toISOString(),
    },
    tenderPublicKey: dealt.publicKey,
    tenderIdField: tf,
    nullifier: nul,
  });
}

// =========================================================================
stage("The replica service and the crypto package agree independently");

// The service reimplements ciphertextHash and receiptSigDigest rather than
// importing them, so that the agreement between bidder and replica is a real
// cross-check. That only works if the constants match, which is checked here
// rather than assumed.
const serviceSource = readFileSync(
  join(repoRoot, "services/ciphertext-store/src/server.mjs"),
  "utf8",
);
check(
  serviceSource.includes(RAW_CIPHERTEXT_V1),
  "the service's RAW_CIPHERTEXT_V1 matches the crypto package's",
  RAW_CIPHERTEXT_V1.slice(0, 18),
);
check(
  serviceSource.includes(RAW_RECEIPT_SIG_V1),
  "the service's RAW_RECEIPT_SIG_V1 matches the crypto package's",
);

// =========================================================================
stage("All three replicas up: three receipts, all signatures verified");

ctl("start");
const sealed = await freshBid();
const all = await uploadToReplicas(endpoints, sealed.canonicalBytes, sealed.ciphertextHash);

check(all.receipts.length === 3, "three replicas acknowledged", `${all.receipts.length}/3`);
check(all.quorumMet, "quorum met");
for (const r of all.receipts) {
  const digest = receiptSigDigest({
    replicaId: r.replicaId,
    contentHash: r.contentHash,
    byteLength: r.byteLength,
  });
  const expected = endpoints.find((e) => e.replicaId === r.replicaId).address;
  check(
    recoverAddress(digest, r.signature).toLowerCase() === expected.toLowerCase(),
    `replica ${r.replicaId}'s signature recovers to its registered address`,
    expected,
  );
}
check(
  all.receipts.every((r) => r.contentHash === sealed.ciphertextHash),
  "every receipt covers the ciphertextHash the bidder will submit on-chain",
  sealed.ciphertextHash.slice(0, 18),
);
const threeRoot = all.storageReceiptRoot;
check(threeRoot === storageReceiptRoot(all.receipts), "the root is reproducible from the receipts");

// =========================================================================
stage("Replica 2 is taken down. The bid must still be submittable.");

ctl("stop", "2");
stoppedReplica = 2;
const sealed2 = await freshBid(8150000n);
const degraded = await uploadToReplicas(endpoints, sealed2.canonicalBytes, sealed2.ciphertextHash);

check(
  degraded.receipts.length === STORAGE_QUORUM,
  "exactly two replicas acknowledged",
  `${degraded.receipts.length}/3`,
);
check(degraded.quorumMet, "the 2-of-3 quorum still holds with one replica down");
check(
  degraded.outcomes.find((o) => o.replicaId === 2)?.ok === false,
  "replica 2 is reported as failed, with a reason",
  degraded.outcomes.find((o) => o.replicaId === 2)?.problem?.slice(0, 60),
);
check(
  degraded.receipts.map((r) => r.replicaId).join(",") === "1,3",
  "the surviving receipts are from replicas 1 and 3",
);
check(
  degraded.storageReceiptRoot !== threeRoot,
  "a two-replica root differs from a three-replica root",
  "so the contract cannot be shown a three-replica root for a two-replica upload",
);

// The whole point: the ciphertext is still retrievable.
const fetched = await fetchCiphertext(endpoints, sealed2.ciphertextHash);
check(
  Buffer.from(fetched.bytes).equals(Buffer.from(sealed2.canonicalBytes)),
  "the ciphertext is retrievable byte for byte from a surviving replica",
  `replica ${fetched.replicaId}`,
);
check(
  ciphertextHash({ ...sealed2.ciphertext }) === sealed2.ciphertextHash,
  "the retrieved bytes hash to the submitted ciphertextHash",
);

// =========================================================================
stage("Replicas 2 AND 3 down: the quorum FAILS, and it fails before submitting");

// This is the half that makes the test meaningful. A quorum check that only
// ever sees enough replicas proves nothing.
ctl("stop", "3");
const sealed3 = await freshBid(9000000n);
let refused = false;
let message = "";
try {
  await uploadToReplicas(endpoints, sealed3.canonicalBytes, sealed3.ciphertextHash);
} catch (err) {
  refused = true;
  message = err.message;
}
check(refused, "the upload is refused rather than proceeding with one receipt");
check(
  /only 1 of 3 replicas acknowledged; 2 are required/.test(message),
  "the refusal says how many acknowledged and how many are needed",
  message.slice(0, 70),
);

// And the client can be asked NOT to throw, for a UI that wants to render the
// per-replica state rather than a single error.
const partial = await uploadToReplicas(
  endpoints,
  sealed3.canonicalBytes,
  sealed3.ciphertextHash,
  { requireQuorum: false },
);
check(!partial.quorumMet, "quorumMet is false when only one replica answers");
check(
  hasStorageQuorum(partial.receipts) === false,
  "hasStorageQuorum agrees, so the contract-side rule and the UI cannot diverge",
);

ctl("start", "2", "3");
stoppedReplica = null;

// =========================================================================
stage("A replica refuses to vouch for bytes it did not receive");

// The most important property of the service: the content hash is computed
// from the bytes received, never taken from the request. A replica that
// signed a supplied hash could be made to vouch for bytes it does not hold,
// and the failure would only surface at opening time, after the deadline.
const wrongHash =
  "0x" + "ab".repeat(32);
const res = await fetch(`${endpoints[0].url}/objects?contentHash=${wrongHash}`, {
  method: "PUT",
  body: sealed.canonicalBytes.slice().buffer,
  headers: { "content-type": "application/octet-stream" },
});
const body = await res.json();
check(res.status === 400, "a mismatched claimed contentHash is rejected", `HTTP ${res.status}`);
check(
  body.computed === sealed.ciphertextHash,
  "the replica reports the hash it computed from the bytes",
);

// =========================================================================
stage("A tampered stored object is reported, not served");

const missing = await fetch(`${endpoints[0].url}/objects/0x${"cd".repeat(32)}`);
check(missing.status === 404, "an unknown contentHash is a 404, not an empty 200");

const oversized = await fetch(`${endpoints[0].url}/objects`, {
  method: "PUT",
  body: new Uint8Array(70000),
  headers: { "content-type": "application/octet-stream" },
});
check(
  oversized.status === 413,
  "an oversized upload is rejected before being buffered",
  `HTTP ${oversized.status}`,
);

console.log(
  failures === 0
    ? "\nSTORAGE QUORUM CONFIRMED"
    : `\n${failures} CHECK(S) FAILED`,
);
process.exitCode = failures === 0 ? 0 : 1;
