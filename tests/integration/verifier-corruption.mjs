#!/usr/bin/env node
/**
 * Feed the independent verifier deliberately corrupted bundles.
 *
 * Plan Section 16.6 requires exactly this: a flipped bit in a proof, a removed
 * accepted bid, a stale root, an extra leaf, a re-ordered leaf, a forged
 * replica signature — each must fail, and each must fail on the RIGHT item.
 *
 * Why the item matters and not just the exit code: a verifier that fails
 * everything on any corruption is nearly useless to an auditor, because it
 * cannot tell them what went wrong. So every case below asserts which check
 * caught it, and a case that fails on the wrong item is treated as a defect.
 *
 * The verifier is also confirmed to ACCEPT the untouched bundle first. Without
 * that, every rejection below could be a verifier that simply rejects
 * everything.
 */
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyBundle } from "../../packages/verifier/src/verify.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "../..");
const evidenceDir = join(repoRoot, "evidence");

let failures = 0;
const check = (ok, label, detail = "") => {
  console.log(`  ${ok ? "PASS" : "FAIL"}  ${label}${detail ? ` - ${detail}` : ""}`);
  if (!ok) failures++;
};

const files = readdirSync(evidenceDir)
  .filter((f) => f.endsWith(".json"))
  .sort();
if (files.length === 0) {
  console.error("no bundles in ./evidence. Run `npm run seed` then `npm run evidence -- --all`.");
  process.exit(1);
}
/**
 * The most recent export, PREFERRING one with at least two accepted bids.
 *
 * Several corruptions here are only meaningful against a multi-bid set — a
 * re-ordering needs two bids to re-order. Taking the newest bundle
 * unconditionally meant a single-bid export silently became the baseline and
 * the suite died on `acceptedBids[1]` being undefined, which reads like a
 * verifier bug rather than an unsuitable fixture.
 */
const parse = (f) => JSON.parse(readFileSync(join(evidenceDir, f), "utf8"));
let file = files[files.length - 1];
for (let i = files.length - 1; i >= 0; i--) {
  try {
    if ((parse(files[i]).acceptedBids ?? []).length >= 2) {
      file = files[i];
      break;
    }
  } catch {
    // Unreadable bundle: not a candidate.
  }
}
const original = parse(file);
/** Corruptions that need a second bid to mean anything. */
const multiBid = (original.acceptedBids ?? []).length >= 2;

console.log("Independent verifier against corrupted bundles");
console.log(`baseline: ${file}\n`);

const clone = () => JSON.parse(JSON.stringify(original));

/** Flip the last hex digit of a decimal-string field, keeping it numeric. */
const bump = (decimalString) => (BigInt(decimalString) + 1n).toString();

console.log("[0] The untouched bundle is ACCEPTED");
{
  const report = await verifyBundle(original);
  check(
    report.failures.length === 0,
    "the pristine bundle passes every check",
    report.failures.map((f) => f.id).join(", ") || `${report.passed} passed`,
  );
  if (report.failures.length > 0) {
    console.log("\n  Cannot trust the corruption results while the baseline fails.");
    process.exit(1);
  }
}

/**
 * @param label     what was corrupted
 * @param mutate    the corruption
 * @param expected  the check id that must catch it
 */
async function corrupt(label, mutate, expected, needsTwoBids = false) {
  if (needsTwoBids && !multiBid) {
    console.log(`  SKIP  ${label} - baseline has one bid, so this corruption is vacuous`);
    return;
  }
  const b = clone();
  mutate(b);
  const report = await verifyBundle(b);
  const ids = report.failures.map((f) => String(f.id));
  const caught = ids.includes(String(expected));
  check(
    caught,
    label,
    caught
      ? `caught by check ${expected}${ids.length > 1 ? ` (also ${ids.filter((i) => i !== String(expected)).join(", ")})` : ""}`
      : ids.length === 0
        ? "NOT DETECTED AT ALL"
        : `caught by ${ids.join(", ")} but not by the expected ${expected}`,
  );
}

console.log("\n[1] The rule document");
await corrupt(
  "a single character changed in the canonical rule document",
  (b) => {
    b.tender.canonicalRuleDocument = b.tender.canonicalRuleDocument.replace(
      "LOWEST_QUALIFIED_PRICE",
      "HIGHEST_QUALIFIED_PRICE",
    );
  },
  1,
);
await corrupt(
  "a document that no longer parses to the enforced fields",
  (b) => {
    // Keep the hash consistent by rewriting both, so only the FIELD comparison
    // can catch it. This is the on-chain gap the verifier exists to close.
    const doc = JSON.parse(b.tender.canonicalRuleDocument);
    doc.requirements.turnoverThreshold = 1;
    b.tender.canonicalRuleDocument = JSON.stringify(doc, Object.keys(doc).sort());
    b.tender.rulesHash = "0x" + "00".repeat(32);
  },
  "1b",
);

console.log("\n[2] The review window");
await corrupt(
  "bidding opening before the review window elapsed",
  (b) => {
    b.tender.biddingStart = b.tender.activatedAt + 1;
  },
  2,
);

console.log("\n[3] The bid set");
await corrupt(
  "an accepted bid REMOVED from the bundle",
  (b) => {
    b.acceptedBids = b.acceptedBids.slice(0, -1);
  },
  3,
);
await corrupt(
  "an extra leaf added to the bid set",
  (b) => {
    const last = JSON.parse(JSON.stringify(b.acceptedBids[b.acceptedBids.length - 1]));
    last.submissionIndex = b.acceptedBids.length;
    last.nullifier = bump(last.nullifier);
    b.acceptedBids.push(last);
    b.roots.submissionCount = b.acceptedBids.length;
  },
  3,
);
await corrupt(
  "two bids RE-ORDERED, so each leaf commits to the wrong index",
  (b) => {
    const [a, c] = [b.acceptedBids[0], b.acceptedBids[1]];
    b.acceptedBids[0] = { ...c, submissionIndex: 0 };
    b.acceptedBids[1] = { ...a, submissionIndex: 1 };
  },
  3,
  true,
);
await corrupt(
  "a STALE bidSetRoot",
  (b) => {
    b.roots.bidSetRoot = bump(b.roots.bidSetRoot);
  },
  3,
);
await corrupt(
  "a bid amount commitment altered",
  (b) => {
    b.acceptedBids[0].bidCommitment = bump(b.acceptedBids[0].bidCommitment);
  },
  3,
);

console.log("\n[4] The eligibility proofs");
await corrupt(
  "one bit flipped in an eligibility proof",
  (b) => {
    b.acceptedBids[0].eligibilityProof.pA[0] = bump(
      b.acceptedBids[0].eligibilityProof.pA[0],
    );
  },
  4,
);
await corrupt(
  "a proof re-pointed at a lower turnover threshold",
  (b) => {
    b.acceptedBids[0].publicSignals[3] = "1";
  },
  4,
);
await corrupt(
  "rulesHash limbs that do not reconstruct the frozen hash",
  (b) => {
    for (const bid of b.acceptedBids) bid.publicSignals[1] = bump(bid.publicSignals[1]);
  },
  "4b",
);

console.log("\n[5] Nullifiers");
await corrupt(
  "the same credential bidding twice",
  (b) => {
    b.acceptedBids[1].nullifier = b.acceptedBids[0].nullifier;
  },
  5,
);

console.log("\n[6] Storage receipts");
await corrupt(
  "a FORGED replica signature",
  (b) => {
    const sig = b.acceptedBids[0].replicaReceipts[0].signature;
    // Flip a byte in the r component; still 65 bytes, still parseable, but it
    // recovers to a different address.
    const flipped =
      sig.slice(0, 10) +
      (sig[10] === "a" ? "b" : "a") +
      sig.slice(11);
    b.acceptedBids[0].replicaReceipts[0].signature = flipped;
  },
  6,
);
await corrupt(
  "a receipt for a DIFFERENT ciphertext",
  (b) => {
    b.acceptedBids[0].replicaReceipts[0].contentHash =
      b.acceptedBids[1].ciphertextHash;
  },
  6,
);
await corrupt(
  "receipts from only ONE replica",
  (b) => {
    b.acceptedBids[0].replicaReceipts = b.acceptedBids[0].replicaReceipts.slice(0, 1);
  },
  6,
);
await corrupt(
  "the replica registry removed entirely",
  (b) => {
    delete b.replicas;
  },
  6,
);

console.log("\n[7] Timing");
await corrupt(
  "a bid accepted at or after the deadline",
  (b) => {
    b.acceptedBids[0].acceptedTimestamp = b.tender.deadline + 1;
  },
  7,
);

console.log("\n[8] The opening ceremony");
await corrupt(
  "one bit flipped in a DLEQ proof",
  (b) => {
    b.opening[0].dleqProof.z = bump(b.opening[0].dleqProof.z);
  },
  8,
);
await corrupt(
  "a forged decryption share with an honest member's proof",
  (b) => {
    b.opening[0].share.x = bump(b.opening[0].share.x);
  },
  8,
);
await corrupt(
  "only TWO valid shares for a bid",
  (b) => {
    const idx = b.opening.findIndex((o) => o.bidIndex === 0);
    b.opening.splice(idx, 1);
  },
  8,
);
await corrupt(
  "a share submitted BEFORE the deadline",
  (b) => {
    b.opening[0].timestamp = b.tender.deadline - 10;
  },
  8,
);

console.log("\n[9] Close-time status");
await corrupt(
  "a status proof checked against the wrong root",
  (b) => {
    b.statusProofs[0].publicSignals[8] = bump(b.statusProofs[0].publicSignals[8]);
  },
  9,
);

console.log("\n[10] The award");
await corrupt(
  "one bit flipped in the award proof",
  (b) => {
    b.award.proof.pC[0] = bump(b.award.proof.pC[0]);
  },
  10,
);
await corrupt(
  "the award claiming a bid that was not accepted",
  (b) => {
    b.award.winnerCommitment = bump(b.award.winnerCommitment);
  },
  10,
);
await corrupt(
  "the award proved against a smaller bid set",
  (b) => {
    b.award.publicSignals[4] = "1";
  },
  10,
);
await corrupt(
  "a price published under a concealing policy",
  (b) => {
    b.tender.disclosurePolicy = 2;
    b.award.winningPrice = "7400000";
  },
  10,
);

console.log("\n[11] The winner identity");
await corrupt(
  "one bit flipped in the identity proof",
  (b) => {
    b.identityLinkage.proof.pA[1] = bump(b.identityLinkage.proof.pA[1]);
  },
  11,
);
await corrupt(
  "an identity record naming a different credential",
  (b) => {
    const rec = JSON.parse(b.identityLinkage.disclosedIdentity);
    rec.credentialId = 9999;
    b.identityLinkage.disclosedIdentity = JSON.stringify(rec);
  },
  11,
);
await corrupt(
  "the identity linked to the LOSING bid's nullifier",
  (b) => {
    b.identityLinkage.publicSignals[2] = b.acceptedBids[1].nullifier;
  },
  11,
);

console.log("\n[13] Secrets in the bundle");
await corrupt(
  "a subjectSecret smuggled into the bundle",
  (b) => {
    b.acceptedBids[0].subjectSecret = "12345";
  },
  13,
);
await corrupt(
  "a data-encryption key smuggled in",
  (b) => {
    b.ciphertexts[0].dek = "0xdeadbeef";
  },
  13,
);
await corrupt(
  "a bid nonce smuggled in",
  (b) => {
    b.acceptedBids[0].bidNonce = "999";
  },
  13,
);

console.log(
  failures === 0
    ? "\nEVERY CORRUPTION WAS CAUGHT BY THE RIGHT CHECK"
    : `\n${failures} CORRUPTION(S) MISHANDLED`,
);
process.exit(failures === 0 ? 0 : 1);
