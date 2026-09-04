#!/usr/bin/env node
/**
 * Publish one tender, and leave the committee able to open it.
 *
 * The Authority workspace can do everything this does, and does it from the
 * browser. The one thing it cannot do is hand its committee shares to a
 * DIFFERENT browser — it keeps them in its own local storage, which is the
 * honest consequence of a trusted dealer. So a tender published from one
 * machine is a tender nobody else can open, and a deployment seeded that way
 * dead-ends at the opening ceremony.
 *
 * This script closes that gap for a seeded tender by writing the dealing to
 * `apps/dashboard/public/committee-dealings/`, where the Committee workspace
 * picks it up. That is a real weakening and the interface says so on the
 * panel that uses it: for a tender seeded this way the five shares sit in one
 * served file, so the "three of five" threshold is a demonstration of the
 * mechanism rather than a property anyone is relying on. Every tender
 * published through the Authority workspace keeps its shares in the browser
 * that dealt them, and none of them is written here.
 *
 *   npm run tender -- --title "Construction of a 2 km rural road"
 *
 * Requires: npm run network:up, npm run deploy, npm run dashboard:sync
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Contract, JsonRpcProvider, Wallet, keccak256, toUtf8Bytes } from "ethers";
import {
  dealCommitteeKey,
  derivePublicKey,
  emptyRevocationTree,
  initBabyjub,
  initEddsa,
  initPoseidon,
  issuerRegistryRoot,
  jcsCanonicalize,
  verifyDealing,
} from "@fairproof/crypto";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const g = JSON.parse(
  readFileSync(join(repoRoot, "apps/dashboard/src/generated/contracts.json"), "utf8"),
);

const arg = (name, fallback) => {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
};

const TITLE = arg("title", "Construction of a 2 km rural road");
const BUYER = arg("buyer", "Roads and Highways Division");
const LOCATION = arg("location", "Rangpur Sadar, Rangpur");
const REFERENCE = arg("reference", `RHD-${new Date().getFullYear()}-0147`);
const TURNOVER = BigInt(arg("turnover", "500000000"));
const EXPERIENCE = BigInt(arg("experience", "60"));
const CERT = BigInt(arg("certification", "9001"));
const EPOCH = BigInt(arg("epoch", "21"));
const REVIEW = BigInt(arg("review", "60"));
const LEAD = BigInt(arg("lead", "150"));
const WINDOW = BigInt(arg("window", "7200"));
const ISSUER_LABEL = arg("issuer", "ICAB Registered Audit Firm");

const provider = new JsonRpcProvider(`http://127.0.0.1:${g.validators[0].rpc}`, {
  chainId: g.chainId,
  name: "fairproof",
});
const acct = (r) => g.roles.find((x) => x.role === r);
const addr = (n) => g.deployments.contracts[n];
const abi = (n) => g.abis[n];
const read = (n) => new Contract(addr(n), abi(n), provider);
const writeAs = (n, role) =>
  new Contract(addr(n), abi(n), new Wallet(acct(role).privateKey, provider));

async function send(fn, args) {
  const gas = await fn.estimateGas(...args, { gasPrice: 0 });
  const tx = await fn(...args, { gasPrice: 0, gasLimit: (gas * 3n) / 2n });
  return tx.wait();
}

const hex32 = (v) => "0x" + v.toString(16).padStart(64, "0");
const ZERO32 = "0x" + "00".repeat(32);
const step = (t, d = "") => console.log(`  ${t}${d ? `  ${d}` : ""}`);

await initPoseidon();
await initEddsa();
await initBabyjub();

const COUNCIL = "council-regulator";
const AUTHORITY = "tender-authority";
const COMMITTEE = [1, 2, 3, 4, 5].map((i) => `committee-${i}`);

const tr = read("TenderRegistry");
const reg = read("IssuerRegistry");

console.log(`\nPublishing "${TITLE}"\n`);

// ---- the council's preconditions -----------------------------------------
if (!(await tr.isTenderAuthority(acct(AUTHORITY).address))) {
  await send(writeAs("TenderRegistry", COUNCIL).setTenderAuthority, [
    acct(AUTHORITY).address,
    true,
  ]);
}
step("the procuring authority holds its role");

const absoluteMin = await tr.ABSOLUTE_MIN_REVIEW_WINDOW();
if ((await tr.minReviewWindow()) > absoluteMin) {
  await send(writeAs("TenderRegistry", COUNCIL).setMinReviewWindow, [
    absoluteMin,
    "Lower the review-window floor to the contract's hard constant for this deployment",
  ]);
}
step("review-window floor", `${await tr.minReviewWindow()}s`);

// The issuer whose key the dashboard's prover signs credentials with.
const issuerId = keccak256(toUtf8Bytes(`ISSUER-${ISSUER_LABEL}`));
const issuerKey = derivePublicKey(new Uint8Array(32).fill(7));
const registryRoot = issuerRegistryRoot([issuerKey, derivePublicKey(new Uint8Array(32).fill(3))]);
const empty = emptyRevocationTree();
{
  const w = writeAs("IssuerRegistry", COUNCIL);
  // getIssuer REVERTS for an unknown id rather than reporting registered:false.
  let registered = false;
  try {
    registered = (await reg.getIssuer(issuerId)).registered;
  } catch {
    registered = false;
  }
  if (!registered) {
    await send(w.registerIssuer, [issuerId, issuerKey.x, issuerKey.y, 1, ISSUER_LABEL]);
  }
  if ((await reg.issuerRegistryRoot(EPOCH)) === ZERO32) {
    await send(w.publishIssuerRegistryRoot, [EPOCH, hex32(registryRoot)]);
  }
  if ((await reg.revocationRoot(EPOCH)) === ZERO32) {
    await send(w.publishRevocationRoot, [EPOCH, hex32(empty.root)]);
  }
  // closeTender pins the CURRENT epoch's root, not the tender's. Without one
  // published there the tender becomes permanently unclosable.
  const current = await reg.currentEpoch();
  if ((await reg.revocationRoot(current)) === ZERO32) {
    await send(w.publishRevocationRoot, [current, hex32(empty.root)]);
  }
}
step("issuer registered and roots published", `epoch ${EPOCH}`);

// ---- the tender ----------------------------------------------------------
const w = writeAs("TenderRegistry", AUTHORITY);
const chainNow = BigInt((await provider.getBlock("latest")).timestamp);
const biddingStart = chainNow + REVIEW + LEAD;
const deadline = biddingStart + WINDOW;

const ruleDoc = jcsCanonicalize({
  awardRule: "LOWEST_QUALIFIED_PRICE",
  biddingStart: Number(biddingStart),
  buyer: BUYER,
  contingencyPolicy: "CANCEL_AND_REISSUE",
  deadline: Number(deadline),
  disclosurePolicy: "PUBLISH_WINNING_PRICE",
  issuerEpoch: Number(EPOCH),
  location: LOCATION,
  requirements: {
    certificationCode: Number(CERT),
    experienceMonths: Number(EXPERIENCE),
    turnoverThreshold: Number(TURNOVER),
  },
  revocationPolicy: "DEADLINE_ROOT",
  reviewWindow: Number(REVIEW),
  schemaVersion: 1,
  selectionRule: "LOWEST_QUALIFIED_PRICE",
  tenderId: REFERENCE,
  tieBreakRule: "SUBMISSION_SEQUENCE",
  title: TITLE,
  verifierVersion: 1,
});
const rulesHash = keccak256(toUtf8Bytes(ruleDoc));
const tenderId = keccak256(toUtf8Bytes(REFERENCE));

await send(w.createTender, [REFERENCE]);
step("created", REFERENCE);

await send(w.setRuleDocument, [tenderId, toUtf8Bytes(ruleDoc)]);
if ((await tr.recomputeRulesHash(tenderId)) !== rulesHash) {
  throw new Error("the contract recomputed a different rules hash from the document it stored");
}
step("rule document stored, and the CONTRACT recomputed the same hash", rulesHash.slice(0, 20));

await send(w.setRuleFields, [
  tenderId,
  {
    requirements: {
      turnoverThreshold: TURNOVER,
      experienceMonths: Number(EXPERIENCE),
      certificationCode: CERT,
    },
    biddingStart,
    deadline,
    requiredIssuerId: issuerId,
    issuerEpoch: EPOCH,
    schemaVersion: 1,
    verifierVersion: 1,
    disclosurePolicy: 1,
    awardRule: 1,
    tieBreakRule: 1,
    contingencyPolicy: 1,
    reviewWindow: REVIEW,
  },
]);
step("enforced fields set");

const dealt = dealCommitteeKey();
const check = verifyDealing(dealt);
if (!check.ok) throw new Error(`the dealing failed its own check: ${check.problems.join("; ")}`);
const members = COMMITTEE.map((r) => acct(r).address);
await send(w.setCommitteeKey, [
  tenderId,
  dealt.publicKey.x,
  dealt.publicKey.y,
  members,
  dealt.shares.map((s) => s.publicShare.x),
  dealt.shares.map((s) => s.publicShare.y),
  dealt.commitments.map((c) => c.x),
  dealt.commitments.map((c) => c.y),
]);
step("committee key dealt, and the CONTRACT verified it");

await send(w.activateTender, [tenderId, rulesHash]);
step("ACTIVE — every rule frozen from this block");

// ---- the dealing, so the ceremony is demonstrable -------------------------
const dir = join(repoRoot, "apps/dashboard/public/committee-dealings");
mkdirSync(dir, { recursive: true });
writeFileSync(
  join(dir, `${tenderId}.json`),
  JSON.stringify(
    {
      $comment:
        "SEEDED TENDER ONLY. These are the five committee members' secret shares, " +
        "written here so the opening ceremony can be carried out from any browser. " +
        "For this tender the threshold therefore demonstrates the mechanism rather " +
        "than protecting anything. A tender published from the Authority workspace " +
        "keeps its shares in the browser that dealt them and is never written here.",
      tenderId,
      tenderIdString: REFERENCE,
      title: TITLE,
      dealtAt: Date.now(),
      seeded: true,
      publicKey: { x: dealt.publicKey.x.toString(), y: dealt.publicKey.y.toString() },
      commitments: dealt.commitments.map((c) => ({ x: c.x.toString(), y: c.y.toString() })),
      shares: dealt.shares.map((s) => ({
        index: s.index,
        share: s.share.toString(),
        publicShareX: s.publicShare.x.toString(),
        publicShareY: s.publicShare.y.toString(),
      })),
      members,
    },
    null,
    1,
  ) + "\n",
);
writeFileSync(
  join(dir, "index.json"),
  JSON.stringify({ dealings: [`${tenderId}.json`] }, null, 1) + "\n",
);
step("dealing written for the Committee workspace", "public/committee-dealings/");

console.log(`
  ${TITLE}
  ${REFERENCE} · ${BUYER} · ${LOCATION}

  bidding opens  ${new Date(Number(biddingStart) * 1000).toLocaleString()}
  bidding closes ${new Date(Number(deadline) * 1000).toLocaleString()}
`);
process.exit(0);
