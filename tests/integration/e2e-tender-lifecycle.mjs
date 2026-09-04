#!/usr/bin/env node
/**
 * Full tender lifecycle against the LIVE permissioned network.
 *
 * Unit tests on a local EVM and a real deployment are different things: this
 * walks the whole flow with the seed dataset, on four Besu validators, with
 * real block timestamps and no time travel.
 *
 * Uses the whitepaper Figure 5 demo data (plan Section 25.4): tender
 * FP-00014, ABC Construction Ltd. at BDT 74,00,000.
 *
 * Covers the stages that exist today (plan Section 25.1 steps 1-5) plus the
 * negative tests those stages make demonstrable.
 */
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { JsonRpcProvider, Wallet, Contract, keccak256, toUtf8Bytes } from "ethers";
import {
  dealCommitteeKey,
  initBabyjub,
  isInPrimeSubgroup,
  verifyDealing,
  verifyShare,
} from "@fairproof/crypto";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "../..");
const artifactsRoot = join(repoRoot, "packages/contracts/artifacts");

const cfg = JSON.parse(
  readFileSync(join(repoRoot, "infrastructure/besu/config/accounts.json"), "utf8"),
);
const dep = JSON.parse(readFileSync(join(repoRoot, "deployments.json"), "utf8"));
const abi = (p) => JSON.parse(readFileSync(join(artifactsRoot, p), "utf8")).abi;

const acct = (role) => cfg.accounts.find((a) => a.role === role);
const provider = new JsonRpcProvider(`http://127.0.0.1:${cfg.validators[0].rpc}`, {
  chainId: cfg.chainId,
  name: "fairproof",
});
const signer = (role) => new Wallet(acct(role).privateKey, provider);
const OPTS = { gasPrice: 0 };

let failures = 0;
let step = 0;
const check = (ok, label, detail = "") => {
  console.log(`  ${ok ? "PASS" : "FAIL"}  ${label}${detail ? ` - ${detail}` : ""}`);
  if (!ok) failures++;
};
const stage = (title) => console.log(`\n[${++step}] ${title}`);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Assert a call reverts, and that it reverts for the RIGHT reason.
 *
 * Uses staticCall so ethers decodes the custom error against the ABI and
 * gives us `err.revert.name`. A test that accepts any revert is weak: it
 * would pass if the call failed for an unrelated reason, which is exactly how
 * a security control silently stops working.
 */
async function expectRevert(staticCallFn, errorName, label) {
  try {
    await staticCallFn();
    check(false, label, "call succeeded but should have reverted");
  } catch (err) {
    const name = err.revert?.name;
    if (name === errorName) {
      check(true, label, errorName);
    } else {
      check(
        false,
        label,
        `expected ${errorName}, got ${name || (err.shortMessage || err.message || "").slice(0, 90)}`,
      );
    }
  }
}

const gov = new Contract(dep.contracts.Governance, abi("contracts/Governance.sol/Governance.json"), provider);
const reg = new Contract(dep.contracts.IssuerRegistry, abi("contracts/IssuerRegistry.sol/IssuerRegistry.json"), provider);
const tr = new Contract(dep.contracts.TenderRegistry, abi("contracts/TenderRegistry.sol/TenderRegistry.json"), provider);

const State = { NONE: 0n, DRAFT: 1n, ACTIVE: 2n, CLOSED: 3n, OPENING: 4n, AWARDED: 5n, CANCELLED: 6n };

// --- seed dataset (plan Section 25.4) -------------------------------------
//
// Every identifier is suffixed with a per-run nonce. The test MUST be
// idempotent: it runs repeatedly against one long-lived deployment, and demo
// rehearsal (plan Section 25.5 requires five timed runs) depends on being
// able to re-run it without wiping the chain. An earlier version used a fixed
// issuer id and failed on its second run with IssuerAlreadyRegistered.
const RUN = Date.now();
const TENDER_ID_STRING = `FP-00014-${RUN}`;
const ISSUER_ID = keccak256(toUtf8Bytes(`ICAB-AUDIT-FIRM-${RUN}`));
const ISSUER_PUB_X = 1234567890123456789012345678901234567890n;
const ISSUER_PUB_Y = 9876543210987654321098765432109876543210n;
// Per-run root values, so the "a later revocation does not alter the pinned
// deadline root" assertion is meaningful on every run rather than comparing
// a value left behind by a previous run.
const runHex = (RUN % 0xff).toString(16).padStart(2, "0");
const REVOCATION_ROOT = "0x" + runHex.repeat(32);
const ISSUER_REGISTRY_ROOT = "0x" + "22".repeat(32);
/**
 * The committee key is DEALT for real, on every run.
 *
 * The earlier version passed round numbers as curve points. They were
 * structurally plausible, every check passed, and nothing in the run would
 * have noticed that the tender's "public key" was not a point on BabyJubjub
 * at all. `setCommitteeKey` now verifies the Feldman dealing on-chain, so this
 * run deals a fresh 3-of-5 key and the live chain checks it.
 */
await initBabyjub();
const DEALT = dealCommitteeKey();
{
  const { ok, problems } = verifyDealing(DEALT);
  if (!ok) {
    console.error("the local dealing failed its own verification:", problems);
    process.exit(1);
  }
}
const PX = DEALT.publicKey.x;
const PY = DEALT.publicKey.y;

console.log("FairProof end-to-end tender lifecycle (live network)");
console.log(`chain ${dep.chainId}, review-window policy floor ${dep.minReviewWindow}s`);

// =========================================================================
stage("Council 3-of-4 registers the qualification issuer");

const c0 = signer("council-regulator");
const c1 = signer("council-procuring-entity");
const c2 = signer("council-auditor");

// Register directly (council-gated). The Governance proposal flow is
// exercised separately below.
await (await reg.connect(c0).registerIssuer(
  ISSUER_ID, ISSUER_PUB_X, ISSUER_PUB_Y, 1, "ICAB Registered Audit Firm", OPTS,
)).wait();
const issuer = await reg.getIssuer(ISSUER_ID);
check(issuer.active, "issuer registered and active", "ICAB Registered Audit Firm");
check(issuer.pubKeyX === ISSUER_PUB_X, "BabyJubjub key stored");

await expectRevert(
  () => reg.connect(signer("tender-authority")).registerIssuer.staticCall(
    keccak256(toUtf8Bytes(`ROGUE-${RUN}`)), ISSUER_PUB_X, ISSUER_PUB_Y, 1, "rogue", OPTS,
  ),
  "NotCouncilMember",
  "a non-council account cannot register an issuer",
);

// =========================================================================
stage("Council publishes the registry and revocation roots");

await (await reg.connect(c0).publishIssuerRegistryRoot(1, ISSUER_REGISTRY_ROOT, OPTS)).wait();
await (await reg.connect(c0).publishRevocationRoot(1, REVOCATION_ROOT, OPTS)).wait();
check(
  (await reg.issuerRegistryRoot(1)) === ISSUER_REGISTRY_ROOT,
  "issuerRegistryRoot published",
  "circuit clause 2 proves membership against this",
);
check((await reg.revocationRoot(1)) === REVOCATION_ROOT, "revocationRoot published");

// =========================================================================
stage("Governance 3-of-4 proposal flow with an on-chain reason");

const proposeTx = await gov.connect(c0).propose(
  4, "0x", "Record validator set for the pilot council", OPTS,
);
await proposeTx.wait();
const pid = await gov.proposalCount();

let st = await gov.executionStatus(pid);
check(st[0] === false && st[1] === 1n, "one approval is insufficient", `${st[1]}/${st[2]}`);

await (await gov.connect(c1).approve(pid, OPTS)).wait();
st = await gov.executionStatus(pid);
check(st[0] === false && st[1] === 2n, "TWO approvals are insufficient", `${st[1]}/${st[2]}`);

await (await gov.connect(c2).approve(pid, OPTS)).wait();
st = await gov.executionStatus(pid);
check(st[0] === true && st[1] === 3n, "three approvals execute", `${st[1]}/${st[2]}`);
await (await gov.connect(c0).execute(pid, OPTS)).wait();
check((await gov.getProposal(pid)).executed, "proposal executed on-chain");

await expectRevert(
  () => gov.connect(c0).propose.staticCall(7, "0x", "", OPTS),
  "ReasonRequired",
  "an action without an on-chain reason is rejected",
);

// =========================================================================
stage("Authority creates tender FP-00014 in DRAFT");

await (await tr.connect(c0).setTenderAuthority(acct("tender-authority").address, true, OPTS)).wait();
const auth = signer("tender-authority");

await (await tr.connect(auth).createTender(TENDER_ID_STRING, OPTS)).wait();
const tenderId = keccak256(toUtf8Bytes(TENDER_ID_STRING));
check((await tr.getState(tenderId)) === State.DRAFT, "tender created in DRAFT", TENDER_ID_STRING);

// =========================================================================
stage("Authority sets the canonical rule document, fields and committee key");

// RFC 8785 JCS: keys sorted. Bidding opens after the review window.
const nowBlock = await provider.getBlock("latest");
// This tender chooses a window equal to the policy floor. An authority
// may choose longer; it may not choose shorter.
const reviewWindow = dep.minReviewWindow;
const biddingStart = nowBlock.timestamp + reviewWindow + 20;
const deadline = biddingStart + 45;

const ruleDoc = JSON.stringify({
  awardRule: "LOWEST_QUALIFIED_PRICE",
  biddingStart,
  contingencyPolicy: "CANCEL_AND_REISSUE",
  deadline,
  disclosurePolicy: "WINNER_ONLY_POST_AWARD",
  issuerEpoch: 1,
  requirements: { certificationCode: 9001, experienceMonths: 60, turnoverThreshold: 500000000 },
  revocationPolicy: "DEADLINE_ROOT",
  reviewWindow,
  schemaVersion: 1,
  selectionRule: "LOWEST_QUALIFIED_PRICE",
  tenderId: TENDER_ID_STRING,
  tieBreakRule: "SUBMISSION_SEQUENCE",
  verifierVersion: 1,
});
const expectedRulesHash = keccak256(toUtf8Bytes(ruleDoc));

await (await tr.connect(auth).setRuleDocument(tenderId, toUtf8Bytes(ruleDoc), OPTS)).wait();
check(
  (await tr.recomputeRulesHash(tenderId)) === expectedRulesHash,
  "the CONTRACT recomputed rulesHash from the stored document",
  expectedRulesHash.slice(0, 18),
);

await (await tr.connect(auth).setRuleFields(tenderId, {
  requirements: { turnoverThreshold: 500000000n, experienceMonths: 60, certificationCode: 9001n },
  biddingStart, deadline,
  requiredIssuerId: ISSUER_ID,
  issuerEpoch: 1,
  schemaVersion: 1, verifierVersion: 1,
  disclosurePolicy: 2, awardRule: 1, tieBreakRule: 1, contingencyPolicy: 1,
  reviewWindow,
}, OPTS)).wait();

const members = [1, 2, 3, 4, 5].map((i) => acct(`committee-${i}`).address);
await (await tr.connect(auth).setCommitteeKey(
  tenderId, PX, PY, members,
  DEALT.shares.map((s) => s.publicShare.x),
  DEALT.shares.map((s) => s.publicShare.y),
  DEALT.commitments.map((c) => c.x),
  DEALT.commitments.map((c) => c.y),
  OPTS,
)).wait();
const key = await tr.getCommitteeKey(tenderId);
check(key.set, "3-of-5 committee key set", `t=3 n=5, Y=${key.yX.toString().slice(0, 12)}...`);
check(
  key.yX === PX && key.yY === PY && key.commitmentX[0] === PX,
  "the CONTRACT verified the Feldman dealing (C_0 == Y, every share consistent)",
  "whitepaper Section 6",
);
check(
  isInPrimeSubgroup({ x: key.yX, y: key.yY }),
  "the pinned key is a prime-order subgroup point, so it is safe to encrypt to",
);
check(
  DEALT.shares.every((s) => verifyShare(s, DEALT.commitments)),
  "every member can verify their own share against the published commitments",
  `${DEALT.shares.length} shares`,
);

// A dishonest dealer must be rejected by the live chain, not merely by the
// members. Two valid shares swapped between indices: both points are correct
// shares of the committed polynomial, only their positions are wrong.
{
  const otherId = `${TENDER_ID_STRING}-baddeal-${RUN}`;
  await (await tr.connect(auth).createTender(otherId, OPTS)).wait();
  const bad = keccak256(toUtf8Bytes(otherId));
  const sx = DEALT.shares.map((s) => s.publicShare.x);
  const sy = DEALT.shares.map((s) => s.publicShare.y);
  [sx[0], sx[1]] = [sx[1], sx[0]];
  [sy[0], sy[1]] = [sy[1], sy[0]];
  await expectRevert(
    () => tr.connect(auth).setCommitteeKey.staticCall(
      bad, PX, PY, members, sx, sy,
      DEALT.commitments.map((c) => c.x),
      DEALT.commitments.map((c) => c.y),
      OPTS,
    ),
    "InconsistentFeldmanShare",
    "the live chain rejects a dealing with two members' shares swapped",
  );
}

// =========================================================================
stage("Activation freezes the rules");

await expectRevert(
  () => tr.connect(auth).activateTender.staticCall(tenderId, "0x" + "de".repeat(32), OPTS),
  "RulesHashMismatch",
  "activation with a wrong expected hash is rejected",
);

const actTx = await (await tr.connect(auth).activateTender(tenderId, expectedRulesHash, OPTS)).wait();
const t = await tr.getTender(tenderId);
check((await tr.getState(tenderId)) === State.ACTIVE, "tender ACTIVE", `block ${actTx.blockNumber}`);
check(t.rulesHash === expectedRulesHash, "rulesHash frozen on-chain");
check(
  t.biddingStart >= t.activatedAt + t.reviewWindow,
  "the tender's own review window is enforced",
  `${t.biddingStart - t.activatedAt}s >= ${t.reviewWindow}s`,
);
check(
  t.reviewWindow >= BigInt(dep.minReviewWindow),
  "the tender window respects the council policy floor",
  `${t.reviewWindow}s >= ${dep.minReviewWindow}s`,
);

// =========================================================================
stage("NEGATIVE TEST 2 (whitepaper Table 14): rule edit after activation");

await expectRevert(
  () => tr.connect(auth).setRuleDocument.staticCall(tenderId, toUtf8Bytes("{}"), OPTS),
  "RulesFrozen",
  "the authority cannot edit the rule document after activation",
);
await expectRevert(
  () => tr.connect(auth).setRuleFields.staticCall(tenderId, {
    requirements: { turnoverThreshold: 1n, experienceMonths: 0, certificationCode: 1n },
    biddingStart, deadline,
    requiredIssuerId: ISSUER_ID, issuerEpoch: 1,
    schemaVersion: 1, verifierVersion: 1,
    disclosurePolicy: 2, awardRule: 1, tieBreakRule: 1, contingencyPolicy: 1,
    reviewWindow,
  }, OPTS),
  "RulesFrozen",
  "the authority cannot lower the thresholds after activation",
);
await expectRevert(
  () => tr.connect(c0).setRuleFields.staticCall(tenderId, {
    requirements: { turnoverThreshold: 1n, experienceMonths: 0, certificationCode: 1n },
    biddingStart, deadline,
    requiredIssuerId: ISSUER_ID, issuerEpoch: 1,
    schemaVersion: 1, verifierVersion: 1,
    disclosurePolicy: 2, awardRule: 1, tieBreakRule: 1, contingencyPolicy: 1,
    reviewWindow,
  }, OPTS),
  "NotAuthority",
  "not even the council can edit an active tender (whitepaper Section 14)",
);

// =========================================================================
stage("Bidding window opens only after the review window elapses");

check(!(await tr.isBiddingOpen(tenderId)), "bidding closed during the review window");

const waitFor = Number(t.biddingStart) - (await provider.getBlock("latest")).timestamp + 4;
console.log(`  waiting ${waitFor}s of real chain time for the review window ...`);
await sleep(Math.max(0, waitFor) * 1000);
// Chain time advances with blocks, so poll rather than assume.
for (let i = 0; i < 20 && !(await tr.isBiddingOpen(tenderId)); i++) await sleep(2000);
check(await tr.isBiddingOpen(tenderId), "bidding OPEN after the review window elapsed");

// =========================================================================
stage("NEGATIVE TEST 1 (whitepaper Table 14): close before the deadline");

await expectRevert(
  () => tr.connect(auth).closeTender.staticCall(tenderId, OPTS),
  "DeadlineNotReached",
  "the tender cannot be closed before its deadline",
);

// =========================================================================
stage("Deadline passes; the tender closes and pins the deadline root");

const untilDeadline = Number(t.deadline) - (await provider.getBlock("latest")).timestamp + 4;
console.log(`  waiting ${untilDeadline}s of real chain time for the deadline ...`);
await sleep(Math.max(0, untilDeadline) * 1000);
for (let i = 0; i < 20 && (await tr.isBiddingOpen(tenderId)); i++) await sleep(2000);
check(!(await tr.isBiddingOpen(tenderId)), "bidding window closed at the deadline");

// Permissionless: an outsider closes it, not the authority.
const outsider = Wallet.createRandom().connect(provider);
const closeTx = await (await tr.connect(outsider).closeTender(tenderId, OPTS)).wait();
check((await tr.getState(tenderId)) === State.CLOSED, "tender CLOSED", `block ${closeTx.blockNumber}`);
check(
  true,
  "closing is permissionless, by an unfunded fresh address",
  outsider.address,
);
check(
  (await reg.deadlineRevocationRoot(tenderId)) === REVOCATION_ROOT,
  "deadline revocation root pinned on close (whitepaper Section 5)",
);

// A later revocation must not change the pinned root.
await (await reg.connect(c0).publishRevocationRoot(1, "0x" + "99".repeat(32), OPTS)).wait();
check(
  (await reg.deadlineRevocationRoot(tenderId)) === REVOCATION_ROOT,
  "a later revocation does not alter the pinned deadline root",
);

await expectRevert(
  () => tr.connect(auth).closeTender.staticCall(tenderId, OPTS),
  "NotActive",
  "the tender cannot be closed twice",
);

// =========================================================================
stage("Cross-node agreement: all four validators see the same final state");

for (const v of cfg.validators) {
  try {
    const p = new JsonRpcProvider(`http://127.0.0.1:${v.rpc}`, { chainId: cfg.chainId, name: "fairproof" });
    const deadlineBlock = closeTx.blockNumber;
    for (let i = 0; i < 30 && (await p.getBlockNumber()) < deadlineBlock; i++) await sleep(1000);
    const remote = new Contract(dep.contracts.TenderRegistry, abi("contracts/TenderRegistry.sol/TenderRegistry.json"), p);
    const rh = (await remote.getTender(tenderId)).rulesHash;
    const state = await remote.getState(tenderId);
    check(
      rh === expectedRulesHash && state === State.CLOSED,
      `validator-${v.id} (${v.label}) agrees on rulesHash and state`,
    );
  } catch (err) {
    check(false, `validator-${v.id} readable`, err.message);
  }
}

console.log(
  `\n${failures === 0 ? "END-TO-END LIFECYCLE PASSED" : `${failures} CHECK(S) FAILED`}`,
);
process.exit(failures === 0 ? 0 : 1);
