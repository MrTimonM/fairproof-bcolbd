#!/usr/bin/env node
/**
 * The whole lifecycle on the live network, ending in an opened bid.
 *
 * Development plan Sections 12.6 and 12.7, whitepaper Section 6.
 * Build order step 12.
 *
 * This is the demonstration the plan asks for, with nothing simulated:
 *
 *   a tender created and activated
 *     -> a bid sealed to the committee key and proved at RUN TIME
 *     -> stored on three real replica processes
 *     -> accepted on-chain
 *     -> the deadline passes and the tender CLOSES
 *     -> the ciphertext body published and checked against its commitment
 *     -> share 1/3, then 2/3, with decryption still impossible
 *     -> a FORGED share from member 4, rejected on-chain by its DLEQ proof
 *     -> share 3/3, threshold reached
 *     -> the three shares combined in the exponent, the bid decrypted,
 *        and the amount checked against the on-chain commitment
 *
 * WHY THE PROOF IS GENERATED HERE. The committed fixtures use a deadline in
 * 2096 so they never rot, which is right for unit tests that can fast-forward.
 * A real chain cannot be fast-forwarded, so a fixture tender can never CLOSE
 * and the opening could never be shown against it. This test therefore proves
 * its own witness, for a tender that closes about two minutes from now.
 *
 * Requires: `npm run network:up`, `npm run deploy`, `npm run replicas:start`.
 */
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  JsonRpcProvider, Wallet, Contract, Interface,
  keccak256, toUtf8Bytes, getBytes,
} from "ethers";
import {
  BID_TREE_DEPTH,
  IncrementalMerkleTree,
  bidLeaf,
  combineInExponent,
  dealCommitteeKey,
  decryptionShare,
  initBabyjub,
  initEddsa,
  initPoseidon,
  jcsCanonicalize,
  mulPoint,
  openSealedBid,
  pointsEqual,
  proveDleq,
  sealBid,
  toField,
  uploadToReplicas,
  verifyDealing,
  verifyDleq,
} from "@fairproof/crypto";
import { buildIssuerRegistry, proveEligibility, shutdownProver } from "./lib/prove.mjs";

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
const stage = (t) => console.log(`\n[${++step}] ${t}`);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Errors from every contract in the call path.
 *
 * `submitBid` reverts with errors declared in EligibilityVerifier, and
 * OpeningManager reads TenderRegistry - so decoding with one ABI yields
 * "unknown custom error", which is exactly what a UI watching a single
 * contract would show. Only the error fragments are merged: including the
 * constructors makes ethers warn about duplicate definitions.
 */
const errorAbi = new Interface(
  [
    ...abi("contracts/OpeningManager.sol/OpeningManager.json"),
    ...abi("contracts/SealedBid.sol/SealedBid.json"),
    ...abi("contracts/EligibilityVerifier.sol/EligibilityVerifier.json"),
    ...abi("contracts/TenderRegistry.sol/TenderRegistry.json"),
  ].filter((f) => f.type === "error"),
);
function revertName(err) {
  if (err.revert?.name) return err.revert.name;
  const data = err.data ?? err.info?.error?.data;
  if (typeof data === "string" && data.length >= 10) {
    try {
      return errorAbi.parseError(data)?.name ?? null;
    } catch {
      return null;
    }
  }
  return null;
}
async function expectRevert(fn, errorName, label) {
  try {
    await fn();
    check(false, label, "call succeeded but should have reverted");
  } catch (err) {
    const name = revertName(err);
    check(
      name === errorName,
      label,
      name === errorName
        ? errorName
        : `expected ${errorName}, got ${name || (err.shortMessage || err.message || "").slice(0, 90)}`,
    );
  }
}

const gov = new Contract(dep.contracts.Governance, abi("contracts/Governance.sol/Governance.json"), provider);
const reg = new Contract(dep.contracts.IssuerRegistry, abi("contracts/IssuerRegistry.sol/IssuerRegistry.json"), provider);
const tr = new Contract(dep.contracts.TenderRegistry, abi("contracts/TenderRegistry.sol/TenderRegistry.json"), provider);
const sb = new Contract(dep.contracts.SealedBid, abi("contracts/SealedBid.sol/SealedBid.json"), provider);
const om = new Contract(dep.contracts.OpeningManager, abi("contracts/OpeningManager.sol/OpeningManager.json"), provider);

const State = { NONE: 0n, DRAFT: 1n, ACTIVE: 2n, CLOSED: 3n };

// ---- the scenario, whitepaper Figure 5 -----------------------------------
const RUN = Date.now();
const TENDER = `FP-OPEN-${RUN}`;
const ISSUER_EPOCH = 11n;
const TURNOVER_THRESHOLD = 500000000n; // BDT 50 crore
const EXPERIENCE_THRESHOLD = 60n;      // months
const CERT_CODE = 9001n;
const BID_AMOUNT = 7400000n;           // BDT 74,00,000 - the Figure 5 winner
const SUBJECT_SECRET = 4759208310398234759832475982374598234759823475982347n;
const BID_NONCE = 8823409128340981234098123409812340981234098123409812n;

console.log("FairProof opening ceremony on the live network");
console.log(`chain ${cfg.chainId}, tender ${TENDER}`);
console.log(`OpeningManager ${dep.contracts.OpeningManager}\n`);

await initPoseidon();
await initEddsa();
await initBabyjub();

const council = signer("council-regulator");
const councilTwo = signer("council-procuring-entity");
const councilThree = signer("council-auditor");
const auth = signer("tender-authority");
const committeeSigners = [1, 2, 3, 4, 5].map((i) => signer(`committee-${i}`));
const committeeAddresses = committeeSigners.map((w) => w.address);

// =========================================================================
stage("A short review window, set by the council with a recorded reason");

// The deployment's floor is 300s, which is fine for a real tender and too
// slow for a demonstration. Lowering it is a governance action, not a code
// change: the contract's own hard constant (60s) still binds, so the council
// cannot make the review window vanish.
const floorBefore = await tr.minReviewWindow();
const absoluteMin = await tr.ABSOLUTE_MIN_REVIEW_WINDOW();
if (floorBefore > absoluteMin) {
  await (await tr.connect(council).setMinReviewWindow(
    absoluteMin, `demonstration run ${RUN}: shorten the review window to the hard floor`, OPTS,
  )).wait();
}
check(
  (await tr.minReviewWindow()) === absoluteMin,
  "the council lowered the policy floor to the contract's hard minimum",
  `${absoluteMin}s`,
);
await expectRevert(
  () => tr.connect(council).setMinReviewWindow.staticCall(absoluteMin - 1n, "go lower", OPTS),
  "ReviewWindowBelowMinimum",
  "not even the council can go below the hard constant",
);

// =========================================================================
stage("Issuer registry and a real 3-of-5 committee dealing");

const registry = buildIssuerRegistry(7, 3);
await (await reg.connect(council).publishIssuerRegistryRoot(
  ISSUER_EPOCH, "0x" + registry.root.toString(16).padStart(64, "0"), OPTS,
)).wait();
await (await reg.connect(council).publishRevocationRoot(
  ISSUER_EPOCH, "0x" + registry.revocation.root.toString(16).padStart(64, "0"), OPTS,
)).wait();
check(true, "issuer registry and revocation roots published", `epoch ${ISSUER_EPOCH}`);

// closeTender pins the root of the REGISTRY's current epoch, not the
// tender's, so that one must exist too. The deployment publishes it; this is
// belt and braces so the test does not depend on deployment order.
{
  const current = await reg.currentEpoch();
  if ((await reg.revocationRoot(current)) === "0x" + "00".repeat(32)) {
    await (await reg.connect(council).publishRevocationRoot(
      current, "0x" + registry.revocation.root.toString(16).padStart(64, "0"), OPTS,
    )).wait();
  }
  check(
    (await reg.revocationRoot(current)) !== "0x" + "00".repeat(32),
    "the registry's current epoch has a revocation root, so the tender can close",
    `epoch ${current}`,
  );
}

const dealt = dealCommitteeKey();
const dealing = verifyDealing(dealt);
check(dealing.ok, "the committee dealing passes every check locally", dealing.problems.join("; "));

// =========================================================================
stage("A tender that closes about two minutes from now");

const reviewWindow = absoluteMin;
// Slack matters. The setup below is several transactions at two seconds a
// block, and `activateTender` re-checks the review window against the
// timestamp AT ACTIVATION - so a tight margin fails with
// ReviewWindowTooShort, which reads like a policy error rather than a slow
// test. 120s is comfortable and still short enough to demonstrate.
const now = BigInt((await provider.getBlock("latest")).timestamp);
const biddingStart = now + reviewWindow + 120n;
const deadline = biddingStart + 45n;

const ruleDoc = jcsCanonicalize({
  awardRule: "LOWEST_QUALIFIED_PRICE",
  biddingStart: Number(biddingStart),
  contingencyPolicy: "CANCEL_AND_REISSUE",
  deadline: Number(deadline),
  disclosurePolicy: "WINNER_ONLY_POST_AWARD",
  issuerEpoch: Number(ISSUER_EPOCH),
  requirements: {
    certificationCode: Number(CERT_CODE),
    experienceMonths: Number(EXPERIENCE_THRESHOLD),
    turnoverThreshold: Number(TURNOVER_THRESHOLD),
  },
  revocationPolicy: "DEADLINE_ROOT",
  reviewWindow: Number(reviewWindow),
  schemaVersion: 1,
  selectionRule: "LOWEST_QUALIFIED_PRICE",
  tenderId: TENDER,
  tieBreakRule: "SUBMISSION_SEQUENCE",
  verifierVersion: 1,
});
const rulesHash = keccak256(toUtf8Bytes(ruleDoc));
const tenderId = keccak256(toUtf8Bytes(TENDER));

if (!(await tr.isTenderAuthority(auth.address))) {
  await (await tr.connect(council).setTenderAuthority(auth.address, true, OPTS)).wait();
}
await (await tr.connect(auth).createTender(TENDER, OPTS)).wait();
await (await tr.connect(auth).setRuleDocument(tenderId, toUtf8Bytes(ruleDoc), OPTS)).wait();
check(
  (await tr.recomputeRulesHash(tenderId)) === rulesHash,
  "the CONTRACT recomputed rulesHash from the stored document",
  rulesHash.slice(0, 18),
);
await (await tr.connect(auth).setRuleFields(tenderId, {
  requirements: {
    turnoverThreshold: TURNOVER_THRESHOLD,
    experienceMonths: Number(EXPERIENCE_THRESHOLD),
    certificationCode: CERT_CODE,
  },
  biddingStart, deadline,
  requiredIssuerId: keccak256(toUtf8Bytes(`ICAB-AUDIT-${RUN}`)),
  issuerEpoch: ISSUER_EPOCH,
  schemaVersion: 1, verifierVersion: 1,
  disclosurePolicy: 2, awardRule: 1, tieBreakRule: 1, contingencyPolicy: 1,
  reviewWindow,
}, OPTS)).wait();
await (await tr.connect(auth).setCommitteeKey(
  tenderId, dealt.publicKey.x, dealt.publicKey.y, committeeAddresses,
  dealt.shares.map((s) => s.publicShare.x),
  dealt.shares.map((s) => s.publicShare.y),
  dealt.commitments.map((c) => c.x),
  dealt.commitments.map((c) => c.y),
  OPTS,
)).wait();
check(true, "the CONTRACT verified the Feldman dealing at setCommitteeKey");
await (await tr.connect(auth).activateTender(tenderId, rulesHash, OPTS)).wait();
check((await tr.getState(tenderId)) === State.ACTIVE, "tender ACTIVE, rules frozen");

// =========================================================================
stage("The bidder proves eligibility at run time, and seals the bid");

console.log("  ..    generating a Groth16 proof (tens of seconds) ...");
const t0 = Date.now();
const proved = await proveEligibility({
  registry,
  tenderIdString: TENDER,
  rulesHash,
  turnoverThreshold: TURNOVER_THRESHOLD,
  experienceMonthsThreshold: EXPERIENCE_THRESHOLD,
  requiredCertificationCode: CERT_CODE,
  deadline,
  credentialEpoch: ISSUER_EPOCH,
  subjectSecret: SUBJECT_SECRET,
  bidAmount: BID_AMOUNT,
  bidNonce: BID_NONCE,
  credentialId: 2042n,
  annualTurnover: 620000000n,
  relevantExperience: 72n,
  validUntil: deadline + 31536000n,
  issuedAt: now - 86400n,
});
check(true, "proof generated and verified off-chain", `${((Date.now() - t0) / 1000).toFixed(1)}s`);

const sealed = await sealBid({
  payload: {
    tenderId: TENDER,
    amountMinorUnit: BID_AMOUNT.toString(),
    currency: "BDT",
    bidNonce: BID_NONCE.toString(),
    subjectCommitment: proved.witness.bidCommitment.toString(),
    createdAt: new Date().toISOString(),
  },
  tenderPublicKey: dealt.publicKey,
  tenderIdField: proved.witness.tenderIdField,
  nullifier: proved.witness.nullifier,
});
check(
  sealed.bidCommitment === proved.publicSignals[11],
  "the sealed bid's commitment IS the proof's public signal 11",
  "so it can only open to the value the proof commits to",
);

const endpoints = JSON.parse(
  execFileSync(process.execPath, [join(repoRoot, "scripts/replica-control.mjs"), "endpoints"], {
    encoding: "utf8", cwd: repoRoot,
  }),
);
const upload = await uploadToReplicas(endpoints, sealed.canonicalBytes, sealed.ciphertextHash);
check(upload.quorumMet, "stored on the replicas", `${upload.receipts.length}/3 acknowledged`);

// =========================================================================
stage("The bid is accepted once the review window elapses");

await expectRevert(
  () =>
    sb.connect(auth).submitBid.staticCall(
      { tenderId, nullifier: proved.publicSignals[10], bidCommitment: proved.publicSignals[11], ciphertextHash: sealed.ciphertextHash },
      upload.receipts.map((r) => ({ replicaId: r.replicaId, contentHash: r.contentHash, byteLength: BigInt(r.byteLength), signature: r.signature })),
      proved.pA, proved.pB, proved.pC, OPTS,
    ),
  "BiddingNotOpen",
  "a bid during the public review window is refused",
);

{
  const t = await tr.getTender(tenderId);
  const nowTs = BigInt((await provider.getBlock("latest")).timestamp);
  console.log(`  ..    waiting ${t.biddingStart - nowTs}s of real chain time for the review window ...`);
  while (!(await tr.isBiddingOpen(tenderId))) await sleep(3000);
}
check(await tr.isBiddingOpen(tenderId), "bidding OPEN");

const anonymous = Wallet.createRandom().connect(provider);
const receiptArgs = upload.receipts.map((r) => ({
  replicaId: r.replicaId, contentHash: r.contentHash,
  byteLength: BigInt(r.byteLength), signature: r.signature,
}));
const submission = {
  tenderId,
  nullifier: proved.publicSignals[10],
  bidCommitment: proved.publicSignals[11],
  ciphertextHash: sealed.ciphertextHash,
};
{
  const gas = await sb.connect(anonymous).submitBid.estimateGas(
    submission, receiptArgs, proved.pA, proved.pB, proved.pC, OPTS,
  );
  const rcpt = await (await sb.connect(anonymous).submitBid(
    submission, receiptArgs, proved.pA, proved.pB, proved.pC,
    { ...OPTS, gasLimit: gas * 2n },
  )).wait();
  check(rcpt.status === 1, "bid ACCEPTED, submitted by an unfunded fresh address", `${rcpt.gasUsed.toLocaleString()} gas`);
}
check((await sb.submissionCount(tenderId)) === 1n, "one accepted bid");

// The contract's accumulator, rebuilt independently.
{
  const tree = new IncrementalMerkleTree(BID_TREE_DEPTH);
  for (const leaf of await sb.getLeaves(tenderId)) tree.insert(leaf);
  check(
    tree.root() === (await sb.bidSetRoot(tenderId)),
    "bidSetRoot is reproducible in TypeScript from the accepted leaves",
  );
}

// =========================================================================
stage("Nothing opens before the deadline");

await expectRevert(
  () => om.connect(committeeSigners[0]).revealCiphertext.staticCall(
    tenderId, 0, sealed.canonicalBytes, OPTS,
  ),
  "TenderNotClosed",
  "the ciphertext cannot be revealed while bidding is open",
);

{
  const t = await tr.getTender(tenderId);
  const nowTs = BigInt((await provider.getBlock("latest")).timestamp);
  console.log(`  ..    waiting ${t.deadline > nowTs ? t.deadline - nowTs : 0n}s of real chain time for the deadline ...`);
  while (await tr.isBiddingOpen(tenderId)) await sleep(3000);
}
// Permissionless close, by yet another unfunded address.
const closer = Wallet.createRandom().connect(provider);
await (await tr.connect(closer).closeTender(tenderId, OPTS)).wait();
check((await tr.getState(tenderId)) === State.CLOSED, "tender CLOSED, permissionlessly", closer.address);

// =========================================================================
stage("The ciphertext body is published and checked against its commitment");

await expectRevert(
  () => om.connect(closer).revealCiphertext.staticCall(
    tenderId, 0, sealed.canonicalBytes.slice(0, -1), OPTS,
  ),
  "CiphertextHashMismatch",
  "bytes that do not hash to the committed ciphertextHash are refused",
);

{
  const gas = await om.connect(closer).revealCiphertext.estimateGas(
    tenderId, 0, sealed.canonicalBytes, OPTS,
  );
  await (await om.connect(closer).revealCiphertext(
    tenderId, 0, sealed.canonicalBytes, { ...OPTS, gasLimit: gas * 2n },
  )).wait();
  check(true, "ciphertext published on-chain", `${gas.toLocaleString()} gas`);
}
const published = await om.getCiphertext(tenderId, 0);
check(
  published.rX === sealed.ciphertext.rX && published.rY === sealed.ciphertext.rY,
  "the contract extracted the ElGamal ephemeral point from the canonical bytes",
);

// =========================================================================
stage("1 of 3, then 2 of 3, and decryption is still impossible");

const R = { x: sealed.ciphertext.rX, y: sealed.ciphertext.rY };

/** One member's honest share and its Chaum-Pedersen proof. */
function shareFor(i) {
  const s = dealt.shares[i - 1];
  const D = decryptionShare(s.share, R);
  const proof = proveDleq({ secret: s.share, ephemeral: R });
  if (!verifyDleq({ publicShare: s.publicShare, ephemeral: R, decryptionShare: D, proof })) {
    throw new Error(`member ${i}'s own proof does not verify`);
  }
  return { D, proof };
}

async function submitShare(i) {
  const { D, proof } = shareFor(i);
  const args = [
    tenderId, 0, i, D.x, D.y,
    { aX: proof.a.x, aY: proof.a.y, bX: proof.b.x, bY: proof.b.y, z: proof.z },
  ];
  const gas = await om.connect(committeeSigners[i - 1]).submitDecryptionShare.estimateGas(...args, OPTS);
  const rcpt = await (await om.connect(committeeSigners[i - 1]).submitDecryptionShare(
    ...args, { ...OPTS, gasLimit: gas * 2n },
  )).wait();
  return rcpt;
}

{
  const rcpt = await submitShare(1);
  const [, accepted, threshold, ready] = await om.openingStatus(tenderId, 0);
  check(accepted === 1n && threshold === 3n && !ready, "1/3 - the bid cannot be decrypted", `${rcpt.gasUsed.toLocaleString()} gas per share`);
}
{
  await submitShare(2);
  const [, accepted, , ready] = await om.openingStatus(tenderId, 0);
  check(accepted === 2n && !ready, "2/3 - STILL cannot be decrypted", "this is what distinguishes a real threshold");
}

// =========================================================================
stage("A forged share from member 4 is rejected on-chain and attributed");

{
  // A valid curve point, with member 4's honest proof attached. Without the
  // DLEQ check this would be accepted, the combination would produce garbage,
  // and the failure would surface as an AES tag error blamed on the bidder.
  const honest = dealt.shares[3];
  const forged = mulPoint(R, honest.share + 1n);
  const { proof } = shareFor(4);
  await expectRevert(
    () =>
      om.connect(committeeSigners[3]).submitDecryptionShare.staticCall(
        tenderId, 0, 4, forged.x, forged.y,
        { aX: proof.a.x, aY: proof.a.y, bX: proof.b.x, bY: proof.b.y, z: proof.z },
        OPTS,
      ),
    "DleqProofInvalid",
    "the forged share is rejected, naming member 4",
  );
  check(
    (await om.shareCount(tenderId, 0)) === 2n,
    "the rejected share was not counted",
    "so a bad share can never be tallied later",
  );
}

// A member cannot submit somebody else's share either.
{
  const { D, proof } = shareFor(3);
  await expectRevert(
    () =>
      om.connect(committeeSigners[4]).submitDecryptionShare.staticCall(
        tenderId, 0, 3, D.x, D.y,
        { aX: proof.a.x, aY: proof.a.y, bX: proof.b.x, bY: proof.b.y, z: proof.z },
        OPTS,
      ),
    "NotThisCommitteeMember",
    "member 5 cannot publish member 3's share",
  );
}

// =========================================================================
stage("3 of 3, and the bid is opened");

await submitShare(3);
{
  const [, accepted, , ready] = await om.openingStatus(tenderId, 0);
  check(accepted === 3n && ready, "3/3 - the threshold is reached");
}
await expectRevert(
  () => {
    const { D, proof } = shareFor(3);
    return om.connect(committeeSigners[2]).submitDecryptionShare.staticCall(
      tenderId, 0, 3, D.x, D.y,
      { aX: proof.a.x, aY: proof.a.y, bX: proof.b.x, bY: proof.b.y, z: proof.z },
      OPTS,
    );
  },
  "ShareAlreadySubmitted",
  "a duplicate share from the same member is refused",
);

// Read the shares back FROM THE CHAIN and combine them. Nobody reconstructs
// the tender secret: the interpolation happens in the exponent.
const onChainShares = await om.getShares(tenderId, 0);
check(onChainShares.length === 3, "three shares published on-chain for anyone to combine");
const shared = combineInExponent(
  onChainShares.map((s) => ({
    index: Number(s.memberIndex),
    point: { x: s.dX, y: s.dY },
  })),
);
check(
  pointsEqual(shared, mulPoint(R, dealt.secret)),
  "the three on-chain shares interpolate to x*R, without the secret existing anywhere",
);

// Fetch the ciphertext back from the chain's own record and decrypt it.
const bid = await sb.getBid(tenderId, 0n);
const opened = await openSealedBid({
  ciphertext: sealed.ciphertext,
  shared,
  expectedCommitment: bid.bidCommitment,
  tenderIdField: proved.witness.tenderIdField,
  nullifier: proved.witness.nullifier,
});
check(opened.bidAmount === BID_AMOUNT, "the bid OPENS to BDT 74,00,000", opened.bidAmount.toString());
check(opened.bidNonce === BID_NONCE, "the nonce matches, so the commitment is reproduced exactly");
check(
  bidLeaf({
    nullifier: bid.nullifier,
    bidCommitment: bid.bidCommitment,
    ciphertextHashField: toField(bid.ciphertextHash),
    submissionIndex: BigInt(bid.submissionIndex),
  }) === bid.leaf,
  "the opened bid's leaf is the one in the accumulator",
);

// Two of the three shares must NOT be enough, even now that all three exist.
{
  const twoOnly = combineInExponent(
    onChainShares.slice(0, 2).map((s) => ({
      index: Number(s.memberIndex),
      point: { x: s.dX, y: s.dY },
    })),
  );
  let refused = false;
  try {
    await openSealedBid({
      ciphertext: sealed.ciphertext,
      shared: twoOnly,
      expectedCommitment: bid.bidCommitment,
      tenderIdField: proved.witness.tenderIdField,
      nullifier: proved.witness.nullifier,
    });
  } catch (err) {
    refused = /authentication failed/.test(err.message);
  }
  check(refused, "two of the three shares still cannot decrypt the bid", "AES-GCM rejects the key");
}

// =========================================================================
stage("Cross-node agreement on the opening");

const roles = ["Procurement Regulator", "Procuring Entity", "Independent Auditor", "Chamber of Commerce"];
for (let i = 0; i < cfg.validators.length; i++) {
  const p = new JsonRpcProvider(`http://127.0.0.1:${cfg.validators[i].rpc}`, {
    chainId: cfg.chainId, name: "fairproof",
  });
  const omN = new Contract(dep.contracts.OpeningManager, abi("contracts/OpeningManager.sol/OpeningManager.json"), p);
  const [revealed, accepted, , ready] = await omN.openingStatus(tenderId, 0);
  check(
    revealed && accepted === 3n && ready,
    `validator-${i + 1} (${roles[i]}) agrees the threshold was reached with 3 shares`,
  );
  p.destroy();
}

console.log(
  failures === 0
    ? "\nOPENING CEREMONY COMPLETE - THE BID WAS OPENED BY 3 OF 5"
    : `\n${failures} CHECK(S) FAILED`,
);
provider.destroy();
await shutdownProver();
process.exit(failures === 0 ? 0 : 1);
