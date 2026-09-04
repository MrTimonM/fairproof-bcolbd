#!/usr/bin/env node
/**
 * Drive one complete tender through every stage, on the live network.
 *
 * This is both the demo script (plan Section 25.3) and the dashboard's data.
 * It is deliberately the same code path an operator would use - there is no
 * privileged shortcut, no pre-baked state, and no fixture standing in for a
 * proof. Every proof here is generated at run time for a tender created at
 * run time, because the committed fixtures use a deadline in 2096 so they
 * never rot, and a real chain cannot be fast-forwarded to it.
 *
 * Roughly four minutes, most of it real chain time waiting out the mandatory
 * public review window and the deadline. That waiting is the point: the
 * contract will not open bidding early, and nobody can make it.
 *
 *   npm run seed
 *
 * Requires: npm run network:up, npm run deploy, npm run replicas:start
 */
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Contract, JsonRpcProvider, Wallet, keccak256, toUtf8Bytes } from "ethers";
import {
  DISCLOSE_WINNING_PRICE,
  combineInExponent,
  dealCommitteeKey,
  decryptionShare,
  initBabyjub,
  initEddsa,
  initPoseidon,
  jcsCanonicalize,
  openSealedBid,
  revocationTreeWith,
  proveDleq,
  sealBid,
  toField,
  uploadToReplicas,
  verifyDealing,
  verifyDleq,
} from "@fairproof/crypto";
import {
  buildIssuerRegistry,
  issueCredential,
  proveAward,
  proveEligibility,
  proveWinnerIdentity,
  shutdownProver,
} from "../tests/integration/lib/prove.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "..");
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
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let step = 0;
const stage = (t) => console.log(`\n\x1b[1m[${++step}] ${t}\x1b[0m`);
const done = (t, detail = "") =>
  console.log(`  ✓ ${t}${detail ? `  \x1b[2m${detail}\x1b[0m` : ""}`);
const note = (t) => console.log(`  · \x1b[2m${t}\x1b[0m`);

/** Send with an estimated limit; a bare send can underestimate a pairing check. */
async function send(fn, ...args) {
  const gas = await fn.estimateGas(...args, OPTS);
  const tx = await fn(...args, { ...OPTS, gasLimit: (gas * 3n) / 2n });
  const receipt = await tx.wait();
  return { receipt, gas: receipt.gasUsed };
}

const gov = new Contract(dep.contracts.Governance, abi("contracts/Governance.sol/Governance.json"), provider);
const reg = new Contract(dep.contracts.IssuerRegistry, abi("contracts/IssuerRegistry.sol/IssuerRegistry.json"), provider);
const tr = new Contract(dep.contracts.TenderRegistry, abi("contracts/TenderRegistry.sol/TenderRegistry.json"), provider);
const sb = new Contract(dep.contracts.SealedBid, abi("contracts/SealedBid.sol/SealedBid.json"), provider);
const om = new Contract(dep.contracts.OpeningManager, abi("contracts/OpeningManager.sol/OpeningManager.json"), provider);
const ds = new Contract(dep.contracts.DeadlineStatus, abi("contracts/DeadlineStatus.sol/DeadlineStatus.json"), provider);
const am = new Contract(dep.contracts.AwardManager, abi("contracts/AwardManager.sol/AwardManager.json"), provider);
const wi = new Contract(dep.contracts.WinnerIdentity, abi("contracts/WinnerIdentity.sol/WinnerIdentity.json"), provider);

// --- the scenario: whitepaper Figure 5 ------------------------------------
const RUN = Date.now();
const TENDER = `FP-00014-${new Date().toISOString().slice(0, 10)}-${String(RUN).slice(-4)}`;
const ISSUER_EPOCH = 21n;
const TURNOVER_THRESHOLD = 500000000n; // BDT 50 crore
const EXPERIENCE_THRESHOLD = 60n;
const CERT_CODE = 9001n;

/**
 * Two bidders. Bidder A is cheaper and wins.
 *
 * The identity records are SYNTHETIC. No real company's registration, trade
 * licence or VAT/BIN appears anywhere in this repository.
 */
const BIDDERS = [
  {
    key: "A",
    subjectSecret: 4759208310398234759832475982374598234759823475982347n,
    bidAmount: 7400000n,
    bidNonce: 8823409128340981234098123409812340981234098123409812n,
    credentialId: 1042n,
    annualTurnover: 620000000n,
    relevantExperience: 72n,
    identityRecord: {
      credentialId: 1042,
      legalName: "Padma Infrastructure Limited",
      registrationNumber: "C-118342/2019",
      tradeLicence: "DSCC/TL/2019/44821",
      vatBin: "004417029-0102",
    },
  },
  {
    key: "B",
    subjectSecret: 1193847562938475629384756293847562938475629384756293n,
    bidAmount: 8150000n,
    bidNonce: 5567788990011223344556677889900112233445566778899001n,
    credentialId: 1043n,
    annualTurnover: 540000000n,
    relevantExperience: 63n,
    identityRecord: {
      credentialId: 1043,
      legalName: "Jamuna Civil Works Limited",
      registrationNumber: "C-127905/2020",
      tradeLicence: "DSCC/TL/2020/51037",
      vatBin: "005182773-0203",
    },
  },
];

console.log("\x1b[1mFairProof — full lifecycle on the live network\x1b[0m");
console.log(`chain ${cfg.chainId} · tender ${TENDER}\n`);

await initPoseidon();
await initEddsa();
await initBabyjub();

const council = signer("council-regulator");
const councilTwo = signer("council-procuring-entity");
const councilThree = signer("council-auditor");
const auth = signer("tender-authority");
const committeeSigners = [1, 2, 3, 4, 5].map((i) => signer(`committee-${i}`));

// =========================================================================
stage("The council registers a qualification issuer");

const registry = buildIssuerRegistry(7, 3);
const ISSUER_ID = keccak256(toUtf8Bytes(`ICAB-AUDIT-FIRM-${RUN}`));
await send(
  reg.connect(council).registerIssuer,
  ISSUER_ID,
  registry.issuerKey.x,
  registry.issuerKey.y,
  1,
  "ICAB Registered Audit Firm",
);
done("issuer registered", "3-of-4 council, reason recorded on-chain");

await send(
  reg.connect(council).publishIssuerRegistryRoot,
  ISSUER_EPOCH,
  "0x" + registry.root.toString(16).padStart(64, "0"),
);
await send(
  reg.connect(council).publishRevocationRoot,
  ISSUER_EPOCH,
  "0x" + registry.revocation.root.toString(16).padStart(64, "0"),
);
done("registry and revocation roots published", `epoch ${ISSUER_EPOCH}`);

// The deadline root comes from the registry's CURRENT epoch at close, so it
// must exist or closeTender reverts and the tender becomes unclosable.
{
  const current = await reg.currentEpoch();
  if ((await reg.revocationRoot(current)) === "0x" + "00".repeat(32)) {
    await send(
      reg.connect(council).publishRevocationRoot,
      current,
      "0x" + registry.revocation.root.toString(16).padStart(64, "0"),
    );
  }
  done("the registry's current epoch has a revocation root", `epoch ${current}`);
}

// =========================================================================
stage("A short review window, by governance rather than by code change");

const absoluteMin = await tr.ABSOLUTE_MIN_REVIEW_WINDOW();
if ((await tr.minReviewWindow()) > absoluteMin) {
  await send(
    tr.connect(council).setMinReviewWindow,
    absoluteMin,
    `demonstration run ${RUN}: shorten the review window to the contract's hard floor`,
  );
}
done(
  "policy floor lowered to the hard constant",
  `${absoluteMin}s — no proposal can go below it`,
);

// =========================================================================
stage("The opening committee key is dealt with Feldman VSS");

const dealt = dealCommitteeKey();
const dealing = verifyDealing(dealt);
if (!dealing.ok) throw new Error(`dealing failed: ${dealing.problems.join("; ")}`);
done("3-of-5 key dealt and verified locally", "every share matches the commitments");
note("the dealer knows the tender secret while this runs, then discards it —");
note("production requires DKG (whitepaper Section 19.1)");

// =========================================================================
stage("The authority publishes the tender and freezes its rules");

const reviewWindow = absoluteMin;
const now = BigInt((await provider.getBlock("latest")).timestamp);
const biddingStart = now + reviewWindow + 120n;
const deadline = biddingStart + 60n;

const ruleDoc = jcsCanonicalize({
  awardRule: "LOWEST_QUALIFIED_PRICE",
  biddingStart: Number(biddingStart),
  contingencyPolicy: "CANCEL_AND_REISSUE",
  deadline: Number(deadline),
  disclosurePolicy: "PUBLISH_WINNING_PRICE",
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
  await send(tr.connect(council).setTenderAuthority, auth.address, true);
}
await send(tr.connect(auth).createTender, TENDER);
await send(tr.connect(auth).setRuleDocument, tenderId, toUtf8Bytes(ruleDoc));
if ((await tr.recomputeRulesHash(tenderId)) !== rulesHash) {
  throw new Error("the contract's recomputed rulesHash does not match");
}
done("the CONTRACT recomputed rulesHash from the document it stores", rulesHash.slice(0, 20));

await send(tr.connect(auth).setRuleFields, tenderId, {
  requirements: {
    turnoverThreshold: TURNOVER_THRESHOLD,
    experienceMonths: Number(EXPERIENCE_THRESHOLD),
    certificationCode: CERT_CODE,
  },
  biddingStart,
  deadline,
  requiredIssuerId: ISSUER_ID,
  issuerEpoch: ISSUER_EPOCH,
  schemaVersion: 1,
  verifierVersion: 1,
  disclosurePolicy: DISCLOSE_WINNING_PRICE,
  awardRule: 1,
  tieBreakRule: 1,
  contingencyPolicy: 1,
  reviewWindow,
});
await send(
  tr.connect(auth).setCommitteeKey,
  tenderId,
  dealt.publicKey.x,
  dealt.publicKey.y,
  committeeSigners.map((w) => w.address),
  dealt.shares.map((s) => s.publicShare.x),
  dealt.shares.map((s) => s.publicShare.y),
  dealt.commitments.map((c) => c.x),
  dealt.commitments.map((c) => c.y),
);
done("the CONTRACT verified the Feldman dealing", "C_0 == Y, every share consistent");

await send(tr.connect(auth).activateTender, tenderId, rulesHash);
done("tender ACTIVE — every rule now frozen", `review window ${reviewWindow}s`);

// =========================================================================
stage("Each bidder proves eligibility and seals a bid");

const endpoints = JSON.parse(
  execFileSync(process.execPath, [join(repoRoot, "scripts/replica-control.mjs"), "endpoints"], {
    encoding: "utf8",
    cwd: repoRoot,
  }),
);

for (const b of BIDDERS) {
  const t0 = Date.now();
  b.credential = issueCredential(registry, {
    ...b,
    certificationCode: CERT_CODE,
    credentialEpoch: ISSUER_EPOCH,
    validUntil: deadline + 31536000n,
    issuedAt: now - 86400n,
  });
  b.proof = await proveEligibility({
    registry,
    tenderIdString: TENDER,
    rulesHash,
    turnoverThreshold: TURNOVER_THRESHOLD,
    experienceMonthsThreshold: EXPERIENCE_THRESHOLD,
    requiredCertificationCode: CERT_CODE,
    deadline,
    credentialEpoch: ISSUER_EPOCH,
    subjectSecret: b.subjectSecret,
    bidAmount: b.bidAmount,
    bidNonce: b.bidNonce,
    credentialId: b.credentialId,
    annualTurnover: b.annualTurnover,
    relevantExperience: b.relevantExperience,
    validUntil: deadline + 31536000n,
    issuedAt: now - 86400n,
  });
  done(
    `bidder ${b.key}: eligibility proved`,
    `${((Date.now() - t0) / 1000).toFixed(1)}s, nothing about the firm disclosed`,
  );

  b.sealed = await sealBid({
    payload: {
      tenderId: TENDER,
      amountMinorUnit: b.bidAmount.toString(),
      currency: "BDT",
      bidNonce: b.bidNonce.toString(),
      subjectCommitment: b.proof.witness.bidCommitment.toString(),
      createdAt: new Date().toISOString(),
    },
    tenderPublicKey: dealt.publicKey,
    tenderIdField: b.proof.witness.tenderIdField,
    nullifier: b.proof.witness.nullifier,
  });
  if (b.sealed.bidCommitment !== b.proof.publicSignals[11]) {
    throw new Error(`bidder ${b.key}: the sealed bid and the proof disagree`);
  }

  b.upload = await uploadToReplicas(
    endpoints,
    b.sealed.canonicalBytes,
    b.sealed.ciphertextHash,
  );
  done(
    `bidder ${b.key}: bid sealed and stored`,
    `${b.upload.receipts.length}/3 replicas acknowledged`,
  );
}

// =========================================================================
stage("The mandatory public review window runs its course");

{
  const t = await tr.getTender(tenderId);
  const nowTs = BigInt((await provider.getBlock("latest")).timestamp);
  note(`waiting ${t.biddingStart - nowTs}s of real chain time — the contract refuses bids until then`);
  while (!(await tr.isBiddingOpen(tenderId))) await sleep(3000);
}
done("bidding OPEN");

// =========================================================================
stage("The bids are submitted from unfunded addresses");

for (const [i, b] of BIDDERS.entries()) {
  const anonymous = Wallet.createRandom().connect(provider);
  const balance = await provider.getBalance(anonymous.address);
  const { gas } = await send(
    sb.connect(anonymous).submitBid,
    {
      tenderId,
      nullifier: b.proof.publicSignals[10],
      bidCommitment: b.proof.publicSignals[11],
      ciphertextHash: b.sealed.ciphertextHash,
    },
    b.upload.receipts.map((r) => ({
      replicaId: r.replicaId,
      contentHash: r.contentHash,
      byteLength: BigInt(r.byteLength),
      signature: r.signature,
    })),
    b.proof.pA,
    b.proof.pB,
    b.proof.pC,
  );
  b.index = i;
  done(
    `bidder ${b.key} accepted as submission #${i}`,
    `${gas.toLocaleString()} gas, from a ${balance}-balance address`,
  );
}
done("bidSetRoot accumulated by the CONTRACT", (await sb.bidSetRoot(tenderId)).toString().slice(0, 22) + "…");

// =========================================================================
stage("A third firm's credential is revoked, then the tender closes");

/**
 * Revoke a credential that belongs to NEITHER bidder, before the close.
 *
 * This is what makes the close-time status check meaningful. If the deadline
 * root equalled the submission-time root, the original eligibility proof would
 * double as a status proof and the check would pass vacuously - the verifier
 * says so explicitly when it happens, which is how this gap was noticed.
 *
 * Both bidders stay unrevoked, so both can still prove status; the tree they
 * prove against is genuinely a different one.
 */
const deadlineTree = revocationTreeWith(9999n);
await send(
  reg.connect(council).publishRevocationRoot,
  await reg.currentEpoch(),
  "0x" + deadlineTree.root.toString(16).padStart(64, "0"),
);
done(
  "credential 9999 revoked in the current epoch",
  "so the deadline root differs from the one bids were checked against",
);

{
  note("waiting for the deadline — nothing can be opened before it");
  while (await tr.isBiddingOpen(tenderId)) await sleep(3000);
}
const closer = Wallet.createRandom().connect(provider);
await send(tr.connect(closer).closeTender, tenderId);
done("tender CLOSED, permissionlessly", "so nobody can hold it open to delay an opening");
done("deadline revocation root pinned one-shot", (await reg.deadlineRevocationRoot(tenderId)).slice(0, 20));

// =========================================================================
stage("The committee opens each bid — three of five, one share at a time");

for (const b of BIDDERS) {
  await send(om.connect(closer).revealCiphertext, tenderId, b.index, b.sealed.canonicalBytes);
  done(`bid #${b.index}: ciphertext published and hash-checked on-chain`);

  const R = { x: b.sealed.ciphertext.rX, y: b.sealed.ciphertext.rY };
  for (const memberIndex of [1, 2, 3]) {
    const share = dealt.shares[memberIndex - 1];
    const D = decryptionShare(share.share, R);
    const proof = proveDleq({ secret: share.share, ephemeral: R });
    if (!verifyDleq({ publicShare: share.publicShare, ephemeral: R, decryptionShare: D, proof })) {
      throw new Error(`member ${memberIndex}'s own proof does not verify`);
    }
    const { gas } = await send(
      om.connect(committeeSigners[memberIndex - 1]).submitDecryptionShare,
      tenderId, b.index, memberIndex, D.x, D.y,
      { aX: proof.a.x, aY: proof.a.y, bX: proof.b.x, bY: proof.b.y, z: proof.z },
    );
    const [, accepted, threshold, ready] = await om.openingStatus(tenderId, b.index);
    done(
      `bid #${b.index}: share ${accepted}/${threshold} accepted from member ${memberIndex}`,
      ready ? `threshold reached, ${gas.toLocaleString()} gas` : "still sealed",
    );
  }

  // Combine in the exponent and open. The tender secret is never reassembled.
  const shares = await om.getShares(tenderId, b.index);
  const shared = combineInExponent(
    shares.map((s) => ({ index: Number(s.memberIndex), point: { x: s.dX, y: s.dY } })),
  );
  const bid = await sb.getBid(tenderId, b.index);
  const opened = await openSealedBid({
    ciphertext: b.sealed.ciphertext,
    shared,
    expectedCommitment: bid.bidCommitment,
    tenderIdField: b.proof.witness.tenderIdField,
    nullifier: b.proof.witness.nullifier,
  });
  b.openedAmount = opened.bidAmount;
  done(`bid #${b.index} OPENED`, `BDT ${opened.bidAmount.toLocaleString()}`);
}

// =========================================================================
stage("Each bidder re-proves eligibility against the pinned deadline root");

const deadlineRoot = await reg.deadlineRevocationRoot(tenderId);
if (BigInt(deadlineRoot) !== deadlineTree.root) {
  throw new Error(
    `the pinned deadline root ${deadlineRoot} is not the tree we published. ` +
      `The close happened before the revocation landed.`,
  );
}
note("the pinned root is the post-revocation tree, so this check is not vacuous");
for (const b of BIDDERS) {
  // The same statement, re-evaluated against the PINNED deadline root, with
  // this credential's sibling path in that tree. A zero leaf at its position
  // is what proves non-revocation.
  const statusProof = await proveEligibility({
    registry: {
      ...registry,
      revocation: {
        root: deadlineTree.root,
        siblings: deadlineTree.siblingsFor(b.credentialId),
      },
    },
    tenderIdString: TENDER,
    rulesHash,
    turnoverThreshold: TURNOVER_THRESHOLD,
    experienceMonthsThreshold: EXPERIENCE_THRESHOLD,
    requiredCertificationCode: CERT_CODE,
    deadline,
    credentialEpoch: ISSUER_EPOCH,
    subjectSecret: b.subjectSecret,
    bidAmount: b.bidAmount,
    bidNonce: b.bidNonce,
    credentialId: b.credentialId,
    annualTurnover: b.annualTurnover,
    relevantExperience: b.relevantExperience,
    validUntil: deadline + 31536000n,
    issuedAt: now - 86400n,
  });
  await send(
    ds.connect(closer).submitStatusProof,
    tenderId, b.index, statusProof.pA, statusProof.pB, statusProof.pC,
  );
  done(`bidder ${b.key}: unrevoked at the deadline`, "not inferred from an older snapshot");
}

// =========================================================================
stage("The authority proves the award over the COMPLETE bid set");

const openedBids = BIDDERS.map((b) => ({
  submissionIndex: b.index,
  nullifier: b.proof.witness.nullifier,
  bidAmount: b.openedAmount,
  bidNonce: b.bidNonce,
  ciphertextHashField: toField(b.sealed.ciphertextHash),
}));
const chainRoot = await sb.bidSetRoot(tenderId);
const award = await proveAward({
  bids: openedBids,
  tenderIdString: TENDER,
  rulesHash,
  disclosurePolicy: DISCLOSE_WINNING_PRICE,
  expectedBidSetRoot: chainRoot,
});
done(
  "award proved, and its root equals the chain's accumulator",
  "so no bid could have been dropped from the comparison",
);

const winner = BIDDERS.find(
  (b) => b.proof.publicSignals[11] === award.witness.winnerCommitment,
);
const { gas: awardGas } = await send(
  am.connect(auth).recordAward,
  tenderId,
  award.witness.winnerCommitment,
  award.witness.winningPrice,
  Number(award.witness.winnerIndex),
  award.pA, award.pB, award.pC,
);
done(
  `award recorded: bidder ${winner.key} at BDT ${award.witness.winningPrice.toLocaleString()}`,
  `${awardGas.toLocaleString()} gas`,
);

// =========================================================================
stage("The winner proves it placed the winning bid, before any name is shown");

const identity = await proveWinnerIdentity({
  registry,
  credential: winner.credential,
  subjectSecret: winner.subjectSecret,
  bidAmount: winner.bidAmount,
  bidNonce: winner.bidNonce,
  tenderIdString: TENDER,
  record: winner.identityRecord,
});
const canonicalRecord = jcsCanonicalize(winner.identityRecord);
const { gas: idGas } = await send(
  wi.connect(closer).submitIdentityProof,
  tenderId,
  winner.identityRecord.credentialId,
  toUtf8Bytes(canonicalRecord),
  identity.pA, identity.pB, identity.pC,
);
done(
  `identity published: ${winner.identityRecord.legalName}`,
  `${idGas.toLocaleString()} gas`,
);
note("a linkage to the credential holder, not a verification of the declared name");

// =========================================================================
stage("Every validator agrees");

for (let i = 0; i < cfg.validators.length; i++) {
  const p = new JsonRpcProvider(`http://127.0.0.1:${cfg.validators[i].rpc}`, {
    chainId: cfg.chainId, name: "fairproof",
  });
  const amN = new Contract(dep.contracts.AwardManager, abi("contracts/AwardManager.sol/AwardManager.json"), p);
  const a = await amN.getAward(tenderId);
  done(
    `validator-${i + 1} agrees on the award`,
    `winner #${a.winnerSubmissionIndex}, BDT ${a.winningPrice.toLocaleString()}`,
  );
  p.destroy();
}

console.log(`\n\x1b[1m\x1b[32mLIFECYCLE COMPLETE\x1b[0m — ${TENDER}`);
console.log(`\nOpen the dashboard to inspect it:  \x1b[1mnpm run dashboard:dev\x1b[0m`);
provider.destroy();
await shutdownProver();
