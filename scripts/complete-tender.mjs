#!/usr/bin/env node
/**
 * Take a published tender all the way to a named winner.
 *
 * Three firms bid, the deadline passes, the tender is closed by an address
 * holding no role, the committee opens every bid three-of-five, each bidder
 * re-proves it was unrevoked at the deadline, the award is proved over the
 * COMPLETE bid set, and the winner proves it placed the winning bid before its
 * name is shown.
 *
 * The bidders are the profiles the dashboard ships in
 * `public/bidder-samples/`, so what happens here and what a reader sees in the
 * Bidder workspace are the same three firms.
 *
 *   npm run tender -- --window 240      # publish first
 *   npm run tender:complete RHD-2026-0147
 *
 * Award and winner-identity proving are not wired into the browser — only
 * eligibility is — so those two stages run here. Everything else this script
 * does can also be done by hand from the workspaces.
 */
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Contract, JsonRpcProvider, Wallet, keccak256, toUtf8Bytes } from "ethers";
import {
  DISCLOSE_WINNING_PRICE,
  combineInExponent,
  decryptionShare,
  initBabyjub,
  initEddsa,
  initPoseidon,
  jcsCanonicalize,
  openSealedBid,
  proveDleq,
  revocationTreeWith,
  sealBid,
  toField,
  uploadToReplicas,
  verifyDleq,
} from "@fairproof/crypto";
import {
  buildIssuerRegistry,
  issueCredential,
  proveAward,
  proveEligibility,
  proveWinnerIdentity,
} from "../tests/integration/lib/prove.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const publicDir = join(repoRoot, "apps/dashboard/public");
const g = JSON.parse(
  readFileSync(join(repoRoot, "apps/dashboard/src/generated/contracts.json"), "utf8"),
);

const REFERENCE = process.argv[2];
if (!REFERENCE) {
  console.error("usage: npm run tender:complete -- <tender reference>");
  process.exit(1);
}
const FIRMS = (process.argv[3] ?? "padma,jamuna,meghna").split(",");

const provider = new JsonRpcProvider(`http://127.0.0.1:${g.validators[0].rpc}`, {
  chainId: g.chainId,
  name: "fairproof",
});
const acct = (r) => g.roles.find((x) => x.role === r);
const addr = (n) => g.deployments.contracts[n];
const abi = (n) => g.abis[n];
const read = (n) => new Contract(addr(n), abi(n), provider);
const as = (n, w) => new Contract(addr(n), abi(n), w);
const signer = (role) => new Wallet(acct(role).privateKey, provider);
const anon = () => Wallet.createRandom().connect(provider);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let n = 0;
const stage = (t) => console.log(`\n[${++n}] ${t}`);
const ok = (t, d = "") => console.log(`  ${t}${d ? `  ${d}` : ""}`);

async function send(fn, args) {
  const gas = await fn.estimateGas(...args, { gasPrice: 0 });
  const tx = await fn(...args, { gasPrice: 0, gasLimit: (gas * 3n) / 2n });
  return tx.wait();
}
const hex32 = (v) => "0x" + v.toString(16).padStart(64, "0");
const bdt = (v) => "৳ " + Number(v).toLocaleString("en-IN");

await initPoseidon();
await initEddsa();
await initBabyjub();

const tr = read("TenderRegistry");
const reg = read("IssuerRegistry");
const sb = read("SealedBid");
const om = read("OpeningManager");
const ds = read("DeadlineStatus");
const am = read("AwardManager");
const wi = read("WinnerIdentity");

const tenderId = keccak256(toUtf8Bytes(REFERENCE));
const t = await tr.getTender(tenderId);
if (Number(t.state) !== 2) throw new Error(`tender ${REFERENCE} is not ACTIVE (state ${t.state})`);

const dealing = JSON.parse(
  readFileSync(join(publicDir, "committee-dealings", `${tenderId}.json`), "utf8"),
);
const registry = buildIssuerRegistry(7, 3);

/** The tender's human title, from the document the contract stores. */
const docHex = await tr.getRuleDocument(tenderId);
const title = (() => {
  try {
    return (
      JSON.parse(Buffer.from(docHex.slice(2), "hex").toString("utf8")).title ??
      t.tenderIdString
    );
  } catch {
    return t.tenderIdString;
  }
})();
const endpoints = g.replicas;

const profile = (id) =>
  JSON.parse(readFileSync(join(repoRoot, "scripts/firms", `${id}.json`), "utf8"));

/** Each firm's private material. None of it reaches the chain. */
const bidders = FIRMS.map((id, i) => {
  const p = profile(id);
  return {
    id,
    firm: p.firm,
    credentialId: BigInt(p.credential.credentialId),
    annualTurnover: BigInt(p.credential.annualTurnover),
    relevantExperience: BigInt(p.credential.relevantExperience),
    bidAmount: BigInt(p.bid.amountMinorUnit),
    // Deterministic per firm, so a re-run of this script is reproducible.
    subjectSecret: BigInt(keccak256(toUtf8Bytes(`subject:${REFERENCE}:${id}`))) >> 8n,
    bidNonce: BigInt(keccak256(toUtf8Bytes(`nonce:${REFERENCE}:${id}`))) >> 8n,
    index: i,
    identityRecord: {
      credentialId: p.credential.credentialId,
      legalName: p.firm.displayName,
      registrationNumber: p.firm.registrationNumber,
      tradeLicence: p.firm.tradeLicence,
      vatBin: p.firm.vatBin,
    },
  };
});

console.log(`\n${REFERENCE} — ${bidders.length} bidders\n`);

// =========================================================================
stage("Each firm proves eligibility and seals a bid");

const issuedAt = t.activatedAt - 86400n;
const validUntil = t.deadline + 31536000n;

for (const b of bidders) {
  const started = Date.now();
  b.credential = issueCredential(registry, {
    subjectSecret: b.subjectSecret,
    annualTurnover: b.annualTurnover,
    relevantExperience: b.relevantExperience,
    credentialId: b.credentialId,
    certificationCode: t.requirements.certificationCode,
    credentialEpoch: t.issuerEpoch,
    validUntil,
    issuedAt,
  });
  b.proof = await proveEligibility({
    registry,
    tenderIdString: t.tenderIdString,
    rulesHash: t.rulesHash,
    turnoverThreshold: t.requirements.turnoverThreshold,
    experienceMonthsThreshold: BigInt(t.requirements.experienceMonths),
    requiredCertificationCode: t.requirements.certificationCode,
    deadline: t.deadline,
    credentialEpoch: t.issuerEpoch,
    subjectSecret: b.subjectSecret,
    bidAmount: b.bidAmount,
    bidNonce: b.bidNonce,
    credentialId: b.credentialId,
    annualTurnover: b.annualTurnover,
    relevantExperience: b.relevantExperience,
    validUntil,
    issuedAt,
  });
  ok(
    `${b.firm.displayName}: eligibility proved`,
    `${((Date.now() - started) / 1000).toFixed(1)}s, nothing about the firm disclosed`,
  );

  b.sealed = await sealBid({
    payload: {
      tenderId: t.tenderIdString,
      amountMinorUnit: b.bidAmount.toString(),
      currency: "BDT",
      bidNonce: b.bidNonce.toString(),
      subjectCommitment: b.proof.witness.bidCommitment.toString(),
      createdAt: new Date().toISOString(),
    },
    tenderPublicKey: { x: BigInt(dealing.publicKey.x), y: BigInt(dealing.publicKey.y) },
    tenderIdField: b.proof.witness.tenderIdField,
    nullifier: b.proof.witness.nullifier,
  });
  if (b.sealed.bidCommitment !== b.proof.publicSignals[11]) {
    throw new Error(`${b.id}: the sealed bid and the proof disagree`);
  }
  b.upload = await uploadToReplicas(endpoints, b.sealed.canonicalBytes, b.sealed.ciphertextHash);
  if (!b.upload.quorumMet) throw new Error(`${b.id}: storage quorum not met`);
  ok(`${b.firm.displayName}: sealed and stored`, `${b.upload.receipts.length}/3 replicas signed`);
}

// =========================================================================
stage("The mandatory review window runs its course");
while (!(await tr.isBiddingOpen(tenderId))) {
  const now = BigInt((await provider.getBlock("latest")).timestamp);
  ok(`waiting ${t.biddingStart - now}s — the contract refuses bids until then`);
  await sleep(5000);
}
ok("bidding OPEN");

// =========================================================================
stage("The bids are submitted from unfunded addresses");
for (const b of bidders) {
  const wallet = anon();
  const balance = await provider.getBalance(wallet.address);
  const receipt = await send(as("SealedBid", wallet).submitBid, [
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
  ]);
  b.index = Number(await sb.submissionCount(tenderId)) - 1;
  b.txHash = receipt.hash;
  b.from = wallet.address;
  b.gasUsed = String(receipt.gasUsed);
  b.submittedAt = Math.floor(Date.now() / 1000);
  ok(
    `${b.firm.displayName} accepted as submission #${b.index}`,
    `${Number(receipt.gasUsed).toLocaleString()} gas, from a ${balance}-balance address`,
  );
}

// =========================================================================
stage("A third firm's credential is revoked, then the deadline passes");

/**
 * Revoke a credential belonging to NONE of the bidders, before the close.
 *
 * If the deadline root equalled the submission-time root, the original
 * eligibility proof would double as a status proof and the close-time check
 * would pass vacuously. Revoking something makes the tree genuinely different
 * while leaving every bidder unrevoked.
 */
const deadlineTree = revocationTreeWith(9999n);
await send(as("IssuerRegistry", signer("council-regulator")).publishRevocationRoot, [
  await reg.currentEpoch(),
  hex32(deadlineTree.root),
]);
ok("credential 9999 revoked", "so the deadline root differs from the one bids were checked against");

while (await tr.isBiddingOpen(tenderId)) {
  const now = BigInt((await provider.getBlock("latest")).timestamp);
  ok(`waiting ${t.deadline - now}s for the deadline`);
  await sleep(5000);
}

const closer = anon();
await send(as("TenderRegistry", closer).closeTender, [tenderId]);
ok("tender CLOSED, permissionlessly", "so nobody can hold it open to delay an opening");
ok("deadline revocation root pinned one-shot", (await reg.deadlineRevocationRoot(tenderId)).slice(0, 20));

// =========================================================================
stage("The committee opens each bid — three of five, one share at a time");

for (const b of bidders) {
  await send(as("OpeningManager", anon()).revealCiphertext, [
    tenderId,
    b.index,
    b.sealed.canonicalBytes,
  ]);
  ok(`bid #${b.index}: ciphertext published and hash-checked on-chain`);

  const R = { x: b.sealed.ciphertext.rX, y: b.sealed.ciphertext.rY };
  for (const m of [1, 2, 3]) {
    const s = dealing.shares.find((x) => x.index === m);
    const D = decryptionShare(BigInt(s.share), R);
    const proof = proveDleq({ secret: BigInt(s.share), ephemeral: R });
    if (
      !verifyDleq({
        publicShare: { x: BigInt(s.publicShareX), y: BigInt(s.publicShareY) },
        ephemeral: R,
        decryptionShare: D,
        proof,
      })
    ) {
      throw new Error(`member ${m}: own DLEQ proof does not verify`);
    }
    await send(as("OpeningManager", signer(`committee-${m}`)).submitDecryptionShare, [
      tenderId,
      b.index,
      m,
      D.x,
      D.y,
      { aX: proof.a.x, aY: proof.a.y, bX: proof.b.x, bY: proof.b.y, z: proof.z },
    ]);
    const [, accepted, threshold, ready] = await om.openingStatus(tenderId, b.index);
    ok(
      `bid #${b.index}: ${accepted}/${threshold} from member ${m}`,
      ready ? "threshold met" : "still sealed",
    );
  }

  const shares = await om.getShares(tenderId, b.index);
  const shared = combineInExponent(
    [...shares].map((s) => ({ index: Number(s.memberIndex), point: { x: s.dX, y: s.dY } })),
  );
  const chainBid = await sb.getBid(tenderId, b.index);
  const opened = await openSealedBid({
    ciphertext: b.sealed.ciphertext,
    shared,
    expectedCommitment: chainBid.bidCommitment,
    tenderIdField: b.proof.witness.tenderIdField,
    nullifier: b.proof.witness.nullifier,
  });
  b.openedAmount = opened.bidAmount;
  ok(`bid #${b.index} OPENED`, `${b.firm.displayName} bid ${bdt(opened.bidAmount)}`);
}

// =========================================================================
stage("Each bidder re-proves eligibility against the pinned deadline root");

for (const b of bidders) {
  const statusProof = await proveEligibility({
    registry: {
      ...registry,
      revocation: { root: deadlineTree.root, siblings: deadlineTree.siblingsFor(b.credentialId) },
    },
    tenderIdString: t.tenderIdString,
    rulesHash: t.rulesHash,
    turnoverThreshold: t.requirements.turnoverThreshold,
    experienceMonthsThreshold: BigInt(t.requirements.experienceMonths),
    requiredCertificationCode: t.requirements.certificationCode,
    deadline: t.deadline,
    credentialEpoch: t.issuerEpoch,
    subjectSecret: b.subjectSecret,
    bidAmount: b.bidAmount,
    bidNonce: b.bidNonce,
    credentialId: b.credentialId,
    annualTurnover: b.annualTurnover,
    relevantExperience: b.relevantExperience,
    validUntil,
    issuedAt,
  });
  await send(as("DeadlineStatus", closer).submitStatusProof, [
    tenderId,
    b.index,
    statusProof.pA,
    statusProof.pB,
    statusProof.pC,
  ]);
  ok(`${b.firm.displayName}: unrevoked at the deadline`, "not inferred from an older snapshot");
}

// =========================================================================
stage("The award is proved over the COMPLETE bid set");

const openedBids = bidders.map((b) => ({
  submissionIndex: b.index,
  nullifier: b.proof.witness.nullifier,
  bidAmount: b.openedAmount,
  bidNonce: b.bidNonce,
  ciphertextHashField: toField(b.sealed.ciphertextHash),
}));
const chainRoot = await sb.bidSetRoot(tenderId);
const award = await proveAward({
  bids: openedBids,
  tenderIdString: t.tenderIdString,
  rulesHash: t.rulesHash,
  disclosurePolicy: DISCLOSE_WINNING_PRICE,
  expectedBidSetRoot: chainRoot,
});
ok("award proved, and its root equals the chain's accumulator",
   "so no bid could have been dropped from the comparison");

const winner = bidders.find((b) => b.proof.publicSignals[11] === award.witness.winnerCommitment);
const awardReceipt = await send(as("AwardManager", signer("tender-authority")).recordAward, [
  tenderId,
  award.witness.winnerCommitment,
  award.witness.winningPrice,
  Number(award.witness.winnerIndex),
  award.pA,
  award.pB,
  award.pC,
]);
ok(
  `award recorded: submission #${award.witness.winnerIndex} at ${bdt(award.witness.winningPrice)}`,
  `${Number(awardReceipt.gasUsed).toLocaleString()} gas`,
);

// =========================================================================
stage("The winner proves it placed the winning bid, before any name is shown");

const identity = await proveWinnerIdentity({
  registry,
  credential: winner.credential,
  subjectSecret: winner.subjectSecret,
  bidAmount: winner.bidAmount,
  bidNonce: winner.bidNonce,
  tenderIdString: t.tenderIdString,
  record: winner.identityRecord,
});
const idReceipt = await send(as("WinnerIdentity", closer).submitIdentityProof, [
  tenderId,
  winner.identityRecord.credentialId,
  toUtf8Bytes(jcsCanonicalize(winner.identityRecord)),
  identity.pA,
  identity.pB,
  identity.pC,
]);
ok(`identity published: ${winner.identityRecord.legalName}`,
   `${Number(idReceipt.gasUsed).toLocaleString()} gas`);
ok("a linkage to the credential holder, not a verification of the declared name");

// =========================================================================
/**
 * The three bidders' own receipts, so the Bidder workspace can show what
 * happened to each. A receipt is private material — one firm holds only its
 * own — so serving all three is a property of a seeded tender and the
 * workspace labels it as such.
 */
const dir = join(publicDir, "bidder-receipts");
mkdirSync(dir, { recursive: true });
const receipts = bidders.map((b) => ({
  tenderId,
  tenderIdString: t.tenderIdString,
  tenderTitle: title,
  firmName: b.firm.displayName,
  submissionIndex: b.index,
  nullifier: b.proof.witness.nullifier.toString(),
  bidCommitment: b.proof.publicSignals[11].toString(),
  ciphertextHash: b.sealed.ciphertextHash,
  amountMinorUnit: b.bidAmount.toString(),
  bidNonce: b.bidNonce.toString(),
  txHash: b.txHash,
  from: b.from,
  gasUsed: b.gasUsed,
  submittedAt: b.submittedAt,
  seeded: true,
}));
writeFileSync(
  join(dir, "index.json"),
  JSON.stringify(
    {
      $comment:
        "SEEDED TENDER ONLY. A bid receipt is a bidder's own private material - " +
        "one firm holds only its own. All three are served here so the Bidder " +
        "workspace can show what happened to each. A bid placed from the " +
        "workspace is kept in that browser and is never written here.",
      receipts,
    },
    null,
    1,
  ) + "\n",
);
ok("bidder receipts written", "public/bidder-receipts/");

console.log(`
  WINNER  ${winner.identityRecord.legalName}
          submission #${award.witness.winnerIndex} at ${bdt(award.witness.winningPrice)}
          over ${bidders.length} bids, proved against the complete set
`);
process.exit(0);
