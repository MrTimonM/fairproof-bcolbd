#!/usr/bin/env node
/**
 * A sealed bid, end to end, on the live network.
 *
 * Development plan Sections 12.3, 12.5 and 13; whitepaper Sections 5 and 7.
 * Build order step 11.
 *
 * This is the full submission path with nothing stubbed:
 *
 *   the bidder's ciphertext, encrypted to the committee key the tender pins
 *     -> uploaded to three real ciphertext-store PROCESSES
 *     -> receipts signed by keys registered on-chain
 *     -> submitted with a real Groth16 proof
 *     -> accepted by the contract, which computes Poseidon itself and appends
 *        the leaf to the bid-set accumulator
 *
 * The accumulator is the point. If the authority computed `bidSetRoot`, it
 * could omit a bid it disliked and the award proof would still verify against
 * the root it published. So the root is checked here against one recomputed
 * independently in TypeScript from the events alone.
 *
 * Requires: `npm run network:up`, `npm run deploy`, `npm run replicas:start`.
 */
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  JsonRpcProvider,
  Wallet,
  Contract,
  ContractFactory,
  Interface,
  keccak256,
  toUtf8Bytes,
  getBytes,
} from "ethers";
import {
  BID_TREE_DEPTH,
  DOMAIN_PADDING_V1,
  IncrementalMerkleTree,
  bidLeaf,
  fetchCiphertext,
  initBabyjub,
  initPoseidon,
  storageReceiptRoot,
  toField,
  uploadToReplicas,
} from "@fairproof/crypto";
import { ensureFixtureTender, waitForBiddingOpen } from "./lib/fixture-tender.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "../..");
const artifactsRoot = join(repoRoot, "packages/contracts/artifacts");

const cfg = JSON.parse(
  readFileSync(join(repoRoot, "infrastructure/besu/config/accounts.json"), "utf8"),
);
const dep = JSON.parse(readFileSync(join(repoRoot, "deployments.json"), "utf8"));
const FIX = JSON.parse(
  readFileSync(join(repoRoot, "packages/circuits/fixtures/eligibility.proof.json"), "utf8"),
);
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

/**
 * Errors from EVERY contract in the call path, for decoding reverts.
 *
 * `submitBid` calls `EligibilityVerifier.requireEligibility`, which reverts
 * with `ProofRejected` - an error declared in the verifier, not in SealedBid.
 * Decoding with SealedBid's ABI alone yields "unknown custom error", which is
 * exactly what a UI watching only SealedBid would show a bidder whose proof
 * failed. Bubbling the verifier's own error is the right behaviour, because it
 * names the actual reason rather than flattening every failure into one; the
 * cost is that a client needs both ABIs, which is recorded here so the UI does
 * not have to rediscover it.
 */
const errorAbi = new Interface(
  [
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

/**
 * Deploy a fresh `SealedBid` against the SAME tender, verifier and replicas.
 *
 * Nullifiers are one-shot per tender per contract, so the negative cases
 * below would be masked by `NullifierAlreadyUsed` on any run after the first.
 * An earlier version of this test simply skipped them when bids already
 * existed, which meant a rerun silently checked far less than the first run -
 * the worst property a test can have, because the output still says PASS.
 *
 * A fresh instance shares all the frozen state that matters (the tender's
 * rules, the registered verifier, the replica keys) and starts with an empty
 * accumulator, so every run exercises every case.
 */
async function freshSealedBid() {
  const art = JSON.parse(
    readFileSync(join(artifactsRoot, "contracts/SealedBid.sol/SealedBid.json"), "utf8"),
  );
  let bytecode = art.bytecode;
  for (const [, libs] of Object.entries(art.linkReferences ?? {})) {
    for (const [name, refs] of Object.entries(libs)) {
      const address = dep.libraries[name];
      if (!address) throw new Error(`no deployed address for library ${name}`);
      for (const { start, length } of refs) {
        if (length !== 20) throw new Error(`unexpected link length ${length}`);
        const from = 2 + start * 2;
        bytecode =
          bytecode.slice(0, from) +
          address.slice(2).toLowerCase() +
          bytecode.slice(from + 40);
      }
    }
  }
  if (bytecode.includes("__$")) throw new Error("unlinked library placeholder remains");

  const deployer = new Wallet(acct("deployer").privateKey, provider);
  const factory = new ContractFactory(art.abi, bytecode, deployer);
  const c = await factory.deploy(
    dep.contracts.Governance,
    dep.contracts.TenderRegistry,
    dep.contracts.EligibilityVerifier,
    OPTS,
  );
  await c.deploymentTransaction().wait();
  for (const e of endpoints) {
    await (await c.connect(council).registerReplica(
      e.replicaId, e.address, `ciphertext-store-${e.replicaId}`, OPTS,
    )).wait();
  }
  return c;
}

const reg = new Contract(dep.contracts.IssuerRegistry, abi("contracts/IssuerRegistry.sol/IssuerRegistry.json"), provider);
const tr = new Contract(dep.contracts.TenderRegistry, abi("contracts/TenderRegistry.sol/TenderRegistry.json"), provider);
const sb = new Contract(dep.contracts.SealedBid, abi("contracts/SealedBid.sol/SealedBid.json"), provider);

const CHAIN = FIX.chain;
const SEALED = FIX.sealed;
const signalsOf = (name) => FIX.fixtures[name].publicSignals.map(BigInt);
const proofOf = (name) => {
  const f = FIX.fixtures[name];
  return [f.pA.map(BigInt), f.pB.map((r) => r.map(BigInt)), f.pC.map(BigInt)];
};

console.log("FairProof sealed bid on the live network");
console.log(`chain ${cfg.chainId}, SealedBid ${dep.contracts.SealedBid}\n`);

await initPoseidon();
await initBabyjub();

// =========================================================================
stage("Replicas are up and registered on-chain with the keys they sign with");

const endpoints = JSON.parse(
  execFileSync(process.execPath, [join(repoRoot, "scripts/replica-control.mjs"), "endpoints"], {
    encoding: "utf8",
    cwd: repoRoot,
  }),
);
let live = 0;
for (const e of endpoints) {
  let health = null;
  try {
    const res = await fetch(`${e.url}/health`, { signal: AbortSignal.timeout(2000) });
    health = res.ok ? await res.json() : null;
  } catch {
    /* a down replica is an expected condition, not an error */
  }
  const onChain = await sb.getReplica(e.replicaId);
  const matches =
    onChain.signer.toLowerCase() === e.address.toLowerCase() && onChain.active;
  if (health) live++;
  check(
    matches,
    `replica ${e.replicaId} registered on-chain with its signing address`,
    e.address,
  );
  check(
    health !== null && health.address.toLowerCase() === e.address.toLowerCase(),
    `replica ${e.replicaId} is running and signs with that same key`,
    health ? `${health.objects} object(s)` : "NOT RUNNING - run npm run replicas:start",
  );
}
if (live < 2) {
  console.log("\nAt least two replicas must be running. Run: npm run replicas:start");
  process.exit(1);
}

// =========================================================================
stage("The tender, with the committee key the ciphertexts are encrypted to");

const council = signer("council-regulator");
const auth = signer("tender-authority");
const { tenderId } = await ensureFixtureTender({
  fixture: FIX,
  tr,
  reg,
  council,
  authority: auth,
  committeeMembers: [1, 2, 3, 4, 5].map((i) => acct(`committee-${i}`).address),
  log: (m) => console.log(`  ..    ${m}`),
});
const key = await tr.getCommitteeKey(tenderId);
check(
  key.yX === BigInt(FIX.committee.publicKey.x) && key.yY === BigInt(FIX.committee.publicKey.y),
  "the tender pins the committee key the fixture's ciphertexts encrypt to",
  "so an accepted bid can actually be opened",
);

await waitForBiddingOpen(tr, tenderId, { log: (m) => console.log(`  ..    ${m}`) });
check(await tr.isBiddingOpen(tenderId), "bidding is OPEN");

// If this tender already carries bids from an earlier run, the nullifiers are
// spent and the submission below cannot be repeated. Report it and stop
// rather than failing on a NullifierAlreadyUsed that looks like a bug.
const already = await sb.submissionCount(tenderId);
if (already > 0n) {
  console.log(
    `\n  ..    this tender already has ${already} accepted bid(s) from an earlier run.`,
  );
  console.log("        Nullifiers are one-shot per tender, so re-running the submission");
  console.log("        requires a fresh deployment: npm run deploy");
  console.log("\n  Verifying the ACCUMULATOR against the existing bids instead.\n");
}

// =========================================================================
stage("The bidder uploads the ciphertext to the real replicas");

const canonicalBytes = getBytes(SEALED.valid.canonicalBytes);
check(
  canonicalBytes.length === SEALED.valid.byteLength,
  "canonical ciphertext bytes are the length the fixture recorded",
  `${canonicalBytes.length} bytes`,
);

const upload = await uploadToReplicas(endpoints, canonicalBytes, SEALED.valid.ciphertextHash);
check(
  upload.quorumMet,
  "the 2-of-3 storage quorum is met",
  `${upload.receipts.length}/${endpoints.length} replicas acknowledged`,
);
check(
  upload.receipts.every((r) => r.contentHash === SEALED.valid.ciphertextHash),
  "every receipt covers the ciphertextHash that will go on-chain",
  SEALED.valid.ciphertextHash.slice(0, 18),
);

const fetched = await fetchCiphertext(endpoints, SEALED.valid.ciphertextHash);
check(
  Buffer.from(fetched.bytes).equals(Buffer.from(canonicalBytes)),
  "the ciphertext is retrievable byte for byte",
  `replica ${fetched.replicaId}`,
);

// =========================================================================
stage("Submission: a real proof, real receipts, accepted on-chain");

const s = signalsOf("valid");
const [pa, pb, pc] = proofOf("valid");
const submission = {
  tenderId,
  nullifier: s[10],
  bidCommitment: s[11],
  ciphertextHash: SEALED.valid.ciphertextHash,
};
const receiptArgs = upload.receipts.map((r) => ({
  replicaId: r.replicaId,
  contentHash: r.contentHash,
  byteLength: BigInt(r.byteLength),
  signature: r.signature,
}));

check(
  BigInt(SEALED.valid.bidCommitment) === s[11],
  "the ciphertext's bidCommitment IS the proof's public signal 11",
  "so the bid can only open to the value the proof commits to",
);

// Submitted by an UNFUNDED fresh address. Gas is free here, so the bidder
// need not fund a wallet - which removes the funding-history correlation
// channel whitepaper Table 4 lists as a residual metadata risk.
const anonymous = Wallet.createRandom().connect(provider);
check(
  (await provider.getBalance(anonymous.address)) === 0n,
  "the submitter holds a zero balance",
  anonymous.address,
);

let accepted = false;
if (already === 0n) {
  const gas = await sb.connect(anonymous).submitBid.estimateGas(
    submission, receiptArgs, pa, pb, pc, OPTS,
  );
  const tx = await sb.connect(anonymous).submitBid(
    submission, receiptArgs, pa, pb, pc, { ...OPTS, gasLimit: gas * 2n },
  );
  const rcpt = await tx.wait();
  accepted = true;
  check(rcpt.status === 1, "bid ACCEPTED on-chain", `block ${rcpt.blockNumber}`);
  check(true, "measured acceptance gas on Besu", `${rcpt.gasUsed.toLocaleString()} gas`);
} else {
  check(true, "skipping submission - this tender already has bids");
}

const count = await sb.submissionCount(tenderId);
check(count > 0n, "the tender has at least one accepted bid", `${count}`);

const bid = await sb.getBid(tenderId, 0n);
check(bid.nullifier === s[10], "the stored nullifier is the proof's public signal 10");
check(bid.bidCommitment === s[11], "the stored bidCommitment is public signal 11");
check(
  bid.ciphertextHash === SEALED.valid.ciphertextHash,
  "the stored ciphertextHash is the one the replicas acknowledged",
);
check(
  bid.storageReceiptRoot === storageReceiptRoot(upload.receipts) ||
    upload.receipts.length !== 3,
  "the contract's storageReceiptRoot matches the one TypeScript computes",
  "spec Section 13",
);

// =========================================================================
stage("The CONTRACT accumulates the root, not the authority");

const onChainRoot = await sb.bidSetRoot(tenderId);
const leaves = await sb.getLeaves(tenderId);

// Recompute the leaf independently. Poseidon in TypeScript against Poseidon
// in Solidity, over four inputs plus the domain constant.
const expectedLeaf = bidLeaf({
  nullifier: bid.nullifier,
  bidCommitment: bid.bidCommitment,
  ciphertextHashField: toField(bid.ciphertextHash),
  submissionIndex: BigInt(bid.submissionIndex),
});
check(
  bid.leaf === expectedLeaf,
  "the contract's bid leaf equals the one TypeScript computes",
  "four inputs plus the domain, whitepaper Section 7",
);

// And rebuild the whole accumulator from the leaves.
const tree = new IncrementalMerkleTree(BID_TREE_DEPTH);
for (const leaf of leaves) tree.insert(leaf);
check(
  tree.root() === onChainRoot,
  "the on-chain bidSetRoot is reproducible from the accepted leaves",
  `root ...${onChainRoot.toString().slice(-10)}`,
);
check(DOMAIN_PADDING_V1 !== 0n, "the padding leaf is not zero, so an empty slot is distinguishable");

// Reproduce the root from EVENTS alone, with no storage reads. This is what
// an independent verifier does, and it only works if the events carry
// everything (plan Section 13).
// Bounded from the deployment block: Besu caps eth_getLogs ranges, and
// fromBlock 0 is rejected outright once the chain has a few thousand blocks.
const logs = await sb.queryFilter(
  sb.filters.BidAccepted(tenderId),
  dep.deployedAt,
  "latest",
);
const fromEvents = new IncrementalMerkleTree(BID_TREE_DEPTH);
for (const ev of [...logs].sort((a, b) => Number(a.args.submissionIndex) - Number(b.args.submissionIndex))) {
  fromEvents.insert(
    bidLeaf({
      nullifier: ev.args.nullifier,
      bidCommitment: ev.args.bidCommitment,
      ciphertextHashField: toField(ev.args.ciphertextHash),
      submissionIndex: BigInt(ev.args.submissionIndex),
    }),
  );
}
check(
  fromEvents.root() === onChainRoot,
  "the root is reproducible from EVENTS alone, without reading storage",
  `${logs.length} BidAccepted event(s)`,
);
check(
  logs.every((ev) => ev.args.bidSetRoot !== 0n),
  "each event carries the root as of that acceptance",
);

// =========================================================================
stage("The submission cannot be replayed");

if (accepted) {
  check(
    await sb.nullifierUsed(tenderId, s[10]),
    "the nullifier is recorded as used - one bid per credential per tender",
  );
  await expectRevert(
    () => sb.connect(anonymous).submitBid.staticCall(submission, receiptArgs, pa, pb, pc, OPTS),
    "NullifierAlreadyUsed",
    "the same bid cannot be submitted twice",
  );
  await expectRevert(
    () =>
      sb.connect(anonymous).submitBid.staticCall(
        {
          ...submission,
          nullifier: signalsOf("secondBidder")[10],
          bidCommitment: signalsOf("secondBidder")[11],
        },
        receiptArgs, pa, pb, pc, OPTS,
      ),
    "CiphertextAlreadySubmitted",
    "the same ciphertext cannot be resubmitted under another commitment",
  );
} else {
  console.log(
    "  ..    skipped: this tender's bids were accepted by an earlier run, so the\n" +
      "        replay path is already closed. The next stage deploys a fresh\n" +
      "        accumulator so nothing is left unchecked.",
  );
}

// =========================================================================
stage("Negative cases, on a fresh accumulator so every run checks them all");

const sb2 = await freshSealedBid();
check(
  (await sb2.submissionCount(tenderId)) === 0n,
  "a fresh SealedBid over the same tender starts empty",
  await sb2.getAddress(),
);

/**
 * The second bidder's ciphertext, uploaded for real, so these cases use
 * genuine receipts rather than fabricated ones.
 *
 * It also avoids a trap: `weakThresholds` is the SAME bidder as `valid` with
 * different thresholds, so it carries the same nullifier by construction.
 * Using it here would revert with NullifierAlreadyUsed and prove nothing
 * about receipts.
 */
const secondBytes = getBytes(SEALED.secondBidder.canonicalBytes);
const secondUpload = await uploadToReplicas(
  endpoints, secondBytes, SEALED.secondBidder.ciphertextHash,
);
check(
  secondUpload.quorumMet,
  "the second bidder's ciphertext is stored too",
  `${secondUpload.receipts.length} receipt(s)`,
);
const secondSignals = signalsOf("secondBidder");
const secondReceipts = secondUpload.receipts.map((r) => ({
  replicaId: r.replicaId,
  contentHash: r.contentHash,
  byteLength: BigInt(r.byteLength),
  signature: r.signature,
}));
const secondSubmission = {
  tenderId,
  nullifier: secondSignals[10],
  bidCommitment: secondSignals[11],
  ciphertextHash: SEALED.secondBidder.ciphertextHash,
};

await expectRevert(
  () =>
    sb2.connect(anonymous).submitBid.staticCall(
      secondSubmission, [secondReceipts[0]], ...proofOf("secondBidder"), OPTS,
    ),
  "StorageQuorumNotMet",
  "one receipt is not a quorum, even with a valid proof and a real receipt",
);

// The length is inside the signed digest, so altering it breaks the
// signature rather than being silently accepted.
await expectRevert(
  () =>
    sb2.connect(anonymous).submitBid.staticCall(
      secondSubmission,
      secondReceipts.map((r, i) => (i === 1 ? { ...r, byteLength: r.byteLength + 1n } : r)),
      ...proofOf("secondBidder"), OPTS,
    ),
  "ReceiptSignatureInvalid",
  "altering a receipt's byteLength invalidates its signature",
);

// The replicas really do hold the other object; holding it is not an
// acknowledgement of this one.
await expectRevert(
  () =>
    sb2.connect(anonymous).submitBid.staticCall(
      secondSubmission, receiptArgs, ...proofOf("secondBidder"), OPTS,
    ),
  "ReceiptContentMismatch",
  "receipts for a different ciphertext are rejected",
);

// The right receipts, the wrong proof. The proof binds the nullifier and the
// commitment, so it cannot be lifted onto another bidder's submission.
await expectRevert(
  () =>
    sb2.connect(anonymous).submitBid.staticCall(
      secondSubmission, secondReceipts, pa, pb, pc, OPTS,
    ),
  "ProofRejected",
  "one bidder's proof cannot authorise another bidder's submission",
);

// With everything correct it IS accepted, so the rejections above are about
// the specific defect and not about the tender being closed to bids.
{
  const gas2 = await sb2.connect(anonymous).submitBid.estimateGas(
    secondSubmission, secondReceipts, ...proofOf("secondBidder"), OPTS,
  );
  const rcpt2 = await (
    await sb2.connect(anonymous).submitBid(
      secondSubmission, secondReceipts, ...proofOf("secondBidder"),
      { ...OPTS, gasLimit: gas2 * 2n },
    )
  ).wait();
  check(rcpt2.status === 1, "the same submission, corrected, is accepted", `block ${rcpt2.blockNumber}`);
  check((await sb2.submissionCount(tenderId)) === 1n, "one bid on the fresh accumulator");

  const t2 = new IncrementalMerkleTree(BID_TREE_DEPTH);
  for (const leaf of await sb2.getLeaves(tenderId)) t2.insert(leaf);
  check(
    t2.root() === (await sb2.bidSetRoot(tenderId)),
    "the fresh accumulator's root is reproducible in TypeScript",
  );
  check(
    (await sb2.bidSetRoot(tenderId)) !== onChainRoot,
    "a different bid set gives a different root",
    "so an award proof cannot be moved between bid sets",
  );
}

// =========================================================================
stage("Cross-node agreement on the accumulator");

const roles = [
  "Procurement Regulator", "Procuring Entity",
  "Independent Auditor", "Chamber of Commerce",
];
for (let i = 0; i < cfg.validators.length; i++) {
  const p = new JsonRpcProvider(`http://127.0.0.1:${cfg.validators[i].rpc}`, {
    chainId: cfg.chainId,
    name: "fairproof",
  });
  const sbN = new Contract(dep.contracts.SealedBid, abi("contracts/SealedBid.sol/SealedBid.json"), p);
  const root = await sbN.bidSetRoot(tenderId);
  const n = await sbN.submissionCount(tenderId);
  check(
    root === (await sb.bidSetRoot(tenderId)) && n === (await sb.submissionCount(tenderId)),
    `validator-${i + 1} (${roles[i]}) agrees on bidSetRoot and submissionCount`,
  );
  p.destroy();
}

console.log(
  failures === 0 ? "\nSEALED BID ACCEPTED AND ACCUMULATED" : `\n${failures} CHECK(S) FAILED`,
);
provider.destroy();
process.exit(failures === 0 ? 0 : 1);
