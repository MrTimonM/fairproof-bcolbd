#!/usr/bin/env node
/**
 * Verify a REAL eligibility proof on the LIVE Besu network.
 *
 * Development plan Sections 20.5 and 25.1 step 8. This is the check that
 * closes the loop the whitepaper describes: a private witness, proved in a
 * browser-grade prover, verified by a contract against rules frozen on a
 * four-validator permissioned chain, with every validator agreeing.
 *
 * Unit tests already verify these proofs against Hardhat's in-process EVM.
 * Running the same proofs against Besu is not redundant: it exercises the
 * real pairing precompiles under a real client, the real block gas limit, the
 * governance-registered verifier version rather than a test-registered one,
 * and cross-node agreement. A proof that verifies in one EVM and not in four
 * is a consensus problem, and nothing but this test would find it.
 *
 * TENDER ID IS FIXED, NOT PER-RUN. `tenderIdField` is public signal 0 and is
 * baked into the proof, so this test cannot suffix the id with a nonce the
 * way the lifecycle test does. It is idempotent by REUSING an existing
 * matching tender instead.
 *
 * ISSUER EPOCH IS 7, NOT 1. The fixture's registry and revocation roots are
 * published at epoch 7 so the lifecycle test, which uses epoch 1, cannot
 * overwrite them. Both write to the same mapping; sharing an epoch would make
 * a previously valid proof stop verifying for reasons unrelated to the proof.
 */
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { JsonRpcProvider, Wallet, Contract, keccak256, toUtf8Bytes } from "ethers";
import { initBabyjub } from "@fairproof/crypto";
import { ensureFixtureTender } from "./lib/fixture-tender.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "../..");
const artifactsRoot = join(repoRoot, "packages/contracts/artifacts");

const cfg = JSON.parse(
  readFileSync(join(repoRoot, "infrastructure/besu/config/accounts.json"), "utf8"),
);
const dep = JSON.parse(readFileSync(join(repoRoot, "deployments.json"), "utf8"));
const FIX = JSON.parse(
  readFileSync(
    join(repoRoot, "packages/circuits/fixtures/eligibility.proof.json"),
    "utf8",
  ),
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

/** Assert a revert, and that it reverts for the RIGHT reason. */
async function expectRevert(fn, errorName, label) {
  try {
    await fn();
    check(false, label, "call succeeded but should have reverted");
  } catch (err) {
    const name = err.revert?.name;
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
const ev = new Contract(
  dep.contracts.EligibilityVerifier,
  abi("contracts/EligibilityVerifier.sol/EligibilityVerifier.json"),
  provider,
);
const groth = new Contract(
  dep.contracts.EligibilityVerifierGroth16,
  abi("contracts/verifiers/EligibilityVerifierGroth16.sol/EligibilityVerifierGroth16.json"),
  provider,
);

const State = { NONE: 0n, DRAFT: 1n, ACTIVE: 2n };
const CHAIN = FIX.chain;
const SPEC = FIX.tender;
const EPOCH = BigInt(SPEC.credentialEpoch);
const tenderId = keccak256(toUtf8Bytes(CHAIN.tenderIdString));

const proofOf = (name) => {
  const f = FIX.fixtures[name];
  return [
    f.pA.map(BigInt),
    f.pB.map((r) => r.map(BigInt)),
    f.pC.map(BigInt),
  ];
};
const signalsOf = (name) => FIX.fixtures[name].publicSignals.map(BigInt);

console.log("FairProof eligibility proof on the live network");
console.log(`chain ${cfg.chainId}, tender ${CHAIN.tenderIdString}, issuer epoch ${EPOCH}`);
console.log(`verifier ${dep.contracts.EligibilityVerifier}\n`);

await initBabyjub();

// =========================================================================
stage("The governance-registered verifier version is live");

check(await ev.isVersionRegistered(1), "verifier version 1 is registered");
const rec = await ev.getVerifier(1);
check(
  rec.impl.toLowerCase() === dep.contracts.EligibilityVerifierGroth16.toLowerCase(),
  "the registered implementation is the deployed Groth16 verifier",
);
const transcript = JSON.parse(
  readFileSync(join(repoRoot, "packages/circuits/ceremony/eligibility.transcript.json"), "utf8"),
);
check(
  rec.vkeyHash === "0x" + transcript.verificationKey.sha256,
  "the on-chain vkeyHash is the published ceremony's",
  rec.vkeyHash.slice(0, 18),
);
check(
  rec.proposalId > 0n && (await gov.getProposal(rec.proposalId)).executed,
  "registration consumed an executed governance proposal",
  `proposal ${rec.proposalId}`,
);

// =========================================================================
stage("The fixture's tender, ACTIVE on-chain with the proved rules");

const council = signer("council-regulator");
const auth = signer("tender-authority");
const { created } = await ensureFixtureTender({
  fixture: FIX,
  tr,
  reg,
  council,
  authority: auth,
  committeeMembers: [1, 2, 3, 4, 5].map((i) => acct(`committee-${i}`).address),
  log: (m) => console.log(`  ..    ${m}`),
});
check(true, created ? "tender created and activated" : "reusing the existing tender");

check(
  (await reg.issuerRegistryRoot(EPOCH)) === CHAIN.issuerRegistryRoot,
  "issuerRegistryRoot published - the circuit proved membership against this",
  CHAIN.issuerRegistryRoot.slice(0, 18),
);
check(
  (await reg.revocationRoot(EPOCH)) === CHAIN.revocationRoot,
  "revocationRoot published - a zero leaf here proves non-revocation",
);

const t = await tr.getTender(tenderId);
check(t.state === State.ACTIVE, "tender ACTIVE", `state ${t.state}`);
check(
  t.rulesHash === CHAIN.rulesHash,
  "the CONTRACT's own keccak of the stored document is the proved rulesHash",
  CHAIN.rulesHash.slice(0, 18),
);
check(
  t.tenderIdField === BigInt(CHAIN.tenderIdField),
  "the on-chain tenderIdField is public signal 0",
);
check(t.verifierVersion === 1n, "the tender pins verifier version 1");
check(
  t.deadline === BigInt(SPEC.deadline),
  "the deadline on-chain is exactly the one proved as public signal 6",
);

// =========================================================================
stage("The CONTRACT derives the twelve public signals, not the caller");

const expected = signalsOf("valid");
const derived = await ev.expectedPublicSignals(tenderId, expected[10], expected[11]);
const labels = [
  "tenderIdField", "rulesHashHi", "rulesHashLo", "turnoverThreshold",
  "experienceMonthsThreshold", "requiredCertificationCode", "deadline",
  "issuerRegistryRoot", "revocationRoot", "credentialEpoch",
  "nullifier", "bidCommitment",
];
let allMatch = true;
for (let i = 0; i < 12; i++) {
  if (derived[i] !== expected[i]) {
    allMatch = false;
    check(false, `signal ${i} (${labels[i]})`, `chain ${derived[i]} != proof ${expected[i]}`);
  }
}
check(
  allMatch,
  "all twelve signals derived from chain state equal the ones proved",
  "encoding spec Section 16",
);

// =========================================================================
stage("Groth16 verification on the live chain");

const [a, b, c] = proofOf("valid");
check(
  await ev.verifyEligibility(tenderId, expected[10], expected[11], a, b, c),
  "a valid eligibility proof VERIFIES on the live chain",
  "whitepaper Figure 3, nine clauses",
);
await ev.requireEligibility(tenderId, expected[10], expected[11], a, b, c);
check(true, "requireEligibility does not revert for a valid proof");

const second = signalsOf("secondBidder");
const [a2, b2, c2] = proofOf("secondBidder");
check(
  await ev.verifyEligibility(tenderId, second[10], second[11], a2, b2, c2),
  "a second, distinct bidder also verifies",
  `nullifiers differ: ...${second[10].toString().slice(-8)}`,
);

// Gas, measured against a real client rather than an in-process EVM.
const gas = await provider.estimateGas({
  to: dep.contracts.EligibilityVerifier,
  data: ev.interface.encodeFunctionData("verifyEligibility", [
    tenderId, expected[10], expected[11], a, b, c,
  ]),
});
check(gas > 200000n, "measured verification gas on Besu", `${gas.toLocaleString()} gas`);

// =========================================================================
stage("The two proofs that MUST be rejected");

const other = signalsOf("otherTender");
const [ao, bo, co] = proofOf("otherTender");
check(
  (await ev.verifyEligibility(tenderId, other[10], other[11], ao, bo, co)) === false,
  "a valid proof for a DIFFERENT tender is rejected",
  "cross-tender replay",
);

const weak = signalsOf("weakThresholds");
const [aw, bw, cw] = proofOf("weakThresholds");
check(weak[3] === 1n && weak[4] === 0n, "the weak proof's thresholds really are 1 and 0");
check(
  (await ev.verifyEligibility(tenderId, weak[10], weak[11], aw, bw, cw)) === false,
  "a proof against thresholds the BIDDER chose is rejected",
  "the attack the adapter exists to stop",
);
await expectRevert(
  () => ev.requireEligibility.staticCall(tenderId, weak[10], weak[11], aw, bw, cw),
  "ProofRejected",
  "requireEligibility reverts, naming the pinned version",
);

check(
  (await groth.verifyProof(ao, bo, co, other)) === true &&
    (await groth.verifyProof(aw, bw, cw, weak)) === true,
  "the RAW verifier accepts both - so the rejection is the adapter's binding",
  "without this, the two checks above could pass for the wrong reason",
);

// =========================================================================
stage("Replay path: limb reconstruction against published signals");

check(
  await ev.verifyWithSignals(tenderId, expected, a, b, c),
  "the published signal array replays correctly",
);
const swapped = [...expected];
[swapped[1], swapped[2]] = [swapped[2], swapped[1]];
await expectRevert(
  () => ev.verifyWithSignals.staticCall(tenderId, swapped, a, b, c),
  "RulesHashMismatchInSignals",
  "swapped rulesHash limbs are rejected",
);
const tampered = [...expected];
tampered[3] = 1n;
await expectRevert(
  () => ev.verifyWithSignals.staticCall(tenderId, tampered, a, b, c),
  "PublicSignalMismatch",
  "a tampered threshold signal is rejected, naming the index",
);

// =========================================================================
stage("Cross-node agreement: every validator verifies the same proof");

// A proof that verifies on one node and not on another is a consensus
// problem, and nothing but this check would find it.
const roles = [
  "Procurement Regulator",
  "Procuring Entity",
  "Independent Auditor",
  "Chamber of Commerce",
];
for (let i = 0; i < cfg.validators.length; i++) {
  const p = new JsonRpcProvider(`http://127.0.0.1:${cfg.validators[i].rpc}`, {
    chainId: cfg.chainId,
    name: "fairproof",
  });
  const evN = new Contract(
    dep.contracts.EligibilityVerifier,
    abi("contracts/EligibilityVerifier.sol/EligibilityVerifier.json"),
    p,
  );
  const okValid = await evN.verifyEligibility(tenderId, expected[10], expected[11], a, b, c);
  const okWeak = await evN.verifyEligibility(tenderId, weak[10], weak[11], aw, bw, cw);
  check(
    okValid === true && okWeak === false,
    `validator-${i + 1} (${roles[i]}) accepts the valid proof and rejects the weak one`,
  );
  p.destroy();
}

console.log(
  failures === 0
    ? "\nELIGIBILITY PROOF VERIFIED ON THE LIVE NETWORK"
    : `\n${failures} CHECK(S) FAILED`,
);
provider.destroy();
process.exit(failures === 0 ? 0 : 1);
