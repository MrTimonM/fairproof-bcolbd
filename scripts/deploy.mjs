#!/usr/bin/env node
/**
 * Deploy the FairProof contracts to the permissioned Besu network.
 *
 * Poseidon is deployed once and linked by every contract that needs it,
 * rather than inlined per contract (docs/stage0-evidence.md).
 *
 * Writes deployments.json, which the seed script, the app, and the
 * independent verifier all read. Nothing hard-codes an address.
 */
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { JsonRpcProvider, Wallet, ContractFactory } from "ethers";
import { emptyRevocationTree, initPoseidon } from "@fairproof/crypto";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "..");
const artifactsRoot = join(repoRoot, "packages/contracts/artifacts");

/**
 * Initial POLICY FLOOR on the rule-review window, not a fixed window.
 * Each tender chooses its own window >= this floor, and the council can raise
 * the floor later under 3-of-4. The contract's own hard constant is 60 s.
 */
const MIN_REVIEW_WINDOW = Number(process.env.MIN_REVIEW_WINDOW || 300);

const cfg = JSON.parse(
  readFileSync(join(repoRoot, "infrastructure/besu/config/accounts.json"), "utf8"),
);
const account = (role) => {
  const a = cfg.accounts.find((x) => x.role === role);
  if (!a) throw new Error(`no such role account: ${role}`);
  return a;
};

function artifact(relPath) {
  return JSON.parse(readFileSync(join(artifactsRoot, relPath), "utf8"));
}

/** Link library placeholders in bytecode. */
function link(bytecode, linkReferences, addresses) {
  let out = bytecode;
  for (const [file, libs] of Object.entries(linkReferences || {})) {
    for (const [libName, refs] of Object.entries(libs)) {
      const addr = addresses[libName];
      if (!addr) throw new Error(`missing library address for ${libName} (${file})`);
      const clean = addr.slice(2).toLowerCase();
      for (const { start, length } of refs) {
        if (length !== 20) throw new Error(`unexpected link length ${length}`);
        const from = 2 + start * 2;
        out = out.slice(0, from) + clean + out.slice(from + 40);
      }
    }
  }
  if (out.includes("__$")) throw new Error("bytecode still contains unlinked placeholders");
  return out;
}

const provider = new JsonRpcProvider(`http://127.0.0.1:${cfg.validators[0].rpc}`, {
  chainId: cfg.chainId,
  name: "fairproof",
});
const deployer = new Wallet(account("deployer").privateKey, provider);

async function deploy(label, art, args = [], libraries = {}) {
  const bytecode = link(art.bytecode, art.linkReferences, libraries);
  const factory = new ContractFactory(art.abi, bytecode, deployer);
  const c = await factory.deploy(...args, { gasPrice: 0 });
  const receipt = await c.deploymentTransaction().wait();
  const address = await c.getAddress();
  console.log(
    `  ${label.padEnd(20)} ${address}  (${receipt.gasUsed.toLocaleString()} gas)`,
  );
  return { contract: c, address, gasUsed: receipt.gasUsed };
}

console.log(`FairProof deployment -> chain ${cfg.chainId}`);
console.log(`initial review-window policy floor: ${MIN_REVIEW_WINDOW}s\n`);
console.log("libraries:");
const t3 = await deploy("PoseidonT3", artifact("poseidon-solidity/PoseidonT3.sol/PoseidonT3.json"));
const t6 = await deploy("PoseidonT6", artifact("poseidon-solidity/PoseidonT6.sol/PoseidonT6.json"));
const libs = { PoseidonT3: t3.address, PoseidonT6: t6.address };

console.log("\ncontracts:");
const councilAddrs = [
  account("council-regulator").address,
  account("council-procuring-entity").address,
  account("council-auditor").address,
  account("council-chamber").address,
];

const gov = await deploy(
  "Governance",
  artifact("contracts/Governance.sol/Governance.json"),
  [councilAddrs],
);
const reg = await deploy(
  "IssuerRegistry",
  artifact("contracts/IssuerRegistry.sol/IssuerRegistry.json"),
  [gov.address],
);
const tr = await deploy(
  "TenderRegistry",
  artifact("contracts/TenderRegistry.sol/TenderRegistry.json"),
  [gov.address, reg.address, MIN_REVIEW_WINDOW],
  libs,
);

const groth = await deploy(
  "EligibilityGroth16",
  artifact("contracts/verifiers/EligibilityVerifierGroth16.sol/EligibilityVerifierGroth16.json"),
);
const ev = await deploy(
  "EligibilityVerifier",
  artifact("contracts/EligibilityVerifier.sol/EligibilityVerifier.json"),
  [gov.address, reg.address, tr.address],
);
const sb = await deploy(
  "SealedBid",
  artifact("contracts/SealedBid.sol/SealedBid.json"),
  [gov.address, tr.address, ev.address],
  libs,
);
const om = await deploy(
  "OpeningManager",
  artifact("contracts/OpeningManager.sol/OpeningManager.json"),
  [gov.address, tr.address, sb.address],
);
const ds = await deploy(
  "DeadlineStatus",
  artifact("contracts/DeadlineStatus.sol/DeadlineStatus.json"),
  [tr.address, reg.address, sb.address, ev.address],
);
const awardGroth = await deploy(
  "AwardGroth16",
  artifact("contracts/verifiers/AwardVerifierGroth16.sol/AwardVerifierGroth16.json"),
);

// AwardManager is bound at construction to ONE verifier and ONE circuit
// version, and refuses any tender pinned to a different one. A new circuit
// version therefore means a new AwardManager, and an in-flight tender keeps
// being awarded under the logic it was activated with - whitepaper Section 14
// obtained structurally rather than by a guard that could be edited.
const awardTranscript = JSON.parse(
  readFileSync(
    join(repoRoot, "packages/circuits/ceremony/award.transcript.json"),
    "utf8",
  ),
);
const am = await deploy(
  "AwardManager",
  artifact("contracts/AwardManager.sol/AwardManager.json"),
  [
    gov.address,
    tr.address,
    sb.address,
    om.address,
    ds.address,
    awardGroth.address,
    1,
    "0x" + awardTranscript.verificationKey.sha256,
    "packages/circuits/ceremony/award.transcript.json",
  ],
);

// Wire the tender module. One-shot by design: a re-settable pointer would let
// a captured council key redirect deadline-root pinning.
console.log("\nwiring:");
const councilSigner = new Wallet(account("council-regulator").privateKey, provider);
const regAsCouncil = reg.contract.connect(councilSigner);
await (await regAsCouncil.setTenderModule(tr.address, { gasPrice: 0 })).wait();
console.log(`  IssuerRegistry.tenderModule -> ${tr.address}`);

// ---- an initial revocation root for the registry's CURRENT epoch ---------
//
// `closeTender` pins the revocation root of the epoch the REGISTRY is on,
// which is not the tender's credential epoch. With no root published there,
// closing reverts RootNotSet - and since closing is permissionless and purely
// time-based, that would leave a tender permanently unclosable through no
// fault of anyone involved with it.
//
// Reverting is the correct behaviour rather than pinning zero: the empty
// sparse revocation tree has a NON-zero root, so zero means "never
// published", and pinning it would let a status proof be checked against a
// tree nobody committed to. The fix belongs here, at deployment: publish the
// empty-tree root so the registry is never in that state to begin with.
await initPoseidon();
const emptyRevocation = emptyRevocationTree();
const emptyRoot = "0x" + emptyRevocation.root.toString(16).padStart(64, "0");
const currentEpoch = await reg.contract.currentEpoch();
await (await reg.contract.connect(councilSigner).publishRevocationRoot(
  currentEpoch, emptyRoot, { gasPrice: 0 },
)).wait();
console.log(`  IssuerRegistry.revocationRoot[${currentEpoch}] -> ${emptyRoot.slice(0, 18)}... (empty tree)`);

await (await tr.contract.connect(councilSigner).setVerifierVersionRegistry(
  ev.address, { gasPrice: 0 },
)).wait();
console.log(`  TenderRegistry.verifierVersionRegistry -> ${ev.address}`);

// ---- register the three ciphertext-store replicas -----------------------
//
// Their signing keys are the role accounts, so the addresses the replica
// processes sign with are the ones the contract will accept. Registration is
// one-shot per id: a re-settable replica key would let a captured council key
// make an old receipt verify, or stop it verifying, and receipts are what the
// bid-set completeness claim rests on.
console.log("\nciphertext-store replicas:");
for (const id of [1, 2, 3]) {
  const a = account(`replica-${id}`);
  await (await sb.contract.connect(councilSigner).registerReplica(
    id, a.address, `ciphertext-store-${id}`, { gasPrice: 0 },
  )).wait();
  console.log(`  replica ${id} -> ${a.address}`);
}
console.log(`  active replicas: ${await sb.contract.activeReplicaCount()} (quorum ${await sb.contract.STORAGE_QUORUM()})`);

// ---- register verifier version 1 through governance ---------------------
//
// Deploying the verifier is not enough: `EligibilityVerifier` refuses to use
// a version that was not activated by an executed, timelocked
// `ActivateVerifierVersion` proposal, and there is deliberately no fallback
// to "the newest verifier" (plan Section 11B.3). So the deployment runs the
// real 3-of-4 flow rather than a privileged shortcut, which also means the
// timelock is exercised on every deployment instead of only in tests.
//
// The recorded hashes are the REAL ones: `vkeyHash` from the published
// ceremony transcript, `sourceHash` from the committed generated verifier
// whose byte-identity with a fresh export `ceremony:verify` checks. Together
// they let an outside reviewer tie this deployed bytecode to that ceremony.
console.log("\nverifier version 1 (governance, 3-of-4 + timelock):");

const transcript = JSON.parse(
  readFileSync(
    join(repoRoot, "packages/circuits/ceremony/eligibility.transcript.json"),
    "utf8",
  ),
);
const verifierSourcePath =
  "packages/contracts/contracts/verifiers/EligibilityVerifierGroth16.sol";
const sourceHash =
  "0x" +
  createHash("sha256")
    .update(readFileSync(join(repoRoot, verifierSourcePath), "utf8"), "utf8")
    .digest("hex");
const vkeyHash = "0x" + transcript.verificationKey.sha256;
const transcriptUri = "packages/circuits/ceremony/eligibility.transcript.json";

const fixture = JSON.parse(
  readFileSync(
    join(repoRoot, "packages/circuits/fixtures/eligibility.proof.json"),
    "utf8",
  ),
).fixtures.valid;

const registration = {
  version: 1,
  impl: groth.address,
  vkeyHash,
  sourceHash,
  transcriptUri,
};
const payload = await ev.contract.encodeActivationPayload(registration);

const councilSigners = [
  "council-regulator",
  "council-procuring-entity",
  "council-auditor",
].map((r) => new Wallet(account(r).privateKey, provider));

const govAsCouncil = gov.contract.connect(councilSigners[0]);
const ACTIVATE_VERIFIER_VERSION = 3; // Governance.ActionType
const proposeTx = await govAsCouncil.propose(
  ACTIVATE_VERIFIER_VERSION,
  payload,
  "activate eligibility verifier v1 from the published phase-2 ceremony",
  { gasPrice: 0 },
);
await proposeTx.wait();
const proposalId = await gov.contract.proposalCount();
console.log(`  proposal ${proposalId} created`);

for (const s of councilSigners.slice(1)) {
  await (await gov.contract.connect(s).approve(proposalId, { gasPrice: 0 })).wait();
}
const status = await gov.contract.executionStatus(proposalId);
console.log(`  approvals ${status[1]}/${status[2]}, executable at ${status[3]}`);

// The timelock is a real wait. Reported rather than silently slept through,
// because "we waited out the timelock" is part of what the deployment shows.
const timelock = await gov.contract.TIMELOCK_SECONDS();
console.log(`  waiting out the ${timelock}s timelock ...`);
for (;;) {
  const now = (await provider.getBlock("latest")).timestamp;
  if (BigInt(now) >= status[3]) break;
  await new Promise((r) => setTimeout(r, 3000));
}
await (await govAsCouncil.execute(proposalId, { gasPrice: 0 })).wait();

const sample = {
  a: fixture.pA.map(BigInt),
  b: fixture.pB.map((row) => row.map(BigInt)),
  c: fixture.pC.map(BigInt),
  signals: fixture.publicSignals.map(BigInt),
};
const regTx = await ev.contract
  .connect(councilSigners[0])
  .registerVerifier(proposalId, registration, sample, { gasPrice: 0 });
const regReceipt = await regTx.wait();
console.log(
  `  registered v1 -> ${groth.address}  (${regReceipt.gasUsed.toLocaleString()} gas)`,
);
if (!(await ev.contract.isVersionRegistered(1))) {
  throw new Error("verifier version 1 did not register");
}
console.log(`  vkeyHash   ${vkeyHash}`);
console.log(`  sourceHash ${sourceHash}`);

const identityGroth = await deploy(
  "IdentityGroth16",
  artifact("contracts/verifiers/WinnerIdentityVerifierGroth16.sol/WinnerIdentityVerifierGroth16.json"),
);
const identityTranscript = JSON.parse(
  readFileSync(
    join(repoRoot, "packages/circuits/ceremony/winner_identity.transcript.json"),
    "utf8",
  ),
);
const wi = await deploy(
  "WinnerIdentity",
  artifact("contracts/WinnerIdentity.sol/WinnerIdentity.json"),
  [
    tr.address,
    reg.address,
    sb.address,
    am.address,
    identityGroth.address,
    1,
    "0x" + identityTranscript.verificationKey.sha256,
    "packages/circuits/ceremony/winner_identity.transcript.json",
  ],
  // Only arity-2 Poseidon: spec Section 23 nests two arity-2 hashes rather
  // than using one arity-3, so no PoseidonT6 link.
  { PoseidonT3: t3.address },
);

const be = await deploy(
  "BondEscrow",
  artifact("contracts/BondEscrow.sol/BondEscrow.json"),
  [gov.address, tr.address, sb.address],
);
const ca = await deploy(
  "CheckpointAnchor",
  artifact("contracts/CheckpointAnchor.sol/CheckpointAnchor.json"),
  [gov.address, cfg.chainId],
);

// The bank adapter is a MOCK. The authoritative guarantee remains a bank
// instrument; this contract records status and holds no value.
console.log("\nbond adapter:");
await (await be.contract.connect(councilSigner).setBankAdapter(
  account("bank-adapter").address,
  true,
  "mock bank adapter for the demonstration; the authoritative guarantee remains a bank instrument",
  { gasPrice: 0 },
)).wait();
console.log(`  BondEscrow.bankAdapter -> ${account("bank-adapter").address}`);

const out = {
  chainId: cfg.chainId,
  deployedAt: (await provider.getBlock("latest")).number,
  deployer: deployer.address,
  minReviewWindow: MIN_REVIEW_WINDOW,
  initialRevocationRoot: { epoch: currentEpoch.toString(), root: emptyRoot },
  libraries: libs,
  contracts: {
    Governance: gov.address,
    IssuerRegistry: reg.address,
    TenderRegistry: tr.address,
    EligibilityVerifier: ev.address,
    EligibilityVerifierGroth16: groth.address,
    SealedBid: sb.address,
    OpeningManager: om.address,
    DeadlineStatus: ds.address,
    AwardManager: am.address,
    WinnerIdentity: wi.address,
    BondEscrow: be.address,
    CheckpointAnchor: ca.address,
    WinnerIdentityVerifierGroth16: identityGroth.address,
    AwardVerifierGroth16: awardGroth.address,
  },
  replicas: [1, 2, 3].map((id) => ({
    replicaId: id,
    url: `http://127.0.0.1:${8100 + id}`,
    address: account(`replica-${id}`).address,
  })),
  council: councilAddrs,
  awardVerifier: {
    circuitVersion: 1,
    impl: awardGroth.address,
    vkeyHash: "0x" + awardTranscript.verificationKey.sha256,
    transcriptUri: "packages/circuits/ceremony/award.transcript.json",
  },
  verifierVersions: {
    1: {
      impl: groth.address,
      vkeyHash,
      sourceHash,
      transcriptUri,
      proposalId: proposalId.toString(),
    },
  },
};
writeFileSync(join(repoRoot, "deployments.json"), JSON.stringify(out, null, 2));
console.log(`\ndeployments.json written (block ${out.deployedAt})`);
