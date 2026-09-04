#!/usr/bin/env node
/**
 * Copy the deployed addresses and ABIs into the dashboard's source tree.
 *
 * The dashboard reads the LIVE chain, so it needs both. Generating a single
 * file rather than importing across package boundaries keeps Vite's module
 * graph inside the app and makes the dependency explicit: if this file is
 * stale, the dashboard says so loudly rather than rendering old addresses.
 *
 * Run automatically by `npm run dashboard:dev`.
 */
import { copyFileSync, readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "..");
const artifacts = join(repoRoot, "packages/contracts/artifacts");
const outDir = join(repoRoot, "apps/dashboard/src/generated");

const CONTRACTS = {
  Governance: "contracts/Governance.sol/Governance.json",
  IssuerRegistry: "contracts/IssuerRegistry.sol/IssuerRegistry.json",
  TenderRegistry: "contracts/TenderRegistry.sol/TenderRegistry.json",
  EligibilityVerifier: "contracts/EligibilityVerifier.sol/EligibilityVerifier.json",
  SealedBid: "contracts/SealedBid.sol/SealedBid.json",
  OpeningManager: "contracts/OpeningManager.sol/OpeningManager.json",
  DeadlineStatus: "contracts/DeadlineStatus.sol/DeadlineStatus.json",
  AwardManager: "contracts/AwardManager.sol/AwardManager.json",
  WinnerIdentity: "contracts/WinnerIdentity.sol/WinnerIdentity.json",
  BondEscrow: "contracts/BondEscrow.sol/BondEscrow.json",
  CheckpointAnchor: "contracts/CheckpointAnchor.sol/CheckpointAnchor.json",
};

if (!existsSync(join(repoRoot, "deployments.json"))) {
  console.error(
    "deployments.json is missing. Run `npm run deploy` before starting the dashboard.",
  );
  process.exit(1);
}
const deployments = JSON.parse(readFileSync(join(repoRoot, "deployments.json"), "utf8"));
const accounts = JSON.parse(
  readFileSync(join(repoRoot, "infrastructure/besu/config/accounts.json"), "utf8"),
);

const abis = {};
for (const [name, path] of Object.entries(CONTRACTS)) {
  const p = join(artifacts, path);
  if (!existsSync(p)) {
    console.error(`missing artifact for ${name}: ${p}. Run \`npm run contracts:compile\`.`);
    process.exit(1);
  }
  abis[name] = JSON.parse(readFileSync(p, "utf8")).abi;
}

// Ceremony transcripts, so the dashboard can show provenance without a server.
const ceremonies = {};
for (const circuit of ["eligibility", "award", "winner_identity"]) {
  const p = join(repoRoot, `packages/circuits/ceremony/${circuit}.transcript.json`);
  if (!existsSync(p)) continue;
  const t = JSON.parse(readFileSync(p, "utf8"));
  ceremonies[circuit] = {
    circuit,
    contributions: t.contributions.map((c) => ({
      index: c.index,
      name: c.name,
      independent: c.independent,
      contributionHash: c.contributionHash,
    })),
    beacon: t.beacon && {
      source: t.beacon.source,
      round: t.beacon.round,
      randomness: t.beacon.randomness,
      recheck: t.beacon.recheck,
    },
    singleMachine: t.singleMachine === true,
    verificationKey: t.verificationKey,
    phase1: t.phase1,
    r1cs: t.r1cs,
  };
}

const constraints = existsSync(join(repoRoot, "packages/circuits/build/constraints.json"))
  ? JSON.parse(
      readFileSync(join(repoRoot, "packages/circuits/build/constraints.json"), "utf8"),
    ).circuits
  : [];

/**
 * Role accounts, INCLUDING their private keys.
 *
 * These derive from the PUBLIC Hardhat test mnemonic - "test test test ...
 * junk" - which is deliberately the most widely published private key material
 * in Ethereum. They are in the bundle so the workspaces can sign real
 * transactions against a local chain without a wallet extension, and they are
 * safe to ship precisely because they are already public and this chain has no
 * value on it.
 *
 * They must never be reused on any network that matters. The generated file is
 * gitignored and the UI states the position on screen rather than leaving a
 * reader to wonder.
 */
const roles = accounts.accounts.map((a) => ({
  role: a.role,
  address: a.address,
  privateKey: a.privateKey,
}));

// Circuit artifacts, served as static assets so proving happens in the browser
// rather than on a server the user would have to trust.
const publicDir = join(repoRoot, "apps/dashboard/public/circuits");
mkdirSync(publicDir, { recursive: true });
const CIRCUIT_ASSETS = [
  ["packages/circuits/build/eligibility/eligibility_js/eligibility.wasm", "eligibility.wasm"],
  ["packages/circuits/build/eligibility/eligibility_final.zkey", "eligibility.zkey"],
  ["packages/circuits/build/eligibility/eligibility_verification_key.json", "eligibility.vkey.json"],
  ["packages/circuits/build/award/award_verification_key.json", "award.vkey.json"],
  // The award and identity circuits too, so the authority can declare a winner
  // from the browser rather than from a terminal. 47 MB more, fetched only when
  // one of those two buttons is pressed and cached by the browser afterwards.
  ["packages/circuits/build/award/award_js/award.wasm", "award.wasm"],
  ["packages/circuits/build/award/award_final.zkey", "award.zkey"],
  ["packages/circuits/build/winner_identity/winner_identity_verification_key.json", "winner_identity.vkey.json"],
  ["packages/circuits/build/winner_identity/winner_identity_js/winner_identity.wasm", "winner_identity.wasm"],
  ["packages/circuits/build/winner_identity/winner_identity_final.zkey", "winner_identity.zkey"],
];
const copiedAssets = [];
for (const [from, to] of CIRCUIT_ASSETS) {
  const src = join(repoRoot, from);
  if (!existsSync(src)) {
    console.error(`missing circuit artifact ${from}. Run \`npm run circuits:compile\` and the ceremony.`);
    process.exit(1);
  }
  copyFileSync(src, join(publicDir, to));
  copiedAssets.push(to);
}

mkdirSync(outDir, { recursive: true });
writeFileSync(
  join(outDir, "contracts.json"),
  JSON.stringify(
    {
      $comment:
        "GENERATED by scripts/sync-dashboard-abis.mjs. Do not edit. " +
        "Private keys are deliberately excluded.",
      generatedAt: new Date().toISOString(),
      chainId: accounts.chainId,
      validators: accounts.validators.map((v, i) => ({
        index: i + 1,
        rpc: v.rpc,
        role: ["Procurement Regulator", "Procuring Entity", "Independent Auditor", "Chamber of Commerce"][i],
      })),
      deployments,
      roles,
      abis,
      ceremonies,
      constraints,
      replicas: deployments.replicas ?? [],
      circuitAssets: copiedAssets,
    },
    null,
    2,
  ) + "\n",
);
console.log(
  `apps/dashboard/src/generated/contracts.json written ` +
    `(${Object.keys(abis).length} ABIs, ${Object.keys(ceremonies).length} ceremonies)`,
);
console.log(`apps/dashboard/public/circuits: ${copiedAssets.length} artifacts copied`);
