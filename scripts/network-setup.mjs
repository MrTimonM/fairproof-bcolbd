#!/usr/bin/env node
/**
 * Generate the four-validator QBFT network material.
 *
 * Development plan Section 7. Produces validator keys, the genesis file, the
 * static-nodes list and the permissioned node allowlist.
 *
 * Validator keys are NEVER committed (plan Section 5.1). This script
 * regenerates them, so a clean clone runs `network:setup` before `network:up`.
 *
 * Role accounts come from the universally recognised Hardhat test mnemonic.
 * Using a well-known test mnemonic is deliberate: it is unmistakably not a
 * real key, which is safer than inventing our own and having someone treat it
 * as a secret.
 */
import { execFileSync } from "node:child_process";
import {
  cpSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { HDNodeWallet, Mnemonic } from "ethers";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "..");
const besuDir = join(repoRoot, "infrastructure/besu");
const configDir = join(besuDir, "config");
const nodesDir = join(besuDir, "nodes");
const workDir = join(besuDir, "networkFiles");

const BESU_IMAGE = "hyperledger/besu:25.7.0";
const CHAIN_ID = 20260;

/**
 * Validator identities. Whitepaper Section 9.2 names these four institutions.
 * They are SYNTHETIC PROTOTYPE ROLES, not claims of real participation - the
 * UI must say so (plan Section 7.2).
 */
/**
 * Static container IPs. Besu's static-nodes.json requires enode URLs with an
 * IP address; it rejects a container hostname outright. The compose file
 * assigns these same addresses on the `fairproof` bridge network, so the two
 * files must be kept in step.
 */
const SUBNET = "172.28.0.0/16";

const VALIDATORS = [
  { id: 1, label: "Procurement Regulator", rpc: 8545, p2p: 30303, ip: "172.28.0.11" },
  { id: 2, label: "Procuring Entity", rpc: 8546, p2p: 30304, ip: "172.28.0.12" },
  { id: 3, label: "Independent Auditor", rpc: 8547, p2p: 30305, ip: "172.28.0.13" },
  { id: 4, label: "Chamber of Commerce", rpc: 8548, p2p: 30306, ip: "172.28.0.14" },
];

/** Well-known test mnemonic. NOT a secret. Never use outside this prototype. */
const TEST_MNEMONIC =
  "test test test test test test test test test test test junk";

/**
 * Protocol role accounts, derived deterministically so every developer and
 * every demo run uses the same addresses.
 */
const ROLE_ACCOUNTS = [
  "deployer",
  "council-regulator",
  "council-procuring-entity",
  "council-auditor",
  "council-chamber",
  "tender-authority",
  "qualification-issuer",
  "committee-1",
  "committee-2",
  "committee-3",
  "committee-4",
  "committee-5",
  "replica-1",
  "replica-2",
  "replica-3",
  "bank-adapter",
];

function deriveRoleAccounts() {
  const mnemonic = Mnemonic.fromPhrase(TEST_MNEMONIC);
  return ROLE_ACCOUNTS.map((role, i) => {
    const wallet = HDNodeWallet.fromMnemonic(mnemonic, `m/44'/60'/0'/0/${i}`);
    return { role, index: i, address: wallet.address, privateKey: wallet.privateKey };
  });
}

function run(cmd, args) {
  return execFileSync(cmd, args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
}

console.log("FairProof network setup\n");

// 1. Generate validator keys and the QBFT genesis via the Besu operator.
if (existsSync(workDir)) rmSync(workDir, { recursive: true, force: true });
mkdirSync(configDir, { recursive: true });

console.log("generating validator keys and QBFT genesis ...");
// Run as the host user so generated keys are not root-owned.
const uid = typeof process.getuid === "function" ? process.getuid() : 0;
const gid = typeof process.getgid === "function" ? process.getgid() : 0;

run("docker", [
  "run", "--rm",
  "--user", `${uid}:${gid}`,
  "-v", `${besuDir}:/work`,
  "-w", "/work",
  BESU_IMAGE,
  "operator", "generate-blockchain-config",
  "--config-file=/work/qbft-config.json",
  "--to=/work/networkFiles",
  "--private-key-file-name=key",
]);

// 2. Prefund the role accounts.
//
// Note: with `zeroBaseFee` and a zero gas price, a zero-balance account can
// still transact. That is what lets a bidder use a fresh per-tender address
// with no funding at all, removing the wallet-funding correlation channel
// that whitepaper Table 4 lists as a residual metadata risk. The role
// accounts are prefunded only for convenience and legibility.
const accounts = deriveRoleAccounts();
const genesis = JSON.parse(readFileSync(join(workDir, "genesis.json"), "utf8"));
genesis.alloc = {};
for (const a of accounts) {
  genesis.alloc[a.address.slice(2).toLowerCase()] = {
    balance: "0x21e19e0c9bab2400000", // 10,000 units, purely cosmetic here
  };
}
writeFileSync(join(configDir, "genesis.json"), JSON.stringify(genesis, null, 2));
console.log(`genesis written: chainId ${genesis.config.chainId}, ${accounts.length} role accounts`);

// 3. Lay out the four node directories.
const keyDirs = readdirSync(join(workDir, "keys")).sort();
if (keyDirs.length !== VALIDATORS.length) {
  throw new Error(`expected ${VALIDATORS.length} validator keys, got ${keyDirs.length}`);
}

const enodes = [];
for (let i = 0; i < VALIDATORS.length; i++) {
  const v = VALIDATORS[i];
  const nodeDir = join(nodesDir, String(v.id));
  mkdirSync(nodeDir, { recursive: true });
  // Besu writes its chain data here. Created by this script so it is owned
  // by the host user; a docker named volume would be root-owned and Besu
  // would fail with "Data directory is not writable".
  mkdirSync(join(nodeDir, "data"), { recursive: true });
  cpSync(join(workDir, "keys", keyDirs[i], "key"), join(nodeDir, "key"));
  cpSync(join(workDir, "keys", keyDirs[i], "key.pub"), join(nodeDir, "key.pub"));

  const pub = readFileSync(join(nodeDir, "key.pub"), "utf8").trim().replace(/^0x/, "");
  // Besu requires an IP here, not a hostname.
  enodes.push(`enode://${pub}@${v.ip}:${v.p2p}`);

  writeFileSync(
    join(nodeDir, "identity.json"),
    JSON.stringify(
      {
        id: v.id,
        label: v.label,
        note: "Synthetic prototype role. Not a claim of real institutional participation.",
        validatorAddress: "0x" + keyDirs[i].replace(/^0x/, ""),
        rpcPort: v.rpc,
        p2pPort: v.p2p,
        ip: v.ip,
      },
      null,
      2,
    ),
  );
}

// 4. static-nodes.json - the peer list every node reads on startup.
writeFileSync(join(configDir, "static-nodes.json"), JSON.stringify(enodes, null, 2));

// 5. Permissioned node allowlist. Plan Section 7.1: node allowlist YES,
//    account allowlist NO - whitepaper Section 9.3 requires pseudonymous
//    bidders to be able to submit proof-valid transactions, and an account
//    allowlist would destroy that.
mkdirSync(join(besuDir, "permissions"), { recursive: true });
writeFileSync(
  join(besuDir, "permissions/permissions_config.toml"),
  [
    "# Permissioned NODE allowlist. Only these four validators may peer.",
    "#",
    "# There is deliberately NO accounts-allowlist. Whitepaper Section 9.3",
    "# requires that pseudonymous bidders and relayers may submit proof-valid",
    "# transactions; an account allowlist would destroy bidder pseudonymity",
    "# and contradict the fresh-per-tender-address mitigation of Table 4.",
    "# Administrative writes are gated by on-chain role, not by node config.",
    "",
    "nodes-allowlist=[",
    ...enodes.map((e) => `  "${e}",`),
    "]",
    "",
  ].join("\n"),
);

// 6. Write the account manifest for the app and deploy scripts.
writeFileSync(
  join(configDir, "accounts.json"),
  JSON.stringify(
    {
      warning:
        "Derived from the public Hardhat test mnemonic. NOT SECRET. " +
        "Prototype use only; never reuse on any real network.",
      mnemonic: TEST_MNEMONIC,
      chainId: CHAIN_ID,
      subnet: SUBNET,
      validators: VALIDATORS,
      accounts,
    },
    null,
    2,
  ),
);

rmSync(workDir, { recursive: true, force: true });

console.log(`nodes laid out:      ${VALIDATORS.map((v) => v.id).join(", ")}`);
console.log(`static-nodes.json:   ${enodes.length} peers`);
console.log(`node allowlist:      ${enodes.length} nodes (no account allowlist, by design)`);
console.log("\nnext: npm run network:up");
