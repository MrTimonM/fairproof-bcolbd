#!/usr/bin/env node
/**
 * Network health check. Development plan Section 7.3.
 *
 * Verifies the acceptance tests a reviewer would run: all nodes up, the
 * expected chain ID, an identical genesis hash, the QBFT validator set
 * visible, blocks advancing, and every node agreeing on head.
 *
 * Exits non-zero on failure so CI and `doctor` can depend on it.
 */
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "..");
const cfg = JSON.parse(
  readFileSync(join(repoRoot, "infrastructure/besu/config/accounts.json"), "utf8"),
);

const EXPECTED_CHAIN_ID = cfg.chainId;
const VALIDATORS = cfg.validators;
const EXPECTED_VALIDATOR_COUNT = VALIDATORS.length;

let failures = 0;
function check(ok, label, detail = "") {
  console.log(`  ${ok ? "PASS" : "FAIL"}  ${label}${detail ? ` - ${detail}` : ""}`);
  if (!ok) failures++;
  return ok;
}

async function rpc(port, method, params = []) {
  const res = await fetch(`http://127.0.0.1:${port}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", method, params, id: 1 }),
    signal: AbortSignal.timeout(8000),
  });
  const body = await res.json();
  if (body.error) throw new Error(`${method}: ${body.error.message}`);
  return body.result;
}

console.log("FairProof network health\n");

// 1. Every node reachable, with the expected chain ID and genesis hash.
const heads = [];
const genesisHashes = [];
for (const v of VALIDATORS) {
  console.log(`validator-${v.id} (${v.label}) :${v.rpc}`);
  try {
    const chainId = Number(await rpc(v.rpc, "eth_chainId"));
    check(chainId === EXPECTED_CHAIN_ID, "chain id", `${chainId}`);

    const genesis = await rpc(v.rpc, "eth_getBlockByNumber", ["0x0", false]);
    genesisHashes.push(genesis.hash);

    const head = Number(await rpc(v.rpc, "eth_blockNumber"));
    heads.push(head);
    check(true, "reachable", `head ${head}`);

    const peers = Number(await rpc(v.rpc, "net_peerCount"));
    check(peers >= 1, "peers", `${peers}`);
  } catch (err) {
    check(false, "reachable", err.message);
    heads.push(null);
    genesisHashes.push(null);
  }
  console.log();
}

// 2. Genesis hash identical everywhere: they really are one chain.
const live = genesisHashes.filter(Boolean);
console.log("network");
check(
  live.length > 0 && new Set(live).size === 1,
  "identical genesis hash across live nodes",
  live[0]?.slice(0, 18),
);

// 3. QBFT validator set visible and complete.
let validatorSet = [];
try {
  const firstLive = VALIDATORS.find((_, i) => heads[i] !== null);
  validatorSet = await rpc(firstLive.rpc, "qbft_getValidatorsByBlockNumber", ["latest"]);
  check(
    validatorSet.length === EXPECTED_VALIDATOR_COUNT,
    "QBFT validator set complete",
    `${validatorSet.length}/${EXPECTED_VALIDATOR_COUNT}`,
  );
} catch (err) {
  check(false, "QBFT validator set", err.message);
}

// 4. Blocks are advancing. QBFT gives immediate finality, so a rising head
//    means finalized blocks, not probabilistic ones (whitepaper Table 6).
const firstLive = VALIDATORS.find((_, i) => heads[i] !== null);
if (firstLive) {
  const before = Number(await rpc(firstLive.rpc, "eth_blockNumber"));
  await new Promise((r) => setTimeout(r, 6000));
  const after = Number(await rpc(firstLive.rpc, "eth_blockNumber"));
  check(after > before, "blocks advancing", `${before} -> ${after}`);
}

// 5. Live nodes agree on head, within one block of drift.
const liveHeads = heads.filter((h) => h !== null);
check(
  liveHeads.length > 0 && Math.max(...liveHeads) - Math.min(...liveHeads) <= 1,
  "live nodes agree on head",
  `spread ${Math.max(...liveHeads) - Math.min(...liveHeads)}`,
);

// 6. Byzantine fault tolerance headroom.
//    QBFT tolerates floor((n-1)/3) faulty validators (whitepaper Section 9.2).
const n = EXPECTED_VALIDATOR_COUNT;
const tolerated = Math.floor((n - 1) / 3);
const down = heads.filter((h) => h === null).length;
check(
  down <= tolerated,
  "faulty validators within QBFT tolerance",
  `${down} down, ${tolerated} tolerated (n=${n})`,
);

console.log(`\n${failures === 0 ? "HEALTHY" : `${failures} CHECK(S) FAILED`}`);
process.exit(failures === 0 ? 0 : 1);
