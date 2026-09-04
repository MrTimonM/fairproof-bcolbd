#!/usr/bin/env node
/**
 * Deploy smoke test against the live permissioned network.
 * Development plan Section 7.3: "A transaction is finalized and visible from
 * all active nodes."
 *
 * Also demonstrates the zero-gas-price property: transactions are sent with
 * gasPrice 0, so a fresh address needs no funding at all. That is what removes
 * the wallet-funding correlation channel of whitepaper Table 4.
 */
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { JsonRpcProvider, Wallet, ContractFactory, Contract } from "ethers";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "../..");
const cfg = JSON.parse(
  readFileSync(join(repoRoot, "infrastructure/besu/config/accounts.json"), "utf8"),
);
const artifact = JSON.parse(
  readFileSync(
    join(repoRoot, "packages/contracts/artifacts/contracts/test/Ping.sol/Ping.json"),
    "utf8",
  ),
);

let failures = 0;
const check = (ok, label, detail = "") => {
  console.log(`  ${ok ? "PASS" : "FAIL"}  ${label}${detail ? ` - ${detail}` : ""}`);
  if (!ok) failures++;
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

console.log("Deploy smoke test against the permissioned network\n");

const deployer = cfg.accounts.find((a) => a.role === "deployer");
const provider = new JsonRpcProvider(`http://127.0.0.1:${cfg.validators[0].rpc}`, {
  chainId: cfg.chainId,
  name: "fairproof",
});
const wallet = new Wallet(deployer.privateKey, provider);

// 1. Deploy.
const factory = new ContractFactory(artifact.abi, artifact.bytecode, wallet);
const ping = await factory.deploy({ gasPrice: 0 });
const receipt = await ping.deploymentTransaction().wait();
const address = await ping.getAddress();
check(!!address, "contract deployed", address);
check(receipt.status === 1, "deployment transaction succeeded", `block ${receipt.blockNumber}`);
check(receipt.gasPrice === 0n, "zero gas price honoured", `gasPrice ${receipt.gasPrice}`);

// 2. Send a state-changing transaction.
const tx = await ping.ping({ gasPrice: 0 });
const pingReceipt = await tx.wait();
check(pingReceipt.status === 1, "state-changing transaction finalized", `block ${pingReceipt.blockNumber}`);
check(pingReceipt.logs.length === 1, "event emitted");

// 3. The same finalized state must be visible from EVERY node. That is the
//    point of a permissioned chain with immediate finality: no node holds a
//    different view of the award record.
for (const v of cfg.validators) {
  try {
    const p = new JsonRpcProvider(`http://127.0.0.1:${v.rpc}`, {
      chainId: cfg.chainId,
      name: "fairproof",
    });
    const deadline = Date.now() + 30000;
    let head = 0;
    while (Date.now() < deadline) {
      head = await p.getBlockNumber();
      if (head >= pingReceipt.blockNumber) break;
      await sleep(1000);
    }
    const readOnly = new Contract(address, artifact.abi, p);
    const count = await readOnly.count();
    check(count === 1n, `count == 1 from validator-${v.id} (${v.label})`, `head ${head}`);
  } catch (err) {
    check(false, `readable from validator-${v.id}`, err.message);
  }
}

// 4. An unfunded fresh address can still transact, because gas is free.
//    The bidder-privacy property, tested rather than asserted.
const fresh = Wallet.createRandom().connect(provider);
const freshBalance = await provider.getBalance(fresh.address);
check(freshBalance === 0n, "fresh address has zero balance", fresh.address);
try {
  const freshPing = new Contract(address, artifact.abi, fresh);
  const ftx = await freshPing.ping({ gasPrice: 0 });
  const fr = await ftx.wait();
  check(fr.status === 1, "unfunded fresh address transacted successfully");
  console.log(
    "        (this is why a bidder can use a fresh per-tender address with no\n" +
      "         funding trail - whitepaper Table 4, metadata linkability)",
  );
} catch (err) {
  check(false, "unfunded fresh address transacted", err.message);
}

console.log(`\n${failures === 0 ? "NETWORK ACCEPTS TRANSACTIONS" : `${failures} CHECK(S) FAILED`}`);
process.exit(failures === 0 ? 0 : 1);
