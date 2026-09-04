#!/usr/bin/env node
/**
 * Export a tender's evidence bundle.
 *
 *   npm run evidence -- --all                   (every tender on the chain)
 *   npm run evidence -- FP-00014-...            (one, by id string or 0x id)
 *
 * Writes to ./evidence/. Determinism is asserted rather than assumed: the
 * bundle is generated twice at the same block and the two serialisations are
 * compared, because "deterministic" is a claim that is easy to make and easy
 * to break with one unordered iteration.
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Contract, JsonRpcProvider, keccak256, toUtf8Bytes } from "ethers";
import {
  assertNoSecrets,
  bundleFilename,
  exportBundle,
  serialise,
} from "../services/evidence/src/bundle.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "..");
const outDir = join(repoRoot, "evidence");

const args = process.argv.slice(2);
const all = args.includes("--all");
const rpcArg = args.find((a) => a.startsWith("--rpc="));
const rpcUrl = rpcArg ? rpcArg.slice("--rpc=".length) : undefined;
const idArg = args.find((a) => !a.startsWith("--"));

const cfg = JSON.parse(
  readFileSync(join(repoRoot, "infrastructure/besu/config/accounts.json"), "utf8"),
);
const dep = JSON.parse(readFileSync(join(repoRoot, "deployments.json"), "utf8"));

async function tenderIds() {
  const provider = new JsonRpcProvider(
    rpcUrl ?? `http://127.0.0.1:${cfg.validators[0].rpc}`,
    { chainId: cfg.chainId, name: "fairproof" },
  );
  const abi = JSON.parse(
    readFileSync(
      join(
        repoRoot,
        "packages/contracts/artifacts/contracts/TenderRegistry.sol/TenderRegistry.json",
      ),
      "utf8",
    ),
  ).abi;
  const tr = new Contract(dep.contracts.TenderRegistry, abi, provider);
  const count = Number(await tr.tenderCount());
  const ids = [];
  for (let i = 0; i < count; i++) ids.push(await tr.tenderIdAt(i));
  provider.destroy();
  return ids;
}

let targets;
if (all || !idArg) {
  targets = await tenderIds();
  if (targets.length === 0) {
    console.error("no tenders on this chain. Run `npm run seed` first.");
    process.exit(1);
  }
} else {
  targets = [idArg.startsWith("0x") ? idArg : keccak256(toUtf8Bytes(idArg))];
}

mkdirSync(outDir, { recursive: true });
console.log(`exporting ${targets.length} evidence bundle(s)\n`);

for (const tenderId of targets) {
  const bundle = await exportBundle({ repoRoot, tenderId, rpcUrl });
  assertNoSecrets(bundle);

  const once = serialise(bundle);
  const twice = serialise(
    await exportBundle({
      repoRoot,
      tenderId,
      rpcUrl,
      atBlock: bundle.generatedFrom.blockNumber,
    }),
  );
  if (once !== twice) {
    console.error(
      `NOT DETERMINISTIC for ${bundle.tender.tenderIdString}: two exports at the ` +
        `same block differ. Something depends on wall-clock time or on an ` +
        `unordered iteration.`,
    );
    process.exit(1);
  }

  const name = bundleFilename(bundle);
  writeFileSync(join(outDir, name), once);
  console.log(`  ${name}`);
  console.log(
    `    ${(once.length / 1024).toFixed(1)} kB · block ${bundle.generatedFrom.blockNumber} · ` +
      `${bundle.acceptedBids.length} bid(s) · ${bundle.opening.length} share(s) · ` +
      `award ${bundle.award ? "present" : "none"} · identity ${bundle.identityLinkage ? "present" : "none"}`,
  );
  console.log(`    two exports at the same block are byte-identical`);
  console.log(`    check it with:  npm run verify -- evidence/${name}\n`);
}
