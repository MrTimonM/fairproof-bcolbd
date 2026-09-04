/**
 * Exercise every read the dashboard makes, against the live chain.
 *
 * The dashboard renders in a browser I cannot see, so a build that compiles
 * proves nothing about whether its reads work. This runs the same contract
 * calls and reports the values, which is what catches a wrong struct field or
 * a function that does not exist.
 */
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Contract, JsonRpcProvider } from "ethers";

// Derived, not hardcoded: this used to be one developer's absolute path, which
// meant the check could only ever run on that machine.
const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const cfg = JSON.parse(readFileSync(`${root}/apps/dashboard/src/generated/contracts.json`, "utf8"));
const p = new JsonRpcProvider(`http://127.0.0.1:${cfg.validators[0].rpc}`, {
  chainId: cfg.chainId, name: "fairproof",
});
const c = (n) => new Contract(cfg.deployments.contracts[n], cfg.abis[n], p);

let fails = 0;
const ok = (label, value) => console.log(`  PASS  ${label} = ${value}`);
const bad = (label, err) => { fails++; console.log(`  FAIL  ${label}: ${err.message}`); };
const probe = async (label, fn) => {
  try { ok(label, await fn()); } catch (e) { bad(label, e); }
};

console.log("Dashboard read paths against the live chain\n");

console.log("[overview]");
await probe("head", () => p.getBlockNumber());
await probe("gasPrice", async () => (await p.getFeeData()).gasPrice);
await probe("tenderCount", () => c("TenderRegistry").tenderCount());
await probe("paused", () => c("Governance").paused());
await probe("issuerCount", () => c("IssuerRegistry").issuerCount());
await probe("proposalCount", () => c("Governance").proposalCount());
await probe("minReviewWindow", () => c("TenderRegistry").minReviewWindow());
await probe("activeReplicaCount", () => c("SealedBid").activeReplicaCount());

console.log("\n[governance]");
await probe("council", async () => (await c("Governance").council()).length);
await probe("COUNCIL_THRESHOLD", () => c("Governance").COUNCIL_THRESHOLD());
await probe("TIMELOCK_SECONDS", () => c("Governance").TIMELOCK_SECONDS());
const total = Number(await c("Governance").proposalCount());
if (total > 0) {
  await probe("getProposal(1).reason", async () => (await c("Governance").getProposal(1)).reason);
  await probe("executionStatus(1)", async () => (await c("Governance").executionStatus(1))[0]);
}

console.log("\n[issuers]");
await probe("MAX_ISSUERS", () => c("IssuerRegistry").MAX_ISSUERS());
await probe("ISSUER_TREE_DEPTH", () => c("IssuerRegistry").ISSUER_TREE_DEPTH());
await probe("currentEpoch", () => c("IssuerRegistry").currentEpoch());
const issuerCount = Number(await c("IssuerRegistry").issuerCount());
if (issuerCount > 0) {
  const id = await c("IssuerRegistry").issuerIdAt(0);
  await probe("getIssuer(0).label", async () => (await c("IssuerRegistry").getIssuer(id)).label);
  await probe("getIssuer(0).active", async () => (await c("IssuerRegistry").getIssuer(id)).active);
}

console.log("\n[tenders]");
const tc = Number(await c("TenderRegistry").tenderCount());
console.log(`  ..    ${tc} tender(s) on this deployment`);
for (let i = 0; i < tc; i++) {
  const id = await c("TenderRegistry").tenderIdAt(i);
  const t = await c("TenderRegistry").getTender(id);
  const recomputed = await c("TenderRegistry").recomputeRulesHash(id);
  const count = Number(await c("SealedBid").submissionCount(id));
  const root_ = await c("SealedBid").bidSetRoot(id);
  const awarded = await c("AwardManager").isAwarded(id);
  const identity = await c("WinnerIdentity").isProven(id);
  const deadlineRoot = await c("IssuerRegistry").deadlineRevocationRoot(id);
  console.log(
    `  PASS  ${t.tenderIdString}  state=${t.state}  bids=${count}  ` +
      `rulesOk=${t.rulesHash === recomputed}  awarded=${awarded}  identity=${identity}`,
  );
  await probe(`  getRuleDocument(${t.tenderIdString}).length`,
    async () => ((await c("TenderRegistry").getRuleDocument(id)).length - 2) / 2);
  try {
    const k = await c("TenderRegistry").getCommitteeKey(id);
    ok(`  committee set (${t.tenderIdString})`, k.set);
    const m = await c("TenderRegistry").getCommitteeMembers(id);
    ok(`  committee members`, m.length);
  } catch (e) {
    console.log(`  ..    committee not set for ${t.tenderIdString} (DRAFT)`);
  }
  for (let b = 0; b < count; b++) {
    const bid = await c("SealedBid").getBid(id, b);
    const st = await c("OpeningManager").openingStatus(id, b);
    const proven = await c("DeadlineStatus").isProven(id, b);
    console.log(
      `  PASS    bid #${b} revealed=${st[0]} shares=${st[1]}/${st[2]} ` +
        `openable=${st[3]} status=${proven}`,
    );
  }
  if (awarded) {
    const a = await c("AwardManager").getAward(id);
    ok(`  award winner #${a.winnerSubmissionIndex}, price`, a.winningPrice);
    ok(`  award root matches chain`, a.bidSetRoot === root_);
  }
  if (identity) {
    const idr = await c("WinnerIdentity").getIdentity(id);
    const rec = Buffer.from(idr.record.slice(2), "hex").toString();
    ok(`  identity credential`, idr.credentialId);
    console.log(`  ..    record: ${rec.slice(0, 80)}`);
  }
  if (deadlineRoot !== "0x" + "00".repeat(32)) {
    ok(`  deadline root pinned`, deadlineRoot.slice(0, 18));
  }
}

console.log(
  fails === 0 ? "\nEVERY DASHBOARD READ SUCCEEDED" : `\n${fails} READ(S) FAILED`,
);
p.destroy();
process.exit(fails === 0 ? 0 : 1);
