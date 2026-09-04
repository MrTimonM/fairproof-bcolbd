#!/usr/bin/env node
/**
 * fairproof-verify — check an evidence bundle from scratch.
 *
 *   npm run verify -- evidence/fairproof-evidence-FP-00014-...json
 *   npm run verify -- <bundle> --rpc=http://127.0.0.1:8545
 *
 * Exits non-zero on any failure. Every line prints the value the verifier
 * derived, because a PASS with no derived value is indistinguishable from a
 * check that did nothing.
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { verifyBundle } from "./verify.mjs";

const args = process.argv.slice(2);
const path = args.find((a) => !a.startsWith("--"));
const rpcArg = args.find((a) => a.startsWith("--rpc"));
const rpcUrl = rpcArg ? rpcArg.replace(/^--rpc=?/, "") || undefined : undefined;
const quiet = args.includes("--quiet");

if (!path) {
  console.error(
    [
      "usage: fairproof-verify <bundle.json> [--rpc=URL] [--quiet]",
      "",
      "Consumes only the evidence bundle. Pass --rpc to additionally confirm",
      "the bundle describes a real chain's history.",
    ].join("\n"),
  );
  process.exit(2);
}

const raw = readFileSync(path);
const bundle = JSON.parse(raw.toString("utf8"));
const sha = createHash("sha256").update(raw).digest("hex");

const bold = (s) => `\x1b[1m${s}\x1b[0m`;
const dim = (s) => `\x1b[2m${s}\x1b[0m`;
const green = (s) => `\x1b[32m${s}\x1b[0m`;
const red = (s) => `\x1b[31m${s}\x1b[0m`;
const amber = (s) => `\x1b[33m${s}\x1b[0m`;

if (!quiet) {
  console.log(bold("FairProof independent verifier"));
  console.log(`bundle    ${path}`);
  console.log(`sha256    ${sha}`);
  console.log(`version   ${bundle.bundleVersion}`);
  console.log(
    `describes chain ${bundle.generatedFrom.chainId} at block ${bundle.generatedFrom.blockNumber}`,
  );
  console.log(`tender    ${bundle.tender.tenderIdString}`);
  console.log(
    dim(
      "\nEvery check below is re-derived from the bundle. Nothing is taken from\n" +
        "a dashboard, a database, or the party that produced this file.\n",
    ),
  );
}

const report = await verifyBundle(bundle, { rpcUrl });

for (const c of report.checks) {
  const tag =
    c.ok === true ? green("PASS") : c.ok === false ? red("FAIL") : amber("SKIP");
  console.log(`${tag}  ${String(c.id).padEnd(5)} ${c.claim}`);
  if (c.derived) console.log(`            ${dim(String(c.derived))}`);
  if (c.note) console.log(`            ${dim(c.note)}`);
}

const failed = report.failures.length;
console.log("");
if (failed === 0) {
  console.log(
    green(bold("BUNDLE VERIFIED")) +
      `  ${report.passed} check(s) passed, ${report.skipped} skipped`,
  );
  if (report.skipped > 0) {
    console.log(
      dim(
        "Skipped checks are stated, not hidden — read them. A skip means the\n" +
          "artefact does not exist yet, not that the check succeeded.",
      ),
    );
  }
} else {
  console.log(
    red(bold(`${failed} CHECK(S) FAILED`)) + `  ${report.passed} passed, ${report.skipped} skipped`,
  );
  for (const c of report.failures) {
    console.log(red(`  ${c.id}: ${c.claim}`));
    if (c.note) console.log(`      ${c.note}`);
  }
}

process.exit(failed === 0 ? 0 : 1);
