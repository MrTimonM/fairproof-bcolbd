#!/usr/bin/env node
/**
 * Check that this machine can actually build and run FairProof.
 *
 * Four of the prerequisites are not npm packages and will not be installed by
 * `npm ci`: Docker, the circom compiler, a 145 MB powers-of-tau file, and the
 * phase-2 ceremony output. A clone that skips any of them fails deep inside a
 * build with an error that does not name the cause, so this names it up front.
 *
 *   npm run doctor
 */
import { execFileSync } from "node:child_process";
import { existsSync, statSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
let fail = 0;
let warn = 0;

const ok = (what, detail = "") => console.log(`  \x1b[32mOK\x1b[0m    ${what}${detail ? `  ${detail}` : ""}`);
const bad = (what, fix) => {
  fail++;
  console.log(`  \x1b[31mMISS\x1b[0m  ${what}`);
  if (fix) console.log(`        \x1b[2m-> ${fix}\x1b[0m`);
};
const soft = (what, fix) => {
  warn++;
  console.log(`  \x1b[33mTODO\x1b[0m  ${what}`);
  if (fix) console.log(`        \x1b[2m-> ${fix}\x1b[0m`);
};

const version = (cmd, args = ["--version"]) => {
  try {
    return execFileSync(cmd, args, { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim().split("\n")[0];
  } catch {
    return null;
  }
};

console.log("\nFairProof — environment check\n");
console.log("[tools]");

const nodeMajor = Number(process.versions.node.split(".")[0]);
if (nodeMajor >= 20) ok("node >= 20", `v${process.versions.node}`);
else bad(`node is v${process.versions.node}, needs >= 20`, "install Node 20 or newer (see .nvmrc)");

const docker = version("docker");
if (docker) ok("docker", docker);
else bad("docker is not installed", "the four-validator network runs in containers");

let compose = version("docker", ["compose", "version"]);
if (compose) ok("docker compose", compose);
else bad("docker compose (v2) is not available", "install the docker-compose-v2 plugin");

const circom = version("circom");
if (circom) {
  if (/2\./.test(circom)) ok("circom 2.x", circom);
  else bad(`circom reports "${circom}", needs 2.x`, "https://docs.circom.io/getting-started/installation/");
} else {
  bad("circom is not on PATH", "a Rust binary, not an npm package: https://docs.circom.io/getting-started/installation/");
}

console.log("\n[workspace]");
if (existsSync(join(root, "node_modules"))) ok("dependencies installed");
else bad("node_modules is missing", "npm ci");

if (existsSync(join(root, "packages/crypto/dist"))) ok("@fairproof/crypto is built");
else soft("@fairproof/crypto is not built", "npm run crypto:build");

console.log("\n[circuit artifacts]");
const ptauMeta = JSON.parse(readFileSync(join(root, "packages/circuits/ceremony/ptau.json"), "utf8"));
const ptau = join(root, "packages/circuits/ptau", ptauMeta.name);
if (existsSync(ptau)) {
  const mb = (statSync(ptau).size / 1048576).toFixed(0);
  ok(`phase-1 powers of tau`, `${ptauMeta.name}, ${mb} MB`);
} else {
  soft(`${ptauMeta.name} is missing (145 MB)`, "npm run setup:ptau");
}

const built = [
  ["eligibility", "packages/circuits/build/eligibility/eligibility_final.zkey"],
  ["award", "packages/circuits/build/award/award_final.zkey"],
  ["winner_identity", "packages/circuits/build/winner_identity/winner_identity_final.zkey"],
];
let missingZkeys = 0;
for (const [name, rel] of built) {
  if (existsSync(join(root, rel))) ok(`${name} proving key`);
  else {
    missingZkeys++;
    soft(`${name} proving key is missing`, "npm run setup:circuits");
  }
}

console.log("\n[deployment]");
if (existsSync(join(root, "deployments.json"))) ok("contracts deployed", "deployments.json present");
else soft("no deployment yet", "npm run network:up && npm run deploy");

if (existsSync(join(root, "apps/dashboard/src/generated/contracts.json"))) ok("dashboard config generated");
else soft("dashboard config not generated", "npm run dashboard:sync");

console.log("");
if (fail) {
  console.log(`\x1b[31m${fail} required tool(s) missing.\x1b[0m Install those first; the TODO items are build steps.`);
  process.exit(1);
}
if (warn) {
  console.log(`\x1b[33mTools are fine. ${warn} build step(s) still to run\x1b[0m — see SETUP.md, or run: npm run setup`);
  process.exit(0);
}
console.log("\x1b[32mReady.\x1b[0m Everything a local run needs is in place.");
