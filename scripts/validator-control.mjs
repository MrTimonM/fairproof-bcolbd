#!/usr/bin/env node
/**
 * Stop and start individual validators. Development plan Section 7.4.
 *
 * Used by the failure-injection test and by the demo: whitepaper Section 9.2
 * claims four validators "tolerate one faulty or malicious institution", and
 * this is how that claim gets demonstrated rather than asserted.
 *
 *   node scripts/validator-control.mjs stop  --id 3
 *   node scripts/validator-control.mjs start --id 3
 */
import { execFileSync } from "node:child_process";

const [action, ...rest] = process.argv.slice(2);
const idIdx = rest.findIndex((a) => a === "--id");
const id = idIdx >= 0 ? rest[idIdx + 1] : rest[0];

if (!["stop", "start", "restart"].includes(action) || !id) {
  console.error("usage: validator-control.mjs <stop|start|restart> --id <1-4>");
  process.exit(2);
}
if (!/^[1-4]$/.test(id)) {
  console.error(`invalid validator id: ${id} (expected 1-4)`);
  process.exit(2);
}

const container = `fairproof-validator-${id}`;
execFileSync("docker", [action, container], { stdio: "inherit" });
console.log(`${container}: ${action} complete`);
