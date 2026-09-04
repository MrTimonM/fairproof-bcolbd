#!/usr/bin/env node
/**
 * Fetch and verify the phase-1 powers-of-tau file.
 *
 * We deliberately do not generate our own phase 1: this is the published Hermez
 * ceremony, and `ceremony/ptau.json` pins its sha256 so the download can be
 * checked against a value committed to this repository rather than trusted.
 *
 *   npm run setup:ptau
 */
import { createHash } from "node:crypto";
import { createWriteStream, existsSync, mkdirSync, readFileSync, statSync, createReadStream, rmSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const meta = JSON.parse(readFileSync(join(root, "packages/circuits/ceremony/ptau.json"), "utf8"));
const dir = join(root, "packages/circuits/ptau");
const dest = join(dir, meta.name);

const sha256 = (file) =>
  new Promise((res, rej) => {
    const h = createHash("sha256");
    createReadStream(file).on("data", (d) => h.update(d)).on("end", () => res(h.digest("hex"))).on("error", rej);
  });

mkdirSync(dir, { recursive: true });

if (existsSync(dest)) {
  process.stdout.write(`${meta.name} already present, verifying ... `);
  const got = await sha256(dest);
  if (got === meta.sha256) {
    console.log("sha256 matches. Nothing to do.");
    process.exit(0);
  }
  console.log("MISMATCH — re-downloading.");
  rmSync(dest);
}

console.log(`downloading ${meta.name}`);
console.log(`  from ${meta.url}`);
console.log(`  ~145 MB, once only\n`);

const res = await fetch(meta.url);
if (!res.ok) {
  console.error(`download failed: HTTP ${res.status}`);
  process.exit(1);
}
const total = Number(res.headers.get("content-length") ?? 0);
let seen = 0;
let lastShown = 0;
const body = Readable.fromWeb(res.body);
body.on("data", (c) => {
  seen += c.length;
  const pct = total ? Math.floor((seen / total) * 100) : 0;
  if (pct >= lastShown + 5) {
    lastShown = pct;
    process.stdout.write(`\r  ${pct}%`);
  }
});
await pipeline(body, createWriteStream(dest));
process.stdout.write("\r  100%\n");

process.stdout.write("verifying sha256 ... ");
const got = await sha256(dest);
if (got !== meta.sha256) {
  console.log("MISMATCH");
  console.error(`  expected ${meta.sha256}`);
  console.error(`  got      ${got}`);
  console.error("\nRefusing to keep a file that is not the pinned ceremony output.");
  rmSync(dest);
  process.exit(1);
}
console.log("matches the pinned value.");
console.log(`\n${(statSync(dest).size / 1048576).toFixed(0)} MB written to packages/circuits/ptau/`);
console.log("next: npm run setup:circuits");
