#!/usr/bin/env node
/**
 * Compile every circuit and record its constraint count.
 *
 * The constraint report is a build artifact on purpose: whitepaper Table 15
 * commits to reporting the eligibility circuit's constraint count "exactly
 * from Circom's constraint report", and CI publishes it so growth is visible
 * per commit (development plan Section 20.7).
 */
import { execFileSync } from "node:child_process";
import {
  mkdirSync,
  readdirSync,
  readFileSync,
  writeFileSync,
  existsSync,
} from "node:fs";
import { dirname, join, resolve, basename } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const pkgRoot = resolve(here, "..");
const repoRoot = resolve(pkgRoot, "../..");
const buildDir = join(pkgRoot, "build");
const nodeModules = join(repoRoot, "node_modules");

/** Circuits to build: [source, label, isTestOnly] */
const TARGETS = [
  ["src/test/encoding_echo.circom", "encoding_echo", true],
];

// Discover production circuits as they are added, so this script does not
// need editing for each one.
const srcDir = join(pkgRoot, "src");
for (const f of readdirSync(srcDir)) {
  if (!f.endsWith(".circom")) continue;
  // Library files have no `component main`; only entry points are compiled.
  const body = readFileSync(join(srcDir, f), "utf8");
  if (body.includes("component main")) {
    TARGETS.push([`src/${f}`, basename(f, ".circom"), false]);
  }
}

mkdirSync(buildDir, { recursive: true });

const report = [];
for (const [src, label, testOnly] of TARGETS) {
  const srcPath = join(pkgRoot, src);
  if (!existsSync(srcPath)) {
    console.error(`skip ${label}: ${src} not found`);
    continue;
  }
  const outDir = join(buildDir, label);
  mkdirSync(outDir, { recursive: true });

  process.stdout.write(`compiling ${label} ... `);
  const output = execFileSync(
    "circom",
    [srcPath, "--r1cs", "--wasm", "--sym", "-o", outDir, "-l", nodeModules],
    { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
  );

  const num = (re) => {
    const m = output.match(re);
    return m ? Number(m[1]) : null;
  };
  const entry = {
    circuit: label,
    testOnly,
    nonLinearConstraints: num(/non-linear constraints:\s*(\d+)/),
    linearConstraints: num(/(?:^|\n)linear constraints:\s*(\d+)/),
    publicInputs: num(/public inputs:\s*(\d+)/),
    privateInputs: num(/private inputs:\s*(\d+)/),
    publicOutputs: num(/public outputs:\s*(\d+)/),
    wires: num(/wires:\s*(\d+)/),
  };
  report.push(entry);
  console.log(`${entry.nonLinearConstraints} non-linear constraints`);
}

writeFileSync(
  join(buildDir, "constraints.json"),
  JSON.stringify({ generatedBy: "circuits:compile", circuits: report }, null, 2),
);
console.log(`\nconstraint report: build/constraints.json`);
