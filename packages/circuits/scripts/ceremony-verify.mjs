#!/usr/bin/env node
/**
 * Independently re-check the published ceremony. Development plan 11B.1(5).
 *
 * The point of publishing a transcript is that a reviewer does not have to
 * take our word for anything, so this script trusts the transcript for
 * nothing except the claims it is checking. Every check names what it would
 * catch, because a verification script whose failures are uninterpretable is
 * only slightly better than no script.
 *
 * Run: npm run ceremony:verify [circuit] [--verify-phase1]
 *
 * Exit code 0 only if every check passes. `--verify-phase1` adds the full
 * phase-1 contribution-chain check, which takes several minutes and is
 * skipped by default so the fast checks stay usable in CI on every commit.
 */
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { exportVerifier } from "./export-verifier.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const pkgRoot = resolve(here, "..");
const repoRoot = resolve(pkgRoot, "../..");

const circuit = process.argv[2]?.startsWith("--") ? "eligibility" : process.argv[2] ?? "eligibility";
const verifyPhase1 = process.argv.includes("--verify-phase1");

const ceremonyDir = join(pkgRoot, "ceremony");
const buildDir = join(pkgRoot, "build", circuit);

let failures = 0;
let checks = 0;

function check(ok, label, detail = "") {
  checks++;
  if (ok) {
    console.log(`  PASS  ${label}${detail ? ` - ${detail}` : ""}`);
  } else {
    failures++;
    console.log(`  FAIL  ${label}${detail ? ` - ${detail}` : ""}`);
  }
  return ok;
}

function sha256File(p) {
  return createHash("sha256").update(readFileSync(p)).digest("hex");
}
function sha256Text(t) {
  return createHash("sha256").update(t, "utf8").digest("hex");
}

/** Strip ANSI colour codes; snarkjs colours its log output. */
const plain = (s) => s.replace(/\u001b\[[0-9;]*m/g, "");

const snarkjs = (args) =>
  plain(
    execFileSync(
      process.execPath,
      [join(repoRoot, "node_modules", "snarkjs", "build", "cli.cjs"), ...args],
      {
        encoding: "utf8",
        cwd: repoRoot,
        maxBuffer: 64 * 1024 * 1024,
        stdio: ["ignore", "pipe", "pipe"],
      },
    ),
  );

/**
 * Pull every 512-bit hash out of snarkjs's log.
 *
 * snarkjs prints a hash as sixteen space-separated groups of eight hex
 * characters spread over four indented lines, so a single-line regex finds
 * nothing and every contribution check fails while the cryptographic check
 * passes - a confusing combination worth avoiding.
 */
function hashesIn(output) {
  const groups = /(?:[0-9a-f]{8}[\s]+){15}[0-9a-f]{8}/g;
  return (output.match(groups) ?? []).map((h) => h.replace(/[^0-9a-f]/g, ""));
}

console.log(`FairProof ceremony verification - circuit '${circuit}'\n`);

const transcriptPath = join(ceremonyDir, `${circuit}.transcript.json`);
if (!existsSync(transcriptPath)) {
  console.error(`no transcript at ${transcriptPath}`);
  process.exit(1);
}
const t = JSON.parse(readFileSync(transcriptPath, "utf8"));
const ptauPin = JSON.parse(readFileSync(join(ceremonyDir, "ptau.json"), "utf8"));
const declared = JSON.parse(readFileSync(join(ceremonyDir, "contributors.json"), "utf8"));

// ------------------------------------------------------------------ phase 1
console.log("[1] Phase 1");
const ptauPath = join(pkgRoot, "ptau", ptauPin.name);
if (!existsSync(ptauPath)) {
  console.log(`  ..    ${ptauPin.name} not present locally; fetching`);
  execFileSync("curl", ["-fL", "--max-time", "1800", "-o", ptauPath, ptauPin.url], {
    stdio: "inherit",
  });
}
// Catches: a swapped phase-1 file, which would make the zkey verify against
// parameters nobody published.
check(sha256File(ptauPath) === ptauPin.sha256, "phase-1 file matches the pinned sha256", ptauPin.name);
check(t.phase1.sha256 === ptauPin.sha256, "the transcript names the pinned phase-1 file");
check(t.phase1.url === ptauPin.url, "the transcript names the published phase-1 URL");

if (verifyPhase1) {
  // Catches: a phase-1 file that is well-formed but not a real ceremony
  // output - i.e. one somebody generated with a known secret.
  let ok = false;
  try {
    ok = /Powers Of tau file OK!/i.test(snarkjs(["powersoftau", "verify", ptauPath]));
  } catch { ok = false; }
  check(ok, "phase-1 contribution chain verifies");
} else {
  console.log("  SKIP  phase-1 contribution chain (pass --verify-phase1; takes minutes)");
}

// ------------------------------------------------------- circuit provenance
console.log("\n[2] Circuit provenance");

/**
 * What binds the parameters to a circuit is the R1CS, not the source text.
 *
 * The first version of this section had the logic backwards: a changed source
 * file was a FAIL and a changed r1cs was only a NOTE. That fires falsely the
 * moment a SHARED library gains something unrelated - adding
 * DOMAIN_IDENTITY_V1 to constants.circom for the winner-identity circuit made
 * the eligibility and award ceremonies "fail" while their compiled constraint
 * systems were byte-for-byte what they had always been.
 *
 * So the r1cs comparison is the authority:
 *
 *   - r1cs byte-identical  -> the circuit is PROVABLY unchanged. A source
 *                             difference is then in a declaration this circuit
 *                             does not use, or is cosmetic, and is reported as
 *                             information rather than as a failure.
 *   - r1cs differs         -> FAIL, whatever the sources say. The circuit that
 *                             went through the ceremony is not the circuit
 *                             here, and the source hashes below help localise
 *                             which file moved.
 */
const r1cs = join(buildDir, `${circuit}.r1cs`);
let r1csIdentical = false;
if (existsSync(r1cs)) {
  const localR1cs = sha256File(r1cs);
  r1csIdentical = localR1cs === t.r1cs.sha256;
  check(
    r1csIdentical,
    "the compiled circuit is byte-identical to the one the ceremony was run against",
    r1csIdentical
      ? `r1cs sha256 ${localR1cs.slice(0, 16)}...`
      : `r1cs sha256 ${localR1cs.slice(0, 16)}... but the transcript records ${t.r1cs.sha256.slice(0, 16)}...`,
  );
  if (!r1csIdentical) {
    console.log(
      "        The parameters do not belong to this circuit. Either recompile the\n" +
        "        circuit that was ceremonied, or run a new ceremony.",
    );
  }
} else {
  check(false, "r1cs present", `${r1cs} missing - run npm run circuits:compile`);
}

// Source hashes: a FAIL only when the r1cs already told us something moved.
const changed = [];
for (const f of t.circuitSources.files) {
  const p = join(repoRoot, f.file);
  const same = existsSync(p) && sha256Text(readFileSync(p, "utf8")) === f.sha256;
  if (!same) changed.push(f.file);
}
if (changed.length === 0) {
  check(true, "every circuit source file is unchanged since the ceremony", `${t.circuitSources.files.length} files`);
} else if (r1csIdentical) {
  check(
    true,
    "source files differ, but the compiled circuit does not",
    `changed: ${changed.join(", ")}`,
  );
  console.log(
    "        A shared library gained something this circuit does not use. The\n" +
      "        r1cs above is byte-identical, so the constraint system the ceremony\n" +
      "        bound its parameters to is provably the same one.",
  );
} else {
  check(false, "circuit source files are unchanged since the ceremony", `changed: ${changed.join(", ")}`);
}

// ------------------------------------------------------- phase-2 transcript
console.log("\n[3] Phase-2 transcript");
check(
  t.contributions.length >= 3,
  "at least three phase-2 contributions (plan 11B.1)",
  `${t.contributions.length} recorded`,
);
check(
  t.contributions.length === declared.contributors.length,
  "the transcript records every declared contributor",
);
let sequential = true;
t.contributions.forEach((c, i) => {
  if (c.index !== i + 1) sequential = false;
});
check(sequential, "contribution indices are sequential with no gaps");
check(
  new Set(t.contributions.map((c) => c.contributionHash)).size === t.contributions.length,
  "every contribution hash is distinct",
  "identical hashes would mean a contribution was replayed rather than made",
);
check(
  t.contributions.every((c) => /^[0-9a-f]{128}$/.test(c.contributionHash)),
  "every contribution hash is a 512-bit value",
);

const independent = t.contributions.filter((c) => c.independent).length;
console.log(
  `  ..    ${independent} of ${t.contributions.length} contributors are recorded as independent of the team`,
);
if (t.singleMachine) {
  console.log(
    "  ..    singleMachine: TRUE - every contribution was produced on one machine.\n" +
      "        This is NOT a real multi-party ceremony. See docs/cryptography.md.",
  );
}

// ------------------------------------------------------------------- beacon
console.log("\n[4] Finalizing beacon");
check(!!t.beacon, "the ceremony was finalized with a beacon");
if (t.beacon) {
  // Catches: a fabricated beacon. Anyone can re-fetch the round by number
  // and compare, which is the whole reason for using an external one.
  let live = null;
  try {
    live = JSON.parse(
      execFileSync("curl", ["-fsS", "--max-time", "30", t.beacon.recheck], {
        encoding: "utf8",
      }),
    );
  } catch (e) {
    console.log(`  ..    could not reach ${t.beacon.recheck}: ${e.message}`);
  }
  if (live) {
    check(live.round === t.beacon.round, "drand returns the recorded round", String(t.beacon.round));
    check(
      live.randomness === t.beacon.randomness,
      "the recorded beacon randomness matches drand's",
      t.beacon.randomness.slice(0, 16) + "...",
    );
    check(
      live.signature === t.beacon.signature,
      "the recorded beacon signature matches drand's",
    );
  } else {
    console.log("  SKIP  beacon re-fetch (offline)");
  }
  check(
    t.beacon.chainHash === declared.beacon.chainHash,
    "the beacon chain is the one declared in contributors.json",
  );
}

// --------------------------------------------------------------- the zkey
console.log("\n[5] Final parameters");
const finalZkey = join(buildDir, `${circuit}_final.zkey`);
if (existsSync(finalZkey) && existsSync(r1cs)) {
  check(
    sha256File(finalZkey) === t.finalZkey.sha256,
    "final zkey matches the transcript's sha256",
  );
  // THE check. It re-derives the whole contribution chain and confirms the
  // final parameters really are phase 1 plus these contributions plus this
  // beacon, applied to THIS circuit. Everything above is bookkeeping around
  // it.
  let ok = false;
  let out = "";
  try {
    out = snarkjs(["zkey", "verify", r1cs, ptauPath, finalZkey]);
    ok = /ZKey Ok!/i.test(out);
  } catch (e) {
    out = plain(String(e.stdout ?? e.message));
  }
  check(ok, "final zkey verifies against the r1cs and phase 1");

  // The hashes snarkjs re-derives must be the ones we published. This is what
  // ties the human-readable transcript to the cryptographic check.
  const found = hashesIn(out).filter((h) => h.length === 128);
  for (const c of t.contributions) {
    check(
      found.includes(c.contributionHash),
      `snarkjs re-derives contribution ${c.index}'s hash`,
      c.name,
    );
  }
} else {
  check(false, "final zkey and r1cs present", "run the ceremony or npm run circuits:compile");
}

// -------------------------------------------------------- verification key
console.log("\n[6] Verification key and Solidity verifier");
const vkeyPath = join(buildDir, `${circuit}_verification_key.json`);
if (existsSync(vkeyPath)) {
  const vkey = JSON.parse(readFileSync(vkeyPath, "utf8"));
  const canonical = JSON.stringify(vkey, Object.keys(vkey).sort());
  check(
    sha256Text(canonical) === t.verificationKey.sha256,
    "verification key matches the transcript's sha256",
  );
  check(vkey.protocol === "groth16" && vkey.curve === "bn128", "protocol groth16 over bn128");
  check(
    vkey.nPublic === t.verificationKey.nPublic,
    "public signal count matches the transcript",
    `${vkey.nPublic}`,
  );
  // Catches: a circuit whose public list changed. Each adapter's signal
  // array is a fixed-width Solidity type, so a different count is an ABI
  // mismatch rather than a subtle misread.
  const EXPECTED_PUBLIC = { eligibility: 12, award: 8, winner_identity: 5 };
  if (EXPECTED_PUBLIC[circuit] !== undefined) {
    check(
      vkey.nPublic === EXPECTED_PUBLIC[circuit],
      `${circuit} has exactly ${EXPECTED_PUBLIC[circuit]} public signals`,
      "encoding spec Sections 16, 17 and 18",
    );
  }
} else {
  check(false, "verification key present");
}

// Catches: a hand-edited verifier contract. One altered constant would make
// the deployed verifier accept proofs from a different setup, and no
// functional test would notice because the fixtures would be regenerated to
// match.
const { VERIFIERS } = await import("./export-verifier.mjs");
const committed = VERIFIERS[circuit]
  ? join(repoRoot, VERIFIERS[circuit].dest)
  : null;
if (committed && existsSync(finalZkey)) {
  if (!existsSync(committed)) {
    check(false, "committed Solidity verifier present", committed);
  } else {
    const tmp = join(tmpdir(), `fairproof-verify-${process.pid}.sol`);
    let regenerated = "";
    try {
      regenerated = exportVerifier(circuit, tmp).source;
    } finally {
      rmSync(tmp, { force: true });
    }
    check(
      regenerated === readFileSync(committed, "utf8"),
      "committed Solidity verifier is byte-identical to a fresh export",
      "a hand edit here would silently change which setup is trusted",
    );
  }
}

console.log(`\n${checks - failures}/${checks} checks passed`);
if (failures > 0) {
  console.log(`${failures} CHECK(S) FAILED`);
  process.exit(1);
}
console.log("CEREMONY VERIFIED");
