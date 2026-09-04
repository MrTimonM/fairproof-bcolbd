#!/usr/bin/env node
/**
 * FairProof Groth16 phase-2 ceremony.
 *
 * Whitepaper Table 11 concedes the Groth16 trusted setup and promises "a
 * public multi-party ceremony with a published transcript". Development plan
 * Section 11B.1 turns that into five requirements: a published phase 1 with a
 * recorded checksum, at least three phase-2 contributors, a published
 * transcript of every contribution hash, an exported verification key with
 * its hash and the circuit source hash, and a `ceremony:verify` script anyone
 * can run.
 *
 * WHY THIS IS A MULTI-COMMAND SCRIPT AND NOT ONE FUNCTION.
 *
 * A ceremony's only security property is that at least one contributor
 * destroyed their secret randomness. If a single script generates the
 * randomness for all three contributions, there is one machine that saw all
 * three secrets, and calling that a three-party ceremony would be a lie.
 * So the real protocol is exposed as separate commands that different people
 * run on different machines, each supplying their own entropy:
 *
 *     ceremony init      <circuit>            (coordinator)
 *     ceremony contribute <circuit> <index>   (each contributor, own machine)
 *     ceremony finalize  <circuit>            (coordinator)
 *
 * `ceremony all` runs the whole thing locally for the prototype. It works,
 * but it records `singleMachine: true` in the transcript, and
 * docs/cryptography.md says what that costs. An honest weak ceremony is
 * defensible; a weak ceremony described as strong is not.
 *
 * TOXIC WASTE. Contributor entropy is read from the CEREMONY_ENTROPY
 * environment variable, or generated with crypto.randomBytes when absent. It
 * is never written to disk and never placed in the transcript. snarkjs mixes
 * it into the contribution; discarding it is what makes the contribution
 * count.
 */
import { execFileSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
  readdirSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const pkgRoot = resolve(here, "..");
const repoRoot = resolve(pkgRoot, "../..");

const PTAU_NAME = "powersOfTau28_hez_final_17.ptau";
const PTAU_URL =
  "https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_17.ptau";
const ptauDir = join(pkgRoot, "ptau");
const ptauPath = join(ptauDir, PTAU_NAME);
const ceremonyDir = join(pkgRoot, "ceremony");
const buildDir = join(pkgRoot, "build");

/** Circuit sources hashed into the transcript, so a silent edit is visible. */
const CIRCUIT_SOURCES = {
  eligibility: [
    "src/eligibility.circom",
    "src/commitments.circom",
    "src/merkle.circom",
    "src/constants.circom",
  ],
  award: [
    "src/award.circom",
    "src/commitments.circom",
    "src/merkle.circom",
    "src/constants.circom",
  ],
  winner_identity: [
    "src/winner_identity.circom",
    "src/commitments.circom",
    "src/merkle.circom",
    "src/constants.circom",
  ],
};

const contributors = JSON.parse(
  readFileSync(join(ceremonyDir, "contributors.json"), "utf8"),
);

function sh(bin, args, opts = {}) {
  return execFileSync(bin, args, {
    encoding: "utf8",
    cwd: repoRoot,
    maxBuffer: 64 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
    ...opts,
  });
}

const snarkjs = (args) =>
  sh(process.execPath, [
    join(repoRoot, "node_modules", "snarkjs", "build", "cli.cjs"),
    ...args,
  ]);

function sha256File(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function sha256Text(text) {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

/**
 * The hash snarkjs prints is four lines of 32 hex characters in groups of 8.
 * Collapse it to one lowercase hex string so the transcript is comparable.
 */
function normalizeHash(block) {
  return block.replace(/[^0-9a-fA-F]/g, "").toLowerCase();
}

function extractContributionHash(output) {
  const m = output.match(
    /Contribution Hash:\s*\n((?:\s*[0-9a-fA-F ]{8,}\n){2,8})/,
  );
  if (!m) throw new Error(`could not find a contribution hash in:\n${output}`);
  const h = normalizeHash(m[1]);
  if (h.length !== 128) {
    throw new Error(`expected a 512-bit contribution hash, got ${h.length / 2} bytes`);
  }
  return h;
}

// ------------------------------------------------------------------- phase 1

/**
 * Pin the phase-1 file.
 *
 * Two independent checks, because a checksum alone would only prove the file
 * matches one this project generated:
 *
 *   1. sha256 pins WHICH file, recorded in ceremony/ptau.json.
 *   2. `snarkjs powersoftau verify` cryptographically verifies the file's own
 *      chain of phase-1 contributions. That is the check that matters, and it
 *      does not depend on trusting us.
 */
function ensurePtau({ verifyChain }) {
  mkdirSync(ptauDir, { recursive: true });
  if (!existsSync(ptauPath)) {
    console.log(`downloading phase 1: ${PTAU_URL}`);
    sh("curl", ["-fL", "--max-time", "1800", "-o", ptauPath, PTAU_URL]);
  }
  const digest = sha256File(ptauPath);
  const pinPath = join(ceremonyDir, "ptau.json");

  if (existsSync(pinPath)) {
    const pin = JSON.parse(readFileSync(pinPath, "utf8"));
    if (pin.sha256 !== digest) {
      throw new Error(
        `phase-1 checksum mismatch\n  pinned:   ${pin.sha256}\n  on disk:  ${digest}\n` +
          `Delete the local file and re-download, or investigate. Do NOT re-pin ` +
          `without understanding why it changed.`,
      );
    }
    console.log(`phase 1 checksum matches the pin (${digest.slice(0, 16)}...)`);
  } else {
    writeFileSync(
      pinPath,
      JSON.stringify(
        {
          $comment:
            "Phase 1 is the published Hermez powers-of-tau. We deliberately do not generate our own phase 1 (development plan Section 11B.1 step 1). The sha256 pins which file; `snarkjs powersoftau verify` proves the file is a valid ceremony output independently of us.",
          name: PTAU_NAME,
          url: PTAU_URL,
          sha256: digest,
          power: 17,
          maxConstraints: 131072,
          curve: "bn128",
          pinnedAt: new Date().toISOString(),
        },
        null,
        2,
      ) + "\n",
    );
    console.log(`pinned phase 1: sha256 ${digest}`);
  }

  if (verifyChain) {
    console.log("verifying the phase-1 contribution chain (this takes a while) ...");
    const out = snarkjs(["powersoftau", "verify", ptauPath]);
    if (!/Powers Of tau file OK!/i.test(out)) {
      throw new Error(`phase-1 verification failed:\n${out}`);
    }
    console.log("phase-1 contribution chain verified");
  }
  return digest;
}

// ------------------------------------------------------------------- phase 2

function circuitPaths(circuit) {
  const r1cs = join(buildDir, circuit, `${circuit}.r1cs`);
  if (!existsSync(r1cs)) {
    throw new Error(`${r1cs} not found - run \`npm run circuits:compile\` first`);
  }
  const work = join(buildDir, circuit, "ceremony");
  mkdirSync(work, { recursive: true });
  return {
    r1cs,
    work,
    zkeyAt: (n) => join(work, `${circuit}_${String(n).padStart(4, "0")}.zkey`),
    final: join(buildDir, circuit, `${circuit}_final.zkey`),
    vkey: join(buildDir, circuit, `${circuit}_verification_key.json`),
    transcript: join(ceremonyDir, `${circuit}.transcript.json`),
    stateFile: join(work, "state.json"),
  };
}

function loadState(p) {
  return existsSync(p.stateFile)
    ? JSON.parse(readFileSync(p.stateFile, "utf8"))
    : null;
}

function saveState(p, state) {
  writeFileSync(p.stateFile, JSON.stringify(state, null, 2) + "\n");
}

function circuitSourceHashes(circuit) {
  const files = CIRCUIT_SOURCES[circuit];
  if (!files) throw new Error(`no source list registered for circuit '${circuit}'`);
  const entries = files.map((rel) => ({
    file: `packages/circuits/${rel}`,
    sha256: sha256Text(readFileSync(join(pkgRoot, rel), "utf8")),
  }));
  // One digest over the per-file digests, so the transcript can be compared
  // against a checkout with a single equality.
  const combined = sha256Text(
    entries.map((e) => `${e.file} ${e.sha256}`).join("\n"),
  );
  return { files: entries, combined };
}

function cmdInit(circuit) {
  const p = circuitPaths(circuit);
  const ptauSha = ensurePtau({ verifyChain: false });
  console.log(`phase-2 setup for '${circuit}' ...`);
  snarkjs(["groth16", "setup", p.r1cs, ptauPath, p.zkeyAt(0)]);

  const r1csInfo = snarkjs(["r1cs", "info", p.r1cs]);
  const num = (re) => {
    const m = r1csInfo.match(re);
    return m ? Number(m[1]) : null;
  };

  saveState(p, {
    ceremonyId: contributors.ceremonyId,
    circuit,
    startedAt: new Date().toISOString(),
    phase1: { name: PTAU_NAME, url: PTAU_URL, sha256: ptauSha, power: 17 },
    circuitSources: circuitSourceHashes(circuit),
    r1cs: {
      sha256: sha256File(p.r1cs),
      constraints: num(/# of Constraints:\s*(\d+)/),
      publicInputs: num(/# of Public Inputs:\s*(\d+)/),
      privateInputs: num(/# of Private Inputs:\s*(\d+)/),
      outputs: num(/# of Outputs:\s*(\d+)/),
    },
    contributions: [],
    beacon: null,
    singleMachine: false,
  });
  console.log(`initial zkey: ${p.zkeyAt(0)}`);
  console.log(`next: ceremony contribute ${circuit} 1`);
}

function cmdContribute(circuit, index) {
  const p = circuitPaths(circuit);
  const state = loadState(p);
  if (!state) throw new Error(`no ceremony in progress - run: ceremony init ${circuit}`);
  if (state.beacon) throw new Error("this ceremony is already finalized");

  const expected = state.contributions.length + 1;
  if (index !== expected) {
    throw new Error(
      `contributions are sequential: expected index ${expected}, got ${index}`,
    );
  }
  const who = contributors.contributors.find((c) => c.index === index);
  if (!who) throw new Error(`contributor ${index} is not declared in contributors.json`);

  const prev = p.zkeyAt(index - 1);
  const next = p.zkeyAt(index);
  if (!existsSync(prev)) throw new Error(`${prev} not found`);

  // Own entropy, never persisted. An explicitly supplied value lets a
  // contributor use their own source; the fallback is the OS CSPRNG.
  const supplied = process.env.CEREMONY_ENTROPY;
  const entropy = supplied && supplied.length >= 32
    ? supplied
    : randomBytes(64).toString("hex");
  if (!supplied) {
    console.log("using crypto.randomBytes for entropy (set CEREMONY_ENTROPY to override)");
  }

  console.log(`contribution ${index} by ${who.name} ...`);
  const out = snarkjs([
    "zkey",
    "contribute",
    prev,
    next,
    `--name=${who.name}`,
    `-e=${entropy}`,
  ]);
  const hash = extractContributionHash(out);

  state.contributions.push({
    index,
    name: who.name,
    affiliation: who.affiliation,
    independent: who.independent,
    contributionHash: hash,
    zkeySha256: sha256File(next),
    entropySource: supplied ? "contributor-supplied (CEREMONY_ENTROPY)" : "crypto.randomBytes(64)",
    at: new Date().toISOString(),
  });
  saveState(p, state);

  console.log(`contribution hash: ${hash}`);
  const remaining = contributors.contributors.length - index;
  console.log(
    remaining > 0
      ? `next: ceremony contribute ${circuit} ${index + 1}`
      : `next: ceremony finalize ${circuit}`,
  );
}

/**
 * Fetch a drand round to use as the finalizing beacon.
 *
 * The beacon exists so that nobody - not even every contributor colluding -
 * can have chosen the final parameters, because the last transformation is
 * derived from a value none of them could predict. That only holds if the
 * value is outside this project's control, which is why it is not a block
 * hash from our own chain.
 */
function fetchBeacon() {
  if (process.env.CEREMONY_BEACON_ROUND) {
    const round = Number(process.env.CEREMONY_BEACON_ROUND);
    const body = sh("curl", ["-fsS", "--max-time", "30", `https://api.drand.sh/public/${round}`]);
    return JSON.parse(body);
  }
  const body = sh("curl", ["-fsS", "--max-time", "30", "https://api.drand.sh/public/latest"]);
  return JSON.parse(body);
}

function cmdFinalize(circuit) {
  const p = circuitPaths(circuit);
  const state = loadState(p);
  if (!state) throw new Error(`no ceremony in progress - run: ceremony init ${circuit}`);
  if (state.beacon) throw new Error("already finalized");

  const declared = contributors.contributors.length;
  if (state.contributions.length < declared) {
    throw new Error(
      `${state.contributions.length} of ${declared} declared contributions recorded - ` +
        `finalizing early would publish a transcript that contradicts contributors.json`,
    );
  }
  if (state.contributions.length < 3) {
    throw new Error(
      "development plan Section 11B.1 requires at least three phase-2 contributors",
    );
  }

  const beacon = fetchBeacon();
  const beaconHash = beacon.randomness;
  if (!/^[0-9a-f]{64}$/.test(beaconHash)) {
    throw new Error(`unexpected beacon randomness: ${beaconHash}`);
  }
  const last = p.zkeyAt(state.contributions.length);
  console.log(`finalizing with drand round ${beacon.round} ...`);
  const out = snarkjs([
    "zkey",
    "beacon",
    last,
    p.final,
    beaconHash,
    "10",
    "-n=drand round " + beacon.round,
  ]);
  const beaconContributionHash = extractContributionHash(out);

  state.beacon = {
    source: contributors.beacon.source,
    chainHash: contributors.beacon.chainHash,
    round: beacon.round,
    randomness: beacon.randomness,
    signature: beacon.signature,
    numIterationsExp: 10,
    contributionHash: beaconContributionHash,
    recheck: `https://api.drand.sh/public/${beacon.round}`,
    at: new Date().toISOString(),
  };

  console.log("verifying the finalized zkey against the r1cs and phase 1 ...");
  const verifyOut = snarkjs(["zkey", "verify", p.r1cs, ptauPath, p.final]);
  if (!/ZKey Ok!/i.test(verifyOut)) {
    throw new Error(`zkey verification failed:\n${verifyOut}`);
  }
  console.log("zkey verified");

  snarkjs(["zkey", "export", "verificationkey", p.final, p.vkey]);
  const vkey = JSON.parse(readFileSync(p.vkey, "utf8"));

  // Hash the verification key canonically (sorted keys, no whitespace) so the
  // recorded hash does not depend on snarkjs's formatting.
  const vkeyCanonical = JSON.stringify(vkey, Object.keys(vkey).sort());
  state.finalZkey = { sha256: sha256File(p.final) };
  state.verificationKey = {
    protocol: vkey.protocol,
    curve: vkey.curve,
    nPublic: vkey.nPublic,
    sha256: sha256Text(vkeyCanonical),
    canonicalization: "JSON.stringify(vkey, Object.keys(vkey).sort())",
  };
  state.finalizedAt = new Date().toISOString();
  saveState(p, state);

  writeFileSync(p.transcript, JSON.stringify(state, null, 2) + "\n");
  console.log(`\ntranscript: packages/circuits/ceremony/${circuit}.transcript.json`);
  console.log(`final zkey: ${p.final}`);
  console.log(`vkey nPublic: ${vkey.nPublic}, sha256 ${state.verificationKey.sha256}`);
  console.log(`\nnext: npm run ceremony:verify`);
}

function cmdAll(circuit) {
  cmdInit(circuit);
  const p = circuitPaths(circuit);
  for (const c of contributors.contributors) cmdContribute(circuit, c.index);
  // Recorded before finalize so it lands in the published transcript.
  const state = loadState(p);
  state.singleMachine = true;
  state.singleMachineNote =
    "All phase-2 contributions were produced on one machine by `ceremony all`. " +
    "One machine therefore saw every contributor's entropy. If that machine was " +
    "compromised, or if its operator retained the secrets, forged eligibility " +
    "proofs would be possible. This is the prototype limitation the whitepaper " +
    "names in Table 11; see docs/cryptography.md.";
  saveState(p, state);
  cmdFinalize(circuit);
}

// ---------------------------------------------------------------------- main

const [cmd, circuit = "eligibility", arg] = process.argv.slice(2);
try {
  switch (cmd) {
    case "ptau":
      ensurePtau({ verifyChain: arg === "--verify-chain" });
      break;
    case "init":
      cmdInit(circuit);
      break;
    case "contribute":
      cmdContribute(circuit, Number(arg));
      break;
    case "finalize":
      cmdFinalize(circuit);
      break;
    case "all":
      cmdAll(circuit);
      break;
    default:
      console.log(
        [
          "usage: ceremony <command> [circuit] [arg]",
          "",
          "  ptau [--verify-chain]     download and pin phase 1",
          "  init <circuit>            phase-2 setup            (coordinator)",
          "  contribute <circuit> <n>  add contribution n       (contributor)",
          "  finalize <circuit>        beacon, verify, publish  (coordinator)",
          "  all <circuit>             run everything locally   (prototype only)",
          "",
          "circuits: " + Object.keys(CIRCUIT_SOURCES).join(", "),
        ].join("\n"),
      );
      process.exit(cmd ? 1 : 0);
  }
} catch (err) {
  console.error(`\nceremony failed: ${err.message}`);
  process.exit(1);
}
