#!/usr/bin/env node
/**
 * Export the ceremony's Groth16 verifier as a Solidity contract.
 *
 * The emitted file is a BUILD ARTIFACT that is nevertheless committed, because
 * it is what gets deployed and what a reviewer reads. Committing a generated
 * file is only safe if anyone can regenerate it and get the same bytes, so:
 *
 *   - the transformation applied to snarkjs's output is declared here, in one
 *     place, and is deterministic;
 *   - `ceremony:verify` re-runs this script into a temporary file and compares
 *     byte for byte, so a hand-edited verifier is caught.
 *
 * A hand-edited verifier is the single most dangerous edit in the repository:
 * changing one constant would make the contract accept proofs from a
 * different (possibly attacker-chosen) setup while every test still passed.
 * Hence the byte comparison rather than a comment asking people not to.
 *
 * LICENCE. snarkjs emits GPL-3.0 headers and that header is preserved. The
 * rest of FairProof is Apache-2.0. Generated verifier files therefore carry a
 * different licence from the code around them; this is normal for
 * snarkjs-generated verifiers and the header is left exactly as emitted.
 */
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const pkgRoot = resolve(here, "..");
const repoRoot = resolve(pkgRoot, "../..");

/** circuit -> [generated contract name, destination] */
export const VERIFIERS = {
  eligibility: {
    contractName: "EligibilityVerifierGroth16",
    dest: "packages/contracts/contracts/verifiers/EligibilityVerifierGroth16.sol",
  },
  award: {
    contractName: "AwardVerifierGroth16",
    dest: "packages/contracts/contracts/verifiers/AwardVerifierGroth16.sol",
  },
  winner_identity: {
    contractName: "WinnerIdentityVerifierGroth16",
    dest: "packages/contracts/contracts/verifiers/WinnerIdentityVerifierGroth16.sol",
  },
};

/**
 * The declared transformation. Renaming the contract is not cosmetic: two
 * circuits would otherwise both emit a contract called `Groth16Verifier`, and
 * Hardhat's artifact lookup by bare name becomes ambiguous the moment the
 * second one lands - a failure mode that shows up as a confusing test error
 * long after the change that caused it.
 */
function transform(source, contractName) {
  const needle = "contract Groth16Verifier {";
  if (!source.includes(needle)) {
    throw new Error(
      "snarkjs output does not contain the expected contract declaration - " +
        "the generator changed and this transformation needs review",
    );
  }
  return source.replace(needle, `contract ${contractName} {`);
}

export function exportVerifier(circuit, outPath) {
  const spec = VERIFIERS[circuit];
  if (!spec) throw new Error(`no verifier destination registered for '${circuit}'`);
  const zkey = join(pkgRoot, "build", circuit, `${circuit}_final.zkey`);
  if (!existsSync(zkey)) {
    throw new Error(`${zkey} not found - run the ceremony first`);
  }
  // snarkjs writes the file with writeFileSync, so it needs a real path;
  // /dev/stdout is not openable that way.
  const scratch = join(tmpdir(), `fairproof-verifier-${process.pid}-${circuit}.sol`);
  execFileSync(
    process.execPath,
    [
      join(repoRoot, "node_modules", "snarkjs", "build", "cli.cjs"),
      "zkey",
      "export",
      "solidityverifier",
      zkey,
      scratch,
    ],
    { encoding: "utf8", maxBuffer: 32 * 1024 * 1024, cwd: repoRoot, stdio: ["ignore", "pipe", "pipe"] },
  );
  const raw = readFileSync(scratch, "utf8");
  rmSync(scratch, { force: true });
  const start = raw.indexOf("// SPDX-License-Identifier");
  if (start < 0) throw new Error("no Solidity source in snarkjs output");
  const source = transform(raw.slice(start), spec.contractName);

  const target = outPath ?? join(repoRoot, spec.dest);
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, source);
  return { target, source, contractName: spec.contractName };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const circuit = process.argv[2] ?? "eligibility";
  const { target, source, contractName } = exportVerifier(circuit);
  console.log(`${contractName} -> ${target} (${source.length} bytes)`);
}
