import { beforeAll, describe, expect, it } from "vitest";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
// @ts-expect-error - circom_tester ships no types
import { wasm as wasmTester } from "circom_tester";
import {
  BID_TREE_DEPTH,
  IncrementalMerkleTree,
  SCHEMA_VERSION,
  bidCommitment,
  bidLeaf,
  credDigest,
  initPoseidon,
  nullifier,
  poseidon,
  subjectCommitment,
  tenderIdField,
} from "@fairproof/crypto";
import { VECTOR } from "./vector.js";

const here = dirname(fileURLToPath(import.meta.url));
const pkgRoot = resolve(here, "..");

/**
 * Cross-language equality test. Development plan Section 11A.6.
 *
 * "Add a single test, run in CI, that is the cheapest insurance in the whole
 *  repository. If this test is absent, assume the three implementations
 *  disagree, because they usually do."
 *
 * This file covers TypeScript vs Circom. The Solidity leg lives in
 * packages/contracts/test/Encoding.equality.test.ts and asserts against the
 * same VECTOR and the same expected values.
 *
 * Stage 1 does not begin until this passes.
 */
describe("TypeScript <-> Circom encoding agreement", () => {
  let circuit: any;
  let witness: bigint[];
  let ts: Record<string, bigint>;

  beforeAll(async () => {
    await initPoseidon();

    circuit = await wasmTester(
      join(pkgRoot, "src/test/encoding_echo.circom"),
      { include: [join(pkgRoot, "../../node_modules")] },
    );

    const tField = tenderIdField(VECTOR.tenderId);

    witness = await circuit.calculateWitness(
      {
        subjectSecret: VECTOR.subjectSecret,
        tenderIdField: tField,
        bidAmount: VECTOR.bidAmount,
        bidNonce: VECTOR.bidNonce,
        ciphertextHashField: VECTOR.ciphertextHashField,
        submissionIndex: VECTOR.submissionIndex,
        annualTurnover: VECTOR.annualTurnover,
        relevantExperience: VECTOR.relevantExperience,
        certificationCode: VECTOR.certificationCode,
        certValidUntil: VECTOR.certValidUntil,
        credentialValidUntil: VECTOR.credentialValidUntil,
        credentialId: VECTOR.credentialId,
        issuerEpoch: VECTOR.issuerEpoch,
        issuedAt: VECTOR.issuedAt,
      },
      true,
    );
    await circuit.checkConstraints(witness);

    // Compute the same values in TypeScript.
    const subj = subjectCommitment(VECTOR.subjectSecret);
    const nul = nullifier(VECTOR.subjectSecret, tField);
    const bc = bidCommitment({
      bidAmount: VECTOR.bidAmount,
      bidNonce: VECTOR.bidNonce,
      tenderIdField: tField,
      nullifier: nul,
    });
    ts = {
      poseidon2: poseidon([1n, 2n]),
      subjectCommitment: subj,
      nullifier: nul,
      bidCommitment: bc,
      credDigest: credDigest({
        schemaVersion: SCHEMA_VERSION,
        subjectCommitment: subj,
        annualTurnover: VECTOR.annualTurnover,
        relevantExperience: VECTOR.relevantExperience,
        certificationCode: VECTOR.certificationCode,
        certValidUntil: VECTOR.certValidUntil,
        credentialValidUntil: VECTOR.credentialValidUntil,
        credentialId: VECTOR.credentialId,
        issuerEpoch: VECTOR.issuerEpoch,
        issuedAt: VECTOR.issuedAt,
      }),
      bidLeaf: bidLeaf({
        nullifier: nul,
        bidCommitment: bc,
        ciphertextHashField: VECTOR.ciphertextHashField,
        submissionIndex: VECTOR.submissionIndex,
      }),
      emptyRoot: IncrementalMerkleTree.emptyRoot(BID_TREE_DEPTH),
    };
  });

  // Witness layout: index 0 is the constant 1, then the public outputs in
  // declaration order.
  const OUTPUTS = [
    "poseidon2",
    "subjectCommitment",
    "nullifier",
    "bidCommitment",
    "credDigest",
    "bidLeaf",
    "emptyRoot",
  ] as const;

  it("the witness exposes all seven outputs", () => {
    expect(witness.length).toBeGreaterThan(OUTPUTS.length);
    expect(witness[0]).toBe(1n);
  });

  for (let i = 0; i < OUTPUTS.length; i++) {
    const name = OUTPUTS[i];
    it(`${name} agrees between TypeScript and Circom`, () => {
      const fromCircuit = witness[1 + i];
      expect(
        fromCircuit,
        `${name}: circom=${fromCircuit} typescript=${ts[name]}\n` +
          `The frozen encoding in docs/field-encoding.md is not implemented ` +
          `identically in packages/crypto and packages/circuits.`,
      ).toBe(ts[name]);
    });
  }

  it("emits the pinned protocol digests, guarding against silent drift", () => {
    // Independent of both implementations: these are the frozen values.
    expect(ts.poseidon2).toBe(
      7853200120776062878684798364095072458815029376092732009249414926327459813530n,
    );
    expect(ts.emptyRoot).toBe(
      18232377929263394053032240335347245131877279331383963775401837732819763548351n,
    );
  });
});
