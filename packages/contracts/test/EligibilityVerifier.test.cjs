const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { join } = require("node:path");
const hre = require("hardhat");
const { time } = require("@nomicfoundation/hardhat-network-helpers");
const {
  encodeAbiParameters,
  keccak256,
  parseAbiParameters,
  stringToHex,
  toHex,
} = require("viem");

/**
 * EligibilityVerifier: the adapter between a Groth16 proof and a tender's
 * frozen rules.
 *
 * Development plan Sections 11B.3, 20.3 and 25.1 step 8. Whitepaper Section 14
 * ("timelocked verifier upgrades never alter a running tender") and Section
 * 19.5 ("each tender pins a circuit/verifier version").
 *
 * THE PROOFS HERE ARE REAL. They come from
 * packages/circuits/fixtures/eligibility.proof.json, produced by
 * `npm run fixtures:eligibility` over the ceremony zkey, and every one was
 * verified by snarkjs before being committed. The contract derives the twelve
 * public signals from on-chain tender state; the fixture derived them from the
 * shared spec in TypeScript. Neither side can see the other's work, so an
 * agreement between them is evidence and not a tautology.
 *
 * The two fixtures that MUST be rejected are the reason this contract exists:
 *
 *   otherTender    - a perfectly valid proof for a different tender.
 *   weakThresholds - a perfectly valid proof against a turnover threshold of
 *                    one taka, chosen by the bidder.
 *
 * Both satisfy the circuit and both are accepted by the raw Groth16 verifier
 * (asserted below, so the layering is demonstrated rather than assumed). Only
 * the adapter's insistence on deriving the public signals from storage stops
 * them.
 */

const FIXTURE = JSON.parse(
  readFileSync(
    join(__dirname, "../../circuits/fixtures/eligibility.proof.json"),
    "utf8",
  ),
);

const SPEC = FIXTURE.tender;
const CHAIN = FIXTURE.chain;
const State = { NONE: 0, DRAFT: 1, ACTIVE: 2, CLOSED: 3, OPENING: 4, AWARDED: 5, CANCELLED: 6 };

/** Governance.ActionType, in declaration order. */
const Action = {
  RegisterIssuer: 0,
  SetIssuerStatus: 1,
  PublishIssuerRegistryRoot: 2,
  ActivateVerifierVersion: 3,
  RecordValidatorChange: 4,
  SetTenderAuthority: 5,
  SetCommittee: 6,
  EmergencyPause: 7,
  Unpause: 8,
  CancelTender: 9,
};

// From the shared spec, so the fixture's rule document and the contract's
// policy floor cannot disagree.
const REVIEW_WINDOW = BigInt(SPEC.reviewWindow);
const TIMELOCK = 60;
const {
  publicKey: COMMITTEE_Y,
  committeeArgs: dealtCommitteeArgs,
} = require("./helpers/committee.cjs");
const PX = COMMITTEE_Y.x;
const PY = COMMITTEE_Y.y;

const VKEY_HASH = keccak256(stringToHex("vkey-sha256-from-the-transcript"));
const SOURCE_HASH = keccak256(stringToHex("generated-verifier-source-sha256"));
const TRANSCRIPT_URI = "packages/circuits/ceremony/eligibility.transcript.json";

/** A fixture's proof as the three calldata arguments. */
function proofArgs(name) {
  const f = FIXTURE.fixtures[name];
  return [
    f.pA.map(BigInt),
    f.pB.map((row) => row.map(BigInt)),
    f.pC.map(BigInt),
  ];
}

const signalsOf = (name) => FIXTURE.fixtures[name].publicSignals.map(BigInt);

describe("EligibilityVerifier", function () {
  this.timeout(180000);

  let gov, reg, tr, groth, ev;
  let council, authority, outsider, committee;
  let tenderId;

  const committeeArgs = () =>
    dealtCommitteeArgs(committee.map((w) => w.account.address));

  function ruleFields(overrides = {}) {
    return {
      requirements: {
        turnoverThreshold: BigInt(SPEC.turnoverThreshold),
        experienceMonths: Number(SPEC.experienceMonthsThreshold),
        certificationCode: BigInt(SPEC.requiredCertificationCode),
      },
      biddingStart: BigInt(SPEC.biddingStart),
      deadline: BigInt(SPEC.deadline),
      requiredIssuerId: keccak256(stringToHex(SPEC.requiredIssuerId)),
      issuerEpoch: BigInt(SPEC.credentialEpoch),
      schemaVersion: SPEC.schemaVersion,
      verifierVersion: SPEC.verifierVersion,
      disclosurePolicy: SPEC.disclosurePolicy,
      awardRule: SPEC.awardRule,
      tieBreakRule: SPEC.tieBreakRule,
      contingencyPolicy: SPEC.contingencyPolicy,
      reviewWindow: REVIEW_WINDOW,
      ...overrides,
    };
  }

  /** A DRAFT tender carrying exactly the fixture's rules. */
  async function prepareDraft(idString, overrides = {}) {
    const id = keccak256(stringToHex(idString));
    await tr.write.createTender([idString], { account: authority.account });
    // The SAME canonical bytes the fixture hashed. The contract hashes them
    // itself, so both sides reach rulesHash independently.
    await tr.write.setRuleDocument([id, stringToHex(CHAIN.canonicalRuleDocument)], {
      account: authority.account,
    });
    await tr.write.setRuleFields([id, ruleFields(overrides)], {
      account: authority.account,
    });
    await tr.write.setCommitteeKey([id, PX, PY, ...committeeArgs()], {
      account: authority.account,
    });
    return id;
  }

  const registration = (overrides = {}) => ({
    version: 1,
    impl: groth.address,
    vkeyHash: VKEY_HASH,
    sourceHash: SOURCE_HASH,
    transcriptUri: TRANSCRIPT_URI,
    ...overrides,
  });

  const sampleProof = (name = "valid") => {
    const [a, b, c] = proofArgs(name);
    return { a, b, c, signals: signalsOf(name) };
  };

  /** Take a registration through the full 3-of-4 + timelock flow. */
  async function activateVersion(r = registration(), sample = sampleProof()) {
    const payload = await ev.read.encodeActivationPayload([r]);
    const id = await gov.write.propose(
      [Action.ActivateVerifierVersion, payload, `activate verifier v${r.version}`],
      { account: council[0].account },
    );
    void id;
    const proposalId = await gov.read.proposalCount();
    await gov.write.approve([proposalId], { account: council[1].account });
    await gov.write.approve([proposalId], { account: council[2].account });
    await time.increase(TIMELOCK + 1);
    await gov.write.execute([proposalId], { account: council[0].account });
    await ev.write.registerVerifier([proposalId, r, sample], {
      account: council[0].account,
    });
    return proposalId;
  }

  beforeEach(async () => {
    const w = await hre.viem.getWalletClients();
    council = w.slice(0, 4);
    authority = w[4];
    outsider = w[5];
    committee = w.slice(6, 11);

    gov = await hre.viem.deployContract("Governance", [
      council.map((x) => x.account.address),
    ]);
    reg = await hre.viem.deployContract("IssuerRegistry", [gov.address]);
    tr = await hre.viem.deployContract("TenderRegistry", [
      gov.address,
      reg.address,
      REVIEW_WINDOW,
    ]);
    groth = await hre.viem.deployContract("EligibilityVerifierGroth16", []);
    ev = await hre.viem.deployContract("EligibilityVerifier", [
      gov.address,
      reg.address,
      tr.address,
    ]);

    await reg.write.setTenderModule([tr.address], { account: council[0].account });
    // The roots the fixture's witness was built against.
    const epoch = BigInt(SPEC.credentialEpoch);
    await reg.write.publishIssuerRegistryRoot([epoch, CHAIN.issuerRegistryRoot], {
      account: council[0].account,
    });
    await reg.write.publishRevocationRoot([epoch, CHAIN.revocationRoot], {
      account: council[0].account,
    });
    await tr.write.setTenderAuthority([authority.account.address, true], {
      account: council[0].account,
    });

    tenderId = await prepareDraft(CHAIN.tenderIdString);
    await tr.write.activateTender([tenderId, CHAIN.rulesHash], {
      account: authority.account,
    });
  });

  // ------------------------------------------------------------------ setup

  describe("the fixture and the chain agree without either trusting the other", () => {
    it("the contract's own keccak of the stored document equals the fixture's rulesHash", async () => {
      assert.equal(await tr.read.recomputeRulesHash([tenderId]), CHAIN.rulesHash);
      const t = await tr.read.getTender([tenderId]);
      assert.equal(t.rulesHash, CHAIN.rulesHash);
      assert.equal(t.state, State.ACTIVE);
    });

    it("the contract's on-chain tenderIdField equals the fixture's", async () => {
      const t = await tr.read.getTender([tenderId]);
      assert.equal(t.tenderIdField, BigInt(CHAIN.tenderIdField));
    });

    it("the fixture carries 12 public signals, matching the frozen order", () => {
      assert.equal(FIXTURE.nPublic, 12);
      assert.equal(signalsOf("valid").length, 12);
    });
  });

  // ------------------------------------------------------------- versioning

  describe("verifier version registration", () => {
    it("registers a version through 3-of-4 with a timelock", async () => {
      assert.equal(await ev.read.isVersionRegistered([1]), false);
      await activateVersion();
      assert.equal(await ev.read.isVersionRegistered([1]), true);

      const rec = await ev.read.getVerifier([1]);
      assert.equal(rec.impl.toLowerCase(), groth.address.toLowerCase());
      assert.equal(rec.vkeyHash, VKEY_HASH);
      assert.equal(rec.sourceHash, SOURCE_HASH);
      assert.equal(rec.transcriptUri, TRANSCRIPT_URI);
      assert.deepEqual(await ev.read.registeredVersions(), [1]);
    });

    it("the on-chain payload encoder agrees with an independent ABI encoder", async () => {
      // If these disagreed, the council would approve one thing and the
      // contract would demand another, and registration could never succeed.
      const onChain = await ev.read.encodeActivationPayload([registration()]);
      const offChain = encodeAbiParameters(
        parseAbiParameters("uint32, address, bytes32, bytes32, string"),
        [1, groth.address, VKEY_HASH, SOURCE_HASH, TRANSCRIPT_URI],
      );
      assert.equal(onChain.toLowerCase(), offChain.toLowerCase());
    });

    it("rejects a proposal that has not been executed", async () => {
      const r = registration();
      const payload = await ev.read.encodeActivationPayload([r]);
      await gov.write.propose([Action.ActivateVerifierVersion, payload, "not yet"], {
        account: council[0].account,
      });
      const proposalId = await gov.read.proposalCount();
      await assert.rejects(
        () =>
          ev.write.registerVerifier([proposalId, r, sampleProof()], {
            account: council[0].account,
          }),
        /ProposalNotExecuted/,
      );
    });

    it("rejects a proposal of the wrong action type", async () => {
      const r = registration();
      const payload = await ev.read.encodeActivationPayload([r]);
      // CancelTender carries no timelock, so this also shows the adapter is
      // not merely relying on the delay: the action type itself must match.
      await gov.write.propose([Action.CancelTender, payload, "wrong action"], {
        account: council[0].account,
      });
      const proposalId = await gov.read.proposalCount();
      await gov.write.approve([proposalId], { account: council[1].account });
      await gov.write.approve([proposalId], { account: council[2].account });
      await gov.write.execute([proposalId], { account: council[0].account });
      await assert.rejects(
        () =>
          ev.write.registerVerifier([proposalId, r, sampleProof()], {
            account: council[0].account,
          }),
        /WrongProposalAction/,
      );
    });

    it("rejects arguments that differ from the approved payload", async () => {
      // The whole point of the timelock: what the public reviewed is what
      // gets registered. A one-field swap must not slip through.
      const approved = registration();
      const payload = await ev.read.encodeActivationPayload([approved]);
      await gov.write.propose([Action.ActivateVerifierVersion, payload, "approved"], {
        account: council[0].account,
      });
      const proposalId = await gov.read.proposalCount();
      await gov.write.approve([proposalId], { account: council[1].account });
      await gov.write.approve([proposalId], { account: council[2].account });
      await time.increase(TIMELOCK + 1);
      await gov.write.execute([proposalId], { account: council[0].account });

      const swapped = registration({ vkeyHash: keccak256(stringToHex("different")) });
      await assert.rejects(
        () =>
          ev.write.registerVerifier([proposalId, swapped, sampleProof()], {
            account: council[0].account,
          }),
        /ProposalPayloadMismatch/,
      );
    });

    it("cannot execute a verifier activation before the timelock elapses", async () => {
      const r = registration();
      const payload = await ev.read.encodeActivationPayload([r]);
      await gov.write.propose([Action.ActivateVerifierVersion, payload, "too soon"], {
        account: council[0].account,
      });
      const proposalId = await gov.read.proposalCount();
      await gov.write.approve([proposalId], { account: council[1].account });
      await gov.write.approve([proposalId], { account: council[2].account });
      await assert.rejects(
        () => gov.write.execute([proposalId], { account: council[0].account }),
        /TimelockNotElapsed/,
      );
    });

    it("spends a proposal exactly once", async () => {
      const proposalId = await activateVersion();
      // Same proposal, different version number - would otherwise let one
      // approval authorise unlimited registrations.
      await assert.rejects(
        () =>
          ev.write.registerVerifier(
            [proposalId, registration({ version: 2 }), sampleProof()],
            { account: council[0].account },
          ),
        /(ProposalAlreadyConsumed|ProposalPayloadMismatch)/,
      );
    });

    it("a registered version is immutable", async () => {
      await activateVersion();
      const r = registration({ vkeyHash: keccak256(stringToHex("v1-replacement")) });
      const payload = await ev.read.encodeActivationPayload([r]);
      await gov.write.propose([Action.ActivateVerifierVersion, payload, "replace v1"], {
        account: council[0].account,
      });
      const proposalId = await gov.read.proposalCount();
      await gov.write.approve([proposalId], { account: council[1].account });
      await gov.write.approve([proposalId], { account: council[2].account });
      await time.increase(TIMELOCK + 1);
      await gov.write.execute([proposalId], { account: council[0].account });
      await assert.rejects(
        () =>
          ev.write.registerVerifier([proposalId, r, sampleProof()], {
            account: council[0].account,
          }),
        /VerifierVersionImmutable/,
      );
    });

    it("only a council member may register", async () => {
      const r = registration();
      const payload = await ev.read.encodeActivationPayload([r]);
      await gov.write.propose([Action.ActivateVerifierVersion, payload, "reg"], {
        account: council[0].account,
      });
      const proposalId = await gov.read.proposalCount();
      await gov.write.approve([proposalId], { account: council[1].account });
      await gov.write.approve([proposalId], { account: council[2].account });
      await time.increase(TIMELOCK + 1);
      await gov.write.execute([proposalId], { account: council[0].account });
      await assert.rejects(
        () =>
          ev.write.registerVerifier([proposalId, r, sampleProof()], {
            account: outsider.account,
          }),
        /NotCouncilMember/,
      );
    });

    it("rejects the zero address as a verifier", async () => {
      await assert.rejects(
        () =>
          activateVersion(
            registration({ impl: "0x0000000000000000000000000000000000000000" }),
          ),
        /VerifierAddressZero/,
      );
    });

    it("rejects a verifier that does not accept the sample proof", async () => {
      // The signals belong to a different proof, so the pairing fails. This is
      // the check that stops a bricked or wrong-circuit verifier from being
      // frozen into tenders.
      const bad = sampleProof();
      bad.signals = signalsOf("otherTender");
      await assert.rejects(() => activateVersion(registration(), bad), /SampleProofRejected/);
    });

    it("an unregistered version cannot be used and does not fall back", async () => {
      // No registration in this test at all. A silent fallback to "the
      // newest verifier" is the failure mode plan 11B.3 forbids.
      const [a, b, c] = proofArgs("valid");
      await assert.rejects(
        () => ev.read.verifyEligibility([tenderId, signalsOf("valid")[10], signalsOf("valid")[11], a, b, c]),
        /VerifierVersionNotRegistered/,
      );
    });
  });

  // ---------------------------------------------------------- public signals

  describe("the contract decides the public signals", () => {
    it("derives exactly the twelve signals the prover used", async () => {
      // The cross-check. The fixture's signals came from TypeScript reading
      // the spec; these come from Solidity reading chain state.
      const expected = signalsOf("valid");
      const got = await ev.read.expectedPublicSignals([
        tenderId,
        expected[10],
        expected[11],
      ]);
      const labels = [
        "tenderIdField", "rulesHashHi", "rulesHashLo", "turnoverThreshold",
        "experienceMonthsThreshold", "requiredCertificationCode", "deadline",
        "issuerRegistryRoot", "revocationRoot", "credentialEpoch",
        "nullifier", "bidCommitment",
      ];
      for (let i = 0; i < 12; i++) {
        assert.equal(got[i], expected[i], `signal ${i} (${labels[i]}) disagrees`);
      }
    });

    it("the two rulesHash limbs reconstruct the stored hash", async () => {
      const got = await ev.read.expectedPublicSignals([tenderId, 1n, 2n]);
      const reconstructed = toHex((got[1] << 128n) | got[2], { size: 32 });
      assert.equal(reconstructed, CHAIN.rulesHash);
      assert.equal(got[1], BigInt(CHAIN.rulesHashLimbs.hi));
      assert.equal(got[2], BigInt(CHAIN.rulesHashLimbs.lo));
    });

    it("refuses to produce signals for a tender that is not activated", async () => {
      const draftId = await prepareDraft("FP-DRAFT-1");
      await assert.rejects(
        () => ev.read.expectedPublicSignals([draftId, 1n, 2n]),
        /TenderNotActivated/,
      );
    });

    it("refuses when the issuer registry root for the epoch is unpublished", async () => {
      // A fresh registry with no roots. Proving against an unpublished root
      // would mean proving membership in a tree nobody committed to.
      const bare = await hre.viem.deployContract("IssuerRegistry", [gov.address]);
      const tr2 = await hre.viem.deployContract("TenderRegistry", [
        gov.address, bare.address, REVIEW_WINDOW,
      ]);
      const ev2 = await hre.viem.deployContract("EligibilityVerifier", [
        gov.address, bare.address, tr2.address,
      ]);
      await bare.write.setTenderModule([tr2.address], { account: council[0].account });
      await tr2.write.setTenderAuthority([authority.account.address, true], {
        account: council[0].account,
      });
      const id = keccak256(stringToHex(CHAIN.tenderIdString));
      await tr2.write.createTender([CHAIN.tenderIdString], { account: authority.account });
      await tr2.write.setRuleDocument([id, stringToHex(CHAIN.canonicalRuleDocument)], {
        account: authority.account,
      });
      await tr2.write.setRuleFields([id, ruleFields()], { account: authority.account });
      await tr2.write.setCommitteeKey([id, PX, PY, ...committeeArgs()], {
        account: authority.account,
      });
      await tr2.write.activateTender([id, CHAIN.rulesHash], { account: authority.account });
      await assert.rejects(
        () => ev2.read.expectedPublicSignals([id, 1n, 2n]),
        /IssuerRootNotPublished/,
      );
    });

    it("refuses when the revocation root for the epoch is unpublished", async () => {
      // The empty sparse revocation tree has a NON-zero root, so a zero here
      // means "never published", not "nothing revoked".
      const epoch = 9n;
      await reg.write.publishIssuerRegistryRoot([epoch, CHAIN.issuerRegistryRoot], {
        account: council[0].account,
      });
      const id = await prepareDraft("FP-EPOCH-9", { issuerEpoch: epoch });
      await tr.write.activateTender([id, CHAIN.rulesHash], { account: authority.account });
      await assert.rejects(
        () => ev.read.expectedPublicSignals([id, 1n, 2n]),
        /RevocationRootNotPublished/,
      );
    });
  });

  // ------------------------------------------------------------ verification

  describe("proof verification", () => {
    beforeEach(async () => {
      await activateVersion();
    });

    it("accepts a valid proof bound to this tender", async () => {
      const s = signalsOf("valid");
      const [a, b, c] = proofArgs("valid");
      assert.equal(
        await ev.read.verifyEligibility([tenderId, s[10], s[11], a, b, c]),
        true,
      );
    });

    it("requireEligibility does not revert for a valid proof", async () => {
      const s = signalsOf("valid");
      const [a, b, c] = proofArgs("valid");
      await ev.read.requireEligibility([tenderId, s[10], s[11], a, b, c]);
    });

    it("accepts a second, distinct bidder on the same tender", async () => {
      const s = signalsOf("secondBidder");
      const v = signalsOf("valid");
      // Distinct nullifiers: the same tender, different subject secrets.
      assert.notEqual(s[10], v[10]);
      const [a, b, c] = proofArgs("secondBidder");
      assert.equal(
        await ev.read.verifyEligibility([tenderId, s[10], s[11], a, b, c]),
        true,
      );
    });

    it("REJECTS a valid proof issued for a different tender", async () => {
      const s = signalsOf("otherTender");
      const [a, b, c] = proofArgs("otherTender");
      // Its nullifier and commitment are passed through faithfully; only
      // tenderIdField differs, and that one comes from storage.
      assert.equal(
        await ev.read.verifyEligibility([tenderId, s[10], s[11], a, b, c]),
        false,
      );
    });

    it("REJECTS a proof against thresholds the bidder chose", async () => {
      // The attack this contract exists to stop. The proof is sound; the
      // circuit is satisfied; the thresholds are turnover 1 and experience 0.
      const s = signalsOf("weakThresholds");
      assert.equal(s[3], 1n);
      assert.equal(s[4], 0n);
      const [a, b, c] = proofArgs("weakThresholds");
      assert.equal(
        await ev.read.verifyEligibility([tenderId, s[10], s[11], a, b, c]),
        false,
      );
    });

    it("the raw Groth16 verifier ACCEPTS both rejected proofs", async () => {
      // Proof that the rejection above comes from the adapter's binding to
      // tender state and not from a broken proof or a broken verifier. If
      // this test ever fails, the two tests above are passing for the wrong
      // reason and prove nothing.
      for (const name of ["otherTender", "weakThresholds"]) {
        const [a, b, c] = proofArgs(name);
        assert.equal(
          await groth.read.verifyProof([a, b, c, signalsOf(name)]),
          true,
          `${name} should verify against the raw verifier`,
        );
      }
    });

    it("rejects a tampered proof", async () => {
      const s = signalsOf("valid");
      const [a, b, c] = proofArgs("valid");
      const tampered = [a[0] + 1n, a[1]];
      assert.equal(
        await ev.read.verifyEligibility([tenderId, s[10], s[11], tampered, b, c]),
        false,
      );
    });

    it("rejects a proof re-used with someone else's nullifier", async () => {
      // The nullifier is a public signal inside the proof, so swapping it
      // breaks the pairing rather than being silently accepted.
      const s = signalsOf("valid");
      const other = signalsOf("secondBidder");
      const [a, b, c] = proofArgs("valid");
      assert.equal(
        await ev.read.verifyEligibility([tenderId, other[10], s[11], a, b, c]),
        false,
      );
    });

    it("requireEligibility reverts with the pinned version on rejection", async () => {
      const s = signalsOf("weakThresholds");
      const [a, b, c] = proofArgs("weakThresholds");
      await assert.rejects(
        () => ev.read.requireEligibility([tenderId, s[10], s[11], a, b, c]),
        /ProofRejected/,
      );
    });
  });

  describe("gas (plan Section 20.6 benchmark record)", () => {
    beforeEach(async () => {
      await activateVersion();
    });

    it("reports the measured cost of on-chain verification", async () => {
      // Both entry points are `view`, so a bidder pays nothing to check a
      // proof. What matters for the benchmark is the cost when SealedBid
      // calls this inside a transaction, which is what estimateGas reports.
      const client = await hre.viem.getPublicClient();
      const s = signalsOf("valid");
      const [a, b, c] = proofArgs("valid");

      const verify = await client.estimateContractGas({
        address: ev.address,
        abi: ev.abi,
        functionName: "verifyEligibility",
        args: [tenderId, s[10], s[11], a, b, c],
        account: outsider.account,
      });
      const raw = await client.estimateContractGas({
        address: groth.address,
        abi: groth.abi,
        functionName: "verifyProof",
        args: [a, b, c, s],
        account: outsider.account,
      });
      const replay = await client.estimateContractGas({
        address: ev.address,
        abi: ev.abi,
        functionName: "verifyWithSignals",
        args: [tenderId, s, a, b, c],
        account: outsider.account,
      });

      console.log(`      raw Groth16 verifyProof: ${raw}`);
      console.log(`      adapter verifyEligibility: ${verify}`);
      console.log(`      adapter verifyWithSignals: ${replay}`);
      console.log(`      adapter overhead: ${verify - raw} gas`);

      // A sanity floor, not a performance target: pairing checks cannot be
      // cheap, so a suspiciously small number would mean the pairing was
      // skipped rather than that the code got fast.
      assert.ok(raw > 200000n, "a Groth16 pairing check cannot cost this little");
      assert.ok(verify > raw, "the adapter must cost more than the bare pairing");
    });
  });

  // ---------------------------------------------------------- replay path

  describe("verifyWithSignals (replay against a published record)", () => {
    beforeEach(async () => {
      await activateVersion();
    });

    it("accepts the published signal array", async () => {
      const [a, b, c] = proofArgs("valid");
      assert.equal(
        await ev.read.verifyWithSignals([tenderId, signalsOf("valid"), a, b, c]),
        true,
      );
    });

    it("rejects limbs that do not reconstruct the stored rulesHash", async () => {
      const s = signalsOf("valid");
      const [a, b, c] = proofArgs("valid");
      const bad = [...s];
      bad[1] = bad[1] + 1n;
      await assert.rejects(
        () => ev.read.verifyWithSignals([tenderId, bad, a, b, c]),
        /RulesHashMismatchInSignals/,
      );
    });

    it("rejects swapped hi and lo limbs", async () => {
      // Individually in range, jointly wrong. A per-limb range check alone
      // would let this through.
      const s = signalsOf("valid");
      const [a, b, c] = proofArgs("valid");
      const swapped = [...s];
      swapped[1] = s[2];
      swapped[2] = s[1];
      await assert.rejects(
        () => ev.read.verifyWithSignals([tenderId, swapped, a, b, c]),
        /RulesHashMismatchInSignals/,
      );
    });

    it("rejects a limb wider than 128 bits", async () => {
      const s = signalsOf("valid");
      const [a, b, c] = proofArgs("valid");
      const bad = [...s];
      bad[1] = 1n << 128n;
      await assert.rejects(
        () => ev.read.verifyWithSignals([tenderId, bad, a, b, c]),
        /LimbExceeds128Bits/,
      );
    });

    it("rejects a tampered threshold, naming the signal index", async () => {
      const s = signalsOf("valid");
      const [a, b, c] = proofArgs("valid");
      const bad = [...s];
      bad[3] = 1n;
      await assert.rejects(
        () => ev.read.verifyWithSignals([tenderId, bad, a, b, c]),
        /PublicSignalMismatch/,
      );
    });

    it("rejects the weak-threshold proof's own signal array", async () => {
      const [a, b, c] = proofArgs("weakThresholds");
      await assert.rejects(
        () => ev.read.verifyWithSignals([tenderId, signalsOf("weakThresholds"), a, b, c]),
        /PublicSignalMismatch/,
      );
    });
  });

  // -------------------------------------------------------- version pinning

  describe("a running tender is never re-scored under a new verifier", () => {
    it("registering v2 mid-tender leaves the ACTIVE tender on v1", async () => {
      // Whitepaper Section 14, and the explicit test plan 11B.3 asks for.
      await activateVersion();
      const before = await tr.read.getTender([tenderId]);
      assert.equal(before.state, State.ACTIVE);
      assert.equal(before.verifierVersion, 1);

      // A second, independently deployed verifier registered as version 2.
      const groth2 = await hre.viem.deployContract("EligibilityVerifierGroth16", []);
      await activateVersion(
        registration({ version: 2, impl: groth2.address }),
        sampleProof(),
      );
      assert.equal(await ev.read.isVersionRegistered([2]), true);

      const after = await tr.read.getTender([tenderId]);
      assert.equal(after.verifierVersion, 1, "the tender's pin must not move");
      assert.equal(after.rulesHash, before.rulesHash);
      assert.equal(after.fieldsDigest, before.fieldsDigest);
      assert.equal(after.activatedAt, before.activatedAt);
      assert.equal(after.state, State.ACTIVE);

      // And it still verifies, against version 1.
      const s = signalsOf("valid");
      const [a, b, c] = proofArgs("valid");
      assert.equal(
        await ev.read.verifyEligibility([tenderId, s[10], s[11], a, b, c]),
        true,
      );
    });

    it("a tender cannot be activated pinning an unregistered version", async () => {
      // Without this guard, a typo produces a permanently unbiddable tender
      // that can only be cancelled, discovered by the first bidder.
      await tr.write.setVerifierVersionRegistry([ev.address], {
        account: council[0].account,
      });
      const id = await prepareDraft("FP-UNPINNED", { verifierVersion: 99 });
      await assert.rejects(
        () => tr.write.activateTender([id, CHAIN.rulesHash], { account: authority.account }),
        /VerifierVersionNotRegistered/,
      );
    });

    it("activation succeeds once the pinned version is registered", async () => {
      await activateVersion();
      await tr.write.setVerifierVersionRegistry([ev.address], {
        account: council[0].account,
      });
      const id = await prepareDraft("FP-PINNED-OK");
      await tr.write.activateTender([id, CHAIN.rulesHash], { account: authority.account });
      assert.equal((await tr.read.getTender([id])).state, State.ACTIVE);
    });

    it("only the council may wire the verifier registry", async () => {
      await assert.rejects(
        () => tr.write.setVerifierVersionRegistry([ev.address], { account: outsider.account }),
        /NotCouncilMember/,
      );
    });
  });
});
