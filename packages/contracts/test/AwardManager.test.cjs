const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { join } = require("node:path");
const hre = require("hardhat");
const {
  time,
  loadFixture,
  reset,
} = require("@nomicfoundation/hardhat-network-helpers");
const { encodePacked, keccak256, stringToHex } = require("viem");
const { privateKeyToAccount } = require("viem/accounts");

/**
 * AwardManager: the award, against a proof over the COMPLETE bid set.
 *
 * Development plan Section 14, whitepaper Section 7.
 *
 * The award proofs come from the shared fixture and are real. The fixture
 * derives `bidSetRoot` from the same spec the bids came from, and the contract
 * reads it from `SealedBid` - two independent routes to one value, which is
 * what makes their agreement evidence rather than a tautology.
 *
 * This suite runs the whole pipeline for every test: two bids accepted, the
 * tender closed, both ciphertexts revealed, six decryption shares verified.
 * That is slow, and it is the only way to test an award: the contract refuses
 * to record one until every accepted bid has been opened.
 */

const FIX = JSON.parse(
  readFileSync(join(__dirname, "../../circuits/fixtures/eligibility.proof.json"), "utf8"),
);
const CHAIN = FIX.chain;
const SPEC = FIX.tender;
const SEALED = FIX.sealed;
const OPENING = FIX.opening;
const AWARD = FIX.award;

const {
  publicKey: COMMITTEE_Y,
  committeeArgs: dealtCommitteeArgs,
} = require("./helpers/committee.cjs");

const RAW_RECEIPT_SIG_V1 =
  "0xc3ffb182dd3ebfe5535def6710ba4562e2bf2416e6ac55e4ac25fc7e14433ea3";
const Action = { ActivateVerifierVersion: 3 };
const TIMELOCK = 60;
const REVIEW_WINDOW = BigInt(SPEC.reviewWindow);
const State = { CLOSED: 3 };
const REPLICA_KEYS = ["0x" + "a1".repeat(32), "0x" + "b2".repeat(32), "0x" + "c3".repeat(32)];
const VKEY_HASH = keccak256(stringToHex("award-vkey"));
const TRANSCRIPT = "packages/circuits/ceremony/award.transcript.json";

const eligProof = (name) => {
  const f = FIX.fixtures[name];
  return [f.pA.map(BigInt), f.pB.map((r) => r.map(BigInt)), f.pC.map(BigInt)];
};
const signalsOf = (name) => FIX.fixtures[name].publicSignals.map(BigInt);

/** An award fixture as the three proof arguments. */
const awardProof = (name) => {
  const a = AWARD[name];
  return [a.pA.map(BigInt), a.pB.map((r) => r.map(BigInt)), a.pC.map(BigInt)];
};

const dleq = (p) => ({
  aX: BigInt(p.aX), aY: BigInt(p.aY),
  bX: BigInt(p.bX), bY: BigInt(p.bY),
  z: BigInt(p.z),
});

describe("AwardManager", function () {
  this.timeout(600000);

  let gov, reg, tr, ev, sb, om, am, ds, awardVerifier;
  let council, authority, outsider, committee, tenderId, poseidonLibs;

  /**
   * Start from a clean network: this suite moves the clock to a deadline in
   * 2096, and mocha shares one network across every test file.
   */
  before(async () => {
    await reset();
  });
  after(async () => {
    await reset();
  });

  /** A signed storage receipt from one replica. */
  async function receipt(replicaId, contentHash, byteLength) {
    const account = privateKeyToAccount(REPLICA_KEYS[replicaId - 1]);
    const digest = keccak256(
      encodePacked(
        ["bytes32", "uint8", "bytes32", "uint64"],
        [RAW_RECEIPT_SIG_V1, replicaId, contentHash, BigInt(byteLength)],
      ),
    );
    return {
      replicaId,
      contentHash,
      byteLength: BigInt(byteLength),
      signature: await account.sign({ hash: digest }),
    };
  }

  /**
   * The whole pipeline, up to a CLOSED tender with two bids fully opened.
   *
   * @param opts.circuitVersion   what AwardManager enforces (default 1)
   * @param opts.openSecondBid    open bid 1 as well (default true)
   * @param opts.disclosurePolicy tender's frozen policy (default 1, publish)
   */
  function makeFixture(opts = {}) {
    const circuitVersion = opts.circuitVersion ?? 1;
    const openSecondBid = opts.openSecondBid ?? true;
    const disclosurePolicy = opts.disclosurePolicy ?? SPEC.disclosurePolicy;

    return async function deployAll() {
      const w = await hre.viem.getWalletClients();
      const councilW = w.slice(0, 4);
      const authorityW = w[4];
      const outsiderW = w[5];
      const committeeW = w.slice(6, 11);

      const govC = await hre.viem.deployContract("Governance", [
        councilW.map((x) => x.account.address),
      ]);
      const regC = await hre.viem.deployContract("IssuerRegistry", [govC.address]);
      const trC = await hre.viem.deployContract("TenderRegistry", [
        govC.address, regC.address, REVIEW_WINDOW,
      ]);
      const grothC = await hre.viem.deployContract("EligibilityVerifierGroth16", []);
      const evC = await hre.viem.deployContract("EligibilityVerifier", [
        govC.address, regC.address, trC.address,
      ]);
      const t3 = await hre.viem.deployContract("PoseidonT3");
      const t6 = await hre.viem.deployContract("PoseidonT6");
      const libs = {
        "poseidon-solidity/PoseidonT3.sol:PoseidonT3": t3.address,
        "poseidon-solidity/PoseidonT6.sol:PoseidonT6": t6.address,
      };
      const sbC = await hre.viem.deployContract(
        "SealedBid",
        [govC.address, trC.address, evC.address],
        { libraries: libs },
      );
      const omC = await hre.viem.deployContract("OpeningManager", [
        govC.address, trC.address, sbC.address,
      ]);
      const awardVerifierC = await hre.viem.deployContract("AwardVerifierGroth16", []);
      const dsC = await hre.viem.deployContract("DeadlineStatus", [
        trC.address, regC.address, sbC.address, evC.address,
      ]);
      const amC = await hre.viem.deployContract("AwardManager", [
        govC.address, trC.address, sbC.address, omC.address, dsC.address,
        awardVerifierC.address, circuitVersion, VKEY_HASH, TRANSCRIPT,
      ]);

      await regC.write.setTenderModule([trC.address], { account: councilW[0].account });
      const epoch = BigInt(SPEC.credentialEpoch);
      await regC.write.publishIssuerRegistryRoot([epoch, CHAIN.issuerRegistryRoot], {
        account: councilW[0].account,
      });
      await regC.write.publishRevocationRoot([epoch, CHAIN.revocationRoot], {
        account: councilW[0].account,
      });
      // The DEADLINE root is pinned from the registry's CURRENT epoch when
      // the tender closes, and it is deliberately a different tree from the
      // submission-time one: credential 9999 is revoked in it while both
      // bidders stay clean. If the two roots were equal, the original
      // eligibility proof would double as a status proof and the close-time
      // check would be exercised only vacuously.
      const currentEpoch = await regC.read.currentEpoch();
      await regC.write.publishRevocationRoot(
        [currentEpoch, CHAIN.deadlineRevocationRoot],
        { account: councilW[0].account },
      );
      await trC.write.setTenderAuthority([authorityW.account.address, true], {
        account: councilW[0].account,
      });
      for (const [i, k] of REPLICA_KEYS.entries()) {
        await sbC.write.registerReplica(
          [i + 1, privateKeyToAccount(k).address, `replica-${i + 1}`],
          { account: councilW[0].account },
        );
      }

      // eligibility verifier v1 through the real governance flow
      const r = {
        version: 1, impl: grothC.address,
        vkeyHash: keccak256(stringToHex("vkey")),
        sourceHash: keccak256(stringToHex("source")),
        transcriptUri: "ceremony",
      };
      const payload = await evC.read.encodeActivationPayload([r]);
      await govC.write.propose([Action.ActivateVerifierVersion, payload, "v1"], {
        account: councilW[0].account,
      });
      const pid = await govC.read.proposalCount();
      await govC.write.approve([pid], { account: councilW[1].account });
      await govC.write.approve([pid], { account: councilW[2].account });
      await time.increase(TIMELOCK + 1);
      await govC.write.execute([pid], { account: councilW[0].account });
      const [pa, pb, pc] = eligProof("valid");
      await evC.write.registerVerifier(
        [pid, r, { a: pa, b: pb, c: pc, signals: signalsOf("valid") }],
        { account: councilW[0].account },
      );

      // the tender
      const nowTs = BigInt(await time.latest());
      const biddingStart = nowTs + REVIEW_WINDOW + 10n;
      const id = keccak256(stringToHex(CHAIN.tenderIdString));
      await trC.write.createTender([CHAIN.tenderIdString], { account: authorityW.account });
      await trC.write.setRuleDocument([id, stringToHex(CHAIN.canonicalRuleDocument)], {
        account: authorityW.account,
      });
      await trC.write.setRuleFields([id, {
        requirements: {
          turnoverThreshold: BigInt(SPEC.turnoverThreshold),
          experienceMonths: Number(SPEC.experienceMonthsThreshold),
          certificationCode: BigInt(SPEC.requiredCertificationCode),
        },
        biddingStart,
        deadline: BigInt(SPEC.deadline),
        requiredIssuerId: keccak256(stringToHex(SPEC.requiredIssuerId)),
        issuerEpoch: epoch,
        schemaVersion: SPEC.schemaVersion,
        verifierVersion: SPEC.verifierVersion,
        disclosurePolicy,
        awardRule: SPEC.awardRule,
        tieBreakRule: SPEC.tieBreakRule,
        contingencyPolicy: SPEC.contingencyPolicy,
        reviewWindow: REVIEW_WINDOW,
      }], { account: authorityW.account });
      await trC.write.setCommitteeKey(
        [id, COMMITTEE_Y.x, COMMITTEE_Y.y,
         ...dealtCommitteeArgs(committeeW.map((x) => x.account.address))],
        { account: authorityW.account },
      );
      await trC.write.activateTender([id, CHAIN.rulesHash], { account: authorityW.account });
      await time.increaseTo(biddingStart + 1n);

      // both bids, in submission order - the leaf commits to the index, so
      // the order here is what the award's bidSetRoot was built from.
      for (const name of ["valid", "secondBidder"]) {
        const s = signalsOf(name);
        const [a, b, c] = eligProof(name);
        const receipts = await Promise.all(
          [1, 2].map((rid) => receipt(rid, SEALED[name].ciphertextHash, SEALED[name].byteLength)),
        );
        await sbC.write.submitBid(
          [
            {
              tenderId: id,
              nullifier: s[10],
              bidCommitment: s[11],
              ciphertextHash: SEALED[name].ciphertextHash,
            },
            receipts, a, b, c,
          ],
          { account: outsiderW.account },
        );
      }

      // close, then open
      await time.increaseTo(BigInt(SPEC.deadline) + 1n);
      await trC.write.closeTender([id], { account: outsiderW.account });

      const toOpen = openSecondBid ? ["valid", "secondBidder"] : ["valid"];
      for (const [bidIndex, name] of toOpen.entries()) {
        await omC.write.revealCiphertext([id, bidIndex, SEALED[name].canonicalBytes], {
          account: outsiderW.account,
        });
        for (const memberIndex of [1, 2, 3]) {
          const sh = OPENING[name].shares.find((x) => x.memberIndex === memberIndex);
          await omC.write.submitDecryptionShare(
            [id, bidIndex, memberIndex, BigInt(sh.share.x), BigInt(sh.share.y), dleq(sh.proof)],
            { account: committeeW[memberIndex - 1].account },
          );
        }
      }

      // Close-time status proofs. Whitepaper Section 5: the winner must be
      // provably unrevoked against the PINNED deadline root, not against the
      // snapshot that was current when the bid was submitted.
      const statusFor = { valid: "statusValid", secondBidder: "statusSecondBidder" };
      if (opts.skipStatusProofs !== true) {
        for (const [bidIndex, name] of toOpen.entries()) {
          const [a, b, c] = eligProof(statusFor[name]);
          await dsC.write.submitStatusProof([id, bidIndex, a, b, c], {
            account: outsiderW.account,
          });
        }
      }

      return {
        gov: govC, reg: regC, tr: trC, ev: evC, sb: sbC, om: omC, am: amC, ds: dsC,
        awardVerifier: awardVerifierC,
        council: councilW, authority: authorityW, outsider: outsiderW,
        committee: committeeW, tenderId: id, poseidonLibs: libs,
      };
    };
  }

  /** The tender exactly as the spec describes it: WINNER_ONLY_POST_AWARD. */
  const standard = makeFixture();

  /**
   * Run a fixture from a PRISTINE chain.
   *
   * `loadFixture` is deliberately NOT used, and the reason is structural.
   * Reaching an awardable state means closing the tender, and the shared
   * fixture's deadline is in 2096 so the committed proofs never rot - so
   * every fixture here ends with the clock past 2096, and any fixture run
   * afterwards computes a biddingStart beyond that deadline and fails with
   * InvalidBiddingWindow, which reads like a rule error rather than a
   * test-ordering problem. Snapshot caching cannot help: the trouble is the
   * chain state a cached fixture is re-run FROM. A full redeploy per test is
   * the price of a suite whose failures mean what they say.
   */
  async function useFixture(fn) {
    await reset();
    return fn();
  }

  beforeEach(async () => {
    ({
      gov, reg, tr, ev, sb, om, am, ds, awardVerifier,
      council, authority, outsider, committee, tenderId, poseidonLibs,
    } = await useFixture(standard));
  });

  /**
   * Record the award for the standard tender.
   *
   * The standard tender's disclosure policy is the one the spec's rule
   * document declares - WINNER_ONLY_POST_AWARD - so the matching award proof
   * is the CONCEALED one and the recorded price is zero. An earlier version of
   * this suite used the disclosing proof here and every test failed with
   * PriceMustBeConcealed, which was the contract being right and the test
   * being wrong about its own tender.
   */
  function record(overrides = {}) {
    const a = AWARD.concealed;
    const [pa, pb, pc] = awardProof(overrides.proof ?? "concealed");
    return am.write.recordAward(
      [
        tenderId,
        overrides.winnerCommitment ?? BigInt(a.winnerCommitment),
        overrides.winningPrice ?? BigInt(a.winningPrice),
        overrides.winnerIndex ?? a.winnerIndex,
        pa, pb, pc,
      ],
      { account: (overrides.account ?? authority).account },
    );
  }

  // ---------------------------------------------------------------- setup

  describe("the pipeline reaches an awardable state", () => {
    it("two bids accepted, tender CLOSED, both opened", async () => {
      assert.equal(await sb.read.submissionCount([tenderId]), 2n);
      assert.equal(await tr.read.getState([tenderId]), State.CLOSED);
      const [opened, total] = await am.read.openedCount([tenderId]);
      assert.equal(opened, 2n);
      assert.equal(total, 2n);
    });

    it("the chain's bidSetRoot is the one the award proof was built against", async () => {
      // The fixture derived this root in TypeScript from the spec; the
      // contract accumulated it from Poseidon on-chain. Neither consulted the
      // other.
      assert.equal(
        await sb.read.bidSetRoot([tenderId]),
        BigInt(AWARD.disclosed.bidSetRoot),
      );
    });

    it("the contract derives exactly the eight signals the prover used", async () => {
      const a = AWARD.concealed;
      const got = await am.read.expectedPublicSignals([
        tenderId, BigInt(a.winnerCommitment), BigInt(a.winningPrice),
      ]);
      const labels = [
        "tenderIdField", "rulesHashHi", "rulesHashLo", "bidSetRoot",
        "submissionCount", "winnerCommitment", "winningPrice", "disclosurePolicy",
      ];
      for (let i = 0; i < 8; i++) {
        assert.equal(got[i], BigInt(a.publicSignals[i]), `signal ${i} (${labels[i]})`);
      }
    });

    it("records the verifier's provenance", async () => {
      assert.equal(await am.read.circuitVersion(), 1);
      assert.equal(await am.read.vkeyHash(), VKEY_HASH);
      assert.equal(await am.read.transcriptUri(), TRANSCRIPT);
      assert.equal(await am.read.PUBLIC_SIGNAL_COUNT(), 8n);
    });
  });

  // ---------------------------------------------------------- the happy path

  describe("recording the award", () => {
    it("records the lowest-priced bid as winner", async () => {
      assert.equal(await am.read.isAwarded([tenderId]), false);
      await record();
      assert.equal(await am.read.isAwarded([tenderId]), true);

      const a = await am.read.getAward([tenderId]);
      // Bidder A at BDT 74,00,000 beats bidder B at BDT 81,50,000. The winner
      // is identified; the AMOUNT is withheld, because this tender's frozen
      // policy is WINNER_ONLY_POST_AWARD.
      assert.equal(a.winningPrice, 0n);
      assert.equal(a.disclosurePolicy, 2);
      assert.equal(a.winnerSubmissionIndex, 0);
      assert.equal(a.winnerCommitment, signalsOf("valid")[11]);
      assert.equal(a.submissionCount, 2n);
      assert.equal(a.bidSetRoot, await sb.read.bidSetRoot([tenderId]));
      assert.equal(a.recordedBy.toLowerCase(), authority.account.address.toLowerCase());
    });

    it("the winner is the bid the chain accepted, not just a commitment", async () => {
      await record();
      const a = await am.read.getAward([tenderId]);
      const bid = await sb.read.getBid([tenderId, BigInt(a.winnerSubmissionIndex)]);
      assert.equal(bid.bidCommitment, a.winnerCommitment);
    });

    it("emits the full award record", async () => {
      const client = await hre.viem.getPublicClient();
      await client.waitForTransactionReceipt({ hash: await record() });
      const logs = await client.getContractEvents({
        address: am.address, abi: am.abi, eventName: "AwardRecorded",
        fromBlock: 0n, toBlock: "latest",
      });
      assert.equal(logs.length, 1);
      assert.equal(logs[0].args.winningPrice, 0n);
      assert.equal(logs[0].args.submissionCount, 2n);
      assert.equal(logs[0].args.bidSetRoot, await sb.read.bidSetRoot([tenderId]));
    });

    it("cannot be recorded twice", async () => {
      await record();
      await assert.rejects(() => record(), /AlreadyAwarded/);
    });

    it("reverts for a tender with no award yet", async () => {
      await assert.rejects(() => am.read.getAward([tenderId]), /NotAwarded/);
    });
  });

  // ------------------------------------------------------------- who may

  describe("only the authority may record", () => {
    it("rejects an outsider", async () => {
      // Whitepaper Section 7 makes the authority the prover; an award
      // recorded by anyone else would not be attributable to the body
      // accountable for it.
      await assert.rejects(() => record({ account: outsider }), /NotAuthority/);
    });

    it("rejects the council", async () => {
      await assert.rejects(() => record({ account: council[0] }), /NotAuthority/);
    });
  });

  // -------------------------------------------------- completeness of opening

  describe("every accepted bid must be opened first", () => {
    const oneUnopened = makeFixture({ openSecondBid: false });

    it("REJECTS an award while a bid is unopened, naming it", async () => {
      // An award over a subset is an award over an incomplete set. If a bid
      // genuinely cannot be opened the correct outcome is cancellation with a
      // recorded reason, not an award over whatever happened to open.
      const f = await useFixture(oneUnopened);
      const [opened, total] = await f.am.read.openedCount([f.tenderId]);
      assert.equal(opened, 1n);
      assert.equal(total, 2n);

      const a = AWARD.concealed;
      const [pa, pb, pc] = awardProof("concealed");
      await assert.rejects(
        () =>
          f.am.write.recordAward(
            [f.tenderId, BigInt(a.winnerCommitment), BigInt(a.winningPrice), a.winnerIndex, pa, pb, pc],
            { account: f.authority.account },
          ),
        /BidNotOpened/,
      );
    });

    it("openedCount lets the UI say how many are outstanding", async () => {
      const f = await useFixture(oneUnopened);
      const [opened, total] = await f.am.read.openedCount([f.tenderId]);
      assert.equal(`${opened}/${total}`, "1/2");
    });
  });

  // ------------------------------------------------------ the winner itself

  describe("the winner must be an accepted bid", () => {
    it("rejects a commitment that is not the named bid's", async () => {
      await assert.rejects(
        () => record({ winnerCommitment: signalsOf("secondBidder")[11] }),
        /WinnerNotAnAcceptedBid/,
      );
    });

    it("rejects a fabricated commitment", async () => {
      await assert.rejects(() => record({ winnerCommitment: 12345n }), /WinnerNotAnAcceptedBid/);
    });

    it("rejects a submission index that does not exist", async () => {
      await assert.rejects(() => record({ winnerIndex: 5 }), /NoBids/);
    });

    it("rejects naming the LOSING bid as winner", async () => {
      // Index 1 and its own commitment: internally consistent, and the proof
      // does not attest to it, so verification fails.
      await assert.rejects(
        () =>
          record({
            winnerIndex: 1,
            winnerCommitment: signalsOf("secondBidder")[11],
          }),
        /AwardProofRejected/,
      );
    });
  });

  // ------------------------------------------------------ disclosure policy

  describe("the disclosure policy is enforced on-chain as well", () => {
    /**
     * A tender whose structured `disclosurePolicy` FIELD says publish.
     *
     * Note what this variant actually is: the stored rule document still reads
     * "WINNER_ONLY_POST_AWARD", because the document is what `rulesHash`
     * covers and every eligibility proof is bound to that hash. Only the
     * structured field differs.
     *
     * That divergence is not an accident of the test - it is exactly the
     * PARTIAL residual documented on `TenderRegistry`: Solidity cannot parse
     * JSON, so the contract cannot check that the stored document parses to
     * the fields it enforces. This test makes the residual concrete, and it
     * also shows what bounds it: the ENFORCEMENT path uses the field, so a
     * misleading document can only misdescribe what the contract does, never
     * change it. The independent verifier re-parses the document and compares
     * field by field, and both values are public and permanent.
     */
    const publishing = makeFixture({ disclosurePolicy: 1 });

    it("the standard tender conceals the price, as its document declares", async () => {
      // Whitepaper Section 7: under a winner-only policy no amount is
      // published, the winner's included.
      await record();
      const rec = await am.read.getAward([tenderId]);
      assert.equal(rec.winningPrice, 0n);
      assert.equal(rec.disclosurePolicy, 2);
      // The winner is still identified; only the amount is withheld.
      assert.equal(rec.winnerCommitment, signalsOf("valid")[11]);
    });

    it("REJECTS publishing a price under a concealing policy", async () => {
      await assert.rejects(() => record({ winningPrice: 7400000n }), /PriceMustBeConcealed/);
    });

    it("a publishing tender records the real price", async () => {
      const f = await useFixture(publishing);
      const a = AWARD.disclosed;
      const [pa, pb, pc] = awardProof("disclosed");
      await f.am.write.recordAward(
        [f.tenderId, BigInt(a.winnerCommitment), BigInt(a.winningPrice), a.winnerIndex, pa, pb, pc],
        { account: f.authority.account },
      );
      const rec = await f.am.read.getAward([f.tenderId]);
      assert.equal(rec.winningPrice, 7400000n);
      assert.equal(rec.disclosurePolicy, 1);
    });

    it("REJECTS a zero price under a publishing policy", async () => {
      const f = await useFixture(publishing);
      const a = AWARD.disclosed;
      const [pa, pb, pc] = awardProof("disclosed");
      await assert.rejects(
        () =>
          f.am.write.recordAward(
            [f.tenderId, BigInt(a.winnerCommitment), 0n, a.winnerIndex, pa, pb, pc],
            { account: f.authority.account },
          ),
        /PriceMustBePublished/,
      );
    });

    it("a proof for one policy does not verify under another", async () => {
      // `disclosurePolicy` is public signal 7, so a proof built for a
      // publishing tender cannot be presented on a concealing one even with a
      // zero price supplied.
      await assert.rejects(
        () => record({ proof: "disclosed" }),
        /AwardProofRejected/,
      );
    });
  });

  // ---------------------------------------------- stale roots and wrong counts

  describe("a stale root or a wrong count is unreachable on-chain", () => {
    it("a single-bid award proof does not verify on a two-bid tender", async () => {
      /**
       * Plan Section 14.3 attacks 4 and 5, "use a stale root" and "use a
       * wrong count". The contract reads `bidSetRoot` and `submissionCount`
       * from SealedBid, so the authority cannot present a proof built against
       * an earlier, smaller set - there is no parameter through which to offer
       * one.
       *
       * Run on the PUBLISHING tender on purpose. The single-bid proof was
       * generated under policy 1, so on the concealing tender the price check
       * would fire first and the test would pass without ever reaching the
       * verifier - proving nothing about roots. Here the policy matches and
       * the only mismatch left is the root and the count.
       */
      const f = await useFixture(makeFixture({ disclosurePolicy: 1 }));
      const a = AWARD.singleBid;
      assert.equal(a.submissionCount, 1);
      assert.equal(a.disclosurePolicy, 1);
      assert.notEqual(a.bidSetRoot, AWARD.disclosed.bidSetRoot);
      assert.equal(await f.sb.read.submissionCount([f.tenderId]), 2n);
      const [pa, pb, pc] = awardProof("singleBid");
      await assert.rejects(
        () =>
          f.am.write.recordAward(
            [f.tenderId, BigInt(a.winnerCommitment), BigInt(a.winningPrice), a.winnerIndex, pa, pb, pc],
            { account: f.authority.account },
          ),
        /AwardProofRejected/,
      );
    });

    it("the raw verifier ACCEPTS the single-bid proof", async () => {
      // So the rejection above comes from the adapter's binding to chain
      // state, not from a broken proof. Without this the test above could be
      // passing for the wrong reason.
      const a = AWARD.singleBid;
      const [pa, pb, pc] = awardProof("singleBid");
      assert.equal(
        await awardVerifier.read.verifyProof([pa, pb, pc, a.publicSignals.map(BigInt)]),
        true,
      );
    });

    it("a tampered proof is rejected", async () => {
      const [pa, pb, pc] = awardProof("concealed");
      const a = AWARD.concealed;
      await assert.rejects(
        () =>
          am.write.recordAward(
            [tenderId, BigInt(a.winnerCommitment), BigInt(a.winningPrice), a.winnerIndex,
             [pa[0] + 1n, pa[1]], pb, pc],
            { account: authority.account },
          ),
        /AwardProofRejected/,
      );
    });
  });

  // ------------------------------------------------ close-time status proofs

  describe("the winner must be unrevoked at the DEADLINE root", () => {
    const noStatus = makeFixture({ skipStatusProofs: true });

    it("both bids carry a status proof against the pinned root", async () => {
      const [proven, total] = await ds.read.provenCount([tenderId]);
      assert.equal(proven, 2n);
      assert.equal(total, 2n);
      const st = await ds.read.getStatus([tenderId, 0]);
      assert.equal(st.proven, true);
      assert.equal(st.deadlineRoot, CHAIN.deadlineRevocationRoot);
    });

    it("the deadline root DIFFERS from the submission-time root", async () => {
      // Otherwise the close-time check would be satisfied by the original
      // eligibility proof and would prove nothing new.
      assert.notEqual(CHAIN.deadlineRevocationRoot, CHAIN.revocationRoot);
      assert.equal(
        await reg.read.deadlineRevocationRoot([tenderId]),
        CHAIN.deadlineRevocationRoot,
      );
    });

    it("REJECTS an award when the winner has no status proof", async () => {
      const f = await useFixture(noStatus);
      const [proven] = await f.ds.read.provenCount([f.tenderId]);
      assert.equal(proven, 0n);
      const a = AWARD.concealed;
      const [pa, pb, pc] = awardProof("concealed");
      await assert.rejects(
        () =>
          f.am.write.recordAward(
            [f.tenderId, BigInt(a.winnerCommitment), BigInt(a.winningPrice), a.winnerIndex, pa, pb, pc],
            { account: f.authority.account },
          ),
        /WinnerStatusNotProven/,
      );
    });

    it("a submission-time proof is NOT a valid status proof", async () => {
      // The whole point of the deadline root: the original proof was checked
      // against the older snapshot, so it cannot stand in for the close-time
      // check.
      const f = await useFixture(noStatus);
      const [a, b, c] = eligProof("valid");
      await assert.rejects(
        () => f.ds.write.submitStatusProof([f.tenderId, 0, a, b, c], {
          account: f.outsider.account,
        }),
        /StatusProofRejected/,
      );
    });

    it("a status proof is one-shot per bid", async () => {
      const [a, b, c] = eligProof("statusValid");
      await assert.rejects(
        () => ds.write.submitStatusProof([tenderId, 0, a, b, c], {
          account: outsider.account,
        }),
        /AlreadyProven/,
      );
    });

    it("one bidder's status proof cannot be filed against another's bid", async () => {
      // The nullifier and commitment come from the accepted bid record, not
      // from the caller, so a proof can only ever be about the slot it is
      // filed against.
      const f = await useFixture(noStatus);
      const [a, b, c] = eligProof("statusSecondBidder");
      await assert.rejects(
        () => f.ds.write.submitStatusProof([f.tenderId, 0, a, b, c], {
          account: f.outsider.account,
        }),
        /StatusProofRejected/,
      );
    });

    it("rejects a status proof for a bid that does not exist", async () => {
      const [a, b, c] = eligProof("statusValid");
      await assert.rejects(
        () => ds.write.submitStatusProof([tenderId, 9, a, b, c], {
          account: outsider.account,
        }),
        /NoSuchBid/,
      );
    });
  });

  // -------------------------------------------------------- version pinning

  describe("a tender is never awarded under a different circuit version", () => {
    const versionTwo = makeFixture({ circuitVersion: 2 });

    it("REJECTS a tender pinned to a version this deployment does not enforce", async () => {
      // The tender freezes verifierVersion 1. An AwardManager built for
      // version 2 refuses it outright: there is no parameter through which to
      // point this contract at another verifier, so the guarantee is
      // structural rather than a check that could be edited away.
      const f = await useFixture(versionTwo);
      assert.equal(await f.am.read.circuitVersion(), 2);
      const a = AWARD.concealed;
      const [pa, pb, pc] = awardProof("concealed");
      await assert.rejects(
        () =>
          f.am.write.recordAward(
            [f.tenderId, BigInt(a.winnerCommitment), BigInt(a.winningPrice), a.winnerIndex, pa, pb, pc],
            { account: f.authority.account },
          ),
        /VerifierVersionMismatch/,
      );
    });
  });

  // -------------------------------------------------------------- gas record

  describe("gas (plan Section 20.6 benchmark record)", () => {
    it("reports the measured cost of recording an award", async () => {
      const client = await hre.viem.getPublicClient();
      const a = AWARD.concealed;
      const [pa, pb, pc] = awardProof("concealed");
      const gas = await client.estimateContractGas({
        address: am.address, abi: am.abi, functionName: "recordAward",
        args: [tenderId, BigInt(a.winnerCommitment), BigInt(a.winningPrice), a.winnerIndex, pa, pb, pc],
        account: authority.account,
      });
      console.log(`      recordAward (2 bids): ${gas}`);
      // A pairing check plus 2 opening-status reads. A small number would
      // mean the proof was not verified.
      assert.ok(gas > 300000n, "an award cannot be recorded this cheaply");
    });
  });
});
