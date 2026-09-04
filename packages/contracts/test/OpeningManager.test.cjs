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
 * OpeningManager: the 3-of-5 threshold opening, verified on-chain.
 *
 * Development plan Sections 12.6 and 12.7, whitepaper Section 6.
 *
 * The decryption shares and their Chaum-Pedersen proofs come from the shared
 * fixture, produced by an INDEPENDENT implementation in
 * packages/crypto/src/dleq.ts. A test that generated the proofs with the same
 * code the contract verifies would only be checking that the code agrees with
 * itself.
 *
 * The fixture also carries a forged share - a valid curve point with an
 * honest proof attached - because the on-chain DLEQ check exists precisely to
 * stop that, and a guarantee with no artifact attacking it is a claim rather
 * than a mechanism.
 */

const FIX = JSON.parse(
  readFileSync(join(__dirname, "../../circuits/fixtures/eligibility.proof.json"), "utf8"),
);
const CHAIN = FIX.chain;
const SPEC = FIX.tender;
const SEALED = FIX.sealed;
const OPENING = FIX.opening;

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

const proofArgs = (name) => {
  const f = FIX.fixtures[name];
  return [f.pA.map(BigInt), f.pB.map((r) => r.map(BigInt)), f.pC.map(BigInt)];
};
const signalsOf = (name) => FIX.fixtures[name].publicSignals.map(BigInt);

const dleq = (p) => ({
  aX: BigInt(p.aX), aY: BigInt(p.aY),
  bX: BigInt(p.bX), bY: BigInt(p.bY),
  z: BigInt(p.z),
});

describe("OpeningManager", function () {
  this.timeout(300000);

  let gov, reg, tr, ev, sb, om;
  let council, authority, outsider, committee, tenderId;

  /**
   * Start from a clean network.
   *
   * These tests move the clock to a deadline in 2096. Mocha runs every test
   * file in one process against one network, so without this the NEXT file's
   * first fixture inherits a clock past that deadline and fails while setting
   * up a bidding window - a failure that points at the wrong file entirely.
   * `reset` also clears the fixture snapshot cache, which a bare
   * hardhat_reset would leave dangling.
   */
  before(async () => {
    await reset();
  });

  after(async () => {
    await reset();
  });

  /**
   * Everything from the sealed-bid stage, then the tender CLOSED and ready to
   * open. Through loadFixture because these tests move the clock past a
   * deadline in 2096, which would otherwise leak into the next test.
   */
  async function deployAll() {
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

    await regC.write.setTenderModule([trC.address], { account: councilW[0].account });
    const epoch = BigInt(SPEC.credentialEpoch);
    await regC.write.publishIssuerRegistryRoot([epoch, CHAIN.issuerRegistryRoot], {
      account: councilW[0].account,
    });
    await regC.write.publishRevocationRoot([epoch, CHAIN.revocationRoot], {
      account: councilW[0].account,
    });
    // closeTender pins the revocation root of the registry's CURRENT epoch,
    // which is not the tender's credential epoch, so that root has to exist
    // too or closing reverts RootNotSet. Read the epoch rather than assuming
    // it: hardcoding zero here failed with RootNotSet(1).
    const currentEpoch = await regC.read.currentEpoch();
    if (currentEpoch !== epoch) {
      await regC.write.publishRevocationRoot([currentEpoch, CHAIN.revocationRoot], {
        account: councilW[0].account,
      });
    }
    await trC.write.setTenderAuthority([authorityW.account.address, true], {
      account: councilW[0].account,
    });

    for (const [i, k] of REPLICA_KEYS.entries()) {
      await sbC.write.registerReplica(
        [i + 1, privateKeyToAccount(k).address, `replica-${i + 1}`],
        { account: councilW[0].account },
      );
    }

    // verifier v1 through the real governance flow
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
    const [pa, pb, pc] = proofArgs("valid");
    await evC.write.registerVerifier(
      [pid, r, { a: pa, b: pb, c: pc, signals: signalsOf("valid") }],
      { account: councilW[0].account },
    );

    // the tender, with a window open now
    const now = BigInt(await time.latest());
    const biddingStart = now + REVIEW_WINDOW + 10n;
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
      issuerEpoch: BigInt(SPEC.credentialEpoch),
      schemaVersion: SPEC.schemaVersion,
      verifierVersion: SPEC.verifierVersion,
      disclosurePolicy: SPEC.disclosurePolicy,
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

    // one accepted bid
    const receipts = await Promise.all(
      [1, 2].map(async (replicaId) => {
        const account = privateKeyToAccount(REPLICA_KEYS[replicaId - 1]);
        const digest = keccak256(
          encodePacked(
            ["bytes32", "uint8", "bytes32", "uint64"],
            [RAW_RECEIPT_SIG_V1, replicaId, SEALED.valid.ciphertextHash, BigInt(SEALED.valid.byteLength)],
          ),
        );
        return {
          replicaId,
          contentHash: SEALED.valid.ciphertextHash,
          byteLength: BigInt(SEALED.valid.byteLength),
          signature: await account.sign({ hash: digest }),
        };
      }),
    );
    const s = signalsOf("valid");
    await sbC.write.submitBid(
      [
        { tenderId: id, nullifier: s[10], bidCommitment: s[11], ciphertextHash: SEALED.valid.ciphertextHash },
        receipts, pa, pb, pc,
      ],
      { account: outsiderW.account },
    );

    return {
      gov: govC, reg: regC, tr: trC, ev: evC, sb: sbC, om: omC,
      council: councilW, authority: authorityW, outsider: outsiderW,
      committee: committeeW, tenderId: id,
    };
  }

  /** Move past the deadline and close the tender. */
  async function closeTender() {
    await time.increaseTo(BigInt(SPEC.deadline) + 1n);
    await tr.write.closeTender([tenderId], { account: outsider.account });
    assert.equal(await tr.read.getState([tenderId]), State.CLOSED);
  }

  const revealArgs = () => [tenderId, 0, SEALED.valid.canonicalBytes];

  /** Submit member `index`'s honest share. */
  async function submitShare(index) {
    const sh = OPENING.valid.shares.find((x) => x.memberIndex === index);
    return om.write.submitDecryptionShare(
      [tenderId, 0, index, BigInt(sh.share.x), BigInt(sh.share.y), dleq(sh.proof)],
      { account: committee[index - 1].account },
    );
  }

  beforeEach(async () => {
    ({ gov, reg, tr, ev, sb, om, council, authority, outsider, committee, tenderId } =
      await loadFixture(deployAll));
  });

  // ------------------------------------------------------------------ timing

  describe("nothing opens before the deadline", () => {
    it("the tender is not CLOSED while bidding is open", async () => {
      assert.equal(await tr.read.isBiddingOpen([tenderId]), true);
    });

    it("refuses to reveal a ciphertext before the tender closes", async () => {
      // Plan Section 12.6 step 2. CLOSED is the state that only exists after
      // the deadline, and closeTender is permissionless, so nobody can hold a
      // tender open to delay an opening either.
      await assert.rejects(
        () => om.write.revealCiphertext(revealArgs(), { account: outsider.account }),
        /TenderNotClosed/,
      );
    });

    it("refuses a decryption share before the tender closes", async () => {
      const sh = OPENING.valid.shares[0];
      await assert.rejects(
        () =>
          om.write.submitDecryptionShare(
            [tenderId, 0, 1, BigInt(sh.share.x), BigInt(sh.share.y), dleq(sh.proof)],
            { account: committee[0].account },
          ),
        /TenderNotClosed/,
      );
    });
  });

  // --------------------------------------------------------- revealing the body

  describe("the ciphertext body is verified against its commitment", () => {
    beforeEach(closeTender);

    it("accepts the committed bytes and extracts the ephemeral point", async () => {
      await om.write.revealCiphertext(revealArgs(), { account: outsider.account });
      const c = await om.read.getCiphertext([tenderId, 0]);
      assert.equal(c.revealed, true);
      assert.equal(c.rX, BigInt(OPENING.valid.ephemeral.x));
      assert.equal(c.rY, BigInt(OPENING.valid.ephemeral.y));
      assert.equal(c.byteLength, SEALED.valid.byteLength);
    });

    it("revealing is permissionless", async () => {
      // The bytes are still encrypted, so publishing them reveals nothing -
      // and a privileged caller could stall every opening.
      const anyone = (await hre.viem.getWalletClients())[15];
      await om.write.revealCiphertext(revealArgs(), { account: anyone.account });
      assert.equal((await om.read.getCiphertext([tenderId, 0])).revealed, true);
    });

    it("REJECTS bytes that do not hash to the committed ciphertextHash", async () => {
      // The whole point: the bytes everyone opens are provably the bytes that
      // were committed to before the deadline.
      const tampered = SEALED.valid.canonicalBytes.slice(0, -2) + "ff";
      await assert.rejects(
        () =>
          om.write.revealCiphertext([tenderId, 0, tampered], { account: outsider.account }),
        /CiphertextHashMismatch/,
      );
    });

    it("rejects another bid's ciphertext", async () => {
      await assert.rejects(
        () =>
          om.write.revealCiphertext(
            [tenderId, 0, SEALED.secondBidder.canonicalBytes],
            { account: outsider.account },
          ),
        /CiphertextHashMismatch/,
      );
    });

    it("rejects a body that is too short to be a ciphertext", async () => {
      await assert.rejects(
        () => om.write.revealCiphertext([tenderId, 0, "0x01"], { account: outsider.account }),
        /CiphertextTooShort/,
      );
    });

    it("rejects a bid index that does not exist", async () => {
      await assert.rejects(
        () =>
          om.write.revealCiphertext([tenderId, 5, SEALED.valid.canonicalBytes], {
            account: outsider.account,
          }),
        /NoSuchBid/,
      );
    });

    it("is one-shot", async () => {
      await om.write.revealCiphertext(revealArgs(), { account: outsider.account });
      await assert.rejects(
        () => om.write.revealCiphertext(revealArgs(), { account: outsider.account }),
        /CiphertextAlreadyRevealed/,
      );
    });

    it("refuses a share until the ciphertext is revealed", async () => {
      // Without R there is nothing to verify a DLEQ proof against.
      const sh = OPENING.valid.shares[0];
      await assert.rejects(
        () =>
          om.write.submitDecryptionShare(
            [tenderId, 0, 1, BigInt(sh.share.x), BigInt(sh.share.y), dleq(sh.proof)],
            { account: committee[0].account },
          ),
        /CiphertextNotRevealed/,
      );
    });
  });

  // -------------------------------------------------------------- the threshold

  describe("three of five, and two is not enough", () => {
    beforeEach(async () => {
      await closeTender();
      await om.write.revealCiphertext(revealArgs(), { account: outsider.account });
    });

    it("declares the threshold publicly", async () => {
      assert.equal(await om.read.THRESHOLD(), 3);
      assert.equal(await om.read.COMMITTEE_SIZE(), 5);
    });

    it("ONE share is not enough", async () => {
      await submitShare(1);
      const [revealed, accepted, threshold, ready] = await om.read.openingStatus([tenderId, 0]);
      assert.equal(revealed, true);
      assert.equal(accepted, 1);
      assert.equal(threshold, 3);
      assert.equal(ready, false, "one share must not open the bid");
    });

    it("TWO shares are not enough", async () => {
      // The step that distinguishes a real threshold from a two-party check.
      // Whitepaper Section 6, plan Section 12.7.
      await submitShare(1);
      await submitShare(2);
      const [, accepted, , ready] = await om.read.openingStatus([tenderId, 0]);
      assert.equal(accepted, 2);
      assert.equal(ready, false, "two shares must not open the bid");
    });

    it("the THIRD share reaches the threshold", async () => {
      await submitShare(1);
      await submitShare(2);
      await submitShare(3);
      const [, accepted, , ready] = await om.read.openingStatus([tenderId, 0]);
      assert.equal(accepted, 3);
      assert.equal(ready, true);
    });

    it("emits the running count and a threshold event", async () => {
      const client = await hre.viem.getPublicClient();
      for (const i of [1, 2, 3]) {
        await client.waitForTransactionReceipt({ hash: await submitShare(i) });
      }
      // fromBlock is required: without it viem reads only the latest block,
      // so this saw one event instead of three and looked like a contract bug.
      const accepts = await client.getContractEvents({
        address: om.address, abi: om.abi, eventName: "DecryptionShareAccepted",
        fromBlock: 0n, toBlock: "latest",
      });
      assert.deepEqual(accepts.map((e) => Number(e.args.accepted)), [1, 2, 3]);
      assert.deepEqual(accepts.map((e) => Number(e.args.memberIndex)), [1, 2, 3]);
      assert.ok(accepts.every((e) => Number(e.args.threshold) === 3));

      const reached = await client.getContractEvents({
        address: om.address, abi: om.abi, eventName: "OpeningThresholdReached",
        fromBlock: 0n, toBlock: "latest",
      });
      assert.equal(reached.length, 1, "exactly one threshold event, on the third share");
    });

    it("ANY three members suffice", async () => {
      // Reconstruction must not depend on which three act.
      for (const set of [[2, 4, 5], [1, 3, 5], [3, 4, 5]]) {
        const fresh = await loadFixture(deployAll);
        ({ om, tr, committee, tenderId, outsider } = fresh);
        await closeTender();
        await om.write.revealCiphertext(revealArgs(), { account: outsider.account });
        for (const i of set) await submitShare(i);
        const [, accepted, , ready] = await om.read.openingStatus([tenderId, 0]);
        assert.equal(accepted, 3, `members ${set} should give three shares`);
        assert.equal(ready, true, `members ${set} should reach the threshold`);
      }
    });

    it("all five may submit", async () => {
      for (const i of [1, 2, 3, 4, 5]) await submitShare(i);
      assert.equal(await om.read.shareCount([tenderId, 0]), 5);
      const shares = await om.read.getShares([tenderId, 0]);
      assert.deepEqual(shares.map((s) => Number(s.memberIndex)), [1, 2, 3, 4, 5]);
    });

    it("publishes the accepted shares so anyone can combine them", async () => {
      // Publishing them is safe: they are per-tender, per-ciphertext values,
      // not long-lived secrets, and it is what makes the ceremony verifiable
      // by someone who was not in it.
      await submitShare(1);
      const shares = await om.read.getShares([tenderId, 0]);
      const expected = OPENING.valid.shares.find((x) => x.memberIndex === 1);
      assert.equal(shares[0].dX, BigInt(expected.share.x));
      assert.equal(shares[0].dY, BigInt(expected.share.y));
      assert.equal(
        shares[0].submitter.toLowerCase(),
        committee[0].account.address.toLowerCase(),
      );
    });
  });

  // ---------------------------------------------------------- bad shares

  describe("a bad share is rejected and attributed", () => {
    beforeEach(async () => {
      await closeTender();
      await om.write.revealCiphertext(revealArgs(), { account: outsider.account });
    });

    it("REJECTS a forged share, naming the member", async () => {
      // The reason the DLEQ proof exists. Without it, this point would be
      // accepted, the Lagrange combination would produce garbage, and the
      // failure would surface as an AES tag error that looks like the
      // BIDDER's fault.
      const f = OPENING.valid.forgedShare;
      await assert.rejects(
        () =>
          om.write.submitDecryptionShare(
            [tenderId, 0, 4, BigInt(f.share.x), BigInt(f.share.y), dleq(f.proof)],
            { account: committee[3].account },
          ),
        /DleqProofInvalid/,
      );
      // Nothing was recorded, so a rejected share cannot be counted later.
      assert.equal(await om.read.shareCount([tenderId, 0]), 0);
      assert.equal(await om.read.shareSubmitted([tenderId, 0, 4]), false);
    });

    it("rejects one member's share submitted under another's index", async () => {
      const sh = OPENING.valid.shares.find((x) => x.memberIndex === 1);
      await assert.rejects(
        () =>
          om.write.submitDecryptionShare(
            [tenderId, 0, 2, BigInt(sh.share.x), BigInt(sh.share.y), dleq(sh.proof)],
            { account: committee[1].account },
          ),
        /DleqProofInvalid/,
      );
    });

    it("rejects a share submitted by someone who is not that member", async () => {
      // Otherwise a member could publish another member's share and the
      // attribution in the events would be wrong - which matters precisely
      // because these events are the evidence the ceremony was held.
      const sh = OPENING.valid.shares.find((x) => x.memberIndex === 1);
      await assert.rejects(
        () =>
          om.write.submitDecryptionShare(
            [tenderId, 0, 1, BigInt(sh.share.x), BigInt(sh.share.y), dleq(sh.proof)],
            { account: outsider.account },
          ),
        /NotThisCommitteeMember/,
      );
    });

    it("rejects a duplicate share from the same member", async () => {
      await submitShare(1);
      await assert.rejects(() => submitShare(1), /ShareAlreadySubmitted/);
      assert.equal(await om.read.shareCount([tenderId, 0]), 1);
    });

    it("rejects member index zero, which would be the secret itself", async () => {
      const sh = OPENING.valid.shares[0];
      await assert.rejects(
        () =>
          om.write.submitDecryptionShare(
            [tenderId, 0, 0, BigInt(sh.share.x), BigInt(sh.share.y), dleq(sh.proof)],
            { account: committee[0].account },
          ),
        /MemberIndexOutOfRange/,
      );
    });

    it("rejects a member index beyond the committee", async () => {
      const sh = OPENING.valid.shares[0];
      await assert.rejects(
        () =>
          om.write.submitDecryptionShare(
            [tenderId, 0, 6, BigInt(sh.share.x), BigInt(sh.share.y), dleq(sh.proof)],
            { account: committee[0].account },
          ),
        /MemberIndexOutOfRange/,
      );
    });

    it("rejects a share that is not a curve point", async () => {
      const sh = OPENING.valid.shares[0];
      await assert.rejects(
        () =>
          om.write.submitDecryptionShare(
            [tenderId, 0, 1, 1n, 1n, dleq(sh.proof)],
            { account: committee[0].account },
          ),
        /ShareNotOnCurve/,
      );
    });

    it("rejects a malformed proof", async () => {
      const sh = OPENING.valid.shares[0];
      const bad = { ...dleq(sh.proof), z: 0n };
      await assert.rejects(
        () =>
          om.write.submitDecryptionShare(
            [tenderId, 0, 1, BigInt(sh.share.x), BigInt(sh.share.y), bad],
            { account: committee[0].account },
          ),
        /DleqProofMalformed/,
      );
      const offCurve = { ...dleq(sh.proof), aX: 1n, aY: 1n };
      await assert.rejects(
        () =>
          om.write.submitDecryptionShare(
            [tenderId, 0, 1, BigInt(sh.share.x), BigInt(sh.share.y), offCurve],
            { account: committee[0].account },
          ),
        /DleqProofMalformed/,
      );
    });

    it("rejects a tampered proof response", async () => {
      const sh = OPENING.valid.shares[0];
      const bad = { ...dleq(sh.proof), z: BigInt(sh.proof.z) + 1n };
      await assert.rejects(
        () =>
          om.write.submitDecryptionShare(
            [tenderId, 0, 1, BigInt(sh.share.x), BigInt(sh.share.y), bad],
            { account: committee[0].account },
          ),
        /DleqProofInvalid/,
      );
    });

    it("a proof for one ciphertext cannot be replayed against another", async () => {
      // The challenge covers R and D_i, so a member cannot prove once and
      // have it accepted for every bid in the tender.
      const other = OPENING.secondBidder.shares.find((x) => x.memberIndex === 1);
      await assert.rejects(
        () =>
          om.write.submitDecryptionShare(
            [tenderId, 0, 1, BigInt(other.share.x), BigInt(other.share.y), dleq(other.proof)],
            { account: committee[0].account },
          ),
        /DleqProofInvalid/,
      );
    });
  });

  // ------------------------------------------------------------- gas record

  describe("gas (plan Section 20.6 benchmark record)", () => {
    beforeEach(async () => {
      await closeTender();
    });

    it("reports the measured cost of revealing and of one verified share", async () => {
      const client = await hre.viem.getPublicClient();
      const revealGas = await client.estimateContractGas({
        address: om.address, abi: om.abi, functionName: "revealCiphertext",
        args: revealArgs(), account: outsider.account,
      });
      await om.write.revealCiphertext(revealArgs(), { account: outsider.account });

      const sh = OPENING.valid.shares[0];
      const shareGas = await client.estimateContractGas({
        address: om.address, abi: om.abi, functionName: "submitDecryptionShare",
        args: [tenderId, 0, 1, BigInt(sh.share.x), BigInt(sh.share.y), dleq(sh.proof)],
        account: committee[0].account,
      });
      console.log(`      revealCiphertext:        ${revealGas}`);
      console.log(`      submitDecryptionShare:   ${shareGas}`);
      console.log(`      full 3-of-5 opening:     ~${revealGas + shareGas * 3n}`);

      // Four 251-bit scalar multiplications per share. A small number would
      // mean a check was skipped, not that the code got fast.
      assert.ok(shareGas > 1000000n, "DLEQ verification cannot be this cheap");
    });
  });
});
