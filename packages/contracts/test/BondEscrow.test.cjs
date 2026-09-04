const assert = require("node:assert/strict");
const hre = require("hardhat");
const { reset } = require("@nomicfoundation/hardhat-network-helpers");
const { keccak256, stringToHex } = require("viem");
const { signalsOf, makePipeline } = require("./helpers/pipeline.cjs");

/**
 * BondEscrow: a non-transferable record of bid-bond status.
 *
 * Development plan Section 9.6. Whitepaper Figure 4 lists the contract,
 * Section 6 routes the bond through it as a metadata-linkability mitigation,
 * and Section 13 has it hold "a tokenized representation" while the bank keeps
 * the guarantee.
 *
 * The tests that matter most are the ones asserting what this contract CANNOT
 * do. Whitepaper Table 7 says bond status is "not an opening dependency", and
 * a contract that quietly became one would turn a procurement formality into a
 * censorship lever.
 */
describe("BondEscrow", function () {
  this.timeout(600000);

  let ctx, be, bank, nullifierA, nullifierB;

  const REF = keccak256(stringToHex("BANK/GTEE/2026/44821"));
  const AMOUNT = 370000n; // 5% of the BDT 74,00,000 bid

  before(async () => { await reset(); });
  after(async () => { await reset(); });

  async function useFixture(fn) {
    await reset();
    return fn();
  }

  const awarded = makePipeline({ stopAfter: "awarded" });

  beforeEach(async () => {
    ctx = await useFixture(awarded);
    be = await hre.viem.deployContract("BondEscrow", [
      ctx.gov.address, ctx.tr.address, ctx.sb.address,
    ]);
    bank = (await hre.viem.getWalletClients())[14];
    await be.write.setBankAdapter(
      [bank.account.address, true, "mock bank adapter for the demonstration"],
      { account: ctx.council[0].account },
    );
    nullifierA = signalsOf("valid")[10];
    nullifierB = signalsOf("secondBidder")[10];
  });

  const post = (nullifier = nullifierA, overrides = {}) =>
    be.write.postBond(
      [
        ctx.tenderId,
        nullifier,
        overrides.ref ?? REF,
        overrides.amount ?? AMOUNT,
      ],
      { account: (overrides.account ?? bank).account },
    );

  // -------------------------------------------------------- the record

  describe("recording a bond", () => {
    it("records POSTED against a nullifier, not an address", async () => {
      // Keyed by nullifier deliberately: a bond posted against a bidder's
      // address would link that firm to the tender, which is the metadata
      // channel whitepaper Section 6 routes the bond through this contract to
      // avoid.
      await post();
      const b = await be.read.getBond([ctx.tenderId, nullifierA]);
      assert.equal(b.status, 1); // POSTED
      assert.equal(b.guaranteeRef, REF);
      assert.equal(b.declaredAmount, AMOUNT);
      assert.equal(b.postedBy.toLowerCase(), bank.account.address.toLowerCase());
      assert.equal(await be.read.postedCount([ctx.tenderId]), 1n);
    });

    it("stores a HASH of the guarantee reference, never an instrument", async () => {
      // A smart contract cannot hold a bank guarantee. The reference hash is
      // the honest maximum.
      await post();
      const b = await be.read.getBond([ctx.tenderId, nullifierA]);
      assert.equal(b.guaranteeRef.length, 66);
      assert.equal(b.guaranteeRef, keccak256(stringToHex("BANK/GTEE/2026/44821")));
    });

    it("rejects a nullifier the chain never accepted", async () => {
      // Otherwise the escrow accumulates records for bids that do not exist,
      // and the count shown beside a tender is meaningless.
      await assert.rejects(() => post(999999n), /UnknownNullifier/);
    });

    it("is one-shot per bid", async () => {
      await post();
      await assert.rejects(() => post(), /BondAlreadyPosted/);
    });

    it("rejects an empty reference or a zero amount", async () => {
      await assert.rejects(
        () => post(nullifierA, { ref: "0x" + "00".repeat(32) }),
        /EmptyGuaranteeRef/,
      );
      await assert.rejects(() => post(nullifierA, { amount: 0n }), /ZeroDeclaredAmount/);
    });

    it("summarises across the tender", async () => {
      await post(nullifierA);
      await post(nullifierB);
      const [accepted, posted] = await be.read.bondSummary([ctx.tenderId]);
      assert.equal(accepted, 2n);
      assert.equal(posted, 2n);
    });
  });

  // ------------------------------------------------------- settlement

  describe("settlement", () => {
    it("releases with a recorded reason", async () => {
      await post();
      await be.write.settleBond(
        [ctx.tenderId, nullifierA, true, "tender awarded elsewhere; bond released"],
        { account: bank.account },
      );
      const b = await be.read.getBond([ctx.tenderId, nullifierA]);
      assert.equal(b.status, 2); // RELEASED
      assert.match(b.settlementReason, /released/);
    });

    it("forfeits with a recorded reason", async () => {
      await post();
      await be.write.settleBond(
        [ctx.tenderId, nullifierA, false, "winner withdrew after award"],
        { account: bank.account },
      );
      assert.equal((await be.read.getBond([ctx.tenderId, nullifierA])).status, 3);
    });

    it("requires a reason", async () => {
      await post();
      await assert.rejects(
        () => be.write.settleBond([ctx.tenderId, nullifierA, true, ""], {
          account: bank.account,
        }),
        /ReasonRequired/,
      );
    });

    it("is one-shot, so a forfeiture cannot be rewritten as a release", async () => {
      await post();
      await be.write.settleBond([ctx.tenderId, nullifierA, false, "forfeited"], {
        account: bank.account,
      });
      await assert.rejects(
        () => be.write.settleBond([ctx.tenderId, nullifierA, true, "actually released"], {
          account: bank.account,
        }),
        /BondAlreadySettled/,
      );
      assert.equal((await be.read.getBond([ctx.tenderId, nullifierA])).status, 3);
    });

    it("cannot settle a bond that was never posted", async () => {
      await assert.rejects(
        () => be.write.settleBond([ctx.tenderId, nullifierA, true, "x"], {
          account: bank.account,
        }),
        /BondNotPosted/,
      );
    });
  });

  // ---------------------------------------------------------- authority

  describe("who may act", () => {
    it("only a registered bank adapter may post or settle", async () => {
      await assert.rejects(() => post(nullifierA, { account: ctx.outsider }), /NotBankAdapter/);
      await assert.rejects(() => post(nullifierA, { account: ctx.authority }), /NotBankAdapter/);
      await assert.rejects(() => post(nullifierA, { account: ctx.council[0] }), /NotBankAdapter/);
    });

    it("only the council may register an adapter, with a reason", async () => {
      await assert.rejects(
        () =>
          be.write.setBankAdapter([ctx.outsider.account.address, true, "x"], {
            account: ctx.outsider.account,
          }),
        /NotCouncilMember/,
      );
      await assert.rejects(
        () =>
          be.write.setBankAdapter([ctx.outsider.account.address, true, ""], {
            account: ctx.council[0].account,
          }),
        /ReasonRequired/,
      );
    });

    it("a revoked adapter can no longer act", async () => {
      await be.write.setBankAdapter(
        [bank.account.address, false, "adapter key rotated"],
        { account: ctx.council[0].account },
      );
      await assert.rejects(() => post(), /NotBankAdapter/);
    });
  });

  // ------------------------------------------- NOT an opening dependency

  describe("bond status gates nothing", () => {
    it("the tender opened and was awarded with NO bonds posted at all", async () => {
      // Whitepaper Table 7: "Procurement workflow; not an opening dependency."
      // The fixture reached an award without this contract existing.
      const [accepted, posted, released, forfeited] = await be.read.bondSummary([
        ctx.tenderId,
      ]);
      assert.equal(accepted, 2n);
      assert.equal(posted, 0n);
      assert.equal(released, 0n);
      assert.equal(forfeited, 0n);
      assert.equal(await ctx.am.read.isAwarded([ctx.tenderId]), true);
      assert.equal(await ctx.om.read.shareCount([ctx.tenderId, 0]), 3);
    });

    it("a FORFEITED bond does not disturb the recorded award", async () => {
      // If bond status could affect the award, a bank adapter that failed to
      // act - or was leaned on - could stall or unpick a tender. The award is
      // a function of proofs, not of a bank's bookkeeping.
      const before = await ctx.am.read.getAward([ctx.tenderId]);
      await post();
      await be.write.settleBond(
        [ctx.tenderId, nullifierA, false, "forfeited after award"],
        { account: bank.account },
      );
      const after = await ctx.am.read.getAward([ctx.tenderId]);
      assert.equal(after.winnerCommitment, before.winnerCommitment);
      assert.equal(after.winningPrice, before.winningPrice);
      assert.equal(after.awardedAt, before.awardedAt);
    });

    it("no other contract reads BondEscrow", async () => {
      // Structural, not behavioural: none of the protocol contracts take this
      // address, so none of them CAN consult it. A guard could be edited away;
      // an absent dependency cannot.
      for (const name of ["OpeningManager", "AwardManager", "SealedBid", "WinnerIdentity"]) {
        const artifact = await hre.artifacts.readArtifact(name);
        const ctor = artifact.abi.find((f) => f.type === "constructor");
        const params = (ctor?.inputs ?? []).map((i) => i.name.toLowerCase());
        assert.ok(
          !params.some((p) => p.includes("bond") || p.includes("escrow")),
          `${name} must not take a BondEscrow reference`,
        );
        assert.ok(
          !JSON.stringify(artifact.abi).toLowerCase().includes("bondescrow"),
          `${name} must not reference BondEscrow`,
        );
      }
    });
  });
});
