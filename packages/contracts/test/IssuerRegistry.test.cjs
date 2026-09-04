const assert = require("node:assert/strict");
const hre = require("hardhat");

/**
 * IssuerRegistry: approved issuer keys, the registry root the circuit proves
 * membership against, epoch-scoped revocation, and the deadline root.
 *
 * Whitepaper Section 5 clauses 2-3, Section 11.2. Plan Sections 9.1, 9.1.1.
 */

const ISSUER_A = "0x" + "a1".padEnd(64, "0");
const ISSUER_B = "0x" + "b2".padEnd(64, "0");
const TENDER = "0x" + "fc".padEnd(64, "0");

// A synthetic BabyJubjub point. Real keys come from the issuer's EdDSA key.
const PUB_X = 1234567890123456789012345678901234567890n;
const PUB_Y = 9876543210987654321098765432109876543210n;

const ROOT_1 = "0x" + "11".repeat(32);
const ROOT_2 = "0x" + "22".repeat(32);
const ZERO = "0x" + "00".repeat(32);

describe("IssuerRegistry", function () {
  this.timeout(120000);

  let gov, reg, council, outsider, tenderModule;

  beforeEach(async () => {
    const wallets = await hre.viem.getWalletClients();
    council = wallets.slice(0, 4);
    outsider = wallets[5];
    tenderModule = wallets[6];

    gov = await hre.viem.deployContract("Governance", [
      council.map((w) => w.account.address),
    ]);
    reg = await hre.viem.deployContract("IssuerRegistry", [gov.address]);
  });

  async function register(id = ISSUER_A, label = "ICAB Audit Firm") {
    await reg.write.registerIssuer([id, PUB_X, PUB_Y, 1, label], {
      account: council[0].account,
    });
  }

  describe("issuer registration", () => {
    it("registers an issuer with a BabyJubjub key, active by default", async () => {
      await register();
      const i = await reg.read.getIssuer([ISSUER_A]);
      assert.equal(i.pubKeyX, PUB_X);
      assert.equal(i.pubKeyY, PUB_Y);
      assert.equal(i.active, true);
      assert.equal(i.registered, true);
      assert.equal(i.epoch, 1n);
      assert.equal(i.label, "ICAB Audit Firm");
      assert.equal(await reg.read.isIssuerActive([ISSUER_A]), true);
    });

    it("only the council may register an issuer", async () => {
      // Whitepaper Section 14: issuers need accreditation plus a
      // governance-board vote. There is no owner and no admin key.
      await assert.rejects(
        () =>
          reg.write.registerIssuer([ISSUER_A, PUB_X, PUB_Y, 1, "rogue"], {
            account: outsider.account,
          }),
        /NotCouncilMember/,
      );
    });

    it("rejects a duplicate issuer id", async () => {
      await register();
      await assert.rejects(() => register(), /IssuerAlreadyRegistered/);
    });

    it("rejects a zero key, which is not on the curve", async () => {
      await assert.rejects(
        () =>
          reg.write.registerIssuer([ISSUER_A, 0n, 0n, 1, "bad"], {
            account: council[0].account,
          }),
        /InvalidIssuerKey/,
      );
    });

    it("an unregistered issuer is not active and reverts on read", async () => {
      assert.equal(await reg.read.isIssuerActive([ISSUER_B]), false);
      await assert.rejects(
        () => reg.read.getIssuer([ISSUER_B]),
        /IssuerNotRegistered/,
      );
    });

    it("enforces the tree capacity of 16 issuers", async () => {
      // Depth 4 (spec Section 15). A 17th issuer would not fit the tree the
      // circuit proves membership against.
      for (let i = 0; i < 16; i++) {
        const id = "0x" + i.toString(16).padStart(2, "0").padEnd(64, "0");
        await reg.write.registerIssuer([id, PUB_X + BigInt(i), PUB_Y, 1, `issuer-${i}`], {
          account: council[0].account,
        });
      }
      assert.equal(await reg.read.issuerCount(), 16n);
      await assert.rejects(
        () =>
          reg.write.registerIssuer([ISSUER_B, PUB_X, PUB_Y, 1, "seventeenth"], {
            account: council[0].account,
          }),
        /IssuerCapacityExhausted/,
      );
    });
  });

  describe("issuer status and revocation of a key", () => {
    it("deactivates an issuer with a mandatory reason", async () => {
      await register();
      await reg.write.setIssuerStatus([ISSUER_A, false, "Accreditation lapsed"], {
        account: council[1].account,
      });
      assert.equal(await reg.read.isIssuerActive([ISSUER_A]), false);
    });

    it("requires a reason for a status change", async () => {
      await register();
      await assert.rejects(
        () =>
          reg.write.setIssuerStatus([ISSUER_A, false, ""], {
            account: council[0].account,
          }),
        /ReasonRequired/,
      );
    });

    it("cannot change the status of an unregistered issuer", async () => {
      await assert.rejects(
        () =>
          reg.write.setIssuerStatus([ISSUER_B, false, "nope"], {
            account: council[0].account,
          }),
        /IssuerNotRegistered/,
      );
    });

    it("a non-member cannot change issuer status", async () => {
      await register();
      await assert.rejects(
        () =>
          reg.write.setIssuerStatus([ISSUER_A, false, "hostile"], {
            account: outsider.account,
          }),
        /NotCouncilMember/,
      );
    });
  });

  describe("issuerRegistryRoot (whitepaper Section 5 clause 2)", () => {
    it("publishes and reads back a root per epoch", async () => {
      await reg.write.publishIssuerRegistryRoot([1n, ROOT_1], {
        account: council[0].account,
      });
      assert.equal(await reg.read.issuerRegistryRoot([1n]), ROOT_1);
    });

    it("is unset before publication, so a circuit cannot prove against zero", async () => {
      assert.equal(await reg.read.issuerRegistryRoot([1n]), ZERO);
    });

    it("keeps roots per epoch independently", async () => {
      await reg.write.publishIssuerRegistryRoot([1n, ROOT_1], {
        account: council[0].account,
      });
      await reg.write.publishIssuerRegistryRoot([2n, ROOT_2], {
        account: council[0].account,
      });
      assert.equal(await reg.read.issuerRegistryRoot([1n]), ROOT_1);
      assert.equal(await reg.read.issuerRegistryRoot([2n]), ROOT_2);
    });

    it("only the council may publish a root", async () => {
      await assert.rejects(
        () =>
          reg.write.publishIssuerRegistryRoot([1n, ROOT_1], {
            account: outsider.account,
          }),
        /NotCouncilMember/,
      );
    });
  });

  describe("epoch-scoped revocation (whitepaper Section 11.2)", () => {
    it("starts at epoch 1", async () => {
      assert.equal(await reg.read.currentEpoch(), 1n);
    });

    it("rolls the epoch forward with a reason", async () => {
      await reg.write.rollEpoch([2n, "Issuer key compromise contained"], {
        account: council[0].account,
      });
      assert.equal(await reg.read.currentEpoch(), 2n);
    });

    it("cannot roll backwards or stand still", async () => {
      // Rolling backwards would let a revoked credential become valid again.
      await reg.write.rollEpoch([5n, "planned rotation"], {
        account: council[0].account,
      });
      await assert.rejects(
        () =>
          reg.write.rollEpoch([5n, "again"], { account: council[0].account }),
        /EpochMustIncrease/,
      );
      await assert.rejects(
        () =>
          reg.write.rollEpoch([4n, "backwards"], { account: council[0].account }),
        /EpochMustIncrease/,
      );
    });

    it("rolling the epoch does not rewrite past roots", async () => {
      // The audit trail must stay replayable: whitepaper Section 14,
      // "Revocation rolls the epoch without rewriting history."
      await reg.write.publishRevocationRoot([1n, ROOT_1], {
        account: council[0].account,
      });
      await reg.write.rollEpoch([2n, "rotation"], { account: council[0].account });
      await reg.write.publishRevocationRoot([2n, ROOT_2], {
        account: council[0].account,
      });
      assert.equal(
        await reg.read.revocationRoot([1n]),
        ROOT_1,
        "epoch 1 root must remain readable after the roll",
      );
      assert.equal(await reg.read.revocationRoot([2n]), ROOT_2);
    });

    it("requires a reason to roll the epoch", async () => {
      await assert.rejects(
        () => reg.write.rollEpoch([2n, ""], { account: council[0].account }),
        /ReasonRequired/,
      );
    });
  });

  /**
   * Whitepaper Section 5: "At close the tender pins a deadline root, and a
   * status proof against that root is required before award, so 'unrevoked at
   * deadline' is not inferred from an older submission snapshot."
   *
   * Figure 5 shows the report row "Close-time credential status valid -
   * deadline root". An implementation that only checks revocation at
   * submission cannot produce that row honestly.
   */
  describe("deadline revocation root (whitepaper Section 5)", () => {
    beforeEach(async () => {
      await reg.write.setTenderModule([tenderModule.account.address], {
        account: council[0].account,
      });
      await reg.write.publishRevocationRoot([1n, ROOT_1], {
        account: council[0].account,
      });
    });

    it("pins the current revocation root for a tender", async () => {
      await reg.write.pinDeadlineRevocationRoot([TENDER], {
        account: tenderModule.account,
      });
      assert.equal(await reg.read.deadlineRevocationRoot([TENDER]), ROOT_1);
      assert.equal(await reg.read.deadlineRootPinned([TENDER]), true);
    });

    it("pinning is one-shot", async () => {
      // Re-pinning would let a later revocation be retroactively hidden or
      // introduced - exactly the manipulation the deadline root prevents.
      await reg.write.pinDeadlineRevocationRoot([TENDER], {
        account: tenderModule.account,
      });
      await assert.rejects(
        () =>
          reg.write.pinDeadlineRevocationRoot([TENDER], {
            account: tenderModule.account,
          }),
        /DeadlineRootAlreadyPinned/,
      );
    });

    it("only the wired tender module may pin", async () => {
      // Not even a council member, and not the deployer: the root must
      // correspond to a real CLOSED transition, not an arbitrary call at a
      // moment of someone's choosing.
      await assert.rejects(
        () =>
          reg.write.pinDeadlineRevocationRoot([TENDER], {
            account: council[0].account,
          }),
        /OnlyTenderModule/,
      );
      await assert.rejects(
        () =>
          reg.write.pinDeadlineRevocationRoot([TENDER], {
            account: outsider.account,
          }),
        /OnlyTenderModule/,
      );
    });

    it("cannot pin a zero root", async () => {
      const fresh = await hre.viem.deployContract("IssuerRegistry", [gov.address]);
      await fresh.write.setTenderModule([tenderModule.account.address], {
        account: council[0].account,
      });
      await assert.rejects(
        () =>
          fresh.write.pinDeadlineRevocationRoot([TENDER], {
            account: tenderModule.account,
          }),
        /RootNotSet/,
      );
    });

    it("a later revocation does not change an already-pinned deadline root", async () => {
      // This is the whole point: the award check uses the state as at the
      // deadline, not a later snapshot.
      await reg.write.pinDeadlineRevocationRoot([TENDER], {
        account: tenderModule.account,
      });
      await reg.write.publishRevocationRoot([1n, ROOT_2], {
        account: council[0].account,
      });
      assert.equal(
        await reg.read.deadlineRevocationRoot([TENDER]),
        ROOT_1,
        "the pinned root must be immune to later revocation publications",
      );
    });
  });

  describe("module wiring", () => {
    it("the tender module can be set only once", async () => {
      // A re-settable pointer would let a captured council key redirect
      // deadline-root pinning to a contract of its choosing.
      await reg.write.setTenderModule([tenderModule.account.address], {
        account: council[0].account,
      });
      await assert.rejects(
        () =>
          reg.write.setTenderModule([outsider.account.address], {
            account: council[0].account,
          }),
        /TenderModuleAlreadySet/,
      );
    });

    it("pinning fails before the module is wired", async () => {
      await assert.rejects(
        () =>
          reg.write.pinDeadlineRevocationRoot([TENDER], {
            account: tenderModule.account,
          }),
        /TenderModuleNotSet/,
      );
    });
  });

  describe("pause interaction (whitepaper Section 14)", () => {
    it("registration is blocked while the protocol is paused", async () => {
      // Pause via 3-of-4.
      await gov.write.propose([7, "0x", "Suspected issuer key compromise"], {
        account: council[0].account,
      });
      const id = await gov.read.proposalCount();
      await gov.write.approve([id], { account: council[1].account });
      await gov.write.approve([id], { account: council[2].account });
      await gov.write.execute([id], { account: council[0].account });
      assert.equal(await gov.read.paused(), true);

      await assert.rejects(() => register(), /SystemPaused/);
    });

    it("status changes still work while paused, so a bad issuer can be stopped", async () => {
      await register();
      await gov.write.propose([7, "0x", "Suspected issuer key compromise"], {
        account: council[0].account,
      });
      const id = await gov.read.proposalCount();
      await gov.write.approve([id], { account: council[1].account });
      await gov.write.approve([id], { account: council[2].account });
      await gov.write.execute([id], { account: council[0].account });

      // Deactivation must remain available under pause: a pause that blocks
      // containment would make the emergency control counterproductive.
      await reg.write.setIssuerStatus([ISSUER_A, false, "Contained under pause"], {
        account: council[0].account,
      });
      assert.equal(await reg.read.isIssuerActive([ISSUER_A]), false);
    });
  });
});
