const assert = require("node:assert/strict");
const hre = require("hardhat");
const { time } = require("@nomicfoundation/hardhat-network-helpers");

/**
 * Governance: 3-of-4 council with a timelock.
 * Whitepaper Section 14, Section 11.3. Development plan Section 9.9.
 *
 * Every "must not be able to" cell in the plan's Section 8 roles table needs a
 * test that calls the function directly and expects a revert. A hidden UI
 * button is not a control.
 */

// ActionType enum, mirroring the contract.
const A = {
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

const TIMELOCK = 60;
const REASON = "Accredit ICAB-registered audit firm as qualification issuer";

describe("Governance", function () {
  this.timeout(120000);

  let gov, council, outsider, members;

  beforeEach(async () => {
    const wallets = await hre.viem.getWalletClients();
    // Four council members: Regulator, Procuring Entity, Auditor, Chamber.
    council = wallets.slice(0, 4);
    outsider = wallets[5];
    members = council.map((w) => w.account.address);
    gov = await hre.viem.deployContract("Governance", [members]);
  });

  /** Propose from member[i], returning the proposal id. */
  async function propose(i, action, payload = "0x", reason = REASON) {
    const before = await gov.read.proposalCount();
    await gov.write.propose([action, payload, reason], {
      account: council[i].account,
    });
    const after = await gov.read.proposalCount();
    assert.equal(after, before + 1n, "proposalCount did not increment");
    return after;
  }

  describe("construction", () => {
    it("registers exactly four council members", async () => {
      const c = await gov.read.council();
      assert.equal(c.length, 4);
      for (const m of members) {
        assert.equal(
          await gov.read.isCouncilMember([m]),
          true,
          `${m} should be a council member`,
        );
      }
    });

    it("does not make a non-member a council member", async () => {
      assert.equal(
        await gov.read.isCouncilMember([outsider.account.address]),
        false,
      );
    });

    it("rejects a duplicate council member", async () => {
      const dup = [members[0], members[0], members[1], members[2]];
      await assert.rejects(
        () => hre.viem.deployContract("Governance", [dup]),
        /DuplicateCouncilMember/,
      );
    });

    it("rejects the zero address as a council member", async () => {
      const withZero = [
        members[0],
        members[1],
        members[2],
        "0x0000000000000000000000000000000000000000",
      ];
      await assert.rejects(
        () => hre.viem.deployContract("Governance", [withZero]),
        /InvalidCouncilSize/,
      );
    });

    it("starts unpaused", async () => {
      assert.equal(await gov.read.paused(), false);
    });

    it("declares the 3-of-4 threshold from whitepaper Section 14", async () => {
      assert.equal(await gov.read.COUNCIL_THRESHOLD(), 3);
      assert.equal(await gov.read.COUNCIL_SIZE(), 4);
    });
  });

  describe("authorisation", () => {
    it("a non-member cannot propose", async () => {
      await assert.rejects(
        () =>
          gov.write.propose([A.EmergencyPause, "0x", REASON], {
            account: outsider.account,
          }),
        /NotCouncilMember/,
      );
    });

    it("a non-member cannot approve", async () => {
      const id = await propose(0, A.EmergencyPause);
      await assert.rejects(
        () => gov.write.approve([id], { account: outsider.account }),
        /NotCouncilMember/,
      );
    });

    it("a non-member cannot execute", async () => {
      const id = await propose(0, A.EmergencyPause);
      await gov.write.approve([id], { account: council[1].account });
      await gov.write.approve([id], { account: council[2].account });
      await assert.rejects(
        () => gov.write.execute([id], { account: outsider.account }),
        /NotCouncilMember/,
      );
    });
  });

  describe("the on-chain reason is mandatory (whitepaper Section 14)", () => {
    it("rejects an empty reason", async () => {
      await assert.rejects(
        () =>
          gov.write.propose([A.EmergencyPause, "0x", ""], {
            account: council[0].account,
          }),
        /ReasonRequired/,
      );
    });

    it("records and returns the reason", async () => {
      const id = await propose(0, A.EmergencyPause, "0x", "Chain outage at deadline");
      const p = await gov.read.getProposal([id]);
      assert.equal(p.reason, "Chain outage at deadline");
    });
  });

  describe("the 3-of-4 threshold", () => {
    it("the proposer's own approval counts as one", async () => {
      const id = await propose(0, A.EmergencyPause);
      const p = await gov.read.getProposal([id]);
      assert.equal(p.approvals, 1);
    });

    it("ONE approval is insufficient", async () => {
      const id = await propose(0, A.EmergencyPause);
      await assert.rejects(
        () => gov.write.execute([id], { account: council[0].account }),
        /ThresholdNotMet/,
      );
    });

    it("TWO approvals are insufficient", async () => {
      // The second insufficient step is what distinguishes a real 3-of-4
      // from a 2-party check.
      const id = await propose(0, A.EmergencyPause);
      await gov.write.approve([id], { account: council[1].account });
      const p = await gov.read.getProposal([id]);
      assert.equal(p.approvals, 2);
      await assert.rejects(
        () => gov.write.execute([id], { account: council[0].account }),
        /ThresholdNotMet/,
      );
    });

    it("THREE approvals execute", async () => {
      const id = await propose(0, A.EmergencyPause);
      await gov.write.approve([id], { account: council[1].account });
      await gov.write.approve([id], { account: council[2].account });
      await gov.write.execute([id], { account: council[0].account });
      const p = await gov.read.getProposal([id]);
      assert.equal(p.executed, true);
      assert.equal(await gov.read.paused(), true);
    });

    it("a member cannot approve the same proposal twice", async () => {
      const id = await propose(0, A.EmergencyPause);
      await assert.rejects(
        () => gov.write.approve([id], { account: council[0].account }),
        /ProposalAlreadyApproved/,
      );
      await gov.write.approve([id], { account: council[1].account });
      await assert.rejects(
        () => gov.write.approve([id], { account: council[1].account }),
        /ProposalAlreadyApproved/,
      );
    });

    it("a proposal cannot be executed twice", async () => {
      const id = await propose(0, A.EmergencyPause);
      await gov.write.approve([id], { account: council[1].account });
      await gov.write.approve([id], { account: council[2].account });
      await gov.write.execute([id], { account: council[0].account });
      await assert.rejects(
        () => gov.write.execute([id], { account: council[0].account }),
        /ProposalAlreadyExecuted/,
      );
    });

    it("an unknown proposal reverts rather than silently succeeding", async () => {
      await assert.rejects(
        () => gov.write.execute([9999n], { account: council[0].account }),
        /ProposalNotFound/,
      );
    });
  });

  describe("the timelock (whitepaper Section 11.3)", () => {
    it("verifier activation and role changes are timelocked", async () => {
      for (const action of [
        A.ActivateVerifierVersion,
        A.SetTenderAuthority,
        A.SetCommittee,
        A.RegisterIssuer,
        A.SetIssuerStatus,
      ]) {
        assert.equal(
          await gov.read.isTimelocked([action]),
          true,
          `action ${action} should be timelocked`,
        );
      }
    });

    it("an emergency pause is NOT timelocked", async () => {
      // A pause that takes effect an hour later is not an emergency control.
      assert.equal(await gov.read.isTimelocked([A.EmergencyPause]), false);
      assert.equal(await gov.read.isTimelocked([A.Unpause]), false);
      assert.equal(await gov.read.isTimelocked([A.CancelTender]), false);
    });

    it("a timelocked action cannot execute early, even with 3 approvals", async () => {
      const id = await propose(0, A.ActivateVerifierVersion);
      await gov.write.approve([id], { account: council[1].account });
      await gov.write.approve([id], { account: council[2].account });
      await assert.rejects(
        () => gov.write.execute([id], { account: council[0].account }),
        /TimelockNotElapsed/,
      );
    });

    it("a timelocked action executes once the delay elapses", async () => {
      const id = await propose(0, A.ActivateVerifierVersion);
      await gov.write.approve([id], { account: council[1].account });
      await gov.write.approve([id], { account: council[2].account });
      await time.increase(TIMELOCK + 1);
      await gov.write.execute([id], { account: council[0].account });
      const p = await gov.read.getProposal([id]);
      assert.equal(p.executed, true);
    });

    it("executionStatus explains WHY an action is unavailable", async () => {
      // The UI must say "awaiting approvals" or "awaiting timelock", not just
      // present a disabled button (plan Section 17.4).
      const id = await propose(0, A.ActivateVerifierVersion);
      let s = await gov.read.executionStatus([id]);
      assert.equal(s[0], false, "not executable with 1 approval");
      assert.equal(s[1], 1, "approvals");
      assert.equal(s[2], 3, "required");

      await gov.write.approve([id], { account: council[1].account });
      await gov.write.approve([id], { account: council[2].account });
      s = await gov.read.executionStatus([id]);
      assert.equal(s[0], false, "still blocked by the timelock");
      assert.equal(s[1], 3, "threshold now met");

      await time.increase(TIMELOCK + 1);
      s = await gov.read.executionStatus([id]);
      assert.equal(s[0], true, "executable once the timelock elapses");
    });
  });

  describe("pause and unpause", () => {
    async function pass(action) {
      const id = await propose(0, action);
      await gov.write.approve([id], { account: council[1].account });
      await gov.write.approve([id], { account: council[2].account });
      if (await gov.read.isTimelocked([action])) await time.increase(TIMELOCK + 1);
      await gov.write.execute([id], { account: council[0].account });
      return id;
    }

    it("pauses and unpauses through 3-of-4", async () => {
      await pass(A.EmergencyPause);
      assert.equal(await gov.read.paused(), true);
      await pass(A.Unpause);
      assert.equal(await gov.read.paused(), false);
    });

    it("cannot pause when already paused", async () => {
      await pass(A.EmergencyPause);
      const id = await propose(1, A.EmergencyPause);
      await gov.write.approve([id], { account: council[2].account });
      await gov.write.approve([id], { account: council[3].account });
      await assert.rejects(
        () => gov.write.execute([id], { account: council[1].account }),
        /SystemPaused/,
      );
    });

    it("cannot unpause when not paused", async () => {
      const id = await propose(0, A.Unpause);
      await gov.write.approve([id], { account: council[1].account });
      await gov.write.approve([id], { account: council[2].account });
      await assert.rejects(
        () => gov.write.execute([id], { account: council[0].account }),
        /SystemNotPaused/,
      );
    });
  });

  /**
   * THE LOAD-BEARING INVARIANT.
   *
   * Whitepaper Section 14 ends: "No action rewrites an active tender's rules
   * or verifier." That is the difference between governance and a backdoor,
   * and it makes "oversight without a rewrite pen" a checkable claim.
   *
   * These are structural tests: they assert the capability does not exist in
   * the ABI at all, rather than that some guard rejects it. A guard can be
   * removed in a later commit; an absent function is absent.
   */
  describe("the council cannot rewrite an active tender", () => {
    const FORBIDDEN = [
      "setRulesHash",
      "updateRules",
      "editRules",
      "setDeadline",
      "extendDeadline",
      "setTenderState",
      "overrideTender",
      "setVerifierForTender",
      "forceAward",
      "setWinner",
      "reopenTender",
    ];

    it("exposes no function that edits tender rules or a deadline", async () => {
      const names = gov.abi
        .filter((e) => e.type === "function")
        .map((e) => e.name);
      for (const forbidden of FORBIDDEN) {
        assert.equal(
          names.includes(forbidden),
          false,
          `Governance must not expose ${forbidden}(): whitepaper Section 14 ` +
            `states no council action rewrites an active tender's rules or verifier`,
        );
      }
    });

    it("has no deadline-extension action", async () => {
      // Whitepaper Section 14 commits to "cancellation and versioned reissue"
      // instead of in-place amendment, so the capability must not exist even
      // as a convenience.
      const names = gov.abi
        .filter((e) => e.type === "function")
        .map((e) => e.name.toLowerCase());
      assert.equal(
        names.some((n) => n.includes("extend")),
        false,
        "no in-place deadline extension may exist",
      );
    });

    it("has no arbitrary-call escape hatch", async () => {
      // A generic execute-arbitrary-calldata function would silently restore
      // every capability the closed ActionType set is meant to exclude.
      const fns = gov.abi.filter((e) => e.type === "function");
      for (const fn of fns) {
        const takesTarget = fn.inputs?.some(
          (i) => i.type === "address" && /target|to|dest/i.test(i.name || ""),
        );
        const takesCalldata = fn.inputs?.some((i) => i.type === "bytes");
        assert.equal(
          takesTarget && takesCalldata && fn.name !== "propose",
          false,
          `${fn.name}() looks like an arbitrary-call escape hatch`,
        );
      }
    });

    it("execute() only returns the action for a module to apply", async () => {
      // Governance itself performs no external call, so it cannot be used as
      // a proxy to reach a contract that was never meant to trust it.
      const execute = gov.abi.find(
        (e) => e.type === "function" && e.name === "execute",
      );
      assert.deepEqual(
        execute.outputs.map((o) => o.type),
        ["uint8", "bytes"],
        "execute must return (ActionType, payload), not perform a call",
      );
    });
  });
});
