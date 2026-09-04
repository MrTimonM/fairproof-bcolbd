const assert = require("node:assert/strict");
const hre = require("hardhat");
const { time } = require("@nomicfoundation/hardhat-network-helpers");
const { keccak256, stringToHex } = require("viem");

/**
 * TenderRegistry: lifecycle, the frozen rulesHash, the committee key, and the
 * contract-enforced public rule-review window.
 *
 * Whitepaper Section 4 (rulesHash), Table 11 (review window), Section 5
 * (deadline root), Section 6 (3-of-5 committee), Section 14 (cancellation
 * instead of amendment). Plan Sections 9.2, 9.2.1.
 */

const TENDER_STRING = "FP-00014";
const REVIEW_WINDOW = 300;
const ROOT_1 = "0x" + "11".repeat(32);

const State = {
  NONE: 0, DRAFT: 1, ACTIVE: 2, CLOSED: 3, OPENING: 4, AWARDED: 5, CANCELLED: 6,
};

// The canonical JCS rule document for the Figure 5 demo tender. Key order is
// sorted, as RFC 8785 requires.
const RULE_DOC = JSON.stringify({
  awardRule: "LOWEST_QUALIFIED_PRICE",
  biddingStart: 0,
  contingencyPolicy: "CANCEL_AND_REISSUE",
  deadline: 0,
  disclosurePolicy: "WINNER_ONLY_POST_AWARD",
  issuerEpoch: 1,
  requirements: {
    certificationCode: 9001,
    experienceMonths: 60,
    turnoverThreshold: 500000000,
  },
  revocationPolicy: "DEADLINE_ROOT",
  schemaVersion: 1,
  selectionRule: "LOWEST_QUALIFIED_PRICE",
  tenderId: "FP-00014",
  tieBreakRule: "SUBMISSION_SEQUENCE",
  verifierVersion: 1,
});

// A real dealt 3-of-5 Feldman key. setCommitteeKey now verifies the dealing
// on-chain, so arbitrary large numbers are no longer accepted as points.
const {
  publicKey: COMMITTEE_Y,
  committeeArgs: dealtCommitteeArgs,
  commitments: COMMITMENTS,
  shares: SHARES,
  offCurve: OFF_CURVE,
  onCurveButNotSubgroup: ORDER_TWO,
} = require("./helpers/committee.cjs");
const PX = COMMITTEE_Y.x;
const PY = COMMITTEE_Y.y;

describe("TenderRegistry", function () {
  this.timeout(180000);

  let gov, reg, tr, council, authority, outsider, committee, tenderId;

  function fields(overrides = {}) {
    return {
      requirements: {
        turnoverThreshold: 500000000n,
        experienceMonths: 60,
        certificationCode: 9001n,
      },
      biddingStart: 0n,
      deadline: 0n,
      requiredIssuerId: "0x" + "a1".padEnd(64, "0"),
      issuerEpoch: 1n,
      schemaVersion: 1,
      verifierVersion: 1,
      disclosurePolicy: 2,
      awardRule: 1,
      tieBreakRule: 1,
      contingencyPolicy: 1,
      reviewWindow: BigInt(REVIEW_WINDOW),
      ...overrides,
    };
  }

  async function futureWindow(startOffset = REVIEW_WINDOW + 60, span = 3600) {
    const now = BigInt(await time.latest());
    return { biddingStart: now + BigInt(startOffset), deadline: now + BigInt(startOffset + span) };
  }

  const committeeArgs = () =>
    dealtCommitteeArgs(committee.map((w) => w.account.address));

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
    // Third argument is the initial POLICY FLOOR, not a fixed window.
    tr = await hre.viem.deployContract("TenderRegistry", [
      gov.address,
      reg.address,
      BigInt(REVIEW_WINDOW),
    ]);

    await reg.write.setTenderModule([tr.address], { account: council[0].account });
    await reg.write.publishRevocationRoot([1n, ROOT_1], { account: council[0].account });
    await tr.write.setTenderAuthority([authority.account.address, true], {
      account: council[0].account,
    });

    await tr.write.createTender([TENDER_STRING], { account: authority.account });
    tenderId = keccak256(stringToHex(TENDER_STRING));
  });

  /** Build a complete, activatable DRAFT tender. */
  async function prepareDraft(overrides = {}) {
    const w = await futureWindow();
    await tr.write.setRuleDocument([tenderId, stringToHex(RULE_DOC)], {
      account: authority.account,
    });
    await tr.write.setRuleFields([tenderId, fields({ ...w, ...overrides })], {
      account: authority.account,
    });
    await tr.write.setCommitteeKey([tenderId, PX, PY, ...committeeArgs()], {
      account: authority.account,
    });
    return keccak256(stringToHex(RULE_DOC));
  }

  async function activate() {
    const h = await prepareDraft();
    await tr.write.activateTender([tenderId, h], { account: authority.account });
    return h;
  }

  describe("creation and authority", () => {
    it("creates a tender in DRAFT and derives tenderIdField on-chain", async () => {
      const t = await tr.read.getTender([tenderId]);
      assert.equal(t.state, State.DRAFT);
      assert.equal(t.tenderIdString, TENDER_STRING);
      // Frozen value from docs/field-encoding.md Section 5. Derived on-chain
      // so the authority cannot supply an unrelated field element.
      assert.equal(
        t.tenderIdField,
        345466083462855046233379317649602515757229700962688122897585307103576758497n,
      );
    });

    it("a non-authority cannot create a tender", async () => {
      await assert.rejects(
        () => tr.write.createTender(["FP-99999"], { account: outsider.account }),
        /NotAuthority/,
      );
    });

    it("rejects a duplicate tender id", async () => {
      await assert.rejects(
        () => tr.write.createTender([TENDER_STRING], { account: authority.account }),
        /TenderAlreadyExists/,
      );
    });

    it("only the council may grant tender-authority", async () => {
      await assert.rejects(
        () =>
          tr.write.setTenderAuthority([outsider.account.address, true], {
            account: outsider.account,
          }),
        /NotCouncilMember/,
      );
    });
  });

  describe("rulesHash is recomputed on-chain (whitepaper Section 4)", () => {
    it("computes rulesHash from the stored canonical document", async () => {
      await tr.write.setRuleDocument([tenderId, stringToHex(RULE_DOC)], {
        account: authority.account,
      });
      const expected = keccak256(stringToHex(RULE_DOC));
      const t = await tr.read.getTender([tenderId]);
      assert.equal(t.rulesHash, expected);
      assert.equal(await tr.read.recomputeRulesHash([tenderId]), expected);
    });

    it("stores the document so any verifier can re-hash it", async () => {
      await tr.write.setRuleDocument([tenderId, stringToHex(RULE_DOC)], {
        account: authority.account,
      });
      const stored = await tr.read.getRuleDocument([tenderId]);
      assert.equal(
        Buffer.from(stored.slice(2), "hex").toString("utf8"),
        RULE_DOC,
        "the canonical document must be readable and re-hashable off-chain",
      );
    });

    it("activation fails if the authority's expected hash disagrees", async () => {
      await prepareDraft();
      await assert.rejects(
        () =>
          tr.write.activateTender([tenderId, "0x" + "de".repeat(32)], {
            account: authority.account,
          }),
        /RulesHashMismatch/,
      );
    });

    it("rejects an empty rule document", async () => {
      await assert.rejects(
        () => tr.write.setRuleDocument([tenderId, "0x"], { account: authority.account }),
        /EmptyRuleDocument/,
      );
    });

    it("a different document yields a different rulesHash", async () => {
      await tr.write.setRuleDocument([tenderId, stringToHex(RULE_DOC)], {
        account: authority.account,
      });
      const first = (await tr.read.getTender([tenderId])).rulesHash;
      const tampered = RULE_DOC.replace("500000000", "400000000");
      await tr.write.setRuleDocument([tenderId, stringToHex(tampered)], {
        account: authority.account,
      });
      const second = (await tr.read.getTender([tenderId])).rulesHash;
      assert.notEqual(first, second);
    });
  });

  describe("the public rule-review window (whitepaper Table 11)", () => {
    it("rejects activation when bidding opens too soon", async () => {
      const now = BigInt(await time.latest());
      await tr.write.setRuleDocument([tenderId, stringToHex(RULE_DOC)], {
        account: authority.account,
      });
      await tr.write.setRuleFields(
        [tenderId, fields({ biddingStart: now + 10n, deadline: now + 3600n })],
        { account: authority.account },
      );
      await tr.write.setCommitteeKey([tenderId, PX, PY, ...committeeArgs()], {
        account: authority.account,
      });
      await assert.rejects(
        () =>
          tr.write.activateTender([tenderId, keccak256(stringToHex(RULE_DOC))], {
            account: authority.account,
          }),
        /ReviewWindowTooShort/,
      );
    });

    it("accepts activation once the window is respected", async () => {
      await activate();
      const t = await tr.read.getTender([tenderId]);
      assert.equal(t.state, State.ACTIVE);
      assert.ok(
        t.biddingStart >= t.activatedAt + BigInt(REVIEW_WINDOW),
        "biddingStart must be at least RULE_REVIEW_WINDOW after activation",
      );
    });

    it("declares the policy floor publicly so the report can show it", async () => {
      assert.equal(await tr.read.minReviewWindow(), BigInt(REVIEW_WINDOW));
      assert.equal(await tr.read.ABSOLUTE_MIN_REVIEW_WINDOW(), 60n);
    });

    it("stores the per-tender window in the frozen tender record", async () => {
      await activate();
      const t = await tr.read.getTender([tenderId]);
      assert.equal(t.reviewWindow, BigInt(REVIEW_WINDOW));
    });

    it("an authority may grant MORE review time than the floor", async () => {
      // The point of the layering: longer is always allowed.
      const w = await futureWindow(REVIEW_WINDOW * 4 + 60, 3600);
      await tr.write.setRuleDocument([tenderId, stringToHex(RULE_DOC)], {
        account: authority.account,
      });
      await tr.write.setRuleFields(
        [tenderId, fields({ ...w, reviewWindow: BigInt(REVIEW_WINDOW * 4) })],
        { account: authority.account },
      );
      await tr.write.setCommitteeKey([tenderId, PX, PY, ...committeeArgs()], {
        account: authority.account,
      });
      await tr.write.activateTender([tenderId, keccak256(stringToHex(RULE_DOC))], {
        account: authority.account,
      });
      const t = await tr.read.getTender([tenderId]);
      assert.equal(t.reviewWindow, BigInt(REVIEW_WINDOW * 4));
    });

    it("an authority may NOT grant less than the policy floor", async () => {
      // Otherwise the authority picks the minimum every time and Table 11's
      // mitigation is toothless.
      const w = await futureWindow();
      await assert.rejects(
        () =>
          tr.write.setRuleFields(
            [tenderId, fields({ ...w, reviewWindow: BigInt(REVIEW_WINDOW - 1) })],
            { account: authority.account },
          ),
        /ReviewWindowBelowMinimum/,
      );
    });

    it("nobody can go below the hard constant, not even the council", async () => {
      await assert.rejects(
        () =>
          tr.write.setMinReviewWindow([59n, "trying to weaken review"], {
            account: council[0].account,
          }),
        /ReviewWindowBelowMinimum/,
      );
      await assert.rejects(
        () =>
          tr.write.setMinReviewWindow([0n, "trying to remove review"], {
            account: council[0].account,
          }),
        /ReviewWindowBelowMinimum/,
      );
      await assert.rejects(
        () =>
          hre.viem.deployContract("TenderRegistry", [gov.address, reg.address, 59n]),
        /ReviewWindowBelowMinimum/,
      );
    });

    it("the council can raise the policy floor, with a reason", async () => {
      await tr.write.setMinReviewWindow([600n, "PPR 2025 review period for works tenders"], {
        account: council[0].account,
      });
      assert.equal(await tr.read.minReviewWindow(), 600n);
      await assert.rejects(
        () => tr.write.setMinReviewWindow([600n, ""], { account: council[0].account }),
        /ReasonRequired/,
      );
    });

    it("the authority cannot change the policy floor", async () => {
      await assert.rejects(
        () =>
          tr.write.setMinReviewWindow([60n, "convenient"], {
            account: authority.account,
          }),
        /NotCouncilMember/,
      );
    });

    it("a floor raised after drafting still applies at activation", async () => {
      // Checked at activation as well as at setRuleFields, so a tender
      // drafted under a lax floor cannot slip through after the council
      // tightens policy.
      await prepareDraft();
      await tr.write.setMinReviewWindow([REVIEW_WINDOW * 10, "tightened policy"], {
        account: council[0].account,
      });
      await assert.rejects(
        () =>
          tr.write.activateTender([tenderId, keccak256(stringToHex(RULE_DOC))], {
            account: authority.account,
          }),
        /ReviewWindowBelowMinimum/,
      );
    });

    it("a floor change does not affect an already-ACTIVE tender", async () => {
      // Whitepaper Section 14: no action rewrites an active tender's rules.
      await activate();
      await tr.write.setMinReviewWindow([REVIEW_WINDOW * 10, "tightened policy"], {
        account: council[0].account,
      });
      const t = await tr.read.getTender([tenderId]);
      assert.equal(t.state, State.ACTIVE, "the active tender is untouched");
      assert.equal(
        t.reviewWindow,
        BigInt(REVIEW_WINDOW),
        "its frozen window is unchanged",
      );
    });
  });

  describe("rules are frozen at activation - the immutability claim", () => {
    it("the rule document cannot be changed after activation", async () => {
      await activate();
      await assert.rejects(
        () =>
          tr.write.setRuleDocument([tenderId, stringToHex("{}")], {
            account: authority.account,
          }),
        /RulesFrozen/,
      );
    });

    it("the rule fields cannot be changed after activation", async () => {
      // Whitepaper Table 4, "Rule modification": the authority edits criteria
      // after observing activity. This is the contract rejecting that.
      await activate();
      const w = await futureWindow();
      await assert.rejects(
        () =>
          tr.write.setRuleFields([tenderId, fields(w)], { account: authority.account }),
        /RulesFrozen/,
      );
    });

    it("the committee key cannot be changed after activation", async () => {
      await activate();
      await assert.rejects(
        () =>
          tr.write.setCommitteeKey([tenderId, PX, PY, ...committeeArgs()], {
            account: authority.account,
          }),
        /RulesFrozen/,
      );
    });

    it("a tender cannot be activated twice", async () => {
      const h = await activate();
      await assert.rejects(
        () => tr.write.activateTender([tenderId, h], { account: authority.account }),
        /NotDraft/,
      );
    });

    it("a non-authority cannot activate", async () => {
      const h = await prepareDraft();
      await assert.rejects(
        () => tr.write.activateTender([tenderId, h], { account: outsider.account }),
        /NotAuthority/,
      );
    });

    it("even the council cannot edit an active tender's rules", async () => {
      // Whitepaper Section 14: "No action rewrites an active tender's rules
      // or verifier." The council is not the authority, so it has no path.
      await activate();
      const w = await futureWindow();
      await assert.rejects(
        () =>
          tr.write.setRuleFields([tenderId, fields(w)], {
            account: council[0].account,
          }),
        /NotAuthority/,
      );
    });

    it("exposes no in-place deadline extension", async () => {
      const names = tr.abi.filter((e) => e.type === "function").map((e) => e.name);
      for (const forbidden of ["extendDeadline", "setDeadline", "amendRules", "reopen"]) {
        assert.equal(names.includes(forbidden), false, `must not expose ${forbidden}`);
      }
    });
  });

  describe("activation completeness", () => {
    it("cannot activate without a rule document", async () => {
      const w = await futureWindow();
      await tr.write.setRuleFields([tenderId, fields(w)], { account: authority.account });
      await tr.write.setCommitteeKey([tenderId, PX, PY, ...committeeArgs()], {
        account: authority.account,
      });
      await assert.rejects(
        () =>
          tr.write.activateTender([tenderId, keccak256(stringToHex(RULE_DOC))], {
            account: authority.account,
          }),
        /EmptyRuleDocument/,
      );
    });

    it("cannot activate without a bidding window", async () => {
      await tr.write.setRuleDocument([tenderId, stringToHex(RULE_DOC)], {
        account: authority.account,
      });
      await tr.write.setCommitteeKey([tenderId, PX, PY, ...committeeArgs()], {
        account: authority.account,
      });
      await assert.rejects(
        () =>
          tr.write.activateTender([tenderId, keccak256(stringToHex(RULE_DOC))], {
            account: authority.account,
          }),
        /InvalidBiddingWindow/,
      );
    });

    it("cannot activate without a committee key", async () => {
      // No committee key means no threshold opening, so the sealed-bid
      // guarantee would not exist for this tender.
      const w = await futureWindow();
      await tr.write.setRuleDocument([tenderId, stringToHex(RULE_DOC)], {
        account: authority.account,
      });
      await tr.write.setRuleFields([tenderId, fields(w)], { account: authority.account });
      await assert.rejects(
        () =>
          tr.write.activateTender([tenderId, keccak256(stringToHex(RULE_DOC))], {
            account: authority.account,
          }),
        /CommitteeKeyNotSet/,
      );
    });

    it("rejects a deadline at or before bidding start", async () => {
      const now = BigInt(await time.latest());
      await assert.rejects(
        () =>
          tr.write.setRuleFields(
            [tenderId, fields({ biddingStart: now + 1000n, deadline: now + 1000n })],
            { account: authority.account },
          ),
        /InvalidBiddingWindow/,
      );
    });

    it("rejects a zero turnover threshold, which would be vacuous", async () => {
      const w = await futureWindow();
      await assert.rejects(
        () =>
          tr.write.setRuleFields(
            [
              tenderId,
              fields({
                ...w,
                requirements: {
                  turnoverThreshold: 0n,
                  experienceMonths: 60,
                  certificationCode: 9001n,
                },
              }),
            ],
            { account: authority.account },
          ),
        /InvalidRequirements/,
      );
    });
  });

  describe("committee key (whitepaper Section 6: 3-of-5)", () => {
    it("records the tender key, five member shares and three VSS commitments", async () => {
      await prepareDraft();
      const k = await tr.read.getCommitteeKey([tenderId]);
      assert.equal(k.yX, PX);
      assert.equal(k.memberX.length, 5);
      assert.equal(k.commitmentX.length, 3);
      assert.equal(k.set, true);
      assert.equal(await tr.read.COMMITTEE_THRESHOLD(), 3);
      assert.equal(await tr.read.COMMITTEE_SIZE(), 5);
    });

    it("rejects a duplicate committee member", async () => {
      // A duplicate member would hold two of the three shares needed to open.
      const dup = [
        committee[0].account.address,
        committee[0].account.address,
        committee[2].account.address,
        committee[3].account.address,
        committee[4].account.address,
      ];
      const [, mx, my, cx, cy] = committeeArgs();
      await assert.rejects(
        () =>
          tr.write.setCommitteeKey([tenderId, PX, PY, dup, mx, my, cx, cy], {
            account: authority.account,
          }),
        /DuplicateCommitteeMember/,
      );
    });

    it("rejects a zero member address", async () => {
      const withZeroAddr = [
        "0x0000000000000000000000000000000000000000",
        ...committee.slice(1).map((w) => w.account.address),
      ];
      const [, mx, my, cx, cy] = committeeArgs();
      await assert.rejects(
        () =>
          tr.write.setCommitteeKey(
            [tenderId, PX, PY, withZeroAddr, mx, my, cx, cy],
            { account: authority.account },
          ),
        /ZeroCommitteeMember/,
      );
    });

    /**
     * The Feldman VSS dealing is verified ON-CHAIN (plan Section 12.2).
     *
     * These are the tests that matter. Before this check existed, the suite
     * passed arbitrary large integers as committee points: every assertion
     * was green and nothing would have noticed that the "public key" was not
     * a point on BabyJubjub at all, let alone one the shares could open.
     */
    describe("the dealing is verified on-chain, not merely recorded", () => {
      it("accepts a correctly dealt 3-of-5 key", async () => {
        await prepareDraft();
        const k = await tr.read.getCommitteeKey([tenderId]);
        assert.equal(k.yX, PX);
        assert.equal(k.yY, PY);
        assert.equal(k.set, true);
      });

      it("rejects a public key that is not on the curve", async () => {
        const [m, mx, my, cx, cy] = committeeArgs();
        for (const bad of OFF_CURVE) {
          await assert.rejects(
            () =>
              tr.write.setCommitteeKey(
                [tenderId, BigInt(bad.x), BigInt(bad.y), m, mx, my, cx, cy],
                { account: authority.account },
              ),
            /CommitteeKeyNotOnCurve/,
          );
        }
      });

      it("rejects a curve point outside the prime-order subgroup", async () => {
        // (0, -1) is on the curve and has order 2. Bidders encrypt to this
        // key, and encrypting to a point with a small-order component leaks
        // information about the plaintext - so inCurve alone is not enough.
        const [m, mx, my, cx, cy] = committeeArgs();
        const p = ORDER_TWO[0];
        await assert.rejects(
          () =>
            tr.write.setCommitteeKey(
              [tenderId, BigInt(p.x), BigInt(p.y), m, mx, my, cx, cy],
              { account: authority.account },
            ),
          /CommitteeKeyNotInSubgroup/,
        );
      });

      it("rejects a public key that is not commitment C_0", async () => {
        // C_0 = a_0 * G and a_0 IS the secret, so C_0 must equal Y. If they
        // differed, every bid in the tender would encrypt to a key the shares
        // cannot open, and the tender would be permanently unopenable.
        const [m, mx, my, cx, cy] = committeeArgs();
        // A different, valid subgroup point: another member's public share.
        const otherX = BigInt(SHARES[1].publicShare.x);
        const otherY = BigInt(SHARES[1].publicShare.y);
        await assert.rejects(
          () =>
            tr.write.setCommitteeKey(
              [tenderId, otherX, otherY, m, mx, my, cx, cy],
              { account: authority.account },
            ),
          /CommitteeKeyNotCommitment0/,
        );
      });

      it("rejects a commitment that is not on the curve", async () => {
        const [m, mx, my, cx, cy] = committeeArgs();
        const badCx = [...cx];
        badCx[1] = badCx[1] + 1n;
        await assert.rejects(
          () =>
            tr.write.setCommitteeKey([tenderId, PX, PY, m, mx, my, badCx, cy], {
              account: authority.account,
            }),
          /InvalidFeldmanCommitment/,
        );
      });

      it("rejects a member share inconsistent with the commitments", async () => {
        // The dishonest-dealer case: a share that is a valid curve point but
        // not the committed polynomial's value at that index.
        const [m, mx, my, cx, cy] = committeeArgs();
        const badMx = [...mx];
        const badMy = [...my];
        badMx[3] = BigInt(SHARES[0].publicShare.x);
        badMy[3] = BigInt(SHARES[0].publicShare.y);
        await assert.rejects(
          () =>
            tr.write.setCommitteeKey([tenderId, PX, PY, m, badMx, badMy, cx, cy], {
              account: authority.account,
            }),
          /InconsistentFeldmanShare/,
        );
      });

      it("rejects two members' shares swapped with each other", async () => {
        // Both points are correct shares; only their indices are wrong. A
        // check that merely verified "each share is on the curve and appears
        // in the dealing" would accept this.
        const [m, mx, my, cx, cy] = committeeArgs();
        const swappedX = [...mx];
        const swappedY = [...my];
        [swappedX[0], swappedX[1]] = [swappedX[1], swappedX[0]];
        [swappedY[0], swappedY[1]] = [swappedY[1], swappedY[0]];
        await assert.rejects(
          () =>
            tr.write.setCommitteeKey(
              [tenderId, PX, PY, m, swappedX, swappedY, cx, cy],
              { account: authority.account },
            ),
          /InconsistentFeldmanShare/,
        );
      });

      it("rejects a member share that is not a curve point", async () => {
        const [m, mx, my, cx, cy] = committeeArgs();
        const badMx = [...mx];
        badMx[2] = 1n;
        const badMy = [...my];
        badMy[2] = 1n;
        await assert.rejects(
          () =>
            tr.write.setCommitteeKey([tenderId, PX, PY, m, badMx, badMy, cx, cy], {
              account: authority.account,
            }),
          /InvalidCommitteePoint/,
        );
      });

      it("reports measured gas for the on-chain dealing check", async () => {
        const client = await hre.viem.getPublicClient();
        const [m, mx, my, cx, cy] = committeeArgs();
        const gas = await client.estimateContractGas({
          address: tr.address,
          abi: tr.abi,
          functionName: "setCommitteeKey",
          args: [tenderId, PX, PY, m, mx, my, cx, cy],
          account: authority.account,
        });
        console.log(`      setCommitteeKey (with Feldman verification): ${gas} gas`);
        // The subgroup check alone is a 251-bit scalar multiplication, so a
        // small number here would mean a check was skipped.
        assert.ok(gas > 400000n, "the dealing verification cannot be this cheap");
      });
    });

    it("the committee key is one-shot even within DRAFT", async () => {
      await tr.write.setCommitteeKey([tenderId, PX, PY, ...committeeArgs()], {
        account: authority.account,
      });
      await assert.rejects(
        () =>
          tr.write.setCommitteeKey([tenderId, PX, PY, ...committeeArgs()], {
            account: authority.account,
          }),
        /CommitteeKeyAlreadySet/,
      );
    });
  });

  describe("bidding window", () => {
    it("is closed before biddingStart, open during, closed after the deadline", async () => {
      await activate();
      assert.equal(await tr.read.isBiddingOpen([tenderId]), false, "before start");

      const t = await tr.read.getTender([tenderId]);
      await time.increaseTo(t.biddingStart);
      assert.equal(await tr.read.isBiddingOpen([tenderId]), true, "during window");

      await time.increaseTo(t.deadline);
      assert.equal(
        await tr.read.isBiddingOpen([tenderId]),
        false,
        "at the deadline the window is closed, not open",
      );
    });
  });

  describe("close and the deadline revocation root (whitepaper Section 5)", () => {
    it("cannot close before the deadline", async () => {
      await activate();
      await assert.rejects(() => tr.write.closeTender([tenderId]), /DeadlineNotReached/);
    });

    it("closes after the deadline and pins the deadline revocation root", async () => {
      await activate();
      const t = await tr.read.getTender([tenderId]);
      await time.increaseTo(t.deadline + 1n);
      await tr.write.closeTender([tenderId]);

      assert.equal(await tr.read.getState([tenderId]), State.CLOSED);
      assert.equal(
        await reg.read.deadlineRevocationRoot([tenderId]),
        ROOT_1,
        "the deadline root must be pinned on close",
      );
    });

    it("closing is permissionless once the deadline passes", async () => {
      // If only the authority could close, it could stall a tender it
      // disliked by never closing it.
      await activate();
      const t = await tr.read.getTender([tenderId]);
      await time.increaseTo(t.deadline + 1n);
      await tr.write.closeTender([tenderId], { account: outsider.account });
      assert.equal(await tr.read.getState([tenderId]), State.CLOSED);
    });

    it("cannot close twice", async () => {
      await activate();
      const t = await tr.read.getTender([tenderId]);
      await time.increaseTo(t.deadline + 1n);
      await tr.write.closeTender([tenderId]);
      await assert.rejects(() => tr.write.closeTender([tenderId]), /NotActive/);
    });

    it("cannot close a DRAFT tender", async () => {
      await assert.rejects(() => tr.write.closeTender([tenderId]), /NotActive/);
    });
  });

  describe("cancellation, not amendment (whitepaper Section 14)", () => {
    it("the council can cancel with a recorded reason", async () => {
      await activate();
      await tr.write.cancelTender([tenderId, "Chain outage at deadline"], {
        account: council[0].account,
      });
      assert.equal(await tr.read.getState([tenderId]), State.CANCELLED);
    });

    it("requires a reason", async () => {
      await activate();
      await assert.rejects(
        () => tr.write.cancelTender([tenderId, ""], { account: council[0].account }),
        /ReasonRequired/,
      );
    });

    it("the authority alone cannot cancel", async () => {
      await activate();
      await assert.rejects(
        () =>
          tr.write.cancelTender([tenderId, "inconvenient"], {
            account: authority.account,
          }),
        /NotCouncilMember/,
      );
    });

    it("cannot cancel an already-cancelled tender", async () => {
      await activate();
      await tr.write.cancelTender([tenderId, "outage"], { account: council[0].account });
      await assert.rejects(
        () => tr.write.cancelTender([tenderId, "again"], { account: council[0].account }),
        /InvalidState/,
      );
    });

    it("cannot cancel a tender that does not exist", async () => {
      await assert.rejects(
        () =>
          tr.write.cancelTender(["0x" + "ff".repeat(32), "nope"], {
            account: council[0].account,
          }),
        /TenderNotFound/,
      );
    });
  });

  describe("pause interaction", () => {
    it("tender creation is blocked while paused", async () => {
      await gov.write.propose([7, "0x", "Emergency"], { account: council[0].account });
      const id = await gov.read.proposalCount();
      await gov.write.approve([id], { account: council[1].account });
      await gov.write.approve([id], { account: council[2].account });
      await gov.write.execute([id], { account: council[0].account });

      await assert.rejects(
        () => tr.write.createTender(["FP-00015"], { account: authority.account }),
        /SystemPaused/,
      );
    });

    it("cancellation still works while paused", async () => {
      // Whitepaper Section 14 pairs pause with cancellation as the outage
      // response, so a pause must not block the remedy it exists to enable.
      await activate();
      await gov.write.propose([7, "0x", "Emergency"], { account: council[0].account });
      const id = await gov.read.proposalCount();
      await gov.write.approve([id], { account: council[1].account });
      await gov.write.approve([id], { account: council[2].account });
      await gov.write.execute([id], { account: council[0].account });

      await tr.write.cancelTender([tenderId, "Outage under pause"], {
        account: council[0].account,
      });
      assert.equal(await tr.read.getState([tenderId]), State.CANCELLED);
    });
  });
});
