const assert = require("node:assert/strict");
const hre = require("hardhat");
const { keccak256, encodePacked, stringToHex } = require("viem");

/**
 * CheckpointAnchor: the checkpoint formula, and an honest account of what
 * recording one on this chain does not achieve.
 *
 * Development plan Section 9.8, whitepaper Section 9.2.
 */
describe("CheckpointAnchor", function () {
  this.timeout(120000);

  const CHAIN_ID = 20260n;
  let gov, ca, council, outsider;

  beforeEach(async () => {
    const w = await hre.viem.getWalletClients();
    council = w.slice(0, 4);
    outsider = w[5];
    gov = await hre.viem.deployContract("Governance", [
      council.map((x) => x.account.address),
    ]);
    ca = await hre.viem.deployContract("CheckpointAnchor", [gov.address, CHAIN_ID]);
  });

  const stateRoot = (n) => keccak256(stringToHex(`tenderStateRoot-${n}`));
  const blockHash = (n) => keccak256(stringToHex(`blockHash-${n}`));

  describe("the formula", () => {
    it("matches the whitepaper's definition", async () => {
      // checkpoint = keccak256(blockNumber, blockHash, tenderStateRoot),
      // Section 9.2. Computed here independently of the contract so the two
      // agree by comparison rather than by construction.
      const bn = 41871n;
      const expected = keccak256(
        encodePacked(
          ["uint64", "uint64", "bytes32", "bytes32"],
          [CHAIN_ID, bn, blockHash(1), stateRoot(1)],
        ),
      );
      assert.equal(
        await ca.read.computeCheckpoint([CHAIN_ID, bn, blockHash(1), stateRoot(1)]),
        expected,
      );
    });

    it("changes if any input changes", async () => {
      const base = await ca.read.computeCheckpoint([CHAIN_ID, 1n, blockHash(1), stateRoot(1)]);
      const variants = [
        [CHAIN_ID + 1n, 1n, blockHash(1), stateRoot(1)],
        [CHAIN_ID, 2n, blockHash(1), stateRoot(1)],
        [CHAIN_ID, 1n, blockHash(2), stateRoot(1)],
        [CHAIN_ID, 1n, blockHash(1), stateRoot(2)],
      ];
      for (const v of variants) {
        assert.notEqual(await ca.read.computeCheckpoint(v), base);
      }
    });
  });

  describe("recording", () => {
    it("records a checkpoint and exposes it", async () => {
      await ca.write.recordCheckpoint([100n, blockHash(1), stateRoot(1)], {
        account: council[0].account,
      });
      assert.equal(await ca.read.count(), 1n);
      const cp = await ca.read.latest();
      assert.equal(cp.blockNumber, 100n);
      assert.equal(cp.tenderStateRoot, stateRoot(1));
      assert.equal(
        cp.checkpoint,
        await ca.read.computeCheckpoint([CHAIN_ID, 100n, blockHash(1), stateRoot(1)]),
      );
      assert.equal(await ca.read.isRecorded([cp.checkpoint]), true);
    });

    it("is council-only", async () => {
      await assert.rejects(
        () =>
          ca.write.recordCheckpoint([100n, blockHash(1), stateRoot(1)], {
            account: outsider.account,
          }),
        /NotCouncilMember/,
      );
    });

    it("must advance the block number", async () => {
      await ca.write.recordCheckpoint([100n, blockHash(1), stateRoot(1)], {
        account: council[0].account,
      });
      await assert.rejects(
        () =>
          ca.write.recordCheckpoint([100n, blockHash(2), stateRoot(2)], {
            account: council[0].account,
          }),
        /BlockNotAdvanced/,
      );
      await assert.rejects(
        () =>
          ca.write.recordCheckpoint([99n, blockHash(2), stateRoot(2)], {
            account: council[0].account,
          }),
        /BlockNotAdvanced/,
      );
    });

    it("a duplicate is impossible, and the monotonic guard is what stops it", async () => {
      /**
       * Worth recording why this test says what it says.
       *
       * It originally asserted that re-submitting the same blockHash and
       * stateRoot at a LATER block number would be caught by the duplicate
       * digest guard. It is not, and cannot be: the block number is inside the
       * digest, so a different block number gives a different digest and there
       * is no duplicate to catch.
       *
       * A genuine duplicate would need the same block number, which the
       * monotonic check rejects first. So `CheckpointAlreadyRecorded` is
       * unreachable defence-in-depth, and the invariant a reader should rely
       * on is monotonicity. The `_seen` mapping still earns its place: it
       * backs `isRecorded`, which is how the independent verifier confirms a
       * checkpoint it recomputed was actually committed here.
       */
      await ca.write.recordCheckpoint([100n, blockHash(1), stateRoot(1)], {
        account: council[0].account,
      });
      // The same content at a later block is a DIFFERENT checkpoint.
      await ca.write.recordCheckpoint([101n, blockHash(1), stateRoot(1)], {
        account: council[0].account,
      });
      assert.equal(await ca.read.count(), 2n);
      assert.notEqual(
        (await ca.read.at([0n])).checkpoint,
        (await ca.read.at([1n])).checkpoint,
      );
      // Re-submitting the same block number is what is actually refused.
      await assert.rejects(
        () =>
          ca.write.recordCheckpoint([101n, blockHash(1), stateRoot(1)], {
            account: council[0].account,
          }),
        /BlockNotAdvanced/,
      );
    });

    it("isRecorded confirms a recomputed checkpoint was committed", async () => {
      // What the independent verifier uses: recompute the checkpoint from the
      // permissioned chain, then ask whether this contract holds it.
      await ca.write.recordCheckpoint([100n, blockHash(1), stateRoot(1)], {
        account: council[0].account,
      });
      const recomputed = await ca.read.computeCheckpoint([
        CHAIN_ID, 100n, blockHash(1), stateRoot(1),
      ]);
      assert.equal(await ca.read.isRecorded([recomputed]), true);
      assert.equal(await ca.read.isRecorded([keccak256(stringToHex("nope"))]), false);
    });

    it("reverts rather than returning an empty checkpoint", async () => {
      await assert.rejects(() => ca.read.latest(), /NoCheckpoints/);
      await assert.rejects(() => ca.read.at([0n]), /CheckpointNotFound/);
    });
  });

  describe("the external anchor is what actually matters", () => {
    it("starts with NO external anchor, and says so", async () => {
      // This is the honest state of the prototype. A checkpoint recorded by
      // the same four validators that could rewrite the history it describes
      // is worth nothing against that threat. The integrity report must read
      // ABSENT, not PENDING.
      await ca.write.recordCheckpoint([100n, blockHash(1), stateRoot(1)], {
        account: council[0].account,
      });
      assert.equal(await ca.read.externallyAnchoredCount(), 0n);
      assert.equal((await ca.read.latest()).externalAnchorUri, "");
    });

    it("records where a checkpoint was published externally", async () => {
      await ca.write.recordCheckpoint([100n, blockHash(1), stateRoot(1)], {
        account: council[0].account,
      });
      await ca.write.recordExternalAnchor(
        [0n, "https://sepolia.etherscan.io/tx/0xabc"],
        { account: council[0].account },
      );
      assert.equal(await ca.read.externallyAnchoredCount(), 1n);
      assert.match((await ca.read.at([0n])).externalAnchorUri, /sepolia/);
    });

    it("the anchor URI is one-shot and council-only", async () => {
      await ca.write.recordCheckpoint([100n, blockHash(1), stateRoot(1)], {
        account: council[0].account,
      });
      await assert.rejects(
        () => ca.write.recordExternalAnchor([0n, "https://x"], { account: outsider.account }),
        /NotCouncilMember/,
      );
      await ca.write.recordExternalAnchor([0n, "https://x"], {
        account: council[0].account,
      });
      await assert.rejects(
        () => ca.write.recordExternalAnchor([0n, "https://y"], { account: council[0].account }),
        /ExternalAnchorAlreadySet/,
      );
    });

    it("rejects an empty anchor URI and an unknown index", async () => {
      await ca.write.recordCheckpoint([100n, blockHash(1), stateRoot(1)], {
        account: council[0].account,
      });
      await assert.rejects(
        () => ca.write.recordExternalAnchor([0n, ""], { account: council[0].account }),
        /ReasonRequired/,
      );
      await assert.rejects(
        () => ca.write.recordExternalAnchor([5n, "https://x"], { account: council[0].account }),
        /CheckpointNotFound/,
      );
    });
  });
});
