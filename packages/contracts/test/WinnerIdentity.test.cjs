const assert = require("node:assert/strict");
const hre = require("hardhat");
const { reset } = require("@nomicfoundation/hardhat-network-helpers");
const { keccak256, stringToHex, toHex } = require("viem");
const {
  IDENTITY, SPEC, IDENTITY_VKEY_HASH,
  identityProof, signalsOf, makePipeline,
} = require("./helpers/pipeline.cjs");

/**
 * WinnerIdentity: the ownership proof that must exist before any legal
 * identity is displayed beside a winning bid.
 *
 * Development plan Section 9.7, whitepaper Section 7, encoding spec
 * Section 23.
 *
 * The proofs are real and come from an independent implementation in
 * packages/crypto/src/identity.ts. The identity records are SYNTHETIC - no
 * real company's registration, trade licence or VAT/BIN appears anywhere in
 * this repository.
 */
describe("WinnerIdentity", function () {
  this.timeout(600000);

  let ctx;

  before(async () => { await reset(); });
  after(async () => { await reset(); });

  /**
   * Every fixture here closes a tender whose deadline is in 2096, so each one
   * must start from a pristine chain - see the note in AwardManager's suite.
   */
  async function useFixture(fn) {
    await reset();
    return fn();
  }

  const awarded = makePipeline({ stopAfter: "awarded" });
  const notAwarded = makePipeline({ stopAfter: "status" });

  beforeEach(async () => {
    ctx = await useFixture(awarded);
  });

  const recordBytes = (name) =>
    toHex(new TextEncoder().encode(IDENTITY[name].canonicalRecord));

  function submit(name = "winner", overrides = {}) {
    const i = IDENTITY[name];
    const [a, b, c] = identityProof(overrides.proof ?? name);
    return ctx.wi.write.submitIdentityProof(
      [
        ctx.tenderId,
        overrides.credentialId ?? BigInt(i.credentialId),
        overrides.record ?? recordBytes(name),
        a, b, c,
      ],
      { account: (overrides.account ?? ctx.anyone).account },
    );
  }

  // ------------------------------------------------------------- encoding

  describe("the encoding matches the specification", () => {
    it("the contract's identityCommitment equals the prover's", async () => {
      // Spec Section 23: two nested arity-2 Poseidon hashes. The fixture
      // computed this in TypeScript; the contract computes it with the
      // PoseidonT3 library it already links.
      const i = IDENTITY.winner;
      const onChain = await ctx.wi.read.identityCommitment([
        BigInt(i.credentialId), recordBytes("winner"),
      ]);
      assert.equal(onChain, BigInt(i.legalIdentityCommitment));
    });

    it("the contract's legalIdentityHash equals the prover's", async () => {
      const i = IDENTITY.winner;
      assert.equal(
        await ctx.wi.read.legalIdentityHash([recordBytes("winner")]),
        BigInt(i.legalIdentityHash),
      );
    });

    it("the commitment changes if the record changes by one byte", async () => {
      const original = IDENTITY.winner.canonicalRecord;
      const altered = original.replace("Padma", "Padmb");
      assert.notEqual(altered, original);
      assert.notEqual(
        await ctx.wi.read.identityCommitment([
          BigInt(IDENTITY.winner.credentialId),
          toHex(new TextEncoder().encode(altered)),
        ]),
        BigInt(IDENTITY.winner.legalIdentityCommitment),
      );
    });

    it("the commitment changes if the credential id changes", async () => {
      assert.notEqual(
        await ctx.wi.read.identityCommitment([9999n, recordBytes("winner")]),
        BigInt(IDENTITY.winner.legalIdentityCommitment),
      );
    });

    it("derives exactly the five signals the prover used", async () => {
      const i = IDENTITY.winner;
      const got = await ctx.wi.read.expectedPublicSignals([
        ctx.tenderId, BigInt(i.credentialId), recordBytes("winner"),
      ]);
      const labels = [
        "tenderIdField", "winnerCommitment", "nullifier",
        "legalIdentityCommitment", "issuerRegistryRoot",
      ];
      for (let k = 0; k < 5; k++) {
        assert.equal(got[k], BigInt(i.publicSignals[k]), `signal ${k} (${labels[k]})`);
      }
    });

    it("records the verifier's provenance", async () => {
      assert.equal(await ctx.wi.read.PUBLIC_SIGNAL_COUNT(), 5n);
      assert.equal(await ctx.wi.read.circuitVersion(), 1);
      assert.equal(await ctx.wi.read.vkeyHash(), IDENTITY_VKEY_HASH);
    });
  });

  // ----------------------------------------------------------- happy path

  describe("publishing the winner's identity", () => {
    it("accepts the winner's proof and stores the record", async () => {
      assert.equal(await ctx.wi.read.isProven([ctx.tenderId]), false);
      await submit();
      assert.equal(await ctx.wi.read.isProven([ctx.tenderId]), true);

      const id = await ctx.wi.read.getIdentity([ctx.tenderId]);
      assert.equal(id.credentialId, BigInt(IDENTITY.winner.credentialId));
      assert.equal(
        id.legalIdentityCommitment,
        BigInt(IDENTITY.winner.legalIdentityCommitment),
      );
      // The record is on-chain, so the claim is permanent and re-hashable by
      // anyone rather than living in a database that could change.
      const stored = new TextDecoder().decode(
        Buffer.from((await ctx.wi.read.getRecord([ctx.tenderId])).slice(2), "hex"),
      );
      assert.equal(stored, IDENTITY.winner.canonicalRecord);
      assert.match(stored, /Padma Infrastructure Limited/);
    });

    it("the stored record names the credential id, so the issuer can confirm it", async () => {
      // This is the only thing bounding the honesty of a self-declared legal
      // name: the record carries the credentialId, so the issuer that signed
      // that credential can check the declaration against the firm it
      // actually issued to.
      await submit();
      const stored = new TextDecoder().decode(
        Buffer.from((await ctx.wi.read.getRecord([ctx.tenderId])).slice(2), "hex"),
      );
      assert.match(stored, /"credentialId":1042/);
      const id = await ctx.wi.read.getIdentity([ctx.tenderId]);
      assert.equal(id.credentialId, 1042n);
    });

    it("is permissionless - the proof authorises it, not the sender", async () => {
      await submit("winner", { account: ctx.outsider });
      assert.equal(await ctx.wi.read.isProven([ctx.tenderId]), true);
    });

    it("emits the linkage", async () => {
      const client = await hre.viem.getPublicClient();
      await client.waitForTransactionReceipt({ hash: await submit() });
      const logs = await client.getContractEvents({
        address: ctx.wi.address, abi: ctx.wi.abi,
        eventName: "WinnerIdentityProven",
        fromBlock: 0n, toBlock: "latest",
      });
      assert.equal(logs.length, 1);
      assert.equal(logs[0].args.credentialId, 1042n);
      assert.equal(logs[0].args.winnerCommitment, signalsOf("valid")[11]);
      assert.equal(logs[0].args.nullifier, signalsOf("valid")[10]);
    });

    it("is one-shot", async () => {
      await submit();
      await assert.rejects(() => submit(), /AlreadyProven/);
    });

    it("reverts rather than returning a blank identity", async () => {
      // A UI that renders an empty name as "unknown bidder" beside a real
      // award is worse than one that cannot render the panel at all.
      await assert.rejects(() => ctx.wi.read.getIdentity([ctx.tenderId]), /NoIdentity/);
    });
  });

  // ------------------------------------------------------ the negative cases

  describe("only the actual winner can be published", () => {
    it("REJECTS the LOSING bidder's identity proof", async () => {
      // The losing bidder holds a perfectly good credential and can prove
      // ownership of THEIR bid - but not of the winning commitment. Plan
      // Section 21's table lists this as the identity-linkage negative test.
      await assert.rejects(() => submit("loser"), /IdentityProofRejected/);
      assert.equal(await ctx.wi.read.isProven([ctx.tenderId]), false);
    });

    it("REJECTS the winner's proof with the loser's record attached", async () => {
      // The record is hashed into public signal 3, so it cannot be swapped
      // even though it is only calldata.
      await assert.rejects(
        () => submit("winner", { record: recordBytes("loser") }),
        /IdentityProofRejected/,
      );
    });

    it("REJECTS a misstated credential id", async () => {
      await assert.rejects(
        () => submit("winner", { credentialId: 1043n }),
        /IdentityProofRejected/,
      );
    });

    it("REJECTS a record altered by one byte", async () => {
      const altered = IDENTITY.winner.canonicalRecord.replace(
        "Padma Infrastructure Limited",
        "Padma Infrastructure Ltd.",
      );
      await assert.rejects(
        () => submit("winner", { record: toHex(new TextEncoder().encode(altered)) }),
        /IdentityProofRejected/,
      );
    });

    it("rejects a tampered proof", async () => {
      const i = IDENTITY.winner;
      const [a, b, c] = identityProof("winner");
      await assert.rejects(
        () =>
          ctx.wi.write.submitIdentityProof(
            [ctx.tenderId, BigInt(i.credentialId), recordBytes("winner"),
             [a[0] + 1n, a[1]], b, c],
            { account: ctx.anyone.account },
          ),
        /IdentityProofRejected/,
      );
    });

    it("rejects an empty record", async () => {
      await assert.rejects(() => submit("winner", { record: "0x" }), /RecordEmpty/);
    });

    it("rejects an absurdly long record", async () => {
      const huge = toHex(new Uint8Array(5000));
      await assert.rejects(() => submit("winner", { record: huge }), /RecordTooLong/);
    });
  });

  // --------------------------------------------------------- the ordering

  describe("nothing is published before the award", () => {
    it("REJECTS an identity proof on a tender that is not awarded", async () => {
      // The winner is not known until the award proof has been verified, so
      // there is nothing to link an identity to.
      const f = await useFixture(notAwarded);
      assert.equal(await f.am.read.isAwarded([f.tenderId]), false);
      const i = IDENTITY.winner;
      const [a, b, c] = identityProof("winner");
      await assert.rejects(
        () =>
          f.wi.write.submitIdentityProof(
            [f.tenderId, BigInt(i.credentialId), recordBytes("winner"), a, b, c],
            { account: f.anyone.account },
          ),
        /NotAwarded/,
      );
    });
  });

  // -------------------------------------------------------- version pinning

  describe("version pinning", () => {
    it("a tender pinned to another circuit version never reaches the identity step", async () => {
      // The award is refused first, so the identity path is unreachable - and
      // that is the point: the guarantee is structural. An earlier version of
      // this test asked the fixture to reach "awarded" with circuitVersion 2,
      // which is impossible, so the fixture threw instead of the assertion
      // running.
      const f = await useFixture(
        makePipeline({ stopAfter: "status", circuitVersion: 2 }),
      );
      assert.equal(await f.wi.read.circuitVersion(), 2);

      const { AWARD, awardProof } = require("./helpers/pipeline.cjs");
      const a = AWARD.concealed;
      const [apa, apb, apc] = awardProof("concealed");
      await assert.rejects(
        () =>
          f.am.write.recordAward(
            [f.tenderId, BigInt(a.winnerCommitment), BigInt(a.winningPrice),
             a.winnerIndex, apa, apb, apc],
            { account: f.authority.account },
          ),
        /VerifierVersionMismatch/,
      );

      const i = IDENTITY.winner;
      const [pa, pb, pc] = identityProof("winner");
      await assert.rejects(
        () =>
          f.wi.write.submitIdentityProof(
            [f.tenderId, BigInt(i.credentialId), recordBytes("winner"), pa, pb, pc],
            { account: f.anyone.account },
          ),
        /NotAwarded/,
      );
    });
  });

  // -------------------------------------------------------------- gas record

  describe("gas (plan Section 20.6 benchmark record)", () => {
    it("reports the measured cost of the identity proof", async () => {
      const client = await hre.viem.getPublicClient();
      const i = IDENTITY.winner;
      const [a, b, c] = identityProof("winner");
      const gas = await client.estimateContractGas({
        address: ctx.wi.address, abi: ctx.wi.abi,
        functionName: "submitIdentityProof",
        args: [ctx.tenderId, BigInt(i.credentialId), recordBytes("winner"), a, b, c],
        account: ctx.anyone.account,
      });
      console.log(`      submitIdentityProof: ${gas}`);
      // A pairing check, two Poseidon hashes, and the record stored on-chain.
      assert.ok(gas > 300000n, "an identity proof cannot be this cheap");
    });
  });
});
