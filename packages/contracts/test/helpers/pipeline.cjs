const { readFileSync } = require("node:fs");
const { join } = require("node:path");
const hre = require("hardhat");
const { time } = require("@nomicfoundation/hardhat-network-helpers");
const { encodePacked, keccak256, stringToHex } = require("viem");
const { privateKeyToAccount } = require("viem/accounts");

/**
 * The whole FairProof pipeline as a reusable test fixture.
 *
 * Extracted because every stage from the award onwards needs the same long
 * setup - two bids accepted, the tender closed, both ciphertexts revealed, six
 * decryption shares verified, status proofs filed - and copying 150 lines per
 * test file guarantees the copies drift.
 *
 * Every proof used here is real, from
 * packages/circuits/fixtures/eligibility.proof.json.
 */

const FIX = JSON.parse(
  readFileSync(
    join(__dirname, "../../../circuits/fixtures/eligibility.proof.json"),
    "utf8",
  ),
);

const {
  publicKey: COMMITTEE_Y,
  committeeArgs: dealtCommitteeArgs,
} = require("./committee.cjs");

const CHAIN = FIX.chain;
const SPEC = FIX.tender;
const SEALED = FIX.sealed;
const OPENING = FIX.opening;
const AWARD = FIX.award;
const IDENTITY = FIX.identity;

/** keccak256("FairProof:receiptSig:v1"), spec Section 22. */
const RAW_RECEIPT_SIG_V1 =
  "0xc3ffb182dd3ebfe5535def6710ba4562e2bf2416e6ac55e4ac25fc7e14433ea3";
const ACTIVATE_VERIFIER_VERSION = 3; // Governance.ActionType
const TIMELOCK = 60;
const REVIEW_WINDOW = BigInt(SPEC.reviewWindow);
const REPLICA_KEYS = [
  "0x" + "a1".repeat(32),
  "0x" + "b2".repeat(32),
  "0x" + "c3".repeat(32),
];
const AWARD_VKEY_HASH = keccak256(stringToHex("award-vkey"));
const IDENTITY_VKEY_HASH = keccak256(stringToHex("identity-vkey"));

const eligProof = (name) => {
  const f = FIX.fixtures[name];
  return [f.pA.map(BigInt), f.pB.map((r) => r.map(BigInt)), f.pC.map(BigInt)];
};
const signalsOf = (name) => FIX.fixtures[name].publicSignals.map(BigInt);
const awardProof = (name) => {
  const a = AWARD[name];
  return [a.pA.map(BigInt), a.pB.map((r) => r.map(BigInt)), a.pC.map(BigInt)];
};
const identityProof = (name) => {
  const i = IDENTITY[name];
  return [i.pA.map(BigInt), i.pB.map((r) => r.map(BigInt)), i.pC.map(BigInt)];
};
const dleq = (p) => ({
  aX: BigInt(p.aX), aY: BigInt(p.aY),
  bX: BigInt(p.bX), bY: BigInt(p.bY),
  z: BigInt(p.z),
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
 * Build a pipeline fixture function.
 *
 * @param opts.stopAfter        "bidding" | "closed" | "opened" | "status" |
 *                              "awarded" (default "status")
 * @param opts.circuitVersion   what AwardManager and WinnerIdentity enforce
 * @param opts.disclosurePolicy the tender's frozen policy (default: the spec's)
 * @param opts.openSecondBid    open bid 1 as well (default true)
 * @param opts.bids             which bids to submit (default both)
 */
function makePipeline(opts = {}) {
  const stopAfter = opts.stopAfter ?? "status";
  const circuitVersion = opts.circuitVersion ?? 1;
  const disclosurePolicy = opts.disclosurePolicy ?? SPEC.disclosurePolicy;
  const openSecondBid = opts.openSecondBid ?? true;
  const bidNames = opts.bids ?? ["valid", "secondBidder"];

  return async function pipeline() {
    const w = await hre.viem.getWalletClients();
    const council = w.slice(0, 4);
    const authority = w[4];
    const outsider = w[5];
    const committee = w.slice(6, 11);
    const anyone = w[15];

    // ---- deploy --------------------------------------------------------
    const gov = await hre.viem.deployContract("Governance", [
      council.map((x) => x.account.address),
    ]);
    const reg = await hre.viem.deployContract("IssuerRegistry", [gov.address]);
    const tr = await hre.viem.deployContract("TenderRegistry", [
      gov.address, reg.address, REVIEW_WINDOW,
    ]);
    const groth = await hre.viem.deployContract("EligibilityVerifierGroth16", []);
    const ev = await hre.viem.deployContract("EligibilityVerifier", [
      gov.address, reg.address, tr.address,
    ]);
    const t3 = await hre.viem.deployContract("PoseidonT3");
    const t6 = await hre.viem.deployContract("PoseidonT6");
    const libs = {
      "poseidon-solidity/PoseidonT3.sol:PoseidonT3": t3.address,
      "poseidon-solidity/PoseidonT6.sol:PoseidonT6": t6.address,
    };
    const sb = await hre.viem.deployContract(
      "SealedBid",
      [gov.address, tr.address, ev.address],
      { libraries: libs },
    );
    const om = await hre.viem.deployContract("OpeningManager", [
      gov.address, tr.address, sb.address,
    ]);
    const ds = await hre.viem.deployContract("DeadlineStatus", [
      tr.address, reg.address, sb.address, ev.address,
    ]);
    const awardVerifier = await hre.viem.deployContract("AwardVerifierGroth16", []);
    const am = await hre.viem.deployContract("AwardManager", [
      gov.address, tr.address, sb.address, om.address, ds.address,
      awardVerifier.address, circuitVersion, AWARD_VKEY_HASH,
      "packages/circuits/ceremony/award.transcript.json",
    ]);
    const identityVerifier = await hre.viem.deployContract(
      "WinnerIdentityVerifierGroth16", [],
    );
    const wi = await hre.viem.deployContract(
      "WinnerIdentity",
      [
        tr.address, reg.address, sb.address, am.address,
        identityVerifier.address, circuitVersion, IDENTITY_VKEY_HASH,
        "packages/circuits/ceremony/winner_identity.transcript.json",
      ],
      // WinnerIdentity uses only arity-2 Poseidon (spec Section 23 nests two
      // arity-2 hashes rather than using one arity-3), so it links T3 alone.
      { libraries: { "poseidon-solidity/PoseidonT3.sol:PoseidonT3": t3.address } },
    );

    // ---- registry, replicas, authority ---------------------------------
    await reg.write.setTenderModule([tr.address], { account: council[0].account });
    const epoch = BigInt(SPEC.credentialEpoch);
    await reg.write.publishIssuerRegistryRoot([epoch, CHAIN.issuerRegistryRoot], {
      account: council[0].account,
    });
    await reg.write.publishRevocationRoot([epoch, CHAIN.revocationRoot], {
      account: council[0].account,
    });
    // The DEADLINE root is pinned from the registry's CURRENT epoch at close,
    // and is deliberately a different tree: credential 9999 is revoked in it
    // while both bidders stay clean. Were the roots equal, the original
    // eligibility proof would double as a status proof.
    const currentEpoch = await reg.read.currentEpoch();
    await reg.write.publishRevocationRoot(
      [currentEpoch, CHAIN.deadlineRevocationRoot],
      { account: council[0].account },
    );
    await tr.write.setTenderAuthority([authority.account.address, true], {
      account: council[0].account,
    });
    for (const [i, k] of REPLICA_KEYS.entries()) {
      await sb.write.registerReplica(
        [i + 1, privateKeyToAccount(k).address, `replica-${i + 1}`],
        { account: council[0].account },
      );
    }

    // ---- eligibility verifier v1, through the real governance flow ------
    const r = {
      version: 1, impl: groth.address,
      vkeyHash: keccak256(stringToHex("vkey")),
      sourceHash: keccak256(stringToHex("source")),
      transcriptUri: "ceremony",
    };
    const payload = await ev.read.encodeActivationPayload([r]);
    await gov.write.propose([ACTIVATE_VERIFIER_VERSION, payload, "v1"], {
      account: council[0].account,
    });
    const pid = await gov.read.proposalCount();
    await gov.write.approve([pid], { account: council[1].account });
    await gov.write.approve([pid], { account: council[2].account });
    await time.increase(TIMELOCK + 1);
    await gov.write.execute([pid], { account: council[0].account });
    const [pa, pb, pc] = eligProof("valid");
    await ev.write.registerVerifier(
      [pid, r, { a: pa, b: pb, c: pc, signals: signalsOf("valid") }],
      { account: council[0].account },
    );

    // ---- the tender ----------------------------------------------------
    const now = BigInt(await time.latest());
    const biddingStart = now + REVIEW_WINDOW + 10n;
    const tenderId = keccak256(stringToHex(CHAIN.tenderIdString));
    await tr.write.createTender([CHAIN.tenderIdString], { account: authority.account });
    await tr.write.setRuleDocument([tenderId, stringToHex(CHAIN.canonicalRuleDocument)], {
      account: authority.account,
    });
    await tr.write.setRuleFields([tenderId, {
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
    }], { account: authority.account });
    await tr.write.setCommitteeKey(
      [tenderId, COMMITTEE_Y.x, COMMITTEE_Y.y,
       ...dealtCommitteeArgs(committee.map((x) => x.account.address))],
      { account: authority.account },
    );
    await tr.write.activateTender([tenderId, CHAIN.rulesHash], {
      account: authority.account,
    });
    await time.increaseTo(biddingStart + 1n);

    const ctx = {
      gov, reg, tr, ev, sb, om, ds, am, wi,
      groth, awardVerifier, identityVerifier,
      council, authority, outsider, committee, anyone,
      tenderId, poseidonLibs: libs, epoch, currentEpoch,
    };
    if (stopAfter === "bidding") return ctx;

    // ---- the bids, in submission order ---------------------------------
    // The leaf commits to the index, so this order is what the award's
    // bidSetRoot was built from.
    for (const name of bidNames) {
      const s = signalsOf(name);
      const [a, b, c] = eligProof(name);
      const receipts = await Promise.all(
        [1, 2].map((rid) =>
          receipt(rid, SEALED[name].ciphertextHash, SEALED[name].byteLength),
        ),
      );
      await sb.write.submitBid(
        [
          {
            tenderId,
            nullifier: s[10],
            bidCommitment: s[11],
            ciphertextHash: SEALED[name].ciphertextHash,
          },
          receipts, a, b, c,
        ],
        { account: outsider.account },
      );
    }

    // ---- close ---------------------------------------------------------
    await time.increaseTo(BigInt(SPEC.deadline) + 1n);
    await tr.write.closeTender([tenderId], { account: outsider.account });
    if (stopAfter === "closed") return ctx;

    // ---- open ----------------------------------------------------------
    const toOpen = openSecondBid ? bidNames : bidNames.slice(0, 1);
    for (const [bidIndex, name] of toOpen.entries()) {
      await om.write.revealCiphertext([tenderId, bidIndex, SEALED[name].canonicalBytes], {
        account: outsider.account,
      });
      for (const memberIndex of [1, 2, 3]) {
        const sh = OPENING[name].shares.find((x) => x.memberIndex === memberIndex);
        await om.write.submitDecryptionShare(
          [tenderId, bidIndex, memberIndex,
           BigInt(sh.share.x), BigInt(sh.share.y), dleq(sh.proof)],
          { account: committee[memberIndex - 1].account },
        );
      }
    }
    if (stopAfter === "opened") return ctx;

    // ---- close-time status proofs --------------------------------------
    const statusFor = { valid: "statusValid", secondBidder: "statusSecondBidder" };
    for (const [bidIndex, name] of toOpen.entries()) {
      const [a, b, c] = eligProof(statusFor[name]);
      await ds.write.submitStatusProof([tenderId, bidIndex, a, b, c], {
        account: outsider.account,
      });
    }
    if (stopAfter === "status") return ctx;

    // ---- the award -----------------------------------------------------
    const awardName = disclosurePolicy === 1 ? "disclosed" : "concealed";
    const a = AWARD[awardName];
    const [apa, apb, apc] = awardProof(awardName);
    await am.write.recordAward(
      [tenderId, BigInt(a.winnerCommitment), BigInt(a.winningPrice), a.winnerIndex,
       apa, apb, apc],
      { account: authority.account },
    );
    return { ...ctx, awardName };
  };
}

module.exports = {
  FIX, CHAIN, SPEC, SEALED, OPENING, AWARD, IDENTITY,
  COMMITTEE_Y, dealtCommitteeArgs,
  RAW_RECEIPT_SIG_V1, REVIEW_WINDOW, REPLICA_KEYS, TIMELOCK,
  ACTIVATE_VERIFIER_VERSION, AWARD_VKEY_HASH, IDENTITY_VKEY_HASH,
  eligProof, signalsOf, awardProof, identityProof, dleq, receipt,
  makePipeline,
};
