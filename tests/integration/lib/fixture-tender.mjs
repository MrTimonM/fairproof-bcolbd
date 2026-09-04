/**
 * Ensure the fixture's tender exists on the live chain, ACTIVE, with a
 * bidding window that opens in the near term.
 *
 * Shared by the proof and sealed-bid end-to-end tests, because they must use
 * the SAME tender: `tenderIdField` is public signal 0, so the tender id is
 * fixed at "FP-00014" and cannot carry a per-run nonce the way the lifecycle
 * test's does. Idempotency comes from reuse instead.
 *
 * WHY THE WINDOW IS MOVED. The fixture's own `biddingStart` is in 2096 so
 * unit tests can activate it without their timestamps rotting. Bidding has to
 * actually open here, so this sets `biddingStart` to just after the review
 * window. That does not disturb any proof: `deadline` is public signal 6 and
 * is left exactly as proved, while `biddingStart` is not a signal at all.
 *
 * The review window is still enforced in full - the contract will not open
 * bidding early - so the first run of the day waits it out. Later runs find
 * the window already open.
 */
import { readFileSync } from "node:fs";
import { keccak256, toUtf8Bytes } from "ethers";
import { dealCommitteeKey, verifyDealing } from "@fairproof/crypto";

export const State = {
  NONE: 0n, DRAFT: 1n, ACTIVE: 2n, CLOSED: 3n, OPENING: 4n, AWARDED: 5n, CANCELLED: 6n,
};

export function loadFixture(repoRoot) {
  return JSON.parse(
    readFileSync(
      `${repoRoot}/packages/circuits/fixtures/eligibility.proof.json`,
      "utf8",
    ),
  );
}

/**
 * @returns {Promise<{tenderId: string, created: boolean, biddingStart: bigint}>}
 */
export async function ensureFixtureTender({
  fixture,
  tr,
  reg,
  council,
  authority,
  committeeMembers,
  opts = { gasPrice: 0 },
  log = () => {},
}) {
  const CHAIN = fixture.chain;
  const SPEC = fixture.tender;
  const epoch = BigInt(SPEC.credentialEpoch);
  const tenderId = keccak256(toUtf8Bytes(CHAIN.tenderIdString));

  // The roots the fixture's witness was built against. Published at epoch 7
  // so the lifecycle test, which uses epoch 1, cannot overwrite them; both
  // write to the same mapping and a shared epoch would make a previously
  // valid proof stop verifying for reasons unrelated to the proof.
  if ((await reg.issuerRegistryRoot(epoch)) !== CHAIN.issuerRegistryRoot) {
    await (await reg.connect(council).publishIssuerRegistryRoot(
      epoch, CHAIN.issuerRegistryRoot, opts,
    )).wait();
  }
  if ((await reg.revocationRoot(epoch)) !== CHAIN.revocationRoot) {
    await (await reg.connect(council).publishRevocationRoot(
      epoch, CHAIN.revocationRoot, opts,
    )).wait();
  }

  if (!(await tr.isTenderAuthority(authority.address))) {
    await (await tr.connect(council).setTenderAuthority(authority.address, true, opts)).wait();
  }

  const state = await tr.getState(tenderId);
  if (state !== State.NONE) {
    const t = await tr.getTender(tenderId);
    if (t.rulesHash !== CHAIN.rulesHash) {
      throw new Error(
        `tender ${CHAIN.tenderIdString} exists on-chain with rulesHash ${t.rulesHash}, ` +
          `but the fixture proves ${CHAIN.rulesHash}. The fixture was regenerated ` +
          `after this tender was activated; redeploy (npm run deploy) to start clean.`,
      );
    }
    log(`reusing tender ${CHAIN.tenderIdString} (state ${t.state})`);
    return { tenderId, created: false, biddingStart: t.biddingStart };
  }

  const reviewWindow = BigInt(SPEC.reviewWindow);
  const floor = await tr.minReviewWindow();
  const window = reviewWindow > floor ? reviewWindow : floor;
  const now = BigInt((await tr.runner.provider.getBlock("latest")).timestamp);
  const biddingStart = now + window + 30n;

  await (await tr.connect(authority).createTender(CHAIN.tenderIdString, opts)).wait();
  await (await tr.connect(authority).setRuleDocument(
    tenderId, toUtf8Bytes(CHAIN.canonicalRuleDocument), opts,
  )).wait();
  await (await tr.connect(authority).setRuleFields(tenderId, {
    requirements: {
      turnoverThreshold: BigInt(SPEC.turnoverThreshold),
      experienceMonths: Number(SPEC.experienceMonthsThreshold),
      certificationCode: BigInt(SPEC.requiredCertificationCode),
    },
    biddingStart,
    deadline: BigInt(SPEC.deadline),
    requiredIssuerId: keccak256(toUtf8Bytes(SPEC.requiredIssuerId)),
    issuerEpoch: epoch,
    schemaVersion: SPEC.schemaVersion,
    verifierVersion: SPEC.verifierVersion,
    disclosurePolicy: SPEC.disclosurePolicy,
    awardRule: SPEC.awardRule,
    tieBreakRule: SPEC.tieBreakRule,
    contingencyPolicy: SPEC.contingencyPolicy,
    reviewWindow: window,
  }, opts)).wait();

  // The committee key from the fixture, so the sealed ciphertexts in that
  // fixture are encrypted to the key this tender pins. The dealing is
  // verified on-chain, so a mismatch would revert rather than pass silently.
  const C = fixture.committee;
  await (await tr.connect(authority).setCommitteeKey(
    tenderId,
    BigInt(C.publicKey.x),
    BigInt(C.publicKey.y),
    committeeMembers,
    C.shares.map((s) => BigInt(s.publicShare.x)),
    C.shares.map((s) => BigInt(s.publicShare.y)),
    C.commitments.map((c) => BigInt(c.x)),
    C.commitments.map((c) => BigInt(c.y)),
    opts,
  )).wait();

  await (await tr.connect(authority).activateTender(tenderId, CHAIN.rulesHash, opts)).wait();
  log(`created tender ${CHAIN.tenderIdString}, bidding opens at ${biddingStart}`);
  return { tenderId, created: true, biddingStart };
}

/** Wait for the contract to report bidding open, polling real chain time. */
export async function waitForBiddingOpen(tr, tenderId, { log = () => {} } = {}) {
  if (await tr.isBiddingOpen(tenderId)) return 0;
  const t = await tr.getTender(tenderId);
  const now = BigInt((await tr.runner.provider.getBlock("latest")).timestamp);
  const wait = t.biddingStart > now ? t.biddingStart - now : 0n;
  log(`waiting ${wait}s of real chain time for the review window ...`);
  for (;;) {
    if (await tr.isBiddingOpen(tenderId)) return Number(wait);
    await new Promise((r) => setTimeout(r, 3000));
  }
}

/** A locally dealt committee key, for tests that do not need the fixture's. */
export function freshCommittee() {
  const dealt = dealCommitteeKey();
  const { ok, problems } = verifyDealing(dealt);
  if (!ok) throw new Error(`local dealing failed: ${problems.join("; ")}`);
  return dealt;
}
