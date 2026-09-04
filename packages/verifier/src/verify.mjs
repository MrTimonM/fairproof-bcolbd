/**
 * The independent verifier.
 *
 * Plan Section 16.6. This consumes only an evidence bundle and, optionally, a
 * public RPC endpoint, and re-derives every claim from scratch. It shares no
 * code with the web application beyond `@fairproof/crypto`, and it is meant to
 * be runnable by someone who does not trust the dashboard at all.
 *
 * Why it is worth the effort: everything else in the prototype asks a reader to
 * believe a screen. This asks them to believe nothing. It is the concrete form
 * of the whitepaper's claim that the report "is the only artefact in
 * procurement that a stranger can check for themselves" - and it converts
 * "trust our UI" into "run our verifier, or write your own against our
 * published bundle".
 *
 * Every check prints the value it derived, not just a verdict. A PASS with no
 * derived value is indistinguishable from a check that did nothing.
 */
import { Contract, JsonRpcProvider, getBytes, keccak256, recoverAddress } from "ethers";
import * as snarkjs from "snarkjs";
import {
  BID_TREE_DEPTH,
  DOMAIN_PADDING_V1,
  RECEIPT_TREE_DEPTH,
  bidCommitment as computeBidCommitment,
  bidLeaf,
  initBabyjub,
  initPoseidon,
  merkleParent,
  receiptLeaf,
  receiptSigDigest,
  rootFromLeaves,
  toField,
  verifyDleq,
} from "@fairproof/crypto";

export class Report {
  constructor() {
    this.checks = [];
  }
  add(id, ok, claim, derived, note) {
    this.checks.push({ id, ok, claim, derived, note });
    return ok;
  }
  pass(id, claim, derived, note) {
    return this.add(id, true, claim, derived, note);
  }
  fail(id, claim, derived, note) {
    return this.add(id, false, claim, derived, note);
  }
  skip(id, claim, why) {
    this.checks.push({ id, ok: null, claim, derived: why, note: undefined });
  }
  get failures() {
    return this.checks.filter((c) => c.ok === false);
  }
  get passed() {
    return this.checks.filter((c) => c.ok === true).length;
  }
  get skipped() {
    return this.checks.filter((c) => c.ok === null).length;
  }
}

const big = (v) => BigInt(v);
const pt = (p) => ({ x: big(p.x), y: big(p.y) });

/** Groth16 verification from a bundled verification key. */
async function verifyGroth16(vkey, publicSignals, proof) {
  if (!vkey) return { ok: false, why: "no verification key in the bundle" };
  const p = {
    pi_a: [proof.pA[0], proof.pA[1], "1"],
    // snarkjs expects its own coordinate order; the bundle stores the SOLIDITY
    // order, in which each pi_b pair is swapped. Undo that here rather than
    // storing two encodings and letting them drift.
    pi_b: [
      [proof.pB[0][1], proof.pB[0][0]],
      [proof.pB[1][1], proof.pB[1][0]],
      ["1", "0"],
    ],
    pi_c: [proof.pC[0], proof.pC[1], "1"],
    protocol: "groth16",
    curve: "bn128",
  };
  try {
    const ok = await snarkjs.groth16.verify(vkey, publicSignals, p);
    return { ok, why: ok ? "" : "the pairing check failed" };
  } catch (err) {
    return { ok: false, why: err.message };
  }
}

/** Recompute a storage receipt root exactly as SealedBid does. */
function storageReceiptRootFrom(receipts) {
  const sorted = [...receipts].sort((a, b) => a.replicaId - b.replicaId);
  const leaves = sorted.map((r) =>
    receiptLeaf({
      replicaId: r.replicaId,
      contentHash: r.contentHash,
      byteLength: Number(r.byteLength),
      signature: r.signature,
    }),
  );
  while (leaves.length < 1 << RECEIPT_TREE_DEPTH) leaves.push(DOMAIN_PADDING_V1);
  return rootFromLeaves(leaves, RECEIPT_TREE_DEPTH);
}

/**
 * Verify a bundle.
 *
 * @param bundle    the parsed evidence bundle
 * @param options.rpcUrl  cross-check the bundle's values against a live chain
 * @param options.forbiddenFields  injected so the verifier does not import the
 *        exporter - it must share no code with the producer of the artefact it
 *        is checking, beyond the crypto package.
 */
export async function verifyBundle(bundle, options = {}) {
  const r = new Report();
  await initPoseidon();
  await initBabyjub();

  const t = bundle.tender;
  const roots = bundle.roots;
  const vks = bundle.verificationKeys ?? {};

  // ---- 1. the rule document hashes to the frozen rulesHash --------------
  {
    const recomputed = keccak256(new TextEncoder().encode(t.canonicalRuleDocument));
    const ok = recomputed.toLowerCase() === t.rulesHash.toLowerCase();
    r.add(
      1,
      ok,
      "The canonical rule document hashes to the frozen rulesHash",
      recomputed,
      ok
        ? "keccak256 over the stored document, the whitepaper's exact formula"
        : `the bundle claims ${t.rulesHash}`,
    );

    // The document must also parse, and its structured values must agree with
    // the fields the contract enforces. This is the comparison Solidity cannot
    // make, so the verifier is where it happens.
    try {
      const doc = JSON.parse(t.canonicalRuleDocument);
      const mismatches = [];
      if (Number(doc.deadline) !== t.deadline) mismatches.push("deadline");
      if (Number(doc.biddingStart) !== t.biddingStart) mismatches.push("biddingStart");
      if (Number(doc.reviewWindow) !== t.reviewWindow) mismatches.push("reviewWindow");
      if (Number(doc.issuerEpoch) !== t.issuerEpoch) mismatches.push("issuerEpoch");
      if (String(doc.requirements?.turnoverThreshold) !== String(t.requirements.turnoverThreshold)) {
        mismatches.push("turnoverThreshold");
      }
      if (Number(doc.requirements?.experienceMonths) !== t.requirements.experienceMonths) {
        mismatches.push("experienceMonths");
      }
      if (String(doc.requirements?.certificationCode) !== String(t.requirements.certificationCode)) {
        mismatches.push("certificationCode");
      }
      if (Number(doc.verifierVersion) !== bundle.versions.verifierVersion) {
        mismatches.push("verifierVersion");
      }
      r.add(
        "1b",
        mismatches.length === 0,
        "The document PARSES to the fields the contract enforces",
        mismatches.length === 0 ? "every field agrees" : `mismatch: ${mismatches.join(", ")}`,
        "Solidity cannot parse JSON, so this is the check the chain cannot make. It is the whole reason this verifier exists.",
      );
    } catch (err) {
      r.fail("1b", "The rule document is valid JSON", err.message);
    }
  }

  // ---- 2. the mandatory public review window was honoured ---------------
  {
    const earliest = t.activatedAt + t.reviewWindow;
    const ok = t.biddingStart >= earliest && t.reviewWindow >= t.absoluteMinReviewWindow;
    r.add(
      2,
      ok,
      "Bidding opened no earlier than activation plus the review window",
      `biddingStart ${t.biddingStart} >= ${earliest}, window ${t.reviewWindow}s >= floor ${t.absoluteMinReviewWindow}s`,
      ok ? "" : "the review window was shorter than the contract's hard minimum",
    );
  }

  // ---- 3. rebuild the accumulator from the leaves ------------------------
  {
    const leaves = [];
    let leafOk = true;
    for (const b of bundle.acceptedBids) {
      const computed = bidLeaf({
        nullifier: big(b.nullifier),
        bidCommitment: big(b.bidCommitment),
        ciphertextHashField: toField(b.ciphertextHash),
        submissionIndex: b.submissionIndex,
      });
      if (computed !== big(b.leaf)) leafOk = false;
      leaves.push(computed);
    }
    const padded = [...leaves];
    while (padded.length < 1 << BID_TREE_DEPTH) padded.push(DOMAIN_PADDING_V1);
    const root = rootFromLeaves(padded, BID_TREE_DEPTH);
    const ok =
      leafOk &&
      root === big(roots.bidSetRoot) &&
      bundle.acceptedBids.length === roots.submissionCount;
    r.add(
      3,
      ok,
      "Every bid leaf and the whole bidSetRoot are reproducible",
      `${leaves.length} leaves -> ${root}`,
      ok
        ? "the padding leaf is DOMAIN_PADDING_V1, never zero"
        : !leafOk
          ? "at least one leaf does not match its recorded value"
          : `root or count disagrees (bundle says ${roots.bidSetRoot}, count ${roots.submissionCount})`,
    );
  }

  // ---- 4. every eligibility proof --------------------------------------
  {
    let allOk = bundle.acceptedBids.length > 0;
    const details = [];
    for (const b of bundle.acceptedBids) {
      const { ok, why } = await verifyGroth16(vks.eligibility, b.publicSignals, b.eligibilityProof);
      // The public signals must ALSO be the tender's own values. A valid proof
      // of the wrong statement is the failure mode this catches.
      const s = b.publicSignals;
      const bound =
        s[0] === t.tenderIdField &&
        s[3] === String(t.requirements.turnoverThreshold) &&
        s[4] === String(t.requirements.experienceMonths) &&
        s[5] === String(t.requirements.certificationCode) &&
        s[6] === String(t.deadline) &&
        s[7] === big(roots.issuerRegistryRoot).toString() &&
        s[8] === big(roots.revocationRoot).toString() &&
        s[9] === String(t.issuerEpoch) &&
        s[10] === b.nullifier &&
        s[11] === b.bidCommitment;
      if (!ok || !bound) allOk = false;
      details.push(
        `#${b.submissionIndex} ${ok ? "proof ok" : `proof FAILED (${why})`}, ${bound ? "bound to this tender" : "NOT bound to this tender's rules"}`,
      );
    }
    r.add(
      4,
      allOk,
      "Every eligibility proof verifies AND is bound to this tender's frozen rules",
      details.join("; ") || "no bids",
      "the rulesHash limbs are also checked, in item 4b",
    );

    // The limbs must reconstruct the frozen rulesHash.
    let limbsOk = bundle.acceptedBids.length > 0;
    for (const b of bundle.acceptedBids) {
      const hi = big(b.publicSignals[1]);
      const lo = big(b.publicSignals[2]);
      if (hi >= 1n << 128n || lo >= 1n << 128n) limbsOk = false;
      const reconstructed = "0x" + ((hi << 128n) | lo).toString(16).padStart(64, "0");
      if (reconstructed.toLowerCase() !== t.rulesHash.toLowerCase()) limbsOk = false;
    }
    r.add(
      "4b",
      limbsOk,
      "Each proof's rulesHash limbs reconstruct the frozen hash",
      limbsOk ? t.rulesHash : "at least one limb pair is out of range or reconstructs the wrong hash",
      "two 128-bit limbs, so the 256-bit hash travels losslessly through a 254-bit field",
    );
  }

  // ---- 5. nullifiers are distinct --------------------------------------
  {
    const seen = new Set(bundle.acceptedBids.map((b) => b.nullifier));
    const ok = seen.size === bundle.acceptedBids.length;
    r.add(
      5,
      ok,
      "Every nullifier is distinct, so no credential bid twice",
      `${seen.size} distinct of ${bundle.acceptedBids.length}`,
      "nullifiers are tender-scoped, so the same firm bidding elsewhere is not linkable",
    );
  }

  // ---- 6. storage receipts ---------------------------------------------
  {
    // A missing replica registry is reported as a MISSING REGISTRY, not as a
    // signature failure. An earlier version of this check silently produced an
    // empty map and then reported "SIGNATURE FAILED" for perfectly valid
    // receipts, which points a reader at the wrong thing entirely.
    if (!bundle.replicas?.registered?.length) {
      r.fail(
        6,
        "Every storage receipt is signed by a registered replica",
        "the bundle carries no replica registry",
        "without the registered signer addresses the receipts cannot be checked at all. Re-export the bundle with a current exporter.",
      );
    } else {
    const registered = new Map(
      bundle.replicas.registered.map((x) => [x.replicaId, x.signer.toLowerCase()]),
    );
    const quorum = bundle.replicas?.quorum ?? 2;
    let allOk = bundle.acceptedBids.length > 0;
    const details = [];
    for (const b of bundle.acceptedBids) {
      const root = storageReceiptRootFrom(b.replicaReceipts);
      const rootOk = root === big(b.storageReceiptRoot);
      let sigsOk = true;
      const ids = new Set();
      for (const rec of b.replicaReceipts) {
        const digest = receiptSigDigest({
          replicaId: rec.replicaId,
          contentHash: rec.contentHash,
          byteLength: Number(rec.byteLength),
        });
        let recovered;
        try {
          recovered = recoverAddress(digest, rec.signature).toLowerCase();
        } catch {
          sigsOk = false;
          continue;
        }
        if (recovered !== registered.get(rec.replicaId)) sigsOk = false;
        if (rec.contentHash.toLowerCase() !== b.ciphertextHash.toLowerCase()) sigsOk = false;
        ids.add(rec.replicaId);
      }
      const quorumOk = ids.size >= quorum;
      if (!rootOk || !sigsOk || !quorumOk) allOk = false;
      details.push(
        `#${b.submissionIndex} root ${rootOk ? "ok" : "MISMATCH"}, ${ids.size}/${quorum} replicas${sigsOk ? "" : ", SIGNATURE FAILED"}`,
      );
    }
    r.add(
      6,
      allOk,
      "Every storage receipt is signed by a registered replica, and the root rebuilds",
      details.join("; ") || "no bids",
      "so no commitment entered the accumulator without a retrievable payload behind it",
    );
    }
  }

  // ---- 7. every bid landed before the deadline -------------------------
  {
    const late = bundle.acceptedBids.filter((b) => b.acceptedTimestamp >= t.deadline);
    const early = bundle.acceptedBids.filter((b) => b.acceptedTimestamp < t.biddingStart);
    const ok = late.length === 0 && early.length === 0 && bundle.acceptedBids.length > 0;
    r.add(
      7,
      ok,
      "Every accepted bid was mined inside the bidding window",
      bundle.acceptedBids
        .map((b) => `#${b.submissionIndex} at ${b.acceptedTimestamp}`)
        .join(", ") || "no bids",
      ok
        ? `window ${t.biddingStart}..${t.deadline}`
        : `${late.length} at or after the deadline, ${early.length} before bidding opened`,
    );
  }

  // ---- 8. the opening ceremony ----------------------------------------
  {
    const members = new Map(
      (t.committeeKey?.memberShares ?? []).map((m) => [m.index, pt(m)]),
    );
    const ephemerals = new Map(bundle.ciphertexts.map((c) => [c.bidIndex, pt({ x: c.rX, y: c.rY })]));
    const threshold = t.committeeKey?.threshold ?? 3;
    const perBid = new Map();
    let allOk = bundle.opening.length > 0;
    const details = [];

    for (const s of bundle.opening) {
      const Y = members.get(s.memberIndex);
      const R = ephemerals.get(s.bidIndex);
      let ok = false;
      let why = "";
      if (!Y) why = `member ${s.memberIndex} is not in the committee`;
      else if (!R) why = `bid ${s.bidIndex}'s ciphertext was never published`;
      else if (!s.dleqProof) why = "no DLEQ proof in the bundle";
      else {
        ok = verifyDleq({
          publicShare: Y,
          ephemeral: R,
          decryptionShare: pt(s.share),
          proof: {
            a: { x: big(s.dleqProof.aX), y: big(s.dleqProof.aY) },
            b: { x: big(s.dleqProof.bX), y: big(s.dleqProof.bY) },
            z: big(s.dleqProof.z),
          },
        });
        if (!ok) why = "the Chaum-Pedersen proof does not verify";
      }
      // Every share must be after the deadline.
      if (ok && s.timestamp !== null && s.timestamp < t.deadline) {
        ok = false;
        why = `submitted at ${s.timestamp}, before the deadline ${t.deadline}`;
      }
      if (!ok) allOk = false;
      const set = perBid.get(s.bidIndex) ?? new Set();
      if (ok) set.add(s.memberIndex);
      perBid.set(s.bidIndex, set);
      if (!ok) details.push(`bid ${s.bidIndex}/member ${s.memberIndex}: ${why}`);
    }

    for (const [bidIndex, set] of [...perBid.entries()].sort((a, b) => a[0] - b[0])) {
      if (set.size < threshold) {
        allOk = false;
        details.push(`bid ${bidIndex}: only ${set.size} valid distinct shares, ${threshold} required`);
      } else {
        details.push(`bid ${bidIndex}: ${set.size} valid distinct shares`);
      }
    }

    r.add(
      8,
      allOk,
      `Every decryption share verifies, at least ${threshold} distinct per bid, all after the deadline`,
      details.join("; ") || "no shares",
      "each share proves the same secret relates the member's published Y_i to the share submitted",
    );
  }

  // ---- 9. close-time status proofs -------------------------------------
  {
    if (bundle.statusProofs.length === 0) {
      r.skip(
        9,
        "Close-time credential status against the pinned deadline root",
        "no status proofs in the bundle. The award, if any, would have been refused without one for the winner.",
      );
    } else {
      let allOk = true;
      const details = [];
      for (const sp of bundle.statusProofs) {
        const { ok, why } = await verifyGroth16(vks.eligibility, sp.publicSignals, sp.proof);
        // Signal 8 must be the PINNED deadline root, not the epoch root.
        const usesDeadlineRoot =
          sp.publicSignals[8] === big(roots.deadlineRevocationRoot).toString();
        const differsFromSubmission =
          big(roots.deadlineRevocationRoot) !== big(roots.revocationRoot);
        if (!ok || !usesDeadlineRoot) allOk = false;
        details.push(
          `#${sp.bidIndex} ${ok ? "ok" : `FAILED (${why})`}, ${usesDeadlineRoot ? "against the deadline root" : "NOT against the deadline root"}${differsFromSubmission ? "" : " (which equals the submission-time root, so this check is vacuous here)"}`,
        );
      }
      r.add(
        9,
        allOk,
        "Each counted bid re-proved eligibility against the pinned deadline root",
        details.join("; "),
        "so 'unrevoked' is not inferred from the snapshot current at submission",
      );
    }
  }

  // ---- 10. the award ---------------------------------------------------
  {
    if (!bundle.award) {
      r.skip(10, "The award proof", "no award recorded for this tender");
    } else {
      const a = bundle.award;
      const { ok, why } = await verifyGroth16(vks.award, a.publicSignals, a.proof);
      const s = a.publicSignals;
      const hi = big(s[1]);
      const lo = big(s[2]);
      const reconstructed = "0x" + ((hi << 128n) | lo).toString(16).padStart(64, "0");
      const bound =
        s[0] === t.tenderIdField &&
        reconstructed.toLowerCase() === t.rulesHash.toLowerCase() &&
        s[3] === big(roots.bidSetRoot).toString() &&
        s[4] === String(roots.submissionCount) &&
        s[5] === a.winnerCommitment &&
        s[6] === a.winningPrice &&
        s[7] === String(t.disclosurePolicy);
      const winner = bundle.acceptedBids.find(
        (b) => b.submissionIndex === a.winnerSubmissionIndex,
      );
      const winnerIsAccepted = winner && winner.bidCommitment === a.winnerCommitment;
      const policyOk =
        t.disclosurePolicy === 2 ? a.winningPrice === "0" : a.winningPrice !== "0";
      r.add(
        10,
        ok && bound && winnerIsAccepted && policyOk,
        "The award proof verifies over the COMPLETE bid set recorded on-chain",
        `winner #${a.winnerSubmissionIndex}, price ${a.winningPrice}, root ${s[3]}`,
        !ok
          ? `the proof failed: ${why}`
          : !bound
            ? "the public signals do not match the tender's own values"
            : !winnerIsAccepted
              ? "the winning commitment is not an accepted bid's"
              : !policyOk
                ? "the published price contradicts the frozen disclosure policy"
                : "bidSetRoot and submissionCount come from the chain, so a stale root cannot be offered",
      );
    }
  }

  // ---- 11. the winner identity linkage --------------------------------
  {
    if (!bundle.identityLinkage) {
      r.skip(
        11,
        "The winner-identity linkage proof",
        "no identity published. The award stands on its own; a name is only shown after this proof.",
      );
    } else {
      const i = bundle.identityLinkage;
      const { ok, why } = await verifyGroth16(vks.winner_identity, i.publicSignals, i.proof);
      const s = i.publicSignals;
      const winner = bundle.award
        ? bundle.acceptedBids.find(
            (b) => b.submissionIndex === bundle.award.winnerSubmissionIndex,
          )
        : null;
      const bound =
        s[0] === t.tenderIdField &&
        (!bundle.award || s[1] === bundle.award.winnerCommitment) &&
        (!winner || s[2] === winner.nullifier) &&
        s[3] === i.legalIdentityCommitment &&
        s[4] === big(roots.issuerRegistryRoot).toString();
      let declared = null;
      try {
        declared = JSON.parse(i.disclosedIdentity);
      } catch {
        declared = null;
      }
      const recordNamesCredential =
        declared && Number(declared.credentialId) === i.credentialId;
      r.add(
        11,
        ok && bound && recordNamesCredential,
        "The published identity belongs to the holder of the winning bid",
        declared ? `${declared.legalName}, credential #${i.credentialId}` : "unparseable record",
        !ok
          ? `the proof failed: ${why}`
          : !bound
            ? "the signals do not tie to the winning bid or the published registry root"
            : !recordNamesCredential
              ? "the record's credentialId disagrees with the one bound into the commitment"
              : "a linkage to the credential holder, NOT a verification of the declared legal name",
      );
    }
  }

  // ---- 12. the public checkpoint anchor -------------------------------
  if (!bundle.anchor) {
    r.skip(
      12,
      "The public checkpoint anchor",
      "not implemented in this prototype. Without it, a reader must trust that this permissioned chain has not been rewritten wholesale by its four validators - which is the residual the whitepaper names for anchoring.",
    );
  } else {
    r.skip(12, "The public checkpoint anchor", "anchor present but checking is not implemented");
  }

  // ---- 13. the bundle carries no secrets ------------------------------
  {
    const forbidden = options.forbiddenFields
      ? options.forbiddenFields(bundle)
      : defaultForbiddenScan(bundle);
    r.add(
      13,
      forbidden.length === 0,
      "The bundle contains no private witness, key or undisclosed amount",
      forbidden.length === 0 ? "no forbidden field found" : forbidden.join(", "),
      "a bundle carrying a private witness would be worse than no bundle at all",
    );
  }

  // ---- optional: cross-check against a live chain ----------------------
  if (options.rpcUrl) {
    try {
      const provider = new JsonRpcProvider(options.rpcUrl, {
        chainId: bundle.generatedFrom.chainId,
        name: "fairproof",
      });
      const net = await provider.getNetwork();
      const chainOk = Number(net.chainId) === bundle.generatedFrom.chainId;
      const block = await provider.getBlock(bundle.generatedFrom.blockNumber);
      const hashOk = block && block.hash === bundle.generatedFrom.blockHash;
      r.add(
        "rpc-1",
        chainOk && !!hashOk,
        "The bundle names a block this chain actually has",
        `chain ${net.chainId}, block ${bundle.generatedFrom.blockNumber} hash ${block?.hash ?? "not found"}`,
        chainOk
          ? hashOk
            ? "so the bundle describes this chain's history, not a fabricated one"
            : "the block hash does not match - the bundle is from a different chain or a reorganised one"
          : "chain id mismatch",
      );

      // The deployed bytecode must still hash to what the bundle recorded.
      let codeOk = true;
      const drifted = [];
      for (const [name, c] of Object.entries(bundle.contracts)) {
        const code = await provider.getCode(c.address, bundle.generatedFrom.blockNumber);
        if (keccak256(code) !== c.codeHash) {
          codeOk = false;
          drifted.push(name);
        }
      }
      r.add(
        "rpc-2",
        codeOk,
        "Every contract's deployed bytecode matches the hash in the bundle",
        codeOk ? `${Object.keys(bundle.contracts).length} contracts` : `drifted: ${drifted.join(", ")}`,
        "so the bundle describes the code that actually ran",
      );
      provider.destroy();
    } catch (err) {
      r.fail("rpc-1", "Cross-check against the live chain", err.message);
    }
  } else {
    r.skip(
      "rpc-1",
      "Cross-check against a live chain",
      "no --rpc given. Every check above ran against the bundle alone, which is the point - but pass --rpc to confirm the bundle describes a real chain's history.",
    );
  }

  return r;
}

/**
 * A structural scan for fields that must never appear.
 *
 * Deliberately implemented here rather than imported from the exporter: a
 * verifier that used the producer's own definition of "forbidden" would agree
 * with it by construction.
 */
export function defaultForbiddenScan(bundle) {
  const FORBIDDEN = [
    "subjectSecret",
    "dek",
    "bidNonce",
    "privateKey",
    "mnemonic",
    "witness",
    "annualTurnover",
    "relevantExperience",
    "issuerSigS",
    "iv",
    "wrapped",
    "entropy",
  ];
  const hits = [];
  const walk = (node, path) => {
    if (Array.isArray(node)) {
      node.forEach((v, i) => walk(v, `${path}[${i}]`));
      return;
    }
    if (node && typeof node === "object") {
      for (const [k, v] of Object.entries(node)) {
        const here = path ? `${path}.${k}` : k;
        if (FORBIDDEN.includes(k)) hits.push(here);
        walk(v, here);
      }
    }
  };
  walk(bundle, "");
  return hits;
}
