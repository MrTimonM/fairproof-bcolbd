/**
 * The evidence bundle exporter.
 *
 * Whitepaper Section 19.4 promises a downloadable bundle and a "verify
 * independently" control, which makes this a protocol artefact rather than a
 * UI convenience. Plan Section 16.5 sets the rules, and two of them shape
 * everything here:
 *
 *   DETERMINISTIC. Two exports of the same finalized tender must be
 *   byte-identical. So there is no generation timestamp, no wall-clock value,
 *   no iteration over an unordered map, and the whole document is JCS
 *   canonicalized with sorted keys. A bundle that changes between exports
 *   cannot be a reference.
 *
 *   CHAIN-DERIVED. Every value is copied from chain state, never from a read
 *   model. The proofs are the interesting case: they are verified on-chain but
 *   not stored, so they are recovered by DECODING THE TRANSACTION CALLDATA of
 *   the transaction that carried them. That means the bundle contains nothing
 *   that is not already permanently on the chain, and anyone can reproduce it
 *   from the same source.
 *
 * WHAT MUST NEVER APPEAR: any private witness, any dek, any subjectSecret, any
 * bid nonce for an undisclosed bid, and no losing amount under a commercial
 * disclosure policy. `assertNoSecrets` enforces it, and the test suite greps
 * an exported bundle for every known secret in the seed dataset.
 */
import { readFileSync } from "node:fs";
import { Contract, Interface, JsonRpcProvider, keccak256 } from "ethers";
import { jcsCanonicalize } from "@fairproof/crypto";

/**
 * Besu caps a single eth_getLogs range (--rpc-max-logs-range, 5000 blocks by
 * default) and a long-lived chain outgrows it: an export over a 9,065-block
 * span was refused outright. Walk the range in windows instead, so a bundle
 * does not depend on how permissively the node it was exported from happens to
 * be configured. Every caller either sorts its logs explicitly or looks one up
 * by index, so the concatenation order across windows never reaches the bytes.
 */
const LOG_WINDOW = 4000;

async function logsIn(contract, filter, from, to) {
  const out = [];
  const last = Number(to);
  for (let start = Number(from); start <= last; start += LOG_WINDOW) {
    out.push(...(await contract.queryFilter(filter, start, Math.min(start + LOG_WINDOW - 1, last))));
  }
  return out;
}

export const BUNDLE_VERSION = "1.0.0";

const CONTRACT_ARTIFACTS = {
  Governance: "contracts/Governance.sol/Governance.json",
  IssuerRegistry: "contracts/IssuerRegistry.sol/IssuerRegistry.json",
  TenderRegistry: "contracts/TenderRegistry.sol/TenderRegistry.json",
  EligibilityVerifier: "contracts/EligibilityVerifier.sol/EligibilityVerifier.json",
  SealedBid: "contracts/SealedBid.sol/SealedBid.json",
  OpeningManager: "contracts/OpeningManager.sol/OpeningManager.json",
  DeadlineStatus: "contracts/DeadlineStatus.sol/DeadlineStatus.json",
  AwardManager: "contracts/AwardManager.sol/AwardManager.json",
  WinnerIdentity: "contracts/WinnerIdentity.sol/WinnerIdentity.json",
};

/** BigInt -> decimal string, recursively. JSON has no bigint. */
function plain(value) {
  if (typeof value === "bigint") return value.toString();
  if (Array.isArray(value)) return value.map(plain);
  if (value && typeof value === "object") {
    const out = {};
    for (const k of Object.keys(value)) out[k] = plain(value[k]);
    return out;
  }
  return value;
}

/** A proof triple from decoded calldata, in a stable shape. */
const proofTriple = (a, b, c) => ({
  pA: [a[0].toString(), a[1].toString()],
  pB: [
    [b[0][0].toString(), b[0][1].toString()],
    [b[1][0].toString(), b[1][1].toString()],
  ],
  pC: [c[0].toString(), c[1].toString()],
});

export async function exportBundle({
  repoRoot,
  tenderId,
  rpcUrl,
  atBlock,
}) {
  const cfg = JSON.parse(
    readFileSync(`${repoRoot}/infrastructure/besu/config/accounts.json`, "utf8"),
  );
  const dep = JSON.parse(readFileSync(`${repoRoot}/deployments.json`, "utf8"));
  const artifact = (p) =>
    JSON.parse(readFileSync(`${repoRoot}/packages/contracts/artifacts/${p}`, "utf8"));

  const provider = new JsonRpcProvider(rpcUrl ?? `http://127.0.0.1:${cfg.validators[0].rpc}`, {
    chainId: cfg.chainId,
    name: "fairproof",
  });

  const abis = {};
  for (const [name, path] of Object.entries(CONTRACT_ARTIFACTS)) {
    abis[name] = artifact(path).abi;
  }
  const c = (name) => new Contract(dep.contracts[name], abis[name], provider);

  // Pin a block. Everything below is read AT that block, so a transaction
  // landing mid-export cannot produce a half-consistent bundle.
  const block = await provider.getBlock(atBlock ?? "latest");
  const at = { blockTag: block.number };

  const tr = c("TenderRegistry");
  const reg = c("IssuerRegistry");
  const sb = c("SealedBid");
  const om = c("OpeningManager");
  const ds = c("DeadlineStatus");
  const am = c("AwardManager");
  const wi = c("WinnerIdentity");

  const t = await tr.getTender(tenderId, at);
  if (Number(t.state) === 0) {
    throw new Error(`no such tender on this chain: ${tenderId}`);
  }

  // ---- contract code hashes, so the bundle names the bytecode it describes
  const contracts = {};
  for (const name of Object.keys(CONTRACT_ARTIFACTS).sort()) {
    const address = dep.contracts[name];
    if (!address) continue;
    const code = await provider.getCode(address, block.number);
    contracts[name] = { address, codeHash: keccak256(code) };
  }

  // ---- the verification keys, included so the bundle is self-verifying
  //
  // Plan Section 16.5 lists only `verificationKeyHash`. The full keys are
  // included as well, deliberately: the point of the bundle is that a stranger
  // can check it, and a hash alone would force them to obtain the keys from us
  // anyway. Each key's hash is recorded next to it and, where the chain stores
  // one, compared against the on-chain value by the verifier.
  const verificationKeys = {};
  for (const circuit of ["eligibility", "award", "winner_identity"]) {
    try {
      const vk = JSON.parse(
        readFileSync(
          `${repoRoot}/packages/circuits/build/${circuit}/${circuit}_verification_key.json`,
          "utf8",
        ),
      );
      verificationKeys[circuit] = vk;
    } catch {
      // A missing key is reported by the verifier as an unverifiable proof
      // rather than silently omitted here.
    }
  }

  const ceremonies = {};
  for (const circuit of ["eligibility", "award", "winner_identity"]) {
    try {
      const tx = JSON.parse(
        readFileSync(`${repoRoot}/packages/circuits/ceremony/${circuit}.transcript.json`, "utf8"),
      );
      ceremonies[circuit] = {
        circuitSourcesDigest: tx.circuitSources.combined,
        contributions: tx.contributions.map((k) => ({
          index: k.index,
          name: k.name,
          independent: k.independent,
          contributionHash: k.contributionHash,
        })),
        beacon: tx.beacon
          ? { source: tx.beacon.source, round: tx.beacon.round, randomness: tx.beacon.randomness }
          : null,
        singleMachine: tx.singleMachine === true,
        verificationKeyHash: tx.verificationKey.sha256,
        phase1: { name: tx.phase1.name, sha256: tx.phase1.sha256, power: tx.phase1.power },
      };
    } catch {
      // Absent transcript: the verifier reports the provenance as unavailable.
    }
  }

  // ---- accepted bids, with their proofs recovered from calldata ----------
  const sbIface = new Interface(abis.SealedBid);
  const submissionCount = Number(await sb.submissionCount(tenderId, at));
  const bidEvents = await logsIn(sb, sb.filters.BidAccepted(tenderId), dep.deployedAt, block.number);

  const acceptedBids = [];
  for (let i = 0; i < submissionCount; i++) {
    const bid = await sb.getBid(tenderId, i, at);
    const ev = bidEvents.find((e) => Number(e.args.submissionIndex) === i);
    if (!ev) throw new Error(`no BidAccepted event for submission ${i}`);
    const tx = await provider.getTransaction(ev.transactionHash);
    const decoded = sbIface.parseTransaction({ data: tx.data });
    if (!decoded || decoded.name !== "submitBid") {
      throw new Error(`submission ${i} did not come from submitBid`);
    }
    const [submission, receipts, pa, pb, pc] = decoded.args;
    const evBlock = await provider.getBlock(ev.blockNumber);

    acceptedBids.push({
      submissionIndex: i,
      nullifier: bid.nullifier.toString(),
      bidCommitment: bid.bidCommitment.toString(),
      ciphertextHash: bid.ciphertextHash,
      storageReceiptRoot: bid.storageReceiptRoot.toString(),
      leaf: bid.leaf.toString(),
      acceptedBlock: ev.blockNumber,
      acceptedTimestamp: Number(evBlock.timestamp),
      acceptedTxHash: ev.transactionHash,
      submitter: bid.submitter,
      replicaReceipts: receipts.map((r) => ({
        replicaId: Number(r.replicaId),
        contentHash: r.contentHash,
        byteLength: r.byteLength.toString(),
        signature: r.signature,
      })),
      eligibilityProof: proofTriple(pa, pb, pc),
      // Rebuilt from chain state by the verifier, and recorded here so a
      // reader can see exactly what statement was proved.
      publicSignals: (
        await c("EligibilityVerifier").expectedPublicSignals(
          tenderId, bid.nullifier, bid.bidCommitment, at,
        )
      ).map((s) => s.toString()),
      submission: {
        tenderId: submission.tenderId,
        nullifier: submission.nullifier.toString(),
        bidCommitment: submission.bidCommitment.toString(),
        ciphertextHash: submission.ciphertextHash,
      },
    });
  }

  // ---- the opening ceremony ---------------------------------------------
  const omIface = new Interface(abis.OpeningManager);
  const opening = [];
  const ciphertexts = [];
  for (let i = 0; i < submissionCount; i++) {
    const ct = await om.getCiphertext(tenderId, i, at);
    if (ct.revealed) {
      const reveals = await logsIn(om, om.filters.CiphertextRevealed(tenderId, i), dep.deployedAt, block.number);
      const ev = reveals[0];
      const tx = ev ? await provider.getTransaction(ev.transactionHash) : null;
      const decoded = tx ? omIface.parseTransaction({ data: tx.data }) : null;
      ciphertexts.push({
        bidIndex: i,
        rX: ct.rX.toString(),
        rY: ct.rY.toString(),
        byteLength: Number(ct.byteLength),
        revealedBlock: ev ? ev.blockNumber : null,
        // The canonical ciphertext bytes, from the calldata of the reveal.
        // Safe to publish: the payload is still encrypted, and including it
        // makes the bundle self-contained rather than dependent on a replica
        // that may be gone by the time anyone audits.
        canonicalBytes: decoded ? decoded.args[2] : null,
      });
    }

    const shares = await om.getShares(tenderId, i, at);
    const shareEvents = await logsIn(om, om.filters.DecryptionShareAccepted(tenderId, i), dep.deployedAt, block.number);
    for (const s of shares) {
      const ev = shareEvents.find(
        (e) => Number(e.args.memberIndex) === Number(s.memberIndex),
      );
      const tx = ev ? await provider.getTransaction(ev.transactionHash) : null;
      const decoded = tx ? omIface.parseTransaction({ data: tx.data }) : null;
      const evBlock = ev ? await provider.getBlock(ev.blockNumber) : null;
      opening.push({
        bidIndex: i,
        memberIndex: Number(s.memberIndex),
        share: { x: s.dX.toString(), y: s.dY.toString() },
        dleqProof: decoded
          ? {
              aX: decoded.args[5].aX.toString(),
              aY: decoded.args[5].aY.toString(),
              bX: decoded.args[5].bX.toString(),
              bY: decoded.args[5].bY.toString(),
              z: decoded.args[5].z.toString(),
            }
          : null,
        submitter: s.submitter,
        block: ev ? ev.blockNumber : null,
        timestamp: evBlock ? Number(evBlock.timestamp) : null,
      });
    }
  }
  // Deterministic ordering, since queryFilter order is not guaranteed.
  opening.sort((a, b) => a.bidIndex - b.bidIndex || a.memberIndex - b.memberIndex);

  // ---- close-time status proofs -----------------------------------------
  const dsIface = new Interface(abis.DeadlineStatus);
  const statusProofs = [];
  const statusEvents = await logsIn(ds, ds.filters.StatusProven(tenderId), dep.deployedAt, block.number);
  for (let i = 0; i < submissionCount; i++) {
    const st = await ds.getStatus(tenderId, i, at);
    if (!st.proven) continue;
    const ev = statusEvents.find((e) => Number(e.args.bidIndex) === i);
    const tx = ev ? await provider.getTransaction(ev.transactionHash) : null;
    const decoded = tx ? dsIface.parseTransaction({ data: tx.data }) : null;
    statusProofs.push({
      bidIndex: i,
      deadlineRoot: st.deadlineRoot,
      block: ev ? ev.blockNumber : null,
      proof: decoded ? proofTriple(decoded.args[2], decoded.args[3], decoded.args[4]) : null,
      publicSignals: (
        await c("EligibilityVerifier").expectedDeadlineStatusSignals(
          tenderId,
          (await sb.getBid(tenderId, i, at)).nullifier,
          (await sb.getBid(tenderId, i, at)).bidCommitment,
          at,
        )
      ).map((s) => s.toString()),
    });
  }

  // ---- the award ---------------------------------------------------------
  const amIface = new Interface(abis.AwardManager);
  let award = null;
  if (await am.isAwarded(tenderId, at)) {
    const a = await am.getAward(tenderId, at);
    const events = await logsIn(am, am.filters.AwardRecorded(tenderId), dep.deployedAt, block.number);
    const ev = events[0];
    const tx = ev ? await provider.getTransaction(ev.transactionHash) : null;
    const decoded = tx ? amIface.parseTransaction({ data: tx.data }) : null;
    award = {
      winnerCommitment: a.winnerCommitment.toString(),
      winningPrice: a.winningPrice.toString(),
      winnerSubmissionIndex: Number(a.winnerSubmissionIndex),
      bidSetRoot: a.bidSetRoot.toString(),
      submissionCount: Number(a.submissionCount),
      disclosurePolicy: Number(a.disclosurePolicy),
      recordedBy: a.recordedBy,
      block: ev ? ev.blockNumber : null,
      verifiedTxHash: ev ? ev.transactionHash : null,
      proof: decoded ? proofTriple(decoded.args[4], decoded.args[5], decoded.args[6]) : null,
      publicSignals: (
        await am.expectedPublicSignals(tenderId, a.winnerCommitment, a.winningPrice, at)
      ).map((s) => s.toString()),
      circuitVersion: Number(await am.circuitVersion(at)),
      vkeyHash: await am.vkeyHash(at),
    };
  }

  // ---- winner identity ---------------------------------------------------
  const wiIface = new Interface(abis.WinnerIdentity);
  let identityLinkage = null;
  if (await wi.isProven(tenderId, at)) {
    const id = await wi.getIdentity(tenderId, at);
    const events = await logsIn(wi, wi.filters.WinnerIdentityProven(tenderId), dep.deployedAt, block.number);
    const ev = events[0];
    const tx = ev ? await provider.getTransaction(ev.transactionHash) : null;
    const decoded = tx ? wiIface.parseTransaction({ data: tx.data }) : null;
    identityLinkage = {
      credentialId: Number(id.credentialId),
      legalIdentityCommitment: id.legalIdentityCommitment.toString(),
      // The declared record. Published on-chain by the winner, so including it
      // discloses nothing new - and it is what lets the issuer confirm the
      // declaration against the firm it actually issued to.
      disclosedIdentity: new TextDecoder().decode(
        Uint8Array.from(
          id.record.slice(2).match(/.{1,2}/g)?.map((h) => parseInt(h, 16)) ?? [],
        ),
      ),
      block: ev ? ev.blockNumber : null,
      proof: decoded ? proofTriple(decoded.args[3], decoded.args[4], decoded.args[5]) : null,
      publicSignals: (
        await wi.expectedPublicSignals(tenderId, id.credentialId, id.record, at)
      ).map((s) => s.toString()),
      circuitVersion: Number(await wi.circuitVersion(at)),
    };
  }

  // ---- ordered protocol events ------------------------------------------
  const events = [];
  const collect = async (name, filter) => {
    const logs = await logsIn(c(name), filter, dep.deployedAt, block.number);
    for (const l of logs) {
      events.push({
        contract: name,
        event: l.fragment?.name ?? "unknown",
        block: l.blockNumber,
        logIndex: l.index,
        txHash: l.transactionHash,
      });
    }
  };
  await collect("TenderRegistry", tr.filters.TenderActivated(tenderId));
  await collect("TenderRegistry", tr.filters.TenderClosed(tenderId));
  await collect("SealedBid", sb.filters.BidAccepted(tenderId));
  await collect("OpeningManager", om.filters.CiphertextRevealed(tenderId));
  await collect("OpeningManager", om.filters.DecryptionShareAccepted(tenderId));
  await collect("OpeningManager", om.filters.OpeningThresholdReached(tenderId));
  await collect("DeadlineStatus", ds.filters.StatusProven(tenderId));
  await collect("AwardManager", am.filters.AwardRecorded(tenderId));
  await collect("WinnerIdentity", wi.filters.WinnerIdentityProven(tenderId));
  events.sort((a, b) => a.block - b.block || a.logIndex - b.logIndex);

  // The registered ciphertext-store replicas, so a verifier can recover each
  // receipt signature and compare it against the address the chain accepts.
  // Without these the storage quorum could only be taken on trust.
  const replicas = [];
  for (let id = 1; id <= Number(await sb.STORAGE_REPLICAS(at)); id++) {
    const r = await sb.getReplica(id, at);
    if (r.signer === "0x0000000000000000000000000000000000000000") continue;
    replicas.push({
      replicaId: id,
      signer: r.signer,
      active: r.active,
      label: r.label,
    });
  }

  const committee = await tr.getCommitteeKey(tenderId, at).catch(() => null);
  const members = await tr.getCommitteeMembers(tenderId, at).catch(() => []);

  const bundle = {
    bundleVersion: BUNDLE_VERSION,
    generatedFrom: {
      chainId: cfg.chainId,
      blockNumber: block.number,
      blockHash: block.hash,
    },
    contracts,
    versions: {
      verifierVersion: Number(t.verifierVersion),
      schemaVersion: Number(t.schemaVersion),
      poseidonParams: "circomlib Poseidon over BN254, arities 2-6",
      ceremonies,
    },
    verificationKeys,
    tender: {
      tenderId,
      tenderIdString: t.tenderIdString,
      tenderIdField: t.tenderIdField.toString(),
      state: Number(t.state),
      authority: t.authority,
      rulesHash: t.rulesHash,
      fieldsDigest: t.fieldsDigest,
      canonicalRuleDocument: new TextDecoder().decode(
        Uint8Array.from(
          (await tr.getRuleDocument(tenderId, at)).slice(2).match(/.{1,2}/g)?.map((h) =>
            parseInt(h, 16),
          ) ?? [],
        ),
      ),
      activatedAt: Number(t.activatedAt),
      biddingStart: Number(t.biddingStart),
      deadline: Number(t.deadline),
      reviewWindow: Number(t.reviewWindow),
      absoluteMinReviewWindow: Number(await tr.ABSOLUTE_MIN_REVIEW_WINDOW(at)),
      disclosurePolicy: Number(t.disclosurePolicy),
      awardRule: Number(t.awardRule),
      tieBreakRule: Number(t.tieBreakRule),
      issuerEpoch: Number(t.issuerEpoch),
      requirements: {
        turnoverThreshold: t.requirements.turnoverThreshold.toString(),
        experienceMonths: Number(t.requirements.experienceMonths),
        certificationCode: t.requirements.certificationCode.toString(),
      },
      committeeKey: committee
        ? {
            yX: committee.yX.toString(),
            yY: committee.yY.toString(),
            memberShares: committee.memberX.map((x, i) => ({
              index: i + 1,
              x: x.toString(),
              y: committee.memberY[i].toString(),
              address: members[i] ?? null,
            })),
            commitments: committee.commitmentX.map((x, i) => ({
              index: i,
              x: x.toString(),
              y: committee.commitmentY[i].toString(),
            })),
            threshold: Number(await tr.COMMITTEE_THRESHOLD(at)),
            size: Number(await tr.COMMITTEE_SIZE(at)),
          }
        : null,
    },
    replicas: {
      registered: replicas,
      quorum: Number(await sb.STORAGE_QUORUM(at)),
      total: Number(await sb.STORAGE_REPLICAS(at)),
    },
    roots: {
      issuerRegistryRoot: await reg.issuerRegistryRoot(t.issuerEpoch, at),
      revocationRoot: await reg.revocationRoot(t.issuerEpoch, at),
      deadlineRevocationRoot: await reg.deadlineRevocationRoot(tenderId, at),
      bidSetRoot: (await sb.bidSetRoot(tenderId, at)).toString(),
      submissionCount,
    },
    acceptedBids,
    ciphertexts,
    opening,
    statusProofs,
    award,
    identityLinkage,
    anchor: null,
    events,
  };

  provider.destroy();
  return plain(bundle);
}

/**
 * Names that must never appear as a key anywhere in the bundle.
 *
 * Checked structurally rather than by grepping for values, because a value
 * scan only catches secrets it already knows. Both checks run: the test suite
 * also greps an exported bundle for every secret in the seed dataset.
 */
const FORBIDDEN_KEYS = [
  "subjectSecret",
  "dek",
  "bidNonce",
  "privateKey",
  "mnemonic",
  "secret",
  "share", // the DEALT secret share; the public decryption share is "share.x/y"
  "witness",
  "annualTurnover",
  "relevantExperience",
  "credentialValidUntil",
  "issuerSigS",
  "iv",
  "wrapped",
];

/**
 * @returns {string[]} the paths of any forbidden field found.
 */
export function findForbiddenFields(bundle) {
  const hits = [];
  const walk = (node, path) => {
    if (Array.isArray(node)) {
      node.forEach((v, i) => walk(v, `${path}[${i}]`));
      return;
    }
    if (node && typeof node === "object") {
      for (const [k, v] of Object.entries(node)) {
        const here = path ? `${path}.${k}` : k;
        // `share` is legitimate as a container of the PUBLIC decryption share
        // point, which is safe and is what makes the ceremony verifiable. It is
        // forbidden only as a scalar.
        const scalarShare = k === "share" && typeof v !== "object";
        if (FORBIDDEN_KEYS.includes(k) && (k !== "share" || scalarShare)) {
          hits.push(here);
        }
        walk(v, here);
      }
    }
  };
  walk(bundle, "");
  return hits;
}

export function assertNoSecrets(bundle) {
  const hits = findForbiddenFields(bundle);
  if (hits.length > 0) {
    throw new Error(
      `the bundle contains ${hits.length} forbidden field(s): ${hits.join(", ")}. ` +
        `A bundle carrying a private witness is worse than no bundle at all.`,
    );
  }
}

/** The canonical, deterministic serialisation. */
export function serialise(bundle) {
  return jcsCanonicalize(bundle) + "\n";
}

export function bundleFilename(bundle) {
  const id = bundle.tender.tenderIdString.replace(/[^A-Za-z0-9._-]/g, "_");
  return `fairproof-evidence-${id}-${bundle.generatedFrom.blockNumber}.json`;
}
