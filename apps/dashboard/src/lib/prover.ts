/**
 * Zero-knowledge proving, in the browser.
 *
 * The witness never leaves this tab. That is the whole point: a bidder's
 * turnover, experience and bid amount are private inputs, and a design that
 * posted them to a proving server would have moved the disclosure rather than
 * removed it. The circuit's wasm and its proving key are served as static
 * assets from this origin, so no third party is involved in producing a proof.
 *
 * 18 MB of assets are fetched on first use and cached by the browser. On
 * localhost that is imperceptible; the progress callbacks exist because on a
 * slower link the wait would otherwise look like a hang.
 */
import {
  DISCLOSE_WINNING_PRICE,
  SCHEMA_VERSION,
  awardCircuitInput,
  awardPublicSignals,
  buildAwardWitness,
  buildWinnerIdentityWitness,
  winnerIdentityCircuitInput,
  winnerIdentityPublicSignals,
  type AwardWitness,
  type OpenedBid,
  type WinnerIdentityWitness,
  bidCommitment as computeBidCommitment,
  buildEligibilityWitness,
  credDigest,
  derivePublicKey,
  emptyRevocationTree,
  initBabyjub,
  initEddsa,
  initPoseidon,
  issuerRegistryPath,
  issuerRegistryRoot,
  nullifier as computeNullifier,
  revocationTreeWith,
  sealBid,
  signCredential,
  subjectCommitment,
  tenderIdField,
  toLimbs,
  type EligibilityWitness,
} from "@fairproof/crypto";

import type { Attestation } from "./attestation";

/** snarkjs ships no types and is loaded lazily so it stays out of first paint. */
let snarkjs: any = null;
async function loadSnarkjs() {
  if (!snarkjs) snarkjs = await import("snarkjs");
  return snarkjs;
}

let cryptoReady: Promise<void> | null = null;
export function initCrypto(): Promise<void> {
  if (!cryptoReady) {
    cryptoReady = (async () => {
      await initPoseidon();
      await initEddsa();
      await initBabyjub();
    })();
  }
  return cryptoReady;
}

/** Which circuit's artefacts to fetch. Each is cached after its first use. */
export type CircuitName = "eligibility" | "award" | "winner_identity";

const assetCache = new Map<CircuitName, { wasm: Uint8Array; zkey: Uint8Array }>();

/** Fetch and cache a circuit's artefacts, reporting progress. */
export async function loadCircuit(
  onProgress?: (loaded: number, total: number, what: string) => void,
  circuit: CircuitName = "eligibility",
): Promise<{ wasm: Uint8Array; zkey: Uint8Array }> {
  const cached = assetCache.get(circuit);
  if (cached) return cached;

  const get = async (url: string, what: string) => {
    const res = await fetch(url);
    if (!res.ok) {
      throw new Error(
        `could not load ${what} (${res.status}). Run \`npm run dashboard:sync\` after the ceremony.`,
      );
    }
    const total = Number(res.headers.get("content-length") ?? 0);
    if (!res.body || !total) return new Uint8Array(await res.arrayBuffer());
    const reader = res.body.getReader();
    const chunks: Uint8Array[] = [];
    let loaded = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
      loaded += value.length;
      onProgress?.(loaded, total, what);
    }
    const out = new Uint8Array(loaded);
    let at = 0;
    for (const c of chunks) {
      out.set(c, at);
      at += c.length;
    }
    return out;
  };

  const wasm = await get(`/circuits/${circuit}.wasm`, "the circuit");
  const zkey = await get(`/circuits/${circuit}.zkey`, "the proving key");
  const loaded = { wasm, zkey };
  assetCache.set(circuit, loaded);
  return loaded;
}

/** A circuit's published verification key. */
async function vkeyOf(circuit: CircuitName): Promise<unknown> {
  const res = await fetch(`/circuits/${circuit}.vkey.json`);
  if (!res.ok) throw new Error(`could not load the ${circuit} verification key (${res.status})`);
  return res.json();
}

export interface CredentialInput {
  /** The bidder's secret. Generated in this tab and never transmitted. */
  subjectSecret: bigint;
  annualTurnover: bigint;
  relevantExperience: bigint;
  credentialId: bigint;
  /**
   * What the issuer actually certified.
   *
   * Defaults to the code the tender requires, which is the right thing for a
   * firm that holds it. Passing a different one produces a witness the circuit
   * refuses — the equality is a constraint, not a formality, and a bidder
   * holding a broader qualification cannot substitute it because deciding
   * whether it is broader is a judgement no circuit can make.
   */
  certificationCode?: bigint;
  validUntil: bigint;
  issuedAt: bigint;
}

export interface TenderInput {
  tenderIdString: string;
  rulesHash: string;
  turnoverThreshold: bigint;
  experienceMonthsThreshold: bigint;
  requiredCertificationCode: bigint;
  deadline: bigint;
  credentialEpoch: bigint;
  /** Which revocation tree the proof must be checked against. */
  revocationRoot: bigint;
  revokedCredentialId?: bigint;
}

/** A 256-bit secret from the platform CSPRNG. */
export function randomSecret(): bigint {
  const b = new Uint8Array(31); // 248 bits, safely inside the field
  crypto.getRandomValues(b);
  let v = 0n;
  for (const x of b) v = (v << 8n) | BigInt(x);
  return v;
}

/**
 * The issuer's signing key.
 *
 * Byte 7 repeated, matching the seed script and the committed fixtures, so a
 * credential minted here is signed by the same issuer whose key is in the
 * published registry root. In a real deployment the issuer signs on its own
 * infrastructure and the bidder receives only the signature.
 */
export function issuerRegistry(privByte = 7, secondPrivByte = 3) {
  const issuerPriv = new Uint8Array(32).fill(privByte);
  const issuerKey = derivePublicKey(issuerPriv);
  const keys = [issuerKey, derivePublicKey(new Uint8Array(32).fill(secondPrivByte))];
  return {
    issuerPriv,
    issuerKey,
    keys,
    root: issuerRegistryRoot(keys),
    path: issuerRegistryPath(keys, 0),
  };
}

export interface ProofResult {
  witness: EligibilityWitness;
  publicSignals: bigint[];
  pA: bigint[];
  pB: bigint[][];
  pC: bigint[];
  provingMs: number;
}

/**
 * Build the witness and prove it.
 *
 * The public-signal order is asserted against the frozen specification. If a
 * circuit's public list were ever reordered, this throws here rather than
 * letting the contract compare a deadline against a threshold.
 */
export async function proveEligibility(params: {
  credential: CredentialInput;
  tender: TenderInput;
  bidAmount: bigint;
  bidNonce: bigint;
  /**
   * A credential an accredited body actually signed.
   *
   * When present these are the figures proved, and the firm's own entries are
   * ignored: the whole point is that the bidder cannot choose them. When
   * absent the browser signs its own — which proves the mechanism but attests
   * nothing, and is why the interface labels the two states differently.
   */
  attestation?: Attestation;
  onStage?: (stage: string) => void;
}): Promise<ProofResult> {
  const { credential, tender, bidAmount, bidNonce, attestation, onStage } = params;
  await initCrypto();
  onStage?.("Assembling the private witness");

  const registry = issuerRegistry();

  // Either an accredited body signed these figures, or this browser does it
  // for itself. Only the first case attests anything.
  let fields;
  let signature;
  let issuerPublicKey = registry.issuerKey;
  if (attestation) {
    // The issuer path below is the registry's leaf 0. A credential signed by
    // any other key cannot be proved against that path, and saying so here is
    // clearer than a witness that fails clause 2 inside the circuit.
    if (
      attestation.issuerPublicKey.x !== registry.issuerKey.x ||
      attestation.issuerPublicKey.y !== registry.issuerKey.y
    ) {
      throw new Error(
        "this credential was signed by a key that is not in the issuer registry " +
          "published for this tender's epoch",
      );
    }
    if (attestation.fields.subjectCommitment !== subjectCommitment(credential.subjectSecret)) {
      throw new Error(
        "this credential was issued to a different subject — the secret in this " +
          "browser does not match the commitment the body signed",
      );
    }
    fields = attestation.fields;
    signature = attestation.signature;
    issuerPublicKey = attestation.issuerPublicKey;
  } else {
    fields = {
      schemaVersion: SCHEMA_VERSION,
      subjectCommitment: subjectCommitment(credential.subjectSecret),
      annualTurnover: credential.annualTurnover,
      relevantExperience: credential.relevantExperience,
      certificationCode: credential.certificationCode ?? tender.requiredCertificationCode,
      certValidUntil: credential.validUntil,
      credentialValidUntil: credential.validUntil,
      credentialId: credential.credentialId,
      issuerEpoch: tender.credentialEpoch,
      issuedAt: credential.issuedAt,
    };
    signature = signCredential(registry.issuerPriv, fields).signature;
  }

  // Non-revocation path in whichever tree the tender points at.
  const revocation =
    tender.revokedCredentialId !== undefined
      ? (() => {
          const tree = revocationTreeWith(tender.revokedCredentialId!);
          return { root: tree.root, siblings: tree.siblingsFor(credential.credentialId) };
        })()
      : (() => {
          const tree = emptyRevocationTree();
          return { root: tree.root, siblings: tree.siblings };
        })();

  const witness = buildEligibilityWitness({
    credential: { fields, signature, issuerPublicKey },
    subjectSecret: credential.subjectSecret,
    bidAmount,
    bidNonce,
    tender: {
      tenderIdField: tenderIdField(tender.tenderIdString),
      rulesHash: tender.rulesHash,
      turnoverThreshold: tender.turnoverThreshold,
      experienceMonthsThreshold: tender.experienceMonthsThreshold,
      requiredCertificationCode: tender.requiredCertificationCode,
      deadline: tender.deadline,
      issuerRegistryRoot: registry.root,
      revocationRoot: revocation.root,
      credentialEpoch: tender.credentialEpoch,
    },
    merkle: {
      issuerPathElements: [...registry.path.pathElements],
      issuerPathIndices: [...registry.path.pathIndices],
      revocationPathElements: [...revocation.siblings],
    },
  });

  onStage?.("Loading the circuit and proving key");
  const { wasm, zkey } = await loadCircuit();

  onStage?.("Generating the zero-knowledge proof");
  const sj = await loadSnarkjs();
  const started = performance.now();
  const s = (v: bigint) => v.toString();
  const input = {
    subjectSecret: s(witness.subjectSecret),
    annualTurnover: s(witness.annualTurnover),
    relevantExperience: s(witness.relevantExperience),
    certificationCode: s(witness.certificationCode),
    certValidUntil: s(witness.certValidUntil),
    credentialValidUntil: s(witness.credentialValidUntil),
    credentialId: s(witness.credentialId),
    issuedAt: s(witness.issuedAt),
    issuerPubKeyX: s(witness.issuerPubKeyX),
    issuerPubKeyY: s(witness.issuerPubKeyY),
    issuerSigR8x: s(witness.issuerSigR8x),
    issuerSigR8y: s(witness.issuerSigR8y),
    issuerSigS: s(witness.issuerSigS),
    issuerPathElements: witness.issuerPathElements.map(String),
    issuerPathIndices: witness.issuerPathIndices.map(String),
    revocationPathElements: witness.revocationPathElements.map(String),
    bidAmount: s(witness.bidAmount),
    bidNonce: s(witness.bidNonce),
    tenderIdField: s(witness.tenderIdField),
    rulesHashHi: s(witness.rulesHashHi),
    rulesHashLo: s(witness.rulesHashLo),
    turnoverThreshold: s(witness.turnoverThreshold),
    experienceMonthsThreshold: s(witness.experienceMonthsThreshold),
    requiredCertificationCode: s(witness.requiredCertificationCode),
    deadline: s(witness.deadline),
    issuerRegistryRoot: s(witness.issuerRegistryRoot),
    revocationRoot: s(witness.revocationRoot),
    credentialEpoch: s(witness.credentialEpoch),
    nullifier: s(witness.nullifier),
    bidCommitment: s(witness.bidCommitment),
  };

  const { proof, publicSignals } = await sj.groth16.fullProve(input, wasm, zkey);
  const provingMs = performance.now() - started;

  const expected = [
    witness.tenderIdField, witness.rulesHashHi, witness.rulesHashLo,
    witness.turnoverThreshold, witness.experienceMonthsThreshold,
    witness.requiredCertificationCode, witness.deadline,
    witness.issuerRegistryRoot, witness.revocationRoot, witness.credentialEpoch,
    witness.nullifier, witness.bidCommitment,
  ].map(String);
  if (JSON.stringify(publicSignals) !== JSON.stringify(expected)) {
    throw new Error(
      "public signal order mismatch — the circuit's public list and the frozen " +
        "specification have diverged",
    );
  }

  onStage?.("Verifying the proof locally before submission");
  const vkey = await vkeyOf("eligibility");
  if (!(await sj.groth16.verify(vkey, publicSignals, proof))) {
    throw new Error("the prover produced a proof that does not verify");
  }

  return {
    witness,
    publicSignals: publicSignals.map((x: string) => BigInt(x)),
    // Solidity calldata order: snarkjs's pi_b has each coordinate pair
    // swapped relative to the generated verifier's expectation.
    pA: [BigInt(proof.pi_a[0]), BigInt(proof.pi_a[1])],
    pB: [
      [BigInt(proof.pi_b[0][1]), BigInt(proof.pi_b[0][0])],
      [BigInt(proof.pi_b[1][1]), BigInt(proof.pi_b[1][0])],
    ],
    pC: [BigInt(proof.pi_c[0]), BigInt(proof.pi_c[1])],
    provingMs,
  };
}

/**
 * Re-prove eligibility against the revocation tree pinned when the tender
 * closed.
 *
 * The same statement, evaluated against a DIFFERENT tree — the one the
 * registry held at the close, not the one bids were checked against. Only the
 * bidder can produce it, because it needs the subject secret, which is exactly
 * why an authority cannot quietly confirm a bidder's standing on its behalf.
 */
export async function proveDeadlineStatus(params: {
  credential: CredentialInput;
  tender: TenderInput;
  bidAmount: bigint;
  bidNonce: bigint;
  /** Carried through, so the close-time re-proof asserts the same credential. */
  attestation?: Attestation;
  /** The root the contract pinned. The tree must reproduce it. */
  pinnedRoot: bigint;
  onStage?: (stage: string) => void;
}): Promise<ProofResult> {
  await initCrypto();

  // Which tree is it? An empty one if nothing was revoked, otherwise the one
  // carrying whatever was. Both are tried and the match is used; if neither
  // reproduces the pinned root, say so rather than submit a proof that will be
  // rejected for a reason nobody can read.
  const empty = emptyRevocationTree();
  let revokedCredentialId: bigint | undefined;
  if (empty.root !== params.pinnedRoot) {
    // The seed script revokes credential 9999 so the close-time check is not
    // vacuous. Anything else would need the registry to publish its contents.
    const withSeed = revocationTreeWith(9999n);
    if (withSeed.root !== params.pinnedRoot) {
      throw new Error(
        "the revocation tree pinned at the close is not one this browser can " +
          "reconstruct, so a non-revocation path cannot be built for it",
      );
    }
    revokedCredentialId = 9999n;
  }

  return proveEligibility({
    ...params,
    tender: { ...params.tender, revocationRoot: params.pinnedRoot, revokedCredentialId },
  });
}

/** Verify a proof already on the chain, in this tab, against the published key. */
export async function verifyEligibilityProof(
  publicSignals: (bigint | string)[],
  proof: { pA: (bigint | string)[]; pB: (bigint | string)[][]; pC: (bigint | string)[] },
): Promise<boolean> {
  const sj = await loadSnarkjs();
  const vkey = await vkeyOf("eligibility");
  return sj.groth16.verify(
    vkey,
    publicSignals.map(String),
    {
      pi_a: [String(proof.pA[0]), String(proof.pA[1]), "1"],
      pi_b: [
        [String(proof.pB[0][1]), String(proof.pB[0][0])],
        [String(proof.pB[1][1]), String(proof.pB[1][0])],
        ["1", "0"],
      ],
      pi_c: [String(proof.pC[0]), String(proof.pC[1]), "1"],
      protocol: "groth16",
      curve: "bn128",
    },
  );
}

export {
  computeBidCommitment,
  computeNullifier,
  credDigest,
  sealBid,
  subjectCommitment,
  tenderIdField,
  toLimbs,
};

// =========================================================================
// Award and winner identity, also in the browser.
//
// These two were terminal-only for a long time, which meant the last two
// stages of a procurement could not be carried out by the person who is
// actually accountable for them. Their proving keys are larger — 35 MB for the
// award, 8 MB for the identity — so they are fetched only when one of those
// buttons is pressed, and cached by the browser afterwards.
// =========================================================================

/** Solidity calldata order, with pi_b's coordinate pairs swapped. */
function calldata(proof: any) {
  return {
    pA: [BigInt(proof.pi_a[0]), BigInt(proof.pi_a[1])],
    pB: [
      [BigInt(proof.pi_b[0][1]), BigInt(proof.pi_b[0][0])],
      [BigInt(proof.pi_b[1][1]), BigInt(proof.pi_b[1][0])],
    ] as bigint[][],
    pC: [BigInt(proof.pi_c[0]), BigInt(proof.pi_c[1])],
  };
}

export interface AwardResult {
  witness: AwardWitness;
  publicSignals: bigint[];
  pA: bigint[];
  pB: bigint[][];
  pC: bigint[];
  provingMs: number;
}

/**
 * Prove the winner over the COMPLETE set of accepted bids.
 *
 * The circuit rebuilds the whole accumulator from all 32 slots, so a proof
 * that omitted a bid would produce a different root and fail against the one
 * the contract holds. `expectedBidSetRoot` catches that here, before a
 * transaction is sent, where the message can say what actually went wrong.
 */
export async function proveAward(params: {
  bids: OpenedBid[];
  tenderIdString: string;
  rulesHash: string;
  disclosurePolicy?: number;
  expectedBidSetRoot?: bigint;
  onStage?: (stage: string) => void;
  onProgress?: (loaded: number, total: number, what: string) => void;
}): Promise<AwardResult> {
  const { bids, tenderIdString, rulesHash, onStage, onProgress } = params;
  await initCrypto();
  onStage?.("Assembling the award witness over every accepted bid");

  const witness = buildAwardWitness({
    bids,
    tenderIdField: tenderIdField(tenderIdString),
    rulesHash,
    disclosurePolicy: params.disclosurePolicy ?? DISCLOSE_WINNING_PRICE,
  });
  if (params.expectedBidSetRoot !== undefined && witness.bidSetRoot !== params.expectedBidSetRoot) {
    throw new Error(
      `the witness accumulates ${witness.bidSetRoot} but the contract holds ` +
        `${params.expectedBidSetRoot}. The opened set is not the set that was accepted.`,
    );
  }

  onStage?.("Loading the award circuit — 38 MB, cached afterwards");
  const { wasm, zkey } = await loadCircuit(onProgress, "award");

  onStage?.("Generating the award proof");
  const sj = await loadSnarkjs();
  const started = performance.now();
  const { proof, publicSignals } = await sj.groth16.fullProve(
    awardCircuitInput(witness),
    wasm,
    zkey,
  );
  const provingMs = performance.now() - started;

  const expected = awardPublicSignals(witness).map(String);
  if (JSON.stringify(publicSignals) !== JSON.stringify(expected)) {
    throw new Error("award public signal order mismatch against the frozen specification");
  }

  onStage?.("Verifying the award proof locally");
  if (!(await sj.groth16.verify(await vkeyOf("award"), publicSignals, proof))) {
    throw new Error("the prover produced an award proof that does not verify");
  }

  return {
    witness,
    publicSignals: publicSignals.map((x: string) => BigInt(x)),
    ...calldata(proof),
    provingMs,
  };
}

export interface IdentityResult {
  witness: WinnerIdentityWitness;
  publicSignals: bigint[];
  pA: bigint[];
  pB: bigint[][];
  pC: bigint[];
  provingMs: number;
}

/**
 * Prove that whoever publishes the identity record placed the winning bid.
 *
 * The order is what matters: this proof is required before any name appears,
 * so a record cannot be a claim attached to someone else's win. What it does
 * NOT do is verify the name — that stays the issuer's job, and the interface
 * says so wherever the name is shown.
 */
export async function proveWinnerIdentity(params: {
  credential: Parameters<typeof buildWinnerIdentityWitness>[0]["credential"];
  subjectSecret: bigint;
  bidAmount: bigint;
  bidNonce: bigint;
  tenderIdString: string;
  record: Parameters<typeof buildWinnerIdentityWitness>[0]["record"];
  onStage?: (stage: string) => void;
  onProgress?: (loaded: number, total: number, what: string) => void;
}): Promise<IdentityResult> {
  const { onStage, onProgress } = params;
  await initCrypto();
  onStage?.("Assembling the ownership witness");

  const registry = issuerRegistry();
  const witness = buildWinnerIdentityWitness({
    credential: params.credential,
    subjectSecret: params.subjectSecret,
    bidAmount: params.bidAmount,
    bidNonce: params.bidNonce,
    tenderIdField: tenderIdField(params.tenderIdString),
    issuerRegistryRoot: registry.root,
    issuerPathElements: [...registry.path.pathElements],
    issuerPathIndices: [...registry.path.pathIndices],
    record: params.record,
  });

  onStage?.("Loading the identity circuit — 12 MB, cached afterwards");
  const { wasm, zkey } = await loadCircuit(onProgress, "winner_identity");

  onStage?.("Generating the ownership proof");
  const sj = await loadSnarkjs();
  const started = performance.now();
  const { proof, publicSignals } = await sj.groth16.fullProve(
    winnerIdentityCircuitInput(witness),
    wasm,
    zkey,
  );
  const provingMs = performance.now() - started;

  const expected = winnerIdentityPublicSignals(witness).map(String);
  if (JSON.stringify(publicSignals) !== JSON.stringify(expected)) {
    throw new Error("identity public signal order mismatch against the frozen specification");
  }

  onStage?.("Verifying the ownership proof locally");
  if (!(await sj.groth16.verify(await vkeyOf("winner_identity"), publicSignals, proof))) {
    throw new Error("the prover produced an ownership proof that does not verify");
  }

  return {
    witness,
    publicSignals: publicSignals.map((x: string) => BigInt(x)),
    ...calldata(proof),
    provingMs,
  };
}

export { signCredential };
