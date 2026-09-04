/**
 * A credential as an accredited certifying body issued it.
 *
 * This is the one file that separates "the firm typed its own figures" from
 * "an approved auditor attested them". The body signs a Poseidon digest over
 * the figures AND over a commitment to a secret the firm never discloses, so:
 *
 *   - the firm cannot alter a figure — the signature stops matching;
 *   - the body cannot bid as the firm — it never holds the secret;
 *   - a stolen credential is inert — the proof needs the secret too.
 *
 * The credential travels as text, because the real handover is out of band:
 * an auditor emails it, hands over a file, or prints a QR code. Nothing here
 * assumes the two parties share a browser.
 */
import {
  credDigest,
  signCredential,
  subjectCommitment,
  verifyField,
  type EddsaSignature,
  type IssuerPublicKey,
} from "@fairproof/crypto";

/** Exactly the ten values the issuer's signature covers. */
export interface CredentialFieldSet {
  schemaVersion: bigint;
  subjectCommitment: bigint;
  annualTurnover: bigint;
  relevantExperience: bigint;
  certificationCode: bigint;
  certValidUntil: bigint;
  credentialValidUntil: bigint;
  credentialId: bigint;
  issuerEpoch: bigint;
  issuedAt: bigint;
}

/** The signed credential, plus the plain text the figures describe. */
export interface Attestation {
  fields: CredentialFieldSet;
  signature: EddsaSignature;
  issuerPublicKey: IssuerPublicKey;
  /** Descriptive only. Never enters the digest, so the firm may correct it. */
  subject: { firmName: string; registrationNumber: string };
  issuerLabel: string;
}

const FIELD_NAMES = [
  "schemaVersion",
  "subjectCommitment",
  "annualTurnover",
  "relevantExperience",
  "certificationCode",
  "certValidUntil",
  "credentialValidUntil",
  "credentialId",
  "issuerEpoch",
  "issuedAt",
] as const;

/** The commitment a firm hands its auditor. Reveals nothing about the secret. */
export function commitmentFor(secret: bigint): bigint {
  return subjectCommitment(secret);
}

/** Sign a set of figures as the issuing body. */
export function issueCredential(
  issuerPriv: Uint8Array,
  issuerPublicKey: IssuerPublicKey,
  issuerLabel: string,
  fields: CredentialFieldSet,
  subject: { firmName: string; registrationNumber: string },
): Attestation {
  const { signature } = signCredential(issuerPriv, fields);
  return { fields, signature, issuerPublicKey, subject, issuerLabel };
}

/**
 * Re-check a credential the way the circuit will.
 *
 * Worth doing on import: a firm that pastes a corrupted credential should be
 * told so here, not sixty seconds into a proof that cannot satisfy clause 1.
 */
export function checkAttestation(a: Attestation): boolean {
  try {
    return verifyField(a.issuerPublicKey, credDigest(a.fields), a.signature);
  } catch {
    return false;
  }
}

/** Does this credential belong to the holder of `secret`? */
export function boundTo(a: Attestation, secret: bigint): boolean {
  return a.fields.subjectCommitment === subjectCommitment(secret);
}

/** The digest the signature covers, for display. */
export function digestOf(a: Attestation): bigint {
  return credDigest(a.fields);
}

// ---------------------------------------------------------------- transport

/**
 * Serialise for handover. JSON cannot carry a bigint, so every field element
 * becomes a decimal string — the same convention the evidence bundle uses.
 */
export function encodeAttestation(a: Attestation): string {
  const fields: Record<string, string> = {};
  for (const k of FIELD_NAMES) fields[k] = a.fields[k].toString();
  return JSON.stringify(
    {
      format: "fairproof.credential.v1",
      issuerLabel: a.issuerLabel,
      subject: a.subject,
      fields,
      signature: {
        R8x: a.signature.R8x.toString(),
        R8y: a.signature.R8y.toString(),
        S: a.signature.S.toString(),
      },
      issuerPublicKey: { x: a.issuerPublicKey.x.toString(), y: a.issuerPublicKey.y.toString() },
    },
    null,
    2,
  );
}

/** Parse a pasted credential. Throws with a readable reason, never silently. */
export function decodeAttestation(text: string): Attestation {
  let raw: any;
  try {
    raw = JSON.parse(text.trim());
  } catch {
    throw new Error("that is not a credential — the text is not valid JSON");
  }
  if (raw?.format !== "fairproof.credential.v1") {
    throw new Error("unrecognised credential format");
  }
  const fields = {} as CredentialFieldSet;
  for (const k of FIELD_NAMES) {
    const v = raw.fields?.[k];
    if (v === undefined) throw new Error(`the credential is missing ${k}`);
    fields[k] = BigInt(v);
  }
  return {
    fields,
    signature: {
      R8x: BigInt(raw.signature.R8x),
      R8y: BigInt(raw.signature.R8y),
      S: BigInt(raw.signature.S),
    },
    issuerPublicKey: { x: BigInt(raw.issuerPublicKey.x), y: BigInt(raw.issuerPublicKey.y) },
    subject: {
      firmName: String(raw.subject?.firmName ?? ""),
      registrationNumber: String(raw.subject?.registrationNumber ?? ""),
    },
    issuerLabel: String(raw.issuerLabel ?? "unnamed body"),
  };
}
