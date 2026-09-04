import { beforeAll, describe, expect, it } from "vitest";
import {
  SCHEMA_VERSION,
  credDigest,
  derivePublicKey,
  initEddsa,
  initPoseidon,
  signCredential,
  signField,
  subjectCommitment,
  verifyField,
} from "../src/index.js";

beforeAll(async () => {
  await initPoseidon();
  await initEddsa();
});

const PRIV = new Uint8Array(32).fill(7);
const OTHER_PRIV = new Uint8Array(32).fill(8);

function credential(overrides: Record<string, bigint> = {}) {
  return {
    schemaVersion: SCHEMA_VERSION,
    subjectCommitment: subjectCommitment(123456789n),
    annualTurnover: 500000000n,
    relevantExperience: 72n,
    certificationCode: 9001n,
    certValidUntil: 1790000000n,
    credentialValidUntil: 1800000000n,
    credentialId: 7n,
    issuerEpoch: 1n,
    issuedAt: 1750000000n,
    ...overrides,
  };
}

describe("EdDSA-BabyJubjub (whitepaper Section 5 clause 1)", () => {
  it("derives a deterministic public key on the curve", () => {
    const a = derivePublicKey(PRIV);
    const b = derivePublicKey(PRIV);
    expect(a.x).toBe(b.x);
    expect(a.y).toBe(b.y);
    expect(a.x).not.toBe(0n);
  });

  it("different private keys give different public keys", () => {
    expect(derivePublicKey(PRIV).x).not.toBe(derivePublicKey(OTHER_PRIV).x);
  });

  it("rejects a private key of the wrong length", () => {
    expect(() => derivePublicKey(new Uint8Array(16))).toThrow(/32 bytes/);
  });

  it("signs and verifies a field element", () => {
    const pub = derivePublicKey(PRIV);
    const msg = 42n;
    const sig = signField(PRIV, msg);
    expect(verifyField(pub, msg, sig)).toBe(true);
  });

  it("fails verification against a different message", () => {
    const pub = derivePublicKey(PRIV);
    const sig = signField(PRIV, 42n);
    expect(verifyField(pub, 43n, sig)).toBe(false);
  });

  it("fails verification against a different public key", () => {
    // This is what prevents self-attestation: a firm signing its own
    // credential produces a signature that does not verify under the
    // registered issuer's key.
    const sig = signField(PRIV, 42n);
    expect(verifyField(derivePublicKey(OTHER_PRIV), 42n, sig)).toBe(false);
  });

  it("fails verification if the signature is tampered with", () => {
    const pub = derivePublicKey(PRIV);
    const sig = signField(PRIV, 42n);
    expect(verifyField(pub, 42n, { ...sig, S: sig.S + 1n })).toBe(false);
  });
});

describe("credential signing (spec Section 8)", () => {
  it("signs credDigest and verifies", () => {
    const pub = derivePublicKey(PRIV);
    const cred = credential();
    const { digest, signature } = signCredential(PRIV, cred);
    expect(digest).toBe(credDigest(cred));
    expect(verifyField(pub, digest, signature)).toBe(true);
  });

  it("a signature over one credential does not verify for a modified one", () => {
    // Whitepaper Table 4 relies on this: an altered credential cannot reuse
    // the issuer's signature.
    const pub = derivePublicKey(PRIV);
    const { signature } = signCredential(PRIV, credential());
    const tampered = credDigest(credential({ annualTurnover: 999999999n }));
    expect(verifyField(pub, tampered, signature)).toBe(false);
  });

  it("every signed field is bound", () => {
    const pub = derivePublicKey(PRIV);
    const base = credential();
    const { signature } = signCredential(PRIV, base);
    const bound: (keyof ReturnType<typeof credential>)[] = [
      "subjectCommitment",
      "annualTurnover",
      "relevantExperience",
      "certificationCode",
      "certValidUntil",
      "credentialValidUntil",
      "credentialId",
      "issuerEpoch",
      "issuedAt",
    ];
    for (const f of bound) {
      const digest = credDigest(credential({ [f]: base[f] + 1n }));
      expect(verifyField(pub, digest, signature), `field ${f} not bound`).toBe(false);
    }
  });
});
