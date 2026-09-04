/**
 * THE COMMITTED TEST VECTOR.
 *
 * These inputs are frozen. The cross-language equality test hashes exactly
 * this vector in TypeScript, Circom and Solidity and asserts all three agree
 * (development plan Section 11A.6).
 *
 * Do not change these values to make a test pass. If the expected digests
 * change, something in the frozen encoding changed and that is a breaking
 * protocol change.
 */
export const VECTOR = {
  // Bidder secrets
  subjectSecret: 4759208310398234759832475982374598234759823475982347n,
  bidNonce: 8823409128340981234098123409812340981234098123409812n,

  // Tender FP-00014, the whitepaper Figure 5 demo tender
  tenderId: "FP-00014",

  // The Figure 5 winning bid: BDT 74,00,000
  bidAmount: 7400000n,

  ciphertextHashField: 99887766554433221100998877665544332211009988776655n,
  submissionIndex: 0,

  // Credential fields (synthetic)
  annualTurnover: 500000000n, // BDT 50 crore
  relevantExperience: 72n, // months
  certificationCode: 9001n,
  certValidUntil: 1790000000n,
  credentialValidUntil: 1800000000n,
  credentialId: 7n,
  issuerEpoch: 1n,
  issuedAt: 1750000000n,
} as const;
