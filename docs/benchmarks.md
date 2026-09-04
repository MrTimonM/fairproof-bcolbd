# Measured results

Every figure here was measured, not estimated. Gas comes from
`estimateContractGas` in the unit suites and from transaction receipts on the
live four-validator Besu network; the two agree to within a few hundred gas.

Reproduce with `npm test`, `npm run seed` and `npm run test:e2e:opening`.

---

## Circuits

| Circuit | Non-linear constraints | Linear | Public signals | Proving time |
|---|---|---|---|---|
| Eligibility | 19,233 | 13,396 | 12 | ~1.5 s |
| Award (MAX_BIDS = 32) | 35,665 | — | 8 | ~2 s |
| Winner identity | 11,391 | — | 5 | ~1 s |

Whitepaper Table 15 budgets 10⁴–10⁵ constraints for the eligibility circuit;
19,233 sits inside it. Proving times are on ordinary desktop hardware with
snarkjs, single-threaded WASM.

`MAX_BIDS = 32` is not negotiable — whitepaper Section 7 states it and
Section 19.3 promises timings "at 5 / 10 / 25 accepted bids in the same padded
circuit". The award circuit is tested at 1, 5, 10, 25 and 32 bids in that one
padded circuit.

## Trusted setup

| | |
|---|---|
| Phase 1 | published Hermez `powersOfTau28_hez_final_17.ptau`, power 17 |
| Phase 1 sha256 | `6b662a324867139fb1a20a324d90b6ff61856dfb23f59326909f14b0e2483ae0` |
| Phase 2 contributions | 3 per circuit |
| Finalising beacon | drand League of Entropy, round recorded per transcript |
| `ceremony:verify` | **28/28 checks pass, per circuit** |

**Independent contributors: zero. `singleMachine: true`.** Every phase-2
contribution was produced on one machine, so one machine saw all of the
contributors' randomness. See `cryptography.md` §2 for what that costs.

---

## Gas

### Proof verification

| Operation | Gas |
|---|---|
| Raw Groth16 `verifyProof` (eligibility) | 291,225 |
| `EligibilityVerifier.verifyEligibility` | 344,581 |
| — on the live Besu chain | 348,483 |
| `EligibilityVerifier.verifyWithSignals` (replay path) | 359,311 |

The 53,356-gas adapter overhead buys the entire binding to tender state —
reading the tender, both registry roots, and the limb reconstruction. That is
the difference between a proof that verifies and a proof that means something.

### The protocol path

| Operation | Gas |
|---|---|
| `SealedBid.submitBid` (3 receipts) | 1,604,086 |
| `SealedBid.submitBid` (2 receipts) | 1,592,880 |
| `OpeningManager.revealCiphertext` (398-byte body) | 750,255 |
| `OpeningManager.submitDecryptionShare` (one verified DLEQ) | 2,785,733 |
| Full 3-of-5 opening for one bid | ~9,100,000 |
| `AwardManager.recordAward` | 449,200 |
| `WinnerIdentity.submitIdentityProof` | 622,759 |
| `TenderRegistry.setCommitteeKey` (Feldman verified on-chain) | 1,614,268 |
| `BabyJubjub.isInPrimeSubgroup` (251-bit scalar mult.) | 616,702 |

### Poseidon on-chain

| Operation | Gas |
|---|---|
| `hash2` (PoseidonT3, arity 2) | 34,096 |
| `bidLeaf` (PoseidonT6, arity 5) | 254,514 |
| Merkle append, first leaf | 255,873 |
| Merkle append, subsequent | 233,682 |

### Deployment

| Contract | Deploy gas | Deployed size | EIP-170 headroom |
|---|---|---|---|
| PoseidonT3 | 3,694,887 | — | — |
| PoseidonT6 | 4,506,682 | — | — |
| Governance | 1,309,445 | — | — |
| IssuerRegistry | 1,309,182 | — | — |
| TenderRegistry | 3,331,978 | 15,064 | 9,512 |
| EligibilityVerifierGroth16 | 572,040 | 2,402 | 22,174 |
| EligibilityVerifier | 1,700,880 | 7,622 | 16,954 |
| SealedBid | 2,065,409 | 9,304 | 15,272 |
| OpeningManager | 1,691,534 | 7,578 | 16,998 |
| DeadlineStatus | 709,407 | — | — |
| AwardVerifierGroth16 | 489,753 | 2,021 | 22,555 |
| AwardManager | 1,501,578 | 6,103 | 18,473 |
| WinnerIdentityVerifierGroth16 | 429,522 | — | — |
| WinnerIdentity | 1,495,648 | 6,301 | 18,275 |
| BondEscrow | 1,020,823 | 4,469 | 20,107 |
| CheckpointAnchor | 960,046 | 4,191 | 20,385 |

Every contract is comfortably inside the 24,576-byte EIP-170 limit. Two
settings are load-bearing and must not be changed without re-checking sizes:
`optimizer.runs = 1` and **`viaIR` off**. With `viaIR: true` the linked
PoseidonT6 compiled to 121,884 bytes — five times the limit
(`stage0-evidence.md`).

### An honest note on the opening cost

A full 3-of-5 opening for one bid is ~9.1 M gas, which is 9% of this network's
100 M block gas limit at a zero gas price. DLEQ verification is four 251-bit
scalar multiplications on BabyJubjub per share, and **memory allocation rather
than field arithmetic dominates** the figure: `add` and `mul` return
`Proj memory` structs. Returning coordinate tuples instead is the documented
optimisation if a public-chain deployment ever needs it. On a permissioned
chain with free gas, clarity in a verification routine is worth more than the
saving.

Every gas test asserts a **floor**, not a ceiling. A suspiciously small number
would mean a check was skipped, not that the code got fast.

---

## Network

| | |
|---|---|
| Consensus | Hyperledger Besu 25.7.0, QBFT |
| Validators | 4, one per institution |
| Byzantine tolerance | ⌊(n−1)/3⌋ = 1 |
| Block period | 2 s |
| Chain ID | 20260 |
| Block gas limit | 100,000,000 |
| Gas price | 0 |

Fault tolerance is demonstrated in **both** directions: stopping one validator
leaves consensus running, and stopping a second **halts** it (verified head
48 → 48), after which restoring quorum recovers. A test that only shows the
tolerated case proves nothing about the bound.

Because gas is free, a bid can be submitted from a **fresh zero-balance
address** — verified in the live run. That removes the wallet-funding
correlation channel whitepaper Table 4 names as a residual metadata risk.

---

## Tests

| Suite | Count |
|---|---|
| `@fairproof/crypto` | 158 |
| Contracts | 350 |
| Circuits | 70 |
| **Total unit** | **578** |

Plus live checks against the running network and services:

| Suite | Checks |
|---|---|
| Network fault tolerance | both directions |
| Deploy smoke | — |
| Tender lifecycle e2e | 30 |
| Eligibility proof on-chain e2e | 26 |
| Sealed bid e2e | 40 |
| Opening ceremony e2e | 44 |
| Storage quorum (real processes) | 25 |
| Dashboard read paths | 30 |
| Evidence bundle verification | 16 pass, 1 skip |
| Verifier against corrupted bundles | **31 corruptions, each caught by the right check** |

The corruption suite is the one worth running first. It confirms the pristine
bundle is **accepted** before testing rejections — without that, every
rejection could be a verifier that rejects everything.
