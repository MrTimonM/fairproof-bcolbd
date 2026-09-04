# Benchmarks

Every figure measured, not estimated. Gas comes from `estimateContractGas` in
the unit suites and from receipts on the live four-validator network; the two
agree to within a few hundred gas. Full tables in `docs/benchmarks.md`.

## Circuits

| Circuit | Non-linear constraints | Linear | Public signals | Proving |
|---|---|---|---|---|
| Eligibility | 19,233 | 13,396 | 12 | ~1.5 s native · **~1.6 s in browser** |
| Award (MAX_BIDS = 32) | 35,665 | — | 8 | ~2 s native · **~4.8 s in browser** |
| Winner identity | 11,391 | — | 5 | ~1 s |

Whitepaper Table 15 budgets 10⁴–10⁵ constraints for eligibility; 19,233 sits
inside it.

## Gas

| Operation | Gas |
|---|---|
| Raw Groth16 `verifyProof` (eligibility) | 291,225 |
| `EligibilityVerifier.verifyEligibility` | 344,581 |
| — on the live Besu chain | 348,483 |
| `verifyWithSignals` (replay path) | 359,311 |
| A sealed bid, end to end | ~1.6 M |
| A full 3-of-5 opening for one bid | ~9.1 M |

The 53,356-gas adapter overhead over raw verification buys the entire binding to
tender state. A full opening is 9% of this network's 100 M block gas limit, at a
**zero gas price** — which is also why a bidder's fresh address needs no
funding, removing the wallet-funding correlation channel.

Every gas test asserts a **floor**, not a ceiling: a suspiciously small number
means a check was skipped.

## Contracts

11 contracts, every one inside the EIP-170 limit of 24,576 bytes. Largest:
`TenderRegistry` at **15,064 bytes**, 61% of the limit.

## Network

| | |
|---|---|
| Validators | 4, Hyperledger Besu, QBFT, chain id 20260 |
| Byzantine tolerance | 1 of 4, proven in both directions |
| Block gas limit | 100,000,000 |
| Gas price | 0 |

## Storage and committee

| | |
|---|---|
| Ciphertext replicas | 3, quorum 2, each signing for the exact bytes |
| Committee | 3-of-5 threshold, DLEQ verified on-chain |

## Tests

| Suite | Count |
|---|---|
| `crypto` | 158 |
| `contracts` | 350 |
| `circuits` | 70 |
| **Unit total** | **578** |

Plus live-network suites: `test:network` (stops a validator, shows 3-of-4
continuing, recovers), `test:deploy`, `test:storage`, `test:e2e:lifecycle`,
`test:e2e:proof`, `test:e2e:bid`, `test:e2e:opening`, `test:dashboard`,
`test:ui`, `test:certify`, `test:verifier`.

## Independent verification

| | |
|---|---|
| Checks re-derived from a bundle | 16 |
| Corrupted bundles, each caught by the right check | 31 / 31 |
| Evidence bundle size | ~33 kB, byte-identical across exports |

## Resource footprint

Measured on a 2 vCPU / 3.7 GB server with `-Xmx448m` per validator:
**~335 MB RSS per validator**, 1.7 GB free with nginx and three stores running.
Each fresh browser visitor fetches **~68 MB** of proving keys, cached
thereafter.
