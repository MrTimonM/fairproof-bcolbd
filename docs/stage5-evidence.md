# Stage 5 evidence: the committee-key ceremony, verified on-chain

Development plan Section 25.1 step 9 and Section 12.2. Whitepaper Section 6
(3-of-5 threshold opening), Section 19.1 (DKG is production design).

This is the **opening** threshold, 3-of-5. It is not the 2-of-3 storage
quorum. The two are separate mechanisms with separate constants and must never
be described with one number.

---

## 1. What was built

| | |
|---|---|
| `packages/crypto/src/babyjub.ts` | curve arithmetic via circomlibjs |
| `packages/crypto/src/vss.ts` | Feldman VSS: deal, verify, Lagrange, exponent-interpolation |
| `packages/contracts/contracts/lib/BabyJubjub.sol` | the same curve, on-chain |
| `scripts/committee-ceremony.mjs` | the dealer ceremony, plus a member's own verification |
| `TenderRegistry.setCommitteeKey` | **verifies** the dealing rather than recording it |

**Test totals after this stage: 364** - 124 crypto, 197 contracts, 43
circuits - plus 30 lifecycle and 26 proof checks on the live network.

---

## 2. The dealing is enforced, not just published

Feldman VSS makes a dealing publicly checkable. The usual implementation stops
there and leaves the checking to members. `setCommitteeKey` performs it
on-chain:

| Check | What it stops |
|---|---|
| `Y` is on the curve | a "public key" that is not a point at all |
| `Y` is in the prime-order subgroup | encrypting to a point with a small-order component, which leaks plaintext information |
| `Y == C_0` | a key the shares cannot open - every bid in the tender permanently unopenable |
| each `C_j` is a curve point | a malformed commitment set |
| `Y_i == Σ_j i^j · C_j` for all five | a dishonest dealer handing out inconsistent shares, or one member's share placed at another's index |

The effect is that the trusted-dealer residual narrows to exactly one thing:
the dealer briefly knew `x`. Everything else a dishonest dealer might attempt
is now rejected by the chain.

Member indices are **1-based**. Index 0 evaluates the polynomial at zero,
which is the secret itself.

### Findings

**1. The old tests passed round numbers as curve points.** `PX =
1234567890123456789012345678901234567890`, `PY = 9876...`, member shares
`PX + i`, commitments `PX + 100i`. Every assertion in the committee-key
section passed, the e2e lifecycle passed, and nothing in the suite would have
noticed that the tender's public key was not on BabyJubjub - let alone that
the shares could not open it. Tests now use a real dealt key from
`scripts/gen-babyjubjub-vectors.mjs`, and the live e2e deals a fresh one on
every run.

This is the most instructive finding of the stage: the contract had no
arithmetic to be wrong, so the tests had nothing to catch. Adding the check
and adding real vectors were the same piece of work.

**2. `mulPoint` reduced its scalar modulo `SUB_ORDER`, silently breaking the
subgroup check.** `isInPrimeSubgroup(P)` is exactly the test
`SUB_ORDER · P == identity`. With the reduction in place the scalar became
zero, the multiplication returned the identity, and **every curve point
passed** - including order-2 points, which are precisely what the check
exists to reject. The reduction was added as a convenience so equal values
would not look different in a test.

Caught by the test that asserts subgroup membership is *strictly stronger*
than curve membership, using `(0, -1)`: on the curve, order 2. Without that
test the defect would have shipped, and the symptom - bidders encrypting to a
leaky key - would never have appeared as a failure.

`mulPoint` now uses the scalar as given and refuses negative scalars rather
than guessing what they mean.

**3. Distinct errors for off-curve and off-subgroup.** A point that is not on
the curve reported `CommitteeKeyNotInSubgroup`, which sends the reader looking
in the wrong place. There are now two checks with two errors, in that order -
which also avoids paying for a 251-bit scalar multiplication to learn
something cheap arithmetic already decided.

**4. `verifyDealing` threw instead of reporting.** Given duplicate share
indices it attempted Lagrange interpolation, which is undefined over duplicate
indices, so the function crashed rather than returning the list of problems it
exists to return. Reconstruction is now skipped when the index set is already
malformed.

**5. The member-verification output said REJECTED while showing two matching
numbers.** It printed `Y_i` from the commitments and `Y_i` as published, but
the tampered value was the *secret* share - a comparison it did not display.
It now prints all three values and names which comparison failed, and
distinguishes a dishonest dealing (caught on-chain too) from a wrong secret
share (invisible on-chain, surfacing only as a failed opening).

---

## 3. Solidity and circomlibjs agree

`BabyJubjub.test.cjs`, 12 tests, checks the Solidity library against vectors
generated from circomlibjs - the same library the circuits use. Applying plan
Section 13.1's rule to curve arithmetic: "If this test does not exist, assume
the three disagree."

The addition law is circomlib's own, rewritten projectively so no modular
inversion is needed per step. That is a change of representation, not of
algorithm: substituting `x = X/Z`, `y = Y/Z` recovers the affine law exactly.
The law is unified, so doubling needs no separate branch - a verifier with a
doubling branch has an untested path that fires only on equal inputs, which is
the input an attacker chooses. The doubling case is a named test.

Comparing a projective result against an affine point is `X == x·Z && Y == y·Z`,
so production code never converts to affine and never pays for an inversion.
The test harness converts, via the modexp precompile, only so the values can be
compared against circomlibjs's affine output.

---

## 4. Measured gas

| Operation | Gas |
|---|---|
| `isInPrimeSubgroup` (251-bit scalar multiplication) | 616,702 |
| `setCommitteeKey` with the full dealing verification | 1,614,268 |
| `TenderRegistry` deployment | 3,331,978 |
| `TenderRegistry` deployed size | 15,064 bytes (EIP-170 limit 24,576) |

1.6 M gas is 1.6% of this network's 100 M block gas limit, paid once per
tender, with a zero gas price. It is not optimised and does not need to be
here. The available optimisation, if a public-chain deployment ever needed it,
is to return coordinate tuples from `add` and `mul` instead of `Proj memory`
structs; memory allocation, not field arithmetic, is what dominates the
number. Clarity in a verification routine is worth more than that saving on a
permissioned chain.

The tests assert **floors**, not ceilings - a suspiciously small number would
mean a check was skipped, not that the code got fast.

---

## 5. A real proof on the live network

`npm run test:e2e:proof` - **26 checks, all passing** against the
four-validator Besu network.

| Stage | What it establishes |
|---|---|
| 1 | verifier v1 is registered, its `vkeyHash` is the published ceremony's, and registration consumed an executed governance proposal |
| 3 | a tender whose contract-recomputed `rulesHash` is the one proved |
| 4 | all twelve signals derived from chain state equal the ones proved |
| 5 | a real Groth16 proof **verifies on the live chain**, 348,471 gas |
| 6 | the cross-tender proof and the weak-threshold proof are rejected, and the raw verifier accepts both |
| 7 | swapped limbs and a tampered threshold are rejected by name |
| 8 | **all four validators** accept the valid proof and reject the weak one |

The unit tests already verify these proofs against Hardhat's in-process EVM.
Running them against Besu is not redundant: it exercises the real pairing
precompiles under a real client, the real block gas limit, the
governance-registered verifier rather than a test-registered one, and
cross-node agreement. A proof that verifies on one node and not on another is
a consensus problem, and nothing but stage 8 would find it.

### Two fixture constraints worth recording

**The tender id cannot carry a per-run nonce.** `tenderIdField` is public
signal 0 and is baked into the proof. The lifecycle test suffixes its ids with
`Date.now()` for idempotency; this test cannot, so it is idempotent by
*reusing* an existing matching tender instead. Confirmed by running it twice.

**The issuer epoch is 7, not 1.** The fixture's registry and revocation roots
are published at epoch 7 so the lifecycle test, which uses epoch 1, cannot
overwrite them. Both write to `issuerRegistryRoot[epoch]`; sharing an epoch
would make a previously valid proof stop verifying for reasons that have
nothing to do with the proof.

---

## 6. Deployment now registers the verifier through governance

`npm run deploy` deploys `EligibilityVerifierGroth16` and
`EligibilityVerifier`, wires `TenderRegistry.verifierVersionRegistry`, and then
runs the **real** 3-of-4 proposal, waits out the 60-second timelock, executes,
and registers version 1 with a sample proof. There is no privileged shortcut,
so the timelock is exercised on every deployment rather than only in tests.

The recorded hashes are the real ones:

```
vkeyHash   0xda484879849c0753f5a26ecd3c0b425d4c19e348764faa2464838d4e77c0ca1a
sourceHash 0xd8d43777cf162d530b5a916cbb89aac135e0e09156df035ad0769947be1be2c4
```

`vkeyHash` is from the published ceremony transcript; `sourceHash` is of the
committed generated verifier, whose byte-identity with a fresh export
`ceremony:verify` checks. Together they let an outside reviewer tie the
deployed bytecode to that ceremony.

Registration cost 596,941 gas, which includes a real pairing check on the
sample proof.

---

## 7. Reproducing

```
npm run crypto:build
npm run committee:deal -- FP-DEMO --members=a,b,c,d,e
npm run committee:verify -- FP-DEMO 3
node scripts/gen-babyjubjub-vectors.mjs      # regenerate the Solidity vectors
npm test                                     # 364 tests
npm run deploy
npm run test:e2e:lifecycle                   # 30 checks
npm run test:e2e:proof                       # 26 checks
```
