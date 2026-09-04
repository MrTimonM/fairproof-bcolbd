# Stage 4 evidence: trusted setup and the eligibility verifier adapter

Development plan Section 25.1 step 8. Whitepaper Table 11 (trusted setup),
Section 14 (timelocked verifier upgrades never alter a running tender),
Section 19.5 (each tender pins a circuit/verifier version).

Everything below was measured, not estimated. Reproduce with the commands in
Section 6.

---

## 1. The ceremony

| | |
|---|---|
| Phase 1 | `powersOfTau28_hez_final_17.ptau`, power 17 (capacity 131,072) |
| Phase 1 sha256 | `6b662a324867139fb1a20a324d90b6ff61856dfb23f59326909f14b0e2483ae0` |
| Phase 1 source | `https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_17.ptau` |
| Phase 2 contributions | 3 |
| Finalizing beacon | drand default chain, round **6430438** |
| Final zkey sha256 | `c83cd81485b656597b56a35d1eacd33e9aa21b568a0bf6efb0b6d471426dd97c` (see transcript) |
| Verification key sha256 | `da484879849c0753f5a26ecd3c0b425d4c19e348764faa2464838d4e77c0ca1a` |
| `nPublic` | **12** - matches `field-encoding.md` Section 16 exactly |

Transcript: `packages/circuits/ceremony/eligibility.transcript.json`.
Declared participants: `packages/circuits/ceremony/contributors.json`.

**`npm run ceremony:verify` - 28/28 checks passed.**

The transcript records `singleMachine: true` and `independent: false` for all
three contributors. `docs/cryptography.md` Section 2 states what that costs
and why it is recorded rather than hidden. A weak ceremony honestly labelled
is defensible; a weak ceremony described as strong is not.

### Findings

**1. Power 17 rather than 15.** The eligibility circuit needs 19,233
non-linear constraints, so power 15 (32,768) would fit. Power 17 was chosen so
the award circuit at `MAX_BIDS = 32` and the winner-identity circuit can share
one phase 1 instead of forcing a second ceremony mid-build. Cost: a 151 MB
download, gitignored and re-fetched by checksum on demand.

**2. The beacon is external on purpose.** An earlier idea was to use a block
hash from our own Besu chain, which would have been neat in the demo and
worthless as a beacon, because the project controls the chain. drand rounds are
operated by an outside consortium and permanently retrievable by number, so
`ceremony:verify` re-fetches round 6430438 and compares the randomness and the
signature.

**3. snarkjs prints hashes across four indented lines.** The first version of
the transcript checker used a single-line regex, so all three
contribution-hash checks failed while the cryptographic `zkey verify` check
passed. That combination is confusing enough to send a reviewer looking for a
ceremony problem that does not exist. The parser now joins sixteen groups of
eight hex characters across newlines.

**4. snarkjs never exits.** Its WebAssembly curve worker pool is not torn
down, so the fixture generator hung after writing its output. `ceremony.mjs`
and the fixture script now call `globalThis.curve_bn128.terminate()`. Without
it a CI job waits for its timeout instead of passing.

---

## 2. `packages/crypto` now builds

The fixture generator runs under plain Node, which cannot resolve the
package's `.js`-suffixed TypeScript import specifiers. `@fairproof/crypto`
therefore has a real `tsc` build and publishes `dist/`; vitest configs alias
the package back to `src/index.ts` so tests still run against source rather
than a possibly stale build. `circomlibjs` ships no types, so
`packages/crypto/types/circomlibjs.d.ts` declares only the members actually
used - a blanket `declare module` would have swallowed member-name typos.

---

## 3. The proof fixtures

`npm run fixtures:eligibility` produces four **real** Groth16 proofs over the
ceremony zkey, each verified by snarkjs before being written:

| Fixture | What it is | Adapter verdict |
|---|---|---|
| `valid` | the Figure 5 winner, matching the tender exactly | accept |
| `secondBidder` | a different subject, so a different nullifier | accept |
| `otherTender` | valid proof for a **different** `tenderIdField` | **reject** |
| `weakThresholds` | valid proof against turnover 1, experience 0 | **reject** |

The generator asserts that snarkjs's own `publicSignals` order equals the order
frozen in `field-encoding.md` Section 16. That assertion is the reason a
reordered `component main { public [...] }` list would fail loudly instead of
the contract quietly comparing a deadline against a threshold.

**Why fixtures rather than proving inside the test.** Generating the proof in
the test would be circular: the same code would compute the signals for the
prover and for the expectation, so a wrong signal order would agree with
itself and every test would pass. The fixture derives the twelve signals in
TypeScript from a shared spec; the Solidity test derives them independently
from on-chain tender state. Agreement between them is evidence.

`rulesHash` forces the direction of that agreement. Nobody can choose a keccak
preimage, so the canonical rule document comes first: the spec holds the
structured object, the generator canonicalizes it with RFC 8785 JCS and
publishes the exact bytes, and the contract test submits those bytes to
`setRuleDocument`, where the contract hashes them itself. Measured
`rulesHash`: `0x3234b1bc8492f32fe2ffbb0329ae0f54f3158fa6ff93d93f37c6af537e0fe9d5`.

The bidding window uses far-future absolute timestamps (`biddingStart`
4000000000). A fixture anchored to "now" passes the day it is generated and
fails every day after, and the failure looks like a broken verifier rather
than a stale fixture.

---

## 4. The adapter

`EligibilityVerifier.sol`, 7,622 bytes deployed (EIP-170 limit 24,576). The
generated `EligibilityVerifierGroth16.sol` is 2,402 bytes.

**39 tests, all passing.** The ones that carry the argument:

| Test | What it proves |
|---|---|
| derives exactly the twelve signals the prover used | Solidity and TypeScript agree, element by element, with labels in the failure message |
| the raw Groth16 verifier **accepts** both rejected proofs | the rejections below come from the adapter's binding to tender state, not from a broken proof. Without this the two tests below could pass for the wrong reason and prove nothing |
| REJECTS a valid proof issued for a different tender | cross-tender replay |
| REJECTS a proof against thresholds the bidder chose | the attack the adapter exists to stop |
| rejects swapped hi and lo limbs | individually in range, jointly wrong - a per-limb range check alone would let it through |
| registering v2 mid-tender leaves the ACTIVE tender on v1 | whitepaper Section 14, tested structurally: state, digests and `activatedAt` all unchanged |
| an unregistered version cannot be used and does not fall back | plan 11B.3 forbids a silent fallback to "the newest verifier" |
| rejects arguments that differ from the approved payload | what the public reviewed during the timelock is what gets registered |
| rejects a verifier that does not accept the sample proof | a bricked or wrong-circuit verifier cannot be frozen into tenders |

### Findings

**5. Registration consumes a governance proposal, unlike the other modules.**
`Governance.execute` hands the payload back to its caller rather than making
the call itself, so the existing `onlyCouncil` gates enforce the 3-of-4
threshold but **not** the timelock. For verifier activation the timelock is
the point - it is the window in which the public can inspect a new verifier
before it can accept proofs - so `registerVerifier` requires an executed
`ActivateVerifierVersion` proposal whose payload hashes to exactly the
arguments supplied, and marks it consumed so one approval cannot authorise a
second registration. `encodeActivationPayload` is a view function so the
council can compute the payload on-chain rather than trusting a script; a test
compares it against an independent ABI encoder, because if the two disagreed
registration could never succeed.

**6. The generated verifier returns false; it does not revert.** It returns
false for a failed pairing and also for a public signal outside the field.
Ignoring the return value would accept every proof, and no test that submits
only valid proofs would notice. `IGroth16Verifier`'s documentation says so at
the point of use, and `requireEligibility` exists so call sites are not
obliged to remember.

**7. A zero revocation root means "never published", not "nothing revoked".**
The empty sparse revocation tree has a non-zero root. Treating zero as "clean"
would let a proof be checked against a tree nobody committed to, so
`expectedPublicSignals` reverts `RevocationRootNotPublished`.

**8. Activation now refuses an unregistered verifier version.**
`verifierVersion` is frozen into the fields digest at activation and there is
deliberately no way to edit an active tender, so activating a tender pinning a
version nobody registered produces a permanently unbiddable tender that can
only be cancelled - a liveness failure created by a typo and discovered by the
first bidder. `TenderRegistry.setVerifierVersionRegistry` wires the check;
zero disables it, which is what keeps the deployment order (registry after
tender module) workable.

**9. Stack too deep, again.** Eleven parameters on `registerVerifier` exceeded
the EVM stack, and `viaIR` is still unavailable because it inflates the linked
Poseidon libraries past EIP-170 (`stage0-evidence.md`). Grouped into
`Registration` and `SampleProof` structs, the same fix as
`TenderRegistry.RuleFields`.

---

## 5. Measured gas

| Operation | Gas |
|---|---|
| Raw Groth16 `verifyProof` | 291,225 |
| `EligibilityVerifier.verifyEligibility` | 344,581 |
| `EligibilityVerifier.verifyWithSignals` | 359,311 |
| Adapter overhead over the bare pairing | **53,356** |

Both entry points are `view`, so a bidder pays nothing to check a proof
before submitting; these figures are what `SealedBid` will pay when it calls
the adapter inside a transaction. The overhead buys the entire binding to
tender state - reading the tender, both registry roots, and the limb
reconstruction - which is the difference between a proof that verifies and a
proof that means something.

The test asserts a floor (`raw > 200,000`) rather than a ceiling: a
suspiciously small number would mean the pairing was skipped, not that the
code got fast.

---

## 6. Reproducing

```
npm run crypto:build
npm run circuits:compile
npm run ceremony -- all eligibility        # or init / contribute / finalize
npm run ceremony:verify                    # 28 checks
npm run fixtures:eligibility               # 4 real proofs
npm run contracts:test                     # 175 tests
```

Test totals after this stage: **307** (89 crypto, 43 circuits, 175 contracts),
plus 30 live-network end-to-end checks.
