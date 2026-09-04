# Stage 3 Evidence: Eligibility Circuit

Development plan Section 24, Stage 3.

Gate requirements: *"Every eligibility negative test fails for the correct
reason. No private input appears in public signals."*

## The circuit

`packages/circuits/src/eligibility.circom`, implementing the **nine clauses of
whitepaper Figure 3** exactly - none omitted, no additions to the public
signal list.

| Metric | Value | Whitepaper target |
|---|---|---|
| Non-linear constraints | **19,233** | Table 15: "from 10^4 to 10^5" - inside budget |
| Linear constraints | 13,396 | |
| Public inputs | 12 | Figure 3, exactly |
| Private inputs | 54 | |
| Wires | 32,626 | |

Reported from Circom's own constraint report via `npm run circuits:compile`,
as Table 15 commits to.

## Clause-by-clause implementation

| WP clause | Statement | Implementation |
|---|---|---|
| 1 | `issuerSig` verifies over the credential fields | `EdDSAPoseidonVerifier` over `credDigest` |
| 2 | `issuerPubKey` is a member of `issuerRegistryRoot` | Merkle inclusion, depth 4; leaf commits to **both** coordinates |
| 3 | Sparse-Merkle leaf at `credentialId` equals zero | `SparseNonMembership`, depth 32, path bits from `credentialId` |
| 4 | signed `subjectCommitment == Poseidon(subjectSecret)` | Computed in-circuit and fed into the signed digest |
| 5 | `T >= turnoverThreshold` | `LessThan(65)` after `Num2Bits(64)` on both operands |
| 6 | `E_m >= experienceMonthsThreshold` | `LessThan(33)` after `Num2Bits(32)` on both operands |
| 7 | `certValidUntil >= deadline` | `LessThan(65)` after range constraints |
| 8 | `nullifier == Poseidon(subjectSecret, tenderIdField)` | `Nullifier` template |
| 9 | `bidCommitment == Poseidon(...)` | `BidCommitment` template |

Two deliberate notes:

- **`rulesHashHi/Lo` carry no in-circuit constraint, and need none.** Any
  change to them changes the verified statement, so a proof built under
  different rules fails at the verifier, which reconstructs the 32-byte hash
  from the limbs and compares it against the tender's stored `rulesHash`. A
  decorative constraint here would misleadingly suggest the binding lives in
  the circuit when it lives in the verifier adapter.
- **Credential expiry (`credentialValidUntil >= deadline`) is a superset** of
  the nine clauses. An expired credential should not qualify even when the
  certificate it references is still valid. Documented as a superset; never
  presented as one of the nine.

## Test results: 34 circuit tests, all passing

Whitepaper Section 19.2: *"Failures persuade more than successes, because each
one shows a guarantee being enforced rather than described."*

### Positive and boundary (plan Section 11.4)

| Case | Result |
|---|---|
| Valid credential above both thresholds | passes |
| Turnover **exactly at** the threshold | passes - proves `>=`, not `>` |
| Turnover at threshold **+1** | passes |
| Turnover at threshold **-1** | **fails** |
| Experience exactly at the threshold | passes |
| Experience one month below | **fails** |
| Certificate expiring **exactly at** the deadline | passes |
| Certificate expiring one second before | **fails** |
| Unrevoked credential against a tree with other revocations | passes |
| Nullifier differs across tenders, both proofs valid | passes |

### Negative

| Attack | Rejected by |
|---|---|
| **BDT 3.8 crore against a BDT 50 crore threshold** (WP Table 14 row 6) | clause 5 |
| Zero turnover | clause 5 |
| Turnover value that would **wrap past uint64** | clause 5 range constraint |
| Self-signed credential | clause 2 |
| Valid signature from a key **outside** the registry | clause 2 |
| Wrong `issuerRegistryRoot` | clause 2 |
| Tampered issuer Merkle path | clause 2 |
| Forged credential - altered values, original signature | clause 1 |
| Tampered signature scalar `S` | clause 1 |
| Tampered signature point `R8x` | clause 1 |
| **Revoked** credential | clause 3 |
| Wrong `revocationRoot` | clause 3 |
| Credential belonging to another subject | clause 4 |
| Wrong certification code | clause 7 |
| Expired credential | superset check |
| Tampered nullifier | clause 8 |
| Tampered bid commitment | clause 9 |
| Bid amount substituted after commitment | clause 9 |
| **Cross-tender replay** | clause 8 |
| Threshold raised above the attested turnover | clause 5 |
| Deadline moved past certificate expiry | clause 7 |

## The soundness test that matters most

`docs/field-encoding.md` Section 14: *"An unconstrained `LessThan` in Circom is
not a comparison; it is a suggestion, and a malicious prover supplies a field
element that wraps."*

The test **forges a signature over the out-of-range value itself**, so clause 1
passes and the range constraint is the single thing that can reject the
witness. Without that care the test would pass because the signature failed,
proving nothing about clause 5.

There is a separate, weaker test asserting the TypeScript builder also refuses
out-of-range values - defence in depth, and a legible error instead of an
opaque constraint failure. The circuit remains the authority.

## Privacy: no private input reaches a public signal

The 12 public signals are `tenderIdField`, `rulesHashHi`, `rulesHashLo`, the
three thresholds, `deadline`, `issuerRegistryRoot`, `revocationRoot`,
`credentialEpoch`, `nullifier`, `bidCommitment`.

`annualTurnover`, `relevantExperience`, `bidAmount`, `bidNonce`,
`subjectSecret`, `certValidUntil` and `credentialId` are **absent**, and a test
asserts their absence. The threshold is public; the firm's actual value is not.
That distinction is whitepaper Figure 3's whole claim.

## Two bugs found while writing the tests

**1. Test pollution through shared arrays.** `makeWitness` passed the same
module-level `issuerPathElements` array reference into every witness. The
tampering test mutated element 0, silently corrupting **every subsequent
test** - which then failed with clause-2 errors that had nothing to do with
what they were testing, and passed when run in isolation. The arrays are now
copied per witness.

Worth recording because the symptom was maximally misleading: four unrelated
tests failing at clause 2, all of them correct.

**2. The sparse-tree sibling rule was wrong.** `revocationTreeWith` compared
single bits of the query and revoked ids and stopped at the first difference.
That is not the right predicate: two ids can differ at a low bit while still
sharing a subtree higher up, so the revoked subtree was placed at the wrong
level and the recomputed root did not match. The correct rule is that at level
L the revoked leaf sits in the sibling block exactly when
`revokedId >> L == ((queryId >> L) ^ 1)`.
