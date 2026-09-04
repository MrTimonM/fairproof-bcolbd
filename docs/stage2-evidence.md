# Stage 2 Evidence: Contract State Machine

Development plan Section 24, Stage 2. **Quality gate: PASSED.**

Gate requirement: *"Unauthorized actions and invalid transitions all fail in
automated tests."*

## Test counts

| Suite | Tests |
|---|---|
| `@fairproof/crypto` | 79 |
| `@fairproof/circuits` (cross-language equality) | 9 |
| Contracts: encoding equality | 12 |
| Contracts: `Governance` | 30 |
| Contracts: `IssuerRegistry` | 28 |
| Contracts: `TenderRegistry` | 41 |
| **Total** | **199** |

## Contracts delivered

### `Governance.sol` - whitepaper Section 14, Section 11.3

3-of-4 council approval, a 60 s timelock on verifier activation and role
changes, no timelock on emergency pause, and a mandatory on-chain reason for
every action.

**The load-bearing invariant is tested structurally.** Whitepaper Section 14
ends: *"No action rewrites an active tender's rules or verifier."* The tests
therefore assert that no such function exists in the ABI at all - no rule
edit, no deadline extension, no arbitrary-call escape hatch, and `execute()`
returns `(ActionType, payload)` rather than performing a call. A guard can be
removed in a later commit; an absent function is absent. This is the
difference between governance and a backdoor, and it is what makes "oversight
without a rewrite pen" (Section 14) a claim a judge can check with a failing
transaction.

Thresholds are demonstrated, not asserted: **one approval is insufficient, two
approvals are insufficient, three execute.** The second insufficient step is
what distinguishes a real 3-of-4 from a 2-party check.

### `IssuerRegistry.sol` - whitepaper Section 5 clauses 2-3, Section 11.2

- `issuerRegistryRoot` per epoch. **This is the item an earlier draft of the
  development plan omitted.** Whitepaper Section 5 clause 2 requires the
  circuit to prove `issuerPubKey` is a *member* of this root; a per-issuer
  boolean in storage cannot satisfy that, because a circuit cannot read
  contract storage. Without the root the circuit would accept any key that
  produced a valid signature - self-attestation, exactly what clause 2 exists
  to prevent.
- Sparse-Merkle `revocationRoot` per epoch. Rolling the epoch never rewrites a
  past root, so the audit trail stays replayable (Section 14).
- `deadlineRevocationRoot`, pinned one-shot on close. Re-pinning would let a
  later revocation be retroactively hidden or introduced, which is the exact
  manipulation the deadline root exists to prevent. Only the wired tender
  module may pin - not the council, not the deployer - so the root always
  corresponds to a real CLOSED transition rather than an arbitrary call at a
  moment of someone's choosing.
- Issuer keys are BabyJubjub points, not Ethereum addresses, because the
  credential signature is EdDSA-BabyJubjub verified inside a BN254 circuit.
- Capacity 16, matching the depth-4 tree of spec Section 15.

Pause behaviour is deliberately asymmetric: registration is blocked while
paused, but **deactivating a bad issuer still works**. A pause that blocked
containment would make the emergency control counterproductive.

### `TenderRegistry.sol` - whitepaper Section 4, Table 11, Section 5, Section 14

- Lifecycle `DRAFT -> ACTIVE -> CLOSED`, plus `CANCELLED`.
- `tenderIdField` derived **on-chain** from the string, so the authority
  cannot supply an unrelated field element for the circuit to bind to. Test
  asserts the frozen value from spec Section 5.
- Rules frozen at activation: the document, the structured fields and the
  committee key all revert with `RulesFrozen` afterwards. Even the council has
  no path, because it is not the authority.
- **The public rule-review window is contract-enforced**:
  `biddingStart >= activatedAt + RULE_REVIEW_WINDOW`. Whitepaper Table 11
  offers this as the mitigation for unfair-but-immutable rules; it is now a
  mechanism rather than a promise.
- Activation completeness: cannot activate without a document, a window, or a
  committee key. A tender with no committee key would have no threshold
  opening, so the sealed-bid guarantee would silently not exist for it.
- Committee key: `Y`, five member shares `Y_i`, three Feldman VSS commitments,
  `t=3`, `n=5`. Duplicate members rejected - a duplicate would let one person
  hold two of the three shares needed to open.
- Closing is **permissionless** once the deadline passes. If only the
  authority could close, it could stall a tender it disliked by never closing
  it.
- Cancellation requires the council plus a reason. There is no in-place
  deadline extension, per Section 14's commitment to "cancellation and
  versioned reissue".

## How `rulesHash` is recomputed on-chain, and the one residual

Whitepaper Section 4 fixes `rulesHash = keccak256(JCS(...))` using RFC 8785,
and says the document "can be re-hashed by any verifier".

Solidity cannot parse JSON, so it cannot canonicalize a document itself. Rather
than silently substituting ABI encoding for JCS - which would make the
on-chain value differ from the published formula - **the authority submits the
canonical JCS bytes, the contract stores them, and the contract computes
`keccak256(document)` itself.** That is a genuine on-chain recomputation of
exactly the whitepaper's value: nobody has to trust a hash the authority
supplied. `activateTender` additionally takes the hash the authority *believes*
it is freezing and reverts on mismatch, so activation cannot succeed against a
document the authority did not intend.

The contract separately stores the structured fields it enforces (window,
thresholds, policies, verifier version) and computes a `fieldsDigest` over
them.

**RESIDUAL, STATED PLAINLY.** The contract cannot verify that the stored
document *parses to* the stored structured fields, because that needs JSON
parsing. A dishonest authority could store a document that reads differently
from the fields the contract enforces. Mitigations:

- The independent verifier (plan Section 16.6, check 1) re-parses the document
  and compares field by field.
- Both values are public and on-chain, so the divergence is detectable by
  anyone, permanently.
- The enforcement path uses the structured fields, so a misleading document
  cannot change what the contract actually enforces - it can only misdescribe
  it.

This must appear as a **PARTIAL** row in the Section 26 traceability table. It
must not be presented as fully on-chain.

## Compiler note

`TenderRegistry.setRuleFields` originally took twelve parameters and hit
"Stack too deep". `viaIR` is not available as a fix here: it inflates the
linked Poseidon libraries past the EIP-170 limit (see
`docs/stage0-evidence.md`). The parameters were grouped into a `RuleFields`
struct instead, and `_computeFieldsDigest` uses a documented two-stage encode
for the same reason. Both are better designs than the flat versions.
