# End-to-End Evidence: Tender Lifecycle on the Live Network

`tests/integration/e2e-tender-lifecycle.mjs`, run against four Besu QBFT
validators with real block timestamps and **no time travel**.

Unit tests on a local EVM and a real deployment are different things. This
walks the whole flow with the seed dataset (plan Section 25.4) and is the test
that would catch an integration gap the unit suites cannot see.

**Result: 30 checks, all PASS, exit 0.**

## Deployment

`npm run deploy`. Poseidon is deployed once and linked, rather than inlined
per contract.

| Contract | Deploy gas |
|---|---|
| `PoseidonT3` | 3,694,887 |
| `PoseidonT6` | 4,506,682 |
| `Governance` | 1,309,445 |
| `IssuerRegistry` | 1,309,182 |
| `TenderRegistry` | 2,567,456 |

Addresses are written to `deployments.json`, which the seed script, the app
and the independent verifier all read. Nothing hard-codes an address.

## Stages walked

| # | Stage | Notable checks |
|---|---|---|
| 1 | Council registers the qualification issuer | BabyJubjub key stored; a non-council account is rejected with `NotCouncilMember` |
| 2 | Registry and revocation roots published | `issuerRegistryRoot` set - circuit clause 2 proves membership against it |
| 3 | Governance 3-of-4 proposal flow | one approval insufficient, **two insufficient**, three execute; empty reason rejected |
| 4 | Tender created in DRAFT | |
| 5 | Canonical rule document, fields, 3-of-5 committee key | **the contract recomputed `rulesHash` from the stored document** |
| 6 | Activation freezes the rules | wrong expected hash rejected with `RulesHashMismatch`; review window enforced (64s >= 60s) |
| 7 | **Negative test 2** (WP Table 14): rule edit after activation | document edit, threshold edit, and a council attempt all revert |
| 8 | Bidding opens only after the review window | closed during the window, open after 66s of real chain time |
| 9 | **Negative test 1** (WP Table 14): early close | `DeadlineNotReached` |
| 10 | Deadline passes, tender closes, deadline root pinned | closed by an **unfunded fresh address**; a later revocation does not alter the pinned root |
| 11 | Cross-node agreement | all four validators agree on `rulesHash` and state |

Two whitepaper negative tests are now demonstrated on a real chain rather than
a simulator. Four more (duplicate nullifier, ciphertext mismatch, dropped low
bid, ineligible firm) need the circuits and `SealedBid`.

## Three findings from writing this test

These are exactly the class of problem unit tests do not surface.

**1. `RULE_REVIEW_WINDOW` was a hard-coded constant.** At 300 s every
automated run took over five minutes, and a zero-length window would have been
the tempting shortcut. It is now **per-tender, in three layers** - see
`docs/time-parameters.md`. The window length is genuinely a policy question
that differs by tender class, so a single global constant was the wrong model;
but it cannot be the authority's free choice either, or the authority picks the
minimum every time and Table 11's mitigation becomes decorative.

**2. The revert assertions were not checking the reason.** Besu returns custom
error data that `ethers` cannot decode on a gas estimation, so every negative
test was reporting "reverted (unknown custom error)" and the helper was
accepting it. **A test that accepts any revert is weak** - it would pass if the
call failed for an unrelated reason, which is precisely how a security control
silently stops working. The helper now uses `staticCall`, which decodes
against the ABI and yields `err.revert.name`, and asserts the exact error.
Every negative check now names its reason: `RulesFrozen`, `NotAuthority`,
`DeadlineNotReached`, `RulesHashMismatch`, `ReasonRequired`,
`NotCouncilMember`, `NotActive`.

**3. The test was not idempotent.** It used a fixed issuer id and failed on its
second run with `IssuerAlreadyRegistered`. Every identifier is now suffixed
with a per-run nonce. This matters beyond tidiness: plan Section 25.5 requires
**five timed rehearsal runs** of the demo, and root values are also
per-run so the "a later revocation does not alter the pinned deadline root"
assertion is meaningful on every run rather than comparing a value left behind
by a previous one.

## Measured gas: the on-chain accumulator

`IncrementalMerkleTree` at depth 5, measured (plan Section 13.1):

| Operation | Gas |
|---|---|
| First append (all-empty siblings) | 255,873 |
| Subsequent append | 233,682 |

Comfortable against the 100M block gas limit. This is the cost of whitepaper
Section 7's guarantee that `bidSetRoot` is "accumulated by the contract, not
supplied by the authority".

The Solidity accumulator is asserted **equal** to the TypeScript one, not
merely sane: empty root and one-leaf root both match the frozen values. A
one-hash disagreement would make every award proof fail against the chain's
root.

All six completeness properties hold on-chain - omission, insertion,
alteration, reordering, and padding-leaf substitution all change the root.
