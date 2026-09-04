# Stage 8 evidence: the 3-of-5 opening ceremony

Development plan Sections 12.6 and 12.7, build order step 12. Whitepaper
Section 6 (threshold opening), Sections 4 and 19.5 (what it does not prevent).

This is the **opening** threshold, 3-of-5. It is not the 2-of-3 storage quorum.

---

## 1. What was built

`OpeningManager.sol` — 7,578 bytes deployed. Two entry points:

**`revealCiphertext`** publishes a bid's ciphertext body and hashes it on-chain
against the `ciphertextHash` committed before the deadline. The chain stores
only the hash at submission time, so it does not know the ElGamal ephemeral
point `R` — and without `R` there is nothing to verify a DLEQ proof against.
Permissionless, because the bytes are still encrypted and a privileged caller
could stall every opening. It also makes the evidence bundle self-contained:
the ciphertext is on-chain, not only in a replica that may be gone by the time
anyone audits.

**`submitDecryptionShare`** verifies a Chaum-Pedersen proof that
`log_G(Y_i) = log_R(D_i)` — that the same secret relates the member's published
public share to the share they are now submitting — and counts it.

**29 unit tests**, plus 44 checks in the live ceremony.

---

## 2. Why the proofs are verified on-chain

A decryption share `D_i = x_i · R` is just a curve point. Nothing about it says
who produced it. Without a proof a member could publish any point at all: the
Lagrange combination would produce garbage, and the failure would surface later
as an **AES-GCM tag error that looks like the bidder's fault**. The plan
requires that "an invalid share is rejected and attributed, not silently
dropped", and attribution is only possible if the share carries a proof.

A failing share **reverts**, naming the member index. The reverted transaction
is itself the public record — it is mined, its sender is recorded, and its
revert reason names who submitted what. Reverting is therefore stronger than
accepting-and-flagging, not weaker.

The contract **never reconstructs the secret**. It counts and verifies; the
Lagrange interpolation happens in the application, in the exponent, producing
`S = x·R` without the tender secret existing anywhere. A contract that
reconstructed `x` would be a contract that published it.

Both DLEQ equations are checked. Verifying only `z·G == A + e·Y_i` would prove
the member knows `x_i` and say nothing about the point they actually submitted.
The challenge covers **both** statements and **both** commitments, so a member
cannot prove once and have it accepted for every bid in the tender — tested by
replaying one bid's proof against another.

---

## 3. Two is not enough, and that is observable

`openingStatus` returns `accepted` and `threshold` **separately** so the UI can
render 1/3, then 2/3, with decryption still impossible. Collapsing them into a
single boolean would hide the step that distinguishes a real threshold from a
two-party check (plan Section 12.7).

Tested at every level:

| | |
|---|---|
| one share | `ready == false` |
| two shares | `ready == false` |
| three shares | `ready == true`, exactly one threshold event |
| any three of five | all four subsets tried |
| two shares, live | AES-GCM **rejects the key** — the bid stays sealed |

---

## 4. The live ceremony

`npm run test:e2e:opening` — **44 checks, all passing** on the four-validator
network. The full lifecycle with nothing simulated:

| Stage | Result |
|---|---|
| council lowers the review-window floor, with a reason | and still cannot go below the contract's hard 60s |
| Feldman dealing verified on-chain at `setCommitteeKey` | — |
| tender activated, rules frozen | `rulesHash` recomputed by the contract |
| **proof generated at run time** | 1.6 s |
| sealed, uploaded to three real replica processes | 3/3 acknowledged |
| bid during the review window | refused, `BiddingNotOpen` |
| bid accepted after the window | 1,604,074 gas, from an **unfunded** address |
| reveal before the deadline | refused, `TenderNotClosed` |
| tender closed permissionlessly by a fresh address | — |
| tampered ciphertext bytes | refused, `CiphertextHashMismatch` |
| ciphertext published | 750,255 gas |
| share 1/3, share 2/3 | not openable |
| **forged share from member 4** | **rejected, `DleqProofInvalid`, not counted** |
| member 5 publishing member 3's share | refused, `NotThisCommitteeMember` |
| share 3/3 | threshold reached |
| three on-chain shares interpolated in the exponent | equals `x·R` |
| **the bid opens** | **BDT 74,00,000** |
| two of the three shares | still cannot decrypt |
| all four validators | agree the threshold was reached |

### Why this test proves its own witness

The committed fixtures use a deadline in **2096** so they never rot, which is
right for unit tests that can fast-forward the clock. A real chain cannot be
fast-forwarded, so a fixture tender can never reach CLOSED and the opening
could never be demonstrated against it. This test therefore builds its own
credential, witness and proof for a tender that closes about two minutes out.
Proving takes 1.6 s, so the cost of honesty here is small.

---

## 5. Findings

**1. `closeTender` had a liveness hole.** It pins the revocation root of the
**registry's** current epoch, which is *not* the tender's credential epoch.
With no root published there, closing reverts `RootNotSet` — and since closing
is permissionless and purely time-based, a tender could become **permanently
unclosable** through no fault of anyone involved with it.

Reverting is the correct behaviour rather than pinning zero: the empty sparse
revocation tree has a non-zero root, so zero means "never published", and
pinning it would let a status proof be checked against a tree nobody committed
to. The fix belongs at deployment, and that is where it now is — `npm run
deploy` publishes the empty-tree root for the current epoch so the registry is
never in that state. Found by the live test; the unit tests had been publishing
a root at epoch 0 and papering over it.

**2. Cross-file clock leakage.** `OpeningManager`'s tests advance the chain to a
deadline in 2096. Mocha runs every file in one process against one network, so
the *next* file's first fixture inherited that clock and failed while setting up
a bidding window — a failure that pointed at the wrong file entirely. Both files
that move time now call `reset()` before and after, which also clears the
fixture snapshot cache that a bare `hardhat_reset` would leave dangling.

**3. `viem.getContractEvents` reads only the latest block without `fromBlock`.**
A test expecting three share events saw one, which looked like the contract
failing to emit. Bounded queries now. On Besu the same call needs an upper
bound too: `fromBlock: 0` is rejected outright with "Requested range exceeds
maximum RPC range limit" once the chain has a few thousand blocks, so the live
tests query from the deployment block recorded in `deployments.json`.

**4. Custom errors do not cross contract boundaries in a client ABI.**
`submitBid` reverts with `ProofRejected`, declared in `EligibilityVerifier`, so
a client decoding with `SealedBid`'s ABI alone gets "unknown custom error" —
exactly what a UI watching one contract would show a bidder. Bubbling the
verifier's own error is right, because it names the actual reason instead of
flattening every failure into one; the cost is that a client needs every ABI in
the call path. Recorded here so the UI does not rediscover it, and the live
tests merge the error fragments (only the errors — merging constructors makes
ethers warn about duplicate definitions).

**5. Timestamp slack in a live test is not a detail.** `activateTender`
re-checks the review window against the timestamp **at activation**, and the
setup is several transactions at two seconds a block. A 12-second margin failed
with `ReviewWindowTooShort`, which reads like a policy error rather than a slow
test. Now 120 s.

---

## 6. Measured gas

| Operation | Gas |
|---|---|
| `revealCiphertext` (398-byte body, keccak + subgroup check) | 750,255 |
| `submitDecryptionShare` (one verified DLEQ proof) | 2,785,733 |
| Full 3-of-5 opening for one bid | ~9,100,000 |
| `OpeningManager` deployment | 1,691,534 |
| `OpeningManager` deployed size | 7,578 bytes (limit 24,576) |

A share costs what it costs because DLEQ verification is **four 251-bit scalar
multiplications** on BabyJubjub plus two point additions. At 9.1 M gas the full
opening of one bid is 9% of this network's 100 M block gas limit, at a zero gas
price. That is affordable here and would not be on a public chain; the
documented optimisation is to return coordinate tuples from `add` and `mul`
rather than `Proj memory` structs, since memory allocation rather than field
arithmetic dominates the figure.

The test asserts a **floor** (`> 1,000,000`) rather than a ceiling: a
suspiciously small number would mean a check was skipped, not that the code got
fast.

---

## 7. What this does not prevent, stated plainly

These events evidence the **official** ceremony. Three colluding committee
members could exchange shares privately and open bids early, and **nothing
on-chain would reveal it**. Whitepaper Sections 4 and 19.5 concede exactly
this. The UI must repeat it wherever the threshold is displayed rather than
letting a reviewer discover it.

The dealer also briefly knew the tender secret (`docs/cryptography.md`
Section 6). On-chain Feldman verification narrows the trusted-dealer residual
to that one fact, but does not remove it; only DKG does.

---

## 8. Reproducing

```
npm run network:up && npm run deploy && npm run replicas:start
npm test                       # 466 tests
npm run test:e2e:opening       # 44 checks, ~4 minutes of real chain time
```
