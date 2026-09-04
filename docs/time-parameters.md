# Time Parameters: What Is Configurable, and What Is Not

Every timing parameter in a FairProof tender, who sets it, and what bounds it.

## Fully per-tender, set by the authority in DRAFT

All of these are frozen at activation, covered by `rulesHash` and
`fieldsDigest`, and publicly readable thereafter.

| Parameter | Meaning | Bound |
|---|---|---|
| `biddingStart` | When the auction opens | Must satisfy the review window (below) |
| `deadline` | When bidding closes | `> biddingStart`. **No upper or lower bound** - 45 seconds for a demo, 90 days for a real works tender |
| `reviewWindow` | Gap between activation and `biddingStart` | `>= minReviewWindow` |

**There is no hard-coded auction length.** The bidding period is
`deadline - biddingStart` and the authority sets both endpoints freely. The
contract only requires that the window is non-empty and that bidding does not
open before the review period has elapsed.

## The review window: three layers

Whitepaper Table 11 offers a "mandatory public rule-review window before
bidding opens" as the mitigation for unfair-but-immutable rules. Two competing
requirements shape how it is implemented:

- It must be **per-tender**, because a small works tender and a national
  infrastructure tender should not be forced to share one value.
- It must **not** be the authority's unilateral choice, because an authority
  free to pick its own review period will pick zero, and the mitigation becomes
  decorative.

Hence three layers. An authority can always grant **more** review time, never
less.

```
ABSOLUTE_MIN_REVIEW_WINDOW = 60s        hard constant in Solidity
        |                                no deployment, council or authority
        |                                can go below it
        v
minReviewWindow                          council 3-of-4, mandatory on-chain
        |                                reason, timelocked
        v
Tender.reviewWindow                      authority's choice, per tender,
                                         frozen at activation
```

| Layer | Who changes it | How |
|---|---|---|
| `ABSOLUTE_MIN_REVIEW_WINDOW` | Nobody | A `constant`. Changing it needs a new contract version, which is itself a timelocked governance action |
| `minReviewWindow` | Governance council | `setMinReviewWindow(window, reason)`, 3-of-4, reverts below the hard constant and on an empty reason |
| `Tender.reviewWindow` | Tender authority | `setRuleFields(...)`, DRAFT only, reverts below `minReviewWindow` |

### Two behaviours worth knowing

**A floor raised after drafting still applies at activation.** The check runs
in `setRuleFields` *and* again in `activateTender`, so a tender drafted while
policy was lax cannot slip through after the council tightens it.

**A floor change never affects an already-ACTIVE tender.** Each tender stores
its own frozen `reviewWindow`, so raising the policy floor constrains future
tenders only. This is required by whitepaper Section 14: *"No action rewrites
an active tender's rules or verifier."*

## Prototype values, and what production would use

The deployment default floor is 300 s, and the automated tests deploy with 60 s
so a full lifecycle run completes in about three minutes.

**Do not describe a sixty-second floor as production-ready.** A real deployment
sets the floor from the applicable procurement rules - in Bangladesh, from PPR
2025 and the relevant BPPA circulars - and records it in the governance
charter. The prototype's short values exist so the workflow is demonstrable in
one sitting, and the UI must label them as demo values.

## Other timing parameters

| Parameter | Where | Value | Notes |
|---|---|---|---|
| Governance timelock | `Governance.TIMELOCK_SECONDS` | 60 s | On verifier activation and role changes. No timelock on emergency pause: a pause that takes effect an hour later is not an emergency control |
| QBFT block period | `infrastructure/besu/qbft-config.json` | 2 s | Deadline enforcement rests on finalized chain time and validator clocks (whitepaper Section 19.5) |
| QBFT request timeout | `infrastructure/besu/qbft-config.json` | 4 s | |
| QBFT epoch length | `infrastructure/besu/qbft-config.json` | 30000 | |

## Deadlines cannot be extended

There is deliberately no `extendDeadline` function anywhere, and a test asserts
its absence. Whitepaper Section 14: *"The prototype supports no in-place
deadline extension: an outage invokes cancellation and versioned reissue under
the precommitted contingency policy."*

If a chain outage strands a tender at its deadline, the remedy is council
cancellation with an on-chain reason, followed by a new tender version - not a
quiet extension that would let an authority wait for a preferred bid to arrive.
