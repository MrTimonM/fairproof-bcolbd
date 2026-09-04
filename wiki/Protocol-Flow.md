# Protocol Flow

Nine phases. For each: who acts, what the contract enforces, what the public
chain records, and what each party can learn.

---

## The actors

| Actor | Can do | Can **never** do |
|---|---|---|
| **Council** (regulator, procuring entity, auditor, chamber) | Accredit certifying bodies, register verifier versions, pause | Act alone — 3 of 4, behind a timelock |
| **Certifying body** (an ICAB-registered audit firm) | Attest a firm's audited figures; revoke a credential | Bid as the firm; learn which tenders it bids on |
| **Procuring authority** | Publish a tender, freeze rules, open bids, record the award | Change a rule after activation; see any firm's finances; confirm a bidder's standing |
| **Bidding firm** | Prove eligibility, seal a bid, confirm its own standing, publish identity if it wins | Alter an attested figure; bid twice; read another bid |
| **Opening committee** (5 members) | Any 3 together decrypt bids after the deadline | Open early, open with 2, or report a different price |
| **Public / auditor** | Close a lapsed tender; recompute every check | Learn any firm's finances or any losing price |

---

## Phase 0 — Accreditation *(once, ever)*

The Council accredits a certifying body: 3-of-4 approval, then a timelock, then
`registerIssuer` records its public key and `publishIssuerRegistryRoot` publishes
the Merkle root of the approved set for that epoch.

**Enforced:** no single office can appoint — or quietly remove — the body that
vouches for bidders.

## Phase 1 — Attestation *(once per firm, no tender involved)*

1. The firm's browser generates a **subject secret** and keeps it, handing the
   auditor only `subjectCommitment = Poseidon(secret)`.
2. The firm gives the auditor its books, off-protocol, exactly as today.
3. The auditor signs one Poseidon digest over **ten values**: schema version,
   subject commitment, turnover, experience, certification code, both validity
   dates, credential id, issuer epoch, issued-at.

**Enforced by that signature:** the firm cannot alter a figure; the auditor
cannot bid as the firm (it never held the secret); a copied credential is inert.

**On the chain:** *nothing.* One credential then works for every tender until it
expires or is revoked, and each tender re-judges its figures against its own
thresholds.

## Phase 2 — Publishing a tender

Six transactions: create → publish the rule document → **freeze** (the contract
hashes what it stored and compares) → set requirements → appoint the committee
(the contract verifies the Feldman dealing) → activate.

**Enforced:** after activation no threshold or date can change. A mandatory
public review window must elapse before bidding opens and cannot be shortened.

## Phase 3 — Sealing a bid

All in the bidder's browser. The eligibility circuit asserts an approved body
signed this credential; that body's key is in the registry root; the credential
is not revoked; the signed commitment matches the held secret; every threshold
is met; the credential is valid **at the deadline**; and the nullifier and bid
commitment bind the proof to this tender and this price.

Then: encrypt the price to the committee key, store the envelope across three
replicas (quorum 2, each signing for the exact bytes), and submit from a fresh
zero-balance address.

**On the chain:** nullifier, price commitment, ciphertext hash, submission index
— folded by the contract itself into the bid-set accumulator. Not the turnover,
the name, or the price.

## Phase 4 — The deadline

Once it passes, **anyone** may close the tender. Closing fixes the accepted set
and pins the revocation root, so "unrevoked" is judged as of the close.

**Enforced:** no official can hold a tender open while deciding whether they
like the result.

## Phase 5 — Opening

Three of five committee members submit decryption shares; the contract verifies
each share's **DLEQ proof** on-chain. At three shares the price is recovered and
must reproduce the commitment recorded at submission.

**Enforced:** one share reveals nothing, two reveal nothing, and the shares
combine without ever reconstructing the master key.

## Phase 6 — Confirming standing *(only the bidder can)*

The firm re-proves its credential was valid against the pinned root, using its
secret. `recordAward` **reverts** with `WinnerStatusNotProven` until it does.

**This is the point, not an inconvenience:** because the proof needs the firm's
secret, the procuring authority is *structurally incapable* of confirming a
bidder's standing on its behalf.

## Phase 7 — The award

The award circuit rebuilds the **complete set of accepted bids inside the
circuit** and proves the published rule selected this winner. The award pins the
accumulator root and count the contract holds; a proof that dropped a bid
produces a different fingerprint and is rejected. The authority never computes
that root, so **it cannot name anyone the rule did not select.**

## Phase 8 — Identity, then verification

The winner proves ownership of the winning bid, and only then does a name appear
anywhere. Anyone can then recompute everything in their own browser, or export
an evidence bundle and run **16 checks offline**.

---

## What each stage records

| Stage | On the chain | Never on the chain |
|---|---|---|
| Accreditation | Issuer key, registry root, epoch | — |
| Attestation | *nothing* | Turnover, experience, the secret |
| Tender published | Rule document, hash, dates, requirements, committee key | — |
| Bid sealed | Nullifier, commitment, ciphertext hash, index | Turnover, name, price |
| Closed | Closed state, pinned revocation root | — |
| Opened | Shares, revealed price | The master key |
| Standing confirmed | Status proof | The subject secret |
| Awarded | Winner commitment, price (by policy), root, count | Losing prices |
| Identity | Identity commitment, declared record | Everything else |

## Who learns what

| Party | Finances | Bid prices | Who bid |
|---|---|---|---|
| Certifying body | **Sees** — it already audits them | Never | Never |
| Procuring authority | Never | After the deadline | Winner only |
| Opening committee | Never | 3-of-5, after the deadline | Never |
| Public & auditors | Never | Winning price, by policy | Winner only |

"Never" means *cryptographically prevented*, not *against policy*.

## Each attack, and the step that stops it

| Attack | What happens |
|---|---|
| Bid after the deadline | Contract reverts |
| Edit a threshold after publication | Fails — rules hash frozen at activation |
| Bid twice from a second address | Fails on the duplicate nullifier |
| Submit with no stored envelope | Never enters the accepted set |
| Drop an inconvenient low bid | Award proof fails against the bid-set root |
| Open bids before the deadline | Contract refuses every share |
| Two committee members collude | They learn nothing; threshold is 3 |
| Report a different opened price | Fails the recorded commitment |
| Hold a tender open past its deadline | Anyone may close it |
| Authority "confirms" a bidder's standing | Impossible — needs the bidder's secret |
| Publish a name that did not win | Identity proof fails against the award |
| An ineligible firm bids | Fails **privately** — the failing value stays hidden |

---

## Two deliberate hard cases

**A lost secret makes a tender unawardable.** If a bidder loses its subject
secret, nobody can confirm its standing, and the tender cannot be awarded. The
remedy is cancellation and reissue. The same property that stops the authority
acting for a bidder is what makes this unrecoverable.

**A revoked cheapest bidder makes a tender unawardable** — not awardable to the
second cheapest. The remedy is cancellation and reissue. Awarding around a
revoked low bid would be exactly the discretion this protocol removes.

See **[[Limitations]]** for what none of this guarantees.
