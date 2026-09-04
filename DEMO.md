# FairProof — the walkthrough

Four roles, one tender, about twenty minutes. Everything below happens on a
live four-validator chain: every proof is generated while you watch, and every
transaction is real.

The order matters. Each role can only do its part because the previous one
finished, and the contract is what enforces that — which is the single most
convincing thing in the whole demonstration. **Do not skip ahead**; the waiting
is the point.

---

## Before you start

```bash
cd /home/mahedi/Music/FairProof/fairproof

npm run network:up          # four Besu validators
npm run replicas:start      # three ciphertext stores — the browser needs these
npm run deploy              # only if you want a clean chain with no tenders
npm run dashboard:sync      # ABIs, role keys, 18 MB of circuit assets

npm run tender -- --window 600     # publish the tender you will use
npm run dashboard:dev              # http://127.0.0.1:5173
```

### If you want a finished tender instead of a live one

```bash
npm run tender -- --window 240
npm run tender:complete RHD-2026-0147
```

That drives three named firms through the whole lifecycle — bids, close,
opening, status proofs, the award over the complete set, and the winner's
ownership proof — in about seven minutes, most of it the deadline. It ends with
a declared winner the dashboard can show, and it also writes the three bidders'
receipts so the **Your bid** panel has something to display for each of them.
Use it when you want the result on screen before you start talking, or as a
fallback if a live run goes wrong.

Check both are healthy before an audience is watching:

```bash
npm run network:health      # expect HEALTHY
npm run replicas:status     # expect 3/3 up
```

### Choosing the timings

`npm run tender` takes the two numbers that shape the whole demonstration:

| Option | What it controls | For a live run |
|---|---|---|
| `--lead` | seconds after publication before bidding opens | `150` (default) |
| `--window` | how long bidding stays open | `600` for a full run to award; `7200` if you only intend to show bidding |

With `--window 600` you get ten minutes to place bids, which is comfortable to
talk over and short enough that the opening ceremony happens inside the
session. The mandatory review window is 60 s on top of `--lead`, and **nobody
can shorten it** — that is a contract rule, not a setting, and it is worth
saying out loud while you wait through it.

Give yourself a second browser tab per role if you like. Committee shares and
bid receipts live in browser storage, so one window is simplest.

---

## Act 1 — Anyone. "Is this real?"

**Role: Public → Ongoing tenders**

Open the dashboard cold. Say what a stranger would want to know first.

- **Four validators, queried separately.** The table makes the same read
  against each node and prints all four heads. It is not one endpoint being
  trusted; it is four being compared. Point at the head spread.
- **The guarantees panel** on the right. Each row is derived from data on the
  page, not asserted by it. The one about a bidder never needing a funded
  wallet is worth reading aloud — gas costs nothing here, so a bid comes from a
  freshly generated address with no funding trail to correlate.
- **Two rows come back short of a tick**, deliberately: no checkpoint has been
  anchored outside this project's control, and the trusted setup had no
  independent contributors. Point at them. An interface that shows only ticks
  is asking to be believed.

Scroll to the tenders table. One tender, its subject as the heading and its
reference beneath.

---

## Act 2 — The procuring authority. "Publish a tender."

**Role: Authority → Create tender**

You already published one with `npm run tender`, so publish a **second** live
if you want the full sequence on screen, or walk the panels without submitting.

Point out, in this order:

1. **The council's preconditions**, at the top. Granting the authority its role,
   the review-window floor, the issuer registry. These are separate powers held
   by separate accounts — the authority cannot grant itself anything.
2. **The form**. Title, buying authority, location, the three requirements, the
   timings.
3. **The rule document below the form**, updating as you type. This is the
   canonical JSON that goes on-chain in full. The reader-facing prose and the
   machine-enforced fields are generated from this one form state, which is the
   only construction that makes them incapable of disagreeing.
4. Press **Publish this tender** and narrate the six steps as they land:
   - create, store the document,
   - **the contract recomputes the hash from the bytes it stored** — this is the
     freeze, and the panel prints the contract's answer, not the browser's;
   - set the enforced fields,
   - deal the committee key with Feldman VSS, **which the contract verifies**
     before accepting: C₀ equals the published key and every share is consistent;
   - activate.

From that block onward every rule is frozen. Nothing — not the authority, not
the council — can edit a threshold or move the deadline.

> If publishing fails at a step, the panel marks that step and the tender is
> genuinely a half-built draft on the chain. That is worth showing if it
> happens; it is not a bug.

---

## Act 3 — A bidding firm. "Apply, without disclosing anything."

**Role: Bidder → Submit bid**

This is the centre of the demonstration. Take your time.

### 3a. The credential — Bidder → My credentials

One credential, held in this browser and never transmitted: the figures an
approved issuer has attested about this firm.

Say plainly, because it is the most misunderstood point in the whole protocol:
**this is the bidder's screen, not a verifier's.** In FairProof the verifier is
precisely the party who never sees a turnover, an experience or a price.

### 3b. The check that makes the rules real — Bidder → Submit bid

The Qualification card reads **Qualified**, with each published requirement
ticked against what the credential holds.

Now go back to My credentials, drop the turnover below the tender's threshold,
and return. The card reads **Not qualified**, names the clause, and the submit
button is dead.

> "The circuit has no branch that lets an unmet requirement through. It fails at
> witness construction, not at submission — so a rule enforced this way cannot
> be waived under pressure, because nobody has the power to waive it."

Put the figure back before continuing.

### 3c. Prove, seal, submit

Type a bid amount and press **Submit sealed bid**. The button narrates itself —
*Generating proof… Encrypting your price… Storing securely… Submitting…* — and
underneath:

- the circuit fetched, 18 MB, from this origin and cached after the first bid;
- **the proof generated in this tab**, in about 1.6 seconds. The turnover, the
  experience and the price are private inputs and are never transmitted;
- **the sealed commitment checked against public signal 11** before anything is
  sent — without that equality a bidder could encrypt one price and prove
  another;
- the price encrypted to the committee, stored on three replicas;
- submitted from a fresh zero-balance address.

The receipt card names the submission number, with the transaction and block in
the small grey strip at its foot — which is where every chain detail lives in
this product.

Place a second bid at a higher amount so the opening has something to compare.

---

## Act 4 — Anyone again. "Check it without trusting the page."

**Role: Auditor → Verification**

This is where "acting as a verifier" actually happens, and the thing to stress
is what the verifier can see: proofs, roots and commitments. Not one private
value.

Press **Recompute everything**. Each row takes primitive data off the chain,
recomputes the derived value in the browser with the same frozen specification
the circuits use, and shows the comparison:

- the frozen rules hash, re-hashed from the stored document;
- **the document's own text against the fields the circuit enforces** — the one
  guarantee the chain delegates, because Solidity cannot parse JSON;
- the bid-set accumulator, rebuilt leaf by leaf with Poseidon. The authority
  never computes this root, so it cannot drop a bid and still produce a matching
  award proof;
- the Feldman dealing, checked against its own commitments using only the
  public shares;
- the award's binding to the set that actually exists.

Two rows come back short of a tick on purpose. Say why.

Below that: the submitted-bids table — nullifiers and commitments, nothing that
names anyone — and the ceremony provenance, with the weak trusted setup stated
at the top of the panel rather than in a footnote.

---

## Act 5 — The authority again. "Open the bids, declare the winner."

**Role: Authority → Bid opening**

While waiting for the deadline, show that the contract refuses everything: the
panel says the deadline has not passed and the buttons are dead.

1. **Close bidding.** Point out that it is signed by a freshly generated address
   holding no role at all. Anyone may close a tender, so nobody can hold one
   open to delay an opening they dislike. The credential records are pinned in
   the same transaction, one-shot.
2. **Open this bid.** Watch the meter: **1 of 3**, still sealed. **2 of 3**,
   still sealed. **3 of 3**, and the amount appears.

> "Three shares are combined in the exponent — the tender secret is never
> reassembled, by anyone, at any point. And the opened price reproduces the
> commitment recorded at submission, which is what stops a committee that
> decrypted correctly from reporting a different number."

Open every bid, then move to **Authority → Award**.

The card lists what has to be true before a winner can be named. Press
**Declare winner**. The selection proof is generated in this browser — 35,665
constraints over the complete set of accepted bids — and takes about a minute
the first time, because the circuit is 38 MB.

> "The authority cannot name anyone the rule did not select. The circuit rebuilds
> the whole accumulator from every slot, so a proof that dropped a bid would
> produce a different root and be rejected."

### Two caveats to state rather than let anyone discover

- For a tender seeded by `npm run tender`, all five committee shares came from
  one served file, so its threshold demonstrates the mechanism rather than
  protecting anything.
- Three genuinely colluding members could open bids early with nothing on-chain
  to show it. The threshold protects against two, not three.

---

## Act 6 — The public, and the firm. "Who won?"

**Role: Public → Results**, then **Integrity report**.

Results lists every tender this authority has run, in progress and completed,
with the winning firm and price. Open the report for the completed one:

| | |
|---|---|
| Winner | Padma Infrastructure Limited |
| Winning price | ৳74,00,000 |
| Rules published and frozen before bidding | Verified |
| Bid set complete | Verified |
| Every bid opened by the committee | Verified |
| Winner proved it placed the winning bid | Verified |
| Cryptographic verification | **PASS** |
| **Confidential documents disclosed** | **0** |

That last line is the one to sit on.

Then **Role: Bidder → My bids**, and reload the page first to show the record
survives.

> "Nothing on the chain says this bid is mine — that is the point, and it is
> exactly why a real bidding firm keeps this same copy. A losing bidder learns
> that they lost and nothing else. A winner can prove the win was theirs."

---

## If you want the whole thing without narration

```bash
npm run tender:complete <reference>   # three firms, to a declared winner
npm run seed                          # all thirteen stages, its own tender
```

It ends with a recorded award and a published winner identity, so the
Verification workspace has a completed tender to check. Useful as a fallback if
a live run goes wrong, and useful for showing the two stages this walkthrough
does not cover — the award proof over the complete bid set, and the winner's
ownership proof before any name is displayed.

---

## Checks you can run in front of an audience

```bash
npm run test:ui             # the dashboard renders, every workspace, no console errors
npm run test:dashboard      # every read path, against the live chain
npm run network:health      # four validators, agreeing
npm run test:network        # halts consensus by stopping a validator, then recovers it
npm run verify -- evidence/<bundle>.json     # sixteen checks, no node, no dashboard
npm run test:verifier       # 31 corrupted bundles, each caught by the right check
```

`npm run test:network` is the most dramatic: it stops a validator, shows the
chain continuing at 3 of 4, and brings it back.

---

## Things that will go wrong, and what they mean

| Symptom | Cause |
|---|---|
| "Prove, seal and submit" stays disabled | Bidding is not open yet, the profile is ineligible, or the replicas are down. The panel says which. |
| The bid submission reverts | Usually the replicas: a bid needs two of three signatures. `npm run replicas:status`. |
| Committee says "no share material" | The tender was dealt in a different browser. Use one published by `npm run tender`, or publish your own from the Authority workspace. |
| Everything empty after a redeploy | `npm run deploy` wipes tenders. Re-run `npm run tender`. |
| The dashboard shows a stale badge | A read is more than twenty seconds old. It is telling you the truth. |
