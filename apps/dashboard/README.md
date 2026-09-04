# FairProof dashboard

Five role workspaces over the live permissioned chain. It reads the chain, and
in three of the five it also writes to it: a tender is published here, a bid is
proved and sealed here, and a threshold opening is carried out here.

```bash
npm run network:up        # four Besu validators
npm run deploy            # contracts + the governance-registered verifier
npm run replicas:start    # three ciphertext-store processes
npm run dashboard:sync    # contract ABIs, role keys, circuit assets
npm run tender            # one tender, ready to bid on
npm run dashboard:dev     # http://127.0.0.1:5173
```

`npm run tender` publishes a single tender and leaves the committee able to
open it — see **Seeded tenders** below. It takes options:

```bash
npm run tender -- --title "Replacement of the Teesta river bridge" \
                  --buyer "Roads and Highways Division" \
                  --location "Kaunia, Rangpur" \
                  --reference RHD-2026-0148 \
                  --turnover 900000000 --experience 84 --window 7200
```

`npm run seed` drives one complete tender through every stage on the chain in
about four minutes, which is the fastest way to get a dashboard with an awarded
tender on it. Everything the seed script does can also be done from these
workspaces by hand.

## Four roles

FairProof is not one audience, and the first version of this interface — one
read-only view for all of them — was the thing that made it unreadable. The top
bar switches role and the sidebar lists that role's sections.

| Role | Sections | What they do |
|---|---|---|
| **Public** | Ongoing tenders · Results · Integrity report | Browse what is open, see past results and the winning firm, open a report whose every line is derived from the chain. |
| **Bidder** | Available tenders · My credentials · Submit bid · My bids | Prove qualification privately, see **Qualified ✓**, enter a price, submit a sealed bid, and track it to the result. |
| **Authority** | Create tender · Tenders · Bid opening · Award | Publish a tender and freeze its rules, watch sealed submissions arrive, close bidding, open the bids after the deadline, declare the winner. |
| **Auditor** | Verification | Recompute every root, hash and proof in the browser — without seeing a single private figure. |

## Keeping the chain quiet

Hashes, roots, transactions and block numbers appear in a **strip at the foot of
a card**, at 12 px, never as a headline. A procurement officer does not need
them and the two people who do know exactly what they are looking for. The
Auditor is the one screen allowed to look like cryptography, because that is
what its reader came for.

## What a bidder keeps

The chain records a nullifier and a commitment, and deliberately nothing that
ties either to a firm. That is the point of the protocol, and it is also the
reason a bidder cannot come back later and ask which submission was theirs.

So the Bidder workspace keeps a copy at submission time — the nullifier, the
commitment, and the price and nonce that reproduce it — in this browser's
storage, never transmitted. The **Your bid** panel matches it against live
chain state and answers the five questions a bidder actually has: is my bid in
the set, is bidding closed, has it been opened, was my credential still valid at
the deadline, and did I win. A real bidding firm keeps exactly this, for exactly
the same reason.

Clearing browser storage loses the record, not the bid: it stays on-chain,
valid and openable. What is lost is only the ability to point at it.

## Proving happens in the tab

All three circuits run in the browser: eligibility (19,233 constraints) when a
firm bids, the award (35,665) when the authority declares a winner, and the
winner's ownership proof (11,391). Their artefacts are served as static assets
from this origin — 68 MB in total, fetched only when the relevant button is
pressed and cached by the browser afterwards.

This is not a performance decision. A bidder's turnover, experience and price
are private inputs, and a design that posted them to a proving service would
have moved the disclosure rather than removed it. The witness never leaves the
browser.

Two equalities are asserted before anything is submitted, because both catch a
class of mistake that would otherwise surface as an unexplained revert: the
proof's public-signal order against the frozen field-encoding spec, and the
sealed bid's commitment against public signal 11.

## Seeded tenders, and the one caveat they carry

A tender published from the Authority workspace keeps its committee shares in
the browser that dealt them. That is the honest consequence of a trusted dealer
— and it means nobody on another machine can ever open that tender.

So `npm run tender` writes its dealing to `public/committee-dealings/`, and the
Authority workspace loads it when the local browser has nothing. For a tender
seeded that way the five members' secret shares sit in one file anyone can
fetch, so its threshold demonstrates the mechanism rather than protecting
anything. `npm run tender:complete` does the same for the three bidders'
receipts, so **My bids** has something to display for each firm.

Everything else about a seeded ceremony is real: each decryption share is
computed properly and the contract verifies its Chaum-Pedersen proof before
accepting it. What is not real is the separation between the five members.

## Writing transactions without a wallet extension

`npm run dashboard:sync` writes role **private keys** into `src/generated/`,
which is gitignored. They derive from the public Hardhat test mnemonic — the
most widely published key material in Ethereum — and this chain has a zero gas
price and nothing of value on it. That is why shipping them to the browser is
acceptable, and the interface says so on screen rather than leaving a reader to
wonder. They must never be reused anywhere that matters.

A bid is the exception: it is submitted from a wallet generated in the tab
seconds earlier, with a zero balance. Gas costs nothing here, so a bidder never
funds an address, which closes the funding-trail correlation the whitepaper
lists as a residual metadata risk.

## Committee shares, and why they are in `localStorage`

The committee key has a trusted dealer. The Authority workspace deals it, the
contract verifies the Feldman commitments, and the five secret shares have to
be reachable by the Committee workspace afterwards — so they are held in the
browser's own storage, on the reader's own machine, and never transmitted.

That is exactly the residual the whitepaper names in Section 19.1: one party
briefly knew the tender secret. Distributed key generation is what removes it,
and this deployment does not have it. The Committee workspace states this on
screen instead of hiding the storage.

## There is no database

Every value is a contract read. A failed read is displayed **as a failed read**,
with the error and a recovery hint, never as an empty panel; reads older than
twenty seconds are badged stale.

`npm run test:dashboard` exercises every read path against the live chain,
because a build that compiles proves nothing about whether the reads work. It is
what caught a wrong struct field and a contract function that did not exist.

`npm run test:ui` opens the running dev server in a headless browser, visits
every workspace and fails on any console error. A bundler resolves modules; it
does not run them, and a green build has twice reported success on a page that
came up blank — once on an unparseable favicon data URI, once on circomlibjs
reaching for Node's `Buffer`. Both were warnings at build time and fatal at load
time. The browser is not a hard dependency; the script prints the two commands
that install it.

## The design brief

An administrative product, not a cryptography console. The people who use this
are procurement officers, bidding firms and the public; the chain is doing
something remarkable underneath and the interface's job is to stay out of its
way.

Light ground, navy ink, one teal accent for anything actionable and one green
for anything verified. Rounded cards, generous white space, minimal drawn
icons. It should feel like a banking or admin product with blockchain
verification happening quietly beneath.

This is the fourth edition. The first was 14 px greys and read-only. The second
was a dark gradient dashboard — legible, and indistinguishable from every other
generated interface. The third was an editorial broadsheet, which read well and
was still far too technical for anyone but an auditor.

Three rules shape every component. The first two are about honesty rather than
taste:

1. **Colour is never the only carrier of meaning.** Every status has a drawn
   mark and a word as well.
2. **A claim with no route to verification appears nowhere.** "Verified" is
   always accompanied by what was checked.
3. **The chain stays in the footer.** Hashes, roots, transactions and block
   numbers live in a strip at the foot of a card, at 12 px. Never a headline.

### Titles and references

A tender's on-chain identity is `tenderIdString`: short, unique, and useless as
a description. Procurement notices are read by their subject, so the rule
document also carries a `title`, a `buyer` and a `location`, and the interface
leads with those. They sit inside the document the frozen `rulesHash` covers, so
they cannot be edited after activation any more than a threshold can — and the
independent verifier tolerates them because it checks the fields it knows rather
than rejecting the ones it does not.

## Stated gaps

- **No checkpoint has been anchored outside this project's control**, so the
  Verification workspace reads that row as *absent* rather than *pending*. A
  checkpoint recorded only on the chain it describes is worth nothing against
  that chain's own operators.
- **The trusted setup is weak** and the Verification workspace says so on the
  page rather than in a footnote. A reviewer who has to dig for a caveat
  concludes it was hidden.
- **Only eligibility proving is wired into the browser.** The award and
  winner-identity proofs are generated by `npm run seed` and by the integration
  suites; their proving keys are 34.8 MB and 8.3 MB and would work the same way.
- **The evidence bundle is exported by a Node script**, not by a button here. A
  bundle a reviewer downloads from the page they are auditing is a weaker
  artefact than one they generate themselves from the chain.
