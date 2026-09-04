# FairProof

**A zero-knowledge procurement integrity protocol.**
Team Bind · Blockchain Olympiad Bangladesh 2026

A procuring entity publishes rules, freezes them, and then cannot change them.
Firms prove they qualify without revealing their turnover, their experience, or
who they are. Bids stay sealed until three of five independent committee members
act. The winner is proved to be the lowest qualified price **over the complete
set of bids** — and the whole thing can be checked by a stranger who trusts
none of it.

---

## Run it

```bash
npm install
npm run network:up          # four Besu validators, QBFT
npm run deploy              # contracts, and verifier v1 through a real 3-of-4 vote
npm run replicas:start      # three ciphertext-store processes
npm run tender              # one tender, ready to bid on
npm run tender:complete RHD-2026-0147   # three firms, through to a named winner
npm run dashboard:dev       # http://127.0.0.1:5173
```

`npm run seed` instead drives one tender through all thirteen stages in about
four minutes, ending in a recorded award — useful when you want a completed
tender rather than a live one.

**First time here?** Read [`SETUP.md`](SETUP.md) — the commands above assume the
circuits are already built, and building them needs `circom` and a 145 MB
powers-of-tau file that are deliberately not in this repository. Start with
`npm run doctor`, which tells you exactly what is missing.

**Deploying it to a server?** [`DEPLOY.md`](DEPLOY.md) is the procedure that
produced the live instance, including the one thing people get wrong (the
bundle's endpoints) and the one thing they must not ignore (every visitor holds
every role private key).

**Showing it to someone?** [`DEMO.md`](DEMO.md) is the hands-on walkthrough.

The dashboard is five role workspaces, not a viewer. A tender can be published
from it, a bid proved **in the browser** and submitted, and a threshold opening
carried out — the same code paths `npm run seed` drives from the command line.
See `apps/dashboard/README.md`.

Then check it without believing any of the above:

```bash
npm run evidence -- --all                      # deterministic evidence bundle
npm run verify -- evidence/<bundle>.json --rpc=http://127.0.0.1:8545
```

## What `npm run seed` actually does

Thirteen stages on the live chain with nothing simulated. Every proof is
generated at run time, for a tender created at run time.

```
issuer registered by 3-of-4 council      review window lowered by governance
Feldman committee key verified on-chain  tender activated, rules frozen
2 bidders prove eligibility (~1.5s each) sealed and stored on 3 replicas
review window waited out in real time    bids submitted from 0-balance addresses
deadline passes, permissionless close    a third firm's credential revoked
ciphertexts published and hash-checked   1/3 → 2/3 → still sealed → 3/3
bids opened: BDT 74,00,000 and 81,50,000 status proofs vs the pinned root
award proved over the COMPLETE bid set   winner's ownership proof
all four validators agree
```

---

## The claims, and how each is enforced

| Claim | Mechanism |
|---|---|
| Rules cannot change after bidding opens | The contract recomputes `rulesHash` from the document it stores. Editing anything post-activation reverts, and no council function reaches an active tender. |
| A bidder's finances stay private | A Groth16 proof of nine clauses. The chain learns a tender-scoped nullifier and a bid commitment, and nothing else. |
| No bid is readable before the deadline | AES-256-GCM under a key encapsulated to a 3-of-5 committee key. Shares are refused until the tender is CLOSED. |
| A bad committee share is caught and attributed | A Chaum-Pedersen proof, verified on-chain. A failing share reverts naming the member; the reverted transaction is the record. |
| No bid can be dropped from the award | The award circuit rebuilds the **entire** accumulator root from all 32 slots. Membership proofs alone would say nothing about leaves omitted. |
| The winner was still qualified at the deadline | Eligibility re-proved against the revocation root pinned one-shot when the tender closed. |
| The named winner really placed the winning bid | An ownership proof, required before any identity is displayed. |
| A procurement runs end to end without a trusted server | Every proof — eligibility, award and winner identity — is generated in the browser from static circuit artefacts. No witness leaves the tab. |
| One party cannot rewrite the ledger | QBFT across four institutions, ⌊(n−1)/3⌋ = 1 Byzantine fault tolerated — demonstrated in both directions. |

## What it does *not* establish

Listed here rather than left for a reader to find. Each is a limitation the
submitted whitepaper also names.

- **The trusted setup is small.** Every phase-2 contribution was made on one
  machine, with no independent contributors. If that machine was compromised,
  forged eligibility proofs would be possible. `docs/cryptography.md` §2.
- **Credentials are trusted, not verified.** A proof shows an approved issuer
  attested facts meeting the thresholds. It cannot show those facts are true.
  Zero-knowledge proofs move trust; they do not remove it.
- **Early opening by three colluding members is undetectable.** They could
  exchange shares privately and nothing on-chain would reveal it.
- **The committee key has a trusted dealer.** On-chain Feldman verification
  narrows the residual to one fact — the dealer briefly knew the tender secret.
  Only DKG removes it.
- **No external anchor exists.** Nothing outside these four validators attests
  to this history, so the anchor row reads **absent**.
- **The rule document ↔ enforced fields link is only partly on-chain.**
  Solidity cannot parse JSON. The independent verifier closes it (check 1b).
- **The dashboard's role accounts are not real custody.** Its Authority,
  Committee and council actions are signed with keys derived from the public
  Hardhat test mnemonic and shipped to the browser, which is safe only because
  this chain has a zero gas price and nothing of value on it. A bid is the
  exception: it is submitted from a wallet generated in the tab. Committee
  secret shares live in browser storage, because the dealer is trusted.
- **BN254 is not 128-bit secure.** Nearer 100 bits. It is the curve the EVM
  precompiles fix.

---

## The independent verifier

Everything else asks you to believe a screen. This asks you to believe nothing.

```bash
npm run verify -- evidence/<bundle>.json
```

Sixteen checks re-derived from the bundle alone, each printing the value it
derived. It shares no code with the dashboard beyond the crypto package, and it
reimplements the forbidden-field scan rather than importing the exporter's — a
verifier using the producer's own definition of "forbidden" would agree with it
by construction.

`npm run test:verifier` feeds it **31 deliberately corrupted bundles** — a
flipped bit in each proof type, a removed bid, an extra leaf, re-ordered
leaves, a stale root, a forged replica signature, a share submitted before the
deadline, a price published under a concealing policy, three kinds of smuggled
secret — and asserts each fails on the **right** check. A verifier that rejects
everything cannot tell an auditor what went wrong.

The bundle is deterministic: two exports at the same block are byte-identical,
asserted by the exporter itself. Every value is chain-derived, including the
proofs, which are recovered by decoding transaction calldata.

---

## Layout

```
packages/crypto        the single TypeScript implementation of the encoding spec
packages/circuits      three Circom circuits, their ceremonies and fixtures
packages/contracts     Solidity, 350 tests
packages/verifier      the independent CLI
apps/dashboard         four role views, all three circuits proved in-browser
scripts/firms          three sample firms, for `npm run tender:complete`
services/ciphertext-store   one replica; three run independently
services/evidence      the deterministic bundle exporter
infrastructure/besu    four-validator QBFT network
docs/                  the frozen encoding spec, cryptography, per-stage evidence
```

## Documentation

| Document | What it covers |
|---|---|
| `SETUP.md` | Clean clone to a working procurement in a browser. Start here. |
| `DEPLOY.md` | Putting it on a server, and why a public instance is a sandbox. |
| `DEMO.md` | The walkthrough: authority, bidder, verifier, committee, bidder again. |
| `docs/field-encoding.md` | The frozen spec. One interface across TypeScript, Circom and Solidity. |
| `docs/cryptography.md` | Primitives, the ceremony, and what none of it guarantees. |
| `docs/benchmarks.md` | Every measured constraint count, gas figure and test total. |
| `docs/stage*-evidence.md` | Per-stage findings, including the bugs and what caused them. |

The stage evidence documents record defects that were found and fixed, with the
reasoning. They are not a changelog — a stage that found nothing would be a
stage whose tests were too weak.

## Verifying the build

```bash
npm test                    # 578 unit tests
npm run ceremony:verify     # 28 checks, per circuit
npm run test:e2e:opening    # the full lifecycle on the live chain
npm run test:storage        # kills a real replica process
npm run test:network        # halts consensus, then recovers it
npm run test:dashboard      # every dashboard read path
npm run test:ui             # the dashboard renders, in a real browser
npm run test:verifier       # 31 corrupted bundles
```

---

## Security notes

The role accounts derive from the **public Hardhat test mnemonic** — a
deliberately well-known key that can never be mistaken for a secret. Never
reuse it on any real network. Validator keys, generated secrets, committee
shares and `deployments.json` are gitignored.

No private witness, data-encryption key, subject secret, bid nonce or unopened
bid value appears in calldata, events, storage, logs or the evidence bundle.
An automated check enforces it, and the corruption suite tests that the check
works.

**This is an unaudited prototype on a local network.** Do not use it to run a
real procurement.
