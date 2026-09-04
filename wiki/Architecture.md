# Architecture

## Repository layout

```
packages/crypto        the frozen field-encoding spec, in TypeScript
packages/circuits      3 Circom circuits, the ceremony, fixtures
packages/contracts     11 Solidity contracts + Hardhat suites
packages/verifier      the independent CLI: 16 checks, offline
apps/dashboard         the 5-role interface (Vite + React)
services/ciphertext-store  a replica; three run at once, quorum 2
services/evidence      the deterministic bundle exporter
infrastructure/besu    the 4-validator QBFT network
tests/integration      live-network suites
docs/                  the frozen spec, cryptography, benchmarks, per-stage evidence
```

## The contracts

| Contract | Role |
|---|---|
| `Governance` | 3-of-4 council with a timelock |
| `IssuerRegistry` | Accredited certifying bodies, epochs, revocation roots |
| `TenderRegistry` | Rule documents, the rules hash, dates, committee appointment |
| `EligibilityVerifier` | Groth16 verification bound to tender state |
| `SealedBid` | Accepted bids and the bid-set accumulator |
| `OpeningManager` | 3-of-5 threshold decryption, DLEQ verified on-chain |
| `DeadlineStatus` | Close-time standing proofs |
| `AwardManager` | The award, proved over the complete set |
| `WinnerIdentity` | Ownership of the winning bid, before any name |
| `BondEscrow` | Bid security |
| `CheckpointAnchor` | State fingerprints (external anchoring unimplemented) |

Every one is inside the **EIP-170** 24,576-byte limit; the largest,
`TenderRegistry`, is 15,064 bytes.

> **`viaIR` must stay off, with `optimizer.runs = 1`.** With `viaIR: true` the
> linked PoseidonT6 compiled to 121,884 bytes — five times the limit.

## The circuits

| Circuit | Constraints | Public signals | Proves |
|---|---|---|---|
| `eligibility` | 19,233 | 12 | A firm meets every published requirement |
| `award` | 35,665 | 8 | The winner is the lowest qualified price over the complete set |
| `winner_identity` | 11,391 | 5 | The firm publishing its name placed the winning bid |

All three prove **in the browser** via snarkjs — no witness reaches a server,
because there is no server to reach.

## One spec, three languages

`docs/field-encoding.md` is frozen, and TypeScript, Circom and Solidity are each
tested against it. A value encoded by one is decodable by the others; a
disagreement is a test failure, not a runtime surprise.

## The dashboard

Five workspaces; the top bar switches role, the sidebar lists that role's
sections. The tender under discussion is shared across all of them.

| Role | Sections |
|---|---|
| **Public** | Ongoing tenders · Results · Integrity report |
| **Bidder** | Available tenders · My company · Submit bid · My bids |
| **Certifying body** | Issue a credential · This body |
| **Authority** | Create tender · All tenders · Bid opening · Award |
| **Auditor** | Verification |

Design rule: hashes, roots, transactions and block numbers live in a 12 px strip
at the **foot** of a card, never as a headline. The Auditor is the one screen
allowed to look like cryptography.

## Endpoints are build-time configuration

`contracts.json` records the loopback addresses the sync script saw. Served from
a host, `127.0.0.1` is the *visitor's* machine. So the bundle takes templates:

```bash
VITE_RPC_URL_TEMPLATE="/rpc/{n}"
VITE_STORE_URL_TEMPLATE="/store/{n}"
```

`{n}` is 1-based. A template starting with `/` resolves against whatever origin
served the page — so one build works on an IP, behind a tunnel, and on a domain
with TLS, **without rebuilding**. Unset means loopback, which is what local
development wants.

## Verification has two independent surfaces

1. **The Auditor view** recomputes, in the reader's own browser from chain state:
   the rules hash; the rule document against the enforced fields; every bid leaf
   and the rebuilt accumulator; the committee dealing; the award's binding to the
   live set; the identity commitment.
2. **The CLI verifier** re-derives **16 checks** from an exported evidence bundle
   with no access to the chain, the dashboard, or us. `npm run test:verifier`
   corrupts a bundle 31 ways and asserts each is caught by the right check.

The second exists because the first is still *our* code. A reviewer who does not
trust the dashboard can generate the bundle themselves and check it elsewhere.
