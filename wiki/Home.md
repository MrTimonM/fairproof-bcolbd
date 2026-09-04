# FairProof

**A zero-knowledge procurement integrity protocol.** Team Bind's entry to
Blockchain Olympiad Bangladesh 2026.

A firm proves it meets a tender's published requirements without revealing its
finances. Every bid stays unreadable until the deadline. Three of five committee
members open them. The winner is proved to be the lowest qualified price over
the complete set of bids. And anyone can re-check all of it without trusting us.

**Live system:** https://fairprocure.xyz

---

## Start here

| If you want to… | Read |
|---|---|
| Run it on your own machine | **[[Local Setup]]** — and `npm run doctor` first |
| Understand what it does, step by step | **[[Protocol Flow]]** |
| Put it on a server | **[[Deployment]]** |
| Know what it does *not* guarantee | **[[Limitations]]** |
| See the measured numbers | **[[Benchmarks]]** |
| Find your way around the code | **[[Architecture]]** |

---

## The problem, in one paragraph

Public procurement asks for two things that fight each other. To prove you
qualify, a firm hands over its audited accounts — which leak, to competitors and
to officials. To check an award was fair, the public wants to see the bids — but
a bid visible before the deadline lets a favoured firm undercut everyone by one
taka. Today both problems are managed with trust: sealed envelopes, a committee,
an audit afterwards. FairProof replaces the trust with cryptography, and keeps
the disclosure at zero.

## What is actually built

- **11 Solidity contracts**, every one inside the EIP-170 size limit
- **3 Circom circuits** — eligibility (19,233 constraints), award (35,665),
  winner identity (11,391) — all proving **in the browser**
- **A 4-validator Hyperledger Besu network** running QBFT, tolerating one
  Byzantine fault
- **3 ciphertext-store replicas** with signed receipts, quorum of 2
- **A 5-role dashboard** — public, bidder, certifying body, authority, auditor
- **A deterministic evidence bundle** and an independent verifier that re-derives
  **16 checks** without touching the dashboard or the chain
- **578 unit tests**, plus ten live-network suites

## The one number to remember

**Confidential documents disclosed: 0.** Not one financial statement changes
hands to award a tender. Not one losing bid is ever readable. And no official
can waive a rule, because no code path exists that would let them.
