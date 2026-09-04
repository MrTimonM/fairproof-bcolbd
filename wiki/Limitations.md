# Limitations

Published here because a protocol that hides its residual risk is asking for
exactly the trust it set out to remove. All of it is also in
`docs/cryptography.md` and the whitepaper.

## The trusted setup is weak

The Groth16 phase-2 ceremony ran on a **single machine with no independent
contributors**. Whoever holds that material could forge a proof for any of the
three circuits.

This is the standard Groth16 requirement, and the remedy is **operational, not
research**: a multi-party ceremony with N independent contributors, each
publishing an attestation. `npm run ceremony:verify` already checks the
transcript chain 25/25 — what is missing is other people in it.

## Credentials are attested, not verified

A proof shows that an **approved certifying body attested** figures meeting the
thresholds. It cannot show the figures are *true*. No zero-knowledge system can:
ZK proves statements about data, not about the world.

That is the same trust a procuring office already places in an audited
statement. What changes is that the figures no longer have to be *handed around*
to be checked. Say **attested**, never *verified*.

## Three colluding committee members break confidentiality

The threshold is 3 of 5. Three members acting together could open bids early,
and **nothing on-chain would show it**. The protocol protects against two, not
three.

## The committee key has a trusted dealer

Shares are dealt, and the dealing is verified on-chain against its commitments —
but a dealer exists. Only distributed key generation removes this.

## No external checkpoint anchor

The auditor view reports this row as **absent**, not pending. A checkpoint
recorded only on the chain it describes is worth nothing against that chain's
own operators. Anchoring to an independent chain is unimplemented.

## Revocation needs an off-chain list

`IssuerRegistry` publishes only `(epoch, root)` and **never which credential was
revoked** — correct, since the ids would leak. But it means a browser cannot
rebuild the revocation tree from chain data alone, so revocation is driven by
scripts rather than from the certifying-body UI.

## Rule document ↔ enforced fields is checked off-chain

Solidity cannot parse JSON. That the human-readable rule document says what the
circuit enforces is closed by the verifier and the auditor view, not by the
chain. It is the one guarantee the chain delegates — and the check exists
precisely so the delegation is honoured rather than assumed.

## Curve strength

BN254 is nearer **100-bit** than 128-bit security under current estimates.

## Capacity, deliberately

- **32 bids** per tender (the award circuit is padded to a fixed width)
- **16** accredited issuers, at issuer-tree depth 4
- A **permissioned** chain with four validators and a zero gas price

## A public instance is a sandbox

`dashboard:sync` writes **16 role private keys** into the browser bundle so any
role can sign without a wallet. On a public URL that means every visitor holds
every role, including a 3-of-4 council majority, and there is one shared chain
with no per-visitor reset. See
[`DEPLOY.md`](https://github.com/MrTimonM/fairproof-bcolbd/blob/main/DEPLOY.md).

## One case that looks like a bug and is not

If the cheapest bidder was **revoked** as of the deadline, the tender becomes
**unawardable** rather than awardable to the second cheapest. The remedy is
cancellation and reissue. Awarding around a revoked low bid would be exactly the
discretion this protocol exists to remove.
