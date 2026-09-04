# FAQ

### What stops the authority just looking at the bids?

It can't. Bids are encrypted to a key split across five committee members, and
the contract refuses every decryption share until the deadline has passed.

### You typed those figures yourself — how was eligibility verified?

It wasn't *verified*, and no zero-knowledge system can verify a claim about the
world. The circuit checks that an **approved certifying body signed those exact
figures**, that its key is in the registry the council published, and that the
attestation was unrevoked at the deadline.

The trust in that body is the same trust a procuring office already places in an
audited statement. We removed the disclosure, not the auditor. Say **attested**,
never *verified*. See [[Limitations]].

### What if three committee members collude?

They could open bids early and nothing on-chain would show it. The threshold
protects against two, not three. We say so rather than claim otherwise.

### Why a blockchain and not a database?

Because the whole problem is that the operator controls the evidence. A database
the procuring authority administers cannot prove to a losing bidder that a
threshold was never edited or that a bid was not dropped. Four independent
institutions running validators can.

### Is it actually running, or a mock-up?

Running. `npm run test:network` stops a validator, shows the chain continuing at
three of four, and recovers it. `npm run test:ui` asserts every workspace renders
in a real browser. `npm run test:certify` drives the whole certification path
from browser to chain. The live instance is at https://fairprocure.xyz.

### Could this scale to real procurement?

32 bids per tender and a permissioned chain today — both deliberate for a
prototype. Proving is already under five seconds on a laptop, and it happens on
the bidder's machine, so it does not centralise as bidders are added.

### What about the trusted setup?

Our ceremony ran on a single machine with no independent contributors, so someone
holding that material could forge a proof. It is the standard Groth16
requirement and the fix is operational, not research: a multi-party ceremony with
N independent contributors. We publish this rather than wait to be asked.

### Why is one auditor check marked "Partial"?

Because no checkpoint has been anchored to a chain outside this project's
control. A checkpoint recorded only on the chain it describes is worth nothing
against that chain's own operators, so the row reads **absent** rather than
pending. Reporting it honestly is the point.

### Can a firm reuse one credential across many tenders?

Yes — until it expires or is revoked, and each tender re-judges its figures
against its own thresholds. Reuse does not make the firm trackable: the marker
published with a bid is `Poseidon(secret, tenderId)`, so ten tenders produce ten
unlinkable markers.

### What happens if a bidder loses its secret?

Nobody can confirm its standing, and the tender becomes permanently unawardable;
the remedy is cancellation and reissue. The same property that prevents the
authority acting on a bidder's behalf is what makes this unrecoverable.

### Why is the tender unawardable when the cheapest bidder was revoked?

Because awarding to the second cheapest would be exactly the discretion this
protocol removes. The remedy is cancellation and reissue. It looks like a bug
and is a decision.

### Can I run this without trusting your dashboard?

That is what the CLI verifier is for:

```bash
npm run evidence -- --tender <REFERENCE>
npm run verify -- evidence/<bundle>.json
```

Sixteen checks, re-derived from the exported record alone, with no access to the
chain, the dashboard, or us.
