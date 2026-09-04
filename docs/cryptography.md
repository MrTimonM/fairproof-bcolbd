# FairProof cryptography, and what it does not guarantee

Required by development plan Section 11B.2. Every limitation named here is
also named in the whitepaper, so stating it plainly costs nothing and omitting
it would cost credibility.

Companion documents: `field-encoding.md` is the frozen interface between the
TypeScript, Circom and Solidity implementations; `stage4-evidence.md` records
the measured results of the trusted setup and the verifier adapter.

---

## 1. Primitives

| Purpose | Primitive | Where |
|---|---|---|
| Statement proofs | Groth16 over BN254 (`alt_bn128`) | Circom 2.2.2, snarkjs 0.7.5 |
| Hashing inside circuits | Poseidon, arities 2 to 6 | `circomlib` / `circomlibjs` / `poseidon-solidity` |
| Credential signatures | EdDSA over BabyJubjub, Poseidon-based | issuer signs `credDigest` |
| Rule-document commitment | keccak256 over RFC 8785 JCS bytes | recomputed on-chain |
| Threshold opening | ElGamal on BabyJubjub, Feldman VSS, Chaum-Pedersen DLEQ | 3-of-5, see Section 6 |

BN254 is chosen because it is the curve the EVM's pairing precompiles support.
BabyJubjub is chosen because it is the curve whose scalar field matches BN254,
which is what makes an issuer signature verifiable *inside* the circuit rather
than merely alongside it.

**BN254 is not 128-bit secure.** Advances in the tower-number-field-sieve
place its security nearer 100 bits. It remains the standard choice for
EVM-verified proofs because the precompiles fix the curve, and the whitepaper's
threat model does not assume more. It should not be described as 128-bit.

### Field encoding

The BN254 scalar field is about 254 bits; every keccak digest is 256. Digests
are therefore truncated by **discarding the low 8 bits** (`uint256(d) >> 8`),
never by `mod p`. Modular reduction would let an attacker search for two
digests that collide in the field, invisibly, inside a witness. `rulesHash`
travels as two 128-bit limbs instead, so it is carried losslessly and the
verifier adapter can reconstruct and compare the full 32 bytes.

---

## 2. The Groth16 trusted setup

Groth16 needs a per-circuit setup. Whoever runs it learns secret values -
"toxic waste" - and anyone retaining them can forge a proof for **any**
statement in that circuit, including eligibility they do not have. This is
inherent to Groth16, conceded in whitepaper Table 11, and the reason the
whitepaper commits to a published ceremony and an eventual PLONK-family
migration.

### Phase 1

The published Hermez powers-of-tau, `powersOfTau28_hez_final_17.ptau`
(power 17, capacity 131,072 constraints). We deliberately do **not** generate
our own phase 1: a phase 1 produced by this project would be worth nothing,
because we would be the only participants.

The file is pinned by sha256 in `packages/circuits/ceremony/ptau.json`, and
`snarkjs powersoftau verify` checks its internal contribution chain
cryptographically. The checksum says *which* file; the chain verification is
what proves it is a real ceremony output, and it does not depend on trusting
us.

### Phase 2

Run per circuit by `packages/circuits/scripts/ceremony.mjs`, which exposes the
real protocol as separate commands - `init`, `contribute`, `finalize` - so
different people can contribute from different machines with their own
entropy. Contributor entropy is never written to disk and never appears in the
transcript.

Finalization applies a beacon from **drand** (League of Entropy). A beacon
must be unpredictable at contribution time and publicly re-checkable
afterwards. A value this project controls - a block hash from our own Besu
chain, for instance - would satisfy neither, which is why the beacon is
external and the transcript records the round number so anyone can re-fetch
it.

### THE HONEST STATEMENT

**The ceremony in this repository is not a production ceremony.**

The published transcript, `packages/circuits/ceremony/eligibility.transcript.json`,
records exactly what happened:

- three phase-2 contributions,
- `independent: false` for all three - every contributor is a project member,
- `singleMachine: true` - all three contributions were produced on one
  machine by `ceremony all`.

That last flag is the one that matters. One machine saw all three
contributors' entropy. **If that machine was compromised, or if its operator
retained the secrets, forged eligibility proofs would be possible** - a bidder
could prove they meet requirements they do not meet, and no on-chain check
would detect it. The soundness of every eligibility proof in this prototype
rests on that assumption.

What the ceremony *does* establish, and what a reviewer can check for
themselves with `npm run ceremony:verify`:

- the parameters really are the published phase 1 plus these three recorded
  contributions plus this drand beacon, applied to this exact circuit;
- the circuit source has not changed since;
- the committed Solidity verifier is byte-identical to a fresh export from
  those parameters, so no constant was hand-edited.

Production requires a ceremony with many independent contributors, at least
one outside any single organisation, published before the system carries real
tenders. Whitepaper Table 11 already commits to that and to a PLONK-family
migration once the circuit stabilises, which removes the per-circuit setup
entirely.

### Version pinning

Each tender freezes a `verifierVersion` in its fields digest at activation.
`EligibilityVerifier` keeps one **immutable** verifier per version, registered
only through a 3-of-4 council proposal whose payload is fixed at proposal time
and public for the whole timelock. There is no default and no fallback: a
tender pinned to an unregistered version reverts rather than silently
resolving to the newest verifier. Registering a new version cannot affect a
running tender, because the lookup is by the tender's own pin and records are
never overwritten (whitepaper Section 14).

---

## 3. What the eligibility proof does and does not say

It says: the holder of a credential signed by an issuer in the published
registry, unrevoked at the credential epoch's revocation root, meets the
tender's turnover, experience, certification and validity requirements, and is
bound to this nullifier and bid commitment.

It does **not** say who they are, and it does not say the credential's
contents are true. A credential asserting a turnover the firm does not have
produces a perfectly valid proof. **Zero-knowledge proofs move trust; they do
not remove it.** The protocol's guarantee is that the *rules were applied as
published*, not that the underlying facts are accurate - the issuer is still
the trust anchor for that.

### The signals are the contract's, not the caller's

The generated Groth16 verifier proves only that *some* assignment of the
twelve public signals satisfies the circuit. It knows nothing about tenders.
`EligibilityVerifier.verifyEligibility` therefore accepts only the tender id,
the nullifier and the bid commitment, and reads the other ten signals out of
storage.

An adapter that accepted a caller-supplied signal array and checked part of it
would be the classic failure of this construction: the proof verifies, the
signature is valid, the tests are green, and the bidder proved eligibility
against a turnover threshold of one taka that they chose themselves. The test
suite contains exactly that proof (`weakThresholds`), demonstrates that the
raw verifier accepts it, and shows the adapter rejecting it.

---

## 4. Credentials

`credDigest` is computed in a fixed field order over two Poseidon-6 and
Poseidon-5 halves combined with Poseidon-2, defined once in
`field-encoding.md` Section 8. The issuer signs that digest with EdDSA over
BabyJubjub. The issuer-registry leaf commits to **both** public-key
coordinates, so a prover cannot substitute a different curve point that shares
one coordinate.

Credentials reference an **issuer epoch**, so a key compromise is contained to
one epoch rather than requiring the revocation of every credential that issuer
ever signed.

Revocation uses a sparse Merkle tree of depth 32 keyed by credential id, where
a **zero leaf proves non-revocation**. Zero is the correct empty value here -
unlike the bid tree, where a zero leaf is indistinguishable from an empty
subtree and the padding leaf is `DOMAIN_PADDING_V1` instead.

---

## 5. Domain separation

Every hash is domain-separated by a constant derived from a distinct label
(`FairProof:cred:v1`, `:leaf:v1`, `:padding:v1`, `:nullifier:v1`,
`:bidcommit:v1`, `:subject:v1`, `:tenderId:v1`). Without this, a value hashed
in one role could be replayed in another - a bid commitment reinterpreted as a
tree leaf, for instance. The `v1` suffix exists so a future change to any
structure produces different digests instead of colliding with old ones.

---

## 6. Two different thresholds, never conflated

| | Threshold | Protects | Whitepaper |
|---|---|---|---|
| **Opening committee** | 3-of-5 threshold ElGamal | the key that opens sealed bids | Section 6, Table 4 |
| **Storage receipts** | 2-of-3 replicated storage | availability of the ciphertext | Section 4, Table 4, Figure 5 |

These are separate mechanisms with separate constants, labels and tests. Three
storage replicas cannot open a bid, and three committee members cannot make a
ciphertext available.

### The dealing is verified on-chain

The committee key is **dealt at tender activation by a script using Feldman
verifiable secret sharing** (`npm run committee:deal`), not produced by a
run-time distributed key generation protocol.

`TenderRegistry.setCommitteeKey` does not merely record the dealing; it
**verifies** it, using `lib/BabyJubjub.sol`:

- the public key `Y` is on BabyJubjub **and** in the prime-order subgroup;
- `Y` equals commitment `C_0` (which it must, since `C_0 = a_0 * G` and `a_0`
  *is* the secret) - otherwise bidders would encrypt to a key the shares
  cannot open, and every bid in the tender would be permanently unopenable;
- every commitment is a curve point;
- every member's public share satisfies `Y_i = Σ_j i^j · C_j`, so a share
  cannot be inconsistent with the commitments, and two members' shares cannot
  be swapped between indices.

The subgroup check is separate from the curve check for a reason. BabyJubjub's
group order is `8 · SUB_ORDER`, so a point can satisfy the curve equation while
carrying a small-order component, and encrypting to such a point leaks
information about the plaintext. Every bidder encrypts to this key, so it is
checked before any of them can.

Member indices are **1-based**. Index 0 evaluates the polynomial at zero,
which is the secret itself.

### Trusted dealer

The on-chain verification narrows the residual to exactly one thing: **the
dealer briefly knows the tender secret** before destroying it. It can no
longer deal inconsistent shares, publish a key the shares cannot open, or hand
a member someone else's share.

Members hold real shares, decryption shares are individually verifiable by
anyone via Chaum-Pedersen DLEQ proofs, and reconstruction genuinely requires
three members. Label this everywhere as "verifiable threshold opening with a
trusted dealer (prototype); production requires DKG". Whitepaper Section 19.1
concedes the same.

The ceremony script prints its destruction step, overwrites its copies of the
secret, and never writes `x` to disk - but a script cannot *prove* it destroyed
something. Only DKG, where no party ever holds `x`, removes the assumption.

A committee member checks their own share with
`npm run committee:verify -- <tenderId> <index>`, which reports three values
and says which comparison failed: `Y_i` recomputed from the commitments, `Y_i`
as published, and `share · G`. A wrong *published* `Y_i` is caught on-chain
too; a wrong *secret* share is invisible on-chain and would surface only as a
failed opening, which is why the member must check it locally.

The bidder deliberately does **not** split its own key. A bidder acting as its
own dealer could hand out inconsistent shares and make its bid permanently
un-openable, breaking the completeness the award proof depends on.

### Early opening is not detectable

The on-chain opening events evidence the **official** ceremony. Three
colluding committee members could exchange shares privately and open bids
early, and nothing on-chain would reveal it. Whitepaper Sections 4 and 19.5
concede this; the UI states it wherever the threshold is displayed.

---

## 7. Verifying all of this yourself

```
npm run ceremony:verify                    # 28 checks, seconds
npm run ceremony:verify eligibility --verify-phase1   # adds the phase-1 chain
npm run circuits:test                      # 43 tests, all nine clauses
npm run contracts:test                     # 197 tests
npm run encoding:test                      # 124 crypto and VSS tests
npm run test:e2e:proof                     # a real proof, on the live chain
```

`ceremony:verify` is written to trust the transcript for nothing except the
claims it is checking, and each check's comment names what it would catch.
