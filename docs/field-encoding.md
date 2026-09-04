# FairProof Field Encoding Specification

**Status: FROZEN.** Version `1.0.0`.

This document is the single interface between TypeScript, Circom and Solidity. It is frozen
in Stage 0 per development plan Section 11A, before any circuit or contract code is written.
Every change here is a breaking protocol change requiring a version bump and a re-run of the
cross-language equality test.

Why this document exists: the BN254 scalar field is ~254 bits and every hash the whitepaper
specifies is 256 bits. Getting this wrong produces a system that compiles, runs, passes the
happy path, and is subtly unsound.

## 1. Curve and field

- Proving system: Groth16 over **BN254** (alt_bn128), as used by snarkjs and by the EVM
  precompiles at 0x06/0x07/0x08.
- Scalar field prime:
  `p = 21888242871839275222246405745257275088548364400416034343698204186575808495617`
- `p` is 254 bits. The largest safe unsigned width for an unreduced value is **248 bits**
  (31 bytes), which is the width this specification uses for every truncated digest.
- Signature curve: **BabyJubjub**, whose base field is the BN254 scalar field. That is why
  EdDSA-BabyJubjub can be verified inside a BN254 circuit.

## 2. Truncation rule for 256-bit digests

Whenever a keccak256 or SHA-256 digest must become a field element:

```
toField(d) = uint256(d) >> 8        // keep the high 248 bits
```

Right-shift, **not** `mod p`. Modular reduction is forbidden: distinct digests can map to
the same residue in a way an attacker can search, and the reduction is invisible in the
resulting witness.

Truncation to 248 bits is sound here because these values are used for *binding and
comparison*, not for collision resistance beyond 2^124. Any change to a bound value changes
the field element with overwhelming probability, which is the only property the protocol
relies on.

## 3. Domain separation

Every hash gets a distinct domain constant, so a digest computed for one purpose can never
be reinterpreted as another.

```
DOMAIN_CRED_V1        = toField(keccak256("FairProof:cred:v1"))
DOMAIN_TENDER_ID_V1   = keccak256("FairProof:tenderId:v1")        // raw 32 bytes
DOMAIN_CIPHERTEXT_V1  = keccak256("FairProof:ciphertext:v1")      // raw 32 bytes
DOMAIN_RECEIPT_V1     = keccak256("FairProof:receipt:v1")         // raw 32 bytes
DOMAIN_LEAF_V1        = toField(keccak256("FairProof:leaf:v1"))
DOMAIN_PADDING_V1     = toField(keccak256("FairProof:padding:v1"))
DOMAIN_NULLIFIER_V1   = toField(keccak256("FairProof:nullifier:v1"))
DOMAIN_BIDCOMMIT_V1   = toField(keccak256("FairProof:bidCommitment:v1"))
DOMAIN_SUBJECT_V1     = toField(keccak256("FairProof:subject:v1"))
```

Constants are derived by `packages/crypto/src/domains.ts` and asserted against committed
literals in the test suite, so they cannot drift.

## 4. `rulesHash` - two 128-bit limbs

`rulesHash = keccak256(JCS(ruleDocument))` is 32 bytes and does **not** fit one field
element. It travels through the circuit as two limbs:

```
rulesHashHi = uint128(uint256(rulesHash) >> 128)
rulesHashLo = uint128(uint256(rulesHash) & ((1 << 128) - 1))
```

Both are public signals. The verifier adapter contract **reconstructs** the 32-byte value
from the two limbs and compares it to the tender's stored `rulesHash`, reverting on
mismatch. The contract must never accept limbs it did not itself derive from stored state.

Limbs rather than truncation, because `rulesHash` is what the entire immutability claim
rests on and is compared against a full 32-byte on-chain value. Limbs are lossless.

## 5. `tenderIdField`

`tenderId` is a human-readable string such as `FP-00014`.

```
tenderIdField = toField(keccak256(DOMAIN_TENDER_ID_V1 || utf8(tenderId)))
```

`||` is byte concatenation: the 32-byte domain constant followed by the UTF-8 bytes of the
identifier. The contract stores both the string and the derived field element, and checks
the derivation on-chain at activation.

## 6. `ciphertextHashField`

```
ciphertextHash      = keccak256(DOMAIN_CIPHERTEXT_V1 || canonicalCiphertextBytes)
ciphertextHashField = toField(ciphertextHash)
```

The full 32-byte `ciphertextHash` is stored on-chain for integrity comparison; the field
form enters the bid leaf. `canonicalCiphertextBytes` is defined in Section 11.

## 7. Poseidon

- Implementation: `circomlib` Poseidon over BN254 - the same constants used by `circomlibjs`
  and by generated Solidity.
- Arities used in this project: **1 through 6**. Never exceed 6.
- For more inputs, use the fixed tree in Section 8. Never invent ad-hoc chaining at a call
  site.

## 8. `credDigest` - the issuer signature message

The whitepaper (Section 4) signs
`(subjectCommitment, T, E_m, certValidUntil, issuedAt, credentialId, issuerEpoch)`.
EdDSA-Poseidon signs one field element, so the digest is pinned as a fixed two-level
Poseidon tree. **This field order is canonical.** Any reordering between the TypeScript
issuer and the Circom verifier produces a signature failure that looks like a curve bug and
costs days.

```
h1 = Poseidon6(
       DOMAIN_CRED_V1,
       schemaVersion,           // = 1 for this release
       subjectCommitment,
       annualTurnover,          // T,   uint64, BDT taka
       relevantExperience,      // E_m, uint32, months
       certificationCode        // uint64
     )

h2 = Poseidon5(
       certValidUntil,          // uint64, UTC unix seconds
       credentialValidUntil,    // uint64, UTC unix seconds
       credentialId,            // uint64
       issuerEpoch,             // uint32
       issuedAt                 // uint64, UTC unix seconds
     )

credDigest = Poseidon2(h1, h2)
```

## 9. `subjectCommitment` and `nullifier`

Per whitepaper Section 5 clauses 4 and 8:

```
subjectCommitment = Poseidon2(DOMAIN_SUBJECT_V1, subjectSecret)
nullifier         = Poseidon3(DOMAIN_NULLIFIER_V1, subjectSecret, tenderIdField)
```

`subjectSecret` is a 248-bit CSPRNG value, held only on the bidder's device and backed up by
the company. It is long-lived across tenders: reissuance must preserve `subjectCommitment`
so a firm cannot obtain a fresh nullifier for the same tender.

The domain constants as first input are a deliberate strengthening. The whitepaper's
notation omits domain separation; development plan Section 21.2 requires it, and without it
a `subjectCommitment` could be reinterpreted as a one-input hash elsewhere. Recorded as an
intentional superset, not a deviation in behaviour.

## 10. `bidCommitment`

Per whitepaper Section 5 clause 9 - four inputs plus the domain constant:

```
bidCommitment = Poseidon5(
                  DOMAIN_BIDCOMMIT_V1,
                  bidAmount,        // uint64, BDT minor unit
                  bidNonce,         // 248-bit CSPRNG, never reused
                  tenderIdField,
                  nullifier
                )
```

`bidNonce` is what makes the commitment hiding. Without it `Poseidon(7400000)` is grindable
in seconds (whitepaper Table 4, dictionary attack).

## 11. Canonical ciphertext bytes

The byte string `ciphertextHash` covers, in this exact order, all lengths fixed:

```
canonicalCiphertextBytes =
     version      (1  byte,  = 0x01)
  || R.x          (32 bytes, big-endian)   // ElGamal ephemeral point
  || R.y          (32 bytes, big-endian)
  || wrapped      (32 bytes)               // wrapped AES data-encryption key
  || iv           (12 bytes)               // AES-GCM IV, unique per key
  || ctLen        (4  bytes, big-endian uint32)
  || ct           (ctLen bytes)            // AES-256-GCM ciphertext
  || tag          (16 bytes)               // GCM authentication tag
```

## 12. Bid leaf and `bidSetRoot`

Per whitepaper Section 7 - **four** inputs plus the domain constant. `storageReceiptRoot` is
deliberately **not** in the leaf; it is stored in the bid record and checked at acceptance.

```
leaf = Poseidon5(
         DOMAIN_LEAF_V1,
         nullifier,
         bidCommitment,
         ciphertextHashField,
         submissionIndex        // uint8, < MAX_BIDS
       )
```

Accumulator - fixed-depth incremental binary Merkle tree:

```
MAX_BIDS   = 32
TREE_DEPTH = 5
zero[0]    = DOMAIN_PADDING_V1
zero[i]    = Poseidon2(zero[i-1], zero[i-1])
parent     = Poseidon2(left, right)
```

The padding leaf is `DOMAIN_PADDING_V1`, **not** zero. A zero leaf is indistinguishable from
an empty subtree and invites a completeness bypass. The empty-tree root is `zero[5]`.

## 13. `storageReceiptRoot`

Receipts ordered canonically by `replicaId` ascending, accumulated in a depth-2 tree
(capacity 4: three replicas plus one padding slot):

```
receiptLeaf_i = toField(keccak256(
                     DOMAIN_RECEIPT_V1
                  || uint8(replicaId)
                  || contentHash          (32 bytes)
                  || uint64(byteLength)
                  || signature            (65 bytes)
                ))
```

Missing replicas use `DOMAIN_PADDING_V1`. At least **two** distinct valid replica leaves are
required for acceptance.

## 14. Numeric ranges

Every comparison must be preceded by an explicit `Num2Bits` range constraint on **both**
operands. An unconstrained `LessThan` in Circom is not a comparison; a malicious prover
supplies a field element that wraps.

| Value | Type | Constraint |
|---|---|---|
| `annualTurnover` (T) | uint64, BDT taka | `Num2Bits(64)` |
| `turnoverThreshold` | uint64 | `Num2Bits(64)` |
| `relevantExperience` (E_m) | uint32, months | `Num2Bits(32)` |
| `experienceMonthsThreshold` | uint32 | `Num2Bits(32)` |
| `certificationCode` | uint64 | `Num2Bits(64)` |
| `certValidUntil` | uint64, UTC seconds | `Num2Bits(64)` |
| `credentialValidUntil` | uint64, UTC seconds | `Num2Bits(64)` |
| `deadline` | uint64, UTC seconds | `Num2Bits(64)` |
| `issuedAt` | uint64, UTC seconds | `Num2Bits(64)` |
| `credentialId` | uint64 | `Num2Bits(64)` |
| `issuerEpoch` | uint32 | `Num2Bits(32)` |
| `bidAmount` | uint64, BDT minor unit | `Num2Bits(64)` |
| `submissionIndex` | uint8, `< 32` | `Num2Bits(8)` + `LessThan` |
| `subjectSecret`, `bidNonce` | 248-bit | generated `< 2^248` |

Currency is **integer minor units only** - no floating point anywhere. Timestamps are UTC
Unix **seconds**, never milliseconds.

## 15. Merkle tree depths

| Tree | Depth | Capacity | Padding / empty leaf |
|---|---|---|---|
| Bid set (`bidSetRoot`) | 5 | 32 | `DOMAIN_PADDING_V1` |
| Issuer registry | 4 | 16 | `DOMAIN_PADDING_V1` |
| Storage receipts | 2 | 4 | `DOMAIN_PADDING_V1` |
| Revocation (sparse) | 32 | 2^32 credential ids | `0` - a zero leaf **proves** non-revocation |

The revocation tree is the one place a zero leaf is correct and load-bearing: whitepaper
Section 5 specifies "a zero-valued leaf proves non-revocation". It is a *sparse* tree keyed
by `credentialId`, so an all-zero subtree is the expected default rather than an ambiguity.

## 16. Public signal order - eligibility circuit

Order is part of the interface, because the Solidity verifier receives a flat array.

```
[0]  tenderIdField
[1]  rulesHashHi
[2]  rulesHashLo
[3]  turnoverThreshold
[4]  experienceMonthsThreshold
[5]  requiredCertificationCode
[6]  deadline
[7]  issuerRegistryRoot
[8]  revocationRoot
[9]  credentialEpoch
[10] nullifier
[11] bidCommitment
```

## 17. Public signal order - award circuit

```
[0] tenderIdField
[1] rulesHashHi
[2] rulesHashLo
[3] bidSetRoot
[4] submissionCount
[5] winnerCommitment
[6] winningPrice        // 0 when disclosurePolicy conceals it
[7] disclosurePolicy
```

## 18. Public signal order - winner identity circuit

```
[0] tenderIdField
[1] winnerCommitment
[2] nullifier
[3] legalIdentityCommitment
```

## 19. Enforcement

`packages/crypto` is the **only** TypeScript implementation of this specification. Circuits
and contracts must not re-derive any constant independently.

The cross-language equality test (development plan Section 11A.6) hashes a committed input
vector in TypeScript, Circom and Solidity and asserts byte-for-byte agreement for
`Poseidon`, `credDigest`, `nullifier`, `bidCommitment`, the bid `leaf`, and the empty-tree
`bidSetRoot`. **CI blocks on this test, and Stage 1 does not begin until it passes.**

---

## Sections 20-22: additions for the sealed-bid stage

Nothing in Sections 1-19 changed. These sections define encodings that did not
exist when the spec was frozen, for mechanisms the whitepaper describes but
which the earlier stages did not yet reach: the wrapped data-encryption key,
the Chaum-Pedersen challenge, and the storage-receipt signature. They follow
the same rules - a distinct domain constant per purpose, all lengths fixed, no
implicit encodings.

New raw domain constants:

```
RAW_DEK_V1         = keccak256("FairProof:dek:v1")
                   = 0x4d81339f62c86b8e778c8291fde69866126f324c401be831dea3c355d885c48d
RAW_DLEQ_V1        = keccak256("FairProof:dleq:v1")
                   = 0x90fcb89fb43b96167b00efaf2bbe93dea466b042c0be602817027df1ed2a572c
RAW_RECEIPT_SIG_V1 = keccak256("FairProof:receiptSig:v1")
                   = 0xc3ffb182dd3ebfe5535def6710ba4562e2bf2416e6ac55e4ac25fc7e14433ea3
```

`RAW_RECEIPT_SIG_V1` is deliberately distinct from `RAW_RECEIPT_V1`, which
separates the receipt *leaf*. One constant for both would let a leaf preimage
be presented as a signature preimage.

## 20. Wrapping the data-encryption key

The bidder encrypts the bid payload under a fresh AES-256 key `dek` and
encapsulates that key to the tender committee's public key `Y` (whitepaper
Section 6, plan Section 12.3):

```
r        <- random scalar in [1, SUB_ORDER)
R        = r * G                       // published, part of the ciphertext
S        = r * Y                       // shared secret, never published
k        = keccak256(RAW_DEK_V1 || S.x (32 bytes BE) || S.y (32 bytes BE))
wrapped  = dek XOR k                   // 32 bytes
```

The committee recovers `S` without reconstructing the tender secret: each
member `i` publishes `D_i = x_i * R`, and three of those interpolate in the
exponent to `x * R = S` (Section 21). Then `dek = wrapped XOR k`.

Both coordinates of `S` enter the KDF. Using only `S.x` would make `S` and
`-S` derive the same key, and the two are distinguishable to an attacker who
can choose points.

`r` must come from a CSPRNG and must never be reused: two bids sharing `r`
under one tender key share `k`, and the XOR of their `wrapped` values reveals
the XOR of their DEKs.

## 21. Chaum-Pedersen DLEQ challenge

A decryption share is only useful if anyone can check it came from the member
who published `Y_i`. The member proves `log_G(Y_i) = log_R(D_i)` without
revealing `x_i`:

```
w  <- random scalar in [1, SUB_ORDER)
A  = w * G
B  = w * R
e  = keccak256(
         RAW_DLEQ_V1
      || G.x || G.y || Y_i.x || Y_i.y      // the first statement
      || R.x || R.y || D_i.x || D_i.y      // the second statement
      || A.x || A.y || B.x   || B.y        // the commitments
     ) mod SUB_ORDER                        // each coordinate 32 bytes BE
z  = (w + e * x_i) mod SUB_ORDER
```

Verification, which the contract performs:

```
z * G == A + e * Y_i      and      z * R == B + e * D_i
```

The challenge covers **both** statements and both commitments. Omitting `R` or
`D_i` would let a proof for one ciphertext be replayed against another.

The reduction `mod SUB_ORDER` biases the challenge negligibly and is the
standard Fiat-Shamir construction; `SUB_ORDER` is used because the exponents
live in the scalar field of the prime-order subgroup, never modulo the field
prime.

## 22. Storage-receipt signature

Each replica signs with its own registered secp256k1 key, over:

```
receiptSigDigest = keccak256(
                       RAW_RECEIPT_SIG_V1
                    || uint8(replicaId)
                    || contentHash        (32 bytes)
                    || uint64(byteLength)
                   )
```

The signature is the 65-byte `r || s || v` form, so the contract recovers the
signer with `ecrecover` and compares against the replica's registered address.

`contentHash` is the `ciphertextHash` of Section 6, so the signature binds the
replica's acknowledgement to the exact bytes the bidder submitted on-chain.

**What the signature does NOT cover, stated plainly:** the `objectId` and
`storedAt` fields of a receipt as returned over HTTP. `objectId` is therefore
defined to *equal* `contentHash`, so it carries no independent information and
nothing is lost by leaving it uncovered. `storedAt` is replica-reported
convenience metadata; the authoritative time is the block timestamp of the
accepting transaction. Adding either to the digest would change
`receiptLeaf`'s meaning without adding a guarantee.

## 23. Winner identity binding

Added for build-order step 15. Development plan Section 9.7: a small circuit
proves the winner controls the winning bid *and* is the holder of the
issuer-signed credential, before any legal identity is displayed.

New domain constants:

```
RAW_IDENTITY_RECORD_V1 = keccak256("FairProof:identityRecord:v1")
                       = 0x57ee84a2a6b343e653337bb04cf73864645746f8b4f0ec3829e1c0493c421fc1
DOMAIN_IDENTITY_V1     = toField(keccak256("FairProof:identity:v1"))
                       = 350255550607654703349396198304734656087699665840881769065044796263778895484
```

The two are deliberately distinct. `RAW_IDENTITY_RECORD_V1` separates the
keccak over the published record; `DOMAIN_IDENTITY_V1` separates the Poseidon
commitment the circuit proves. Sharing one constant between a keccak preimage
and a Poseidon input is the reuse domain separation exists to prevent.

### The published record

The winner publishes a canonical JCS record naming itself:

```json
{
  "credentialId": 1042,
  "legalName": "...",
  "registrationNumber": "...",
  "tradeLicence": "...",
  "vatBin": "..."
}
```

```
legalIdentityHash = toField(keccak256(RAW_IDENTITY_RECORD_V1 || JCS(record)))
```

### The commitment

```
legalIdentityCommitment = Poseidon2(
                              Poseidon2(DOMAIN_IDENTITY_V1, credentialId),
                              legalIdentityHash
                          )
```

Two nested arity-2 hashes rather than one arity-3, so no third Poseidon
library has to be deployed on-chain — `PoseidonT3` is already linked. The
nesting order is fixed and part of this specification.

`credentialId` is a **private** circuit input but is supplied to the contract
as ordinary calldata. The contract recomputes the commitment from the
calldata `credentialId` and the keccak of the published record, and compares
it to public signal 3. So the winner cannot swap the record or misstate the
credential id without breaking the comparison, even though neither value is a
proof signal.

### Public signal order — winner identity circuit

**Section 18 is amended here: a fifth signal was added during
implementation.**

```
[0] tenderIdField
[1] winnerCommitment
[2] nullifier
[3] legalIdentityCommitment
[4] issuerRegistryRoot        <- added
```

The reason is a soundness gap, not a convenience. With four signals the
circuit's issuer-registry membership check was **vacuous**: the prover
supplies both the Merkle path and the root it reconstructs to, so any key at
all can be made to "verify". A winner could mint their own issuer key, sign a
credential carrying somebody else's `credentialId`, and publish an identity
record naming it. They would still genuinely own the winning bid — but the
check that lets the *issuer* confirm the declaration, which is the only thing
bounding the honesty of a self-declared legal name, would be worthless.

Exposing the root lets the contract compare it against
`IssuerRegistry.issuerRegistryRoot(epoch)`, the same way the eligibility
adapter does, which makes the membership claim mean something.

This is recorded as an amendment rather than presented as the original design.
No other section changed.

### What this proves, and what it does not

**Proves:** the party publishing the record holds the `subjectSecret` behind
the winning bid's nullifier, that the same secret opens the
`subjectCommitment` in a credential signed by an issuer in the published
registry, and that the record and credential id are the ones bound into the
commitment.

**Does not prove** that the declared legal name is accurate. Nothing
cryptographic stops a party misdescribing itself; the record is the winner's
own declaration. What bounds it is that the record carries the `credentialId`,
so the issuer that signed that credential — and any auditor — can confirm the
declaration against the firm it actually issued to. The identity-linkage row
in the integrity report must say "linked to the credential holder", not
"legal identity verified".
