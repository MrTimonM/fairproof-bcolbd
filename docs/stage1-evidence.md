# Stage 1 Evidence: Infrastructure

Development plan Section 24, Stage 1. **Quality gate: PASSED.**

Gate requirement: *"Clean network startup and health test passes three times
consecutively."* Plus the Section 7.3 network acceptance tests.

## Network profile

| Property | Value | Source |
|---|---|---|
| Client | Hyperledger Besu 25.7.0 | Whitepaper Section 19.1 pins this version |
| Consensus | QBFT | Whitepaper Table 6 |
| Validators | 4 | Whitepaper Section 9.2 |
| Chain ID | 20260 | Fixed for the competition |
| Block period | 2 s | `qbft-config.json` |
| Epoch length | 30000 | `qbft-config.json` |
| Request timeout | 4 s | `qbft-config.json` |
| Gas price | **0**, `zeroBaseFee` | Whitepaper Table 6: no gas token, no volatility |
| Block gas limit | 100,000,000 (`0x5F5E100`) | On-chain Poseidon is expensive (Stage 0 evidence) |
| Node allowlist | Enabled, 4 nodes | Plan Section 7.1 |
| Account allowlist | **Deliberately absent** | Whitepaper Section 9.3 - see below |
| JVM heap per node | 1 GB cap | Four unbounded JVMs would contend with the app |

## Validator identities

Whitepaper Section 9.2 names four institutions. **These are synthetic
prototype roles, not claims of real institutional participation** (plan
Section 7.2), and the UI must say so.

| # | Institution | RPC | WS | P2P | Container IP |
|---|---|---|---|---|---|
| 1 | Procurement Regulator | 8545 | 8555 | 30303 | 172.28.0.11 |
| 2 | Procuring Entity | 8546 | 8556 | 30304 | 172.28.0.12 |
| 3 | Independent Auditor | 8547 | 8557 | 30305 | 172.28.0.13 |
| 4 | Chamber of Commerce | 8548 | 8558 | 30306 | 172.28.0.14 |

## Section 7.3 acceptance tests

| Test | Result |
|---|---|
| All four nodes start successfully | PASS |
| Each node reports the expected chain ID | PASS - 20260 on all four |
| Identical genesis hash across nodes | PASS - one chain, not four |
| Validators visible through the QBFT RPC | PASS - `qbft_getValidatorsByBlockNumber` returns 4 |
| Blocks continue when one validator stops | **PASS** - head advanced with 3 of 4 |
| A transaction is finalized and visible from all active nodes | PASS - `count == 1` from all four |
| A restarted validator catches up correctly | PASS - rejoined and validator set restored to 4/4 |
| **Consensus halts with 2 of 4 down** | PASS - head 48 -> 48, tolerance bound is exactly 1 |
| Consensus resumes once quorum returns | PASS |
| An unknown node cannot join | Node allowlist enabled; peers limited to the 4 listed enodes |
| No repeated consensus errors in logs | PASS |

Run with `npm run network:health`, `npm run test:network`, `npm run test:deploy`.

## Byzantine fault tolerance, demonstrated

Whitepaper Section 9.2: *"QBFT tolerates floor((n-1)/3) Byzantine validators,
so four tolerate one faulty or malicious institution and no single institution
can halt the network or rewrite a finalised award."*

`tests/integration/network-fault-tolerance.mjs` stops validator 3, confirms the
remaining three keep finalizing, confirms the stopped node is genuinely
unreachable (so the test cannot pass vacuously), restarts it, and polls until
it has caught up and rejoined the validator set.

This is also a demo beat: stop a validator on stage and show blocks continuing.

**The bound is verified to be exactly one.** The test then stops a *second*
validator and asserts that consensus **halts**, because QBFT needs a
supermajority (3 of 4) to finalize. This check exists to keep the suite honest:
without it, the one-validator test could pass vacuously, and if the chain kept
producing blocks with two nodes down it would mean consensus was not requiring
a quorum at all - which would leave "no single institution can rewrite a
finalised award" resting on nothing. Whitepaper Section 19.5 already concedes
that a Byzantine quorum can affect liveness; this is the other side of that
coin, and it is a property rather than a defect. The test then restores the
quorum and confirms the chain resumes.

The test also waits for all four validators to be in sync *before* injecting a
fault, so it cannot report a false failure against a network still catching up
from a previous run.

Verified from a cold start: full teardown (`down -v` plus wiped node data and
config), fresh `network:setup`, then `network:health` **three times
consecutively HEALTHY**, followed by the fault-tolerance and deploy suites.

## Zero gas price is a privacy property, not just a cost choice

`tests/integration/deploy-smoke.mjs` creates a **fresh random address with zero
balance** and successfully sends a state-changing transaction from it.

This matters because whitepaper Table 4 lists metadata linkability as a
residual risk, noting that "a bond paid from a known corporate wallet ...
deanonymises the bidder even with perfect cryptography". On a chain where gas
is free, a bidder's fresh per-tender address needs no funding at all, so there
is no funding trail to correlate. On a public chain this channel would be
unavoidable.

The residual risks Table 4 names - RPC and timing correlation - remain, and are
still labelled PARTIAL.

## Why there is no account allowlist

Plan Section 7.1 and whitepaper Section 9.3. The **node** allowlist is enabled:
only the four listed enodes may peer. There is deliberately **no** account
allowlist, because Section 9.3 requires that "pseudonymous bidders/relayers may
submit only proof-valid transactions". An account allowlist covering bidders
would destroy pseudonymity and contradict the fresh-per-tender-address
mitigation above.

Administrative writes are gated by on-chain role instead. Anyone may submit a
bid transaction; the proof and the nullifier decide whether it is accepted.

## Operational notes for a clean machine

Three issues were hit and fixed; they will recur on any fresh setup, so they
are recorded rather than left as folklore:

1. **`static-nodes.json` requires IP addresses.** Besu rejects a container
   hostname in an enode URL outright. The compose file therefore assigns fixed
   IPs on a `172.28.0.0/16` bridge network, and `network-setup.mjs` writes those
   same IPs into the enode URLs. The two files must be kept in step.
2. **The Besu container must run as the host user.** `operator
   generate-blockchain-config` otherwise writes root-owned keys that the setup
   script cannot clean up.
3. **Chain data uses bind mounts, not named volumes.** A docker named volume is
   created root-owned, and Besu then fails with "Data directory is not
   writable". `network-setup.mjs` creates `nodes/<id>/data` with host ownership.
4. **The Besu image ships no `curl`, `wget` or `nc`.** The first healthcheck
   used `wget` and failed on every single probe with `wget: not found`. The
   chain was healthy throughout - `network:health` passed, blocks were
   advancing - but `docker ps` reported all four validators **unhealthy**, and
   any `depends_on: service_healthy` would have waited forever. `bash` IS in
   the image, so the healthcheck now speaks HTTP through bash's `/dev/tcp`.

   Worth recording for two reasons. A demo where `docker ps` shows four
   unhealthy validators undermines the infrastructure claim before a word is
   spoken. And it is a reminder that a health probe which never succeeds is
   indistinguishable from one that is merely unimplemented - the failure was
   silent for hours because the real health script disagreed with it.

## Secrets

No validator private key is committed (plan Section 5.1). `network:setup`
regenerates them, so a clean clone runs setup before `network:up`.

Role accounts are derived from the **public Hardhat test mnemonic**
(`test test ... junk`). Using a universally recognised test mnemonic is
deliberate: it is unmistakably not a real key, which is safer than inventing
our own and having someone mistake it for a secret.
