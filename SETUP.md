# Running FairProof locally

From a clean clone to a working procurement you can click through in a browser.

Budget **about 45 minutes**, most of it unattended: a 145 MB download and a
phase-2 ceremony for three circuits. Everything after that is seconds.

---

## 1. Prerequisites

Four things `npm ci` will **not** install for you.

| | Why | Install |
|---|---|---|
| **Node 20+** | Workspaces, native fetch | See `.nvmrc` |
| **Docker + compose v2** | The four validators run in containers | `docker.io docker-compose-v2` |
| **circom 2.x** | Compiles the circuits. A Rust binary, not an npm package | [docs.circom.io](https://docs.circom.io/getting-started/installation/) |
| **~2 GB free disk** | Circuit build output is ~330 MB; chain data grows | — |

Check all of it at once:

```bash
npm ci
npm run doctor
```

`doctor` separates **MISS** (a tool you must install) from **TODO** (a build step
you have not run yet), and prints the exact command for each. Run it whenever
something behaves oddly — it is the fastest way to find a missing artifact.

---

## 2. Build the cryptography

```bash
npm run setup
```

That is four steps, and you can run them individually if you prefer:

```bash
npm run setup:ptau        # 145 MB Hermez powers-of-tau, sha256 pinned in the repo
npm run crypto:build      # TypeScript field-encoding library
npm run setup:circuits    # compile 3 circuits + phase-2 ceremony for each  <- the slow one
npm run contracts:compile # 27 Solidity files
```

**On `setup:ptau`.** We deliberately do not generate our own phase 1. This is
the published Hermez ceremony, and `packages/circuits/ceremony/ptau.json` pins
its sha256, so the download is *verified against a value committed here* rather
than trusted. A mismatch deletes the file and exits non-zero.

**On `setup:circuits`.** This is the long step (~30 min on a laptop). It produces
the proving and verification keys — roughly 330 MB that is deliberately not in
git. Confirm the result independently:

```bash
npm run ceremony:verify -- eligibility      # expect: VERIFIED, 25/25
npm run ceremony:verify -- award
npm run ceremony:verify -- winner_identity
```

> The ceremony in this repository ran on a **single machine with no independent
> contributors**. That is a real weakness, stated plainly in
> `docs/cryptography.md`: whoever holds that material could forge a proof. The
> remedy is a multi-party ceremony, which is operational work rather than
> research.

---

## 3. Run the tests

No chain required — these are the fastest proof that the checkout is sound:

```bash
npm test          # 578 tests: 158 crypto, 350 contracts, 70 circuits
```

Once a chain is up (next step), the live suites become available. The one worth
running first:

```bash
npm run test:verifier   # 31 deliberately corrupted evidence bundles
```

It confirms a pristine bundle passes all 16 checks, then corrupts it thirty-one
ways and asserts each corruption is caught **by the specific check meant to
catch it**.

---

## 4. Start the chain and deploy

```bash
npm run network:setup     # genesis + four validator keys
npm run network:up        # four Besu containers, QBFT
npm run network:health    # expect HEALTHY, 4/4, spread 0

npm run deploy            # 11 contracts, via real 3-of-4 governance + timelock
npm run replicas:start    # 3 ciphertext stores; the browser needs these
npm run replicas:status   # expect 3/3 up

npm run dashboard:sync    # ABIs, role keys, and the circuit assets the browser fetches
```

`deploy` takes a couple of minutes: registering the verifier goes through the
council's real 3-of-4 approval and waits out a 60-second timelock, rather than
being written directly.

> `npm run deploy` **wipes every tender** — there is no delete on a chain.
> Re-seed afterwards.

---

## 5. Seed a tender and open the app

```bash
npm run tender -- --window 3600     # one tender, ready to bid on
npm run dashboard:dev               # http://127.0.0.1:5173
```

Bidding opens 3½ minutes after publication — a mandatory review window the
contract enforces and nobody can shorten. That wait is the protocol working.

To skip straight to a finished procurement with three bidders and a declared
winner (about seven minutes, unattended):

```bash
npm run tender -- --reference RHD-2026-0400 --window 600
npm run tender:complete RHD-2026-0400
```

---

## 6. Click through it

Five workspaces in the top bar. The order that tells the story:

1. **Certifying body → Issue a credential** — attest a firm's figures against
   the subject commitment it gives you.
2. **Bidder → My company** — register, copy the commitment, import the
   credential. The figures then become read-only.
3. **Bidder → Submit bid** — first bid fetches 18 MB of circuit, then proves in
   ~1.6 s. Try lowering the turnover below the threshold first and watch the
   card flip to **Not qualified** with the button dead.
4. **Authority → Bid opening** — after the deadline: close, then open with three
   of five committee shares.
5. **Bidder → My bids → Confirm eligibility** — *only the bidder can do this*,
   and the award cannot be recorded until they have.
6. **Authority → Award → Declare winner**, then **Bidder → Publish identity**.
7. **Auditor → Verification → Recompute everything**, and **Public → Integrity
   report**.

Verify the whole thing outside the dashboard:

```bash
npm run evidence -- --tender RHD-2026-0400
npm run verify -- evidence/<bundle>.json     # 16 checks, no chain access
```

---

## Checking the UI actually renders

A green build proves nothing about whether the page comes up — two blank screens
here have shipped past a passing build. Puppeteer is deliberately not a hard
dependency, because it downloads a browser:

```bash
npm i --no-save puppeteer
npx puppeteer browsers install chrome-headless-shell

npm run dashboard:dev &     # must be running
npm run test:ui             # every workspace renders, no console errors
npm run test:certify        # the whole certification path, browser to chain
```

`test:certify` needs a tender that is **open for bidding**; it says so clearly if
the review window has not elapsed.

---

## If something breaks

| Symptom | Cause |
|---|---|
| `npm run doctor` shows **MISS** | A tool is missing. Nothing downstream will work. |
| Blank page, but the build passed | Stale Vite transforms. `rm -rf apps/dashboard/node_modules/.vite node_modules/.vite`, restart. |
| `Cannot find module 'ethers'` | You are not in the repo root. |
| Bids rejected, "storage unavailable" | `npm run replicas:status` — the quorum is 2 of 3. |
| Reads fail everywhere | `npm run network:health`. Containers may be down. |
| A tender cannot be closed | Its epoch has no revocation root published. `npm run tender` publishes one. |
| Proving is slow the first time | The browser is fetching 18 MB of proving key. It caches. |

---

## What is generated, and never committed

Regenerate all of it with the commands above; none of it belongs in git.

- `packages/circuits/build/`, `packages/circuits/ptau/` — ~475 MB of artifacts
- `packages/contracts/artifacts/`, `cache/`, `typechain-types/`
- `infrastructure/besu/nodes/*/data`, validator keys, `infrastructure/replica-run/`
- `deployments.json`
- `apps/dashboard/src/generated/contracts.json` — **contains role private keys**
- `apps/dashboard/public/circuits/` — the 68 MB the browser fetches
- `apps/dashboard/public/committee-dealings/`, `public/bidder-receipts/` —
  per-deployment seed material

**On those private keys.** `dashboard:sync` writes role keys into the generated
config so the browser can sign as any role without a wallet. They derive from
the public Hardhat test mnemonic and this chain has a zero gas price, which is
why shipping them to a browser is acceptable *for a prototype*. It is also why
the file is gitignored, and why the deployment notes in `DEPLOY.md` say not to
expose a public instance without gating it.
