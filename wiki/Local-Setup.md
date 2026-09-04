# Local Setup

Clean clone to a working procurement in a browser. Budget **~45 minutes**, most
of it unattended.

The repository's [`SETUP.md`](https://github.com/MrTimonM/fairproof-bcolbd/blob/main/SETUP.md)
is the authoritative version; this page is the short form.

## 1. Prerequisites `npm ci` will not install

| | Why |
|---|---|
| **Node 20+** | Workspaces, native fetch |
| **Docker + compose v2** | The four validators run in containers |
| **circom 2.x** | Compiles the circuits — a **Rust binary**, not an npm package |
| **~2 GB disk** | Circuit build output is ~330 MB |

```bash
npm ci
npm run doctor
```

`doctor` separates **MISS** (install this) from **TODO** (run this build step),
and prints the command for each. Run it whenever anything behaves oddly.

## 2. Build the cryptography

```bash
npm run setup
```

Which is:

```bash
npm run setup:ptau        # 145 MB Hermez powers-of-tau, sha256 pinned in-repo
npm run crypto:build
npm run setup:circuits    # compile + phase-2 ceremony x3   <- ~30 min
npm run contracts:compile
```

Confirm the ceremony independently:

```bash
npm run ceremony:verify -- eligibility     # expect VERIFIED, 25/25
```

## 3. Test before touching a chain

```bash
npm test           # 578 tests: 158 crypto, 350 contracts, 70 circuits
```

## 4. Chain, contracts, stores

```bash
npm run network:setup && npm run network:up
npm run network:health          # HEALTHY, 4/4
npm run deploy                  # 11 contracts via real 3-of-4 + timelock
npm run replicas:start          # 3/3 — the browser needs these
npm run dashboard:sync
```

> `npm run deploy` **wipes every tender.** Re-seed afterwards.

## 5. Seed and run

```bash
npm run tender -- --window 3600
npm run dashboard:dev           # http://127.0.0.1:5173
```

Bidding opens 3½ minutes after publication — a review window the contract
enforces and nobody can shorten. That wait is the protocol working.

Or skip to a finished procurement with three bidders (~7 min, unattended):

```bash
npm run tender -- --reference RHD-2026-0400 --window 600
npm run tender:complete RHD-2026-0400
```

## 6. Verify it without believing the dashboard

```bash
npm run test:verifier                        # 31 corrupted bundles
npm run evidence -- --tender RHD-2026-0400
npm run verify -- evidence/<bundle>.json     # 16 checks, no chain access
```

## Common problems

| Symptom | Cause |
|---|---|
| `doctor` shows **MISS** | A tool is missing; nothing downstream works |
| Blank page, build passed | Stale Vite transforms — `rm -rf apps/dashboard/node_modules/.vite node_modules/.vite` |
| `Cannot find module 'ethers'` | Not in the repo root |
| Bids rejected, storage unavailable | `npm run replicas:status` — quorum is 2 of 3 |
| A tender cannot be closed | Its epoch has no revocation root; `npm run tender` publishes one |
| First proof is slow | The browser is fetching 18 MB of proving key. It caches. |
