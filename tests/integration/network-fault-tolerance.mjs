#!/usr/bin/env node
/**
 * Failure injection: stop one validator, confirm the network keeps
 * finalizing blocks and accepting transactions, then restart it and confirm
 * it catches up. Development plan Sections 7.3 and 20.6.
 *
 * This backs whitepaper Section 9.2: "QBFT tolerates floor((n-1)/3) Byzantine
 * validators, so four tolerate one faulty or malicious institution and no
 * single institution can halt the network".
 *
 * It is also a demo beat: stop a validator on stage, show blocks continuing.
 */
import { execFileSync } from "node:child_process";

const PORTS = { 1: 8545, 2: 8546, 3: 8547, 4: 8548 };
const TARGET = Number(process.env.TARGET_VALIDATOR || 3);

let failures = 0;
function check(ok, label, detail = "") {
  console.log(`  ${ok ? "PASS" : "FAIL"}  ${label}${detail ? ` - ${detail}` : ""}`);
  if (!ok) failures++;
}

async function rpc(port, method, params = []) {
  const res = await fetch(`http://127.0.0.1:${port}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", method, params, id: 1 }),
    signal: AbortSignal.timeout(8000),
  });
  const body = await res.json();
  if (body.error) throw new Error(body.error.message);
  return body.result;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Wait until `port` advances past `from`, or time out. */
async function waitForAdvance(port, from, timeoutMs = 40000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const head = Number(await rpc(port, "eth_blockNumber"));
      if (head > from) return head;
    } catch {
      /* node may be briefly unreachable; keep waiting */
    }
    await sleep(2000);
  }
  return null;
}

console.log("QBFT fault tolerance: one validator down\n");

const survivors = Object.entries(PORTS)
  .filter(([id]) => Number(id) !== TARGET)
  .map(([, port]) => port);

// Precondition: all four validators must be up and advancing together
// before a fault is injected. Without this the test can report a false
// failure when it runs against a network that is still catching up from a
// previous run.
console.log("precondition: waiting for all four validators to be in sync ...");
const readyDeadline = Date.now() + 120000;
let ready = false;
while (Date.now() < readyDeadline) {
  try {
    const heads = await Promise.all(
      Object.values(PORTS).map((p) => rpc(p, "eth_blockNumber").then(Number)),
    );
    const spread = Math.max(...heads) - Math.min(...heads);
    if (spread <= 1) {
      // Confirm the chain is actually live, not merely uniformly stuck.
      const before = Math.min(...heads);
      await sleep(5000);
      const now = Number(await rpc(PORTS[1], "eth_blockNumber"));
      if (now > before) {
        ready = true;
        break;
      }
    }
  } catch {
    /* a node may still be starting */
  }
  await sleep(2000);
}
if (!ready) {
  console.error("  FAIL  precondition: network not healthy before fault injection");
  process.exit(1);
}
console.log("  ok - all four in sync and advancing\n");

// Baseline
const baseline = Number(await rpc(survivors[0], "eth_blockNumber"));
console.log(`baseline head: ${baseline}\n`);

// 1. Stop the target validator.
console.log(`stopping validator-${TARGET} ...`);
execFileSync("docker", ["stop", `fairproof-validator-${TARGET}`], { stdio: "ignore" });
await sleep(3000);

console.log("\nwith one validator down (3 of 4 remaining):");
let progressed = null;
for (const port of survivors) {
  const head = await waitForAdvance(port, baseline);
  if (port === survivors[0]) progressed = head;
  check(head !== null, `validator on :${port} still finalizing`, head ? `head ${head}` : "stalled");
}

// 2. The stopped node must be unreachable - proving the test is real.
let stoppedReachable = true;
try {
  await rpc(PORTS[TARGET], "eth_blockNumber");
} catch {
  stoppedReachable = false;
}
check(!stoppedReachable, `validator-${TARGET} is genuinely down`);

// 3. Restart and confirm catch-up.
console.log(`\nrestarting validator-${TARGET} ...`);
execFileSync("docker", ["start", `fairproof-validator-${TARGET}`], { stdio: "ignore" });

const target = await waitForAdvance(PORTS[TARGET], 0, 90000);
check(target !== null, `validator-${TARGET} restarted and syncing`, target ? `head ${target}` : "no response");

if (target !== null) {
  // Poll until it converges on the others' head. A restarted node has to
  // replay the blocks it missed, so a fixed sleep is the wrong tool - how
  // long it needs depends on how long it was down.
  const deadline = Date.now() + 90000;
  let rejoined = 0;
  let others = 0;
  let caughtUp = false;
  while (Date.now() < deadline) {
    rejoined = Number(await rpc(PORTS[TARGET], "eth_blockNumber"));
    others = Number(await rpc(survivors[0], "eth_blockNumber"));
    if (others - rejoined <= 2) {
      caughtUp = true;
      break;
    }
    await sleep(2000);
  }
  check(caughtUp, `validator-${TARGET} caught up`, `${rejoined} vs ${others}`);

  // And it must be back in the validator set, actively proposing again.
  const set = await rpc(PORTS[TARGET], "qbft_getValidatorsByBlockNumber", ["latest"]);
  check(set.length === 4, `validator set restored`, `${set.length}/4`);
}

// 4. The tolerance bound is exactly one. Stopping a SECOND validator must
//    HALT consensus, because QBFT needs a supermajority (ceil(2n/3) = 3 of 4)
//    to finalize a block.
//
//    This check exists to keep us honest. Without it, the test above could
//    pass vacuously - if the chain kept producing blocks with two nodes down,
//    it would mean consensus was not actually requiring a quorum, and the
//    "no single institution can rewrite a finalised award" claim would rest on
//    nothing. Whitepaper Section 19.5 already concedes that a Byzantine
//    quorum can censor or affect liveness; this is the other side of that
//    coin, and it is a property, not a defect.
console.log("\nverifying the tolerance bound is exactly one:");
const second = TARGET === 2 ? 4 : 2;
execFileSync("docker", ["stop", `fairproof-validator-${TARGET}`, `fairproof-validator-${second}`], {
  stdio: "ignore",
});
await sleep(3000);

const stalledPort = Object.entries(PORTS).find(
  ([id]) => Number(id) !== TARGET && Number(id) !== second,
)[1];
const beforeStall = Number(await rpc(stalledPort, "eth_blockNumber"));
// Well over the 2 s block period: if it can advance, it will have.
await sleep(12000);
const afterStall = Number(await rpc(stalledPort, "eth_blockNumber"));
check(
  afterStall === beforeStall,
  "consensus halts with 2 of 4 down, as QBFT requires",
  `head ${beforeStall} -> ${afterStall}`,
);

// 5. Recovery: restore the quorum and confirm the chain resumes. An outage
//    must not be terminal - whitepaper Section 14 treats a chain outage at a
//    deadline as a legal event handled by the contingency policy, which
//    presumes the chain itself recovers.
console.log("\nrestoring quorum:");
execFileSync("docker", ["start", `fairproof-validator-${TARGET}`, `fairproof-validator-${second}`], {
  stdio: "ignore",
});
const resumed = await waitForAdvance(stalledPort, afterStall, 90000);
check(resumed !== null, "consensus resumes once quorum returns", resumed ? `head ${resumed}` : "still stalled");

console.log(`\n${failures === 0 ? "FAULT TOLERANCE CONFIRMED" : `${failures} CHECK(S) FAILED`}`);
process.exit(failures === 0 ? 0 : 1);
