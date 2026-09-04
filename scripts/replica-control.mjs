#!/usr/bin/env node
/**
 * Start, stop and inspect the three ciphertext-store replicas.
 *
 * Development plan Section 12.5. Three independent processes with three
 * distinct signing keys, taken from the role accounts so the same addresses
 * are registered on-chain.
 *
 * Each replica is a separate OS process on its own port with its own data
 * directory. That matters for the demo: "take replica 2 down" has to mean
 * actually killing a process, not flipping a flag in a shared server, or the
 * 2-of-3 quorum is being simulated rather than exercised.
 */
import { spawn } from "node:child_process";
import {
  closeSync,
  existsSync,
  mkdirSync,
  openSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "..");
const runDir = join(repoRoot, "infrastructure", "replica-run");
const server = join(repoRoot, "services/ciphertext-store/src/server.mjs");

const cfg = JSON.parse(
  readFileSync(join(repoRoot, "infrastructure/besu/config/accounts.json"), "utf8"),
);
const account = (role) => {
  const a = cfg.accounts.find((x) => x.role === role);
  if (!a) throw new Error(`no such role account: ${role}`);
  return a;
};

const REPLICAS = [1, 2, 3].map((id) => ({
  replicaId: id,
  port: 8100 + id,
  account: account(`replica-${id}`),
}));

const pidFile = (id) => join(runDir, `replica-${id}.pid`);
const logFile = (id) => join(runDir, `replica-${id}.log`);
const dataDir = (id) => join(runDir, `data/replica-${id}`);

function isRunning(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

function pidOf(id) {
  if (!existsSync(pidFile(id))) return null;
  const pid = Number(readFileSync(pidFile(id), "utf8").trim());
  if (!Number.isInteger(pid) || !isRunning(pid)) {
    // A stale pid file is worse than none: it makes `status` report a replica
    // as up while every upload to it fails.
    rmSync(pidFile(id), { force: true });
    return null;
  }
  return pid;
}

async function health(port) {
  try {
    const res = await fetch(`http://127.0.0.1:${port}/health`, {
      signal: AbortSignal.timeout(2000),
    });
    return res.ok ? await res.json() : null;
  } catch {
    return null;
  }
}

async function start(ids) {
  mkdirSync(runDir, { recursive: true });
  for (const r of REPLICAS.filter((r) => ids.includes(r.replicaId))) {
    if (pidOf(r.replicaId)) {
      console.log(`replica ${r.replicaId} already running (pid ${pidOf(r.replicaId)})`);
      continue;
    }
    mkdirSync(dataDir(r.replicaId), { recursive: true });
    // Log to an APPEND FILE DESCRIPTOR, not a pipe.
    //
    // With "pipe", the parent holds the read ends open and its event loop
    // never drains, so `replicas:start` hangs forever even after
    // `child.unref()` - unref does not cover the stdio streams. Handing the
    // child a real fd detaches it properly and the parent exits.
    const out = openSync(logFile(r.replicaId), "a");
    const child = spawn(process.execPath, [server], {
      env: {
        ...process.env,
        REPLICA_ID: String(r.replicaId),
        PORT: String(r.port),
        REPLICA_PRIVATE_KEY: r.account.privateKey,
        DATA_DIR: dataDir(r.replicaId),
      },
      detached: true,
      stdio: ["ignore", out, out],
    });
    child.unref();
    closeSync(out);
    writeFileSync(pidFile(r.replicaId), String(child.pid));
    console.log(`replica ${r.replicaId} -> 127.0.0.1:${r.port} (pid ${child.pid})`);
  }

  // Wait for readiness rather than sleeping a guessed interval: a test that
  // starts uploading before a replica is listening fails intermittently, and
  // an intermittent test in a quorum mechanism is indistinguishable from a
  // real quorum failure.
  for (const r of REPLICAS.filter((r) => ids.includes(r.replicaId))) {
    for (let i = 0; i < 50; i++) {
      if (await health(r.port)) break;
      await new Promise((res) => setTimeout(res, 100));
    }
  }
}

function stop(ids) {
  for (const id of ids) {
    const pid = pidOf(id);
    if (!pid) {
      console.log(`replica ${id} is not running`);
      continue;
    }
    process.kill(pid, "SIGTERM");
    rmSync(pidFile(id), { force: true });
    console.log(`replica ${id} stopped (pid ${pid})`);
  }
}

async function status() {
  console.log("ciphertext-store replicas");
  let up = 0;
  for (const r of REPLICAS) {
    const pid = pidOf(r.replicaId);
    const h = await health(r.port);
    if (h) up++;
    console.log(
      `  replica ${r.replicaId}  port ${r.port}  ${
        h ? `UP   pid ${pid}  ${h.objects} object(s)  signer ${h.address}` : "DOWN"
      }`,
    );
  }
  console.log(
    `\n${up}/3 up; the storage quorum is 2, so ${up >= 2 ? "bids can be accepted" : "bids CANNOT be accepted"}`,
  );
  return up;
}

function endpoints() {
  console.log(
    JSON.stringify(
      REPLICAS.map((r) => ({
        replicaId: r.replicaId,
        url: `http://127.0.0.1:${r.port}`,
        address: r.account.address,
      })),
      null,
      2,
    ),
  );
}

const [cmd, ...rest] = process.argv.slice(2);
const ids = rest.length ? rest.map(Number) : [1, 2, 3];

switch (cmd) {
  case "start":
    await start(ids);
    await status();
    break;
  case "stop":
    stop(ids);
    break;
  case "restart":
    stop(ids);
    await start(ids);
    break;
  case "status":
    process.exit((await status()) >= 2 ? 0 : 1);
  case "endpoints":
    endpoints();
    break;
  default:
    console.log(
      [
        "usage: replica-control <command> [replicaIds...]",
        "",
        "  start [ids]     start replicas (default all three)",
        "  stop  [ids]     stop replicas - use this to demonstrate the 2-of-3 quorum",
        "  restart [ids]",
        "  status          which replicas are up, and whether the quorum holds",
        "  endpoints       the registered endpoint list, as JSON",
      ].join("\n"),
    );
    process.exit(cmd ? 1 : 0);
}
