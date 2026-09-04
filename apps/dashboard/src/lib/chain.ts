/**
 * The only route to data, and now also to writes.
 *
 * Contract state and finalized events are the source of truth. There is no
 * database behind this app: every value is a read, and a failed read is shown
 * as a failed read rather than as an empty panel.
 *
 * SIGNING. The workspaces submit real transactions, signed here with the role
 * keys from the generated bundle. Those keys derive from the public Hardhat
 * test mnemonic — the most widely published private key material in Ethereum —
 * and this chain has a zero gas price and no value on it. That is why shipping
 * them to the browser is acceptable, and the interface says so on screen
 * rather than leaving a reader to wonder. They must never be reused anywhere
 * that matters.
 */
import { Contract, HDNodeWallet, JsonRpcProvider, Wallet } from "ethers";
import generated from "../generated/contracts.json";

export const CONFIG = generated;

/**
 * Where the chain and the stores actually are.
 *
 * `contracts.json` records the loopback addresses the sync script saw, which
 * are right on the machine that ran it and wrong everywhere else: served from
 * a host, `127.0.0.1` is the VISITOR's own machine, so every read fails. These
 * templates let a build point the same bundle at a proxy instead.
 *
 *   VITE_RPC_URL_TEMPLATE=/rpc/{n}
 *   VITE_STORE_URL_TEMPLATE=/store/{n}
 *
 * A template beginning with "/" is resolved against whatever origin served
 * the page, which is what you almost always want: the same bundle then works
 * on an IP, behind a tunnel, and on a domain later without being rebuilt, and
 * no deployment bakes in an address that a certificate or a DNS change would
 * invalidate. Absolute templates are still honoured for a split deployment
 * where the chain is not proxied by the host serving this page.
 *
 * `{n}` is 1-based — validator 1..4, replica 1..3 — and `{port}` is the local
 * port, so a template can preserve the loopback shape if it wants to. Unset
 * means loopback, which is what a developer wants and what the tests assume.
 */
const RPC_TEMPLATE = (import.meta.env?.VITE_RPC_URL_TEMPLATE as string | undefined) ?? "";
const STORE_TEMPLATE = (import.meta.env?.VITE_STORE_URL_TEMPLATE as string | undefined) ?? "";

const fromTemplate = (tpl: string, n: number, port: number) => {
  const path = tpl.replace(/\{n\}/g, String(n)).replace(/\{port\}/g, String(port));
  // ethers' provider needs an absolute URL, so a root-relative template is
  // joined to the serving origin here rather than left for fetch() to resolve.
  return path.startsWith("/") && typeof window !== "undefined"
    ? `${window.location.origin}${path}`
    : path;
};

/** Every validator's RPC endpoint, in the order the config lists them. */
export const RPC_URLS: string[] = CONFIG.validators.map((v, i) =>
  RPC_TEMPLATE ? fromTemplate(RPC_TEMPLATE, i + 1, v.rpc) : `http://127.0.0.1:${v.rpc}`,
);

/**
 * The ciphertext stores, with their URLs rewritten for wherever this is served.
 *
 * The signer addresses are NOT rewritten: a replica's receipt is checked
 * against the key the chain registered, so moving a store changes where it is
 * reached and nothing about whether its signature counts.
 */
export const REPLICAS = CONFIG.replicas.map((r, i) => ({
  ...r,
  url: STORE_TEMPLATE
    ? fromTemplate(STORE_TEMPLATE, i + 1, Number(new URL(r.url).port || 80))
    : r.url,
}));
export type ContractName = keyof typeof generated.abis;

export const TENDER_STATES = [
  "Not created",
  "Draft",
  "Active",
  "Closed",
  "Opening",
  "Awarded",
  "Cancelled",
] as const;

export const ACTION_TYPES = [
  "Register issuer",
  "Set issuer status",
  "Publish registry root",
  "Activate verifier version",
  "Record validator change",
  "Set tender authority",
  "Set committee",
  "Emergency pause",
  "Unpause",
  "Cancel tender",
] as const;

export const DISCLOSURE = {
  1: "Publish the winning price",
  2: "Winner only — price withheld",
} as const;

export const providers = RPC_URLS.map(
  (url) =>
    new JsonRpcProvider(url, {
      chainId: CONFIG.chainId,
      name: "fairproof",
    }),
);
export const provider = providers[0];

const readCache = new Map<string, Contract>();

export function addressOf(name: ContractName | string): string {
  return (CONFIG.deployments.contracts as Record<string, string>)[name] ?? "";
}

export function abiOf(name: ContractName | string): unknown[] {
  return (CONFIG.abis as Record<string, unknown[]>)[name] ?? [];
}

/** A read-only contract instance. */
export function contract(name: ContractName | string): Contract {
  const address = addressOf(name);
  if (!address) {
    throw new Error(
      `${name} is not in deployments.json. Run \`npm run deploy\`, then restart.`,
    );
  }
  let c = readCache.get(name as string);
  if (!c) {
    c = new Contract(address, abiOf(name) as never, provider);
    readCache.set(name as string, c);
  }
  return c;
}

export interface RoleAccount {
  role: string;
  address: string;
  privateKey: string;
}

export const ACCOUNTS: RoleAccount[] = CONFIG.roles as RoleAccount[];

export function account(role: string): RoleAccount {
  const a = ACCOUNTS.find((x) => x.role === role);
  if (!a) throw new Error(`no such role account: ${role}`);
  return a;
}

/** A signer for a role. */
export function signer(role: string): Wallet {
  return new Wallet(account(role).privateKey, provider);
}

/** A contract bound to a role's signer, for writes. */
export function writeAs(name: ContractName | string, role: string): Contract {
  return new Contract(addressOf(name), abiOf(name) as never, signer(role));
}

/**
 * A fresh throwaway signer, so a bid carries no funding history.
 *
 * Gas costs nothing on this chain, so a bidder never has to fund a wallet —
 * which closes the funding-trail correlation channel the whitepaper lists as a
 * residual metadata risk.
 */
export function anonymousSigner(): HDNodeWallet {
  return Wallet.createRandom().connect(provider);
}

/**
 * Send a transaction with a generous gas limit.
 *
 * Estimation is used but padded: a pairing check estimated tightly can revert
 * on a slightly different state, and a failed submission near a deadline is
 * expensive in a way a wasted gas allowance is not. Gas is free here.
 */
export async function send(
  fn: any,
  args: unknown[],
  onStatus?: (s: string) => void,
): Promise<{ hash: string; gasUsed: bigint; blockNumber: number }> {
  onStatus?.("estimating");
  const gas = await fn.estimateGas(...args, { gasPrice: 0 });
  onStatus?.("signing");
  const tx = await fn(...args, { gasPrice: 0, gasLimit: (gas * 3n) / 2n });
  onStatus?.("pending");
  const receipt = await tx.wait();
  onStatus?.("confirmed");
  return {
    hash: receipt.hash,
    gasUsed: receipt.gasUsed as bigint,
    blockNumber: receipt.blockNumber as number,
  };
}

export function roleLabel(role: string): string {
  const parts = role.split("-").map((w) => w[0].toUpperCase() + w.slice(1));
  if (parts[0] === "Council") return `Council · ${parts.slice(1).join(" ")}`;
  if (parts[0] === "Committee") return `Committee member ${parts[1]}`;
  if (parts[0] === "Replica") return `Storage replica ${parts[1]}`;
  return parts.join(" ");
}

export function roleOf(address: string): string | null {
  const hit = ACCOUNTS.find((r) => r.address.toLowerCase() === address.toLowerCase());
  return hit ? hit.role : null;
}

// ------------------------------------------------------------------ format

/** Bangladeshi grouping: last three digits, then pairs. */
export function formatBdt(minorUnits: bigint | string | number): string {
  const s = BigInt(minorUnits).toString();
  if (s.length <= 3) return `৳ ${s}`;
  const head = s.slice(0, -3);
  const tail = s.slice(-3);
  return `৳ ${head.replace(/\B(?=(\d{2})+(?!\d))/g, ",")},${tail}`;
}

export function shortHash(v: string | bigint, lead = 12, tail = 8): string {
  const s = typeof v === "bigint" ? "0x" + v.toString(16) : v;
  return s.length <= lead + tail + 2 ? s : `${s.slice(0, lead)}…${s.slice(-tail)}`;
}

export function fieldToHex(v: bigint): string {
  return "0x" + v.toString(16).padStart(64, "0");
}

export function formatTime(seconds: bigint | number): string {
  const n = Number(seconds);
  if (!n) return "—";
  return new Date(n * 1000).toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

export function formatCountdown(target: bigint | number, now: number): string {
  const delta = Number(target) - now;
  if (!Number(target)) return "—";
  const abs = Math.abs(delta);
  const h = Math.floor(abs / 3600);
  const m = Math.floor((abs % 3600) / 60);
  const s = abs % 60;
  const body =
    h > 0 ? `${h}h ${m}m` : m > 0 ? `${m}m ${s}s` : `${s}s`;
  return delta >= 0 ? `in ${body}` : `${body} ago`;
}

export function formatGas(g: bigint | number): string {
  return Number(g).toLocaleString();
}
