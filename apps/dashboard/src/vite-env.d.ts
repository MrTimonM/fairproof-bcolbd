/// <reference types="vite/client" />

/**
 * Build-time endpoint overrides.
 *
 * Unset for local development, where the loopback addresses in
 * `contracts.json` are correct. Set when the bundle is served from a host,
 * because a visitor's `127.0.0.1` is their own machine. See `lib/chain.ts`.
 */
interface ImportMetaEnv {
  readonly VITE_RPC_URL_TEMPLATE?: string;
  readonly VITE_STORE_URL_TEMPLATE?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
