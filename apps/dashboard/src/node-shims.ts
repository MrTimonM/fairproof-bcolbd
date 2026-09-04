/**
 * Node globals that circomlibjs expects and a browser does not have.
 *
 * `buildEddsa` signs with BLAKE-512 via `blake-hash`, which is written against
 * Node's `Buffer` — and `blake-hash` in turn drags in `readable-stream`, which
 * reaches for `events`, `util` and `process`. Vite replaces all four with empty
 * stubs and does not fail the build, so the first symptom is a blank page and a
 * `ReferenceError: Buffer is not defined` thrown while the module graph is still
 * loading. A build that succeeds proves nothing about this.
 *
 * Substituting a different hash is not an option: the credential signature has
 * to be byte-identical to the one the circuit's EdDSA verifier checks, and that
 * is circomlib's BLAKE-512 or nothing.
 *
 * This module is imported for its side effects, before anything that touches
 * the crypto package. Import order is what makes it work, so it must stay the
 * first import in `main.tsx`.
 */
import { Buffer } from "buffer";

declare global {
  // eslint-disable-next-line no-var
  var Buffer: typeof import("buffer").Buffer;
  // eslint-disable-next-line no-var
  var global: typeof globalThis;
}

const g = globalThis as Record<string, unknown>;

if (!g.Buffer) g.Buffer = Buffer;
if (!g.global) g.global = globalThis;

// `readable-stream` reads process.nextTick and process.env.READABLE_STREAM.
if (!g.process) {
  g.process = {
    env: {},
    version: "",
    nextTick: (fn: (...a: unknown[]) => void, ...args: unknown[]) =>
      queueMicrotask(() => fn(...args)),
  };
}

export {};
