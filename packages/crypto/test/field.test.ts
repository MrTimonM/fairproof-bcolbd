import { describe, expect, it } from "vitest";
import {
  FIELD_PRIME,
  SAFE_MAX,
  assertUint,
  fromLimbs,
  toBigInt,
  toBytes,
  toField,
  toHex32,
  toLimbs,
} from "../src/field.js";

describe("field encoding (spec Sections 1-2, 4)", () => {
  it("FIELD_PRIME is the BN254 scalar field and is 254 bits", () => {
    expect(FIELD_PRIME.toString(2).length).toBe(254);
  });

  it("toField keeps the high 248 bits, never reducing mod p", () => {
    // All-ones digest: >> 8 must give 2^248 - 1, which is < p.
    const allOnes = "0x" + "ff".repeat(32);
    expect(toField(allOnes)).toBe(SAFE_MAX);
    expect(toField(allOnes)).toBeLessThan(FIELD_PRIME);
  });

  it("toField output is always a valid field element", () => {
    // The largest possible 256-bit input still lands below p after shifting.
    const max = (1n << 256n) - 1n;
    expect(toField(max)).toBeLessThan(FIELD_PRIME);
  });

  it("toField discards exactly the low byte", () => {
    expect(toField(0x1234n)).toBe(0x12n);
    expect(toField(0xffn)).toBe(0n);
  });

  it("toField rejects values wider than 256 bits", () => {
    expect(() => toField(1n << 256n)).toThrow(/exceeds 256 bits/);
  });

  it("limbs round-trip losslessly for rulesHash", () => {
    const hash =
      "0x8f3a2b1c4d5e6f708192a3b4c5d6e7f80112233445566778899aabbccddeeff0";
    const { hi, lo } = toLimbs(hash);
    expect(hi).toBeLessThan(1n << 128n);
    expect(lo).toBeLessThan(1n << 128n);
    expect(fromLimbs(hi, lo)).toBe(toHex32(toBigInt(hash)));
  });

  it("limbs distinguish hashes that differ only in the low bits", () => {
    const a = toLimbs("0x" + "00".repeat(31) + "01");
    const b = toLimbs("0x" + "00".repeat(31) + "02");
    expect(a.lo).not.toBe(b.lo);
  });

  it("fromLimbs rejects oversized limbs", () => {
    expect(() => fromLimbs(1n << 128n, 0n)).toThrow(/hi limb/);
    expect(() => fromLimbs(0n, 1n << 128n)).toThrow(/lo limb/);
  });

  it("toBytes is big-endian and fixed width", () => {
    expect(Array.from(toBytes(1n, 4))).toEqual([0, 0, 0, 1]);
    expect(Array.from(toBytes(0x0102n, 2))).toEqual([1, 2]);
  });

  it("toBytes rejects a value too large for the width", () => {
    expect(() => toBytes(256n, 1)).toThrow(/does not fit/);
  });

  it("assertUint enforces the range constraints of spec Section 14", () => {
    expect(assertUint((1n << 64n) - 1n, 64, "x")).toBeDefined();
    expect(() => assertUint(1n << 64n, 64, "turnover")).toThrow(/uint64/);
    expect(() => assertUint(-1n, 64, "turnover")).toThrow(/negative/);
  });
});
