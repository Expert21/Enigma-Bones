import { describe, expect, it } from "vitest";
import { compose, fixedPoints, identity, invert, isInvolution, isPermutation, keyedShuffle } from "../src/common/perm.js";
import { HashStream } from "../src/common/kdf.js";

describe("perm", () => {
  it("keyed shuffle is a deterministic permutation", () => {
    const a = keyedShuffle(256, (n) => new HashStream(new Uint8Array([1]), "t").uniform(n));
    const s1 = new HashStream(new Uint8Array([7]), "t");
    const s2 = new HashStream(new Uint8Array([7]), "t");
    const p = keyedShuffle(256, (n) => s1.uniform(n));
    expect(isPermutation(a)).toBe(true);
    expect(isPermutation(p)).toBe(true);
    expect(p).toEqual(keyedShuffle(256, (n) => s2.uniform(n)));
  });
  it("invert undoes a permutation", () => {
    const s = new HashStream(new Uint8Array([9]), "t");
    const p = keyedShuffle(256, (n) => s.uniform(n));
    expect(compose(p, invert(p))).toEqual(identity(256));
  });
  it("involution and fixed-point helpers", () => {
    expect(isInvolution(Uint8Array.from([1, 0, 2]))).toBe(true);
    expect(isInvolution(Uint8Array.from([1, 2, 0]))).toBe(false);
    expect(fixedPoints(Uint8Array.from([1, 0, 2]))).toBe(1);
  });
});
