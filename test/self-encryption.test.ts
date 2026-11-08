import { describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";
import { aesCtr, noSelfMatchEvidence, possibleCribOffsets } from "../src/attacks/self-encryption.js";
import { v1 } from "../src/versions/v1-byte-enigma.js";

describe("self-encryption distinguisher", () => {
  const pt = randomBytes(64 * 1024);
  it("flags v1 as a reflector machine", () => {
    const e = noSelfMatchEvidence(pt, v1.encrypt(v1.keygen(randomBytes(16)), pt));
    expect(e.matches).toBe(0);
    expect(e.reflectorLike).toBe(true);
  });
  it("does not flag a modern cipher", () => {
    const e = noSelfMatchEvidence(pt, aesCtr(pt));
    expect(e.reflectorLike).toBe(false);
    expect(e.matches).toBeGreaterThan(150); // expected 256
  });
  it("the true crib offset always survives crib dragging", () => {
    const key = v1.keygen(randomBytes(16));
    const msg = new TextEncoder().encode("xxxxxxxxxx" + "SECRET HEADER v1" + "yyyyyyyyyyyy");
    const offsets = possibleCribOffsets(v1.encrypt(key, msg), new TextEncoder().encode("SECRET HEADER v1"));
    expect(offsets).toContain(10);
  });
});
