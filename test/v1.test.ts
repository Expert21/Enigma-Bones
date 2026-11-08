import { describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";
import { fixedPoints, isInvolution, isPermutation } from "../src/common/perm.js";
import { expandV1Key, V1Machine, v1 } from "../src/versions/v1-byte-enigma.js";

const fixedKey = { secret: Uint8Array.from({ length: 32 }, (_, i) => i) };

describe("v1 byte Enigma", () => {
  it("decrypt(encrypt(m)) == m for random keys, rotor counts and lengths", () => {
    for (let t = 0; t < 40; t++) {
      const key = { ...v1.keygen(randomBytes(16)), rotors: 1 + (t % 8) };
      const pt = randomBytes(Math.floor(Math.random() * 20_000));
      expect(v1.decrypt(key, v1.encrypt(key, pt))).toEqual(Uint8Array.from(pt));
    }
  });

  it("handles every byte value and empty input", () => {
    const all = Uint8Array.from({ length: 256 }, (_, i) => i);
    expect(v1.decrypt(fixedKey, v1.encrypt(fixedKey, all))).toEqual(all);
    expect(v1.encrypt(fixedKey, new Uint8Array(0))).toEqual(new Uint8Array(0));
  });

  it("key expands into valid tables", () => {
    const t = expandV1Key(fixedKey);
    expect(t.fwd).toHaveLength(5);
    for (const p of [...t.fwd, ...t.bwd, t.reflector, t.plugboard]) expect(isPermutation(p)).toBe(true);
    expect(isInvolution(t.reflector) && fixedPoints(t.reflector) === 0).toBe(true);
    expect(isInvolution(t.plugboard) && fixedPoints(t.plugboard) === 128).toBe(true);
  });

  it("every step is a self-inverse pairing with no fixed points (still reflector-like)", () => {
    const m = new V1Machine(expandV1Key(fixedKey));
    for (let s = 0; s < 300; s++) {
      m.step();
      const S = Uint8Array.from({ length: 256 }, (_, x) => m.scramble(x));
      expect(isInvolution(S)).toBe(true);
      expect(fixedPoints(S)).toBe(0);
    }
  });

  it("all rotors eventually move (stepping carries through)", () => {
    const key = { secret: fixedKey.secret, rotors: 3 };
    const m = new V1Machine(expandV1Key(key));
    const moved = [false, false, false];
    for (let s = 0; s < 256 * 256 + 512; s++) {
      const before = Uint8Array.from(m.pos);
      m.step();
      for (let i = 0; i < 3; i++) if (m.pos[i] !== before[i]) moved[i] = true;
    }
    expect(moved).toEqual([true, true, true]);
  });

  it("different keys give different ciphertext", () => {
    const pt = new TextEncoder().encode("same message, two keys");
    expect(v1.encrypt(fixedKey, pt)).not.toEqual(v1.encrypt(v1.keygen(randomBytes(16)), pt));
  });

  it("frozen known-answer vector (old ciphertext must stay decryptable)", () => {
    const pt = new TextEncoder().encode("Wettervorhersage Biskaya: Regen, Sturm aus West.");
    const ct = v1.encrypt(fixedKey, pt);
    expect(Buffer.from(ct).toString("hex")).toMatchSnapshot();
    expect(v1.decrypt(fixedKey, ct)).toEqual(pt);
  });
});

describe("v1 fast path", () => {
  it("matches the readable V1Machine reference byte for byte", () => {
    for (const rotors of [1, 2, 5, 8]) {
      const key = { ...v1.keygen(randomBytes(16)), rotors };
      const pt = randomBytes(70_000); // long enough for the slow rotors to turn over
      const m = new V1Machine(expandV1Key(key));
      const ref = Uint8Array.from(pt, (b) => m.press(b));
      expect(v1.encrypt(key, pt)).toEqual(ref);
    }
  });
});
