import { describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";
import { EnigmaMachine, encryptText, v0, type EnigmaKey } from "../src/versions/v0-enigma.js";

const base: EnigmaKey = { rotors: ["I", "II", "III"], reflector: "B", rings: [0, 0, 0], positions: [0, 0, 0], plugs: [] };
const bytes = (s: string) => new TextEncoder().encode(s);

describe("v0 faithful Enigma", () => {
  it("matches historical known-answer vectors", () => {
    expect(encryptText(base, "AAAAA")).toBe("BDZGO");
    expect(encryptText(base, "HELLOWORLD")).toBe("ILBDAAMTAZ");
  });

  it("double-steps the middle rotor (ADU → ADV → AEW → BFX)", () => {
    const m = new EnigmaMachine({ ...base, positions: [0, 3, 20] });
    const seen: string[] = [];
    for (let i = 0; i < 3; i++) {
      m.step();
      seen.push(m.pos.map((x) => String.fromCharCode(65 + x)).join(""));
    }
    expect(seen).toEqual(["ADV", "AEW", "BFX"]);
  });

  it("frozen vector with rings and plugboard (guards against regressions)", () => {
    const key: EnigmaKey = { rotors: ["IV", "II", "V"], reflector: "C", rings: [3, 17, 25], positions: [11, 4, 21], plugs: ["AQ", "BY", "CK", "DX", "FL"] };
    const ct = encryptText(key, "ATTACKATDAWN");
    expect(encryptText(key, ct)).toBe("ATTACKATDAWN");
    expect(ct).toMatchSnapshot();
  });

  it("decrypt(encrypt(m)) == m for random keys and messages", () => {
    for (let t = 0; t < 50; t++) {
      const key = v0.keygen(randomBytes(16));
      const len = Math.floor(Math.random() * 500);
      const pt = Uint8Array.from({ length: len }, () => 65 + Math.floor(Math.random() * 26));
      expect(v0.decrypt(key, v0.encrypt(key, pt))).toEqual(pt);
    }
  });

  it("never encrypts a letter to itself (the flaw the Bombe exploits)", () => {
    const key = v0.keygen(randomBytes(16));
    const pt = bytes("A".repeat(5000));
    const ct = v0.encrypt(key, pt);
    expect(ct.some((c, i) => c === pt[i])).toBe(false);
  });

  it("rejects non-letters instead of silently mangling them", () => {
    expect(() => v0.encrypt(base, bytes("HI THERE"))).toThrow();
  });
});
