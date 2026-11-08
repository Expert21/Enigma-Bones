import { describe, expect, it } from "vitest";
import { bombe, possibleCribOffsets, verifyStop } from "../src/attacks/bombe.js";
import { encryptText, normalize, v0, type EnigmaKey } from "../src/versions/v0-enigma.js";

describe("Bombe attack on v0", () => {
  it("recovers rotor positions and plugs from a crib", () => {
    const key: EnigmaKey = { ...v0.keygen(Buffer.from("bombe-test")), rings: [0, 0, 0] };
    const pt = normalize("Wettervorhersage Biskaya Regen Sturm aus West Sicht schlecht");
    const ct = encryptText(key, pt);
    const crib = "WETTERVORHERSAGEBISKAYA";
    expect(possibleCribOffsets(ct, crib)).toContain(0);

    const stops = bombe(ct, crib, 0, [key.rotors]).filter((s) => verifyStop(s, ct, crib, 0));
    const hit = stops.find((s) => s.positions.join() === key.positions.join());
    expect(hit).toBeDefined();
    // Every deduced plug must agree with the real plugboard.
    const real = new Map<string, string>();
    for (const [a, b] of key.plugs) { real.set(a, b); real.set(b, a); }
    for (const [a, b] of hit!.deducedPlugs) {
      const A = String.fromCharCode(65 + a), B = String.fromCharCode(65 + b);
      expect(real.get(A) ?? A).toBe(B);
    }
  }, 30_000);
});
