/**
 * v0 — a faithful Enigma I / M3.
 *
 *   keyboard → plugboard → R → M → L → reflector → L⁻¹ → M⁻¹ → R⁻¹ → plugboard → lamp
 *
 * Historical behaviour reproduced exactly:
 *  - 5 rotors (I–V) with their real wirings and turnover notches; pick 3.
 *  - Reflector B or C.
 *  - Ring settings (Ringstellung) and starting positions (Grundstellung).
 *  - Plugboard (Steckerbrett) with up to 13 swapped pairs (10 was standard).
 *  - The odometer stepping including the middle rotor's "double step".
 *
 * Because the reflector is an involution with no fixed points, every key
 * position is a self-inverse permutation with no fixed points. So
 * encryption == decryption, and no letter ever encrypts to itself — the
 * property the Bombe exploited.
 */
import { HashStream } from "../common/kdf.js";
import { fixedPoints, fromLetters, invert, isInvolution, type Perm } from "../common/perm.js";
import type { CipherVersion } from "../common/types.js";

export const ROTORS = {
  I: { wiring: "EKMFLGDQVZNTOWYHXUSPAIBRCJ", notch: "Q" },
  II: { wiring: "AJDKSIRUXBLHWTMCQGZNPYFVOE", notch: "E" },
  III: { wiring: "BDFHJLCPRTXVZNYEIWGAKMUSQO", notch: "V" },
  IV: { wiring: "ESOVPZJAYQUIRHXLNFTGKDCMWB", notch: "J" },
  V: { wiring: "VZBRGITYUPSDNHLXAWMJQOFECK", notch: "Z" },
} as const;
export type RotorName = keyof typeof ROTORS;
export const ROTOR_NAMES = Object.keys(ROTORS) as RotorName[];

export const REFLECTORS = {
  B: "YRUHQSLDPXNGOKMIEBFZCWVJAT",
  C: "FVPJIAOYEDRZXWGCTKUQSBNMHL",
} as const;
export type ReflectorName = keyof typeof REFLECTORS;

export interface EnigmaKey {
  /** Left, middle, right. */
  rotors: [RotorName, RotorName, RotorName];
  reflector: ReflectorName;
  /** Ring settings, 0–25 (A=0). */
  rings: [number, number, number];
  /** Starting window letters, 0–25 (A=0). */
  positions: [number, number, number];
  /** Plugboard pairs as two-letter strings, e.g. ["AB", "CD"]. */
  plugs: string[];
}

const mod26 = (x: number) => ((x % 26) + 26) % 26;

interface RotorTables {
  fwd: Perm;
  bwd: Perm;
  notch: number;
}

const ROTOR_TABLES: Record<RotorName, RotorTables> = Object.fromEntries(
  ROTOR_NAMES.map((n) => {
    const fwd = fromLetters(ROTORS[n].wiring);
    return [n, { fwd, bwd: invert(fwd), notch: ROTORS[n].notch.charCodeAt(0) - 65 }];
  }),
) as Record<RotorName, RotorTables>;

function reflectorTable(name: ReflectorName): Perm {
  const p = fromLetters(REFLECTORS[name]);
  // A real reflector pairs letters up: self-inverse, nothing maps to itself.
  if (!isInvolution(p) || fixedPoints(p) !== 0) throw new Error(`reflector ${name} is miswired`);
  return p;
}

const REFLECTOR_TABLES: Record<ReflectorName, Perm> = { B: reflectorTable("B"), C: reflectorTable("C") };

export function plugboardTable(plugs: string[]): Perm {
  const p = Uint8Array.from({ length: 26 }, (_, i) => i);
  for (const pair of plugs) {
    const up = pair.toUpperCase();
    if (!/^[A-Z]{2}$/.test(up)) throw new RangeError(`bad plug pair: ${pair}`);
    const a = up.charCodeAt(0) - 65;
    const b = up.charCodeAt(1) - 65;
    if (a === b || p[a] !== a || p[b] !== b) throw new RangeError(`plug letter reused: ${pair}`);
    p[a] = b;
    p[b] = a;
  }
  return p;
}

/** A stateful machine: create one per message, press keys in order. */
export class EnigmaMachine {
  private readonly r: RotorTables[];
  private readonly refl: Perm;
  private readonly plug: Perm;
  private readonly rings: number[];
  /** Current window letters [left, middle, right]. */
  readonly pos: number[];

  constructor(key: EnigmaKey) {
    if (new Set(key.rotors).size !== 3) throw new RangeError("rotors must be distinct");
    this.r = key.rotors.map((n) => ROTOR_TABLES[n]);
    this.refl = REFLECTOR_TABLES[key.reflector];
    this.plug = plugboardTable(key.plugs);
    this.rings = [...key.rings];
    this.pos = [...key.positions];
  }

  /** Rotors step BEFORE each key press, like the real machine. */
  step(): void {
    const [, m, r] = this.r;
    if (this.pos[1] === m.notch) {
      // Double step: the middle rotor at its notch carries itself and the left rotor.
      this.pos[1] = mod26(this.pos[1] + 1);
      this.pos[0] = mod26(this.pos[0] + 1);
    } else if (this.pos[2] === r.notch) {
      this.pos[1] = mod26(this.pos[1] + 1);
    }
    this.pos[2] = mod26(this.pos[2] + 1);
  }

  /** Signal path through the rotors and reflector only (no plugboard, no stepping). */
  scramble(c: number): number {
    for (let i = 2; i >= 0; i--) {
      const shift = this.pos[i] - this.rings[i];
      c = mod26(this.r[i].fwd[mod26(c + shift)] - shift);
    }
    c = this.refl[c];
    for (let i = 0; i <= 2; i++) {
      const shift = this.pos[i] - this.rings[i];
      c = mod26(this.r[i].bwd[mod26(c + shift)] - shift);
    }
    return c;
  }

  /** Press one key (0–25), return the lamp that lights (0–25). */
  press(c: number): number {
    this.step();
    return this.plug[this.scramble(this.plug[c])];
  }
}

/** Uppercase and drop everything that isn't A–Z (Enigma had no other keys). */
export function normalize(text: string): string {
  return text.toUpperCase().replace(/[^A-Z]/g, "");
}

function run(key: EnigmaKey, data: Uint8Array): Uint8Array {
  const m = new EnigmaMachine(key);
  const out = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i++) {
    const c = data[i] - 65;
    if (c < 0 || c > 25) throw new RangeError(`v0 only accepts A–Z (byte ${data[i]} at ${i}); use normalize()`);
    out[i] = m.press(c) + 65;
  }
  return out;
}

export function encryptText(key: EnigmaKey, text: string): string {
  return new TextDecoder().decode(run(key, new TextEncoder().encode(normalize(text))));
}

export const v0: CipherVersion<EnigmaKey> = {
  id: 0,
  name: "Enigma I/M3 (faithful)",
  keygen(seed) {
    const s = new HashStream(seed, "v0-keygen");
    const names = [...ROTOR_NAMES];
    const rotors: RotorName[] = [];
    for (let i = 0; i < 3; i++) rotors.push(names.splice(s.uniform(names.length), 1)[0]);
    const letters = Array.from({ length: 26 }, (_, i) => i);
    const plugs: string[] = [];
    for (let i = 0; i < 10; i++) {
      const a = letters.splice(s.uniform(letters.length), 1)[0];
      const b = letters.splice(s.uniform(letters.length), 1)[0];
      plugs.push(String.fromCharCode(65 + a, 65 + b));
    }
    return {
      rotors: rotors as EnigmaKey["rotors"],
      reflector: "B",
      rings: [s.uniform(26), s.uniform(26), s.uniform(26)],
      positions: [s.uniform(26), s.uniform(26), s.uniform(26)],
      plugs,
    };
  },
  // Enigma is reciprocal: the same settings encrypt and decrypt.
  encrypt: (key, pt) => run(key, pt),
  decrypt: (key, ct) => run(key, ct),
};
