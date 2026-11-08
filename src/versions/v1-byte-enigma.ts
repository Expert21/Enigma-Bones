/**
 * v1 — Byte Enigma with key-generated wirings.
 *
 * Fixes from v0:
 *  - Alphabet is all 256 byte values instead of A–Z, so it encrypts any file.
 *  - Rotor wirings, reflector, plugboard, notches and start positions are all
 *    generated from a 256-bit secret. Nothing is fixed hardware that can be
 *    captured, and the Bombe (which needs known wirings) has nothing to run on.
 *  - 5 rotors by default (configurable), instead of 3 picked from 5.
 *
 * Kept on purpose (fixed in later versions):
 *  - The reflector, so the machine is still its own inverse and a byte
 *    never encrypts to itself (→ v2).
 *  - Regular odometer stepping with the double step (→ v3).
 *  - Same start positions for every message under one key (→ v4).
 */
import { HashStream } from "../common/kdf.js";
import { invert, keyedShuffle, type Perm } from "../common/perm.js";
import type { CipherVersion } from "../common/types.js";

export interface V1Key {
  /** 32-byte secret; every table is derived from it. */
  secret: Uint8Array;
  /** Number of rotors (default 5). */
  rotors?: number;
}

export const V1_DEFAULT_ROTORS = 5;
const PLUG_PAIRS = 64; // 128 of 256 byte values are swapped, like 20 of 26 letters on Enigma

/** All tables a v1 key expands into. Exposed so attacks and tests can inspect them. */
export interface V1Tables {
  fwd: Perm[];
  bwd: Perm[];
  notch: Uint8Array;
  reflector: Perm;
  plugboard: Perm;
  start: Uint8Array;
}

/** Random pairing of all 256 values: an involution with no fixed points. */
function keyedReflector(s: HashStream): Perm {
  const order = keyedShuffle(256, (n) => s.uniform(n));
  const r = new Uint8Array(256);
  for (let i = 0; i < 256; i += 2) {
    r[order[i]] = order[i + 1];
    r[order[i + 1]] = order[i];
  }
  return r;
}

/** Plugboard: PLUG_PAIRS random swaps, every other value left alone. */
function keyedPlugboard(s: HashStream): Perm {
  const order = keyedShuffle(256, (n) => s.uniform(n));
  const p = Uint8Array.from({ length: 256 }, (_, i) => i);
  for (let i = 0; i < PLUG_PAIRS * 2; i += 2) {
    p[order[i]] = order[i + 1];
    p[order[i + 1]] = order[i];
  }
  return p;
}

export function expandV1Key(key: V1Key): V1Tables {
  if (key.secret.length !== 32) throw new RangeError("v1 secret must be 32 bytes");
  const n = key.rotors ?? V1_DEFAULT_ROTORS;
  if (!Number.isInteger(n) || n < 1 || n > 32) throw new RangeError("v1 rotor count must be 1–32");
  const s = new HashStream(key.secret, "v1-tables");
  const fwd: Perm[] = [];
  for (let i = 0; i < n; i++) fwd.push(keyedShuffle(256, (k) => s.uniform(k)));
  const notch = Uint8Array.from({ length: n }, () => s.uniform(256));
  const start = Uint8Array.from({ length: n }, () => s.uniform(256));
  return { fwd, bwd: fwd.map(invert), notch, reflector: keyedReflector(s), plugboard: keyedPlugboard(s), start };
}

/**
 * Rotor 0 is the leftmost (slowest), rotor n-1 the rightmost (fastest).
 * Generalised Enigma stepping: the rightmost rotor always steps; a rotor at
 * its notch carries the rotor to its left, and a non-rightmost rotor at its
 * notch also steps itself (the double step).
 */
export class V1Machine {
  readonly pos: Uint8Array;
  private readonly n: number;
  private readonly carry: Uint8Array;

  constructor(readonly t: V1Tables) {
    this.n = t.fwd.length;
    this.pos = Uint8Array.from(t.start);
    this.carry = new Uint8Array(this.n);
  }

  step(): void {
    const { n, pos, carry } = this;
    const notch = this.t.notch;
    carry.fill(0);
    carry[n - 1] = 1;
    for (let i = n - 1; i >= 1; i--) {
      if (pos[i] === notch[i]) {
        carry[i - 1] = 1;
        if (i < n - 1) carry[i] = 1; // double step
      }
    }
    for (let i = 0; i < n; i++) if (carry[i]) pos[i] = (pos[i] + 1) & 255;
  }

  scramble(c: number): number {
    const { fwd, bwd, reflector } = this.t;
    const pos = this.pos;
    for (let i = this.n - 1; i >= 0; i--) c = (fwd[i][(c + pos[i]) & 255] - pos[i]) & 255;
    c = reflector[c];
    for (let i = 0; i < this.n; i++) c = (bwd[i][(c + pos[i]) & 255] - pos[i]) & 255;
    return c;
  }

  press(c: number): number {
    this.step();
    const p = this.t.plugboard;
    return p[this.scramble(p[c])];
  }
}

/**
 * Fast path: the same machine as V1Machine.press, with tables flattened into
 * single arrays and the stepping inlined. The tests check the two agree.
 */
function run(key: V1Key, data: Uint8Array): Uint8Array {
  const t = expandV1Key(key);
  const n = t.fwd.length;
  const fwd = new Uint8Array(n * 256);
  const bwd = new Uint8Array(n * 256);
  for (let i = 0; i < n; i++) {
    fwd.set(t.fwd[i], i * 256);
    bwd.set(t.bwd[i], i * 256);
  }
  const { reflector, plugboard, notch } = t;
  const pos = Uint8Array.from(t.start);
  const out = new Uint8Array(data.length);

  for (let k = 0; k < data.length; k++) {
    // Step, same rules as V1Machine.step, right to left in one pass:
    // rotor i moves if the rotor to its right was at its notch (carry), or it
    // is the rightmost rotor, or it is a middle rotor at its own notch (double step).
    let carry = 1;
    for (let i = n - 1; i >= 0; i--) {
      const atNotch = i > 0 && pos[i] === notch[i];
      const moves = carry | (atNotch && i < n - 1 ? 1 : 0);
      carry = atNotch ? 1 : 0;
      pos[i] = (pos[i] + moves) & 255;
    }

    // signal path
    let c = plugboard[data[k]];
    for (let i = n - 1; i >= 0; i--) c = (fwd[(i << 8) | ((c + pos[i]) & 255)] - pos[i]) & 255;
    c = reflector[c];
    for (let i = 0; i < n; i++) c = (bwd[(i << 8) | ((c + pos[i]) & 255)] - pos[i]) & 255;
    out[k] = plugboard[c];
  }
  return out;
}

export const v1: CipherVersion<V1Key> = {
  id: 1,
  name: "Byte Enigma, keyed wirings",
  keygen(seed) {
    const s = new HashStream(seed, "v1-keygen");
    return { secret: Uint8Array.from({ length: 32 }, () => s.nextByte()) };
  },
  // Still reciprocal: the same key encrypts and decrypts (the reflector's doing).
  encrypt: (key, pt) => run(key, pt),
  decrypt: (key, ct) => run(key, ct),
};
