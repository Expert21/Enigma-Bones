/**
 * Permutation helpers. A permutation of size n is a Uint8Array p where
 * p[i] is the image of i. Rotor wirings are permutations.
 */

export type Perm = Uint8Array;

export function identity(n: number): Perm {
  const p = new Uint8Array(n);
  for (let i = 0; i < n; i++) p[i] = i;
  return p;
}

export function isPermutation(p: ArrayLike<number>): boolean {
  const seen = new Uint8Array(p.length);
  for (let i = 0; i < p.length; i++) {
    const v = p[i];
    if (v < 0 || v >= p.length || seen[v]) return false;
    seen[v] = 1;
  }
  return true;
}

export function invert(p: Perm): Perm {
  const inv = new Uint8Array(p.length);
  for (let i = 0; i < p.length; i++) inv[p[i]] = i;
  return inv;
}

/** (a then b): result[i] = b[a[i]] */
export function compose(a: Perm, b: Perm): Perm {
  if (a.length !== b.length) throw new RangeError("compose: size mismatch");
  const r = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) r[i] = b[a[i]];
  return r;
}

/** True if p is its own inverse (p[p[i]] == i), like Enigma's reflector and plugboard. */
export function isInvolution(p: Perm): boolean {
  for (let i = 0; i < p.length; i++) if (p[p[i]] !== i) return false;
  return true;
}

/** Number of fixed points (i where p[i] == i). */
export function fixedPoints(p: Perm): number {
  let n = 0;
  for (let i = 0; i < p.length; i++) if (p[i] === i) n++;
  return n;
}

/** Keyed Fisher–Yates shuffle of the identity permutation. */
export function keyedShuffle(n: number, uniform: (k: number) => number): Perm {
  const p = identity(n);
  for (let i = n - 1; i > 0; i--) {
    const j = uniform(i + 1);
    const t = p[i];
    p[i] = p[j];
    p[j] = t;
  }
  return p;
}

/** Parse an A–Z wiring string ("EKMFLG...") into a permutation of 0..25. */
export function fromLetters(s: string): Perm {
  if (s.length !== 26) throw new RangeError(`wiring must have 26 letters: ${s}`);
  const p = Uint8Array.from(s, (c) => c.charCodeAt(0) - 65);
  if (!isPermutation(p)) throw new RangeError(`not a permutation: ${s}`);
  return p;
}
