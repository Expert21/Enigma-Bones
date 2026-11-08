/**
 * Attack on v0: a simplified Turing–Welchman Bombe.
 *
 * Inputs: ciphertext, a crib (guessed plaintext such as "WETTERVORHERSAGE")
 * and where it sits in the message. Rotor wirings are known (captured).
 *
 * For every rotor order and starting position, the Bombe asks: "is there a
 * plugboard consistent with this crib?" It doesn't search the ~1.5e14
 * plugboards. Instead it guesses one plug, P(L) = x, and follows logical
 * consequences around the crib's "menu":
 *
 *   crib letter a ↔ cipher letter b at step i   ⇒   P(b) = S_i(P(a))
 *   (S_i = rotors + reflector at step i, P = plugboard)
 *   plus the "diagonal board": P(a) = y  ⇒  P(y) = a
 *
 * If that ever forces some letter to plug to two different letters, the
 * guess is impossible. Positions that survive are "stops".
 *
 * Flaws exploited: known wirings, reciprocity (S_i is its own inverse), and
 * the plugboard staying fixed during the message.
 *
 * Simplification: ring settings are taken as known (A-A-A in the demo).
 * Historically the Bombe found rotor "core" offsets and the rings were
 * worked out afterwards.
 */
import { pathToFileURL } from "node:url";
import { randomBytes } from "node:crypto";
import {
  EnigmaMachine,
  ROTOR_NAMES,
  encryptText,
  normalize,
  v0,
  type EnigmaKey,
  type ReflectorName,
  type RotorName,
} from "../versions/v0-enigma.js";

export interface BombeStop {
  rotors: [RotorName, RotorName, RotorName];
  positions: [number, number, number];
  /** Plug pairs deduced from the stop, e.g. ["AQ", "EE" (= unplugged)]. */
  deducedPlugs: Map<number, number>;
}

const A = 65;
const letter = (n: number) => String.fromCharCode(A + n);

/** Offsets where the crib could sit: Enigma never encrypts a letter to itself. */
export function possibleCribOffsets(ciphertext: string, crib: string): number[] {
  const out: number[] = [];
  for (let k = 0; k + crib.length <= ciphertext.length; k++) {
    let ok = true;
    for (let j = 0; j < crib.length && ok; j++) if (crib[j] === ciphertext[k + j]) ok = false;
    if (ok) out.push(k);
  }
  return out;
}

export function allRotorOrders(): [RotorName, RotorName, RotorName][] {
  const out: [RotorName, RotorName, RotorName][] = [];
  for (const l of ROTOR_NAMES)
    for (const m of ROTOR_NAMES)
      for (const r of ROTOR_NAMES) if (l !== m && m !== r && l !== r) out.push([l, m, r]);
  return out;
}

export function bombe(
  ciphertext: string,
  crib: string,
  cribOffset: number,
  rotorOrders: [RotorName, RotorName, RotorName][],
  reflector: ReflectorName = "B",
): BombeStop[] {
  const n = crib.length;
  const p = Array.from(crib, (c) => c.charCodeAt(0) - A);
  const c = Array.from(ciphertext.slice(cribOffset, cribOffset + n), (ch) => ch.charCodeAt(0) - A);
  for (let i = 0; i < n; i++) if (p[i] === c[i]) throw new Error("crib letter equals cipher letter: impossible offset");

  // Menu: for each letter, the (other letter, crib index) edges touching it.
  const edges: [number, number][][] = Array.from({ length: 26 }, () => []);
  const degree = new Array(26).fill(0);
  for (let i = 0; i < n; i++) {
    edges[p[i]].push([c[i], i]);
    edges[c[i]].push([p[i], i]);
    degree[p[i]]++;
    degree[c[i]]++;
  }
  const testLetter = degree.indexOf(Math.max(...degree));

  const S = Array.from({ length: n }, () => new Uint8Array(26));
  const image = new Int8Array(26);
  const queue = new Int16Array(26 * 26 * 2);
  const stops: BombeStop[] = [];

  for (const rotors of rotorOrders) {
    for (let start = 0; start < 26 ** 3; start++) {
      const positions: [number, number, number] = [Math.floor(start / 676), Math.floor(start / 26) % 26, start % 26];
      const m = new EnigmaMachine({ rotors, reflector, rings: [0, 0, 0], positions, plugs: [] });
      for (let k = 0; k < cribOffset; k++) m.step();
      for (let i = 0; i < n; i++) {
        m.step();
        for (let x = 0; x < 26; x++) S[i][x] = m.scramble(x);
      }

      for (let guess = 0; guess < 26; guess++) {
        image.fill(-1);
        let qh = 0;
        let qt = 0;
        let contradiction = false;
        const light = (a: number, y: number) => {
          if (image[a] === y) return;
          if (image[a] !== -1) {
            contradiction = true;
            return;
          }
          image[a] = y;
          queue[qt++] = a;
          queue[qt++] = y;
          if (image[y] !== a) light(y, a); // diagonal board
        };
        light(testLetter, guess);
        while (qh < qt && !contradiction) {
          const a = queue[qh++];
          const y = queue[qh++];
          for (const [b, i] of edges[a]) {
            light(b, S[i][y]);
            if (contradiction) break;
          }
        }
        if (!contradiction) {
          const deducedPlugs = new Map<number, number>();
          for (let a = 0; a < 26; a++) if (image[a] !== -1) deducedPlugs.set(a, image[a]);
          stops.push({ rotors, positions, deducedPlugs });
        }
      }
    }
  }
  return stops;
}

/** Turn a stop into a usable (possibly partial) key. */
export function stopToKey(stop: BombeStop, reflector: ReflectorName = "B"): EnigmaKey {
  const plugs: string[] = [];
  for (const [a, b] of stop.deducedPlugs) if (a < b) plugs.push(letter(a) + letter(b));
  return { rotors: stop.rotors, reflector, rings: [0, 0, 0], positions: stop.positions, plugs };
}

/** Accept a stop if its partial key decrypts the crib exactly. */
export function verifyStop(stop: BombeStop, ciphertext: string, crib: string, offset: number): boolean {
  const key = stopToKey(stop);
  const pt = encryptText(key, ciphertext);
  let match = 0;
  for (let j = 0; j < crib.length; j++) if (pt[offset + j] === crib[j]) match++;
  return match === crib.length;
}

// ---------------------------------------------------------------------------
// Demo: npx tsx src/attacks/bombe.ts [--all-orders] [--seed hex]
// ---------------------------------------------------------------------------
function main() {
  const args = process.argv.slice(2);
  const seedArg = args[args.indexOf("--seed") + 1];
  const seed = args.includes("--seed") ? Buffer.from(seedArg, "hex") : randomBytes(16);
  const allOrders = args.includes("--all-orders");

  const key: EnigmaKey = { ...v0.keygen(seed), rings: [0, 0, 0] };
  const plaintext = normalize(
    "Wettervorhersage Biskaya: Regen, Sturm aus West, zwei fuenf Knoten, Sicht schlecht. " +
      "Keine besonderen Ereignisse. Heil Hitler.",
  );
  const ciphertext = encryptText(key, plaintext);
  const crib = "WETTERVORHERSAGEBISKAYA";

  console.log(`secret key   : ${key.rotors.join("-")}  pos ${key.positions.map(letter).join("")}  plugs ${key.plugs.join(" ")}`);
  console.log(`ciphertext   : ${ciphertext}`);
  console.log(`crib         : ${crib} (offsets allowed by "no self-encryption": ${possibleCribOffsets(ciphertext, crib).length} of ${ciphertext.length - crib.length + 1})`);

  const orders = allOrders ? allRotorOrders() : [key.rotors];
  console.log(`searching    : ${orders.length} rotor order(s) × 17,576 positions × 26 plug guesses...`);
  const t0 = performance.now();
  const stops = bombe(ciphertext, crib, 0, orders);
  const verified = stops.filter((s) => verifyStop(s, ciphertext, crib, 0));
  const ms = (performance.now() - t0).toFixed(0);
  console.log(`bombe stops  : ${stops.length} raw, ${verified.length} verified on the crib (${ms} ms)`);

  for (const s of verified) {
    const k = stopToKey(s);
    const hit = s.rotors.join() === key.rotors.join() && s.positions.join() === key.positions.join();
    console.log(`\n${hit ? "✔ correct key found" : "✘ false stop"}: ${s.rotors.join("-")} pos ${s.positions.map(letter).join("")}`);
    console.log(`  deduced plugs: ${k.plugs.join(" ") || "(none)"}`);
    console.log(`  decrypt      : ${encryptText(k, ciphertext)}`);
  }
  console.log("\nPlugs the crib didn't touch stay unknown; letters they affect come out wrong and are fixed by reading the text.");
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
