/**
 * Attack on v0/v1: messages "in depth" (same settings every time).
 *
 * In v0 and v1 every message under a key starts the rotors at the same
 * positions, so byte i of every message goes through the SAME substitution
 * S_i. An attacker never needs the key. They collect known-plaintext
 * messages and write down a codebook: "at position i, cipher byte c means
 * plaintext p". Reflector machines make this twice as fast, because S_i is
 * its own inverse (learning p→c also gives c→p).
 *
 * Real-world messages have fixed formats (headers, field names, stock phrases),
 * so the codebook fills in exactly the parts that repeat — and they decrypt
 * the next message wherever its plaintext overlaps a previous one.
 *
 * Historically, operators setting the same rotor start for many messages, and
 * reused message keys, gave Bletchley messages "in depth". A per-message
 * nonce (v4) breaks this: each message gets a fresh S_0, S_1, ...
 */
import { randomBytes } from "node:crypto";
import { pathToFileURL } from "node:url";
import { v1 } from "../versions/v1-byte-enigma.js";

export interface DepthResult {
  /** Fraction of the secret message's bytes recovered correctly. */
  recovered: number;
  /** The attacker's reconstruction, with unknown bytes as null. */
  guess: (number | null)[];
}

/**
 * Build a per-position codebook from known (plaintext, ciphertext) pairs and
 * use it to decrypt a new ciphertext.
 * @param reciprocal also record c→p as p→c (valid against reflector machines)
 */
export function depthAttack(
  known: { pt: Uint8Array; ct: Uint8Array }[],
  secretCt: Uint8Array,
  secretPt: Uint8Array,
  reciprocal = true,
): DepthResult {
  const book: Map<number, number>[] = Array.from({ length: secretCt.length }, () => new Map());
  for (const { pt, ct } of known) {
    const n = Math.min(pt.length, ct.length, secretCt.length);
    for (let i = 0; i < n; i++) {
      book[i].set(ct[i], pt[i]);
      if (reciprocal) book[i].set(pt[i], ct[i]);
    }
  }
  const guess = Array.from(secretCt, (c, i) => book[i].get(c) ?? null);
  let ok = 0;
  for (let i = 0; i < guess.length; i++) if (guess[i] === secretPt[i]) ok++;
  return { recovered: guess.length ? ok / guess.length : 0, guess };
}

/** Formatted weather reports: realistic fixed structure with varying fields. */
export function weatherReport(i: number, rand: () => number): string {
  const stations = ["Biskaya", "Nordsee", "Kanal", "Ostsee", "Atlantik"];
  const dirs = ["N", "NO", "O", "SO", "S", "SW", "W", "NW"];
  const sea = ["calm", "moderate", "rough", "very rough"];
  const vis = ["good", "moderate", "poor"];
  const pick = <T>(a: T[]) => a[Math.floor(rand() * a.length)];
  const hh = String(Math.floor(rand() * 24)).padStart(2, "0");
  return (
    `WEATHER REPORT ${String(i).padStart(4, "0")} station=${pick(stations)} time=${hh}00 ` +
    `wind=${pick(dirs)} ${Math.floor(rand() * 12)} kn sea=${pick(sea)} visibility=${pick(vis)} ENDS\n`
  );
}

function main() {
  const enc = new TextEncoder();
  const key = v1.keygen(randomBytes(16));
  const rand = Math.random;
  const secretText = weatherReport(9999, rand);
  const secretPt = enc.encode(secretText);
  const secretCt = v1.encrypt(key, secretPt);

  console.log("v1, same key and same start positions for every message.");
  console.log("Attacker has k earlier reports with their plaintext, plus one new ciphertext.\n");
  console.log(`secret: ${secretText.trim()}\n`);
  for (const k of [1, 5, 20, 100]) {
    const known = Array.from({ length: k }, (_, i) => {
      const pt = enc.encode(weatherReport(i, rand));
      return { pt, ct: v1.encrypt(key, pt) };
    });
    const r = depthAttack(known, secretCt, secretPt);
    const shown = r.guess.map((b) => (b === null ? "·" : b === 10 ? "" : String.fromCharCode(b))).join("");
    console.log(`k=${String(k).padStart(3)}  ${(r.recovered * 100).toFixed(0).padStart(3)}% recovered  ${shown}`);
  }
  console.log("\nNo key recovered, none needed. Fixed by a fresh nonce per message (v4).");
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
