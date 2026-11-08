/**
 * Attack on v1 (and v0): the "never encrypts to itself" flaw.
 *
 * The reflector makes every key position a pairing with no fixed points, so
 * ciphertext byte i is NEVER equal to plaintext byte i. A good cipher matches
 * by chance 1 time in 256.
 *
 * Two uses:
 *  1. Distinguisher (known plaintext): count matches. Random → about n/256.
 *     v0/v1 → exactly 0. With a few KB we can say "this is a reflector
 *     machine" with near certainty. Telling a cipher apart from random is
 *     already a break by modern standards.
 *  2. Crib dragging (ciphertext only): a crib can't sit anywhere it would
 *     line up a byte with itself, which rules out positions for free.
 *
 * Lesson from v0 → v1: with 256 symbols instead of 26 each position rules
 * out far less, so crib dragging gets weaker — but the distinguisher still
 * works perfectly. Making the alphabet bigger dilutes the flaw without fixing
 * it; v2 fixes it by removing the reflector.
 */
import { createCipheriv, randomBytes } from "node:crypto";
import { pathToFileURL } from "node:url";
import { getVersion } from "../index.js";
import { v0 } from "../versions/v0-enigma.js";

export function selfMatches(pt: Uint8Array, ct: Uint8Array): number {
  let k = 0;
  const n = Math.min(pt.length, ct.length);
  for (let i = 0; i < n; i++) if (pt[i] === ct[i]) k++;
  return k;
}

/**
 * Known-plaintext test. If the cipher behaved randomly, matches would be
 * ~Poisson(n/alphabet); seeing 0 has probability e^(-n/alphabet).
 * Returns log10 of that probability (more negative = stronger evidence).
 */
export function noSelfMatchEvidence(pt: Uint8Array, ct: Uint8Array, alphabet = 256) {
  const matches = selfMatches(pt, ct);
  const expected = Math.min(pt.length, ct.length) / alphabet;
  const log10p = matches === 0 ? -expected / Math.LN10 : 0;
  return { matches, expected, log10p, reflectorLike: matches === 0 && expected >= 10 };
}

/** Offsets where the crib could sit without lining a byte up with itself. */
export function possibleCribOffsets(ct: Uint8Array, crib: Uint8Array): number[] {
  const out: number[] = [];
  outer: for (let k = 0; k + crib.length <= ct.length; k++) {
    for (let j = 0; j < crib.length; j++) if (crib[j] === ct[k + j]) continue outer;
    out.push(k);
  }
  return out;
}

/** A one-time pad over A–Z: the ideal letter cipher, for comparison with v0. */
export function letterOneTimePad(pt: Uint8Array): Uint8Array {
  const r = randomBytes(pt.length);
  return pt.map((c, i) => 65 + ((c - 65 + (r[i] % 26)) % 26));
}

/** A modern reference: AES-256-CTR, for comparison. */
export function aesCtr(pt: Uint8Array): Uint8Array {
  const c = createCipheriv("aes-256-ctr", randomBytes(32), randomBytes(16));
  return Uint8Array.from(Buffer.concat([c.update(pt), c.final()]));
}

// ---------------------------------------------------------------------------
// Demo: npx tsx src/attacks/self-encryption.ts [--target v1]
// ---------------------------------------------------------------------------
function main() {
  const args = process.argv.slice(2);
  const t = args.includes("--target") ? args[args.indexOf("--target") + 1] : "v1";
  const target = Number(t.replace(/^v/, ""));
  const enc = new TextEncoder();

  const record = (i: number) =>
    `{"station":"Biskaya-${i % 7}","wind":"W ${(i * 7) % 12} kn","sea":"rough","visibility":"poor"}\n`;
  const text = Array.from({ length: 60 }, (_, i) => record(i)).join("");

  let pt: Uint8Array;
  let ct: Uint8Array;
  let alphabet: number;
  if (target === 0) {
    pt = enc.encode(text.toUpperCase().replace(/[^A-Z]/g, ""));
    ct = v0.encrypt(v0.keygen(randomBytes(16)), pt);
    alphabet = 26;
  } else {
    const v = getVersion(target);
    pt = enc.encode(text);
    ct = v.encrypt(v.keygen(randomBytes(16)), pt);
    alphabet = 256;
  }

  console.log(`target: v${target}, ${pt.length} bytes of known plaintext\n`);
  console.log("1) Distinguisher — how often does a byte encrypt to itself?");
  const reference = target === 0 ? (["letter OTP", letterOneTimePad(pt)] as const) : (["AES-256-CTR", aesCtr(pt)] as const);
  for (const [name, c] of [[`v${target}`, ct], reference] as const) {
    const e = noSelfMatchEvidence(pt, c, alphabet);
    console.log(
      `   ${name.padEnd(12)} matches ${String(e.matches).padStart(4)}  (random ≈ ${e.expected.toFixed(1)})` +
        (e.reflectorLike ? `  → reflector machine; chance this is random ≈ 10^${e.log10p.toFixed(0)}` : "  → looks random"),
    );
  }

  console.log("\n2) Crib dragging — where could a known phrase sit?");
  const crib = target === 0 ? enc.encode("STATIONBISKAYA") : enc.encode('{"station":"Biskaya-');
  const total = ct.length - crib.length + 1;
  const left = possibleCribOffsets(ct, crib).length;
  console.log(
    `   crib ${JSON.stringify(new TextDecoder().decode(crib))} (${crib.length} bytes): ${total - left} of ${total} offsets ruled out (${(((total - left) / total) * 100).toFixed(1)}%)`,
  );
  console.log(
    `   per position a ${alphabet}-symbol alphabet rules out 1-(${alphabet - 1}/${alphabet})^${crib.length} ≈ ${((1 - ((alphabet - 1) / alphabet) ** crib.length) * 100).toFixed(1)}%`,
  );
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
