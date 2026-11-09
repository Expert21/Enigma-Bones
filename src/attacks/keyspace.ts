/**
 * Keyspace and attack-cost comparison, v0 vs v1.
 *
 * v0's real weakness wasn't key size (≈ 2^76 with the plugboard). It was that
 * the Bombe could skip the plugboard and search just order × positions, with
 * the wirings known. v1 generates every table from a 256-bit secret, so:
 *   - no known wirings → the Bombe's scrambler tables can't be computed;
 *   - brute force is 2^256 → out of reach, even at absurd speeds.
 */
import { pathToFileURL } from "node:url";

const log2Fact = (n: number) => {
  let s = 0;
  for (let i = 2; i <= n; i++) s += Math.log2(i);
  return s;
};
const log2Choose = (n: number, k: number) => log2Fact(n) - log2Fact(k) - log2Fact(n - k);

/** Ways to choose p disjoint pairs from n symbols. */
export const log2Plugboard = (n: number, p: number) => log2Fact(n) - log2Fact(n - 2 * p) - log2Fact(p) - p;

export function v0Keyspace() {
  const orders = Math.log2(60);
  const positions = 3 * Math.log2(26);
  const rings = 2 * Math.log2(26); // the left ring has no effect on the output
  const plugs = log2Plugboard(26, 10);
  const bombeWork = Math.log2(60 * 26 ** 3 * 26); // orders × positions × one plug guess
  return { orders, positions, rings, plugs, total: orders + positions + rings + plugs, bombeWork };
}

export function v1Keyspace(rotors = 5) {
  const tables =
    rotors * log2Fact(256) + // wirings
    rotors * 8 * 2 + // notches + start positions
    (log2Fact(256) - log2Fact(128) - 128) + // reflector: perfect matchings of 256
    log2Plugboard(256, 64);
  return { secret: 256, tables, effective: Math.min(256, tables) };
}

const years = (log2Ops: number, perSecond = 1e12) => 2 ** log2Ops / perSecond / 3.156e7;

function main() {
  const a = v0Keyspace();
  const b = v1Keyspace();
  const f = (x: number) => `2^${x.toFixed(1)}`;
  console.log("v0 (Enigma I, 5 rotors, 10 plugs)");
  console.log(`  rotor order ${f(a.orders)} · positions ${f(a.positions)} · rings ${f(a.rings)} · plugboard ${f(a.plugs)}`);
  console.log(`  total keyspace ${f(a.total)}  — but the Bombe searches only ${f(a.bombeWork)} (plugboard skipped, wirings known)`);
  console.log("\nv1 (byte Enigma, 5 keyed rotors)");
  console.log(`  possible table sets ${f(b.tables)}, but they come from a 256-bit secret → effective ${f(b.effective)}`);
  console.log(`  Bombe: not applicable (needs known wirings)`);
  console.log(`  brute force at 10^12 keys/s: ~${years(b.effective - 1).toExponential(1)} years on average`);
  console.log("\nKeyspace isn't security: v0's 2^76 keys fell to a 2^25 search. v1's table generation is");
  console.log("SHA-256's work (borrowed), and v1 is still broken structurally:");
  console.log("  - same settings every message → depth.ts reads new messages without the key");
  console.log("  - the reflector's fingerprint  → self-encryption.ts");
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
