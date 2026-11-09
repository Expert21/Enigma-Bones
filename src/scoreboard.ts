/**
 * Scoreboard: the same battery of measurements against every version, plus
 * AES-256-CTR as a modern reference row. This is how "how far did we push
 * Enigma" gets measured instead of guessed.
 *
 *   npx tsx src/scoreboard.ts [--practrand GB]
 *
 * Writes docs/SCOREBOARD.md and analysis/scoreboard.json.
 *
 * Every metric is reported as a ratio to what an ideal cipher would give, so
 * 1.00 is "indistinguishable from random" in that test.
 */
import { createCipheriv, randomBytes } from "node:crypto";
import { spawnSync, spawn } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { depthAttack, weatherReport } from "./attacks/depth.js";
import { VERSIONS } from "./index.js";
import { normalize } from "./versions/v0-enigma.js";

/** What the scoreboard needs from a cipher. */
interface Target {
  label: string;
  alphabet: number;
  /** Turn text into this cipher's plaintext alphabet. */
  prepare(text: string): Uint8Array;
  /** The "zero" symbol, for raw-output tests. */
  zero: number;
  newKey(): unknown;
  /** Encrypt one message the way a user would (fresh nonce if the cipher takes one). */
  encryptMessage(key: unknown, pt: Uint8Array): { ct: Uint8Array; nonce?: Uint8Array };
  decryptMessage(key: unknown, ct: Uint8Array, nonce?: Uint8Array): Uint8Array;
}

const enc = new TextEncoder();

function versionTarget(id: number): Target {
  const v = VERSIONS[id];
  const letters = id === 0;
  const nl = v.nonceLength ?? 0;
  return {
    label: `v${id} ${v.name}`,
    alphabet: letters ? 26 : 256,
    prepare: (t) => (letters ? enc.encode(normalize(t)) : enc.encode(t)),
    zero: letters ? 65 : 0,
    newKey: () => v.keygen(randomBytes(16)),
    encryptMessage(key, pt) {
      const nonce = nl ? randomBytes(nl) : undefined;
      return { ct: v.encrypt(key, pt, nonce), nonce };
    },
    decryptMessage: (key, ct, nonce) => v.decrypt(key, ct, nonce),
  };
}

const aesTarget: Target = {
  label: "AES-256-CTR (reference)",
  alphabet: 256,
  prepare: (t) => enc.encode(t),
  zero: 0,
  newKey: () => randomBytes(32),
  encryptMessage(key, pt) {
    const nonce = randomBytes(16);
    const c = createCipheriv("aes-256-ctr", key as Buffer, nonce);
    return { ct: Uint8Array.from(Buffer.concat([c.update(pt), c.final()])), nonce };
  },
  decryptMessage(key, ct, nonce) {
    const c = createCipheriv("aes-256-ctr", key as Buffer, nonce!);
    return Uint8Array.from(Buffer.concat([c.update(ct), c.final()]));
  },
};

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

function corpus(t: Target, bytes: number): Uint8Array {
  const parts: string[] = [];
  let n = 0;
  for (let i = 0; n < bytes * 1.5; i++) {
    const r = weatherReport(i, Math.random);
    parts.push(r);
    n += r.length;
  }
  return t.prepare(parts.join("")).subarray(0, bytes);
}

/** Self-match rate vs chance. Reflector machines score 0. Ideal ≈ 1. */
function selfMatch(t: Target, key: unknown) {
  const pt = corpus(t, 64 * 1024);
  const { ct } = t.encryptMessage(key, pt);
  let m = 0;
  for (let i = 0; i < pt.length; i++) if (pt[i] === ct[i]) m++;
  return m / (pt.length / t.alphabet);
}

/** Index of coincidence of ciphertext × alphabet. Flat = 1. Plaintext is far higher. */
function flatness(t: Target, key: unknown) {
  const { ct } = t.encryptMessage(key, corpus(t, 64 * 1024));
  return ioc(ct, t.alphabet);
}

function ioc(data: Uint8Array, alphabet: number) {
  const counts = new Float64Array(256);
  for (const b of data) counts[b]++;
  let s = 0;
  for (const c of counts) s += c * (c - 1);
  return (s / (data.length * (data.length - 1))) * alphabet;
}

/** Output for an all-"zero" input: the machine's raw substitution stream. */
function rawOutput(t: Target, key: unknown, n: number) {
  return t.encryptMessage(key, new Uint8Array(n).fill(t.zero)).ct;
}

/** Chi-square of raw output symbol counts, as a z-score. |z| < ~4 is fine. */
function biasZ(t: Target, key: unknown) {
  const out = rawOutput(t, key, 1 << 20);
  const counts = new Float64Array(256);
  for (const b of out) counts[b]++;
  const exp = out.length / t.alphabet;
  let chi = 0;
  for (let s = 0; s < 256; s++) {
    if (t.alphabet === 26 && (s < 65 || s > 90)) continue;
    chi += (counts[s] - exp) ** 2 / exp;
  }
  const df = t.alphabet - 1;
  // Wilson–Hilferty: chi²/df is approx normal
  const x = Math.cbrt(chi / df);
  return (x - (1 - 2 / (9 * df))) / Math.sqrt(2 / (9 * df));
}

/**
 * Strongest repeat in raw output: max over lags 1–2048 of match rate vs chance.
 * With 256 KB, random noise alone gives about 1 + 3.5·sqrt(alphabet/n):
 * ≈ 1.11 for bytes, ≈ 1.035 for letters. Anything clearly above that is structure.
 */
function repeatStructure(t: Target, key: unknown) {
  const out = rawOutput(t, key, 256 * 1024);
  let best = 0;
  let bestLag = 0;
  for (let lag = 1; lag <= 2048; lag++) {
    let m = 0;
    const n = out.length - lag;
    for (let i = 0; i < n; i++) if (out[i] === out[i + lag]) m++;
    const r = m / (n / t.alphabet);
    if (r > best) {
      best = r;
      bestLag = lag;
    }
  }
  return { ratio: best, lag: bestLag };
}

/** Depth attack: % of a new message recovered from 20 known messages under the same key. */
function depth(t: Target, key: unknown) {
  let total = 0;
  const trials = 5;
  for (let trial = 0; trial < trials; trial++) {
    const known = Array.from({ length: 20 }, (_, i) => {
      const pt = t.prepare(weatherReport(i, Math.random));
      return { pt, ct: t.encryptMessage(key, pt).ct };
    });
    const secretPt = t.prepare(weatherReport(9000 + trial, Math.random));
    total += depthAttack(known, t.encryptMessage(key, secretPt).ct, secretPt).recovered;
  }
  return total / trials;
}

/** Ciphertext bytes changed by editing 1 plaintext byte at the start of a 4 KB message. */
function diffusion(t: Target, key: unknown) {
  // Same nonce for both so we only see the effect of the plaintext edit.
  const pt = corpus(t, 4096);
  let changed = 0;
  const trials = 10;
  for (let k = 0; k < trials; k++) {
    const pt2 = Uint8Array.from(pt);
    pt2[0] = t.alphabet === 26 ? 65 + ((pt2[0] - 65 + 1 + k) % 26) : pt2[0] ^ (1 << (k % 8));
    const a = t.encryptMessage(key, pt);
    const b = encryptWithNonce(t, key, pt2, a.nonce);
    for (let i = 0; i < a.ct.length; i++) if (a.ct[i] !== b[i]) changed++;
  }
  return changed / trials;
}

function encryptWithNonce(t: Target, key: unknown, pt: Uint8Array, nonce?: Uint8Array) {
  if (t === aesTarget) {
    const c = createCipheriv("aes-256-ctr", key as Buffer, nonce!);
    return Uint8Array.from(Buffer.concat([c.update(pt), c.final()]));
  }
  // Version targets: re-encrypt with the same nonce through the version directly.
  const id = Number(t.label.slice(1, t.label.indexOf(" ")));
  return VERSIONS[id].encrypt(key, pt, nonce);
}

/** Every message must decrypt back exactly. */
function decrypts(t: Target, key: unknown) {
  for (let i = 0; i < 50; i++) {
    const pt = t.alphabet === 26 ? corpus(t, Math.floor(Math.random() * 2000)) : randomBytes(Math.floor(Math.random() * 5000));
    const { ct, nonce } = t.encryptMessage(key, pt);
    const back = t.decryptMessage(key, ct, nonce);
    if (back.length !== pt.length || back.some((b, j) => b !== pt[j])) return false;
  }
  return true;
}

function speed(t: Target, key: unknown) {
  const n = t.alphabet === 26 ? 1 << 20 : 8 << 20;
  const pt = new Uint8Array(n).fill(t.zero);
  t.encryptMessage(key, pt.subarray(0, 4096));
  const t0 = performance.now();
  t.encryptMessage(key, pt);
  return n / 2 ** 20 / ((performance.now() - t0) / 1000);
}

/** Optional: stream raw output into PractRand, report GB passed before first FAIL. */
async function practrand(t: Target, key: unknown, maxGB: number): Promise<string> {
  if (spawnSync("sh", ["-c", "command -v RNG_test"]).status !== 0) return "not run";
  if (t.alphabet !== 256) return "n/a";
  return new Promise((resolve) => {
    const p = spawn("RNG_test", ["stdin8", "-tlmax", `${maxGB}GB`, "-multithreaded"]);
    let log = "";
    p.stdout.on("data", (d) => (log += d));
    p.stdin.on("error", () => {});
    const chunk = 4 << 20;
    const pump = () => {
      while (!p.stdin.destroyed) {
        if (!p.stdin.write(rawOutput(t, key, chunk))) return void p.stdin.once("drain", pump);
      }
    };
    pump();
    p.on("close", () => {
      const fail = log.match(/length=\s*([\d.]+\s*\w+)[^\n]*\n(?:(?!length=)[\s\S])*?FAIL/);
      resolve(fail ? `fails at ${fail[1]}` : `passes ${maxGB} GB`);
    });
  });
}

// ---------------------------------------------------------------------------

interface Row {
  target: string;
  decrypts: boolean;
  selfMatch: number;
  flatness: number;
  biasZ: number;
  repeat: number;
  repeatLag: number;
  depth: number;
  diffusion: number;
  mbps: number;
  practrand: string;
}

async function main() {
  const args = process.argv.slice(2);
  const prGB = args.includes("--practrand") ? Number(args[args.indexOf("--practrand") + 1] ?? 1) : 0;
  const targets = [...Object.keys(VERSIONS).map(Number).sort((a, b) => a - b).map(versionTarget), aesTarget];
  const rows: Row[] = [];
  for (const t of targets) {
    process.stderr.write(`measuring ${t.label}...\n`);
    const key = t.newKey();
    const rep = repeatStructure(t, key);
    rows.push({
      target: t.label,
      decrypts: decrypts(t, key),
      selfMatch: selfMatch(t, key),
      flatness: flatness(t, key),
      biasZ: biasZ(t, key),
      repeat: rep.ratio,
      repeatLag: rep.lag,
      depth: depth(t, key),
      diffusion: diffusion(t, key),
      mbps: speed(t, key),
      practrand: prGB ? await practrand(t, key, prGB) : "not run",
    });
  }

  const f2 = (x: number) => x.toFixed(2);
  const header =
    "| Target | Decrypts | Self-match | Flatness | Bias z | Worst repeat | Depth attack | Diffusion | MB/s | PractRand |\n" +
    "|---|---|---|---|---|---|---|---|---|---|\n";
  const body = rows
    .map(
      (r) =>
        `| ${r.target} | ${r.decrypts ? "✓" : "✗"} | ${f2(r.selfMatch)} | ${f2(r.flatness)} | ${r.biasZ.toFixed(1)} | ${f2(r.repeat)} (lag ${r.repeatLag}) | ${(r.depth * 100).toFixed(0)}% | ${r.diffusion.toFixed(1)} B | ${r.mbps.toFixed(0)} | ${r.practrand} |`,
    )
    .join("\n");
  const table = header + body + "\n";
  console.log("\n" + table);

  const md = `# Scoreboard

Generated by \`npx tsx src/scoreboard.ts\` on ${new Date().toISOString().slice(0, 10)}. Numbers vary slightly per run (random keys).

${table}
## How to read it

| Column | Meaning | Ideal |
|---|---|---|
| Decrypts | 50 random messages encrypt and decrypt back exactly | ✓ (required) |
| Self-match | How often a plaintext byte encrypts to itself, ÷ chance | 1.00 (reflector machines: 0.00) |
| Flatness | Index of coincidence of ciphertext × alphabet size | 1.00 (plaintext is much higher) |
| Bias z | Chi-square of raw output (encrypting all zeros), as a z-score | between −4 and 4 |
| Worst repeat | Highest match rate of raw output against itself at any lag 1–2048, ÷ chance | noise level: ≈ 1.11 (bytes), ≈ 1.04 (letters) |
| Depth attack | % of a new message recovered from 20 known messages under the same key | a few % (see note) |
| Diffusion | Ciphertext bytes changed by editing 1 plaintext byte (4 KB message) | see note |
| MB/s | Encryption speed (single core, Node) | higher is better |
| PractRand | Raw output through PractRand (\`--practrand GB\`; needs RNG_test) | passes |

**Note on bias:** for v0/v1 the bias is entirely the reflector again. Encrypting
all zeros can never output a zero, and with that symbol excluded the rest of
the output is flat (z ≈ 1). It's the self-match flaw seen from another angle.

**Note on the depth attack:** a few % happens even against AES. The messages
share a fixed format, so a codebook "guess" of the template text is sometimes
right by luck. The real signal is the gap: ~95%+ for v0/v1 against a few %.

**Note on diffusion:** AES-256-CTR scores 1 byte too. Stream ciphers don't
diffuse plaintext edits; tampering is stopped by a MAC (v6), not by diffusion.
A score of 1 only matters when combined with no MAC, which makes the cipher
malleable.

**Note on borrowed parts:** see "Borrowed vs rotor" in VERSIONS.md. Where a
score is good because of SHA-256 or HMAC rather than the rotors, VERSIONS.md
says so.
`;
  writeFileSync("docs/SCOREBOARD.md", md);
  mkdirSync("analysis", { recursive: true });
  writeFileSync("analysis/scoreboard.json", JSON.stringify({ date: new Date().toISOString(), rows }, null, 2) + "\n");
  process.stderr.write("wrote docs/SCOREBOARD.md and analysis/scoreboard.json\n");
}

main();
