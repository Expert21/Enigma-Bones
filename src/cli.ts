/**
 * enigma-bones CLI (educational only, not for real data).
 *
 *   tsx src/cli.ts encrypt  --pass <phrase> [--v N] <in> <out>
 *   tsx src/cli.ts decrypt  --pass <phrase> <in> <out>      (version read from the file)
 *   tsx src/cli.ts keystream --pass <phrase> [--v N] [--bytes N]   (encrypted zeros to stdout, for PractRand)
 *   tsx src/cli.ts bench [--v N] [--mb N]
 *
 * Keys: --key <64 hex chars> or --pass <phrase>. For now a passphrase is
 * simply SHA-256 hashed; v4 introduces a proper slow KDF.
 * v0 works on A–Z settings rather than a byte key, so the CLI starts at v1.
 */
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { getVersion, LATEST, open, seal } from "./index.js";

function arg(args: string[], name: string): string | undefined {
  const i = args.indexOf(name);
  if (i === -1) return undefined;
  const v = args[i + 1];
  args.splice(i, 2);
  return v;
}

function keyFrom(args: string[]): { secret: Uint8Array } {
  const hex = arg(args, "--key");
  const pass = arg(args, "--pass");
  if (hex) {
    if (!/^[0-9a-fA-F]{64}$/.test(hex)) throw new Error("--key must be 64 hex characters");
    return { secret: Buffer.from(hex, "hex") };
  }
  if (pass !== undefined) return { secret: createHash("sha256").update(pass).digest() };
  throw new Error("need --key <hex> or --pass <phrase>");
}

function versionFrom(args: string[]) {
  const id = Number(arg(args, "--v") ?? LATEST);
  if (id < 1) throw new Error("the CLI supports v1 and later (v0 uses letter settings, see the tests)");
  return getVersion(id);
}

function main(argv: string[]): void {
  const [cmd, ...args] = argv;
  switch (cmd) {
    case "encrypt": {
      const key = keyFrom(args);
      const v = versionFrom(args);
      const [inp, out] = args;
      writeFileSync(out, seal(v, key, readFileSync(inp)));
      console.error(`encrypted with v${v.id} (${v.name}) → ${out}`);
      return;
    }
    case "decrypt": {
      const key = keyFrom(args);
      const [inp, out] = args;
      writeFileSync(out, open(key, readFileSync(inp)));
      console.error(`decrypted → ${out}`);
      return;
    }
    case "keystream": {
      // The machine's output for an all-zero input, i.e. its raw substitution
      // stream. One call, so the rotors run continuously for the whole length.
      const key = keyFrom(args);
      const v = versionFrom(args);
      const n = Number(arg(args, "--bytes") ?? 64 << 20);
      process.stdout.on("error", () => process.exit(0)); // reader closed the pipe
      process.stdout.write(v.encrypt(key, new Uint8Array(n)));
      return;
    }
    case "bench": {
      const v = versionFrom(args);
      const mb = Number(arg(args, "--mb") ?? 32);
      const key = v.keygen(new Uint8Array(16));
      const data = new Uint8Array(mb << 20);
      v.encrypt(key, data.subarray(0, 1 << 16)); // warm-up
      const t0 = performance.now();
      v.encrypt(key, data);
      const s = (performance.now() - t0) / 1000;
      console.log(`v${v.id} ${v.name}: ${(mb / s).toFixed(1)} MB/s`);
      return;
    }
    default:
      console.error("usage: cli.ts encrypt|decrypt|keystream|bench ... (see header of src/cli.ts)");
      process.exitCode = 2;
  }
}

try {
  main(process.argv.slice(2));
} catch (e) {
  console.error(`error: ${(e as Error).message}`);
  process.exitCode = 1;
}
