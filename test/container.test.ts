import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { pack, unpack } from "../src/common/container.js";
import { open, seal } from "../src/index.js";
import { v1 } from "../src/versions/v1-byte-enigma.js";

describe("container and dispatch", () => {
  it("pack/unpack round-trips header fields", () => {
    const body = randomBytes(100);
    const nonce = randomBytes(12);
    const tag = randomBytes(32);
    const p = unpack(pack(7, body, nonce, tag));
    expect(p.version).toBe(7);
    expect(Buffer.from(p.nonce)).toEqual(nonce);
    expect(Buffer.from(p.tag)).toEqual(tag);
    expect(Buffer.from(p.body)).toEqual(body);
  });

  it("rejects garbage and truncated headers", () => {
    expect(() => unpack(new Uint8Array([1, 2, 3, 4, 5]))).toThrow();
    expect(() => unpack(new Uint8Array([0x45, 0x42, 1, 200, 0]))).toThrow();
  });

  it("open() picks the right version from the header", () => {
    const key = v1.keygen(randomBytes(16));
    const pt = randomBytes(5000);
    const blob = seal(v1, key, pt);
    expect(blob[2]).toBe(1);
    expect(Buffer.from(open(key, blob))).toEqual(pt);
  });

  it("CLI encrypt → decrypt through files restores the original", () => {
    const dir = mkdtempSync(join(tmpdir(), "eb-"));
    const pt = randomBytes(50_000);
    writeFileSync(join(dir, "in.bin"), pt);
    const cli = (...a: string[]) => execFileSync("npx", ["tsx", "src/cli.ts", ...a], { stdio: "pipe" });
    cli("encrypt", "--pass", "correct horse", "--v", "1", join(dir, "in.bin"), join(dir, "ct.eb"));
    cli("decrypt", "--pass", "correct horse", join(dir, "ct.eb"), join(dir, "out.bin"));
    expect(readFileSync(join(dir, "out.bin"))).toEqual(pt);
    expect(readFileSync(join(dir, "ct.eb"))).not.toEqual(pt);
  }, 30_000);
});
