import { describe, expect, it } from "vitest";
import { createCipheriv, randomBytes } from "node:crypto";
import { depthAttack, weatherReport } from "../src/attacks/depth.js";
import { v1 } from "../src/versions/v1-byte-enigma.js";

const enc = new TextEncoder();
const reports = (n: number, offset = 0) => Array.from({ length: n }, (_, i) => enc.encode(weatherReport(offset + i, Math.random)));

describe("depth attack (same settings for every message)", () => {
  it("reads most of a new v1 message from 20 known ones, without the key", () => {
    const key = v1.keygen(randomBytes(16));
    const known = reports(20).map((pt) => ({ pt, ct: v1.encrypt(key, pt) }));
    const [secret] = reports(1, 9000);
    expect(depthAttack(known, v1.encrypt(key, secret), secret).recovered).toBeGreaterThan(0.75);
  });

  it("gets almost nothing when every message has a fresh nonce (AES-CTR)", () => {
    const key = randomBytes(32);
    const aes = (pt: Uint8Array) => {
      const c = createCipheriv("aes-256-ctr", key, randomBytes(16));
      return Uint8Array.from(Buffer.concat([c.update(pt), c.final()]));
    };
    const known = reports(20).map((pt) => ({ pt, ct: aes(pt) }));
    const [secret] = reports(1, 9000);
    expect(depthAttack(known, aes(secret), secret).recovered).toBeLessThan(0.2);
  });
});
