import { createHash } from "node:crypto";

/**
 * Deterministic byte stream: SHA-256(seed || label || counter) blocks.
 * Used for key schedules (choosing rotor orders, building keyed wirings, ...).
 * It's a modern primitive on purpose: the key schedule isn't what we're
 * studying, the rotor machinery is.
 */
export class HashStream {
  private buf = new Uint8Array(0);
  private idx = 0;
  private counter = 0;
  constructor(private readonly seed: Uint8Array, private readonly label: string) {}

  private refill(): void {
    const ctr = Buffer.alloc(8);
    ctr.writeBigUInt64BE(BigInt(this.counter++));
    this.buf = createHash("sha256").update(this.seed).update(this.label).update(ctr).digest();
    this.idx = 0;
  }

  nextByte(): number {
    if (this.idx >= this.buf.length) this.refill();
    return this.buf[this.idx++];
  }

  nextU32(): number {
    return ((this.nextByte() << 24) | (this.nextByte() << 16) | (this.nextByte() << 8) | this.nextByte()) >>> 0;
  }

  /** Uniform integer in [0, n) using rejection sampling (no modulo bias). */
  uniform(n: number): number {
    if (n <= 0 || n > 2 ** 32) throw new RangeError("uniform: n out of range");
    const limit = Math.floor(2 ** 32 / n) * n;
    for (;;) {
      const x = this.nextU32();
      if (x < limit) return x % n;
    }
  }
}

export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}
