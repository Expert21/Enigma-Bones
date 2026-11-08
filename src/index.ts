/**
 * Version registry. `seal` encrypts with a chosen version and wraps the result
 * in the container; `open` reads the version byte and decrypts with the
 * matching version, so ciphertext from any past version stays readable.
 */
import { pack, unpack } from "./common/container.js";
import type { CipherVersion } from "./common/types.js";
import { v0 } from "./versions/v0-enigma.js";
import { v1 } from "./versions/v1-byte-enigma.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const VERSIONS: Record<number, CipherVersion<any>> = { 0: v0, 1: v1 };
export const LATEST = Math.max(...Object.keys(VERSIONS).map(Number));

export function getVersion(id: number): CipherVersion<unknown> {
  const v = VERSIONS[id];
  if (!v) throw new Error(`unknown cipher version ${id}`);
  return v;
}

export function seal<K>(version: CipherVersion<K>, key: K, plaintext: Uint8Array, nonce?: Uint8Array): Uint8Array {
  return pack(version.id, version.encrypt(key, plaintext, nonce), nonce);
}

export function open(key: unknown, blob: Uint8Array): Uint8Array {
  const { version, nonce, body } = unpack(blob);
  return getVersion(version).decrypt(key, body, nonce.length ? nonce : undefined);
}
