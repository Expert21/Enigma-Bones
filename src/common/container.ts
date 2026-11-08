/**
 * Self-describing ciphertext container, so old messages stay decryptable as
 * the project evolves:
 *
 *   "EB" | version (1) | nonceLen (1) | nonce | tagLen (1) | tag | ciphertext
 *
 * v0–v3 have no nonce or tag (lengths 0); later versions fill them in.
 */
const MAGIC = [0x45, 0x42]; // "EB"

export interface Parsed {
  version: number;
  nonce: Uint8Array;
  tag: Uint8Array;
  body: Uint8Array;
}

export function pack(version: number, body: Uint8Array, nonce: Uint8Array = new Uint8Array(0), tag: Uint8Array = new Uint8Array(0)): Uint8Array {
  if (nonce.length > 255 || tag.length > 255) throw new RangeError("nonce/tag too long");
  const out = new Uint8Array(5 + nonce.length + tag.length + body.length);
  let o = 0;
  out[o++] = MAGIC[0];
  out[o++] = MAGIC[1];
  out[o++] = version;
  out[o++] = nonce.length;
  out.set(nonce, o);
  o += nonce.length;
  out[o++] = tag.length;
  out.set(tag, o);
  o += tag.length;
  out.set(body, o);
  return out;
}

export function unpack(blob: Uint8Array): Parsed {
  const bad = () => new Error("not an enigma-bones ciphertext (bad header)");
  if (blob.length < 5 || blob[0] !== MAGIC[0] || blob[1] !== MAGIC[1]) throw bad();
  let o = 2;
  const version = blob[o++];
  const nl = blob[o++];
  if (o + nl + 1 > blob.length) throw bad();
  const nonce = blob.slice(o, o + nl);
  o += nl;
  const tl = blob[o++];
  if (o + tl > blob.length) throw bad();
  const tag = blob.slice(o, o + tl);
  o += tl;
  return { version, nonce, tag, body: blob.slice(o) };
}
