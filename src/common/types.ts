/**
 * Every version of the cipher implements this interface, so the attack
 * toolkit, benchmarks and tests can target any version interchangeably.
 *
 * Decryption rule (see docs/VERSIONS.md): decrypt(key, encrypt(key, m, n), n)
 * must always return m. Anything that would break that is not allowed in.
 */
export interface CipherVersion<K> {
  /** Version number written into the ciphertext container header. */
  readonly id: number;
  readonly name: string;
  /** Bytes of fresh nonce each message needs (absent/0 = no nonce, settings repeat). */
  readonly nonceLength?: number;
  /** Deterministically derive a full key/setting from seed bytes. */
  keygen(seed: Uint8Array): K;
  encrypt(key: K, plaintext: Uint8Array, nonce?: Uint8Array): Uint8Array;
  decrypt(key: K, ciphertext: Uint8Array, nonce?: Uint8Array): Uint8Array;
}
