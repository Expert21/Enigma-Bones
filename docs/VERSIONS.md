# Version log

Each version removes one weakness that got the real Enigma broken. Every
version keeps one rule: **with the key, decryption always works directly**
(`decrypt(key, encrypt(key, m)) == m`, enforced by tests and frozen vectors).

## v0 — faithful Enigma I/M3

**What it is:** three of rotors I–V, reflector B/C, ring settings, plugboard,
and odometer stepping including the middle-rotor double step. Checked against
historical vectors (`AAAAA → BDZGO`, `HELLOWORLD → ILBDAAMTAZ` on I-II-III/B/AAA).

**Weaknesses (the to-do list for later versions):**
1. Rotor wirings are fixed and were captured → v1
2. The reflector makes it reciprocal and **no letter encrypts to itself** → v2
3. Stepping is regular and predictable; the left rotor barely moves → v3
4. Message keys were badly handled (sent twice, daily key reused) → v4
5. One letter in, one letter out: no diffusion → v5
6. No integrity: ciphertext can be altered without detection → v6

**Attack shipped:** `src/attacks/bombe.ts`, a simplified Turing–Welchman
Bombe. Given a crib, it tests every start position and plugboard guess by
logical propagation over the crib "menu", with the diagonal board.
- Uses: known wirings, reciprocity, and a plugboard that stays fixed during the message.
- Result: with the rotor order known, it recovers the start positions **and all
  10 plug pairs** from a 23-letter crib in ~2 s (`--all-orders` tries all 60
  rotor orders, about 2–3 min).
- The "no self-encryption" rule alone rules out more than half of the possible
  crib positions (`possibleCribOffsets`).
- Simplification: ring settings are taken as known (A-A-A).

## v1 — Byte Enigma with key-generated wirings

**Changes:** 256-symbol alphabet (any file, not just A–Z). Every table (5
rotor wirings, notches, start positions, reflector and a 64-pair plugboard)
is generated from a 256-bit secret. Ring settings are gone; with secret
wirings they add nothing. Ciphertext now goes in a container with a version
byte (`src/common/container.ts`), and `open()` picks the right version, so
old files stay decryptable.

**Fixed:** captured or known wirings and a small keyspace. The Bombe needs
the scrambler tables S_i, and without the wirings it can't compute them.
`src/attacks/keyspace.ts`: v0 is about 2^76.5 keys but the Bombe only searches
about 2^24.7; v1 has an effective 2^256 (brute force at 10^12/s takes ~10^57 years).

**Still broken: the reflector's fingerprint.** `src/attacks/self-encryption.ts`
- *Distinguisher (known plaintext):* in 4.4 KB, a random cipher repeats a
  plaintext byte about 17 times; v1 does it **0** times (chance ≈ 10^-8).
  AES-256-CTR, as a control, gives 17. In 64 KB the evidence is overwhelming.
- *Crib dragging:* with 256 symbols each crib byte rules out far less than with
  26 letters (a 20-byte crib rules out ~7% of positions vs ~42% for a 14-letter
  crib on v0). **A bigger alphabet dilutes the flaw but doesn't fix it.**

**Speed:** 52 MB/s. Most of the cost is 12 dependent table lookups per byte
(in through 5 rotors, reflector, back out, plus the plugboard).

**Decryption:** still reciprocal (same function). Tested with randomized
round-trips over 1–8 rotors, all 256 byte values, a frozen known-answer
vector, CLI encrypt → decrypt through files, and the optimized fast path
matched byte for byte against the readable `V1Machine`.
