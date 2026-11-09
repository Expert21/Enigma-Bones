# Version log

Each version removes one weakness that got the real Enigma broken. Every
version keeps one rule: **with the key, decryption always works directly**
(`decrypt(key, encrypt(key, m)) == m`, enforced by tests and frozen vectors).

Measurements for every version are in [SCOREBOARD.md](SCOREBOARD.md)
(`npx tsx src/scoreboard.ts`).

## Borrowed vs rotor

The project's question is how far *Enigma's ideas* can be pushed. So any part
that gets its strength from a modern primitive instead of the rotors is
labelled here, and good results that come from a borrowed part don't count
as rotor wins.

| Part | Where | Borrowed? | What it gives us |
|---|---|---|---|
| Key schedule: secret → wirings, notches, positions, reflector, plugboard | `src/common/kdf.ts` (`HashStream`, SHA-256), used from v1 | **Borrowed** (SHA-256) | Tables look random and unrelated across keys. Any "flipping one key bit changes everything" result is SHA-256's credit. |
| Passphrase → key in the CLI | `src/cli.ts` | **Borrowed** (SHA-256, not even a slow KDF yet; v4) | Convenience only |
| Rotors, stepping, reflector, plugboard, signal path | `src/versions/*` | Rotor | Everything the attacks and scoreboard actually test |
| Planned: per-message key derivation (v4), MAC (v6) | — | Will be borrowed (HKDF/HMAC) | A stretch goal is to replace these with rotor-based constructions and see what breaks |

## v0 — faithful Enigma I/M3

**What it is:** three of rotors I–V, reflector B/C, ring settings, plugboard,
and odometer stepping including the middle-rotor double step. Checked against
historical vectors (`AAAAA → BDZGO`, `HELLOWORLD → ILBDAAMTAZ` on I-II-III/B/AAA).

**Weaknesses (the to-do list for later versions):**
1. Rotor wirings are fixed and were captured → v1
2. The reflector makes it reciprocal and **no letter encrypts to itself** → v2
3. Stepping is regular and predictable; the left rotor barely moves → v3
4. Settings repeat across messages (messages "in depth") → v4
5. One letter in, one letter out: no diffusion → v5
6. No integrity: ciphertext can be altered without detection → v6

**Keyspace isn't security.** v0 has about 2^76.5 keys (`src/attacks/keyspace.ts`),
which was unsearchable in 1940, and still fell. The Bombe skipped the plugboard
and only searched about 2^24.7 settings. Structure beats size.

**Attacks shipped:**
- `src/attacks/bombe.ts`: a simplified Turing–Welchman Bombe. Given a crib, it
  tests every start position and plugboard guess by logical propagation over
  the crib "menu", with the diagonal board. It uses the known wirings,
  reciprocity, and a plugboard that stays fixed during the message. With the
  rotor order known, it recovers the start positions **and all 10 plug pairs**
  from a 23-letter crib in ~2 s (`--all-orders` tries all 60 rotor orders,
  about 2–3 min). The "no self-encryption" rule alone rules out more than half
  of the possible crib positions (`possibleCribOffsets`). Simplification: ring
  settings are taken as known (A-A-A).
- `src/attacks/depth.ts` also applies (see v1). Our v0 starts every message at
  the same positions. Real operators were supposed to pick a fresh message key
  per message, but sent it twice and chose predictable ones, which gave the
  same result: messages in depth.

**Scoreboard finding:** v0's raw output repeats well above noise (≈ 1.2–1.26
against a noise level of ≈ 1.04) at multiples of 26, the right rotor's cycle.
Which lag wins depends on the key: runs have hit lag 26 and lag 1300 = 2 × 650.
650 = 26 × 25 is the cycle of the right and middle rotors: 25 rather than 26
because of the double step, which is also why Enigma's full period is 16,900
rather than 26³ = 17,576. This is the regular-stepping weakness that v3 targets,
found without telling the scoreboard to look for it.

## v1 — Byte Enigma with key-generated wirings

**Changes:** 256-symbol alphabet (any file, not just A–Z). Every table (5
rotor wirings, notches, start positions, reflector and a 64-pair plugboard)
is generated from a 256-bit secret through the **borrowed** SHA-256 key
schedule. Ring settings are gone; with secret wirings they add nothing.
Ciphertext now goes in a container with a version byte
(`src/common/container.ts`), and `open()` picks the right version, so old
files stay decryptable.

**Fixed:** captured or known wirings. The Bombe needs the scrambler tables S_i,
and without the wirings it can't compute them. Brute force over the 256-bit
secret is out of reach (~10^57 years at 10^12 keys/s), **but see v0: a big
keyspace says nothing about structural attacks**, and v1 still has two.

**Biggest remaining break: same settings for every message.**
`src/attacks/depth.ts`. Every message starts at the same rotor positions, so
byte i of every message goes through the same substitution. With known
plaintext from earlier messages, the attacker writes a per-position codebook
and reads new messages **without ever finding the key**:

| Known earlier messages | Recovered from a new message |
|---|---|
| 1 | ~43% |
| 5 | ~55% |
| 20 | ~96% |
| 100 | ~98% |

Fixed by a fresh nonce per message (v4).

**Also still broken: the reflector's fingerprint.** `src/attacks/self-encryption.ts`
- *Distinguisher (known plaintext):* in 4.4 KB, a random cipher repeats a
  plaintext byte about 17 times; v1 does it **0** times (chance ≈ 10^-8).
  AES-256-CTR, as a control, gives 17. In 64 KB the evidence is overwhelming.
  The scoreboard's bias column shows the same flaw from another angle: when
  encrypting zeros, v1 never outputs a zero byte, and otherwise its output is flat.
- *Crib dragging:* with 256 symbols each crib byte rules out far less than with
  26 letters (a 20-byte crib rules out ~7% of positions vs ~42% for a 14-letter
  crib on v0). **A bigger alphabet dilutes the flaw but doesn't fix it.**

**Speed:** ~40–50 MB/s. Most of the cost is 12 dependent table lookups per byte
(in through 5 rotors, reflector, back out, plus the plugboard). For scale:
AES-256-CTR with hardware support runs at ~3 GB/s on the same machine.

**Decryption:** still reciprocal (same function). Tested with randomized
round-trips over 1–8 rotors, all 256 byte values, a frozen known-answer
vector, CLI encrypt → decrypt through files, and the optimized fast path
matched byte for byte against the readable `V1Machine`.
