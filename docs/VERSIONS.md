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
