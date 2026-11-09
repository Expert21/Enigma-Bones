# enigma-bones

An Enigma machine evolved, one historical weakness at a time, toward a modern
cipher with Enigma bones. **Educational only: not for real data.**

Built with AI Assistance because I never made a algorithm before, let alone something "New" cryptologically 

```sh
npm test                          # round-trips, historical vectors, attack regressions
npx tsx src/attacks/bombe.ts                     # break a random v0 key from a crib
npx tsx src/attacks/self-encryption.ts --target v1   # reflector fingerprint on v1
npx tsx src/attacks/keyspace.ts                  # keyspace / attack cost, v0 vs v1
npx tsx src/attacks/depth.ts                     # read v1 messages without the key
npx tsx src/scoreboard.ts                        # measure every version → docs/SCOREBOARD.md

npx tsx src/cli.ts encrypt --pass "phrase" --v 1 in.txt out.eb
npx tsx src/cli.ts decrypt --pass "phrase" out.eb back.txt   # version read from the file
npx tsx src/cli.ts bench --v 1
```

See [docs/VERSIONS.md](docs/VERSIONS.md) for the version ladder, what each step fixes,
and which parts are borrowed modern primitives; [docs/SCOREBOARD.md](docs/SCOREBOARD.md)
for measurements of every version against AES-256-CTR.
