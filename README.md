# enigma-bones

An Enigma machine evolved, one historical weakness at a time, toward a modern
cipher with Enigma bones. **Educational only: not for real data.**

```sh
npm test                          # round-trips, historical vectors, attack regressions
npx tsx src/attacks/bombe.ts      # break a random v0 key from a crib
```

See [docs/VERSIONS.md](docs/VERSIONS.md) for the version ladder and what each step fixes.
