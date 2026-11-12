# Third-party data and software

TestAndFix is released under the MIT licence (see `LICENSE`). It ships or relies on the following
third-party work, each under its own licence.

| What | Where in this repository | Source | Licence |
|---|---|---|---|
| Candidate public DNS resolvers | `server/data-seed/resolvers.json` | [trickest/resolvers](https://github.com/trickest/resolvers), Copyright (c) 2022 Trickest, plus the resolver addresses each provider documents itself (Cloudflare, Quad9, Google…) | MIT |
| Resolver locations | `server/data-seed/resolvers.json` (`lat`, `lon`, `city`) | RIPEstat `maxmind-geo-lite` data call. This product includes GeoLite2 data created by MaxMind, available from https://www.maxmind.com | GeoLite2 End User License Agreement |
| Country to continent and UN M49 region tables | `server/data-seed/resolvers-continents.json`, `server/data-seed/resolvers-regions.json` | [lukes/ISO-3166-Countries-with-Regional-Codes](https://github.com/lukes/ISO-3166-Countries-with-Regional-Codes) | CC BY-SA 4.0 (these two files are shared under the same licence) |
| Apache SpamAssassin | `docker/spamassassin` installs the Debian packages; `knowledge/situations/spamassassin-*.yaml` explain its rules by name | [spamassassin.apache.org](https://spamassassin.apache.org/), The Apache Software Foundation | Apache License 2.0 |
| Fonts | `@fontsource-variable/mona-sans`, `@fontsource-variable/jetbrains-mono` (npm) | GitHub (Mona Sans), JetBrains (JetBrains Mono) | SIL Open Font License 1.1 |
| Icons, flags, world map | `lucide-react`, `flag-icons`, `world-atlas` (npm) | Lucide, flag-icons, Natural Earth via world-atlas | ISC, MIT, ISC |

The public edition of the resolver pool keeps only the sources above. `server/src/tools/propagation/seed/build-seed.ts`
shows how a larger pool can be built from more sources on your own side, under their own terms.
