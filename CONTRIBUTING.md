# Contributing to Kavach SAST

Thanks for helping. This project is a static analyser for Android and iOS apps, so the
most useful contributions are usually **a rule that catches something real**, **a
false positive fixed**, or **an app the scanner gets wrong**. Bug reports with a
sample are as welcome as code.

By contributing you agree that your work is released under the project's
[Apache-2.0 licence](LICENSE).

## Run it

You need Node.js 22.6 or newer. A full Android scan also needs `apktool`, `apksigner`
and a JDK (and `jadx` for readable Java); `npm run doctor` says what is missing.
iOS needs nothing extra.

```bash
npm install
npm run backend      # API on http://127.0.0.1:8788
npm run console      # console on http://localhost:5174, signs in as admin / kavach
```

Or with Docker: `docker compose up -d --build`.

## Before you open a pull request

```bash
npm run typecheck    # the console, strictly
npm run build        # the console bundle
```

Both must pass. If you change `scripts/install-linux.sh`, run `shellcheck -S warning scripts/*.sh`
too; CI also runs the installer on Debian, Ubuntu and Fedora.

## Adding or changing a rule

Code rules are entries in `backend/src/sast/rules.ts` (Android and shared) and
`rulesIos.ts`. A rule is a `PatternRule`: an `id`, a `title`, a `severity`, a
`description`, an `impact` sentence, a concrete `remediation`, a `cwe` and
`masvs` identifier, the `platforms` it applies to, and one of `pattern` (one line),
`allOf` (every pattern in the same file) or `anyOf`. Prefer `allOf` over a loose
single pattern: precision is what makes a report usable.

Choose the severity with the same discipline as the report's own definitions. **Critical**
is reserved for something that works for anyone who holds the app, with nothing else needed
(in practice a leaked credential). **High** is a
serious weakness reachable with one realistic step: a network position, another app on the
device, input the attacker controls. A setting that merely permits a weakness, a hardening
gap, or anything that needs the device in hand is **medium** or below. If you are unsure,
pick the lower one and say why in the rule's `impact`.

A good rule:

- names a weakness that can really hurt, and says how (write the impact and the
  remediation as you would tell a developer, not as a category);
- fires on a vulnerable sample and **stays quiet on a safe one**. Check both;
- is written from the platform's documentation and your own reading of real apps.
  Do not paste rules, text or regular expressions from another scanner; they have
  licences too. API and class names are fine, they belong to the platform.

Flow rules (a value that travels from a source to a sink) live in `javaFlow.ts`,
`rulesFlow.ts` and, for iOS machine code, `iosFlow.ts`.

## Checking a detection change

Beyond the unit tests, scan a few real apps before and after your change and compare the reports.
Intentionally vulnerable apps such as DVIA-v2, AndroGoat, InsecureBankv2 and OVAA are good for finding
what a rule now catches, and any ordinary app you are free to scan shows whether it got noisier. Say in
the pull request what changed. A rule that finds more by also firing on safe code is not an improvement.

## Code style

- TypeScript, run by Node's type stripping: no parameter properties, no enums, and
  imports carry their `.ts` extension. The console is React with Tailwind.
- The server keeps a very short dependency list on purpose. Do not add a package for
  something a few lines do; if you must, say why in the pull request.
- Comments explain **why**, not what. Match the surrounding code's tone and density.
- Findings must be honest: say what was seen and what was not. Never present a guess
  as a result.

## Pull requests

Keep one change per pull request, describe the problem it solves, and link the issue.
Small and focused is reviewed faster.

## Reporting a security problem

Please do not open a public issue. See [SECURITY.md](SECURITY.md).

## Conduct

Everyone taking part is expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
