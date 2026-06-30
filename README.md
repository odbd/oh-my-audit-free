# oh-my-audit (free engine + CLI)

The open-source security scan engine and CLI behind **[ohmyaudit.app](https://ohmyaudit.app)**.

Point it at a codebase; it runs [gitleaks](https://github.com/gitleaks/gitleaks)
(committed secrets), [semgrep](https://semgrep.dev) (SAST), and
[osv-scanner](https://github.com/google/osv-scanner) (vulnerable dependencies),
folds in a set of heuristic checks, and returns a **0–100 security score** with
**deduplicated, actionable findings** — each with its location and how to fix it.

It runs **entirely locally**. No database, no cloud, no network calls of its
own, no secrets, no telemetry — it only shells out to the three scanner CLIs.
Nothing about your code leaves your machine. That's the point: you shouldn't
have to hand your private source to a stranger to get a security read.

## Why this is open source

Most people are (rightly) reluctant to upload their source to a scanner they
can't inspect. So the engine that produces the **free** oh-my-audit report is
open under **AGPL-3.0** — run it yourself, read exactly what it does, trust the
methodology. The hosted service adds what a local run can't: a shareable,
signed **verified report/badge**, history, continuous monitoring, and teams.

## Install & run

No npm registry needed — use Docker, the GitHub Action, or run straight from
the repo with `npx`. (Publishing to npm is optional; everything below works
without it.)

### Docker (recommended — scanners bundled, zero setup)

```bash
docker run --rm -v "$PWD:/src" ghcr.io/odbd/oh-my-audit-free scan /src
docker run --rm -v "$PWD:/src" ghcr.io/odbd/oh-my-audit-free scan /src --sarif > results.sarif
```

### npx, straight from GitHub (Node ≥ 20; needs the scanner CLIs on PATH)

```bash
npx github:odbd/oh-my-audit-free scan ./            # pretty report
npx github:odbd/oh-my-audit-free scan ./ --json     # full JSON
npx github:odbd/oh-my-audit-free scan ./ --sarif > results.sarif
npx github:odbd/oh-my-audit-free scan ./ --fail-on high   # exit 1 on any high+ (CI)
```

Install the scanners: `gitleaks`, `semgrep`, `osv-scanner`. Missing scanners are
skipped (heuristics still run) — or use the Docker image, which bundles them.

### GitHub Action

```yaml
# .github/workflows/security.yml
name: security
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write   # to upload SARIF to code scanning
    steps:
      - uses: actions/checkout@v4
      - uses: odbd/oh-my-audit-free@v1
        with:
          path: .
          format: sarif
          output: results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

## Options

| Flag | Meaning |
|------|---------|
| `--json` | Full result as JSON |
| `--sarif` | SARIF 2.1.0 (GitHub code scanning / CI) |
| `--fail-on <sev>` | Exit 1 if any finding ≥ `critical\|high\|medium\|low` |
| `--no-semgrep` / `--no-gitleaks` / `--no-osv` | Skip a scanner |

## Use as a library

```ts
import { runOptionalExternalScans, analyzeScoreFiles } from "oh-my-audit";

const files = [{ path: "app.js", content: "..." }];
const external = await runOptionalExternalScans(files, process.env, {});
const result = analyzeScoreFiles(files, external);
console.log(result.score, result.internalFindings);
```

## What it covers (and doesn't)

Automated checks for **leaked secrets**, **vulnerable dependencies**, and
**common code-level security issues** (SAST). It is *not* a manual penetration
test and does not cover business logic, infrastructure, or runtime config.
Automated analysis can include false positives — verify before acting.

## License

[AGPL-3.0-only](./LICENSE). Use, modify, and self-host freely. If you offer a
modified version as a network service, you must release your changes under the
same license.
