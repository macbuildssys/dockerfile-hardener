# 🐳 dockerfile-hardener

**Lint and auto-fix Dockerfiles against Docker hardening best practices.**

`dockerfile-hardener` analyses Dockerfiles for security misconfigurations, applies auto-fixes where possible, and produces reports in four formats, including SARIF for native GitHub Code Scanning integration. It covers the hardening principles documented by Docker's own [Hardened Images](https://docs.docker.com/dhi/core-concepts/hardening/) specification.

Unlike Hadolint, Trivy, and Dockle which detect issues but do not remediate `dockerfile-hardener` can **automatically fix** a subset of findings in-place.



## Features

- **10 hardening rules** covering root user, latest tags, secrets, shell tools, multi-stage builds, apt hygiene, ADD vs COPY, port exposure, file ownership, and healthchecks.

- **Auto-fix mode** applies safe, targeted fixes and writes a `.bak` backup first.

- **4 output formats** Rich terminal table, JSON, SARIF (GitHub Code Scanning), HTML dashboard.

- **Configurable severity threshold**  fail CI only on findings above `--fail-on`.

- **GitHub Action** drop-in integration for any repository.

- **Docker image** run without installing Python.


## Installation

```
pip install dockerfile-hardener
```

Or run via Docker:

```
docker run --rm -v "$(pwd)":/work ghcr.io/macbuildssys/dockerfile-hardener lint Dockerfile
```

## Quick Start

```
# Lint with terminal output
dockerfile-hardener lint Dockerfile

# Generate an HTML report
dockerfile-hardener lint Dockerfile --format html -o report.html

# Generate a SARIF report (GitHub Code Scanning compatible)
dockerfile-hardener lint Dockerfile --format sarif -o results.sarif

# Auto-fix fixable findings (dry-run preview first)
dockerfile-hardener fix Dockerfile --dry-run

dockerfile-hardener fix Dockerfile

# List all rules
dockerfile-hardener rules
```


## CLI Reference

### `lint`

```
dockerfile-hardener lint [OPTIONS] [DOCKERFILE]

Options:
  -f, --format [table|json|sarif|html]  Output format (default: table)
  -o, --output FILE                     Write output to FILE instead of stdout
  -F, --fail-on SEVERITY                Exit 1 on findings >= SEVERITY (default: LOW)
  -r, --rule RULE_ID                    Run only specified rule(s) (repeatable)
  -i, --ignore RULE_ID                  Skip specified rule(s) (repeatable)
  -V, --version                         Show version and exit
```

**Exit codes:**
- `0` — no findings at or above `--fail-on` severity.

- `1` — one or more findings at or above `--fail-on` severity.

- `2` — file not found or parse error.

### `fix`

```
dockerfile-hardener fix [OPTIONS] [DOCKERFILE]

Options:
  -n, --dry-run       Show changes without writing to disk
  --no-backup         Skip writing a .bak backup before modifying
  -r, --rule RULE_ID  Fix only specified rule(s) (repeatable)
```

### `rules`

```
dockerfile-hardener rules [OPTIONS]

Options:
  -f, --format [table|json]   Output format (default: table)
```

## Rules

| ID | Name | Severity | Auto-fix | Description |
|----|------|----------|----------|-------------|
| DH001 | RootUser | 🔴 CRITICAL | ✔ | Final stage must set a non-root USER |
| DH002 | LatestTag | 🟠 HIGH | ✗ | FROM must pin an explicit tag or digest |
| DH003 | ShellTools | 🟠 HIGH | ✗ | Shell/debug/network tools in final stage |
| DH004 | MultiStage | 🟡 MEDIUM | ✗ | Build toolchains must use multi-stage builds |
| DH005 | NoHealthcheck | 🔵 LOW | ✔ | Every image should define a HEALTHCHECK |
| DH006 | SecretsInEnv | 🔴 CRITICAL | ✗ | Secrets/tokens must not be hardcoded in ENV/ARG |
| DH007 | AddInstruction | 🟡 MEDIUM | ✔ | Use COPY instead of ADD for local files |
| DH008 | AptHygiene | 🟡 MEDIUM | ✔ | apt/apk: clean cache, --no-install-recommends, pin versions |
| DH009 | PrivilegedPort | 🔵 LOW | ✗ | EXPOSE should not use privileged ports (< 1024) |
| DH010 | FileOwnership | ⚪ INFO | ✔ | COPY/ADD should use --chown when running as non-root |

### Rule tags

Rules are tagged with compliance references where applicable:

- `CIS-DI-XXXX` CIS Docker Benchmark

- `OWASP-AXX` OWASP Top 10

- `Docker-Hardening` Docker Hardened Images specification

- `Supply-Chain` Software supply chain security

- `Secrets` Secrets management


## GitHub Action

Add to any workflow:

```
- name: Harden Dockerfile
  uses: macbuildssys/dockerfile-hardener@v1
  with:
    dockerfile: Dockerfile       # default
    fail-on: HIGH                # default
    format: sarif                # default
    upload-sarif: "true"         # uploads to GitHub Security tab
```

**Full example:**

```
name: Security

on: [push, pull_request]

jobs:
  dockerfile-hardening:
    runs-on: ubuntu-latest
    permissions:
      security-events: write   # required for SARIF upload

    steps:
      - uses: actions/checkout@v4

      - name: Lint Dockerfile
        uses: macbuildssys/dockerfile-hardener@v1
        with:
          dockerfile: Dockerfile
          fail-on: MEDIUM
          ignore: "DH009"       # ignore privileged port rule
```

**Outputs:**

| Output | Description |
|--------|-------------|
| `score` | Hardening score (0–100) |
| `grade` | Grade letter (A–F) |
| `findings` | Total number of findings |


## Scoring

Each finding deducts points from a base score of 100:

| Severity | Deduction per finding |
|----------|----------------------|
| CRITICAL | 25 |
| HIGH | 15 |
| MEDIUM | 8 |
| LOW | 3 |
| INFO | 0 |

Scores map to grades: A (≥90), B (≥75), C (≥60), D (≥40), F (<40).


## Comparison with other tools

| Feature | dockerfile-hardener | Hadolint | Dockle | Trivy |
|---------|-------------------|----------|--------|-------|
| Dockerfile linting | ✔ | ✔ | ✔ | ✔ |
| **Auto-fix** | **✔** | ✗ | ✗ | ✗ |
| SARIF output | ✔ | ✔ | ✗ | ✔ |
| HTML report | ✔ | ✗ | ✗ | ✔ |
| Scoring / grading | ✔ | ✗ | ✗ | ✗ |
| GitHub Action | ✔ | ✔ | ✗ | ✔ |
| Python / pip | ✔ | ✗ | ✗ | ✗ |


## Development

```
git clone https://github.com/macbuildssys/dockerfile-hardener

cd dockerfile-hardener

pip install -e ".[dev]"

pytest
```

### Adding a new rule

1. Create `dockerfile_hardener/rules/my_rule.py` subclassing `BaseRule`.

2. Set `RULE_ID`, `NAME`, `SEVERITY`, `TAGS`, `DESCRIPTION`.

3. Implement `check(self, dockerfile) -> RuleResult`.

4. Import and append to `ALL_RULES` in `dockerfile_hardener/rules/__init__.py`.

5. Add tests in `tests/test_rules.py`.

```
from dockerfile_hardener.rules.base import BaseRule, RuleResult, Severity

class MyRule(BaseRule):
    RULE_ID = "DH011"
    NAME = "MyRule"
    SEVERITY = Severity.MEDIUM
    TAGS = ["Docker-Hardening"]
    DESCRIPTION = "Short description of what this rule checks."

    def check(self, dockerfile) -> RuleResult:
        findings = []
        for instr in dockerfile.by_command("RUN"):
            if "something_bad" in instr.value:
                findings.append(self._finding(
                    message="Explanation of the issue.",
                    line_number=instr.line_number,
                    fix_description="How to fix it.",
                    context=instr.value[:80],
                ))
        return self._make_result(findings)
```

## License

Distributed under the MIT License. See [LICENSE](LICENSE).

