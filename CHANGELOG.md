# Changelog

All notable changes to `dockerfile-hardener` are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] — 2026-03-21

### Added

**Rules**
- `DH001` RootUser — CRITICAL; flags final stages without a non-root `USER` instruction
- `DH002` LatestTag — HIGH; flags `FROM` instructions using `:latest` or no tag
- `DH003` ShellTools — HIGH; flags shell, network, and debugging tools in the final stage
- `DH004` MultiStage — MEDIUM; flags compiled-language builds that do not use multi-stage builds
- `DH005` NoHealthcheck — LOW; flags images with no `HEALTHCHECK` instruction
- `DH006` SecretsInEnv — CRITICAL; flags credentials and tokens hardcoded in `ENV`/`ARG`
- `DH007` AddInstruction — MEDIUM/HIGH; flags `ADD` for local files (use `COPY`) and remote URLs
- `DH008` AptHygiene — MEDIUM/LOW; flags missing cache cleanup, `--no-install-recommends`, version pinning, and stale `apt-get update` layers
- `DH009` PrivilegedPort — LOW; flags `EXPOSE` on ports below 1024
- `DH010` FileOwnership — INFO; flags `COPY`/`ADD` without `--chown` in non-root stages

**CLI**
- `dockerfile-hardener lint <dockerfile>` — lint with configurable `--format`, `--fail-on`, `--rule`, `--ignore`
- `dockerfile-hardener fix <dockerfile>` — auto-apply fixable findings with `--dry-run` and `--no-backup` options
- `dockerfile-hardener rules` — list all available rules in table or JSON format

**Output formats**
- `table` — Rich terminal table with severity colours, score, and grade
- `json` — machine-readable JSON with findings, score, summary, and metadata
- `sarif` — SARIF 2.1.0 for GitHub Code Scanning integration
- `html` — self-contained dark-themed HTML dashboard

**Auto-fixers**
- DH001: inserts `USER nonroot` before `CMD`/`ENTRYPOINT`
- DH005: inserts `HEALTHCHECK` template before `CMD`/`ENTRYPOINT`
- DH007: replaces `ADD` with `COPY` for local file instructions
- DH008: appends cache cleanup and `--no-install-recommends` to `apt-get install`
- DH010: adds `--chown=<user>:<user>` to `COPY`/`ADD` instructions

**Scoring**
- 0–100 score with A–F grade; per-severity deductions (CRITICAL: 25, HIGH: 15, MEDIUM: 8, LOW: 3)

**GitHub Action**
- `action.yml` — composite action with SARIF upload and GitHub Step Summary output
- `.github/workflows/ci.yml` — CI pipeline covering tests, linting, and self-scan

**Packaging**
- Hardened `Dockerfile` for the tool itself (multi-stage, non-root, pinned tags, HEALTHCHECK)
- `pyproject.toml` with `[dev]` extras for test tooling
- Per-rule documentation in `docs/rules/`

[1.0.0]: https://github.com/macbuildssys/dockerfile-hardener/releases/tag/v1.0.0
