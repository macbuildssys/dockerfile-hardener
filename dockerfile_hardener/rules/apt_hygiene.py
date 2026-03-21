"""
DH008 - AptHygiene

RUN instructions that install packages via apt-get or apk should:
  1. Clean the package manager cache in the same RUN layer.
  2. Use --no-install-recommends (apt-get) to avoid pulling in unnecessary packages.
  3. Pin explicit package versions to make builds reproducible.
  4. Combine `apt-get update` and `apt-get install` in the same RUN to prevent
     stale cache being used in a later layer.

Violations inflate image size and weaken reproducibility and security.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, List

from .base import BaseRule, Finding, RuleResult, Severity

if TYPE_CHECKING:
    from dockerfile_hardener.parser import ParsedDockerfile

# ----------------------------------------------------------------- apt patterns

_APT_INSTALL_RE = re.compile(r"\bapt-get\s+install\b", re.IGNORECASE)
_APT_UPDATE_RE  = re.compile(r"\bapt-get\s+update\b",  re.IGNORECASE)
_APT_CLEAN_RE   = re.compile(
    r"rm\s+-rf\s+/var/lib/apt/lists|apt-get\s+clean|apt-get\s+autoclean",
    re.IGNORECASE,
)
_APT_NO_RECOMMENDS_RE = re.compile(r"--no-install-recommends", re.IGNORECASE)

# ----------------------------------------------------------------- apk patterns

_APK_ADD_RE     = re.compile(r"\bapk\s+add\b",      re.IGNORECASE)
_APK_NO_CACHE_RE = re.compile(r"--no-cache\b",      re.IGNORECASE)
_APK_VIRTUAL_RE = re.compile(r"--virtual\b",        re.IGNORECASE)
_APK_DEL_RE     = re.compile(r"\bapk\s+del\b",      re.IGNORECASE)

# ----------------------------------------------------------------- version pinning

# Package name without a version spec. Version pinning looks like:
#   pkg=1.2.3  (apt)   pkg==1.2.3  (pip)   pkg-1.2.3  (apk)
_APT_UNVERSIONED_RE = re.compile(r"\b([a-z][a-z0-9+.\-]*)(?<![=<>])\s+", re.IGNORECASE)
_APT_VERSIONED_RE   = re.compile(r"[a-z][a-z0-9+.\-]*=\S+", re.IGNORECASE)


def _has_version_pin(package_list_text: str) -> bool:
    """Return True if at least some packages have a version specification."""
    return bool(_APT_VERSIONED_RE.search(package_list_text))


class AptHygieneRule(BaseRule):
    RULE_ID = "DH008"
    NAME = "AptHygiene"
    SEVERITY = Severity.MEDIUM
    TAGS = ["Docker-Best-Practice", "Image-Size", "Reproducibility"]
    DESCRIPTION = (
        "Package install commands should clean caches, use --no-install-recommends, "
        "and pin explicit package versions."
    )

    def check(self, dockerfile: "ParsedDockerfile") -> RuleResult:
        findings: list[Finding] = []
        run_instrs = [i for i in dockerfile.instructions if i.command == "RUN"]

        for instr in run_instrs:
            value = instr.value
            findings.extend(self._check_apt(instr, value))
            findings.extend(self._check_apk(instr, value))
            findings.extend(self._check_update_without_install(instr, value))

        return self._make_result(findings)

    # ------------------------------------------------------------------ helpers

    def _check_apt(self, instr, value: str) -> List[Finding]:
        findings: List[Finding] = []
        if not _APT_INSTALL_RE.search(value):
            return findings

        # 1. Cache not cleaned in the same layer.
        if not _APT_CLEAN_RE.search(value):
            findings.append(
                self._finding(
                    message=(
                        "apt-get install does not clean the package cache in the same RUN layer. "
                        "The /var/lib/apt/lists directory will bloat the image."
                    ),
                    line_number=instr.line_number,
                    fix_description=(
                        "Append to the same RUN: "
                        "&& rm -rf /var/lib/apt/lists/*"
                    ),
                    fixable=True,
                    context=value[:120],
                    stage_index=instr.stage_index,
                )
            )

        # 2. Missing --no-install-recommends.
        if not _APT_NO_RECOMMENDS_RE.search(value):
            findings.append(
                self._finding(
                    message=(
                        "apt-get install is missing --no-install-recommends. "
                        "Recommended packages will be installed, increasing image size."
                    ),
                    line_number=instr.line_number,
                    fix_description=(
                        "Add --no-install-recommends to apt-get install."
                    ),
                    fixable=True,
                    context=value[:120],
                    stage_index=instr.stage_index,
                )
            )

        # 3. No version pinning at all.
        if not _has_version_pin(value):
            findings.append(
                Finding(
                    rule_id=self.RULE_ID,
                    rule_name=self.NAME,
                    severity=Severity.LOW,
                    message=(
                        "apt-get install does not pin any package versions. "
                        "Package versions may change between builds, breaking reproducibility."
                    ),
                    line_number=instr.line_number,
                    fix_description=(
                        "Pin packages using pkg=version, "
                        'e.g. "apt-get install -y curl=7.88.1-10+deb12u5".'
                    ),
                    fixable=False,
                    context=value[:120],
                    stage_index=instr.stage_index,
                    tags=list(self.TAGS),
                )
            )

        return findings

    def _check_apk(self, instr, value: str) -> List[Finding]:
        findings: List[Finding] = []
        if not _APK_ADD_RE.search(value):
            return findings

        # 1. Missing --no-cache (preferred) or virtual+del pattern.
        has_no_cache = _APK_NO_CACHE_RE.search(value)
        has_virtual_del = _APK_VIRTUAL_RE.search(value) and _APK_DEL_RE.search(value)

        if not has_no_cache and not has_virtual_del:
            findings.append(
                self._finding(
                    message=(
                        "apk add is missing --no-cache. "
                        "The apk cache directory will be included in the image layer."
                    ),
                    line_number=instr.line_number,
                    fix_description=(
                        "Use: apk add --no-cache <packages>  "
                        "(or: apk add --virtual .build-deps <packages> && apk del .build-deps)"
                    ),
                    fixable=True,
                    context=value[:120],
                    stage_index=instr.stage_index,
                )
            )

        return findings

    def _check_update_without_install(self, instr, value: str) -> List[Finding]:
        """
        Detect `RUN apt-get update` in a layer that does NOT also contain
        `apt-get install`. This leaves a stale update cache in the image;
        any subsequent install in a later layer picks up the cached (and
        potentially outdated) package index.
        """
        findings: List[Finding] = []
        if not _APT_UPDATE_RE.search(value):
            return findings
        if _APT_INSTALL_RE.search(value):
            return findings  # update + install in same layer is correct.

        findings.append(
            self._finding(
                message=(
                    "apt-get update runs without apt-get install in the same RUN layer. "
                    "A later install step may use a stale package index from this cached layer."
                ),
                line_number=instr.line_number,
                fix_description=(
                    "Combine update and install in a single RUN: "
                    "RUN apt-get update && apt-get install -y <packages> && rm -rf /var/lib/apt/lists/*"
                ),
                fixable=False,
                context=value[:120],
                stage_index=instr.stage_index,
            )
        )

        return findings
