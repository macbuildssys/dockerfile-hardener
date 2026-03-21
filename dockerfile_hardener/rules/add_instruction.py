"""
DH007 - AddInstruction

The ADD instruction has two extra behaviours beyond COPY:
  1. It can fetch remote URLs (a network call at build time — security risk).
  2. It auto-extracts tar archives.

Both behaviours are surprising and can be exploited. COPY is explicit and
predictable. Use ADD only when its extra features are genuinely required
and the source is trusted.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from .base import BaseRule, Finding, RuleResult, Severity

if TYPE_CHECKING:
    from dockerfile_hardener.parser import ParsedDockerfile

# Detect remote URL sources in ADD instructions.
_URL_RE = re.compile(r"^https?://", re.IGNORECASE)

# Detect tar-like source files that justify ADD's auto-extraction.
_TAR_RE = re.compile(r"\.(tar|tgz|tar\.gz|tar\.bz2|tar\.xz|tbz2|txz)\s", re.IGNORECASE)


class AddInstructionRule(BaseRule):
    RULE_ID = "DH007"
    NAME = "AddInstruction"
    SEVERITY = Severity.MEDIUM
    TAGS = ["CIS-DI-0009", "Docker-Best-Practice", "Docker-Hardening"]
    DESCRIPTION = (
        "Use COPY instead of ADD unless you specifically need URL fetching or tar auto-extraction. "
        "ADD with a remote URL performs a network request at build time."
    )

    def check(self, dockerfile: "ParsedDockerfile") -> RuleResult:
        findings: list[Finding] = []

        for instr in dockerfile.by_command("ADD"):
            value = instr.value.strip()
            src = value.split()[0] if value.split() else ""

            if _URL_RE.match(src):
                # Remote URL — elevated to HIGH: unverified network fetch at build time.
                findings.append(
                    Finding(
                        rule_id=self.RULE_ID,
                        rule_name=self.NAME,
                        severity=Severity.HIGH,
                        message=(
                            f'ADD fetches a remote URL at build time: "{src}". '
                            "The fetched content is not verified. "
                            "Use RUN curl/wget with checksum verification instead."
                        ),
                        line_number=instr.line_number,
                        fix_description=(
                            "Replace with: RUN curl -fsSL <url> -o <dest> && "
                            "echo '<sha256>  <dest>' | sha256sum -c"
                        ),
                        fixable=False,
                        context=instr.value[:120],
                        stage_index=instr.stage_index,
                        tags=list(self.TAGS),
                    )
                )
            elif _TAR_RE.search(src + " "):
                # Tar source: auto-extraction may be intentional — INFO level.
                findings.append(
                    Finding(
                        rule_id=self.RULE_ID,
                        rule_name=self.NAME,
                        severity=Severity.INFO,
                        message=(
                            f'ADD is used with a tar archive "{src}". '
                            "If auto-extraction is intentional this may be acceptable, "
                            "but prefer explicit: COPY + RUN tar xf."
                        ),
                        line_number=instr.line_number,
                        fix_description=(
                            "Replace with: COPY <archive> /tmp/ && RUN tar xf /tmp/<archive>"
                        ),
                        fixable=True,
                        context=instr.value[:120],
                        stage_index=instr.stage_index,
                        tags=list(self.TAGS),
                    )
                )
            else:
                # Plain local file copy — COPY is always the right choice.
                findings.append(
                    self._finding(
                        message=(
                            f'ADD is used for a local file copy: "{value[:60]}". '
                            "ADD is unpredictable for local files — use COPY instead."
                        ),
                        line_number=instr.line_number,
                        fix_description='Replace "ADD" with "COPY".',
                        fixable=True,
                        context=instr.value[:120],
                        stage_index=instr.stage_index,
                    )
                )

        return self._make_result(findings)
