"""
DH010 - FileOwnership

Files copied into a container default to root ownership. If the application
runs as a non-root user (as required by DH001), files it needs to read or
write should be owned by that user. Without --chown, the non-root process
may be unable to access its own application files.

This rule emits an INFO finding when COPY/ADD instructions do not specify
--chown and the Dockerfile also sets a non-root USER.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from .base import BaseRule, Finding, RuleResult, Severity

if TYPE_CHECKING:
    from dockerfile_hardener.parser import ParsedDockerfile

_CHOWN_RE = re.compile(r"--chown\s*=\s*\S+", re.IGNORECASE)
_ROOT_PATTERNS = re.compile(r"^(root|0)$", re.IGNORECASE)


class FileOwnershipRule(BaseRule):
    RULE_ID = "DH010"
    NAME = "FileOwnership"
    SEVERITY = Severity.INFO
    TAGS = ["Docker-Hardening", "Least-Privilege"]
    DESCRIPTION = (
        "COPY and ADD instructions should use --chown=<user>:<group> "
        "when the container runs as a non-root user."
    )

    def check(self, dockerfile: "ParsedDockerfile") -> RuleResult:
        findings: list[Finding] = []

        for stage_idx in range(dockerfile.stage_count):
            stage_instrs = dockerfile.in_stage(stage_idx)

            # Only flag if this stage sets a non-root user.
            user_instrs = [i for i in stage_instrs if i.command == "USER"]
            if not user_instrs:
                continue  # No USER set — DH001 covers this.

            last_user = user_instrs[-1]
            user_value = last_user.value.split()[0] if last_user.value.split() else ""
            if _ROOT_PATTERNS.match(user_value):
                continue  # Running as root — file ownership is not the concern here.

            # Check COPY and ADD instructions after the USER instruction.
            copy_add = [
                i for i in stage_instrs
                if i.command in ("COPY", "ADD")
                and i.line_number > last_user.line_number
            ]
            # Also check instructions before USER (they default to root ownership).
            copy_add_before = [
                i for i in stage_instrs
                if i.command in ("COPY", "ADD")
                and i.line_number <= last_user.line_number
            ]

            for instr in copy_add + copy_add_before:
                if not _CHOWN_RE.search(instr.value):
                    findings.append(
                        self._finding(
                            message=(
                                f'{instr.command} at line {instr.line_number} does not specify --chown. '
                                f'Files will be owned by root, but the container runs as "{user_value}".'
                            ),
                            line_number=instr.line_number,
                            fix_description=(
                                f'Add --chown={user_value}:{user_value} to the {instr.command} instruction: '
                                f'{instr.command} --chown={user_value}:{user_value} ...'
                            ),
                            fixable=True,
                            context=instr.value[:120],
                            stage_index=stage_idx,
                        )
                    )

        return self._make_result(findings)
