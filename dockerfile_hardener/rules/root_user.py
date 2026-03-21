"""
DH001 - RootUser

The final build stage must set a non-root USER before CMD/ENTRYPOINT.
Running containers as root exposes the host if the container is compromised.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from .base import BaseRule, Finding, RuleResult, Severity

if TYPE_CHECKING:
    from dockerfile_hardener.parser import ParsedDockerfile

# UIDs/names that indicate a privileged user.
_ROOT_PATTERNS = re.compile(r"^(root|0)$", re.IGNORECASE)


class RootUserRule(BaseRule):
    RULE_ID = "DH001"
    NAME = "RootUser"
    SEVERITY = Severity.CRITICAL
    TAGS = ["CIS-DI-0001", "OWASP-A05", "Docker-Hardening"]
    DESCRIPTION = (
        "The final stage should run as a non-root user. "
        "Add USER <nonroot> before CMD/ENTRYPOINT."
    )

    def check(self, dockerfile: "ParsedDockerfile") -> RuleResult:
        findings: list[Finding] = []

        # Inspect each stage independently.
        for stage_idx in range(dockerfile.stage_count):
            stage_instrs = dockerfile.in_stage(stage_idx)

            # Collect all USER instructions in this stage.
            user_instrs = [i for i in stage_instrs if i.command == "USER"]

            if not user_instrs:
                # No USER instruction at all — default is root.
                # Only flag the final stage to avoid noise from build stages.
                if stage_idx == dockerfile.stage_count - 1:
                    # Find the line of FROM for context.
                    from_instr = next(
                        (i for i in stage_instrs if i.command == "FROM"), None
                    )
                    line = from_instr.line_number if from_instr else None
                    findings.append(
                        self._finding(
                            message=(
                                "Final stage has no USER instruction. "
                                "The container will run as root by default."
                            ),
                            line_number=line,
                            fix_description='Add "USER nonroot" before CMD/ENTRYPOINT.',
                            fixable=True,
                            context=from_instr.value if from_instr else "",
                            stage_index=stage_idx,
                        )
                    )
                continue

            # Check the *last* USER instruction set in this stage.
            last_user = user_instrs[-1]
            user_value = last_user.value.split()[0] if last_user.value.split() else ""

            if _ROOT_PATTERNS.match(user_value):
                findings.append(
                    self._finding(
                        message=(
                            f'USER is explicitly set to "{user_value}" (root). '
                            "The container will run with full host privileges."
                        ),
                        line_number=last_user.line_number,
                        fix_description='Change USER to a non-root account, e.g. "USER nonroot".',
                        fixable=False,  # We won't blindly rename the user.
                        context=last_user.value,
                        stage_index=stage_idx,
                    )
                )

        return self._make_result(findings)
