"""
DH005 - NoHealthcheck

Every production container image should define a HEALTHCHECK instruction.
Docker and orchestrators (Kubernetes liveness probes aside) use HEALTHCHECK
to determine whether a container is operational. Without it, a container
that is running but has a broken application will never be restarted.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .base import BaseRule, Finding, RuleResult, Severity

if TYPE_CHECKING:
    from dockerfile_hardener.parser import ParsedDockerfile


class NoHealthcheckRule(BaseRule):
    RULE_ID = "DH005"
    NAME = "NoHealthcheck"
    SEVERITY = Severity.LOW
    TAGS = ["Docker-Best-Practice", "Reliability"]
    DESCRIPTION = "Every image should define a HEALTHCHECK instruction for liveness monitoring."

    def check(self, dockerfile: "ParsedDockerfile") -> RuleResult:
        findings: list[Finding] = []

        # Check the final stage for a HEALTHCHECK.
        final_instrs = dockerfile.in_last_stage()
        has_healthcheck = any(i.command == "HEALTHCHECK" for i in final_instrs)

        if not has_healthcheck:
            # Find the last instruction in the final stage for context.
            last_instr = final_instrs[-1] if final_instrs else None
            findings.append(
                self._finding(
                    message=(
                        "No HEALTHCHECK instruction found in the final stage. "
                        "Docker cannot determine whether the container is healthy."
                    ),
                    line_number=last_instr.line_number if last_instr else None,
                    fix_description=(
                        'Add a HEALTHCHECK, e.g.: '
                        'HEALTHCHECK --interval=30s --timeout=5s --retries=3 '
                        'CMD curl -f http://localhost:8080/health || exit 1'
                    ),
                    fixable=True,
                    context="",
                )
            )

        return self._make_result(findings)
