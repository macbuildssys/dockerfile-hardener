"""
DH009 - PrivilegedPort

Exposing a port below 1024 requires the container to run as root (or with
CAP_NET_BIND_SERVICE). This defeats the goal of running containers as
non-root. Use port >= 1024 and let an ingress controller / load balancer
handle external port mapping.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from .base import BaseRule, Finding, RuleResult, Severity

if TYPE_CHECKING:
    from dockerfile_hardener.parser import ParsedDockerfile

_PORT_RE = re.compile(r"\b(\d+)(?:/(?:tcp|udp))?\b", re.IGNORECASE)


class PrivilegedPortRule(BaseRule):
    RULE_ID = "DH009"
    NAME = "PrivilegedPort"
    SEVERITY = Severity.LOW
    TAGS = ["Docker-Hardening", "Least-Privilege"]
    DESCRIPTION = (
        "EXPOSE should not declare privileged ports (< 1024). "
        "Use a port >= 1024 and remap externally."
    )

    def check(self, dockerfile: "ParsedDockerfile") -> RuleResult:
        findings: list[Finding] = []

        for instr in dockerfile.by_command("EXPOSE"):
            for m in _PORT_RE.finditer(instr.value):
                port = int(m.group(1))
                if port < 1024:
                    findings.append(
                        self._finding(
                            message=(
                                f"EXPOSE declares privileged port {port} (< 1024). "
                                "Binding this port requires root or CAP_NET_BIND_SERVICE."
                            ),
                            line_number=instr.line_number,
                            fix_description=(
                                f"Change the application to listen on port >= 1024 "
                                f"(e.g. {port + 8000}) and remap externally with "
                                f"-p 80:{port + 8000}."
                            ),
                            fixable=False,
                            context=instr.value,
                            stage_index=instr.stage_index,
                        )
                    )

        return self._make_result(findings)
