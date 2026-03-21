"""
DH003 - ShellTools

Installing debugging or network tools (curl, wget, bash, nc, nmap, etc.)
in the final stage widens the attack surface significantly. An attacker who
gains code execution can use these tools to exfiltrate data or escalate.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, List, Tuple

from .base import BaseRule, Finding, RuleResult, Severity

if TYPE_CHECKING:
    from dockerfile_hardener.parser import ParsedDockerfile

# Map of risky package name → reason for concern.
# We only flag these in the *final* stage (build stages may legitimately need them).
_RISKY_PACKAGES: dict[str, str] = {
    "curl": "network utility; can be used to exfiltrate data or fetch payloads",
    "wget": "network utility; can be used to download attacker-controlled files",
    "bash": "interactive shell; enables arbitrary command execution",
    "sh": "shell; enables arbitrary command execution",
    "nc": "netcat; can create reverse shells or probe internal network",
    "netcat": "netcat; can create reverse shells or probe internal network",
    "ncat": "netcat; can create reverse shells or probe internal network",
    "nmap": "network scanner; exposes internal network topology",
    "tcpdump": "packet capture tool; can expose sensitive traffic",
    "strace": "syscall tracer; provides deep process introspection",
    "ltrace": "library call tracer",
    "gdb": "debugger; can attach to and modify running processes",
    "vim": "text editor; not required at runtime",
    "nano": "text editor; not required at runtime",
    "emacs": "text editor; not required at runtime",
    "ssh": "remote shell access",
    "sshd": "SSH server; should not run inside application containers",
    "telnet": "cleartext remote access protocol",
    "ftp": "cleartext file transfer protocol",
    "socat": "multi-purpose relay; commonly used in privilege escalation",
    "python3": "interpreter; enables arbitrary code execution if not the app runtime",
    "python": "interpreter; enables arbitrary code execution if not the app runtime",
    "perl": "interpreter; enables arbitrary code execution",
    "ruby": "interpreter; enables arbitrary code execution",
    "gcc": "C compiler; should only be in build stages",
    "g++": "C++ compiler; should only be in build stages",
    "make": "build tool; should only be in build stages",
    "git": "version control; not needed at runtime",
}

# Install command patterns to detect package installs.
_INSTALL_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("apt-get", re.compile(r"\bapt-get\s+install\b")),
    ("apt", re.compile(r"\bapt\s+install\b")),
    ("apk", re.compile(r"\bapk\s+add\b")),
    ("yum", re.compile(r"\byum\s+install\b")),
    ("dnf", re.compile(r"\bdnf\s+install\b")),
    ("zypper", re.compile(r"\bzypper\s+install\b")),
    ("pip", re.compile(r"\bpip(?:3)?\s+install\b")),
    ("pip", re.compile(r"\bpip(?:3)?\s+install\b")),
    ("npm", re.compile(r"\bnpm\s+install\b")),
    ("brew", re.compile(r"\bbrew\s+install\b")),
]

# Tokenise a package install command value into individual package names.
# Strips flags (start with -) and version specifiers (contains = or >=).
_PACKAGE_TOKEN_RE = re.compile(r"[a-zA-Z0-9][\w.\-+]*")


def _extract_packages(run_value: str) -> List[str]:
    """
    Best-effort extraction of package names from a RUN instruction value.
    Returns a list of lowercase package name candidates.
    """
    tokens = _PACKAGE_TOKEN_RE.findall(run_value)
    packages = []
    skip_next = False
    for tok in tokens:
        if skip_next:
            skip_next = False
            continue
        lower = tok.lower()
        # Skip flags, version numbers, and common shell keywords.
        if tok.startswith("-"):
            continue
        if any(c in tok for c in ("=", ">", "<", "/")):
            continue
        if lower in (
            "install",
            "apt",
            "apt-get",
            "apk",
            "add",
            "yum",
            "dnf",
            "zypper",
            "pip",
            "pip3",
            "npm",
            "brew",
            "run",
            "update",
            "upgrade",
            "y",
            "yes",
            "no",
            "rm",
            "rf",
            "var",
            "lib",
            "lists",
            "cache",
            "clean",
            "autoclean",
            "autoremove",
        ):
            continue
        packages.append(lower)
    return packages


class ShellToolsRule(BaseRule):
    RULE_ID = "DH003"
    NAME = "ShellTools"
    SEVERITY = Severity.HIGH
    TAGS = ["CIS-DI-0007", "Docker-Hardening", "Attack-Surface"]
    DESCRIPTION = (
        "Shell, network, or debugging tools should not be installed in the final stage. "
        "Move them to a build stage or remove them."
    )

    def check(self, dockerfile: "ParsedDockerfile") -> RuleResult:
        findings: list[Finding] = []

        # Only flag the final stage — build stages legitimately use these tools.
        final_stage_instrs = dockerfile.in_last_stage()
        run_instrs = [i for i in final_stage_instrs if i.command == "RUN"]

        for instr in run_instrs:
            value_lower = instr.value.lower()

            # Check whether this RUN contains an install command.
            is_install = any(pat.search(value_lower) for _, pat in _INSTALL_PATTERNS)
            if not is_install:
                continue

            packages = _extract_packages(value_lower)
            risky_found = {pkg: _RISKY_PACKAGES[pkg] for pkg in packages if pkg in _RISKY_PACKAGES}

            for pkg, reason in risky_found.items():
                findings.append(
                    self._finding(
                        message=(
                            f'Package "{pkg}" is installed in the final stage. ' f"Risk: {reason}."
                        ),
                        line_number=instr.line_number,
                        fix_description=(
                            f'Remove "{pkg}" from the final stage. '
                            "If it is only needed at build time, install it in an earlier stage."
                        ),
                        fixable=False,
                        context=instr.value[:120],
                        stage_index=instr.stage_index,
                    )
                )

        return self._make_result(findings)
