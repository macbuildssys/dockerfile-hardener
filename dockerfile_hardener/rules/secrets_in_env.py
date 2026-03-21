"""
DH006 - SecretsInEnv

Hardcoding secrets in ENV or ARG instructions embeds them in the image layers
and in `docker history` output. Anyone with read access to the image can
retrieve credentials, tokens, or keys — even if the value is overwritten
in a later layer.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, List

from .base import BaseRule, Finding, RuleResult, Severity

if TYPE_CHECKING:
    from dockerfile_hardener.parser import ParsedDockerfile

# Suspicious key name fragments. Matched as case-insensitive substrings of the
# variable name so compound names like DATABASE_PASSWORD and SECRET_TOKEN are
# caught even though word boundaries don't apply across underscores.
_SECRET_KEY_FRAGMENTS: list[str] = [
    "password",
    "passwd",
    "secret",
    "apikey",
    "api_key",
    "accesskey",
    "access_key",
    "privatekey",
    "private_key",
    "token",
    "auth",
    "credential",
    "jwt",
    "certificate",
    "ssl_cert",
    "tls_key",
    "db_pass",
    "dbpass",
    "database_url",
    "connection_string",
    "aws_secret",
    "aws_access",
    "github_token",
]


def _secret_key_label(name: str) -> str | None:
    """
    Return the matched fragment label if *name* looks like a secret-bearing
    variable name, else None.
    """
    lower = name.lower().replace("-", "_")
    for frag in _SECRET_KEY_FRAGMENTS:
        if frag in lower:
            return frag
    return None

# Patterns that look like actual secret values (not empty or placeholder).
_VALUE_IS_PLACEHOLDER = re.compile(
    r"^(\s*|<.*?>|CHANGE_ME|changeme|placeholder|todo|fixme|xxx+|your[_-].*here)$",
    re.IGNORECASE,
)

# ENV can be: ENV KEY=VALUE or ENV KEY VALUE (legacy form)
_ENV_PAIR_RE = re.compile(r"(\w+)\s*=\s*(\S+|\".+?\"|'.+?')")
_ENV_LEGACY_RE = re.compile(r"^(\w+)\s+(\S+)")

# ARG form: ARG NAME=default_value
_ARG_RE = re.compile(r"^(\w+)(?:=(.*))?$")


def _parse_env_pairs(value: str) -> List[Tuple[str, str]]:
    """Return list of (name, value) pairs from an ENV instruction value."""
    pairs = _ENV_PAIR_RE.findall(value)
    if not pairs:
        # Legacy: ENV KEY VALUE
        m = _ENV_LEGACY_RE.match(value.strip())
        if m:
            pairs = [(m.group(1), m.group(2))]
    return pairs


def _parse_arg(value: str) -> Tuple[str, str]:
    """Return (name, default_value) from an ARG instruction value."""
    m = _ARG_RE.match(value.strip())
    if m:
        return m.group(1), (m.group(2) or "")
    return value.strip(), ""


def _is_suspicious_value(val: str) -> bool:
    """Return True if the value looks like a real secret rather than a placeholder."""
    val = val.strip().strip('"').strip("'")
    if not val:
        return False
    return not _VALUE_IS_PLACEHOLDER.match(val)


class SecretsInEnvRule(BaseRule):
    RULE_ID = "DH006"
    NAME = "SecretsInEnv"
    SEVERITY = Severity.CRITICAL
    TAGS = ["CIS-DI-0010", "OWASP-A02", "Docker-Hardening", "Secrets"]
    DESCRIPTION = (
        "ENV and ARG instructions must not contain credentials, tokens, or keys. "
        "Secrets in image layers are readable via docker history."
    )

    def check(self, dockerfile: "ParsedDockerfile") -> RuleResult:
        findings: list[Finding] = []

        env_instrs = dockerfile.by_command("ENV")
        arg_instrs = dockerfile.by_command("ARG")

        # --- ENV ---
        for instr in env_instrs:
            pairs = _parse_env_pairs(instr.value)
            for name, val in pairs:
                label = _secret_key_label(name)
                if label is None:
                    continue
                if _is_suspicious_value(val):
                    findings.append(
                        self._finding(
                            message=(
                                f'ENV variable "{name}" appears to contain a hardcoded secret '
                                f'(matched pattern: {label}). '
                                "Secrets embedded in ENV are stored in every image layer."
                            ),
                            line_number=instr.line_number,
                            fix_description=(
                                "Remove the secret from the Dockerfile. "
                                "Pass it at runtime via --env or --env-file, "
                                "or use Docker secrets / a secrets manager."
                            ),
                            fixable=False,
                            context=f"ENV {name}=***",
                            stage_index=instr.stage_index,
                        )
                    )
                else:
                    # Suspicious name but empty/placeholder value — warn at MEDIUM.
                    findings.append(
                        Finding(
                            rule_id=self.RULE_ID,
                            rule_name=self.NAME,
                            severity=Severity.MEDIUM,
                            message=(
                                f'ENV variable "{name}" has a secret-like name. '
                                "Ensure its value is never hardcoded in this file."
                            ),
                            line_number=instr.line_number,
                            fix_description=(
                                f"Inject at runtime: docker run --env {name}=<value> ..."
                            ),
                            fixable=False,
                            context=f"ENV {name}=<empty/placeholder>",
                            stage_index=instr.stage_index,
                            tags=list(self.TAGS),
                        )
                    )

        # --- ARG ---
        for instr in arg_instrs:
            name, default_val = _parse_arg(instr.value)
            label = _secret_key_label(name)
            if label is None:
                continue
            if _is_suspicious_value(default_val):
                findings.append(
                    self._finding(
                        message=(
                            f'ARG "{name}" has a secret-like name with a non-empty default value. '
                            "ARG defaults are stored in the image manifest."
                        ),
                        line_number=instr.line_number,
                        fix_description=(
                            f'Remove the default value: "ARG {name}". '
                            "Pass the value via --build-arg at build time "
                            "(but avoid this for production secrets — use BuildKit secrets instead)."
                        ),
                        fixable=False,
                        context=f"ARG {name}=***",
                        stage_index=instr.stage_index,
                    )
                )
            else:
                findings.append(
                    Finding(
                        rule_id=self.RULE_ID,
                        rule_name=self.NAME,
                        severity=Severity.LOW,
                        message=(
                            f'ARG "{name}" has a secret-like name. '
                            "If a real secret is passed via --build-arg, "
                            "it will appear in docker history."
                        ),
                        line_number=instr.line_number,
                        fix_description=(
                            "Use BuildKit secret mounts (--mount=type=secret) "
                            "instead of build args for sensitive values."
                        ),
                        fixable=False,
                        context=f"ARG {name}",
                        stage_index=instr.stage_index,
                        tags=list(self.TAGS),
                    )
                )

        return self._make_result(findings)
