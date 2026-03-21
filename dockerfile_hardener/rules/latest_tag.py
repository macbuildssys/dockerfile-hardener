"""
DH002 - LatestTag

FROM instructions should pin an explicit, non-latest tag (ideally a digest).
Using :latest breaks immutability — rebuilding the same Dockerfile may pull
a different image, making builds non-reproducible and hard to audit.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from .base import BaseRule, Finding, RuleResult, Severity

if TYPE_CHECKING:
    from dockerfile_hardener.parser import ParsedDockerfile

# Matches a valid image reference to extract the tag portion.
# Covers: image, image:tag, registry/image:tag, image@sha256:...
_IMAGE_RE = re.compile(
    r"""
    ^(?P<image>[^\s@:]+)        # image name (no whitespace, @, or :)
    (?::(?P<tag>[^\s@]+))?      # optional :tag
    (?:@(?P<digest>\S+))?       # optional @digest
    (?:\s+AS\s+\S+)?            # optional AS alias
    """,
    re.VERBOSE | re.IGNORECASE,
)

# Scratch and build-arg-based FROM are special cases.
_SCRATCH_RE = re.compile(r"^scratch\s*$", re.IGNORECASE)
_ARG_RE = re.compile(r"^\$\{?[\w]+\}?")  # ${BASE_IMAGE} or $BASE_IMAGE


class LatestTagRule(BaseRule):
    RULE_ID = "DH002"
    NAME = "LatestTag"
    SEVERITY = Severity.HIGH
    TAGS = ["CIS-DI-0006", "Docker-Hardening", "Supply-Chain"]
    DESCRIPTION = (
        "FROM should pin an explicit image tag or digest. " "Avoid :latest and untagged images."
    )

    def check(self, dockerfile: "ParsedDockerfile") -> RuleResult:
        findings: list[Finding] = []

        for instr in dockerfile.by_command("FROM"):
            value = instr.value.strip()

            # Scratch is intentionally tag-free — skip.
            if _SCRATCH_RE.match(value):
                continue

            # Build-arg references — we can't resolve these statically.
            if _ARG_RE.match(value):
                continue

            m = _IMAGE_RE.match(value)
            if not m:
                continue

            image = m.group("image") or ""
            tag = m.group("tag")
            digest = m.group("digest")

            # A digest pin is the most secure form — always accept.
            if digest:
                continue

            if tag is None:
                findings.append(
                    self._finding(
                        message=(
                            f'FROM "{image}" has no tag. '
                            "Docker will pull :latest, making this build non-reproducible."
                        ),
                        line_number=instr.line_number,
                        fix_description=(
                            f'Pin an explicit tag, e.g. "{image}:1.2.3", '
                            f'or a digest: "{image}@sha256:<hash>".'
                        ),
                        fixable=False,
                        context=instr.value,
                        stage_index=instr.stage_index,
                    )
                )
            elif tag.lower() == "latest":
                findings.append(
                    self._finding(
                        message=(
                            f'FROM "{image}:latest" uses the :latest tag. '
                            "This tag is mutable and may pull a different image on each build."
                        ),
                        line_number=instr.line_number,
                        fix_description=(
                            f'Replace ":latest" with a specific version tag or digest, '
                            f'e.g. "{image}:1.2.3".'
                        ),
                        fixable=False,
                        context=instr.value,
                        stage_index=instr.stage_index,
                    )
                )

        return self._make_result(findings)
