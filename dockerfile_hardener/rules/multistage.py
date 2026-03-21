"""
DH004 - MultiStage

Compiled languages (Go, C/C++, Rust, Java, etc.) should use multi-stage builds.
The build toolchain stays in the builder stage; only the final binary is copied
to a minimal runtime image. Single-stage builds ship compilers, source code,
and build artefacts alongside the application — all unnecessary attack surface.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, List

from .base import BaseRule, Finding, RuleResult, Severity

if TYPE_CHECKING:
    from dockerfile_hardener.parser import ParsedDockerfile

# Build-tool package names that indicate a compiled project.
_BUILD_TOOLS: List[str] = [
    "gcc", "g++", "clang", "make", "cmake", "ninja",
    "rustc", "cargo",
    "golang", "go",
    "javac", "maven", "gradle",
    "dotnet", "msbuild",
    "build-essential",
    "autoconf", "automake", "libtool",
]

_BUILD_TOOL_RE = re.compile(
    r"\b(" + "|".join(re.escape(t) for t in _BUILD_TOOLS) + r")\b",
    re.IGNORECASE,
)

# Patterns for install commands in RUN instructions.
_INSTALL_RE = re.compile(
    r"\b(apt-get|apt|apk|yum|dnf|zypper)\s+(install|add)\b",
    re.IGNORECASE,
)

# Common source-code file extensions that should not be in a production image.
_SOURCE_COPY_RE = re.compile(
    r"\.(go|rs|c|cpp|cc|cxx|h|hpp|java|cs|kt|swift|ts|tsx)\s",
    re.IGNORECASE,
)

# Makefile / build script execution patterns.
_BUILD_EXEC_RE = re.compile(
    r"\b(make|cmake|cargo\s+build|go\s+build|mvn\s+package|gradle\s+build|"
    r"dotnet\s+build|dotnet\s+publish)\b",
    re.IGNORECASE,
)


class MultiStageRule(BaseRule):
    RULE_ID = "DH004"
    NAME = "MultiStage"
    SEVERITY = Severity.MEDIUM
    TAGS = ["Docker-Hardening", "Attack-Surface", "Image-Size"]
    DESCRIPTION = (
        "Compiled languages should use multi-stage builds to keep the final image minimal. "
        "Build toolchains must not be present in the production stage."
    )

    def check(self, dockerfile: "ParsedDockerfile") -> RuleResult:
        findings: list[Finding] = []

        # If already using multiple stages, this rule is satisfied.
        if dockerfile.stage_count > 1:
            return self._make_result()

        # Single-stage Dockerfile — check for build-tool indicators.
        run_instrs = [i for i in dockerfile.instructions if i.command == "RUN"]
        copy_instrs = [i for i in dockerfile.instructions if i.command == "COPY"]

        for instr in run_instrs:
            value = instr.value

            # Check for build tool installation.
            if _INSTALL_RE.search(value):
                m = _BUILD_TOOL_RE.search(value.lower())
                if m:
                    tool = m.group(1)
                    findings.append(
                        self._finding(
                            message=(
                                f'Build tool "{tool}" is installed in a single-stage Dockerfile. '
                                "The compiler/toolchain will be shipped in the production image."
                            ),
                            line_number=instr.line_number,
                            fix_description=(
                                "Convert to a multi-stage build: use a builder stage to compile, "
                                "then COPY only the output binary into a minimal runtime image "
                                "(e.g. scratch, distroless, or alpine)."
                            ),
                            fixable=False,
                            context=value[:120],
                        )
                    )

            # Check for direct build command execution.
            if _BUILD_EXEC_RE.search(value):
                findings.append(
                    self._finding(
                        message=(
                            f"Build command detected in a single-stage Dockerfile: "
                            f'"{value[:60].strip()}". '
                            "Build artefacts and tools will be included in the final image."
                        ),
                        line_number=instr.line_number,
                        fix_description=(
                            "Move the build step to a dedicated builder stage. "
                            "Use COPY --from=builder to extract only the compiled output."
                        ),
                        fixable=False,
                        context=value[:120],
                    )
                )

        # Check for COPY of source files directly.
        for instr in copy_instrs:
            if _SOURCE_COPY_RE.search(instr.value):
                findings.append(
                    self._finding(
                        message=(
                            f"Source code files are being COPYed in a single-stage build: "
                            f'"{instr.value[:60]}". '
                            "Source code should not be present in a production image."
                        ),
                        line_number=instr.line_number,
                        fix_description=(
                            "Use a multi-stage build. Compile in a builder stage, "
                            "then copy only the output binary."
                        ),
                        fixable=False,
                        context=instr.value[:120],
                    )
                )

        # De-duplicate findings by line number to avoid multiple reports per instruction.
        seen: set[int] = set()
        deduped: list[Finding] = []
        for f in findings:
            key = f.line_number or 0
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        return self._make_result(deduped)
