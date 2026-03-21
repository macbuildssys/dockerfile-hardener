"""
Tests for dockerfile_hardener.parser
"""

from __future__ import annotations

import pytest

from dockerfile_hardener.parser import parse_dockerfile

# ---------------------------------------------------------------------------- basic parsing


def test_parse_simple_dockerfile(parse_inline):
    df = parse_inline("""
        FROM ubuntu:22.04
        RUN echo hello
        CMD ["bash"]
    """)
    assert df.stage_count == 1
    assert len(df.by_command("FROM")) == 1
    assert len(df.by_command("RUN")) == 1
    assert len(df.by_command("CMD")) == 1


def test_parse_skips_blank_lines_and_comments(parse_inline):
    df = parse_inline("""
        # This is a comment
        FROM python:3.12.3-slim

        # Another comment
        RUN pip install flask
    """)
    assert df.stage_count == 1
    cmds = [i.command for i in df.instructions]
    assert "FROM" in cmds
    assert "RUN" in cmds
    # Comments must not appear as instructions.
    assert all(c != "#" for c in cmds)


def test_parse_line_continuation(parse_inline):
    df = parse_inline("""
        FROM debian:12
        RUN apt-get update \\
            && apt-get install -y curl \\
            && rm -rf /var/lib/apt/lists/*
    """)
    run = df.by_command("RUN")[0]
    assert "apt-get update" in run.value
    assert "apt-get install" in run.value
    assert "rm -rf" in run.value


def test_parse_multistage(parse_inline):
    df = parse_inline("""
        FROM golang:1.22 AS builder
        RUN go build -o /out/app .

        FROM gcr.io/distroless/static:nonroot
        COPY --from=builder /out/app /app
        CMD ["/app"]
    """)
    assert df.stage_count == 2
    builder_instrs = df.in_stage(0)
    runtime_instrs = df.in_stage(1)
    assert any(i.command == "RUN" for i in builder_instrs)
    assert any(i.command == "COPY" for i in runtime_instrs)


def test_parse_stage_names(parse_inline):
    df = parse_inline("""
        FROM python:3.12-slim AS base
        RUN echo base

        FROM base AS final
        CMD ["python"]
    """)
    names = df.stage_names()
    assert names[0] == "base"
    assert names[1] == "final"


def test_parse_last_stage_flag(parse_inline):
    df = parse_inline("""
        FROM alpine:3.19 AS build
        RUN apk add --no-cache gcc

        FROM alpine:3.19
        COPY --from=build /app /app
        CMD ["/app"]
    """)
    last_stage_cmds = {i.command for i in df.in_last_stage()}
    assert "COPY" in last_stage_cmds
    assert "CMD" in last_stage_cmds
    # The RUN in stage 0 must NOT be in last stage.
    build_run = df.in_stage(0)
    assert all(not i.is_last_stage for i in build_run)


def test_parse_line_numbers_are_correct(parse_inline):
    df = parse_inline("""
        FROM ubuntu:22.04
        RUN echo first
        ENV FOO=bar
        CMD ["bash"]
    """)
    frm = df.by_command("FROM")[0]
    run = df.by_command("RUN")[0]
    env = df.by_command("ENV")[0]
    assert frm.line_number == 1
    assert run.line_number == 2
    assert env.line_number == 3


def test_parse_file_not_found():
    with pytest.raises(FileNotFoundError):
        parse_dockerfile("/nonexistent/path/Dockerfile")


def test_parse_fixture_insecure(fixture_path):
    df = parse_dockerfile(fixture_path("Dockerfile.insecure"))
    assert df.stage_count == 1
    assert df.has_command("FROM")
    assert df.has_command("ENV")
    assert df.has_command("RUN")
    assert df.has_command("EXPOSE")
    assert df.has_command("ADD")


def test_parse_fixture_secure(fixture_path):
    df = parse_dockerfile(fixture_path("Dockerfile.secure"))
    assert df.stage_count == 2
    assert df.has_command("HEALTHCHECK")
    assert df.has_command("USER")
