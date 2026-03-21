FROM python:3.12.3-slim AS builder

WORKDIR /build
COPY pyproject.toml .
COPY dockerfile_hardener/ ./dockerfile_hardener/

RUN pip install --no-cache-dir --prefix=/install .


FROM python:3.12.3-slim

LABEL org.opencontainers.image.title="dockerfile-hardener" \
      org.opencontainers.image.description="Lint and auto-fix Dockerfiles against Docker hardening best practices" \
      org.opencontainers.image.source="https://github.com/macbuildssys/dockerfile-hardener" \
      org.opencontainers.image.licenses="MIT"

COPY --from=builder /install /usr/local

RUN groupadd --gid 65532 nonroot && useradd --uid 65532 --gid nonroot --no-create-home --shell /sbin/nologin nonroot

WORKDIR /work

HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD dockerfile-hardener --version || exit 1

USER nonroot

ENTRYPOINT ["dockerfile-hardener"]
CMD ["--help"]
