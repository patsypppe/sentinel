# The scanner as a container: `docker run ghcr.io/patsypppe/sentinel scan --endpoint ...`.
#
# Two stages, so the image carries the installed wheel and nothing that built it:
# no compiler, no pip cache, no source tree. It runs as an unprivileged user, and
# the only network call it makes is to the endpoint it is given.
#
# `python:3.12-slim` rather than a distroless base: the harness needs a Python 3.12
# runtime, and the distroless Python images are older. Slim plus a non-root user,
# nothing else installed, is the honest description of what this is.

FROM python:3.12-slim AS build
WORKDIR /src
COPY harness/ /src/harness/
RUN pip install --no-cache-dir build \
    && python -m build --wheel --outdir /dist /src/harness

FROM python:3.12-slim
LABEL org.opencontainers.image.source="https://github.com/patsypppe/sentinel" \
      org.opencontainers.image.description="Conformance harness for MCP 2026-07-28" \
      org.opencontainers.image.licenses="MIT"
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin sentinel
COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -f /tmp/*.whl
USER 10001
WORKDIR /work
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
ENTRYPOINT ["sentinel"]
CMD ["--help"]
