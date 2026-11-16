# The scanner as a container: `docker run ghcr.io/patsypppe/toolgauge scan --endpoint ...`.
#
# Two stages, so the image carries the installed wheel and nothing that built it:
# no compiler, no pip cache, no source tree. It runs as an unprivileged user, and
# the only network call it makes is to the endpoint it is given.
#
# `python:3.12-slim` rather than a distroless base: the harness needs a Python 3.12
# runtime, and the distroless Python images are older. Node comes from the official
# slim image in its own stage, so `lint --command "npx -y ..."` works; both bases
# are Debian bookworm, so the binary and its shared libraries match.

FROM node:22-slim AS node

FROM python:3.12-slim AS build
WORKDIR /src
COPY harness/ /src/harness/
# harness/pyproject.toml force-includes ../fixtures/server in the wheel; without it
# `python -m build` fails with "Forced include not found".
COPY fixtures/server/ /src/fixtures/server/
RUN pip install --no-cache-dir build \
    && python -m build --wheel --outdir /dist /src/harness

FROM python:3.12-slim
LABEL org.opencontainers.image.source="https://github.com/patsypppe/sentinel" \
      org.opencontainers.image.description="Conformance harness for MCP 2026-07-28" \
      org.opencontainers.image.licenses="MIT"
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin toolgauge
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules /usr/local/lib/node_modules
# npm and npx ship as symlinks into node_modules; COPY would flatten them into
# scripts whose relative requires then point at the wrong directory.
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
    && ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx
COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -f /tmp/*.whl
USER 10001
WORKDIR /work
# npx and npm cache under HOME; the unprivileged user has no home of its own, and
# /work is not writable by it.
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 HOME=/tmp
ENTRYPOINT ["toolgauge"]
CMD ["--help"]
