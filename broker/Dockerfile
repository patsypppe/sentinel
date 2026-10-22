# syntax=docker/dockerfile:1
# Pinned to the floor documented in docs/HANDOFF.md §4, not to "latest".
#
# This image runs with GOTOOLCHAIN=local, so it cannot paper over a dependency
# that raises broker/go.mod above 1.23 — it just fails. CI sets GOTOOLCHAIN=local
# everywhere for the same reason, so the failure arrives in the fast job instead.
FROM golang:1.23-alpine AS build
# Built from the repository root: the broker imports the server kit in ../mcp, and
# its go.mod replaces that module with the sibling directory.
WORKDIR /src
COPY mcp/go.mod mcp/go.sum ./mcp/
COPY broker/go.mod broker/go.sum ./broker/
WORKDIR /src/broker
RUN go mod download
WORKDIR /src
COPY mcp ./mcp
COPY broker ./broker
WORKDIR /src/broker
ARG VERSION=0.1.0-dev
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X github.com/patsypppe/sentinel/broker/internal/version.Version=${VERSION}" \
      -o /out/broker ./cmd/broker

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata \
 && adduser -D -u 10001 broker
COPY --from=build /out/broker /usr/local/bin/broker
USER broker
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/broker"]
CMD ["serve"]
