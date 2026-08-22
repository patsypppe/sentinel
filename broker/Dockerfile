# syntax=docker/dockerfile:1
# Pinned to the floor documented in docs/HANDOFF.md §4, not to "latest".
#
# This image runs with GOTOOLCHAIN=local, so it cannot paper over a dependency
# that raises broker/go.mod above 1.23 — it just fails. CI sets GOTOOLCHAIN=local
# everywhere for the same reason, so the failure arrives in the fast job instead.
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
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
