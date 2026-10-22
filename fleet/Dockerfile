# syntax=docker/dockerfile:1
# The fleet service. Built from the fleet/ directory: it depends on nothing else in
# this repository (the Go module needs only pgx), so the context is small and the
# build does not need the rest of the tree.
#
# Pinned to the Go floor the repository documents, with GOTOOLCHAIN=local so a
# dependency that raises it fails the build instead of quietly fetching a toolchain.
FROM golang:1.23-alpine AS build
ENV GOTOOLCHAIN=local
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=0.1.0-dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/sentinel-server ./cmd/sentinel-server

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata && adduser -D -u 10001 sentinel
COPY --from=build /out/sentinel-server /usr/local/bin/sentinel-server
USER sentinel
EXPOSE 8088
# The default address binds loopback inside the container, which is unreachable from
# outside it. Set SENTINEL_SERVER_ADDR=0.0.0.0:8088 deliberately, and set both tokens.
ENTRYPOINT ["/usr/local/bin/sentinel-server"]
CMD ["serve"]
