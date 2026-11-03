# SecureOps API and migration binaries.
#
# The API orchestrates and never executes untrusted target content, so this
# image deliberately contains no scanner binaries, no shell tooling, and no
# package managers (CLAUDE.md §14.1).

# Named down to the patch version: go.mod requires 1.27.3, this image sets
# GOTOOLCHAIN=local, and a cached older 1.27 image would fail the build.
FROM golang:1.27.3-alpine AS build
WORKDIR /src

# Cache dependency download separately from the source layer.
COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build \
        -trimpath \
        -ldflags "-s -w -X main.version=${VERSION}" \
        -o /out/api ./cmd/api && \
    CGO_ENABLED=0 GOOS=linux go build \
        -trimpath \
        -ldflags "-s -w -X main.version=${VERSION}" \
        -o /out/worker ./cmd/worker && \
    CGO_ENABLED=0 GOOS=linux go build \
        -trimpath \
        -ldflags "-s -w" \
        -o /out/migrate ./cmd/migrate && \
    CGO_ENABLED=0 GOOS=linux go build \
        -trimpath \
        -ldflags "-s -w" \
        -o /out/useradd ./cmd/useradd

# Distroless: no shell, no package manager, minimal attack surface.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/api /usr/local/bin/api
COPY --from=build /out/worker /usr/local/bin/worker
COPY --from=build /out/migrate /usr/local/bin/migrate
# The bootstrap command (ADR 033 §6a). In the image so the first admin can be
# created without a Go toolchain on the host -- which is the situation every
# real deployment is in.
#
# It reads the password from stdin, so it is only usable by somebody who can
# already run a container here. That is a higher bar than API access, which is
# the whole reason this is a command and not an endpoint.
COPY --from=build /out/useradd /usr/local/bin/useradd
COPY migrations /migrations

# Rule §15.10: containers run as non-root.
USER nonroot:nonroot
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/api"]
