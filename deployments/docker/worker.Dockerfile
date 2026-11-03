# SecureOps scanner worker.
#
# This image is deliberately NOT the API image. The worker is the only
# component that executes scanner binaries and touches untrusted target content
# (CLAUDE.md §14.2), so it needs a toolchain the API must never have. Keeping
# them separate is what lets the API stay distroless: no shell, no package
# manager, no scanner binaries in the process that is actually exposed.
#
# Everything installed here is pinned and checksum-verified. A scanner binary is
# a supply-chain dependency that runs against attacker-controlled input, so
# "latest" is not acceptable (threat model T-10).

# Named down to the patch version: go.mod requires 1.27.3, this image sets
# GOTOOLCHAIN=local, and a cached older 1.27 image would fail the build.
FROM golang:1.27.3-alpine AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build \
        -trimpath \
        -ldflags "-s -w -X main.version=${VERSION}" \
        -o /out/worker ./cmd/worker

# The scan job (ADR 039). One image carries both because it already carries the
# scanner binaries the job needs, and a second image differing only in its
# entrypoint would be a second thing to build, pin and scan.
#
# The image is what the Job's `command` selects. Omitting this binary is why a
# scan pod died with `stat /usr/local/bin/scanjob: no such file or directory` --
# `make build-go` had it, the image did not, and nothing compared the two.
RUN CGO_ENABLED=0 GOOS=linux go build \
        -trimpath \
        -ldflags "-s -w -X main.version=${VERSION}" \
        -o /out/scanjob ./cmd/scanjob

# --- scanner toolchain -------------------------------------------------------
#
# Scanners are BUILT FROM SOURCE rather than installed from release archives.
# This is a deliberate supply-chain decision (ADR 009), not a convenience.
#
# The published gitleaks 8.30.1 binary carries 32 HIGH/CRITICAL CVEs: 21 in a
# stale Go standard library (it is built with Go 1.24.11) and 11 in x/crypto and
# x/text. There is no newer release to upgrade to -- 8.30.1 is the latest.
# Rebuilding here with this project's Go toolchain and patched x/ libraries
# brings that to zero, and the resulting binary produces byte-identical output
# on a 22-finding corpus of real planted secrets.
#
# The source is pinned to an immutable commit SHA, not a tag. Tags are mutable,
# so a SHA is a stronger guarantee than the publisher checksum this replaces.

FROM golang:1.27.3-alpine AS tools
RUN apk add --no-cache git

# v8.30.1
ARG GITLEAKS_COMMIT=83d9cd684c87d95d656c1458ef04895a7f1cbd8e
ARG GITLEAKS_VERSION=8.30.1
# Patched versions of the two x/ libraries carrying the remaining CVEs. Bumped
# explicitly and pinned: the build must not drift with the module proxy.
# GO-2026-6354 and GO-2026-6355 (CVE-2026-78662, CVE-2026-56855): two DoS
# advisories in golang.org/x/crypto/ssh, both fixed in v0.56.0. Every scanner
# below pulls x/crypto transitively, so every one is pinned past them.
# GO-2026-5932 (x/crypto/openpgp) has no tagged release yet: this is the commit
# the advisory names as its fix, which removes the package. Replace it with a
# tag once one exists.
ARG X_CRYPTO_VERSION=v0.58.1-0.20261009181718-2f1f834330b2
ARG X_TEXT_VERSION=v0.43.0
# Three archive-handling advisories that trivy does not report and govulncheck
# does. All three are in code that parses attacker-supplied archives, which is
# exactly the code path a secret scanner points at untrusted repositories.
#
# Bumped through mholt/archives rather than by pinning its dependencies
# underneath it: rardecode v2.2.0 changes an interface that archives v0.1.2
# implements against, so forcing the child alone fails to compile. v0.1.5
# already carries the fixed rardecode and xz. klauspost/compress still needs
# its own bump -- archives v0.1.5 pins v1.18.0 and the fix landed in v1.18.7.
ARG ARCHIVES_VERSION=v0.1.5
ARG COMPRESS_VERSION=v1.18.7

RUN set -eux; \
    git clone --no-checkout https://github.com/gitleaks/gitleaks /src; \
    cd /src; \
    git checkout -q "${GITLEAKS_COMMIT}"; \
    # Confirm the checkout really is the pinned commit before building it.
    test "$(git rev-parse HEAD)" = "${GITLEAKS_COMMIT}"; \
    go get "golang.org/x/crypto@${X_CRYPTO_VERSION}" "golang.org/x/text@${X_TEXT_VERSION}" \
           "github.com/mholt/archives@${ARCHIVES_VERSION}" \
           "github.com/klauspost/compress@${COMPRESS_VERSION}"; \
    go mod tidy; \
    CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X github.com/zricethezav/gitleaks/v8/version.Version=${GITLEAKS_VERSION}" \
      -o /out/gitleaks .; \
    # The version is captured per scan and persisted (§7 rule 6), so a binary
    # that misreports it is a defect. Without the ldflag above gitleaks prints
    # "version is set by build process", which would be stored as the scanner
    # version for every result.
    test "$(/out/gitleaks version)" = "${GITLEAKS_VERSION}"

# Syft, same pattern: pinned commit, our toolchain, version asserted.
# v1.51.0
ARG SYFT_COMMIT=2293641e3bd628a01bb37639318d62c0ebe89b39
ARG SYFT_VERSION=1.51.0
# Carries the two x/mod advisories that survive a plain rebuild.
ARG X_MOD_VERSION=v0.41.0
# The same OpenTelemetry advisory already pinned out of grype. Fixed here too:
# a fix applied to one scanner and not another is an accident waiting to be
# rediscovered.
# GO-2026-6505 needs the SDK at the same version.
ARG SYFT_OTEL_VERSION=v1.45.0
# CVE-2026-84304 (HIGH): gRPC-Go. Fixed in 1.83.1, and every scanner below
# vendors an affected version -- syft and trivy at v1.82.1, grype at v1.83.0,
# measured with `go version -m` on the built binaries rather than inferred.
# Pinned per stage rather than globally: a fix applied to one scanner and not
# another is an accident waiting to be rediscovered.
# GO-2026-6443 (CVE-2026-84445) moved the floor to 1.83.2.
ARG SYFT_GRPC_VERSION=v1.83.2
# Advisories a plain rebuild leaves behind, found by govulncheck and trivy on the
# built binaries. x/net: seven advisories, the last two fixed only in v0.62.0.
# containerd: four, the last fixed in v2.3.6. Pinned per stage like gRPC above.
ARG SYFT_X_NET_VERSION=v0.62.0
ARG SYFT_CONTAINERD_VERSION=v2.3.6
ARG SYFT_MOBY_USER_VERSION=v0.4.1
ARG SYFT_JOSE_VERSION=v4.1.6

RUN set -eux; \
    git clone --no-checkout https://github.com/anchore/syft /syft-src; \
    cd /syft-src; \
    git checkout -q "${SYFT_COMMIT}"; \
    test "$(git rev-parse HEAD)" = "${SYFT_COMMIT}"; \
    go get "golang.org/x/mod@${X_MOD_VERSION}" \
           "golang.org/x/crypto@${X_CRYPTO_VERSION}" \
           "go.opentelemetry.io/otel@${SYFT_OTEL_VERSION}" \
           "go.opentelemetry.io/otel/sdk@${SYFT_OTEL_VERSION}" \
           "google.golang.org/grpc@${SYFT_GRPC_VERSION}" \
           "golang.org/x/net@${SYFT_X_NET_VERSION}" \
           "github.com/containerd/containerd/v2@${SYFT_CONTAINERD_VERSION}" \
           "github.com/moby/sys/user@${SYFT_MOBY_USER_VERSION}" \
           "github.com/go-jose/go-jose/v4@${SYFT_JOSE_VERSION}"; \
    go mod tidy; \
    CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X main.version=${SYFT_VERSION}" \
      -o /out/syft ./cmd/syft; \
    # The version is captured per scan and persisted (§7 rule 6), so a binary
    # that misreports it is a defect, not cosmetics.
    /out/syft version -o text | grep -q "${SYFT_VERSION}"

# Grype, same pattern: pinned commit, our toolchain, version asserted.
#
# The binary only. Its 2 GB vulnerability database is NOT baked in -- it is
# provisioned into a volume at worker startup, before any job is claimed
# (ADR 012). A database in the image would be stale the moment it was built.
# v0.118.0
ARG GRYPE_COMMIT=756eb9a24f7beeafb6871a24e943e8a3ae210695
ARG GRYPE_VERSION=0.118.0
# Carries the two x/mod advisories that survive a plain rebuild, same as syft.
ARG GRYPE_X_MOD_VERSION=v0.41.0
# And an OpenTelemetry advisory that a plain rebuild also leaves behind.
ARG GRYPE_OTEL_VERSION=v1.45.0
# CVE-2026-84304, the same gRPC-Go advisory pinned out of syft above.
ARG GRYPE_GRPC_VERSION=v1.83.2
# The same advisories pinned out of syft above.
ARG GRYPE_X_NET_VERSION=v0.62.0
ARG GRYPE_CONTAINERD_VERSION=v2.3.6
ARG GRYPE_MOBY_USER_VERSION=v0.4.1
ARG GRYPE_JOSE_VERSION=v4.1.6

RUN set -eux; \
    git clone --no-checkout https://github.com/anchore/grype /grype-src; \
    cd /grype-src; \
    git checkout -q "${GRYPE_COMMIT}"; \
    test "$(git rev-parse HEAD)" = "${GRYPE_COMMIT}"; \
    go get "golang.org/x/mod@${GRYPE_X_MOD_VERSION}" \
           "golang.org/x/crypto@${X_CRYPTO_VERSION}" \
           "go.opentelemetry.io/otel@${GRYPE_OTEL_VERSION}" \
           "go.opentelemetry.io/otel/sdk@${GRYPE_OTEL_VERSION}" \
           "google.golang.org/grpc@${GRYPE_GRPC_VERSION}" \
           "golang.org/x/net@${GRYPE_X_NET_VERSION}" \
           "github.com/containerd/containerd/v2@${GRYPE_CONTAINERD_VERSION}" \
           "github.com/moby/sys/user@${GRYPE_MOBY_USER_VERSION}" \
           "github.com/go-jose/go-jose/v4@${GRYPE_JOSE_VERSION}"; \
    go mod tidy; \
    CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X main.version=${GRYPE_VERSION}" \
      -o /out/grype ./cmd/grype; \
    /out/grype version -o text | grep -q "${GRYPE_VERSION}"

# Trivy needs its own build stage, on its own Go version.
#
# ADR 009 builds every scanner with this project's toolchain. Trivy is the first
# that cannot be: v0.74.0 targets Go 1.26.3 and uses encoding/json/v2, which is
# experimental and whose API is not stable across releases. `json.SkipFunc`
# exists in Go 1.26 and was removed in 1.27 -- checked in both, not inferred --
# so building it here with 1.27 fails outright with "undefined: json.SkipFunc".
#
# Pinning the toolchain the scanner targets is the more honest reading of ADR
# 009 than forcing a version its source does not compile against. The cost is
# that this binary misses Go 1.27's standard-library fixes, which is why trivy
# is in the govulncheck gate (ADR 013) and the image scan: if that costs us an
# advisory, both will say so rather than us finding out later.
FROM golang:1.26-alpine AS trivy-build
RUN apk add --no-cache git

# v0.74.0
ARG TRIVY_COMMIT=e1fd17a0ea4a8cf24bc4b4dd7e2cfbf4bb31b994
ARG TRIVY_VERSION=0.74.0
# CVE-2026-84304, the same gRPC-Go advisory pinned out of syft and grype.
ARG TRIVY_GRPC_VERSION=v1.83.2
# Redeclared rather than inherited: an ARG does not cross a FROM, and trivy
# builds in its own stage. GO-2026-6354 / GO-2026-6355 as above.
ARG TRIVY_X_CRYPTO_VERSION=v0.58.1-0.20261009181718-2f1f834330b2
# The same advisories pinned out of syft and grype. The exporters move with the
# SDK, because trivy links them and GO-2026-6505 reports all three.
ARG TRIVY_X_NET_VERSION=v0.62.0
ARG TRIVY_CONTAINERD_VERSION=v2.3.6
ARG TRIVY_OTEL_VERSION=v1.45.0
ARG TRIVY_JOSE_VERSION=v4.1.6

RUN set -eux; \
    # Shallow, at the tag, unlike the other scanners' full clones. Trivy's
    # repository is large enough that a full clone failed mid-transfer with an
    # SSL EOF; fetching one commit is far less to go wrong with.
    #
    # This does not weaken the pin. The assertion below still compares the
    # resolved HEAD against the commit SHA, so a tag repointed at different
    # code fails the build exactly as it would with a full clone.
    git clone --depth 1 --branch "v${TRIVY_VERSION}" \
        https://github.com/aquasecurity/trivy /trivy-src; \
    cd /trivy-src; \
    test "$(git rev-parse HEAD)" = "${TRIVY_COMMIT}"; \
    # GOEXPERIMENT is set on the module commands too, not just the build.
    # trivy's pkg/x/json imports encoding/json/v2, which only exists under the
    # experiment, so `go mod tidy` without it fails to load the package.
    GOEXPERIMENT=jsonv2 go get "google.golang.org/grpc@${TRIVY_GRPC_VERSION}" \
        "golang.org/x/crypto@${TRIVY_X_CRYPTO_VERSION}" \
        "golang.org/x/net@${TRIVY_X_NET_VERSION}" \
        "github.com/containerd/containerd/v2@${TRIVY_CONTAINERD_VERSION}" \
        "go.opentelemetry.io/otel@${TRIVY_OTEL_VERSION}" \
        "go.opentelemetry.io/otel/sdk@${TRIVY_OTEL_VERSION}" \
        "go.opentelemetry.io/otel/exporters/otlp/otlptrace@${TRIVY_OTEL_VERSION}" \
        "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc@${TRIVY_OTEL_VERSION}" \
        "github.com/go-jose/go-jose/v4@${TRIVY_JOSE_VERSION}"; \
    GOEXPERIMENT=jsonv2 go mod tidy; \
    # GOEXPERIMENT=jsonv2 is not optional and not a tuning choice: trivy's
    # pkg/x/json calls into encoding/json/v2. This matches what trivy's own
    # release build sets, which is also what ADR 009's equivalence requirement
    # wants -- the same source, built the way upstream builds it.
    CGO_ENABLED=0 GOEXPERIMENT=jsonv2 go build -trimpath \
      -ldflags "-s -w -X github.com/aquasecurity/trivy/pkg/version/app.ver=${TRIVY_VERSION}" \
      -o /out/trivy ./cmd/trivy; \
    # The version is captured per scan and persisted (§7 rule 6), so a binary
    # that misreports it is a defect.
    /out/trivy --version | grep -q "${TRIVY_VERSION}"

# --- runtime -----------------------------------------------------------------
#
# Alpine rather than distroless: the worker needs git, which needs a libc and a
# filesystem layout. The trade is accepted because the worker is not
# network-exposed -- it consumes a queue and never serves requests.

FROM alpine:3.22 AS worker

# --- OWASP ZAP ---------------------------------------------------------------
#
# ZAP cannot be built from source with this project's toolchain, so ADR 009 does
# not transfer -- the situation semgrep is in, and ADR 014 already settled the
# pattern: pin the version and verify the publisher's own digest before anything
# executes. ZAP publishes a SHA-256 for every release asset in its release notes.
#
# The Crossplatform archive rather than the Linux tarball: ZAP is Java, so the
# archive is architecture-independent and ONE digest covers both amd64 and
# arm64. Semgrep above needs a digest per architecture; this does not, and fewer
# pins is fewer things to get wrong.
ARG ZAP_VERSION=2.17.0
ARG ZAP_SHA256=94c8f767b1c2e94f0db66b3ae56514d5e3f5a728ee1b6c798e0c8fe2d61fbff0

# The add-ons the automation plan actually uses, and nothing else.
#
# The archive ships 50 add-ons totalling 276 MB; these nine total 82.5 MB and
# were verified to produce identical findings -- same alert count, same plugin
# ids, against the same target.
#
# The point is not the disk space. What is removed includes `ascanrules`, ZAP's
# ACTIVE SCAN RULES. ADR 026's control is that the activeScan job is absent from
# the plan rather than disabled in it, so that no configuration change can
# switch it on; not shipping the payloads carries that one layer further, so
# there is no configuration AND no code in the image that could run one. `fuzz`
# and `spiderAjax` (which pulls in browser automation) go with them.
#
# Three of these are not obvious and were found by running, not by reading:
# `callhome` is MANDATORY -- ZAP refuses to start without it even though the
# adapter disables its telemetry by config -- and `commonlib` and `database` are
# transitive dependencies whose absence produces no message naming them.
ARG ZAP_ADDONS="automation callhome commonlib database network pscan pscanrules reports spider"

# This block runs BEFORE the semgrep install below, and the order is load-
# bearing: that block ends by deleting apk, so anything needing a package must
# be installed before it. Moving this after it fails with exit 127.
RUN set -eux; \
    # Headless: a worker has no display, and ZAP's GUI classes have no business
    # in the container that executes untrusted content. From the distribution's
    # package index rather than from ZAP's own bundled JVM, so it is patched on
    # Alpine's schedule and not on an application vendor's.
    apk add --no-cache openjdk21-jre-headless; \
    apk add --no-cache --virtual .zap-install curl unzip; \
    curl -fsSL -o /tmp/zap.zip \
      "https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Crossplatform.zip"; \
    # Verified before anything is unpacked, let alone executed. This is the
    # whole substitute for building from source (ADR 014).
    echo "${ZAP_SHA256}  /tmp/zap.zip" | sha256sum -c -; \
    unzip -q /tmp/zap.zip -d /opt; \
    mv "/opt/ZAP_${ZAP_VERSION}" /opt/zap; \
    rm -f /tmp/zap.zip; \
    \
    # Trimmed in the SAME layer as the unpack. Deleting in a later RUN leaves
    # the files in the image -- the layer below still carries them -- so the
    # 194 MB saving depends on this being one instruction.
    cd /opt/zap/plugin; \
    mkdir -p /tmp/keep; \
    for k in ${ZAP_ADDONS}; do \
      for f in ${k}-*.zap; do \
        if [ -e "$f" ]; then cp "$f" /tmp/keep/; fi; \
      done; \
    done; \
    rm -f /opt/zap/plugin/*.zap; \
    cp /tmp/keep/*.zap /opt/zap/plugin/; \
    rm -rf /tmp/keep; \
    \
    # A stable path, so bumping ZAP does not mean editing the worker's
    # configuration. The adapter still asks ZAP for its version per scan, so the
    # symlink hides nothing that is recorded.
    ln -s "/opt/zap/zap-${ZAP_VERSION}.jar" /opt/zap/zap.jar; \
    \
    apk del .zap-install; \
    \
    # Asserted after the teardown, for the reason semgrep's assertion is:
    # a check that runs before the cleanup passes against a filesystem that does
    # not ship. The version is captured per scan and persisted (§7 rule 6), so a
    # binary that misreports it is a defect.
    #
    # `java -jar` and not `zap.sh`: the launcher is `#!/usr/bin/env bash` and
    # uses bash-only constructs, and adding a general-purpose shell to the one
    # container that executes untrusted content is not a trade worth making
    # (ADR 030).
    # -dir is required even to print a version: ZAP creates its home first, and
    # without one it throws on $HOME/.ZAP and prints a stack trace instead. The
    # adapter's version probe passes it for the same reason.
    java -jar /opt/zap/zap.jar -dir /tmp/zapcheck -version | grep -qx "${ZAP_VERSION}"; \
    rm -rf /tmp/zapcheck

# Note on what is NOT done here: `chmod -R a-w /opt/zap`.
#
# It looks like obvious hardening and it breaks ZAP. ZAP seeds a new home
# directory by COPYING config.xml out of the install directory, and the copy
# inherits the source's mode -- so a read-only template produces a read-only
# config.xml that ZAP then fails to write, with "Permission denied" on a path
# under the home rather than under /opt. Found by running it, not by reading.
#
# It is also redundant. The installation is owned by root and every scan runs as
# nonroot (USER below), so the worker already cannot write to it.

# Semgrep is Python, so unlike every other scanner here it cannot be built from
# source with our own toolchain (ADR 009 does not transfer; see ADR 014). It is
# installed from the musllinux wheel published on PyPI, with that wheel's
# SHA-256 verified against the digest PyPI publishes for it.
#
# Pinned per architecture because the digest differs: the build resolves
# TARGETARCH rather than trusting whichever wheel pip happens to pick.
ARG SEMGREP_VERSION=1.183.0
ARG SEMGREP_SHA256_AMD64=204dce82a74be29cf6d84aa6a32b2244ff7429fafd3d77e0ea44996d0398ba4a
ARG SEMGREP_SHA256_ARM64=a06b09d20c5595a31be210283b8ce50251305d49fb6e9214b50329a119779751
ARG TARGETARCH

# git is required to fetch repository targets (ADR 008). ca-certificates is
# required for https remotes. python3 is required by semgrep. Nothing else is
# installed, and everything used only to install is removed again below --
# including apk itself, which is why the ZAP block above must come first.
RUN set -eux; \
    apk add --no-cache git ca-certificates python3; \
    apk add --no-cache --virtual .semgrep-install py3-pip; \
    \
    case "${TARGETARCH}" in \
      amd64) wheel_sha="${SEMGREP_SHA256_AMD64}" ;; \
      arm64) wheel_sha="${SEMGREP_SHA256_ARM64}" ;; \
      *) echo "no pinned semgrep wheel for TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    pip download --no-deps --no-cache-dir -d /tmp semgrep=="${SEMGREP_VERSION}"; \
    # The artifact is verified before anything executes it. This is the whole
    # substitute for building from source: semgrep cannot be rebuilt with our
    # toolchain, so we at least refuse to install a wheel that is not the one
    # PyPI published (ADR 014).
    echo "${wheel_sha}  $(ls /tmp/semgrep-*.whl)" | sha256sum -c -; \
    \
    # Installed under its own prefix, not into the system site-packages.
    # Sharing that directory with apk means pip skips any dependency apk
    # already provides, and removing pip afterwards then takes those with it --
    # which is exactly how the first attempt produced a semgrep that could not
    # import `packaging`. A separate prefix has no such overlap.
    # --ignore-installed matters as much as --prefix. Without it pip treats any
    # dependency apk already provides as satisfied and does not place a copy in
    # the prefix; removing pip's apk package then takes those shared copies
    # away, leaving a semgrep that cannot import `packaging`.
    pip install --no-cache-dir --break-system-packages --ignore-installed \
        --prefix=/opt/semgrep /tmp/semgrep-*.whl; \
    rm -f /tmp/semgrep-*.whl; \
    \
    # pip is a strictly better escalation tool than apk -- it downloads and
    # executes arbitrary code by design -- so it leaves with everything else.
    apk del .semgrep-install; \
    \
    # The version is captured per scan and persisted (§7 rule 6), so a binary
    # that misreports it is a defect.
    #
    # Asserted AFTER the teardown above, deliberately. Run before it, this test
    # passes against a filesystem that does not ship: the first attempt checked
    # a working semgrep, then deleted the packages it depended on, and produced
    # a green build and a broken image.
    test "$(PATH=/opt/semgrep/bin:$PATH \
            PYTHONPATH=/opt/semgrep/lib/python3.12/site-packages \
            semgrep --version)" = "${SEMGREP_VERSION}"; \
    \
    # Pick up any security fixes newer than the base image tag.
    apk upgrade --no-cache; \
    # No package manager in the running container: the worker executes
    # untrusted content, and apk would be a convenient escalation tool.
    rm -rf /sbin/apk /etc/apk /lib/apk /usr/share/apk /var/cache/apk

# 65532 matches the distroless "nonroot" UID the other images use, so the
# compose tmpfs ownership is the same for every service.
RUN addgroup -g 65532 -S nonroot && \
    adduser -u 65532 -S nonroot -G nonroot

# semgrep lives under its own prefix, so neither its packages nor its helper
# executables are found by default. Both are needed: the `semgrep` entrypoint is
# an OCaml binary that execs a `pysemgrep` helper, which fails with a bare
# "execvp pysemgrep" if the prefix's bin is not on PATH.
#
# SECUREOPS_ZAP_JAR: jar mode is opt-in and the image is what opts in (ADR 030).
# Config defaults it to empty so a developer's checkout keeps using the launcher
# its local ZAP install ships with.
ENV PATH=/opt/semgrep/bin:/usr/local/bin:/usr/bin:/bin \
    PYTHONPATH=/opt/semgrep/lib/python3.12/site-packages \
    SECUREOPS_ZAP_JAR=/opt/zap/zap.jar

COPY --from=build /out/worker /usr/local/bin/worker
COPY --from=build /out/scanjob /usr/local/bin/scanjob
COPY --from=tools /out/gitleaks /usr/local/bin/gitleaks
COPY --from=tools /out/syft /usr/local/bin/syft
COPY --from=tools /out/grype /usr/local/bin/grype
COPY --from=trivy-build /out/trivy /usr/local/bin/trivy

# The workspace root is created by the runtime (a tmpfs in compose, an
# emptyDir in Kubernetes) so that untrusted content never touches the image
# layers.
RUN mkdir -p /workspaces && chown nonroot:nonroot /workspaces
# The vulnerability database lives outside the workspace root on purpose: a
# workspace is ephemeral and destroyed after each job, while the database is
# long-lived and shared across them (ADR 012). Owned by the runtime user
# because provisioning writes to it as that user, not as root.
RUN mkdir -p /var/cache/grype/db /var/cache/semgrep /var/cache/trivy /var/cache/zap && \
    chown -R nonroot:nonroot /var/cache/grype /var/cache/semgrep /var/cache/trivy /var/cache/zap

# Rule §15.10: containers run as non-root.
USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/worker"]

# =============================================================================
# The scan job (ADR 040)
#
# THIS IS THE LAST STAGE, so a build with no --target produces THIS image, not
# the worker. Both build sites therefore name their target explicitly:
#
#     docker build --target worker  -f deployments/docker/worker.Dockerfile .
#     docker build --target scanjob -f deployments/docker/worker.Dockerfile .
#
# Adding this stage without that change tagged the scan job as the worker, and
# the worker pod crash-looped on "SECUREOPS_JOB_SCAN_ID ... required" -- an
# image that was exactly what was asked for and not what was meant.
# =============================================================================
#
# A build TARGET on top of the worker image, not a second Dockerfile. Every
# scanner above is built from a pinned commit across ~200 lines that must not be
# duplicated: two copies is how "adding a scanner is one entry" quietly becomes
# two, with the missed one showing up as a scan resolving an adapter its pod
# cannot run.
#
#     docker build --target scanjob -f deployments/docker/worker.Dockerfile .
#
# What this stage adds is the DATA. A scan running under ADR 039 has no network
# egress, so grype, semgrep and trivy cannot fetch what they need at run time --
# which is exactly why Phase 12b stopped. Fetching it here, once, at build time,
# is the only moment the network is available to them.
FROM worker AS scanjob

# Whether to include trivy's vulnerability database (~1.3 GB on disk, a 112 MB
# download). Needed only for image targets. A deployment that scans no images
# can set this false and save the space; the default includes it, because an
# adapter that declares KindImage and cannot serve it is worse than a big image.
ARG INCLUDE_IMAGE_DB=true

# The build date, so staleness is visible rather than implied (ADR 040 §5).
# Passed by the build so it reflects when the DATA was fetched, not when the
# base layers were cached.
ARG SCANNER_DATA_BUILT_AT=unknown

# One root step, to own a directory the provisioning below can write to.
# /var/cache is root-owned in the base image and only its subdirectories were
# chowned, so the build-date marker had nowhere to land.
USER root
RUN mkdir -p /var/cache/secureops && chown nonroot:nonroot /var/cache/secureops

USER nonroot:nonroot

# Provisioned as the runtime user, into the directories the adapters already
# read from. Running this as root would produce data the scan pod can read and
# a set of ownerships that differ from every other path in the image.
RUN set -eux; \
    \
    # --- grype: the vulnerability database ---------------------------------
    # Fetched here rather than at startup. `db update` is the only network
    # operation grype performs, and the running pod has no route to perform it.
    GRYPE_DB_CACHE_DIR=/var/cache/grype/db \
    GRYPE_DB_AUTO_UPDATE=true \
    GRYPE_CHECK_FOR_APP_UPDATE=false \
    HOME=/tmp \
      grype db update; \
    test -f /var/cache/grype/db/6/vulnerability.db; \
    \
    # --- semgrep: the rulesets ---------------------------------------------
    # The same seven the adapter provisions by default. Fetched with wget
    # rather than the adapter's own client because this is a build step; the
    # adapter validates them at load time either way.
    mkdir -p /var/cache/semgrep/rules /var/cache/semgrep/home /var/cache/semgrep/tmp; \
    for r in security-audit golang javascript typescript python java dockerfile; do \
      wget -q --header="Accept: application/x-yaml" \
        -O "/var/cache/semgrep/rules/p_$r.yaml" "https://semgrep.dev/c/p/$r"; \
      test -s "/var/cache/semgrep/rules/p_$r.yaml"; \
    done; \
    \
    # --- trivy: the checks bundle, and optionally the vulnerability DB ------
    # The throwaway scan is how trivy is made to fetch its checks bundle; it
    # has no download-only flag for that, unlike the database below.
    mkdir -p /var/cache/trivy/cache /var/cache/trivy/tmp /var/cache/trivy/empty; \
    trivy --cache-dir /var/cache/trivy/cache fs --scanners misconfig \
        --skip-db-update --skip-version-check --format json --quiet \
        /var/cache/trivy/empty > /dev/null; \
    test -d /var/cache/trivy/cache/policy; \
    if [ "${INCLUDE_IMAGE_DB}" = "true" ]; then \
      trivy --cache-dir /var/cache/trivy/cache image --download-db-only \
          --skip-version-check; \
      test -d /var/cache/trivy/cache/db; \
    fi; \
    \
    # The age of this data is a security property, so it is recorded where the
    # running scan can read it rather than inferred from the image tag.
    printf '%s\n' "${SCANNER_DATA_BUILT_AT}" > /var/cache/secureops/scanner-data-built-at

# The data is read-only at run time. The three directories the scanners WRITE to
# are overlaid by the runtime with an emptyDir, which is what keeps the process
# running untrusted binaries unable to modify the data every finding is derived
# from -- a shared writable volume would have permitted exactly that.
#
# Verified before this was written: grype needs no writable directory, trivy
# needs its tmp, and semgrep needs both HOME and TMPDIR. Semgrep's is the one
# that would not have been guessed -- it creates $HOME/.semgrep on every run.
ENV SECUREOPS_SCANNER_DATA_BUILT_AT_FILE=/var/cache/secureops/scanner-data-built-at

ENTRYPOINT ["/usr/local/bin/scanjob"]
