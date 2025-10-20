# syntax = docker/dockerfile-upstream:1.19.0-labs

# THIS FILE WAS AUTOMATICALLY GENERATED, PLEASE DO NOT EDIT.
#
# Generated on 2025-10-20T11:05:18Z by kres 46e133d.

ARG TOOLCHAIN

FROM ghcr.io/siderolabs/ca-certificates:v1.11.0 AS image-ca-certificates

FROM ghcr.io/siderolabs/fhs:v1.11.0 AS image-fhs

# runs markdownlint
FROM docker.io/oven/bun:1.3.0-alpine AS lint-markdown
WORKDIR /src
RUN bun i markdownlint-cli@0.45.0 sentences-per-line@0.3.0
COPY .markdownlint.json .
COPY ./README.md ./README.md
RUN bunx markdownlint --ignore "CHANGELOG.md" --ignore "**/node_modules/**" --ignore '**/hack/chglog/**' --rules sentences-per-line .

# base toolchain image
FROM --platform=${BUILDPLATFORM} ${TOOLCHAIN} AS toolchain
RUN apk --update --no-cache add bash build-base curl jq protoc protobuf-dev

# build tools
FROM --platform=${BUILDPLATFORM} toolchain AS tools
ENV GO111MODULE=on
ARG CGO_ENABLED
ENV CGO_ENABLED=${CGO_ENABLED}
ARG GOTOOLCHAIN
ENV GOTOOLCHAIN=${GOTOOLCHAIN}
ARG GOEXPERIMENT
ENV GOEXPERIMENT=${GOEXPERIMENT}
ENV GOPATH=/go
ARG DEEPCOPY_VERSION
RUN --mount=type=cache,target=/root/.cache/go-build,id=go-tools/root/.cache/go-build --mount=type=cache,target=/go/pkg,id=go-tools/go/pkg go install github.com/siderolabs/deep-copy@${DEEPCOPY_VERSION} \
	&& mv /go/bin/deep-copy /bin/deep-copy
ARG GOLANGCILINT_VERSION
RUN --mount=type=cache,target=/root/.cache/go-build,id=go-tools/root/.cache/go-build --mount=type=cache,target=/go/pkg,id=go-tools/go/pkg go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@${GOLANGCILINT_VERSION} \
	&& mv /go/bin/golangci-lint /bin/golangci-lint
RUN --mount=type=cache,target=/root/.cache/go-build,id=go-tools/root/.cache/go-build --mount=type=cache,target=/go/pkg,id=go-tools/go/pkg go install golang.org/x/vuln/cmd/govulncheck@latest \
	&& mv /go/bin/govulncheck /bin/govulncheck
ARG GOFUMPT_VERSION
RUN go install mvdan.cc/gofumpt@${GOFUMPT_VERSION} \
	&& mv /go/bin/gofumpt /bin/gofumpt

# tools and sources
FROM tools AS base
WORKDIR /src
COPY go.mod go.mod
COPY go.sum go.sum
RUN cd .
RUN --mount=type=cache,target=/go/pkg,id=go-tools/go/pkg go mod download
RUN --mount=type=cache,target=/go/pkg,id=go-tools/go/pkg go mod verify
COPY ./cmd ./cmd
COPY ./internal ./internal
COPY ./pkg ./pkg
RUN --mount=type=cache,target=/go/pkg,id=go-tools/go/pkg go list -mod=readonly all >/dev/null

FROM tools AS embed-generate
ARG SHA
ARG TAG
WORKDIR /src
RUN mkdir -p internal/version/data && \
    echo -n ${SHA} > internal/version/data/sha && \
    echo -n ${TAG} > internal/version/data/tag

# runs gofumpt
FROM base AS lint-gofumpt
RUN FILES="$(gofumpt -l .)" && test -z "${FILES}" || (echo -e "Source code is not formatted with 'gofumpt -w .':\n${FILES}"; exit 1)

# runs golangci-lint
FROM base AS lint-golangci-lint
WORKDIR /src
COPY .golangci.yml .
ENV GOGC=50
RUN --mount=type=cache,target=/root/.cache/go-build,id=go-tools/root/.cache/go-build --mount=type=cache,target=/root/.cache/golangci-lint,id=go-tools/root/.cache/golangci-lint,sharing=locked --mount=type=cache,target=/go/pkg,id=go-tools/go/pkg golangci-lint run --config .golangci.yml

# runs golangci-lint fmt
FROM base AS lint-golangci-lint-fmt-run
WORKDIR /src
COPY .golangci.yml .
ENV GOGC=50
RUN --mount=type=cache,target=/root/.cache/go-build,id=go-tools/root/.cache/go-build --mount=type=cache,target=/root/.cache/golangci-lint,id=go-tools/root/.cache/golangci-lint,sharing=locked --mount=type=cache,target=/go/pkg,id=go-tools/go/pkg golangci-lint fmt --config .golangci.yml
RUN --mount=type=cache,target=/root/.cache/go-build,id=go-tools/root/.cache/go-build --mount=type=cache,target=/root/.cache/golangci-lint,id=go-tools/root/.cache/golangci-lint,sharing=locked --mount=type=cache,target=/go/pkg,id=go-tools/go/pkg golangci-lint run --fix --issues-exit-code 0 --config .golangci.yml

# runs govulncheck
FROM base AS lint-govulncheck
WORKDIR /src
COPY --chmod=0755 hack/govulncheck.sh ./hack/govulncheck.sh
RUN --mount=type=cache,target=/root/.cache/go-build,id=go-tools/root/.cache/go-build --mount=type=cache,target=/go/pkg,id=go-tools/go/pkg ./hack/govulncheck.sh ./...

# runs unit-tests with race detector
FROM base AS unit-tests-race
WORKDIR /src
ARG TESTPKGS
RUN --mount=type=cache,target=/root/.cache/go-build,id=go-tools/root/.cache/go-build --mount=type=cache,target=/go/pkg,id=go-tools/go/pkg --mount=type=cache,target=/tmp,id=go-tools/tmp CGO_ENABLED=1 go test -race ${TESTPKGS}

# runs unit-tests
FROM base AS unit-tests-run
WORKDIR /src
ARG TESTPKGS
RUN --mount=type=cache,target=/root/.cache/go-build,id=go-tools/root/.cache/go-build --mount=type=cache,target=/go/pkg,id=go-tools/go/pkg --mount=type=cache,target=/tmp,id=go-tools/tmp go test -covermode=atomic -coverprofile=coverage.txt -coverpkg=${TESTPKGS} ${TESTPKGS}

FROM embed-generate AS embed-abbrev-generate
WORKDIR /src
ARG ABBREV_TAG
RUN echo -n 'undefined' > internal/version/data/sha && \
    echo -n ${ABBREV_TAG} > internal/version/data/tag

# clean golangci-lint fmt output
FROM scratch AS lint-golangci-lint-fmt
COPY --from=lint-golangci-lint-fmt-run /src .

FROM scratch AS unit-tests
COPY --from=unit-tests-run /src/coverage.txt /coverage-unit-tests.txt

# cleaned up specs and compiled versions
FROM scratch AS generate
COPY --from=embed-abbrev-generate /src/internal/version internal/version

# builds image-signer-linux-amd64
FROM base AS image-signer-linux-amd64-build
COPY --from=generate / /
COPY --from=embed-generate / /
WORKDIR /src/cmd/image-signer
ARG GO_BUILDFLAGS
ARG GO_LDFLAGS
ARG VERSION_PKG="internal/version"
ARG SHA
ARG TAG
RUN --mount=type=cache,target=/root/.cache/go-build,id=go-tools/root/.cache/go-build --mount=type=cache,target=/go/pkg,id=go-tools/go/pkg GOARCH=amd64 GOOS=linux go build ${GO_BUILDFLAGS} -ldflags "${GO_LDFLAGS} -X ${VERSION_PKG}.Name=image-signer -X ${VERSION_PKG}.SHA=${SHA} -X ${VERSION_PKG}.Tag=${TAG}" -o /image-signer-linux-amd64

# builds image-signer-linux-arm64
FROM base AS image-signer-linux-arm64-build
COPY --from=generate / /
COPY --from=embed-generate / /
WORKDIR /src/cmd/image-signer
ARG GO_BUILDFLAGS
ARG GO_LDFLAGS
ARG VERSION_PKG="internal/version"
ARG SHA
ARG TAG
RUN --mount=type=cache,target=/root/.cache/go-build,id=go-tools/root/.cache/go-build --mount=type=cache,target=/go/pkg,id=go-tools/go/pkg GOARCH=arm64 GOOS=linux go build ${GO_BUILDFLAGS} -ldflags "${GO_LDFLAGS} -X ${VERSION_PKG}.Name=image-signer -X ${VERSION_PKG}.SHA=${SHA} -X ${VERSION_PKG}.Tag=${TAG}" -o /image-signer-linux-arm64

FROM scratch AS image-signer-linux-amd64
COPY --from=image-signer-linux-amd64-build /image-signer-linux-amd64 /image-signer-linux-amd64

FROM scratch AS image-signer-linux-arm64
COPY --from=image-signer-linux-arm64-build /image-signer-linux-arm64 /image-signer-linux-arm64

FROM image-signer-linux-${TARGETARCH} AS image-signer

FROM scratch AS image-signer-all
COPY --from=image-signer-linux-amd64 / /
COPY --from=image-signer-linux-arm64 / /

FROM scratch AS image-image-signer
ARG TARGETARCH
COPY --from=image-signer image-signer-linux-${TARGETARCH} /image-signer
COPY --from=image-fhs / /
COPY --from=image-ca-certificates / /
LABEL org.opencontainers.image.source=https://github.com/siderolabs/go-tools
ENTRYPOINT ["/image-signer"]

