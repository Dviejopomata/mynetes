FROM golang:1.10.3 as build-env

RUN curl -fsSL -o /usr/bin/dep https://github.com/golang/dep/releases/download/v0.5.0/dep-linux-amd64 && chmod +x /usr/bin/dep

WORKDIR /go/src/gitlab.nextagilesoft.com/saas2/core

COPY Gopkg.toml Gopkg.lock ./
COPY main.go ./
COPY cmd ./cmd
COPY pkg ./pkg
COPY log ./log
COPY vendor ./vendor
COPY config ./config
COPY scripts/crossbinary ./scripts/crossbinary
RUN bash scripts/crossbinary

FROM gcr.io/distroless/base
COPY --from=build-env /go/src/gitlab.nextagilesoft.com/saas2/core/dist /dist
CMD ["/dist/na-cli_linux-amd64"]
