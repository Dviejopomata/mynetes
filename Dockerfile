FROM golang:1.10.3 as build-env

RUN curl -fsSL -o /usr/bin/dep https://github.com/golang/dep/releases/download/v0.5.0/dep-linux-amd64 && chmod +x /usr/bin/dep

WORKDIR $GOPATH/src/github.com/Dviejopomata/mynetes

COPY main.go config.yml Gopkg.toml Gopkg.lock ./
COPY ./charts ./charts
COPY ./cmd ./cmd
COPY ./config ./config
COPY ./log ./log
COPY ./pkg ./pkg
COPY ./vendor ./vendor
RUN go build -ldflags "-s -w" -o "mynetes" main.go

FROM gcr.io/distroless/base:debug
COPY --from=build-env /go/src/github.com/Dviejopomata/mynetes/mynetes /
COPY --from=build-env /go/src/github.com/Dviejopomata/mynetes/charts /charts
COPY --from=build-env /go/src/github.com/Dviejopomata/mynetes/config.yml /config.yml
ENV GIN_MODE=release
ENTRYPOINT ["/mynetes"]