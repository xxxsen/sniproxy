FROM golang:1.22

WORKDIR /build
COPY . ./
RUN CGO_ENABLED=0 go build -a -tags netgo -ldflags '-w' -o sniproxy ./cmd

FROM alpine:3.12
COPY --from=0 /build/sniproxy /bin/

ENTRYPOINT [ "/bin/sniproxy" ]