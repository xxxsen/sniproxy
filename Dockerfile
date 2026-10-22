FROM golang:1.26.10-alpine@sha256:5cb67f19c5e7994dcb80c074f7cfca8aeeada45bbdca035f73df269cefdcce61

WORKDIR /build
COPY . ./
RUN CGO_ENABLED=0 go build -a -tags netgo -ldflags '-w' -o sniproxy ./cmd

FROM alpine:3.14
COPY --from=0 /build/sniproxy /bin/

ENTRYPOINT [ "/bin/sniproxy" ]
