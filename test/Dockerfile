# Multi-stage: build from source then produce a small runtime image.
FROM golang:1.24-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/holepunch-server ./cmd/server && \
    CGO_ENABLED=0 go build -o /out/holepunch-client ./cmd/client

FROM python:3.12-alpine
RUN apk add --no-cache netcat-openbsd iproute2 iptables bash curl
COPY --from=builder /out/holepunch-server /usr/local/bin/
COPY --from=builder /out/holepunch-client /usr/local/bin/
