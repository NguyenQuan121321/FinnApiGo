# Multi-stage build for FinnApiGo.
FROM golang:1.26.9-alpine AS builder
WORKDIR /src
ENV GOTOOLCHAIN=local

# Cache deps first.
COPY go.mod go.sum* ./
RUN go mod download

COPY . .
# Static-ish build; CGO disabled so the binary runs on the slim final image.
ENV CGO_ENABLED=0 GOOS=linux
RUN go build -ldflags="-s -w" -o /out/finnapigo ./cmd/server
# The deploy-step binary: Render Release Command runs `/app/migrate up` before
# the new release serves traffic (R1 — production never auto-migrates).
RUN go build -ldflags="-s -w" -o /out/migrate ./cmd/migrate
# Fail the build if either artifact was compiled with a different toolchain.
RUN go version -m /out/finnapigo /out/migrate && \
    test "$(go version /out/finnapigo)" = "/out/finnapigo: go1.26.9" && \
    test "$(go version /out/migrate)" = "/out/migrate: go1.26.9"

# Runtime base: alpine with apk upgrade ensures all patched packages are pulled
# so the Trivy container image scan passes with 0 HIGH/CRITICAL CVEs.
FROM alpine:latest
RUN apk add --no-cache ca-certificates tzdata && \
    apk upgrade --no-cache && \
    adduser -D -u 10001 app
WORKDIR /app
COPY --from=builder /out/finnapigo /app/finnapigo
COPY --from=builder /out/migrate /app/migrate
USER app
EXPOSE 8080
ENTRYPOINT ["/app/finnapigo"]
