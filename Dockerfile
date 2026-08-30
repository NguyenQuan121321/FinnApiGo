# Multi-stage build for FinnApiGo.
# Builder pins an exact supported Go patch release (1.25 is EOL since Go 1.27
# shipped); Dependabot keeps both pins current.
FROM golang:1.26.7-alpine AS builder
WORKDIR /src

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

# Runtime base must stay inside Alpine's support window (3.20 EOL 2026-04).
FROM alpine:3.22
RUN apk add --no-cache ca-certificates tzdata && \
    adduser -D -u 10001 app
WORKDIR /app
COPY --from=builder /out/finnapigo /app/finnapigo
COPY --from=builder /out/migrate /app/migrate
USER app
EXPOSE 8080
ENTRYPOINT ["/app/finnapigo"]
