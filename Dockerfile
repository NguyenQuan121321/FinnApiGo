# Multi-stage build for FinnApiGo.
FROM golang:1.25-alpine AS builder
WORKDIR /src

# Cache deps first.
COPY go.mod go.sum* ./
RUN go mod download

COPY . .
# Static-ish build; CGO disabled so the binary runs on the slim final image.
ENV CGO_ENABLED=0 GOOS=linux
RUN go build -ldflags="-s -w" -o /out/finnapigo ./cmd/server

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata && \
    adduser -D -u 10001 app
WORKDIR /app
COPY --from=builder /out/finnapigo /app/finnapigo
USER app
EXPOSE 8080
ENTRYPOINT ["/app/finnapigo"]
