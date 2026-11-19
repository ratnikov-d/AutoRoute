# syntax=docker/dockerfile:1
# Ядро — официальный Xray-core (XTLS). В отличие от sing-box умеет XHTTP и
# VLESS-шифрование mlkem768x25519plus, в отличие от mihomo — без сторонних образов.
# В образ ядро НЕ входит (экономия ~28 МБ): при первом запуске качается свежий
# релиз XTLS в /data/core/xray — переживает reboot и замену образа, но исчезает
# при удалении контейнера (root-dir стирается).

# --- сам сервис (stdlib, без внешних зависимостей) ---
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
COPY web ./web
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/autoroute .

# --- рантайм: только alpine + busybox ip (iproute2 не нужен) ---
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
COPY --from=build /out/autoroute           /usr/local/bin/autoroute

ENV DATA_DIR=/data \
    LISTEN=:8080 \
    TUN_NAME=tun0 \
    TUN_ADDR=172.19.0.1/30 \
    TUN_MTU=1420 \
    PROXY_PORT=1080 \
    CHECK_INTERVAL=60

VOLUME ["/data"]
EXPOSE 8080 1080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD wget -qO- http://127.0.0.1:8080/healthz >/dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/autoroute"]
