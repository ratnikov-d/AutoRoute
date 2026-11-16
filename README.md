# AutoRoute

Контейнер-шлюз для MikroTik RouterOS: веб-панель + **Xray-core** внутри, который поднимает
TUN и уводит трафик роутера в выбранный VPN.

Загружаешь ссылку `vless://` или URL подписки — AutoRoute сам проверяет серверы, выбирает
лучший по реальной задержке и держит тоннель. Понятный интерфейс на русском, тёмная тема,
всё в одном бинарнике без внешних зависимостей.

```
LAN-клиент ──► RouterOS (mangle → routing-mark)
                  │  next-hop: IP контейнера
                  ▼
   контейнер AutoRoute ──[ip rule iif <iface> → table 100]──► tun0
                                                                │
                                                 Xray ──────────┴──► VPN-сервер
```

## Возможности

| Что | Как работает |
|---|---|
| Протоколы | VLESS (WS, XHTTP, Reality + X25519MLKEM768, шифрование `mlkem…`), Hysteria2 (в т.ч. Salamander obfs, ECH), Trojan, Shadowsocks, VMess, AmneziaWG 2.0 |
| **HWID** | при первом запуске генерируется свой UUID и хранится в `/data/state.json` — у каждого пользователя он разный и не меняется при перезапусках и смене образа. Можно переопределить общий HWID в настройках или свой у источника, есть «не передавать HWID». Подставляется в подписку параметром `hwid` и заголовком `x-hwid` — так панели привязывают ключ к устройству |
| **User-Agent** | у каждого источника: Авто / Hiddify / Happ / v2rayNG / Streisand / Chrome. Панели отдают разный набор серверов разным клиентам — выбор UA открывает полный список (например, 22 сервера вместо 6 «браузерных ключей») |
| Источники | сколько угодно независимых: URL подписки (`kind: url`) или вставленные ссылки (`kind: links`); общий пул с дедупликацией, перетаскивание для порядка групп |
| Проверка | TCP+TLS — доступность узла; **реальная HTTP-задержка** через временное ядро (раз в `latency_every_min`, пачками по 6 узлов). Узел, который пропускает TCP, но не пропускает HTTP, считается нерабочим |
| Режимы | **Авто** (лучший по задержке, с дельтой переключения), **Стабильный** (гистерезис), **Failover** (основной + резервы, порог задержки и падений, возврат на основной), **Ручной** |
| Выходной IP | у активного узла через живой тоннель: `IP · страна · задержка` в полосе состояния |
| Данные источников | лимиты подписки (трафик, срок), автообновление и период в часах, переименование |
| Ядро | Xray ставится при первом запуске в `/data/core/xray`, выбор из 5 последних релизов XTLS, автообновление раз в сутки |
| Доступ | один пользователь, PBKDF2-HMAC-SHA256 (120 000 итераций), cookie на 7 дней, 10 попыток за 5 минут на IP |
| Эксплуатация | логи ядра в UI, перезапуск, `/api/diag`, healthcheck, состояние в `/data/state.json` |

## Быстрый старт (Docker на ПК)

```bash
docker run -d --name autoroute -p 8080:8080 \
  --device /dev/net/tun --cap-add NET_ADMIN \
  -v autoroute:/data ruiiru/autoroute:latest
```

Открыть `http://localhost:8080` — пароля по умолчанию нет: панель сама попросит создать
его при первом запуске (минимум 8 символов, PBKDF2-HMAC-SHA256 в `/data/auth.json`).

Дальше — задать пароль и добавить подписку. Без `/dev/net/tun`
интерфейс и проверки работают, а тоннель — нет (в UI будет предупреждение).

## Установка на RouterOS

Архитектуры: `linux/arm64` (hAP ax2/ax3, RB5009, CCR2004), `linux/arm/v7` (RB4011),
`linux/amd64`. MIPS-платы (hEX, hAP ac²) контейнеры не поддерживают.

Дальше используются условные имена — подставь свои:

| Обозначение | Что это | Пример |
|---|---|---|
| `<BRIDGE>` | отдельный bridge для контейнеров | `containers` |
| `<GATEWAY>` | шлюз этого bridge | `192.168.77.1/24` |
| `<IFACE>` | veth-интерфейс контейнера | `autoroute-net` |
| `<IP>` | адрес контейнера в этом bridge | `192.168.77.2/24` |
| `<ROUTER_IP>` | адрес роутера, по которому открывается панель | `192.168.88.1` |

`<BRIDGE>` **не** добавлять в interface-list `LAN`: иначе mangle пометит и egress
контейнера — получится петля.

### 1. Подготовка

```routeros
/system/device-mode/update container=yes    ; # подтвердить reset-кнопкой
/container/config/set registry-url=https://registry-1.docker.io tmpdir=disk1/tmp
```

`root-dir` держать на USB/SSD (`/file/print` → `usb1`, `disk1`).

### 2. Сеть и veth

```routeros
/interface/bridge/add name=<BRIDGE>
/ip/address/add address=<GATEWAY> interface=<BRIDGE>
/interface/veth/add name=<IFACE> address=<IP> gateway=<GATEWAY>
/interface/bridge/port/add bridge=<BRIDGE> interface=<IFACE>

/ip/firewall/filter/add chain=input action=accept in-interface=<BRIDGE> \
  place-before=[find where comment~"defconf: drop all not coming from LAN"]
```

### 3. Данные и контейнер

Один внешний mount на `/data` — настройки и ядро переживают перезагрузку и замену образа:

```routeros
/file/add name=usb1/docker/autoroute-data type=directory
/container/mounts/add list=autoroute_data src=/usb1/docker/autoroute-data dst=/data

/container/envs/add list=autoroute key=TZ value="Europe/Moscow"
/container/add remote-image=ruiiru/autoroute:latest interface=<IFACE> \
  envlist=autoroute root-dir=usb1/docker/autoroute \
  mountlists=autoroute_data \
  memory-high=200M memory-max=300M \
  start-on-boot=yes logging=yes name=autoroute
/container/start autoroute
```

Пояснения:

* `dns=` указывать не обязательно. Если он не задан (или в `/etc/resolv.conf` пусто),
  контейнер сам прописывает `1.1.1.1`, `9.9.9.9`, `8.8.8.8`. Лучше указать DNS роутера,
  чтобы домены серверов резолвились локально: `dns=<адрес роутера в <BRIDGE>>`.
* При первом старте ядро качается из релизов XTLS в `/data/core/xray` (~33 МБ, 10–30 с).
  Дальше оно берётся с диска; повторно скачивается только при удалении каталога.
* Обновление образа: `/container/check-update` или `stop` + `remove` + `add` с тем же
  `root-dir` и `mountlists` — данные на mount остаются.

### 4. Веб-интерфейс

```routeros
/ip/firewall/nat/add chain=dstnat dst-address=<ROUTER_IP> dst-port=8080 \
  protocol=tcp action=dst-nat to-addresses=<IP> to-ports=8080
```

Открыть `http://<ROUTER_IP>:8080` → задать пароль → «Добавить» подписку → дождаться
зелёных статусов → «Проверить туннель» (должен показать IP VPN-сервера).

### 5. Маршрутизация трафика в VPN

Отдельная таблица `to_autoroute` и метка с тем же именем:

```routeros
/routing/table/add name=to_autoroute fib

/ip/firewall/mangle/add chain=prerouting src-address=<LAN_SUBNET> \
  dst-address-type=local action=accept passthrough=yes
/ip/firewall/mangle/add chain=prerouting src-address=<LAN_SUBNET> \
  dst-address-list=private action=accept passthrough=yes
/ip/firewall/mangle/add chain=prerouting src-address=<LAN_SUBNET> \
  action=mark-routing new-routing-mark=to_autoroute passthrough=no

/ip/route/add dst-address=0.0.0.0/0 gateway=<IP> routing-table=to_autoroute \
  distance=1 check-gateway=ping comment="autoroute"
/ip/route/add dst-address=0.0.0.0/0 blackhole routing-table=to_autoroute \
  distance=10 comment="autoroute killswitch"
```

Обязательные детали:

* `dst-address-list=private` — RFC1918, иначе локальная сеть уйдёт в тоннель.
* FastTrack несовместим с routing-mark:
  `/ip/firewall/filter/set [find where action=fasttrack-connection] connection-mark=no-mark`
* DNS остаётся на роутере (`dst-address-type=local` покрывает запросы к нему).

Точечно — только один сайт через VPN, не трогая остальную маршрутизацию:

```routeros
/ip/firewall/address-list/add list=autoroute_test address=example.com
/ip/firewall/mangle/add chain=prerouting dst-address-list=autoroute_test \
  dst-address-type=!local action=mark-routing new-routing-mark=to_autoroute passthrough=no
```

Проверка: `/ip/route/print detail where routing-table=to_autoroute` — две записи (gateway
и blackhole), `/container/print` — `running`, `/tool/torch interface=<BRIDGE> duration=5` —
трафик идёт.

## Переменные окружения

| Переменная | По умолчанию | Назначение |
|---|---|---|
| `LISTEN` | `:8080` | адрес веб-интерфейса |
| `DATA_DIR` | `/data` | состояние, ядро, логи |
| `CHECK_INTERVAL` | `60` | период TCP-проверки серверов, сек |
| `SUB_REFRESH` | `21600` | автообновление подписок, сек |
| `PROXY_PORT` | `1080` | порт SOCKS/HTTP внутри контейнера; слушает все интерфейсы и без авторизации — закрывать firewall-ом, если LAN не нужен |
| `TUN_NAME` | `tun0` | имя tun |
| `TUN_ADDR` | `172.19.0.1/30` | адрес tun, не пересекать с LAN |
| `TUN_MTU` | `1420` | MTU tun |
| `ROUTE_IFACE` | автоопределение | интерфейс, с которого приходит трафик роутера |
| `SETUP_ROUTES` | `on` | `off` — не трогать `ip rule/route` |
| `SOCKS_ENABLED` | `on` | `off` — не поднимать SOCKS |
| `XRAY_BIN` | `xray` | путь к ядру (переопределяется `/data/core/xray`) |

## Как это устроено

| Файл | Назначение |
|---|---|
| `main.go` | HTTP API, состояние, авто/ручной выбор, цикл проверок, воркер применения |
| `core.go` | конфиг Xray (tun-in + socks-in), супервизор, policy-routing, нормализация `ip rule` |
| `coreversion.go` | релизы XTLS, скачивание и активация версии, стартовая установка ядра |
| `parse.go` | URI → узел и Xray-outbound (vless/xhttp/reality/encryption, hysteria2+ECH, trojan, ss, vmess, `vpn://` AWG) |
| `awg.go` | AmneziaWG через `amneziawg-go`: UAPI, маршрут по метке `fwmark 0x64 → table 101 → awg0` |
| `check.go` | TCP+TLS проверка доступности узлов |
| `latency.go` | HTTP-замер через временные ядра пачками, `real_ms` |
| `sources.go` | источники: подписки и ссылки, HWID, User-Agent, автообновление, лимиты |
| `failover.go` | failover, слоты основной/резерв, пробы узла и туннеля |
| `settings.go` | настройки в `state.json`, представление узла для UI |
| `auth.go` | пароль (PBKDF2), сессии, лимит попыток |
| `web/index.html` | интерфейс целиком (inline CSS/JS, встроен через `go:embed`) |

Поток: источник → `Node` → конфиг Xray (`tun-in`, `socks-in`) → `xray -test` → перезапуск
ядра → `ip rule add iif <iface> lookup 100` + `ip route replace default dev tun0 table 100`.
Смена узла = перезапуск ядра (~1.5 с): API управления у Xray нет.

## API (кратко)

`/api/state`, `/api/sources`, `/api/sources/update|delete|refresh|reorder`,
`/api/mode`, `/api/select`, `/api/check`, `/api/node/toggle|probe|check`,
`/api/settings`, `/api/password`, `/api/probe`, `/api/diag`, `/api/logs`,
`/api/core/versions|version|check|reload`, `/api/failover/chain`,
`/api/restart`, `/api/login`, `/api/setup`, `/api/logout`, `/healthz`.

Все POST требуют `Content-Type: application/json`; до установки пароля все `/api/*`, кроме
`authstate|setup|login`, отвечают `401`.

## Диагностика

| Симптом | Причина / решение |
|---|---|
| «маршруты не настроены» | нет `/dev/net/tun` или прав; смотреть логи ядра в UI |
| Все серверы нерабочие | нет DNS: задать `dns=` в `/container/add` или проверить `1.1.1.1` из контейнера |
| «Проверить туннель» = ошибка | сервер отверг ключ/uuid; проверить ссылку |
| Трафик LAN не идёт в VPN | нет routing-mark / не тот next-hop, включён FastTrack |
| Ядро «Загрузка» дольше минуты | нет доступа к `github.com`; нужен рабочий канал |
| Контейнер `exited with status 1` без логов | кончилось место: удалить старые архивы из `usb1/tmp` |

## Ограничения

* Только IPv4 в тоннеле.
* Один активный узел, без балансировки.
* Авторизация на одного пользователя.
* После `container/remove` каталог `root-dir` стирается, но `/data` на внешнем mount
  остаётся — настройки и ядро на месте.

## Ссылки

* GitHub: <https://github.com/ratnikov-d/AutoRoute>
* Docker Hub: <https://hub.docker.com/r/ruiiru/autoroute>
* Сайт: <https://ruii.ru>
* Почта: <dmitriy@ratnikov.su>

## Лицензия

MIT. Ядро — [Xray-core](https://github.com/XTLS/Xray-core) (MPL-2.0), AmneziaWG —
[amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go).
