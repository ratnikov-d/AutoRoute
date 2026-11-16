package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Node — узел из ссылки/подписки + готовый outbound для Xray.
type Node struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Raw      string `json:"raw"`
	Protocol string `json:"protocol"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	SNI      string `json:"sni,omitempty"`
	Security string `json:"security,omitempty"`

	Transport   string `json:"transport,omitempty"`
	Quic        bool   `json:"quic,omitempty"`
	Unsupported string `json:"unsupported,omitempty"`

	Status  string `json:"status"`
	Latency int64  `json:"latency_ms"`
	RealMS  int64  `json:"real_ms,omitempty"` // полное время HTTP через узел
	RealAt  int64  `json:"real_at,omitempty"`
	LastErr string `json:"error,omitempty"`
	Checked int64  `json:"checked_at,omitempty"`

	// Выходной IP узла (кэшируется, см. ExitAt).
	ExitIP string `json:"exit_ip,omitempty"`
	ExitCC string `json:"exit_country,omitempty"`
	ExitAt int64  `json:"exit_checked_at,omitempty"`

	Outbound      map[string]any `json:"outbound,omitempty"`
	AltOutbound   map[string]any `json:"alt_outbound,omitempty"`
	ObfsStripped  bool           `json:"obfs_stripped,omitempty"`

	// AmneziaWG: исходный INI-конфиг из ссылки vpn:// (AWG 1.5 / 2.0).
	AWG string `json:"awg,omitempty"`
}

var supportedSchemes = []string{"vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://", "vpn://", "awg://"}

func isSupportedLink(s string) bool {
	for _, p := range supportedSchemes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func parseLinks(text string) []*Node {
	var nodes []*Node
	seen := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(strings.Trim(line, "\r"))
		if line == "" || !isSupportedLink(line) {
			continue
		}
		n, err := ParseLink(line)
		if err != nil || seen[n.ID] {
			continue
		}
		seen[n.ID] = true
		nodes = append(nodes, n)
	}
	return nodes
}

func ParseLink(raw string) (*Node, error) {
	raw = strings.TrimSpace(raw)
	var (
		n   *Node
		ob  map[string]any
		err error
	)
	switch {
	case strings.HasPrefix(raw, "vless://"):
		n, ob, err = parseVLESS(raw)
	case strings.HasPrefix(raw, "trojan://"):
		n, ob, err = parseTrojan(raw)
	case strings.HasPrefix(raw, "vmess://"):
		n, ob, err = parseVMess(raw)
	case strings.HasPrefix(raw, "ss://"):
		n, ob, err = parseSS(raw)
	case strings.HasPrefix(raw, "hysteria2://"), strings.HasPrefix(raw, "hy2://"):
		n, ob, err = parseHysteria2(raw)
	case strings.HasPrefix(raw, "vpn://"), strings.HasPrefix(raw, "awg://"):
		n, ob, err = parseAmnezia(raw)
	default:
		return nil, errors.New("неизвестный протокол")
	}
	if err != nil {
		return nil, err
	}
	n.Raw = raw
	n.ID = shortHash(raw)
	if n.Status == "" {
		n.Status = "unknown"
	}
	n.Outbound = ob
	return n, nil
}

// --- VLESS ---

func parseVLESS(raw string) (*Node, map[string]any, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, nil, err
	}
	uuid := ""
	if u.User != nil {
		uuid = u.User.Username()
	}
	if uuid == "" {
		return nil, nil, errors.New("нет uuid")
	}
	host := u.Hostname()
	port, err := portOf(u)
	if err != nil {
		return nil, nil, err
	}
	q := u.Query()
	typ := strings.ToLower(orDefault(q.Get("type"), "tcp"))
	sec := strings.ToLower(q.Get("security"))
	sni := firstNonEmpty(q.Get("sni"), q.Get("peer"), q.Get("host"))
	fp := q.Get("fp")
	flow := q.Get("flow")
	enc := orDefault(q.Get("encryption"), "none")
	pbk := strings.ReplaceAll(q.Get("pbk"), " ", "+")
	sid := q.Get("sid")
	spx := q.Get("spx")

	user := map[string]any{"id": uuid, "encryption": enc, "level": 0}
	if flow != "" {
		user["flow"] = flow
	}
	ob := map[string]any{
		"tag":      "node",
		"protocol": "vless",
		"settings": map[string]any{
			"vnext": []any{map[string]any{
				"address": host, "port": port, "users": []any{user},
			}},
		},
	}
	ss := map[string]any{"network": typ}
	switch sec {
	case "tls":
		tls := map[string]any{"serverName": orDefault(sni, host)}
		if truthy(q.Get("allowInsecure")) || truthy(q.Get("insecure")) {
			tls["allowInsecure"] = true
		}
		if fp != "" && fp != "none" {
			tls["fingerprint"] = fp
		}
		if alpn := splitList(q.Get("alpn")); len(alpn) > 0 {
			tls["alpn"] = alpn
		}
		ss["security"] = "tls"
		ss["tlsSettings"] = tls
	case "reality":
		r := map[string]any{
			"serverName":  orDefault(sni, host),
			"publicKey":   pbk,
			"shortId":     sid,
			"fingerprint": orDefault(fp, "chrome"),
		}
		if spx != "" {
			r["spiderX"] = spx
		}
		ss["security"] = "reality"
		ss["realitySettings"] = r
	}
	addTransport(ss, typ, q)
	ob["streamSettings"] = ss

	node := &Node{
		Name:      fragName(u, host, port),
		Protocol:  "vless",
		Host:      host,
		Port:      port,
		SNI:       orDefault(sni, host),
		Security:  sec,
		Transport: typ,
	}
	return node, ob, nil
}

func addTransport(ss map[string]any, typ string, q url.Values) {
	path := orDefault(q.Get("path"), "/")
	host := firstNonEmpty(q.Get("host"), q.Get("Host"))
	switch typ {
	case "ws", "websocket":
		ws := map[string]any{"path": path}
		if host != "" {
			ws["host"] = host
		}
		ss["wsSettings"] = ws
	case "grpc", "gun":
		ss["grpcSettings"] = map[string]any{"serviceName": firstNonEmpty(q.Get("serviceName"), q.Get("servicename"))}
	case "httpupgrade":
		hu := map[string]any{"path": path}
		if host != "" {
			hu["host"] = host
		}
		ss["httpupgradeSettings"] = hu
	case "xhttp", "splithttp":
		x := map[string]any{"path": path}
		if host != "" {
			x["host"] = host
		}
		if mode := q.Get("mode"); mode != "" {
			x["mode"] = mode
		}
		if extra := q.Get("extra"); extra != "" {
			var ex map[string]any
			if json.Unmarshal([]byte(extra), &ex) == nil && len(ex) > 0 {
				x["extra"] = ex
			}
		} else if pad := q.Get("x_padding_bytes"); pad != "" {
			x["extra"] = map[string]any{"xPaddingBytes": pad}
		}
		ss["xhttpSettings"] = x
	case "tcp", "raw":
		if strings.EqualFold(q.Get("headerType"), "http") {
			ss["tcpSettings"] = map[string]any{
				"header": map[string]any{
					"type": "http",
					"request": map[string]any{
						"path":    []string{path},
						"headers": map[string]any{"Host": []string{orDefault(host, path)}},
					},
				},
			}
		}
	}
}

// --- Trojan ---

func parseTrojan(raw string) (*Node, map[string]any, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, nil, err
	}
	pass := ""
	if u.User != nil {
		pass = u.User.Username()
	}
	if pass == "" {
		return nil, nil, errors.New("нет пароля")
	}
	host := u.Hostname()
	port, err := portOf(u)
	if err != nil {
		return nil, nil, err
	}
	q := u.Query()
	typ := strings.ToLower(orDefault(q.Get("type"), "tcp"))
	sni := firstNonEmpty(q.Get("sni"), q.Get("peer"), q.Get("host"))
	ob := map[string]any{
		"tag":      "node",
		"protocol": "trojan",
		"settings": map[string]any{
			"servers": []any{map[string]any{"address": host, "port": port, "password": pass}},
		},
	}
	ss := map[string]any{"network": typ}
	ss["security"] = "tls"
	tls := map[string]any{"serverName": orDefault(sni, host)}
	if fp := q.Get("fp"); fp != "" && fp != "none" {
		tls["fingerprint"] = fp
	}
	ss["tlsSettings"] = tls
	addTransport(ss, typ, q)
	ob["streamSettings"] = ss
	return &Node{Name: fragName(u, host, port), Protocol: "trojan", Host: host, Port: port,
		SNI: orDefault(sni, host), Security: "tls", Transport: typ}, ob, nil
}

// --- VMess ---

type vmessCfg struct {
	PS   string `json:"ps"`
	Add  string `json:"add"`
	Port any    `json:"port"`
	ID   string `json:"id"`
	Aid  any    `json:"aid"`
	Net  string `json:"net"`
	Type string `json:"type"`
	Host string `json:"host"`
	Path string `json:"path"`
	TLS  string `json:"tls"`
	SNI  string `json:"sni"`
}

func parseVMess(raw string) (*Node, map[string]any, error) {
	body := strings.TrimPrefix(raw, "vmess://")
	if i := strings.Index(body, "#"); i >= 0 {
		body = body[:i]
	}
	dec, err := b64dec(body)
	if err != nil {
		return nil, nil, fmt.Errorf("vmess base64: %w", err)
	}
	var c vmessCfg
	if err := json.Unmarshal([]byte(dec), &c); err != nil {
		return nil, nil, fmt.Errorf("vmess json: %w", err)
	}
	if c.Add == "" || c.ID == "" {
		return nil, nil, errors.New("vmess: нет add/id")
	}
	port, err := anyInt(c.Port)
	if err != nil || port <= 0 {
		return nil, nil, errors.New("vmess: нет порта")
	}
	aid, _ := anyInt(c.Aid)
	typ := strings.ToLower(orDefault(c.Net, "tcp"))
	user := map[string]any{"id": c.ID, "security": "auto", "level": 0}
	if aid > 0 {
		user["alterId"] = aid
	}
	ob := map[string]any{
		"tag":      "node",
		"protocol": "vmess",
		"settings": map[string]any{
			"vnext": []any{map[string]any{"address": c.Add, "port": port, "users": []any{user}}},
		},
	}
	ss := map[string]any{"network": typ}
	if strings.EqualFold(c.TLS, "tls") {
		ss["security"] = "tls"
		ss["tlsSettings"] = map[string]any{"serverName": orDefault(c.SNI, orDefault(c.Host, c.Add))}
	}
	q := url.Values{}
	if c.Path != "" {
		q.Set("path", c.Path)
	}
	if c.Host != "" {
		q.Set("host", c.Host)
	}
	if typ == "tcp" && c.Type == "http" {
		q.Set("headerType", "http")
	}
	addTransport(ss, typ, q)
	ob["streamSettings"] = ss
	name := strings.TrimSpace(c.PS)
	if name == "" {
		name = c.Add + ":" + strconv.Itoa(port)
	}
	return &Node{Name: name, Protocol: "vmess", Host: c.Add, Port: port,
		SNI: orDefault(c.SNI, c.Add), Security: strings.ToLower(c.TLS), Transport: typ}, ob, nil
}

// --- Shadowsocks ---

func parseSS(raw string) (*Node, map[string]any, error) {
	body := strings.TrimPrefix(raw, "ss://")
	name := ""
	if i := strings.Index(body, "#"); i >= 0 {
		if v, err := url.PathUnescape(body[i+1:]); err == nil {
			name = v
		} else {
			name = body[i+1:]
		}
		body = body[:i]
	}
	if i := strings.Index(body, "?"); i >= 0 {
		if strings.Contains(body[i+1:], "plugin=") {
			return nil, nil, errors.New("ss с plugin не поддерживается")
		}
		body = body[:i]
	}
	var method, pass, hp string
	if i := strings.LastIndex(body, "@"); i >= 0 {
		cred := body[:i]
		hp = body[i+1:]
		if j := strings.Index(hp, "/"); j >= 0 {
			hp = hp[:j]
		}
		if c, err := b64dec(cred); err == nil {
			cred = c
		}
		m, p, ok := strings.Cut(cred, ":")
		if !ok {
			return nil, nil, errors.New("ss: нет method:password")
		}
		method, pass = m, p
	} else {
		dec, err := b64dec(body)
		if err != nil {
			return nil, nil, fmt.Errorf("ss base64: %w", err)
		}
		cred, rest, ok := strings.Cut(dec, "@")
		if !ok {
			return nil, nil, errors.New("ss: нет @")
		}
		if j := strings.IndexAny(rest, "/?"); j >= 0 {
			rest = rest[:j]
		}
		m, p, ok := strings.Cut(cred, ":")
		if !ok {
			return nil, nil, errors.New("ss: нет method:password")
		}
		method, pass, hp = m, p, rest
	}
	host, portStr, err := net.SplitHostPort(hp)
	if err != nil {
		return nil, nil, fmt.Errorf("ss: адрес: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 {
		return nil, nil, errors.New("ss: плохой порт")
	}
	if name == "" {
		name = host + ":" + portStr
	}
	ob := map[string]any{
		"tag":      "node",
		"protocol": "shadowsocks",
		"settings": map[string]any{
			"servers": []any{map[string]any{"address": host, "port": port, "method": method, "password": pass}},
		},
	}
	return &Node{Name: name, Protocol: "ss", Host: host, Port: port, Security: "none", Transport: "tcp"}, ob, nil
}

// --- AmneziaWG (vpn:// из Amnezia, awg:// как синоним) ---

func parseAmnezia(raw string) (*Node, map[string]any, error) {
	body := raw
	if i := strings.Index(body, "://"); i > 0 {
		body = body[i+3:]
	}
	text, err := decodeAnyB64(body)
	if err != nil {
		return nil, nil, errors.New("vpn://: не base64")
	}
	cfg := string(text)
	host, port := awgEndpoint(cfg)
	if host == "" || port == 0 {
		return nil, nil, errors.New("vpn://: нет Endpoint в конфиге")
	}
	name := awgName(cfg)
	if name == "" {
		name = host + ":" + strconv.Itoa(port)
	}
	n := &Node{
		Protocol: "awg",
		Name:     name,
		Host:     host,
		Port:     port,
		AWG:      cfg,
		Status:   "unknown",
	}
	// Имя: сначала fragment ссылки (если он есть), иначе комментарий из конфига.
	if u, err := url.Parse(raw); err == nil && u.Fragment != "" {
		if frag := fragName(u, host, port); frag != "" {
			n.Name = frag
		}
	}
	return n, awgOutbound(awgMark), nil
}

// awgName берёт имя из комментария внутри конфига: "# 🇱🇹 1. Amnezia".
func awgName(cfg string) string {
	for _, line := range strings.Split(cfg, "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "#") {
			if t := strings.TrimSpace(strings.TrimPrefix(l, "#")); t != "" {
				return t
			}
		}
	}
	return ""
}

// decodeAnyB64 терпит URL-safe алфавит и отсутствие паддинга.
func decodeAnyB64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.NewReplacer("\n", "", "\r", "", " ", "", "\t", "").Replace(s)
	var lastErr error
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding, base64.URLEncoding,
		base64.RawStdEncoding, base64.StdEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil && len(b) > 0 {
			return b, nil
		} else if err != nil {
			lastErr = err
		}
	}
	return nil, lastErr
}

// --- Hysteria2 ---

func parseHysteria2(raw string) (*Node, map[string]any, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, nil, err
	}
	pass := ""
	if u.User != nil {
		pass = u.User.Username()
	}
	if pass == "" {
		return nil, nil, errors.New("hysteria2: нет пароля")
	}
	host := u.Hostname()
	port, err := portOf(u)
	if err != nil {
		return nil, nil, err
	}
	q := u.Query()
	sni := firstNonEmpty(q.Get("sni"), q.Get("peer"), host)
	alpn := splitList(q.Get("alpn"))
	if len(alpn) == 0 {
		alpn = []string{"h3"}
	}
	tls := map[string]any{"serverName": orDefault(sni, host), "alpn": alpn}
	if truthy(q.Get("insecure")) || truthy(q.Get("allowInsecure")) {
		tls["allowInsecure"] = true
	}
	if ech := q.Get("ech"); ech != "" {
		tls["echConfigList"] = ech
	}
	ss := map[string]any{
		"network":          "hysteria",
		"security":         "tls",
		"tlsSettings":      tls,
		"hysteriaSettings": map[string]any{"version": 2, "auth": pass},
	}
	// obfs=salamander (Hysteria2) в Xray делается через finalmask
	if obfs := strings.ToLower(q.Get("obfs")); obfs == "salamander" || obfs == "gecko" {
		obfsPass := firstNonEmpty(q.Get("obfs-password"), q.Get("obfspassword"), q.Get("obfsPassword"))
		settings := map[string]any{"password": obfsPass}
		if obfs == "gecko" {
			if ps := firstNonEmpty(q.Get("obfs-packet-size"), q.Get("packetSize")); ps != "" {
				settings["packetSize"] = ps
			}
			obfs = "salamander"
		}
		ss["finalmask"] = map[string]any{
			"udp": []any{map[string]any{"type": "salamander", "settings": settings}},
		}
	}
	ob := map[string]any{
		"tag":            "node",
		"protocol":       "hysteria",
		"settings":       map[string]any{"version": 2, "address": host, "port": port},
		"streamSettings": ss,
	}
	node := &Node{Name: fragName(u, host, port), Protocol: "hysteria2", Host: host, Port: port,
		SNI: orDefault(sni, host), Security: "tls", Transport: "hysteria2", Quic: true}
	// Некоторые серверы принимают hysteria2 и без obfs: держим запасной вариант без finalmask,
	// приложение переключится на него, если проверка с obfs не проходит.
	if _, ok := ss["finalmask"]; ok {
		alt := map[string]any{}
		for k, v := range ss {
			if k != "finalmask" {
				alt[k] = v
			}
		}
		node.AltOutbound = map[string]any{
			"tag":            "node",
			"protocol":       "hysteria",
			"settings":       map[string]any{"version": 2, "address": host, "port": port},
			"streamSettings": alt,
		}
	}
	return node, ob, nil
}

// --- helpers ---

func portOf(u *url.URL) (int, error) {
	p := u.Port()
	if p == "" {
		switch u.Scheme {
		case "vless", "vmess", "trojan", "hysteria2", "hy2":
			return 443, nil
		case "ss":
			return 8388, nil
		}
		return 0, errors.New("нет порта")
	}
	n, err := strconv.Atoi(p)
	if err != nil || n <= 0 || n > 65535 {
		return 0, errors.New("плохой порт")
	}
	return n, nil
}

func fragName(u *url.URL, host string, port int) string {
	raw := strings.TrimSpace(u.Fragment)
	if raw == "" {
		return host + ":" + strconv.Itoa(port)
	}
	parts := strings.Split(raw, "|")
	kept := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" || isNodeMeta(p) {
			continue
		}
		kept = append(kept, p)
	}
	if len(kept) == 0 {
		return host + ":" + strconv.Itoa(port)
	}
	return strings.Join(kept, " ")
}

// isNodeMeta отсекает служебные хвосты из имени узла, которые панель дописывает
// к названию: «📊4.00TB», «⏳53D», «4.00 TB», «expire 53d».
func isNodeMeta(s string) bool {
	low := strings.ToLower(strings.TrimSpace(s))
	if strings.ContainsAny(low, "📊⏳⌛📈💾") {
		return true
	}
	if strings.Contains(low, "expire") || strings.Contains(low, "traffic") || strings.Contains(low, "осталось") {
		return true
	}
	// «4.00TB», «53D», «4 TB», «53 дн»
	var b strings.Builder
	for _, r := range low {
		if (r >= '0' && r <= '9') || r == '.' || r == ',' || r == ' ' {
			continue
		}
		b.WriteRune(r)
	}
	unit := b.String()
	switch unit {
	case "tb", "gb", "mb", "kb", "b", "d", "day", "days", "д", "дн", "дней", "сут", "суток":
		return true
	}
	return false
}

func shortHash(s string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(s))
	return fmt.Sprintf("%08x", h.Sum32())
}

func b64dec(s string) (string, error) {
	t := strings.NewReplacer("\n", "", "\r", "", " ", "").Replace(strings.TrimSpace(s))
	for _, e := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := e.DecodeString(t); err == nil {
			return string(b), nil
		}
	}
	return "", errors.New("base64")
}

func anyInt(v any) (int, error) {
	switch x := v.(type) {
	case nil:
		return 0, nil
	case float64:
		return int(x), nil
	case string:
		if strings.TrimSpace(x) == "" {
			return 0, nil
		}
		return strconv.Atoi(strings.TrimSpace(x))
	}
	return 0, fmt.Errorf("не число: %v", v)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func truthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}
