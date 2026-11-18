package main

// Конфиги Happ/Hiddify: панель отдаёт массив полноценных Xray-конфигов
// (25 штук по 27 outbounds), а не список ссылок. Переводим outbound'ы в
// обычные vless:// и hysteria2:// — дальше их разбирает стандартный парсер.

import (
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
)

type happConfig struct {
	Remarks   string           `json:"remarks"`
	Outbounds []map[string]any `json:"outbounds"`
}

// xrayConfigsToLinks возвращает ссылки, если body — массив Xray-конфигов.
func xrayConfigsToLinks(raw string) string {
	t := strings.TrimSpace(raw)
	if !strings.HasPrefix(t, "[") || !strings.Contains(t, `"outbounds"`) {
		return ""
	}
	var cfgs []happConfig
	if err := json.Unmarshal([]byte(t), &cfgs); err != nil || len(cfgs) == 0 {
		return ""
	}
	var links []string
	seen := map[string]bool{}
	for _, cfg := range cfgs {
		for _, ob := range cfg.Outbounds {
			link := happOutboundLink(ob, cfg.Remarks)
			if link == "" || seen[link] {
				continue
			}
			seen[link] = true
			links = append(links, link)
		}
	}
	return strings.Join(links, "\n")
}

func happMap(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return nil
}

func happStr(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	switch v := m[key].(type) {
	case string:
		return strings.TrimSpace(v)
	case float64:
		return strconv.FormatInt(int64(v), 10)
	case json.Number:
		return v.String()
	}
	return ""
}

func happInt(m map[string]any, key string) int {
	if m == nil {
		return 0
	}
	switch v := m[key].(type) {
	case float64:
		return int(v)
	case json.Number:
		n, _ := v.Int64()
		return int(n)
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(v))
		return n
	}
	return 0
}

func happList(v any) []string {
	var out []string
	switch items := v.(type) {
	case []any:
		for _, x := range items {
			if s, ok := x.(string); ok && s != "" {
				out = append(out, s)
			}
		}
	case string:
		if s := strings.TrimSpace(items); s != "" {
			out = append(out, strings.Split(s, ",")...)
		}
	}
	return out
}

// happOutboundLink превращает один outbound в ссылку, понятную parse.go.
func happOutboundLink(ob map[string]any, remark string) string {
	protocol := strings.ToLower(happStr(ob, "protocol"))
	settings := happMap(ob["settings"])
	stream := happMap(ob["streamSettings"])
	name := strings.TrimSpace(remark)

	switch protocol {
	case "vless":
		vnext, _ := settings["vnext"].([]any)
		if len(vnext) == 0 {
			return ""
		}
		peer := happMap(vnext[0])
		users, _ := peer["users"].([]any)
		if len(users) == 0 {
			return ""
		}
		user := happMap(users[0])
		id := happStr(user, "id")
		host := happStr(peer, "address")
		port := happInt(peer, "port")
		if id == "" || host == "" || port <= 0 {
			return ""
		}
		q := url.Values{}
		q.Set("encryption", orDefault(happStr(user, "encryption"), "none"))
		if f := happStr(user, "flow"); f != "" {
			q.Set("flow", f)
		}
		typ := orDefault(strings.ToLower(happStr(stream, "network")), "tcp")
		q.Set("type", typ)
		tls := happMap(stream["tlsSettings"])
		reality := happMap(stream["realitySettings"])
		sni := firstNonEmpty(happStr(tls, "serverName"), happStr(reality, "serverName"), host)
		switch strings.ToLower(happStr(stream, "security")) {
		case "tls":
			q.Set("security", "tls")
			q.Set("sni", sni)
			if fp := happStr(tls, "fingerprint"); fp != "" {
				q.Set("fp", fp)
			}
			if alpn := happList(tls["alpn"]); len(alpn) > 0 {
				q.Set("alpn", strings.Join(alpn, ","))
			}
		case "reality":
			q.Set("security", "reality")
			q.Set("sni", sni)
			q.Set("pbk", happStr(reality, "publicKey"))
			if sid := happStr(reality, "shortId"); sid != "" {
				q.Set("sid", sid)
			}
			if spx := happStr(reality, "spiderX"); spx != "" {
				q.Set("spx", spx)
			}
			if fp := happStr(reality, "fingerprint"); fp != "" {
				q.Set("fp", fp)
			}
		}
		switch typ {
		case "ws", "websocket":
			ws := happMap(stream["wsSettings"])
			if p := happStr(ws, "path"); p != "" {
				q.Set("path", p)
			}
			if h := happStr(ws, "host"); h != "" {
				q.Set("host", h)
			}
		case "xhttp", "splithttp":
			x := happMap(stream["xhttpSettings"])
			if p := happStr(x, "path"); p != "" {
				q.Set("path", p)
			}
			if h := happStr(x, "host"); h != "" {
				q.Set("host", h)
			}
			if mode := happStr(x, "mode"); mode != "" {
				q.Set("mode", mode)
			}
			if extra := x["extra"]; extra != nil {
				if b, err := json.Marshal(extra); err == nil {
					q.Set("extra", string(b))
				}
			}
		case "grpc", "gun":
			g := happMap(stream["grpcSettings"])
			if s := happStr(g, "serviceName"); s != "" {
				q.Set("serviceName", s)
			}
		}
		return "vless://" + id + "@" + host + ":" + strconv.Itoa(port) + "?" + q.Encode() + "#" + url.QueryEscape(name)

	case "hysteria":
		host := happStr(settings, "address")
		port := happInt(settings, "port")
		hy := happMap(stream["hysteriaSettings"])
		auth := happStr(hy, "auth")
		if auth == "" {
			if v := settings["auth"]; v != nil {
				auth = happStr(map[string]any{"auth": v}, "auth")
			}
		}
		if host == "" || port <= 0 || auth == "" {
			return ""
		}
		q := url.Values{}
		tls := happMap(stream["tlsSettings"])
		q.Set("sni", firstNonEmpty(happStr(tls, "serverName"), host))
		if alpn := happList(tls["alpn"]); len(alpn) > 0 {
			q.Set("alpn", strings.Join(alpn, ","))
		}
		return "hysteria2://" + url.User(auth).String() + "@" + host + ":" + strconv.Itoa(port) + "?" + q.Encode() + "#" + url.QueryEscape(name)
	}
	return ""
}
