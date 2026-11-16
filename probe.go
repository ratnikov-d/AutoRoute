package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// defaultProbeURL — эндпоинт, который отдаёт внешний IP и страну.
// Cloudflare trace: anycast, без лимитов на частоту (в отличие от ifconfig.me/ipify),
// формат: строки key=value, нам нужны ip= и loc=.
const defaultProbeURL = "https://1.1.1.1/cdn-cgi/trace"

type probeResult struct {
	OK     bool   `json:"ok"`
	IP     string `json:"ip,omitempty"`
	CC     string `json:"country,omitempty"`
	MS     int64  `json:"latency_ms"`
	Bytes  int64  `json:"bytes,omitempty"`
	Status int    `json:"http_status,omitempty"`
	Error  string `json:"error,omitempty"`
}

// probeThroughTunnel проверяет не «жив ли сервер», а «идёт ли трафик через тоннель»:
// запрос через локальный SOCKS-порт sing-box/xray.
func (c *Core) probeThroughTunnel(ctx context.Context, target string, insecure bool) probeResult {
	return probeSocks(ctx, c.proxyPort, target, insecure)
}

// probeSocks — HTTP-запрос через SOCKS5 на указанном порту.
func probeSocks(ctx context.Context, port int, target string, insecure bool) probeResult {
	if target == "" {
		target = defaultProbeURL
	}
	pu, err := url.Parse("socks5://127.0.0.1:" + strconv.Itoa(port))
	if err != nil {
		return probeResult{Error: err.Error()}
	}
	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			Proxy:               http.ProxyURL(pu),
			DisableKeepAlives:   true,
			ForceAttemptHTTP2:   false,
			TLSHandshakeTimeout: 10 * time.Second,
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: insecure},
		},
	}
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return probeResult{Error: err.Error()}
	}
	req.Header.Set("User-Agent", "curl/8.0")
	resp, err := client.Do(req)
	if err != nil {
		return probeResult{Error: shortErr(err)}
	}
	defer resp.Body.Close()
	// Если в URL запрошено N байт, читаем не меньше — иначе проверка передачей
	// «оборвано» на лимите 8 КиБ.
	limit := int64(8192)
	if want := expectedBytes(target); want > 0 {
		limit = want + 1024
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return probeResult{Error: shortErr(err)}
	}
	ms := time.Since(start).Milliseconds()
	if resp.StatusCode >= 500 {
		return probeResult{MS: ms, Status: resp.StatusCode, Error: fmt.Sprintf("HTTP %d через тоннель", resp.StatusCode)}
	}
	ip, cc := parseTrace(body)
	if ip == "" {
		ip = ipFromBody(body)
	}
	// Проверка реальной передачей: если в URL просили N байт, ответ должен быть не меньше.
	if want := expectedBytes(target); want > 0 && int64(len(body)) < want {
		return probeResult{MS: ms, Bytes: int64(len(body)), Status: resp.StatusCode,
			Error: fmt.Sprintf("оборвано: получено %d из %d байт", len(body), want)}
	}
	return probeResult{OK: true, IP: ip, CC: cc, MS: ms, Bytes: int64(len(body)), Status: resp.StatusCode}
}

// parseTrace разбирает ответ Cloudflare trace: "ip=1.2.3.4\nloc=DE\n...".
func parseTrace(b []byte) (string, string) {
	var ip, cc string
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "ip="); ok && ip == "" {
			ip = strings.TrimSpace(v)
		}
		if v, ok := strings.CutPrefix(line, "loc="); ok && cc == "" {
			cc = strings.TrimSpace(v)
		}
	}
	return ip, cc
}

func expectedBytes(target string) int64 {
	if i := strings.Index(target, "bytes="); i >= 0 {
		if n, err := strconv.ParseInt(target[i+6:], 10, 64); err == nil && n > 0 {
			return n
		}
	}
	return 0
}

// ipFromBody вытаскивает IP из ответа ifconfig.me / 2ip.io / ipify (текст или JSON).
var reIPv4 = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)

func ipFromBody(b []byte) string {
	s := strings.TrimSpace(string(b))
	if net.ParseIP(s) != nil {
		return s
	}
	// ifconfig.me с браузерным UA отдаёт HTML — ищем первый валидный IP.
	for _, f := range strings.Fields(strings.NewReplacer("<", " ", ">", " ", "\"", " ", ",", " ").Replace(s)) {
		if net.ParseIP(f) != nil {
			return f
		}
	}
	// общий случай: IPv4 где угодно в тексте (html, json, «Ваш IP: …»)
	if m := reIPv4.FindString(s); m != "" {
		return m
	}
	var parsed struct {
		IP      string `json:"ip"`
		Address string `json:"yourFuckingIPAddress"`
	}
	if err := json.Unmarshal(b, &parsed); err == nil {
		if ip := orDefault(parsed.IP, parsed.Address); ip != "" {
			return ip
		}
	}
	return ""
}
