package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// AmneziaWG (AWG) в этом контейнере: userspace-демон amneziawg-go создаёт
// интерфейс (awg0), а Xray выходит в него outbound'ом freedom с sockopt.interface.
// Так сохраняются TUN, SOCKS и все проверки. Поддерживаются параметры AWG 2.0
// (i1..i5, header_protection_key, content_padding_addition, timings, trailers).

const (
	awgIfName     = "awg0"
	awgProbeIf    = "awgp0"
	awgBinEnv     = "AWG_BIN"
	awgDefaultMTU = 1420

	// Трафик в AWG заворачивается по метке: Xray ставит SO_MARK на сокет
	// (sockopt.mark), правило отправляет такие пакеты в свою таблицу,
	// а таблица — в TUN-интерфейс amneziawg. Так не зависим от SO_BINDTODEVICE.
	awgMark      = 100
	awgTable     = 101
	awgProbeMark = 110
	awgProbeTab  = 111
)

type awgDevice struct {
	name  string
	cmd   *exec.Cmd
	mark  int
	table int
}

func awgBin() string {
	if p := strings.TrimSpace(os.Getenv(awgBinEnv)); p != "" {
		return p
	}
	for _, p := range []string{"/usr/local/bin/amneziawg-go", "/usr/bin/amneziawg-go"} {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	if p, err := exec.LookPath("amneziawg-go"); err == nil {
		return p
	}
	return ""
}

// awgOutbound — freedom с меткой: дальше маршрут уводит в AWG-интерфейс.
func awgOutbound(mark int) map[string]any {
	return map[string]any{
		"tag":      "node",
		"protocol": "freedom",
		"settings": map[string]any{"domainStrategy": "UseIP"},
		"streamSettings": map[string]any{
			"sockopt": map[string]any{"mark": mark},
		},
	}
}

// awgRoute включает маршрут «метка → таблица → интерфейс».
func awgRoute(name string, mark, table int) {
	_ = run("ip", "rule", "del", "fwmark", strconv.Itoa(mark), "lookup", strconv.Itoa(table))
	_ = run("ip", "rule", "add", "fwmark", strconv.Itoa(mark), "lookup", strconv.Itoa(table),
		"priority", strconv.Itoa(400+mark))
	_ = run("ip", "route", "replace", "default", "dev", name, "table", strconv.Itoa(table))
}

func awgRouteOff(mark, table int) {
	_ = run("ip", "rule", "del", "fwmark", strconv.Itoa(mark), "lookup", strconv.Itoa(table))
	_ = run("ip", "route", "flush", "table", strconv.Itoa(table))
}

// startAWGDevice поднимает amneziawg-go и применяет конфиг через UAPI.
func startAWGDevice(name, rawCfg string, mark, table int) (*awgDevice, error) {
	bin := awgBin()
	if bin == "" {
		return nil, errors.New("amneziawg-go не установлен в образе")
	}
	if st, err := os.Stat("/dev/net/tun"); err != nil || st.Mode()&os.ModeDevice == 0 {
		return nil, errors.New("нет /dev/net/tun (нужен --device /dev/net/tun)")
	}
	uapi, err := awgUAPIConfig(rawCfg)
	if err != nil {
		return nil, err
	}
	// остатки прошлого запуска
	_ = run("ip", "link", "del", name)

	cmd := exec.Command(bin, "-f", name)
	cmd.Env = append(os.Environ(), "LOG_LEVEL=error", "WG_PROCESS_FOREGROUND=1")
	logFile := filepath.Join(os.TempDir(), name+".log")
	if f, err := os.Create(logFile); err == nil {
		cmd.Stdout = f
		cmd.Stderr = f
		defer f.Close()
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("amneziawg-go: %w", err)
	}
	dev := &awgDevice{name: name, cmd: cmd}

	if err := awgApplyUAPI(name, uapi); err != nil {
		dev.Stop()
		var tail string
		if b, e := os.ReadFile(logFile); e == nil {
			tail = strings.TrimSpace(string(b))
			if len(tail) > 300 {
				tail = tail[len(tail)-300:]
			}
		}
		return nil, fmt.Errorf("настройка AWG: %w %s", err, tail)
	}

	ini, _ := parseINI(rawCfg)
	iface := ini["Interface"]
	if addr := strings.TrimSpace(iface["Address"]); addr != "" {
		_ = run("ip", "addr", "add", addr, "dev", name)
	}
	mtu := awgDefaultMTU
	if v, err := strconv.Atoi(strings.TrimSpace(iface["MTU"])); err == nil && v > 0 {
		mtu = v
	}
	if out := run("ip", "link", "set", "dev", name, "mtu", strconv.Itoa(mtu), "up"); out != "" {
		dev.Stop()
		return nil, fmt.Errorf("ip link up %s: %s", name, out)
	}
	awgRoute(name, mark, table)
	dev.mark, dev.table = mark, table
	return dev, nil
}

func (d *awgDevice) Stop() {
	if d == nil {
		return
	}
	if d.mark != 0 {
		awgRouteOff(d.mark, d.table)
	}
	if d.cmd != nil && d.cmd.Process != nil {
		_ = d.cmd.Process.Kill()
		_, _ = d.cmd.Process.Wait()
	}
	_ = run("ip", "link", "del", d.name)
}

// awgApplyUAPI отправляет конфиг в unix-сокет демона.
func awgApplyUAPI(name, conf string) error {
	paths := []string{
		"/var/run/amneziawg/" + name + ".sock",
		"/var/run/wireguard/" + name + ".sock",
		"/run/amneziawg/" + name + ".sock",
	}
	var lastErr error
	for i := 0; i < 40; i++ {
		for _, p := range paths {
			conn, err := net.Dial("unix", p)
			if err != nil {
				lastErr = err
				continue
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(6 * time.Second))
			if _, err := conn.Write([]byte("set=1\n" + conf + "\n")); err != nil {
				return err
			}
			buf := make([]byte, 4096)
			n, err := conn.Read(buf)
			if err != nil {
				return err
			}
			resp := string(buf[:n])
			if strings.Contains(resp, "errno=0") {
				return nil
			}
			return fmt.Errorf("UAPI: %s", strings.TrimSpace(resp))
		}
		time.Sleep(80 * time.Millisecond)
	}
	if lastErr == nil {
		lastErr = errors.New("сокет UAPI не появился")
	}
	return lastErr
}

// awgUAPIConfig превращает INI из ссылки vpn:// в текст для UAPI.
func awgUAPIConfig(raw string) (string, error) {
	ini, err := parseINI(raw)
	if err != nil {
		return "", err
	}
	iface, peer := ini["Interface"], ini["Peer"]
	priv := strings.TrimSpace(iface["PrivateKey"])
	pub := strings.TrimSpace(peer["PublicKey"])
	endpoint := strings.TrimSpace(peer["Endpoint"])
	if priv == "" || pub == "" || endpoint == "" {
		return "", errors.New("в конфиге AWG нет PrivateKey / PublicKey / Endpoint")
	}
	var b strings.Builder
	line := func(k, v string) {
		if strings.TrimSpace(v) == "" {
			return
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(strings.TrimSpace(v))
		b.WriteByte('\n')
	}
	keyLine := func(k, v string) {
		if h, ok := b64KeyToHex(v); ok {
			line(k, h)
		}
	}

	keyLine("private_key", priv)
	if lp := strings.TrimSpace(iface["ListenPort"]); lp != "" && lp != "0" {
		line("listen_port", lp)
	}
	// параметры обфускации: только те, что есть в конфиге (1.5 и 2.0)
	for _, k := range []string{"Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4"} {
		line(strings.ToLower(k), iface[k])
	}
	for _, k := range []string{"H1", "H2", "H3", "H4"} {
		line(strings.ToLower(k), iface[k])
	}
	for _, k := range []string{"I1", "I2", "I3", "I4", "I5"} {
		line(strings.ToLower(k), iface[k])
	}
	keyLine("header_protection_key", iface["HeaderProtectionKey"])
	for _, k := range [][2]string{
		{"ContentPaddingAddition", "content_padding_addition"},
		{"RekeyAfterTime", "rekey_after_time"},
		{"RekeyTimeout", "rekey_timeout"},
		{"RejectAfterTime", "reject_after_time"},
		{"KeepaliveTimeout", "keepalive_timeout"},
		{"MaxHandshakeAttempts", "max_handshake_attempts"},
	} {
		line(k[1], iface[k[0]])
	}
	if v, ok := onOff(iface["RandomTrailers"]); ok {
		line("random_trailers", v)
	}
	if v, ok := onOff(iface["DisableCookies"]); ok {
		line("disable_cookies", v)
	}

	keyLine("public_key", pub)
	keyLine("preshared_key", peer["PresharedKey"])
	for _, a := range strings.Split(peer["AllowedIPs"], ",") {
		line("allowed_ip", a)
	}
	// UAPI принимает только IP:port — имя резолвим сами.
	epHost, epPort, epErr := splitHostPortLoose(endpoint)
	if epErr != nil {
		return "", fmt.Errorf("Endpoint: %w", epErr)
	}
	if net.ParseIP(epHost) == nil {
		ips, err := net.LookupHost(epHost)
		if err != nil || len(ips) == 0 {
			return "", fmt.Errorf("Endpoint: не удалось разрешить %s", epHost)
		}
		picked := ips[0]
		for _, ip := range ips {
			if v4 := net.ParseIP(ip); v4 != nil && v4.To4() != nil {
				picked = ip
				break
			}
		}
		epHost = picked
	}
	line("endpoint", net.JoinHostPort(epHost, strconv.Itoa(epPort)))
	if ka := strings.TrimSpace(peer["PersistentKeepalive"]); ka != "" {
		line("persistent_keepalive_interval", ka)
	}
	return b.String(), nil
}

func onOff(v string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "on", "true", "yes", "1":
		return "true", true
	case "off", "false", "no", "0":
		return "false", true
	}
	return "", false
}

// b64KeyToHex переводит ключ WireGuard (base64, 32 байта) в hex для UAPI.
func b64KeyToHex(v string) (string, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", false
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(v); err == nil && len(b) == 32 {
			return hex.EncodeToString(b), true
		}
	}
	return "", false
}

// parseINI — минимальный разбор INI: секции и пары ключ-значение.
func parseINI(text string) (map[string]map[string]string, error) {
	out := map[string]map[string]string{}
	var cur map[string]string
	for _, raw := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			name := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]"))
			cur = map[string]string{}
			out[name] = cur
			continue
		}
		if cur == nil {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		cur[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	if len(out) == 0 {
		return nil, errors.New("не INI-конфиг AWG")
	}
	return out, nil
}

// awgEndpoint достаёт host:port и имя из конфига.
func awgEndpoint(raw string) (host string, port int) {
	ini, err := parseINI(raw)
	if err != nil {
		return "", 0
	}
	ep := strings.TrimSpace(ini["Peer"]["Endpoint"])
	if h, p, err := splitHostPortLoose(ep); err == nil {
		return h, p
	}
	return "", 0
}

func splitHostPortLoose(s string) (string, int, error) {
	i := strings.LastIndex(s, ":")
	if i <= 0 {
		return "", 0, errors.New("нет порта")
	}
	p, err := strconv.Atoi(strings.Trim(s[i+1:], "[]"))
	if err != nil {
		return "", 0, err
	}
	return strings.Trim(s[:i], "[]"), p, nil
}

// probeAWGNode — проверка AWG-узла: временный туннель + временное ядро.
func (c *Core) probeAWGNode(ctx context.Context, node *Node) (bool, int64, string, bool) {
	dev, err := startAWGDevice(awgProbeIf, node.AWG, awgProbeMark, awgProbeTab)
	if err != nil {
		return false, 0, err.Error(), false
	}
	defer dev.Stop()
	ok, ms, errMsg := c.probeWithOutbound(ctx, node, awgOutbound(awgProbeMark))
	return ok, ms, errMsg, false
}
