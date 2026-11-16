package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	routingTable = "100"
	routingPrio  = "1000"
)

type ring struct {
	mu  sync.Mutex
	buf []string
	max int
}

func newRing(n int) *ring { return &ring{max: n} }

func (r *ring) add(s string) {
	s = strings.TrimRight(s, "\r\n")
	if strings.TrimSpace(s) == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf = append(r.buf, s)
	if len(r.buf) > r.max {
		r.buf = r.buf[len(r.buf)-r.max:]
	}
}

func (r *ring) Write(p []byte) (int, error) {
	for _, line := range strings.Split(string(p), "\n") {
		r.add(line)
	}
	return len(p), nil
}

func (r *ring) slice() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.buf))
	copy(out, r.buf)
	return out
}

// Core — супервизор Xray и policy-routing внутри netns контейнера.
type Core struct {
	mu      sync.Mutex
	applyMu sync.Mutex
	awgMu   sync.Mutex
	awgDev  *awgDevice
	// probeMu сериализует временные ядра: у них общие файлы конфигов и порты,
	// параллельный запуск ломает проверки.
	probeMu sync.Mutex
	dir     string
	bin     string

	tunName    string
	tunAddr    string
	tunMtu     int
	routeIface string
	proxyPort  int
	setupRoutes bool
	socksOn    bool

	cmd     *exec.Cmd
	done    chan struct{}
	running bool
	started time.Time
	starts  int64
	version string
	gen     int

	lastErr    string
	routingOK  bool
	routingErr string

	// bootText/bootPct — прогресс первичной загрузки ядра из GitHub.
	bootText string
	bootPct  int

	logs *ring
}

func NewCore(dir string) *Core {
	c := &Core{
		dir:         dir,
		bin:         envOr("XRAY_BIN", "xray"),
		tunName:     envOr("TUN_NAME", "tun0"),
		tunAddr:     envOr("TUN_ADDR", "172.19.0.1/30"),
		tunMtu:      envInt("TUN_MTU", 1420),
		routeIface:  strings.TrimSpace(os.Getenv("ROUTE_IFACE")),
		proxyPort:   envInt("PROXY_PORT", 1080),
		setupRoutes: envOr("SETUP_ROUTES", "on") != "off",
		socksOn:     envOr("SOCKS_ENABLED", "on") != "off",
		logs:        newRing(300),
	}
	if custom := filepath.Join(dir, "core", "xray"); fileExists(custom) {
		// После копирования через SFTP/архив файл бывает без +x — ядро не стартует.
		if st, err := os.Stat(custom); err == nil && st.Mode().Perm()&0o111 == 0 {
			_ = os.Chmod(custom, 0o755)
		}
		c.bin = custom
	}
	if out, err := exec.Command(c.bin, "version").Output(); err == nil {
		c.version = firstLine(string(out))
	} else {
		c.lastErr = "xray: " + err.Error()
	}
	return c
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// SetBoot показывает ход первичной установки ядра (пусто — готово).
func (c *Core) SetBoot(text string, pct int) {
	c.mu.Lock()
	c.bootText = text
	c.bootPct = pct
	c.mu.Unlock()
}

// Ready — бинарник ядра на месте и запускается.
func (c *Core) Ready() bool {
	return fileExists(c.binPath())
}

// binPath возвращает путь к текущему бинарнику ядра.
func (c *Core) binPath() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.bin
}

// SetBin переключает ядро на другой бинарник и запоминает его версию.
func (c *Core) SetBin(path string) (string, error) {
	out, err := exec.Command(path, "version").Output()
	if err != nil {
		return "", err
	}
	ver := firstLine(string(out))
	c.mu.Lock()
	c.bin = path
	c.version = ver
	c.mu.Unlock()
	return ver, nil
}

type coreInfo struct {
	Running      bool     `json:"running"`
	PID          int      `json:"pid"`
	Version      string   `json:"version"`
	UptimeSec    int64    `json:"uptime_sec"`
	Starts       int64    `json:"starts"`
	TunUp        bool     `json:"tun_up"`
	Routing      bool     `json:"routing"`
	RoutingErr   string   `json:"routing_error,omitempty"`
	TunName      string   `json:"tun_name"`
	TunAddr      string   `json:"tun_addr"`
	ProxyPort    int      `json:"proxy_port"`
	RouteIface   string   `json:"route_iface,omitempty"`
	Table100     string   `json:"table_100,omitempty"`
	IPForward    string   `json:"ip_forward,omitempty"`
	SocksEnabled bool     `json:"socks_enabled"`
	ContainerIP  string   `json:"container_ip,omitempty"`
	LastError    string   `json:"last_error,omitempty"`
	Boot         string   `json:"boot,omitempty"`
	BootPct      int      `json:"boot_pct,omitempty"`
}

func (c *Core) Info() coreInfo {
	c.mu.Lock()
	info := coreInfo{
		Running:      c.running,
		Version:      c.version,
		Routing:      c.routingOK,
		RoutingErr:   c.routingErr,
		TunName:      c.tunName,
		TunAddr:      c.tunAddr,
		ProxyPort:    c.proxyPort,
		SocksEnabled: c.socksOn,
		LastError:    c.lastErr,
		Boot:         c.bootText,
		BootPct:      c.bootPct,
	}
	if c.running && c.cmd != nil && c.cmd.Process != nil {
		info.PID = c.cmd.Process.Pid
		info.UptimeSec = int64(time.Since(c.started).Seconds())
		info.Starts = c.starts
	}
	if _, err := net.InterfaceByName(c.tunName); err == nil {
		info.TunUp = true
	}
	iface := c.routeIface
	c.mu.Unlock()

	info.RouteIface = iface
	info.Table100 = run("ip", "route", "show", "table", routingTable)
	info.IPForward = readSysFile("/proc/sys/net/ipv4/ip_forward")
	info.ContainerIP = containerIP(iface)
	return info
}

// SetSocksEnabled включает/выключает SOCKS-inbound в конфиге ядра.
func (c *Core) SetSocksEnabled(on bool) {
	c.mu.Lock()
	changed := c.socksOn != on
	c.socksOn = on
	c.mu.Unlock()
	if changed {
		if on {
			c.logs.add("SOCKS-прокси включён")
		} else {
			c.logs.add("SOCKS-прокси выключен (остаётся только маршрутизация)")
		}
	}
}

// socksListen — при включённом SOCKS inbound слушает все интерфейсы (доступен из LAN).
func (c *Core) socksListen() string {
	return "0.0.0.0"
}

// containerIP — адрес контейнера для подсказок в UI (env CONTAINER_IP или первый IPv4).
func containerIP(iface string) string {
	if v := strings.TrimSpace(os.Getenv("CONTAINER_IP")); v != "" {
		return v
	}
	pick := func(name string) string {
		if name == "" {
			return ""
		}
		ifi, err := net.InterfaceByName(name)
		if err != nil {
			return ""
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			return ""
		}
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				if v4 := ipn.IP.To4(); v4 != nil && !v4.IsLoopback() {
					return v4.String()
				}
			}
		}
		return ""
	}
	if ip := pick(iface); ip != "" {
		return ip
	}
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, ifi := range ifaces {
			if ifi.Flags&net.FlagLoopback != 0 || ifi.Flags&net.FlagUp == 0 {
				continue
			}
			if ip := pick(ifi.Name); ip != "" {
				return ip
			}
		}
	}
	return ""
}

func (c *Core) socksEnabled() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.socksOn
}

func readSysFile(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return err.Error()
	}
	return strings.TrimSpace(string(b))
}

func (c *Core) Running() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.running
}

// Apply проверяет конфиг на узле и перезапускает ядро.
func (c *Core) Apply(node *Node) error {
	c.applyMu.Lock()
	defer c.applyMu.Unlock()

	cfg := buildConfig(c, nodeOutbound(node), node != nil && node.AWG != "")
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	bin := c.binPath()
	tmp := filepath.Join(c.dir, "config.new.json")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if out, err := exec.Command(bin, "-test", "-c", tmp).CombinedOutput(); err != nil {
		msg := ellipsis(strings.TrimSpace(string(out)), 600)
		if msg == "" {
			// Пустой вывод = проблема запуска, а не конфига.
			msg = "не удалось запустить ядро: " + err.Error()
		}
		c.mu.Lock()
		c.lastErr = "конфиг отклонён: " + msg
		c.mu.Unlock()
		c.logs.add("xray -test: " + msg)
		return fmt.Errorf("конфиг отклонён: %s", msg)
	}
	if err := os.Rename(tmp, filepath.Join(c.dir, "config.json")); err != nil {
		return err
	}
	c.Stop()
	// AWG-узлу нужен интерфейс до старта ядра: Xray выходит в него freedom'ом.
	c.prepareAWG(node)
	c.mu.Lock()
	c.gen++
	gen := c.gen
	c.lastErr = ""
	c.routingOK = false
	c.routingErr = ""
	c.mu.Unlock()
	c.logs.add("применён узел: " + node.Name)
	if err := c.start(); err != nil {
		return err
	}
	if c.setupRoutes {
		go c.setupRouting(gen)
	}
	return nil
}

func nodeOutbound(node *Node) map[string]any {
	if node != nil && node.ObfsStripped && node.AltOutbound != nil {
		return node.AltOutbound
	}
	if node == nil {
		return nil
	}
	return node.Outbound
}

func buildConfig(c *Core, nodeOut map[string]any, awgTunnel bool) map[string]any {
	// Копия: outbound узла переиспользуется, его тег менять нельзя.
	ob := map[string]any{"tag": "node"}
	if nodeOut == nil {
		ob["protocol"] = "freedom"
	} else {
		for k, v := range nodeOut {
			ob[k] = v
		}
		ob["tag"] = "node"
	}
	tunSettings := map[string]any{
		"name":    c.tunName,
		"mtu":     c.tunMtu,
		"gateway": []string{c.tunAddr},
	}
	// autoOutboundsInterface прибивает outbound к основному интерфейсу.
	// Для AWG это ломает метку (mark) и трафик уходит мимо туннеля.
	if !awgTunnel {
		tunSettings["autoOutboundsInterface"] = "auto"
	}
	inbounds := []any{
		map[string]any{
			"tag":      "tun-in",
			"protocol": "tun",
			"settings": tunSettings,
			"sniffing": map[string]any{"enabled": true, "destOverride": []string{"http", "tls", "quic"}},
		},
	}
	inTags := []string{"tun-in"}
	if c.socksEnabled() {
		inbounds = append(inbounds, map[string]any{
			"tag":      "socks-in",
			"protocol": "socks",
			"listen":   c.socksListen(),
			"port":     c.proxyPort,
			"settings": map[string]any{"udp": true},
		})
		inTags = append(inTags, "socks-in")
	}
	return map[string]any{
		"log":      map[string]any{"loglevel": "warning"},
		"inbounds": inbounds,
		"outbounds": []any{
			ob,
			map[string]any{"tag": "direct", "protocol": "freedom"},
		},
		"routing": map[string]any{
			"domainStrategy": "AsIs",
			"rules": []any{map[string]any{
				"type":        "field",
				"inboundTag":  inTags,
				"outboundTag": "node",
			}},
		},
	}
}

func (c *Core) start() error {
	cfgPath := filepath.Join(c.dir, "config.json")
	cmd := exec.Command(c.binPath(), "-c", cfgPath)
	cmd.Dir = c.dir
	w := io.Writer(c.logs)
	if f, err := os.OpenFile(filepath.Join(c.dir, "xray.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err == nil {
		if fi, err := f.Stat(); err == nil && fi.Size() > 1<<20 {
			_ = f.Truncate(0)
		}
		w = io.MultiWriter(c.logs, f)
	}
	cmd.Stdout = w
	cmd.Stderr = w
	if err := cmd.Start(); err != nil {
		c.mu.Lock()
		c.lastErr = "запуск xray: " + err.Error()
		c.mu.Unlock()
		return err
	}
	done := make(chan struct{})
	c.mu.Lock()
	c.cmd = cmd
	c.done = done
	c.running = true
	c.started = time.Now()
	c.starts++
	c.mu.Unlock()
	go func() {
		err := cmd.Wait()
		close(done)
		c.mu.Lock()
		if c.cmd == cmd {
			c.cmd = nil
			c.running = false
		}
		if err != nil {
			c.lastErr = "xray остановился: " + err.Error()
			c.logs.add("xray остановился: " + err.Error())
		}
		c.mu.Unlock()
	}()
	return nil
}

func (c *Core) Stop() {
	c.mu.Lock()
	c.gen++
	cmd, done := c.cmd, c.done
	c.cmd, c.done = nil, nil
	c.running = false
	c.mu.Unlock()
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(4 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	}
	c.stopAWG()
	// Чтобы трафик, ушедший в контейнер, не крутился по кругу без тоннеля.
	if c.setupRoutes {
		run("ip", "route", "replace", "blackhole", "default", "table", routingTable)
	}
}

// prepareAWG поднимает awg0 под выбранный узел (или гасит, если узел обычный).
func (c *Core) prepareAWG(node *Node) {
	if node == nil || node.AWG == "" {
		c.stopAWG()
		return
	}
	c.awgMu.Lock()
	defer c.awgMu.Unlock()
	if c.awgDev != nil {
		c.awgDev.Stop()
		c.awgDev = nil
	}
	dev, err := startAWGDevice(awgIfName, node.AWG, awgMark, awgTable)
	if err != nil {
		c.mu.Lock()
		c.lastErr = "AWG: " + err.Error()
		c.mu.Unlock()
		c.logs.add("AWG: " + err.Error())
		return
	}
	c.awgDev = dev
	c.logs.add("AWG-туннель поднят: " + node.Name)
}

func (c *Core) stopAWG() {
	c.awgMu.Lock()
	defer c.awgMu.Unlock()
	if c.awgDev != nil {
		c.awgDev.Stop()
		c.awgDev = nil
	}
}

func (c *Core) setupRouting(gen int) {
	up := false
	for i := 0; i < 40; i++ {
		if !c.genOK(gen) {
			return
		}
		if _, err := net.InterfaceByName(c.tunName); err == nil {
			up = true
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if !c.genOK(gen) {
		return
	}
	if !up {
		c.setRouting(gen, false, "интерфейс "+c.tunName+" не появился")
		return
	}

	normalizeRules()
	iface := c.detectRouteIface()

	var errs []string
	if v, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward"); err != nil || strings.TrimSpace(string(v)) != "1" {
		if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0o644); err != nil {
			errs = append(errs, "ip_forward=0 и записать нельзя: "+err.Error())
		}
	}
	_ = os.WriteFile("/proc/sys/net/ipv4/conf/all/rp_filter", []byte("0"), 0o644)
	_ = os.WriteFile("/proc/sys/net/ipv4/conf/"+iface+"/rp_filter", []byte("0"), 0o644)

	if !c.genOK(gen) {
		return
	}
	if out, err := runOut("ip", "rule", "add", "iif", iface, "lookup", routingTable, "priority", routingPrio); err != nil {
		if !strings.Contains(out, "exists") {
			errs = append(errs, "ip rule: "+firstLine(out+err.Error()))
		}
	}
	if out, err := runOut("ip", "route", "replace", "default", "dev", c.tunName, "table", routingTable); err != nil {
		errs = append(errs, "ip route: "+firstLine(out+err.Error()))
	}
	if !c.genOK(gen) {
		return
	}
	if len(errs) > 0 {
		c.setRouting(gen, false, strings.Join(errs, "; "))
		return
	}
	c.setRouting(gen, true, "")
	c.logs.add("маршрутизация готова: iif " + iface + " -> table " + routingTable + " -> " + c.tunName)
}

func (c *Core) genOK(gen int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return gen == c.gen
}

func (c *Core) detectRouteIface() string {
	c.mu.Lock()
	configured := c.routeIface
	c.mu.Unlock()
	if configured != "" {
		return configured
	}
	iface := "eth0"
	if out, err := runOut("ip", "route", "show", "default"); err == nil {
		f := strings.Fields(out)
		for i, w := range f {
			if w == "dev" && i+1 < len(f) {
				iface = f[i+1]
				break
			}
		}
	}
	c.mu.Lock()
	c.routeIface = iface
	c.mu.Unlock()
	c.logs.add("интерфейс для маршрутизации: " + iface)
	return iface
}

// normalizeRules возвращает исторический набор правил: RouterOS 7.22+ ставит
// local/main/default на приоритеты 1/2/3 и ломает policy-routing в контейнере.
func normalizeRules() {
	out, err := runOut("ip", "rule", "show")
	if err != nil {
		return
	}
	byPref := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		i := strings.Index(line, ":")
		if i <= 0 {
			continue
		}
		byPref[strings.TrimSpace(line[:i])] = strings.TrimSpace(line[i+1:])
	}
	if _, ok := byPref["1"]; !ok {
		return
	}
	hasLocal, hasMain := false, false
	for pref, sel := range byPref {
		n, err := strconv.Atoi(pref)
		if err != nil || n > 3 {
			continue
		}
		if strings.Contains(sel, "lookup local") {
			hasLocal = true
		}
		if strings.Contains(sel, "lookup main") {
			hasMain = true
		}
	}
	if !hasLocal && !hasMain {
		return
	}
	run("ip", "rule", "add", "pref", "200", "from", "all", "lookup", "local")
	run("ip", "rule", "add", "pref", "2147483646", "from", "all", "lookup", "main")
	run("ip", "rule", "add", "pref", "2147483647", "from", "all", "lookup", "default")
	for _, p := range []string{"1", "2", "3"} {
		run("ip", "rule", "del", "pref", p)
	}
}

func (c *Core) setRouting(gen int, ok bool, errMsg string) {
	c.mu.Lock()
	if gen != c.gen {
		c.mu.Unlock()
		return
	}
	c.routingOK = ok
	c.routingErr = errMsg
	c.mu.Unlock()
	if !ok {
		c.logs.add("маршрутизация: " + errMsg)
	}
}

func (c *Core) Diag() map[string]any {
	c.mu.Lock()
	iface := c.routeIface
	c.mu.Unlock()
	read := func(p string) string {
		b, err := os.ReadFile(p)
		if err != nil {
			return err.Error()
		}
		return strings.TrimSpace(string(b))
	}
	out := map[string]any{
		"route_iface":   iface,
		"ip_forward":    read("/proc/sys/net/ipv4/ip_forward"),
		"rp_filter_all": read("/proc/sys/net/ipv4/conf/all/rp_filter"),
		"links":         run("ip", "addr"),
		"rules":         run("ip", "rule", "show"),
		"default_route": run("ip", "route", "show", "default"),
		"table_100":     run("ip", "route", "show", "table", routingTable),
		"tun_name":      c.tunName,
		"core_version":  c.version,
		"awg_rule":      run("ip", "rule", "show"),
		"awg_table":     run("ip", "route", "show", "table", strconv.Itoa(awgTable)),
		"awg_link":      run("ip", "link", "show", awgIfName),
		"awg_tx":        readSysFile("/sys/class/net/" + awgIfName + "/statistics/tx_bytes"),
		"awg_rx":        readSysFile("/sys/class/net/" + awgIfName + "/statistics/rx_bytes"),
		"awg_peers":     readSysFile("/proc/net/amneziawg/" + awgIfName),
		"mem_current":   readSysFile("/sys/fs/cgroup/memory.current"),
		"mem_peak":      readSysFile("/sys/fs/cgroup/memory.peak"),
		"mem_max":       readSysFile("/sys/fs/cgroup/memory.max"),
		"procs":         run("ps", "-o", "comm,rss", "-A"),
	}
	if iface != "" {
		out["rp_filter_iface"] = read("/proc/sys/net/ipv4/conf/" + iface + "/rp_filter")
	}
	return out
}

// ProbeNode проверяет узел, поднимая временный Xray с SOCKS-инбаундом (нужно для
// QUIC-узлов: hysteria2 по TCP не проверить). Если с obfs не вышло, пробует без него.
func (c *Core) ProbeNode(ctx context.Context, node *Node) (ok bool, ms int64, errMsg string, usedAlt bool) {
	if node != nil && node.AWG != "" {
		return c.probeAWGNode(ctx, node)
	}
	ok, ms, errMsg = c.probeWithOutbound(ctx, node, nodeOutbound(node))
	if ok || node.AltOutbound == nil || node.ObfsStripped {
		return ok, ms, errMsg, false
	}
	if ok2, ms2, _ := c.probeWithOutbound(ctx, node, node.AltOutbound); ok2 {
		return true, ms2, "", true
	}
	return false, 0, errMsg, false
}

func (c *Core) probeWithOutbound(ctx context.Context, node *Node, ob map[string]any) (bool, int64, string) {
	tag := "probe"
	if node != nil && node.ID != "" {
		tag = "probe-" + node.ID
	}
	res := c.probeThroughOutbound(ctx, ob, []string{""}, tag)
	if res.OK {
		return true, res.MS, ""
	}
	return false, 0, res.Error
}

// probeThroughOutbound — единственный путь проверок через временное ядро:
// поднимает Xray с SOCKS-инбаундом и гоняет запросы к targets по очереди.
func (c *Core) probeThroughOutbound(ctx context.Context, ob map[string]any, targets []string, tag string) probeResult {
	c.probeMu.Lock()
	defer c.probeMu.Unlock()

	// Копия с гарантированным тегом: оригинал принадлежит узлу.
	obCopy := make(map[string]any, len(ob)+1)
	for k, v := range ob {
		obCopy[k] = v
	}
	obCopy["tag"] = "node"
	ob = obCopy

	port := freePort()
	cfg := map[string]any{
		"log": map[string]any{"loglevel": "none"},
		"inbounds": []any{map[string]any{
			"tag":      "probe-in",
			"protocol": "socks",
			"listen":   "127.0.0.1",
			"port":     port,
			"settings": map[string]any{"udp": true},
		}},
		"outbounds": []any{ob},
		"routing": map[string]any{
			"rules": []any{map[string]any{
				"type":        "field",
				"inboundTag":  []string{"probe-in"},
				"outboundTag": stringOf(ob["tag"], "node"),
			}},
		},
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		return probeResult{Error: err.Error()}
	}
	if tag == "" {
		tag = "probe"
	}
	path := filepath.Join(c.dir, tag+".json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return probeResult{Error: err.Error()}
	}
	defer os.Remove(path)
	cmd := exec.Command(c.binPath(), "-c", path)
	if err := cmd.Start(); err != nil {
		return probeResult{Error: "xray: " + err.Error()}
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()
	ready := false
	for i := 0; i < 30; i++ {
		if conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 200*time.Millisecond); err == nil {
			_ = conn.Close()
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		return probeResult{Error: "пробник не поднялся"}
	}

	var last probeResult
	var firstOK *probeResult
	failed := make([]string, 0, len(targets))
	for _, target := range targets {
		if target == "" {
			target = defaultProbeURL
		}
		// свой таймаут: «висящая» цель не должна съедать весь бюджет
		tctx, tcancel := context.WithTimeout(ctx, 10*time.Second)
		res := probeSocks(tctx, port, target, false)
		tcancel()
		if res.OK && res.IP == "" {
			// 200 без IP (html/редирект): добираем через trace.
			tctx2, tcancel2 := context.WithTimeout(ctx, 10*time.Second)
			if trace := probeSocks(tctx2, port, defaultProbeURL, false); trace.OK {
				res.IP, res.CC = trace.IP, trace.CC
			}
			tcancel2()
		}
		if res.OK && res.IP != "" {
			return res
		}
		if res.OK && firstOK == nil {
			r := res
			firstOK = &r
		}
		if res.Error != "" {
			failed = append(failed, shortHost(target)+": "+res.Error)
			last = res
		}
		if ctx.Err() != nil {
			break
		}
	}
	// Узел ответил, но IP из ответа не достали (бывает за DPI) — считаем живым.
	if firstOK != nil {
		return *firstOK
	}
	if len(failed) > 0 {
		last.Error = strings.Join(failed, "; ")
	}
	return last
}

func shortHost(u string) string {
	i := strings.Index(u, "://")
	if i < 0 {
		return u
	}
	h := u[i+3:]
	if j := strings.IndexAny(h, "/?"); j > 0 {
		h = h[:j]
	}
	return h
}

func stringOf(v any, def string) string {
	if s, ok := v.(string); ok && s != "" {
		return s
	}
	return def
}

func freePort() int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 25000 + int(time.Now().UnixNano()%2000)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func run(name string, args ...string) string {
	out, _ := runOut(name, args...)
	return out
}

func runOut(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return ellipsis(s, 200)
}

// LogLines — последние строки журнала ядра. Отдаются отдельным запросом,
// а не в каждом опросе состояния.
func (c *Core) LogLines() []string {
	lines := c.logs.slice()
	if len(lines) > 120 {
		lines = lines[len(lines)-120:]
	}
	return lines
}
