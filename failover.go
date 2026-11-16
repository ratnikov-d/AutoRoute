package main

import (
	"context"
	"log"
	"net/http"
	"strconv"
	"time"
)

// Р ежим failover: закреплённый основной узел + резервы по возрастанию задержки.
// Переключение — только при падении/превышении задержки, возврат — по гистерезису.

const (
	defaultMaxLatencyMS  = 500
	defaultFailThreshold = 2
	minMaxLatencyMS      = 50
	maxMaxLatencyMS      = 10000
	minFailThreshold     = 1
	maxFailThreshold     = 10
	failoverBanSeconds   = 600
	failoverProbeURL     = "https://speed.cloudflare.com/__down?bytes=65536"
	failoverProbeBytes   = 65536
	exitRefreshAfter     = 300 // как часто обновлять выходной IP, сек
)

// nodeMeta — то, что не влезает в Node (Node живёт в parse.go).
type nodeMeta struct {
	Fails         int    `json:"fails,omitempty"`
	Oks           int    `json:"oks,omitempty"`
	RealFails     int    `json:"real_fails,omitempty"`
	ExitIP        string `json:"exit_ip,omitempty"`
	ExitCountry   string `json:"exit_country,omitempty"`
	ExitCheckedAt int64  `json:"exit_checked_at,omitempty"`
	SourceID      string `json:"source_id,omitempty"`
}

// Дельта автопереключения в миллисекундах: насколько лучший узел должен быть
// быстрее текущего, чтобы имело смысл переключаться.
const (
	defaultAutoDeltaMS = 50
	maxAutoDeltaMS     = 5000
)

func clampAutoDeltaMS(v int) int {
	if v < 0 || v > maxAutoDeltaMS {
		return defaultAutoDeltaMS
	}
	return v
}

func clampMaxLatency(ms int) int {
	if ms < minMaxLatencyMS || ms > maxMaxLatencyMS {
		return defaultMaxLatencyMS
	}
	return ms
}

func clampFailThreshold(n int) int {
	if n < minFailThreshold || n > maxFailThreshold {
		return defaultFailThreshold
	}
	return n
}

func (a *App) metaLocked(id string) *nodeMeta {
	if a.state.NodeMeta == nil {
		a.state.NodeMeta = map[string]*nodeMeta{}
	}
	m := a.state.NodeMeta[id]
	if m == nil {
		m = &nodeMeta{}
		a.state.NodeMeta[id] = m
	}
	return m
}

func (a *App) maxLatencyLocked() int {
	if a.state.MaxLatencyMS <= 0 {
		return defaultMaxLatencyMS
	}
	return a.state.MaxLatencyMS
}

func (a *App) failThresholdLocked() int {
	if a.state.FailThreshold <= 0 {
		return defaultFailThreshold
	}
	return a.state.FailThreshold
}

// countersFromAvailabilityLocked обновляет oks/fails у всех узлов, кроме активного:
// для активного источником истины служит реальная проверка передачей.
func (a *App) countersFromAvailabilityLocked(activeID string) {
	for _, n := range a.state.Nodes {
		if n == nil || n.ID == activeID {
			continue
		}
		m := a.metaLocked(n.ID)
		switch n.Status {
		case "ok":
			m.Oks++
			m.Fails = 0
		case "fail":
			m.Fails++
			m.Oks = 0
		}
	}
}

// recordChannelLocked пишет результат реальной проверки активного узла.
func (a *App) recordChannelLocked(id string, res probeResult) bool {
	n := findNode(a.state.Nodes, id)
	if n == nil {
		return false
	}
	ok := res.OK && res.Bytes >= failoverProbeBytes
	m := a.metaLocked(id)
	now := time.Now().Unix()
	n.Checked = now
	if ok {
		m.Oks++
		m.Fails = 0
		n.Status = "ok"
		n.LastErr = ""
		if res.MS > 0 {
			n.Latency = res.MS
		}
		return true
	}
	m.Fails++
	m.Oks = 0
	if res.Error != "" {
		n.LastErr = "канал: " + res.Error
	}
	return false
}

func (a *App) recordExitLocked(id string, res probeResult) {
	if !res.OK || res.IP == "" {
		return
	}
	n := findNode(a.state.Nodes, id)
	if n == nil {
		return
	}
	m := a.metaLocked(id)
	m.ExitIP = res.IP
	m.ExitCountry = normalCountry(res.CC)
	m.ExitCheckedAt = time.Now().Unix()
}

func normalCountry(cc string) string {
	if len(cc) != 2 {
		return ""
	}
	out := make([]byte, 0, 2)
	for i := 0; i < len(cc); i++ {
		c := cc[i]
		if c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		if c < 'A' || c > 'Z' {
			return ""
		}
		out = append(out, c)
	}
	return string(out)
}

func (a *App) exitStaleLocked(id string, now int64) bool {
	m := a.state.NodeMeta[id]
	if m == nil || m.ExitIP == "" {
		return true
	}
	return now-m.ExitCheckedAt >= exitRefreshAfter
}

// pickReserveLocked — резерв с наименьшей задержкой. Узлы с задержкой выше
// максимума берутся только если нормальных нет.
func (a *App) pickReserveLocked(exceptID string) *Node {
	maxLat := a.maxLatencyLocked()
	var below, above *Node
	for _, n := range a.state.Nodes {
		if n == nil || n.ID == exceptID {
			continue
		}
		if n.Status != "ok" || n.Unsupported != "" || nodeMS(n) <= 0 {
			continue
		}
		if a.blacklisted(n.ID) || a.nodeDisabledLocked(n) {
			continue
		}
		ms := nodeMS(n)
		if ms <= 0 {
			continue
		}
		if ms <= int64(maxLat) {
			if below == nil || ms < nodeMS(below) {
				below = n
			}
		} else if above == nil || ms < nodeMS(above) {
			above = n
		}
	}
	if below != nil {
		return below
	}
	return above
}

func (a *App) primaryUsableLocked(p *Node, maxLat int) bool {
	if p == nil || p.Status != "ok" || p.Unsupported != "" || nodeMS(p) <= 0 {
		return false
	}
	if a.blacklisted(p.ID) || a.nodeDisabledLocked(p) {
		return false
	}
	return p.Latency <= int64(maxLat) && a.metaLocked(p.ID).Oks >= 2
}

// sanitizeChain чистит цепочку: только существующие id, без дублей, максимум 3.
func sanitizeChain(ids []string, nodes []*Node) []string {
	out := make([]string, 0, 3)
	seen := map[string]bool{}
	for _, id := range ids {
		if len(out) >= 3 {
			break
		}
		if id == "" || seen[id] || findNode(nodes, id) == nil {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

func (a *App) promoteChainLocked(id string) {
	chain := []string{id}
	for _, x := range a.state.FailoverChain {
		if x != id && len(chain) < 3 {
			chain = append(chain, x)
		}
	}
	a.state.FailoverChain = chain
	a.state.Primary = id
}

// chainTargetLocked выбирает узел по цепочке: первый ok в пределах лимита,
// иначе первый живой из цепочки. nil — если в цепочке нет живых.
func (a *App) chainTargetLocked(except string) *Node {
	maxLat := a.maxLatencyLocked()
	var firstAlive *Node
	for _, id := range a.state.FailoverChain {
		if id == except {
			continue
		}
		n := findNode(a.state.Nodes, id)
		if n == nil || n.Status != "ok" || n.Unsupported != "" {
			continue
		}
		if a.nodeDisabledLocked(n) || a.blacklisted(n.ID) {
			continue
		}
		if firstAlive == nil {
			firstAlive = n
		}
		if nodeMS(n) > 0 && nodeMS(n) <= int64(maxLat) {
			return n
		}
	}
	return firstAlive
}

// nextTargetLocked — куда переключаться: цепочка, а без неё — лучший резерв.
func (a *App) nextTargetLocked(except string) *Node {
	if len(a.state.FailoverChain) > 0 {
		return a.chainTargetLocked(except)
	}
	return a.pickReserveLocked(except)
}

// failoverDecideLocked принимает решение о переключении. true — активный узел
// изменился, нужен apply. Приоритет — failover_chain сверху вниз.
func (a *App) failoverDecideLocked() bool {
	cur := findNode(a.state.Nodes, a.state.Selected)
	maxLat := a.maxLatencyLocked()
	thr := a.failThresholdLocked()

	if cur != nil {
		m := a.metaLocked(cur.ID)
		if m.Fails >= thr {
			cur.Status = "fail"
			cur.Latency = 0
			cur.LastErr = "канал не работает " + strconv.Itoa(m.Fails) + " проверок подряд"
			if a.state.FailUntil == nil {
				a.state.FailUntil = map[string]int64{}
			}
			a.state.FailUntil[cur.ID] = time.Now().Add(failoverBanSeconds * time.Second).Unix()
			m.Fails = 0
			if next := a.nextTargetLocked(cur.ID); next != nil {
				a.state.Selected = next.ID
				if !a.state.ReturnToPrimary {
					a.promoteChainLocked(next.ID)
				}
				return true
			}
			return false
		}
		if cur.Latency > int64(maxLat) {
			if next := a.nextTargetLocked(cur.ID); next != nil && next.ID != cur.ID {
				a.state.Selected = next.ID
				if !a.state.ReturnToPrimary {
					a.promoteChainLocked(next.ID)
				}
				return true
			}
		}
	}

	if !a.state.ReturnToPrimary {
		return false
	}
	primary := findNode(a.state.Nodes, a.state.Primary)
	if primary == nil || (cur != nil && primary.ID == cur.ID) {
		return false
	}
	if a.primaryUsableLocked(primary, maxLat) {
		a.state.Selected = primary.ID
		return true
	}
	return false
}

// handleNodeCheck — POST /api/node/check {id}: лёгкая проверка одного узла.
func (a *App) handleNodeCheck(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID string `json:"id"`
	}
	if !jsonPost(w, r, &body) {
		return
	}
	a.mu.Lock()
	n := findNode(a.state.Nodes, body.ID)
	if n == nil {
		a.mu.Unlock()
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "узел не найден"})
		return
	}
	if n.Unsupported != "" {
		reason := n.Unsupported
		a.mu.Unlock()
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "узел не поддерживается: " + reason})
		return
	}
	cp := *n
	a.mu.Unlock()

	ctx, cancel := context.WithTimeout(r.Context(), 35*time.Second)
	defer cancel()

	// Всегда реальный HTTP через узел: иначе TCP-успех маскирует
	// «узел не пропускает HTTP» и цифра задержки не обновляется.
	ok, ms, errMsg, _ := a.core.ProbeNode(ctx, &cp)
	status := ""

	now := time.Now().Unix()
	a.mu.Lock()
	if cur := findNode(a.state.Nodes, body.ID); cur != nil {
		cur.Checked = now
		if ok {
			cur.Status = "ok"
			cur.Latency = ms
			cur.LastErr = ""
			m := a.metaLocked(cur.ID)
			m.RealFails = 0
			if ms > 0 {
				cur.RealMS = ms
				cur.RealAt = now
			}
		} else {
			cur.Status = "fail"
			cur.Latency = 0
			cur.LastErr = errMsg
			if status != "" {
				cur.Status = status
			}
		}
		a.persistLocked()
	}
	curStatus := ""
	if cur := findNode(a.state.Nodes, body.ID); cur != nil {
		curStatus = cur.Status
	}
	a.mu.Unlock()

	out := map[string]any{"ok": ok, "latency_ms": ms, "status": curStatus, "checked_at": now}
	if errMsg != "" {
		out["error"] = errMsg
	}
	writeJSON(w, http.StatusOK, out)
}

// probeViaTempNode проверяет текущий узел временным ядром (SOCKS поднимается
// только на время запроса); живое ядро и socks_enabled не меняются.
func (a *App) probeViaTempNode(ctx context.Context, target string) probeResult {
	a.mu.Lock()
	id := a.appliedID
	var node *Node
	if id != "" {
		if n := findNode(a.state.Nodes, id); n != nil {
			cp := *n
			node = &cp
		}
	}
	a.mu.Unlock()
	if node == nil {
		return probeResult{Error: "включите SOCKS или повторите позже: ядро ещё не применило узел"}
	}
	return a.probeNodeExitTargets(ctx, node, target)
}

// handleFailoverChain — POST /api/failover/chain {chain:[...]}.
func (a *App) handleFailoverChain(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Chain []string `json:"chain"`
	}
	if !jsonPost(w, r, &body) {
		return
	}
	if len(body.Chain) > 3 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "в цепочке максимум 3 узла"})
		return
	}
	a.mu.Lock()
	seen := map[string]bool{}
	for _, id := range body.Chain {
		if id == "" {
			continue
		}
		if seen[id] {
			a.mu.Unlock()
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "узел указан дважды"})
			return
		}
		seen[id] = true
		if findNode(a.state.Nodes, id) == nil {
			a.mu.Unlock()
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "узел не найден: " + id})
			return
		}
	}
	a.state.FailoverChain = sanitizeChain(body.Chain, a.state.Nodes)
	if len(a.state.FailoverChain) > 0 {
		a.state.Primary = a.state.FailoverChain[0]
	} else {
		a.state.Primary = ""
	}
	switched := false
	if a.state.Mode == "failover" {
		if target := a.nextTargetLocked(""); target != nil && target.ID != a.state.Selected {
			a.state.Selected = target.ID
			switched = true
		}
	}
	a.persistLocked()
	chain := append([]string{}, a.state.FailoverChain...)
	a.mu.Unlock()

	if switched {
		a.requestApply()
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "chain": chain})
}

// failoverTick — часть doCheck для режима failover.
func (a *App) failoverProbe(activeID string) (res probeResult, probed bool) {
	if activeID == "" || !a.core.Running() || !a.socksOn() {
		return probeResult{}, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	res = a.core.probeThroughTunnel(ctx, failoverProbeURL, false)
	return res, true
}

func (a *App) lookupExit() probeResult {
	if !a.core.Running() || !a.socksOn() {
		return probeResult{}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return a.core.probeThroughTunnel(ctx, defaultProbeURL, false)
}

// probeNodeExit поднимает временный Xray с одним узлом и узнаёт выходной IP/страну.
// exitProbeURLs — по порядку: домен (есть SNI, реже режут), IP Cloudflare, ipify.
var exitProbeURLs = []string{
	"https://1.1.1.1/cdn-cgi/trace",
	"https://www.cloudflare.com/cdn-cgi/trace",
	"https://api.ipify.org?format=json",
	// запасные: часть серверов пропускает только обычный HTTP
	"https://ipinfo.io/ip",
	"http://ip-api.com/line/?fields=query,countryCode",
	"http://ifconfig.me/ip",
}

// probeNodeExit пробует несколько адресов: часть серверов режет прямой 1.1.1.1,
// поэтому выходной IP берём с первого ответившего.
func (a *App) probeNodeExit(ctx context.Context, node *Node) probeResult {
	return a.probeNodeExitTargets(ctx, node, "")
}

// probeNodeExitTargets поднимает временный Xray с узлом и одним-двумя запросами:
// сначала по target (объём), затем trace — чтобы заполнить ip/страну.
// probeNodeExitTargets: до двух попыток — временные ядра иногда стартуют
// или отвечают с первого раза не сразу.
func (a *App) probeNodeExitTargets(ctx context.Context, node *Node, target string) probeResult {
	var res probeResult
	for attempt := 0; attempt < 2; attempt++ {
		res = a.probeNodeExitOnce(ctx, node, target)
		if (res.OK && res.IP != "") || ctx.Err() != nil {
			break
		}
	}
	return res
}

func (a *App) probeNodeExitOnce(ctx context.Context, node *Node, target string) probeResult {
	targets := exitProbeURLs
	if target != "" {
		targets = append([]string{target}, exitProbeURLs...)
	}
	// AWG: свой временный туннель, иначе запрос ушёл бы через активный awg0.
	if node != nil && node.AWG != "" {
		dev, err := startAWGDevice(awgProbeIf, node.AWG, awgProbeMark, awgProbeTab)
		if err != nil {
			return probeResult{Error: "AWG: " + err.Error()}
		}
		defer dev.Stop()
		return a.probeWithOutboundTargets(ctx, awgOutbound(awgProbeMark), targets)
	}
	return a.probeWithOutboundTargets(ctx, nodeOutbound(node), targets)
}

// probeWithOutboundTargets — временное ядро с одним outbound'ом и запросом.
func (a *App) probeWithOutboundTargets(ctx context.Context, outbound map[string]any, targets []string) probeResult {
	return a.core.probeThroughOutbound(ctx, outbound, targets, "probe-exit")
}

// handleNodeProbe — POST /api/node/probe {id}: проверка узла временным ядром.
func (a *App) handleNodeProbe(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID string `json:"id"`
	}
	if !jsonPost(w, r, &body) {
		return
	}
	a.mu.Lock()
	node := findNode(a.state.Nodes, body.ID)
	if node == nil {
		a.mu.Unlock()
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "узел не найден"})
		return
	}
	if node.Unsupported != "" {
		reason := node.Unsupported
		a.mu.Unlock()
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "узел не поддерживается: " + reason})
		return
	}
	cp := *node
	applied := a.appliedID
	a.mu.Unlock()

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	ok, ms, errMsg, usedAlt := a.core.ProbeNode(ctx, &cp)
	var exit probeResult
	if ok {
		if cp.ID == applied && a.core.Running() {
			exit = a.lookupExit()
		} else {
			exit = a.probeNodeExit(ctx, &cp)
		}
	}

	now := time.Now().Unix()
	a.mu.Lock()
	n := findNode(a.state.Nodes, body.ID)
	if n != nil {
		n.Checked = now
		m := a.metaLocked(n.ID)
		if ok {
			n.Status = "ok"
			n.LastErr = ""
			if ms > 0 {
				n.Latency = ms
			}
			m.Oks++
			m.Fails = 0
			delete(a.state.FailUntil, n.ID)
		} else {
			n.Status = "fail"
			n.Latency = 0
			n.LastErr = errMsg
			m.Fails++
			m.Oks = 0
		}
		if exit.OK && exit.IP != "" {
			m.ExitIP = exit.IP
			m.ExitCountry = normalCountry(exit.CC)
			m.ExitCheckedAt = now
		}
		a.persistLocked()
	}
	var exitIP, exitCC string
	var exitAt int64
	if m := a.state.NodeMeta[body.ID]; m != nil {
		exitIP, exitCC, exitAt = m.ExitIP, m.ExitCountry, m.ExitCheckedAt
	}
	a.mu.Unlock()

	out := map[string]any{
		"ok":              ok,
		"latency_ms":      ms,
		"used_alt":        usedAlt,
		"exit_ip":         exitIP,
		"exit_country":    exitCC,
		"exit_checked_at": exitAt,
	}
	if errMsg != "" {
		out["error"] = errMsg
	}
	if exit.Error != "" && ok && exitIP == "" {
		out["exit_error"] = exit.Error
	}
	if !ok {
		log.Printf("проверка узла %s: %s", cp.Name, errMsg)
	}
	writeJSON(w, http.StatusOK, out)
}
