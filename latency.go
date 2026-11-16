package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Реальная задержка: полное время HTTP-ответа через узел, а не только TCP/TLS.
// Одно временное ядро на всю пачку узлов — у каждого узла свой SOCKS-инбаунд,
// поэтому запуск стоит ~1.5 с на все узлы, а не на каждый.

const defaultLatencyURL = "https://www.gstatic.com/generate_204"

const (
	latencyProbeWorkers = 2
	latencyFresh        = 20 * time.Minute
	defaultLatencyMin   = 5 // как часто мерить HTTP-задержку, если не задано
	minLatencyMin       = 1
	maxLatencyMin       = 60
)

// clampLatencyMin — период замера задержки в минутах (1..60).
func clampLatencyMin(v int) int {
	if v < minLatencyMin || v > maxLatencyMin {
		return defaultLatencyMin
	}
	return v
}

type latencyPort struct {
	id   string
	port int
}

// reservePorts выдаёт n заведомо разных свободных портов: держим слушатели
// открытыми, пока не соберём все (freePort по одному может выдать дубли).
func reservePorts(n int) []int {
	ports := make([]int, 0, n)
	listeners := make([]net.Listener, 0, n)
	for i := 0; i < n; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			break
		}
		listeners = append(listeners, l)
		ports = append(ports, l.Addr().(*net.TCPAddr).Port)
	}
	for _, l := range listeners {
		_ = l.Close()
	}
	if len(ports) == 0 {
		ports = append(ports, freePort())
	}
	return ports
}

func latencyURL(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return defaultLatencyURL
	}
	return s
}

// freshReal — свежая реальная HTTP-задержка (0, если её нет).
func freshReal(n *Node) int64 {
	if n != nil && n.RealMS > 0 && n.RealAt > 0 && time.Since(time.Unix(n.RealAt, 0)) < latencyFresh {
		return n.RealMS
	}
	return 0
}

// nodeMS — задержка узла: только реальная HTTP. TCP (TLS-хендшейк) — это
// проверка живости, а не задержка: показывать и сравнивать её нельзя.
func nodeMS(n *Node) int64 {
	return freshReal(n)
}

// probeHTTPBatch меряет время ответа target через каждый узел.
// Возвращает id узла → миллисекунды (только успешные).
func (c *Core) probeHTTPBatch(ctx context.Context, nodes []*Node, target string, onDone func()) map[string]int64 {
	out := make(map[string]int64, len(nodes))
	if len(nodes) == 0 || !c.Ready() {
		// Ядро ещё не установлено (первый запуск) — не помечаем узлы нерабочими.
		return out
	}
	c.probeMu.Lock()
	defer c.probeMu.Unlock()
	if target == "" {
		target = defaultLatencyURL
	}
	inbounds := make([]any, 0, len(nodes))
	outbounds := make([]any, 0, len(nodes))
	rules := make([]any, 0, len(nodes))
	ports := make([]latencyPort, 0, len(nodes))

	portsList := reservePorts(len(nodes))
	for i, n := range nodes {
		port := portsList[i]
		itag := fmt.Sprintf("lat-in-%d", i)
		otag := fmt.Sprintf("lat-out-%d", i)
		inbounds = append(inbounds, map[string]any{
			"tag":      itag,
			"protocol": "socks",
			"listen":   "127.0.0.1",
			"port":     port,
			"settings": map[string]any{"udp": false},
		})
		src := nodeOutbound(n)
		ob := make(map[string]any, len(src)+1)
		for k, v := range src {
			ob[k] = v
		}
		ob["tag"] = otag
		outbounds = append(outbounds, ob)
		rules = append(rules, map[string]any{
			"type":        "field",
			"inboundTag":  []string{itag},
			"outboundTag": otag,
		})
		ports = append(ports, latencyPort{id: n.ID, port: port})
	}

	cfg := map[string]any{
		"log":       map[string]any{"loglevel": "none"},
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"routing":   map[string]any{"rules": rules},
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		return out
	}
	path := filepath.Join(c.dir, "latency-probe.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return out
	}
	defer os.Remove(path)

	cmd := exec.Command(c.binPath(), "-c", path)
	if err := cmd.Start(); err != nil {
		return out
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	// ждём, пока поднимутся SOCKS-порты (не дольше 4 с; не поднявшиеся просто не ответят)
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		alive := 0
		for _, p := range ports {
			conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p.port)), 120*time.Millisecond)
			if err == nil {
				_ = conn.Close()
				alive++
			}
		}
		if alive == len(ports) {
			break
		}
		time.Sleep(80 * time.Millisecond)
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, latencyProbeWorkers)
	for _, p := range ports {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(p latencyPort) {
			defer wg.Done()
			defer func() { <-sem }()
			// лёгкая пауза: серверы не любят пачку одновременных рукопожатий
			time.Sleep(120 * time.Millisecond)
			res := probeSocks(ctx, p.port, target, false)
			if res.OK && res.MS > 0 {
				mu.Lock()
				out[p.id] = res.MS
				mu.Unlock()
			}
			if onDone != nil {
				onDone()
			}
		}(p)
	}
	wg.Wait()
	return out
}
