package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

//go:embed web/index.html
var indexHTML []byte

//go:embed web/favicon.svg
var faviconSVG []byte

type State struct {
	Mode      string           `json:"mode"` // auto | failover | manual
	Selected  string           `json:"selected"`
	Primary   string           `json:"primary,omitempty"`
	Source    string           `json:"source"` // устаревшее поле, только чтение старых файлов
	Sources   []*Source        `json:"sources,omitempty"`
	Nodes     []*Node          `json:"nodes"`
	UpdatedAt int64            `json:"updated_at,omitempty"`
	SubErr    string           `json:"sub_error,omitempty"`
	FailUntil map[string]int64 `json:"fail_until,omitempty"`
	NodeMeta  map[string]*nodeMeta `json:"node_meta,omitempty"`

	// Настройки (живут в state.json, старые файлы читаются как есть).
	CheckInterval   int             `json:"check_interval,omitempty"`
	Excluded        map[string]bool `json:"excluded,omitempty"`
	MaxLatencyMS    int             `json:"max_latency_ms,omitempty"`
	FailThreshold   int             `json:"fail_threshold,omitempty"`
	ReturnToPrimary bool            `json:"return_to_primary"`
	SocksEnabled    bool            `json:"socks_enabled"`
	CoreAutoupdate  bool            `json:"core_autoupdate"`
	HWID            string          `json:"hwid,omitempty"`
	HWIDAuto        bool            `json:"hwid_auto,omitempty"` // сгенерирован при первом запуске
	UA              string          `json:"ua,omitempty"`
	HWIDOff         bool            `json:"hwid_off,omitempty"`
	LatencyURL      string          `json:"latency_url,omitempty"`
	RefreshHoursDef int             `json:"refresh_hours_default,omitempty"`
	FailoverChain   []string        `json:"failover_chain,omitempty"`
	AutoDeltaMS     int             `json:"auto_delta_ms,omitempty"`
	LatencyMin      int             `json:"latency_every_min,omitempty"`
}

type checkProgress struct {
	Phase     string `json:"phase"` // "tcp" | "http"
	Checked   int   `json:"checked"`
	Total     int   `json:"total"`
	StartedAt int64 `json:"started_at"`
}

type App struct {
	mu          sync.Mutex
	dir         string
	state       State
	core        *Core
	auth        *Auth
	checkDur    time.Duration
	subDur      time.Duration
	checking    bool
	applyCh     chan struct{}
	applyQueued bool
	intervalCh  chan struct{}
	checkNow    chan struct{}
	appliedID   string             // узел, реально применённый ядром
	srcNodes    map[string][]*Node // узлы по источникам (в памяти, восстанавливаются из state)
	refreshing  bool
	rotating    bool
	latencyAt   int64
	startedAt   time.Time
	coreStarts  int64
	forceLatency bool
	progress    checkProgress
	lastAutoUpd int64 // unix: когда автообновление последний раз отрабатывало
}

func envOr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n > 0 {
			return n
		}
	}
	return def
}

// appVersion — версия сборки; последняя цифра увеличивается при каждой пересборке.
const appVersion = "1.0.2"

func main() {
	log.SetFlags(log.LstdFlags)
	dir := envOr("DATA_DIR", "/data")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Fatalf("каталог данных: %v", err)
	}
	ensureResolvConf()
	a := &App{
		dir:        dir,
		startedAt:  time.Now(),
		checkDur:   time.Duration(envInt("CHECK_INTERVAL", 60)) * time.Second,
		subDur:     time.Duration(envInt("SUB_REFRESH", 21600)) * time.Second,
		applyCh:    make(chan struct{}, 1),
		intervalCh: make(chan struct{}, 1),
		checkNow:   make(chan struct{}, 1),
		srcNodes:   map[string][]*Node{},
	}
	a.core = NewCore(dir)
	a.load()
	a.ensureHWID()
	a.core.SetSocksEnabled(a.socksOn())
	a.auth = NewAuth(dir)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	a.mu.Lock()
	hasNodes := len(a.state.Nodes) > 0
	a.mu.Unlock()
	go a.applyLoop()
	// Ядро живёт в /data и ставится при первом запуске (в образе его нет).
	go a.bootCore(ctx)
	if hasNodes && a.core.Ready() {
		a.requestApply()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", a.handleIndex)
	mux.HandleFunc("/favicon.svg", a.handleFavicon)
	mux.HandleFunc("/favicon.ico", a.handleFavicon)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })

	// Открытые: состояние авторизации, первый запуск, логин.
	mux.HandleFunc("/api/authstate", a.handleAuthState)
	mux.HandleFunc("/api/setup", a.handleSetup)
	mux.HandleFunc("/api/login", a.handleLogin)
	mux.HandleFunc("/api/logout", a.authOnly(a.handleLogout))

	mux.HandleFunc("/api/state", a.authOnly(a.handleState))
	mux.HandleFunc("/api/source", a.authOnly(a.handleSource))
	mux.HandleFunc("/api/select", a.authOnly(a.handleSelect))
	mux.HandleFunc("/api/logs", a.authOnly(a.handleLogs))
	mux.HandleFunc("/api/mode", a.authOnly(a.handleMode))
	mux.HandleFunc("/api/check", a.authOnly(a.handleCheck))
	mux.HandleFunc("/api/probe", a.authOnly(a.handleProbe))
	mux.HandleFunc("/api/diag", a.authOnly(a.handleDiag))
	mux.HandleFunc("/api/restart", a.authOnly(a.handleRestart))
	mux.HandleFunc("/api/core/reload", a.authOnly(a.handleCoreReload))
	mux.HandleFunc("/api/core/versions", a.authOnly(a.handleCoreVersions))
	mux.HandleFunc("/api/core/version", a.authOnly(a.handleCoreVersion))
	mux.HandleFunc("/api/core/check", a.authOnly(a.handleCoreCheck))
	mux.HandleFunc("/api/failover/chain", a.authOnly(a.handleFailoverChain))
	mux.HandleFunc("/api/settings", a.authOnly(a.handleSettings))
	mux.HandleFunc("/api/node/toggle", a.authOnly(a.handleNodeToggle))
	mux.HandleFunc("/api/node/probe", a.authOnly(a.handleNodeProbe))
	mux.HandleFunc("/api/node/check", a.authOnly(a.handleNodeCheck))
	mux.HandleFunc("/api/password", a.authOnly(a.handlePassword))

	mux.HandleFunc("/api/sources", a.authOnly(a.handleSourcesList))
	mux.HandleFunc("/api/sources/update", a.authOnly(a.handleSourceUpdate))
	mux.HandleFunc("/api/sources/delete", a.authOnly(a.handleSourceDelete))
	mux.HandleFunc("/api/sources/refresh", a.authOnly(a.handleSourceRefresh))
	mux.HandleFunc("/api/sources/reorder", a.authOnly(a.handleSourcesReorder))

	srv := &http.Server{
		Addr:              envOr("LISTEN", ":8080"),
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		log.Printf("веб-интерфейс: http://0.0.0.0%s", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("http: %v", err)
		}
	}()
	go a.loop(ctx)

	<-ctx.Done()
	log.Println("остановка")
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(sctx)
	a.core.Stop()
}

// ensureHWID выдаёт устройству собственный HWID при первом запуске с пустым
// конфигом и записывает его в state.json: у разных пользователей значения разные,
// а повторные запуски и смены образа его не меняют. Явно заданный HWID
// (в настройках или у источника) не трогаем.
func (a *App) ensureHWID() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if strings.TrimSpace(a.state.HWID) != "" || a.state.HWIDAuto {
		return
	}
	a.state.HWID = newHWID()
	a.state.HWIDAuto = true
	a.persistLocked()
	log.Printf("HWID: сгенерирован %s", a.state.HWID)
}

// ensureResolvConf: RouterOS без `dns=` оставляет /etc/resolv.conf пустым —
// подписка и ядро не скачиваются. Тогда прописываем публичные резолверы.
func ensureResolvConf() {
	const path = "/etc/resolv.conf"
	if b, err := os.ReadFile(path); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "nameserver") {
				return
			}
		}
	}
	conf := "nameserver 1.1.1.1\nnameserver 9.9.9.9\nnameserver 8.8.8.8\n"
	if err := os.WriteFile(path, []byte(conf), 0o644); err != nil {
		log.Printf("resolv.conf: %v", err)
		return
	}
	log.Print("resolv.conf: резолверы не заданы, прописал 1.1.1.1, 9.9.9.9, 8.8.8.8")
}

func (a *App) load() {
	a.state = State{
		Mode:            "auto",
		FailUntil:       map[string]int64{},
		Excluded:        map[string]bool{},
		CheckInterval:   clampInterval(int(a.checkDur.Seconds())),
		MaxLatencyMS:    defaultMaxLatencyMS,
		FailThreshold:   defaultFailThreshold,
		ReturnToPrimary: true,
		AutoDeltaMS:     defaultAutoDeltaMS,
		LatencyMin:      defaultLatencyMin,
		SocksEnabled:    true,
		CoreAutoupdate:  true,
		RefreshHoursDef: clampRefreshHours(int(a.subDur.Hours())),
		NodeMeta:        map[string]*nodeMeta{},
		Sources:         []*Source{},
	}
	b, err := os.ReadFile(filepath.Join(a.dir, "state.json"))
	if err != nil {
		return
	}
	var st State
	if err := json.Unmarshal(b, &st); err != nil {
		return
	}
	switch st.Mode {
	case "manual", "failover", "auto", "stable":
	default:
		st.Mode = "auto"
	}
	if st.Nodes == nil {
		st.Nodes = []*Node{}
	}
	if st.FailUntil == nil {
		st.FailUntil = map[string]int64{}
	}
	if st.Excluded == nil {
		st.Excluded = map[string]bool{}
	}
	if st.NodeMeta == nil {
		st.NodeMeta = map[string]*nodeMeta{}
	}
	if st.CheckInterval >= minCheckInterval && st.CheckInterval <= maxCheckInterval {
		a.checkDur = time.Duration(st.CheckInterval) * time.Second
	} else {
		st.CheckInterval = clampInterval(int(a.checkDur.Seconds()))
	}
	st.MaxLatencyMS = clampMaxLatency(st.MaxLatencyMS)
	st.FailThreshold = clampFailThreshold(st.FailThreshold)
	st.RefreshHoursDef = clampRefreshHours(st.RefreshHoursDef)
	st.AutoDeltaMS = clampAutoDeltaMS(st.AutoDeltaMS)
	st.LatencyMin = clampLatencyMin(st.LatencyMin)
	// failover_chain: чистим несуществующие/дубли, primary = chain[0].
	st.FailoverChain = sanitizeChain(st.FailoverChain, st.Nodes)
	if len(st.FailoverChain) == 0 && st.Primary != "" && findNode(st.Nodes, st.Primary) != nil {
		st.FailoverChain = []string{st.Primary}
	}
	if len(st.FailoverChain) > 0 {
		st.Primary = st.FailoverChain[0]
	}
	// return_to_primary и socks_enabled: отличаем «поля нет в файле» от false.
	var rawKeys map[string]json.RawMessage
	if json.Unmarshal(b, &rawKeys) == nil {
		if _, ok := rawKeys["return_to_primary"]; !ok {
			st.ReturnToPrimary = true
		}
		if _, ok := rawKeys["socks_enabled"]; !ok {
			st.SocksEnabled = true
		}
		if _, ok := rawKeys["core_autoupdate"]; !ok {
			st.CoreAutoupdate = true
		}
		// авто-дельта: нет ключа — берём значение по умолчанию (50 мс)
		if _, ok := rawKeys["auto_delta_ms"]; !ok {
			st.AutoDeltaMS = defaultAutoDeltaMS
		}
	}
	kept := st.Nodes[:0]
	for _, n := range st.Nodes {
		if n == nil {
			continue
		}
		if n.Outbound == nil {
			if nn, err := ParseLink(n.Raw); err == nil {
				*n = *nn
			}
		}
		kept = append(kept, n)
	}
	st.Nodes = kept
	a.state = st
	a.migrateSourcesLocked()
}

// migrateSourcesLocked превращает старое поле source в один источник и
// раскладывает уже сохранённые узлы по источникам.
func (a *App) migrateSourcesLocked() {
	a.srcNodes = map[string][]*Node{}
	if len(a.state.Sources) == 0 && strings.TrimSpace(a.state.Source) != "" {
		kind := "links"
		if isHTTPURL(a.state.Source) {
			kind = "url"
		}
		src := &Source{
			ID:        newSourceID(),
			Kind:      kind,
			Title:     defaultSourceTitle(kind, a.state.Source),
			Value:     a.state.Source,
			Enabled:   true,
			UpdatedAt: a.state.UpdatedAt,
		}
		a.state.Sources = []*Source{src}
	}
	if a.state.Sources == nil {
		a.state.Sources = []*Source{}
	}
	first := ""
	if len(a.state.Sources) > 0 {
		first = a.state.Sources[0].ID
	}
	for _, n := range a.state.Nodes {
		m := a.metaLocked(n.ID)
		if m.SourceID == "" {
			m.SourceID = first
		}
		a.srcNodes[m.SourceID] = append(a.srcNodes[m.SourceID], n)
	}
	for _, s := range a.state.Sources {
		s.NodesCount = len(a.srcNodes[s.ID])
	}
}

func (a *App) persistLocked() {
	b, err := json.MarshalIndent(a.state, "", "  ")
	if err != nil {
		return
	}
	tmp := filepath.Join(a.dir, "state.json.tmp")
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		log.Printf("state.json: %v", err)
		return
	}
	_ = os.Rename(tmp, filepath.Join(a.dir, "state.json"))
}

func (a *App) loop(ctx context.Context) {
	if len(a.snapshot()) > 0 {
		a.doCheck()
	}
	t := time.NewTicker(a.periodDur())
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-a.checkNow:
			// Ручной запуск (кнопка или обновление источника) — через тот же цикл.
			a.doCheck()
		case <-a.intervalCh:
			// Период или настройки изменились — пересоздаём ticker без перезапуска.
			t.Stop()
			t = time.NewTicker(a.periodDur())
		case <-t.C:
			a.refreshDueSources(ctx)
			a.maybeAutoUpdate(ctx)
			a.doCheck()
		}
	}
}

// autoUpdateEvery — суточная проверка новой версии ядра (галочка «Автообновление»).
const autoUpdateEvery = 24 * time.Hour

func (a *App) maybeAutoUpdate(ctx context.Context) {
	a.mu.Lock()
	on := a.state.CoreAutoupdate
	last := a.lastAutoUpd
	a.mu.Unlock()
	if !on {
		return
	}
	if last > 0 && time.Since(time.Unix(last, 0)) < autoUpdateEvery {
		return
	}
	a.mu.Lock()
	a.lastAutoUpd = time.Now().Unix()
	a.mu.Unlock()

	latest, err := a.latestRelease(ctx)
	if err != nil {
		log.Printf("автообновление ядра: проверка не удалась: %v", err)
		return
	}
	inst := a.currentTag()
	if inst == latest.Tag {
		log.Printf("автообновление ядра: %s — актуальная версия", latest.Tag)
		return
	}
	if err := a.installVersion(ctx, latest); err != nil {
		log.Printf("автообновление ядра: установка %s не удалась: %v", latest.Tag, err)
		return
	}
	log.Printf("автообновление ядра: установлено %s", latest.Tag)
}

func (a *App) periodDur() time.Duration {	a.mu.Lock()
	defer a.mu.Unlock()
	if a.checkDur < time.Duration(minCheckInterval)*time.Second {
		return time.Duration(minCheckInterval) * time.Second
	}
	return a.checkDur
}

func (a *App) snapshot() []*Node {
	a.mu.Lock()
	defer a.mu.Unlock()
	return copyNodes(a.state.Nodes)
}

func copyNodes(nodes []*Node) []*Node {
	out := make([]*Node, len(nodes))
	for i, n := range nodes {
		if n == nil {
			continue
		}
		c := *n
		out[i] = &c
	}
	return out
}

// doCheck пингует все узлы и в авторежиме выбирает лучший.
func (a *App) doCheck() {
	a.mu.Lock()
	if a.checking {
		a.mu.Unlock()
		return
	}
	a.checking = true
	nodes := copyNodes(a.state.Nodes)
	interval := int(a.checkDur.Seconds())
	a.mu.Unlock()
	if len(nodes) > 0 {
		log.Printf("проверка: %d узлов, интервал %d с", len(nodes), interval)
	}

	defer func() {
		a.mu.Lock()
		a.checking = false
		a.mu.Unlock()
	}()

	if len(nodes) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	a.beginProgress(len(nodes), "tcp")
	res := checkAllProgress(ctx, nodes, a.bumpProgress)

	// QUIC-узлы (hysteria2) по TCP не проверить: гоняем реальный запрос через временное ядро,
	// чтобы они получали настоящий статус и пинг и могли участвовать в авто/failover.
	altUsed := map[string]bool{}
	idx := make(map[string]int, len(nodes))
	quicTotal := 0
	for i, n := range nodes {
		idx[n.ID] = i
		if n.Quic || n.AWG != "" {
			quicTotal++
		}
	}
	var quic []*Node
	a.mu.Lock()
	for _, n := range nodes {
		if (n.Quic || n.AWG != "") && n.Unsupported == "" && !a.nodeDisabledLocked(n) {
			cp := *n
			quic = append(quic, &cp)
		}
	}
	a.mu.Unlock()
	for _, n := range quic {
		ok, ms, errMsg, usedAlt := a.core.ProbeNode(ctx, n)
		i := idx[n.ID]
		if ok {
			res[i] = checkResult{ok: true, ms: ms}
			if usedAlt {
				altUsed[n.ID] = true
			}
		} else {
			res[i] = checkResult{err: errMsg}
		}
		a.bumpProgress()
	}
	// Пропущенные QUIC-узлы (отключённые/неподдерживаемые) тоже считаем пройденными.
	for k := len(quic); k < quicTotal; k++ {
		a.bumpProgress()
	}

	// Реальная задержка: одно временное ядро, запрос через каждый живой TCP-узел
	// до адреса проверки (по умолчанию лёгкий 204-эндпоинт).
	a.mu.Lock()
	latURL := latencyURL(a.state.LatencyURL)
	latEvery := time.Duration(clampLatencyMin(a.state.LatencyMin)) * time.Minute
	runLatency := a.forceLatency || time.Since(time.Unix(a.latencyAt, 0)) >= latEvery
	a.forceLatency = false
	var liveNodes []*Node
	missing := 0
	for i, n := range nodes {
		if res[i].ok && !n.Quic && n.AWG == "" {
			cp := *n
			liveNodes = append(liveNodes, &cp)
			if freshReal(n) == 0 {
				missing++
			}
		}
	}
	// После старта или после долгого простоя замеров нет почти у всех — меряем сразу,
	// не дожидаясь периода.
	if len(liveNodes) > 0 && missing*2 > len(liveNodes) {
		runLatency = true
	}
	a.mu.Unlock()
	// Пачки по 6: одно ядро с десятками SOCKS-инобаундов ведёт себя нестабильно.
	// Свой контекст: цикл проверки живёт 60 с, а замер всех узлов дольше.
	realMS := make(map[string]int64, len(liveNodes))
	if runLatency && len(liveNodes) > 0 {
		// Вторая фаза: счётчик показывает, сколько узлов уже измерено HTTP.
		a.beginProgress(len(liveNodes), "http")
	}
	latCtx, latCancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer latCancel()
	for start := 0; runLatency && start < len(liveNodes); start += 6 {
		end := start + 6
		if end > len(liveNodes) {
			end = len(liveNodes)
		}
		for id, ms := range a.core.probeHTTPBatch(latCtx, liveNodes[start:end], latURL, a.bumpProgress) {
			realMS[id] = ms
		}
		if latCtx.Err() != nil {
			break
		}
	}
	if len(realMS) > 0 {
		a.mu.Lock()
		a.latencyAt = time.Now().Unix()
		a.mu.Unlock()
	}

	a.mu.Lock()
	if len(a.state.Nodes) != len(nodes) {
		a.mu.Unlock()
		return
	}
	for i, n := range nodes {
		if a.state.Nodes[i].ID != n.ID {
			a.mu.Unlock()
			return
		}
	}
	now := time.Now().Unix()
	for i, n := range a.state.Nodes {
		r := res[i]
		n.Checked = now
		if altUsed[n.ID] {
			n.ObfsStripped = true
		}
		m := a.metaLocked(n.ID)
		_, hasReal := realMS[n.ID]
		if hasReal {
			n.RealMS = realMS[n.ID]
			n.RealAt = now
			m.RealFails = 0
		} else if r.ok && len(realMS) > 0 {
			n.RealMS, n.RealAt = 0, 0
		}
		// Узел отвечает по TCP, но HTTP через него не идёт (белые списки,
		// чужая REALITY-обвязка) — считаем нерабочим до первого успешного HTTP.
		if runLatency && r.ok && !n.Quic && n.AWG == "" && !hasReal && len(realMS) > 0 {
			m.RealFails++
		}
		httpDead := r.ok && !n.Quic && n.AWG == "" && m.RealFails > 0
		// QUIC проверяется временным ядром по HTTP — это уже реальная задержка.
		if (n.Quic || n.AWG != "") && r.ok && r.ms > 0 {
			n.RealMS = r.ms
			n.RealAt = now
		}
		switch {
		case httpDead:
			n.Status = "fail"
			n.Latency = 0
			n.RealMS, n.RealAt = 0, 0
			n.LastErr = "узел не пропускает HTTP"
		case r.ok:
			n.Status = "ok"
			n.Latency = r.ms
			n.LastErr = ""
		case r.status != "":
			n.Status = r.status
			n.Latency = 0
			n.LastErr = r.err
		default:
			n.Status = "fail"
			n.Latency = 0
			n.LastErr = r.err
		}
	}
	a.state.UpdatedAt = now
	prev := a.state.Selected
	failover := a.state.Mode == "failover"
	activeID := a.state.Selected
	if failover {
		a.countersFromAvailabilityLocked(activeID)
		if a.state.ReturnToPrimary && a.state.Primary == "" && activeID != "" {
			a.state.Primary = activeID
		}
	} else {
		a.autoSelectLocked()
	}
	changed := a.state.Selected != prev
	needApply := changed || !a.core.Running()
	exitNeed := failover && a.exitStaleLocked(activeID, now)
	a.persistLocked()
	a.mu.Unlock()

	if !failover {
		if needApply {
			a.requestApply()
		}
		// IP активного узла — через живой туннель, без временных ядер.
		if activeID != "" && a.exitStaleLocked(activeID, now) && a.core.Running() && a.socksOn() {
			go func(id string) {
				res := a.lookupExit()
				if !res.OK || res.IP == "" {
					return
				}
				a.mu.Lock()
				if a.state.Selected == id {
					m := a.metaLocked(id)
					m.ExitIP = res.IP
					m.ExitCountry = normalCountry(res.CC)
					m.ExitCheckedAt = time.Now().Unix()
					a.persistLocked()
				}
				a.mu.Unlock()
			}(activeID)
		}
		return
	}

	// Failover: проверка реальной передачей через текущий тоннель.
	chRes, probed := a.failoverProbe(activeID)
	var exit probeResult
	if probed {
		okChannel := chRes.OK && chRes.Bytes >= failoverProbeBytes
		if okChannel && exitNeed {
			exit = a.lookupExit()
		}
	}

	a.mu.Lock()
	if findNode(a.state.Nodes, activeID) == nil {
		a.mu.Unlock()
		return
	}
	if probed {
		a.recordChannelLocked(activeID, chRes)
		a.recordExitLocked(activeID, exit)
	} else {
		// Ядро не работает: считаем это провалом активного узла.
		m := a.metaLocked(activeID)
		m.Fails++
		m.Oks = 0
	}
	switched := a.failoverDecideLocked()
	a.persistLocked()
	a.mu.Unlock()

	if switched || needApply {
		a.requestApply()
	}
}

// autoSelectLocked: auto — меняем узел, только если лучший быстрее текущего
// на заданную дельту; stable — держим текущий, пока он отвечает.
func (a *App) autoSelectLocked() {
	cur := findNode(a.state.Nodes, a.state.Selected)
	curOK := cur != nil && !a.nodeDisabledLocked(cur) && cur.Status == "ok" && !a.blacklisted(cur.ID)

	switch a.state.Mode {
	case "stable":
		if curOK {
			return
		}
		if best := a.pickBestLocked(); best != nil && best.ID != a.state.Selected {
			a.state.Selected = best.ID
		}
		return
	case "auto":
	default:
		return
	}

	best := a.pickBestLocked()
	if best == nil {
		return
	}
	curMS := nodeMS(cur)
	if !curOK || curMS <= 0 {
		a.state.Selected = best.ID
		return
	}
	if best.ID == cur.ID {
		return
	}
	bm := nodeMS(best)
	if bm <= 0 {
		return
	}
	// переключаемся, только если лучший выигрывает больше дельты (мс)
	if curMS-bm > int64(clampAutoDeltaMS(a.state.AutoDeltaMS)) {
		a.state.Selected = best.ID
	}
}

func (a *App) blacklisted(id string) bool {
	until, ok := a.state.FailUntil[id]
	return ok && time.Now().Unix() < until
}

func (a *App) pickBestLocked() *Node {
	var best *Node
	for _, n := range a.state.Nodes {
		if n.Status != "ok" || n.Unsupported != "" {
			continue
		}
		if a.blacklisted(n.ID) || a.nodeDisabledLocked(n) {
			continue
		}
		ms := nodeMS(n)
		if ms <= 0 {
			continue
		}
		if best == nil || ms < nodeMS(best) {
			best = n
		}
	}
	return best
}

// requestCheck ставит проверку в очередь единственного цикла (без новых горутин).
func (a *App) requestCheck() {
	select {
	case a.checkNow <- struct{}{}:
	default:
	}
}

func (a *App) requestApply() {
	a.mu.Lock()
	a.applyQueued = true
	a.mu.Unlock()
	select {
	case a.applyCh <- struct{}{}:
	default:
	}
}

func (a *App) applyLoop() {
	for range a.applyCh {
		for {
			a.mu.Lock()
			queued := a.applyQueued
			a.applyQueued = false
			a.mu.Unlock()
			if !queued {
				break
			}
			a.applyOnce()
		}
	}
}

// applyOnce применяет узел и проверяет, что тоннель реально пропускает трафик.
// Если нет — блокирует узел на 10 минут и (в авторежиме) берёт следующий.
func (a *App) applyOnce() {
	// Пока ядро не установлено (первый старт), применять нечего:
	// bootCore вызовет requestApply после загрузки.
	if !a.core.Ready() {
		return
	}
	n := a.currentSelected()
	for attempt := 0; attempt < 3 && n != nil; attempt++ {
		if err := a.core.Apply(n); err != nil {
			log.Printf("применение узла %s: %v", n.Name, err)
			return
		}
		a.mu.Lock()
		a.appliedID = n.ID
		a.mu.Unlock()
		if a.probeVerify(n.ID) {
			return
		}
		n = a.afterFailedProbe(n.ID)
	}
	if n == nil {
		a.core.Stop()
		a.mu.Lock()
		a.appliedID = ""
		a.mu.Unlock()
	}
}

func (a *App) currentSelected() *Node {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := a.selectedLocked()
	if n != nil && n.Unsupported != "" {
		return nil
	}
	return n
}

func (a *App) selectedLocked() *Node {
	cur := findNode(a.state.Nodes, a.state.Selected)
	if a.state.Mode != "auto" {
		// manual и failover: узел выбран явно (или логикой failover), не переопределяем.
		if cur != nil && a.nodeDisabledLocked(cur) {
			return nil
		}
		return cur
	}
	if best := a.pickBestLocked(); best != nil {
		a.state.Selected = best.ID
		return best
	}
	if cur != nil && a.nodeDisabledLocked(cur) {
		return nil
	}
	return cur
}

func (a *App) probeVerify(id string) bool {
	// Без SOCKS-инбаунда проверить канал нельзя — не баним узел зря.
	if !a.socksOn() {
		return true
	}
	var last probeResult
	for attempt := 0; attempt < 3; attempt++ {
		time.Sleep(time.Duration(900+attempt*1300) * time.Millisecond)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		res := a.core.probeThroughTunnel(ctx, "", false)
		cancel()
		if res.OK {
			a.mu.Lock()
			if n := findNode(a.state.Nodes, id); n != nil {
				n.Checked = time.Now().Unix()
				n.Status = "ok"
				if n.Latency == 0 {
					n.Latency = res.MS
				}
				n.LastErr = ""
				delete(a.state.FailUntil, id)
				if res.IP != "" {
					m := a.metaLocked(id)
					m.ExitIP = res.IP
					m.ExitCountry = normalCountry(res.CC)
					m.ExitCheckedAt = time.Now().Unix()
				}
				a.persistLocked()
			}
			a.mu.Unlock()
			return true
		}
		last = res
	}

	a.mu.Lock()
	n := findNode(a.state.Nodes, id)
	if n == nil {
		a.mu.Unlock()
		return true
	}
	n.Checked = time.Now().Unix()
	n.Status = "fail"
	n.Latency = 0
	n.LastErr = "тоннель не пропускает трафик: " + last.Error
	if a.state.FailUntil == nil {
		a.state.FailUntil = map[string]int64{}
	}
	a.state.FailUntil[id] = time.Now().Add(10 * time.Minute).Unix()
	a.persistLocked()
	a.mu.Unlock()
	log.Printf("узел %s не пропускает трафик: %s", n.Name, last.Error)
	return false
}

func (a *App) afterFailedProbe(id string) *Node {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.state.Mode == "failover" {
		if a.state.FailUntil == nil {
			a.state.FailUntil = map[string]int64{}
		}
		a.state.FailUntil[id] = time.Now().Add(failoverBanSeconds * time.Second).Unix()
		next := a.pickReserveLocked(id)
		if next != nil {
			a.state.Selected = next.ID
			if !a.state.ReturnToPrimary {
				a.state.Primary = next.ID
			}
			a.persistLocked()
			return next
		}
		return nil
	}
	if a.state.Mode != "auto" && a.state.Mode != "stable" {
		return nil
	}
	if best := a.pickBestLocked(); best != nil && best.ID != id {
		a.state.Selected = best.ID
		a.persistLocked()
		return best
	}
	return nil
}

func findNode(nodes []*Node, id string) *Node {
	if id == "" {
		return nil
	}
	for _, n := range nodes {
		if n.ID == id {
			return n
		}
	}
	return nil
}

func (a *App) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(indexHTML)
}

// handleFavicon отдаёт встроенную SVG-иконку (щит + орбита, без анимации).
func (a *App) handleFavicon(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "max-age=300")
	_, _ = w.Write(faviconSVG)
}

func (a *App) handleState(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	st := a.state
	checking := a.checking
	interval := int(a.checkDur.Seconds())
	progress := a.progress
	views := a.nodeViewsLocked()
	excluded := make(map[string]bool, len(a.state.Excluded))
	for id, v := range a.state.Excluded {
		excluded[id] = v
	}
	sources := make([]Source, 0, len(a.state.Sources))
	for _, s := range a.state.Sources {
		if s == nil {
			continue
		}
		c := *s
		c.NodesCount = len(a.srcNodes[c.ID])
		sources = append(sources, c)
	}
	maxLat := a.maxLatencyLocked()
	failThr := a.failThresholdLocked()
	latAt := a.latencyAt
	a.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"mode":                  st.Mode,
		"selected":              st.Selected,
		"primary":               st.Primary,
		"source":                st.Source,
		"sources":               sources,
		"nodes":                 views,
		"updated_at":            st.UpdatedAt,
		"sub_error":             st.SubErr,
		"core":                  a.core.Info(),
		"app_uptime_sec":        int64(time.Since(a.startedAt).Seconds()),
		"app_version":           appVersion,
		"core_starts":           a.coreStarts,
		"checking":              checking,
		"check_interval":        interval,
		"check_progress":        progress,
		"excluded":              excluded,
		"max_latency_ms":        maxLat,
		"fail_threshold":        failThr,
		"return_to_primary":     st.ReturnToPrimary,
		"socks_enabled":         st.SocksEnabled,
		"core_autoupdate":       st.CoreAutoupdate,
		"hwid":                  st.HWID,
		"ua":                    st.UA,
		"hwid_off":             st.HWIDOff,
		"latency_url":          latencyURL(st.LatencyURL),
		"refresh_hours_default": st.RefreshHoursDef,
		"failover_chain":        st.FailoverChain,
		"auto_delta_ms":         clampAutoDeltaMS(st.AutoDeltaMS),
		"latency_every_min":     clampLatencyMin(st.LatencyMin),
		"latency_at":            latAt,
	})
}

func (a *App) handleSource(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Text string `json:"text"`
	}
	if !jsonPost(w, r, &body) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	if _, _, _, err := a.addSource(ctx, "", body.Text, "", "", false, ""); err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, errDuplicateSub) || errors.Is(err, errDuplicateServers) {
			code = http.StatusConflict
		}
		writeJSON(w, code, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *App) handleSelect(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID   string `json:"id"`
		Mode string `json:"mode"`
	}
	if !jsonPost(w, r, &body) {
		return
	}
	a.mu.Lock()
	node := findNode(a.state.Nodes, body.ID)
	if node == nil {
		a.mu.Unlock()
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "узел не найден"})
		return
	}
	if node.Unsupported != "" {
		reason := node.Unsupported
		a.mu.Unlock()
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "узел не поддерживается: " + reason})
		return
	}
	if a.nodeDisabledLocked(node) {
		a.mu.Unlock()
		writeJSON(w, http.StatusConflict, map[string]string{"error": "узел отключён — включите его в списке"})
		return
	}
	// Клиент может сразу попросить ручной режим (закрепление сервера).
	switch body.Mode {
	case "auto", "stable", "manual", "failover":
		a.state.Mode = body.Mode
	}
	mode := a.state.Mode
	switch mode {
	case "failover":
		// выбор узла = сделать его основным (голова цепочки)
		a.promoteChainLocked(body.ID)
		if node.Status == "ok" && !a.blacklisted(node.ID) {
			a.state.Selected = body.ID
		}
	default:
		if body.Mode == "" {
			a.state.Mode = "manual"
		}
		a.state.Selected = body.ID
	}
	a.persistLocked()
	a.mu.Unlock()
	a.requestApply()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "mode": mode})
}

func (a *App) handleMode(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Mode string `json:"mode"`
	}
	if !jsonPost(w, r, &body) {
		return
	}
	if body.Mode != "auto" && body.Mode != "manual" && body.Mode != "failover" && body.Mode != "stable" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "режим: auto, stable, failover или manual"})
		return
	}
	a.mu.Lock()
	a.state.Mode = body.Mode
	switch body.Mode {
	case "auto":
		a.autoSelectLocked()
	case "failover":
		if a.state.Primary == "" {
			a.state.Primary = a.state.Selected
		}
		if len(a.state.FailoverChain) == 0 && a.state.Selected != "" {
			a.state.FailoverChain = []string{a.state.Selected}
		}
		primary := findNode(a.state.Nodes, a.state.Primary)
		if primary != nil && primary.Status == "ok" && !a.nodeDisabledLocked(primary) && !a.blacklisted(primary.ID) {
			a.state.Selected = primary.ID
		} else if best := a.pickBestLocked(); best != nil {
			a.state.Selected = best.ID
			if a.state.Primary == "" {
				a.state.Primary = best.ID
			}
		}
	}
	a.persistLocked()
	a.mu.Unlock()
	a.requestApply()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *App) handleCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "нужен POST"})
		return
	}
	a.mu.Lock()
	a.forceLatency = true
	a.mu.Unlock()
	a.requestCheck()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *App) handleProbe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "нужен POST"})
		return
	}
	var body struct {
		URL      string `json:"url"`
		Insecure bool   `json:"insecure"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body)
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if !a.socksOn() {
		// SOCKS выключен: временный Xray с тем же узлом, живое ядро не трогаем.
		writeJSON(w, http.StatusOK, a.probeViaTempNode(ctx, body.URL))
		return
	}
	writeJSON(w, http.StatusOK, a.core.probeThroughTunnel(ctx, body.URL, body.Insecure))
}

func (a *App) handleDiag(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.core.Diag())
}

func (a *App) handleRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "нужен POST"})
		return
	}
	a.requestApply()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (a *App) handleLogs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"logs": a.core.LogLines()})
}
