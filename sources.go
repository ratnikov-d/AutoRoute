package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Несколько источников: подписка (url) или вставленные ссылки (links).
// Узлы всех включённых источников складываются в общий пул с дедупликацией по ID.

type Source struct {
	ID           string       `json:"id"`
	Kind         string       `json:"kind"` // url | links
	Title        string       `json:"title,omitempty"`
	TitleManual  bool         `json:"title_manual,omitempty"`
	Value        string       `json:"value"`
	Enabled      bool         `json:"enabled"`
	Error        string       `json:"error,omitempty"`
	UpdatedAt    int64        `json:"updated_at,omitempty"`
	NodesCount   int          `json:"nodes_count"`
	RefreshHours int          `json:"refresh_hours,omitempty"`
	AutoRefresh  *bool        `json:"auto_refresh,omitempty"` // nil = включено
	HWID         string       `json:"hwid,omitempty"`         // пусто = общий из настроек
	HWIDOff      bool         `json:"hwid_off,omitempty"`
	UA           string       `json:"ua,omitempty"`           // свой User-Agent подписки
	Userinfo     *subUserinfo `json:"userinfo,omitempty"`
}

// autoOn — автообновление подписки; отсутствие поля означает «включено».
func (s *Source) autoOn() bool {
	return s.AutoRefresh == nil || *s.AutoRefresh
}

// subUserinfo — заголовок subscription-userinfo подписки (байты, unix-время).
type subUserinfo struct {
	Upload   int64 `json:"upload,omitempty"`
	Download int64 `json:"download,omitempty"`
	Total    int64 `json:"total,omitempty"`
	Expire   int64 `json:"expire,omitempty"`
}

// parseUserinfo разбирает "upload=1; download=2; total=3; expire=4".
func parseUserinfo(v string) *subUserinfo {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	u := &subUserinfo{}
	found := false
	for _, part := range strings.Split(v, ";") {
		key, val, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		n, err := strconv.ParseInt(strings.TrimSpace(val), 10, 64)
		if err != nil || n < 0 {
			continue
		}
		switch key {
		case "upload":
			u.Upload, found = n, true
		case "download":
			u.Download, found = n, true
		case "total":
			u.Total, found = n, true
		case "expire":
			u.Expire, found = n, true
		}
	}
	if !found {
		return nil
	}
	return u
}

func newSourceID() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return shortHash(time.Now().String())
	}
	return hex.EncodeToString(b)
}

func isHTTPURL(s string) bool {
	l := strings.ToLower(strings.TrimSpace(s))
	return strings.HasPrefix(l, "http://") || strings.HasPrefix(l, "https://")
}

func normalizeKind(kind, value string) string {
	kind = strings.ToLower(strings.TrimSpace(kind))
	switch kind {
	case "url", "links":
		return kind
	}
	if isHTTPURL(value) {
		return "url"
	}
	return "links"
}

func defaultSourceTitle(kind, value string) string {
	if kind == "url" {
		if u, err := url.Parse(strings.TrimSpace(value)); err == nil && u.Host != "" {
			return u.Host
		}
		return "подписка"
	}
	return "ссылки"
}

func sourceByID(list []*Source, id string) *Source {
	for _, s := range list {
		if s != nil && s.ID == id {
			return s
		}
	}
	return nil
}

// decodeProfileTitle разбирает заголовок profile-title (может быть base64:...).
func decodeProfileTitle(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if strings.HasPrefix(strings.ToLower(v), "base64:") {
		if dec, err := b64dec(v[len("base64:"):]); err == nil {
			v = strings.TrimSpace(dec)
		}
	}
	return v
}

// titleFromBody ищет название подписки в комментариях: "#profile-title: ..." или "# Название".
func titleFromBody(raw string) string {
	var first string
	lines := strings.Split(raw, "\n")
	for i, line := range lines {
		if i > 40 {
			break
		}
		l := strings.TrimSpace(strings.TrimRight(line, "\r"))
		if !strings.HasPrefix(l, "#") {
			continue
		}
		body := strings.TrimSpace(strings.TrimPrefix(l, "#"))
		low := strings.ToLower(body)
		if strings.HasPrefix(low, "profile-title:") {
			if v := strings.TrimSpace(body[len("profile-title:"):]); v != "" {
				return decodeProfileTitle(v)
			}
		}
		if first == "" && body != "" && !strings.Contains(low, ":") && !strings.Contains(low, "://") {
			first = body
		}
	}
	return first
}

// browserUA — часть панелей отвечает 400 на «не браузерный» User-Agent.
const browserUA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36"

// clientUA — большинство панелей отдают полный список серверов только
// клиентским приложениям. Браузеру достаётся урезанный набор ключей.
const clientUA = "Hiddify/2.0.0"

// normalizeSubscriptionBody понимает формат панелей Remnawave и подобных:
// вместо списка ссылок они отдают JSON {"keys":[{"base_key":"vless://..."}]}.
func normalizeSubscriptionBody(raw string) string {
	t := strings.TrimSpace(raw)
	if !strings.HasPrefix(t, "{") {
		return raw
	}
	var obj struct {
		Keys []struct {
			BaseKey string `json:"base_key"`
			Flag    string `json:"flag"`
		} `json:"keys"`
	}
	if err := json.Unmarshal([]byte(t), &obj); err == nil && len(obj.Keys) > 0 {
		out := make([]string, 0, len(obj.Keys))
		for _, k := range obj.Keys {
			if v := strings.TrimSpace(k.BaseKey); v != "" {
				out = append(out, v)
			}
		}
		if len(out) > 0 {
			return strings.Join(out, "\n")
		}
	}
	var plain struct {
		Keys []string `json:"keys"`
	}
	if err := json.Unmarshal([]byte(t), &plain); err == nil && len(plain.Keys) > 0 {
		return strings.Join(plain.Keys, "\n")
	}
	return raw
}

// --- страницы-ключей (HTML) ---

var (
	reFetchURL = regexp.MustCompile(`data-fetch-url="([^"]+)"`)
	reTitle    = regexp.MustCompile(`(?is)<title>([^<]{1,120})</title>`)
	reUsedGB   = regexp.MustCompile(`Израсходовано трафика:\s*<strong>([\d.,]+)</strong>\s*ГБ`)
	reDays     = regexp.MustCompile(`Остаток дней:\s*<strong>([\d]+)</strong>`)
)

func isKeysPage(body string) bool {
	if !strings.Contains(body, "<") {
		return false
	}
	low := strings.ToLower(body)
	return strings.Contains(low, "<html") || strings.Contains(low, "data-fetch-url=")
}

func htmlTitle(body string) string {
	if m := reTitle.FindStringSubmatch(body); len(m) == 2 {
		t := strings.TrimSpace(m[1])
		if t != "" && !strings.Contains(strings.ToLower(t), "keys") {
			return t
		}
	}
	return ""
}

// keysPageURL — абсолютный адрес JSON-списка ключей из страницы.
func keysPageURL(page, base string) string {
	m := reFetchURL.FindStringSubmatch(page)
	if len(m) != 2 {
		return ""
	}
	ref, err := url.Parse(strings.TrimSpace(m[1]))
	if err != nil {
		return ""
	}
	b, err := url.Parse(base)
	if err != nil {
		return ""
	}
	return b.ResolveReference(ref).String()
}

// parseKeysPageInfo — срок и израсходованный трафик со страницы-ключей.
func parseKeysPageInfo(page string) *subUserinfo {
	info := &subUserinfo{}
	got := false
	if m := reUsedGB.FindStringSubmatch(page); len(m) == 2 {
		v := strings.ReplaceAll(m[1], ",", ".")
		if gb, err := strconv.ParseFloat(v, 64); err == nil && gb >= 0 {
			info.Download = int64(gb * 1024 * 1024 * 1024)
			got = true
		}
	}
	if m := reDays.FindStringSubmatch(page); len(m) == 2 {
		if d, err := strconv.Atoi(m[1]); err == nil && d >= 0 {
			info.Expire = time.Now().Add(time.Duration(d) * 24 * time.Hour).Unix()
			got = true
		}
	}
	if !got {
		return nil
	}
	return info
}

// fetchKeysPage забирает JSON со ссылками по адресу из страницы.
func fetchKeysPage(ctx context.Context, u, hwid string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, withHWID(u, hwid), nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", browserUA)
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("X-Requested-With", "fetch")
	applyHWID(req, hwid)
	resp, err := httpClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return ""
	}
	return string(b)
}

// fetchSourceText загружает подписку, её название и лимиты трафика.
// Сначала как клиент (полный список), если ссылок не нашлось — как браузер.
func fetchSourceText(ctx context.Context, u, hwid, ua string) (text, title string, info *subUserinfo, err error) {
	uas := []string{clientUA, browserUA}
	if strings.TrimSpace(ua) != "" {
		// Свой UA: сначала он, браузерный — как запасной вариант.
		uas = []string{strings.TrimSpace(ua), browserUA}
	}
	for _, ua := range uas {
		text, title, info, err = fetchSourceOnce(ctx, u, hwid, ua)
		if err == nil && strings.Contains(text, "://") {
			return text, title, info, nil
		}
	}
	return text, title, info, err
}

func fetchSourceOnce(ctx context.Context, u, hwid, ua string) (text, title string, info *subUserinfo, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, withHWID(u, hwid), nil)
	if err != nil {
		return "", "", nil, err
	}
	// Панели (Remnawave и подобные) отдают JSON только браузерному UA.
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "*/*")
	applyHWID(req, hwid)
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", "", nil, fmt.Errorf("загрузка подписки: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", nil, fmt.Errorf("подписка: HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return "", "", nil, fmt.Errorf("чтение подписки: %w", err)
	}
	raw := string(b)
	title = decodeProfileTitle(resp.Header.Get("profile-title"))
	info = parseUserinfo(resp.Header.Get("subscription-userinfo"))
	if info == nil {
		info = parseUserinfo(resp.Header.Get("Subscription-Userinfo"))
	}
	// Страница-ключей (Remnawave и форки): срок и трафик лежат в HTML,
	// а ссылки подтягиваются с адреса из data-fetch-url.
	if isKeysPage(raw) {
		if info == nil {
			info = parseKeysPageInfo(raw)
		}
		if keysURL := keysPageURL(raw, u); keysURL != "" {
			if keys := fetchKeysPage(ctx, keysURL, hwid); keys != "" {
				raw = keys
			}
		}
		if title == "" {
			title = htmlTitle(string(b))
		}
	}
	raw = normalizeSubscriptionBody(raw)
	text = maybeBase64(raw)
	if title == "" {
		title = titleFromBody(raw)
	}
	if title == "" && text != raw {
		title = titleFromBody(text)
	}
	return text, title, info, nil
}

// effectiveUA: UA источника, иначе общий из настроек (пусто = авто).
func (a *App) effectiveUA(s *Source) string {
	if s != nil {
		if v := strings.TrimSpace(s.UA); v != "" {
			return v
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return strings.TrimSpace(a.state.UA)
}

// effectiveHWID: HWID источника, иначе общий из настроек.
// Пустая строка — HWID не передаётся (глобальный запрет или запрет источника).
func (a *App) effectiveHWID(s *Source) string {
	a.mu.Lock()
	off := a.state.HWIDOff
	global := strings.TrimSpace(a.state.HWID)
	a.mu.Unlock()
	if off || (s != nil && s.HWIDOff) {
		return ""
	}
	if s != nil {
		if v := strings.TrimSpace(s.HWID); v != "" {
			return v
		}
	}
	return global
}

// fetchSource разбирает источник в узлы (сеть — только для kind=url).
func (a *App) fetchSource(ctx context.Context, s *Source) ([]*Node, string, *subUserinfo, error) {
	value := strings.TrimSpace(s.Value)
	if value == "" {
		return nil, "", nil, errors.New("пустое значение источника")
	}
	var (
		text  string
		title string
		info  *subUserinfo
		err   error
	)
	hwid := a.effectiveHWID(s)
	if s.Kind == "url" {
		text, title, info, err = fetchSourceText(ctx, value, hwid, a.effectiveUA(s))
	} else {
		text, err = resolveSource(ctx, value, hwid)
	}
	if err != nil {
		return nil, "", nil, err
	}
	nodes := parseLinks(text)
	if len(nodes) == 0 {
		return nil, title, info, errors.New("не найдено поддерживаемых ссылок (vless / vmess / trojan / ss / hysteria2)")
	}
	return nodes, title, info, nil
}

func (a *App) setSourceNodesLocked(s *Source, nodes []*Node) {
	for _, n := range nodes {
		if n == nil {
			continue
		}
		a.metaLocked(n.ID).SourceID = s.ID
	}
	a.srcNodes[s.ID] = nodes
	s.NodesCount = len(nodes)
	s.UpdatedAt = time.Now().Unix()
	s.Error = ""
}

// rebuildPoolLocked собирает общий пул узлов из включённых источников.
func (a *App) rebuildPoolLocked() {
	old := make(map[string]*Node, len(a.state.Nodes))
	for _, n := range a.state.Nodes {
		old[n.ID] = n
	}
	var pool []*Node
	seen := make(map[string]bool)
	for _, s := range a.state.Sources {
		if s == nil {
			continue
		}
		s.NodesCount = len(a.srcNodes[s.ID])
		if !s.Enabled {
			continue
		}
		for _, n := range a.srcNodes[s.ID] {
			if n == nil || seen[n.ID] {
				continue
			}
			seen[n.ID] = true
			if p, ok := old[n.ID]; ok {
				n.Status, n.Latency, n.LastErr, n.Checked = p.Status, p.Latency, p.LastErr, p.Checked
			}
			a.metaLocked(n.ID).SourceID = s.ID
			pool = append(pool, n)
		}
	}
	a.state.Nodes = pool
	a.state.FailoverChain = sanitizeChain(a.state.FailoverChain, pool)
	if len(a.state.FailoverChain) > 0 {
		a.state.Primary = a.state.FailoverChain[0]
	} else {
		a.state.Primary = ""
	}
	if findNode(pool, a.state.Selected) == nil {
		if len(pool) > 0 {
			a.state.Selected = pool[0].ID
		} else {
			a.state.Selected = ""
		}
	}
	if findNode(pool, a.state.Primary) == nil {
		a.state.Primary = ""
	}
}

// addSource создаёт источник и сразу подтягивает узлы. Ошибка загрузки не мешает
// сохранить источник: она пишется в s.Error, карточка в UI покажет её.
// Ошибки добавления источника (409 на дубли).
var (
	errDuplicateSub     = errors.New("Такая подписка уже добавлена")
	errDuplicateServers = errors.New("Эти серверы уже добавлены")
)

// normalizeSourceURL приводит ссылку подписки к виду для сравнения:
// схема и хост в нижнем регистре, fragment отброшен, дефолтный порт убран,
// хвостовой «/» у пути срезан; query не трогаем.
func normalizeSourceURL(s string) string {
	s = strings.TrimSpace(s)
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return strings.ToLower(s)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Fragment = ""
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		u.Host = net.JoinHostPort(host, port)
	} else {
		u.Host = host
	}
	if u.Path == "/" {
		u.Path = ""
	} else {
		u.Path = strings.TrimRight(u.Path, "/")
	}
	return u.String()
}

// sourceHostPath — запасное сравнение «host + path» без схемы и без хвостового «/».
func sourceHostPath(s string) string {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || u.Host == "" {
		return ""
	}
	out := strings.ToLower(u.Hostname())
	if p := strings.TrimRight(u.Path, "/"); p != "" {
		out += p
	}
	return out
}

// sameSubscription сравнивает две ссылки подписки с нормализацией и запасным
// правилом «одинаковые host+path».
func sameSubscription(a, b string) bool {
	if normalizeSourceURL(a) == normalizeSourceURL(b) {
		return true
	}
	ha, hb := sourceHostPath(a), sourceHostPath(b)
	return ha != "" && ha == hb
}

// poolIDsLocked — все узлы включённых источников (для отсева дублей).
func (a *App) poolIDsLocked() map[string]bool {
	out := make(map[string]bool)
	for _, s := range a.state.Sources {
		if s == nil || !s.Enabled {
			continue
		}
		for _, n := range a.srcNodes[s.ID] {
			if n != nil {
				out[n.ID] = true
			}
		}
	}
	return out
}

// addSource ????????? ???????? ? ?????????? (src, ?????????, ?????????, ??????).
func (a *App) addSource(ctx context.Context, kind, value, title, hwid string, hwidOff bool, ua string) (*Source, int, int, error) {
	src := &Source{
		ID:      newSourceID(),
		Kind:    normalizeKind(kind, value),
		Value:   strings.TrimSpace(value),
		HWID:    strings.TrimSpace(hwid),
		HWIDOff: hwidOff,
		UA:      strings.TrimSpace(ua),
		Enabled: true,
	}
	if src.Value == "" {
		return nil, 0, 0, errors.New("нужно значение: ссылка на подписку или список ссылок")
	}
	if t := strings.TrimSpace(title); t != "" {
		src.Title = t
		src.TitleManual = true
	} else {
		src.Title = defaultSourceTitle(src.Kind, src.Value)
	}
	a.mu.Lock()
	if src.RefreshHours == 0 {
		src.RefreshHours = clampRefreshHours(a.state.RefreshHoursDef)
	}
	// 1. Такая же подписка уже есть?
	if src.Kind == "url" {
		for _, s := range a.state.Sources {
			if s != nil && s.Kind == "url" && sameSubscription(s.Value, src.Value) {
				a.mu.Unlock()
				return nil, 0, 0, errDuplicateSub
			}
		}
	}
	inPool := a.poolIDsLocked()
	a.mu.Unlock()

	var (
		nodes    []*Node
		detected string
		info     *subUserinfo
		err      error
		added    int
		skipped  int
	)

	if src.Kind == "links" {
		// 2. РР· набора ссылок оставляем только С‚Рµ, которых РµС‰С‘ нет в пуле.
		all := parseLinks(src.Value)
		if len(all) == 0 {
			return nil, 0, 0, errors.New("не найдено поддерживаемых ссылок (vless / vmess / trojan / ss / hysteria2)")
		}
		fresh := make([]*Node, 0, len(all))
		raws := make([]string, 0, len(all))
		for _, n := range all {
			if inPool[n.ID] {
				skipped++
				continue
			}
			fresh = append(fresh, n)
			raws = append(raws, n.Raw)
		}
		if len(fresh) == 0 {
			return nil, 0, skipped, errDuplicateServers
		}
		src.Value = strings.Join(raws, "\n")
		nodes = fresh
	} else {
		nodes, detected, info, err = a.fetchSource(ctx, src)
		if err == nil && !src.TitleManual && detected != "" {
			src.Title = detected
		}
		if err == nil {
			added = len(nodes)
		}
	}

	a.mu.Lock()
	if err != nil {
		src.Error = err.Error()
	} else {
		a.setSourceNodesLocked(src, nodes)
		src.Userinfo = info
	}
	a.state.Sources = append(a.state.Sources, src)
	a.rebuildPoolLocked()
	a.persistLocked()
	a.mu.Unlock()

	if err == nil {
		added = len(nodes)
		a.requestApply()
		a.requestCheck()
	}
	return src, added, skipped, err
}

func (a *App) refreshSource(ctx context.Context, id string) error {
	a.mu.Lock()
	s := sourceByID(a.state.Sources, id)
	if s == nil {
		a.mu.Unlock()
		return errors.New("источник не найден")
	}
	cp := *s
	a.mu.Unlock()

	nodes, detected, info, err := a.fetchSource(ctx, &cp)

	a.mu.Lock()
	s = sourceByID(a.state.Sources, id)
	if s == nil {
		a.mu.Unlock()
		return errors.New("источник удалён")
	}
	if s.Value != cp.Value {
		// Пока шла загрузка, ссылку источника поменяли — результат старый, не применяем.
		a.mu.Unlock()
		return errors.New("источник изменён во время обновления")
	}
	if err != nil {
		s.Error = err.Error()
		a.persistLocked()
		a.mu.Unlock()
		return err
	}
	if !s.TitleManual && detected != "" {
		s.Title = detected
	}
	s.Userinfo = info
	old := make(map[string]*Node, len(a.state.Nodes))
	for _, n := range a.state.Nodes {
		old[n.ID] = n
	}
	for _, n := range nodes {
		if p, ok := old[n.ID]; ok {
			n.Status, n.Latency, n.LastErr, n.Checked = p.Status, p.Latency, p.LastErr, p.Checked
		}
	}
	a.setSourceNodesLocked(s, nodes)
	a.rebuildPoolLocked()
	a.persistLocked()
	a.mu.Unlock()

	a.requestApply()
	a.requestCheck()
	return nil
}

// refreshDueSources обновляет URL-подписки по их refresh_hours (или глобальному дефолту).
func (a *App) refreshDueSources(ctx context.Context) {
	a.mu.Lock()
	if a.refreshing {
		a.mu.Unlock()
		return
	}
	defHours := clampRefreshHours(a.state.RefreshHoursDef)
	var due []string
	for _, s := range a.state.Sources {
		if s == nil || !s.Enabled || s.Kind != "url" || !s.autoOn() {
			continue
		}
		hours := s.RefreshHours
		if hours <= 0 {
			hours = defHours
		}
		last := s.UpdatedAt
		if last == 0 || time.Since(time.Unix(last, 0)) >= time.Duration(clampRefreshHours(hours))*time.Hour {
			due = append(due, s.ID)
		}
	}
	if len(due) > 0 {
		a.refreshing = true
	}
	a.mu.Unlock()
	if len(due) == 0 {
		return
	}
	defer func() {
		a.mu.Lock()
		a.refreshing = false
		a.mu.Unlock()
	}()
	for _, id := range due {
		rctx, cancel := context.WithTimeout(ctx, 45*time.Second)
		if err := a.refreshSource(rctx, id); err != nil {
			log.Printf("обновление источника %s: %v", id, err)
		}
		cancel()
	}
}

func (a *App) sourceIDs() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]string, 0, len(a.state.Sources))
	for _, s := range a.state.Sources {
		if s != nil {
			out = append(out, s.ID)
		}
	}
	return out
}

// --- HTTP ---

func (a *App) sourcesSnapshot() []Source {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]Source, 0, len(a.state.Sources))
	for _, s := range a.state.Sources {
		if s == nil {
			continue
		}
		c := *s
		c.NodesCount = len(a.srcNodes[c.ID])
		out = append(out, c)
	}
	return out
}

func (a *App) handleSourcesList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		a.handleSourceAdd(w, r)
		return
	}
	list := a.sourcesSnapshot()
	total := 0
	for _, s := range list {
		if s.Enabled {
			total += s.NodesCount
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"sources": list, "nodes_total": total})
}

func (a *App) handleSourceAdd(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Kind         string `json:"kind"`
		Value        string `json:"value"`
		Title        string `json:"title"`
		HWID         string `json:"hwid"`
		HWIDOff      bool   `json:"hwid_off"`
		UA           string `json:"ua"`
		RefreshHours int    `json:"refresh_hours"`
	}
	if !jsonPost(w, r, &body) {
		return
	}
	if body.RefreshHours != 0 && (body.RefreshHours < minRefreshHours || body.RefreshHours > maxRefreshHours) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "refresh_hours: допустимо 1..168 часов"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	src, added, skipped, err := a.addSource(ctx, body.Kind, body.Value, body.Title, body.HWID, body.HWIDOff, body.UA)
	if src == nil {
		code := http.StatusBadRequest
		if errors.Is(err, errDuplicateSub) || errors.Is(err, errDuplicateServers) {
			code = http.StatusConflict
		}
		writeJSON(w, code, map[string]string{"error": err.Error()})
		return
	}
	if body.RefreshHours != 0 {
		a.mu.Lock()
		if s := sourceByID(a.state.Sources, src.ID); s != nil {
			s.RefreshHours = body.RefreshHours
			src.RefreshHours = body.RefreshHours
			a.persistLocked()
		}
		a.mu.Unlock()
	}
	writeJSON(w, http.StatusOK, sourceAddResult{Source: src, OK: true, Added: added, Skipped: skipped})
}

// sourceAddResult — ответ добавления источника: поля источника + статистика дедупа.
type sourceAddResult struct {
	*Source
	OK      bool `json:"ok"`
	Added   int  `json:"added"`
	Skipped int  `json:"skipped"`
}

func (a *App) handleSourceUpdate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID           string  `json:"id"`
		Value        *string `json:"value"`
		Title        *string `json:"title"`
		Enabled      *bool   `json:"enabled"`
		RefreshHours *int    `json:"refresh_hours"`
		AutoRefresh  *bool   `json:"auto_refresh"`
		HWID         *string `json:"hwid"`
		HWIDOff      *bool   `json:"hwid_off"`
		UA           *string `json:"ua"`
	}
	if !jsonPost(w, r, &body) {
		return
	}
	if body.RefreshHours != nil && (*body.RefreshHours < minRefreshHours || *body.RefreshHours > maxRefreshHours) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "refresh_hours: допустимо 1..168 часов"})
		return
	}
	a.mu.Lock()
	s := sourceByID(a.state.Sources, body.ID)
	if s == nil {
		a.mu.Unlock()
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "источник не найден"})
		return
	}
	if body.Title != nil {
		if t := strings.TrimSpace(*body.Title); t != "" {
			s.Title = t
			s.TitleManual = true
		}
	}
	valueChanged := false
	if body.Value != nil && strings.TrimSpace(*body.Value) != s.Value {
		s.Value = strings.TrimSpace(*body.Value)
		valueChanged = true
	}
	if body.RefreshHours != nil {
		s.RefreshHours = *body.RefreshHours
	}
	if body.AutoRefresh != nil {
		v := *body.AutoRefresh
		s.AutoRefresh = &v
	}
	hwidChanged := false
	if body.HWID != nil && strings.TrimSpace(*body.HWID) != s.HWID {
		s.HWID = strings.TrimSpace(*body.HWID)
		hwidChanged = s.Kind == "url"
	}
	if body.UA != nil {
		s.UA = strings.TrimSpace(*body.UA)
	}
	if body.HWIDOff != nil && *body.HWIDOff != s.HWIDOff {
		s.HWIDOff = *body.HWIDOff
		hwidChanged = s.Kind == "url"
	}
	if body.Enabled != nil {
		s.Enabled = *body.Enabled
	}
	needRefresh := valueChanged || hwidChanged || (body.Enabled != nil && *body.Enabled && s.Kind == "url" && len(a.srcNodes[s.ID]) == 0)
	needRebuild := body.Enabled != nil || valueChanged
	if valueChanged && !s.TitleManual {
		s.Title = defaultSourceTitle(s.Kind, s.Value)
	}
	cp := *s
	a.mu.Unlock()

	if needRefresh {
		ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
		err := a.refreshSource(ctx, cp.ID)
		cancel()
		if err != nil && cp.Value == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
	} else if needRebuild {
		a.mu.Lock()
		a.rebuildPoolLocked()
		a.persistLocked()
		a.mu.Unlock()
		a.requestApply()
	}

	a.mu.Lock()
	if cur := sourceByID(a.state.Sources, body.ID); cur != nil {
		cp = *cur
	}
	cp.NodesCount = len(a.srcNodes[cp.ID])
	a.persistLocked()
	a.mu.Unlock()
	writeJSON(w, http.StatusOK, cp)
}

// handleSourcesReorder сохраняет порядок источников (перетаскивание в UI).
func (a *App) handleSourcesReorder(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Order []string `json:"order"`
	}
	if !jsonPost(w, r, &body) {
		return
	}
	a.mu.Lock()
	list := make([]*Source, 0, len(a.state.Sources))
	seen := make(map[string]bool, len(body.Order))
	for _, id := range body.Order {
		if s := sourceByID(a.state.Sources, id); s != nil && !seen[id] {
			list = append(list, s)
			seen[id] = true
		}
	}
	// то, чего не было в запросе, оставляем в конце
	for _, s := range a.state.Sources {
		if s != nil && !seen[s.ID] {
			list = append(list, s)
		}
	}
	a.state.Sources = list
	a.rebuildPoolLocked()
	a.persistLocked()
	a.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *App) handleSourceDelete(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID string `json:"id"`
	}
	if !jsonPost(w, r, &body) {
		return
	}
	a.mu.Lock()
	s := sourceByID(a.state.Sources, body.ID)
	if s == nil {
		a.mu.Unlock()
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "источник не найден"})
		return
	}
	kept := a.state.Sources[:0]
	for _, x := range a.state.Sources {
		if x != nil && x.ID != body.ID {
			kept = append(kept, x)
		}
	}
	a.state.Sources = kept
	removed := 0
	for _, n := range a.srcNodes[body.ID] {
		if n != nil {
			delete(a.state.NodeMeta, n.ID)
			delete(a.state.FailUntil, n.ID)
			delete(a.state.Excluded, n.ID)
			removed++
		}
	}
	delete(a.srcNodes, body.ID)
	a.rebuildPoolLocked()
	a.persistLocked()
	a.mu.Unlock()

	a.requestApply()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": body.ID, "nodes_removed": removed})
}

func (a *App) handleSourceRefresh(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID string `json:"id"`
	}
	if !jsonPost(w, r, &body) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	if err := a.refreshSource(ctx, body.ID); err != nil {
		a.mu.Lock()
		s := sourceByID(a.state.Sources, body.ID)
		out := map[string]any{"ok": false, "error": err.Error()}
		if s != nil {
			c := *s
			c.NodesCount = len(a.srcNodes[c.ID])
			out["source"] = c
		}
		a.mu.Unlock()
		writeJSON(w, http.StatusBadGateway, out)
		return
	}
	a.mu.Lock()
	s := sourceByID(a.state.Sources, body.ID)
	out := map[string]any{"ok": true}
	if s != nil {
		c := *s
		c.NodesCount = len(a.srcNodes[c.ID])
		out["source"] = c
	}
	a.mu.Unlock()
	writeJSON(w, http.StatusOK, out)
}

// handleCoreReload — POST /api/core/reload: перечитать все источники и
// перезапустить ядро на текущем узле.
func (a *App) handleCoreReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "нужен POST"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 150*time.Second)
	defer cancel()
	refreshed, failed := 0, 0
	var errs []string
	for _, id := range a.sourceIDs() {
		if err := a.refreshSource(ctx, id); err != nil {
			failed++
			errs = append(errs, err.Error())
			continue
		}
		refreshed++
	}
	a.requestApply()
	log.Printf("ядро перезапущено вручную: источников обновлено %d, ошибок %d", refreshed, failed)
	out := map[string]any{"ok": true, "refreshed": refreshed, "failed": failed}
	if len(errs) > 0 {
		out["errors"] = errs
	}
	writeJSON(w, http.StatusOK, out)
}
