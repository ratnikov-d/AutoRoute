package main

import (
	"log"
	"net/http"
	"strings"
	"time"
)

// Настройки, которые живут в state.json рядом с узлами (обратная совместимость:
// старые state.json читаются, новые поля просто пустые).

const (
	minCheckInterval = 15
	maxCheckInterval = 3600
	minRefreshHours  = 1
	maxRefreshHours  = 168
)

func clampRefreshHours(h int) int {
	if h < minRefreshHours || h > maxRefreshHours {
		return 6
	}
	return h
}

// socksOn — включён ли SOCKS-inbound (нужен для проверки туннеля).
func (a *App) socksOn() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.state.SocksEnabled
}

// nodeView — узел для API: поля Node + вычисленные признаки и метаданные.
type nodeView struct {
	Node
	Disabled      bool   `json:"disabled"`
	Reason        string `json:"disabled_reason,omitempty"`
	Fails         int    `json:"fails"`
	Oks           int    `json:"oks"`
	ExitIP        string `json:"exit_ip,omitempty"`
	ExitCountry   string `json:"exit_country,omitempty"`
	ExitCheckedAt int64  `json:"exit_checked_at,omitempty"`
	SourceID      string `json:"source_id,omitempty"`
	SourceTitle   string `json:"source_title,omitempty"`
	Primary       bool   `json:"primary,omitempty"`
}

func (a *App) nodeViewsLocked() []nodeView {
	out := make([]nodeView, 0, len(a.state.Nodes))
	for _, n := range a.state.Nodes {
		if n == nil {
			continue
		}
		reason := a.disabledReasonLocked(n)
		m := a.state.NodeMeta[n.ID]
		v := nodeView{
			Node:     *n,
			Disabled: reason != "",
			Reason:   reason,
			Primary:  n.ID == a.state.Primary && a.state.Primary != "",
		}
		if m != nil {
			v.Fails = m.Fails
			v.Oks = m.Oks
			v.ExitIP = m.ExitIP
			v.ExitCountry = m.ExitCountry
			v.ExitCheckedAt = m.ExitCheckedAt
			v.SourceID = m.SourceID
			if s := sourceByID(a.state.Sources, m.SourceID); s != nil {
				v.SourceTitle = s.Title
			}
		}
		out = append(out, v)
	}
	return out
}

// disabledReasonLocked: "manual" — узел выключен вручную, "" — активен.
func (a *App) disabledReasonLocked(n *Node) string {
	if a.state.Excluded[n.ID] {
		return "manual"
	}
	return ""
}

func (a *App) nodeDisabledLocked(n *Node) bool {
	return a.disabledReasonLocked(n) != ""
}

// setCheckInterval сохраняет период и просит цикл проверки пересоздать ticker.
func (a *App) setCheckInterval(sec int) {
	sec = clampInterval(sec)
	a.mu.Lock()
	changed := int(a.checkDur.Seconds()) != sec
	a.checkDur = time.Duration(sec) * time.Second
	a.state.CheckInterval = sec
	a.persistLocked()
	a.mu.Unlock()

	if changed {
		// Пересоздаёт ticker только при реальном изменении периода.
		select {
		case a.intervalCh <- struct{}{}:
		default:
		}
		log.Printf("период проверки: %d с", sec)
	}
}

func clampInterval(sec int) int {
	if sec < minCheckInterval {
		return minCheckInterval
	}
	if sec > maxCheckInterval {
		return maxCheckInterval
	}
	return sec
}

func (a *App) handleSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		a.mu.Lock()
		st := map[string]any{
			"check_interval":       int(a.checkDur.Seconds()),
			"excluded":             a.state.Excluded,
			"max_latency_ms":       a.maxLatencyLocked(),
			"fail_threshold":       a.failThresholdLocked(),
			"return_to_primary":    a.state.ReturnToPrimary,
			"socks_enabled":        a.state.SocksEnabled,
			"core_autoupdate":      a.state.CoreAutoupdate,
			"hwid":                 a.state.HWID,
			"ua":                   a.state.UA,
			"hwid_off":             a.state.HWIDOff,
			"latency_url":          latencyURL(a.state.LatencyURL),
			"refresh_hours_default": a.state.RefreshHoursDef,
			"auto_delta_ms":         clampAutoDeltaMS(a.state.AutoDeltaMS),
			"latency_every_min":     clampLatencyMin(a.state.LatencyMin),
		}
		a.mu.Unlock()
		writeJSON(w, http.StatusOK, st)
	case http.MethodPost:
		var body struct {
			CheckInterval   *int    `json:"check_interval"`
			MaxLatencyMS    *int    `json:"max_latency_ms"`
			FailThreshold   *int    `json:"fail_threshold"`
			ReturnToPrimary *bool   `json:"return_to_primary"`
			SocksEnabled    *bool   `json:"socks_enabled"`
			CoreAutoupdate  *bool   `json:"core_autoupdate"`
			HWID            *string `json:"hwid"`
			UA              *string `json:"ua"`
			HWIDOff         *bool   `json:"hwid_off"`
			LatencyURL      *string `json:"latency_url"`
			RefreshHoursDef *int    `json:"refresh_hours_default"`
			AutoDeltaMS     *int    `json:"auto_delta_ms"`
			LatencyMin      *int    `json:"latency_every_min"`
		}
		if !jsonPost(w, r, &body) {
			return
		}
		if body.CheckInterval == nil && body.MaxLatencyMS == nil && body.HWID == nil && body.HWIDOff == nil && body.LatencyURL == nil && body.AutoDeltaMS == nil && body.LatencyMin == nil && body.UA == nil &&
			body.FailThreshold == nil && body.ReturnToPrimary == nil && body.SocksEnabled == nil &&
			body.CoreAutoupdate == nil && body.RefreshHoursDef == nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "нечего сохранять"})
			return
		}
		if body.CheckInterval != nil && (*body.CheckInterval < minCheckInterval || *body.CheckInterval > maxCheckInterval) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "check_interval: допустимо 15..3600 секунд"})
			return
		}
		if body.MaxLatencyMS != nil && (*body.MaxLatencyMS < minMaxLatencyMS || *body.MaxLatencyMS > maxMaxLatencyMS) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "max_latency_ms: допустимо 50..10000"})
			return
		}
		if body.FailThreshold != nil && (*body.FailThreshold < minFailThreshold || *body.FailThreshold > maxFailThreshold) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "fail_threshold: допустимо 1..10"})
			return
		}
		if body.RefreshHoursDef != nil && (*body.RefreshHoursDef < minRefreshHours || *body.RefreshHoursDef > maxRefreshHours) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "refresh_hours_default: допустимо 1..168 часов"})
			return
		}

		socksChanged := false
		a.mu.Lock()
		if body.MaxLatencyMS != nil {
			a.state.MaxLatencyMS = *body.MaxLatencyMS
		}
		if body.FailThreshold != nil {
			a.state.FailThreshold = *body.FailThreshold
		}
		if body.ReturnToPrimary != nil {
			a.state.ReturnToPrimary = *body.ReturnToPrimary
		}
		if body.RefreshHoursDef != nil {
			a.state.RefreshHoursDef = *body.RefreshHoursDef
		}
		if body.UA != nil {
			a.state.UA = strings.TrimSpace(*body.UA)
		}
		if body.HWID != nil {
			a.state.HWID = strings.TrimSpace(*body.HWID)
			a.state.HWIDAuto = false
		}
		if body.HWIDOff != nil {
			a.state.HWIDOff = *body.HWIDOff
		}
		if body.LatencyMin != nil {
			a.state.LatencyMin = clampLatencyMin(*body.LatencyMin)
		}
		if body.AutoDeltaMS != nil {
			a.state.AutoDeltaMS = clampAutoDeltaMS(*body.AutoDeltaMS)
		}
		if body.LatencyURL != nil {
			u := strings.TrimSpace(*body.LatencyURL)
			if u != "" && !isHTTPURL(u) {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Адрес проверки: нужен http:// или https://"})
				return
			}
			a.state.LatencyURL = u
		}
		if body.CoreAutoupdate != nil {
			a.state.CoreAutoupdate = *body.CoreAutoupdate
			if !*body.CoreAutoupdate {
				a.lastAutoUpd = 0
			}
		}
		if body.SocksEnabled != nil && *body.SocksEnabled != a.state.SocksEnabled {
			a.state.SocksEnabled = *body.SocksEnabled
			socksChanged = true
		}
		a.persistLocked()
		a.mu.Unlock()

		if socksChanged {
			a.core.SetSocksEnabled(*body.SocksEnabled)
			a.requestApply()
		}
		if body.CheckInterval != nil {
			a.setCheckInterval(clampInterval(*body.CheckInterval))
		}

		a.mu.Lock()
		resp := map[string]any{
			"ok":                    true,
			"check_interval":        int(a.checkDur.Seconds()),
			"max_latency_ms":        a.maxLatencyLocked(),
			"fail_threshold":        a.failThresholdLocked(),
			"return_to_primary":     a.state.ReturnToPrimary,
			"socks_enabled":         a.state.SocksEnabled,
			"core_autoupdate":       a.state.CoreAutoupdate,
			"hwid":                  a.state.HWID,
			"refresh_hours_default": a.state.RefreshHoursDef,
		}
		a.mu.Unlock()
		writeJSON(w, http.StatusOK, resp)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "нужен GET или POST"})
	}
}

func (a *App) handleNodeToggle(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID       string `json:"id"`
		Disabled *bool  `json:"disabled"`
	}
	if !jsonPost(w, r, &body) {
		return
	}
	if body.Disabled == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "нужно поле disabled"})
		return
	}

	a.mu.Lock()
	n := findNode(a.state.Nodes, body.ID)
	if n == nil {
		a.mu.Unlock()
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "узел не найден"})
		return
	}
	if a.state.Excluded == nil {
		a.state.Excluded = map[string]bool{}
	}
	if *body.Disabled {
		a.state.Excluded[n.ID] = true
	} else {
		delete(a.state.Excluded, n.ID)
	}
	reason := a.disabledReasonLocked(n)
	name := n.Name
	a.persistLocked()
	a.mu.Unlock()

	if *body.Disabled {
		log.Printf("узел отключён: %s", name)
	} else {
		log.Printf("узел включён: %s", name)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":              true,
		"id":              body.ID,
		"disabled":        reason != "",
		"disabled_reason": reason,
	})
}
