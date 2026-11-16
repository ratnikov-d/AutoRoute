package main

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// coreversion.go — выбор и установка версии ядра Xray из официальных релизов.
// Бинарник живёт в /data/core/xray, рядом лежит installed.json с тегом версии.

const coreReleasesAPI = "https://api.github.com/repos/XTLS/Xray-core/releases?per_page=10"

type coreRelease struct {
	Tag        string `json:"tag"`
	Name       string `json:"name"`
	Published  int64  `json:"published"`
	Prerelease bool   `json:"prerelease"`
	Size       int64  `json:"size"`
	URL        string `json:"-"`
}

type coreInstalled struct {
	Tag         string `json:"tag"`
	InstalledAt int64  `json:"installed_at"`
}

var (
	releasesMu    sync.Mutex
	releasesCache []coreRelease
	releasesAt    time.Time
)

func coreDir(dir string) string { return filepath.Join(dir, "core") }

func coreBinPath(dir string) string { return filepath.Join(coreDir(dir), "xray") }

func installedFile(dir string) string { return filepath.Join(coreDir(dir), "installed.json") }

func readInstalled(dir string) coreInstalled {
	var out coreInstalled
	b, err := os.ReadFile(installedFile(dir))
	if err == nil {
		_ = json.Unmarshal(b, &out)
	}
	return out
}

func writeInstalled(dir string, in coreInstalled) {
	_ = os.MkdirAll(coreDir(dir), 0o755)
	b, _ := json.MarshalIndent(in, "", "  ")
	tmp := installedFile(dir) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err == nil {
		_ = os.Rename(tmp, installedFile(dir))
	}
}

// assetSuffix подбирает имя архива под архитектуру контейнера.
func assetSuffix() string {
	switch runtime.GOARCH {
	case "arm64":
		return "arm64-v8a"
	case "arm":
		return "arm32-v7a"
	case "386":
		return "32"
	default:
		return "64"
	}
}

type ghAsset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
	Size int64  `json:"size"`
}

type ghRelease struct {
	Tag         string    `json:"tag_name"`
	Name        string    `json:"name"`
	PublishedAt time.Time `json:"published_at"`
	Prerelease  bool      `json:"prerelease"`
	Assets      []ghAsset `json:"assets"`
}

// fetchReleases возвращает последние стабильные релизы (кэш 10 минут).
func (a *App) fetchReleases(ctx context.Context) ([]coreRelease, error) {
	releasesMu.Lock()
	if len(releasesCache) > 0 && time.Since(releasesAt) < 10*time.Minute {
		out := append([]coreRelease{}, releasesCache...)
		releasesMu.Unlock()
		return out, nil
	}
	releasesMu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, coreReleasesAPI, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "autoroute")
	cl := &http.Client{Timeout: 20 * time.Second}
	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github: HTTP %d", resp.StatusCode)
	}
	var raw []ghRelease
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&raw); err != nil {
		return nil, err
	}
	suffix := "Xray-linux-" + assetSuffix() + ".zip"
	out := make([]coreRelease, 0, len(raw))
	for _, r := range raw {
		if r.Prerelease {
			continue
		}
		rel := coreRelease{
			Tag:       strings.TrimPrefix(r.Tag, "v"),
			Name:      r.Name,
			Published: r.PublishedAt.Unix(),
		}
		for _, as := range r.Assets {
			if as.Name == suffix {
				rel.URL = as.URL
				rel.Size = as.Size
			}
		}
		if rel.URL == "" {
			continue
		}
		out = append(out, rel)
		if len(out) >= 5 {
			break
		}
	}
	if len(out) == 0 {
		return nil, errors.New("не найдено подходящих сборок Xray")
	}
	releasesMu.Lock()
	releasesCache = append([]coreRelease{}, out...)
	releasesAt = time.Now()
	releasesMu.Unlock()
	return out, nil
}

// bootProgress считает байты и раз в ~0.4 с сообщает процент.
type bootProgress struct {
	r     io.Reader
	total int64
	done  int64
	last  time.Time
	cb    func(done, total int64)
}

func (p *bootProgress) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	p.done += int64(n)
	if p.cb != nil && time.Since(p.last) > 400*time.Millisecond {
		p.last = time.Now()
		p.cb(p.done, p.total)
	}
	return n, err
}

// installVersion скачивает релиз, проверяет бинарник и атомарно подменяет ядро.
func (a *App) installVersion(ctx context.Context, rel coreRelease) error {
	if rel.URL == "" {
		return errors.New("у версии нет сборки под эту архитектуру")
	}
	if err := os.MkdirAll(coreDir(a.dir), 0o755); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rel.URL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "autoroute")
	cl := &http.Client{Timeout: 5 * time.Minute}
	resp, err := cl.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("скачивание: HTTP %d", resp.StatusCode)
	}
	tmpZip := filepath.Join(coreDir(a.dir), "xray-download.zip")
	f, err := os.Create(tmpZip)
	if err != nil {
		return err
	}
	src := &bootProgress{
		r:     io.LimitReader(resp.Body, 128<<20),
		total: resp.ContentLength,
		cb: func(done, total int64) {
			pct := 0
			if total > 0 {
				pct = int(done * 100 / total)
			}
			a.core.SetBoot("Загрузка ядра "+rel.Tag, pct)
		},
	}
	if _, err := io.Copy(f, src); err != nil {
		f.Close()
		_ = os.Remove(tmpZip)
		return err
	}
	f.Close()
	defer os.Remove(tmpZip)

	zr, err := zip.OpenReader(tmpZip)
	if err != nil {
		return err
	}
	defer zr.Close()
	return a.extractXray(zr.File, rel)
}

func (a *App) extractXray(files []*zip.File, rel coreRelease) error {
	var src *zip.File
	for _, f := range files {
		if strings.EqualFold(filepath.Base(f.Name), "xray") {
			src = f
			break
		}
	}
	if src == nil {
		return errors.New("в архиве нет бинарника xray")
	}
	tmp := filepath.Join(coreDir(a.dir), "xray.new")
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	rc, err := src.Open()
	if err != nil {
		out.Close()
		return err
	}
	_, err = io.Copy(out, io.LimitReader(rc, 64<<20))
	rc.Close()
	out.Close()
	if err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		return err
	}
	if _, err := a.core.SetBin(tmp); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("скачанный бинарник не запускается: %v", err)
	}
	if err := os.Rename(tmp, coreBinPath(a.dir)); err != nil {
		return err
	}
	if _, err := a.core.SetBin(coreBinPath(a.dir)); err != nil {
		return err
	}
	writeInstalled(a.dir, coreInstalled{Tag: rel.Tag, InstalledAt: time.Now().Unix()})
	a.core.SetBoot("", 0)
	a.requestApply()
	return nil
}

// bootCore ставит ядро, если в /data его нет: первый запуск, обновление
// образа без сохранения данных, повтор после container/remove.
// Скачивается самый свежий релиз XTLS; попытки повторяются, пока нет сети.
func (a *App) bootCore(ctx context.Context) {
	if a.core.Ready() {
		return
	}
	log.Print("ядро: бинарника нет, скачиваю свежий релиз")
	delays := []time.Duration{0, 5 * time.Second, 15 * time.Second, 30 * time.Second, time.Minute}
	for attempt := 0; ; attempt++ {
		if d := delays[min(attempt, len(delays)-1)]; d > 0 {
			a.core.SetBoot("Ядро: повтор через "+fmtSecs(d), 0)
			select {
			case <-ctx.Done():
				a.core.SetBoot("", 0)
				return
			case <-time.After(d):
			}
		}
		if a.core.Ready() {
			a.core.SetBoot("", 0)
			a.requestApply()
			return
		}
		rel, err := a.latestRelease(ctx)
		if err != nil {
			log.Printf("ядро: список релизов не получен: %v", err)
			a.core.SetBoot("Ядро: нет связи с GitHub", 0)
			continue
		}
		if err := a.installVersion(ctx, rel); err != nil {
			log.Printf("ядро: установка %s не удалась: %v", rel.Tag, err)
			a.core.SetBoot("Ядро: ошибка загрузки", 0)
			continue
		}
		log.Printf("ядро: Xray %s установлен в %s", rel.Tag, a.dir)
		a.core.SetBoot("", 0)
		a.requestApply()
		return
	}
}

// fmtSecs — короткая запись задержки для индикатора.
func fmtSecs(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%d с", int(d.Seconds()))
	}
	return fmt.Sprintf("%d мин", int(d.Minutes()))
}

func (a *App) latestRelease(ctx context.Context) (coreRelease, error) {
	list, err := a.fetchReleases(ctx)
	if err != nil {
		return coreRelease{}, err
	}
	if len(list) == 0 {
		return coreRelease{}, errors.New("список версий пуст")
	}
	return list[0], nil
}

// currentTag — тег установленной версии; для встроенного в образ ядра
// installed.json отсутствует, поэтому берём номер из вывода `xray version`.
func (a *App) currentTag() string {
	if tag := readInstalled(a.dir).Tag; tag != "" {
		return tag
	}
	ver := a.core.Info().Version
	fields := strings.Fields(ver)
	for _, f := range fields {
		if f == "" || !strings.Contains(f, ".") {
			continue
		}
		digits := true
		for _, r := range f {
			if (r < '0' || r > '9') && r != '.' {
				digits = false
				break
			}
		}
		if digits {
			return f
		}
	}
	return ""
}

// handleCoreVersions — GET /api/core/versions: последние 5 версий + текущая.
func (a *App) handleCoreVersions(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	list, err := a.fetchReleases(ctx)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	inst := readInstalled(a.dir)
	info := a.core.Info()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":        true,
		"current":   a.currentTag(),
		"runtime":   info.Version,
		"versions":  list,
		"installed": inst.InstalledAt,
	})
}

// handleCoreVersion — POST /api/core/version {"version":"26.11.9"}.
func (a *App) handleCoreVersion(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Version string `json:"version"`
	}
	if !jsonPost(w, r, &body) {
		return
	}
	tag := strings.TrimSpace(strings.TrimPrefix(body.Version, "v"))
	if tag == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "нужен version"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	list, err := a.fetchReleases(ctx)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	var rel *coreRelease
	for i := range list {
		if list[i].Tag == tag {
			rel = &list[i]
			break
		}
	}
	if rel == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "версия не найдена среди последних релизов"})
		return
	}
	if err := a.installVersion(ctx, *rel); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	log.Printf("ядро обновлено до %s", tag)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "version": tag, "runtime": a.core.Info().Version})
}

// handleCoreCheck — POST /api/core/check: сравнить текущую версию с последней.
func (a *App) handleCoreCheck(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	latest, err := a.latestRelease(ctx)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	cur := a.currentTag()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"current": cur,
		"latest":  latest.Tag,
		"update":  latest.Tag != cur,
		"runtime": a.core.Info().Version,
	})
}
