package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var httpClient = &http.Client{Timeout: 25 * time.Second}

// withHWID добавляет hwid в адрес подписки (если его там ещё нет).
func withHWID(u, hwid string) string {
	hwid = strings.TrimSpace(hwid)
	if hwid == "" {
		return u
	}
	parsed, err := url.Parse(u)
	if err != nil {
		return u
	}
	q := parsed.Query()
	if strings.TrimSpace(q.Get("hwid")) == "" {
		q.Set("hwid", hwid)
		parsed.RawQuery = q.Encode()
	}
	return parsed.String()
}

// applyHWID — единое место подстановки hwid: адрес + заголовок x-hwid.
func applyHWID(req *http.Request, hwid string) {
	hwid = strings.TrimSpace(hwid)
	if hwid == "" {
		return
	}
	req.Header.Set("x-hwid", hwid)
	req.Header.Set("X-HWID", hwid)
}

// resolveSource принимает URL подписки или готовый список ссылок.
func resolveSource(ctx context.Context, src, hwid string) (string, error) {
	s := strings.TrimSpace(src)
	if s == "" {
		return "", errors.New("пустой источник")
	}
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		return fetchSubscription(ctx, s, hwid)
	}
	return s, nil
}

func fetchSubscription(ctx context.Context, u, hwid string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, withHWID(u, hwid), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36")
	req.Header.Set("Accept", "*/*")
	applyHWID(req, hwid)
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("загрузка подписки: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("подписка: HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return "", fmt.Errorf("чтение подписки: %w", err)
	}
	text := string(b)
	if strings.Contains(text, "proxies:") && !strings.Contains(text, "://") {
		return "", errors.New("подписка в формате Clash/YAML не поддерживается, нужен base64-список ссылок")
	}
	return maybeBase64(text), nil
}

func maybeBase64(s string) string {
	if strings.Contains(s, "://") {
		return s
	}
	t := strings.NewReplacer("\n", "", "\r", "", " ", "", "\t", "").Replace(strings.TrimSpace(s))
	if t == "" {
		return s
	}
	for _, e := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := e.DecodeString(t); err == nil && bytes.Contains(b, []byte("://")) {
			return string(b)
		}
	}
	return s
}
