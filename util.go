package main

import (
	"crypto/rand"
	"fmt"
	"strings"
)

// newHWID — короткий идентификатор устройства, как у клиентов Happ/Hiddify:
// 8 случайных байт в hex (16 символов). Панели подписок ожидают именно такой.
func newHWID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	return fmt.Sprintf("%x", b)
}

func ellipsis(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

func shortErr(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 && i+2 < len(s) {
		s = s[i+2:]
	}
	return ellipsis(s, 120)
}
