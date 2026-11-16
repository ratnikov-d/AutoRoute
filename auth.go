package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Авторизация на одного пользователя: PBKDF2-HMAC-SHA256, сессии в памяти,
// секрет для подписи токенов и хеш пароля — в /data/auth.json.

const (
	pbkdf2Iterations = 120000
	saltLen          = 16
	keyLen           = 32
	sessionCookie    = "autoroute_session"
	sessionTTL       = 7 * 24 * time.Hour
	minPasswordLen   = 8
	maxFailPerWindow = 10
	failWindow       = 5 * time.Minute
)

type authRecord struct {
	User      string `json:"user,omitempty"`
	Salt      string `json:"salt"`
	Hash      string `json:"hash"`
	Iter      int    `json:"iter"`
	Secret    string `json:"session_secret"`
	CreatedAt int64  `json:"created_at,omitempty"`
	UpdatedAt int64  `json:"updated_at,omitempty"`
}

const defaultUser = "admin"

type Auth struct {
	mu    sync.Mutex
	dir   string
	rec   authRecord
	sess  map[string]int64 // token -> unix-время истечения
	fails map[string][]int64
}

func NewAuth(dir string) *Auth {
	a := &Auth{
		dir:   dir,
		sess:  map[string]int64{},
		fails: map[string][]int64{},
	}
	a.load()
	return a
}

func (a *Auth) path() string { return filepath.Join(a.dir, "auth.json") }

func (a *Auth) load() {
	b, err := os.ReadFile(a.path())
	if err != nil {
		return
	}
	var rec authRecord
	if err := json.Unmarshal(b, &rec); err != nil {
		return
	}
	if rec.User == "" {
		// миграция со старых файлов без имени пользователя
		rec.User = defaultUser
	}
	a.mu.Lock()
	a.rec = rec
	a.mu.Unlock()
}

func (a *Auth) saveLocked() error {
	b, err := json.MarshalIndent(a.rec, "", "  ")
	if err != nil {
		return err
	}
	tmp := a.path() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, a.path())
}

// Enabled — пароль задан.
func (a *Auth) Enabled() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.rec.Hash != "" && a.rec.Salt != ""
}

// User — текущее имя пользователя (по умолчанию admin).
func (a *Auth) User() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.rec.User == "" {
		return defaultUser
	}
	return a.rec.User
}

func validUsername(s string) bool {
	if len(s) < 3 || len(s) > 32 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

// SetCredentials задаёт пользователя и пароль (PBKDF2-HMAC-SHA256).
func (a *Auth) SetCredentials(user, pw string) error {
	if user == "" {
		user = defaultUser
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	dk := pbkdf2SHA256([]byte(pw), salt, pbkdf2Iterations, keyLen)
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return err
	}
	now := time.Now().Unix()

	a.mu.Lock()
	defer a.mu.Unlock()
	a.rec = authRecord{
		User:      user,
		Salt:      base64.StdEncoding.EncodeToString(salt),
		Hash:      base64.StdEncoding.EncodeToString(dk),
		Iter:      pbkdf2Iterations,
		Secret:    base64.StdEncoding.EncodeToString(secret),
		CreatedAt: now,
		UpdatedAt: now,
	}
	return a.saveLocked()
}

// CheckCredentials сверяет имя пользователя и пароль (одинаковый ответ на оба промаха).
func (a *Auth) CheckCredentials(user, pw string) bool {
	a.mu.Lock()
	recUser := a.rec.User
	a.mu.Unlock()
	if recUser == "" {
		recUser = defaultUser
	}
	if user == "" {
		user = recUser
	}
	userOK := subtle.ConstantTimeCompare([]byte(user), []byte(recUser)) == 1
	pwOK := a.CheckPassword(pw)
	return userOK && pwOK
}

// CheckPassword проверяет пароль за постоянное время.
func (a *Auth) CheckPassword(pw string) bool {
	a.mu.Lock()
	rec := a.rec
	a.mu.Unlock()
	if rec.Hash == "" || rec.Salt == "" {
		return false
	}
	salt, err1 := base64.StdEncoding.DecodeString(rec.Salt)
	want, err2 := base64.StdEncoding.DecodeString(rec.Hash)
	if err1 != nil || err2 != nil || len(salt) == 0 || len(want) == 0 {
		return false
	}
	iter := rec.Iter
	if iter <= 0 {
		iter = pbkdf2Iterations
	}
	got := pbkdf2SHA256([]byte(pw), salt, iter, len(want))
	return subtle.ConstantTimeCompare(got, want) == 1
}

func (a *Auth) NewSession() (string, time.Time) {
	tok := make([]byte, 32)
	_, _ = rand.Read(tok)
	token := base64.RawURLEncoding.EncodeToString(tok)
	exp := time.Now().Add(sessionTTL)

	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now().Unix()
	for t, e := range a.sess {
		if e < now {
			delete(a.sess, t)
		}
	}
	a.sess[token] = exp.Unix()
	return token, exp
}

func (a *Auth) ValidSession(token string) bool {
	if token == "" {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	exp, ok := a.sess[token]
	if !ok {
		return false
	}
	if exp < time.Now().Unix() {
		delete(a.sess, token)
		return false
	}
	return true
}

func (a *Auth) DropSession(token string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.sess, token)
}

// DropAllSessions — после смены пароля.
func (a *Auth) DropAllSessions(except string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for t := range a.sess {
		if t != except {
			delete(a.sess, t)
		}
	}
}

// --- лимит попыток логина ---

func (a *Auth) tooManyFails(ip string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now().Unix()
	cut := now - int64(failWindow/time.Second)
	list := a.fails[ip]
	kept := list[:0]
	for _, t := range list {
		if t >= cut {
			kept = append(kept, t)
		}
	}
	if len(kept) == 0 {
		delete(a.fails, ip)
		return false
	}
	a.fails[ip] = kept
	return len(kept) >= maxFailPerWindow
}

func (a *Auth) noteFail(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.fails[ip] = append(a.fails[ip], time.Now().Unix())
}

func (a *Auth) clearFails(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.fails, ip)
}

// --- PBKDF2 ---

func pbkdf2SHA256(password, salt []byte, iter, length int) []byte {
	if iter < 1 {
		iter = 1
	}
	prf := hmac.New(sha256.New, password)
	hashLen := prf.Size()
	blocks := (length + hashLen - 1) / hashLen
	dk := make([]byte, 0, blocks*hashLen)
	u := make([]byte, hashLen)
	t := make([]byte, hashLen)
	var idx [4]byte
	for block := 1; block <= blocks; block++ {
		prf.Reset()
		prf.Write(salt)
		binary.BigEndian.PutUint32(idx[:], uint32(block))
		prf.Write(idx[:])
		u = prf.Sum(u[:0])
		copy(t, u)
		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(u[:0])
			for i := range t {
				t[i] ^= u[i]
			}
		}
		dk = append(dk, t...)
	}
	return dk[:length]
}

// --- HTTP ---

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func sessionToken(r *http.Request) string {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return ""
	}
	return c.Value
}

func setSessionCookie(w http.ResponseWriter, token string, exp time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  exp,
		MaxAge:   int(sessionTTL / time.Second),
	})
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}

// jsonPost проверяет метод и Content-Type, затем декодирует тело.
func jsonPost(w http.ResponseWriter, r *http.Request, dst any) bool {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "нужен POST"})
		return false
	}
	ct := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type")))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	if ct != "application/json" {
		writeJSON(w, http.StatusUnsupportedMediaType, map[string]string{"error": "нужен Content-Type: application/json"})
		return false
	}
	if dst == nil {
		return true
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(dst); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "плохой JSON: " + err.Error()})
		return false
	}
	return true
}

// authOnly защищает /api/*: сессия + корректный Content-Type для POST.
func (a *App) authOnly(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			ct := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type")))
			if i := strings.IndexByte(ct, ';'); i >= 0 {
				ct = strings.TrimSpace(ct[:i])
			}
			if ct != "application/json" {
				writeJSON(w, http.StatusUnsupportedMediaType, map[string]string{"error": "нужен Content-Type: application/json"})
				return
			}
		}
		if a.auth == nil || !a.auth.Enabled() {
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"error": "пароль не задан", "needs_setup": true,
			})
			return
		}
		if !a.auth.ValidSession(sessionToken(r)) {
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"error": "нужна авторизация", "needs_login": true,
			})
			return
		}
		h(w, r)
	}
}

func (a *App) handleAuthState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "нужен GET"})
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	needsSetup := a.auth == nil || !a.auth.Enabled()
	authed := a.auth != nil && a.auth.ValidSession(sessionToken(r))
	user := ""
	if a.auth != nil {
		user = a.auth.User()
	} else {
		user = defaultUser
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"needs_setup":   needsSetup,
		"authenticated": authed,
		"user":          user,
	})
}

func (a *App) handleSetup(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !jsonPost(w, r, &body) {
		return
	}
	if a.auth == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "авторизация недоступна"})
		return
	}
	if a.auth.Enabled() {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "пароль уже задан"})
		return
	}
	user := strings.TrimSpace(body.Username)
	if user == "" {
		user = defaultUser
	}
	if !validUsername(user) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "имя пользователя: 3–32 символа, буквы/цифры/._-"})
		return
	}
	pw := body.Password
	if len([]rune(pw)) < minPasswordLen {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "пароль короче 8 символов"})
		return
	}
	if err := a.auth.SetCredentials(user, pw); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "не удалось сохранить пароль: " + err.Error()})
		return
	}
	token, exp := a.auth.NewSession()
	setSessionCookie(w, token, exp)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "user": user})
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !jsonPost(w, r, &body) {
		return
	}
	if a.auth == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "авторизация недоступна"})
		return
	}
	if !a.auth.Enabled() {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "пароль не задан", "needs_setup": true})
		return
	}
	ip := clientIP(r)
	if a.auth.tooManyFails(ip) {
		w.Header().Set("Retry-After", "300")
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "слишком много попыток, подождите 5 минут"})
		return
	}
	if !a.auth.CheckCredentials(strings.TrimSpace(body.Username), body.Password) {
		a.auth.noteFail(ip)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "неверный пользователь или пароль"})
		return
	}
	a.auth.clearFails(ip)
	token, exp := a.auth.NewSession()
	setSessionCookie(w, token, exp)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "user": a.auth.User()})
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	if !jsonPost(w, r, nil) {
		return
	}
	if a.auth != nil {
		a.auth.DropSession(sessionToken(r))
	}
	clearSessionCookie(w)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *App) handlePassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Old      string `json:"old"`
		New      string `json:"new"`
		Username string `json:"username"`
	}
	if !jsonPost(w, r, &body) {
		return
	}
	if a.auth == nil || !a.auth.Enabled() {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "пароль не задан", "needs_setup": true})
		return
	}
	ip := clientIP(r)
	if a.auth.tooManyFails(ip) {
		w.Header().Set("Retry-After", "300")
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "слишком много попыток, подождите 5 минут"})
		return
	}
	if !a.auth.CheckPassword(body.Old) {
		a.auth.noteFail(ip)
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "старый пароль неверен"})
		return
	}
	if len([]rune(body.New)) < minPasswordLen {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "пароль короче 8 символов"})
		return
	}
	user := strings.TrimSpace(body.Username)
	if user == "" {
		user = a.auth.User()
	}
	if !validUsername(user) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "имя пользователя: 3–32 символа, буквы/цифры/._-"})
		return
	}
	a.auth.clearFails(ip)
	if err := a.auth.SetCredentials(user, body.New); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "не удалось сохранить пароль: " + err.Error()})
		return
	}
	// Текущая сессия остаётся валидной, остальные отзываем.
	a.auth.DropAllSessions(sessionToken(r))
	log.Printf("учётные данные веб-интерфейса изменены (пользователь %s)", user)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "user": user})
}
