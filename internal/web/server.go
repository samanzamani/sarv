// Package web serves the optional control panel: a self-contained HTTP server
// (independent from the host's Apache/Nginx/OLS) with a JSON API and an
// embedded static frontend.
package web

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/samanzamani/sarv/internal/config"
	"github.com/samanzamani/sarv/internal/quarantine"
	"github.com/samanzamani/sarv/internal/store"
)

//go:embed static
var staticFS embed.FS

// Hooks let the panel trigger actions owned by the main process.
type Hooks struct {
	StartScan  func(kind string) error // "manual" | "full" | "quick"
	ScanStatus func() map[string]any
	TestNotify func() error
	SaveConfig func(mutate func(*config.Config)) error
}

type Server struct {
	Cfg   *config.Config
	Store *store.Store
	Quar  *quarantine.Manager
	Hooks Hooks

	mu       sync.Mutex
	sessions map[string]time.Time
}

const sessionTTL = 12 * time.Hour

func New(cfg *config.Config, st *store.Store, q *quarantine.Manager, hooks Hooks) *Server {
	return &Server{Cfg: cfg, Store: st, Quar: q, Hooks: hooks, sessions: map[string]time.Time{}}
}

// ListenAndServe blocks serving the panel.
func (s *Server) ListenAndServe() error {
	mux := s.routes()
	srv := &http.Server{
		Addr:              s.Cfg.Web.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("web: panel listening on %s", s.Cfg.Web.Listen)
	if s.Cfg.Web.TLSCert != "" && s.Cfg.Web.TLSKey != "" {
		return srv.ListenAndServeTLS(s.Cfg.Web.TLSCert, s.Cfg.Web.TLSKey)
	}
	return srv.ListenAndServe()
}

func (s *Server) routes() *http.ServeMux {
	mux := http.NewServeMux()
	static, _ := fs.Sub(staticFS, "static")
	mux.Handle("/", http.FileServer(http.FS(static)))

	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/logout", s.auth(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("sarv_session"); err == nil {
			s.mu.Lock()
			delete(s.sessions, c.Value)
			s.mu.Unlock()
		}
		writeJSON(w, map[string]bool{"ok": true})
	}))
	mux.HandleFunc("GET /api/overview", s.auth(s.handleOverview))
	mux.HandleFunc("GET /api/findings", s.auth(s.handleFindings))
	mux.HandleFunc("POST /api/findings/{id}/{action}", s.auth(s.handleFindingAction))
	mux.HandleFunc("GET /api/quarantine", s.auth(s.handleQuarList))
	mux.HandleFunc("POST /api/quarantine/{id}/{action}", s.auth(s.handleQuarAction))
	mux.HandleFunc("POST /api/scan", s.auth(s.handleScan))
	mux.HandleFunc("GET /api/scan/status", s.auth(s.handleScanStatus))
	mux.HandleFunc("GET /api/advice", s.auth(s.handleAdvice))
	mux.HandleFunc("POST /api/advice/{id}/{state}", s.auth(s.handleAdviceState))
	mux.HandleFunc("GET /api/settings", s.auth(s.handleGetSettings))
	mux.HandleFunc("POST /api/settings", s.auth(s.handleSetSettings))
	mux.HandleFunc("POST /api/notify/test", s.auth(s.handleTestNotify))
	return mux
}

// --- auth ---

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct{ Username, Password string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpErr(w, 400, "bad request")
		return
	}
	time.Sleep(300 * time.Millisecond) // slow brute force
	if s.Cfg.Web.PasswordHash == "" {
		httpErr(w, 403, "no panel password set — run: sarv web set-password")
		return
	}
	if req.Username != s.Cfg.Web.Username ||
		bcrypt.CompareHashAndPassword([]byte(s.Cfg.Web.PasswordHash), []byte(req.Password)) != nil {
		httpErr(w, 401, "invalid credentials")
		return
	}
	tok := randToken()
	s.mu.Lock()
	s.sessions[tok] = time.Now().Add(sessionTTL)
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: "sarv_session", Value: tok, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteStrictMode, MaxAge: int(sessionTTL.Seconds()),
	})
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("sarv_session")
		if err != nil {
			httpErr(w, 401, "unauthorized")
			return
		}
		s.mu.Lock()
		exp, ok := s.sessions[c.Value]
		if ok && time.Now().After(exp) {
			delete(s.sessions, c.Value)
			ok = false
		}
		s.mu.Unlock()
		if !ok {
			httpErr(w, 401, "unauthorized")
			return
		}
		next(w, r)
	}
}

// --- handlers ---

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	open, _ := s.Store.CountFindings(store.StatusOpen)
	quarantined, _ := s.Store.CountFindings(store.StatusQuarantined)
	scans, _ := s.Store.RecentScans(10)
	adv, _ := s.Store.AdviceList()
	openAdvice := 0
	for _, a := range adv {
		if a.State == "open" {
			openAdvice++
		}
	}
	status := map[string]any{}
	if s.Hooks.ScanStatus != nil {
		status = s.Hooks.ScanStatus()
	}
	writeJSON(w, map[string]any{
		"open_findings": open,
		"quarantined":   quarantined,
		"open_advice":   openAdvice,
		"recent_scans":  scans,
		"scan_status":   status,
	})
}

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	list, err := s.Store.Findings(status, limit)
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	writeJSON(w, list)
}

func (s *Server) handleFindingAction(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		httpErr(w, 400, "bad id")
		return
	}
	f, err := s.Store.GetFinding(id)
	if err != nil {
		httpErr(w, 404, err.Error())
		return
	}
	switch r.PathValue("action") {
	case "quarantine":
		if _, err := s.Quar.Add(f.Path, f.SHA256, f.Rule, f.ID); err != nil {
			httpErr(w, 500, err.Error())
			return
		}
		_ = s.Store.UpdateFindingStatus(id, store.StatusQuarantined)
	case "ignore":
		_ = s.Store.UpdateFindingStatus(id, store.StatusIgnored)
	case "reopen":
		_ = s.Store.UpdateFindingStatus(id, store.StatusOpen)
	case "resolve":
		_ = s.Store.UpdateFindingStatus(id, store.StatusResolved)
	default:
		httpErr(w, 400, "unknown action")
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) handleQuarList(w http.ResponseWriter, r *http.Request) {
	list, err := s.Quar.List()
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	writeJSON(w, list)
}

func (s *Server) handleQuarAction(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	switch r.PathValue("action") {
	case "restore":
		meta, err := s.Quar.Restore(id)
		if err != nil {
			httpErr(w, 500, err.Error())
			return
		}
		if meta.FindingID > 0 {
			_ = s.Store.UpdateFindingStatus(meta.FindingID, store.StatusOpen)
		}
	case "delete":
		if err := s.Quar.Delete(id); err != nil {
			httpErr(w, 500, err.Error())
			return
		}
	default:
		httpErr(w, 400, "unknown action")
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if s.Hooks.StartScan == nil {
		httpErr(w, 501, "scanning unavailable in this mode")
		return
	}
	kind := r.URL.Query().Get("kind")
	if kind == "" {
		kind = "manual"
	}
	if err := s.Hooks.StartScan(kind); err != nil {
		httpErr(w, 409, err.Error())
		return
	}
	writeJSON(w, map[string]bool{"started": true})
}

func (s *Server) handleScanStatus(w http.ResponseWriter, r *http.Request) {
	if s.Hooks.ScanStatus == nil {
		writeJSON(w, map[string]any{})
		return
	}
	writeJSON(w, s.Hooks.ScanStatus())
}

func (s *Server) handleAdvice(w http.ResponseWriter, r *http.Request) {
	list, err := s.Store.AdviceList()
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	writeJSON(w, list)
}

func (s *Server) handleAdviceState(w http.ResponseWriter, r *http.Request) {
	state := r.PathValue("state")
	if state != "open" && state != "done" && state != "dismissed" {
		httpErr(w, 400, "bad state")
		return
	}
	if err := s.Store.SetAdviceState(r.PathValue("id"), state); err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

// settingsView is the editable subset of config exposed to the panel.
type settingsView struct {
	ScanPaths     []string `json:"scan_paths"`
	QuarantineAuto string  `json:"quarantine_auto"`
	ScheduleQuick string   `json:"schedule_quick"`
	ScheduleFull  string   `json:"schedule_full"`
	TgEnabled     bool     `json:"tg_enabled"`
	TgBotToken    string   `json:"tg_bot_token"`
	TgChatID      string   `json:"tg_chat_id"`
	TgProxyURL    string   `json:"tg_proxy_url"`
}

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	c := s.Cfg
	tok := c.Telegram.BotToken
	if len(tok) > 8 {
		tok = tok[:8] + "…" // don't echo the full secret back
	}
	writeJSON(w, settingsView{
		ScanPaths: c.ScanPaths, QuarantineAuto: c.Quarantine.Auto,
		ScheduleQuick: c.Schedule.Quick, ScheduleFull: c.Schedule.Full,
		TgEnabled: c.Telegram.Enabled, TgBotToken: tok,
		TgChatID: c.Telegram.ChatID, TgProxyURL: c.Telegram.ProxyURL,
	})
}

func (s *Server) handleSetSettings(w http.ResponseWriter, r *http.Request) {
	if s.Hooks.SaveConfig == nil {
		httpErr(w, 501, "config editing unavailable")
		return
	}
	var v settingsView
	if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	err := s.Hooks.SaveConfig(func(c *config.Config) {
		if len(v.ScanPaths) > 0 {
			c.ScanPaths = v.ScanPaths
		}
		if v.QuarantineAuto != "" {
			c.Quarantine.Auto = v.QuarantineAuto
		}
		c.Schedule.Quick = v.ScheduleQuick
		c.Schedule.Full = v.ScheduleFull
		c.Telegram.Enabled = v.TgEnabled
		if v.TgBotToken != "" && !strings.HasSuffix(v.TgBotToken, "…") {
			c.Telegram.BotToken = v.TgBotToken
		}
		c.Telegram.ChatID = v.TgChatID
		c.Telegram.ProxyURL = v.TgProxyURL
	})
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) handleTestNotify(w http.ResponseWriter, r *http.Request) {
	if s.Hooks.TestNotify == nil {
		httpErr(w, 501, "notify unavailable")
		return
	}
	if err := s.Hooks.TestNotify(); err != nil {
		httpErr(w, 502, err.Error())
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

// --- helpers ---

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func httpErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func randToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
