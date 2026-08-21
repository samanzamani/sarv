// Package notify sends alerts through the Telegram Bot API, with optional
// HTTP or SOCKS5 proxy support and burst aggregation.
package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"

	"github.com/samanzamani/sarv/internal/config"
	"github.com/samanzamani/sarv/internal/store"
)

type Telegram struct {
	cfg    config.TelegramConfig
	client *http.Client

	mu      sync.Mutex
	pending []string
	timer   *time.Timer
}

// NewTelegram builds a notifier; returns nil when disabled/unconfigured.
func NewTelegram(cfg config.TelegramConfig) (*Telegram, error) {
	if !cfg.Enabled || cfg.BotToken == "" || cfg.ChatID == "" {
		return nil, nil
	}
	transport := &http.Transport{}
	if cfg.ProxyURL != "" {
		u, err := url.Parse(cfg.ProxyURL)
		if err != nil {
			return nil, fmt.Errorf("proxy_url: %w", err)
		}
		switch u.Scheme {
		case "http", "https":
			transport.Proxy = http.ProxyURL(u)
		case "socks5", "socks5h":
			var auth *proxy.Auth
			if u.User != nil {
				pw, _ := u.User.Password()
				auth = &proxy.Auth{User: u.User.Username(), Password: pw}
			}
			dialer, err := proxy.SOCKS5("tcp", u.Host, auth, proxy.Direct)
			if err != nil {
				return nil, fmt.Errorf("socks5 proxy: %w", err)
			}
			if cd, ok := dialer.(proxy.ContextDialer); ok {
				transport.DialContext = cd.DialContext
			}
		default:
			return nil, fmt.Errorf("unsupported proxy scheme %q (use http:// or socks5://)", u.Scheme)
		}
	}
	return &Telegram{
		cfg:    cfg,
		client: &http.Client{Timeout: 30 * time.Second, Transport: transport},
	}, nil
}

// Send delivers one message immediately.
func (t *Telegram) Send(text string) error {
	body, _ := json.Marshal(map[string]any{
		"chat_id":    t.cfg.ChatID,
		"text":       text,
		"parse_mode": "HTML",
		"disable_web_page_preview": true,
	})
	resp, err := t.client.Post(
		"https://api.telegram.org/bot"+t.cfg.BotToken+"/sendMessage",
		"application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		var e struct {
			Description string `json:"description"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&e)
		return fmt.Errorf("telegram api %d: %s", resp.StatusCode, e.Description)
	}
	return nil
}

// NotifyFinding queues a finding alert; findings arriving within a short window
// are batched into a single message to avoid alert storms during large scans.
func (t *Telegram) NotifyFinding(f store.Finding) {
	line := fmt.Sprintf("• <b>%s</b> [%s]\n  <code>%s</code>\n  %s", f.Rule, f.Severity, f.Path, f.Detail)
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pending = append(t.pending, line)
	if t.timer == nil {
		t.timer = time.AfterFunc(10*time.Second, t.flush)
	}
}

func (t *Telegram) flush() {
	t.mu.Lock()
	lines := t.pending
	t.pending = nil
	t.timer = nil
	t.mu.Unlock()
	if len(lines) == 0 {
		return
	}
	const maxLines = 20
	header := fmt.Sprintf("🛡 <b>Sarv</b> — %d finding(s)\n\n", len(lines))
	shown := lines
	if len(shown) > maxLines {
		shown = shown[:maxLines]
	}
	msg := header + strings.Join(shown, "\n")
	if len(lines) > maxLines {
		msg += fmt.Sprintf("\n… and %d more (see sarv report)", len(lines)-maxLines)
	}
	if len(msg) > 4000 {
		msg = msg[:4000] + "…"
	}
	_ = t.Send(msg)
}

// Flush forces pending alerts out (used at scan end / shutdown).
func (t *Telegram) Flush() {
	t.mu.Lock()
	if t.timer != nil {
		t.timer.Stop()
		t.timer = nil
	}
	t.mu.Unlock()
	t.flush()
}
