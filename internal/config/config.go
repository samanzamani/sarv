// Package config loads and stores sarv configuration.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"gopkg.in/yaml.v3"
)

// DefaultPath is the default config file location on Linux servers.
const DefaultPath = "/etc/sarv/config.yml"

type Config struct {
	// Paths to scan for web malware.
	ScanPaths []string `yaml:"scan_paths"`
	// Directory name patterns excluded from scanning.
	Exclude []string `yaml:"exclude"`
	// Max file size in bytes eligible for content scanning.
	MaxFileSize int64 `yaml:"max_file_size"`
	// Number of parallel scan workers (0 = NumCPU/2).
	Workers int `yaml:"workers"`
	// Data directory (SQLite DB, quarantine, caches).
	DataDir string `yaml:"data_dir"`

	Quarantine QuarantineConfig `yaml:"quarantine"`
	Schedule   ScheduleConfig   `yaml:"schedule"`
	Telegram   TelegramConfig   `yaml:"telegram"`
	Web        WebConfig        `yaml:"web"`
	Syscheck   SyscheckConfig   `yaml:"syscheck"`
}

type QuarantineConfig struct {
	// Auto-quarantine level: "none" (report only), "high" (high severity only), "all".
	Auto string `yaml:"auto"`
}

type ScheduleConfig struct {
	// Quick scan interval, e.g. "1h". Empty disables.
	Quick string `yaml:"quick"`
	// Full scan time in cron format (min hour dom mon dow). Empty disables.
	Full string `yaml:"full"`
}

type TelegramConfig struct {
	Enabled  bool   `yaml:"enabled"`
	BotToken string `yaml:"bot_token"`
	ChatID   string `yaml:"chat_id"`
	// ProxyURL supports http://host:port and socks5://[user:pass@]host:port.
	ProxyURL string `yaml:"proxy_url"`
}

type WebConfig struct {
	Enabled bool   `yaml:"enabled"`
	Listen  string `yaml:"listen"`
	// Bcrypt hash of the panel password (set via `sarv web set-password`).
	Username     string `yaml:"username"`
	PasswordHash string `yaml:"password_hash"`
	TLSCert      string `yaml:"tls_cert"`
	TLSKey       string `yaml:"tls_key"`
}

type SyscheckConfig struct {
	Enabled bool `yaml:"enabled"`
	// Verify installed package binaries against dpkg md5sums.
	VerifyBinaries bool `yaml:"verify_binaries"`
}

func Default() *Config {
	return &Config{
		ScanPaths:   []string{"/www/wwwroot"},
		Exclude:     []string{"node_modules", ".git", ".svn", "cache", ".cache", "lscache"},
		MaxFileSize: 5 * 1024 * 1024,
		Workers:     0,
		DataDir:     "/var/lib/sarv",
		Quarantine:  QuarantineConfig{Auto: "none"},
		Schedule:    ScheduleConfig{Quick: "1h", Full: "0 3 * * *"},
		Telegram:    TelegramConfig{},
		Web:         WebConfig{Listen: "127.0.0.1:8181", Username: "admin"},
		Syscheck:    SyscheckConfig{Enabled: true, VerifyBinaries: true},
	}
}

// Load reads the config file at path, falling back to defaults for a missing file.
func Load(path string) (*Config, error) {
	cfg := Default()
	if path == "" {
		path = DefaultPath
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, err
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return cfg, nil
}

func (c *Config) Save(path string) error {
	if path == "" {
		path = DefaultPath
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func (c *Config) EffectiveWorkers() int {
	if c.Workers > 0 {
		return c.Workers
	}
	n := runtime.NumCPU() / 2
	if n < 1 {
		n = 1
	}
	return n
}

func (c *Config) DBPath() string        { return filepath.Join(c.DataDir, "sarv.db") }
func (c *Config) QuarantineDir() string { return filepath.Join(c.DataDir, "quarantine") }
func (c *Config) APICacheDir() string   { return filepath.Join(c.DataDir, "apicache") }
