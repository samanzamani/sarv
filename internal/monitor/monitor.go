// Package monitor runs the long-lived service: realtime inotify watching,
// hourly quick scans, and the nightly full scan.
package monitor

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/samanzamani/sarv/internal/config"
	"github.com/samanzamani/sarv/internal/scanner"
	"github.com/samanzamani/sarv/internal/store"
)

type Monitor struct {
	Cfg     *config.Config
	Store   *store.Store
	Scanner *scanner.Scanner
	// RunQuick and RunFull are provided by the caller (they wire notifications,
	// wpverify, syscheck, advisor around the raw scans).
	RunQuick func()
	RunFull  func()

	watcher  *fsnotify.Watcher
	mu       sync.Mutex
	pending  map[string]*time.Timer
	dirCount int
}

const debounce = 3 * time.Second

func New(cfg *config.Config, st *store.Store, sc *scanner.Scanner) *Monitor {
	return &Monitor{Cfg: cfg, Store: st, Scanner: sc, pending: map[string]*time.Timer{}}
}

// Run blocks until ctx is cancelled.
func (m *Monitor) Run(ctx context.Context) error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	m.watcher = w
	defer w.Close()

	excl := map[string]bool{}
	for _, e := range m.Cfg.Exclude {
		excl[e] = true
	}
	start := time.Now()
	for _, root := range m.Cfg.ScanPaths {
		m.addRecursive(root, excl)
	}
	log.Printf("monitor: watching %d directories under %v (setup took %s)", m.dirCount, m.Cfg.ScanPaths, time.Since(start).Round(time.Millisecond))

	quickTick := make(<-chan time.Time)
	if d, err := time.ParseDuration(m.Cfg.Schedule.Quick); err == nil && d > 0 {
		t := time.NewTicker(d)
		defer t.Stop()
		quickTick = t.C
	}
	cronTick := time.NewTicker(30 * time.Second)
	defer cronTick.Stop()
	var lastFull time.Time

	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-w.Events:
			if !ok {
				return nil
			}
			m.handleEvent(ev, excl)
		case err, ok := <-w.Errors:
			if !ok {
				return nil
			}
			log.Printf("monitor: watcher error: %v", err)
		case <-quickTick:
			if m.RunQuick != nil {
				go m.RunQuick()
			}
		case now := <-cronTick.C:
			if m.RunFull != nil && cronMatches(m.Cfg.Schedule.Full, now) && now.Sub(lastFull) > time.Minute {
				lastFull = now
				go m.RunFull()
			}
		}
	}
}

func (m *Monitor) addRecursive(root string, excl map[string]bool) {
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		if excl[d.Name()] {
			return filepath.SkipDir
		}
		if err := m.watcher.Add(path); err != nil {
			// Log once per root rather than spamming for every subdir.
			return filepath.SkipDir
		}
		m.dirCount++
		return nil
	})
}

func (m *Monitor) handleEvent(ev fsnotify.Event, excl map[string]bool) {
	if ev.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Rename) == 0 {
		return
	}
	st, err := os.Lstat(ev.Name)
	if err != nil {
		return
	}
	if st.IsDir() {
		if ev.Op&fsnotify.Create != 0 && !excl[filepath.Base(ev.Name)] {
			m.addRecursive(ev.Name, excl)
		}
		return
	}
	if !riskyName(ev.Name) {
		return
	}
	// Debounce: editors and uploads produce bursts of writes per file.
	m.mu.Lock()
	if t, ok := m.pending[ev.Name]; ok {
		t.Reset(debounce)
		m.mu.Unlock()
		return
	}
	path := ev.Name
	m.pending[path] = time.AfterFunc(debounce, func() {
		m.mu.Lock()
		delete(m.pending, path)
		m.mu.Unlock()
		m.Scanner.ScanOne(path)
	})
	m.mu.Unlock()
}

var riskyExts = map[string]bool{
	".php": true, ".phtml": true, ".php5": true, ".php7": true, ".phar": true, ".inc": true,
	".ico": true, ".js": true, ".ini": true, ".sh": true, ".svg": true, ".htaccess": true,
}

func riskyName(p string) bool {
	base := strings.ToLower(filepath.Base(p))
	if base == ".htaccess" || base == ".user.ini" {
		return true
	}
	if riskyExts[filepath.Ext(base)] {
		return true
	}
	parts := strings.Split(base, ".")
	return len(parts) >= 3 && riskyExts["."+parts[len(parts)-2]]
}

// cronMatches implements the 5-field cron subset: numbers, *, and */n steps.
func cronMatches(expr string, t time.Time) bool {
	f := strings.Fields(expr)
	if len(f) != 5 {
		return false
	}
	vals := []int{t.Minute(), t.Hour(), t.Day(), int(t.Month()), int(t.Weekday())}
	for i, spec := range f {
		if !cronFieldMatches(spec, vals[i]) {
			return false
		}
	}
	// Only fire in the first 30s window of the minute (ticker is 30s).
	return t.Second() < 30
}

func cronFieldMatches(spec string, v int) bool {
	if spec == "*" {
		return true
	}
	if strings.HasPrefix(spec, "*/") {
		var n int
		if _, err := fmtSscanf(spec[2:], &n); err == nil && n > 0 {
			return v%n == 0
		}
		return false
	}
	for _, part := range strings.Split(spec, ",") {
		var n int
		if _, err := fmtSscanf(part, &n); err == nil && n == v {
			return true
		}
	}
	return false
}

func fmtSscanf(s string, out *int) (int, error) {
	n := 0
	if s == "" {
		return 0, os.ErrInvalid
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, os.ErrInvalid
		}
		n = n*10 + int(c-'0')
	}
	*out = n
	return 1, nil
}
