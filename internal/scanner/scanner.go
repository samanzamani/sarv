// Package scanner walks scan paths with a worker pool and runs each file
// through the detection pipeline: cache check → signature rules → heuristics.
package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/samanzamani/sarv/internal/config"
	"github.com/samanzamani/sarv/internal/heuristics"
	"github.com/samanzamani/sarv/internal/rules"
	"github.com/samanzamani/sarv/internal/store"
)

// scanExts are file extensions whose content is scanned. Files with other
// extensions are still subject to name-based heuristics when risky.
var scanExts = map[string]bool{
	"php": true, "phtml": true, "php5": true, "php7": true, "phar": true, "inc": true,
	"js": true, "html": true, "htm": true, "ico": true, "ini": true, "htaccess": true,
	"sh": true, "pl": true, "py": true, "cgi": true, "svg": true,
}

type Result struct {
	Scanned  int64
	Skipped  int64
	Findings int64
	Errors   int64
}

// FindingHandler receives each finding as it is discovered (already persisted).
type FindingHandler func(f store.Finding, isNew bool)

type Scanner struct {
	Cfg     *config.Config
	Store   *store.Store
	Engine  *rules.Engine
	Sites   []Site
	OnFind  FindingHandler
	// Progress is called periodically with the number of files processed.
	Progress func(done int64)
	// UseCache skips files whose size+mtime match a prior clean verdict.
	UseCache bool
}

func New(cfg *config.Config, st *store.Store) (*Scanner, error) {
	eng, err := rules.Load(rules.UserRulesDir)
	if err != nil {
		return nil, err
	}
	return &Scanner{Cfg: cfg, Store: st, Engine: eng, UseCache: true}, nil
}

// ScanPaths scans the given roots (files or directories).
func (s *Scanner) ScanPaths(roots []string) (*Result, error) {
	if s.Sites == nil {
		s.Sites = DetectSites(roots, 3)
	}
	res := &Result{}
	files := make(chan string, 4096)
	var wg sync.WaitGroup
	workers := s.Cfg.EffectiveWorkers()
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range files {
				s.scanFile(p, res)
				if s.Progress != nil {
					done := atomic.LoadInt64(&res.Scanned) + atomic.LoadInt64(&res.Skipped)
					if done%2000 == 0 {
						s.Progress(done)
					}
				}
			}
		}()
	}

	excl := map[string]bool{}
	for _, e := range s.Cfg.Exclude {
		excl[e] = true
	}
	for _, root := range roots {
		st, err := os.Stat(root)
		if err != nil {
			log.Printf("scan: %v", err)
			continue
		}
		if !st.IsDir() {
			files <- root
			continue
		}
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				atomic.AddInt64(&res.Errors, 1)
				return nil
			}
			if d.IsDir() {
				if excl[d.Name()] {
					return filepath.SkipDir
				}
				return nil
			}
			if d.Type()&fs.ModeSymlink != 0 {
				return nil
			}
			if shouldScanName(d.Name()) {
				files <- path
			}
			return nil
		})
	}
	close(files)
	wg.Wait()
	return res, nil
}

// ScanOne scans a single file (used by the realtime monitor).
func (s *Scanner) ScanOne(path string) {
	res := &Result{}
	s.scanFile(path, res)
}

func shouldScanName(name string) bool {
	// AppleDouble resource-fork files ("._foo.php") from unzipped macOS archives
	// are binary junk that trips content heuristics; never scan them.
	if strings.HasPrefix(name, "._") {
		return false
	}
	base := strings.ToLower(name)
	if base == ".htaccess" || base == ".user.ini" || base == "php.ini" {
		return true
	}
	ext := strings.TrimPrefix(filepath.Ext(base), ".")
	if scanExts[ext] {
		return true
	}
	// double extensions like x.php.jpg — check the second-to-last part too
	parts := strings.Split(base, ".")
	if len(parts) >= 3 && scanExts[parts[len(parts)-2]] {
		return true
	}
	return false
}

func extOf(path string) string {
	base := strings.ToLower(filepath.Base(path))
	if base == ".htaccess" {
		return "htaccess"
	}
	if strings.HasSuffix(base, ".ini") {
		return "ini"
	}
	return strings.TrimPrefix(filepath.Ext(base), ".")
}

func (s *Scanner) scanFile(path string, res *Result) {
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() {
		return
	}
	size, mtime := st.Size(), st.ModTime().Unix()
	if size > s.Cfg.MaxFileSize {
		atomic.AddInt64(&res.Skipped, 1)
		return
	}
	if s.UseCache {
		if verdict, ok := s.Store.CachedVerdict(path, size, mtime); ok && verdict == "clean" {
			atomic.AddInt64(&res.Skipped, 1)
			return
		}
	}
	content, err := os.ReadFile(path)
	if err != nil {
		atomic.AddInt64(&res.Errors, 1)
		return
	}
	atomic.AddInt64(&res.Scanned, 1)
	sum := sha256.Sum256(content)
	shaHex := hex.EncodeToString(sum[:])

	var found []store.Finding
	ext := extOf(path)
	for _, m := range s.Engine.Scan(content, ext) {
		found = append(found, store.Finding{
			Path: path, Rule: m.Rule.ID, Detail: m.Detail, Severity: m.Rule.Severity, SHA256: shaHex,
		})
	}
	// Heuristics only when no signature already flagged the file at high/critical.
	var parentMtime int64
	if pst, err := os.Stat(filepath.Dir(path)); err == nil {
		parentMtime = pst.ModTime().Unix()
	}
	hits := heuristics.Analyze(path, content, mtime, parentMtime)
	if score := heuristics.TotalScore(hits); score >= heuristics.Threshold {
		var parts []string
		for _, h := range hits {
			parts = append(parts, h.Detail)
		}
		sev := store.SevMedium
		if score >= 8 {
			sev = store.SevHigh
		}
		found = append(found, store.Finding{
			Path: path, Rule: "heuristics", Detail: fmt.Sprintf("score %d: %s", score, strings.Join(parts, "; ")),
			Severity: sev, SHA256: shaHex,
		})
	}

	verdict := "clean"
	for i := range found {
		verdict = "finding"
		if site := SiteFor(s.Sites, path); site != nil {
			found[i].Site = filepath.Base(site.Root)
		}
		id, isNew, err := s.Store.AddFinding(&found[i])
		if err != nil {
			log.Printf("store finding: %v", err)
			continue
		}
		found[i].ID = id
		if isNew {
			atomic.AddInt64(&res.Findings, 1)
		}
		if s.OnFind != nil {
			s.OnFind(found[i], isNew)
		}
	}
	if err := s.Store.SetVerdict(path, size, mtime, shaHex, verdict); err != nil {
		log.Printf("store verdict: %v", err)
	}
}
