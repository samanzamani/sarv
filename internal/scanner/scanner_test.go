package scanner

import (
	"path/filepath"
	"testing"

	"github.com/samanzamani/sarv/internal/config"
	"github.com/samanzamani/sarv/internal/store"
)

func TestScanTestdata(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.DataDir = dir
	cfg.ScanPaths = []string{"../../testdata"}
	cfg.Workers = 2

	st, err := store.Open(filepath.Join(dir, "sarv.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	sc, err := New(cfg, st)
	if err != nil {
		t.Fatal(err)
	}
	var findings []store.Finding
	sc.OnFind = func(f store.Finding, isNew bool) { findings = append(findings, f) }

	res, err := sc.ScanPaths([]string{"../../testdata/malicious"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Findings < 4 {
		t.Errorf("expected >=4 findings in malicious testdata, got %d", res.Findings)
	}

	// Clean files must not be flagged.
	clean := &store.Finding{}
	_ = clean
	before := len(findings)
	if _, err := sc.ScanPaths([]string{"../../testdata/clean"}); err != nil {
		t.Fatal(err)
	}
	for _, f := range findings[before:] {
		t.Errorf("false positive on clean file: %s (%s)", f.Path, f.Rule)
	}
}

func TestCacheSkips(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.DataDir = dir
	st, _ := store.Open(filepath.Join(dir, "sarv.db"))
	defer st.Close()
	sc, _ := New(cfg, st)

	r1, _ := sc.ScanPaths([]string{"../../testdata/clean"})
	if r1.Scanned == 0 {
		t.Fatal("first scan processed nothing")
	}
	r2, _ := sc.ScanPaths([]string{"../../testdata/clean"})
	if r2.Skipped == 0 {
		t.Error("second scan did not use the clean-file cache")
	}
}
