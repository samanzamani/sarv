// Package wpverify checks WordPress core/plugin files against official
// wordpress.org checksums and Laravel public dirs against a local baseline.
package wpverify

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/samanzamani/sarv/internal/scanner"
	"github.com/samanzamani/sarv/internal/store"
)

type Verifier struct {
	Store    *store.Store
	CacheDir string
	Client   *http.Client
	OnFind   scanner.FindingHandler
}

func New(st *store.Store, cacheDir string) *Verifier {
	return &Verifier{
		Store:    st,
		CacheDir: cacheDir,
		Client:   &http.Client{Timeout: 30 * time.Second},
	}
}

type coreChecksumResp struct {
	Checksums map[string]string `json:"checksums"`
}

// VerifyWordPress compares core files of site against official MD5 checksums.
// Modified or unknown-extra files inside wp-admin/ and wp-includes/ are reported.
func (v *Verifier) VerifyWordPress(site scanner.Site) error {
	if site.Type != scanner.SiteWordPress || site.Version == "" {
		return nil
	}
	// Localized WordPress builds (e.g. fa_IR) ship different core files than the
	// en_US build, so fetch checksums for the site's actual locale.
	locale := detectLocale(site.Root)
	sums, err := v.coreChecksums(site.Version, locale)
	if err != nil {
		return fmt.Errorf("checksums for WP %s (%s) unavailable: %w", site.Version, locale, err)
	}
	// Verify listed files and collect the known set.
	known := map[string]bool{}
	for rel, want := range sums {
		known[rel] = true
		// wp-content is site-specific; the API lists default themes/plugins only.
		if strings.HasPrefix(rel, "wp-content/") {
			continue
		}
		full := filepath.Join(site.Root, rel)
		got, err := md5File(full)
		if err != nil {
			continue // missing files are usually intentional (e.g. removed readme)
		}
		if got != want {
			v.report(store.Finding{
				Path:     full,
				Site:     filepath.Base(site.Root),
				Rule:     "wp-core-modified",
				Detail:   fmt.Sprintf("core file differs from official WordPress %s checksum", site.Version),
				Severity: store.SevCritical,
			})
		}
	}
	// Extra PHP files in core directories are a classic injection spot.
	for _, dir := range []string{"wp-admin", "wp-includes"} {
		root := filepath.Join(site.Root, dir)
		_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			if !strings.HasSuffix(p, ".php") {
				return nil
			}
			rel, _ := filepath.Rel(site.Root, p)
			rel = filepath.ToSlash(rel)
			if !known[rel] {
				v.report(store.Finding{
					Path:     p,
					Site:     filepath.Base(site.Root),
					Rule:     "wp-core-extra-file",
					Detail:   fmt.Sprintf("PHP file not part of official WordPress %s: %s", site.Version, rel),
					Severity: store.SevCritical,
				})
			}
			return nil
		})
	}
	return nil
}

// detectLocale reads $wp_local_package from wp-includes/version.php; empty means en_US.
func detectLocale(root string) string {
	data, err := os.ReadFile(filepath.Join(root, "wp-includes", "version.php"))
	if err != nil {
		return "en_US"
	}
	if m := reLocalPackage.FindSubmatch(data); m != nil && len(m[1]) > 0 {
		return string(m[1])
	}
	return "en_US"
}

var reLocalPackage = regexp.MustCompile(`\$wp_local_package\s*=\s*'([^']*)'`)

// coreChecksums fetches (with on-disk cache) the official core checksum list.
func (v *Verifier) coreChecksums(version, locale string) (map[string]string, error) {
	if locale == "" {
		locale = "en_US"
	}
	cacheFile := filepath.Join(v.CacheDir, "wp-core-"+version+"-"+locale+".json")
	if data, err := os.ReadFile(cacheFile); err == nil {
		var m map[string]string
		if json.Unmarshal(data, &m) == nil && len(m) > 0 {
			return m, nil
		}
	}
	url := "https://api.wordpress.org/core/checksums/1.0/?version=" + version + "&locale=" + locale
	resp, err := v.Client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("api status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	var parsed coreChecksumResp
	if err := json.Unmarshal(body, &parsed); err != nil || len(parsed.Checksums) == 0 {
		return nil, fmt.Errorf("unexpected checksum response")
	}
	_ = os.MkdirAll(v.CacheDir, 0o750)
	if data, err := json.Marshal(parsed.Checksums); err == nil {
		_ = os.WriteFile(cacheFile, data, 0o644)
	}
	return parsed.Checksums, nil
}

// VerifyLaravel maintains a hash baseline of PHP files in public/ and reports
// files that appear or change after the baseline was recorded. First run
// records the baseline (assumed clean).
func (v *Verifier) VerifyLaravel(site scanner.Site) error {
	if site.Type != scanner.SiteLaravel {
		return nil
	}
	kind := "laravel_pub"
	keyPrefix := site.Root + "|"
	baselineExists := v.Store.BaselineHas(kind)

	dirs := []string{filepath.Join(site.Root, "public"), filepath.Join(site.Root, "storage")}
	for _, dir := range dirs {
		_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(p, ".php") {
				return nil
			}
			// Laravel's public/ legitimately contains only index.php; storage/ none.
			sum, err := sha256File(p)
			if err != nil {
				return nil
			}
			key := keyPrefix + p
			prev, ok := v.Store.BaselineGet(kind, key)
			switch {
			case !ok && baselineExists:
				v.report(store.Finding{
					Path: p, Site: filepath.Base(site.Root), Rule: "laravel-new-php",
					Detail:   "new PHP file outside Laravel baseline in " + filepath.Base(dir) + "/",
					Severity: store.SevHigh, SHA256: sum,
				})
			case ok && prev != sum:
				v.report(store.Finding{
					Path: p, Site: filepath.Base(site.Root), Rule: "laravel-modified-php",
					Detail:   "PHP file changed since Laravel baseline in " + filepath.Base(dir) + "/",
					Severity: store.SevHigh, SHA256: sum,
				})
			}
			_ = v.Store.BaselineSet(kind, key, sum)
			return nil
		})
	}
	return nil
}

func (v *Verifier) report(f store.Finding) {
	id, isNew, err := v.Store.AddFinding(&f)
	if err != nil {
		return
	}
	f.ID = id
	if v.OnFind != nil {
		v.OnFind(f, isNew)
	}
}

func md5File(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func sha256File(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
