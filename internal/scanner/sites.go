package scanner

import (
	"os"
	"path/filepath"
	"regexp"
)

type SiteType string

const (
	SiteWordPress SiteType = "wordpress"
	SiteLaravel   SiteType = "laravel"
)

type Site struct {
	Root    string   `json:"root"`
	Type    SiteType `json:"type"`
	Version string   `json:"version"` // WordPress core version if detectable
}

var reWPVersion = regexp.MustCompile(`\$wp_version\s*=\s*'([^']+)'`)

// DetectSites walks roots up to maxDepth looking for WordPress and Laravel
// installations. Detection is automatic: wp-config.php + wp-includes/version.php
// marks WordPress; artisan + bootstrap/app.php marks Laravel.
func DetectSites(roots []string, maxDepth int) []Site {
	var sites []Site
	seen := map[string]bool{}
	for _, root := range roots {
		walkDepth(root, 0, maxDepth, func(dir string) bool {
			if s, ok := detectAt(dir); ok && !seen[s.Root] {
				seen[s.Root] = true
				sites = append(sites, s)
				return false // don't descend into a detected site looking for more sites
			}
			return true
		})
	}
	return sites
}

func detectAt(dir string) (Site, bool) {
	if fileExists(filepath.Join(dir, "wp-config.php")) || fileExists(filepath.Join(dir, "wp-includes", "version.php")) {
		if fileExists(filepath.Join(dir, "wp-includes", "version.php")) {
			s := Site{Root: dir, Type: SiteWordPress}
			if data, err := os.ReadFile(filepath.Join(dir, "wp-includes", "version.php")); err == nil {
				if m := reWPVersion.FindSubmatch(data); m != nil {
					s.Version = string(m[1])
				}
			}
			return s, true
		}
	}
	if fileExists(filepath.Join(dir, "artisan")) && fileExists(filepath.Join(dir, "bootstrap", "app.php")) {
		return Site{Root: dir, Type: SiteLaravel}, true
	}
	return Site{}, false
}

// SiteFor returns the site containing path, if any.
func SiteFor(sites []Site, path string) *Site {
	for i := range sites {
		if path == sites[i].Root || len(path) > len(sites[i].Root) && path[:len(sites[i].Root)+1] == sites[i].Root+"/" {
			return &sites[i]
		}
	}
	return nil
}

func walkDepth(dir string, depth, maxDepth int, visit func(string) bool) {
	if depth > maxDepth {
		return
	}
	if !visit(dir) {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			name := e.Name()
			if name == "node_modules" || name == ".git" || name == "vendor" {
				continue
			}
			walkDepth(filepath.Join(dir, name), depth+1, maxDepth, visit)
		}
	}
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}
