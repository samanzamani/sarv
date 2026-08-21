// Package rules implements the signature engine: YAML-defined rules with
// literal strings and regexes, compiled once and matched against file content.
package rules

import (
	"bytes"
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed builtin/*.yml
var builtinFS embed.FS

// UserRulesDir is scanned for additional *.yml rule files at load time.
const UserRulesDir = "/etc/sarv/rules.d"

type Rule struct {
	ID          string   `yaml:"id"`
	Description string   `yaml:"description"`
	Severity    string   `yaml:"severity"`             // low | medium | high | critical
	Extensions  []string `yaml:"extensions,omitempty"` // empty = any extension
	Strings     []string `yaml:"strings,omitempty"`    // literal substrings (case sensitive)
	IStrings    []string `yaml:"istrings,omitempty"`   // literal substrings (case insensitive)
	Regex       []string `yaml:"regex,omitempty"`
	// MinMatches is how many distinct patterns must hit (default 1).
	MinMatches int `yaml:"min_matches,omitempty"`

	compiled []*regexp.Regexp
	extSet   map[string]bool
}

type Engine struct {
	Rules []*Rule
}

// Load compiles built-in rules plus any user rules found in extraDirs.
func Load(extraDirs ...string) (*Engine, error) {
	var all []*Rule
	err := fs.WalkDir(builtinFS, "builtin", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".yml") {
			return err
		}
		data, err := builtinFS.ReadFile(path)
		if err != nil {
			return err
		}
		rs, err := parse(data)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		all = append(all, rs...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	for _, dir := range extraDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue // optional dir
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".yml") {
				continue
			}
			data, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				continue
			}
			rs, err := parse(data)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", e.Name(), err)
			}
			all = append(all, rs...)
		}
	}
	for _, r := range all {
		if err := r.compile(); err != nil {
			return nil, fmt.Errorf("rule %s: %w", r.ID, err)
		}
	}
	return &Engine{Rules: all}, nil
}

func parse(data []byte) ([]*Rule, error) {
	var rs []*Rule
	if err := yaml.Unmarshal(data, &rs); err != nil {
		return nil, err
	}
	return rs, nil
}

func (r *Rule) compile() error {
	if r.ID == "" {
		return fmt.Errorf("rule missing id")
	}
	if r.MinMatches <= 0 {
		r.MinMatches = 1
	}
	if r.Severity == "" {
		r.Severity = "medium"
	}
	for _, re := range r.Regex {
		c, err := regexp.Compile(re)
		if err != nil {
			return fmt.Errorf("regex %q: %w", re, err)
		}
		r.compiled = append(r.compiled, c)
	}
	// Extension scoping:
	//   - explicit list  → match only those extensions
	//   - ["*"]          → match any extension (opt-in for cross-type rules)
	//   - omitted        → default to PHP-executable extensions, since every
	//                      cross-type rule (js/htaccess/ini/image) sets its own
	//                      list and a bare PHP-language rule must not match e.g.
	//                      an editor's mode-php.js keyword data.
	if len(r.Extensions) == 1 && r.Extensions[0] == "*" {
		r.extSet = nil
	} else if len(r.Extensions) > 0 {
		r.extSet = make(map[string]bool, len(r.Extensions))
		for _, e := range r.Extensions {
			r.extSet[strings.ToLower(strings.TrimPrefix(e, "."))] = true
		}
	} else {
		r.extSet = map[string]bool{"php": true, "phtml": true, "php5": true, "php7": true, "phar": true, "inc": true}
	}
	return nil
}

type Match struct {
	Rule    *Rule
	Detail  string
}

// Scan runs every applicable rule against content. ext is the lowercase file
// extension without the dot ("" for none).
func (e *Engine) Scan(content []byte, ext string) []Match {
	var lower []byte // built lazily for case-insensitive rules
	var out []Match
	for _, r := range e.Rules {
		if r.extSet != nil && !r.extSet[ext] {
			continue
		}
		hits := 0
		var first string
		for _, s := range r.Strings {
			if bytes.Contains(content, []byte(s)) {
				hits++
				if first == "" {
					first = s
				}
			}
		}
		if len(r.IStrings) > 0 && lower == nil {
			lower = bytes.ToLower(content)
		}
		for _, s := range r.IStrings {
			if bytes.Contains(lower, []byte(strings.ToLower(s))) {
				hits++
				if first == "" {
					first = s
				}
			}
		}
		for _, re := range r.compiled {
			if loc := re.FindIndex(content); loc != nil {
				hits++
				if first == "" {
					first = string(content[loc[0]:min(loc[1], loc[0]+60)])
				}
			}
		}
		if hits >= r.MinMatches {
			out = append(out, Match{Rule: r, Detail: fmt.Sprintf("%s (pattern: %.60s)", r.Description, first)})
		}
	}
	return out
}
