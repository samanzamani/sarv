// Package heuristics scores files on structural signals that indicate
// obfuscated or out-of-place code, independent of known signatures.
package heuristics

import (
	"bytes"
	"math"
	"path/filepath"
	"regexp"
	"strings"
)

type Hit struct {
	Check    string
	Detail   string
	Score    int // contribution to the total suspicion score
}

// Threshold is the combined score at which a file is reported.
const Threshold = 5

var (
	rePHPTag    = regexp.MustCompile(`<\?php|<\?=`)
	reBase64Run = regexp.MustCompile(`[A-Za-z0-9+/]{200,}={0,2}`)
	reHexRun    = regexp.MustCompile(`(\\x[0-9a-fA-F]{2}){40,}`)
	reDangerFn  = regexp.MustCompile(`\b(eval|assert|system|shell_exec|passthru|proc_open|popen|base64_decode|gzinflate|str_rot13)\s*\(`)
	// Embedded data URIs (base64 images/fonts in CSS/HTML) are legitimate content
	// that otherwise inflates line length, entropy, and base64-blob scoring. They
	// are stripped before the structural heuristics run. Real payloads hidden in a
	// data: URI are still caught by the signature rules, which scan full content.
	reDataURI = regexp.MustCompile(`data:[\w.+-]*/[\w.+-]*;base64,[A-Za-z0-9+/=]+`)
)

var phpExts = map[string]bool{"php": true, "phtml": true, "php5": true, "php7": true, "phar": true, "inc": true}

// uploadDirs are directory names that hold user-uploaded content where
// executable PHP should never legitimately live. Kept deliberately narrow:
// generic names like "files"/"media" also appear in legit app structure
// (admin/files file-managers, Modules/Media), so they are excluded.
var uploadDirs = []string{"uploads", "upload"}

// Analyze scores content at path. parentDirMtime/fileMtime (unix seconds) enable the
// timestomping check; pass 0 to skip.
func Analyze(path string, content []byte, fileMtime, parentDirMtime int64) []Hit {
	var hits []Hit
	base := filepath.Base(path)
	ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(base), "."))
	isPHP := phpExts[ext] || rePHPTag.Match(content)

	// PHP file inside an uploads-style directory.
	if phpExts[ext] {
		lowerPath := strings.ToLower(path)
		for _, d := range uploadDirs {
			if strings.Contains(lowerPath, "/"+d+"/") {
				hits = append(hits, Hit{"php-in-uploads", "executable PHP inside " + d + "/ directory", 4})
				break
			}
		}
	}

	// Double extension: shell.jpg.php / image.php.jpg with PHP tag.
	parts := strings.Split(base, ".")
	if len(parts) >= 3 {
		imgExts := map[string]bool{"jpg": true, "jpeg": true, "png": true, "gif": true, "ico": true, "svg": true}
		last := strings.ToLower(parts[len(parts)-1])
		second := strings.ToLower(parts[len(parts)-2])
		if (phpExts[last] && imgExts[second]) || (imgExts[last] && phpExts[second] && rePHPTag.Match(content)) {
			hits = append(hits, Hit{"double-extension", "double extension " + base, 4})
		}
	}

	// Hidden PHP file (.x.php).
	if strings.HasPrefix(base, ".") && phpExts[ext] {
		hits = append(hits, Hit{"hidden-php", "hidden PHP file", 3})
	}

	// Strip embedded base64 data URIs (images/fonts) so legit assets — including
	// the base64 JPEG that nulled plugins stuff into inline CSS — don't drive the
	// length/entropy/base64 signals.
	codeView := content
	if bytes.Contains(content, []byte("base64,")) {
		codeView = reDataURI.ReplaceAll(content, []byte("data:stripped"))
	}

	// Structural heuristics (entropy, single-line length) apply only to native
	// PHP files: minified JS/CSS/HTML legitimately have huge lines and high
	// entropy, so restricting these avoids mass false positives on bundled
	// assets (e.g. elementor's scripts).
	if phpExts[ext] && len(codeView) > 0 {
		if l := maxLineLen(codeView); l > 8000 && reDangerFn.Match(codeView) {
			hits = append(hits, Hit{"long-line", "line longer than 8000 chars with dangerous calls", 3})
		}
		if e := stringEntropy(codeView); e > 5.7 {
			hits = append(hits, Hit{"entropy", "high string entropy (packed/encrypted payload)", 2})
		}
	}
	// These require a dangerous PHP call to be present, so they are safe on any
	// file that contains PHP (including disguised extensions).
	if isPHP && len(content) > 0 {
		if reBase64Run.Match(codeView) && reDangerFn.Match(content) {
			hits = append(hits, Hit{"base64-blob", "long base64 blob combined with decode/exec call", 3})
		}
		if reHexRun.Match(content) && reDangerFn.Match(content) {
			hits = append(hits, Hit{"hex-blob", "long \\x-escaped hex payload near decode/exec call", 3})
		}
		if n := len(reDangerFn.FindAll(content, 8)); n >= 5 {
			hits = append(hits, Hit{"danger-density", "5+ dangerous function calls in one file", 2})
		}
	}

	// Timestomping: file claims to be much older than its parent directory allows.
	// Attackers commonly reset mtimes to blend in; a file whose mtime predates the
	// directory's creation-era mtime by years while siblings are consistent is odd.
	// Only a weak signal on its own.
	if fileMtime > 0 && parentDirMtime > 0 && parentDirMtime-fileMtime > 3*365*24*3600 && isPHP {
		hits = append(hits, Hit{"timestomp", "mtime years older than parent directory", 1})
	}

	return hits
}

// TotalScore sums hit scores.
func TotalScore(hits []Hit) int {
	t := 0
	for _, h := range hits {
		t += h.Score
	}
	return t
}

func maxLineLen(b []byte) int {
	maxL, cur := 0, 0
	for _, c := range b {
		if c == '\n' {
			if cur > maxL {
				maxL = cur
			}
			cur = 0
		} else {
			cur++
		}
	}
	if cur > maxL {
		maxL = cur
	}
	return maxL
}

// stringEntropy computes Shannon entropy over quoted-string contents, which is
// where packed payloads live; falls back to whole-file entropy for large blobs.
func stringEntropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	sample := b
	if len(sample) > 128*1024 {
		sample = sample[:128*1024]
	}
	var freq [256]int
	for _, c := range sample {
		freq[c]++
	}
	n := float64(len(sample))
	e := 0.0
	for _, f := range freq {
		if f == 0 {
			continue
		}
		p := float64(f) / n
		e -= p * math.Log2(p)
	}
	return e
}
