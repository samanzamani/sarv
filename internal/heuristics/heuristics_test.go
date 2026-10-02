package heuristics

import (
	"strings"
	"testing"
)

// A legit (if nulled) plugin with a huge embedded base64 image in inline CSS,
// plus incidental base64_decode calls, must not score as a packed payload.
func TestEmbeddedDataURINotFlagged(t *testing.T) {
	img := strings.Repeat("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123456789+/", 1000) // ~44k chars
	content := "<?php\nclass yoast_01 {\n  public function css(){\n" +
		"    return \"background:url('data:image/jpeg;base64," + img + "')\";\n" +
		"  }\n  // licensing helper\n  private $k = base64_decode('aGVsbG8=');\n}\n"
	hits := Analyze("/www/wwwroot/site/wp-content/plugins/x/premium.php", []byte(content), 0, 0)
	if s := TotalScore(hits); s >= Threshold {
		t.Errorf("embedded data-URI image scored %d (>=%d); hits=%v", s, Threshold, hits)
	}
}

// A genuine packed payload inline in code (a long base64 blob NOT wrapped in a
// data: URI, fed to eval(gzinflate(base64_decode(...)))) must still be flagged:
// stripping data URIs must not weaken detection of real obfuscation.
func TestRealPackedPayloadFlagged(t *testing.T) {
	blob := strings.Repeat("QWxhZGRpbjpvcGVuIHNlc2FtZQ", 400) // ~10k char base64 run on one line
	content := "<?php eval(gzinflate(base64_decode('" + blob + "')));"
	hits := Analyze("/www/wwwroot/site/x.php", []byte(content), 0, 0)
	if TotalScore(hits) < Threshold {
		t.Errorf("real packed payload not flagged; hits=%v", hits)
	}
}
