package rules

import "testing"

func mustLoad(t *testing.T) *Engine {
	t.Helper()
	e, err := Load()
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	if len(e.Rules) == 0 {
		t.Fatal("no rules loaded")
	}
	return e
}

func TestDetectsWebshells(t *testing.T) {
	e := mustLoad(t)
	cases := []struct {
		name    string
		content string
		ext     string
	}{
		{"eval-base64", `<?php eval(base64_decode($_POST["c"])); ?>`, "php"},
		{"system-get", `<?php $x=$_GET["a"]; system($_GET["a"]); ?>`, "php"},
		{"variable-func", `<?php @$_POST["f"]($_POST["p"]); ?>`, "php"},
		{"preg-e", `<?php preg_replace("/.*/e", $_POST["x"], ""); ?>`, "php"},
		{"htaccess-handler", "AddHandler application/x-httpd-php .jpg .png", "htaccess"},
		{"known-shell", `<?php /* FilesMan */ $auth_pass="x"; ?>`, "php"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if m := e.Scan([]byte(c.content), c.ext); len(m) == 0 {
				t.Errorf("expected detection for %q", c.name)
			}
		})
	}
}

func TestCleanFilesPass(t *testing.T) {
	e := mustLoad(t)
	clean := []struct {
		content, ext string
	}{
		{`<?php function hello($n){ return "Hi ".htmlspecialchars($n); } echo hello("world");`, "php"},
		{"<?php define('DB_NAME','mydb'); $table_prefix='wp_';", "php"},
		{`<?php $data = base64_encode("hello"); echo $data;`, "php"}, // encode, not eval(decode)
		{`<?php $out = system_status(); return $out;`, "php"},        // "system" as substring
		// Regression fixtures — real false positives found on a production server:
		{"<?php /* Post content refers to `$_POST` */ function x(){}", "php"},           // markdown docblock
		{`<?php $_ = eval($__psysh__->flushCode());`, "php"},                            // psysh local, not superglobal
		{`<?php file_get_contents($stub); file_put_contents($to, $c);`, "php"},          // installer copy
		{"; auto_prepend_file =\nauto_prepend_file =\n", "ini"},                         // stock php.ini (commented + empty)
		{"$wp_version = '6.9';\n$wp_local_package = 'fa_IR';", "php"},                   // localized version.php
		// PHP-language rules must not fire on non-PHP files (editor syntax data):
		{`var php = {keywords:"system|exec|passthru", snippet:"system($_POST[x])"};`, "js"}, // ace-builds mode-php.js
		{`function pcntl_exec($path){ /* thecodingmachine/safe wrapper */ }`, "php"},         // safe lib wrapper, not request-fed
	}
	for i, c := range clean {
		if m := e.Scan([]byte(c.content), c.ext); len(m) > 0 {
			t.Errorf("false positive on clean file %d: matched %s", i, m[0].Rule.ID)
		}
	}
}
