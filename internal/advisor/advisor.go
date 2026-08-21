// Package advisor produces actionable hardening recommendations for the OS
// and web stack. It only reports — it never changes system state.
package advisor

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/samanzamani/sarv/internal/scanner"
	"github.com/samanzamani/sarv/internal/store"
)

type Advisor struct {
	Store *store.Store
	Sites []scanner.Site
	// ScanPaths lets ownership/permission checks know where the web roots are.
	ScanPaths []string
}

func New(st *store.Store) *Advisor { return &Advisor{Store: st} }

func (a *Advisor) add(id, title, detail, severity, remedy string) {
	_ = a.Store.UpsertAdvice(store.Advice{ID: id, Title: title, Detail: detail, Severity: severity, Remedy: remedy})
}

// Run executes all advisory checks.
func (a *Advisor) Run() {
	a.checkSiteIsolation()
	a.checkPHP()
	a.checkSSH()
	a.checkWebPermissions()
	a.checkWordPress()
	a.checkOS()
	a.checkListeners()
}

// --- site isolation ---

func (a *Advisor) checkSiteIsolation() {
	owners := map[uint32]int{}
	for _, root := range a.ScanPaths {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			if st, err := os.Stat(filepath.Join(root, e.Name())); err == nil {
				if sys, ok := st.Sys().(*syscall.Stat_t); ok {
					owners[sys.Uid]++
				}
			}
		}
	}
	total := 0
	maxCount := 0
	for _, n := range owners {
		total += n
		if n > maxCount {
			maxCount = n
		}
	}
	if total > 3 && maxCount == total {
		a.add("site-isolation", "All sites run under a single user",
			fmt.Sprintf("%d site directories share one owner. A compromise of any site can spread to every other site.", total),
			store.SevHigh,
			"Use per-site PHP-FPM pools with separate users (aaPanel: site isolation / open_basedir per site), or migrate to per-user vhosts.")
	}
}

// --- PHP ---

var eolPHP = map[string]bool{"52": true, "53": true, "54": true, "55": true, "56": true, "70": true, "71": true, "72": true, "73": true, "74": true, "80": true, "81": true}

func (a *Advisor) checkPHP() {
	// aaPanel layout: /www/server/php/<ver>/etc/php.ini ; Debian: /etc/php/<ver>/fpm/php.ini
	iniGlobs := []string{"/www/server/php/*/etc/php.ini", "/etc/php/*/fpm/php.ini"}
	for _, g := range iniGlobs {
		matches, _ := filepath.Glob(g)
		for _, ini := range matches {
			ver := phpVerFromPath(ini)
			data, err := os.ReadFile(ini)
			if err != nil {
				continue
			}
			content := string(data)
			if eolPHP[strings.ReplaceAll(ver, ".", "")] {
				a.add("php-eol-"+ver, "PHP "+ver+" is end-of-life",
					"PHP "+ver+" no longer receives security fixes but is installed and configured on this server.",
					store.SevHigh,
					"Migrate remaining sites to a supported PHP version (8.2+), then remove the EOL version.")
			}
			if v := iniValue(content, "disable_functions"); v == "" {
				a.add("php-disable-functions-"+ver, "PHP "+ver+": disable_functions is empty",
					"Webshells rely on exec-family functions. Nothing is disabled for PHP "+ver+".",
					store.SevMedium,
					"In "+ini+" set: disable_functions = exec,shell_exec,system,passthru,proc_open,popen,pcntl_exec (verify no legit site needs them).")
			}
			if v := iniValue(content, "display_errors"); strings.EqualFold(v, "On") {
				a.add("php-display-errors-"+ver, "PHP "+ver+": display_errors is On",
					"Error output leaks paths and internals to visitors.", store.SevLow,
					"Set display_errors = Off and log_errors = On in "+ini+".")
			}
			if v := iniValue(content, "expose_php"); strings.EqualFold(v, "On") {
				a.add("php-expose-"+ver, "PHP "+ver+": expose_php is On",
					"The X-Powered-By header reveals the exact PHP version.", store.SevLow,
					"Set expose_php = Off in "+ini+".")
			}
		}
	}
}

func phpVerFromPath(p string) string {
	parts := strings.Split(p, string(filepath.Separator))
	for i, s := range parts {
		if (s == "php" || s == "etc") && i+1 < len(parts) {
			cand := parts[i+1]
			if len(cand) >= 2 && cand[0] >= '0' && cand[0] <= '9' {
				return cand
			}
		}
	}
	return "?"
}

func iniValue(content, key string) string {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, ";") || !strings.HasPrefix(line, key) {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(line, key))
		if !strings.HasPrefix(rest, "=") {
			continue
		}
		return strings.TrimSpace(strings.TrimPrefix(rest, "="))
	}
	return ""
}

// --- SSH ---

func (a *Advisor) checkSSH() {
	data, err := os.ReadFile("/etc/ssh/sshd_config")
	if err != nil {
		return
	}
	rootLogin, passAuth := "", ""
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		switch strings.ToLower(f[0]) {
		case "permitrootlogin":
			rootLogin = strings.ToLower(f[1])
		case "passwordauthentication":
			passAuth = strings.ToLower(f[1])
		}
	}
	if rootLogin != "no" && rootLogin != "prohibit-password" && passAuth != "no" {
		a.add("ssh-root-password", "SSH allows root login with password",
			"Root password login enables brute-force attacks against the most powerful account.",
			store.SevHigh,
			"In /etc/ssh/sshd_config set PermitRootLogin prohibit-password (key-only) and PasswordAuthentication no, then systemctl reload sshd. Ensure your key works first!")
	}
	if !binExists("fail2ban-server") && !binExists("fail2ban-client") {
		a.add("no-fail2ban", "No fail2ban installed",
			"Nothing throttles repeated SSH/panel login failures.", store.SevMedium,
			"apt install fail2ban (aaPanel also ships its own brute-force protection — enable one of them).")
	}
}

// --- filesystem permissions ---

func (a *Advisor) checkWebPermissions() {
	worldWritable := 0
	example := ""
	for _, root := range a.ScanPaths {
		// Sample the top two levels only; a full walk is done by the scanner anyway.
		level1, _ := filepath.Glob(filepath.Join(root, "*"))
		for _, d := range level1 {
			st, err := os.Stat(d)
			if err != nil || !st.IsDir() {
				continue
			}
			if st.Mode().Perm()&0o002 != 0 {
				worldWritable++
				if example == "" {
					example = d
				}
			}
		}
	}
	if worldWritable > 0 {
		noun := "directory is"
		if worldWritable > 1 {
			noun = "directories are"
		}
		a.add("world-writable-dirs", "World-writable directories in web root",
			fmt.Sprintf("%d %s chmod 777-style (e.g. %s). Any local process can plant files there.", worldWritable, noun, example),
			store.SevHigh, "chmod 755 the directories; the web user should own them instead of needing world write.")
	}
	for _, s := range a.Sites {
		if s.Type != scanner.SiteWordPress {
			continue
		}
		wc := filepath.Join(s.Root, "wp-config.php")
		if st, err := os.Stat(wc); err == nil && st.Mode().Perm()&0o044 != 0 {
			a.add("wp-config-perm-"+shortID(s.Root), "wp-config.php is world/group readable: "+filepath.Base(s.Root),
				wc+" contains DB credentials and is readable beyond its owner.", store.SevMedium,
				"chmod 600 "+wc)
		}
	}
}

// --- WordPress ---

func (a *Advisor) checkWordPress() {
	for _, s := range a.Sites {
		if s.Type != scanner.SiteWordPress {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.Root, "wp-config.php"))
		if err != nil {
			continue
		}
		if !strings.Contains(string(data), "DISALLOW_FILE_EDIT") {
			a.add("wp-file-edit-"+shortID(s.Root), "WordPress file editor enabled: "+filepath.Base(s.Root),
				"The built-in plugin/theme editor lets any compromised admin account write PHP directly.",
				store.SevMedium,
				"Add define('DISALLOW_FILE_EDIT', true); to "+filepath.Join(s.Root, "wp-config.php"))
		}
	}
}

// --- OS ---

func (a *Advisor) checkOS() {
	if data, err := os.ReadFile("/etc/apt/apt.conf.d/20auto-upgrades"); err == nil {
		if !strings.Contains(string(data), `Unattended-Upgrade "1"`) {
			a.add("unattended-upgrades", "Automatic security updates disabled",
				"Security patches are not applied automatically.", store.SevMedium,
				`dpkg-reconfigure -plow unattended-upgrades (or set APT::Periodic::Unattended-Upgrade "1")`)
		}
	}
	if data, err := os.ReadFile("/var/lib/update-notifier/updates-available"); err == nil {
		txt := string(data)
		if strings.Contains(txt, "security update") && !strings.Contains(txt, "0 updates are security updates") {
			a.add("pending-security-updates", "Security updates pending",
				strings.TrimSpace(txt), store.SevMedium, "apt update && apt upgrade during a maintenance window.")
		}
	}
}

// --- network listeners ---

// riskyPorts are services that should almost never listen on all interfaces.
var riskyPorts = map[int]string{3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 11211: "memcached", 27017: "MongoDB", 9200: "Elasticsearch"}

func (a *Advisor) checkListeners() {
	for _, proc := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(proc)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n")[1:] {
			f := strings.Fields(line)
			if len(f) < 4 || f[3] != "0A" { // 0A = LISTEN
				continue
			}
			addrPort := strings.Split(f[1], ":")
			if len(addrPort) != 2 {
				continue
			}
			portB, err := hex.DecodeString(addrPort[1])
			if err != nil || len(portB) != 2 {
				continue
			}
			port := int(binary.BigEndian.Uint16(portB))
			name, risky := riskyPorts[port]
			if !risky {
				continue
			}
			addr := addrPort[0]
			isAny := strings.Trim(addr, "0") == "" // 00000000 or v6 all-zero
			if isAny {
				a.add(fmt.Sprintf("open-listener-%d", port), name+" listens on all interfaces",
					fmt.Sprintf("%s (port %d) accepts connections from any address. Databases/caches should bind to localhost.", name, port),
					store.SevHigh,
					fmt.Sprintf("Bind %s to 127.0.0.1 or firewall port %d to trusted IPs only.", name, port))
			}
		}
	}
}

func binExists(name string) bool {
	for _, dir := range strings.Split(os.Getenv("PATH")+":/usr/bin:/usr/sbin:/usr/local/bin", ":") {
		if dir == "" {
			continue
		}
		if st, err := os.Stat(filepath.Join(dir, name)); err == nil && !st.IsDir() {
			return true
		}
	}
	return false
}

func shortID(s string) string {
	sum := 0
	for _, c := range s {
		sum = sum*31 + int(c)
	}
	return fmt.Sprintf("%x", uint32(sum))
}
