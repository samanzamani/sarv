// Package syscheck looks for signs of attacker persistence on the OS after a
// web compromise: replaced binaries, droppers in tmp dirs, rogue cron jobs and
// systemd units, SSH key changes, suspicious users and processes.
//
// Results are diffed against a baseline stored on first run, so only changes
// are reported. This complements — not replaces — rkhunter/AIDE.
package syscheck

import (
	"bufio"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/samanzamani/sarv/internal/store"
)

type Checker struct {
	Store          *store.Store
	VerifyBinaries bool
	OnFind         func(f store.Finding, isNew bool)
}

func New(st *store.Store, verifyBinaries bool) *Checker {
	return &Checker{Store: st, VerifyBinaries: verifyBinaries}
}

// Run executes all checks. firstRun baselines are recorded silently.
func (c *Checker) Run() error {
	c.checkTmpExecutables()
	c.checkPersistence()
	c.checkAuthorizedKeys()
	c.checkUsers()
	c.checkProcesses()
	if c.VerifyBinaries {
		c.checkDpkgBinaries()
	}
	return nil
}

func (c *Checker) report(rule, path, detail, severity string) {
	f := store.Finding{Path: path, Rule: rule, Detail: detail, Severity: severity, Site: "system"}
	sum := sha256.Sum256([]byte(rule + path + detail))
	f.SHA256 = hex.EncodeToString(sum[:8])
	id, isNew, err := c.Store.AddFinding(&f)
	if err != nil {
		return
	}
	f.ID = id
	if c.OnFind != nil {
		c.OnFind(f, isNew)
	}
}

// --- tmp executables ---

func (c *Checker) checkTmpExecutables() {
	for _, dir := range []string{"/tmp", "/var/tmp", "/dev/shm"} {
		_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			// Only regular files — sockets, pipes, and devices (e.g. mysql.sock)
			// carry the execute bit but are not droppers.
			if !info.Mode().IsRegular() {
				return nil
			}
			if info.Mode()&0o111 != 0 || isELF(p) {
				kind := "executable file"
				if isELF(p) {
					kind = "ELF binary"
				}
				c.report("tmp-executable", p, kind+" in temporary directory (classic dropper/miner location)", store.SevHigh)
			}
			return nil
		})
	}
}

func isELF(p string) bool {
	f, err := os.Open(p)
	if err != nil {
		return false
	}
	defer f.Close()
	var magic [4]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil {
		return false
	}
	return magic == [4]byte{0x7f, 'E', 'L', 'F'}
}

// --- persistence: cron, systemd, rc.local, ld.so.preload ---

func (c *Checker) checkPersistence() {
	kind := "persist"
	first := !c.Store.BaselineHas(kind)

	// ld.so.preload should not normally exist.
	if data, err := os.ReadFile("/etc/ld.so.preload"); err == nil && len(strings.TrimSpace(string(data))) > 0 {
		c.report("ld-preload", "/etc/ld.so.preload", "ld.so.preload is set: "+strings.TrimSpace(string(data)), store.SevCritical)
	}

	var files []string
	// user crontabs + system cron dirs + systemd units + rc.local
	globs := []string{
		"/var/spool/cron/crontabs/*",
		"/etc/crontab", "/etc/rc.local",
		"/etc/cron.d/*", "/etc/cron.daily/*", "/etc/cron.hourly/*", "/etc/cron.weekly/*", "/etc/cron.monthly/*",
		"/etc/systemd/system/*.service", "/etc/systemd/system/*.timer",
	}
	for _, g := range globs {
		m, _ := filepath.Glob(g)
		files = append(files, m...)
	}
	for _, p := range files {
		st, err := os.Stat(p)
		if err != nil || st.IsDir() {
			continue
		}
		sum, err := sha256File(p)
		if err != nil {
			continue
		}
		prev, ok := c.Store.BaselineGet(kind, p)
		switch {
		case !ok && !first:
			c.report("persist-new", p, "new cron/systemd/startup file since baseline", store.SevHigh)
		case ok && prev != sum:
			c.report("persist-modified", p, "cron/systemd/startup file changed since baseline", store.SevHigh)
		}
		_ = c.Store.BaselineSet(kind, p, sum)
	}
}

// --- authorized_keys ---

func (c *Checker) checkAuthorizedKeys() {
	kind := "authkeys"
	first := !c.Store.BaselineHas(kind)
	var paths []string
	if m, err := filepath.Glob("/home/*/.ssh/authorized_keys*"); err == nil {
		paths = append(paths, m...)
	}
	paths = append(paths, "/root/.ssh/authorized_keys", "/root/.ssh/authorized_keys2")
	for _, p := range paths {
		sum, err := sha256File(p)
		if err != nil {
			continue
		}
		prev, ok := c.Store.BaselineGet(kind, p)
		switch {
		case !ok && !first:
			c.report("authkeys-new", p, "new authorized_keys file since baseline", store.SevCritical)
		case ok && prev != sum:
			c.report("authkeys-modified", p, "authorized_keys changed since baseline — verify every key", store.SevCritical)
		}
		_ = c.Store.BaselineSet(kind, p, sum)
	}
}

// --- users ---

func (c *Checker) checkUsers() {
	kind := "users"
	first := !c.Store.BaselineHas(kind)
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.Split(sc.Text(), ":")
		if len(parts) < 7 {
			continue
		}
		user, uid, shell := parts[0], parts[2], parts[6]
		if uid == "0" && user != "root" {
			c.report("uid0-user", "/etc/passwd", "non-root user with UID 0: "+user, store.SevCritical)
		}
		if !strings.HasSuffix(shell, "sh") {
			continue // only track users that can log in
		}
		key := user
		val := uid + ":" + shell
		prev, ok := c.Store.BaselineGet(kind, key)
		switch {
		case !ok && !first:
			c.report("new-shell-user", "/etc/passwd", fmt.Sprintf("new user with login shell since baseline: %s (uid %s, %s)", user, uid, shell), store.SevHigh)
		case ok && prev != val:
			c.report("changed-user", "/etc/passwd", fmt.Sprintf("user %s changed: %s -> %s", user, prev, val), store.SevHigh)
		}
		_ = c.Store.BaselineSet(kind, key, val)
	}
}

// --- processes ---

func (c *Checker) checkProcesses() {
	procs, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	for _, e := range procs {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
		if err != nil {
			continue
		}
		comm, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		name := strings.TrimSpace(string(comm))
		if strings.HasSuffix(exe, " (deleted)") {
			base := strings.TrimSuffix(exe, " (deleted)")
			// Interpreters and runtimes get upgraded while running; flag only
			// binaries that ran from web/tmp paths or unknown locations.
			if strings.HasPrefix(base, "/tmp/") || strings.HasPrefix(base, "/var/tmp/") ||
				strings.HasPrefix(base, "/dev/shm/") || strings.HasPrefix(base, "/www/wwwroot/") {
				c.report("proc-deleted-exe", base,
					fmt.Sprintf("process %d (%s) runs from a deleted binary in a suspicious path", pid, name), store.SevCritical)
			}
		}
		if strings.HasPrefix(exe, "/tmp/") || strings.HasPrefix(exe, "/var/tmp/") || strings.HasPrefix(exe, "/dev/shm/") {
			c.report("proc-tmp-exe", exe, fmt.Sprintf("process %d (%s) executing from temporary directory", pid, name), store.SevCritical)
		}
	}
}

// --- dpkg binary verification ---

// checkDpkgBinaries verifies md5sums of files under /bin,/sbin,/usr/bin,/usr/sbin
// against the dpkg database (like debsums, subset for speed).
func (c *Checker) checkDpkgBinaries() {
	infoDir := "/var/lib/dpkg/info"
	entries, err := os.ReadDir(infoDir)
	if err != nil {
		return // not a dpkg system
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".md5sums") {
			continue
		}
		f, err := os.Open(filepath.Join(infoDir, e.Name()))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := sc.Text()
			// format: "<md5>  path/relative/to/root"
			if len(line) < 34 {
				continue
			}
			want := line[:32]
			rel := strings.TrimSpace(line[33:])
			if !strings.HasPrefix(rel, "bin/") && !strings.HasPrefix(rel, "sbin/") &&
				!strings.HasPrefix(rel, "usr/bin/") && !strings.HasPrefix(rel, "usr/sbin/") {
				continue
			}
			full := "/" + rel
			// Verify only ELF binaries: shell/PHP wrapper scripts (pear, pecl,
			// phpize…) are legitimately rewritten by their package manager after
			// install and would otherwise be noisy false positives.
			if !isELF(full) {
				continue
			}
			got, err := md5File(full)
			if err != nil {
				continue
			}
			if got != want {
				pkg := strings.TrimSuffix(strings.TrimSuffix(e.Name(), ".md5sums"), ":amd64")
				c.report("binary-modified", full,
					fmt.Sprintf("system binary differs from dpkg record (package %s) — possible trojaned binary", pkg), store.SevCritical)
			}
		}
		f.Close()
	}
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
