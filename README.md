# 🛡 Sarv

**Open-source malware guard for Linux web servers**, focused on web-borne infections: webshells, injected PHP, tampered WordPress/Laravel files, and post-compromise persistence.

A single static Go binary — no dependencies, no agent, no CGO. Built for shared hosting boxes running many WordPress and Laravel sites.

> فارسی: [README.fa.md](README.fa.md)

## Why

ClamAV signatures miss most PHP webshells, and Linux Malware Detect is slow to rescan large trees. Sarv is purpose-built for the web-hosting threat model:

- **Realtime** — an `inotify` watcher scans every new/changed PHP-ish file within seconds of it landing (the moment a shell is uploaded).
- **Fast rescans** — a SQLite clean-file cache keyed on `path+size+mtime` means a full rescan of hundreds of thousands of files takes seconds after the first run.
- **Integrity, not just signatures** — WordPress core/plugin files are checked against official wordpress.org checksums; Laravel `public/`/`storage/` PHP is diffed against a baseline.
- **Beyond the web root** — optional OS health checks catch attacker persistence (trojaned binaries, `/tmp` droppers, rogue cron/systemd units, SSH key changes, miner processes).
- **Actionable advice** — a hardening advisor turns findings into concrete recommendations.

## Detection pipeline

Each file flows through: **clean-file cache → signature rules → heuristics**, plus integrity checks on the full scan.

- **Signature rules** — curated YAML rules for common PHP webshells (WSO, c99, r57, b374k, alfa, FilesMan…), obfuscated droppers (`eval(base64_decode(...))`, goto/`$GLOBALS` packers), request-fed `system()`/variable-functions, malicious `.htaccess` handlers, JS miners, and more. Ships embedded; extend via `/etc/sarv/rules.d/*.yml`.
- **Heuristics** — entropy, giant one-liners, base64/hex blobs, PHP inside `uploads/`, double extensions (`.jpg.php`), hidden PHP files, timestomping.
- **WordPress verify** — official checksums flag any modified or extra file in `wp-admin/` and `wp-includes/`.
- **Laravel baseline** — new/changed PHP in `public/` or `storage/` after the first (clean) scan is reported.

## Scan schedule

| Layer | When | Scope |
|---|---|---|
| Realtime | seconds after a file changes | new/changed high-risk files via inotify |
| Quick | hourly | uploads / wp-content / public dirs + recently modified files |
| Full | nightly (3am, configurable) | everything + WP checksums + syscheck + advisor |

All run inside `sarv monitor`, niced and idle-io'd to stay off production's critical path.

## Install

```bash
git clone https://github.com/samanzamani/sarv && cd sarv
sudo make install         # builds, installs binary + config + systemd unit
```

Or grab a prebuilt binary from [Releases](https://github.com/samanzamani/sarv/releases) and run `deploy/install.sh`.

Then:

```bash
sudoedit /etc/sarv/config.yml     # scan paths, Telegram token/chat/proxy
sarv web set-password             # optional: web panel login
sarv scan --full                  # initial baseline scan
systemctl enable --now sarv       # realtime + scheduled scanning
sarv notify test                  # verify Telegram alerts
```

## Commands

```
sarv scan [paths...] [--full]   Scan for malware (--full adds WP verify, syscheck, advisor)
sarv monitor                    Realtime service: inotify + scheduled scans (+ web panel)
sarv sites                      List auto-detected WordPress/Laravel installs
sarv syscheck                   OS health: binaries, /tmp droppers, persistence, processes
sarv advise                     Security hardening recommendations
sarv report [--status open]     Show findings
sarv quarantine list|add|restore|delete
sarv web [set-password]         Run/configure the web panel
sarv notify test                Send a Telegram test message
```

## Response

Default is **report + manual quarantine** — findings are recorded and alerted, nothing is touched until you act. Quarantine moves the file to `/var/lib/sarv/quarantine/` with full metadata (perms, owner, hash) so `restore` puts it back exactly. Set `quarantine.auto: high|all` to quarantine automatically.

## Web panel (optional)

Off by default. `web.enabled: true` (or `sarv web`) serves a self-contained panel — **independent of the server's Apache/OpenLiteSpeed/FrankenPHP** — with dashboard, findings, quarantine, manual scan, system health, recommendations, and settings. Login is required (bcrypt); bind to `127.0.0.1` and reach it over an SSH tunnel, or set TLS and a firewall rule for remote access.

## Alerts

Telegram Bot API with optional **HTTP or SOCKS5 proxy** (`proxy_url`) — useful where `api.telegram.org` is blocked. Findings during a scan are batched into a single message.

## Notes & scope

- Sarv **detects and reports**; it never modifies your sites or OS on its own (only quarantine, and only when you enable it).
- It complements, not replaces, `rkhunter`/`AIDE`/a WAF.
- Signature coverage is a moving target — PRs with new rules and test fixtures are welcome.

## License

MIT — see [LICENSE](LICENSE).
