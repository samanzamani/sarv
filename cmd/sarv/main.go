// Sarv — open-source malware guard for Linux web servers.
// Focused on web-borne infections: webshells, injected PHP, tampered
// WordPress/Laravel files, and post-compromise persistence.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"

	"github.com/samanzamani/sarv/internal/advisor"
	"github.com/samanzamani/sarv/internal/config"
	"github.com/samanzamani/sarv/internal/monitor"
	"github.com/samanzamani/sarv/internal/notify"
	"github.com/samanzamani/sarv/internal/quarantine"
	"github.com/samanzamani/sarv/internal/scanner"
	"github.com/samanzamani/sarv/internal/store"
	"github.com/samanzamani/sarv/internal/syscheck"
	"github.com/samanzamani/sarv/internal/web"
	"github.com/samanzamani/sarv/internal/wpverify"
)

var version = "dev" // set via -ldflags at release time

var (
	flagConfig  string
	flagJSON    bool
	flagNoCache bool
)

type app struct {
	cfg      *config.Config
	store    *store.Store
	quar     *quarantine.Manager
	telegram *notify.Telegram

	scanMu   sync.Mutex
	scanning atomic.Bool
	scanDone atomic.Int64
}

func newApp() (*app, error) {
	cfg, err := config.Load(flagConfig)
	if err != nil {
		return nil, err
	}
	st, err := store.Open(cfg.DBPath())
	if err != nil {
		return nil, fmt.Errorf("open database (need write access to %s): %w", cfg.DataDir, err)
	}
	tg, err := notify.NewTelegram(cfg.Telegram)
	if err != nil {
		log.Printf("warning: telegram disabled: %v", err)
	}
	return &app{
		cfg:      cfg,
		store:    st,
		quar:     quarantine.New(cfg.QuarantineDir()),
		telegram: tg,
	}, nil
}

// onFind handles a new finding: auto-quarantine per config and notify.
func (a *app) onFind(f store.Finding, isNew bool) {
	if !isNew {
		return
	}
	auto := a.cfg.Quarantine.Auto
	if f.Site != "system" && (auto == "all" ||
		(auto == "high" && (f.Severity == store.SevHigh || f.Severity == store.SevCritical))) {
		if _, err := a.quar.Add(f.Path, f.SHA256, f.Rule, f.ID); err == nil {
			_ = a.store.UpdateFindingStatus(f.ID, store.StatusQuarantined)
			f.Detail += " [auto-quarantined]"
		}
	}
	if a.telegram != nil {
		a.telegram.NotifyFinding(f)
	}
}

func (a *app) newScanner() (*scanner.Scanner, error) {
	sc, err := scanner.New(a.cfg, a.store)
	if err != nil {
		return nil, err
	}
	sc.OnFind = a.onFind
	sc.UseCache = !flagNoCache
	sc.Progress = func(done int64) { a.scanDone.Store(done) }
	return sc, nil
}

// runScan performs a scan of kind over paths; full scans add WP verification,
// Laravel baselines, syscheck, and the advisor.
func (a *app) runScan(kind string, paths []string) (*scanner.Result, error) {
	if !a.scanning.CompareAndSwap(false, true) {
		return nil, fmt.Errorf("a scan is already running")
	}
	defer a.scanning.Store(false)
	a.scanDone.Store(0)

	if len(paths) == 0 {
		paths = a.cfg.ScanPaths
	}
	sc, err := a.newScanner()
	if err != nil {
		return nil, err
	}
	scanID, _ := a.store.StartScan(kind)
	res, err := sc.ScanPaths(paths)
	status := "done"
	if err != nil {
		status = "failed"
	}

	if kind == "full" {
		v := wpverify.New(a.store, a.cfg.APICacheDir())
		v.OnFind = a.onFind
		for _, site := range sc.Sites {
			switch site.Type {
			case scanner.SiteWordPress:
				if err := v.VerifyWordPress(site); err != nil {
					log.Printf("wpverify %s: %v", site.Root, err)
				}
			case scanner.SiteLaravel:
				_ = v.VerifyLaravel(site)
			}
		}
		if a.cfg.Syscheck.Enabled {
			chk := syscheck.New(a.store, a.cfg.Syscheck.VerifyBinaries)
			chk.OnFind = a.onFind
			_ = chk.Run()
		}
		adv := advisor.New(a.store)
		adv.Sites = sc.Sites
		adv.ScanPaths = a.cfg.ScanPaths
		adv.Run()
	}

	_ = a.store.FinishScan(scanID, res.Scanned, res.Skipped, res.Findings, status)
	if a.telegram != nil {
		a.telegram.Flush()
	}
	return res, err
}

func (a *app) webHooks() web.Hooks {
	return web.Hooks{
		StartScan: func(kind string) error {
			if a.scanning.Load() {
				return fmt.Errorf("a scan is already running")
			}
			go func() {
				if _, err := a.runScan(kind, nil); err != nil {
					log.Printf("panel scan: %v", err)
				}
			}()
			return nil
		},
		ScanStatus: func() map[string]any {
			return map[string]any{"running": a.scanning.Load(), "done": a.scanDone.Load()}
		},
		TestNotify: func() error {
			tg, err := notify.NewTelegram(a.cfg.Telegram)
			if err != nil {
				return err
			}
			if tg == nil {
				return fmt.Errorf("telegram is not enabled/configured")
			}
			return tg.Send("✅ Sarv test message — notifications are working.")
		},
		SaveConfig: func(mutate func(*config.Config)) error {
			mutate(a.cfg)
			return a.cfg.Save(flagConfig)
		},
	}
}

func main() {
	root := &cobra.Command{
		Use:           "sarv",
		Short:         "Sarv — malware guard for Linux web servers (webshells, WP/Laravel integrity, persistence)",
		SilenceUsage:  true,
		SilenceErrors: false,
	}
	root.PersistentFlags().StringVarP(&flagConfig, "config", "c", "", "config file (default /etc/sarv/config.yml)")

	// --- scan ---
	scanCmd := &cobra.Command{
		Use:   "scan [paths...]",
		Short: "Scan paths for web malware (default: configured scan_paths)",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := newApp()
			if err != nil {
				return err
			}
			defer a.store.Close()
			start := time.Now()
			kind := "manual"
			if full, _ := cmd.Flags().GetBool("full"); full {
				kind = "full"
			}
			res, err := a.runScan(kind, args)
			if err != nil {
				return err
			}
			if flagJSON {
				return json.NewEncoder(os.Stdout).Encode(res)
			}
			fmt.Printf("Scanned %d files (%d skipped via cache, %d errors) in %s — %d new finding(s)\n",
				res.Scanned, res.Skipped, res.Errors, time.Since(start).Round(time.Millisecond), res.Findings)
			if res.Findings > 0 {
				fmt.Println("Run `sarv report` to review findings.")
			}
			return nil
		},
	}
	scanCmd.Flags().Bool("full", false, "full scan: also verify WordPress checksums, Laravel baselines, syscheck, advisor")
	scanCmd.Flags().BoolVar(&flagNoCache, "no-cache", false, "rescan every file, ignoring the clean-file cache")
	scanCmd.Flags().BoolVar(&flagJSON, "json", false, "JSON output")

	// --- monitor ---
	monitorCmd := &cobra.Command{
		Use:   "monitor",
		Short: "Run the realtime service: inotify watcher + scheduled scans (+ web panel if enabled)",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := newApp()
			if err != nil {
				return err
			}
			defer a.store.Close()
			sc, err := a.newScanner()
			if err != nil {
				return err
			}
			sc.Sites = scanner.DetectSites(a.cfg.ScanPaths, 3)
			log.Printf("monitor: detected %d sites", len(sc.Sites))

			m := monitor.New(a.cfg, a.store, sc)
			m.RunQuick = func() {
				if _, err := a.runScan("quick", quickPaths(a.cfg, sc.Sites)); err != nil {
					log.Printf("quick scan: %v", err)
				}
			}
			m.RunFull = func() {
				if _, err := a.runScan("full", nil); err != nil {
					log.Printf("full scan: %v", err)
				}
			}

			if a.cfg.Web.Enabled {
				srv := web.New(a.cfg, a.store, a.quar, a.webHooks())
				go func() {
					if err := srv.ListenAndServe(); err != nil {
						log.Printf("web panel: %v", err)
					}
				}()
			}

			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			return m.Run(ctx)
		},
	}

	// --- sites ---
	sitesCmd := &cobra.Command{
		Use:   "sites",
		Short: "List auto-detected WordPress and Laravel installations",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := newApp()
			if err != nil {
				return err
			}
			defer a.store.Close()
			sites := scanner.DetectSites(a.cfg.ScanPaths, 3)
			if flagJSON {
				return json.NewEncoder(os.Stdout).Encode(sites)
			}
			for _, s := range sites {
				v := s.Version
				if v == "" {
					v = "-"
				}
				fmt.Printf("%-10s %-8s %s\n", s.Type, v, s.Root)
			}
			fmt.Printf("%d site(s)\n", len(sites))
			return nil
		},
	}
	sitesCmd.Flags().BoolVar(&flagJSON, "json", false, "JSON output")

	// --- syscheck ---
	syscheckCmd := &cobra.Command{
		Use:   "syscheck",
		Short: "Check OS health: modified binaries, tmp droppers, persistence, SSH keys, processes",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := newApp()
			if err != nil {
				return err
			}
			defer a.store.Close()
			n := 0
			chk := syscheck.New(a.store, a.cfg.Syscheck.VerifyBinaries)
			chk.OnFind = func(f store.Finding, isNew bool) {
				a.onFind(f, isNew)
				if isNew {
					n++
					fmt.Printf("[%s] %-20s %s\n    %s\n", f.Severity, f.Rule, f.Path, f.Detail)
				}
			}
			if err := chk.Run(); err != nil {
				return err
			}
			if a.telegram != nil {
				a.telegram.Flush()
			}
			fmt.Printf("syscheck complete — %d new finding(s)\n", n)
			return nil
		},
	}

	// --- advise ---
	adviseCmd := &cobra.Command{
		Use:   "advise",
		Short: "Generate security hardening recommendations",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := newApp()
			if err != nil {
				return err
			}
			defer a.store.Close()
			adv := advisor.New(a.store)
			adv.Sites = scanner.DetectSites(a.cfg.ScanPaths, 3)
			adv.ScanPaths = a.cfg.ScanPaths
			adv.Run()
			list, err := a.store.AdviceList()
			if err != nil {
				return err
			}
			if flagJSON {
				return json.NewEncoder(os.Stdout).Encode(list)
			}
			for _, ad := range list {
				if ad.State != "open" {
					continue
				}
				fmt.Printf("[%s] %s\n    %s\n    💡 %s\n\n", ad.Severity, ad.Title, ad.Detail, ad.Remedy)
			}
			return nil
		},
	}
	adviseCmd.Flags().BoolVar(&flagJSON, "json", false, "JSON output")

	// --- quarantine ---
	quarCmd := &cobra.Command{Use: "quarantine", Short: "Manage quarantined files"}
	quarCmd.AddCommand(
		&cobra.Command{
			Use: "list", Short: "List quarantined files",
			RunE: func(cmd *cobra.Command, args []string) error {
				a, err := newApp()
				if err != nil {
					return err
				}
				defer a.store.Close()
				items, err := a.quar.List()
				if err != nil {
					return err
				}
				for _, m := range items {
					fmt.Printf("%-24s %-20s %s\n", m.ID, m.Rule, m.OriginalPath)
				}
				fmt.Printf("%d item(s)\n", len(items))
				return nil
			},
		},
		&cobra.Command{
			Use: "add <finding-id|file>", Short: "Quarantine a finding by id, or a file by path", Args: cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				a, err := newApp()
				if err != nil {
					return err
				}
				defer a.store.Close()
				var path, sha, rule string
				var fid int64
				if id, err := strconv.ParseInt(args[0], 10, 64); err == nil {
					f, err := a.store.GetFinding(id)
					if err != nil {
						return err
					}
					path, sha, rule, fid = f.Path, f.SHA256, f.Rule, f.ID
				} else {
					path, rule = args[0], "manual"
				}
				qid, err := a.quar.Add(path, sha, rule, fid)
				if err != nil {
					return err
				}
				if fid > 0 {
					_ = a.store.UpdateFindingStatus(fid, store.StatusQuarantined)
				}
				fmt.Printf("quarantined as %s\n", qid)
				return nil
			},
		},
		&cobra.Command{
			Use: "restore <id>", Short: "Restore a quarantined file to its original location", Args: cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				a, err := newApp()
				if err != nil {
					return err
				}
				defer a.store.Close()
				meta, err := a.quar.Restore(args[0])
				if err != nil {
					return err
				}
				if meta.FindingID > 0 {
					_ = a.store.UpdateFindingStatus(meta.FindingID, store.StatusOpen)
				}
				fmt.Printf("restored to %s\n", meta.OriginalPath)
				return nil
			},
		},
		&cobra.Command{
			Use: "delete <id>", Short: "Permanently delete a quarantined file", Args: cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				a, err := newApp()
				if err != nil {
					return err
				}
				defer a.store.Close()
				if err := a.quar.Delete(args[0]); err != nil {
					return err
				}
				fmt.Println("deleted")
				return nil
			},
		},
	)

	// --- report ---
	reportCmd := &cobra.Command{
		Use:   "report",
		Short: "Show findings (default: open)",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := newApp()
			if err != nil {
				return err
			}
			defer a.store.Close()
			status, _ := cmd.Flags().GetString("status")
			list, err := a.store.Findings(status, 500)
			if err != nil {
				return err
			}
			if flagJSON {
				return json.NewEncoder(os.Stdout).Encode(list)
			}
			for _, f := range list {
				fmt.Printf("#%-5d [%s] %-24s %s\n       %s\n", f.ID, f.Severity, f.Rule, f.Path, f.Detail)
			}
			fmt.Printf("%d finding(s)\n", len(list))
			return nil
		},
	}
	reportCmd.Flags().String("status", "open", "filter: open|quarantined|ignored|resolved|'' for all")
	reportCmd.Flags().BoolVar(&flagJSON, "json", false, "JSON output")

	// --- notify ---
	notifyCmd := &cobra.Command{Use: "notify", Short: "Notification helpers"}
	notifyCmd.AddCommand(&cobra.Command{
		Use: "test", Short: "Send a Telegram test message (verifies token, chat id, and proxy)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(flagConfig)
			if err != nil {
				return err
			}
			cfg.Telegram.Enabled = true
			tg, err := notify.NewTelegram(cfg.Telegram)
			if err != nil {
				return err
			}
			if tg == nil {
				return fmt.Errorf("telegram bot_token/chat_id not configured in %s", config.DefaultPath)
			}
			if err := tg.Send("✅ Sarv test message — notifications are working."); err != nil {
				return err
			}
			fmt.Println("sent")
			return nil
		},
	})

	// --- web ---
	webCmd := &cobra.Command{
		Use:   "web",
		Short: "Run the web panel standalone (it also runs inside `sarv monitor` when web.enabled)",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := newApp()
			if err != nil {
				return err
			}
			defer a.store.Close()
			if a.cfg.Web.PasswordHash == "" {
				return fmt.Errorf("no panel password set — run: sarv web set-password")
			}
			srv := web.New(a.cfg, a.store, a.quar, a.webHooks())
			return srv.ListenAndServe()
		},
	}
	webCmd.AddCommand(&cobra.Command{
		Use: "set-password", Short: "Set the panel login password",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(flagConfig)
			if err != nil {
				return err
			}
			fmt.Print("New panel password: ")
			pw, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Println()
			if err != nil {
				return err
			}
			if len(pw) < 8 {
				return fmt.Errorf("password must be at least 8 characters")
			}
			hash, err := bcrypt.GenerateFromPassword(pw, bcrypt.DefaultCost)
			if err != nil {
				return err
			}
			cfg.Web.PasswordHash = string(hash)
			if err := cfg.Save(flagConfig); err != nil {
				return err
			}
			fmt.Println("password saved")
			return nil
		},
	})

	root.AddCommand(scanCmd, monitorCmd, sitesCmd, syscheckCmd, adviseCmd, quarCmd, reportCmd, notifyCmd, webCmd,
		&cobra.Command{
			Use: "version", Short: "Print version",
			Run: func(cmd *cobra.Command, args []string) { fmt.Println("sarv", version) },
		})

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

// quickPaths returns the high-risk subset scanned hourly: uploads/public dirs.
func quickPaths(cfg *config.Config, sites []scanner.Site) []string {
	var out []string
	for _, s := range sites {
		switch s.Type {
		case scanner.SiteWordPress:
			out = append(out, s.Root+"/wp-content")
		case scanner.SiteLaravel:
			out = append(out, s.Root+"/public", s.Root+"/storage")
		}
	}
	if len(out) == 0 {
		return cfg.ScanPaths
	}
	return out
}
