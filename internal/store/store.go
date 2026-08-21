// Package store persists scan state: the clean-file cache, findings,
// baselines, and scan history. Backed by pure-Go SQLite (no CGO).
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

// Finding severity levels.
const (
	SevLow      = "low"
	SevMedium   = "medium"
	SevHigh     = "high"
	SevCritical = "critical"
)

// Finding statuses.
const (
	StatusOpen        = "open"
	StatusQuarantined = "quarantined"
	StatusIgnored     = "ignored"
	StatusResolved    = "resolved"
)

type Finding struct {
	ID        int64     `json:"id"`
	Path      string    `json:"path"`
	Site      string    `json:"site"`
	Rule      string    `json:"rule"`
	Detail    string    `json:"detail"`
	Severity  string    `json:"severity"`
	SHA256    string    `json:"sha256"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type ScanRun struct {
	ID        int64      `json:"id"`
	Kind      string     `json:"kind"` // full | quick | realtime | manual
	StartedAt time.Time  `json:"started_at"`
	EndedAt   *time.Time `json:"ended_at,omitempty"`
	Scanned   int64      `json:"scanned"`
	Skipped   int64      `json:"skipped"`
	Findings  int64      `json:"findings"`
	Status    string     `json:"status"` // running | done | failed
}

const schema = `
CREATE TABLE IF NOT EXISTS filecache (
  path TEXT PRIMARY KEY,
  size INTEGER NOT NULL,
  mtime INTEGER NOT NULL,
  sha256 TEXT NOT NULL,
  verdict TEXT NOT NULL,        -- clean | finding
  scanned_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  path TEXT NOT NULL,
  site TEXT NOT NULL DEFAULT '',
  rule TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '',
  severity TEXT NOT NULL,
  sha256 TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'open',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_dedup ON findings(path, rule, sha256);
CREATE TABLE IF NOT EXISTS baseline (
  kind TEXT NOT NULL,           -- laravel_pub | authorized_keys | systemd | cron | ...
  key TEXT NOT NULL,
  value TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (kind, key)
);
CREATE TABLE IF NOT EXISTS scans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,
  started_at INTEGER NOT NULL,
  ended_at INTEGER,
  scanned INTEGER NOT NULL DEFAULT 0,
  skipped INTEGER NOT NULL DEFAULT 0,
  findings INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'running'
);
CREATE TABLE IF NOT EXISTS advice (
  id TEXT PRIMARY KEY,          -- stable check id
  title TEXT NOT NULL,
  detail TEXT NOT NULL,
  severity TEXT NOT NULL,
  remedy TEXT NOT NULL DEFAULT '',
  state TEXT NOT NULL DEFAULT 'open',  -- open | done | dismissed
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS kv (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
`

func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)")
	if err != nil {
		return nil, err
	}
	// SQLite allows one writer; serialize access through a single connection.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// --- file cache ---

// CachedVerdict returns the stored verdict for a file if size and mtime are
// unchanged since the last scan. ok=false means the file must be (re)scanned.
func (s *Store) CachedVerdict(path string, size, mtime int64) (verdict string, ok bool) {
	row := s.db.QueryRow(`SELECT verdict FROM filecache WHERE path=? AND size=? AND mtime=?`, path, size, mtime)
	if err := row.Scan(&verdict); err != nil {
		return "", false
	}
	return verdict, true
}

func (s *Store) SetVerdict(path string, size, mtime int64, sha256, verdict string) error {
	_, err := s.db.Exec(`INSERT INTO filecache(path,size,mtime,sha256,verdict,scanned_at)
		VALUES(?,?,?,?,?,?)
		ON CONFLICT(path) DO UPDATE SET size=excluded.size, mtime=excluded.mtime,
		  sha256=excluded.sha256, verdict=excluded.verdict, scanned_at=excluded.scanned_at`,
		path, size, mtime, sha256, verdict, time.Now().Unix())
	return err
}

// --- findings ---

// AddFinding inserts a finding, reopening an identical resolved one if present.
// Returns the finding id and whether it is new (not a duplicate of an open one).
func (s *Store) AddFinding(f *Finding) (int64, bool, error) {
	now := time.Now().Unix()
	res, err := s.db.Exec(`INSERT INTO findings(path,site,rule,detail,severity,sha256,status,created_at,updated_at)
		VALUES(?,?,?,?,?,?,?,?,?)
		ON CONFLICT(path,rule,sha256) DO UPDATE SET updated_at=excluded.updated_at`,
		f.Path, f.Site, f.Rule, f.Detail, f.Severity, f.SHA256, StatusOpen, now, now)
	if err != nil {
		return 0, false, err
	}
	if n, _ := res.RowsAffected(); n == 1 {
		id, _ := res.LastInsertId()
		return id, true, nil
	}
	var id int64
	_ = s.db.QueryRow(`SELECT id FROM findings WHERE path=? AND rule=? AND sha256=?`, f.Path, f.Rule, f.SHA256).Scan(&id)
	return id, false, nil
}

func (s *Store) UpdateFindingStatus(id int64, status string) error {
	_, err := s.db.Exec(`UPDATE findings SET status=?, updated_at=? WHERE id=?`, status, time.Now().Unix(), id)
	return err
}

func (s *Store) GetFinding(id int64) (*Finding, error) {
	rows, err := s.db.Query(`SELECT id,path,site,rule,detail,severity,sha256,status,created_at,updated_at FROM findings WHERE id=?`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list, err := scanFindings(rows)
	if err != nil || len(list) == 0 {
		return nil, fmt.Errorf("finding %d not found", id)
	}
	return &list[0], nil
}

// Findings lists findings, optionally filtered by status ("" = all), newest first.
func (s *Store) Findings(status string, limit int) ([]Finding, error) {
	q := `SELECT id,path,site,rule,detail,severity,sha256,status,created_at,updated_at FROM findings`
	args := []any{}
	if status != "" {
		q += ` WHERE status=?`
		args = append(args, status)
	}
	q += ` ORDER BY id DESC`
	if limit > 0 {
		q += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanFindings(rows)
}

func scanFindings(rows *sql.Rows) ([]Finding, error) {
	var out []Finding
	for rows.Next() {
		var f Finding
		var created, updated int64
		if err := rows.Scan(&f.ID, &f.Path, &f.Site, &f.Rule, &f.Detail, &f.Severity, &f.SHA256, &f.Status, &created, &updated); err != nil {
			return nil, err
		}
		f.CreatedAt = time.Unix(created, 0)
		f.UpdatedAt = time.Unix(updated, 0)
		out = append(out, f)
	}
	return out, rows.Err()
}

func (s *Store) CountFindings(status string) (int64, error) {
	var n int64
	err := s.db.QueryRow(`SELECT COUNT(*) FROM findings WHERE status=?`, status).Scan(&n)
	return n, err
}

// --- baselines ---

func (s *Store) BaselineGet(kind, key string) (string, bool) {
	var v string
	if err := s.db.QueryRow(`SELECT value FROM baseline WHERE kind=? AND key=?`, kind, key).Scan(&v); err != nil {
		return "", false
	}
	return v, true
}

func (s *Store) BaselineSet(kind, key, value string) error {
	_, err := s.db.Exec(`INSERT INTO baseline(kind,key,value,created_at) VALUES(?,?,?,?)
		ON CONFLICT(kind,key) DO UPDATE SET value=excluded.value`, kind, key, value, time.Now().Unix())
	return err
}

func (s *Store) BaselineAll(kind string) (map[string]string, error) {
	rows, err := s.db.Query(`SELECT key, value FROM baseline WHERE kind=?`, kind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

func (s *Store) BaselineHas(kind string) bool {
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM baseline WHERE kind=?`, kind).Scan(&n)
	return n > 0
}

// --- scan runs ---

func (s *Store) StartScan(kind string) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO scans(kind,started_at,status) VALUES(?,?,'running')`, kind, time.Now().Unix())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) FinishScan(id, scanned, skipped, findings int64, status string) error {
	_, err := s.db.Exec(`UPDATE scans SET ended_at=?, scanned=?, skipped=?, findings=?, status=? WHERE id=?`,
		time.Now().Unix(), scanned, skipped, findings, status, id)
	return err
}

func (s *Store) RecentScans(limit int) ([]ScanRun, error) {
	rows, err := s.db.Query(`SELECT id,kind,started_at,ended_at,scanned,skipped,findings,status FROM scans ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ScanRun
	for rows.Next() {
		var r ScanRun
		var started int64
		var ended sql.NullInt64
		if err := rows.Scan(&r.ID, &r.Kind, &started, &ended, &r.Scanned, &r.Skipped, &r.Findings, &r.Status); err != nil {
			return nil, err
		}
		r.StartedAt = time.Unix(started, 0)
		if ended.Valid {
			t := time.Unix(ended.Int64, 0)
			r.EndedAt = &t
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// --- advice ---

type Advice struct {
	ID        string    `json:"id"`
	Title     string    `json:"title"`
	Detail    string    `json:"detail"`
	Severity  string    `json:"severity"`
	Remedy    string    `json:"remedy"`
	State     string    `json:"state"`
	UpdatedAt time.Time `json:"updated_at"`
}

// UpsertAdvice records a hardening recommendation, preserving done/dismissed state.
func (s *Store) UpsertAdvice(a Advice) error {
	_, err := s.db.Exec(`INSERT INTO advice(id,title,detail,severity,remedy,state,updated_at)
		VALUES(?,?,?,?,?,'open',?)
		ON CONFLICT(id) DO UPDATE SET title=excluded.title, detail=excluded.detail,
		  severity=excluded.severity, remedy=excluded.remedy, updated_at=excluded.updated_at`,
		a.ID, a.Title, a.Detail, a.Severity, a.Remedy, time.Now().Unix())
	return err
}

func (s *Store) SetAdviceState(id, state string) error {
	_, err := s.db.Exec(`UPDATE advice SET state=?, updated_at=? WHERE id=?`, state, time.Now().Unix(), id)
	return err
}

func (s *Store) AdviceList() ([]Advice, error) {
	rows, err := s.db.Query(`SELECT id,title,detail,severity,remedy,state,updated_at FROM advice ORDER BY
		CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Advice
	for rows.Next() {
		var a Advice
		var updated int64
		if err := rows.Scan(&a.ID, &a.Title, &a.Detail, &a.Severity, &a.Remedy, &a.State, &updated); err != nil {
			return nil, err
		}
		a.UpdatedAt = time.Unix(updated, 0)
		out = append(out, a)
	}
	return out, rows.Err()
}

// --- kv ---

func (s *Store) KVGet(key string, out any) bool {
	var v string
	if err := s.db.QueryRow(`SELECT value FROM kv WHERE key=?`, key).Scan(&v); err != nil {
		return false
	}
	return json.Unmarshal([]byte(v), out) == nil
}

func (s *Store) KVSet(key string, val any) error {
	b, err := json.Marshal(val)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO kv(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, string(b))
	return err
}
