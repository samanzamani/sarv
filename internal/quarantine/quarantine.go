// Package quarantine moves detected files into an isolated store with full
// metadata so they can be restored exactly, and neutralizes their permissions.
package quarantine

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

type Meta struct {
	ID           string    `json:"id"`
	OriginalPath string    `json:"original_path"`
	SHA256       string    `json:"sha256"`
	Mode         uint32    `json:"mode"`
	UID          int       `json:"uid"`
	GID          int       `json:"gid"`
	Rule         string    `json:"rule"`
	FindingID    int64     `json:"finding_id"`
	QuarantinedAt time.Time `json:"quarantined_at"`
}

type Manager struct {
	Dir string
}

func New(dir string) *Manager { return &Manager{Dir: dir} }

// Add moves path into quarantine and returns the quarantine id.
func (m *Manager) Add(path, sha, rule string, findingID int64) (string, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", path)
	}
	id := time.Now().UTC().Format("20060102-150405") + "-" + strconv.FormatInt(time.Now().UnixNano()%1e6, 10)
	qdir := filepath.Join(m.Dir, id)
	if err := os.MkdirAll(qdir, 0o700); err != nil {
		return "", err
	}
	meta := Meta{
		ID: id, OriginalPath: path, SHA256: sha, Rule: rule, FindingID: findingID,
		Mode: uint32(st.Mode().Perm()), QuarantinedAt: time.Now(),
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		meta.UID = int(sys.Uid)
		meta.GID = int(sys.Gid)
	}
	dst := filepath.Join(qdir, "payload")
	if err := moveFile(path, dst); err != nil {
		os.RemoveAll(qdir)
		return "", err
	}
	_ = os.Chmod(dst, 0)
	mb, _ := json.MarshalIndent(meta, "", "  ")
	if err := os.WriteFile(filepath.Join(qdir, "meta.json"), mb, 0o600); err != nil {
		return "", err
	}
	return id, nil
}

// Restore puts a quarantined file back with original permissions and ownership.
func (m *Manager) Restore(id string) (*Meta, error) {
	meta, err := m.meta(id)
	if err != nil {
		return nil, err
	}
	src := filepath.Join(m.Dir, id, "payload")
	if err := moveFile(src, meta.OriginalPath); err != nil {
		return nil, err
	}
	_ = os.Chmod(meta.OriginalPath, os.FileMode(meta.Mode))
	_ = os.Chown(meta.OriginalPath, meta.UID, meta.GID)
	_ = os.RemoveAll(filepath.Join(m.Dir, id))
	return meta, nil
}

// Delete permanently removes a quarantined item.
func (m *Manager) Delete(id string) error {
	if _, err := m.meta(id); err != nil {
		return err
	}
	return os.RemoveAll(filepath.Join(m.Dir, id))
}

func (m *Manager) List() ([]Meta, error) {
	entries, err := os.ReadDir(m.Dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []Meta
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if meta, err := m.meta(e.Name()); err == nil {
			out = append(out, *meta)
		}
	}
	return out, nil
}

func (m *Manager) meta(id string) (*Meta, error) {
	if filepath.Base(id) != id {
		return nil, fmt.Errorf("invalid quarantine id")
	}
	data, err := os.ReadFile(filepath.Join(m.Dir, id, "meta.json"))
	if err != nil {
		return nil, fmt.Errorf("quarantine item %s not found", id)
	}
	var meta Meta
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, err
	}
	return &meta, nil
}

// moveFile renames, falling back to copy+remove across filesystems.
func moveFile(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Remove(src)
}
