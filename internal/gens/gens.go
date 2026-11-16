// Package gens stores restore generations under ~/.mimo-backup: displaced
// trees, the extracted-entry journal, status metadata, and the shared event
// log. A generation is the unit of rollback: restore creates one, rollback
// consumes one, cleanup prunes old ones.
package gens

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Layout under the store root (~/.mimo-backup):
//
//	generations/<id>/            id = UTC timestamp
//	  meta.json                  source, status, displaced roots, git commits
//	  displaced/<home-rel path>  trees taken aside before restore
//	  extracted.jsonl            every entry the restore wrote
//	settings-repo/               git copies of tracked settings (see vcs)
//	journal.jsonl                shared event log (restore/rollback/cleanup)
const (
	DirName        = ".mimo-backup"
	generationsDir = "generations"
	settingsRepo   = "settings-repo"
	eventLogName   = "journal.jsonl"
	metaName       = "meta.json"
	extractedName  = "extracted.jsonl"
	displacedName  = "displaced"
)

// Status is the lifecycle state of a generation.
type Status string

const (
	StatusInProgress Status = "in-progress"
	StatusApplied    Status = "applied"
	StatusFailed     Status = "failed"
	StatusRolledBack Status = "rolled-back"
)

// Meta is the generation descriptor (meta.json).
type Meta struct {
	ID                string            `json:"id"`
	CreatedAt         time.Time         `json:"created_at"`
	Source            string            `json:"source"`
	Status            Status            `json:"status"`
	DisplacedRoots    []string          `json:"displaced_roots"`
	DirMTimes         map[string]string `json:"dir_mtimes,omitempty"` // home-rel → RFC3339Nano
	PreRestoreCommit  string            `json:"pre_restore_commit,omitempty"`
	PostRestoreCommit string            `json:"post_restore_commit,omitempty"`
	PreRollbackCommit string            `json:"pre_rollback_commit,omitempty"`
}

// ExtractedEntry is one entry a restore wrote (or created) under $HOME.
type ExtractedEntry struct {
	Path    string `json:"path"` // home-relative
	Type    string `json:"type"` // "file" | "dir" | "symlink"
	Created bool   `json:"created,omitempty"`
	SHA256  string `json:"sha256,omitempty"`
	Link    string `json:"link,omitempty"`
}

// Event is one line of the shared journal.jsonl.
type Event struct {
	Event string    `json:"event"` // restore | rollback | cleanup | prune
	Gen   string    `json:"gen,omitempty"`
	At    time.Time `json:"at"`
	Note  string    `json:"note,omitempty"`
}

// Store is the ~/.mimo-backup root.
type Store struct {
	root string
}

// Open creates (if needed) and returns the store for a home directory.
func Open(home string) (*Store, error) {
	root := filepath.Join(home, DirName)
	if err := os.MkdirAll(filepath.Join(root, generationsDir), 0o700); err != nil {
		return nil, fmt.Errorf("mimo-backup store: %w", err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return nil, err
	}
	return &Store{root: root}, nil
}

// Root returns the store root (~/.mimo-backup).
func (s *Store) Root() string { return s.root }

// SettingsRepo returns the git settings-repo path inside the store.
func (s *Store) SettingsRepo() string { return filepath.Join(s.root, settingsRepo) }

// NewGeneration creates the next generation directory and its meta.json.
// The ID is a UTC timestamp, unique per second; a collision suffixes _N.
func (s *Store) NewGeneration(source string) (*Generation, error) {
	base := time.Now().UTC().Format("20060102-150405")
	id := base
	for n := 1; ; n++ {
		if _, err := os.Stat(filepath.Join(s.root, generationsDir, id)); os.IsNotExist(err) {
			break
		}
		id = fmt.Sprintf("%s_%d", base, n)
	}
	dir := filepath.Join(s.root, generationsDir, id)
	if err := os.MkdirAll(filepath.Join(dir, displacedName), 0o700); err != nil {
		return nil, err
	}
	g := &Generation{dir: dir, store: s}
	g.Meta = Meta{
		ID:        id,
		CreatedAt: time.Now().UTC(),
		Source:    source,
		Status:    StatusInProgress,
	}
	if err := g.SaveMeta(); err != nil {
		return nil, err
	}
	return g, nil
}

// Generations returns all generations sorted by id (oldest first).
func (s *Store) Generations() ([]*Generation, error) {
	ents, err := os.ReadDir(filepath.Join(s.root, generationsDir))
	if err != nil {
		return nil, err
	}
	var out []*Generation
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		g, err := s.load(e.Name())
		if err != nil {
			continue // corrupt meta: skip, Cleanup can drop it
		}
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Meta.ID < out[j].Meta.ID })
	return out, nil
}

// Latest returns the newest generation that rollback can consume
// (status applied or failed), or nil when the stack is empty.
func (s *Store) Latest() (*Generation, error) {
	gs, err := s.Generations()
	if err != nil {
		return nil, err
	}
	for i := len(gs) - 1; i >= 0; i-- {
		switch gs[i].Meta.Status {
		case StatusApplied, StatusFailed:
			return gs[i], nil
		}
	}
	return nil, nil
}

func (s *Store) load(id string) (*Generation, error) {
	dir := filepath.Join(s.root, generationsDir, id)
	b, err := os.ReadFile(filepath.Join(dir, metaName))
	if err != nil {
		return nil, err
	}
	var m Meta
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	if m.ID == "" {
		m.ID = id
	}
	return &Generation{dir: dir, store: s, Meta: m}, nil
}

// LogEvent appends one event to the shared journal.
func (s *Store) LogEvent(e Event) error {
	e.At = time.Now().UTC()
	f, err := os.OpenFile(filepath.Join(s.root, eventLogName), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		return err
	}
	return f.Sync()
}

// PruneDisplaced drops displaced trees of every generation except keepID,
// turning them into meta-only records. Returns the pruned ids.
func (s *Store) PruneDisplaced(keepID string) ([]string, error) {
	gs, err := s.Generations()
	if err != nil {
		return nil, err
	}
	var pruned []string
	for _, g := range gs {
		if g.Meta.ID == keepID {
			continue
		}
		d := g.DisplacedDir()
		if _, err := os.Stat(d); err != nil {
			continue
		}
		if err := os.RemoveAll(d); err != nil {
			return pruned, err
		}
		if err := os.MkdirAll(d, 0o700); err != nil {
			return pruned, err
		}
		pruned = append(pruned, g.Meta.ID)
	}
	return pruned, nil
}

// Cleanup removes generations per the retention policy: keep the newest
// `keep` (default 3) and every generation that still holds displaced data
// at the top of the stack; --all keeps only the newest. With dryRun it only
// reports. Returns removed ids and warnings about displaced trees that
// still hold user data.
func (s *Store) Cleanup(keep int, all, dryRun bool) (removed []string, warnings []string, err error) {
	if keep <= 0 {
		keep = 3
	}
	gs, err := s.Generations()
	if err != nil {
		return nil, nil, err
	}
	// The newest generation with displaced data is the rollback point —
	// never remove it here.
	protect := map[string]bool{}
	for i := len(gs) - 1; i >= 0; i-- {
		if gs[i].HasDisplaced() {
			protect[gs[i].Meta.ID] = true
			break
		}
	}
	if all {
		if len(gs) > 0 {
			protect[gs[len(gs)-1].Meta.ID] = true
		}
	}
	for i, g := range gs {
		fromEnd := len(gs) - i // 1 = newest
		if protect[g.Meta.ID] {
			continue
		}
		if !all && fromEnd <= keep {
			continue
		}
		if g.HasDisplaced() {
			warnings = append(warnings, fmt.Sprintf("поколение %s содержит отодвинутые данные — проверьте перед удалением", g.Meta.ID))
		}
		if !dryRun {
			if err := os.RemoveAll(g.dir); err != nil {
				return removed, warnings, err
			}
		}
		removed = append(removed, g.Meta.ID)
	}
	return removed, warnings, nil
}

// Generation is one restore/rollback unit.
type Generation struct {
	dir   string
	store *Store
	Meta  Meta
}

// ID returns the generation id.
func (g *Generation) ID() string { return g.Meta.ID }

// Dir returns the generation directory.
func (g *Generation) Dir() string { return g.dir }

// DisplacedDir returns the displaced-trees directory.
func (g *Generation) DisplacedDir() string { return filepath.Join(g.dir, displacedName) }

// DisplacedPath maps a home-relative path to its displaced location.
func (g *Generation) DisplacedPath(rel string) string {
	return filepath.Join(g.DisplacedDir(), filepath.FromSlash(rel))
}

// HasDisplaced reports whether the generation still holds displaced data.
func (g *Generation) HasDisplaced() bool {
	ents, err := os.ReadDir(g.DisplacedDir())
	if err != nil {
		return false
	}
	return len(ents) > 0
}

// SaveMeta writes meta.json atomically (tmp + rename + fsync).
func (g *Generation) SaveMeta() error {
	b, err := json.MarshalIndent(g.Meta, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(g.dir, metaName), b, 0o600)
}

// SetStatus updates the status and persists meta.json.
func (g *Generation) SetStatus(st Status) error {
	g.Meta.Status = st
	return g.SaveMeta()
}

// Journal is the append-only extracted.jsonl of one generation.
type Journal struct {
	f *os.File
	w *bufio.Writer
}

// OpenJournal opens the extracted journal for appending.
func (g *Generation) OpenJournal() (*Journal, error) {
	f, err := os.OpenFile(filepath.Join(g.dir, extractedName), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	return &Journal{f: f, w: bufio.NewWriter(f)}, nil
}

// Record appends one entry and fsyncs it (crash-safe write-ahead).
func (j *Journal) Record(e ExtractedEntry) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if _, err := j.w.Write(append(b, '\n')); err != nil {
		return fmt.Errorf("extracted journal: %w", err)
	}
	if err := j.w.Flush(); err != nil {
		return fmt.Errorf("extracted journal: %w", err)
	}
	return j.f.Sync()
}

// Close flushes and closes the journal.
func (j *Journal) Close() error {
	if err := j.w.Flush(); err != nil {
		return err
	}
	return j.f.Close()
}

// Extracted reads all recorded entries (oldest first).
func (g *Generation) Extracted() ([]ExtractedEntry, error) {
	f, err := os.Open(filepath.Join(g.dir, extractedName))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var out []ExtractedEntry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e ExtractedEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return nil, fmt.Errorf("extracted journal: %w", err)
		}
		out = append(out, e)
	}
	return out, sc.Err()
}

// MoveTree renames src to dst (creating parents), falling back to a
// metadata-preserving copy across filesystems (EXDEV), then fsyncs the
// destination parent.
func MoveTree(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	// An empty leftover directory would block the rename; drop it.
	if fi, err := os.Stat(dst); err == nil && fi.IsDir() {
		if ents, err := os.ReadDir(dst); err == nil && len(ents) == 0 {
			_ = os.Remove(dst)
		}
	}
	if err := os.Rename(src, dst); err == nil {
		return syncDir(filepath.Dir(dst))
	} else {
		// Cross-device (or blocked) rename: copy then remove.
		if err := copyTree(src, dst); err != nil {
			return err
		}
		if err := os.RemoveAll(src); err != nil {
			return err
		}
		return syncDir(filepath.Dir(dst))
	}
}

// copyTree recreates src at dst preserving modes, mtimes and symlinks.
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case d.IsDir():
			if err := os.MkdirAll(target, info.Mode().Perm()); err != nil {
				return err
			}
		case info.Mode()&fs.ModeSymlink != 0:
			link, err := os.Readlink(p)
			if err != nil {
				return err
			}
			if err := os.Symlink(link, target); err != nil {
				return err
			}
		case info.Mode().IsRegular():
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			if err := os.WriteFile(target, data, info.Mode().Perm()); err != nil {
				return err
			}
			if err := os.Chtimes(target, info.ModTime(), info.ModTime()); err != nil {
				return err
			}
		}
		return nil
	})
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return syncDir(filepath.Dir(path))
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
