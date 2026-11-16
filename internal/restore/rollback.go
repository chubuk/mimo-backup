package restore

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/chubuk/mimo-backup/internal/archive"
	"github.com/chubuk/mimo-backup/internal/env"
	"github.com/chubuk/mimo-backup/internal/gens"
)

// Rollback sentinel errors mapped to CLI exit codes.
var (
	// ErrNoGeneration (exit 7): nothing to roll back.
	ErrNoGeneration = errors.New("нет поколения для отката")
	// ErrConflict (exit 2): user data that rollback would destroy.
	ErrConflict = errors.New("конфликт отката")
)

// RollbackOptions configures a rollback run.
type RollbackOptions struct {
	Home            string
	DryRun          bool
	Yes             bool
	Log             *slog.Logger
	StopMimo        bool
	ConfirmStopMimo func() (stop bool, err error)
	SkipProcGate    bool
}

// Rollback undoes the most recent restore: deletes what it wrote and puts
// the displaced trees back. User edits to tracked settings are preserved in
// the git history first (pre-rollback commit).
func Rollback(o RollbackOptions) error {
	if o.Log == nil {
		o.Log = slog.Default()
	}
	// Process gate: mimo must not touch the files we move.
	if alive := env.FindMimoProcesses(nil); len(alive) > 0 && !o.SkipProcGate {
		if o.StopMimo {
			if rest := env.StopProcesses(alive, 10_000); len(rest) > 0 {
				return fmt.Errorf("%w: не остановилась (pids %v)", ErrMimoLive, rest)
			}
		} else if o.ConfirmStopMimo != nil {
			stop, err := o.ConfirmStopMimo()
			if err != nil {
				return err
			}
			if !stop {
				return fmt.Errorf("%w: остановите mimo и запустите команду снова", ErrMimoLive)
			}
			if rest := env.StopProcesses(alive, 10_000); len(rest) > 0 {
				return fmt.Errorf("%w: не остановилась (pids %v)", ErrMimoLive, rest)
			}
		} else {
			return fmt.Errorf("%w: остановите её или используйте --stop-mimo", ErrMimoLive)
		}
	}

	store, err := gens.Open(o.Home)
	if err != nil {
		return err
	}
	g, err := store.Latest()
	if err != nil {
		return err
	}
	if g == nil {
		return ErrNoGeneration
	}

	entries, err := g.Extracted()
	if err != nil {
		return err
	}
	if len(entries) == 0 && !g.HasDisplaced() {
		return fmt.Errorf("%w: поколение %s пусто", ErrNoGeneration, g.ID())
	}

	// --- conflict report ------------------------------------------------
	// Later journal entries win (secrets re-record the redacted copies).
	last := map[string]gens.ExtractedEntry{}
	for _, e := range entries {
		last[e.Path] = e
	}
	entrySet := map[string]bool{}
	for p := range last {
		entrySet[p] = true
	}
	var modified, extra []string
	for _, e := range last {
		if e.Type != "file" && e.Type != "symlink" {
			continue
		}
		p := filepath.Join(o.Home, filepath.FromSlash(e.Path))
		fi, err := os.Lstat(p)
		if err != nil {
			continue // already gone: nothing to compare
		}
		if e.Type == "symlink" {
			if link, err := os.Readlink(p); err == nil && link != e.Link {
				modified = append(modified, e.Path)
			}
			continue
		}
		if !fi.Mode().IsRegular() {
			modified = append(modified, e.Path+" (тип изменился)")
			continue
		}
		sum, _, err := archive.HashFile(p)
		if err != nil {
			modified = append(modified, e.Path+" (не прочитан)")
			continue
		}
		if e.SHA256 != "" && sum != e.SHA256 {
			modified = append(modified, e.Path)
		}
	}
	for _, r := range g.Meta.DisplacedRoots {
		if _, err := os.Stat(g.DisplacedPath(r)); err != nil {
			continue // nothing was displaced for this root
		}
		root := filepath.Join(o.Home, filepath.FromSlash(r))
		_ = filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			rel, rErr := filepath.Rel(o.Home, p)
			if rErr != nil {
				return nil
			}
			rel = filepath.ToSlash(rel)
			if !entrySet[rel] {
				extra = append(extra, rel)
			}
			return nil
		})
	}
	sort.Strings(modified)
	sort.Strings(extra)

	if len(extra) > 0 {
		return fmt.Errorf("%w: под отодвинутыми деревьями есть лишние файлы (откат их удалил бы) — уберите их вручную: %s",
			ErrConflict, strings.Join(firstN(extra, 10), ", "))
	}
	if len(modified) > 0 {
		o.Log.Warn("файлы изменены после восстановления — правки будут потеряны (снимок в git-истории)",
			"count", len(modified), "paths", strings.Join(firstN(modified, 10), ", "))
		if !o.Yes && !o.DryRun {
			return fmt.Errorf("%w: изменённые файлы: %s (подтвердите --yes или отмените)", ErrConflict, strings.Join(firstN(modified, 10), ", "))
		}
	}

	o.Log.Info("откат поколения", "id", g.ID(), "entries", len(entries),
		"displaced", len(g.Meta.DisplacedRoots), "modified", len(modified))

	if o.DryRun {
		o.Log.Info("dry-run: откат пропущен")
		return nil
	}

	// --- non-destructive git snapshot of the user's edits ---------------
	if repo := openSettingsRepo(store, o.Home, o.Log); repo != nil {
		if hash, sErr := repo.Snapshot("pre-rollback " + g.ID()); sErr == nil {
			g.Meta.PreRollbackCommit = hash
			_ = g.SaveMeta()
			if g.Meta.PreRestoreCommit != "" {
				if stat, dErr := repo.DiffStat(g.Meta.PreRestoreCommit, hash); dErr == nil && strings.TrimSpace(stat) != "" {
					o.Log.Info("правки настроек с момента восстановления (сохранены в git):\n" + stat)
				}
			}
		}
	}

	// --- delete what the restore wrote ----------------------------------
	// Order: files, then symlinks, then dirs the restore created (deepest
	// first). Files added by the user outside displaced roots are kept.
	var files, symlinks, dirs []gens.ExtractedEntry
	for _, e := range entries {
		switch e.Type {
		case "file":
			files = append(files, e)
		case "symlink":
			symlinks = append(symlinks, e)
		case "dir":
			if e.Created {
				dirs = append(dirs, e)
			}
		}
	}
	for _, e := range files {
		_ = os.Remove(filepath.Join(o.Home, filepath.FromSlash(e.Path)))
	}
	for _, e := range symlinks {
		_ = os.Remove(filepath.Join(o.Home, filepath.FromSlash(e.Path)))
	}
	// Reverse-sorted paths remove children before parents.
	sort.Slice(dirs, func(i, j int) bool { return dirs[i].Path > dirs[j].Path })
	for _, e := range dirs {
		_ = os.Remove(filepath.Join(o.Home, filepath.FromSlash(e.Path))) // only if empty
	}

	// --- put the displaced trees back -----------------------------------
	for _, r := range g.Meta.DisplacedRoots {
		src := g.DisplacedPath(r)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		dst := filepath.Join(o.Home, filepath.FromSlash(r))
		if err := gens.MoveTree(src, dst); err != nil {
			return fmt.Errorf("возврат %s: %w", r, err)
		}
		o.Log.Info("путь восстановлен", "from", src, "to", dst)
	}

	// --- restore directory mtimes (byte-for-byte round trip) ------------
	for rel, ts := range g.Meta.DirMTimes {
		mt, err := time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			continue
		}
		p := filepath.Join(o.Home, filepath.FromSlash(rel))
		if fi, err := os.Stat(p); err == nil && fi.IsDir() {
			_ = os.Chtimes(p, mt, mt)
		}
	}

	if err := g.SetStatus(gens.StatusRolledBack); err != nil {
		return err
	}
	_ = store.LogEvent(gens.Event{Event: "rollback", Gen: g.ID(), Note: "rolled-back"})
	o.Log.Info("откат завершён", "generation", g.ID())
	return nil
}
