package restore

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// FixNestedOptions configures the v1.0.0 repair run.
type FixNestedOptions struct {
	Home    string
	Apply   bool // dry-run is the default
	Yes     bool // delete empty safety copies without asking
	Log     *slog.Logger
	Confirm func(prompt string) (bool, error) // optional: offer cleanup
}

// FixNested repairs a machine restored by mimo-backup v1.0.0, whose bug A
// nested everything under $HOME/home/. It moves the restored trees back to
// $HOME without overwriting anything the user already has:
//
//   - .bashrc/.profile/.bash_profile: returned from *.pre-restore-* copies
//   - empty recreated shells (.local/.config/.cache): replaced
//   - .ssh: files merged in, never overwritten
//   - everything else: moved only where free; same-path files are conflicts
//
// Dry-run by default; --apply performs the safe subset and reports the rest.
func FixNested(o FixNestedOptions) error {
	if o.Log == nil {
		o.Log = slog.Default()
	}
	home := o.Home
	nested := filepath.Join(home, "home")
	if fi, err := os.Stat(nested); err != nil || !fi.IsDir() {
		return fmt.Errorf("%s не найден — похоже, эта машина не пострадала от бага v1.0.0", nested)
	}

	ents, err := os.ReadDir(nested)
	if err != nil {
		return err
	}
	if len(ents) == 0 {
		o.Log.Info("каталог пуст — удаляю", "path", nested)
		if o.Apply {
			return os.Remove(nested)
		}
		return nil
	}

	verb := "план"
	if o.Apply {
		verb = "применение"
	}
	o.Log.Info("fix-nested: "+verb, "nested", nested)

	var conflicts []string
	var moved []string

	// RC files never arrive through the nested tree (the restore skips
	// them): return them from their .pre-restore-* safety copies.
	for _, name := range []string{".bashrc", ".profile", ".bash_profile"} {
		msg, err := restoreRC(home, name, filepath.Join(nested, name), o)
		if err != nil {
			return err
		}
		if msg != "" {
			moved = append(moved, msg)
		}
	}

	for _, e := range ents {
		name := e.Name()
		src := filepath.Join(nested, name)
		dst := filepath.Join(home, name)

		switch name {
		case ".bashrc", ".profile", ".bash_profile":
			// The restore skipped these; the original lives in .pre-restore-*.
			msg, err := restoreRC(home, name, src, o)
			if err != nil {
				return err
			}
			if msg != "" {
				moved = append(moved, msg)
			}
			continue
		case ".local", ".config", ".cache":
			if fi, err := os.Stat(dst); err == nil && fi.IsDir() {
				if empty, _ := isEmptyDir(dst); empty {
					moved = append(moved, fmt.Sprintf("%s: пустая оболочка заменена", name))
					if o.Apply {
						if err := os.Remove(dst); err != nil {
							return err
						}
						if err := gensMove(src, dst); err != nil {
							return err
						}
					}
					continue
				}
				// Non-empty: merge below without overwriting.
			}
		}

		if _, err := os.Lstat(dst); err != nil {
			moved = append(moved, fmt.Sprintf("%s → %s", name, name))
			if o.Apply {
				if err := gensMove(src, dst); err != nil {
					return err
				}
			}
			continue
		}
		// Target exists: merge without overwriting.
		n, err := mergeMove(src, dst, name, &conflicts, o.Apply)
		if err != nil {
			return err
		}
		if n > 0 {
			moved = append(moved, fmt.Sprintf("%s: слито файлов без затирания: %d", name, n))
		}
	}

	for _, msg := range moved {
		o.Log.Info(msg)
	}
	if len(conflicts) > 0 {
		sort.Strings(conflicts)
		return fmt.Errorf("%w: %d путей уже заняты (разберите вручную): %s",
			ErrConflict, len(conflicts), strings.Join(firstN(conflicts, 15), ", "))
	}

	// Offer to drop the empty safety copies left by v1.0.0.
	var empties []string
	if matches, _ := filepath.Glob(filepath.Join(home, "*.pre-restore-*")); len(matches) > 0 {
		for _, p := range matches {
			if ok, _ := isEmptyDir(p); ok {
				empties = append(empties, p)
			}
		}
	}
	if len(empties) > 0 {
		sort.Strings(empties)
		drop := o.Yes
		if !drop && o.Confirm != nil && o.Apply {
			ok, err := o.Confirm(fmt.Sprintf("Удалить пустые страховочные копии (%d)?", len(empties)))
			if err != nil {
				return err
			}
			drop = ok
		}
		if drop && o.Apply {
			for _, p := range empties {
				_ = os.Remove(p)
			}
			o.Log.Info("пустые страховки удалены", "count", len(empties))
		} else {
			o.Log.Info("пустые страховки (можно удалить):", "paths", strings.Join(empties, ", "))
		}
	}

	// The nested root goes away when emptied.
	if o.Apply {
		if ents, err := os.ReadDir(nested); err == nil && len(ents) == 0 {
			_ = os.Remove(nested)
			o.Log.Info("каталог home/ удалён")
		} else if err == nil {
			o.Log.Warn("в home/ остались файлы — проверьте вручную", "count", len(ents))
		}
	}
	return nil
}

// restoreRC returns the skipped rc file from its safety copy (or the
// nested tree when the safety copy is gone).
func restoreRC(home, name, nestedSrc string, o FixNestedOptions) (string, error) {
	dst := filepath.Join(home, name)
	if _, err := os.Lstat(dst); err == nil {
		return "", nil // already present — never overwrite
	}
	// Prefer the displaced original.
	if matches, _ := filepath.Glob(dst + ".pre-restore-*"); len(matches) > 0 {
		sort.Strings(matches)
		src := matches[len(matches)-1]
		msg := fmt.Sprintf("%s: возвращён из %s", name, filepath.Base(src))
		if o.Apply {
			if err := gensMove(src, dst); err != nil {
				return "", err
			}
		}
		return msg, nil
	}
	// Fall back to the restored copy (the archive's version).
	if _, err := os.Stat(nestedSrc); err == nil {
		msg := fmt.Sprintf("%s: взят из распакованного архива", name)
		if o.Apply {
			if err := gensMove(nestedSrc, dst); err != nil {
				return "", err
			}
		}
		return msg, nil
	}
	return "", nil
}

// mergeMove moves files from src into dst without overwriting anything.
// Same-path files are collected as conflicts. Returns the number moved.
func mergeMove(src, dst, label string, conflicts *[]string, apply bool) (int, error) {
	moved := 0
	err := filepath.Walk(src, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if fi.IsDir() {
			if apply {
				return os.MkdirAll(target, fi.Mode().Perm())
			}
			return nil
		}
		if _, err := os.Lstat(target); err == nil {
			*conflicts = append(*conflicts, filepath.ToSlash(filepath.Join(label, rel)))
			return nil
		}
		moved++
		if apply {
			if err := gensMove(p, target); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return moved, err
	}
	if apply {
		_ = removeTreeIfEmpty(src)
	}
	return moved, nil
}

func gensMove(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	return os.Rename(src, dst)
}

func isEmptyDir(p string) (bool, error) {
	ents, err := os.ReadDir(p)
	if err != nil {
		return false, err
	}
	return len(ents) == 0, nil
}

func removeTreeIfEmpty(root string) error {
	var dirs []string
	_ = filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err == nil && fi.IsDir() {
			dirs = append(dirs, p)
		}
		return nil
	})
	// Deepest first.
	sort.Sort(sort.Reverse(sort.StringSlice(dirs)))
	for _, d := range dirs {
		_ = os.Remove(d) // only when empty
	}
	return nil
}
