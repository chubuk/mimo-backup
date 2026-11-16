// Package vcs keeps a git history of the tracked settings files. It shells
// out to the git binary (stdlib-only dependency policy) with a copy-based
// repository — never a bare work tree of $HOME. All git operations are
// best-effort: when git is absent the restore/rollback flow works without
// the history layer.
package vcs

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// TrackedRelPaths are the home-relative settings paths tracked in the git
// layer: global text configs only (decision: no projects, no data).
var TrackedRelPaths = []string{
	".config/mimocode",
	".bashrc",
	".profile",
	".bash_profile",
}

// Commit is one snapshot in the settings history.
type Commit struct {
	Hash    string
	Message string
	When    time.Time
}

// Repo is a copy-based git repository of tracked settings.
type Repo struct {
	path string // repository root (settings-repo)
	home string // source home to copy files from
}

// Available reports whether the git binary is in PATH.
func Available() bool {
	_, err := exec.LookPath("git")
	return err == nil
}

// Open prepares the settings repository (git init on first use).
func Open(path, home string) (*Repo, error) {
	r := &Repo{path: path, home: home}
	if _, err := os.Stat(filepath.Join(path, ".git")); err == nil {
		return r, nil
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return nil, err
	}
	if err := r.git("init", "-q"); err != nil {
		return nil, fmt.Errorf("git init: %w", err)
	}
	return r, nil
}

// Snapshot copies the current tracked settings into the repo and commits
// them. Returns the commit hash. label is e.g. "pre-restore <id>".
func (r *Repo) Snapshot(label string) (string, error) {
	if err := r.syncWorkTree(); err != nil {
		return "", err
	}
	if err := r.git("add", "-A"); err != nil {
		return "", err
	}
	if err := r.git("commit", "-q", "--allow-empty", "-m", label); err != nil {
		return "", err
	}
	return r.revParse()
}

// Log returns the settings history (newest first).
func (r *Repo) Log() ([]Commit, error) {
	out, err := r.gitOut("log", "--format=%H%x00%ct%x00%s")
	if err != nil {
		return nil, err
	}
	var commits []Commit
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "\x00", 3)
		if len(parts) != 3 {
			continue
		}
		var ts int64
		fmt.Sscanf(parts[1], "%d", &ts)
		commits = append(commits, Commit{
			Hash:    parts[0],
			Message: parts[2],
			When:    time.Unix(ts, 0).Local(),
		})
	}
	return commits, nil
}

// DiffStat returns the --stat summary between two commits ("" = working tree).
func (r *Repo) DiffStat(from, to string) (string, error) {
	args := []string{"diff", "--stat"}
	if from != "" && to != "" {
		args = append(args, from+".."+to)
	} else if from != "" {
		args = append(args, from)
	}
	return r.gitOut(args...)
}

// syncWorkTree replaces the repo copies with the current tracked files:
// files that disappeared from $HOME are removed from the repo too.
func (r *Repo) syncWorkTree() error {
	for _, rel := range TrackedRelPaths {
		src := filepath.Join(r.home, filepath.FromSlash(rel))
		dst := filepath.Join(r.path, filepath.FromSlash(rel))
		if _, err := os.Stat(src); err != nil {
			_ = os.RemoveAll(dst)
			continue
		}
		if err := copyPath(src, dst); err != nil {
			return err
		}
	}
	return nil
}

func (r *Repo) revParse() (string, error) {
	out, err := r.gitOut("rev-parse", "HEAD")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// git runs git in the repo with a hostile-environment-safe config:
// no prompts, no gpg signing, fixed identity, no user/system config.
func (r *Repo) git(args ...string) error {
	_, err := r.gitOut(args...)
	return err
}

func (r *Repo) gitOut(args ...string) (string, error) {
	full := append([]string{
		"-c", "user.name=mimo-backup",
		"-c", "user.email=mimo-backup@localhost",
		"-c", "commit.gpgsign=false",
		"-c", "core.hooksPath=/dev/null",
		"-c", "advice.detachedHead=false",
	}, args...)
	cmd := exec.Command("git", full...)
	cmd.Dir = r.path
	cmd.Env = append(os.Environ(),
		"GIT_TERMINAL_PROMPT=0",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// copyPath copies a file or directory tree, preserving modes and symlinks.
func copyPath(src, dst string) error {
	fi, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		link, err := os.Readlink(src)
		if err != nil {
			return err
		}
		_ = os.RemoveAll(dst)
		return os.Symlink(link, dst)
	}
	if fi.IsDir() {
		_ = os.RemoveAll(dst)
		return filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
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
			if d.IsDir() {
				return os.MkdirAll(target, info.Mode().Perm())
			}
			if info.Mode()&os.ModeSymlink != 0 {
				link, err := os.Readlink(p)
				if err != nil {
					return err
				}
				return os.Symlink(link, target)
			}
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			return os.WriteFile(target, data, info.Mode().Perm())
		})
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	_ = os.RemoveAll(dst)
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, fi.Mode().Perm())
}
