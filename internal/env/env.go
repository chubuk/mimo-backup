// Package env discovers MiMoCode data roots, detects running mimo processes,
// checks free space, and drives `mimo db` for consistent DB snapshots.
package env

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Roots holds the absolute paths of everything a backup touches.
type Roots struct {
	Home        string // e.g. /home/chubuk
	Data        string // ~/.local/share/mimocode
	Config      string // ~/.config/mimocode
	State       string // ~/.local/state/mimocode
	Cache       string // ~/.cache/mimocode
	Install     string // ~/.mimocode
	Projects    string // ~/projects
	Bashrc      string
	Profile     string
	BashProfile string
}

// Discover resolves all roots under home.
func Discover(home string) Roots {
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	return Roots{
		Home:        home,
		Data:        filepath.Join(home, ".local", "share", "mimocode"),
		Config:      filepath.Join(home, ".config", "mimocode"),
		State:       filepath.Join(home, ".local", "state", "mimocode"),
		Cache:       filepath.Join(home, ".cache", "mimocode"),
		Install:     filepath.Join(home, ".mimocode"),
		Projects:    filepath.Join(home, "projects"),
		Bashrc:      filepath.Join(home, ".bashrc"),
		Profile:     filepath.Join(home, ".profile"),
		BashProfile: filepath.Join(home, ".bash_profile"),
	}
}

// MimoBinary returns the absolute path of the mimo binary for a home.
func (r Roots) MimoBinary() string {
	return filepath.Join(r.Install, "bin", "mimo")
}

// FindMimoProcesses scans /proc for processes whose comm is "mimo",
// excluding self and the given ignore PIDs (e.g. children we spawned).
func FindMimoProcesses(ignore map[int]bool) []int {
	var pids []int
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	self := os.Getpid()
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if pid == self || ignore[pid] {
			continue
		}
		comm, err := os.ReadFile(filepath.Join("/proc", e.Name(), "comm"))
		if err != nil {
			continue
		}
		name := strings.TrimSpace(string(comm))
		if name == "mimo" || strings.HasPrefix(name, "mimo") {
			pids = append(pids, pid)
		}
	}
	return pids
}

// StopProcesses sends SIGTERM to each pid and waits up to timeoutMs for exit.
// Returns pids still alive after the wait.
func StopProcesses(pids []int, timeoutMs int) []int {
	for _, pid := range pids {
		syscall.Kill(pid, syscall.SIGTERM)
	}
	deadline := timeoutMs
	for deadline > 0 {
		alive := alivePids(pids)
		if len(alive) == 0 {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
		deadline -= 100
		pids = alive
	}
	return pids
}

func alivePids(pids []int) []int {
	var out []int
	for _, pid := range pids {
		if isAlive(pid) {
			out = append(out, pid)
		}
	}
	return out
}

// isAlive reports whether pid is a running (non-zombie) process.
func isAlive(pid int) bool {
	if err := syscall.Kill(pid, 0); err != nil {
		return false
	}
	// kill 0 succeeds on zombies too; check the /proc state field.
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	// Format: pid (comm) state ...
	s := string(b)
	if i := strings.LastIndex(s, ") "); i >= 0 && len(s) > i+2 {
		return s[i+2] != 'Z'
	}
	return true
}

// FreeBytes reports the free space available to non-root users on the
// filesystem containing path.
func FreeBytes(path string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, fmt.Errorf("statfs %s: %w", path, err)
	}
	return st.Bavail * uint64(st.Bsize), nil
}

// QuoteSQLLiteral escapes s as a single-quoted SQL string literal,
// rejecting characters that have no business in a filesystem path used as SQL.
func QuoteSQLLiteral(s string) (string, error) {
	for _, r := range s {
		if r < 0x20 || r == ';' {
			return "", fmt.Errorf("illegal character %q in SQL path", r)
		}
	}
	return "'" + strings.ReplaceAll(s, "'", "''") + "'", nil
}

// SnapshotDB runs `mimo db "VACUUM INTO '<dest>'"` for a consistent hot
// snapshot of the live database (mimo db already opens the live DB).
func SnapshotDB(home, dest string) error {
	bin := filepath.Join(home, ".mimocode", "bin", "mimo")
	if _, err := os.Stat(bin); err != nil {
		return fmt.Errorf("mimo binary: %w", err)
	}
	q, err := QuoteSQLLiteral(dest)
	if err != nil {
		return err
	}
	cmd := exec.Command(bin, "db", fmt.Sprintf("VACUUM INTO %s", q))
	cmd.Env = append(os.Environ(), "HOME="+home)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("mimo db VACUUM INTO: %w: %s", err, strings.TrimSpace(string(out)))
	}
	if _, err := os.Stat(dest); err != nil {
		return fmt.Errorf("snapshot not created: %w", err)
	}
	return nil
}
