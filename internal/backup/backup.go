// Package backup orchestrates the full backup flow: discovery, classification,
// process gating, DB snapshot, secrets archive, and the streaming main archive.
package backup

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/chubuk/mimo-backup/internal/archive"
	"github.com/chubuk/mimo-backup/internal/env"
	"github.com/chubuk/mimo-backup/internal/manifest"
	"github.com/chubuk/mimo-backup/internal/secbox"
	"github.com/chubuk/mimo-backup/internal/ui"
)

// Options configures a backup run.
type Options struct {
	Dest        string
	Home        string
	Label       string
	Hot         bool
	Cold        bool
	NoSecrets   bool
	SecretGlobs []string
	GzipLevel   int
	Force       bool
	DryRun      bool
	StopMimo    bool
	Yes         bool
	// Interactive hooks (nil = non-interactive).
	ConfirmStopMimo func() (stop bool, hot bool, err error) // returns user's choice
	AskPassphrase   func() (string, error)                  // twice-validated passphrase or "" for none
	Log             *slog.Logger
	NoProgress      bool
	// SkipProcGate disables the mimo-process check. Tests only: the host may
	// legitimately run mimo (e.g. the agent executing this test suite).
	SkipProcGate bool
}

// item is one classified path to archive.
type item struct {
	abs    string
	rel    string // home-relative archive name, e.g. "home/..."
	kind   string // "file" | "dir" | "symlink"
	size   int64
	mode   fs.FileMode
	mtime  time.Time
	link   string
	secret bool
	redact bool // secret file whose redacted copy goes to main
}

const stagingPrefix = ".mimo-backup-staging-"

// Run executes a full backup.
func Run(o Options) error {
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.GzipLevel == 0 {
		o.GzipLevel = 1
	}
	if o.Label == "" {
		host, _ := os.Hostname()
		o.Label = fmt.Sprintf("%s-%s", host, time.Now().Format("20060102-150405"))
	} else {
		// User label is a tag; the timestamp is always appended so the
		// artifact name always shows when the backup was made.
		if err := validateLabel(o.Label); err != nil {
			return err
		}
		o.Label = fmt.Sprintf("%s-%s", o.Label, time.Now().Format("20060102-150405"))
	}

	roots := env.Discover(o.Home)
	if fi, err := os.Stat(roots.Home); err != nil || !fi.IsDir() {
		return fmt.Errorf("home %q: %w", roots.Home, err)
	}
	if fi, err := os.Stat(o.Dest); err != nil || !fi.IsDir() {
		return fmt.Errorf("dest %q: %w", o.Dest, err)
	}

	// --- discovery & classification -------------------------------------
	items, skipped, err := discover(roots, o)
	if err != nil {
		return err
	}
	o.Log.Info("discovered", "items", len(items), "skipped", skipped)

	// --- process gate ---------------------------------------------------
	alive := env.FindMimoProcesses(nil)
	if o.SkipProcGate {
		alive = nil
	}
	if len(alive) > 0 && !o.Hot {
		if o.StopMimo {
			if rest := env.StopProcesses(alive, 10_000); len(rest) > 0 {
				return fmt.Errorf("mimo не остановилась (pids %v): остановите вручную", rest)
			}
		} else if o.ConfirmStopMimo != nil {
			stop, hot, err := o.ConfirmStopMimo()
			if err != nil {
				return err
			}
			if stop {
				if rest := env.StopProcesses(alive, 10_000); len(rest) > 0 {
					return fmt.Errorf("mimo не остановилась (pids %v)", rest)
				}
			} else if hot {
				o.Hot = true
			} else {
				return fmt.Errorf("mimo запущена; остановите её и запустите команду снова")
			}
		} else {
			return fmt.Errorf("mimo запущена; остановите её или используйте --hot (только backup)")
		}
	}
	if o.Cold && len(env.FindMimoProcesses(nil)) > 0 && !o.SkipProcGate {
		return fmt.Errorf("--cold невозможен при работающей mimo")
	}

	// --- totals & free space -------------------------------------------
	// estBytes: ALL source bytes (incl. secrets) — for the free-space estimate.
	// barTotalBytes (computed in writeMainArchive) counts only bytes written
	// into the main archive; the two must not be conflated.
	var estBytes int64
	var totalFiles int
	for _, it := range items {
		if it.kind == "file" {
			estBytes += it.size
			totalFiles++
		}
	}
	need := uint64(float64(estBytes)*0.55) + 64<<20 + uint64(estBytes)/20
	free, err := env.FreeBytes(o.Dest)
	if err != nil {
		return err
	}
	if free < need {
		return fmt.Errorf("на %s недостаточно места: свободно %.1f ГиБ, нужно ~%.1f ГиБ", o.Dest, float64(free)/(1<<30), float64(need)/(1<<30))
	}

	if o.DryRun {
		o.Log.Info("dry-run: архивирование пропущено", "files", totalFiles, "bytes", estBytes)
		return nil
	}

	// --- staging + DB snapshot -----------------------------------------
	staging := filepath.Join(o.Dest, stagingPrefix+o.Label)
	if err := os.MkdirAll(staging, 0o755); err != nil {
		return fmt.Errorf("staging: %w", err)
	}
	defer os.RemoveAll(staging)

	dbPath := filepath.Join(roots.Data, "mimocode.db")
	m := manifest.New()
	m.Source = manifest.Source{
		Home:     roots.Home,
		Username: os.Getenv("USER"),
		UID:      os.Getuid(),
	}
	if hn, err := os.Hostname(); err == nil {
		m.Source.Hostname = hn
	}
	m.Totals.Skipped = skipped

	o.Log.Info("снимок БД…")
	if err := snapshotDB(o, roots, dbPath, staging, m); err != nil {
		return err
	}

	// --- secrets archive ------------------------------------------------
	secretsItems := filterSecrets(items)
	if o.NoSecrets {
		if len(secretsItems) > 0 {
			o.Log.Warn("--no-secrets: секреты пропущены", "paths", secretRels(secretsItems))
		}
		m.Secrets = manifest.Secrets{Present: false}
	} else if len(secretsItems) > 0 {
		o.Log.Info("секреты…")
		if err := writeSecretsArchive(o, secretsItems, m); err != nil {
			return err
		}
	}

	// --- main archive ---------------------------------------------------
	mainPath := filepath.Join(o.Dest, "mimo-backup-"+o.Label+".tar.gz")
	if _, err := os.Stat(mainPath); err == nil && !o.Force {
		return fmt.Errorf("%s уже существует (use --force)", mainPath)
	}
	if err := writeMainArchive(o, roots, items, staging, m, mainPath); err != nil {
		return err
	}

	// --- sidecar manifest ----------------------------------------------
	writeSidecar(o, m, mainPath)
	o.Log.Info("backup готов",
		"main", mainPath,
		"secrets", m.Secrets.Filename,
		"files", m.Totals.Files,
		"bytes", m.Totals.Bytes)
	return nil
}

// validateLabel enforces [A-Za-z0-9._-]{1,64}.
func validateLabel(s string) error {
	if len(s) == 0 || len(s) > 64 {
		return fmt.Errorf("label %q: длина 1..64", s)
	}
	for _, r := range s {
		ok := r == '-' || r == '_' || r == '.' ||
			(r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
		if !ok {
			return fmt.Errorf("label %q: допустимы только A-Z a-z 0-9 . _ -", s)
		}
	}
	return nil
}

// discover walks all include-set roots and classifies every entry.
func discover(roots env.Roots, o Options) ([]item, int, error) {
	var items []item
	skipped := 0

	// Top-level: 4 XDG roots + install + shell rc files.
	addRoot := func(root, prefix string) error {
		return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				if os.IsNotExist(err) {
					return nil
				}
				return err
			}
			rel, err := filepath.Rel(roots.Home, path)
			if err != nil {
				return err
			}
			arch := filepath.ToSlash(filepath.Join("home", rel))
			name := d.Name()
			if isTransient(arch, name) {
				skipped++
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			it := item{abs: path, rel: arch}
			fi, err := d.Info()
			if err != nil {
				return nil
			}
			it.size = fi.Size()
			it.mode = fi.Mode()
			it.mtime = fi.ModTime()
			switch {
			case d.IsDir():
				it.kind = "dir"
			case fi.Mode()&fs.ModeSymlink != 0:
				it.kind = "symlink"
				it.link, _ = os.Readlink(path)
			case fi.Mode().IsRegular():
				it.kind = "file"
			default:
				skipped++
				return nil
			}
			if classifySecret(arch) {
				it.secret = true
				it.redact = isTextConfig(arch)
			}
			items = append(items, it)
			_ = prefix
			return nil
		})
	}

	if err := os.MkdirAll(roots.Data, 0o755); err != nil {
		return nil, 0, err
	}
	for _, r := range []string{roots.Data, roots.Config, roots.State, roots.Cache, roots.Install} {
		if _, err := os.Stat(r); os.IsNotExist(err) {
			continue
		}
		if err := addRoot(r, ""); err != nil {
			return nil, 0, err
		}
	}

	// Shell rc files (restored only via --restore-shell-rc).
	for _, rc := range []string{roots.Bashrc, roots.Profile, roots.BashProfile} {
		if fi, err := os.Stat(rc); err == nil && fi.Mode().IsRegular() {
			rel, _ := filepath.Rel(roots.Home, rc)
			items = append(items, item{
				abs: rc, rel: filepath.ToSlash(filepath.Join("home", rel)),
				kind: "file", size: fi.Size(), mode: fi.Mode(), mtime: fi.ModTime(),
			})
		}
	}

	// Projects: full trees.
	entries, err := os.ReadDir(roots.Projects)
	if err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			if err := addRoot(filepath.Join(roots.Projects, e.Name()), ""); err != nil {
				return nil, 0, err
			}
		}
	}

	// Out-of-tree .mimocode dirs (e.g. ~/nvidia-install/.mimocode).
	homeEntries, _ := os.ReadDir(roots.Home)
	for _, e := range homeEntries {
		if !e.IsDir() || e.Name() == "projects" {
			continue
		}
		mc := filepath.Join(roots.Home, e.Name(), ".mimocode")
		if _, err := os.Stat(mc); err == nil {
			if err := addRoot(mc, ""); err != nil {
				return nil, 0, err
			}
		}
	}

	// Extra secret globs: reclassify matches.
	for _, g := range o.SecretGlobs {
		matches, _ := filepath.Glob(filepath.Join(roots.Home, g))
		for _, mm := range matches {
			rel, _ := filepath.Rel(roots.Home, mm)
			arch := filepath.ToSlash(filepath.Join("home", rel))
			for i := range items {
				if items[i].rel == arch {
					items[i].secret = true
					items[i].redact = isTextConfig(arch)
				}
			}
		}
	}

	// Explicit ssh deploy key (outside the walked roots).
	for _, k := range []string{".ssh/mimo_deploy", ".ssh/mimo_deploy.pub"} {
		p := filepath.Join(roots.Home, k)
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			items = append(items, item{
				abs: p, rel: "home/" + k,
				kind: "file", size: fi.Size(), mode: fi.Mode(), mtime: fi.ModTime(),
				secret: true,
			})
		}
	}

	return items, skipped, nil
}

// isTransient matches always-excluded paths.
func isTransient(arch, name string) bool {
	switch name {
	case ".cron-lock", ".restore-journal.jsonl", "migration":
		return true
	}
	if strings.HasSuffix(name, ".partial") {
		return true
	}
	if strings.Contains(arch, "/state/mimocode/locks/") {
		return true
	}
	if strings.Contains(arch, "/state/mimocode/llm-server/") && strings.HasPrefix(name, "server-") && strings.HasSuffix(name, ".json") {
		return true
	}
	if strings.Contains(arch, "/storage/migration") {
		return true
	}
	return false
}

// classifySecret matches the built-in secret path rules (by nature of path).
func classifySecret(arch string) bool {
	base := path.Base(arch)
	switch base {
	case "auth.json", "mimo-free-client", "mimo-key-name", "tokens.json":
		return true
	case "mimo_deploy", "mimo_deploy.pub":
		return strings.Contains(arch, "/.ssh/") && !strings.Contains(arch, "/projects/")
	}
	if strings.HasSuffix(base, ".env") {
		return true
	}
	// Any mimocode.json* at any depth (including .bak*).
	if strings.HasPrefix(base, "mimocode.json") {
		return true
	}
	return false
}

// isTextConfig reports whether a secret file is a text config deserving a
// redacted copy in the main archive.
func isTextConfig(arch string) bool {
	base := path.Base(arch)
	return strings.HasPrefix(base, "mimocode.json") || strings.HasSuffix(base, ".env")
}

func filterSecrets(items []item) []item {
	var out []item
	for _, it := range items {
		if it.secret && it.kind == "file" {
			out = append(out, it)
		}
	}
	return out
}

func secretRels(items []item) []string {
	var out []string
	for _, it := range items {
		out = append(out, it.rel)
	}
	return out
}

// snapshotDB captures mimocode.db: hot via VACUUM INTO, cold as a trio copy.
func snapshotDB(o Options, roots env.Roots, dbPath, staging string, m *manifest.Manifest) error {
	archPath := "home/.local/share/mimocode/mimocode.db"
	if _, err := os.Stat(dbPath); err != nil {
		m.DB = manifest.DB{Method: "cold-copy", Note: "mimocode.db отсутствует"}
		return nil
	}
	mimoAlive := len(env.FindMimoProcesses(nil)) > 0 && !o.SkipProcGate

	if o.Hot || (!o.Cold && mimoAlive) {
		snap := filepath.Join(staging, "mimocode.db.snap")
		if err := env.SnapshotDB(roots.Home, snap); err != nil {
			if mimoAlive {
				return fmt.Errorf("hot-снапшот не удался при работающей mimo: %w", err)
			}
			o.Log.Warn("VACUUM INTO не удался, перехожу на холодную копию", "err", err)
		} else {
			st, _ := os.Stat(snap)
			sum, _, _ := archive.HashFile(snap)
			m.DB = manifest.DB{
				Method:      "vacuum-into",
				ArchivePath: archPath,
				Bytes:       st.Size(),
				SHA256:      sum,
				MimoRunning: mimoAlive,
			}
			// Move snapshot where the archiver expects it.
			return os.Rename(snap, filepath.Join(staging, "db-snapshot"))
		}
	}

	// Cold copy: db + wal + shm, streamed later straight from source.
	for _, suf := range []string{"", "-wal", "-shm"} {
		p := dbPath + suf
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}
		sum, _, _ := archive.HashFile(p)
		if suf == "" {
			m.DB.ArchivePath = archPath
			m.DB.Bytes = fi.Size()
			m.DB.SHA256 = sum
		} else {
			m.DB.WALBytes += fi.Size()
			m.DB.WALSHA256 = sum
		}
	}
	m.DB.Method = "cold-copy"
	m.DB.MimoRunning = mimoAlive
	return nil
}

// writeSecretsArchive packs secret files into tar.gz (in memory) and seals it.
func writeSecretsArchive(o Options, secrets []item, m *manifest.Manifest) error {
	var payload bytes.Buffer
	sw, err := archive.NewWriter(&payload, o.GzipLevel)
	if err != nil {
		return err
	}
	inner := manifest.New()
	for _, it := range secrets {
		if it.kind != "file" {
			continue
		}
		f, err := os.Open(it.abs)
		if err != nil {
			return err
		}
		sha, _, err := sw.AddFile(it.rel, f, it.size, 0o600, it.mtime)
		f.Close()
		if err != nil {
			return err
		}
		inner.Files = append(inner.Files, manifest.FileEntry{
			Path: it.rel, Type: "file", Size: it.size, SHA256: sha,
			Mode: "0600", MTime: it.mtime,
		})
	}
	// Inner manifest as last entry.
	var mb bytes.Buffer
	if err := inner.Encode(&mb); err != nil {
		return err
	}
	if _, err := sw.AddBytes("manifest.json", mb.Bytes(), 0o644, time.Now().UTC()); err != nil {
		return err
	}
	if err := sw.Close(); err != nil {
		return err
	}

	passphrase := ""
	if o.AskPassphrase != nil {
		p, err := o.AskPassphrase()
		if err != nil {
			return err
		}
		passphrase = p
	}

	var artifact bytes.Buffer
	var name string
	if passphrase == "" {
		name = "mimo-backup-" + o.Label + "-secrets.tar.gz"
		artifact = payload
		m.Secrets = manifest.Secrets{Present: true, Filename: name, Encrypted: false, PayloadBytes: int64(payload.Len())}
	} else {
		name = "mimo-backup-" + o.Label + "-secrets.mimosec"
		params := secbox.DefaultParams()
		if _, err := secbox.Seal([]byte(passphrase), payload.Bytes(), params, &artifact); err != nil {
			return err
		}
		m.Secrets = manifest.Secrets{
			Present: true, Filename: name, Encrypted: true,
			KDF: "argon2id", MCost: params.M, TCost: params.T, PCost: params.P,
			PayloadBytes: int64(payload.Len()),
		}
	}

	out := filepath.Join(o.Dest, name)
	if _, err := os.Stat(out); err == nil && !o.Force {
		return fmt.Errorf("%s уже существует (use --force)", out)
	}
	pf, err := archive.CreatePartial(out)
	if err != nil {
		return err
	}
	if _, err := pf.Write(artifact.Bytes()); err != nil {
		pf.Abort()
		return err
	}
	if err := pf.Commit(); err != nil {
		return err
	}
	sum := sha256.Sum256(artifact.Bytes())
	m.Secrets.SHA256 = hex.EncodeToString(sum[:])
	m.Secrets.Bytes = int64(artifact.Len())
	return nil
}

// writeMainArchive streams every non-secret item into the main tar.gz,
// hashing on the fly; the manifest is the final entry.
func writeMainArchive(o Options, roots env.Roots, items []item, staging string, m *manifest.Manifest, outPath string) error {
	pf, err := archive.CreatePartial(outPath)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			pf.Abort()
		}
	}()

	hasher := sha256.New()
	dest := io.MultiWriter(pf, hasher)
	w, err := archive.NewWriter(dest, o.GzipLevel)
	if err != nil {
		return err
	}

	// barTotalBytes: only bytes actually written into the main archive
	// (secret-only files excluded; redacted sizes corrected on the fly).
	var barTotalBytes int64
	var barTotalFiles int
	for _, it := range items {
		if it.secret && !it.redact {
			continue
		}
		if it.kind == "file" {
			if it.rel == "home/.local/share/mimocode/mimocode.db" && m.DB.Method == "vacuum-into" {
				barTotalBytes += fileSize(filepath.Join(staging, "db-snapshot"))
			} else {
				barTotalBytes += it.size
			}
			barTotalFiles++
		}
	}

	bar := ui.NewBar(os.Stderr, o.Log, "Сжатие", barTotalBytes, barTotalFiles)
	if o.NoProgress {
		bar.SetQuiet()
	}
	ui.HandleSignals(bar)
	defer bar.Abort()

	for _, it := range items {
		if it.secret && !it.redact {
			continue // secrets-only file: lives in the secrets archive
		}
		switch it.kind {
		case "dir":
			if err := w.AddDir(it.rel, it.mode, it.mtime); err != nil {
				return err
			}
			m.Totals.Dirs++
		case "symlink":
			if err := w.AddSymlink(it.rel, it.link, it.mode, it.mtime); err != nil {
				return err
			}
			m.Totals.Symlinks++
		case "file":
			// DB snapshot handling: hot snapshot lives in staging, cold trio streams.
			src := it.abs
			if it.rel == "home/.local/share/mimocode/mimocode.db" && m.DB.Method == "vacuum-into" {
				src = filepath.Join(staging, "db-snapshot")
				it.size = fileSize(src)
			}
			var r io.Reader
			var f *os.File
			var data []byte
			if it.redact {
				data, err = os.ReadFile(it.abs)
				if err != nil {
					return err
				}
				data = secbox.Redact(data)
				r = bytes.NewReader(data)
				// Redacted size differs from source: correct the total.
				bar.AdjustTotal(int64(len(data)) - it.size)
				it.size = int64(len(data))
			} else {
				f, err = os.Open(src)
				if err != nil {
					return err
				}
				r = f
			}
			// Per-chunk progress: the bar must not stall on the 581MB DB file.
			cr := &countingReader{r: r, bar: bar}
			sha, torn, err := w.AddFile(it.rel, cr, it.size, it.mode, it.mtime)
			if f != nil {
				f.Close()
			}
			if err != nil {
				return err
			}
			if torn {
				m.Torn = append(m.Torn, it.rel)
				bar.Log("файл усечён при чтении (torn): " + it.rel)
			}
			mode := fmt.Sprintf("%04o", it.mode&0o777)
			if it.secret {
				mode = "0600"
			}
			m.Files = append(m.Files, manifest.FileEntry{
				Path: it.rel, Type: "file", Size: it.size, SHA256: sha,
				Mode: mode, MTime: it.mtime,
			})
			if it.redact {
				m.RedactedPaths = append(m.RedactedPaths, it.rel)
			}
			m.Totals.Files++
			m.Totals.Bytes += it.size
			bar.NextFile()
		}
		if it.secret {
			m.SecretPaths = append(m.SecretPaths, it.rel)
		}
	}

	// Manifest as the final entry (buffered: tar needs the size upfront).
	var mb bytes.Buffer
	if err := m.Encode(&mb); err != nil {
		return err
	}
	if _, err := w.AddBytes("manifest.json", mb.Bytes(), 0o644, time.Now().UTC()); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	if err := pf.Commit(); err != nil {
		return err
	}
	committed = true
	bar.Finish()
	m.ArchiveSHA256 = hex.EncodeToString(hasher.Sum(nil))
	return nil
}

// writeSidecar writes the authoritative manifest next to the main archive.
func writeSidecar(o Options, m *manifest.Manifest, mainPath string) {
	sidecar := strings.TrimSuffix(mainPath, ".tar.gz") + ".manifest.json"
	f, err := os.Create(sidecar)
	if err != nil {
		o.Log.Error("sidecar manifest: %v", "err", err)
		return
	}
	defer f.Close()
	if err := m.Encode(f); err != nil {
		o.Log.Error("sidecar encode: %v", "err", err)
	}
}

func fileSize(path string) int64 {
	fi, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return fi.Size()
}

// countingReader reports per-chunk progress while streaming file content.
type countingReader struct {
	r   io.Reader
	bar *ui.Bar
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 {
		c.bar.Add(int64(n))
	}
	return n, err
}
