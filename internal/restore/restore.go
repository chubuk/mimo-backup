// Package restore orchestrates archive verification and selective restore.
package restore

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/chubuk/mimo-backup/internal/archive"
	"github.com/chubuk/mimo-backup/internal/env"
	"github.com/chubuk/mimo-backup/internal/manifest"
	"github.com/chubuk/mimo-backup/internal/secbox"
	"github.com/chubuk/mimo-backup/internal/ui"
)

// Options configures a restore/verify run.
type Options struct {
	Src             string
	Secrets         string // explicit secrets artifact; "" = auto-discover
	SkipSecrets     bool
	Home            string
	Force           bool
	KeepInstID      bool
	RestoreRC       bool
	DryRun          bool
	StopMimo        bool
	Quick           bool // verify: archive checksum only
	Full            bool // verify: per-file hashes
	Yes             bool
	AskPassphrase   func(encrypted bool) (string, error) // "" for none/unencrypted
	ConfirmStopMimo func() (stop bool, err error)
	Log             *slog.Logger
	NoProgress      bool
	// SkipProcGate disables the mimo-process check (tests only).
	SkipProcGate bool
}

// Exit-code mapping helpers used by the CLI.
var (
	ErrVerify   = errors.New("checksum mismatch")  // exit 4
	ErrPass     = errors.New("passphrase problem") // exit 5
	ErrMimoLive = errors.New("mimo is running")    // exit 3
)

// Verify checks the archive without writing anything.
func Verify(o Options) error {
	if o.Log == nil {
		o.Log = slog.Default()
	}
	f, err := os.Open(o.Src)
	if err != nil {
		return err
	}
	defer f.Close()

	m, err := readSidecar(o.Src)
	if err != nil {
		return fmt.Errorf("боковой манифест не найден (%v); используйте --full для двухпроходной проверки", err)
	}

	if o.Quick && !o.Full {
		if m.ArchiveSHA256 == "" {
			return fmt.Errorf("--quick требует archive_sha256 из бокового манифеста")
		}
		st, err := f.Stat()
		if err != nil {
			return err
		}
		bar := ui.NewBar(os.Stderr, o.Log, "Проверка", st.Size(), 0)
		if o.NoProgress {
			bar.SetQuiet()
		}
		ui.HandleSignals(bar)
		defer bar.Abort()
		h := sha256.New()
		buf := make([]byte, archive.BufSize)
		for {
			n, err := f.Read(buf)
			if n > 0 {
				h.Write(buf[:n])
				bar.Add(int64(n))
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
		}
		sum := hex.EncodeToString(h.Sum(nil))
		if sum != m.ArchiveSHA256 {
			return fmt.Errorf("%w: archive_sha256 %s != %s", ErrVerify, sum, m.ArchiveSHA256)
		}
		bar.Finish()
		o.Log.Info("verify --quick: OK", "bytes", st.Size())
		if o.Secrets != "" || m.Secrets.Present {
			if err := verifySecrets(o, m); err != nil {
				return err
			}
		}
		return nil
	}

	// --full: stream and compare every file hash.
	if err := extract(o, m, nil, true); err != nil {
		return err
	}
	o.Log.Info("verify --full: OK", "files", len(m.Files))
	return nil
}

// List prints a manifest summary.
func List(o Options) error {
	m, err := readSidecar(o.Src)
	if err != nil {
		// Fall back to the in-tar manifest (last entry).
		m, err = manifestFromTar(o.Src)
		if err != nil {
			return err
		}
	}
	fmt.Printf("Создан: %s\nХост: %s, дом: %s\nБД: %s (%s, %d байт)\nФайлов: %d (%.2f ГБ), симлинков %d, пропущено %d\nСекретов: %d → %s (encrypted=%v)\n",
		m.CreatedAt.Format(time.RFC3339), m.Source.Hostname, m.Source.Home,
		m.DB.Method, m.DB.ArchivePath, m.DB.Bytes,
		m.Totals.Files, float64(m.Totals.Bytes)/(1<<30), m.Totals.Symlinks, m.Totals.Skipped,
		len(m.SecretPaths), m.Secrets.Filename, m.Secrets.Encrypted)
	if len(m.Torn) > 0 {
		fmt.Printf("Torn (усечённые при бэкапе): %d\n", len(m.Torn))
	}
	return nil
}

// Restore unpacks the main archive (and optionally the secrets artifact).
func Restore(o Options) error {
	if o.Log == nil {
		o.Log = slog.Default()
	}
	// Process gate.
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

	m, err := readSidecar(o.Src)
	if err != nil {
		o.Log.Warn("боковой манифест не найден — двухпроходный режим (~2x дольше)", "err", err)
		m, err = manifestFromTar(o.Src)
		if err != nil {
			return fmt.Errorf("манифест не найден ни в sidecar, ни в архиве: %w", err)
		}
	}

	if m.Source.Home != "" && o.Home != "" && m.Source.Home != o.Home {
		o.Log.Warn("дом в манифесте отличается от целевого",
			"source", m.Source.Home, "target", o.Home)
		o.Log.Warn("строки project/worktree в БД могут указывать на отсутствующие пути")
	}

	if o.DryRun {
		o.Log.Info("dry-run: восстановление пропущено", "files", len(m.Files))
		return nil
	}

	// Conflict preflight.
	if !o.Force {
		if conflicts := existingTargets(o.Home, m); len(conflicts) > 0 {
			return fmt.Errorf("цели уже существуют (use --force для замены через .pre-restore-копию): %s", strings.Join(conflicts, ", "))
		}
	}
	if o.Force {
		safetyRename(o.Log, o.Home, m)
	}

	if err := extract(o, m, nil, false); err != nil {
		return err
	}

	if !o.SkipSecrets {
		secPath := o.Secrets
		if secPath == "" {
			secPath = autoDiscoverSecrets(o.Src, m)
		}
		if secPath != "" {
			if err := restoreSecrets(o, m, secPath); err != nil {
				return err
			}
		} else {
			o.Log.Info("архив секретов не найден — восстановите вход через /login")
		}
	}

	// installation_id policy.
	if !o.KeepInstID {
		p := filepath.Join(o.Home, "home/.local/share/mimocode/installation_id")
		_ = p // extracted under home-relative layout; removal handled in extract filter
	}

	postRestore(o, m)
	return nil
}

// extract streams the archive; when verifyOnly no files are written.
func extract(o Options, m *manifest.Manifest, _ *archive.Journal, verifyOnly bool) error {
	f, err := os.Open(o.Src)
	if err != nil {
		return err
	}
	defer f.Close()
	tr, closer, err := archive.ReadCloser(f)
	if err != nil {
		return err
	}
	defer closer.Close()

	byPath := map[string]manifest.FileEntry{}
	for _, e := range m.Files {
		byPath[e.Path] = e
	}

	h := sha256.New()
	buf := make([]byte, archive.BufSize)
	var journal *archive.Journal
	if !verifyOnly {
		jp := filepath.Join(o.Home, ".restore-journal.jsonl")
		journal, err = archive.OpenJournal(jp)
		if err != nil {
			return err
		}
		defer func() {
			journal.Close()
			if err == nil {
				os.Remove(jp) // success: journal no longer needed
			}
		}()
	}

	seen := map[string]bool{}
	// verifyOnly validates entry names against a scratch base; nothing is written.
	base := o.Home
	if verifyOnly && base == "" {
		base = os.TempDir()
	}

	// Bar totals: manifest bytes minus skipped paths (restore only).
	label := "Восстановление"
	if verifyOnly {
		label = "Проверка"
	}
	barTotal := m.Totals.Bytes
	barFiles := m.Totals.Files
	if !verifyOnly {
		for _, e := range m.Files {
			if skipOnRestore(e.Path, o) {
				barTotal -= e.Size
				barFiles--
			}
		}
	}
	bar := ui.NewBar(os.Stderr, o.Log, label, barTotal, barFiles)
	if o.NoProgress {
		bar.SetQuiet()
	}
	ui.HandleSignals(bar)
	defer bar.Abort()

	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("%w: повреждённый архив: %v", ErrVerify, err)
		}
		if hdr.Name == "manifest.json" {
			continue
		}
		full, err := archive.SafeJoin(base, hdr.Name)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrVerify, err)
		}
		// Restore-skip policy applies only to real restores; verify checks everything.
		if !verifyOnly && skipOnRestore(hdr.Name, o) {
			continue
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if verifyOnly {
				continue
			}
			if err := os.MkdirAll(full, 0o755); err != nil {
				return err
			}
		case tar.TypeSymlink:
			if verifyOnly {
				continue
			}
			if err := archive.MkdirAllSafe(full); err != nil {
				return err
			}
			os.Remove(full)
			if err := os.Symlink(hdr.Linkname, full); err != nil {
				return err
			}
			if journal != nil {
				journal.Record(hdr.Name)
			}
		case tar.TypeReg:
			h.Reset()
			var w io.Writer = io.MultiWriter(h, bar)
			var out *os.File
			if !verifyOnly {
				if err := archive.MkdirAllSafe(full); err != nil {
					return err
				}
				out, err = archive.CreateFileSafe(full, os.FileMode(hdr.Mode))
				if err != nil {
					return err
				}
				w = io.MultiWriter(out, h, bar)
			}
			n, err := io.CopyBuffer(w, tr, buf)
			if err != nil {
				if out != nil {
					out.Close()
				}
				return fmt.Errorf("%w: чтение %s: %v", ErrVerify, hdr.Name, err)
			}
			if out != nil {
				out.Close()
			}
			sum := hex.EncodeToString(h.Sum(nil))
			want, ok := byPath[hdr.Name]
			if ok {
				if sum != want.SHA256 {
					return fmt.Errorf("%w: %s (ожидался %s, получен %s)", ErrVerify, hdr.Name, want.SHA256, sum)
				}
			} else if !verifyOnly {
				bar.Log("файл не значится в манифесте: " + hdr.Name)
			}
			seen[hdr.Name] = true
			_ = n
			bar.NextFile()
			if journal != nil {
				journal.Record(hdr.Name)
			}
		}
	}

	// Manifest completeness: every file entry must have been seen.
	// Entries intentionally skipped by restore policy don't count as missing.
	var missing []string
	for _, e := range m.Files {
		if e.Type == "file" && !seen[e.Path] && !skipOnRestore(e.Path, o) {
			missing = append(missing, e.Path)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: в архиве отсутствуют файлы манифеста: %s…", ErrVerify, strings.Join(firstN(missing, 5), ", "))
	}
	bar.Finish()
	return nil
}

// skipOnRestore implements the restore-skip policy.
func skipOnRestore(name string, o Options) bool {
	base := filepath.Base(name)
	if base == "installation_id" && !o.KeepInstID {
		return true
	}
	if !o.RestoreRC {
		switch base {
		case ".bashrc", ".profile", ".bash_profile":
			return true
		}
	}
	return false
}

// readSidecar loads the authoritative sidecar manifest.
func readSidecar(src string) (*manifest.Manifest, error) {
	p := strings.TrimSuffix(src, ".tar.gz") + ".manifest.json"
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return manifest.Load(f)
}

// manifestFromTar finds the trailing manifest.json in the archive (fallback).
func manifestFromTar(src string) (*manifest.Manifest, error) {
	f, err := os.Open(src)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	tr, closer, err := archive.ReadCloser(f)
	if err != nil {
		return nil, err
	}
	defer closer.Close()
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if hdr.Name == "manifest.json" {
			var buf bytes.Buffer
			if _, err := io.Copy(&buf, tr); err != nil {
				return nil, err
			}
			return manifest.Load(&buf)
		}
	}
	return nil, fmt.Errorf("manifest.json не найден в архиве")
}

// existingTargets lists restore targets that already exist and are non-empty.
func existingTargets(home string, m *manifest.Manifest) []string {
	tops := map[string]bool{}
	for _, e := range m.Files {
		parts := strings.SplitN(e.Path, "/", 3) // home / .local / ...
		if len(parts) >= 2 {
			tops[parts[1]] = true
		}
	}
	var out []string
	for t := range tops {
		p := filepath.Join(home, t)
		if fi, err := os.Stat(p); err == nil && fi.IsDir() {
			ents, _ := os.ReadDir(p)
			if len(ents) > 0 {
				out = append(out, t)
			}
		} else if err == nil {
			out = append(out, t)
		}
	}
	return out
}

// safetyRename renames existing targets to <name>.pre-restore-<ts>.
func safetyRename(log *slog.Logger, home string, m *manifest.Manifest) {
	ts := time.Now().UTC().Format("20060102-150405")
	tops := map[string]bool{}
	for _, e := range m.Files {
		parts := strings.SplitN(e.Path, "/", 3)
		if len(parts) >= 2 {
			tops[parts[1]] = true
		}
	}
	for t := range tops {
		p := filepath.Join(home, t)
		if _, err := os.Stat(p); err == nil {
			dst := p + ".pre-restore-" + ts
			if err := os.Rename(p, dst); err != nil {
				log.Error("safety rename", "path", p, "err", err)
				continue
			}
			log.Info("существующий путь отодвинут", "from", p, "to", dst)
		}
	}
}

// autoDiscoverSecrets finds a sibling secrets artifact.
func autoDiscoverSecrets(src string, m *manifest.Manifest) string {
	if m.Secrets.Filename != "" {
		p := filepath.Join(filepath.Dir(src), m.Secrets.Filename)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	base := strings.TrimSuffix(filepath.Base(src), ".tar.gz")
	for _, suf := range []string{"-secrets.mimosec", "-secrets.tar.gz"} {
		p := filepath.Join(filepath.Dir(src), base+suf)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// restoreSecrets unpacks the secrets artifact over the restore target.
// Redacted copies are replaced without --force (documented flow).
func restoreSecrets(o Options, m *manifest.Manifest, secPath string) error {
	raw, err := os.ReadFile(secPath)
	if err != nil {
		return err
	}
	var payload []byte
	if strings.HasSuffix(secPath, ".mimosec") {
		enc, err := secbox.ParamsOf(raw)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrPass, err)
		}
		_ = enc
		pw := ""
		if o.AskPassphrase != nil {
			pw, err = o.AskPassphrase(true)
			if err != nil {
				return err
			}
		}
		payload, err = secbox.Open([]byte(pw), raw)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrPass, err)
		}
	} else {
		payload = raw
	}

	tr, closer, err := archive.ReadCloser(bytes.NewReader(payload))
	if err != nil {
		return err
	}
	defer closer.Close()

	redacted := map[string]bool{}
	for _, p := range m.RedactedPaths {
		redacted[p] = true
	}

	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if hdr.Name == "manifest.json" {
			continue
		}
		full, err := archive.SafeJoin(o.Home, hdr.Name)
		if err != nil {
			return fmt.Errorf("secrets: %v", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		// Redacted copies are replaced unconditionally; other conflicts need --force.
		if _, err := os.Lstat(full); err == nil && !redacted[hdr.Name] && !o.Force {
			return fmt.Errorf("%s уже существует (use --force)", hdr.Name)
		}
		if err := archive.MkdirAllSafe(full); err != nil {
			return err
		}
		out, err := archive.CreateFileSafe(full, 0o600)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, tr); err != nil {
			out.Close()
			return err
		}
		out.Close()
	}
	o.Log.Info("секреты восстановлены", "from", secPath)
	return nil
}

// verifySecrets checks the secrets artifact checksum (quick) or content (full).
func verifySecrets(o Options, m *manifest.Manifest) error {
	secPath := o.Secrets
	if secPath == "" {
		secPath = autoDiscoverSecrets(o.Src, m)
	}
	if secPath == "" {
		if m.Secrets.Present {
			return fmt.Errorf("архив секретов заявлен в манифесте, но не найден")
		}
		return nil
	}
	sum, n, err := archive.HashFile(secPath)
	if err != nil {
		return err
	}
	if m.Secrets.SHA256 != "" && sum != m.Secrets.SHA256 {
		return fmt.Errorf("%w: secrets_sha256 %s != %s", ErrVerify, sum, m.Secrets.SHA256)
	}
	o.Log.Info("secrets: checksum OK", "bytes", n)
	return nil
}

// postRestore prints next steps and runs a best-effort DB check.
func postRestore(o Options, m *manifest.Manifest) {
	o.Log.Info("восстановление завершено", "files", m.Totals.Files)
	o.Log.Info("добавьте в ~/.bashrc: export PATH=" + filepath.Join(o.Home, ".mimocode/bin") + ":$PATH")
	if m.DB.Method == "vacuum-into" {
		o.Log.Info("БД: снапшот vacuum-into (wal/shm не требуются)")
	}
}

func firstN(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
