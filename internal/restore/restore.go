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
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/chubuk/mimo-backup/internal/archive"
	"github.com/chubuk/mimo-backup/internal/env"
	"github.com/chubuk/mimo-backup/internal/gens"
	"github.com/chubuk/mimo-backup/internal/manifest"
	"github.com/chubuk/mimo-backup/internal/secbox"
	"github.com/chubuk/mimo-backup/internal/ui"
	"github.com/chubuk/mimo-backup/internal/vcs"
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
	// Passphrase is the already-asked password for sealed sources and
	// secrets artifacts (set by Restore/Verify after AskPassphrase).
	Passphrase string
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
	// Sealed containers carry no sidecar: the passphrase is asked up front
	// and integrity is proven by AEAD plus per-file hashes.
	sealed := sourceEncrypted(o.Src)
	if sealed && o.Passphrase == "" {
		if o.AskPassphrase == nil {
			return fmt.Errorf("%w: контейнер зашифрован, ввод пароля недоступен", ErrPass)
		}
		pw, err := o.AskPassphrase(true)
		if err != nil {
			return err
		}
		o.Passphrase = pw
	}

	m, err := resolveManifest(o, sealed)
	if err != nil {
		return err
	}

	if o.Quick && !o.Full && !sealed {
		if m.ArchiveSHA256 == "" {
			return fmt.Errorf("--quick требует archive_sha256 из бокового манифеста")
		}
		f, err := os.Open(o.Src)
		if err != nil {
			return err
		}
		defer f.Close()
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

	// --full (and sealed containers): stream and compare every file hash.
	if err := extract(o, m, nil, true); err != nil {
		return err
	}
	o.Log.Info("verify: OK", "files", len(m.Files))
	return nil
}

// List prints a manifest summary.
func List(o Options) error {
	if sourceEncrypted(o.Src) && o.Passphrase == "" {
		if o.AskPassphrase == nil {
			return fmt.Errorf("%w: контейнер зашифрован, ввод пароля недоступен", ErrPass)
		}
		pw, err := o.AskPassphrase(true)
		if err != nil {
			return err
		}
		o.Passphrase = pw
	}
	m, err := resolveManifest(o, sourceEncrypted(o.Src))
	if err != nil {
		return err
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

	// A sealed source must be unlocked before its (in-tar) manifest is read.
	if sourceEncrypted(o.Src) && o.Passphrase == "" {
		if o.AskPassphrase == nil {
			return fmt.Errorf("%w: контейнер зашифрован, ввод пароля недоступен", ErrPass)
		}
		pw, err := o.AskPassphrase(true)
		if err != nil {
			return err
		}
		o.Passphrase = pw
	}

	m, err := resolveManifest(o, sourceEncrypted(o.Src))
	if err != nil {
		return err
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

	// Secrets artifact + passphrase are resolved BEFORE extraction so the
	// password is asked up front (not after a long unpack).
	var secPath string
	secEncrypted := false
	if !o.SkipSecrets {
		secPath = o.Secrets
		if secPath == "" {
			secPath = autoDiscoverSecrets(o.Src, m)
		}
		if secPath == "" && m.Secrets.Present {
			return fmt.Errorf("архив секретов %q заявлен в манифесте, но не найден рядом с %s (укажите --secrets или --skip-secrets)", m.Secrets.Filename, o.Src)
		}
		if secPath != "" {
			secEncrypted = m.Secrets.Encrypted || looksEncrypted(secPath)
		}
	}
	passphrase := o.Passphrase
	if (sourceEncrypted(o.Src) || secEncrypted) && passphrase == "" {
		if o.AskPassphrase == nil {
			return fmt.Errorf("%w: архив зашифрован, но ввод пароля недоступен", ErrPass)
		}
		passphrase, err = o.AskPassphrase(true)
		if err != nil {
			return err
		}
		o.Passphrase = passphrase
	}

	// Conflict preflight (before any bookkeeping).
	if !o.Force {
		if conflicts := existingTargets(o.Home, m, o); len(conflicts) > 0 {
			return fmt.Errorf("цели уже существуют (use --force для замены с откатом через ~/.mimo-backup): %s", strings.Join(conflicts, ", "))
		}
	}

	// Generation bookkeeping: everything below is journaled and rollbackable.
	store, err := gens.Open(o.Home)
	if err != nil {
		return err
	}
	g, err := store.NewGeneration(o.Src)
	if err != nil {
		return err
	}
	roots := restoreRoots(m, o)
	g.Meta.DisplacedRoots = roots
	g.Meta.DirMTimes = recordDirMTimes(o.Home, m, o)
	if err := g.SaveMeta(); err != nil {
		return err // fsync before the first rename
	}
	if repo := openSettingsRepo(store, o.Home, o.Log); repo != nil {
		if hash, sErr := repo.Snapshot("pre-restore " + g.ID()); sErr == nil {
			g.Meta.PreRestoreCommit = hash
			_ = g.SaveMeta()
		}
	}

	if o.Force {
		if err := displaceRoots(o.Log, o.Home, g, roots); err != nil {
			_ = g.SetStatus(gens.StatusFailed)
			return err
		}
	}

	if err := extract(o, m, g, false); err != nil {
		_ = g.SetStatus(gens.StatusFailed)
		_ = store.LogEvent(gens.Event{Event: "restore", Gen: g.ID(), Note: "failed: " + err.Error()})
		return err
	}

	if secPath != "" {
		if err := restoreSecrets(o, m, g, secPath, passphrase); err != nil {
			_ = g.SetStatus(gens.StatusFailed)
			_ = store.LogEvent(gens.Event{Event: "restore", Gen: g.ID(), Note: "failed: " + err.Error()})
			return err
		}
	} else if !o.SkipSecrets && !m.ArchiveEncrypted {
		o.Log.Info("архив секретов не найден — восстановите вход через /login")
	}

	if repo := openSettingsRepo(store, o.Home, o.Log); repo != nil {
		if hash, sErr := repo.Snapshot("post-restore " + g.ID()); sErr == nil {
			g.Meta.PostRestoreCommit = hash
			_ = g.SaveMeta()
		}
	}
	_ = g.SetStatus(gens.StatusApplied)
	_ = store.LogEvent(gens.Event{Event: "restore", Gen: g.ID(), Note: "applied"})
	if pruned, err := store.PruneDisplaced(g.ID()); err == nil && len(pruned) > 0 {
		o.Log.Info("страховки старых поколений очищены", "generations", pruned)
	}

	postRestore(o, m, g)
	return nil
}

// dirRecorder creates parent dirs safely and journals the ones it creates,
// so rollback can remove them again. Shared by extract and restoreSecrets.
type dirRecorder struct {
	journal *gens.Journal
	base    string
	seen    map[string]bool
}

// Ensure creates the missing parents of full (symlink-safe) and journals
// them as created dirs. rel is the home-relative entry path.
func (d *dirRecorder) Ensure(rel, full string) error {
	var chain []string
	for p := path.Dir(rel); p != "." && p != ""; p = path.Dir(p) {
		if d.seen[p] {
			break
		}
		chain = append(chain, p)
	}
	if len(chain) == 0 {
		return nil
	}
	var created []string
	for i := len(chain) - 1; i >= 0; i-- {
		p := filepath.Join(d.base, filepath.FromSlash(chain[i]))
		if _, err := os.Stat(p); os.IsNotExist(err) {
			created = append(created, chain[i])
		}
	}
	if err := archive.MkdirAllSafe(d.base, full); err != nil {
		return err
	}
	for _, p := range chain {
		d.seen[p] = true
	}
	if d.journal != nil {
		for _, p := range created {
			if err := d.journal.Record(gens.ExtractedEntry{Path: p, Type: "dir", Created: true}); err != nil {
				return err
			}
		}
	}
	return nil
}

// extract streams the archive; when verifyOnly no files are written.
// With a generation, every written entry is recorded to extracted.jsonl
// (append + fsync) so a later rollback can undo the restore precisely.
func extract(o Options, m *manifest.Manifest, g *gens.Generation, verifyOnly bool) (err error) {
	f, err := openSource(o.Src, o.Passphrase)
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
	var journal *gens.Journal
	if !verifyOnly && g != nil {
		journal, err = g.OpenJournal()
		if err != nil {
			return err
		}
		defer journal.Close()
	}
	seen := map[string]bool{}
	// verifyOnly validates entry names against a scratch base; nothing is written.
	base := o.Home
	if verifyOnly && base == "" {
		base = os.TempDir()
	}
	rec := &dirRecorder{journal: journal, base: base, seen: map[string]bool{}}

	// Bar totals: manifest bytes minus skipped paths (restore only).
	label := "Восстановление"
	if verifyOnly {
		label = "Проверка"
	}
	barTotal := m.Totals.Bytes
	barFiles := m.Totals.Files
	if !verifyOnly {
		for _, e := range m.Files {
			if e.Type == "file" && skipEntry(e.Path, m, o) {
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
		var hdr *tar.Header
		hdr, err = tr.Next()
		if errors.Is(err, io.EOF) {
			err = nil
			break
		}
		if err != nil {
			return fmt.Errorf("%w: повреждённый архив: %v", ErrVerify, err)
		}
		if hdr.Name == "manifest.json" {
			continue
		}
		rel, relErr := archive.HomeRel(hdr.Name)
		if relErr != nil {
			return fmt.Errorf("%w: %v", ErrVerify, relErr)
		}
		if rel == "." {
			continue // the home root entry itself
		}
		full, err2 := archive.SafeJoin(base, rel)
		if err2 != nil {
			return fmt.Errorf("%w: %v", ErrVerify, err2)
		}
		// Restore-skip policy applies only to real restores; verify checks everything.
		if !verifyOnly && skipEntry(hdr.Name, m, o) {
			continue
		}
		seen[hdr.Name] = true

		switch hdr.Typeflag {
		case tar.TypeDir:
			if verifyOnly {
				continue
			}
			_, statErr := os.Stat(full)
			created := os.IsNotExist(statErr)
			if err = rec.Ensure(rel, full); err != nil {
				return err
			}
			if err = os.MkdirAll(full, 0o755); err != nil {
				return err
			}
			if journal != nil {
				if err = journal.Record(gens.ExtractedEntry{Path: rel, Type: "dir", Created: created}); err != nil {
					return err
				}
			}
		case tar.TypeSymlink:
			if verifyOnly {
				continue
			}
			if err = rec.Ensure(rel, full); err != nil {
				return err
			}
			os.Remove(full)
			if err = os.Symlink(hdr.Linkname, full); err != nil {
				return err
			}
			if journal != nil {
				if err = journal.Record(gens.ExtractedEntry{Path: rel, Type: "symlink", Link: hdr.Linkname}); err != nil {
					return err
				}
			}
		case tar.TypeReg:
			h.Reset()
			var w io.Writer = io.MultiWriter(h, bar)
			var out *os.File
			if !verifyOnly {
				if err = rec.Ensure(rel, full); err != nil {
					return err
				}
				out, err = archive.CreateFileSafe(base, full, os.FileMode(hdr.Mode))
				if err != nil {
					return err
				}
				w = io.MultiWriter(out, h, bar)
			}
			n, cErr := io.CopyBuffer(w, tr, buf)
			if cErr != nil {
				if out != nil {
					out.Close()
				}
				err = cErr
				return fmt.Errorf("%w: чтение %s: %v", ErrVerify, hdr.Name, cErr)
			}
			if out != nil {
				out.Close()
			}
			sum := hex.EncodeToString(h.Sum(nil))
			if journal != nil {
				// Record what is actually on disk before any check, so
				// rollback can clean up even a hash-mismatched write.
				if err = journal.Record(gens.ExtractedEntry{Path: rel, Type: "file", SHA256: sum}); err != nil {
					return err
				}
			}
			want, ok := byPath[hdr.Name]
			if ok && want.Type == "file" {
				if sum != want.SHA256 {
					err = fmt.Errorf("%w: %s (ожидался %s, получен %s)", ErrVerify, hdr.Name, want.SHA256, sum)
					return err
				}
			} else if !ok && !verifyOnly {
				bar.Log("файл не значится в манифесте: " + hdr.Name)
			}
			_ = n
			bar.NextFile()
		}
	}

	// Manifest completeness: every entry must have been seen.
	// Entries intentionally skipped by restore policy don't count as missing.
	var missing []string
	for _, e := range m.Files {
		if !seen[e.Path] && !skipEntry(e.Path, m, o) {
			missing = append(missing, e.Path)
		}
	}
	if len(missing) > 0 {
		err = fmt.Errorf("%w: в архиве отсутствуют файлы манифеста: %s…", ErrVerify, strings.Join(firstN(missing, 5), ", "))
		return err
	}
	bar.Finish()
	return nil
}

// skipOnRestore implements the restore-skip policy. Only exact top-level
// paths are skipped; same-named files at other depths are restored normally.
func skipOnRestore(name string, o Options) bool {
	if !o.KeepInstID && name == "home/.local/share/mimocode/installation_id" {
		return true
	}
	if !o.RestoreRC {
		switch name {
		case "home/.bashrc", "home/.profile", "home/.bash_profile":
			return true
		}
	}
	return false
}

// sourceEncrypted reports whether src is a sealed .mimosec container.
func sourceEncrypted(src string) bool {
	f, err := os.Open(src)
	if err != nil {
		return false
	}
	defer f.Close()
	var head [8]byte
	if _, err := io.ReadFull(f, head[:]); err != nil {
		return false
	}
	return secbox.LooksEncrypted(head[:])
}

// openSource opens the archive payload, transparently decrypting sealed
// containers. The caller must Close the returned reader (for containers
// this unblocks the decrypting goroutine).
func openSource(src, passphrase string) (io.ReadCloser, error) {
	f, err := os.Open(src)
	if err != nil {
		return nil, err
	}
	var head [8]byte
	if _, err := io.ReadFull(f, head[:]); err != nil {
		f.Close()
		return nil, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		f.Close()
		return nil, err
	}
	if !secbox.LooksEncrypted(head[:]) {
		return f, nil
	}
	pr, pw := io.Pipe()
	go func() {
		_, err := secbox.OpenStream(pw, f, []byte(passphrase))
		pw.CloseWithError(err)
		f.Close()
	}()
	return pr, nil
}

// skipEntry reports entries the restore must not write: the rc/installation
// policy, stale DB sidecars shadowing a vacuum-into snapshot, and (with
// --skip-secrets) raw secret files carried inside a sealed container.
func skipEntry(name string, m *manifest.Manifest, o Options) bool {
	if skipOnRestore(name, o) {
		return true
	}
	if m.DB.Method == "vacuum-into" &&
		(name == "home/.local/share/mimocode/mimocode.db-wal" || name == "home/.local/share/mimocode/mimocode.db-shm") {
		return true
	}
	if o.SkipSecrets {
		for _, r := range m.RedactedPaths {
			if r == name {
				return false // redacted copies keep configs working
			}
		}
		for _, p := range m.SecretPaths {
			if p == name {
				return true
			}
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

// resolveManifest returns the archive manifest. Sealed containers carry no
// sidecar by design — it would leak entry names next to the archive — so the
// in-tar manifest (last entry) is read directly and the extra read pass is
// expected, not a defect. Only plain .tar.gz archives without their sidecar
// get the two-pass warning.
func resolveManifest(o Options, sealed bool) (*manifest.Manifest, error) {
	if sealed {
		o.Log.Info("манифест внутри контейнера — архив читается дважды (sidecar не пишется: имена не утекают)")
		m, err := manifestFromTar(o.Src, o.Passphrase)
		if err != nil {
			return nil, fmt.Errorf("манифест из контейнера: %w", err)
		}
		return m, nil
	}
	m, err := readSidecar(o.Src)
	if err != nil {
		o.Log.Warn("боковой манифест не найден — двухпроходный режим (~2x дольше)", "err", err)
		m, err = manifestFromTar(o.Src, o.Passphrase)
		if err != nil {
			return nil, fmt.Errorf("манифест не найден ни в sidecar, ни в архиве: %w", err)
		}
	}
	return m, nil
}

// manifestFromTar finds the trailing manifest.json in the archive (fallback).
func manifestFromTar(src, passphrase string) (*manifest.Manifest, error) {
	f, err := openSource(src, passphrase)
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

// writeSet returns the home-relative paths a restore writes (files,
// symlinks and secrets — leaves) plus archived directory entries, with
// skipOnRestore-filtered entries reported separately as skips.
func writeSet(m *manifest.Manifest, o Options) (leaves, dirs, skips []string) {
	seen := map[string]bool{}
	add := func(p, typ string) {
		if seen[p] {
			return
		}
		seen[p] = true
		rel, err := archive.HomeRel(p)
		if err != nil || rel == "." {
			return
		}
		if skipEntry(p, m, o) {
			skips = append(skips, rel)
			return
		}
		if typ == "dir" {
			dirs = append(dirs, rel)
			return
		}
		leaves = append(leaves, rel)
	}
	for _, e := range m.Files {
		add(e.Path, e.Type)
	}
	for _, p := range m.SecretPaths {
		add(p, "file")
	}
	return leaves, dirs, skips
}

// under reports whether p is root itself or lives inside it.
func under(p, root string) bool {
	return p == root || strings.HasPrefix(p, root+"/")
}

// covered reports whether p falls under any of the roots.
func covered(p string, roots []string) bool {
	for _, r := range roots {
		if under(p, r) {
			return true
		}
	}
	return false
}

// topmost drops entries that have an ancestor in the same set.
func topmost(set []string) []string {
	var out []string
	for _, a := range set {
		anc := false
		for _, b := range set {
			if a != b && strings.HasPrefix(a, b+"/") {
				anc = true
				break
			}
		}
		if !anc {
			out = append(out, a)
		}
	}
	return out
}

// restoreRoots returns the home-relative paths a restore replaces — the
// real restore roots: topmost archived directory trees plus leaf files
// living outside such trees. A root that covers a skipped path (like
// installation_id) is split into per-entry roots so skipped files stay put.
func restoreRoots(m *manifest.Manifest, o Options) []string {
	leaves, dirs, skips := writeSet(m, o)
	dirty := func(p string) bool {
		for _, s := range skips {
			if under(s, p) {
				return true
			}
		}
		return false
	}

	var roots []string
	for _, d := range topmost(dirs) {
		if !dirty(d) {
			roots = append(roots, d)
			continue
		}
		// Split the dirty tree: keep clean sub-trees and individual leaves.
		var subDirs []string
		for _, sd := range dirs {
			if strings.HasPrefix(sd, d+"/") {
				subDirs = append(subDirs, sd)
			}
		}
		var subRoots []string
		for _, sd := range topmost(subDirs) {
			if !dirty(sd) {
				subRoots = append(subRoots, sd)
			}
		}
		for _, w := range leaves {
			if !under(w, d) || covered(w, subRoots) {
				continue
			}
			dirw := path.Dir(w)
			if dirw != "." && !dirty(dirw) {
				subRoots = append(subRoots, dirw)
			} else {
				subRoots = append(subRoots, w)
			}
		}
		roots = append(roots, subRoots...)
	}
	for _, w := range leaves {
		if !covered(w, roots) {
			roots = append(roots, w)
		}
	}
	roots = topmost(roots)
	sort.Strings(roots)
	return roots
}

// recordDirMTimes captures the mtimes of every directory the restore will
// touch (write-set dirs and their ancestors) so rollback can return the
// tree byte-for-byte.
func recordDirMTimes(home string, m *manifest.Manifest, o Options) map[string]string {
	leaves, dirs, _ := writeSet(m, o)
	set := map[string]bool{}
	addAncestors := func(p string) {
		for p != "." && p != "" && p != "/" {
			set[p] = true
			p = path.Dir(p)
		}
	}
	for _, d := range dirs {
		addAncestors(d)
	}
	for _, l := range leaves {
		addAncestors(l)
	}
	out := map[string]string{}
	for rel := range set {
		p := filepath.Join(home, filepath.FromSlash(rel))
		if fi, err := os.Stat(p); err == nil && fi.IsDir() {
			out[rel] = fi.ModTime().UTC().Format(time.RFC3339Nano)
		}
	}
	return out
}

// existingTargets lists restore roots that already exist and hold data
// (non-empty dirs, or any file/symlink).
func existingTargets(home string, m *manifest.Manifest, o Options) []string {
	var out []string
	for _, r := range restoreRoots(m, o) {
		p := filepath.Join(home, filepath.FromSlash(r))
		fi, err := os.Lstat(p)
		if err != nil {
			continue
		}
		if fi.IsDir() {
			ents, _ := os.ReadDir(p)
			if len(ents) > 0 {
				out = append(out, r)
			}
			continue
		}
		out = append(out, r)
	}
	return out
}

// displaceRoots moves existing restore roots into the generation's
// displaced/ tree (O(1) rename; cross-device copy fallback). Fatal on
// error: extracting over an undisplaced root would lose data.
func displaceRoots(log *slog.Logger, home string, g *gens.Generation, roots []string) error {
	for _, r := range roots {
		p := filepath.Join(home, filepath.FromSlash(r))
		if _, err := os.Lstat(p); err != nil {
			continue
		}
		dst := g.DisplacedPath(r)
		if err := gens.MoveTree(p, dst); err != nil {
			return fmt.Errorf("displace %s: %w", r, err)
		}
		log.Info("существующий путь отодвинут", "from", p, "to", dst)
	}
	return nil
}

// openSettingsRepo opens the settings git repo when git is available.
func openSettingsRepo(store *gens.Store, home string, log *slog.Logger) *vcs.Repo {
	if !vcs.Available() {
		return nil
	}
	repo, err := vcs.Open(store.SettingsRepo(), home)
	if err != nil {
		log.Debug("git-слой настроек недоступен", "err", err)
		return nil
	}
	return repo
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
// Encryption is decided by the manifest and the container magic, not by
// the file suffix; the passphrase is asked up front (see Restore).
func restoreSecrets(o Options, m *manifest.Manifest, g *gens.Generation, secPath, passphrase string) error {
	raw, err := os.ReadFile(secPath)
	if err != nil {
		return err
	}
	payload := raw
	if m.Secrets.Encrypted || secbox.LooksEncrypted(raw) {
		payload, err = secbox.Open([]byte(passphrase), raw)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrPass, err)
		}
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

	// Every secret write is journaled so rollback can undo it (this also
	// refreshes entries extract wrote as redacted copies).
	var journal *gens.Journal
	if g != nil {
		journal, err = g.OpenJournal()
		if err != nil {
			return err
		}
		defer journal.Close()
	}
	rec := &dirRecorder{journal: journal, base: o.Home, seen: map[string]bool{}}

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
		rel, err := archive.HomeRel(hdr.Name)
		if err != nil {
			return fmt.Errorf("secrets: %v", err)
		}
		if rel == "." {
			continue
		}
		full, err := archive.SafeJoin(o.Home, rel)
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
		if err := rec.Ensure(rel, full); err != nil {
			return err
		}
		out, err := archive.CreateFileSafe(o.Home, full, 0o600)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, tr); err != nil {
			out.Close()
			return err
		}
		out.Close()
		if journal != nil {
			sum, _, err := archive.HashFile(full)
			if err != nil {
				return err
			}
			if err := journal.Record(gens.ExtractedEntry{Path: rel, Type: "file", SHA256: sum}); err != nil {
				return err
			}
		}
	}
	o.Log.Info("секреты восстановлены", "from", secPath)
	return nil
}

// looksEncrypted reports whether the secrets artifact is a secbox container.
func looksEncrypted(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var head [8]byte
	if _, err := io.ReadFull(f, head[:]); err != nil {
		return false
	}
	return secbox.LooksEncrypted(head[:])
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
func postRestore(o Options, m *manifest.Manifest, g *gens.Generation) {
	o.Log.Info("восстановление завершено", "files", m.Totals.Files, "generation", g.ID())
	o.Log.Info("откат: mimo-backup rollback  (поколение " + g.ID() + ")")
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
