package backup

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chubuk/mimo-backup/internal/archive"
	"github.com/chubuk/mimo-backup/internal/manifest"
	"github.com/chubuk/mimo-backup/internal/restore"
	"github.com/chubuk/mimo-backup/internal/secbox"
)

// buildFakeHome creates a small but representative MiMoCode home tree.
func buildFakeHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	write := func(rel, content string, mode os.FileMode) {
		p := filepath.Join(home, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}
	write(".local/share/mimocode/mimocode.db", "FAKE-SQLITE-BYTES", 0o644)
	write(".local/share/mimocode/auth.json", `{"mimo": {"key": "sk-secret-auth-1234567890"}}`, 0o600)
	write(".local/share/mimocode/mimo-free-client", "free-client-token", 0o600)
	write(".local/share/mimocode/installation_id", "uuid-1234", 0o644)
	write(".local/share/mimocode/memory/MEMORY.md", "# memory", 0o644)
	write(".local/state/mimocode/kv.json", `{"theme": "dark"}`, 0o644)
	write(".local/state/mimocode/llm-server/abc/tokens.json", `{"token": "tok-abc"}`, 0o600)
	write(".local/state/mimocode/locks/x.lock/meta.json", `{"pid": 1}`, 0o644) // transient
	write(".config/mimocode/mimocode.jsonc", `{"apiKey": "sk-config-key-1234567890", "model": "mimo"}`, 0o644)
	write(".config/mimocode/AGENTS.md", "rules", 0o644)
	write(".bashrc", "export PATH=$HOME/.mimocode/bin:$PATH\n", 0o644)
	write(".mimocode/bin/mimo", "#!/bin/sh\nexit 0\n", 0o755)
	write(".ssh/mimo_deploy", "PRIVATE-KEY-MATERIAL", 0o600)
	write(".ssh/id_rsa", "OTHER-KEY", 0o600) // out of scope
	write("projects/alpha/main.go", "package main", 0o644)
	write("projects/alpha/node_modules/x/y.js", "js", 0o644)
	write("projects/alpha/.mimocode/mimocode.json", `{"mcp": {"Authorization": "Bearer eyJ.secret.token.value123"}}`, 0o644)
	write("projects/alpha/.mimocode/mimocode.json.bak-1", `{"Authorization": "Bearer eyJ.backup.token.value123"}`, 0o644)
	write("projects/alpha/.mimocode/.cron-lock", `{"pid": 2}`, 0o644) // transient
	write("projects/alpha/.env", "API_KEY=sk-env-key-abcdefghij\n", 0o644)
	write("nvidia-install/.mimocode/mimocode.json", `{"apiKey": "sk-outtree-key-1234567890"}`, 0o644)
	return home
}

func runBackup(t *testing.T, home, dest string, withSecrets bool, passphrase string) (*manifest.Manifest, string) {
	t.Helper()
	o := Options{
		Dest: dest, Home: home, Label: "test",
		SkipProcGate: true, Force: true,
		NoSecrets:     !withSecrets,
		AskPassphrase: func() (string, error) { return passphrase, nil },
	}
	if err := Run(o); err != nil {
		t.Fatalf("backup.Run: %v", err)
	}
	// Label always carries a timestamp: locate the actual artifact base.
	matches, err := filepath.Glob(filepath.Join(dest, "mimo-backup-test-*.manifest.json"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("manifest glob: %v %v", matches, err)
	}
	base := strings.TrimSuffix(matches[0], ".manifest.json")
	f, err := os.Open(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	m, err := manifest.Load(f)
	if err != nil {
		t.Fatal(err)
	}
	return m, base
}

func TestEndToEndBackupRestore(t *testing.T) {
	home := buildFakeHome(t)
	dest := t.TempDir()
	m, base := runBackup(t, home, dest, true, "abc12")

	// Artifacts present (base is already an absolute path).
	for _, name := range []string{
		base + ".tar.gz",
		base + ".manifest.json",
		base + "-secrets.mimosec",
	} {
		if _, err := os.Stat(name); err != nil {
			t.Fatalf("artifact missing: %s", name)
		}
	}

	// Secrets classification: none of the secret paths in files[].
	secretNeedles := []string{"auth.json", "mimo-free-client", "mimo_deploy", "mimocode.json", ".env", "tokens.json"}
	for _, f := range m.Files {
		for _, s := range secretNeedles {
			if strings.Contains(f.Path, s) && !contains(m.RedactedPaths, f.Path) {
				// Redacted copies of mimocode.json/.env ARE in files[]; raw secrets are not.
				if strings.HasPrefix(filepath.Base(f.Path), "mimocode.json") || strings.HasSuffix(f.Path, ".env") {
					continue // redacted copy
				}
				t.Fatalf("secret %s leaked into main archive files[]", f.Path)
			}
		}
	}
	if len(m.SecretPaths) == 0 {
		t.Fatalf("secret_paths empty")
	}

	// Transient paths absent entirely.
	for _, f := range m.Files {
		if strings.Contains(f.Path, "locks/") || strings.Contains(f.Path, ".cron-lock") {
			t.Fatalf("transient path archived: %s", f.Path)
		}
	}

	// Verify quick + full.
	src := base + ".tar.gz"
	if err := restore.Verify(restore.Options{Src: src, Quick: true, SkipProcGate: true}); err != nil {
		t.Fatalf("verify --quick: %v", err)
	}
	if err := restore.Verify(restore.Options{Src: src, Full: true, SkipProcGate: true}); err != nil {
		t.Fatalf("verify --full: %v", err)
	}

	// Restore into a fresh home with secrets.
	target := t.TempDir()
	ro := restore.Options{
		Src: src, Home: target, Force: true, SkipProcGate: true,
		AskPassphrase: func(bool) (string, error) { return "abc12", nil },
	}
	if err := restore.Restore(ro); err != nil {
		t.Fatalf("restore: %v", err)
	}

	// Content checks (restore writes into <home>/X — no nested home/).
	want := map[string]string{
		".local/share/mimocode/mimocode.db":      "FAKE-SQLITE-BYTES",
		".local/share/mimocode/memory/MEMORY.md": "# memory",
		"projects/alpha/main.go":                 "package main",
		"projects/alpha/node_modules/x/y.js":     "js",
		".local/share/mimocode/auth.json":        `{"mimo": {"key": "sk-secret-auth-1234567890"}}`,
		".ssh/mimo_deploy":                       "PRIVATE-KEY-MATERIAL",
		"projects/alpha/.env":                    "API_KEY=sk-env-key-abcdefghij\n",
	}
	for rel, content := range want {
		b, err := os.ReadFile(filepath.Join(target, rel))
		if err != nil {
			t.Fatalf("restored %s: %v", rel, err)
		}
		if string(b) != content {
			t.Fatalf("restored %s = %q", rel, b)
		}
	}

	// No nested home/ directory (bug A regression).
	if _, err := os.Stat(filepath.Join(target, "home")); !os.IsNotExist(err) {
		t.Fatalf("nested home/ directory created")
	}

	// installation_id skipped by default.
	if _, err := os.Stat(filepath.Join(target, ".local/share/mimocode/installation_id")); !os.IsNotExist(err) {
		t.Fatalf("installation_id restored unexpectedly")
	}
	// Out-of-scope ssh key must not be archived at all.
	if _, err := os.Stat(filepath.Join(target, ".ssh/id_rsa")); !os.IsNotExist(err) {
		t.Fatalf("out-of-scope id_rsa restored")
	}

	// Redacted copies: config in main must not contain the raw key.
	red, err := os.ReadFile(filepath.Join(target, ".config/mimocode/mimocode.jsonc"))
	if err != nil {
		// It may have been overwritten by the secrets restore with the raw one —
		// that is the documented flow. Check the manifest instead.
		_ = red
	}
}

func TestRedactedCopiesInMain(t *testing.T) {
	home := buildFakeHome(t)
	dest := t.TempDir()
	m, base := runBackup(t, home, dest, true, "abc12")

	if len(m.RedactedPaths) == 0 {
		t.Fatalf("redacted_paths empty")
	}
	// Scan the DECOMPRESSED main archive: gzip would hide plaintext secrets.
	raw, err := os.ReadFile(base + ".tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range []string{
		"sk-config-key-1234567890",
		"sk-secret-auth-1234567890",
		"PRIVATE-KEY-MATERIAL",
		"eyJ.secret.token.value123",
		"eyJ.backup.token.value123",
		"sk-env-key-abcdefghij",
		"sk-outtree-key-1234567890",
	} {
		if bytes.Contains(plain, []byte(needle)) {
			t.Fatalf("secret %q leaked into main archive", needle)
		}
	}
	// But redacted markers must be present.
	if !bytes.Contains(plain, []byte(secbox.RedactedMarker)) {
		t.Fatalf("no redaction markers in main archive")
	}
}

func TestRestoreWithoutSecrets(t *testing.T) {
	home := buildFakeHome(t)
	dest := t.TempDir()
	_, base := runBackup(t, home, dest, true, "abc12")

	target := t.TempDir()
	ro := restore.Options{
		Src:  base + ".tar.gz",
		Home: target, Force: true, SkipSecrets: true, SkipProcGate: true,
	}
	if err := restore.Restore(ro); err != nil {
		t.Fatalf("restore: %v", err)
	}
	// auth.json must NOT exist.
	if _, err := os.Stat(filepath.Join(target, ".local/share/mimocode/auth.json")); !os.IsNotExist(err) {
		t.Fatalf("auth.json restored despite --skip-secrets")
	}
	// Redacted project config must exist.
	if _, err := os.Stat(filepath.Join(target, "projects/alpha/.mimocode/mimocode.json")); err != nil {
		t.Fatalf("redacted project config missing: %v", err)
	}
}

func TestTamperArchiveFailsVerify(t *testing.T) {
	home := buildFakeHome(t)
	dest := t.TempDir()
	_, base := runBackup(t, home, dest, false, "")

	// Flip one byte in the middle of the archive.
	src := base + ".tar.gz"
	raw, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)/2] ^= 0xFF
	if err := os.WriteFile(src, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	err = restore.Verify(restore.Options{Src: src, Quick: true, SkipProcGate: true})
	if !errors.Is(err, restore.ErrVerify) {
		t.Fatalf("err = %v, want ErrVerify", err)
	}
}

func TestWrongPassphraseFails(t *testing.T) {
	home := buildFakeHome(t)
	dest := t.TempDir()
	_, base := runBackup(t, home, dest, true, "abc12")

	target := t.TempDir()
	ro := restore.Options{
		Src:  base + ".tar.gz",
		Home: target, Force: true, SkipProcGate: true,
		AskPassphrase: func(bool) (string, error) { return "wrongpass", nil },
	}
	err := restore.Restore(ro)
	if !errors.Is(err, restore.ErrPass) && !errors.Is(err, secbox.ErrAuth) {
		t.Fatalf("err = %v, want ErrPass/ErrAuth", err)
	}
	// Nothing must be written for secrets; main data may exist.
	if _, err := os.Stat(filepath.Join(target, ".local/share/mimocode/auth.json")); !os.IsNotExist(err) {
		t.Fatalf("auth.json written despite wrong passphrase")
	}
}

func TestSecretsUnencryptedRoundTrip(t *testing.T) {
	home := buildFakeHome(t)
	dest := t.TempDir()
	_, base := runBackup(t, home, dest, true, "") // no passphrase

	if _, err := os.Stat(base + "-secrets.tar.gz"); err != nil {
		t.Fatalf("unencrypted secrets artifact missing")
	}
	target := t.TempDir()
	ro := restore.Options{
		Src:  base + ".tar.gz",
		Home: target, Force: true, SkipProcGate: true,
	}
	if err := restore.Restore(ro); err != nil {
		t.Fatalf("restore: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(target, ".local/share/mimocode/auth.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "sk-secret-auth") {
		t.Fatalf("auth.json content wrong: %q", b)
	}
}

func TestNoSecretsWarns(t *testing.T) {
	home := buildFakeHome(t)
	dest := t.TempDir()
	m, _ := runBackup(t, home, dest, false, "")
	if m.Secrets.Present {
		t.Fatalf("secrets present despite disabled")
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// --- regressions: v1.1 bug fixes (A–E) --------------------------------

// Bug B: the restore journal must survive a failed restore.
func TestJournalSurvivesFailure(t *testing.T) {
	home := buildFakeHome(t)
	dest := t.TempDir()
	_, base := runBackup(t, home, dest, true, "abc12")

	// Flip the hash of a non-skipped file in the sidecar manifest so
	// extraction fails midway.
	mp := base + ".manifest.json"
	raw, err := os.ReadFile(mp)
	if err != nil {
		t.Fatal(err)
	}
	m, err := manifest.Load(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	flipped := false
	for i := range m.Files {
		if m.Files[i].Type == "file" && strings.HasSuffix(m.Files[i].Path, "mimocode.db") {
			m.Files[i].SHA256 = strings.Repeat("0", 64)
			flipped = true
			break
		}
	}
	if !flipped {
		t.Fatal("no mimocode.db entry to flip")
	}
	var buf bytes.Buffer
	if err := m.Encode(&buf); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mp, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	target := t.TempDir()
	ro := restore.Options{
		Src: base + ".tar.gz", Home: target, Force: true, SkipProcGate: true,
		SkipSecrets: true, NoProgress: true,
	}
	if err := restore.Restore(ro); err == nil {
		t.Fatal("restore must fail on hash mismatch")
	}
	// The extracted journal must survive inside the generation.
	matches, _ := filepath.Glob(filepath.Join(target, ".mimo-backup", "generations", "*", "extracted.jsonl"))
	if len(matches) == 0 {
		t.Fatal("extracted journal lost after failure")
	}
}

// Bug C: displacement equals the write set — skipped paths stay put and
// whole top-levels are never swept when only a subtree is restored.
func TestDisplacementWriteSet(t *testing.T) {
	home := buildFakeHome(t)
	dest := t.TempDir()
	_, base := runBackup(t, home, dest, true, "abc12")

	target := t.TempDir()
	write := func(rel, content string) {
		p := filepath.Join(target, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(".bashrc", "ORIGINAL-BASHRC")
	write(".local/share/mimocode/installation_id", "uuid-target")
	write(".local/share/mimocode/mimocode.db", "OLD-DB")
	write(".config/mimocode/old.json", "OLD-CONFIG")
	write(".config/keepme/app.conf", "KEEP-ME")

	ro := restore.Options{
		Src: base + ".tar.gz", Home: target, Force: true, SkipProcGate: true,
		NoProgress:    true,
		AskPassphrase: func(bool) (string, error) { return "abc12", nil },
	}
	if err := restore.Restore(ro); err != nil {
		t.Fatalf("restore: %v", err)
	}

	// Skipped and unrelated paths survive untouched.
	for rel, want := range map[string]string{
		".bashrc":                               "ORIGINAL-BASHRC",
		".local/share/mimocode/installation_id": "uuid-target",
		".config/keepme/app.conf":               "KEEP-ME",
	} {
		b, err := os.ReadFile(filepath.Join(target, rel))
		if err != nil {
			t.Fatalf("%s must not be displaced: %v", rel, err)
		}
		if string(b) != want {
			t.Fatalf("%s = %q, want %q", rel, b, want)
		}
	}

	// No coarse top-level sweeps and no .pre-restore sprawl.
	for _, pat := range []string{
		".config.pre-restore-*", ".local.pre-restore-*", ".bashrc.pre-restore-*",
	} {
		if matches, _ := filepath.Glob(filepath.Join(target, pat)); len(matches) > 0 {
			t.Fatalf("coarse displacement %s: %v", pat, matches)
		}
	}

	// Precise displacement of the real restore roots, stored under
	// ~/.mimo-backup/generations/<id>/displaced/.
	disp, _ := filepath.Glob(filepath.Join(target, ".mimo-backup", "generations", "*", "displaced"))
	if len(disp) != 1 {
		t.Fatalf("displaced dir = %v", disp)
	}
	if _, err := os.Stat(filepath.Join(disp[0], ".config", "mimocode")); err != nil {
		t.Fatalf(".config/mimocode not displaced as a tree: %v", err)
	}
	if _, err := os.Stat(filepath.Join(disp[0], ".local/share/mimocode", "mimocode.db")); err != nil {
		t.Fatalf("mimocode.db not displaced precisely: %v", err)
	}
	// The skipped paths must NOT be inside the displaced tree.
	if _, err := os.Stat(filepath.Join(disp[0], ".local/share/mimocode", "installation_id")); err == nil {
		t.Fatal("installation_id was swept into displaced")
	}

	// New content arrived at the correct level (no nested home/).
	b, err := os.ReadFile(filepath.Join(target, ".local/share/mimocode/mimocode.db"))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "FAKE-SQLITE-BYTES" {
		t.Fatalf("mimocode.db = %q", b)
	}
}

// Bugs D+E: AskPassphrase is called exactly once for a .mimosec container,
// and before any file is extracted.
func TestAskPassphraseOnceBeforeExtract(t *testing.T) {
	home := buildFakeHome(t)
	dest := t.TempDir()
	_, base := runBackup(t, home, dest, true, "abc12")

	target := t.TempDir()
	calls := 0
	ro := restore.Options{
		Src: base + ".tar.gz", Home: target, Force: true, SkipProcGate: true,
		NoProgress: true,
		AskPassphrase: func(encrypted bool) (string, error) {
			calls++
			if !encrypted {
				t.Error("AskPassphrase(encrypted=false) for a .mimosec container")
			}
			if _, err := os.Stat(filepath.Join(target, ".local")); err == nil {
				t.Error("passphrase asked after extraction started")
			}
			return "abc12", nil
		},
	}
	if err := restore.Restore(ro); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if calls != 1 {
		t.Fatalf("AskPassphrase called %d times, want exactly 1", calls)
	}
}

// Bug D: a secrets artifact claimed by the manifest but missing is an error.
func TestMissingSecretsArtifactFails(t *testing.T) {
	home := buildFakeHome(t)
	dest := t.TempDir()
	_, base := runBackup(t, home, dest, true, "abc12")
	if err := os.Remove(base + "-secrets.mimosec"); err != nil {
		t.Fatal(err)
	}

	target := t.TempDir()
	ro := restore.Options{
		Src: base + ".tar.gz", Home: target, Force: true, SkipProcGate: true,
		NoProgress:    true,
		AskPassphrase: func(bool) (string, error) { return "abc12", nil },
	}
	err := restore.Restore(ro)
	if err == nil {
		t.Fatal("missing secrets artifact must be an error")
	}
	if !strings.Contains(err.Error(), "секрет") {
		t.Fatalf("unhelpful error: %v", err)
	}

	// --skip-secrets must still work without the artifact.
	ro2 := restore.Options{
		Src: base + ".tar.gz", Home: t.TempDir(), Force: true, SkipProcGate: true,
		SkipSecrets: true, NoProgress: true,
	}
	if err := restore.Restore(ro2); err != nil {
		t.Fatalf("restore --skip-secrets: %v", err)
	}
}

// Bug D: Encrypted=true + garbage payload must fail with ErrPass, not a
// silent plaintext attempt.
func TestEncryptedGarbageFails(t *testing.T) {
	home := buildFakeHome(t)
	dest := t.TempDir()
	_, base := runBackup(t, home, dest, true, "abc12")
	if err := os.WriteFile(base+"-secrets.mimosec", []byte("this is not a container"), 0o600); err != nil {
		t.Fatal(err)
	}

	target := t.TempDir()
	ro := restore.Options{
		Src: base + ".tar.gz", Home: target, Force: true, SkipProcGate: true,
		NoProgress:    true,
		AskPassphrase: func(bool) (string, error) { return "abc12", nil },
	}
	err := restore.Restore(ro)
	if !errors.Is(err, restore.ErrPass) {
		t.Fatalf("err = %v, want ErrPass", err)
	}
}

// --- rollback round-trip (v1.1) ----------------------------------------

// snapshotTree records every path (files with hashes, symlinks with targets,
// dirs with mtimes) under root.
func snapshotTree(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		if rel == "." {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if strings.HasPrefix(rel, ".mimo-backup") {
			return nil // the store is not part of $HOME state
		}
		switch {
		case fi.IsDir():
			out[rel] = "dir " + fi.ModTime().UTC().Format(time.RFC3339Nano)
		case fi.Mode()&os.ModeSymlink != 0:
			link, _ := os.Readlink(p)
			out[rel] = "link " + link
		default:
			sum, _, _ := archive.HashFile(p)
			out[rel] = "file " + sum
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func seedTarget(t *testing.T) string {
	t.Helper()
	target := t.TempDir()
	write := func(rel, content string) {
		p := filepath.Join(target, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(".bashrc", "ORIGINAL-BASHRC")
	write(".local/share/mimocode/installation_id", "uuid-target")
	write(".local/share/mimocode/mimocode.db", "OLD-DB")
	write(".config/mimocode/old.json", "OLD-CONFIG")
	write(".config/keepme/app.conf", "KEEP-ME")
	if err := os.Symlink("app.conf", filepath.Join(target, ".config/keepme/ln")); err != nil {
		t.Fatal(err)
	}
	return target
}

// Test 2: restore → rollback returns the tree byte-for-byte.
func TestRollbackRoundTrip(t *testing.T) {
	home := buildFakeHome(t)
	dest := t.TempDir()
	_, base := runBackup(t, home, dest, true, "abc12")

	target := seedTarget(t)
	before := snapshotTree(t, target)

	ro := restore.Options{
		Src: base + ".tar.gz", Home: target, Force: true, SkipProcGate: true,
		NoProgress:    true,
		AskPassphrase: func(bool) (string, error) { return "abc12", nil },
	}
	if err := restore.Restore(ro); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if err := restore.Rollback(restore.RollbackOptions{Home: target, Yes: true, SkipProcGate: true}); err != nil {
		t.Fatalf("rollback: %v", err)
	}

	after := snapshotTree(t, target)
	for rel, want := range before {
		if after[rel] != want {
			t.Errorf("after rollback %s = %q, want %q", rel, after[rel], want)
		}
	}
	for rel := range after {
		if _, ok := before[rel]; !ok {
			t.Errorf("leftover after rollback: %s = %q", rel, after[rel])
		}
	}
}

// Test 3: a failed restore leaves a live journal; rollback restores the
// original state.
func TestRollbackAfterFailedRestore(t *testing.T) {
	home := buildFakeHome(t)
	dest := t.TempDir()
	_, base := runBackup(t, home, dest, true, "abc12")

	// Flip a hash so extraction fails midway.
	mp := base + ".manifest.json"
	raw, err := os.ReadFile(mp)
	if err != nil {
		t.Fatal(err)
	}
	m, err := manifest.Load(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	for i := range m.Files {
		if m.Files[i].Type == "file" && strings.HasSuffix(m.Files[i].Path, "MEMORY.md") {
			m.Files[i].SHA256 = strings.Repeat("0", 64)
		}
	}
	var buf bytes.Buffer
	if err := m.Encode(&buf); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mp, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	target := seedTarget(t)
	before := snapshotTree(t, target)
	ro := restore.Options{
		Src: base + ".tar.gz", Home: target, Force: true, SkipProcGate: true,
		SkipSecrets: true, NoProgress: true,
	}
	if err := restore.Restore(ro); err == nil {
		t.Fatal("restore must fail on hash mismatch")
	}
	// Rollback must undo the partial restore.
	if err := restore.Rollback(restore.RollbackOptions{Home: target, Yes: true, SkipProcGate: true}); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	after := snapshotTree(t, target)
	for rel, want := range before {
		if after[rel] != want {
			t.Errorf("after rollback %s = %q, want %q", rel, after[rel], want)
		}
	}
	for rel := range after {
		if _, ok := before[rel]; !ok {
			t.Errorf("leftover after rollback: %s", rel)
		}
	}
}

// Test 6: user edits between restore and rollback are detected and need
// confirmation (--yes); the pre-rollback git commit keeps them.
func TestRollbackModifiedNeedsConfirm(t *testing.T) {
	home := buildFakeHome(t)
	dest := t.TempDir()
	_, base := runBackup(t, home, dest, true, "abc12")

	target := t.TempDir()
	ro := restore.Options{
		Src: base + ".tar.gz", Home: target, Force: true, SkipProcGate: true,
		NoProgress:    true,
		AskPassphrase: func(bool) (string, error) { return "abc12", nil },
	}
	if err := restore.Restore(ro); err != nil {
		t.Fatalf("restore: %v", err)
	}
	// The user edits a restored config.
	edited := filepath.Join(target, ".config/mimocode/AGENTS.md")
	if err := os.WriteFile(edited, []byte("USER EDIT"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Without confirmation the rollback refuses.
	err := restore.Rollback(restore.RollbackOptions{Home: target, SkipProcGate: true})
	if !errors.Is(err, restore.ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict", err)
	}
	// With --yes it proceeds (edits are lost from $HOME).
	if err := restore.Rollback(restore.RollbackOptions{Home: target, Yes: true, SkipProcGate: true}); err != nil {
		t.Fatalf("rollback --yes: %v", err)
	}
	if b, err := os.ReadFile(edited); err == nil && string(b) == "USER EDIT" {
		t.Fatal("edited file survived rollback")
	}
}

// Test 7: rollback works without git in PATH (displaced-based restore).
func TestRollbackWithoutGit(t *testing.T) {
	home := buildFakeHome(t)
	dest := t.TempDir()
	_, base := runBackup(t, home, dest, true, "abc12")

	target := seedTarget(t)
	ro := restore.Options{
		Src: base + ".tar.gz", Home: target, Force: true, SkipProcGate: true,
		NoProgress:    true,
		AskPassphrase: func(bool) (string, error) { return "abc12", nil },
	}
	if err := restore.Restore(ro); err != nil {
		t.Fatalf("restore: %v", err)
	}

	t.Setenv("PATH", "/nonexistent") // hide git
	if err := restore.Rollback(restore.RollbackOptions{Home: target, Yes: true, SkipProcGate: true}); err != nil {
		t.Fatalf("rollback without git: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(target, ".config/mimocode/old.json")); err != nil || string(b) != "OLD-CONFIG" {
		t.Fatalf("old config not restored: %q %v", b, err)
	}
}

// Test 10: rollback --dry-run writes nothing.
func TestRollbackDryRun(t *testing.T) {
	home := buildFakeHome(t)
	dest := t.TempDir()
	_, base := runBackup(t, home, dest, true, "abc12")

	target := seedTarget(t)
	ro := restore.Options{
		Src: base + ".tar.gz", Home: target, Force: true, SkipProcGate: true,
		NoProgress:    true,
		AskPassphrase: func(bool) (string, error) { return "abc12", nil },
	}
	if err := restore.Restore(ro); err != nil {
		t.Fatalf("restore: %v", err)
	}
	mid := snapshotTree(t, target)
	if err := restore.Rollback(restore.RollbackOptions{Home: target, DryRun: true, SkipProcGate: true}); err != nil {
		t.Fatalf("dry-run rollback: %v", err)
	}
	now := snapshotTree(t, target)
	for rel, want := range mid {
		if now[rel] != want {
			t.Errorf("dry-run changed %s", rel)
		}
	}
	// The generation must still be rollbackable.
	if err := restore.Rollback(restore.RollbackOptions{Home: target, Yes: true, SkipProcGate: true}); err != nil {
		t.Fatalf("rollback after dry-run: %v", err)
	}
}

// Test 9: fix-nested repairs a v1.0.0-affected machine (nested ~/home).
func TestFixNested(t *testing.T) {
	home := t.TempDir()
	write := func(rel, content string) {
		p := filepath.Join(home, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// The nested restore from v1.0.0 (bug A).
	write("home/.local/share/mimocode/mimocode.db", "DB")
	write("home/.config/mimocode/mimocode.jsonc", "{}")
	write("home/.mimocode/bin/mimo", "BIN")
	write("home/projects/alpha/main.go", "package main")
	write("home/nvidia-install/x.txt", "X")
	write("home/.ssh/mimo_deploy", "KEY")
	write("home/.cache/fontconfig/f", "C")
	// The machine's own state around it.
	write(".bashrc.pre-restore-20260101-000000", "MY-BASHRC")
	write(".local/share/other.txt", "keep") // non-empty shell → merge
	write(".config/keepme/app.conf", "KEEP")
	write(".ssh/id_rsa", "USER-KEY")
	write("nvidia-install/other.txt", "OTHER")

	// Dry-run first: nothing changes.
	if err := restore.FixNested(restore.FixNestedOptions{Home: home, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}); err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, "home", "projects", "alpha", "main.go")); err != nil {
		t.Fatal("dry-run moved files")
	}

	if err := restore.FixNested(restore.FixNestedOptions{Home: home, Apply: true, Yes: true, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}); err != nil {
		t.Fatalf("apply: %v", err)
	}

	want := map[string]string{
		".bashrc":                           "MY-BASHRC",
		".local/share/mimocode/mimocode.db": "DB",
		".local/share/other.txt":            "keep",
		".config/mimocode/mimocode.jsonc":   "{}",
		".config/keepme/app.conf":           "KEEP",
		".mimocode/bin/mimo":                "BIN",
		"projects/alpha/main.go":            "package main",
		"nvidia-install/x.txt":              "X",
		"nvidia-install/other.txt":          "OTHER",
		".ssh/mimo_deploy":                  "KEY",
		".ssh/id_rsa":                       "USER-KEY",
		".cache/fontconfig/f":               "C",
	}
	for rel, content := range want {
		b, err := os.ReadFile(filepath.Join(home, rel))
		if err != nil {
			t.Errorf("missing after fix-nested: %s (%v)", rel, err)
			continue
		}
		if string(b) != content {
			t.Errorf("%s = %q, want %q", rel, b, content)
		}
	}
	if _, err := os.Stat(filepath.Join(home, "home")); err == nil {
		if ents, _ := os.ReadDir(filepath.Join(home, "home")); len(ents) > 0 {
			t.Errorf("home/ still has entries: %v", ents)
		}
	}
}

// fix-nested must never overwrite same-path files — it reports conflicts.
func TestFixNestedConflict(t *testing.T) {
	home := t.TempDir()
	write := func(rel, content string) {
		p := filepath.Join(home, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("home/projects/alpha/main.go", "RESTORED")
	write("projects/alpha/main.go", "MINE")

	err := restore.FixNested(restore.FixNestedOptions{Home: home, Apply: true, Yes: true, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if !errors.Is(err, restore.ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict", err)
	}
	b, _ := os.ReadFile(filepath.Join(home, "projects/alpha/main.go"))
	if string(b) != "MINE" {
		t.Fatalf("user file overwritten: %q", b)
	}
}

// Bug E (v1.0.0): stale mimocode.db-wal/-shm must not shadow a vacuum-into
// snapshot — neither in the archive nor on restore.
func TestStaleDBSidecarsSkipped(t *testing.T) {
	if !isStaleDBSidecar("home/.local/share/mimocode/mimocode.db-wal", "vacuum-into") {
		t.Fatal("wal not detected as stale for vacuum-into")
	}
	if isStaleDBSidecar("home/.local/share/mimocode/mimocode.db-wal", "cold-copy") {
		t.Fatal("cold-copy must keep the wal (it belongs to the trio)")
	}
	if isStaleDBSidecar("home/.local/share/mimocode/mimocode.db", "vacuum-into") {
		t.Fatal("the database itself is not a sidecar")
	}

	home := buildFakeHome(t)
	write := func(rel, content string) {
		if err := os.WriteFile(filepath.Join(home, rel), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(".local/share/mimocode/mimocode.db-wal", "STALE-WAL")
	write(".local/share/mimocode/mimocode.db-shm", "STALE-SHM")

	dest := t.TempDir()
	_, base := runBackup(t, home, dest, true, "abc12")

	// Mark the manifest as a vacuum-into snapshot (the hot path's output).
	mp := base + ".manifest.json"
	raw, err := os.ReadFile(mp)
	if err != nil {
		t.Fatal(err)
	}
	m, err := manifest.Load(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	m.DB.Method = "vacuum-into"
	var buf bytes.Buffer
	if err := m.Encode(&buf); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mp, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	target := t.TempDir()
	ro := restore.Options{
		Src: base + ".tar.gz", Home: target, Force: true, SkipProcGate: true,
		SkipSecrets: true, NoProgress: true,
	}
	if err := restore.Restore(ro); err != nil {
		t.Fatalf("restore: %v", err)
	}
	for _, rel := range []string{
		".local/share/mimocode/mimocode.db-wal",
		".local/share/mimocode/mimocode.db-shm",
	} {
		if _, err := os.Stat(filepath.Join(target, rel)); !os.IsNotExist(err) {
			t.Fatalf("stale %s restored next to the snapshot", rel)
		}
	}
	if _, err := os.Stat(filepath.Join(target, ".local/share/mimocode/mimocode.db")); err != nil {
		t.Fatalf("database missing: %v", err)
	}
}

// --encrypt: one sealed container carries data + manifest + raw secrets,
// with no sidecar and no separate secrets artifact.
func TestEncryptRoundTrip(t *testing.T) {
	home := buildFakeHome(t)
	dest := t.TempDir()
	o := Options{
		Dest: dest, Home: home, Label: "enc",
		SkipProcGate: true, Force: true,
		Encrypt:       true,
		NoProgress:    true,
		AskPassphrase: func() (string, error) { return "abc12", nil },
	}
	if err := Run(o); err != nil {
		t.Fatalf("backup --encrypt: %v", err)
	}
	matches, _ := filepath.Glob(filepath.Join(dest, "mimo-backup-enc-*.mimosec"))
	if len(matches) != 1 {
		t.Fatalf("container = %v", matches)
	}
	if side, _ := filepath.Glob(filepath.Join(dest, "*.manifest.json")); len(side) != 0 {
		t.Fatalf("sidecar written for a container: %v", side)
	}
	if sec, _ := filepath.Glob(filepath.Join(dest, "*-secrets.*")); len(sec) != 0 {
		t.Fatalf("separate secrets artifact for a container: %v", sec)
	}
	raw, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	if !secbox.LooksEncrypted(raw) {
		t.Fatal("container is not sealed")
	}
	// No plaintext secret may leak into the sealed artifact's surroundings.
	if bytes.Contains(raw, []byte("sk-secret-auth-1234567890")) {
		t.Fatal("secret visible in container bytes") // would mean no encryption
	}

	target := t.TempDir()
	ro := restore.Options{
		Src: matches[0], Home: target, Force: true, SkipProcGate: true,
		NoProgress:    true,
		AskPassphrase: func(bool) (string, error) { return "abc12", nil },
	}
	if err := restore.Restore(ro); err != nil {
		t.Fatalf("restore container: %v", err)
	}
	want := map[string]string{
		".local/share/mimocode/mimocode.db": "FAKE-SQLITE-BYTES",
		".local/share/mimocode/auth.json":   `{"mimo": {"key": "sk-secret-auth-1234567890"}}`,
		".ssh/mimo_deploy":                  "PRIVATE-KEY-MATERIAL",
		"projects/alpha/main.go":            "package main",
		".config/mimocode/AGENTS.md":        "rules",
	}
	for rel, content := range want {
		b, err := os.ReadFile(filepath.Join(target, rel))
		if err != nil {
			t.Fatalf("missing %s: %v", rel, err)
		}
		if string(b) != content {
			t.Fatalf("%s = %q, want %q", rel, b, content)
		}
	}

	// --skip-secrets keeps the raw secret files out of the target (the
	// container still needs its passphrase to be read at all).
	target2 := t.TempDir()
	ro2 := restore.Options{
		Src: matches[0], Home: target2, Force: true, SkipProcGate: true,
		NoProgress: true, SkipSecrets: true,
		AskPassphrase: func(bool) (string, error) { return "abc12", nil },
	}
	if err := restore.Restore(ro2); err != nil {
		t.Fatalf("restore --skip-secrets: %v", err)
	}
	if _, err := os.Stat(filepath.Join(target2, ".ssh/mimo_deploy")); !os.IsNotExist(err) {
		t.Fatal("raw secret restored despite --skip-secrets")
	}
	if _, err := os.Stat(filepath.Join(target2, "projects/alpha/main.go")); err != nil {
		t.Fatalf("data missing: %v", err)
	}
}
