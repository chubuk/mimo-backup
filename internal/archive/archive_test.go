package archive

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func buildTree(t *testing.T) (files map[string]string, root string) {
	t.Helper()
	root = t.TempDir()
	files = map[string]string{
		"a.txt":          "hello",
		"sub/b.txt":      "world",
		"sub/deep/c.txt": "!!!",
		"d.txt":          strings.Repeat("x", 300_000), // multi-buffer
	}
	for rel, content := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return files, root
}

func TestWriteReadRoundTrip(t *testing.T) {
	files, root := buildTree(t)
	var buf bytes.Buffer
	w, err := NewWriter(&buf, 1)
	if err != nil {
		t.Fatal(err)
	}
	hashes := map[string]string{}
	for rel, content := range files {
		fi, err := os.Stat(filepath.Join(root, rel))
		if err != nil {
			t.Fatal(err)
		}
		f, err := os.Open(filepath.Join(root, rel))
		if err != nil {
			t.Fatal(err)
		}
		sha, torn, err := w.AddFile("home/"+rel, f, fi.Size(), fi.Mode(), fi.ModTime())
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		if torn {
			t.Fatalf("unexpected torn for %s", rel)
		}
		if sha == "" {
			t.Fatalf("empty sha for %s", rel)
		}
		hashes[rel] = sha
		if int64(len(content)) != fi.Size() {
			t.Fatalf("fixture mismatch %s", rel)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	// Read back into a fresh tree and compare.
	dst := t.TempDir()
	tr, closer, err := ReadCloser(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	defer closer.Close()
	seen := map[string]bool{}
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		rel := strings.TrimPrefix(hdr.Name, "home/")
		full, err := SafeJoin(dst, hdr.Name)
		if err != nil {
			t.Fatalf("SafeJoin: %v", err)
		}
		if hdr.Typeflag == tar.TypeReg {
			if err := MkdirAllSafe(full); err != nil {
				t.Fatal(err)
			}
			f, err := CreateFileSafe(full, os.FileMode(hdr.Mode))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.Copy(f, tr); err != nil {
				t.Fatal(err)
			}
			f.Close()
			seen[rel] = true
		}
	}
	for rel := range files {
		if !seen[rel] {
			t.Fatalf("missing entry %s", rel)
		}
		got, err := os.ReadFile(filepath.Join(dst, "home", rel))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != files[rel] {
			t.Fatalf("content mismatch %s", rel)
		}
	}
}

func TestAddFileShortReadPads(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewWriter(&buf, 1)
	if err != nil {
		t.Fatal(err)
	}
	// Declare 100 bytes but supply 10.
	sha, torn, err := w.AddFile("home/x", bytes.NewReader([]byte("0123456789")), 100, 0o644, time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if !torn {
		t.Fatalf("expected torn=true")
	}
	if sha == "" {
		t.Fatalf("empty sha")
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	tr, closer, err := ReadCloser(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	defer closer.Close()
	hdr, err := tr.Next()
	if err != nil {
		t.Fatal(err)
	}
	if hdr.Size != 100 {
		t.Fatalf("size = %d, want 100 (zero-padded)", hdr.Size)
	}
}

func TestSafeJoinRejects(t *testing.T) {
	dst := t.TempDir()
	bad := []string{
		"home/../../etc/passwd",
		"../evil",
		"/abs/path",
		"home/x/../../y",
		"..",
	}
	for _, name := range bad {
		if _, err := SafeJoin(dst, name); err == nil {
			t.Fatalf("accepted %q", name)
		}
	}
	if _, err := SafeJoin(dst, "home/ok.txt"); err != nil {
		t.Fatalf("rejected good name: %v", err)
	}
}

func TestSymlinkParentRejected(t *testing.T) {
	dst := t.TempDir()
	evil := t.TempDir()
	if err := os.Symlink(evil, filepath.Join(dst, "link")); err != nil {
		t.Fatal(err)
	}
	// Writing home/link/file must fail: "link" parent is a symlink.
	err := MkdirAllSafe(filepath.Join(dst, "link", "file.txt"))
	if err == nil {
		t.Fatalf("symlink parent accepted")
	}
}

func TestCreateFileSafeRefusesSymlinkFinal(t *testing.T) {
	dst := t.TempDir()
	target := filepath.Join(dst, "target")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dst, "sym")); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateFileSafe(filepath.Join(dst, "sym"), 0o644); err == nil {
		t.Fatalf("symlink final component accepted")
	}
}

func TestPartialCommitAndAbort(t *testing.T) {
	dir := t.TempDir()
	final := filepath.Join(dir, "out.bin")

	p, err := CreatePartial(final)
	if err != nil {
		t.Fatal(err)
	}
	p.Write([]byte("data"))
	if err := p.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(final); err != nil {
		t.Fatalf("final missing after commit: %v", err)
	}
	if _, err := os.Stat(final + ".partial"); !os.IsNotExist(err) {
		t.Fatalf("partial left behind")
	}

	p2, err := CreatePartial(final + ".2")
	if err != nil {
		t.Fatal(err)
	}
	p2.Write([]byte("x"))
	p2.Abort()
	if _, err := os.Stat(final + ".2"); !os.IsNotExist(err) {
		t.Fatalf("aborted file exists")
	}
}

func TestJournal(t *testing.T) {
	dir := t.TempDir()
	jp := filepath.Join(dir, ".restore-journal.jsonl")
	j, err := OpenJournal(jp)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.Record("home/a"); err != nil {
		t.Fatal(err)
	}
	if err := j.Record("home/b"); err != nil {
		t.Fatal(err)
	}
	j.Close()
	b, err := os.ReadFile(jp)
	if err != nil {
		t.Fatal(err)
	}
	if cnt := strings.Count(string(b), "\n"); cnt != 2 {
		t.Fatalf("journal lines = %d", cnt)
	}
}
