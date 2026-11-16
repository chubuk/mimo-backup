// Package archive provides streaming tar.gz writing with hash-while-write,
// safe extraction (zip-slip and symlink-parent protection), atomic
// partial-file commits, and a restore journal.
package archive

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// BufSize is the streaming copy buffer (O(1) memory per file).
const BufSize = 256 << 10

// Writer streams a gzip-compressed tar archive. Hashes are computed while
// content is written (single pass, no TOCTOU window).
type Writer struct {
	gz  *gzip.Writer
	tw  *tar.Writer
	buf []byte
}

// NewWriter wraps w with gzip level (1..9) and a tar writer.
func NewWriter(w io.Writer, level int) (*Writer, error) {
	if level < 1 || level > 9 {
		return nil, fmt.Errorf("gzip level %d out of range 1..9", level)
	}
	gz, err := gzip.NewWriterLevel(w, level)
	if err != nil {
		return nil, fmt.Errorf("gzip writer: %w", err)
	}
	return &Writer{gz: gz, tw: tar.NewWriter(gz), buf: make([]byte, BufSize)}, nil
}

// WriteHeader writes a raw tar header entry.
func (w *Writer) WriteHeader(hdr *tar.Header) error {
	return w.tw.WriteHeader(hdr)
}

// AddFile streams one regular file entry, hashing content on the fly.
// If the source yields fewer than size bytes, the entry is zero-padded to
// size (tar requires exact sizes) and torn is reported true.
func (w *Writer) AddFile(path string, r io.Reader, size int64, mode fs.FileMode, mtime time.Time) (sha string, torn bool, err error) {
	hdr := &tar.Header{
		Typeflag: tar.TypeReg,
		Name:     path,
		Mode:     int64(mode & 0o777),
		Size:     size,
		ModTime:  mtime,
		Format:   tar.FormatPAX,
	}
	if err := w.tw.WriteHeader(hdr); err != nil {
		return "", false, fmt.Errorf("write header %s: %w", path, err)
	}
	h := sha256.New()
	mw := io.MultiWriter(w.tw, h)
	n, err := io.CopyBuffer(mw, io.LimitReader(r, size), w.buf)
	if err != nil {
		return "", false, fmt.Errorf("copy %s: %w", path, err)
	}
	if n < size {
		torn = true
		pad := size - n
		if _, err := io.CopyBuffer(w.tw, io.LimitReader(zeroReader{}, pad), w.buf); err != nil {
			return "", true, fmt.Errorf("pad %s: %w", path, err)
		}
	}
	return hex.EncodeToString(h.Sum(nil)), torn, nil
}

// AddDir writes a directory entry.
func (w *Writer) AddDir(path string, mode fs.FileMode, mtime time.Time) error {
	hdr := &tar.Header{
		Typeflag: tar.TypeDir,
		Name:     path,
		Mode:     int64(mode & 0o777),
		ModTime:  mtime,
		Format:   tar.FormatPAX,
	}
	return w.tw.WriteHeader(hdr)
}

// AddSymlink writes a symlink entry.
func (w *Writer) AddSymlink(path, target string, mode fs.FileMode, mtime time.Time) error {
	hdr := &tar.Header{
		Typeflag: tar.TypeSymlink,
		Name:     path,
		Linkname: target,
		Mode:     int64(mode & 0o777),
		ModTime:  mtime,
		Format:   tar.FormatPAX,
	}
	return w.tw.WriteHeader(hdr)
}

// AddBytes writes a regular file entry from an in-memory buffer (e.g. manifest).
func (w *Writer) AddBytes(path string, data []byte, mode fs.FileMode, mtime time.Time) (sha string, err error) {
	hdr := &tar.Header{
		Typeflag: tar.TypeReg,
		Name:     path,
		Mode:     int64(mode & 0o777),
		Size:     int64(len(data)),
		ModTime:  mtime,
		Format:   tar.FormatPAX,
	}
	if err := w.tw.WriteHeader(hdr); err != nil {
		return "", err
	}
	h := sha256.New()
	if _, err := io.MultiWriter(w.tw, h).Write(data); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Close finalizes tar then gzip.
func (w *Writer) Close() error {
	if err := w.tw.Close(); err != nil {
		return fmt.Errorf("close tar: %w", err)
	}
	if err := w.gz.Close(); err != nil {
		return fmt.Errorf("close gzip: %w", err)
	}
	return nil
}

// zeroReader yields an endless stream of zero bytes.
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// ReadCloser opens a gzip'd tar stream for sequential reading.
func ReadCloser(r io.Reader) (*tar.Reader, io.Closer, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, nil, fmt.Errorf("gzip reader: %w", err)
	}
	return tar.NewReader(gz), gz, nil
}

// HomePrefix is the archive-name prefix every backup entry carries.
const HomePrefix = "home/"

// HomeRel maps an archive entry name ("home/…") to its home-relative path,
// rejecting absolute names, traversal components and entries that do not
// live under the home prefix. The bare "home" root entry maps to ".".
func HomeRel(name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("empty entry name")
	}
	if strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("absolute entry name %q", name)
	}
	for _, part := range strings.Split(filepath.ToSlash(name), "/") {
		if part == ".." {
			return "", fmt.Errorf("path traversal in entry %q", name)
		}
	}
	clean := filepath.ToSlash(filepath.Clean("/" + name))
	clean = strings.TrimPrefix(clean, "/")
	if clean == "home" {
		return ".", nil
	}
	if !strings.HasPrefix(clean, HomePrefix) {
		return "", fmt.Errorf("entry %q: нет префикса %s", name, HomePrefix)
	}
	return strings.TrimPrefix(clean, HomePrefix), nil
}

// SafeJoin resolves a home-relative entry name (e.g. ".local/…") under
// destHome, rejecting traversal, absolute names and escapes.
func SafeJoin(destHome, name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("empty entry name")
	}
	if strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("absolute entry name %q", name)
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." {
			return "", fmt.Errorf("path traversal in entry %q", name)
		}
	}
	clean := filepath.Clean("/" + name) // forces the name relative
	rel := strings.TrimPrefix(clean, "/")
	if rel == "" || rel == "." {
		return "", fmt.Errorf("empty entry name")
	}
	full := filepath.Join(destHome, rel)
	// The cleaned join must stay under destHome.
	sep := string(os.PathSeparator)
	if full != filepath.Clean(destHome) && !strings.HasPrefix(full, filepath.Clean(destHome)+sep) {
		return "", fmt.Errorf("entry %q escapes destination", name)
	}
	return full, nil
}

// MkdirAllSafe creates parent directories of full, verifying that no existing
// path component below root is a symlink (symlink-parent zip-slip protection).
// Root and its own parents are OS-managed and may legitimately be symlinks
// (macOS /var -> /private/var), so they are neither inspected nor rejected.
func MkdirAllSafe(root, full string) error {
	if err := os.MkdirAll(root, 0o755); err != nil {
		return fmt.Errorf("mkdir root %s: %w", root, err)
	}
	dest := filepath.Dir(full)
	rel, err := filepath.Rel(root, dest)
	if err != nil {
		return fmt.Errorf("rel %s to %s: %w", dest, root, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return fmt.Errorf("%s is outside destination root %s", full, root)
	}
	cur := root
	for _, p := range strings.Split(rel, string(os.PathSeparator)) {
		if p == "" || p == "." {
			continue
		}
		cur = filepath.Join(cur, p)
		fi, err := os.Lstat(cur)
		if os.IsNotExist(err) {
			if err := os.Mkdir(cur, 0o755); err != nil {
				return fmt.Errorf("mkdir %s: %w", cur, err)
			}
			continue
		}
		if err != nil {
			return fmt.Errorf("lstat %s: %w", cur, err)
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink in parent path: %s", cur)
		}
	}
	return nil
}

// CreateFileSafe creates full for writing, refusing symlinks on the final
// component and in parents below root.
func CreateFileSafe(root, full string, mode fs.FileMode) (*os.File, error) {
	if err := MkdirAllSafe(root, full); err != nil {
		return nil, err
	}
	fi, err := os.Lstat(full)
	if err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("refusing to overwrite symlink %s", full)
	}
	f, err := os.OpenFile(full, os.O_CREATE|os.O_WRONLY|os.O_TRUNC|os.O_EXCL, mode&0o777)
	if err != nil && os.IsExist(err) {
		// Replacing an existing regular file is allowed on restore.
		f, err = os.OpenFile(full, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode&0o777)
	}
	if err != nil {
		return nil, fmt.Errorf("create %s: %w", full, err)
	}
	return f, nil
}

// HashFile computes the sha256 of a file (used for verify).
func HashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.CopyBuffer(h, f, make([]byte, BufSize))
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// HashReader computes sha256 while draining r.
func HashReader(r io.Reader, buf []byte) (string, int64, error) {
	h := sha256.New()
	n, err := io.CopyBuffer(h, r, buf)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// PartialFile writes to name.partial and promotes atomically on Commit.
type PartialFile struct {
	f     *os.File
	final string
	done  bool
}

// CreatePartial opens final+".partial" for writing.
func CreatePartial(final string) (*PartialFile, error) {
	f, err := os.Create(final + ".partial")
	if err != nil {
		return nil, fmt.Errorf("create partial %s: %w", final, err)
	}
	return &PartialFile{f: f, final: final}, nil
}

func (p *PartialFile) Write(b []byte) (int, error) { return p.f.Write(b) }

// Commit fsyncs and renames the partial file to its final name.
func (p *PartialFile) Commit() error {
	if p.done {
		return fmt.Errorf("already committed")
	}
	if err := p.f.Sync(); err != nil {
		return fmt.Errorf("fsync: %w", err)
	}
	if err := p.f.Close(); err != nil {
		return fmt.Errorf("close: %w", err)
	}
	if err := os.Rename(p.final+".partial", p.final); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	p.done = true
	return nil
}

// Abort closes and removes the partial file.
func (p *PartialFile) Abort() {
	if p.done {
		return
	}
	p.f.Close()
	os.Remove(p.final + ".partial")
}
