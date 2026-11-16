package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/chubuk/mimo-backup/internal/archive"
	"github.com/chubuk/mimo-backup/internal/restore"
	"github.com/chubuk/mimo-backup/internal/secbox"
)

// secretsPack tars the given paths (relative to cwd) into a secrets container.
func secretsPack(out, passphrase string, paths []string, log *slog.Logger) error {
	var payload bytes.Buffer
	w, err := archive.NewWriter(&payload, 6)
	if err != nil {
		return err
	}
	for _, p := range paths {
		fi, err := os.Stat(p)
		if err != nil {
			return err
		}
		if fi.IsDir() {
			err := filepath.Walk(p, func(path string, fi os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if fi.IsDir() || !fi.Mode().IsRegular() {
					return nil
				}
				f, err := os.Open(path)
				if err != nil {
					return err
				}
				defer f.Close()
				_, _, err = w.AddFile(filepath.ToSlash(path), f, fi.Size(), 0o600, fi.ModTime())
				return err
			})
			if err != nil {
				return err
			}
			continue
		}
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		_, _, err = w.AddFile(filepath.ToSlash(p), f, fi.Size(), 0o600, fi.ModTime())
		f.Close()
		if err != nil {
			return err
		}
	}
	if err := w.Close(); err != nil {
		return err
	}

	var artifact bytes.Buffer
	if passphrase == "" {
		artifact = payload
	} else {
		if _, err := secbox.Seal([]byte(passphrase), payload.Bytes(), secbox.DefaultParams(), &artifact); err != nil {
			return err
		}
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
	log.Info("секреты упакованы", "out", out, "bytes", artifact.Len(), "encrypted", passphrase != "")
	return nil
}

// secretsUnpack decrypts (if needed) and extracts a secrets container into out.
func secretsUnpack(src, out, passphrase string, force bool) error {
	raw, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	var payload []byte
	if strings.HasSuffix(src, ".mimosec") {
		if _, err := secbox.ParamsOf(raw); err != nil {
			return fmt.Errorf("%w: %v", restore.ErrPass, err)
		}
		payload, err = secbox.Open([]byte(passphrase), raw)
		if err != nil {
			return fmt.Errorf("%w: %v", restore.ErrPass, err)
		}
	} else {
		payload = raw
	}

	tr, closer, err := archive.ReadCloser(bytes.NewReader(payload))
	if err != nil {
		return err
	}
	defer closer.Close()

	if fi, err := os.Stat(out); err == nil && fi.IsDir() {
		ents, _ := os.ReadDir(out)
		if len(ents) > 0 && !force {
			return fmt.Errorf("%s не пуст (use --force)", out)
		}
	}
	if err := os.MkdirAll(out, 0o700); err != nil {
		return err
	}

	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if hdr.Typeflag != 0x30 { // tar.TypeReg
			continue
		}
		full, err := archive.SafeJoin(out, hdr.Name)
		if err != nil {
			return fmt.Errorf("secrets: %v", err)
		}
		if err := archive.MkdirAllSafe(full); err != nil {
			return err
		}
		f, err := archive.CreateFileSafe(full, 0o600)
		if err != nil {
			return err
		}
		if _, err := io.Copy(f, tr); err != nil {
			f.Close()
			return err
		}
		f.Close()
	}
	return nil
}
