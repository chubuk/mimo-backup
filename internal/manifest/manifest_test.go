package manifest

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestEncodeLoadRoundTrip(t *testing.T) {
	m := New()
	m.Source.Home = "/home/chubuk"
	m.Files = append(m.Files,
		FileEntry{Path: "home/a.txt", Type: "file", Size: 3, SHA256: "aa", Mode: "0644", MTime: time.Unix(0, 0).UTC()},
		FileEntry{Path: "home/link", Type: "symlink", Mode: "0777", LinkTarget: "../a.txt"},
	)
	m.Torn = append(m.Torn, "home/log/x.log")

	var buf bytes.Buffer
	if err := m.Encode(&buf); err != nil {
		t.Fatalf("Encode: %v", err)
	}
	got, err := Load(&buf)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.SchemaVersion != SchemaVersion {
		t.Fatalf("schema_version = %d", got.SchemaVersion)
	}
	if len(got.Files) != 2 || got.Files[0].Path != "home/a.txt" {
		t.Fatalf("files mismatch: %+v", got.Files)
	}
	if len(got.Torn) != 1 {
		t.Fatalf("torn mismatch: %v", got.Torn)
	}
	if len(got.RestoreSkipDefault) == 0 {
		t.Fatalf("restore_skip_default empty")
	}
}

func TestLoadRejectsUnknownSchema(t *testing.T) {
	raw := `{"schema_version": 99}`
	if _, err := Load(strings.NewReader(raw)); err == nil {
		t.Fatalf("unknown schema_version accepted")
	}
}

func TestLargeManifestStreams(t *testing.T) {
	// 300k entries must encode without exceeding a sane buffer (Encoder streams).
	m := New()
	for i := 0; i < 300_000; i++ {
		m.Files = append(m.Files, FileEntry{
			Path:   "home/projects/x/node_modules/f" + strings.Repeat("0", 60) + string(rune('a'+i%26)),
			Type:   "file",
			Size:   int64(i),
			SHA256: strings.Repeat("ab", 32),
			Mode:   "0644",
			MTime:  time.Unix(0, 0).UTC(),
		})
	}
	var buf bytes.Buffer
	if err := m.Encode(&buf); err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if buf.Len() < 40<<20 {
		t.Fatalf("expected >40MB manifest, got %d", buf.Len())
	}
	got, err := Load(&buf)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got.Files) != 300_000 {
		t.Fatalf("files = %d", len(got.Files))
	}
}
