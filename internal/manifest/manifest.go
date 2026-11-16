// Package manifest defines the backup manifest schema and its build/load/verify logic.
package manifest

import (
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// SchemaVersion is the manifest format version written by this tool.
const SchemaVersion = 1

// Manifest is the authoritative inventory of a backup archive.
type Manifest struct {
	SchemaVersion      int         `json:"schema_version"`
	Tool               Tool        `json:"tool"`
	CreatedAt          time.Time   `json:"created_at"`
	Source             Source      `json:"source"`
	DB                 DB          `json:"db"`
	Secrets            Secrets     `json:"secrets"`
	ArchiveEncrypted   bool        `json:"archive_encrypted,omitempty"` // whole archive is a .mimosec container
	Totals             Totals      `json:"totals"`
	SecretPaths        []string    `json:"secret_paths"`
	RedactedPaths      []string    `json:"redacted_paths"`
	Torn               []string    `json:"torn"`
	RestoreSkipDefault []string    `json:"restore_skip_default"`
	Files              []FileEntry `json:"files"`
	ArchiveSHA256      string      `json:"archive_sha256,omitempty"` // sidecar only
	SecretsSHA256      string      `json:"secrets_sha256,omitempty"` // sidecar only
}

// Tool identifies the producing binary.
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Source describes the machine the backup was taken from.
type Source struct {
	Hostname    string `json:"hostname"`
	Username    string `json:"username"`
	Home        string `json:"home"`
	UID         int    `json:"uid"`
	MimoVersion string `json:"mimo_version"`
	GoVersion   string `json:"go_version"`
}

// DB describes the captured mimocode.db snapshot.
type DB struct {
	Method      string `json:"method"` // "vacuum-into" | "cold-copy"
	ArchivePath string `json:"archive_path"`
	Bytes       int64  `json:"bytes"`
	SHA256      string `json:"sha256"`
	WALBytes    int64  `json:"wal_bytes"`
	WALSHA256   string `json:"wal_sha256"`
	MimoRunning bool   `json:"mimo_running"`
	Note        string `json:"note"`
}

// Secrets describes the separate secrets artifact.
type Secrets struct {
	Present      bool   `json:"present"`
	Filename     string `json:"filename"`
	Encrypted    bool   `json:"encrypted"`
	SHA256       string `json:"sha256"`
	Bytes        int64  `json:"bytes"`
	KDF          string `json:"kdf"`
	Iterations   uint32 `json:"iterations,omitempty"` // legacy field, unused for argon2
	MCost        uint32 `json:"m_cost,omitempty"`
	TCost        uint32 `json:"t_cost,omitempty"`
	PCost        uint32 `json:"p_cost,omitempty"`
	PayloadBytes int64  `json:"payload_bytes"`
}

// Totals counts archived entries.
type Totals struct {
	Files    int   `json:"files"`
	Bytes    int64 `json:"bytes"`
	Dirs     int   `json:"dirs"`
	Symlinks int   `json:"symlinks"`
	Skipped  int   `json:"skipped"`
}

// FileEntry is one archived path.
type FileEntry struct {
	Path       string    `json:"path"`
	Type       string    `json:"type"` // "file" | "dir" | "symlink"
	Size       int64     `json:"size"`
	SHA256     string    `json:"sha256,omitempty"`
	Mode       string    `json:"mode"`
	MTime      time.Time `json:"mtime"`
	LinkTarget string    `json:"link_target,omitempty"`
}

// New returns an initialized manifest with fixed defaults.
func New() *Manifest {
	return &Manifest{
		SchemaVersion: SchemaVersion,
		Tool:          Tool{Name: "mimo-backup", Version: "1.1.0"},
		CreatedAt:     time.Now().UTC(),
		SecretPaths:   []string{},
		RedactedPaths: []string{},
		Torn:          []string{},
		RestoreSkipDefault: []string{
			"home/.bashrc",
			"home/.profile",
			"home/.bash_profile",
		},
		Files: []FileEntry{},
	}
}

// Encode streams the manifest as JSON to w.
func (m *Manifest) Encode(w io.Writer) error {
	enc := json.NewEncoder(w)
	if err := enc.Encode(m); err != nil {
		return fmt.Errorf("encode manifest: %w", err)
	}
	return nil
}

// Load reads a manifest from r and validates the schema version.
func Load(r io.Reader) (*Manifest, error) {
	var m Manifest
	dec := json.NewDecoder(r)
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("decode manifest: %w", err)
	}
	if m.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("unsupported manifest schema_version %d (want %d): upgrade the tool", m.SchemaVersion, SchemaVersion)
	}
	return &m, nil
}
