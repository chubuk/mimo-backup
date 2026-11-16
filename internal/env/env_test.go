package env

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDiscover(t *testing.T) {
	r := Discover("/home/chubuk")
	if r.Data != "/home/chubuk/.local/share/mimocode" {
		t.Fatalf("Data = %s", r.Data)
	}
	if r.Install != "/home/chubuk/.mimocode" {
		t.Fatalf("Install = %s", r.Install)
	}
	if r.Projects != "/home/chubuk/projects" {
		t.Fatalf("Projects = %s", r.Projects)
	}
	if r.MimoBinary() != "/home/chubuk/.mimocode/bin/mimo" {
		t.Fatalf("MimoBinary = %s", r.MimoBinary())
	}
}

func TestQuoteSQLLiteral(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"/tmp/plain.db", "'/tmp/plain.db'", false},
		{"/media/My USB's Disk/x.db", "'/media/My USB''s Disk/x.db'", false},
		{"/tmp/evil; DROP", "", true},
		{"/tmp/with\nnewline", "", true},
	}
	for _, tt := range tests {
		got, err := QuoteSQLLiteral(tt.in)
		if (err != nil) != tt.wantErr {
			t.Fatalf("QuoteSQLLiteral(%q) err=%v", tt.in, err)
		}
		if !tt.wantErr && got != tt.want {
			t.Fatalf("got %q want %q", got, tt.want)
		}
	}
}

func TestFindAndStopProcesses(t *testing.T) {
	// Spawn a copy of /bin/sleep named "mimo"; it must be detected and stoppable.
	dir := t.TempDir()
	mimoPath := filepath.Join(dir, "mimo")
	src, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("sleep not available")
	}
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mimoPath, data, 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(mimoPath, "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()

	deadline := time.Now().Add(2 * time.Second)
	var found []int
	for time.Now().Before(deadline) {
		found = FindMimoProcesses(nil)
		for _, pid := range found {
			if pid == cmd.Process.Pid {
				goto detected
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("spawned mimo process not detected")
detected:

	// Stop ONLY the process we spawned — never foreign mimo processes.
	alive := StopProcesses([]int{cmd.Process.Pid}, 3000)
	if len(alive) != 0 {
		t.Fatalf("process still alive after stop: %v", alive)
	}
}

func TestFindMimoProcessesIgnoresGiven(t *testing.T) {
	dir := t.TempDir()
	src, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("sleep not available")
	}
	data, _ := os.ReadFile(src)
	mimoPath := filepath.Join(dir, "mimo")
	os.WriteFile(mimoPath, data, 0o755)
	cmd := exec.Command(mimoPath, "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	time.Sleep(200 * time.Millisecond)

	found := FindMimoProcesses(map[int]bool{cmd.Process.Pid: true})
	for _, pid := range found {
		if pid == cmd.Process.Pid {
			t.Fatalf("ignored pid still reported")
		}
	}
}

func TestFreeBytes(t *testing.T) {
	n, err := FreeBytes(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatalf("free bytes = 0")
	}
}

func TestSnapshotDBRejectsBadPath(t *testing.T) {
	home := t.TempDir()
	mimoDir := filepath.Join(home, ".mimocode", "bin")
	if err := os.MkdirAll(mimoDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mimoDir, "mimo"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	err := SnapshotDB(home, "/tmp/has;semicolon")
	if err == nil || !strings.Contains(err.Error(), "illegal character") {
		t.Fatalf("err = %v", err)
	}
}
