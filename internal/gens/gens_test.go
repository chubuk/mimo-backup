package gens

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGenerationLifecycle(t *testing.T) {
	home := t.TempDir()
	s, err := Open(home)
	if err != nil {
		t.Fatal(err)
	}
	g, err := s.NewGeneration("/media/usb/x.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	if g.Meta.Status != StatusInProgress {
		t.Fatalf("status = %s", g.Meta.Status)
	}

	j, err := g.OpenJournal()
	if err != nil {
		t.Fatal(err)
	}
	if err := j.Record(ExtractedEntry{Path: ".local/share/mimocode/mimocode.db", Type: "file", SHA256: "abc"}); err != nil {
		t.Fatal(err)
	}
	if err := j.Record(ExtractedEntry{Path: ".config/mimocode", Type: "dir", Created: true}); err != nil {
		t.Fatal(err)
	}
	j.Close()

	entries, err := g.Extracted()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].SHA256 != "abc" || !entries[1].Created {
		t.Fatalf("entries = %+v", entries)
	}

	if err := g.SetStatus(StatusApplied); err != nil {
		t.Fatal(err)
	}
	// Reload from disk: meta must persist.
	gs, err := s.Generations()
	if err != nil {
		t.Fatal(err)
	}
	if len(gs) != 1 || gs[0].Meta.Status != StatusApplied {
		t.Fatalf("reloaded = %+v", gs)
	}

	latest, err := s.Latest()
	if err != nil || latest == nil || latest.ID() != g.ID() {
		t.Fatalf("latest = %v, %v", latest, err)
	}
	// Rolled-back generations are not rollbackable.
	if err := g.SetStatus(StatusRolledBack); err != nil {
		t.Fatal(err)
	}
	latest, err = s.Latest()
	if err != nil {
		t.Fatal(err)
	}
	if latest != nil {
		t.Fatalf("latest after rollback = %v, want nil", latest)
	}
}

func TestDisplacedAndPrune(t *testing.T) {
	home := t.TempDir()
	s, err := Open(home)
	if err != nil {
		t.Fatal(err)
	}
	g1, _ := s.NewGeneration("a")
	g2, _ := s.NewGeneration("b")

	// Fake displaced data for both.
	for _, g := range []*Generation{g1, g2} {
		p := g.DisplacedPath(".config/mimocode")
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p, "x.json"), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if !g1.HasDisplaced() || !g2.HasDisplaced() {
		t.Fatal("displaced not detected")
	}

	pruned, err := s.PruneDisplaced(g2.ID())
	if err != nil {
		t.Fatal(err)
	}
	if len(pruned) != 1 || pruned[0] != g1.ID() {
		t.Fatalf("pruned = %v", pruned)
	}
	if g1.HasDisplaced() {
		t.Fatal("g1 displaced survived prune")
	}
	if !g2.HasDisplaced() {
		t.Fatal("g2 displaced must be kept")
	}
}

func TestCleanupRetention(t *testing.T) {
	home := t.TempDir()
	s, err := Open(home)
	if err != nil {
		t.Fatal(err)
	}
	var gs []*Generation
	for i := 0; i < 5; i++ {
		g, err := s.NewGeneration("src")
		if err != nil {
			t.Fatal(err)
		}
		_ = g.SetStatus(StatusApplied)
		gs = append(gs, g)
	}
	removed, _, err := s.Cleanup(2, false, false)
	if err != nil {
		t.Fatal(err)
	}
	// keep 2 newest + nothing displaced → 3 removed.
	if len(removed) != 3 {
		t.Fatalf("removed = %v", removed)
	}
	all, _ := s.Generations()
	if len(all) != 2 {
		t.Fatalf("left = %d", len(all))
	}

	// Cleanup must not touch a generation that still holds displaced data.
	g, _ := s.NewGeneration("c")
	_ = g.SetStatus(StatusApplied)
	p := g.DisplacedPath(".x")
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
	removed, _, err = s.Cleanup(1, true, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range removed {
		if id == g.ID() {
			t.Fatal("cleanup removed the displaced rollback point")
		}
	}
}

func TestMoveTreeRenameAndCopy(t *testing.T) {
	base := t.TempDir()
	src := filepath.Join(base, "src", ".config", "mimocode")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "a.json"), []byte("A"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("a.json", filepath.Join(src, "link")); err != nil {
		t.Fatal(err)
	}

	dst := filepath.Join(base, "dst", ".config", "mimocode")
	if err := MoveTree(src, dst); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Fatal("src survived move")
	}
	b, err := os.ReadFile(filepath.Join(dst, "a.json"))
	if err != nil || string(b) != "A" {
		t.Fatalf("content = %q, %v", b, err)
	}
	fi, err := os.Lstat(filepath.Join(dst, "link"))
	if err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("symlink not preserved: %v", err)
	}
}
