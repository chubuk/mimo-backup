package ui

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"
)

// newTestBar builds a TTY bar writing into a buffer, with an injected clock.
func newTestBar(t *testing.T, buf *bytes.Buffer, total int64, totalFiles int) (*Bar, *time.Time) {
	t.Helper()
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	b := &Bar{
		out:        buf,
		fd:         -1,
		label:      "Сжатие",
		total:      total,
		totalFiles: totalFiles,
		start:      now,
		lastDraw:   now,
		now:        func() time.Time { return now },
		tty:        true,
	}
	return b, &now
}

func TestHumanBytes(t *testing.T) {
	tests := []struct {
		n    int64
		want string
	}{
		{0, "0 Б"},
		{999, "999 Б"},
		{1024, "1.0 КиБ"},
		{1536, "1.5 КиБ"},
		{1 << 20, "1.0 МиБ"},
		{3 << 30, "3.0 ГиБ"},
		{5 << 40, "5.0 ТиБ"},
	}
	for _, tt := range tests {
		if got := humanBytes(tt.n); got != tt.want {
			t.Errorf("humanBytes(%d) = %q, want %q", tt.n, got, tt.want)
		}
	}
}

func TestFormatETA(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{0, "0:00"},
		{59 * time.Second, "0:59"},
		{80 * time.Second, "1:20"},
		{10 * time.Minute, "10:00"},
		{time.Hour, "1:00:00"},
		{-5 * time.Second, "0:00"},
	}
	for _, tt := range tests {
		if got := formatETA(tt.d); got != tt.want {
			t.Errorf("formatETA(%v) = %q, want %q", tt.d, got, tt.want)
		}
	}
	// Monotonicity is a numeric property: parse M:SS (or H:MM:SS) back.
	parse := func(s string) int {
		var h, m, sec int
		if n, _ := fmt.Sscanf(s, "%d:%d:%d", &h, &m, &sec); n == 3 {
			return h*3600 + m*60 + sec
		}
		fmt.Sscanf(s, "%d:%d", &m, &sec)
		return m*60 + sec
	}
	prev := 1 << 30
	for _, d := range []time.Duration{10 * time.Minute, 5 * time.Minute, 30 * time.Second, 0} {
		got := parse(formatETA(d))
		if got > prev {
			t.Errorf("formatETA not monotonic: %ds after %ds", got, prev)
		}
		prev = got
	}
}

func TestPercentClamp(t *testing.T) {
	buf := &bytes.Buffer{}
	b, _ := newTestBar(t, buf, 100, 0)
	b.Add(50)
	if p := b.percent(); p != 50 {
		t.Fatalf("percent = %v, want 50", p)
	}
	b.Add(200) // done > total
	if p := b.percent(); p != 100 {
		t.Fatalf("percent = %v, want clamped 100", p)
	}
}

func TestPercentTotalZeroFallbackToFiles(t *testing.T) {
	buf := &bytes.Buffer{}
	b, _ := newTestBar(t, buf, 0, 4)
	b.NextFile()
	b.NextFile()
	if p := b.percent(); p != 50 {
		t.Fatalf("percent = %v, want 50 (by files)", p)
	}
}

func TestTotalZeroNoFiles(t *testing.T) {
	buf := &bytes.Buffer{}
	b, now := newTestBar(t, buf, 0, 0)
	*now = now.Add(3 * time.Second)
	b.Add(10) // stray bytes with no declared total
	b.Finish()
	out := buf.String()
	if strings.Contains(out, "NaN") || strings.Contains(out, "Inf") {
		t.Fatalf("degenerate output: %q", out)
	}
}

func TestETABehavior(t *testing.T) {
	buf := &bytes.Buffer{}
	b, now := newTestBar(t, buf, 1000, 0)

	// Cold start (< 2s): ETA placeholder.
	if got := b.eta(); got != "~—" {
		t.Fatalf("eta cold = %q, want ~—", got)
	}

	// After warmup with some rate.
	*now = now.Add(3 * time.Second)
	b.Add(300) // rate ≈ 100 B/s → 700 remain ≈ 7s
	if got := b.eta(); got == "~—" {
		t.Fatalf("eta warm = %q, want a duration", got)
	}

	// rate == 0 case.
	b2, _ := newTestBar(t, &bytes.Buffer{}, 1000, 0)
	if got := b2.eta(); got != "~—" {
		t.Fatalf("eta zero-rate = %q, want ~—", got)
	}
}

func TestThrottleRedraw(t *testing.T) {
	buf := &bytes.Buffer{}
	b, now := newTestBar(t, buf, 10000, 0)
	for i := 0; i < 100; i++ {
		b.Add(10)
	}
	// Time frozen: no redraws yet except maybe none.
	draws := strings.Count(buf.String(), "\r")
	if draws > 1 {
		t.Fatalf("frozen clock drew %d times", draws)
	}
	*now = now.Add(200 * time.Millisecond)
	b.Add(10)
	if draws := strings.Count(buf.String(), "\r"); draws != 1 {
		t.Fatalf("after tick draws = %d, want 1", draws)
	}
	*now = now.Add(200 * time.Millisecond)
	b.Add(10)
	if draws := strings.Count(buf.String(), "\r"); draws != 2 {
		t.Fatalf("after 2nd tick draws = %d, want 2", draws)
	}
}

func TestWriteContract(t *testing.T) {
	buf := &bytes.Buffer{}
	b, _ := newTestBar(t, buf, 100, 0)
	n, err := b.Write([]byte("hello"))
	if n != 5 || err != nil {
		t.Fatalf("Write = (%d, %v), want (5, nil)", n, err)
	}
	if b.done != 5 {
		t.Fatalf("done = %d, want 5", b.done)
	}
}

func TestTruncateToTermWidth(t *testing.T) {
	buf := &bytes.Buffer{}
	b, now := newTestBar(t, buf, 6<<30, 328000)
	*now = now.Add(3 * time.Second)
	b.Add(3 << 30)
	b.NextFile()
	b.draw(true)
	// Simulate 80-column terminal: compose must not exceed 79 runes.
	line := b.compose(80)
	if len([]rune(line)) > 79 {
		t.Fatalf("line too wide (%d): %q", len([]rune(line)), line)
	}
	if !strings.Contains(line, "Сжатие") || !strings.Contains(line, "%") {
		t.Fatalf("mandatory fields lost: %q", line)
	}
	// Narrow terminal: still fits and keeps mandatory parts.
	line = b.compose(30)
	if len([]rune(line)) > 29 {
		t.Fatalf("narrow line too wide (%d): %q", len([]rune(line)), line)
	}
	if !strings.Contains(line, "%") {
		t.Fatalf("percent lost in narrow line: %q", line)
	}
}

func TestLogDuringBar(t *testing.T) {
	buf := &bytes.Buffer{}
	b, now := newTestBar(t, buf, 100, 0)
	var logBuf bytes.Buffer
	b.log = slog.New(slog.NewTextHandler(&logBuf, nil))

	*now = now.Add(100 * time.Millisecond)
	b.Add(50)
	b.Log("файл усечён")
	if !strings.Contains(logBuf.String(), "файл усечён") {
		t.Fatalf("log message missing: %q", logBuf.String())
	}
	// Bar must have been redrawn after the log line.
	if !b.drawn {
		t.Fatalf("bar not redrawn after Log")
	}
	// The erase sequence must precede the redraw after the message.
	out := buf.String()
	if !strings.Contains(out, "\r\x1b[K") {
		t.Fatalf("no erase sequence in output: %q", out)
	}
}

func TestAbortLeavesCleanLine(t *testing.T) {
	buf := &bytes.Buffer{}
	b, now := newTestBar(t, buf, 100, 0)
	*now = now.Add(100 * time.Millisecond)
	b.Add(50)
	b.Abort()
	out := buf.String()
	if !strings.HasSuffix(out, "\r\x1b[K") {
		t.Fatalf("abort should end with erase, got %q", out)
	}
	// After abort nothing else is written.
	before := buf.Len()
	b.Add(10)
	b.Log("x")
	if buf.Len() != before {
		t.Fatalf("output after abort: %q", buf.String()[before:])
	}
}

func TestNonTTYFallback(t *testing.T) {
	// NewBar with a non-terminal file → non-TTY mode; a pipe works.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()

	var logBuf bytes.Buffer
	b := NewBar(w, slog.New(slog.NewTextHandler(&logBuf, nil)), "Сжатие", 400<<20, 0)
	if b.tty {
		t.Fatalf("pipe detected as tty")
	}

	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	b.now = func() time.Time { return now }
	b.start = now
	b.lastDraw = now

	b.Add(100) // nothing yet (below thresholds)
	if strings.Contains(logBuf.String(), "Сжатие") {
		t.Fatalf("premature log line")
	}

	// 15-second trigger.
	now = now.Add(16 * time.Second)
	b.Add(100)
	if !strings.Contains(logBuf.String(), "Сжатие") {
		t.Fatalf("15s trigger produced no line: %q", logBuf.String())
	}
	if strings.Contains(logBuf.String(), "\r") {
		t.Fatalf("\\r leaked into non-TTY output")
	}

	b.Finish()
	if !strings.Contains(logBuf.String(), "готово") {
		t.Fatalf("no final line: %q", logBuf.String())
	}
}

func TestQuietMode(t *testing.T) {
	buf := &bytes.Buffer{}
	b, now := newTestBar(t, buf, 100, 0)
	b.SetQuiet()
	*now = now.Add(time.Second)
	b.Add(50)
	b.Log("x")
	b.Finish()
	b.Abort()
	if buf.Len() != 0 {
		t.Fatalf("quiet mode wrote %q", buf.String())
	}
}
