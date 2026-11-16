// Progress reporting for long operations: an interactive single-line bar
// (percent, bytes, rate, ETA) on TTY, periodic log lines otherwise.
package ui

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// Bar renders progress for one phase ("Сжатие", "Восстановление", "Проверка").
// On a TTY it draws a throttled single line via \r; otherwise it emits periodic
// slog lines. It is safe for use with io.MultiWriter via Write.
type Bar struct {
	out        io.Writer
	fd         int // terminal fd for width queries; -1 when not a terminal
	log        *slog.Logger
	label      string
	total      int64 // bytes to write (uncompressed), adjustable
	totalFiles int
	done       int64
	files      int
	start      time.Time
	lastDraw   time.Time
	lastBytes  int64
	lastFiles  int
	rate       float64 // EWMA bytes/sec
	now        func() time.Time
	tty        bool
	drawn      bool
	finished   bool
	quiet      bool // no output at all (e.g. --no-progress with no fallback wanted)
}

const (
	ewmaAlpha     = 0.15
	minDrawEvery  = 100 * time.Millisecond
	logEveryFiles = 2000
	logEveryBytes = 512 << 20
	logEveryDur   = 15 * time.Second
	etaWarmup     = 2 * time.Second
)

// NewBar creates a progress bar writing to out (typically os.Stderr).
// tty is auto-detected from out; when not a terminal, periodic log lines are
// used instead. Pass quiet=true to silence output entirely (--no-progress).
func NewBar(out *os.File, log *slog.Logger, label string, totalBytes int64, totalFiles int) *Bar {
	b := &Bar{
		out:        out,
		fd:         -1,
		log:        log,
		label:      label,
		total:      totalBytes,
		totalFiles: totalFiles,
		start:      time.Now(),
		lastDraw:   time.Now(),
		now:        time.Now,
	}
	if out != nil {
		if _, isTTY, _ := termiosGet(int(out.Fd())); isTTY {
			b.tty = true
			b.fd = int(out.Fd())
		}
	}
	return b
}

// SetQuiet silences all output (used for --no-progress/--quiet).
func (b *Bar) SetQuiet() { b.quiet = true }

// Add records n written bytes and maybe redraws.
func (b *Bar) Add(n int64) {
	b.done += n
	b.maybeDraw()
}

// NextFile increments the processed-file counter.
func (b *Bar) NextFile() {
	b.files++
	b.maybeDraw()
}

// AdjustTotal corrects the total byte count on the fly (e.g. redacted sizes).
func (b *Bar) AdjustTotal(delta int64) {
	b.total += delta
}

// Write implements io.Writer so Bar can sit in an io.MultiWriter.
// It counts bytes and always reports a full write.
func (b *Bar) Write(p []byte) (int, error) {
	b.done += int64(len(p))
	b.maybeDraw()
	return len(p), nil
}

// Log prints a message without corrupting the drawn line: the bar line is
// erased, the message printed, and the bar redrawn. After Finish/Abort it is
// a no-op (use slog directly then).
func (b *Bar) Log(msg string) {
	if b.quiet || b.finished {
		return
	}
	b.erase()
	if b.log != nil {
		b.log.Info(msg)
	} else {
		fmt.Fprintln(b.out, msg)
	}
	if b.tty {
		b.draw(true)
	}
}

// Suspend runs fn with the bar line erased, then redraws.
func (b *Bar) Suspend(fn func()) {
	if b.tty && b.drawn {
		b.erase()
	}
	fn()
	if b.tty && !b.finished {
		b.draw(true)
	}
}

// Finish draws the final 100% state and ends the line.
func (b *Bar) Finish() {
	if b.finished {
		return
	}
	if b.quiet {
		b.finished = true
		return
	}
	if b.tty {
		b.done = b.total
		if b.total == 0 {
			b.done, b.total = 0, 0
		}
		// Final draw bypasses the finished-guard via ordering.
		term := b.termWidth()
		fmt.Fprintf(b.out, "\r%s\x1b[K", b.compose(term))
		b.drawn = false
		fmt.Fprintln(b.out)
	} else {
		b.logf("готово: %s, %d файлов", humanBytes(b.done), b.files)
	}
	b.finished = true
}

// Abort erases the bar line without a trailing newline (errors, Ctrl-C).
func (b *Bar) Abort() {
	if b.finished {
		return
	}
	b.finished = true
	if b.tty && b.drawn {
		b.erase()
	}
}

// HandleSignals erases the bar on SIGINT/SIGTERM and exits cleanly.
func HandleSignals(b *Bar) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-ch
		b.Abort()
		os.Exit(130)
	}()
}

// ---------------------------------------------------------------------------

func (b *Bar) maybeDraw() {
	if b.quiet || b.finished {
		return
	}
	now := b.now()
	if b.tty {
		if now.Sub(b.lastDraw) < minDrawEvery {
			return
		}
		b.updateRate(now)
		b.lastDraw = now
		b.draw(false)
		return
	}
	// Non-TTY: periodic log lines.
	if b.files-b.lastFiles >= logEveryFiles ||
		b.done-b.lastBytes >= logEveryBytes ||
		now.Sub(b.lastDraw) >= logEveryDur {
		b.lastDraw = now
		b.lastFiles = b.files
		b.lastBytes = b.done
		b.logf("%s: %.0f%%, %s, %d файлов", b.label, b.percent(), humanBytes(b.done), b.files)
	}
}

func (b *Bar) updateRate(now time.Time) {
	elapsed := now.Sub(b.lastDraw)
	if elapsed <= 0 {
		return
	}
	inst := float64(b.done-b.lastBytes) / elapsed.Seconds()
	if b.rate == 0 {
		b.rate = inst
	} else {
		b.rate = ewmaAlpha*inst + (1-ewmaAlpha)*b.rate
	}
	b.lastBytes = b.done
}

func (b *Bar) percent() float64 {
	switch {
	case b.total > 0:
		p := float64(b.done) / float64(b.total) * 100
		if p > 100 {
			return 100
		}
		return p
	case b.totalFiles > 0:
		p := float64(b.files) / float64(b.totalFiles) * 100
		if p > 100 {
			return 100
		}
		return p
	default:
		return 100
	}
}

func (b *Bar) eta() string {
	now := b.now()
	if now.Sub(b.start) < etaWarmup || b.rate <= 0 {
		return "~—"
	}
	if b.total <= 0 {
		return "~—"
	}
	remain := b.total - b.done
	if remain <= 0 {
		return "~0:00"
	}
	d := time.Duration(float64(remain)/b.rate) * time.Second
	return "~" + formatETA(d)
}

func (b *Bar) draw(force bool) {
	_ = force
	if b.finished {
		return
	}
	term := b.termWidth()
	line := b.compose(term)
	// Pad with erase-to-EOL so shorter lines clear longer predecessors.
	fmt.Fprintf(b.out, "\r%s\x1b[K", line)
	b.drawn = true
}

// compose builds the progress line, truncating optional fields to fit width.
func (b *Bar) compose(width int) string {
	pct := fmt.Sprintf("%.0f%%", b.percent())
	// Optional blocks, in priority order (lowest first — dropped first).
	optional := []string{
		fmt.Sprintf("%d/%d файлов", b.files, b.totalFiles),
		b.rateString(),
		b.eta(),
	}
	core := func(extra []string) string {
		parts := append([]string{}, extra...)
		if b.total > 0 {
			parts = append(parts, fmt.Sprintf("%s/%s", humanBytes(b.done), humanBytes(b.total)))
		} else {
			parts = append(parts, humanBytes(b.done))
		}
		return fmt.Sprintf("%s [%s] %s %s",
			b.label, b.barGlyphs(width, len(strings.Join(parts, "  "))), pct,
			strings.Join(parts, "  "))
	}

	// Drop optional fields until the line fits.
	for i := 0; i <= len(optional); i++ {
		line := core(optional[i:])
		if len([]rune(line)) <= width-1 {
			return line
		}
	}
	// Last resort: label + percent only.
	return fmt.Sprintf("%s %s", b.label, pct)
}

// barGlyphs returns the bar string sized to the remaining terminal width.
func (b *Bar) barGlyphs(width, restLen int) string {
	const maxGlyphs = 24
	glyphs := maxGlyphs
	if avail := width - restLen - len(b.label) - len(b.label) - 20; avail < glyphs {
		glyphs = avail
	}
	if glyphs < 4 {
		glyphs = 4
	}
	filled := int(b.percent() / 100 * float64(glyphs))
	if filled > glyphs {
		filled = glyphs
	}
	return strings.Repeat("#", filled) + strings.Repeat("-", glyphs-filled)
}

func (b *Bar) rateString() string {
	if b.rate <= 0 {
		return ""
	}
	return humanBytes(int64(b.rate)) + "/с"
}

func (b *Bar) erase() {
	if b.tty && b.drawn {
		fmt.Fprint(b.out, "\r\x1b[K")
		b.drawn = false
	}
}

func (b *Bar) logf(format string, args ...any) {
	if b.log != nil {
		b.log.Info(fmt.Sprintf(format, args...))
		return
	}
	fmt.Fprintf(b.out, format+"\n", args...)
}

// termWidth queries the terminal width via TIOCGWINSZ; fallback 80.
func (b *Bar) termWidth() int {
	if b.fd < 0 {
		return 80
	}
	var ws struct {
		Row, Col, X, Y uint16
	}
	_, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, uintptr(b.fd), syscall.TIOCGWINSZ,
		uintptr(unsafe.Pointer(&ws)), 0, 0, 0)
	if errno != 0 || ws.Col == 0 {
		return 80
	}
	return int(ws.Col)
}

// ---------------------------------------------------------------------------

// humanBytes formats n as a human-readable byte count (binary units, dot decimal).
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d Б", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	units := []string{"КиБ", "МиБ", "ГиБ", "ТиБ"}
	return fmt.Sprintf("%.1f %s", float64(n)/float64(div), units[exp])
}

// formatETA formats a duration as M:SS (or H:MM:SS for >= 1 hour).
func formatETA(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	s := int(d.Seconds())
	h := s / 3600
	m := s % 3600 / 60
	sec := s % 60
	if h > 0 {
		return fmt.Sprintf("%d:%02d:%02d", h, m, sec)
	}
	return fmt.Sprintf("%d:%02d", m, sec)
}
