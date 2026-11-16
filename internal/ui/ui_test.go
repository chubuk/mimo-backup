package ui

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

func newTestUI(input string) (*UI, *bytes.Buffer) {
	out := &bytes.Buffer{}
	return &UI{in: bufio.NewReader(strings.NewReader(input)), out: out}, out
}

func TestAskWithDefault(t *testing.T) {
	u, _ := newTestUI("\n")
	got, err := u.Ask("куда писать", "/media/usb")
	if err != nil {
		t.Fatal(err)
	}
	if got != "/media/usb" {
		t.Fatalf("got %q", got)
	}
}

func TestAskExplicit(t *testing.T) {
	u, _ := newTestUI("/tmp/x\n")
	got, err := u.Ask("куда писать", "/media/usb")
	if err != nil {
		t.Fatal(err)
	}
	if got != "/tmp/x" {
		t.Fatalf("got %q", got)
	}
}

func TestConfirm(t *testing.T) {
	tests := []struct {
		in   string
		def  bool
		want bool
	}{
		{"\n", true, true},
		{"\n", false, false},
		{"y\n", false, true},
		{"n\n", true, false},
		{"да\n", false, true},
	}
	for _, tt := range tests {
		u, _ := newTestUI(tt.in)
		got, err := u.Confirm("вопрос", tt.def)
		if err != nil {
			t.Fatal(err)
		}
		if got != tt.want {
			t.Fatalf("Confirm(%q, %v) = %v", tt.in, tt.def, got)
		}
	}
}

func TestChoose(t *testing.T) {
	u, _ := newTestUI("2\n")
	idx, err := u.Choose("что делаем", []string{"backup", "restore"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if idx != 1 {
		t.Fatalf("idx = %d", idx)
	}

	u2, _ := newTestUI("\n")
	idx, err = u2.Choose("что делаем", []string{"backup", "restore"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if idx != 1 {
		t.Fatalf("default idx = %d", idx)
	}

	u3, _ := newTestUI("9\n")
	if _, err := u3.Choose("что делаем", []string{"backup", "restore"}, 0); err == nil {
		t.Fatalf("out-of-range accepted")
	}
}

func TestReadPasswordNotTTY(t *testing.T) {
	// strings.Reader is not a tty: ReadPassword should fall back to plain read.
	u, out := newTestUI("abc12\n")
	pw, err := u.ReadPassword("пароль")
	if err != nil {
		t.Fatal(err)
	}
	if pw != "abc12" {
		t.Fatalf("pw = %q", pw)
	}
	if !strings.Contains(out.String(), "пароль") {
		t.Fatalf("prompt not printed")
	}
}

func TestReadPasswordNewMismatchLoops(t *testing.T) {
	// First pair mismatched, second matches.
	u, _ := newTestUI("abc12\nabc13\nabc12\nabc12\n")
	pw, err := u.ReadPasswordNew()
	if err != nil {
		t.Fatal(err)
	}
	if pw != "abc12" {
		t.Fatalf("pw = %q", pw)
	}
}

func TestReadPasswordNewInvalidLoops(t *testing.T) {
	// "ab cd" invalid, then "abc12" twice.
	u, _ := newTestUI("ab cd\nabc12\nabc12\n")
	pw, err := u.ReadPasswordNew()
	if err != nil {
		t.Fatal(err)
	}
	if pw != "abc12" {
		t.Fatalf("pw = %q", pw)
	}
}
