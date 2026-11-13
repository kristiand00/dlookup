package ui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
)

func widths(s string) []int {
	var w []int
	for _, l := range strings.Split(s, "\n") {
		w = append(w, ansi.StringWidth(l))
	}
	return w
}

// assertCleanEscapes checks that every ESC starts a complete sequence: after
// stripping escapes no ESC or CSI remnants remain.
func assertCleanEscapes(t *testing.T, s string) {
	t.Helper()
	plain := ansi.Strip(s)
	if strings.ContainsRune(plain, '\x1b') {
		t.Fatalf("broken escape in %q", s)
	}
	if strings.Contains(plain, "[3") || strings.Contains(plain, "[0m") {
		t.Fatalf("escape remnants in plain text %q", plain)
	}
}

func TestOverlayPlain(t *testing.T) {
	bg := "aaaaa\nbbbbb\nccccc"
	out := Overlay(bg, "XY\nZW", 1, 1)
	want := "aaaaa\nbXYbb\ncZWcc"
	if got := ansi.Strip(out); got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestOverlayANSIBackground(t *testing.T) {
	red := "\x1b[31m"
	bold := "\x1b[1m"
	bg := red + "hello " + bold + "world" + sgrReset + " tail"
	fg := "\x1b[44mXYZ\x1b[0m"
	out := Overlay(bg, fg, 4, 0)
	if got, want := ansi.Strip(out), "hellXYZorld tail"; got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	if ansi.StringWidth(out) != ansi.StringWidth(bg) {
		t.Fatalf("width changed: %d vs %d", ansi.StringWidth(out), ansi.StringWidth(bg))
	}
	assertCleanEscapes(t, out)
	// After the overlay the red+bold state must be re-established before "orld".
	i := strings.Index(out, "XYZ")
	rest := out[i:]
	j := strings.Index(rest, "orld")
	seg := rest[:j]
	if !strings.Contains(seg, sgrReset) || !strings.Contains(seg, red) || !strings.Contains(seg, bold) {
		t.Fatalf("style not restored before right part: %q", seg)
	}
	// The fg must start from a reset so bg style doesn't bleed into it.
	if !strings.Contains(out[:strings.Index(out, "\x1b[44m")], sgrReset) {
		t.Fatalf("no reset before fg: %q", out)
	}
}

func TestOverlayClipping(t *testing.T) {
	bg := "12345\n12345"
	// Right edge: clipped to bg width.
	out := Overlay(bg, "ABCDEF", 3, 0)
	if got := strings.Split(ansi.Strip(out), "\n")[0]; got != "123AB" {
		t.Fatalf("right clip: %q", got)
	}
	// Bottom edge: rows past bg dropped.
	out = Overlay(bg, "A\nB\nC", 0, 1)
	if got := ansi.Strip(out); got != "12345\nA2345" {
		t.Fatalf("bottom clip: %q", got)
	}
	// Negative x/y clip fg's left/top.
	out = Overlay(bg, "AB\nCD", -1, -1)
	if got := ansi.Strip(out); got != "D2345\n12345" {
		t.Fatalf("negative clip: %q", got)
	}
	// Short bg line is padded.
	out = Overlay("ab\n12345", "X", 4, 0)
	if got := strings.Split(ansi.Strip(out), "\n")[0]; got != "ab  X" {
		t.Fatalf("pad: %q", got)
	}
}

func TestOverlayWideChars(t *testing.T) {
	bg := "日本語テキスト" // 14 cells
	out := Overlay(bg, "X", 1, 0)
	if got := ansi.Strip(out); got != " X本語テキスト" {
		t.Fatalf("straddle left: %q", got)
	}
	out = Overlay(bg, "XYZ", 2, 0) // covers 本 and half of 語
	if got := ansi.Strip(out); got != "日XYZ テキスト" {
		t.Fatalf("straddle right: %q", got)
	}
	if ansi.StringWidth(out) != 14 {
		t.Fatalf("width %d", ansi.StringWidth(out))
	}
	// Wide fg over ascii bg.
	out = Overlay("abcdef", "€漢", 1, 0)
	if got := ansi.Strip(out); got != "a€漢ef" {
		t.Fatalf("wide fg: %q", got)
	}
}

func TestOverlayKeepsZonesPaired(t *testing.T) {
	bg := Mark("ov-a", "AAAA") + " " + Mark("ov-b", "BBBB") + " " + Mark("ov-c", "CCCC")
	// Fully hide ov-b, partially hide ov-c.
	out := Overlay(bg, "########", 4, 0)
	scan(t, out)
	if x, _, w, _, ok := ZonePos("ov-a"); !ok || x != 0 || w != 4 {
		t.Fatalf("ov-a: %d %d %v", x, w, ok)
	}
	if _, _, _, _, ok := ZonePos("ov-b"); ok {
		t.Fatalf("ov-b should be hidden")
	}
	if x, _, w, _, ok := ZonePos("ov-c"); !ok || x != 12 || w != 2 {
		t.Fatalf("ov-c: x=%d w=%d ok=%v", x, w, ok)
	}
}

func TestOverlayShadowAndCenter(t *testing.T) {
	bg := strings.Repeat(strings.Repeat(".", 20)+"\n", 9) + strings.Repeat(".", 20)
	fg := "+--+\n|  |\n+--+"
	out := OverlayShadow(bg, fg, 3, 2)
	for i, w := range widths(out) {
		if w != 20 {
			t.Fatalf("line %d width %d", i, w)
		}
	}
	lines := strings.Split(ansi.Strip(out), "\n")
	if lines[2][3:7] != "+--+" || lines[4][3:7] != "+--+" {
		t.Fatalf("fg misplaced:\n%s", ansi.Strip(out))
	}
	assertCleanEscapes(t, out)

	c := OverlayCenter("", "AB\nCD", 10, 5)
	cl := strings.Split(ansi.Strip(c), "\n")
	if len(cl) != 5 || !strings.HasPrefix(cl[1], "    AB") || !strings.HasPrefix(cl[2], "    CD") {
		t.Fatalf("center: %q", cl)
	}
}
