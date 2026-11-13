package ui

import (
	"strings"
	"unicode"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

// ParseHotkey strips the '&' marker from a label like "&File" and returns the
// display text, the byte index of the hotkey rune in it (-1 if none) and the
// lower-cased hotkey rune (0 if none). "&&" renders a literal '&'.
func ParseHotkey(label string) (text string, idx int, hot rune) {
	idx = -1
	var b strings.Builder
	rs := []rune(label)
	for i := 0; i < len(rs); i++ {
		if rs[i] == '&' && i+1 < len(rs) {
			if rs[i+1] == '&' {
				b.WriteRune('&')
				i++
				continue
			}
			if idx < 0 {
				idx = b.Len()
				hot = unicode.ToLower(rs[i+1])
			}
			continue
		}
		b.WriteRune(rs[i])
	}
	return b.String(), idx, hot
}

// renderHot renders text with the rune at byte index idx in hotStyle.
func renderHot(text string, idx int, base, hotStyle lipgloss.Style) string {
	if idx < 0 || idx >= len(text) {
		return base.Render(text)
	}
	r := []rune(text[idx:])[0]
	n := len(string(r))
	out := ""
	if idx > 0 {
		out += base.Render(text[:idx])
	}
	out += hotStyle.Render(text[idx : idx+n])
	if idx+n < len(text) {
		out += base.Render(text[idx+n:])
	}
	return out
}

// truncPlain truncates a plain string to w cells, appending "…" if cut.
func truncPlain(s string, w int) string {
	if w <= 0 {
		return ""
	}
	if ansi.StringWidth(s) <= w {
		return s
	}
	return ansi.Truncate(s, w, "…")
}

// padRight pads a (possibly styled) string with spaces rendered in style up to
// w cells, truncating first if it is wider.
func padRight(s string, w int, style lipgloss.Style) string {
	sw := ansi.StringWidth(s)
	if sw > w {
		s = ansi.Truncate(s, w, "")
		sw = ansi.StringWidth(s)
	}
	if sw < w {
		s += style.Render(strings.Repeat(" ", w-sw))
	}
	return s
}

// fitPlain truncates/pads a plain string to exactly w cells.
func fitPlain(s string, w int) string {
	s = truncPlain(s, w)
	if sw := ansi.StringWidth(s); sw < w {
		s += strings.Repeat(" ", w-sw)
	}
	return s
}

func clamp(v, lo, hi int) int {
	if hi < lo {
		return lo
	}
	return max(lo, min(v, hi))
}
