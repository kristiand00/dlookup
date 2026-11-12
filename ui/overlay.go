package ui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

const sgrReset = "\x1b[0m"

// isSGR reports whether seq is a CSI ... m (Select Graphic Rendition) sequence.
func isSGR(seq string) bool {
	return len(seq) >= 3 && seq[0] == '\x1b' && seq[1] == '[' && seq[len(seq)-1] == 'm'
}

func isSGRReset(seq string) bool { return seq == "\x1b[0m" || seq == "\x1b[m" }

// isZoneMarker reports whether seq is a bubblezone marker (ESC [ digits z).
func isZoneMarker(seq string) bool {
	if len(seq) < 4 || seq[0] != '\x1b' || seq[1] != '[' || seq[len(seq)-1] != 'z' {
		return false
	}
	for _, c := range seq[2 : len(seq)-1] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// cutLine splits an ANSI-styled line at display columns x and x+w.
//
//   - left:  everything visible in [0,x) plus escape sequences seen there
//     (padded with spaces if the line is shorter than x).
//   - mid:   the PLAIN text (no escapes) of cells [x,x+w), exactly w cells wide.
//   - right: a prefix that restores the SGR state active at column x+w, any
//     zone markers that were hidden in [x,x+w) (so bubblezone markers stay
//     paired), followed by the rest of the line verbatim.
//
// Graphemes straddling a cut are replaced by spaces.
func cutLine(line string, x, w int) (left, mid, right string) {
	var lb, mb, rb strings.Builder
	var sgr []string     // SGR sequences active (since the last reset)
	var markers []string // zone markers hidden in the middle
	col := 0
	end := x + w
	var state byte
	inRight := false
	startRight := func() {
		inRight = true
		rb.WriteString(sgrReset)
		for _, s := range sgr {
			rb.WriteString(s)
		}
		for _, m := range markers {
			rb.WriteString(m)
		}
	}
	i := 0
	for i < len(line) {
		if inRight {
			rb.WriteString(line[i:])
			break
		}
		seq, width, n, ns := ansi.DecodeSequence(line[i:], state, nil)
		state = ns
		if n <= 0 {
			n = 1
			seq = line[i : i+1]
		}
		i += n
		if width == 0 {
			// Escape / control sequence (or zero-width cluster).
			if seq == "\n" || seq == "\r" {
				continue
			}
			isEsc := len(seq) > 0 && seq[0] == '\x1b'
			if isEsc && isSGR(seq) {
				if isSGRReset(seq) {
					sgr = sgr[:0]
				} else {
					sgr = append(sgr, seq)
				}
			}
			switch {
			case col <= x:
				// Zero-width at or before the left cut (e.g. a zone end
				// marker right before the overlay) stays on the left.
				lb.WriteString(seq)
			case col < end:
				if isEsc && isZoneMarker(seq) {
					markers = append(markers, seq)
				}
			default:
				// col >= end: begin right part
				startRight()
				rb.WriteString(seq)
			}
			continue
		}
		// Printable grapheme occupying [col, col+width).
		c0, c1 := col, col+width
		col = c1
		if c0 >= end {
			startRight()
			rb.WriteString(seq)
			continue
		}
		if c1 <= x {
			lb.WriteString(seq)
			continue
		}
		// Overlaps [x, end) at least partially.
		if c0 < x {
			lb.WriteString(strings.Repeat(" ", x-c0))
		}
		if c0 >= x && c1 <= end {
			mb.WriteString(seq)
		} else {
			lo, hi := max(c0, x), min(c1, end)
			mb.WriteString(strings.Repeat(" ", hi-lo))
		}
		if c1 > end {
			startRight()
			rb.WriteString(strings.Repeat(" ", c1-end))
		}
	}
	// Line ended before reaching the cuts: pad.
	if col < x {
		lb.WriteString(strings.Repeat(" ", x-col))
		col = x
	}
	if mw := ansi.StringWidth(mb.String()); mw < w {
		mb.WriteString(strings.Repeat(" ", w-mw))
	}
	if !inRight && len(markers) > 0 {
		for _, m := range markers {
			rb.WriteString(m)
		}
	}
	return lb.String(), mb.String(), rb.String()
}

func maxWidth(lines []string) int {
	w := 0
	for _, l := range lines {
		w = max(w, ansi.StringWidth(l))
	}
	return w
}

// placeLine replaces cells [x, x+width(fg)) of line with fg.
func placeLine(line, fg string, x int) string {
	w := ansi.StringWidth(fg)
	if w == 0 {
		return line
	}
	left, _, right := cutLine(line, x, w)
	return left + sgrReset + fg + sgrReset + right
}

// Overlay draws fg on top of bg with fg's top-left corner at cell (x, y).
// It is ANSI-aware: bg styles are restored after the overlaid segment and
// escape sequences are never split. fg is clipped to bg's bounds (rows beyond
// bg's last line and columns beyond bg's widest line are dropped; negative
// x/y clip fg's top/left).
func Overlay(bg, fg string, x, y int) string {
	if fg == "" {
		return bg
	}
	bgLines := strings.Split(bg, "\n")
	fgLines := strings.Split(fg, "\n")
	bgW := maxWidth(bgLines)
	for i, fl := range fgLines {
		row := y + i
		if row < 0 || row >= len(bgLines) {
			continue
		}
		fx := x
		if fx < 0 {
			fl = ansi.TruncateLeft(fl, -fx, "")
			fx = 0
		}
		if fx >= bgW {
			continue
		}
		if ansi.StringWidth(fl) > bgW-fx {
			fl = ansi.Truncate(fl, bgW-fx, "")
		}
		bgLines[row] = placeLine(bgLines[row], fl, fx)
	}
	return strings.Join(bgLines, "\n")
}

// OverlayCenter centers fg inside a width×height area and overlays it on bg.
// bg is padded with empty lines up to height if it is shorter.
func OverlayCenter(bg, fg string, width, height int) string {
	fgLines := strings.Split(fg, "\n")
	fw, fh := maxWidth(fgLines), len(fgLines)
	x := max(0, (width-fw)/2)
	y := max(0, (height-fh)/2)
	bgLines := strings.Split(bg, "\n")
	for len(bgLines) < height {
		bgLines = append(bgLines, "")
	}
	if maxWidth(bgLines) < width && len(bgLines) > 0 {
		// Make sure the area is wide enough so fg isn't clipped.
		l := bgLines[0]
		bgLines[0] = l + strings.Repeat(" ", width-ansi.StringWidth(l))
	}
	return Overlay(strings.Join(bgLines, "\n"), fg, x, y)
}

// CenterPos returns the top-left position that centers fg in width×height.
func CenterPos(fg string, width, height int) (x, y int) {
	fgLines := strings.Split(fg, "\n")
	return max(0, (width-maxWidth(fgLines))/2), max(0, (height-len(fgLines))/2)
}

// OverlayShadow is Overlay plus an MC-style drop shadow: two cells to the
// right and one row below fg, which re-draws the covered background text in
// the active theme's shadow style.
func OverlayShadow(bg, fg string, x, y int) string {
	return OverlayShadowStyle(bg, fg, x, y, ActiveTheme().Shadow)
}

// OverlayShadowStyle is OverlayShadow with a custom shadow style.
func OverlayShadowStyle(bg, fg string, x, y int, shadow lipgloss.Style) string {
	if fg == "" {
		return bg
	}
	fgLines := strings.Split(fg, "\n")
	fw, fh := maxWidth(fgLines), len(fgLines)
	bgLines := strings.Split(bg, "\n")
	bgW := maxWidth(bgLines)
	shade := func(row, sx, sw int) {
		if row < 0 || row >= len(bgLines) || sx >= bgW {
			return
		}
		if sx < 0 {
			sw += sx
			sx = 0
		}
		sw = min(sw, bgW-sx)
		if sw <= 0 {
			return
		}
		left, mid, right := cutLine(bgLines[row], sx, sw)
		bgLines[row] = left + sgrReset + shadow.Render(mid) + sgrReset + right
	}
	for r := 1; r <= fh; r++ {
		shade(y+r, x+fw, 2)
	}
	shade(y+fh, x+2, fw-2)
	return Overlay(strings.Join(bgLines, "\n"), fg, x, y)
}
