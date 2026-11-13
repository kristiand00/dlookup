package ui

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

// Palette holds the semantic colours of a theme. ThemeFromPalette turns it into
// the widget Theme; the app derives its own styles (result headers, diffs, the
// panel frame, ...) from the same palette.
//
// A nil colour means "terminal default" (no colour sequence is emitted).
type Palette struct {
	Name  string
	Light bool // light background theme

	// Reverse draws selection/focus/cursor/active-tab with reverse video
	// instead of colours, so they follow the terminal's own colours (system).
	Reverse bool

	// Screen. Background is painted behind the whole screen when set (see
	// PaintBackground); nil keeps the terminal background.
	Background lipgloss.TerminalColor
	Panel      lipgloss.TerminalColor // surface colour (dialog body)
	Element    lipgloss.TerminalColor // raised elements (menu bar, inputs)
	Text       lipgloss.TerminalColor
	TextMuted  lipgloss.TerminalColor // hints, descriptions
	TextSubtle lipgloss.TerminalColor // labels
	TextFaint  lipgloss.TerminalColor // notes

	Primary   lipgloss.TerminalColor // keys, result headers
	Secondary lipgloss.TerminalColor
	Accent    lipgloss.TerminalColor // section headings, panel title
	Title     lipgloss.TerminalColor // app title on the Home screen

	Border       lipgloss.TerminalColor
	BorderActive lipgloss.TerminalColor // panel frame, scroll thumb

	Success, Warning, Error, Info lipgloss.TerminalColor
	DiffAdd, DiffRemove           lipgloss.TerminalColor

	// Menu bar, dropdowns, select lists and F-key labels.
	MenuBg, MenuFg lipgloss.TerminalColor
	MenuHotkey     lipgloss.TerminalColor // hotkey letter in the menu bar
	MenuShortcut   lipgloss.TerminalColor // right-aligned shortcut in dropdowns
	MenuMuted      lipgloss.TerminalColor // disabled items
	MenuBorder     lipgloss.TerminalColor

	// Highlighted menu item / option.
	SelectionBg, SelectionFg lipgloss.TerminalColor
	SelectionHotkey          lipgloss.TerminalColor

	// Dialogs.
	DialogBg, DialogFg lipgloss.TerminalColor
	DialogBorder       lipgloss.TerminalColor
	DialogTitle        lipgloss.TerminalColor // also focused labels
	DialogInfo         lipgloss.TerminalColor
	DialogMuted        lipgloss.TerminalColor // help, placeholders
	DialogError        lipgloss.TerminalColor
	FieldBg, FieldFg   lipgloss.TerminalColor
	FocusBg, FocusFg   lipgloss.TerminalColor // focused field/button/checkbox, active list item
	FocusMuted         lipgloss.TerminalColor // placeholder in a focused field
	CursorBg, CursorFg lipgloss.TerminalColor

	// Tab bar.
	TabActiveBg, TabActiveFg     lipgloss.TerminalColor
	TabInactiveBg, TabInactiveFg lipgloss.TerminalColor
	TabClose, TabBadge, TabAdd   lipgloss.TerminalColor

	// Loose text drawn on the screen background.
	FKeyNum      lipgloss.TerminalColor
	ListMuted    lipgloss.TerminalColor
	ListDisabled lipgloss.TerminalColor

	// Home screen buttons.
	ButtonBg, ButtonFg lipgloss.TerminalColor

	ShadowBg, ShadowFg lipgloss.TerminalColor
}

// ThemeFromPalette builds the widget theme for p.
func ThemeFromPalette(p Palette) Theme {
	s := lipgloss.NewStyle
	// on returns a style with the given colours; nil colours are left unset.
	on := func(bg, fg lipgloss.TerminalColor) lipgloss.Style {
		st := s()
		if bg != nil {
			st = st.Background(bg)
		}
		if fg != nil {
			st = st.Foreground(fg)
		}
		return st
	}
	fg := func(st lipgloss.Style, c lipgloss.TerminalColor) lipgloss.Style {
		if c != nil {
			st = st.Foreground(c)
		}
		return st
	}
	rev := func(st lipgloss.Style) lipgloss.Style {
		if p.Reverse {
			st = st.Reverse(true)
		}
		return st
	}
	border := func(st lipgloss.Style, bfg, bbg lipgloss.TerminalColor) lipgloss.Style {
		if bfg != nil {
			st = st.BorderForeground(bfg)
		}
		if bbg != nil {
			st = st.BorderBackground(bbg)
		}
		return st
	}

	menu := on(p.MenuBg, p.MenuFg)
	sel := rev(on(p.SelectionBg, p.SelectionFg))
	dlg := on(p.DialogBg, p.DialogFg)
	focus := rev(on(p.FocusBg, p.FocusFg))
	field := on(p.FieldBg, p.FieldFg)

	return Theme{
		MenuBar:          menu,
		MenuItem:         menu,
		MenuItemActive:   sel,
		MenuHotkey:       fg(menu, p.MenuHotkey).Bold(true).Underline(true),
		MenuHotkeyActive: fg(sel, p.SelectionHotkey).Bold(true).Underline(true),

		Dropdown:             border(menu, p.MenuBorder, p.MenuBg),
		DropdownItem:         menu,
		DropdownItemActive:   sel,
		DropdownDisabled:     fg(menu, p.MenuMuted),
		DropdownHotkey:       fg(menu, p.MenuShortcut),
		DropdownHotkeyActive: fg(sel, p.SelectionHotkey),
		DropdownSeparator:    fg(menu, p.MenuBorder),

		Dialog:             dlg,
		DialogBorder:       fg(dlg, p.DialogBorder),
		DialogTitle:        fg(dlg, p.DialogTitle).Bold(true),
		Label:              dlg,
		LabelFocused:       fg(dlg, p.DialogTitle).Bold(true),
		Field:              field,
		FieldFocused:       focus,
		Placeholder:        fg(field, p.DialogMuted),
		PlaceholderFocused: fg(focus, p.FocusMuted),
		Cursor:             rev(on(p.CursorBg, p.CursorFg)),
		Info:               fg(dlg, p.DialogInfo),
		Button:             dlg,
		ButtonFocused:      focus.Bold(true),
		CheckboxOn:         dlg,
		CheckboxOff:        dlg,
		CheckboxFocused:    focus,
		Error:              fg(dlg, p.DialogError).Bold(true),
		Help:               fg(dlg, p.DialogMuted),
		SelectList:         border(menu, p.MenuBorder, p.MenuBg),
		SelectItem:         menu,
		SelectItemActive:   sel,

		FKeyNum:      on(nil, p.FKeyNum).Bold(true),
		FKeyLabel:    menu,
		FKeyDisabled: fg(menu, p.MenuMuted),

		TabBar:      s(),
		TabActive:   rev(on(p.TabActiveBg, p.TabActiveFg)).Bold(true),
		TabInactive: on(p.TabInactiveBg, p.TabInactiveFg),
		TabClose:    on(nil, p.TabClose),
		TabBadge:    on(nil, p.TabBadge),
		TabAdd:      on(nil, p.TabAdd).Bold(true),
		TabScroll:   on(nil, p.TabAdd).Bold(true),

		ListItem:       s(),
		ListItemActive: focus,
		ListDesc:       on(nil, p.ListMuted),
		ListDescActive: fg(focus, p.FocusMuted),
		ListDisabled:   on(nil, p.ListDisabled),

		Shadow: on(p.ShadowBg, p.ShadowFg),
	}
}

// ---- registry ----

var (
	registryOnce sync.Once
	registry     map[string]Palette
)

func palettes() map[string]Palette {
	registryOnce.Do(func() {
		registry = make(map[string]Palette)
		for _, p := range builtinPalettes() {
			registry[p.Name] = p
		}
	})
	return registry
}

// DefaultThemeName is the name of the classic Midnight Commander theme.
const DefaultThemeName = "mc"

// Themes returns the names of the built-in themes: "mc" first, the rest sorted.
func Themes() []string {
	var names []string
	for n := range palettes() {
		if n != DefaultThemeName {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	return append([]string{DefaultThemeName}, names...)
}

// ThemeByName returns the built-in theme name (case-insensitive) and its palette.
func ThemeByName(name string) (Theme, Palette, bool) {
	p, ok := palettes()[strings.ToLower(strings.TrimSpace(name))]
	if !ok {
		return Theme{}, Palette{}, false
	}
	return ThemeFromPalette(p), p, true
}

// ---- active theme ----

var active struct {
	sync.RWMutex
	set     bool
	theme   Theme
	palette Palette
}

// SetActiveTheme makes the named built-in theme the active one (used by
// ActiveTheme and OverlayShadow). Unknown names return an error and leave the
// active theme unchanged.
func SetActiveTheme(name string) error {
	th, p, ok := ThemeByName(name)
	if !ok {
		return fmt.Errorf("unknown theme %q (available: %s)", name, strings.Join(Themes(), ", "))
	}
	active.Lock()
	active.set, active.theme, active.palette = true, th, p
	active.Unlock()
	return nil
}

// ActiveTheme returns the active theme (the mc theme until SetActiveTheme).
func ActiveTheme() Theme {
	active.RLock()
	defer active.RUnlock()
	if !active.set {
		return DefaultTheme()
	}
	return active.theme
}

// ActivePalette returns the palette of the active theme.
func ActivePalette() Palette {
	active.RLock()
	defer active.RUnlock()
	if !active.set {
		return palettes()[DefaultThemeName]
	}
	return active.palette
}

// ---- background painting ----

// PaintBackground gives every line of s the background bg and default
// foreground fg, padded to width cells. Styled segments keep their own colours;
// after each SGR reset the base colours are re-applied. With bg == nil, or a
// colour profile without colours, s is returned unchanged.
func PaintBackground(s string, width int, bg, fg lipgloss.TerminalColor) string {
	if bg == nil {
		return s
	}
	st := lipgloss.NewStyle().Background(bg)
	if fg != nil {
		st = st.Foreground(fg)
	}
	probe := st.Render("X")
	i := strings.Index(probe, "X")
	if i <= 0 {
		return s
	}
	base := probe[:i]
	lines := strings.Split(s, "\n")
	for n, l := range lines {
		l = strings.ReplaceAll(l, "\x1b[0m", "\x1b[0m"+base)
		l = strings.ReplaceAll(l, "\x1b[m", "\x1b[m"+base)
		if w := ansi.StringWidth(l); w < width {
			l += strings.Repeat(" ", width-w)
		}
		lines[n] = base + l + "\x1b[0m"
	}
	return strings.Join(lines, "\n")
}

// ---- colour helpers ----

// HexOf returns the "#rrggbb" value of c for contrast checks: a hex Color, or
// the Dark/Light side of an AdaptiveColor (dark unless light). ANSI indices and
// nil return "".
func HexOf(c lipgloss.TerminalColor, light bool) string {
	switch v := c.(type) {
	case lipgloss.Color:
		if strings.HasPrefix(string(v), "#") {
			return string(v)
		}
		if n, err := strconv.Atoi(string(v)); err == nil && n >= 16 && n <= 255 {
			return xterm256Hex(n)
		}
	case lipgloss.AdaptiveColor:
		if light {
			return HexOf(lipgloss.Color(v.Light), light)
		}
		return HexOf(lipgloss.Color(v.Dark), light)
	}
	return ""
}

func xterm256Hex(n int) string {
	if n >= 232 {
		v := 8 + (n-232)*10
		return fmt.Sprintf("#%02x%02x%02x", v, v, v)
	}
	n -= 16
	lv := func(x int) int {
		if x == 0 {
			return 0
		}
		return 55 + x*40
	}
	return fmt.Sprintf("#%02x%02x%02x", lv(n/36), lv(n/6%6), lv(n%6))
}

func parseHex(h string) (r, g, b float64, ok bool) {
	h = strings.TrimPrefix(h, "#")
	if len(h) != 6 {
		return 0, 0, 0, false
	}
	v, err := strconv.ParseUint(h, 16, 32)
	if err != nil {
		return 0, 0, 0, false
	}
	return float64(v >> 16 & 0xff), float64(v >> 8 & 0xff), float64(v & 0xff), true
}

// luminance is the WCAG relative luminance of a "#rrggbb" colour.
func luminance(h string) float64 {
	r, g, b, ok := parseHex(h)
	if !ok {
		return 0
	}
	lin := func(c float64) float64 {
		c /= 255
		if c <= 0.03928 {
			return c / 12.92
		}
		return math.Pow((c+0.055)/1.055, 2.4)
	}
	return 0.2126*lin(r) + 0.7152*lin(g) + 0.0722*lin(b)
}

// ContrastRatio is the WCAG contrast ratio of two "#rrggbb" colours (1..21).
func ContrastRatio(a, b string) float64 {
	la, lb := luminance(a), luminance(b)
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05)
}

// blend mixes a and b ("#rrggbb"): t=0 → a, t=1 → b.
func blend(a, b string, t float64) string {
	ar, ag, ab, ok1 := parseHex(a)
	br, bg, bb, ok2 := parseHex(b)
	if !ok1 || !ok2 {
		return a
	}
	mix := func(x, y float64) int { return int(math.Round(x + (y-x)*t)) }
	return fmt.Sprintf("#%02x%02x%02x", mix(ar, br), mix(ag, bg), mix(ab, bb))
}

// readableOn returns whichever candidate has the best contrast on bg.
func readableOn(bg string, candidates ...string) string {
	best, bestC := candidates[0], -1.0
	for _, c := range candidates {
		if r := ContrastRatio(c, bg); r > bestC {
			best, bestC = c, r
		}
	}
	return best
}
