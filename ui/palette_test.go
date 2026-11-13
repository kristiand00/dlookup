package ui

import (
	"reflect"
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/muesli/termenv"
)

// withTrueColor forces colour output for the duration of the test.
func withTrueColor(t *testing.T) {
	t.Helper()
	prev := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.TrueColor)
	t.Cleanup(func() { lipgloss.SetColorProfile(prev) })
}

func TestMCThemeMatchesLegacyDefault(t *testing.T) {
	withTrueColor(t)
	got, want := DefaultTheme(), legacyMCTheme()
	if !reflect.DeepEqual(got, want) {
		t.Error("DefaultTheme() differs from the pre-theme default")
	}
	mc, _, ok := ThemeByName("mc")
	if !ok || !reflect.DeepEqual(mc, want) {
		t.Error(`ThemeByName("mc") differs from the pre-theme default`)
	}
	render := func(th Theme) string {
		d := NewDialog("cmp", "Title", []Field{
			{Key: "a", Label: "&Name", Kind: FieldText, Placeholder: "ph"},
			{Key: "b", Label: "Type", Kind: FieldSelect, Options: []Option{{"x", "x"}, {"y", "y"}}},
			{Key: "c", Label: "Check", Kind: FieldCheckbox},
		}, []Button{{Label: "&OK", Action: "ok", Default: true}, {Label: "Cancel", Action: "cancel"}}, th)
		d.Err = "bad"
		d.Help = "help"
		mb := NewMenuBar("cmpm", testMenus(), th)
		fb := FKeyBar{ID: "cmpf", Theme: th}
		tb := TabBar{ID: "cmpt", Theme: th}
		return d.View() + mb.View(60) + fb.View([]FKey{{Num: "1", Label: "Help"}, {Num: "2", Label: "X", Disabled: true}}, 40) +
			tb.View([]Tab{{Title: "a", Closable: true, Badge: "●"}, {Title: "b"}}, 0, 40)
	}
	if a, b := render(DefaultTheme()), render(legacyMCTheme()); a != b {
		t.Errorf("rendering differs:\n%q\n%q", a, b)
	}
}

func TestThemesRegistry(t *testing.T) {
	names := Themes()
	if names[0] != "mc" {
		t.Fatalf("first theme = %q, want mc", names[0])
	}
	for i := 2; i < len(names); i++ {
		if names[i-1] >= names[i] {
			t.Errorf("themes not sorted: %v", names)
		}
	}
	for _, want := range []string{"system", "opencode", "claude", "tokyonight", "catppuccin", "catppuccin-latte",
		"gruvbox", "nord", "dracula", "one-dark", "everforest", "kanagawa", "ayu", "rose-pine",
		"solarized-dark", "solarized-light", "monokai", "matrix", "flexoki"} {
		if _, p, ok := ThemeByName(want); !ok || p.Name != want {
			t.Errorf("theme %q missing", want)
		}
	}
	if _, _, ok := ThemeByName("no-such-theme"); ok {
		t.Error("unknown theme reported as found")
	}
	if _, _, ok := ThemeByName(" Dracula "); !ok {
		t.Error("lookup should be case-insensitive and trimmed")
	}
}

func TestThemesRenderWithColours(t *testing.T) {
	withTrueColor(t)
	for _, name := range Themes() {
		th, _, _ := ThemeByName(name)
		v := reflect.ValueOf(th)
		for i := 0; i < v.NumField(); i++ {
			st := v.Field(i).Interface().(lipgloss.Style)
			if out := st.Render("x"); !strings.Contains(out, "x") {
				t.Errorf("%s.%s renders %q", name, v.Type().Field(i).Name, out)
			}
		}
		if out := th.MenuItemActive.Render("x"); out == "x" {
			t.Errorf("%s: active menu item is unstyled", name)
		}
		if out := th.Dialog.Render("x"); name != "system" && out == "x" {
			t.Errorf("%s: dialog is unstyled", name)
		}
	}
}

func TestThemeContrast(t *testing.T) {
	type pair struct {
		what   string
		fg, bg func(Palette) lipgloss.TerminalColor
	}
	pairs := []pair{
		{"Text/Panel", func(p Palette) lipgloss.TerminalColor { return p.Text }, func(p Palette) lipgloss.TerminalColor { return p.Panel }},
		{"Text/Background", func(p Palette) lipgloss.TerminalColor { return p.Text }, func(p Palette) lipgloss.TerminalColor { return p.Background }},
		{"Menu", func(p Palette) lipgloss.TerminalColor { return p.MenuFg }, func(p Palette) lipgloss.TerminalColor { return p.MenuBg }},
		{"Selection", func(p Palette) lipgloss.TerminalColor { return p.SelectionFg }, func(p Palette) lipgloss.TerminalColor { return p.SelectionBg }},
		{"Dialog", func(p Palette) lipgloss.TerminalColor { return p.DialogFg }, func(p Palette) lipgloss.TerminalColor { return p.DialogBg }},
		{"Field", func(p Palette) lipgloss.TerminalColor { return p.FieldFg }, func(p Palette) lipgloss.TerminalColor { return p.FieldBg }},
		{"Focus", func(p Palette) lipgloss.TerminalColor { return p.FocusFg }, func(p Palette) lipgloss.TerminalColor { return p.FocusBg }},
		{"DialogTitle", func(p Palette) lipgloss.TerminalColor { return p.DialogTitle }, func(p Palette) lipgloss.TerminalColor { return p.DialogBg }},
		{"TabActive", func(p Palette) lipgloss.TerminalColor { return p.TabActiveFg }, func(p Palette) lipgloss.TerminalColor { return p.TabActiveBg }},
		{"TabInactive", func(p Palette) lipgloss.TerminalColor { return p.TabInactiveFg }, func(p Palette) lipgloss.TerminalColor { return p.TabInactiveBg }},
		{"Button", func(p Palette) lipgloss.TerminalColor { return p.ButtonFg }, func(p Palette) lipgloss.TerminalColor { return p.ButtonBg }},
	}
	for _, name := range Themes() {
		if name == "system" {
			continue
		}
		_, p, _ := ThemeByName(name)
		checked := 0
		for _, pr := range pairs {
			fg, bg := HexOf(pr.fg(p), p.Light), HexOf(pr.bg(p), p.Light)
			if fg == "" || bg == "" {
				continue
			}
			checked++
			if r := ContrastRatio(fg, bg); r < 3.0 {
				t.Errorf("%s: %s contrast %.2f (%s on %s) < 3.0", name, pr.what, r, fg, bg)
			}
		}
		if checked < 8 {
			t.Errorf("%s: only %d colour pairs could be checked", name, checked)
		}
	}
}

func TestActiveTheme(t *testing.T) {
	t.Cleanup(func() { _ = SetActiveTheme("mc") })
	if err := SetActiveTheme("nope"); err == nil {
		t.Fatal("expected error for unknown theme")
	}
	if err := SetActiveTheme("nord"); err != nil {
		t.Fatal(err)
	}
	if ActivePalette().Name != "nord" {
		t.Errorf("active palette = %q", ActivePalette().Name)
	}
	nord, _, _ := ThemeByName("nord")
	if !reflect.DeepEqual(ActiveTheme(), nord) {
		t.Error("ActiveTheme is not nord")
	}
}

func TestPaintBackground(t *testing.T) {
	withTrueColor(t)
	if got := PaintBackground("abc", 10, nil, nil); got != "abc" {
		t.Errorf("nil bg changed the string: %q", got)
	}
	in := "a" + lipgloss.NewStyle().Foreground(lipgloss.Color("#ff0000")).Render("b") + "c\nxy"
	out := PaintBackground(in, 6, lipgloss.Color("#102030"), lipgloss.Color("#eeeeee"))
	bgSeq := "48;2;16;32;48"
	lines := strings.Split(out, "\n")
	for _, l := range lines {
		if w := ansi.StringWidth(l); w != 6 {
			t.Errorf("line width %d, want 6: %q", w, l)
		}
		if !strings.HasPrefix(l, "\x1b[") || !strings.Contains(l, bgSeq) {
			t.Errorf("line not painted: %q", l)
		}
	}
	// The background is re-applied after the styled segment's reset.
	if i := strings.Index(lines[0], "\x1b[0m"); i < 0 || !strings.Contains(lines[0][i:], bgSeq) {
		t.Errorf("background not restored after reset: %q", lines[0])
	}
	if ansi.Strip(out) != "abc   \nxy    " {
		t.Errorf("text changed: %q", ansi.Strip(out))
	}
}

func TestContrastRatio(t *testing.T) {
	if r := ContrastRatio("#000000", "#ffffff"); r < 20.9 || r > 21.1 {
		t.Errorf("black/white = %.2f", r)
	}
	if HexOf(lipgloss.Color("16"), false) != "#000000" || HexOf(lipgloss.Color("231"), false) != "#ffffff" {
		t.Error("xterm-256 conversion")
	}
}

// ---- pre-theme default, kept to verify the mc theme is unchanged ----

// Palette (MC-inspired). The coloured surfaces use the same colours in light
// and dark terminals (they bring their own background), only the "loose" text
// drawn on the terminal background (tabs, lists, F-key labels) adapts.
var (
	lBlue       = lipgloss.Color("#1c3f94")
	lBlueDeep   = lipgloss.Color("#12296b")
	lCyan       = lipgloss.Color("#3fb6c4")
	lCyanLight  = lipgloss.Color("#9ee6ee")
	lBlack      = lipgloss.Color("#101010")
	lWhite      = lipgloss.Color("#f2f2f2")
	lYellow     = lipgloss.Color("#ffe066")
	lGrayOnCyan = lipgloss.Color("#2a6b73")
	lDimOnBlue  = lipgloss.Color("#9aa9d6")
	lRedOnBlue  = lipgloss.Color("#ff9a9a")
)

// legacyMCTheme is DefaultTheme as it was before themes were added.
func legacyMCTheme() Theme {
	s := lipgloss.NewStyle
	onCyan := s().Background(lCyan).Foreground(lBlack)
	onBlack := s().Background(lBlack).Foreground(lWhite)
	onBlue := s().Background(lBlue).Foreground(lWhite)

	return Theme{
		MenuBar:          onCyan,
		MenuItem:         onCyan,
		MenuItemActive:   onBlack,
		MenuHotkey:       onCyan.Foreground(lipgloss.Color("#fff6b0")).Bold(true).Underline(true),
		MenuHotkeyActive: onBlack.Foreground(lYellow).Bold(true).Underline(true),

		Dropdown:             onCyan.BorderForeground(lBlack).BorderBackground(lCyan),
		DropdownItem:         onCyan,
		DropdownItemActive:   onBlack,
		DropdownDisabled:     onCyan.Foreground(lGrayOnCyan),
		DropdownHotkey:       onCyan.Foreground(lipgloss.Color("#1d4a50")),
		DropdownHotkeyActive: onBlack.Foreground(lYellow),
		DropdownSeparator:    onCyan.Foreground(lBlack),

		Dialog:             onBlue,
		DialogBorder:       onBlue.Foreground(lCyanLight),
		DialogTitle:        onBlue.Foreground(lYellow).Bold(true),
		Label:              onBlue,
		LabelFocused:       onBlue.Foreground(lYellow).Bold(true),
		Field:              s().Background(lBlueDeep).Foreground(lWhite),
		FieldFocused:       onCyan,
		Placeholder:        s().Background(lBlueDeep).Foreground(lDimOnBlue),
		PlaceholderFocused: onCyan.Foreground(lGrayOnCyan),
		Cursor:             s().Background(lBlack).Foreground(lWhite),
		Info:               onBlue.Foreground(lCyanLight),
		Button:             onBlue,
		ButtonFocused:      onCyan.Bold(true),
		CheckboxOn:         onBlue,
		CheckboxOff:        onBlue,
		CheckboxFocused:    onCyan,
		Error:              onBlue.Foreground(lRedOnBlue).Bold(true),
		Help:               onBlue.Foreground(lDimOnBlue),
		SelectList:         onCyan.BorderForeground(lBlack).BorderBackground(lCyan),
		SelectItem:         onCyan,
		SelectItemActive:   onBlack,

		FKeyNum:      s().Foreground(ac("#101010", "#f2f2f2")).Bold(true),
		FKeyLabel:    onCyan,
		FKeyDisabled: onCyan.Foreground(lGrayOnCyan),

		TabBar:      s(),
		TabActive:   onBlue.Bold(true),
		TabInactive: s().Background(ac("#d0d4dc", "#30343c")).Foreground(ac("#303030", "#c8c8c8")),
		TabClose:    s().Foreground(ac("#b00020", "#ff8080")),
		TabBadge:    s().Foreground(ac("#b07000", "#ffd060")),
		TabAdd:      s().Foreground(ac("#1c3f94", "#7fd8e2")).Bold(true),
		TabScroll:   s().Foreground(ac("#1c3f94", "#7fd8e2")).Bold(true),

		ListItem:       s(),
		ListItemActive: onCyan,
		ListDesc:       s().Foreground(ac("#606060", "#8a8a8a")),
		ListDescActive: onCyan.Foreground(lGrayOnCyan),
		ListDisabled:   s().Foreground(ac("#a0a0a0", "#5a5a5a")),

		Shadow: s().Background(lipgloss.Color("#000000")).Foreground(lipgloss.Color("#5a5a5a")),
	}
}
