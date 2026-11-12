package ui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
)

func testMenus() []Menu {
	f := false
	return []Menu{
		{Title: "&File", Items: []MenuItem{
			{Label: "&New tab", Hotkey: "ctrl+t", Action: "new"},
			{Separator: true},
			{Label: "Close", Action: "close", Disabled: true},
			{Label: "&Quit", Hotkey: "F10", Action: "quit"},
		}},
		{Title: "&View", Items: []MenuItem{
			{Label: "Wrap", Action: "wrap", Checked: &f},
			{Label: "Off", Action: "off", Disabled: true},
		}},
		{Title: "&Help", Items: []MenuItem{{Label: "About", Action: "about"}}},
	}
}

func TestMenuKeyboard(t *testing.T) {
	m := NewMenuBar("mk", testMenus(), DefaultTheme())
	m, _, consumed := m.Update(keyRunes("x"))
	if consumed || m.IsOpen() {
		t.Fatal("closed menu must not consume plain keys")
	}
	m, _, consumed = m.Update(key(tea.KeyF9))
	if !consumed || !m.IsOpen() || m.cur != 0 || m.sel != 0 {
		t.Fatalf("F9: open=%v cur=%d sel=%d", m.IsOpen(), m.cur, m.sel)
	}
	m, _, _ = m.Update(key(tea.KeyDown)) // skips separator and disabled
	if m.sel != 3 {
		t.Fatalf("down: sel=%d want 3", m.sel)
	}
	m, _, _ = m.Update(key(tea.KeyDown)) // wraps
	if m.sel != 0 {
		t.Fatalf("wrap: sel=%d", m.sel)
	}
	m, _, _ = m.Update(key(tea.KeyUp))
	if m.sel != 3 {
		t.Fatalf("up: sel=%d", m.sel)
	}
	m, _, consumed = m.Update(keyRunes("z")) // swallowed while open
	if !consumed || !m.IsOpen() {
		t.Fatal("open menu must swallow keys")
	}
	m, act, _ := m.Update(key(tea.KeyEnter))
	if act != "quit" || m.IsOpen() {
		t.Fatalf("enter: act=%q open=%v", act, m.IsOpen())
	}

	// alt+hotkey, left/right wrap.
	m, _, consumed = m.Update(keyAlt('v'))
	if !consumed || !m.IsOpen() || m.cur != 1 || m.sel != 0 {
		t.Fatalf("alt+v: cur=%d sel=%d", m.cur, m.sel)
	}
	m, _, _ = m.Update(key(tea.KeyDown)) // only Wrap is selectable
	if m.sel != 0 {
		t.Fatalf("disabled not skipped: %d", m.sel)
	}
	m, _, _ = m.Update(key(tea.KeyRight))
	m, _, _ = m.Update(key(tea.KeyRight))
	if m.cur != 0 {
		t.Fatalf("right wrap: cur=%d", m.cur)
	}
	m, _, _ = m.Update(key(tea.KeyLeft))
	if m.cur != 2 {
		t.Fatalf("left wrap: cur=%d", m.cur)
	}
	// Item hotkey letter.
	m.Open(0)
	m, act, _ = m.Update(keyRunes("n"))
	if act != "new" || m.IsOpen() {
		t.Fatalf("item hotkey: %q", act)
	}
	m.Open(0)
	m, _, consumed = m.Update(key(tea.KeyEsc))
	if !consumed || m.IsOpen() {
		t.Fatal("esc must close")
	}
	// Unknown alt key while closed isn't consumed.
	_, _, consumed = m.Update(keyAlt('q'))
	if consumed {
		t.Fatal("unknown alt key consumed")
	}
}

func TestMenuSetCheckedDisabled(t *testing.T) {
	menus := testMenus()
	m := NewMenuBar("ms", menus, DefaultTheme())
	m.SetChecked("wrap", true)
	if *menus[1].Items[0].Checked {
		t.Fatal("NewMenuBar must deep-copy")
	}
	m.SetDisabled("close", false)
	m.Open(1)
	v, _, _ := m.DropdownView()
	if !strings.Contains(ansi.Strip(v), "✓ Wrap") {
		t.Fatalf("checkmark missing:\n%s", ansi.Strip(v))
	}
	m.Open(0)
	m, _, _ = m.Update(key(tea.KeyDown))
	if m.sel != 2 {
		t.Fatalf("re-enabled item not selectable: %d", m.sel)
	}
}

func menuScreen(m MenuBar, w, h int) string {
	lines := []string{m.View(w)}
	for len(lines) < h {
		lines = append(lines, strings.Repeat(".", w))
	}
	s := strings.Join(lines, "\n")
	if dd, x, y := m.DropdownView(); dd != "" {
		s = OverlayShadow(s, dd, x, y)
	}
	return s
}

func TestMenuMouse(t *testing.T) {
	m := NewMenuBar("mm", testMenus(), DefaultTheme())
	scan(t, menuScreen(m, 60, 10))
	m, _, consumed := m.Update(clickZone(t, "mm-m-1", 1))
	if !consumed || !m.IsOpen() || m.cur != 1 {
		t.Fatalf("click title: open=%v cur=%d", m.IsOpen(), m.cur)
	}
	// Click same title again toggles closed.
	scan(t, menuScreen(m, 60, 10))
	m, _, _ = m.Update(clickZone(t, "mm-m-1", 0))
	if m.IsOpen() {
		t.Fatal("second click should close")
	}
	m.Open(0)
	scan(t, menuScreen(m, 60, 10))
	// Motion highlights.
	mv := clickZone(t, "mm-i-0-3", 2)
	mv.Action, mv.Button = tea.MouseActionMotion, tea.MouseButtonNone
	m, _, consumed = m.Update(mv)
	if !consumed || m.sel != 3 {
		t.Fatalf("motion: sel=%d", m.sel)
	}
	// Disabled item click does nothing.
	m, act, _ := m.Update(clickZone(t, "mm-i-0-2", 2))
	if act != "" || !m.IsOpen() {
		t.Fatal("disabled item chosen")
	}
	// Motion over another title switches menus while open.
	mv = clickZone(t, "mm-m-2", 0)
	mv.Action, mv.Button = tea.MouseActionMotion, tea.MouseButtonNone
	m, _, _ = m.Update(mv)
	if m.cur != 2 {
		t.Fatalf("motion title: cur=%d", m.cur)
	}
	m.Open(0)
	scan(t, menuScreen(m, 60, 10))
	m, act, consumed = m.Update(clickZone(t, "mm-i-0-0", 3))
	if act != "new" || !consumed || m.IsOpen() {
		t.Fatalf("click item: act=%q", act)
	}
	// Click outside closes and is consumed.
	m.Open(0)
	scan(t, menuScreen(m, 60, 10))
	m, act, consumed = m.Update(mouseAt(50, 8, tea.MouseButtonLeft, tea.MouseActionPress))
	if act != "" || !consumed || m.IsOpen() {
		t.Fatal("click outside should close")
	}
	// Closed: click outside not consumed.
	_, _, consumed = m.Update(mouseAt(50, 8, tea.MouseButtonLeft, tea.MouseActionPress))
	if consumed {
		t.Fatal("closed menu consumed outside click")
	}
}

func TestMenuViewWidth(t *testing.T) {
	m := NewMenuBar("mw", testMenus(), DefaultTheme())
	for _, w := range []int{5, 20, 80} {
		if got := ansi.StringWidth(m.View(w)); got != w {
			t.Fatalf("width %d: got %d", w, got)
		}
	}
	m.Open(2)
	_, x, _ := m.DropdownViewAt(20)
	v, _, _ := m.DropdownView()
	if x+maxWidth(strings.Split(v, "\n")) > 20 {
		t.Fatalf("DropdownViewAt did not clamp: x=%d", x)
	}
}
