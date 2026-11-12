package ui

import (
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
)

// MenuItem is an entry of a dropdown menu.
type MenuItem struct {
	Label     string // may contain "&x" to mark an item hotkey letter
	Hotkey    string // shown right-aligned, e.g. "F2" or "ctrl+x" (display only)
	Action    string
	Disabled  bool
	Separator bool
	Checked   *bool // nil = not a checkbox item
}

// Menu is a top-level menu title with its dropdown items.
type Menu struct {
	Title string // "&File": the char after & is the alt-hotkey and is underlined
	Items []MenuItem
}

// MenuBar is an MC-style menu bar with dropdown menus.
//
// Zone ids: ID+"-m-<menu>" for titles, ID+"-i-<menu>-<item>" for items.
type MenuBar struct {
	ID    string
	Menus []Menu
	Theme Theme

	open bool
	cur  int // active menu
	sel  int // active item (-1 = none)
}

// NewMenuBar creates a menu bar. The menus are deep-copied.
func NewMenuBar(id string, menus []Menu, th Theme) MenuBar {
	cp := make([]Menu, len(menus))
	for i, m := range menus {
		cp[i] = Menu{Title: m.Title, Items: make([]MenuItem, len(m.Items))}
		for j, it := range m.Items {
			if it.Checked != nil {
				v := *it.Checked
				it.Checked = &v
			}
			cp[i].Items[j] = it
		}
	}
	return MenuBar{ID: id, Menus: cp, Theme: th, sel: -1}
}

// IsOpen reports whether a dropdown is open.
func (m MenuBar) IsOpen() bool { return m.open }

// Active returns the index of the open menu (or the last one opened).
func (m MenuBar) Active() int { return m.cur }

// Open opens menu menuIndex and highlights its first selectable item.
func (m *MenuBar) Open(menuIndex int) {
	if len(m.Menus) == 0 {
		return
	}
	m.open = true
	m.cur = clamp(menuIndex, 0, len(m.Menus)-1)
	m.sel = m.nextSelectable(-1, 1)
}

// Close closes any open dropdown.
func (m *MenuBar) Close() {
	m.open = false
	m.sel = -1
}

// SetDisabled enables/disables every item with the given action.
func (m *MenuBar) SetDisabled(action string, disabled bool) {
	for i := range m.Menus {
		for j := range m.Menus[i].Items {
			if m.Menus[i].Items[j].Action == action {
				m.Menus[i].Items[j].Disabled = disabled
			}
		}
	}
}

// SetChecked sets the check state of every item with the given action (making
// it a checkbox item if it wasn't).
func (m *MenuBar) SetChecked(action string, checked bool) {
	for i := range m.Menus {
		for j := range m.Menus[i].Items {
			if m.Menus[i].Items[j].Action == action {
				v := checked
				m.Menus[i].Items[j].Checked = &v
			}
		}
	}
}

func (m MenuBar) selectable(i int) bool {
	if !m.open || m.cur < 0 || m.cur >= len(m.Menus) {
		return false
	}
	items := m.Menus[m.cur].Items
	return i >= 0 && i < len(items) && !items[i].Separator && !items[i].Disabled
}

// nextSelectable finds the next selectable item from `from` in direction dir,
// wrapping around. Returns -1 if none.
func (m MenuBar) nextSelectable(from, dir int) int {
	if m.cur < 0 || m.cur >= len(m.Menus) {
		return -1
	}
	items := m.Menus[m.cur].Items
	n := len(items)
	if n == 0 {
		return -1
	}
	i := from
	for range n {
		i += dir
		if i < 0 {
			i = n - 1
		} else if i >= n {
			i = 0
		}
		if !items[i].Separator && !items[i].Disabled {
			return i
		}
	}
	return -1
}

func (m MenuBar) titleID(i int) string { return m.ID + "-m-" + strconv.Itoa(i) }
func (m MenuBar) itemID(i, j int) string {
	return m.ID + "-i-" + strconv.Itoa(i) + "-" + strconv.Itoa(j)
}

// titleX returns the screen column where title i starts.
func (m MenuBar) titleX(i int) int {
	x := 1
	for k := 0; k < i && k < len(m.Menus); k++ {
		t, _, _ := ParseHotkey(m.Menus[k].Title)
		x += ansi.StringWidth(t) + 2 + 1
	}
	return x
}

func (m MenuBar) menuForHotkey(r rune) int {
	for i, mn := range m.Menus {
		if _, _, h := ParseHotkey(mn.Title); h != 0 && h == r {
			return i
		}
	}
	return -1
}

func altRune(k tea.KeyMsg) (rune, bool) {
	if k.Alt && k.Type == tea.KeyRunes && len(k.Runes) == 1 {
		return toLower(k.Runes[0]), true
	}
	return 0, false
}

func toLower(r rune) rune { return []rune(strings.ToLower(string(r)))[0] }

// Update handles keyboard and mouse input. It returns the chosen Action (""
// if none) and whether msg was consumed. While a dropdown is open every key
// and mouse message is consumed (the menu is modal).
func (m MenuBar) Update(msg tea.Msg) (MenuBar, string, bool) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		return m.updateKey(msg)
	case tea.MouseMsg:
		return m.updateMouse(msg)
	}
	return m, "", false
}

func (m MenuBar) updateKey(k tea.KeyMsg) (MenuBar, string, bool) {
	if r, ok := altRune(k); ok {
		if i := m.menuForHotkey(r); i >= 0 {
			if m.open && m.cur == i {
				m.Close()
			} else {
				m.Open(i)
			}
			return m, "", true
		}
		return m, "", m.open
	}
	if !m.open {
		if k.String() == "f9" {
			m.Open(0)
			return m, "", true
		}
		return m, "", false
	}
	n := len(m.Menus)
	switch k.String() {
	case "esc", "f9", "f10":
		m.Close()
	case "left", "shift+tab":
		m.Open((m.cur - 1 + n) % n)
	case "right", "tab":
		m.Open((m.cur + 1) % n)
	case "up":
		m.sel = m.nextSelectable(m.sel, -1)
	case "down":
		if m.sel < 0 {
			m.sel = m.nextSelectable(-1, 1)
		} else {
			m.sel = m.nextSelectable(m.sel, 1)
		}
	case "home", "pgup":
		m.sel = m.nextSelectable(-1, 1)
	case "end", "pgdown":
		m.sel = m.nextSelectable(len(m.Menus[m.cur].Items), -1)
	case "enter", " ":
		if m.selectable(m.sel) {
			a := m.Menus[m.cur].Items[m.sel].Action
			m.Close()
			return m, a, true
		}
	default:
		// Item hotkey letters ("&Open").
		if k.Type == tea.KeyRunes && len(k.Runes) == 1 {
			r := toLower(k.Runes[0])
			for j, it := range m.Menus[m.cur].Items {
				if _, _, h := ParseHotkey(it.Label); h == r && m.selectable(j) {
					m.Close()
					return m, it.Action, true
				}
			}
		}
	}
	return m, "", true
}

func (m MenuBar) updateMouse(ev tea.MouseMsg) (MenuBar, string, bool) {
	click := IsLeftClick(ev)
	motion := IsMotion(ev)
	// Titles.
	for i := range m.Menus {
		if !Hit(m.titleID(i), ev) {
			continue
		}
		switch {
		case click:
			if m.open && m.cur == i {
				m.Close()
			} else {
				m.Open(i)
			}
			return m, "", true
		case motion && m.open && m.cur != i:
			m.Open(i)
			return m, "", true
		}
		return m, "", m.open || click
	}
	if !m.open {
		return m, "", false
	}
	// Items of the open menu.
	for j := range m.Menus[m.cur].Items {
		if !Hit(m.itemID(m.cur, j), ev) {
			continue
		}
		if click && m.selectable(j) {
			a := m.Menus[m.cur].Items[j].Action
			m.Close()
			return m, a, true
		}
		if motion && m.selectable(j) {
			m.sel = j
		}
		return m, "", true
	}
	if click || ev.Button == tea.MouseButtonRight && ev.Action == tea.MouseActionPress {
		m.Close()
	}
	return m, "", true
}

// View renders the 1-line menu bar, width cells wide.
func (m MenuBar) View(width int) string {
	th := m.Theme
	var b strings.Builder
	b.WriteString(th.MenuBar.Render(" "))
	for i, mn := range m.Menus {
		text, idx, _ := ParseHotkey(mn.Title)
		base, hot := th.MenuItem, th.MenuHotkey
		if m.open && m.cur == i {
			base, hot = th.MenuItemActive, th.MenuHotkeyActive
		}
		t := base.Render(" ") + renderHot(text, idx, base, hot) + base.Render(" ")
		b.WriteString(Mark(m.titleID(i), t))
		if i < len(m.Menus)-1 {
			b.WriteString(th.MenuBar.Render(" "))
		}
	}
	out := b.String()
	if ansi.StringWidth(out) > width {
		return ansi.Truncate(out, width, "")
	}
	return padRight(out, width, th.MenuBar)
}

// DropdownView renders the open dropdown box. It returns "" when closed. The
// app overlays it at (x, y) on the full screen (y is always 1, just below the
// bar). See DropdownViewAt to clamp x to the screen width.
func (m MenuBar) DropdownView() (view string, x, y int) {
	if !m.open || m.cur < 0 || m.cur >= len(m.Menus) {
		return "", 0, 0
	}
	th := m.Theme
	items := m.Menus[m.cur].Items
	hasCheck := false
	lw, hw := 0, 0
	for _, it := range items {
		if it.Checked != nil {
			hasCheck = true
		}
		t, _, _ := ParseHotkey(it.Label)
		lw = max(lw, ansi.StringWidth(t))
		hw = max(hw, ansi.StringWidth(it.Hotkey))
	}
	checkW := 0
	if hasCheck {
		checkW = 2
	}
	gap := 0
	if hw > 0 {
		gap = 3
	}
	iw := 1 + checkW + lw + gap + hw + 1
	iw = max(iw, 12)

	bs := th.Dropdown
	lines := make([]string, 0, len(items)+2)
	lines = append(lines, bs.Render("┌"+strings.Repeat("─", iw)+"┐"))
	for j, it := range items {
		if it.Separator {
			lines = append(lines, th.DropdownSeparator.Render("├"+strings.Repeat("─", iw)+"┤"))
			continue
		}
		st, hs := th.DropdownItem, th.DropdownHotkey
		switch {
		case it.Disabled:
			st, hs = th.DropdownDisabled, th.DropdownDisabled
		case j == m.sel:
			st, hs = th.DropdownItemActive, th.DropdownHotkeyActive
		}
		text, idx, _ := ParseHotkey(it.Label)
		var c strings.Builder
		c.WriteString(st.Render(" "))
		if hasCheck {
			mark := "  "
			if it.Checked != nil && *it.Checked {
				mark = "✓ "
			}
			c.WriteString(st.Render(mark))
		}
		hot := st.Underline(true)
		if !it.Disabled {
			hot = hot.Bold(true)
		}
		c.WriteString(renderHot(text, idx, st, hot))
		used := 1 + checkW + ansi.StringWidth(text)
		hk := it.Hotkey
		fill := iw - used - ansi.StringWidth(hk) - 1
		c.WriteString(st.Render(strings.Repeat(" ", max(0, fill))))
		c.WriteString(hs.Render(hk))
		c.WriteString(st.Render(" "))
		lines = append(lines, bs.Render("│")+Mark(m.itemID(m.cur, j), c.String())+bs.Render("│"))
	}
	lines = append(lines, bs.Render("└"+strings.Repeat("─", iw)+"┘"))
	return strings.Join(lines, "\n"), m.titleX(m.cur) - 1, 1
}

// DropdownViewAt is DropdownView with x clamped so the box fits in screenWidth.
func (m MenuBar) DropdownViewAt(screenWidth int) (view string, x, y int) {
	v, x, y := m.DropdownView()
	if v == "" {
		return v, x, y
	}
	w := maxWidth(strings.Split(v, "\n"))
	if x+w > screenWidth {
		x = max(0, screenWidth-w)
	}
	return v, x, y
}
