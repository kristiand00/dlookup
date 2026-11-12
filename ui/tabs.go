package ui

import (
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
)

// Tab describes one tab of a TabBar.
type Tab struct {
	Title    string
	Badge    string // e.g. "●" when the tab changed; "" for none
	Closable bool
}

// TabBar renders a clickable tab strip. It is stateless: the app owns the tab
// list and active index.
//
// Zone ids: ID+"-t-<i>" tab title, ID+"-x-<i>" close button, ID+"-new" the
// [+] button, ID+"-prev"/ID+"-next" the scroll indicators, ID+"-bar" the
// whole line (for wheel events).
type TabBar struct {
	ID    string
	Theme Theme
}

// TabEvent is the kind of mouse interaction on a TabBar.
type TabEvent int

const (
	TabNone  TabEvent = iota
	TabClick          // select tab idx
	TabClose          // close tab idx (click on ×, or middle-click on a tab)
	TabNew            // [+] clicked
	TabPrev           // wheel up over the bar, or ‹ clicked
	TabNext           // wheel down over the bar, or › clicked
)

const (
	tabAdd      = " [+]"
	tabScrollL  = "‹ "
	tabScrollR  = " ›"
	tabMinTitle = 4
	// tabScrollTitle caps titles when the bar scrolls (shrinking further
	// would only make every title unreadable).
	tabScrollTitle = 16
)

func (t TabBar) tabID(i int) string   { return t.ID + "-t-" + strconv.Itoa(i) }
func (t TabBar) closeID(i int) string { return t.ID + "-x-" + strconv.Itoa(i) }

// tabWidth is the rendered width of a tab with its title capped at tw cells.
func tabWidth(tb Tab, tw int) int {
	w := 2 + min(ansi.StringWidth(tb.Title), tw)
	if tb.Badge != "" {
		w += ansi.StringWidth(tb.Badge) + 1
	}
	if tb.Closable {
		w += 2
	}
	return w
}

func rangeWidth(tabs []Tab, from, to, tw int) int {
	w := 0
	for i := from; i < to; i++ {
		if i > from {
			w++ // gap
		}
		w += tabWidth(tabs[i], tw)
	}
	return w
}

// layout picks the title cap and the visible window [start, end).
func (t TabBar) layout(tabs []Tab, active, width int) (tw, start, end int) {
	n := len(tabs)
	avail := width - ansi.StringWidth(tabAdd)
	maxT := 0
	for _, tb := range tabs {
		maxT = max(maxT, ansi.StringWidth(tb.Title))
	}
	// Shrink titles until everything fits or we hit the minimum.
	for tw = maxT; tw > tabMinTitle && rangeWidth(tabs, 0, n, tw) > avail; tw-- {
	}
	if rangeWidth(tabs, 0, n, tw) <= avail {
		return tw, 0, n
	}
	// Scrolling: titles keep a readable cap; reserve room for indicators.
	tw = min(maxT, tabScrollTitle)
	avail -= ansi.StringWidth(tabScrollL) + ansi.StringWidth(tabScrollR)
	start, end = 0, 0
	for end < n && rangeWidth(tabs, 0, end+1, tw) <= avail {
		end++
	}
	if active < end {
		return tw, 0, max(end, min(1, n))
	}
	start, end = active, active+1
	for start > 0 && rangeWidth(tabs, start-1, end, tw) <= avail {
		start--
	}
	for end < n && rangeWidth(tabs, start, end+1, tw) <= avail {
		end++
	}
	return tw, start, end
}

// View renders the 1-line tab bar: tabs (titles truncated to fit, with ‹ ›
// indicators when not all tabs fit — the active tab is always visible) and a
// trailing "[+]" new-tab button.
func (t TabBar) View(tabs []Tab, active, width int) string {
	th := t.Theme
	tw, start, end := t.layout(tabs, active, width)
	scrolling := start > 0 || end < len(tabs)
	var b strings.Builder
	if scrolling {
		ind := tabScrollL
		if start == 0 {
			ind = strings.Repeat(" ", ansi.StringWidth(tabScrollL))
		}
		b.WriteString(Mark(t.ID+"-prev", th.TabScroll.Render(ind)))
	}
	for i := start; i < end; i++ {
		tb := tabs[i]
		st := th.TabInactive
		if i == active {
			st = th.TabActive
		}
		bg := st.GetBackground()
		title := st.Render(" " + truncPlain(tb.Title, tw) + " ")
		if tb.Badge != "" {
			title += th.TabBadge.Background(bg).Render(tb.Badge) + st.Render(" ")
		}
		b.WriteString(Mark(t.tabID(i), title))
		if tb.Closable {
			b.WriteString(Mark(t.closeID(i), th.TabClose.Background(bg).Render("×")))
			b.WriteString(st.Render(" "))
		}
		if i < end-1 {
			b.WriteString(th.TabBar.Render(" "))
		}
	}
	if scrolling {
		ind := tabScrollR
		if end == len(tabs) {
			ind = strings.Repeat(" ", ansi.StringWidth(tabScrollR))
		}
		b.WriteString(Mark(t.ID+"-next", th.TabScroll.Render(ind)))
	}
	b.WriteString(Mark(t.ID+"-new", th.TabAdd.Render(tabAdd)))
	out := b.String()
	if ansi.StringWidth(out) > width {
		out = ansi.Truncate(out, width, "")
	}
	return Mark(t.ID+"-bar", padRight(out, width, th.TabBar))
}

// HandleMouse maps a mouse event to a TabEvent. n is the number of tabs.
// Left click on a title → TabClick, on × → TabClose, middle click on a tab →
// TabClose, [+] → TabNew, ‹/› or wheel over the bar → TabPrev/TabNext. The
// returned index is the tab concerned (-1 when not applicable).
func (t TabBar) HandleMouse(msg tea.MouseMsg, n int) (TabEvent, int) {
	if !Hit(t.ID+"-bar", msg) {
		return TabNone, -1
	}
	switch {
	case IsWheelUp(msg) || msg.Button == tea.MouseButtonWheelLeft:
		return TabPrev, -1
	case IsWheelDown(msg) || msg.Button == tea.MouseButtonWheelRight:
		return TabNext, -1
	}
	if msg.Action != tea.MouseActionPress {
		return TabNone, -1
	}
	if msg.Button == tea.MouseButtonMiddle {
		for i := 0; i < n; i++ {
			if Hit(t.tabID(i), msg) || Hit(t.closeID(i), msg) {
				return TabClose, i
			}
		}
		return TabNone, -1
	}
	if msg.Button != tea.MouseButtonLeft {
		return TabNone, -1
	}
	for i := 0; i < n; i++ {
		if Hit(t.closeID(i), msg) {
			return TabClose, i
		}
		if Hit(t.tabID(i), msg) {
			return TabClick, i
		}
	}
	switch {
	case Hit(t.ID+"-new", msg):
		return TabNew, -1
	case Hit(t.ID+"-prev", msg):
		return TabPrev, -1
	case Hit(t.ID+"-next", msg):
		return TabNext, -1
	}
	return TabNone, -1
}
