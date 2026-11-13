package ui

import (
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
)

// DoubleClickInterval is the max delay between two presses on the same item
// to count as a double-click.
var DoubleClickInterval = 500 * time.Millisecond

// now is replaceable in tests.
var now = time.Now

// ListItem is one row of a List.
type ListItem struct {
	Title, Desc, Value string
	Disabled           bool
}

// List is a scrollable single-line-per-item list. Mouse: click selects,
// double-click activates, wheel scrolls. Keys: up/down/k/j, home/end, pgup/pgdn,
// enter activates.
//
// Zone ids: ID+"-list" whole list, ID+"-r-<i>" row i.
type List struct {
	ID    string
	Items []ListItem
	Theme Theme

	cursor    int
	offset    int
	lastClick time.Time
	lastIdx   int
}

// NewList creates a list with the cursor on the first enabled item.
func NewList(id string, items []ListItem, th Theme) List {
	l := List{ID: id, Items: items, Theme: th, lastIdx: -1}
	l.cursor = l.nextEnabled(-1, 1)
	if l.cursor < 0 {
		l.cursor = 0
	}
	return l
}

// Cursor returns the selected index.
func (l List) Cursor() int { return l.cursor }

// Offset returns the index of the first visible row.
func (l List) Offset() int { return l.offset }

// Selected returns the selected item, or nil if the list is empty.
func (l List) Selected() *ListItem {
	if l.cursor < 0 || l.cursor >= len(l.Items) {
		return nil
	}
	it := l.Items[l.cursor]
	return &it
}

// SetCursor moves the cursor (clamped). The view scrolls on the next Update/View.
func (l *List) SetCursor(i int) { l.cursor = clamp(i, 0, len(l.Items)-1) }

// SetItems replaces the items, keeping the cursor in range.
func (l *List) SetItems(items []ListItem) {
	l.Items = items
	l.cursor = clamp(l.cursor, 0, len(items)-1)
	l.offset = clamp(l.offset, 0, max(0, len(items)-1))
}

func (l List) nextEnabled(from, dir int) int {
	for i := from + dir; i >= 0 && i < len(l.Items); i += dir {
		if !l.Items[i].Disabled {
			return i
		}
	}
	return -1
}

func (l *List) move(to, dir int) {
	if len(l.Items) == 0 {
		return
	}
	to = clamp(to, 0, len(l.Items)-1)
	if !l.Items[to].Disabled {
		l.cursor = to
		return
	}
	if i := l.nextEnabled(to, dir); i >= 0 {
		l.cursor = i
	} else if i := l.nextEnabled(to, -dir); i >= 0 {
		l.cursor = i
	}
}

// scrollToCursor keeps the cursor inside the viewport of height rows.
func (l *List) scrollToCursor(height int) {
	height = max(1, height)
	if l.cursor < l.offset {
		l.offset = l.cursor
	}
	if l.cursor >= l.offset+height {
		l.offset = l.cursor - height + 1
	}
	l.offset = clamp(l.offset, 0, max(0, len(l.Items)-height))
}

func (l List) rowID(i int) string { return l.ID + "-r-" + strconv.Itoa(i) }

// Update handles input. height is the viewport height in rows (same as passed
// to View). Returns the activated item (enter / double-click) and whether the
// message was consumed.
func (l List) Update(msg tea.Msg, width, height int) (List, *ListItem, bool) {
	_ = width
	l.offset = l.viewOffset(height)
	switch msg := msg.(type) {
	case tea.KeyMsg:
		consumed := true
		switch msg.String() {
		case "up", "k":
			l.move(l.cursor-1, -1)
		case "down", "j":
			l.move(l.cursor+1, 1)
		case "home", "g":
			l.move(0, 1)
		case "end", "G":
			l.move(len(l.Items)-1, -1)
		case "pgup":
			l.move(l.cursor-max(1, height-1), -1)
		case "pgdown":
			l.move(l.cursor+max(1, height-1), 1)
		case "enter":
			if it := l.Selected(); it != nil && !it.Disabled {
				return l, it, true
			}
		default:
			consumed = false
		}
		l.scrollToCursor(height)
		return l, nil, consumed

	case tea.MouseMsg:
		if !Hit(l.ID+"-list", msg) {
			return l, nil, false
		}
		maxOff := max(0, len(l.Items)-max(1, height))
		switch {
		case IsWheelUp(msg):
			l.offset = clamp(l.offset-3, 0, maxOff)
			l.cursorIntoView(height)
			return l, nil, true
		case IsWheelDown(msg):
			l.offset = clamp(l.offset+3, 0, maxOff)
			l.cursorIntoView(height)
			return l, nil, true
		case IsLeftClick(msg):
			for i := l.offset; i < len(l.Items) && i < l.offset+height; i++ {
				if !Hit(l.rowID(i), msg) {
					continue
				}
				if l.Items[i].Disabled {
					return l, nil, true
				}
				t := now()
				double := l.lastIdx == i && t.Sub(l.lastClick) <= DoubleClickInterval
				l.cursor = i
				if double {
					l.lastIdx = -1
					it := l.Items[i]
					return l, &it, true
				}
				l.lastIdx, l.lastClick = i, t
				return l, nil, true
			}
			return l, nil, true
		}
		return l, nil, true
	}
	return l, nil, false
}

// viewOffset is the offset View uses: l.offset adjusted to show the cursor.
func (l List) viewOffset(height int) int {
	height = max(1, height)
	off := l.offset
	if l.cursor < off {
		off = l.cursor
	}
	if l.cursor >= off+height {
		off = l.cursor - height + 1
	}
	return clamp(off, 0, max(0, len(l.Items)-height))
}

// cursorIntoView moves the cursor (not the viewport) after wheel scrolling.
func (l *List) cursorIntoView(height int) {
	height = max(1, height)
	if l.cursor < l.offset {
		l.move(l.offset, 1)
	} else if l.cursor >= l.offset+height {
		l.move(l.offset+height-1, -1)
	}
}

// View renders exactly height rows of width cells. A scrollbar is drawn in the
// last column when the items don't fit.
func (l List) View(width, height int) string {
	if width <= 0 || height <= 0 {
		return ""
	}
	th := l.Theme
	off := l.viewOffset(height)
	scroll := len(l.Items) > height
	rw := width
	if scroll {
		rw--
	}
	thumbStart, thumbLen := 0, 0
	if scroll {
		thumbLen = max(1, height*height/len(l.Items))
		thumbStart = (height - thumbLen) * off / max(1, len(l.Items)-height)
	}
	rows := make([]string, height)
	for r := 0; r < height; r++ {
		i := off + r
		var row string
		if i < len(l.Items) {
			it := l.Items[i]
			st, ds := th.ListItem, th.ListDesc
			switch {
			case it.Disabled:
				st, ds = th.ListDisabled, th.ListDisabled
			case i == l.cursor:
				st, ds = th.ListItemActive, th.ListDescActive
			}
			title := truncPlain(it.Title, max(0, rw-2))
			row = st.Render(" " + title)
			used := 1 + ansi.StringWidth(title)
			if it.Desc != "" && rw-used > 3 {
				d := truncPlain(it.Desc, rw-used-3)
				row += st.Render("  ") + ds.Render(d)
				used += 2 + ansi.StringWidth(d)
			}
			row += st.Render(strings.Repeat(" ", max(0, rw-used)))
			row = Mark(l.rowID(i), row)
		} else {
			row = strings.Repeat(" ", rw)
		}
		if scroll {
			if r >= thumbStart && r < thumbStart+thumbLen {
				row += th.TabScroll.Render("█")
			} else {
				row += th.ListDesc.Render("│")
			}
		}
		rows[r] = row
	}
	return Mark(l.ID+"-list", strings.Join(rows, "\n"))
}
