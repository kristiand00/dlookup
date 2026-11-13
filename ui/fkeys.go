package ui

import (
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
)

// FKey is one slot of the bottom function-key bar.
type FKey struct {
	Key      string // key name as reported by tea.KeyMsg.String(), e.g. "f1"
	Num      string // shown highlighted, e.g. "1"
	Label    string
	Action   string
	Disabled bool
}

// FKeyBar renders the MC-style "1Help 2Menu ..." bar. Stateless.
// Zone ids: ID+"-k-<i>".
type FKeyBar struct {
	ID    string
	Theme Theme
}

func (f FKeyBar) keyID(i int) string { return f.ID + "-k-" + strconv.Itoa(i) }

// View spreads keys evenly across width (remainder cells go to the first slots).
func (f FKeyBar) View(keys []FKey, width int) string {
	if len(keys) == 0 || width <= 0 {
		return strings.Repeat(" ", max(0, width))
	}
	th := f.Theme
	n := len(keys)
	base, rem := width/n, width%n
	var b strings.Builder
	for i, k := range keys {
		sw := base
		if i < rem {
			sw++
		}
		numW := ansi.StringWidth(k.Num)
		lw := max(0, sw-numW)
		ls := th.FKeyLabel
		if k.Disabled {
			ls = th.FKeyDisabled
		}
		num := k.Num
		if numW > sw {
			num = ansi.Truncate(num, sw, "")
		}
		slot := th.FKeyNum.Render(num)
		if lw > 0 {
			slot += ls.Render(fitPlain(k.Label, lw))
		}
		b.WriteString(Mark(f.keyID(i), slot))
	}
	return b.String()
}

// HandleMouse returns the action of the clicked (enabled) key, or "".
func (f FKeyBar) HandleMouse(msg tea.MouseMsg, keys []FKey) string {
	if !IsLeftClick(msg) {
		return ""
	}
	for i, k := range keys {
		if Hit(f.keyID(i), msg) {
			if k.Disabled {
				return ""
			}
			return k.Action
		}
	}
	return ""
}

// KeyAction returns the action bound to the pressed key (matching FKey.Key
// against msg.String()), or "" if none / disabled.
func (f FKeyBar) KeyAction(msg tea.KeyMsg, keys []FKey) string {
	s := msg.String()
	for _, k := range keys {
		if k.Key == s && !k.Disabled {
			return k.Action
		}
	}
	return ""
}
