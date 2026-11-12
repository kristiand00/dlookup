package ui

import (
	"fmt"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
)

func mkItems(n int) []ListItem {
	items := make([]ListItem, n)
	for i := range items {
		items[i] = ListItem{Title: fmt.Sprintf("item %d", i), Desc: "desc", Value: fmt.Sprint(i)}
	}
	return items
}

func TestListKeys(t *testing.T) {
	items := mkItems(20)
	items[1].Disabled = true
	l := NewList("lk", items, DefaultTheme())
	l, _, ok := l.Update(key(tea.KeyDown), 30, 5)
	if !ok || l.Cursor() != 2 {
		t.Fatalf("down skips disabled: %d", l.Cursor())
	}
	l, _, _ = l.Update(key(tea.KeyEnd), 30, 5)
	if l.Cursor() != 19 || l.Offset() != 15 {
		t.Fatalf("end: cursor %d off %d", l.Cursor(), l.Offset())
	}
	l, it, _ := l.Update(key(tea.KeyEnter), 30, 5)
	if it == nil || it.Value != "19" {
		t.Fatalf("enter: %v", it)
	}
	_, _, ok = l.Update(keyRunes("x"), 30, 5)
	if ok {
		t.Fatal("unknown key consumed")
	}
	v := l.View(30, 5)
	if lines := strings.Split(v, "\n"); len(lines) != 5 || ansi.StringWidth(lines[0]) != 30 {
		t.Fatalf("view size: %d lines, w=%d", len(lines), ansi.StringWidth(lines[0]))
	}
	if !strings.Contains(ansi.Strip(v), "item 19") {
		t.Fatal("cursor row not visible")
	}
}

func TestListMouse(t *testing.T) {
	cur := time.Unix(1000, 0)
	now = func() time.Time { return cur }
	defer func() { now = time.Now }()

	l := NewList("lm", mkItems(30), DefaultTheme())
	const w, h = 30, 6
	render := func() { scan(t, "top\n"+l.View(w, h)) }
	render()

	var ok bool
	l, _, ok = l.Update(mouseAt(3, 2, tea.MouseButtonWheelDown, tea.MouseActionPress), w, h)
	if !ok || l.Offset() != 3 || l.Cursor() != 3 {
		t.Fatalf("wheel down: off %d cursor %d", l.Offset(), l.Cursor())
	}
	render()
	l, _, _ = l.Update(mouseAt(3, 2, tea.MouseButtonWheelUp, tea.MouseActionPress), w, h)
	if l.Offset() != 0 {
		t.Fatalf("wheel up: off %d", l.Offset())
	}
	render()
	var act *ListItem
	l, act, ok = l.Update(clickZone(t, "lm-r-4", 2), w, h)
	if !ok || act != nil || l.Cursor() != 4 {
		t.Fatalf("click: cursor %d act %v", l.Cursor(), act)
	}
	cur = cur.Add(200 * time.Millisecond)
	l, act, _ = l.Update(clickZone(t, "lm-r-4", 2), w, h)
	if act == nil || act.Value != "4" {
		t.Fatalf("double-click: %v", act)
	}
	// Slow second click is not a double click.
	l, _, _ = l.Update(clickZone(t, "lm-r-2", 2), w, h)
	cur = cur.Add(2 * time.Second)
	l, act, _ = l.Update(clickZone(t, "lm-r-2", 2), w, h)
	if act != nil {
		t.Fatal("slow clicks activated")
	}
	// Outside the list: not consumed.
	_, _, ok = l.Update(mouseAt(3, 0, tea.MouseButtonLeft, tea.MouseActionPress), w, h)
	if ok {
		t.Fatal("click outside consumed")
	}
}
