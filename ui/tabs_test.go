package ui

import (
	"fmt"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
)

func mkTabs(n int, title string) []Tab {
	tabs := make([]Tab, n)
	for i := range tabs {
		tabs[i] = Tab{Title: fmt.Sprintf("%s%d", title, i), Closable: true}
	}
	return tabs
}

func TestTabBarFitsAndTruncates(t *testing.T) {
	tb := TabBar{ID: "tt", Theme: DefaultTheme()}
	tabs := mkTabs(3, "a-very-long-domain-name.example.com-")
	tabs[1].Badge = "●"
	v := tb.View(tabs, 0, 60)
	if w := ansi.StringWidth(v); w != 60 {
		t.Fatalf("width %d", w)
	}
	plain := ansi.Strip(v)
	if !strings.Contains(plain, "…") || !strings.Contains(plain, "[+]") || !strings.Contains(plain, "●") {
		t.Fatalf("expected truncated titles, badge and [+]: %q", plain)
	}
	if strings.Contains(plain, "‹") || strings.Contains(plain, "›") {
		t.Fatalf("should fit without scrolling: %q", plain)
	}
	if strings.Count(plain, "×") != 3 {
		t.Fatalf("close buttons: %q", plain)
	}
}

func TestTabBarScrollKeepsActiveVisible(t *testing.T) {
	tb := TabBar{ID: "ts", Theme: DefaultTheme()}
	tabs := mkTabs(20, "tab")
	for _, active := range []int{0, 7, 19} {
		v := tb.View(tabs, active, 50)
		if w := ansi.StringWidth(v); w != 50 {
			t.Fatalf("width %d", w)
		}
		plain := ansi.Strip(v)
		if !strings.Contains(plain, fmt.Sprintf("tab%d ", active)) {
			t.Fatalf("active %d not visible: %q", active, plain)
		}
		if active == 0 && !strings.Contains(plain, "›") {
			t.Fatalf("missing › : %q", plain)
		}
		if active == 19 && !strings.Contains(plain, "‹") {
			t.Fatalf("missing ‹ : %q", plain)
		}
	}
}

func TestTabBarMouse(t *testing.T) {
	tb := TabBar{ID: "tm", Theme: DefaultTheme()}
	tabs := mkTabs(3, "site")
	scan(t, "header\n"+tb.View(tabs, 0, 60))
	if ev, i := tb.HandleMouse(clickZone(t, "tm-t-1", 1), 3); ev != TabClick || i != 1 {
		t.Fatalf("click: %v %d", ev, i)
	}
	if ev, i := tb.HandleMouse(clickZone(t, "tm-x-2", 0), 3); ev != TabClose || i != 2 {
		t.Fatalf("close: %v %d", ev, i)
	}
	mid := clickZone(t, "tm-t-0", 1)
	mid.Button = tea.MouseButtonMiddle
	if ev, i := tb.HandleMouse(mid, 3); ev != TabClose || i != 0 {
		t.Fatalf("middle close: %v %d", ev, i)
	}
	if ev, _ := tb.HandleMouse(clickZone(t, "tm-new", 2), 3); ev != TabNew {
		t.Fatalf("new: %v", ev)
	}
	if ev, _ := tb.HandleMouse(mouseAt(55, 1, tea.MouseButtonWheelUp, tea.MouseActionPress), 3); ev != TabPrev {
		t.Fatalf("wheel up: %v", ev)
	}
	if ev, _ := tb.HandleMouse(mouseAt(55, 1, tea.MouseButtonWheelDown, tea.MouseActionPress), 3); ev != TabNext {
		t.Fatalf("wheel down: %v", ev)
	}
	if ev, _ := tb.HandleMouse(mouseAt(5, 0, tea.MouseButtonWheelDown, tea.MouseActionPress), 3); ev != TabNone {
		t.Fatalf("wheel outside bar: %v", ev)
	}
	rel := clickZone(t, "tm-t-1", 1)
	rel.Action = tea.MouseActionRelease
	if ev, _ := tb.HandleMouse(rel, 3); ev != TabNone {
		t.Fatalf("release should be ignored: %v", ev)
	}
}

func TestFKeyBar(t *testing.T) {
	fb := FKeyBar{ID: "fk", Theme: DefaultTheme()}
	keys := []FKey{
		{Key: "f1", Num: "1", Label: "Help", Action: "help"},
		{Key: "f2", Num: "2", Label: "New", Action: "new"},
		{Key: "f3", Num: "3", Label: "Off", Action: "off", Disabled: true},
		{Key: "f10", Num: "10", Label: "Quit", Action: "quit"},
	}
	for _, w := range []int{23, 80, 81} {
		if got := ansi.StringWidth(fb.View(keys, w)); got != w {
			t.Fatalf("width %d: %d", w, got)
		}
	}
	v := fb.View(keys, 80)
	if !strings.HasPrefix(ansi.Strip(v), "1Help") {
		t.Fatalf("layout: %q", ansi.Strip(v))
	}
	scan(t, "x\n"+v)
	if a := fb.HandleMouse(clickZone(t, "fk-k-1", 5), keys); a != "new" {
		t.Fatalf("click: %q", a)
	}
	if a := fb.HandleMouse(clickZone(t, "fk-k-2", 1), keys); a != "" {
		t.Fatalf("disabled click: %q", a)
	}
	if a := fb.HandleMouse(clickZone(t, "fk-k-3", 0), keys); a != "quit" {
		t.Fatalf("click num: %q", a)
	}
	if a := fb.KeyAction(key(tea.KeyF10), keys); a != "quit" {
		t.Fatalf("key: %q", a)
	}
}
