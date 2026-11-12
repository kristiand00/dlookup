package ui

import (
	"errors"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
)

func testDialog(id string) Dialog {
	return NewDialog(id, "New lookup", []Field{
		{Key: "domain", Label: "&Domain", Placeholder: "example.com", Validate: func(s string) error {
			if s == "" {
				return errors.New("domain required")
			}
			return nil
		}},
		{Label: "Server", Kind: FieldInfo, Value: "1.1.1.1"},
		{Key: "type", Label: "&Type", Kind: FieldSelect, Value: "A", Options: []Option{
			{"A", "A"}, {"AAAA", "AAAA"}, {"MX", "MX"}, {"TXT", "TXT"}, {"CNAME", "CNAME"},
		}},
		{Key: "rec", Label: "&Recursive", Kind: FieldCheckbox},
	}, []Button{{Label: "&OK", Action: "ok", Default: true}, {Label: "&Cancel", Action: "cancel"}}, DefaultTheme())
}

func typeStr(d Dialog, s string) Dialog {
	for _, r := range s {
		d, _, _ = d.Update(keyRunes(string(r)))
	}
	return d
}

func TestDialogFocusAndTyping(t *testing.T) {
	d := testDialog("dk")
	if d.Focused() != "domain" {
		t.Fatalf("initial focus %q", d.Focused())
	}
	d = typeStr(d, "example.org")
	if d.Value("domain") != "example.org" {
		t.Fatalf("typed %q", d.Value("domain"))
	}
	d, _, _ = d.Update(key(tea.KeyTab)) // skips info field
	if d.Focused() != "type" {
		t.Fatalf("tab -> %q", d.Focused())
	}
	d, _, _ = d.Update(key(tea.KeyDown))
	if d.Focused() != "rec" {
		t.Fatalf("down -> %q", d.Focused())
	}
	d, _, _ = d.Update(keyRunes(" "))
	if d.Value("rec") != "true" {
		t.Fatal("space should toggle checkbox")
	}
	d, _, _ = d.Update(key(tea.KeyTab))
	if d.focusedButton() != 0 {
		t.Fatal("focus should reach OK button")
	}
	d, _, _ = d.Update(key(tea.KeyShiftTab))
	d, _, _ = d.Update(key(tea.KeyUp))
	if d.Focused() != "type" {
		t.Fatalf("back -> %q", d.Focused())
	}
	// Wraps from first to last.
	d.FocusField("domain")
	d, _, _ = d.Update(key(tea.KeyShiftTab))
	if d.focusedButton() != 1 {
		t.Fatal("shift+tab should wrap to last button")
	}
	// alt+hotkey focuses a field.
	d, _, _ = d.Update(keyAlt('t'))
	if d.Focused() != "type" {
		t.Fatalf("alt+t -> %q", d.Focused())
	}
}

func TestDialogSubmitAndValidation(t *testing.T) {
	d := testDialog("dv")
	d.FocusField("type")
	d, _, _ = d.Update(key(tea.KeyTab)) // rec
	d, res, _ := d.Update(key(tea.KeyEnter))
	if res != nil {
		t.Fatal("validation should fail")
	}
	if d.Err != "domain required" || d.Focused() != "domain" {
		t.Fatalf("err=%q focus=%q", d.Err, d.Focused())
	}
	if !strings.Contains(ansi.Strip(d.View()), "domain required") {
		t.Fatal("error not rendered")
	}
	d = typeStr(d, "x.com")
	d, res, _ = d.Update(key(tea.KeyEnter)) // enter in text field -> default button
	if res == nil || res.Action != "ok" || res.Values["domain"] != "x.com" || res.Values["type"] != "A" || res.Values["rec"] != "false" {
		t.Fatalf("result %+v", res)
	}
	if d.Err != "" {
		t.Fatal("err not cleared")
	}
	// Esc cancels without validation.
	d2 := testDialog("dv2")
	_, res, _ = d2.Update(key(tea.KeyEsc))
	if res == nil || res.Action != ActionCancel {
		t.Fatalf("esc: %+v", res)
	}
	// alt+c presses Cancel.
	_, res, _ = d2.Update(keyAlt('c'))
	if res == nil || res.Action != "cancel" {
		t.Fatalf("alt+c: %+v", res)
	}
	// SetValue.
	d2.SetValue("domain", "set.me")
	d2.SetValue("rec", "true")
	if d2.Value("domain") != "set.me" || d2.Value("rec") != "true" {
		t.Fatal("SetValue")
	}
}

func TestDialogDropdownKeys(t *testing.T) {
	d := testDialog("dd")
	d.FocusField("type")
	d, _, _ = d.Update(key(tea.KeyEnter))
	if !d.DropdownOpen() {
		t.Fatal("enter should open dropdown")
	}
	d, _, _ = d.Update(key(tea.KeyDown))
	d, _, _ = d.Update(key(tea.KeyDown))
	d, _, _ = d.Update(key(tea.KeyEnter))
	if d.DropdownOpen() || d.Value("type") != "MX" {
		t.Fatalf("select: open=%v val=%q", d.DropdownOpen(), d.Value("type"))
	}
	// Esc closes only the dropdown.
	d, _, _ = d.Update(keyRunes(" "))
	d, res, _ := d.Update(key(tea.KeyEsc))
	if res != nil || d.DropdownOpen() {
		t.Fatal("esc should only close dropdown")
	}
	// Type-to-filter (typing on a closed select opens it filtered).
	d = typeStr(d, "na")
	if !d.DropdownOpen() || d.ddFilter != "na" {
		t.Fatalf("filter: open=%v %q", d.DropdownOpen(), d.ddFilter)
	}
	if !strings.Contains(ansi.Strip(d.View()), "/na") {
		t.Fatal("filter not shown")
	}
	d, _, _ = d.Update(key(tea.KeyEnter))
	if d.Value("type") != "CNAME" {
		t.Fatalf("filtered select: %q", d.Value("type"))
	}
	// Backspace widens the filter; end selects last.
	d = typeStr(d, "aa")
	d, _, _ = d.Update(key(tea.KeyBackspace))
	d, _, _ = d.Update(key(tea.KeyEnd))
	d, _, _ = d.Update(key(tea.KeyEnter))
	if d.Value("type") != "CNAME" {
		t.Fatalf("backspace/end: %q", d.Value("type"))
	}
}

func TestDialogMouse(t *testing.T) {
	d := testDialog("dm")
	screen := func() {
		scan(t, d.Render(strings.Repeat(strings.Repeat(".", 80)+"\n", 23)+strings.Repeat(".", 80), 80, 24))
	}
	screen()
	var res *DialogResult
	// Click checkbox toggles + focuses.
	d, _, _ = d.Update(clickZone(t, "dm-f-3", 1))
	if d.Value("rec") != "true" || d.Focused() != "rec" {
		t.Fatalf("checkbox click: %q %q", d.Value("rec"), d.Focused())
	}
	screen()
	// Click select opens dropdown; click option selects.
	d, _, _ = d.Update(clickZone(t, "dm-fb-2", 1))
	if !d.DropdownOpen() {
		t.Fatal("click select should open")
	}
	screen()
	d, _, _ = d.Update(clickZone(t, "dm-o-3", 1))
	if d.DropdownOpen() || d.Value("type") != "TXT" {
		t.Fatalf("option click: %q", d.Value("type"))
	}
	// Wheel scrolls an open dropdown (5 options > visible? use small max).
	d.Fields[2].Options = append(d.Fields[2].Options, Option{"NS", "NS"}, Option{"SOA", "SOA"}, Option{"SRV", "SRV"}, Option{"PTR", "PTR"}, Option{"CAA", "CAA"})
	d.FocusField("type")
	d, _, _ = d.Update(key(tea.KeyEnter))
	screen()
	x, y, _, _, _ := ZonePos("dm-dd")
	d, _, _ = d.Update(mouseAt(x+2, y+2, tea.MouseButtonWheelDown, tea.MouseActionPress))
	if d.ddOff != 1 {
		t.Fatalf("wheel: off %d", d.ddOff)
	}
	// Click outside closes dropdown (and does not cancel the dialog).
	screen()
	d, res, _ = d.Update(mouseAt(0, 0, tea.MouseButtonLeft, tea.MouseActionPress))
	if d.DropdownOpen() || res != nil {
		t.Fatal("outside click should only close dropdown")
	}
	// Click text field focuses it.
	screen()
	d, _, _ = d.Update(clickZone(t, "dm-fb-0", 0))
	if d.Focused() != "domain" {
		t.Fatalf("text click focus: %q", d.Focused())
	}
	d = typeStr(d, "abc")
	// Click OK button.
	screen()
	_, res, _ = d.Update(clickZone(t, "dm-b-0", 1))
	if res == nil || res.Action != "ok" || res.Values["domain"] != "abc" || res.Values["type"] != "TXT" {
		t.Fatalf("button click: %+v", res)
	}
}

func TestDialogViewShape(t *testing.T) {
	d := testDialog("ds")
	d.Help = "tab: next • esc: cancel"
	v := d.View()
	lines := strings.Split(v, "\n")
	w, h := d.Size()
	if len(lines) != h {
		t.Fatalf("height %d want %d", len(lines), h)
	}
	for i, l := range lines {
		if ansi.StringWidth(l) != w {
			t.Fatalf("line %d width %d want %d: %q", i, ansi.StringWidth(l), w, ansi.Strip(l))
		}
	}
	plain := ansi.Strip(v)
	for _, want := range []string{"[ New lookup ]", "[< OK >]", "[ Cancel ]", "[ ] Recursive", "1.1.1.1", "tab: next"} {
		if !strings.Contains(plain, want) {
			t.Fatalf("missing %q in\n%s", want, plain)
		}
	}
	// With dropdown open, View keeps a rectangular box.
	d.FocusField("type")
	d, _, _ = d.Update(key(tea.KeyEnter))
	for i, l := range strings.Split(d.View(), "\n") {
		if ansi.StringWidth(l) != w {
			t.Fatalf("dd line %d width %d", i, ansi.StringWidth(l))
		}
	}
	if d.Init() != nil {
		t.Fatal("Init with select focused should be nil")
	}
	if testDialog("ds2").Init() == nil {
		t.Fatal("Init with text focused should blink")
	}
}
