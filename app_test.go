package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"dlookup/lookup"
	"dlookup/ui"
)

const (
	tuiFakeName = "Zz TUI Fake Lookup"
	tuiFakeFlag = "zz-tui-fake"
)

// tuiFakeProvider is a network-free lookup provider used by the model tests.
type tuiFakeProvider struct {
	mu      sync.Mutex
	calls   map[string]int
	outputs map[string]string
	errs    map[string]error
	servers []string
}

func (p *tuiFakeProvider) Name() string            { return tuiFakeName }
func (p *tuiFakeProvider) FlagName() string        { return tuiFakeFlag }
func (p *tuiFakeProvider) Usage() string           { return "tuiFake" }
func (p *tuiFakeProvider) Command() string         { return "" }
func (p *tuiFakeProvider) CheckAvailability() bool { return true }
func (p *tuiFakeProvider) Execute(ctx context.Context, target string, opts lookup.Options) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls[target]++
	p.servers = append(p.servers, opts.Server)
	if err := p.errs[target]; err != nil {
		return "", err
	}
	if out, ok := p.outputs[target]; ok {
		return out, nil
	}
	return "result for " + target, nil
}

func (p *tuiFakeProvider) count(target string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls[target]
}

func (p *tuiFakeProvider) lastServer() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.servers) == 0 {
		return ""
	}
	return p.servers[len(p.servers)-1]
}

func (p *tuiFakeProvider) set(target, out string, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.outputs[target] = out
	p.errs[target] = err
}

func (p *tuiFakeProvider) reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = map[string]int{}
	p.outputs = map[string]string{}
	p.errs = map[string]error{}
	p.servers = nil
}

var tuiFake = &tuiFakeProvider{}

func TestMain(m *testing.M) {
	tuiFake.reset()
	lookup.RegisterProvider(tuiFake)
	ui.InitZones()
	// Ticks and status timeouts fire immediately so tests never sleep.
	tickAfter = func(d time.Duration, fn func(time.Time) tea.Msg) tea.Cmd {
		return func() tea.Msg { return fn(time.Time{}) }
	}
	clipboardWriteAll = func(string) error { return nil }
	os.Exit(m.Run())
}

// collect runs cmd (recursively expanding batches) and returns the produced
// messages. Commands that block (e.g. cursor blink timers) are dropped.
func collect(cmd tea.Cmd) []tea.Msg {
	if cmd == nil {
		return nil
	}
	ch := make(chan tea.Msg, 1)
	go func() { ch <- cmd() }()
	select {
	case msg := <-ch:
		if msg == nil {
			return nil
		}
		if b, ok := msg.(tea.BatchMsg); ok {
			var out []tea.Msg
			for _, c := range b {
				out = append(out, collect(c)...)
			}
			return out
		}
		return []tea.Msg{msg}
	case <-time.After(200 * time.Millisecond):
		return nil
	}
}

// send delivers msg and returns the model and the messages its commands produced.
func send(t *testing.T, m mainModel, msg tea.Msg) (mainModel, []tea.Msg) {
	t.Helper()
	nm, cmd := m.Update(msg)
	return nm.(mainModel), collect(cmd)
}

// settle feeds lookup results/errors/status messages back until none remain.
// Watch ticks are returned (not fed) so tests control them.
func settle(t *testing.T, m mainModel, msgs []tea.Msg) (mainModel, []watchTickMsg) {
	t.Helper()
	var ticks []watchTickMsg
	for len(msgs) > 0 {
		var next []tea.Msg
		for _, msg := range msgs {
			switch msg := msg.(type) {
			case watchTickMsg:
				ticks = append(ticks, msg)
			case lookupResultMsg, errorMsg, tabStatusMsg, zoneDiffResultMsg:
				var out []tea.Msg
				m, out = send(t, m, msg)
				next = append(next, out...)
			}
		}
		msgs = next
	}
	return m, ticks
}

var namedKeys = map[string]tea.KeyType{
	"enter": tea.KeyEnter, "esc": tea.KeyEsc, "right": tea.KeyRight, "left": tea.KeyLeft,
	"up": tea.KeyUp, "down": tea.KeyDown, "tab": tea.KeyTab, "shift+tab": tea.KeyShiftTab,
	"ctrl+c": tea.KeyCtrlC, "ctrl+q": tea.KeyCtrlQ, "ctrl+x": tea.KeyCtrlX, "ctrl+e": tea.KeyCtrlE,
	"ctrl+n": tea.KeyCtrlN,
	"f1":     tea.KeyF1, "f2": tea.KeyF2, "f3": tea.KeyF3, "f4": tea.KeyF4, "f5": tea.KeyF5,
	"f6": tea.KeyF6, "f7": tea.KeyF7, "f8": tea.KeyF8, "f9": tea.KeyF9, "f10": tea.KeyF10,
}

func keyMsg(s string) tea.KeyMsg {
	if s == "space" {
		return tea.KeyMsg{Type: tea.KeySpace, Runes: []rune{' '}}
	}
	if t, ok := namedKeys[s]; ok {
		return tea.KeyMsg{Type: t}
	}
	if strings.HasPrefix(s, "alt+") && len(s) == 5 {
		return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{rune(s[4])}, Alt: true}
	}
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

func typeKeys(t *testing.T, m mainModel, keys ...string) (mainModel, []tea.Msg) {
	t.Helper()
	var all []tea.Msg
	for _, k := range keys {
		var out []tea.Msg
		m, out = send(t, m, keyMsg(k))
		all = append(all, out...)
	}
	return m, all
}

// homeModel returns a model started without targets (on the Home tab).
func homeModel(t *testing.T, cfg AppConfig) mainModel {
	t.Helper()
	tuiFake.reset()
	m := newMainModel(nil, "", cfg, lookup.Options{})
	m, _ = send(t, m, tea.WindowSizeMsg{Width: 100, Height: 30})
	return m
}

// startedModel returns a model with one tab per domain, all initial lookups done.
func startedModel(t *testing.T, domains ...string) mainModel {
	t.Helper()
	tuiFake.reset()
	m := newMainModel(domains, tuiFakeName, DefaultConfig(), lookup.Options{})
	m, _ = send(t, m, tea.WindowSizeMsg{Width: 100, Height: 30})
	m, _ = settle(t, m, collect(m.Init()))
	return m
}

// expectDialog fails unless dialog kind is open.
func expectDialog(t *testing.T, m mainModel, kind dialogKind) {
	t.Helper()
	if m.dlg != kind {
		t.Fatalf("dialog = %v, want %v", m.dlg, kind)
	}
}

// submit sets the open dialog's values and presses enter.
func submit(t *testing.T, m mainModel, values map[string]string) (mainModel, []tea.Msg) {
	t.Helper()
	for k, v := range values {
		m.dialog.SetValue(k, v)
	}
	return send(t, m, keyMsg("enter"))
}

// startWatch opens the watch dialog on the active tab and confirms interval sec.
func startWatch(t *testing.T, m mainModel, sec string) (mainModel, []watchTickMsg) {
	t.Helper()
	m, _ = typeKeys(t, m, "w")
	expectDialog(t, m, dlgWatch)
	vals := map[string]string{}
	if sec != "" {
		vals["interval"], vals["custom"] = customInterval, sec
	}
	m, msgs := submit(t, m, vals)
	return settle(t, m, msgs)
}

var sentinelN atomic.Int64

// scanView renders and scans the model, waiting until bubblezone's async
// worker has stored this scan's zones.
func scanView(t *testing.T, m mainModel) string {
	t.Helper()
	id := "test-sentinel-" + strconv.FormatInt(sentinelN.Add(1), 10)
	out := ui.Scan(m.render() + "\n" + ui.Mark(id, "#"))
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, _, _, _, ok := ui.ZonePos(id); ok {
			return out
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("zones never settled")
	return out
}

// click scans the view and left-clicks zone id.
func click(t *testing.T, m mainModel, id string) (mainModel, []tea.Msg) {
	t.Helper()
	scanView(t, m)
	x, y, _, _, ok := ui.ZonePos(id)
	if !ok {
		t.Fatalf("zone %q not found", id)
	}
	return send(t, m, tea.MouseMsg{X: x, Y: y, Button: tea.MouseButtonLeft, Action: tea.MouseActionPress})
}

func isQuit(msgs []tea.Msg) bool {
	for _, msg := range msgs {
		if _, ok := msg.(tea.QuitMsg); ok {
			return true
		}
	}
	return false
}

func TestStartsOnHomeWithoutFocusedInput(t *testing.T) {
	m := homeModel(t, DefaultConfig())
	if len(m.tabs) != 1 || !m.tabs[0].isHome() || m.dlg != dlgNone {
		t.Fatalf("expected Home tab without dialog: tabs=%d dlg=%v", len(m.tabs), m.dlg)
	}
	v := m.View()
	for _, want := range []string{"Get started", "[ New lookup ]", "[ Zone diff ]", "Lookup", "1Help", "10Quit"} {
		if !strings.Contains(v, want) {
			t.Errorf("home view missing %q", want)
		}
	}
	// The shortcut table is further down the scrollable Home content.
	if !strings.Contains(helpContent(m.config, 100), "Keyboard shortcuts") {
		t.Error("home content missing \"Keyboard shortcuts\"")
	}
	// Global letter keys work right away; x can't close the only Home tab.
	m, _ = typeKeys(t, m, "x")
	if len(m.tabs) != 1 {
		t.Fatal("x closed the Home tab")
	}
	m, _ = typeKeys(t, m, "n")
	expectDialog(t, m, dlgLookup)
	if m.dialog.Focused() != "domain" || m.dialog.Title != "New lookup" {
		t.Fatalf("focused=%q title=%q", m.dialog.Focused(), m.dialog.Title)
	}
	// Printable keys are typed into the dialog, not handled globally.
	m, _ = typeKeys(t, m, "x", "n", "q")
	if got := m.dialog.Value("domain"); got != "xnq" || len(m.tabs) != 1 {
		t.Fatalf("domain=%q tabs=%d", got, len(m.tabs))
	}
	m, _ = typeKeys(t, m, "esc")
	if m.dlg != dlgNone {
		t.Fatal("esc should close the dialog")
	}
	m, _ = typeKeys(t, m, "f2")
	expectDialog(t, m, dlgLookup)
}

func TestNewLookupDialogRunsInNewTab(t *testing.T) {
	m := homeModel(t, DefaultConfig())
	m, _ = typeKeys(t, m, "n")
	m, msgs := submit(t, m, map[string]string{"domain": "a.test", "type": tuiFakeName})
	if m.dlg != dlgNone || len(m.tabs) != 2 || m.activeTab != 1 {
		t.Fatalf("dlg=%v tabs=%d active=%d", m.dlg, len(m.tabs), m.activeTab)
	}
	if tab := m.tabs[1]; tab.state != stateLoading || tab.domain != "a.test" || tab.lookupType != tuiFakeName {
		t.Fatalf("tab: state=%v domain=%q type=%q", tab.state, tab.domain, tab.lookupType)
	}
	m, _ = settle(t, m, msgs)
	if m.tabs[1].state != stateViewResults || tuiFake.count("a.test") != 1 {
		t.Fatalf("state=%v calls=%d", m.tabs[1].state, tuiFake.count("a.test"))
	}
	v := m.View()
	if !strings.Contains(v, "a.test · "+tuiFakeName) || !strings.Contains(v, "result for a.test") {
		t.Fatalf("results panel:\n%s", v)
	}
	// Another new lookup opens another tab; the type defaults to the last used.
	m, _ = typeKeys(t, m, "n")
	if m.dialog.Value("type") != tuiFakeName {
		t.Fatalf("type default = %q", m.dialog.Value("type"))
	}
	m, msgs = submit(t, m, map[string]string{"domain": "b.test"})
	m, _ = settle(t, m, msgs)
	if len(m.tabs) != 3 || m.activeTab != 2 || m.tabs[2].domain != "b.test" {
		t.Fatalf("tabs=%d active=%d", len(m.tabs), m.activeTab)
	}
}

func TestLookupTypeDropdownSelection(t *testing.T) {
	m := homeModel(t, DefaultConfig())
	m, _ = typeKeys(t, m, "n", "a.test", "tab")
	if m.dialog.Focused() != "type" {
		t.Fatalf("focused %q", m.dialog.Focused())
	}
	m, _ = typeKeys(t, m, "space")
	if !m.dialog.DropdownOpen() {
		t.Fatal("space should open the dropdown")
	}
	m, _ = typeKeys(t, m, "tui", "enter")
	if m.dialog.DropdownOpen() || m.dialog.Value("type") != tuiFakeName {
		t.Fatalf("dropdown open=%v type=%q", m.dialog.DropdownOpen(), m.dialog.Value("type"))
	}
	// Enter on the closed select runs the dialog.
	m, msgs := send(t, m, keyMsg("enter"))
	m, _ = settle(t, m, msgs)
	if m.dlg != dlgNone || tuiFake.count("a.test") != 1 {
		t.Fatalf("dlg=%v calls=%d", m.dlg, tuiFake.count("a.test"))
	}
}

func TestChoosingZoneDiffSwapsDialog(t *testing.T) {
	m := homeModel(t, DefaultConfig())
	m, _ = typeKeys(t, m, "n", "example.com", "tab", "space", "zone", "enter")
	expectDialog(t, m, dlgZoneDiff)
	if m.dialog.Value("domain") != "example.com" || m.dialog.Focused() != "new" {
		t.Fatalf("zone diff dialog: domain=%q focus=%q", m.dialog.Value("domain"), m.dialog.Focused())
	}
}

func TestChangeLookupReusesTab(t *testing.T) {
	m := startedModel(t, "a.test")
	m, _ = typeKeys(t, m, "enter")
	expectDialog(t, m, dlgLookup)
	if m.dialog.Title != "Change lookup" || m.dialog.Value("domain") != "a.test" || m.dialog.Value("type") != tuiFakeName {
		t.Fatalf("prefill: title=%q domain=%q type=%q", m.dialog.Title, m.dialog.Value("domain"), m.dialog.Value("type"))
	}
	m, msgs := submit(t, m, map[string]string{"domain": "b.test"})
	m, _ = settle(t, m, msgs)
	if len(m.tabs) != 1 || m.tabs[0].domain != "b.test" || tuiFake.count("b.test") != 1 {
		t.Fatalf("tabs=%d domain=%q", len(m.tabs), m.tabs[0].domain)
	}
	// F3 opens the same dialog.
	m, _ = typeKeys(t, m, "f3")
	expectDialog(t, m, dlgLookup)
}

func TestFKeysAndMenuDispatch(t *testing.T) {
	m := startedModel(t, "a.test")
	m, _ = typeKeys(t, m, "f1")
	if !m.tabs[m.activeTab].isHome() || len(m.tabs) != 2 {
		t.Fatalf("F1 should open Home: tabs=%d", len(m.tabs))
	}
	m, _ = typeKeys(t, m, "?") // already open: just focuses it
	if len(m.tabs) != 2 {
		t.Fatal("? should not open a second Home")
	}
	m, _ = typeKeys(t, m, "f4")
	expectDialog(t, m, dlgZoneDiff)
	m, _ = typeKeys(t, m, "esc", "f9")
	if !m.menu.IsOpen() {
		t.Fatal("F9 should open the menu")
	}
	if !strings.Contains(m.View(), "New lookup…") {
		t.Fatal("dropdown not rendered")
	}
	m, _ = typeKeys(t, m, "esc")
	if m.menu.IsOpen() {
		t.Fatal("esc should close the menu")
	}
	// alt+l opens Lookup; "n" is the New lookup item hotkey.
	m, _ = typeKeys(t, m, "alt+l", "n")
	expectDialog(t, m, dlgLookup)
	m, _ = typeKeys(t, m, "esc", "right") // focus a.test
	m, _ = typeKeys(t, m, "alt+t", "c")   // Tab → Close tab
	if len(m.tabs) != 1 || !m.tabs[0].isHome() {
		t.Fatalf("menu close: tabs=%d", len(m.tabs))
	}
	// F10 quits right away when nothing runs.
	_, msgs := typeKeys(t, m, "f10")
	if !isQuit(msgs) {
		t.Fatal("F10 should quit")
	}
}

func TestMenuDisablesInapplicableItems(t *testing.T) {
	m := homeModel(t, DefaultConfig())
	for _, a := range []string{actExport, actCopy, actRerun, actWatch, actServer, actMatches} {
		if it := m.menuItem(a); it == nil || !it.Disabled {
			t.Errorf("%s should be disabled on Home", a)
		}
	}
	m = startedModel(t, "a.test")
	for _, a := range []string{actExport, actCopy, actRerun, actWatch, actServer} {
		if it := m.menuItem(a); it == nil || it.Disabled {
			t.Errorf("%s should be enabled on results", a)
		}
	}
	if it := m.menuItem(actMatches); !it.Disabled {
		t.Error("show matches only applies to zone diffs")
	}
}

func TestMouseTabBarFKeysAndHomeButtons(t *testing.T) {
	m := startedModel(t, "a.test", "b.test")
	m, _ = click(t, m, "dl-tabs-t-1")
	if m.activeTab != 1 {
		t.Fatalf("click on tab 1: active=%d", m.activeTab)
	}
	m, _ = click(t, m, "dl-tabs-x-0")
	if len(m.tabs) != 1 || m.tabs[0].domain != "b.test" {
		t.Fatalf("× should close tab 0: tabs=%d", len(m.tabs))
	}
	m, _ = click(t, m, "dl-tabs-new")
	expectDialog(t, m, dlgLookup)
	// Clicks outside the modal dialog do nothing.
	m, _ = send(t, m, tea.MouseMsg{X: 0, Y: 1, Button: tea.MouseButtonLeft, Action: tea.MouseActionPress})
	expectDialog(t, m, dlgLookup)
	m, _ = typeKeys(t, m, "esc")

	m, _ = click(t, m, "dl-fkeys-k-0") // F1 Help
	if !m.tabs[m.activeTab].isHome() {
		t.Fatal("F1 click should show Home")
	}
	m, _ = click(t, m, "dl-home-zonediff")
	expectDialog(t, m, dlgZoneDiff)
	m, _ = typeKeys(t, m, "esc")
	m, _ = click(t, m, "dl-home-new")
	expectDialog(t, m, dlgLookup)
	m, _ = typeKeys(t, m, "esc")
	m, _ = click(t, m, "dl-menu-m-4") // Help menu title
	if !m.menu.IsOpen() {
		t.Fatal("clicking a menu title should open it")
	}
}

func TestMouseWheelScrollsResults(t *testing.T) {
	tuiFake.reset()
	tuiFake.set("a.test", strings.Repeat("line\n", 200), nil)
	m := newMainModel([]string{"a.test"}, tuiFakeName, DefaultConfig(), lookup.Options{})
	m, _ = send(t, m, tea.WindowSizeMsg{Width: 100, Height: 30})
	m, _ = settle(t, m, collect(m.Init()))
	m, _ = send(t, m, tea.MouseMsg{X: 10, Y: 10, Button: tea.MouseButtonWheelDown, Action: tea.MouseActionPress})
	if m.tabs[0].viewport.YOffset == 0 {
		t.Fatal("wheel should scroll the results")
	}
	if v := m.View(); !strings.Contains(v, "▼") || !strings.Contains(v, "█") {
		t.Fatal("scrollbar should be drawn")
	}
}

func TestCtrlCAlwaysQuits(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Keybindings.Quit = "c"
	m := newMainModel(nil, "", cfg, lookup.Options{})
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	if cmd == nil {
		t.Fatal("ctrl+c returned no command")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Fatal("ctrl+c did not quit when quit is rebound to c")
	}
	// Even with a dialog open and lookups being watched.
	m = startedModel(t, "a.test")
	m, _ = startWatch(t, m, "5")
	m, _ = typeKeys(t, m, "n")
	if _, msgs := typeKeys(t, m, "ctrl+c"); !isQuit(msgs) {
		t.Fatal("ctrl+c should quit from a dialog")
	}
}

func TestConfiguredQuitKey(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Keybindings.Quit = "ctrl+q"
	m := homeModel(t, cfg)
	if _, msgs := typeKeys(t, m, "ctrl+q"); !isQuit(msgs) {
		t.Fatal("configured quit key should quit")
	}
	// A printable quit key is typed into dialogs instead.
	cfg.Keybindings.Quit = "Q"
	m = homeModel(t, cfg)
	m, msgs := typeKeys(t, m, "n", "Q")
	if isQuit(msgs) || m.dialog.Value("domain") != "Q" {
		t.Fatal("Q should be typed into the dialog")
	}
}

func TestConfirmQuitWhenWatching(t *testing.T) {
	m := startedModel(t, "a.test")
	m, _ = startWatch(t, m, "5")
	m, msgs := typeKeys(t, m, "f10")
	if isQuit(msgs) {
		t.Fatal("should ask before quitting while watching")
	}
	expectDialog(t, m, dlgConfirmQuit)
	m, msgs = typeKeys(t, m, "esc")
	if isQuit(msgs) || m.dlg != dlgNone {
		t.Fatal("esc should cancel quitting")
	}
	m, _ = typeKeys(t, m, "f10")
	if _, msgs = typeKeys(t, m, "enter"); !isQuit(msgs) {
		t.Fatal("Yes should quit")
	}
}

func TestConfirmCloseWatchingTab(t *testing.T) {
	m := startedModel(t, "a.test", "b.test")
	m, _ = startWatch(t, m, "5")
	m, _ = typeKeys(t, m, "x")
	expectDialog(t, m, dlgConfirmClose)
	m, _ = typeKeys(t, m, "esc")
	if len(m.tabs) != 2 {
		t.Fatal("No should keep the tab")
	}
	m, _ = typeKeys(t, m, "f8", "enter")
	if len(m.tabs) != 1 || m.tabs[0].domain != "b.test" {
		t.Fatalf("Yes should close: tabs=%d", len(m.tabs))
	}
	// Closing the last lookup tab shows Home.
	m, _ = typeKeys(t, m, "x")
	if len(m.tabs) != 1 || !m.tabs[0].isHome() {
		t.Fatal("closing the last tab should show Home")
	}
}

func TestMouseToggleEmitsCommand(t *testing.T) {
	m := homeModel(t, DefaultConfig())
	if !m.mouse {
		t.Fatal("mouse defaults to on")
	}
	m, msgs := typeKeys(t, m, "alt+o", "m")
	if m.mouse || len(msgs) != 1 || reflect.TypeOf(msgs[0]) != reflect.TypeOf(tea.DisableMouse()) {
		t.Fatalf("mouse=%v msgs=%#v", m.mouse, msgs)
	}
	if it := m.menuItem(actMouse); it.Checked == nil || *it.Checked {
		t.Fatal("menu checkbox should be off")
	}
	// Mouse events are ignored while off.
	m, _ = send(t, m, tea.MouseMsg{X: 3, Y: 0, Button: tea.MouseButtonLeft, Action: tea.MouseActionPress})
	if m.menu.IsOpen() {
		t.Fatal("mouse is off")
	}
	m, msgs = typeKeys(t, m, "alt+o", "m")
	if !m.mouse || len(msgs) != 1 || reflect.TypeOf(msgs[0]) != reflect.TypeOf(tea.EnableMouseCellMotion()) {
		t.Fatalf("mouse=%v msgs=%#v", m.mouse, msgs)
	}
}

func TestHelpListsConfiguredKeys(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Keybindings.NewTab = "ctrl+n"
	cfg.Keybindings.ZoneDiff = "z"
	m := homeModel(t, cfg)
	content := m.tabs[0].viewport.View()
	h := helpContent(cfg, 100)
	for _, want := range []string{"ctrl+n", "Zone diff (DNS migration check)  z", "F10", "hold Shift"} {
		if !strings.Contains(h, want) {
			t.Errorf("help missing %q", want)
		}
	}
	if !strings.Contains(content, "Press ctrl+n or F2") {
		t.Errorf("home should show the configured key:\n%s", content)
	}
	if it := m.menuItem(actNew); it.Hotkey != "ctrl+n F2" {
		t.Errorf("menu hotkey = %q", it.Hotkey)
	}
	m, _ = typeKeys(t, m, "ctrl+n")
	expectDialog(t, m, dlgLookup)
}

func TestInitStartsAllTabsAndSwitchDoesNotRerun(t *testing.T) {
	m := startedModel(t, "a.test", "b.test", "c.test")
	for i, tab := range m.tabs {
		if tab.state != stateViewResults {
			t.Fatalf("tab %d: state %v, want results", i, tab.state)
		}
	}
	m, msgs := typeKeys(t, m, "right", "right", "left", "right")
	m, _ = settle(t, m, msgs)
	if m.activeTab != 2 {
		t.Fatalf("activeTab = %d, want 2", m.activeTab)
	}
	for _, d := range []string{"a.test", "b.test", "c.test"} {
		if n := tuiFake.count(d); n != 1 {
			t.Fatalf("%s: %d calls, want 1", d, n)
		}
	}
	// F5 / r re-run.
	m, msgs = typeKeys(t, m, "f5")
	m, _ = settle(t, m, msgs)
	m, msgs = typeKeys(t, m, "r")
	_, _ = settle(t, m, msgs)
	if n := tuiFake.count("c.test"); n != 3 {
		t.Fatalf("re-run: %d calls", n)
	}
}

func TestWatchTicksRouteToOwningTab(t *testing.T) {
	m := startedModel(t, "a.test", "b.test")
	m, ticks := startWatch(t, m, "")
	a := m.tabs[0]
	if !a.isWatching || a.watchInterval != 5*time.Second {
		t.Fatalf("watch not started: watching=%v interval=%v", a.isWatching, a.watchInterval)
	}
	if len(ticks) != 1 || ticks[0].tabId != a.id {
		t.Fatalf("expected one tick for tab %d, got %+v", a.id, ticks)
	}
	if n := tuiFake.count("a.test"); n != 2 {
		t.Fatalf("watch start should refresh immediately: %d calls", n)
	}
	m, _ = typeKeys(t, m, "right")
	m, msgs := send(t, m, ticks[0])
	m, ticks = settle(t, m, msgs)
	if n := tuiFake.count("a.test"); n != 3 {
		t.Fatalf("background tick did not refresh tab a: %d calls", n)
	}
	if n := tuiFake.count("b.test"); n != 1 {
		t.Fatalf("tab b should not be refreshed: %d calls", n)
	}
	if len(ticks) != 1 || ticks[0].tabId != a.id || m.tabs[0].state != stateViewResults {
		t.Fatalf("tick chain should continue for tab a, got %+v", ticks)
	}
}

func TestStopWatchIgnoresStaleTicks(t *testing.T) {
	m := startedModel(t, "a.test")
	m, ticks := startWatch(t, m, "5")
	stale := ticks[0]

	m, _ = typeKeys(t, m, "w") // stop
	if m.tabs[0].isWatching || m.dlg != dlgNone {
		t.Fatal("watch toggle should stop watching")
	}
	before := tuiFake.count("a.test")
	m, msgs := send(t, m, stale)
	m, ticks = settle(t, m, msgs)
	if tuiFake.count("a.test") != before || len(ticks) != 0 {
		t.Fatal("stale tick ran a lookup or rescheduled")
	}

	m, ticks = startWatch(t, m, "")
	fresh := ticks[0]
	if fresh.gen == stale.gen || m.dialog.Value("interval") != "" {
		t.Fatal("restart should use a new generation")
	}
	before = tuiFake.count("a.test")
	m, msgs = send(t, m, stale)
	m, ticks = settle(t, m, msgs)
	if tuiFake.count("a.test") != before || len(ticks) != 0 {
		t.Fatal("old-generation tick must be ignored after restart")
	}

	// Back stops watching too and keeps the results.
	m, _ = typeKeys(t, m, "q")
	if m.tabs[0].isWatching || m.tabs[0].state != stateViewResults {
		t.Fatalf("back should stop watch, state=%v", m.tabs[0].state)
	}
	m, msgs = send(t, m, fresh)
	_, ticks = settle(t, m, msgs)
	if len(ticks) != 0 {
		t.Fatal("tick after Back must not reschedule")
	}
}

func TestWatchDialogPrefillsInterval(t *testing.T) {
	m := startedModel(t, "a.test")
	m, _ = startWatch(t, m, "7")
	m, _ = typeKeys(t, m, "w", "w") // stop, reopen
	expectDialog(t, m, dlgWatch)
	if m.dialog.Value("interval") != customInterval || m.dialog.Value("custom") != "7" {
		t.Fatalf("prefill interval=%q custom=%q", m.dialog.Value("interval"), m.dialog.Value("custom"))
	}
	m, _ = submit(t, m, map[string]string{"interval": "30"})
	if m.tabs[0].watchInterval != 30*time.Second {
		t.Fatalf("interval=%v", m.tabs[0].watchInterval)
	}
}

func TestWatchDiffAndChangedIndicator(t *testing.T) {
	m := startedModel(t, "a.test", "b.test")
	tuiFake.set("a.test", "line1\nline2", nil)
	m, ticks := startWatch(t, m, "5")
	m, _ = typeKeys(t, m, "right")

	tuiFake.set("a.test", "line1\nline3", nil)
	m, msgs := send(t, m, ticks[0])
	m, _ = settle(t, m, msgs)

	a := m.tabs[0]
	if !a.diffAdded[1] || len(a.diffAdded) != 1 || len(a.diffRemoved) != 1 || a.diffRemoved[0] != "line2" {
		t.Fatalf("diff = +%v -%v", a.diffAdded, a.diffRemoved)
	}
	if !a.changed || !strings.Contains(m.View(), "●") {
		t.Fatal("background tab should be marked changed")
	}
	content := a.viewport.View()
	for _, want := range []string{"+ line3", "- line2", "Last updated", "[Watching: 5s]"} {
		if !strings.Contains(content, want) {
			t.Errorf("content missing %q:\n%s", want, content)
		}
	}
	m, _ = typeKeys(t, m, "left")
	if m.tabs[0].changed {
		t.Fatal("focusing the tab should clear changed")
	}
	if !strings.Contains(m.View(), "[watching 5s]") {
		t.Fatal("panel title should show watching")
	}
}

func TestDiffIgnoresTTLAndTimings(t *testing.T) {
	prev := "example.com. 300 IN A 1.2.3.4\n;; Query time: 12 msec"
	cur := "example.com. 299 IN A 1.2.3.4\n;; Query time: 40 msec"
	added, removed := diffLines(prev, cur)
	if len(added) != 0 || len(removed) != 0 {
		t.Fatalf("expected no diff, got +%v -%v", added, removed)
	}
}

func TestResizeKeepsWatchAndErrorHeaders(t *testing.T) {
	m := startedModel(t, "a.test")
	m, _ = startWatch(t, m, "7")
	m, _ = send(t, m, tea.WindowSizeMsg{Width: 120, Height: 40})
	if v := m.tabs[0].viewport.View(); !strings.Contains(v, "[Watching: 7s]") {
		t.Fatalf("resize dropped watch header:\n%s", v)
	}

	tuiFake.reset()
	tuiFake.set("e.test", "", errors.New("boom"))
	m = newMainModel([]string{"e.test"}, tuiFakeName, DefaultConfig(), lookup.Options{})
	m, _ = settle(t, m, collect(m.Init()))
	m, _ = send(t, m, tea.WindowSizeMsg{Width: 90, Height: 30})
	v := m.tabs[0].viewport.View()
	if !strings.Contains(v, "Error running "+tuiFakeName+" for e.test") || !strings.Contains(v, "boom") {
		t.Fatalf("resize dropped error header:\n%s", v)
	}
}

func TestBackCancelsRunningLookup(t *testing.T) {
	m := homeModel(t, DefaultConfig())
	m, _ = typeKeys(t, m, "n")
	m, _ = submit(t, m, map[string]string{"domain": "a.test", "type": tuiFakeName}) // result never delivered
	seq := m.tabs[1].lookupSeq
	m, _ = typeKeys(t, m, "esc")
	tab := m.tabs[1]
	if tab.state != stateIdle || tab.inFlight || tab.lookupSeq == seq {
		t.Fatalf("esc should cancel: state=%v inFlight=%v", tab.state, tab.inFlight)
	}
	m, _ = send(t, m, lookupResultMsg{tabId: tab.id, seq: seq, output: "late"})
	if m.tabs[1].state != stateIdle {
		t.Fatal("stale result should be ignored")
	}
}

func TestValidationMessagesKeepInput(t *testing.T) {
	m := homeModel(t, DefaultConfig())
	m, _ = typeKeys(t, m, "n", "enter")
	expectDialog(t, m, dlgLookup)
	if m.dialog.Err == "" || len(m.tabs) != 1 {
		t.Fatalf("empty target: err=%q tabs=%d", m.dialog.Err, len(m.tabs))
	}
	if !strings.Contains(m.View(), "invalid target") {
		t.Fatal("validation message should be displayed")
	}
	m, _ = submit(t, m, map[string]string{"domain": "a.test", "server": "bad server!"})
	if m.dlg != dlgLookup || !strings.Contains(m.dialog.Err, "server") || m.dialog.Value("server") != "bad server!" {
		t.Fatalf("bad server: dlg=%v err=%q", m.dlg, m.dialog.Err)
	}

	m = startedModel(t, "a.test")
	m, _ = typeKeys(t, m, "w")
	m, _ = submit(t, m, map[string]string{"interval": customInterval, "custom": "ab"})
	expectDialog(t, m, dlgWatch)
	if m.dialog.Err == "" || m.tabs[0].isWatching {
		t.Fatal("invalid interval must not start watching")
	}

	m, _ = typeKeys(t, m, "esc", "ctrl+x")
	m, _ = submit(t, m, map[string]string{"file": ""})
	expectDialog(t, m, dlgExport)
	if m.dialog.Err == "" {
		t.Fatal("empty filename should be rejected")
	}
}

func TestExportDefaultFilenameAndExport(t *testing.T) {
	ts := time.Date(2026, 11, 4, 13, 5, 9, 0, time.UTC)
	if got, want := defaultExportFilename("Example.COM", tuiFakeName, ts), "example.com-"+tuiFakeFlag+"-20261104-130509.txt"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if got := defaultExportFilename("a/b c", "Custom Thing", ts); got != "a-b-c-custom-thing-20261104-130509.txt" {
		t.Fatalf("unknown lookup slug: got %q", got)
	}

	m := startedModel(t, "a.test")
	m, _ = typeKeys(t, m, "ctrl+x")
	expectDialog(t, m, dlgExport)
	if !strings.HasPrefix(m.dialog.Value("file"), "a.test-"+tuiFakeFlag+"-") {
		t.Fatalf("export not prefilled: %q", m.dialog.Value("file"))
	}
	path := filepath.Join(t.TempDir(), "sub", "out.txt")
	m, msgs := submit(t, m, map[string]string{"file": path})
	m, _ = settle(t, m, msgs)
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "result for a.test" {
		t.Fatalf("export file: %q, %v", data, err)
	}
	if m.dlg != dlgNone || !strings.Contains(m.tabs[0].statusMsg, "Saved to") {
		t.Fatalf("after export: dlg=%v status=%q", m.dlg, m.tabs[0].statusMsg)
	}
}

func TestExportAllContent(t *testing.T) {
	m := startedModel(t, "a.test", "b.test")
	m, _ = typeKeys(t, m, "f1") // Home is skipped
	content := m.exportAllContent()
	for _, want := range []string{"===== a.test — " + tuiFakeName, "result for a.test", "===== b.test — " + tuiFakeName, "result for b.test"} {
		if !strings.Contains(content, want) {
			t.Errorf("export-all missing %q:\n%s", want, content)
		}
	}
	if strings.Contains(content, "Home") || strings.HasPrefix(content, "\n") {
		t.Errorf("Home should not be exported:\n%s", content)
	}
}

func TestCopyToClipboard(t *testing.T) {
	var got string
	clipboardWriteAll = func(s string) error { got = s; return nil }
	defer func() { clipboardWriteAll = func(string) error { return nil } }()

	m := startedModel(t, "a.test")
	m, msgs := typeKeys(t, m, "y")
	m, _ = settle(t, m, msgs)
	if got != "result for a.test" || !strings.Contains(m.View(), "Copied") {
		t.Fatalf("clipboard=%q", got)
	}
}

func TestServerDialogSetsOptions(t *testing.T) {
	tuiFake.reset()
	m := newMainModel([]string{"a.test"}, tuiFakeName, DefaultConfig(), lookup.Options{Server: "9.9.9.9"})
	m, _ = send(t, m, tea.WindowSizeMsg{Width: 100, Height: 30})
	m, _ = settle(t, m, collect(m.Init()))
	if !strings.Contains(m.View(), "@9.9.9.9") {
		t.Fatal("initial server should be shown in the panel title")
	}
	m, _ = typeKeys(t, m, "s")
	expectDialog(t, m, dlgServer)
	if m.dialog.Value("server") != "9.9.9.9" {
		t.Fatalf("server prefill %q", m.dialog.Value("server"))
	}
	m, msgs := submit(t, m, map[string]string{"server": "1.1.1.1"})
	m, _ = settle(t, m, msgs)
	if m.tabs[0].lookupOpts.Server != "1.1.1.1" || tuiFake.count("a.test") != 2 || tuiFake.lastServer() != "1.1.1.1" {
		t.Fatalf("server=%q calls=%d", m.tabs[0].lookupOpts.Server, tuiFake.count("a.test"))
	}
	// New lookups default to the CLI server.
	m, _ = typeKeys(t, m, "n")
	if m.dialog.Value("server") != "9.9.9.9" {
		t.Fatalf("new lookup server = %q", m.dialog.Value("server"))
	}
	m, msgs = submit(t, m, map[string]string{"domain": "b.test"})
	m, _ = settle(t, m, msgs)
	if m.tabs[1].lookupOpts.Server != "9.9.9.9" || tuiFake.lastServer() != "9.9.9.9" {
		t.Fatalf("new tab server = %q", m.tabs[1].lookupOpts.Server)
	}
}

func TestTruncateUnicode(t *testing.T) {
	s := "日本語のとても長いドメイン名.example.jp"
	for _, w := range []int{1, 5, 8, 13} {
		got := truncateWidth(s, w)
		if !utf8.ValidString(got) || lipgloss.Width(got) > w || !strings.HasSuffix(got, "…") {
			t.Fatalf("width %d: %q", w, got)
		}
	}
	if got := truncateWidth("short", 10); got != "short" {
		t.Fatalf("short string changed: %q", got)
	}

	m := startedModel(t, s, "ünïcødé-ドメイン.test")
	m, _ = typeKeys(t, m, "n") // with a dialog on top too
	v := m.View()
	lines := strings.Split(v, "\n")
	if len(lines) != m.height {
		t.Fatalf("view has %d lines, want %d", len(lines), m.height)
	}
	for _, line := range lines {
		if !utf8.ValidString(line) {
			t.Fatalf("view contains invalid UTF-8: %q", line)
		}
		if lipgloss.Width(line) > m.width {
			t.Fatalf("view line wider than terminal (%d > %d): %q", lipgloss.Width(line), m.width, line)
		}
	}
}

func TestLookupDialogListOpensTabEach(t *testing.T) {
	m := homeModel(t, DefaultConfig())
	m, _ = typeKeys(t, m, "n")
	expectDialog(t, m, dlgLookup)
	m.dialog.SetValue("domain", "a.example, b.example c.example")
	m.dialog.SetValue("type", tuiFakeName)
	m.submitDialog(ui.DialogResult{Action: btnRun, Values: m.dialog.Values()})
	if m.dlg != dlgNone {
		t.Fatalf("dialog still open: %q", m.dialog.Err)
	}
	var domains []string
	for _, tab := range m.tabs {
		if !tab.isHome() {
			domains = append(domains, tab.domain+"/"+tab.lookupType)
		}
	}
	want := "a.example/" + tuiFakeName + " b.example/" + tuiFakeName + " c.example/" + tuiFakeName
	if strings.Join(domains, " ") != want {
		t.Fatalf("tabs %v", domains)
	}
	if err := validateTargetsField("a.example, -bad"); err == nil {
		t.Error("invalid entry in a list must fail validation")
	}
}
