package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"dlookup/lookup"
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
}

var tuiFake = &tuiFakeProvider{}

func TestMain(m *testing.M) {
	tuiFake.reset()
	lookup.RegisterProvider(tuiFake)
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
			case lookupResultMsg, errorMsg, tabStatusMsg:
				var out []tea.Msg
				m, out = send(t, m, msg)
				next = append(next, out...)
			}
		}
		msgs = next
	}
	return m, ticks
}

func keyMsg(s string) tea.KeyMsg {
	switch s {
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	case "right":
		return tea.KeyMsg{Type: tea.KeyRight}
	case "left":
		return tea.KeyMsg{Type: tea.KeyLeft}
	case "ctrl+c":
		return tea.KeyMsg{Type: tea.KeyCtrlC}
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

// startedModel returns a model with one tab per domain, all initial lookups done.
func startedModel(t *testing.T, domains ...string) mainModel {
	t.Helper()
	tuiFake.reset()
	m := newMainModel(domains, tuiFakeName, DefaultConfig(), lookup.Options{})
	m, _ = send(t, m, tea.WindowSizeMsg{Width: 100, Height: 30})
	m, _ = settle(t, m, collect(m.Init()))
	return m
}

// startWatch opens the watch modal on the active tab and confirms interval sec.
func startWatch(t *testing.T, m mainModel, sec string) (mainModel, []watchTickMsg) {
	t.Helper()
	m, _ = typeKeys(t, m, "w")
	if m.tabs[m.activeTab].state != stateWatchIntervalInput {
		t.Fatalf("expected watch interval modal, got state %v", m.tabs[m.activeTab].state)
	}
	m, _ = typeKeys(t, m, strings.Split(sec, "")...)
	m, msgs := send(t, m, keyMsg("enter"))
	return settle(t, m, msgs)
}

func TestInitStartsAllTabsAndSwitchDoesNotRerun(t *testing.T) {
	m := startedModel(t, "a.test", "b.test", "c.test")
	for i, tab := range m.tabs {
		if tab.state != stateViewResults {
			t.Fatalf("tab %d: state %v, want results", i, tab.state)
		}
	}
	for _, d := range []string{"a.test", "b.test", "c.test"} {
		if n := tuiFake.count(d); n != 1 {
			t.Fatalf("%s: %d calls, want 1", d, n)
		}
	}
	m, msgs := typeKeys(t, m, "right", "right", "left", "right")
	m, _ = settle(t, m, msgs)
	if m.activeTab != 2 {
		t.Fatalf("activeTab = %d, want 2", m.activeTab)
	}
	for _, d := range []string{"a.test", "b.test", "c.test"} {
		if n := tuiFake.count(d); n != 1 {
			t.Fatalf("%s: %d calls after switching, want 1", d, n)
		}
	}
}

func TestWatchTicksRouteToOwningTab(t *testing.T) {
	m := startedModel(t, "a.test", "b.test")
	m, ticks := startWatch(t, m, "5")
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

	// Focus tab b; tab a's tick must still reach tab a.
	m, _ = typeKeys(t, m, "right")
	m, msgs := send(t, m, ticks[0])
	m, ticks = settle(t, m, msgs)
	if n := tuiFake.count("a.test"); n != 3 {
		t.Fatalf("background tick did not refresh tab a: %d calls", n)
	}
	if n := tuiFake.count("b.test"); n != 1 {
		t.Fatalf("tab b should not be refreshed: %d calls", n)
	}
	if len(ticks) != 1 || ticks[0].tabId != a.id {
		t.Fatalf("tick chain should continue for tab a, got %+v", ticks)
	}
	if m.tabs[0].state != stateViewResults {
		t.Fatalf("watch refresh should stay on results, got %v", m.tabs[0].state)
	}
}

func TestStopWatchIgnoresStaleTicks(t *testing.T) {
	m := startedModel(t, "a.test")
	m, ticks := startWatch(t, m, "5")
	stale := ticks[0]

	// Stop via toggle.
	m, _ = typeKeys(t, m, "w")
	if m.tabs[0].isWatching {
		t.Fatal("watch toggle should stop watching")
	}
	before := tuiFake.count("a.test")
	m, msgs := send(t, m, stale)
	m, ticks = settle(t, m, msgs)
	if tuiFake.count("a.test") != before || len(ticks) != 0 {
		t.Fatalf("stale tick ran a lookup or rescheduled: calls %d->%d ticks %v", before, tuiFake.count("a.test"), ticks)
	}

	// Restart; the old chain's tick must still be ignored, only the new one counts.
	m, ticks = startWatch(t, m, "")
	fresh := ticks[0]
	if fresh.gen == stale.gen {
		t.Fatal("restart should use a new generation")
	}
	before = tuiFake.count("a.test")
	m, msgs = send(t, m, stale)
	_, ticks = settle(t, m, msgs)
	if tuiFake.count("a.test") != before || len(ticks) != 0 {
		t.Fatal("old-generation tick must be ignored after restart")
	}

	// Stop via Back: chain stops too.
	m, _ = typeKeys(t, m, "q")
	if m.tabs[0].isWatching || m.tabs[0].state != stateInputDomain {
		t.Fatalf("back should stop watch and return to input, state=%v", m.tabs[0].state)
	}
	m, msgs = send(t, m, fresh)
	_, ticks = settle(t, m, msgs)
	if len(ticks) != 0 {
		t.Fatal("tick after Back must not reschedule")
	}
}

func TestWatchDiffAndChangedIndicator(t *testing.T) {
	m := startedModel(t, "a.test", "b.test")
	tuiFake.set("a.test", "line1\nline2", nil)
	m, ticks := startWatch(t, m, "5")
	m, _ = typeKeys(t, m, "right") // focus b

	tuiFake.set("a.test", "line1\nline3", nil)
	m, msgs := send(t, m, ticks[0])
	m, _ = settle(t, m, msgs)

	a := m.tabs[0]
	if !a.diffAdded[1] || len(a.diffAdded) != 1 {
		t.Fatalf("diffAdded = %v, want line index 1", a.diffAdded)
	}
	if len(a.diffRemoved) != 1 || a.diffRemoved[0] != "line2" {
		t.Fatalf("diffRemoved = %v", a.diffRemoved)
	}
	if !a.changed {
		t.Fatal("background tab should be marked changed")
	}
	view := m.View()
	if !strings.Contains(view, "●") {
		t.Fatal("tab bar should show changed indicator")
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

func TestGlobalKeysDoNotSwallowTabKeys(t *testing.T) {
	m := startedModel(t, "a.test", "b.test")
	// "w" must reach the tab (watch), not close it.
	m, _ = typeKeys(t, m, "w")
	if len(m.tabs) != 2 || m.tabs[0].state != stateWatchIntervalInput {
		t.Fatalf("w should open watch modal: tabs=%d state=%v", len(m.tabs), m.tabs[0].state)
	}
	// Printable global keys are typed into inputs, and "q" doesn't cancel text entry.
	m, _ = typeKeys(t, m, "x", "n", "q")
	if got := m.tabs[0].intervalInput.Value(); got != "xnq" || len(m.tabs) != 2 {
		t.Fatalf("interval input = %q, tabs = %d", got, len(m.tabs))
	}
	m, _ = typeKeys(t, m, "esc")
	if m.tabs[0].state != stateViewResults {
		t.Fatalf("esc should cancel modal, state=%v", m.tabs[0].state)
	}
	m, _ = typeKeys(t, m, "x")
	if len(m.tabs) != 1 {
		t.Fatal("x should close the tab")
	}
}

func TestValidationMessagesKeepInput(t *testing.T) {
	tuiFake.reset()
	m := newMainModel(nil, "", DefaultConfig(), lookup.Options{})
	m, _ = send(t, m, tea.WindowSizeMsg{Width: 100, Height: 30})
	m, _ = typeKeys(t, m, "enter")
	tab := m.tabs[0]
	if tab.state != stateInputDomain || tab.textInput.Value() != "" || tab.inputErr == "" {
		t.Fatalf("empty target: state=%v value=%q err=%q", tab.state, tab.textInput.Value(), tab.inputErr)
	}
	if !strings.Contains(m.View(), tab.inputErr) {
		t.Fatal("validation message should be displayed")
	}

	m = startedModel(t, "a.test")
	m, _ = typeKeys(t, m, "w", "a", "b", "enter")
	tab = m.tabs[0]
	if tab.state != stateWatchIntervalInput || tab.intervalInput.Value() != "ab" || tab.inputErr == "" {
		t.Fatalf("bad interval: state=%v value=%q err=%q", tab.state, tab.intervalInput.Value(), tab.inputErr)
	}
	if tab.isWatching {
		t.Fatal("invalid interval must not start watching")
	}

	m, _ = typeKeys(t, m, "esc", "ctrl+x")
	m.tabs[0].exportInput.SetValue("")
	m, _ = typeKeys(t, m, "enter")
	tab = m.tabs[0]
	if tab.state != stateExportFilenameInput || tab.exportInput.Value() != "" || tab.inputErr == "" {
		t.Fatalf("empty filename: state=%v value=%q err=%q", tab.state, tab.exportInput.Value(), tab.inputErr)
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
	tab := m.tabs[0]
	if tab.state != stateExportFilenameInput || !strings.HasPrefix(tab.exportInput.Value(), "a.test-"+tuiFakeFlag+"-") {
		t.Fatalf("export not prefilled: state=%v value=%q", tab.state, tab.exportInput.Value())
	}
	path := filepath.Join(t.TempDir(), "sub", "out.txt")
	m.tabs[0].exportInput.SetValue(path)
	m, msgs := send(t, m, keyMsg("enter"))
	m, _ = settle(t, m, msgs)
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "result for a.test" {
		t.Fatalf("export file: %q, %v", data, err)
	}
	if m.tabs[0].state != stateViewResults || !strings.Contains(m.tabs[0].statusMsg, "Saved to") {
		t.Fatalf("after export: state=%v status=%q", m.tabs[0].state, m.tabs[0].statusMsg)
	}
}

func TestExportAllContent(t *testing.T) {
	m := startedModel(t, "a.test", "b.test")
	content := m.exportAllContent()
	for _, want := range []string{"===== a.test — " + tuiFakeName, "result for a.test", "===== b.test — " + tuiFakeName, "result for b.test"} {
		if !strings.Contains(content, want) {
			t.Errorf("export-all missing %q:\n%s", want, content)
		}
	}
}

func TestCopyToClipboard(t *testing.T) {
	var got string
	clipboardWriteAll = func(s string) error { got = s; return nil }
	defer func() { clipboardWriteAll = func(string) error { return nil } }()

	m := startedModel(t, "a.test")
	m, msgs := typeKeys(t, m, "y")
	var status string
	for _, msg := range msgs {
		if s, ok := msg.(tabStatusMsg); ok {
			status = s.text
		}
		m, _ = send(t, m, msg)
	}
	if got != "result for a.test" || !strings.Contains(status, "Copied") {
		t.Fatalf("clipboard=%q status=%q", got, status)
	}
	if !strings.Contains(m.View(), "Copied") {
		t.Fatal("status should be shown")
	}
}

func TestServerModalSetsOptions(t *testing.T) {
	tuiFake.reset()
	m := newMainModel([]string{"a.test"}, tuiFakeName, DefaultConfig(), lookup.Options{Server: "9.9.9.9"})
	m, _ = send(t, m, tea.WindowSizeMsg{Width: 100, Height: 30})
	m, _ = settle(t, m, collect(m.Init()))
	if !strings.Contains(m.View(), "Server: 9.9.9.9") {
		t.Fatal("initial server should be shown in header")
	}
	m, _ = typeKeys(t, m, "s")
	if m.tabs[0].state != stateServerInput || m.tabs[0].serverInput.Value() != "9.9.9.9" {
		t.Fatalf("server modal: state=%v value=%q", m.tabs[0].state, m.tabs[0].serverInput.Value())
	}
	m.tabs[0].serverInput.SetValue("1.1.1.1")
	m, msgs := send(t, m, keyMsg("enter"))
	m, _ = settle(t, m, msgs)
	if m.tabs[0].lookupOpts.Server != "1.1.1.1" || tuiFake.count("a.test") != 2 {
		t.Fatalf("server=%q calls=%d", m.tabs[0].lookupOpts.Server, tuiFake.count("a.test"))
	}
	// New tabs inherit the default options.
	m, _ = typeKeys(t, m, "n")
	if m.tabs[1].lookupOpts.Server != "9.9.9.9" {
		t.Fatalf("new tab server = %q", m.tabs[1].lookupOpts.Server)
	}
}

func TestTruncateUnicode(t *testing.T) {
	s := "日本語のとても長いドメイン名.example.jp"
	for _, w := range []int{1, 5, 8, 13} {
		got := truncateWidth(s, w)
		if !utf8.ValidString(got) {
			t.Fatalf("width %d: invalid UTF-8 %q", w, got)
		}
		if lipgloss.Width(got) > w {
			t.Fatalf("width %d: %q is %d cells", w, got, lipgloss.Width(got))
		}
		if !strings.HasSuffix(got, "…") {
			t.Fatalf("width %d: missing ellipsis in %q", w, got)
		}
	}
	if got := truncateWidth("short", 10); got != "short" {
		t.Fatalf("short string changed: %q", got)
	}

	m := startedModel(t, s, "ünïcødé-ドメイン.test")
	for _, line := range strings.Split(m.View(), "\n") {
		if !utf8.ValidString(line) {
			t.Fatalf("view contains invalid UTF-8: %q", line)
		}
		if lipgloss.Width(line) > m.width {
			t.Fatalf("view line wider than terminal (%d > %d): %q", lipgloss.Width(line), m.width, line)
		}
	}
}
