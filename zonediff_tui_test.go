package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"dlookup/lookup"
)

func zdKey(s string) tea.KeyMsg {
	switch s {
	case "tab":
		return tea.KeyMsg{Type: tea.KeyTab}
	case "shift+tab":
		return tea.KeyMsg{Type: tea.KeyShiftTab}
	case "space":
		return tea.KeyMsg{Type: tea.KeySpace, Runes: []rune{' '}}
	}
	return keyMsg(s)
}

func zdKeys(t *testing.T, m mainModel, keys ...string) (mainModel, []tea.Msg) {
	t.Helper()
	var all []tea.Msg
	for _, k := range keys {
		var out []tea.Msg
		m, out = send(t, m, zdKey(k))
		all = append(all, out...)
	}
	return m, all
}

// stubDiffZone replaces diffZoneFunc for the duration of the test.
func stubDiffZone(t *testing.T, fn func(context.Context, lookup.ZoneDiffOptions) (*lookup.ZoneDiffResult, error)) {
	t.Helper()
	old := diffZoneFunc
	diffZoneFunc = fn
	t.Cleanup(func() { diffZoneFunc = old })
}

func cannedZoneDiff() *lookup.ZoneDiffResult {
	return &lookup.ZoneDiffResult{
		Domain:      "example.com",
		OldServers:  []string{"ns1.old.test", "ns2.old.test"},
		NewServer:   "192.0.2.53",
		Enumeration: "AXFR refused; common names",
		Records: []lookup.RecordDiff{
			{Name: "example.com.", Type: "MX", Status: lookup.DiffMatch, Old: []string{"10 mx.example.com."}, New: []string{"10 mx.example.com."}},
			{Name: "www.example.com.", Type: "A", Status: lookup.DiffChanged, Old: []string{"1.1.1.1"}, New: []string{"2.2.2.2"}, Note: "TTL 300 vs 60"},
			{Name: "mail.example.com.", Type: "A", Status: lookup.DiffMissing, Old: []string{"3.3.3.3"}},
			{Name: "new.example.com.", Type: "TXT", Status: lookup.DiffExtra, New: []string{`"hello"`}},
			{Name: "broken.example.com.", Type: "AAAA", Status: lookup.DiffError, Err: "timeout"},
		},
		Counts: map[lookup.DiffStatus]int{lookup.DiffMatch: 1, lookup.DiffChanged: 1, lookup.DiffMissing: 1, lookup.DiffExtra: 1, lookup.DiffError: 1},
	}
}

// zdResultsModel opens the form via the key from a results view, fills the new
// server and runs the (stubbed) diff to completion.
func zdResultsModel(t *testing.T, res *lookup.ZoneDiffResult) mainModel {
	t.Helper()
	stubDiffZone(t, func(ctx context.Context, o lookup.ZoneDiffOptions) (*lookup.ZoneDiffResult, error) {
		return res, nil
	})
	m := startedModel(t, "example.com")
	m, _ = send(t, m, tea.WindowSizeMsg{Width: 220, Height: 60})
	m, _ = zdKeys(t, m, "D")
	m.tabs[0].zd.form.newServer.SetValue("192.0.2.53")
	m, msgs := send(t, m, keyMsg("enter"))
	for _, msg := range msgs {
		if r, ok := msg.(zoneDiffResultMsg); ok {
			m, _ = send(t, m, r)
		}
	}
	if m.tabs[0].state != stateViewResults || !m.tabs[0].isZoneDiff() {
		t.Fatalf("expected zone diff results, state=%v type=%q err=%v", m.tabs[0].state, m.tabs[0].lookupType, m.tabs[0].err)
	}
	return m
}

func TestZoneDiffOpenFromListAndKey(t *testing.T) {
	tuiFake.reset()
	m := newMainModel(nil, "", DefaultConfig(), lookup.Options{})
	m, _ = send(t, m, tea.WindowSizeMsg{Width: 100, Height: 40})
	m.tabs[0].textInput.SetValue("example.com")
	m, _ = typeKeys(t, m, "enter")
	if !strings.Contains(m.tabs[0].lookupList.View(), zoneDiffName) {
		t.Fatalf("lookup list should contain %q:\n%s", zoneDiffName, m.tabs[0].lookupList.View())
	}
	m, _ = typeKeys(t, m, "G", "enter") // last item is Zone Diff
	tab := m.tabs[0]
	if tab.state != stateZoneDiffForm || tab.lastState != stateSelectLookup {
		t.Fatalf("list entry: state=%v last=%v", tab.state, tab.lastState)
	}
	if v := m.View(); !strings.Contains(v, "Zone diff for example.com") || !strings.Contains(v, "authoritative NS (auto)") {
		t.Fatalf("form not rendered:\n%s", v)
	}
	m, _ = typeKeys(t, m, "esc")
	if m.tabs[0].state != stateSelectLookup {
		t.Fatalf("esc should return to list, got %v", m.tabs[0].state)
	}
	// Shortcut key from the list.
	m, _ = typeKeys(t, m, "D")
	if m.tabs[0].state != stateZoneDiffForm {
		t.Fatalf("D from list: state=%v", m.tabs[0].state)
	}

	// Shortcut key from another lookup's results; esc returns there.
	m = startedModel(t, "example.com")
	m, _ = typeKeys(t, m, "D")
	if m.tabs[0].state != stateZoneDiffForm || m.tabs[0].lastState != stateViewResults {
		t.Fatalf("D from results: state=%v last=%v", m.tabs[0].state, m.tabs[0].lastState)
	}
	// Printable global keys are typed into the form, not handled globally.
	m, _ = typeKeys(t, m, "n", "x", "q")
	if len(m.tabs) != 1 || m.tabs[0].zd.form.newServer.Value() != "nxq" {
		t.Fatalf("typing: tabs=%d value=%q", len(m.tabs), m.tabs[0].zd.form.newServer.Value())
	}
	m, _ = typeKeys(t, m, "esc")
	if m.tabs[0].state != stateViewResults || m.tabs[0].isZoneDiff() {
		t.Fatalf("esc should return to previous results, state=%v type=%q", m.tabs[0].state, m.tabs[0].lookupType)
	}
}

func TestZoneDiffValidation(t *testing.T) {
	called := false
	stubDiffZone(t, func(context.Context, lookup.ZoneDiffOptions) (*lookup.ZoneDiffResult, error) {
		called = true
		return cannedZoneDiff(), nil
	})
	m := startedModel(t, "example.com")
	m, _ = typeKeys(t, m, "D", "enter")
	if tab := m.tabs[0]; tab.state != stateZoneDiffForm || !strings.Contains(tab.inputErr, "required") {
		t.Fatalf("empty server: state=%v err=%q", tab.state, tab.inputErr)
	}
	m, _ = typeKeys(t, m, "b", "a", "d", " ", "!")
	m, _ = typeKeys(t, m, "enter")
	tab := m.tabs[0]
	if tab.state != stateZoneDiffForm || !strings.Contains(tab.inputErr, "new server") || tab.zd.form.newServer.Value() != "bad !" {
		t.Fatalf("bad server: state=%v err=%q value=%q", tab.state, tab.inputErr, tab.zd.form.newServer.Value())
	}
	if !strings.Contains(m.View(), "new server") {
		t.Fatal("validation error should be shown")
	}
	// Bad old server.
	m.tabs[0].zd.form.newServer.SetValue("1.2.3.4")
	m.tabs[0].zd.form.oldServer.SetValue("nope nope")
	m, _ = typeKeys(t, m, "enter")
	if tab := m.tabs[0]; tab.state != stateZoneDiffForm || !strings.Contains(tab.inputErr, "old server") {
		t.Fatalf("bad old server: state=%v err=%q", tab.state, tab.inputErr)
	}
	// IP targets can't be zone-diffed.
	m = startedModel(t, "192.0.2.1")
	m, _ = typeKeys(t, m, "D")
	m.tabs[0].zd.form.newServer.SetValue("1.2.3.4")
	m, _ = typeKeys(t, m, "enter")
	if tab := m.tabs[0]; tab.state != stateZoneDiffForm || !strings.Contains(tab.inputErr, "domain name") {
		t.Fatalf("ip target: state=%v err=%q", tab.state, tab.inputErr)
	}
	if called {
		t.Fatal("invalid form must not run a diff")
	}
}

func TestZoneDiffFormNavigationAndToggles(t *testing.T) {
	m := startedModel(t, "example.com")
	m, _ = zdKeys(t, m, "D")
	f := func() zoneDiffForm { return m.tabs[0].zd.form }
	if f().focus != zdFieldNew || !f().newServer.Focused() || f().compareTTL || !f().tryAXFR {
		t.Fatalf("initial form: focus=%d ttl=%v axfr=%v", f().focus, f().compareTTL, f().tryAXFR)
	}
	m, _ = zdKeys(t, m, "tab")
	if f().focus != zdFieldOld || !f().oldServer.Focused() || f().newServer.Focused() {
		t.Fatalf("tab: focus=%d", f().focus)
	}
	m, _ = zdKeys(t, m, "shift+tab")
	if f().focus != zdFieldNew {
		t.Fatalf("shift+tab: focus=%d", f().focus)
	}
	m, _ = zdKeys(t, m, "shift+tab") // wraps
	if f().focus != zdFieldAXFR {
		t.Fatalf("shift+tab wrap: focus=%d", f().focus)
	}
	m, _ = zdKeys(t, m, "space")
	if f().tryAXFR {
		t.Fatal("space should toggle AXFR off")
	}
	m, _ = zdKeys(t, m, "shift+tab", "space", "space", "space")
	if f().focus != zdFieldTTL || !f().compareTTL {
		t.Fatalf("ttl toggles: focus=%d ttl=%v", f().focus, f().compareTTL)
	}
	if v := m.View(); !strings.Contains(v, "[x] Compare TTLs") || !strings.Contains(v, "[ ] Try AXFR") {
		t.Fatalf("checkboxes not rendered:\n%s", v)
	}
	// Space in a text field is typed, not toggled.
	m, _ = zdKeys(t, m, "shift+tab", "a", "space", "b")
	if f().focus != zdFieldExtra || f().extraNames.Value() != "a b" || !f().compareTTL {
		t.Fatalf("extra names: focus=%d value=%q", f().focus, f().extraNames.Value())
	}
	if got := parseExtraNames(" www, mail ,,_dmarc  x"); strings.Join(got, "|") != "www|mail|_dmarc|x" {
		t.Fatalf("parseExtraNames = %q", got)
	}
}

func TestZoneDiffRunProgressAndResult(t *testing.T) {
	var got lookup.ZoneDiffOptions
	res := cannedZoneDiff()
	stubDiffZone(t, func(ctx context.Context, o lookup.ZoneDiffOptions) (*lookup.ZoneDiffResult, error) {
		got = o
		o.Progress(123, 400)
		return res, nil
	})
	m := startedModel(t, "example.com")
	m, _ = send(t, m, tea.WindowSizeMsg{Width: 200, Height: 60})
	m, _ = zdKeys(t, m, "D")
	m, _ = typeKeys(t, m, strings.Split("192.0.2.53", "")...)
	m.tabs[0].zd.form.oldServer.SetValue("ns1.old.test")
	m.tabs[0].zd.form.extraNames.SetValue("www,mail")
	m, _ = zdKeys(t, m, "tab", "tab", "tab", "space") // TTL on
	m, msgs := send(t, m, keyMsg("enter"))
	if m.tabs[0].state != stateLoading || !m.tabs[0].inFlight {
		t.Fatalf("expected loading, state=%v", m.tabs[0].state)
	}
	if got.NewServer != "192.0.2.53" || got.OldServer != "ns1.old.test" || got.Domain != "example.com" ||
		strings.Join(got.ExtraNames, ",") != "www,mail" || !got.CompareTTL || !got.TryAXFR {
		t.Fatalf("options = %+v", got)
	}
	var prog []tea.Msg
	var result *zoneDiffResultMsg
	for _, msg := range msgs {
		switch msg := msg.(type) {
		case zoneDiffProgressMsg:
			prog = append(prog, msg)
		case zoneDiffResultMsg:
			result = &msg
		}
	}
	if len(prog) != 1 || result == nil {
		t.Fatalf("expected a progress tick and a result, got %#v", msgs)
	}
	m, next := send(t, m, prog[0])
	if !strings.Contains(m.tabs[0].loadingMsg, "Checked 123/400 records") || !strings.Contains(m.View(), "Checked 123/400 records") {
		t.Fatalf("progress not shown: %q", m.tabs[0].loadingMsg)
	}
	if len(next) != 1 {
		t.Fatalf("progress chain should continue while running, got %v", next)
	}
	m, _ = send(t, m, *result)
	tab := m.tabs[0]
	if tab.state != stateViewResults || tab.inFlight {
		t.Fatalf("after result: state=%v inFlight=%v", tab.state, tab.inFlight)
	}
	// Chain ends once the run is done.
	if _, out := send(t, m, next[0]); len(out) != 0 {
		t.Fatalf("progress chain should stop after result, got %v", out)
	}
	content := tab.viewport.View()
	for _, want := range []string{
		"Zone Diff for example.com", "ns1.old.test, ns2.old.test", "192.0.2.53", "AXFR refused; common names",
		"1 match", "1 changed", "1 missing", "1 extra", "1 error",
		"~ www.example.com. A", "- 1.1.1.1", "+ 2.2.2.2", "note: TTL 300 vs 60",
		"- mail.example.com. A", "+ new.example.com. TXT", "! broken.example.com. AAAA", "error: timeout",
	} {
		if !strings.Contains(content, want) {
			t.Errorf("results missing %q:\n%s", want, content)
		}
	}
	if strings.Contains(content, "(authoritative)") {
		t.Error("explicit old server should not be labelled authoritative")
	}
	if strings.Contains(content, "MX") || strings.Contains(content, "No differences") {
		t.Errorf("matches/banner should be hidden:\n%s", content)
	}
	if !strings.Contains(m.View(), "example.com ⇄") {
		t.Errorf("tab title should indicate zone diff:\n%s", m.View())
	}
}

func TestZoneDiffToggleMatchesAndFilter(t *testing.T) {
	m := zdResultsModel(t, cannedZoneDiff())
	content := func() string { return m.tabs[0].viewport.View() }
	if strings.Contains(content(), "= example.com. MX") {
		t.Fatal("matches hidden by default")
	}
	m, _ = typeKeys(t, m, "a")
	if !m.tabs[0].zd.showMatches || !strings.Contains(content(), "= example.com. MX") || !strings.Contains(content(), "10 mx.example.com.") {
		t.Fatalf("toggle should show matches:\n%s", content())
	}
	m, _ = typeKeys(t, m, "a")
	if strings.Contains(content(), "= example.com. MX") {
		t.Fatal("second toggle should hide matches")
	}
	m, _ = typeKeys(t, m, "2")
	c := content()
	if !strings.Contains(c, "mail.example.com.") || strings.Contains(c, "www.example.com.") || !strings.Contains(c, "only missing") {
		t.Fatalf("missing filter:\n%s", c)
	}
	m, _ = typeKeys(t, m, "5")
	if c := content(); !strings.Contains(c, "= example.com. MX") || strings.Contains(c, "mail.example.com.") {
		t.Fatalf("match filter:\n%s", c)
	}
	m, _ = typeKeys(t, m, "0")
	if c := content(); !strings.Contains(c, "www.example.com.") || !strings.Contains(c, "mail.example.com.") {
		t.Fatalf("clear filter:\n%s", c)
	}
}

func TestZoneDiffCleanBanner(t *testing.T) {
	res := &lookup.ZoneDiffResult{
		Domain: "example.com", OldServers: []string{"ns1.old.test"}, NewServer: "192.0.2.53",
		Records: []lookup.RecordDiff{{Name: "example.com.", Type: "A", Status: lookup.DiffMatch, Old: []string{"1.1.1.1"}, New: []string{"1.1.1.1"}}},
		Counts:  map[lookup.DiffStatus]int{lookup.DiffMatch: 1},
	}
	m := zdResultsModel(t, res)
	c := m.tabs[0].viewport.View()
	if !strings.Contains(c, "✓ No differences — new server matches") || !strings.Contains(c, "(authoritative)") {
		t.Fatalf("clean result:\n%s", c)
	}
}

func TestZoneDiffCancel(t *testing.T) {
	started := make(chan struct{}, 4)
	cancelled := make(chan struct{}, 4)
	stubDiffZone(t, func(ctx context.Context, o lookup.ZoneDiffOptions) (*lookup.ZoneDiffResult, error) {
		started <- struct{}{}
		<-ctx.Done()
		cancelled <- struct{}{}
		return nil, ctx.Err()
	})
	wait := func(ch chan struct{}, what string) {
		t.Helper()
		select {
		case <-ch:
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for %s", what)
		}
	}
	run := func(m mainModel) mainModel {
		t.Helper()
		m, _ = typeKeys(t, m, "D")
		m.tabs[m.activeTab].zd.form.newServer.SetValue("192.0.2.53")
		nm, cmd := m.Update(keyMsg("enter"))
		m = nm.(mainModel)
		go collect(cmd) // the diff blocks until cancelled
		wait(started, "diff start")
		return m
	}

	m := run(startedModel(t, "example.com"))
	if m.tabs[0].state != stateLoading {
		t.Fatalf("state=%v", m.tabs[0].state)
	}
	seq := m.tabs[0].lookupSeq
	m, _ = typeKeys(t, m, "esc")
	wait(cancelled, "ctx cancel on esc")
	if m.tabs[0].state != stateSelectLookup || m.tabs[0].inFlight || m.tabs[0].lookupSeq == seq {
		t.Fatalf("after esc: state=%v inFlight=%v", m.tabs[0].state, m.tabs[0].inFlight)
	}
	// A late result of the cancelled run is ignored.
	m, _ = send(t, m, zoneDiffResultMsg{tabId: m.tabs[0].id, seq: seq, result: cannedZoneDiff()})
	if m.tabs[0].state != stateSelectLookup {
		t.Fatalf("stale result changed state to %v", m.tabs[0].state)
	}

	// Closing the tab cancels its run.
	m = run(startedModel(t, "a.test", "example.com"))
	m, _ = typeKeys(t, m, "x")
	wait(cancelled, "ctx cancel on tab close")
	if len(m.tabs) != 1 {
		t.Fatalf("tabs=%d", len(m.tabs))
	}
}

func TestZoneDiffExportCopyAndBack(t *testing.T) {
	var clip string
	clipboardWriteAll = func(s string) error { clip = s; return nil }
	defer func() { clipboardWriteAll = func(string) error { return nil } }()

	res := cannedZoneDiff()
	m := zdResultsModel(t, res)
	want := lookup.FormatZoneDiff(res, false)

	m, _ = typeKeys(t, m, "ctrl+x")
	tab := m.tabs[0]
	if tab.state != stateExportFilenameInput || !strings.HasPrefix(tab.exportInput.Value(), "example.com-zone-diff-") {
		t.Fatalf("export: state=%v value=%q", tab.state, tab.exportInput.Value())
	}
	path := filepath.Join(t.TempDir(), "zd.txt")
	m.tabs[0].exportInput.SetValue(path)
	m, msgs := send(t, m, keyMsg("enter"))
	m, _ = settle(t, m, msgs)
	data, err := os.ReadFile(path)
	if err != nil || string(data) != want {
		t.Fatalf("export file = %q, %v; want %q", data, err, want)
	}

	m, msgs = typeKeys(t, m, "y")
	m, _ = settle(t, m, msgs)
	if clip != want {
		t.Fatalf("clipboard = %q, want %q", clip, want)
	}

	// Showing matches is reflected in the export text.
	m, _ = typeKeys(t, m, "a")
	if got := m.tabs[0].plainContent(); got != lookup.FormatZoneDiff(res, true) {
		t.Fatalf("plain content with matches = %q", got)
	}

	all := m.exportAllContent()
	if !strings.Contains(all, "===== example.com — "+zoneDiffName+" ⇄ 192.0.2.53 =====") {
		t.Fatalf("export-all header:\n%s", all)
	}

	// Watch and server don't apply here.
	m, _ = typeKeys(t, m, "w", "s")
	if m.tabs[0].state != stateViewResults || m.tabs[0].isWatching {
		t.Fatalf("w/s should be ignored: state=%v", m.tabs[0].state)
	}

	// Re-run reopens the form prefilled; esc returns to results.
	m, _ = typeKeys(t, m, "r")
	if m.tabs[0].state != stateZoneDiffForm || m.tabs[0].zd.form.newServer.Value() != "192.0.2.53" {
		t.Fatalf("r: state=%v value=%q", m.tabs[0].state, m.tabs[0].zd.form.newServer.Value())
	}
	m, _ = typeKeys(t, m, "esc", "enter")
	if m.tabs[0].state != stateZoneDiffForm {
		t.Fatalf("enter should reopen the form, state=%v", m.tabs[0].state)
	}
	m, _ = typeKeys(t, m, "esc", "q")
	if m.tabs[0].state != stateSelectLookup {
		t.Fatalf("back should go to the lookup list, state=%v", m.tabs[0].state)
	}
}

func TestZoneDiffErrorView(t *testing.T) {
	stubDiffZone(t, func(context.Context, lookup.ZoneDiffOptions) (*lookup.ZoneDiffResult, error) {
		return nil, os.ErrDeadlineExceeded
	})
	m := startedModel(t, "example.com")
	m, _ = typeKeys(t, m, "D")
	m.tabs[0].zd.form.newServer.SetValue("192.0.2.53")
	m, msgs := send(t, m, keyMsg("enter"))
	m, _ = settle(t, m, msgs)
	if m.tabs[0].state != stateError || !strings.Contains(m.tabs[0].viewport.View(), "Error running "+zoneDiffName) {
		t.Fatalf("error view: state=%v\n%s", m.tabs[0].state, m.tabs[0].viewport.View())
	}
	m, _ = typeKeys(t, m, "r")
	if m.tabs[0].state != stateZoneDiffForm {
		t.Fatalf("r from error should reopen the form, state=%v", m.tabs[0].state)
	}
}

func TestZoneDiffHelpBar(t *testing.T) {
	m := zdResultsModel(t, cannedZoneDiff())
	help := m.helpView()
	for _, want := range []string{"Re-run", "a: Show matches", "Filter", "ctrl+x: Export", "y: Copy"} {
		if !strings.Contains(help, want) {
			t.Errorf("results help missing %q: %s", want, help)
		}
	}
	for _, bad := range []string{"Watch", "s: Server", "D: Zone diff"} {
		if strings.Contains(help, bad) {
			t.Errorf("results help should not contain %q: %s", bad, help)
		}
	}
	m, _ = typeKeys(t, m, "a")
	if !strings.Contains(m.helpView(), "a: Hide matches") {
		t.Errorf("help should offer hiding matches: %s", m.helpView())
	}
	m, _ = typeKeys(t, m, "r")
	if h := m.helpView(); !strings.Contains(h, "Field") || !strings.Contains(h, "Toggle") || !strings.Contains(h, "enter: Run") {
		t.Errorf("form help: %s", h)
	}
	m, _ = typeKeys(t, m, "esc", "q")
	if h := m.helpView(); !strings.Contains(h, "D: Zone diff") {
		t.Errorf("select help missing zone diff key: %s", h)
	}

	m = startedModel(t, "a.test")
	m, _ = send(t, m, tea.WindowSizeMsg{Width: 220, Height: 40})
	if h := m.helpView(); !strings.Contains(h, "D: Zone diff") || !strings.Contains(h, "Watch") {
		t.Errorf("regular results help: %s", h)
	}
}

func TestZoneDiffKeybindings(t *testing.T) {
	k := DefaultKeybindings()
	if k.ZoneDiff != "D" || k.ToggleMatches != "a" {
		t.Fatalf("defaults: zone_diff=%q toggle_matches=%q", k.ZoneDiff, k.ToggleMatches)
	}
	if err := validateKeybindings(k); err != nil {
		t.Fatal(err)
	}
	k.ToggleMatches = "y"
	if err := validateKeybindings(k); err == nil || !strings.Contains(err.Error(), "toggle_matches") {
		t.Fatalf("expected conflict with copy, got %v", err)
	}
	k = DefaultKeybindings()
	k.ZoneDiff = ""
	if err := validateKeybindings(k); err == nil || !strings.Contains(err.Error(), "zone_diff is empty") {
		t.Fatalf("expected empty zone_diff error, got %v", err)
	}

	// Custom bindings are honoured.
	cfg := DefaultConfig()
	cfg.Keybindings.ZoneDiff = "z"
	cfg.Keybindings.ToggleMatches = "m"
	stubDiffZone(t, func(context.Context, lookup.ZoneDiffOptions) (*lookup.ZoneDiffResult, error) {
		return cannedZoneDiff(), nil
	})
	tuiFake.reset()
	m := newMainModel([]string{"example.com"}, tuiFakeName, cfg, lookup.Options{})
	m, _ = send(t, m, tea.WindowSizeMsg{Width: 200, Height: 40})
	m, _ = settle(t, m, collect(m.Init()))
	m, _ = typeKeys(t, m, "z")
	m.tabs[0].zd.form.newServer.SetValue("192.0.2.53")
	m, msgs := send(t, m, keyMsg("enter"))
	for _, msg := range msgs {
		if r, ok := msg.(zoneDiffResultMsg); ok {
			m, _ = send(t, m, r)
		}
	}
	m, _ = typeKeys(t, m, "m")
	if !m.tabs[0].zd.showMatches {
		t.Fatal("custom toggle_matches key should work")
	}
}
