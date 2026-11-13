package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"dlookup/lookup"
)

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

// setZoneDiffSource chooses a source in the open zone diff dialog and lets it
// show the matching fields.
func setZoneDiffSource(t *testing.T, m mainModel, key, value string) mainModel {
	t.Helper()
	m.dialog.SetValue(key, value)
	m.syncZoneDiffDialog()
	return m
}

// runZoneDiffDialog opens the zone diff dialog with D on the active tab and
// submits it with values.
func runZoneDiffDialog(t *testing.T, m mainModel, values map[string]string) (mainModel, []tea.Msg) {
	t.Helper()
	m, _ = typeKeys(t, m, "D")
	expectDialog(t, m, dlgZoneDiff)
	return submit(t, m, values)
}

// zdResultsModel runs the (stubbed) diff to completion from a results tab.
func zdResultsModel(t *testing.T, res *lookup.ZoneDiffResult) mainModel {
	t.Helper()
	stubDiffZone(t, func(ctx context.Context, o lookup.ZoneDiffOptions) (*lookup.ZoneDiffResult, error) {
		return res, nil
	})
	m := startedModel(t, "example.com")
	m, _ = send(t, m, tea.WindowSizeMsg{Width: 220, Height: 60})
	m, msgs := runZoneDiffDialog(t, m, map[string]string{"new": "192.0.2.53"})
	m, _ = settle(t, m, msgs)
	if m.tabs[0].state != stateViewResults || !m.tabs[0].isZoneDiff() {
		t.Fatalf("expected zone diff results, state=%v type=%q err=%v", m.tabs[0].state, m.tabs[0].lookupType, m.tabs[0].err)
	}
	return m
}

func TestZoneDiffDialogFromKeyAndHome(t *testing.T) {
	m := startedModel(t, "example.com")
	m, _ = typeKeys(t, m, "D")
	expectDialog(t, m, dlgZoneDiff)
	if m.dialog.Value("domain") != "example.com" || m.dialog.Focused() != "new" {
		t.Fatalf("prefill: domain=%q focus=%q", m.dialog.Value("domain"), m.dialog.Focused())
	}
	if v := m.View(); !strings.Contains(v, "Zone diff") || !strings.Contains(v, "Authoritative servers (auto)") {
		t.Fatalf("dialog not rendered:\n%s", v)
	}
	// Printable global keys are typed into the dialog.
	m, _ = typeKeys(t, m, "n", "x", "q")
	if len(m.tabs) != 1 || m.dialog.Value("new") != "nxq" {
		t.Fatalf("typing: tabs=%d value=%q", len(m.tabs), m.dialog.Value("new"))
	}
	m, _ = typeKeys(t, m, "esc")
	if m.dlg != dlgNone || m.tabs[0].state != stateViewResults || m.tabs[0].isZoneDiff() {
		t.Fatalf("esc should leave the tab as it was, type=%q", m.tabs[0].lookupType)
	}

	// From Home (F4) the dialog starts empty and runs in a new tab.
	stubDiffZone(t, func(context.Context, lookup.ZoneDiffOptions) (*lookup.ZoneDiffResult, error) {
		return cannedZoneDiff(), nil
	})
	m = homeModel(t, DefaultConfig())
	m, _ = typeKeys(t, m, "f4")
	expectDialog(t, m, dlgZoneDiff)
	if m.dialog.Value("domain") != "" || m.dialog.Focused() != "domain" {
		t.Fatalf("home zone diff: domain=%q focus=%q", m.dialog.Value("domain"), m.dialog.Focused())
	}
	m, msgs := submit(t, m, map[string]string{"domain": "example.com", "new": "192.0.2.53"})
	m, _ = settle(t, m, msgs)
	if len(m.tabs) != 2 || m.activeTab != 1 || !m.tabs[1].isZoneDiff() || m.tabs[1].state != stateViewResults {
		t.Fatalf("tabs=%d active=%d", len(m.tabs), m.activeTab)
	}
}

func TestZoneDiffValidation(t *testing.T) {
	var called atomic.Bool
	stubDiffZone(t, func(context.Context, lookup.ZoneDiffOptions) (*lookup.ZoneDiffResult, error) {
		called.Store(true)
		return cannedZoneDiff(), nil
	})
	m := startedModel(t, "example.com")
	m, _ = runZoneDiffDialog(t, m, nil)
	if m.dlg != dlgZoneDiff || !strings.Contains(m.dialog.Err, "required") {
		t.Fatalf("empty server: dlg=%v err=%q", m.dlg, m.dialog.Err)
	}
	m, _ = typeKeys(t, m, "bad", "space", "!", "enter")
	if m.dlg != dlgZoneDiff || !strings.Contains(m.dialog.Err, "new server") || m.dialog.Value("new") != "bad !" {
		t.Fatalf("bad server: err=%q value=%q", m.dialog.Err, m.dialog.Value("new"))
	}
	if !strings.Contains(m.View(), "new server") {
		t.Fatal("validation error should be shown")
	}
	m = setZoneDiffSource(t, m, "oldsrc", zdSrcServer)
	m, _ = submit(t, m, map[string]string{"new": "1.2.3.4", "old": ""})
	if m.dlg != dlgZoneDiff || !strings.Contains(m.dialog.Err, "old server is required") {
		t.Fatalf("empty old server: err=%q", m.dialog.Err)
	}
	m, _ = submit(t, m, map[string]string{"new": "1.2.3.4", "old": "nope nope"})
	if m.dlg != dlgZoneDiff || !strings.Contains(m.dialog.Err, "old server") {
		t.Fatalf("bad old server: err=%q", m.dialog.Err)
	}
	// IP targets can't be zone-diffed: the domain isn't prefilled, and typing one is rejected.
	m = startedModel(t, "192.0.2.1")
	m, _ = runZoneDiffDialog(t, m, map[string]string{"new": "1.2.3.4"})
	if m.dlg != dlgZoneDiff || !strings.Contains(m.dialog.Err, "domain") {
		t.Fatalf("empty domain: err=%q", m.dialog.Err)
	}
	m, _ = submit(t, m, map[string]string{"domain": "192.0.2.1"})
	if m.dlg != dlgZoneDiff || !strings.Contains(m.dialog.Err, "domain name") {
		t.Fatalf("ip target: err=%q", m.dialog.Err)
	}
	if called.Load() {
		t.Fatal("invalid form must not run a diff")
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
	m, _ = typeKeys(t, m, "D", "192.0.2.53")
	m = setZoneDiffSource(t, m, "oldsrc", zdSrcServer)
	m.dialog.FocusField("old")
	m, _ = typeKeys(t, m, "ns1.old.test", "tab", "www,mail", "tab")
	if m.dialog.Focused() != "ttl" || m.dialog.Value("ttl") != "false" || m.dialog.Value("axfr") != "true" {
		t.Fatalf("focus=%q ttl=%q axfr=%q", m.dialog.Focused(), m.dialog.Value("ttl"), m.dialog.Value("axfr"))
	}
	m, _ = typeKeys(t, m, "space") // TTL on
	if v := m.View(); !strings.Contains(v, "[x] Compare TTLs") || !strings.Contains(v, "[x] Try AXFR") {
		t.Fatalf("checkboxes not rendered:\n%s", v)
	}
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
	if v := m.View(); !strings.Contains(v, "example.com ⇄") || !strings.Contains(v, "⇄ 192.0.2.53") {
		t.Errorf("tab/panel title should indicate zone diff:\n%s", v)
	}
	// The form values are kept for the next run.
	if f := m.tabs[0].zd.form; f.newServer != "192.0.2.53" || !f.compareTTL || f.extraNames != "www,mail" {
		t.Fatalf("form = %+v", f)
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
	if it := m.menuItem(actMatches); it.Disabled || it.Checked == nil || !*it.Checked {
		t.Fatal("View → Show matches should be enabled and checked")
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
	// The View menu's filter items do the same as the number keys.
	m, _ = typeKeys(t, m, "alt+v", "down") // Show matches → Filter: all
	m, _ = typeKeys(t, m, "enter")
	if m.menu.IsOpen() || m.tabs[0].zd.filtered {
		t.Fatalf("menu Filter: all should clear the filter (open=%v)", m.menu.IsOpen())
	}
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
		m.dialog.SetValue("new", "192.0.2.53")
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
	if m.tabs[0].state != stateIdle || m.tabs[0].inFlight || m.tabs[0].lookupSeq == seq {
		t.Fatalf("after esc: state=%v inFlight=%v", m.tabs[0].state, m.tabs[0].inFlight)
	}
	m, _ = send(t, m, zoneDiffResultMsg{tabId: m.tabs[0].id, seq: seq, result: cannedZoneDiff()})
	if m.tabs[0].state != stateIdle {
		t.Fatalf("stale result changed state to %v", m.tabs[0].state)
	}

	// Closing the tab cancels its run.
	m = startedModel(t, "a.test", "example.com")
	m, _ = typeKeys(t, m, "right")
	m = run(m)
	m, _ = typeKeys(t, m, "x")
	wait(cancelled, "ctx cancel on tab close")
	if len(m.tabs) != 1 {
		t.Fatalf("tabs=%d", len(m.tabs))
	}
}

func TestZoneDiffExportCopyRerunAndEdit(t *testing.T) {
	var clip string
	clipboardWriteAll = func(s string) error { clip = s; return nil }
	defer func() { clipboardWriteAll = func(string) error { return nil } }()

	res := cannedZoneDiff()
	m := zdResultsModel(t, res)
	want := lookup.FormatZoneDiff(res, false)

	m, _ = typeKeys(t, m, "ctrl+x")
	expectDialog(t, m, dlgExport)
	if !strings.HasPrefix(m.dialog.Value("file"), "example.com-zone-diff-") {
		t.Fatalf("export prefill %q", m.dialog.Value("file"))
	}
	path := filepath.Join(t.TempDir(), "zd.txt")
	m, msgs := submit(t, m, map[string]string{"file": path})
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

	m, _ = typeKeys(t, m, "a")
	if got := m.tabs[0].plainContent(); got != lookup.FormatZoneDiff(res, true) {
		t.Fatalf("plain content with matches = %q", got)
	}
	if all := m.exportAllContent(); !strings.Contains(all, "===== example.com — "+zoneDiffName+" ⇄ 192.0.2.53 =====") {
		t.Fatalf("export-all header:\n%s", all)
	}

	// Watch and server don't apply here.
	m, _ = typeKeys(t, m, "w", "s")
	if m.dlg != dlgNone || m.tabs[0].isWatching {
		t.Fatalf("w/s should be ignored: dlg=%v", m.dlg)
	}

	// r re-runs with the same options.
	var runs atomic.Int32
	stubDiffZone(t, func(context.Context, lookup.ZoneDiffOptions) (*lookup.ZoneDiffResult, error) {
		runs.Add(1)
		return res, nil
	})
	m, msgs = typeKeys(t, m, "r")
	m, _ = settle(t, m, msgs)
	if runs.Load() != 1 || m.tabs[0].state != stateViewResults {
		t.Fatalf("re-run: runs=%d state=%v", runs.Load(), m.tabs[0].state)
	}
	// Enter (Change) reopens the zone diff dialog prefilled.
	m, _ = typeKeys(t, m, "enter")
	expectDialog(t, m, dlgZoneDiff)
	if m.dialog.Value("new") != "192.0.2.53" || m.dialog.Value("domain") != "example.com" {
		t.Fatalf("prefill new=%q", m.dialog.Value("new"))
	}
}

func TestZoneDiffErrorView(t *testing.T) {
	stubDiffZone(t, func(context.Context, lookup.ZoneDiffOptions) (*lookup.ZoneDiffResult, error) {
		return nil, os.ErrDeadlineExceeded
	})
	m := startedModel(t, "example.com")
	m, msgs := runZoneDiffDialog(t, m, map[string]string{"new": "192.0.2.53"})
	m, _ = settle(t, m, msgs)
	if m.tabs[0].state != stateError || !strings.Contains(m.tabs[0].viewport.View(), "Error running "+zoneDiffName) {
		t.Fatalf("error view: state=%v\n%s", m.tabs[0].state, m.tabs[0].viewport.View())
	}
	m, _ = typeKeys(t, m, "f3")
	expectDialog(t, m, dlgZoneDiff)
}

func TestZoneDiffHints(t *testing.T) {
	m := zdResultsModel(t, cannedZoneDiff())
	h := m.hints()
	for _, want := range []string{"a matches", "1-5/0 filter", "r re-run", "ctrl+x export", "y copy"} {
		if !strings.Contains(h, want) {
			t.Errorf("hints missing %q: %s", want, h)
		}
	}
	for _, bad := range []string{"watch", "server"} {
		if strings.Contains(h, bad) {
			t.Errorf("hints should not contain %q: %s", bad, h)
		}
	}
	m = startedModel(t, "a.test")
	if h := m.hints(); !strings.Contains(h, "w watch") || !strings.Contains(h, "s server") {
		t.Errorf("regular results hints: %s", h)
	}
}

func TestZoneDiffKeybindings(t *testing.T) {
	k := DefaultKeybindings()
	if k.ZoneDiff != "D" || k.ToggleMatches != "a" {
		t.Fatalf("defaults: zone_diff=%q toggle_matches=%q", k.ZoneDiff, k.ToggleMatches)
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
	expectDialog(t, m, dlgZoneDiff)
	m, msgs := submit(t, m, map[string]string{"new": "192.0.2.53"})
	m, _ = settle(t, m, msgs)
	m, _ = typeKeys(t, m, "m")
	if !m.tabs[0].zd.showMatches {
		t.Fatal("custom toggle_matches key should work")
	}
}

func TestZoneDiffDialogZoneFileSource(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "export.zone")
	if err := os.WriteFile(good, []byte("$ORIGIN example.com.\n$TTL 300\n@ IN A 192.0.2.1\nwww IN A 192.0.2.2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	broken := filepath.Join(dir, "broken.zone")
	if err := os.WriteFile(broken, []byte("@ IN A not-an-address\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var got lookup.ZoneDiffOptions
	var called atomic.Int32
	stubDiffZone(t, func(ctx context.Context, o lookup.ZoneDiffOptions) (*lookup.ZoneDiffResult, error) {
		got = o
		called.Add(1)
		r := cannedZoneDiff()
		r.OldServers, r.OldFile = nil, o.OldZoneLabel
		r.NewServers = []string{"192.0.2.53:53", "192.0.2.54:53"}
		r.NewServer = "192.0.2.53:53"
		r.Warnings = []string{"old zone file: ignored 1 record(s) outside example.com."}
		return r, nil
	})
	m := startedModel(t, "example.com")
	m, _ = send(t, m, tea.WindowSizeMsg{Width: 200, Height: 60})
	m, _ = typeKeys(t, m, "D")
	expectDialog(t, m, dlgZoneDiff)
	if hasField(m, "old") || hasField(m, "oldfile") || hasField(m, "probe") || !hasField(m, "new") {
		t.Fatalf("default fields: %+v", m.dialog.Fields)
	}
	m = setZoneDiffSource(t, m, "oldsrc", zdSrcFile)
	if !hasField(m, "oldfile") || hasField(m, "old") || !hasField(m, "probe") {
		t.Fatalf("file fields: %+v", m.dialog.Fields)
	}
	if !strings.Contains(m.View(), "Old zone file") {
		t.Fatal("old zone file field not rendered")
	}
	m = setZoneDiffSource(t, m, "newsrc", zdSrcAuth)
	if hasField(m, "new") || hasField(m, "newfile") {
		t.Fatalf("live new side should have no server/file field: %+v", m.dialog.Fields)
	}

	// Validation: missing path, missing file, unparseable file.
	m, _ = submit(t, m, nil)
	if m.dlg != dlgZoneDiff || !strings.Contains(m.dialog.Err, "old zone file: enter a file path") {
		t.Fatalf("empty path: err=%q", m.dialog.Err)
	}
	m, _ = submit(t, m, map[string]string{"oldfile": filepath.Join(dir, "missing.zone")})
	if m.dlg != dlgZoneDiff || !strings.Contains(m.dialog.Err, "old zone file") || !strings.Contains(m.dialog.Err, "no such file") {
		t.Fatalf("missing file: err=%q", m.dialog.Err)
	}
	m, _ = submit(t, m, map[string]string{"oldfile": broken})
	if m.dlg != dlgZoneDiff || !strings.Contains(m.dialog.Err, "old zone file") {
		t.Fatalf("broken file: err=%q", m.dialog.Err)
	}
	if called.Load() != 0 {
		t.Fatal("invalid form must not run a diff")
	}

	// Valid: file vs live authoritative, domain may be left empty.
	m, msgs := submit(t, m, map[string]string{"oldfile": good, "domain": "", "probe": "true"})
	if m.dlg != dlgNone {
		t.Fatalf("dialog still open: err=%q", m.dialog.Err)
	}
	if !strings.Contains(m.tabs[0].loadingMsg, "the live zone") {
		t.Errorf("loading msg = %q", m.tabs[0].loadingMsg)
	}
	m, _ = settle(t, m, msgs)
	if got.Domain != "example.com" || got.OldZone == nil || got.OldZoneLabel != good || got.NewServer != "" || got.NewZone != nil || !got.Probe {
		t.Fatalf("options = %+v", got)
	}
	if len(got.OldZone.Lookup("www", "A")) != 1 {
		t.Errorf("parsed zone = %+v", got.OldZone)
	}
	content := m.tabs[0].viewport.View()
	for _, want := range []string{"zone file " + good, "live authoritative", "Warning:", "outside example.com."} {
		if !strings.Contains(content, want) {
			t.Errorf("results missing %q:\n%s", want, content)
		}
	}

	// The sources and path are remembered for the next dialog on this tab.
	m, _ = typeKeys(t, m, "D")
	expectDialog(t, m, dlgZoneDiff)
	if m.dialog.Value("oldsrc") != zdSrcFile || m.dialog.Value("oldfile") != good || m.dialog.Value("newsrc") != zdSrcAuth || m.dialog.Value("probe") != "true" {
		t.Fatalf("remembered: %v", m.dialog.Values())
	}

	// New side as a file too; live new side needs an old file.
	m = setZoneDiffSource(t, m, "newsrc", zdSrcFile)
	if m.dialog.Focused() == "" || !hasField(m, "newfile") {
		t.Fatalf("new file field: %+v", m.dialog.Fields)
	}
	m, msgs = submit(t, m, map[string]string{"newfile": good})
	m, _ = settle(t, m, msgs)
	if got.NewZone == nil || got.NewZoneLabel != good || got.OldZone == nil {
		t.Fatalf("file vs file options = %+v", got)
	}
	m, _ = typeKeys(t, m, "D")
	m = setZoneDiffSource(t, m, "oldsrc", zdSrcAuth)
	m = setZoneDiffSource(t, m, "newsrc", zdSrcAuth)
	m, _ = submit(t, m, nil)
	if m.dlg != dlgZoneDiff || !strings.Contains(m.dialog.Err, "need an old zone file") {
		t.Fatalf("auth vs auth: err=%q", m.dialog.Err)
	}
}
