package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"dlookup/lookup"
	"dlookup/ui"
	"dlookup/zonefile"
)

// openZoneItem opens the Zone menu with alt+z and presses the item's hotkey.
// If the action is not dispatched to a dialog (not wired into do() yet), it
// runs the action directly.
func openZoneItem(t *testing.T, m mainModel, hotkey, action string, want dialogKind) mainModel {
	t.Helper()
	m, _ = typeKeys(t, m, "alt+z", hotkey)
	if m.dlg == dlgNone {
		cmd := m.handleZoneAction(action)
		collect(cmd)
		m.syncMenu()
	}
	expectDialog(t, m, want)
	return m
}

// submitZone sets the open zone dialog's values and submits it.
func submitZone(t *testing.T, m mainModel, values map[string]string) (mainModel, []tea.Msg) {
	t.Helper()
	for k, v := range values {
		m.dialog.SetValue(k, v)
	}
	cmd, ok := m.submitZoneDialog(m.dlg, ui.DialogResult{Action: btnRun, Values: m.dialog.Values()})
	if !ok {
		t.Fatalf("dialog %v not handled by submitZoneDialog", m.dlg)
	}
	m.syncMenu()
	return m, collect(cmd)
}

func TestZoneMenu(t *testing.T) {
	m := homeModel(t, DefaultConfig())
	var titles []string
	for _, menu := range m.menu.Menus {
		titles = append(titles, menu.Title)
	}
	if got := strings.Join(titles, " "); got != "&Lookup &Tab &Zone &View &Options &Help" {
		t.Fatalf("menus = %s", got)
	}
	for _, a := range []string{actZoneExport, actZoneConvert, actZoneShow} {
		if it := m.menuItem(a); it == nil || it.Disabled {
			t.Errorf("menu item %s missing or disabled", a)
		}
		if !isZoneAction(a) {
			t.Errorf("isZoneAction(%s) = false", a)
		}
	}
	if isZoneAction(actZoneDiff) {
		t.Error("zone diff is not a zone: action")
	}
	if _, ok := m.submitZoneDialog(dlgLookup, ui.DialogResult{Action: btnRun}); ok {
		t.Error("submitZoneDialog claimed the lookup dialog")
	}
	m, _ = typeKeys(t, m, "alt+z")
	if !m.menu.IsOpen() || !strings.Contains(m.View(), "Show zone file…") {
		t.Fatal("alt+z should open the Zone menu")
	}
	// Zone diff… in the Zone menu is the existing zone diff action.
	m, _ = typeKeys(t, m, "d")
	expectDialog(t, m, dlgZoneDiff)
}

func TestZoneExportDialogFlow(t *testing.T) {
	var got lookup.ZoneDumpOptions
	stubDumpZone(t, func(ctx context.Context, o lookup.ZoneDumpOptions) (*zonefile.Zone, string, error) {
		got = o
		return cannedZone(), "probe (12 names)", nil
	})
	m := startedModel(t, "example.com")
	m = openZoneItem(t, m, "e", actZoneExport, dlgZoneExport)
	if m.dialog.Value("domain") != "example.com" || m.dialog.Value("file") != "example.com.zone" || m.dialog.Value("format") != "bind" {
		t.Fatalf("prefill: %v", m.dialog.Values())
	}
	dir := t.TempDir()
	// Changing the format retargets the default file name.
	m.dialog.SetValue("file", filepath.Join(dir, "example.com.zone"))
	m, msgs := submitZone(t, m, map[string]string{"format": "route53-change", "extra": "shop vpn", "axfr": "false"})
	if m.dlg != dlgNone {
		t.Fatalf("dialog still open: %s", m.dialog.Err)
	}
	if len(m.tabs) != 2 || m.activeTab != 1 {
		t.Fatalf("export should run in a new tab: tabs=%d active=%d", len(m.tabs), m.activeTab)
	}
	m, _ = settle(t, m, msgs)
	tab := m.tabs[m.activeTab]
	if tab.state != stateViewResults || tab.inFlight {
		t.Fatalf("state=%v err=%v", tab.state, tab.err)
	}
	if got.Domain != "example.com" || got.TryAXFR || strings.Join(got.ExtraNames, ",") != "shop,vpn" {
		t.Errorf("dump options = %+v", got)
	}
	out := filepath.Join(dir, "example.com.route53-change.json")
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("export file: %v", err)
	}
	if !strings.Contains(string(data), `"Action": "UPSERT"`) || strings.Contains(string(data), `"SOA"`) {
		t.Errorf("change batch:\n%s", data)
	}
	content := tab.plainContent()
	for _, want := range []string{"Zone export of example.com", "probe (12 names)", "may be incomplete", out, "www", "CNAME"} {
		if !strings.Contains(content, want) {
			t.Errorf("result lacks %q:\n%s", want, content)
		}
	}
	// No lookup type: re-run and watch don't apply.
	if it := m.menuItem(actRerun); it == nil || !it.Disabled {
		t.Error("re-run should be disabled on an export tab")
	}
}

func TestZoneExportValidationAndErrors(t *testing.T) {
	stubDumpZone(t, func(ctx context.Context, o lookup.ZoneDumpOptions) (*zonefile.Zone, string, error) {
		return nil, "", context.DeadlineExceeded
	})
	m := homeModel(t, DefaultConfig())
	m = openZoneItem(t, m, "e", actZoneExport, dlgZoneExport)
	if m.dialog.Value("domain") != "" || m.dialog.Value("file") != "zone.zone" {
		t.Errorf("prefill on Home: %v", m.dialog.Values())
	}
	m, _ = submitZone(t, m, map[string]string{"domain": "not a domain!"})
	if m.dlg != dlgZoneExport || m.dialog.Err == "" {
		t.Fatal("invalid domain should keep the dialog open with an error")
	}
	m, _ = submitZone(t, m, map[string]string{"domain": "example.com", "server": "bad server!"})
	if m.dlg != dlgZoneExport || m.dialog.Err == "" {
		t.Fatal("invalid server should keep the dialog open")
	}
	m, msgs := submitZone(t, m, map[string]string{"server": "", "file": filepath.Join(t.TempDir(), "x.zone")})
	m, _ = settle(t, m, msgs)
	if tab := m.tabs[m.activeTab]; tab.state != stateError || !strings.Contains(tab.plainContent(), "deadline") {
		t.Errorf("dump error: state=%v content=%q", tab.state, tab.plainContent())
	}
}

func TestZoneExportCancel(t *testing.T) {
	started := make(chan struct{})
	stubDumpZone(t, func(ctx context.Context, o lookup.ZoneDumpOptions) (*zonefile.Zone, string, error) {
		close(started)
		<-ctx.Done()
		return nil, "", ctx.Err()
	})
	m := startedModel(t, "example.com")
	m = openZoneItem(t, m, "e", actZoneExport, dlgZoneExport)
	m.dialog.SetValue("file", filepath.Join(t.TempDir(), "example.com.zone"))
	cmd, _ := m.submitZoneDialog(m.dlg, ui.DialogResult{Action: btnRun, Values: m.dialog.Values()})
	done := make(chan tea.Msg, 1)
	go func() { done <- cmd() }()
	<-started
	if !m.busy() {
		t.Error("an export should count as busy")
	}
	m, _ = typeKeys(t, m, "esc")
	msg := <-done
	m, _ = send(t, m, msg) // stale result is ignored
	if tab := m.tabs[m.activeTab]; tab.state != stateIdle || tab.inFlight {
		t.Errorf("after cancel: state=%v inFlight=%v", tab.state, tab.inFlight)
	}
}

func TestZoneConvertDialogFlow(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "example.com.zone")
	if err := os.WriteFile(in, []byte(strings.Replace(testZoneFile, "host IN HINFO \"PC\" \"Linux\"\n", "", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	m := homeModel(t, DefaultConfig())
	m = openZoneItem(t, m, "c", actZoneConvert, dlgZoneConvert)
	m, _ = submitZone(t, m, map[string]string{"in": in, "to": "terraform"})
	if m.dlg != dlgNone {
		t.Fatalf("dialog open: %v %s", m.dlg, m.dialog.Err)
	}
	out := filepath.Join(dir, "example.com.tf")
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `resource "aws_route53_record" "www_cname"`) {
		t.Errorf("terraform:\n%s", data)
	}
	if !strings.Contains(m.status, "Converted 5 records (bind → terraform)") {
		t.Errorf("status = %q", m.status)
	}

	// Warnings open an info box; explicit output path.
	m = openZoneItem(t, m, "c", actZoneConvert, dlgZoneConvert)
	z := cannedZone()
	z.Records = append(z.Records, zonefile.Record{Name: "h.example.com.", Type: "HINFO", TTL: 60, Data: `"PC" "Linux"`})
	var buf strings.Builder
	if err := zonefile.Write(&buf, z, zonefile.JSON, zonefile.WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	jin := filepath.Join(dir, "zone.json")
	os.WriteFile(jin, []byte(buf.String()), 0o644)
	out = filepath.Join(dir, "out", "cf.json")
	m, _ = submitZone(t, m, map[string]string{"in": jin, "to": "cloudflare", "out": out})
	expectDialog(t, m, dlgInfo)
	if !strings.Contains(m.View(), "HINFO") {
		t.Error("warning not shown")
	}
	if _, err := os.Stat(out); err != nil {
		t.Error(err)
	}

	// Errors keep the dialog open.
	m, _ = typeKeys(t, m, "enter")
	m = openZoneItem(t, m, "c", actZoneConvert, dlgZoneConvert)
	m, _ = submitZone(t, m, map[string]string{"in": filepath.Join(dir, "missing.zone")})
	if m.dlg != dlgZoneConvert || m.dialog.Err == "" {
		t.Error("missing input should show an error")
	}
	m, _ = submitZone(t, m, map[string]string{"in": in, "to": "bind", "out": in})
	if m.dlg != dlgZoneConvert || !strings.Contains(m.dialog.Err, "differ") {
		t.Errorf("same output: %q", m.dialog.Err)
	}
}

func TestZoneShowDialogFlow(t *testing.T) {
	in := filepath.Join(t.TempDir(), "example.com.zone")
	os.WriteFile(in, []byte(testZoneFile), 0o644)
	m := startedModel(t, "a.test")
	m = openZoneItem(t, m, "s", actZoneShow, dlgZoneShow)
	m, msgs := submitZone(t, m, map[string]string{"file": in})
	m, _ = settle(t, m, msgs)
	if m.dlg != dlgNone || len(m.tabs) != 2 || m.activeTab != 1 {
		t.Fatalf("show: dlg=%v tabs=%d err=%q", m.dlg, len(m.tabs), m.dialog.Err)
	}
	tab := m.tabs[1]
	if tab.domain != "example.com" || tab.state != stateViewResults {
		t.Errorf("tab = %q %v", tab.domain, tab.state)
	}
	for _, want := range []string{"Zone file " + in + " (bind)", "HINFO", "6 records"} {
		if !strings.Contains(tab.plainContent(), want) {
			t.Errorf("tab lacks %q:\n%s", want, tab.plainContent())
		}
	}
	m = openZoneItem(t, m, "s", actZoneShow, dlgZoneShow)
	m, _ = submitZone(t, m, map[string]string{"file": in, "from": "octodns"})
	if m.dlg != dlgZoneShow || m.dialog.Err == "" {
		t.Error("wrong format should show an error")
	}
}

func TestZoneFileNames(t *testing.T) {
	if got := zoneFileName("example.com", zonefile.Route53Change); got != "example.com.route53-change.json" {
		t.Errorf("zoneFileName = %q", got)
	}
	if got := retargetFileName("out/example.com.zone", "example.com", zonefile.OctoDNS); got != filepath.Join("out", "example.com.yaml") {
		t.Errorf("retarget = %q", got)
	}
	if got := retargetFileName("mine.txt", "example.com", zonefile.OctoDNS); got != "mine.txt" {
		t.Errorf("custom name changed: %q", got)
	}
	if got := convertOutputName("/z/example.com.cloudflare.json", zonefile.BIND); got != "/z/example.com.zone" {
		t.Errorf("convertOutputName = %q", got)
	}
	if got := convertOutputName("/z/example.com.zone", zonefile.BIND); got != "/z/example.com.converted.zone" {
		t.Errorf("convertOutputName same = %q", got)
	}
}
