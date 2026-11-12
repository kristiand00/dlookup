package main

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"dlookup/lookup"
	"dlookup/ui"
	"dlookup/zonefile"
)

// Zone menu dialogs (kept clear of the iota block in dialogs.go and the theme
// dialog's 100).
const (
	dlgZoneExport  dialogKind = 200
	dlgZoneConvert dialogKind = 201
	dlgZoneShow    dialogKind = 202
)

// Zone menu actions. They all start with zoneActionPrefix.
const (
	zoneActionPrefix = "zone:"
	actZoneExport    = "zone:export"
	actZoneConvert   = "zone:convert"
	actZoneShow      = "zone:show"
)

// autoFormat is the "detect" choice of the input format dropdowns.
const autoFormat = ""

// zoneMenuItems are the items of the Zone menu.
func zoneMenuItems(k Keybindings) []ui.MenuItem {
	return []ui.MenuItem{
		{Label: "&Export zone…", Action: actZoneExport},
		{Label: "&Convert file…", Action: actZoneConvert},
		{Label: "&Show zone file…", Action: actZoneShow},
		{Separator: true},
		{Label: "Zone &diff…", Hotkey: hk(k.ZoneDiff, "F4"), Action: actZoneDiff},
	}
}

// isZoneAction reports whether action belongs to the Zone menu (except Zone
// diff, which is the existing actZoneDiff).
func isZoneAction(action string) bool { return strings.HasPrefix(action, zoneActionPrefix) }

// formatOptions lists the formats that can be read (read) or written.
func formatOptions(read bool) []ui.Option {
	var opts []ui.Option
	if read {
		opts = append(opts, ui.Option{Label: "Auto-detect", Value: autoFormat})
	}
	for _, f := range zonefile.Formats() {
		if read && !zonefile.CanRead(f) || !read && !zonefile.CanWrite(f) {
			continue
		}
		fi, _ := zonefile.Info(f)
		opts = append(opts, ui.Option{Label: fmt.Sprintf("%s — %s", f, fi.Description), Value: string(f)})
	}
	return opts
}

// zoneFileName is the default file name of domain's zone in format f.
func zoneFileName(domain string, f zonefile.Format) string {
	domain = strings.TrimSuffix(strings.TrimSpace(domain), ".")
	if domain == "" {
		domain = "zone"
	}
	ext := zonefile.Extension(f)
	switch f {
	case zonefile.Route53, zonefile.Route53Change, zonefile.Cloudflare, zonefile.TerraformCloudflare:
		ext = "." + string(f) + ext
	}
	return domain + ext
}

// retargetFileName swaps the extension of a default file name (one made by
// zoneFileName for any format) to format f; other names are kept.
func retargetFileName(name, domain string, f zonefile.Format) string {
	base := filepath.Base(name)
	for _, g := range zonefile.Formats() {
		if base == zoneFileName(domain, g) {
			return filepath.Join(filepath.Dir(name), zoneFileName(domain, f))
		}
	}
	return name
}

// convertOutputName derives the output file of a conversion: the input's
// stem with the target format's extension, next to the input.
func convertOutputName(in string, f zonefile.Format) string {
	in = strings.TrimSpace(in)
	if in == "" {
		return ""
	}
	dir, base := filepath.Split(in)
	stem := strings.TrimSuffix(base, filepath.Ext(base))
	for _, g := range zonefile.Formats() {
		stem = strings.TrimSuffix(stem, "."+string(g))
	}
	out := filepath.Join(dir, zoneFileName(stem, f))
	if out == in {
		out = filepath.Join(dir, stem+".converted"+zonefile.Extension(f))
	}
	return out
}

// activeDomain is the active lookup tab's domain if it is a valid zone name.
func (m *mainModel) activeDomain() string {
	t := m.active()
	if t == nil || t.isHome() || t.domain == "" || lookup.ValidateTarget(t.domain) != nil {
		return ""
	}
	return t.domain
}

// handleZoneAction runs a Zone menu action (see isZoneAction).
func (m *mainModel) handleZoneAction(act string) tea.Cmd {
	switch act {
	case actZoneExport:
		return m.openZoneExportDialog(m.activeDomain())
	case actZoneConvert:
		return m.openZoneConvertDialog("")
	case actZoneShow:
		return m.openZoneShowDialog("")
	}
	return nil
}

func (m *mainModel) openZoneExportDialog(domain string) tea.Cmd {
	d := ui.NewDialog("dl-dlg-zone-export", "Export zone", []ui.Field{
		{Key: "domain", Label: "Domain", Kind: ui.FieldText, Value: domain, Placeholder: "example.com", CharLimit: lookup.MaxTargetLength},
		{Key: "format", Label: "Format", Kind: ui.FieldSelect, Value: string(zonefile.BIND), Options: formatOptions(false)},
		{Key: "file", Label: "File", Kind: ui.FieldText, Value: zoneFileName(domain, zonefile.BIND), Placeholder: "example.com.zone", CharLimit: 512},
		{Key: "server", Label: "Server", Kind: ui.FieldText, Placeholder: "authoritative NS (auto)", Validate: validateOptionalServer, CharLimit: 128},
		{Key: "extra", Label: "Extra names", Kind: ui.FieldText, Placeholder: "e.g. shop, vpn, _dmarc", CharLimit: 512},
		{Key: "axfr", Label: "Try AXFR", Kind: ui.FieldCheckbox, Checked: true},
		{Key: "keepns", Label: "Keep apex NS/SOA", Kind: ui.FieldCheckbox},
	}, []ui.Button{
		{Label: "Export", Action: btnRun, Default: true},
		{Label: "Cancel", Action: btnCancel},
	}, ui.ActiveTheme())
	d.Width = m.dialogWidth(72)
	d.Help = "Without AXFR names are probed, so the export may be incomplete."
	cmd := m.openDialog(dlgZoneExport, -1, d)
	if domain != "" {
		m.dialog.FocusField("format")
	}
	return cmd
}

func (m *mainModel) openZoneConvertDialog(in string) tea.Cmd {
	d := ui.NewDialog("dl-dlg-zone-convert", "Convert zone file", []ui.Field{
		{Key: "in", Label: "Input file", Kind: ui.FieldText, Value: in, Placeholder: "path/to/example.com.zone", CharLimit: 512},
		{Key: "from", Label: "Input format", Kind: ui.FieldSelect, Value: autoFormat, Options: formatOptions(true)},
		{Key: "origin", Label: "Origin", Kind: ui.FieldText, Placeholder: "zone domain if the file lacks it", CharLimit: lookup.MaxTargetLength},
		{Key: "to", Label: "Output format", Kind: ui.FieldSelect, Value: string(zonefile.Route53Change), Options: formatOptions(false)},
		{Key: "out", Label: "Output file", Kind: ui.FieldText, Placeholder: "default: next to the input", CharLimit: 512},
		{Key: "keepns", Label: "Keep apex NS/SOA", Kind: ui.FieldCheckbox},
	}, []ui.Button{
		{Label: "Convert", Action: btnRun, Default: true},
		{Label: "Cancel", Action: btnCancel},
	}, ui.ActiveTheme())
	d.Width = m.dialogWidth(72)
	d.Help = "Formats are detected from the file; ~/ is expanded."
	return m.openDialog(dlgZoneConvert, -1, d)
}

func (m *mainModel) openZoneShowDialog(path string) tea.Cmd {
	d := ui.NewDialog("dl-dlg-zone-show", "Show zone file", []ui.Field{
		{Key: "file", Label: "File", Kind: ui.FieldText, Value: path, Placeholder: "path/to/zone file", CharLimit: 512},
		{Key: "from", Label: "Format", Kind: ui.FieldSelect, Value: autoFormat, Options: formatOptions(true)},
		{Key: "origin", Label: "Origin", Kind: ui.FieldText, Placeholder: "zone domain if the file lacks it", CharLimit: lookup.MaxTargetLength},
	}, []ui.Button{
		{Label: "Show", Action: btnRun, Default: true},
		{Label: "Cancel", Action: btnCancel},
	}, ui.ActiveTheme())
	d.Width = m.dialogWidth(66)
	d.Help = "Opens the normalized records in a new tab."
	return m.openDialog(dlgZoneShow, -1, d)
}

// submitZoneDialog handles the result of a Zone dialog; ok is false when the
// open dialog is not one of them.
func (m *mainModel) submitZoneDialog(kind dialogKind, res ui.DialogResult) (cmd tea.Cmd, ok bool) {
	switch kind {
	case dlgZoneExport, dlgZoneConvert, dlgZoneShow:
	default:
		return nil, false
	}
	if res.Action != btnRun {
		m.closeDialog()
		return nil, true
	}
	var err error
	switch kind {
	case dlgZoneExport:
		cmd, err = m.submitZoneExport(res.Values)
	case dlgZoneConvert:
		cmd, err = m.submitZoneConvert(res.Values)
	case dlgZoneShow:
		cmd, err = m.submitZoneShow(res.Values)
	}
	if err != nil {
		m.dialog.Err = err.Error()
		return nil, true
	}
	return cmd, true
}

func (m *mainModel) submitZoneShow(v map[string]string) (tea.Cmd, error) {
	path := strings.TrimSpace(v["file"])
	if path == "" || path == "-" {
		return nil, fmt.Errorf("enter a file name")
	}
	z, f, err := readZoneInput(path, v["from"], strings.TrimSpace(v["origin"]), strings.NewReader(""))
	if err != nil {
		return nil, err
	}
	m.closeDialog()
	text := fmt.Sprintf("Zone file %s (%s)\n\n%s", path, f, zoneTable(z))
	i := m.zoneResultTab(strings.TrimSuffix(z.Origin, "."), text)
	m.focus(i)
	return m.tabs[i].setStatus(fmt.Sprintf("%d records from %s", len(z.Records), filepath.Base(path))), nil
}

func (m *mainModel) submitZoneConvert(v map[string]string) (tea.Cmd, error) {
	in := strings.TrimSpace(v["in"])
	if in == "" || in == "-" {
		return nil, fmt.Errorf("enter the input file")
	}
	to, err := zonefile.ParseFormat(v["to"])
	if err != nil {
		return nil, err
	}
	z, from, err := readZoneInput(in, v["from"], strings.TrimSpace(v["origin"]), strings.NewReader(""))
	if err != nil {
		return nil, err
	}
	out := strings.TrimSpace(v["out"])
	if out == "" {
		out = convertOutputName(in, to)
	}
	if out == "-" {
		return nil, fmt.Errorf("enter an output file name")
	}
	if expandHome(out) == expandHome(in) {
		return nil, fmt.Errorf("the output file must differ from the input")
	}
	opts := zonefile.WriteOptions{SkipApexNSSOA: zonefile.DefaultSkipApexNSSOA(to) && !fieldTrue(v["keepns"])}
	path, warns, err := writeZoneOutput(expandHome(out), nil, z, to, opts)
	if err != nil {
		return nil, err
	}
	m.closeDialog()
	msg := fmt.Sprintf("Converted %d records (%s → %s) to %s", len(z.Records), from, to, path)
	if len(warns) == 0 {
		m.status = msg
		return nil, nil
	}
	return m.openInfo("Zone converted", msg+warningsText(warns)), nil
}

// warningsText lists conversion warnings for an info box (at most 12).
func warningsText(warns []string) string {
	if len(warns) == 0 {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "\n\n%d warning(s):", len(warns))
	for i, w := range warns {
		if i == 12 {
			fmt.Fprintf(&b, "\n… and %d more", len(warns)-i)
			break
		}
		b.WriteString("\n• " + w)
	}
	return b.String()
}

// zoneExportRequest is a validated Export zone dialog.
type zoneExportRequest struct {
	dump   lookup.ZoneDumpOptions
	format zonefile.Format
	file   string
	opts   zonefile.WriteOptions
}

func (m *mainModel) submitZoneExport(v map[string]string) (tea.Cmd, error) {
	domain, err := lookup.NormalizeTarget(strings.TrimSpace(v["domain"]))
	if err != nil {
		return nil, err
	}
	f, err := zonefile.ParseFormat(v["format"])
	if err != nil {
		return nil, err
	}
	server := strings.TrimSpace(v["server"])
	if err := validateOptionalServer(server); err != nil {
		return nil, err
	}
	file := strings.TrimSpace(v["file"])
	if file == "" {
		file = zoneFileName(domain, f)
	}
	if file == "-" {
		return nil, fmt.Errorf("enter a file name")
	}
	file = retargetFileName(file, domain, f)
	req := zoneExportRequest{
		dump: lookup.ZoneDumpOptions{
			Domain: domain, Server: server, ExtraNames: splitNames(v["extra"]),
			TryAXFR: fieldTrue(v["axfr"]), Timeout: defaultZoneExportTimeout,
		},
		format: f,
		file:   expandHome(file),
		opts:   zonefile.WriteOptions{SkipApexNSSOA: zonefile.DefaultSkipApexNSSOA(f) && !fieldTrue(v["keepns"])},
	}
	m.closeDialog()
	i := m.targetTab(-1)
	t := &m.tabs[i]
	t.stopWatch()
	t.cancelLookup()
	t.domain = domain
	t.lookupType = ""
	t.hasResult = false
	t.result = ""
	t.err = nil
	t.state = stateLoading
	t.loadingMsg = fmt.Sprintf("Exporting zone %s as %s…", domain, f)
	t.lookupSeq++
	ctx, cancel := context.WithCancel(t.ctx)
	t.lookupCancel = cancel
	t.inFlight = true
	m.focus(i)
	return zoneExportCmd(ctx, t.id, t.lookupSeq, req), nil
}

// zoneExportCmd dumps the live zone and writes the file. It reports through
// the regular lookup messages, so the tab shows progress, Esc cancels and the
// result is displayed like a lookup result.
func zoneExportCmd(ctx context.Context, id, seq int, req zoneExportRequest) tea.Cmd {
	return func() tea.Msg {
		start := time.Now()
		z, method, err := dumpZone(ctx, req.dump)
		if err != nil {
			return errorMsg{tabId: id, seq: seq, err: err}
		}
		path, warns, err := writeZoneOutput(req.file, nil, z, req.format, req.opts)
		if err != nil {
			return errorMsg{tabId: id, seq: seq, err: err}
		}
		if abs, err := filepath.Abs(path); err == nil {
			path = abs
		}
		var b strings.Builder
		fmt.Fprintf(&b, "Zone export of %s\n\n", req.dump.Domain)
		fmt.Fprintf(&b, "Method:   %s (%s)\n", method, time.Since(start).Round(time.Millisecond))
		fmt.Fprintf(&b, "Format:   %s\n", req.format)
		fmt.Fprintf(&b, "Saved to: %s\n", path)
		if w := probeWarning(method); w != "" {
			fmt.Fprintf(&b, "\nWarning: %s.\n", strings.Replace(w, "--names", "Extra names", 1))
		}
		if len(warns) > 0 {
			fmt.Fprintf(&b, "\n%d record(s) skipped or changed for %s:\n", len(warns), req.format)
			for _, w := range warns {
				fmt.Fprintf(&b, "  %s\n", w)
			}
		}
		b.WriteString("\n" + zoneTable(z))
		return lookupResultMsg{tabId: id, seq: seq, output: strings.TrimRight(b.String(), "\n")}
	}
}

// zoneResultTab shows text as the result of a new (or reused placeholder)
// tab for domain and returns its index. The tab has no lookup type, so
// re-run and watch don't apply.
func (m *mainModel) zoneResultTab(domain, text string) int {
	i := m.targetTab(-1)
	t := &m.tabs[i]
	t.stopWatch()
	t.cancelLookup()
	t.domain = domain
	t.lookupType = ""
	t.result = text
	t.hasResult = true
	t.err = nil
	t.loadingMsg = ""
	t.lastUpdated = now()
	t.state = stateViewResults
	t.renderContent()
	t.viewport.GotoTop()
	return i
}
