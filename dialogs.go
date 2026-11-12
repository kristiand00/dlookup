package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"dlookup/lookup"
	"dlookup/ui"
)

// dialogKind identifies the open modal dialog.
type dialogKind int

const (
	dlgNone dialogKind = iota
	dlgLookup
	dlgZoneDiff
	dlgWatch
	dlgExport
	dlgServer
	dlgConfirmQuit
	dlgConfirmClose
	dlgInfo
)

// Dialog button actions.
const (
	btnRun    = "run"
	btnOK     = "ok"
	btnYes    = "yes"
	btnCancel = ui.ActionCancel
)

// customInterval is the watch interval option that enables the custom field.
const customInterval = "custom"

// watchPresets are the watch interval dropdown options, in seconds.
var watchPresets = []int{5, 10, 30, 60}

// lookupTypeOptions lists all providers (sorted) followed by Zone diff.
func lookupTypeOptions() []ui.Option {
	providers := lookup.AvailableProviders()
	sort.Slice(providers, func(i, j int) bool { return providers[i].Name() < providers[j].Name() })
	opts := make([]ui.Option, 0, len(providers)+1)
	for _, p := range providers {
		opts = append(opts, ui.Option{Label: p.Name(), Value: p.Name()})
	}
	return append(opts, ui.Option{Label: zoneDiffName + " (DNS migration check)", Value: zoneDiffName})
}

// defaultLookupType is preselected in the New lookup dialog.
func (m mainModel) defaultLookupType() string {
	if m.lastLookupType != "" {
		return m.lastLookupType
	}
	if _, ok := lookup.GetProvider(lookup.DefaultLookupName); ok {
		return lookup.DefaultLookupName
	}
	if _, ok := lookup.GetProvider("DIG (A)"); ok {
		return "DIG (A)"
	}
	if opts := lookupTypeOptions(); len(opts) > 0 {
		return opts[0].Value
	}
	return ""
}

func validateTargetField(s string) error {
	if err := lookup.ValidateTarget(strings.TrimSpace(s)); err != nil {
		return fmt.Errorf("invalid target: %w", err)
	}
	return nil
}

func validateOptionalServer(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	if err := lookup.ValidateServer(s); err != nil {
		return fmt.Errorf("invalid server: %w", err)
	}
	return nil
}

// fieldTrue interprets a checkbox value.
func fieldTrue(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "1", "yes", "on", "x":
		return true
	}
	return false
}

// dialogWidth is the width of a regular dialog for the current terminal.
func (m mainModel) dialogWidth(want int) int {
	return max(20, min(want, m.width-4))
}

// openDialog shows d as the modal dialog of kind for tab tabID (-1: none/new).
func (m *mainModel) openDialog(kind dialogKind, tabID int, d ui.Dialog) tea.Cmd {
	m.dlg = kind
	m.dlgTab = tabID
	m.dialog = d
	m.menu.Close()
	return m.dialog.Init()
}

func (m *mainModel) closeDialog() {
	m.dlg = dlgNone
	m.dlgTab = -1
	m.dialog = ui.Dialog{}
}

// sdigQTypes are the query types offered for the SDIG lookup.
var sdigQTypes = []string{"A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "CAA", "PTR", "SRV", "DS", "DNSKEY", "HTTPS", "SVCB", "TLSA", "SSHFP", "NAPTR", "ANY"}

// sdigQTypeOptions returns the Query type dropdown options; cur is added if
// it is not one of them (e.g. set with --qtype).
func sdigQTypeOptions(cur string) []ui.Option {
	opts := []ui.Option{{Label: "Auto (A; PTR for IPs)", Value: ""}}
	found := cur == ""
	for _, t := range sdigQTypes {
		opts = append(opts, ui.Option{Label: t, Value: t})
		found = found || t == cur
	}
	if !found {
		opts = append(opts, ui.Option{Label: cur, Value: cur})
	}
	return opts
}

// lookupDialogFields are the lookup dialog's fields. The SDIG options are
// only shown when lookupType is SDIG (the dialog is rebuilt when it changes).
func lookupDialogFields(domain, lookupType, server string, opts lookup.Options) []ui.Field {
	fields := []ui.Field{
		{Key: "domain", Label: "Domain/IP", Kind: ui.FieldText, Value: domain, Placeholder: "example.com or 1.1.1.1", Validate: validateTargetField, CharLimit: lookup.MaxTargetLength},
		{Key: "type", Label: "Lookup", Kind: ui.FieldSelect, Value: lookupType, Options: lookupTypeOptions()},
		{Key: "server", Label: "DNS server", Kind: ui.FieldText, Value: server, Placeholder: "system default", Validate: validateOptionalServer, CharLimit: 128},
	}
	if lookupType == lookup.SDIGName {
		qt := strings.ToUpper(strings.TrimSpace(opts.QType))
		fields = append(fields,
			ui.Field{Key: "qtype", Label: "Query type", Kind: ui.FieldSelect, Value: qt, Options: sdigQTypeOptions(qt)},
			ui.Field{Key: "recurse", Label: "Recurse (RD)", Kind: ui.FieldCheckbox, Checked: !opts.NoRecurse},
			ui.Field{Key: "dnssec", Label: "DNSSEC (DO)", Kind: ui.FieldCheckbox, Checked: opts.DNSSEC},
			ui.Field{Key: "tcp", Label: "TCP", Kind: ui.FieldCheckbox, Checked: opts.TCP},
			ui.Field{Key: "hidettl", Label: "Hide TTL", Kind: ui.FieldCheckbox, Checked: opts.HideTTL},
		)
	}
	return fields
}

// applySDIGFields copies the SDIG dialog fields from v into opts (if present).
func applySDIGFields(opts lookup.Options, v map[string]string) lookup.Options {
	if _, ok := v["qtype"]; !ok {
		return opts
	}
	opts.QType = v["qtype"]
	opts.NoRecurse = !fieldTrue(v["recurse"])
	opts.DNSSEC = fieldTrue(v["dnssec"])
	opts.TCP = fieldTrue(v["tcp"])
	opts.HideTTL = fieldTrue(v["hidettl"])
	return opts
}

// newLookupDialog builds the New/Change lookup dialog.
func (m *mainModel) newLookupDialog(title, domain, lookupType, server string, opts lookup.Options) ui.Dialog {
	d := ui.NewDialog("dl-dlg-lookup", title, lookupDialogFields(domain, lookupType, server, opts), []ui.Button{
		{Label: "Run", Action: btnRun, Default: true},
		{Label: "Cancel", Action: btnCancel},
	}, ui.ActiveTheme())
	d.Width = m.dialogWidth(64)
	d.Help = "Tab: next · Space: open list · Enter: run · Esc: cancel"
	return d
}

// openLookupDialog opens the New/Change lookup dialog prefilled from opts
// (server and SDIG options). tabID -1 runs the lookup in a new tab (or reuses
// an empty one).
func (m *mainModel) openLookupDialog(tabID int, domain, lookupType string, opts lookup.Options) tea.Cmd {
	title := "New lookup"
	if tabID >= 0 {
		title = "Change lookup"
	}
	if lookupType == "" {
		lookupType = m.defaultLookupType()
	}
	m.dlgOpts = opts
	return m.openDialog(dlgLookup, tabID, m.newLookupDialog(title, domain, lookupType, opts.Server, opts))
}

// syncLookupDialog rebuilds the lookup dialog when the chosen lookup type
// gains or loses the SDIG option fields, keeping the entered values.
func (m *mainModel) syncLookupDialog() tea.Cmd {
	typ := m.dialog.Value("type")
	v := m.dialog.Values()
	_, hasSDIG := v["qtype"]
	if hasSDIG == (typ == lookup.SDIGName) {
		return nil
	}
	m.dlgOpts = applySDIGFields(m.dlgOpts, v)
	d := m.newLookupDialog(m.dialog.Title, v["domain"], typ, v["server"], m.dlgOpts)
	d.Width = m.dialog.Width
	d.FocusField("type")
	m.dialog = d
	return d.Init()
}

// zoneDiffSourceOptions are the old/new source choices of the zone diff dialog.
var (
	zoneDiffOldSources = []ui.Option{
		{Label: "Authoritative servers (auto)", Value: zdSrcAuth},
		{Label: "Server…", Value: zdSrcServer},
		{Label: "Zone file…", Value: zdSrcFile},
	}
	zoneDiffNewSources = []ui.Option{
		{Label: "Server…", Value: zdSrcServer},
		{Label: "Zone file…", Value: zdSrcFile},
		{Label: "Live authoritative (old = file)", Value: zdSrcAuth},
	}
)

const zoneFilePlaceholder = "export: BIND, Cloudflare/Route 53 JSON, YAML, CSV"

// zoneDiffDialogFields builds the zone diff dialog fields; the server and
// zone file fields are shown according to the chosen sources.
func zoneDiffDialogFields(domain string, f zoneDiffForm) []ui.Field {
	oldSrc, newSrc := f.sources()
	fields := []ui.Field{
		{Key: "domain", Label: "Domain", Kind: ui.FieldText, Value: domain, Placeholder: "example.com", CharLimit: lookup.MaxTargetLength},
		{Key: "newsrc", Label: "New source", Kind: ui.FieldSelect, Value: newSrc, Options: zoneDiffNewSources},
	}
	switch newSrc {
	case zdSrcServer:
		fields = append(fields, ui.Field{Key: "new", Label: "New server", Kind: ui.FieldText, Value: f.newServer, Placeholder: "new server IP or hostname", CharLimit: 128})
	case zdSrcFile:
		fields = append(fields, ui.Field{Key: "newfile", Label: "New zone file", Kind: ui.FieldText, Value: f.newFile, Placeholder: zoneFilePlaceholder, CharLimit: 1024})
	}
	fields = append(fields, ui.Field{Key: "oldsrc", Label: "Old source", Kind: ui.FieldSelect, Value: oldSrc, Options: zoneDiffOldSources})
	switch oldSrc {
	case zdSrcServer:
		fields = append(fields, ui.Field{Key: "old", Label: "Old server", Kind: ui.FieldText, Value: f.oldServer, Placeholder: "current server IP or hostname", CharLimit: 128})
	case zdSrcFile:
		fields = append(fields, ui.Field{Key: "oldfile", Label: "Old zone file", Kind: ui.FieldText, Value: f.oldFile, Placeholder: zoneFilePlaceholder, CharLimit: 1024})
	}
	fields = append(fields,
		ui.Field{Key: "extra", Label: "Extra names", Kind: ui.FieldText, Value: f.extraNames, Placeholder: "e.g. www, mail, _dmarc", CharLimit: 512},
		ui.Field{Key: "ttl", Label: "Compare TTLs", Kind: ui.FieldCheckbox, Checked: f.compareTTL},
		ui.Field{Key: "axfr", Label: "Try AXFR", Kind: ui.FieldCheckbox, Checked: f.tryAXFR},
	)
	if oldSrc == zdSrcFile || newSrc == zdSrcFile {
		fields = append(fields, ui.Field{Key: "probe", Label: "Probe common names", Kind: ui.FieldCheckbox, Checked: f.probe})
	}
	return fields
}

// zoneDiffFormFromValues reads the dialog values into a form; fields not
// shown keep their values from prev.
func zoneDiffFormFromValues(v map[string]string, prev zoneDiffForm) zoneDiffForm {
	f := prev
	str := func(key string, dst *string) {
		if x, ok := v[key]; ok {
			*dst = x
		}
	}
	str("new", &f.newServer)
	str("old", &f.oldServer)
	str("newfile", &f.newFile)
	str("oldfile", &f.oldFile)
	str("newsrc", &f.newSource)
	str("oldsrc", &f.oldSource)
	str("extra", &f.extraNames)
	if x, ok := v["ttl"]; ok {
		f.compareTTL = fieldTrue(x)
	}
	if x, ok := v["axfr"]; ok {
		f.tryAXFR = fieldTrue(x)
	}
	if x, ok := v["probe"]; ok {
		f.probe = fieldTrue(x)
	}
	return f
}

// newZoneDiffDialog builds the zone diff dialog.
func (m *mainModel) newZoneDiffDialog(domain string, f zoneDiffForm) ui.Dialog {
	d := ui.NewDialog("dl-dlg-zonediff", "Zone diff", zoneDiffDialogFields(domain, f), []ui.Button{
		{Label: "Run", Action: btnRun, Default: true},
		{Label: "Cancel", Action: btnCancel},
	}, ui.ActiveTheme())
	d.Width = m.dialogWidth(70)
	d.Help = "Compares the old side (nameservers, a server or a zone file) with the new side."
	return d
}

// openZoneDiffDialog opens the zone diff dialog prefilled with domain and form.
func (m *mainModel) openZoneDiffDialog(tabID int, domain string, f zoneDiffForm) tea.Cmd {
	cmd := m.openDialog(dlgZoneDiff, tabID, m.newZoneDiffDialog(domain, f))
	if domain != "" {
		_, newSrc := f.sources()
		if newSrc == zdSrcFile {
			m.dialog.FocusField("newfile")
		} else if newSrc == zdSrcServer {
			m.dialog.FocusField("new")
		}
	}
	return cmd
}

// zoneDiffTabForm returns the remembered zone diff form of the dialog's tab.
func (m mainModel) zoneDiffTabForm() zoneDiffForm {
	if i := m.tabIndex(m.dlgTab); i >= 0 {
		return m.tabs[i].zd.form
	}
	return newZoneDiffForm()
}

// syncZoneDiffDialog rebuilds the zone diff dialog when a source select
// changed which server / zone file fields are needed, keeping the values.
func (m *mainModel) syncZoneDiffDialog() tea.Cmd {
	v := m.dialog.Values()
	f := zoneDiffFormFromValues(v, m.zoneDiffTabForm())
	want := zoneDiffDialogFields(v["domain"], f)
	if len(want) == len(m.dialog.Fields) {
		same := true
		for i := range want {
			if want[i].Key != m.dialog.Fields[i].Key {
				same = false
				break
			}
		}
		if same {
			return nil
		}
	}
	focus := m.dialog.Focused()
	d := m.newZoneDiffDialog(v["domain"], f)
	d.Width = m.dialog.Width
	d.Err = m.dialog.Err
	if focus != "" {
		d.FocusField(focus)
	}
	m.dialog = d
	return d.Init()
}

// openWatchDialog asks for the watch interval of tab t.
func (m *mainModel) openWatchDialog(t *tabModel) tea.Cmd {
	opts := make([]ui.Option, 0, len(watchPresets)+1)
	for _, s := range watchPresets {
		opts = append(opts, ui.Option{Label: fmt.Sprintf("Every %d seconds", s), Value: strconv.Itoa(s)})
	}
	opts = append(opts, ui.Option{Label: "Custom…", Value: customInterval})
	value, custom := "5", ""
	if t.watchInterval > 0 {
		sec := int(t.watchInterval / time.Second)
		value = customInterval
		custom = strconv.Itoa(sec)
		for _, p := range watchPresets {
			if p == sec {
				value, custom = strconv.Itoa(sec), ""
			}
		}
	}
	d := ui.NewDialog("dl-dlg-watch", "Watch "+t.domain, []ui.Field{
		{Key: "interval", Label: "Refresh", Kind: ui.FieldSelect, Value: value, Options: opts},
		{Key: "custom", Label: "Custom (s)", Kind: ui.FieldText, Value: custom, Placeholder: "seconds, for Custom…", CharLimit: 6},
	}, []ui.Button{
		{Label: "Watch", Action: btnRun, Default: true},
		{Label: "Cancel", Action: btnCancel},
	}, ui.ActiveTheme())
	d.Width = m.dialogWidth(50)
	d.Help = "Re-runs the lookup and highlights changes."
	return m.openDialog(dlgWatch, t.id, d)
}

// openExportDialog asks for the export filename of tab t.
func (m *mainModel) openExportDialog(t *tabModel) tea.Cmd {
	d := ui.NewDialog("dl-dlg-export", "Export result", []ui.Field{
		{Key: "file", Label: "File", Kind: ui.FieldText, Value: defaultExportFilename(t.domain, t.lookupType, now()), Placeholder: "path/to/file.txt", CharLimit: 512},
	}, []ui.Button{
		{Label: "Save", Action: btnRun, Default: true},
		{Label: "Cancel", Action: btnCancel},
	}, ui.ActiveTheme())
	d.Width = m.dialogWidth(70)
	d.Help = "Relative paths are saved in the current directory; ~/ is expanded."
	return m.openDialog(dlgExport, t.id, d)
}

// openServerDialog asks for the DNS server of tab t.
func (m *mainModel) openServerDialog(t *tabModel) tea.Cmd {
	d := ui.NewDialog("dl-dlg-server", "DNS server", []ui.Field{
		{Key: "server", Label: "Server", Kind: ui.FieldText, Value: t.lookupOpts.Server, Placeholder: "e.g. 1.1.1.1 (empty = system default)", Validate: validateOptionalServer, CharLimit: 128},
	}, []ui.Button{
		{Label: "Set", Action: btnRun, Default: true},
		{Label: "Cancel", Action: btnCancel},
	}, ui.ActiveTheme())
	d.Width = m.dialogWidth(56)
	d.Help = "Applies to this tab; the lookup re-runs when it changes."
	return m.openDialog(dlgServer, t.id, d)
}

// openConfirm opens a Yes/No dialog.
func (m *mainModel) openConfirm(kind dialogKind, tabID int, title, text string) tea.Cmd {
	d := ui.NewDialog("dl-dlg-confirm", title, infoFields(text), []ui.Button{
		{Label: "Yes", Action: btnYes, Default: true},
		{Label: "No", Action: btnCancel},
	}, ui.ActiveTheme())
	d.Width = m.dialogWidth(50)
	return m.openDialog(kind, tabID, d)
}

// infoFields turns text into one read-only line per field.
func infoFields(text string) []ui.Field {
	lines := strings.Split(text, "\n")
	out := make([]ui.Field, len(lines))
	for i, l := range lines {
		out[i] = ui.Field{Kind: ui.FieldInfo, Value: l}
	}
	return out
}

// openInfo opens a message dialog with an OK button.
func (m *mainModel) openInfo(title, text string) tea.Cmd {
	d := ui.NewDialog("dl-dlg-info", title, infoFields(text), []ui.Button{{Label: "OK", Action: btnOK, Default: true}}, ui.ActiveTheme())
	d.Width = m.dialogWidth(64)
	return m.openDialog(dlgInfo, -1, d)
}

// updateDialog forwards msg to the open dialog and handles its result.
func (m *mainModel) updateDialog(msg tea.Msg) tea.Cmd {
	// Enter on a closed select submits the dialog (MC style: Enter runs the
	// default button); Space or typing opens the list.
	if km, ok := msg.(tea.KeyMsg); ok && km.Type == tea.KeyEnter && !m.dialog.DropdownOpen() && m.focusedSelect() {
		for _, b := range m.dialog.Buttons {
			if b.Default {
				return m.submitDialog(ui.DialogResult{Action: b.Action, Values: m.dialog.Values()})
			}
		}
	}
	d, res, cmd := m.dialog.Update(msg)
	m.dialog = d
	if m.dlg == dlgTheme && (res == nil || res.Action == ui.ActionCancel) {
		m.previewTheme(res != nil)
	}
	if res == nil {
		// Choosing Zone diff in the lookup dialog swaps to the zone diff dialog.
		if m.dlg == dlgLookup && m.dialog.Value("type") == zoneDiffName {
			return tea.Batch(cmd, m.switchToZoneDiff(m.dialog.Value("domain")))
		}
		if m.dlg == dlgLookup {
			return tea.Batch(cmd, m.syncLookupDialog())
		}
		if m.dlg == dlgZoneDiff {
			return tea.Batch(cmd, m.syncZoneDiffDialog())
		}
		return cmd
	}
	if res.Action == ui.ActionCancel || res.Action == "" {
		m.closeDialog()
		return cmd
	}
	return tea.Batch(cmd, m.submitDialog(*res))
}

// focusedSelect reports whether the dialog's focused field is a select.
func (m mainModel) focusedSelect() bool {
	key := m.dialog.Focused()
	if key == "" {
		return false
	}
	for _, f := range m.dialog.Fields {
		if f.Key == key {
			return f.Kind == ui.FieldSelect
		}
	}
	return false
}

// switchToZoneDiff replaces the lookup dialog with the zone diff dialog.
func (m *mainModel) switchToZoneDiff(domain string) tea.Cmd {
	tabID := m.dlgTab
	form := newZoneDiffForm()
	if i := m.tabIndex(tabID); i >= 0 {
		form = m.tabs[i].zd.form
	}
	return m.openZoneDiffDialog(tabID, strings.TrimSpace(domain), form)
}

// tabIndex returns the index of the tab with id, or -1.
func (m mainModel) tabIndex(id int) int {
	if id < 0 {
		return -1
	}
	for i := range m.tabs {
		if m.tabs[i].id == id {
			return i
		}
	}
	return -1
}

// targetTab returns the index of the tab a dialog runs in: tab id if it still
// exists, else the active tab if it is an unused placeholder, else a new tab.
func (m *mainModel) targetTab(id int) int {
	if i := m.tabIndex(id); i >= 0 && !m.tabs[i].isHome() {
		return i
	}
	if m.hasActive() && m.tabs[m.activeTab].isPlaceholder() {
		return m.activeTab
	}
	w, h := m.innerSize()
	m.tabs = append(m.tabs, newTabModel(w, h, "", "", m.defaultOpts))
	return len(m.tabs) - 1
}

// submitDialog handles a dialog's non-cancel result.
func (m *mainModel) submitDialog(res ui.DialogResult) tea.Cmd {
	v := res.Values
	fail := func(err error) tea.Cmd {
		m.dialog.Err = err.Error()
		return nil
	}
	if cmd, ok := m.submitZoneDialog(m.dlg, res); ok {
		return cmd
	}
	switch m.dlg {
	case dlgLookup:
		domain := strings.TrimSpace(v["domain"])
		if err := validateTargetField(domain); err != nil {
			return fail(err)
		}
		typ := v["type"]
		if typ == zoneDiffName {
			return m.switchToZoneDiff(domain)
		}
		if _, ok := lookup.GetProvider(typ); !ok {
			return fail(fmt.Errorf("choose a lookup type"))
		}
		server := strings.TrimSpace(v["server"])
		if err := validateOptionalServer(server); err != nil {
			return fail(err)
		}
		reuse := m.tabIndex(m.dlgTab) >= 0
		i := m.targetTab(m.dlgTab)
		opts := m.defaultOpts
		if reuse {
			opts = m.tabs[i].lookupOpts
		}
		opts.Server = server
		if typ == lookup.SDIGName {
			opts = applySDIGFields(opts, v)
		}
		m.closeDialog()
		m.lastLookupType = typ
		cmd := m.tabs[i].run(domain, typ, opts)
		m.focus(i)
		return cmd

	case dlgZoneDiff:
		form := zoneDiffFormFromValues(v, m.zoneDiffTabForm())
		opts, err := zoneDiffOptions(v["domain"], form)
		if err != nil {
			return fail(err)
		}
		i := m.targetTab(m.dlgTab)
		m.closeDialog()
		m.tabs[i].zd.form = form
		cmd := m.tabs[i].runZoneDiff(opts)
		m.focus(i)
		return cmd

	case dlgWatch:
		raw := v["interval"]
		if raw == customInterval {
			raw = v["custom"]
		}
		sec, err := strconv.Atoi(strings.TrimSpace(raw))
		if err != nil || sec <= 0 {
			return fail(fmt.Errorf("enter a whole number of seconds greater than 0"))
		}
		i := m.tabIndex(m.dlgTab)
		m.closeDialog()
		if i < 0 {
			return nil
		}
		return m.tabs[i].startWatch(time.Duration(sec) * time.Second)

	case dlgExport:
		name := strings.TrimSpace(v["file"])
		if name == "" {
			return fail(fmt.Errorf("filename cannot be empty"))
		}
		i := m.tabIndex(m.dlgTab)
		if i < 0 {
			m.closeDialog()
			return nil
		}
		path, err := writeExportFile(name, m.tabs[i].plainContent())
		if err != nil {
			return fail(err)
		}
		m.closeDialog()
		return m.tabs[i].setStatus("Saved to " + path)

	case dlgServer:
		server := strings.TrimSpace(v["server"])
		if err := validateOptionalServer(server); err != nil {
			return fail(err)
		}
		i := m.tabIndex(m.dlgTab)
		m.closeDialog()
		if i < 0 {
			return nil
		}
		t := &m.tabs[i]
		changed := server != t.lookupOpts.Server
		t.lookupOpts.Server = server
		label := server
		if label == "" {
			label = "system default"
		}
		cmds := []tea.Cmd{t.setStatus("DNS server: " + label)}
		if changed && t.lookupType != "" && (t.resultsVisible() || t.state == stateLoading) {
			cmds = append(cmds, t.rerun())
		}
		return tea.Batch(cmds...)

	case dlgTheme:
		return m.submitThemeDialog(res)

	case dlgConfirmQuit:
		m.closeDialog()
		if res.Action == btnYes {
			return tea.Quit
		}

	case dlgConfirmClose:
		id := m.dlgTab
		m.closeDialog()
		if res.Action == btnYes {
			if i := m.tabIndex(id); i >= 0 {
				m.closeTab(i)
			}
		}

	default:
		m.closeDialog()
	}
	return nil
}
