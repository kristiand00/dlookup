package main

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"dlookup/lookup"
	"dlookup/ui"
)

// Fixed screen rows outside the panel: menu bar, tab bar, status line, F-key bar.
const chromeRows = 4

type mainModel struct {
	tabs        []tabModel
	activeTab   int
	width       int
	height      int
	config      AppConfig
	defaultOpts lookup.Options // options for new tabs (e.g. --server)
	status      string         // app-level status line (e.g. export all); cleared on next key

	menu    ui.MenuBar
	tabBar  ui.TabBar
	fkeyBar ui.FKeyBar
	mouse   bool // mouse capture on

	// Modal dialog (dlg == dlgNone when closed).
	dialog         ui.Dialog
	dlg            dialogKind
	dlgTab         int            // id of the tab the dialog acts on; -1 = none/new tab
	dlgOpts        lookup.Options // options the lookup dialog was opened with
	lastLookupType string
	initCmd        tea.Cmd
}

// newMainModel builds the main model. With no initial targets it starts on the
// Home (help) tab; otherwise there is one tab per target, all started by Init.
// Targets given without a lookup type run the default SDIG lookup (opts.QType,
// default A). Every tab, including ones opened later, starts with opts.
func newMainModel(initialDomains []string, initialLookupType string, cfg AppConfig, opts lookup.Options) mainModel {
	th := ui.ActiveTheme()
	m := mainModel{
		width:       80,
		height:      24,
		config:      cfg,
		defaultOpts: opts,
		mouse:       cfg.Mouse,
		menu:        buildMenuBar(cfg),
		tabBar:      ui.TabBar{ID: "dl-tabs", Theme: th},
		fkeyBar:     ui.FKeyBar{ID: "dl-fkeys", Theme: th},
		dlgTab:      -1,
	}
	if initialLookupType == "" && len(initialDomains) > 0 {
		if _, ok := lookup.GetProvider(lookup.DefaultLookupName); ok {
			initialLookupType = lookup.DefaultLookupName
		}
	}
	if _, ok := lookup.GetProvider(initialLookupType); ok {
		m.lastLookupType = initialLookupType
	}
	w, h := m.innerSize()
	for _, domain := range initialDomains {
		m.tabs = append(m.tabs, newTabModel(w, h, domain, initialLookupType, opts))
	}
	if len(m.tabs) == 0 {
		m.tabs = []tabModel{newHomeTab(w, h)}
	}
	m.refreshHome()
	if t := m.tabs[0]; t.state == stateIdle && t.domain != "" {
		m.initCmd = m.openLookupDialog(t.id, t.domain, "", t.lookupOpts)
	}
	m.syncMenu()
	return m
}

// Init starts every tab's initial command (lookups are bounded by lookupSem).
func (m mainModel) Init() tea.Cmd {
	cmds := make([]tea.Cmd, 0, len(m.tabs)+1)
	for i := range m.tabs {
		cmds = append(cmds, m.tabs[i].Init())
	}
	cmds = append(cmds, m.initCmd)
	return tea.Batch(cmds...)
}

func (m mainModel) hasActive() bool {
	return m.activeTab >= 0 && m.activeTab < len(m.tabs)
}

// active returns the active tab, or nil.
func (m *mainModel) active() *tabModel {
	if !m.hasActive() {
		return nil
	}
	return &m.tabs[m.activeTab]
}

// panelHeight is the height of the bordered panel including its border.
func (m mainModel) panelHeight() int { return max(3, m.height-chromeRows) }

// innerSize is the panel interior size.
func (m mainModel) innerSize() (int, int) {
	return max(1, m.width-2), max(1, m.panelHeight()-2)
}

// focus makes tab i active without re-running anything.
func (m *mainModel) focus(i int) {
	m.activeTab = i
	m.tabs[i].changed = false
}

// refreshHome re-renders the help text of the Home tab (if open).
func (m *mainModel) refreshHome() {
	for i := range m.tabs {
		if m.tabs[i].isHome() {
			m.tabs[i].viewport.SetContent(helpContent(m.config, m.tabs[i].viewport.Width-2))
		}
	}
}

// showHome focuses the Home tab, opening it first if it was closed.
func (m *mainModel) showHome() {
	for i := range m.tabs {
		if m.tabs[i].isHome() {
			m.focus(i)
			return
		}
	}
	w, h := m.innerSize()
	m.tabs = append([]tabModel{newHomeTab(w, h)}, m.tabs...)
	m.refreshHome()
	m.focus(0)
}

// closeTab closes tab i (cancelling its lookups). Closing the last tab shows Home.
func (m *mainModel) closeTab(i int) {
	if i < 0 || i >= len(m.tabs) {
		return
	}
	if len(m.tabs) == 1 && m.tabs[0].isHome() {
		return
	}
	m.tabs[i].cancel()
	m.tabs = append(m.tabs[:i], m.tabs[i+1:]...)
	if len(m.tabs) == 0 {
		m.showHome()
		return
	}
	if m.activeTab > i || m.activeTab >= len(m.tabs) {
		m.activeTab--
	}
	m.focus(max(0, min(m.activeTab, len(m.tabs)-1)))
}

// busy reports whether any lookup is running or any tab is watching.
func (m mainModel) busy() bool {
	for _, t := range m.tabs {
		if t.inFlight || t.isWatching {
			return true
		}
	}
	return false
}

func (m mainModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	cmd := m.update(msg)
	m.syncMenu()
	return m, cmd
}

func (m *mainModel) update(msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		w, h := m.innerSize()
		for i := range m.tabs {
			m.tabs[i].setSize(w, h)
			m.tabs[i].renderContent()
		}
		m.refreshHome()
		if m.dlg != dlgNone {
			m.dialog.Width = min(m.dialog.Width, m.dialogWidth(m.dialog.Width))
		}
		return nil

	case tea.KeyMsg:
		return m.handleKey(msg)

	case tea.MouseMsg:
		return m.handleMouse(msg)

	case tabMsg:
		if i := m.tabIndex(msg.targetTab()); i >= 0 {
			var cmd tea.Cmd
			m.tabs[i], cmd = m.tabs[i].Update(msg)
			if i == m.activeTab {
				m.tabs[i].changed = false
			}
			return cmd
		}
		// Messages for closed tabs are dropped, which also ends their tick chains.
		return nil
	}
	if m.dlg != dlgNone {
		return m.updateDialog(msg) // cursor blink etc.
	}
	return nil
}

func (m *mainModel) handleKey(msg tea.KeyMsg) tea.Cmd {
	key := msg.String()
	// ctrl+c always quits, whatever the config or the open dialog.
	if key == "ctrl+c" {
		return tea.Quit
	}
	if m.dlg != dlgNone {
		return m.updateDialog(msg)
	}
	mb, action, consumed := m.menu.Update(msg)
	m.menu = mb
	if action != "" {
		return m.do(action)
	}
	if consumed {
		return nil
	}

	m.status = ""
	if a := fkeyAction(key); a != "" {
		return m.do(a)
	}
	k := m.config.Keybindings
	t := m.active()
	switch key {
	case k.Quit:
		return m.do(actQuit)
	case k.NewTab:
		return m.do(actNew)
	case k.CloseTab:
		return m.do(actClose)
	case k.NextTab:
		return m.do(actNextTab)
	case k.PrevTab:
		return m.do(actPrevTab)
	case k.ExportAll:
		return m.do(actExportAll)
	case k.Export:
		return m.do(actExport)
	case k.Copy:
		return m.do(actCopy)
	case k.WatchToggle:
		return m.do(actWatch)
	case k.Server:
		return m.do(actServer)
	case k.ZoneDiff:
		return m.do(actZoneDiff)
	case k.Confirm:
		if t == nil || t.isHome() {
			return m.do(actNew)
		}
		return m.do(actChange)
	case k.Back, "esc":
		return m.do(actBack)
	case k.ToggleMatches:
		if t != nil && t.isZoneDiff() && t.state == stateViewResults {
			return m.do(actMatches)
		}
	case "?":
		return m.do(actHelp)
	case "r":
		return m.do(actRerun)
	}
	if t == nil {
		return nil
	}
	var cmd tea.Cmd
	*t, cmd = t.Update(msg)
	return cmd
}

func (m *mainModel) handleMouse(msg tea.MouseMsg) tea.Cmd {
	if !m.mouse {
		return nil
	}
	if m.dlg != dlgNone {
		return m.updateDialog(msg) // modal: clicks outside do nothing
	}
	mb, action, consumed := m.menu.Update(msg)
	m.menu = mb
	if action != "" {
		return m.do(action)
	}
	if consumed {
		return nil
	}
	if ev, idx := m.tabBar.HandleMouse(msg, len(m.tabs)); ev != ui.TabNone {
		m.status = ""
		switch ev {
		case ui.TabClick:
			if idx >= 0 && idx < len(m.tabs) {
				m.focus(idx)
			}
		case ui.TabClose:
			if idx >= 0 && idx < len(m.tabs) {
				return m.requestClose(idx)
			}
		case ui.TabNew:
			return m.do(actNew)
		case ui.TabPrev:
			return m.do(actPrevTab)
		case ui.TabNext:
			return m.do(actNextTab)
		}
		return nil
	}
	if a := m.fkeyBar.HandleMouse(msg, m.fkeys()); a != "" {
		m.status = ""
		return m.do(a)
	}
	t := m.active()
	if t == nil {
		return nil
	}
	if t.isHome() && ui.IsLeftClick(msg) {
		for _, b := range homeButtons {
			if ui.Hit(b.id, msg) {
				return m.do(b.action)
			}
		}
	}
	if ui.IsWheelUp(msg) || ui.IsWheelDown(msg) {
		var cmd tea.Cmd
		*t, cmd = t.Update(msg)
		return cmd
	}
	return nil
}

// requestClose closes tab i, asking first if it is watching.
func (m *mainModel) requestClose(i int) tea.Cmd {
	t := m.tabs[i]
	if t.isWatching {
		return m.openConfirm(dlgConfirmClose, t.id, "Close tab", fmt.Sprintf("%s is being watched.\nClose the tab and stop watching?", t.domain))
	}
	m.closeTab(i)
	return nil
}

// do performs a named action (from a key, the menu, the F-key bar or a button).
func (m *mainModel) do(action string) tea.Cmd {
	t := m.active()
	lookupTab := t != nil && !t.isHome()
	results := lookupTab && t.resultsVisible()

	if strings.HasPrefix(action, "filter:") {
		if results && t.isZoneDiff() && t.state == stateViewResults {
			t.setZoneDiffFilter(strings.TrimPrefix(action, "filter:"))
		}
		return nil
	}

	switch action {
	case actTheme:
		return m.openThemeDialog()
	case actHelp:
		m.showHome()
	case actNew, actNewTab:
		return m.openLookupDialog(-1, "", "", m.defaultOpts)
	case actChange:
		if !lookupTab {
			return m.do(actNew)
		}
		if t.isZoneDiff() {
			return m.openZoneDiffDialog(t.id, t.domain, t.zd.form)
		}
		return m.openLookupDialog(t.id, t.domain, t.lookupType, t.lookupOpts)
	case actZoneDiff:
		if lookupTab {
			domain := t.domain
			if lookup.ValidateTarget(domain) != nil {
				domain = ""
			}
			return m.openZoneDiffDialog(t.id, domain, t.zd.form)
		}
		return m.openZoneDiffDialog(-1, "", newZoneDiffForm())
	case actRerun:
		if lookupTab {
			return t.rerun()
		}
	case actReport:
		if lookupTab && t.domain != "" {
			m.lastLookupType = lookup.ComprehensiveReportName
			return t.run(t.domain, lookup.ComprehensiveReportName, t.lookupOpts)
		}
		return m.openLookupDialog(-1, "", lookup.ComprehensiveReportName, m.defaultOpts)
	case actWatch:
		if !lookupTab {
			return nil
		}
		if t.isWatching {
			t.stopWatch()
			t.renderContent()
			return t.setStatus("Watch stopped")
		}
		if t.watchAvailable() && t.resultsVisible() {
			return m.openWatchDialog(t)
		}
	case actServer:
		if lookupTab && !t.isZoneDiff() {
			return m.openServerDialog(t)
		}
	case actClose:
		if t != nil {
			return m.requestClose(m.activeTab)
		}
	case actMenu:
		m.menu.Open(0)
	case actQuit:
		if m.busy() {
			return m.openConfirm(dlgConfirmQuit, -1, "Quit", "Lookups are running or being watched.\nQuit dlookup?")
		}
		return tea.Quit
	case actExport:
		if results {
			return m.openExportDialog(t)
		}
	case actExportAll:
		m.status = m.exportAll()
	case actCopy:
		if results {
			return t.copyCmd()
		}
	case actNextTab:
		if len(m.tabs) > 1 {
			m.focus((m.activeTab + 1) % len(m.tabs))
		}
	case actPrevTab:
		if len(m.tabs) > 1 {
			m.focus((m.activeTab - 1 + len(m.tabs)) % len(m.tabs))
		}
	case actBack:
		if lookupTab {
			if s := t.back(); s != "" {
				return t.setStatus(s)
			}
		}
	case actMatches:
		if results && t.isZoneDiff() && t.state == stateViewResults {
			return t.toggleMatches()
		}
	case actTop:
		if t != nil {
			t.viewport.GotoTop()
		}
	case actBottom:
		if t != nil {
			t.viewport.GotoBottom()
		}
	case actMouse:
		m.mouse = !m.mouse
		if m.mouse {
			m.status = "Mouse on — hold Shift (Option on macOS) to select text"
			return tea.EnableMouseCellMotion
		}
		m.status = "Mouse off — select text normally; turn it back on in Options"
		return tea.DisableMouse
	case actConfigInfo:
		path, err := getConfigPath()
		if err != nil {
			path = "(unknown: " + err.Error() + ")"
		}
		return m.openInfo("Config file", "Configuration is read from:\n"+path+
			"\n\nEdit it to change keybindings or set\nmouse: false to start with the mouse off.\nRestart dlookup to apply changes.")
	case actAbout:
		return m.openInfo("About dlookup", "dlookup "+versionString()+
			"\nDNS, RDAP & WHOIS lookups with tabs, watch mode\nand zone diffs for DNS migrations.\n\nhttps://github.com/kristiand00/dlookup")
	}
	return nil
}

// exportAllContent concatenates every lookup tab's result/error with a header.
func (m mainModel) exportAllContent() string {
	var b strings.Builder
	n := 0
	for i, t := range m.tabs {
		if t.isHome() {
			continue
		}
		if n > 0 {
			b.WriteString("\n\n")
		}
		n++
		title := t.domain
		if title == "" {
			title = fmt.Sprintf("Tab %d", i+1)
		}
		if t.lookupType != "" {
			title += " — " + t.lookupLabel()
		}
		if t.isZoneDiff() {
			if t.zd.opts.NewServer != "" {
				title += " ⇄ " + t.zd.opts.NewServer
			}
		} else if t.lookupOpts.Server != "" {
			title += " @" + t.lookupOpts.Server
		}
		fmt.Fprintf(&b, "===== %s =====\n", title)
		if !t.lastUpdated.IsZero() {
			fmt.Fprintf(&b, "Updated: %s\n", t.lastUpdated.Format("2006-01-02 15:04:05"))
		}
		b.WriteString(t.plainContent())
		b.WriteString("\n")
	}
	return b.String()
}

// exportAll writes all lookup tabs into one timestamped file in the working
// directory and returns a status message.
func (m mainModel) exportAll() string {
	n := 0
	for _, t := range m.tabs {
		if !t.isHome() {
			n++
		}
	}
	if n == 0 {
		return "Nothing to export"
	}
	name := fmt.Sprintf("dlookup-all-%s.txt", now().Format("20060102-150405"))
	path, err := writeExportFile(name, m.exportAllContent())
	if err != nil {
		return "Export all failed: " + err.Error()
	}
	return fmt.Sprintf("Exported %d tabs to %s", n, path)
}

// tabInfos describes the tabs for the tab bar.
func (m mainModel) tabInfos() []ui.Tab {
	out := make([]ui.Tab, len(m.tabs))
	for i, t := range m.tabs {
		title := t.domain
		switch {
		case t.isHome():
			title = "Home"
		case title == "":
			title = "New tab"
		}
		title = truncateWidth(title, 24)
		if t.isZoneDiff() && t.domain != "" {
			title += " ⇄"
		}
		badge := ""
		switch {
		case t.changed && i != m.activeTab:
			badge = "●"
		case t.inFlight:
			badge = "⟳"
		case t.isWatching:
			badge = "◉"
		}
		out[i] = ui.Tab{Title: title, Badge: badge, Closable: !(t.isHome() && len(m.tabs) == 1)}
	}
	return out
}

func (m mainModel) View() string { return paintScreen(ui.Scan(m.render()), m.width) }

// render composes the screen with zone markers still in place (View scans them).
func (m mainModel) render() string {
	if m.width == 0 || m.height == 0 {
		return "Initializing..."
	}
	rows := []string{
		fitLine(m.menu.View(m.width), m.width),
		fitLine(m.tabBar.View(m.tabInfos(), m.activeTab, m.width), m.width),
		m.panelView(),
		m.statusLine(),
		fitLine(m.fkeyBar.View(m.fkeys(), m.width), m.width),
	}
	view := strings.Join(rows, "\n")
	if m.menu.IsOpen() {
		dd, x, y := m.menu.DropdownViewAt(m.width)
		if dd != "" {
			view = ui.OverlayShadow(view, dd, x, y)
		}
	}
	if m.dlg != dlgNone {
		w, h := m.dialog.Size()
		x := max(0, (m.width-w)/2)
		y := max(0, 2+(m.panelHeight()-h)/2)
		view = m.dialog.RenderAt(view, x, y, m.height)
	}
	return view
}

// fitLine truncates s to one line of width cells (padding is left to the
// terminal background).
func fitLine(s string, width int) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return truncateWidth(s, width)
}

// statusLine renders the status message, or context hints for the active tab.
func (m mainModel) statusLine() string {
	status := m.status
	t := m.active()
	if status == "" && t != nil {
		status = t.statusMsg
	}
	if status != "" {
		return statusStyle.Render(truncateWidth(status, max(1, m.width-2)))
	}
	return hintStyle.Render(truncateWidth(m.hints(), max(1, m.width-2)))
}

// hints are short context-specific key hints using the configured keys.
func (m mainModel) hints() string {
	k := m.config.Keybindings
	h := func(key, desc string) string { return prettyKey(key) + " " + desc }
	t := m.active()
	var parts []string
	switch {
	case t == nil:
	case t.isHome():
		parts = []string{h(k.NewTab, "new lookup"), h(k.ZoneDiff, "zone diff"), "↑↓ scroll", "F9 menu", "F10 quit"}
	case t.state == stateLoading:
		parts = []string{h(k.Back, "cancel"), h(k.NewTab, "new lookup")}
	case t.state == stateIdle:
		parts = []string{h(k.Confirm, "choose lookup"), h(k.NewTab, "new lookup"), h(k.CloseTab, "close")}
	case t.isZoneDiff():
		parts = []string{h(k.ToggleMatches, "matches"), "1-5/0 filter", "r re-run", h(k.Confirm, "edit"), h(k.Export, "export"), h(k.Copy, "copy")}
	default:
		parts = []string{h(k.Confirm, "change"), "r re-run"}
		if t.isWatching {
			parts = append(parts, h(k.WatchToggle, "stop watch"))
		} else if t.watchAvailable() {
			parts = append(parts, h(k.WatchToggle, "watch"))
		}
		parts = append(parts, h(k.Server, "server"), h(k.Copy, "copy"), h(k.Export, "export"))
	}
	if len(m.tabs) > 1 {
		parts = append(parts, prettyKey(k.PrevTab)+prettyKey(k.NextTab)+" tabs")
	}
	return strings.Join(parts, " · ")
}

// panelView renders the active tab inside a bordered box with its title in the
// top border and a scrollbar on the right edge when the content overflows.
func (m mainModel) panelView() string {
	w := max(4, m.width)
	h := m.panelHeight()
	innerW, innerH := w-2, h-2
	t := m.active()

	title, body := "", ""
	if t != nil {
		title = t.panelTitle()
		if t.isHome() {
			body = homeButtonsView() + "\n\n" + t.viewport.View()
		} else {
			body = t.body()
		}
	}
	lines := strings.Split(body, "\n")

	b := panelBorderStyle
	var out strings.Builder
	title = truncateWidth(title, max(0, innerW-4))
	top := b.Render("┌─")
	used := 1
	if title != "" {
		top += panelTitleStyle.Render(" " + title + " ")
		used += lipgloss.Width(title) + 2
	}
	top += b.Render(strings.Repeat("─", max(0, innerW-used)) + "┐")
	out.WriteString(top)

	bar := m.scrollbar(t, innerH)
	for i := 0; i < innerH; i++ {
		line := ""
		if i < len(lines) {
			line = truncateWidth(lines[i], innerW)
		}
		line += strings.Repeat(" ", max(0, innerW-lipgloss.Width(line)))
		right := b.Render("│")
		if bar != nil {
			right = bar[i]
		}
		out.WriteString("\n" + b.Render("│") + line + right)
	}
	out.WriteString("\n" + b.Render("└"+strings.Repeat("─", innerW)+"┘"))
	return out.String()
}

// scrollbar returns the right-edge cells (▲ track/thumb ▼) for t's viewport,
// or nil when everything fits.
func (m mainModel) scrollbar(t *tabModel, rows int) []string {
	if t == nil || !t.scrollable() || rows < 3 {
		return nil
	}
	vp := t.viewport
	total := vp.TotalLineCount()
	if total <= vp.Height {
		return nil
	}
	track := rows - 2
	thumb := max(1, track*vp.Height/total)
	pos := int(vp.ScrollPercent()*float64(track-thumb) + 0.5)
	out := make([]string, rows)
	out[0] = scrollThumbStyle.Render("▲")
	out[rows-1] = scrollThumbStyle.Render("▼")
	for i := 0; i < track; i++ {
		if i >= pos && i < pos+thumb {
			out[i+1] = scrollThumbStyle.Render("█")
		} else {
			out[i+1] = scrollTrackStyle.Render("░")
		}
	}
	return out
}
