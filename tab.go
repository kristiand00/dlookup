package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/atotto/clipboard"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"dlookup/lookup"
)

// maxConcurrentLookups bounds how many lookups run at once across all tabs.
const maxConcurrentLookups = 8

// lookupSem is a counting semaphore shared by all lookup commands.
var lookupSem = make(chan struct{}, maxConcurrentLookups)

// Hooks replaceable in tests.
var (
	tickAfter          = tea.Tick
	clipboardWriteAll  = clipboard.WriteAll
	now                = time.Now
	statusClearTimeout = 3 * time.Second
)

// tabMsg is implemented by messages addressed to a single tab; mainModel routes
// them by id regardless of which tab is active.
type tabMsg interface{ targetTab() int }

// lookupResultMsg carries a successful lookup's output back to the tab with id tabId.
// seq identifies the lookup run; results from superseded runs are ignored.
type lookupResultMsg struct {
	tabId  int
	seq    int
	output string
}

// errorMsg carries a failed lookup's error back to the tab with id tabId.
type errorMsg struct {
	tabId int
	seq   int
	err   error
}

// watchTickMsg triggers a watch refresh for tab tabId. gen must match the tab's
// current watch generation, so stopping/restarting watch kills older tick chains.
type watchTickMsg struct {
	tabId int
	gen   int
}

// tabStatusMsg sets a brief status line on a tab.
type tabStatusMsg struct {
	tabId int
	text  string
}

// clearStatusMsg clears a tab's status line if it has not been replaced since.
type clearStatusMsg struct {
	tabId int
	seq   int
}

func (m lookupResultMsg) targetTab() int { return m.tabId }
func (m errorMsg) targetTab() int        { return m.tabId }
func (m watchTickMsg) targetTab() int    { return m.tabId }
func (m tabStatusMsg) targetTab() int    { return m.tabId }
func (m clearStatusMsg) targetTab() int  { return m.tabId }

type tabState int

const (
	stateIdle tabState = iota // no lookup yet (or cancelled)
	stateLoading
	stateViewResults
	stateError
)

// tabKind distinguishes the Home (help) tab from lookup tabs.
type tabKind int

const (
	tabLookup tabKind = iota
	tabHome
)

var nextTabID = 0

type tabModel struct {
	id            int
	kind          tabKind
	state         tabState
	viewport      viewport.Model
	domain        string
	lookupType    string
	result        string
	hasResult     bool // result holds a successful run of the current domain+lookup
	err           error
	loadingMsg    string
	idleMsg       string // shown in the idle state (e.g. "Lookup cancelled")
	width         int    // panel interior width
	height        int    // panel interior height
	viewportReady bool

	// Watch mode.
	isWatching    bool
	watchInterval time.Duration
	watchGen      int
	lastUpdated   time.Time
	diffAdded     map[int]bool // indices of result lines that are new vs. the previous run
	diffRemoved   []string     // lines from the previous run that disappeared
	changed       bool         // result changed since the tab was last focused

	// Lookup bookkeeping.
	lookupSeq    int
	inFlight     bool
	lookupCancel context.CancelFunc
	initCmd      tea.Cmd

	statusMsg string
	statusSeq int

	// ctx is cancelled when the tab is closed; lookups run under it.
	ctx        context.Context
	cancel     context.CancelFunc
	lookupOpts lookup.Options

	// Zone diff (see zonediff_tui.go).
	zd zoneDiffState
}

// newTabModel creates a lookup tab sized to the panel interior. If both
// initialDomain and initialLookupType are set (and the lookup type exists), the
// tab starts loading; the lookup itself is started by Init. opts are this tab's
// initial lookup options (e.g. DNS server).
func newTabModel(width, height int, initialDomain, initialLookupType string, opts lookup.Options) tabModel {
	ctx, cancel := context.WithCancel(context.Background())
	m := tabModel{
		id:         nextTabID,
		width:      width,
		height:     height,
		domain:     initialDomain,
		ctx:        ctx,
		cancel:     cancel,
		lookupOpts: opts,
		zd:         zoneDiffState{form: newZoneDiffForm()},
	}
	nextTabID++
	if initialDomain != "" && initialLookupType != "" {
		if _, exists := lookup.GetProvider(initialLookupType); exists {
			m.lookupType = initialLookupType
			m.state = stateLoading
			m.loadingMsg = fmt.Sprintf("Running %s on %s...", m.lookupLabel(), m.domain)
			m.initCmd = m.startLookup()
		} else {
			log.Printf("Warning: Invalid initial lookup type provided: %s", initialLookupType)
		}
	}
	m.setSize(width, height)
	return m
}

// newHomeTab creates the Home (welcome/help) tab; its content is set by the
// main model, which knows the keybindings.
func newHomeTab(width, height int) tabModel {
	m := newTabModel(width, height, "", "", lookup.Options{})
	m.kind = tabHome
	m.setSize(width, height)
	return m
}

// homeHeaderHeight is the number of interior rows above the Home viewport
// (the button row and a blank line).
const homeHeaderHeight = 2

// setSize sets the panel interior size.
func (m *tabModel) setSize(width, height int) {
	m.width = max(1, width)
	m.height = max(1, height)
	vpHeight := m.height
	if m.kind == tabHome {
		vpHeight = max(1, m.height-homeHeaderHeight)
	}
	if !m.viewportReady {
		m.viewport = viewport.New(m.width, vpHeight)
		m.viewport.Style = lipgloss.NewStyle().Padding(0, 1)
		m.viewport.KeyMap.Left.SetEnabled(false) // left/right switch tabs
		m.viewport.KeyMap.Right.SetEnabled(false)
		m.viewportReady = true
	} else {
		m.viewport.Width = m.width
		m.viewport.Height = vpHeight
	}
}

// Init returns the tab's startup command (its initial lookup, if any).
// mainModel calls it exactly once per tab.
func (m tabModel) Init() tea.Cmd { return m.initCmd }

func (m tabModel) isHome() bool { return m.kind == tabHome }

// watchAvailable reports whether watch mode applies to the tab's lookup.
func (m tabModel) watchAvailable() bool {
	return m.kind == tabLookup && m.lookupType != "" && m.lookupType != lookup.ComprehensiveReportName && !m.isZoneDiff()
}

// resultsVisible reports whether results or an error are shown.
func (m tabModel) resultsVisible() bool {
	return m.state == stateViewResults || m.state == stateError
}

// scrollable reports whether the panel shows the tab's viewport.
func (m tabModel) scrollable() bool { return m.isHome() || m.resultsVisible() }

// isPlaceholder reports whether the tab is an unused lookup tab that a new
// lookup may reuse.
func (m tabModel) isPlaceholder() bool {
	return m.kind == tabLookup && m.state == stateIdle && !m.hasResult && m.lookupType == "" && !m.inFlight
}

// stopWatch ends watch mode; pending ticks from the old chain become stale.
func (m *tabModel) stopWatch() {
	if m.isWatching {
		m.watchGen++
	}
	m.isWatching = false
	m.diffAdded = nil
	m.diffRemoved = nil
}

// startWatch starts watch mode with interval d: one refresh right away, then
// one per tick.
func (m *tabModel) startWatch(d time.Duration) tea.Cmd {
	m.watchInterval = d
	m.isWatching = true
	m.watchGen++
	m.renderContent()
	cmds := []tea.Cmd{m.watchTick()}
	if !m.inFlight {
		cmds = append(cmds, m.startLookup())
	}
	return tea.Batch(cmds...)
}

// cancelLookup aborts any in-flight lookup and makes its result stale.
func (m *tabModel) cancelLookup() {
	if m.lookupCancel != nil {
		m.lookupCancel()
		m.lookupCancel = nil
	}
	if m.inFlight {
		m.lookupSeq++
	}
	m.inFlight = false
}

// back cancels a running lookup or stops watching. It returns a status text
// ("" when there was nothing to do).
func (m *tabModel) back() string {
	switch {
	case m.state == stateLoading:
		m.stopWatch()
		m.cancelLookup()
		m.loadingMsg = ""
		if m.hasResult || m.zd.result != nil && m.isZoneDiff() {
			m.state = stateViewResults
		} else {
			m.state = stateIdle
			m.idleMsg = "Lookup cancelled."
		}
		m.renderContent()
		return "Cancelled"
	case m.isWatching:
		m.stopWatch()
		m.cancelLookup()
		m.renderContent()
		return "Watch stopped"
	}
	return ""
}

// run starts lookupType on domain with opts in this tab, replacing whatever it
// showed. Zone diffs use runZoneDiff instead.
func (m *tabModel) run(domain, lookupType string, opts lookup.Options) tea.Cmd {
	m.stopWatch()
	m.cancelLookup()
	if domain != m.domain || lookupType != m.lookupType {
		m.hasResult = false
		m.result = ""
	}
	m.domain = domain
	m.lookupType = lookupType
	m.lookupOpts = opts
	return m.rerun()
}

// rerun runs the tab's current lookup again.
func (m *tabModel) rerun() tea.Cmd {
	if m.kind != tabLookup || m.lookupType == "" {
		return nil
	}
	if m.isZoneDiff() {
		return m.runZoneDiff(m.zd.opts)
	}
	m.state = stateLoading
	m.loadingMsg = fmt.Sprintf("Running %s on %s...", m.lookupLabel(), m.domain)
	m.err = nil
	m.viewport.GotoTop()
	return m.startLookup()
}

// setStatus shows a brief status message and schedules its removal.
func (m *tabModel) setStatus(text string) tea.Cmd {
	m.statusMsg = text
	m.statusSeq++
	id, seq := m.id, m.statusSeq
	return tickAfter(statusClearTimeout, func(time.Time) tea.Msg { return clearStatusMsg{tabId: id, seq: seq} })
}

// copyCmd copies the visible result to the clipboard and reports via a status.
func (m tabModel) copyCmd() tea.Cmd {
	content := m.plainContent()
	id := m.id
	return func() tea.Msg {
		if err := clipboardWriteAll(content); err != nil {
			return tabStatusMsg{tabId: id, text: fmt.Sprintf("Copy failed: %v", err)}
		}
		return tabStatusMsg{tabId: id, text: "Copied result to clipboard"}
	}
}

func (m tabModel) Update(msg tea.Msg) (tabModel, tea.Cmd) {
	if cmd, ok := m.handleZoneDiffMsg(msg); ok {
		return m, cmd
	}

	var cmds []tea.Cmd
	switch msg := msg.(type) {
	case tea.KeyMsg:
		cmds = append(cmds, m.handleKey(msg))

	case tea.MouseMsg:
		if m.scrollable() {
			var cmd tea.Cmd
			m.viewport, cmd = m.viewport.Update(msg)
			cmds = append(cmds, cmd)
		}

	case watchTickMsg:
		if msg.tabId != m.id || !m.isWatching || msg.gen != m.watchGen {
			break // stale chain
		}
		if !m.inFlight {
			cmds = append(cmds, m.startLookup())
		}
		cmds = append(cmds, m.watchTick())

	case lookupResultMsg:
		if msg.tabId != m.id || msg.seq != m.lookupSeq {
			break
		}
		m.inFlight = false
		m.lookupCancel = nil
		if m.isWatching && m.hasResult {
			m.diffAdded, m.diffRemoved = diffLines(m.result, msg.output)
			if len(m.diffAdded) > 0 || len(m.diffRemoved) > 0 {
				m.changed = true
			}
		} else {
			m.diffAdded, m.diffRemoved = nil, nil
		}
		wasVisible := m.state == stateViewResults
		m.result = msg.output
		m.hasResult = true
		m.err = nil
		m.loadingMsg = ""
		m.lastUpdated = now()
		m.state = stateViewResults
		m.renderContent()
		if !(m.isWatching && wasVisible) {
			m.viewport.GotoTop()
		}

	case errorMsg:
		if msg.tabId != m.id || msg.seq != m.lookupSeq {
			break
		}
		m.inFlight = false
		m.lookupCancel = nil
		m.err = msg.err
		m.loadingMsg = ""
		m.lastUpdated = now()
		m.state = stateError
		m.renderContent()
		if !m.isWatching {
			m.viewport.GotoTop()
		}

	case tabStatusMsg:
		if msg.tabId == m.id {
			cmds = append(cmds, m.setStatus(msg.text))
		}

	case clearStatusMsg:
		if msg.tabId == m.id && msg.seq == m.statusSeq {
			m.statusMsg = ""
		}
	}
	return m, tea.Batch(cmds...)
}

// handleKey handles keys not bound to a global action: scrolling and the zone
// diff filter keys.
func (m *tabModel) handleKey(msg tea.KeyMsg) tea.Cmd {
	if !m.scrollable() {
		return nil
	}
	if m.isZoneDiff() && m.state == stateViewResults {
		if cmd, ok := m.handleZoneDiffFilterKey(msg.String()); ok {
			return cmd
		}
	}
	switch msg.String() {
	case "home", "g":
		m.viewport.GotoTop()
		return nil
	case "end", "G":
		m.viewport.GotoBottom()
		return nil
	}
	var cmd tea.Cmd
	m.viewport, cmd = m.viewport.Update(msg)
	return cmd
}

// watchTick schedules the next tick of the current watch chain. Only the id,
// generation and interval are captured, never the tab itself.
func (m tabModel) watchTick() tea.Cmd {
	id, gen, d := m.id, m.watchGen, m.watchInterval
	return tickAfter(d, func(time.Time) tea.Msg { return watchTickMsg{tabId: id, gen: gen} })
}

// watchLabel is the " [Watching: 5s]" suffix, or "" when not watching.
func (m tabModel) watchLabel() string {
	if !m.isWatching {
		return ""
	}
	return fmt.Sprintf(" [Watching: %s]", m.watchInterval)
}

// renderContent renders the result or error (with watch header and diff) into
// the viewport. It is the single rendering path for results, errors and resizes.
func (m *tabModel) renderContent() {
	if !m.viewportReady || m.isHome() {
		return
	}
	var b strings.Builder
	switch m.state {
	case stateViewResults:
		if m.isZoneDiff() {
			m.viewport.SetContent(m.renderZoneDiff())
			return
		}
		b.WriteString(resultHeaderStyle.Render(strings.TrimSpace(fmt.Sprintf("%s Results for %s%s", m.lookupLabel(), m.domain, m.watchLabel()))))
		b.WriteString("\n")
		if m.isWatching && !m.lastUpdated.IsZero() {
			b.WriteString(watchInfoStyle.Render("Last updated " + m.lastUpdated.Format("15:04:05")))
			b.WriteString("\n")
		}
		lines := strings.Split(m.result, "\n")
		for i, line := range lines {
			switch {
			case m.diffAdded[i]:
				b.WriteString(diffAddStyle.Render("+ " + line))
			case m.diffAdded != nil || len(m.diffRemoved) > 0:
				b.WriteString("  " + line)
			default:
				b.WriteString(line)
			}
			if i < len(lines)-1 {
				b.WriteString("\n")
			}
		}
		if len(m.diffRemoved) > 0 {
			b.WriteString("\n\n")
			b.WriteString(diffRemoveStyle.Render("Removed since previous run:"))
			for _, line := range m.diffRemoved {
				b.WriteString("\n")
				b.WriteString(diffRemoveStyle.Render("- " + line))
			}
		}
	case stateError:
		header := fmt.Sprintf("Error running %s for %s%s", m.lookupLabel(), m.domain, m.watchLabel())
		if m.isWatching && !m.lastUpdated.IsZero() {
			header += "\nLast updated " + m.lastUpdated.Format("15:04:05")
		}
		b.WriteString(errorStyle.Render(fmt.Sprintf("%s\nError:\n%v", header, m.err)))
	default:
		return
	}
	m.viewport.SetContent(b.String())
}

// plainContent is the unstyled text of the visible result or error, used for
// export and clipboard.
func (m tabModel) plainContent() string {
	switch m.state {
	case stateViewResults:
		if m.isZoneDiff() {
			return m.zoneDiffPlain()
		}
		return m.result
	case stateError:
		return fmt.Sprintf("Error running %s for %s%s\nError:\n%v", m.lookupLabel(), m.domain, m.watchLabel(), m.err)
	case stateLoading:
		return "(lookup in progress)"
	}
	return "(no results)"
}

// lookupLabel is the display name of the tab's lookup, e.g. "SDIG MX".
func (m tabModel) lookupLabel() string {
	return lookupLabel(m.lookupType, m.domain, m.lookupOpts)
}

// lookupLabel is the display name of lookupType on target: the SDIG lookup
// includes its query type ("SDIG A"), other lookups are shown by name.
func lookupLabel(lookupType, target string, opts lookup.Options) string {
	if lookupType == lookup.SDIGName {
		return lookup.SDIGLabel(target, opts)
	}
	return lookupType
}

// panelTitle is the title shown in the panel's top border:
// "domain · lookup · @server · [watching 5s]".
func (m tabModel) panelTitle() string {
	if m.isHome() {
		return "Home"
	}
	if m.domain == "" {
		return "New tab"
	}
	parts := []string{m.domain}
	if m.lookupType != "" {
		parts = append(parts, m.lookupLabel())
	}
	if m.isZoneDiff() {
		if m.zd.opts.NewServer != "" {
			parts = append(parts, "⇄ "+m.zd.opts.NewServer)
		}
	} else if m.lookupOpts.Server != "" {
		parts = append(parts, "@"+m.lookupOpts.Server)
	}
	if m.isWatching {
		w := fmt.Sprintf("[watching %s]", m.watchInterval)
		if m.inFlight {
			w += " ⟳"
		}
		parts = append(parts, w)
	}
	return strings.Join(parts, " · ")
}

// body renders the panel interior for lookup tabs (Home is rendered by the
// main model).
func (m tabModel) body() string {
	switch m.state {
	case stateLoading:
		return loadingStyle.Render(m.loadingMsg) + "\n" + helpDescStyle.Padding(0, 1).Render("esc/q cancels")
	case stateViewResults, stateError:
		return m.viewport.View()
	}
	if m.domain != "" {
		msg := fmt.Sprintf("No lookup selected for %s.", m.domain)
		if m.idleMsg != "" {
			msg = m.idleMsg
		}
		return lipgloss.NewStyle().Padding(1, 2).Render(msg + "\n\n" + helpDescStyle.Render("Press F3 or Enter to choose a lookup."))
	}
	return lipgloss.NewStyle().Padding(1, 2).Render("Empty tab.\n\n" + helpDescStyle.Render("Press F2 or n for a new lookup."))
}

// startLookup starts a new lookup run for the tab's domain and lookup type,
// superseding any in-flight run.
func (m *tabModel) startLookup() tea.Cmd {
	if m.isZoneDiff() {
		return m.startZoneDiff()
	}
	if m.lookupCancel != nil {
		m.lookupCancel()
	}
	m.lookupSeq++
	ctx, cancel := context.WithCancel(m.ctx)
	m.lookupCancel = cancel
	m.inFlight = true
	return lookupCmd(ctx, m.id, m.lookupSeq, m.domain, m.lookupType, m.lookupOpts)
}

// lookupCmd returns a command running one lookup. All inputs are copied values,
// so the closure never reads mutable tab state. At most maxConcurrentLookups
// run at once.
func lookupCmd(ctx context.Context, id, seq int, domain, lookupType string, opts lookup.Options) tea.Cmd {
	return func() tea.Msg {
		provider, exists := lookup.GetProvider(lookupType)
		if !exists {
			return errorMsg{tabId: id, seq: seq, err: fmt.Errorf("internal error: unknown lookup type selected: %s", lookupType)}
		}
		if !provider.CheckAvailability() {
			return errorMsg{tabId: id, seq: seq, err: fmt.Errorf("required command for %s not found", provider.Name())}
		}
		select {
		case lookupSem <- struct{}{}:
		case <-ctx.Done():
			return errorMsg{tabId: id, seq: seq, err: ctx.Err()}
		}
		defer func() { <-lookupSem }()
		output, err := provider.Execute(ctx, domain, opts)
		if err != nil {
			return errorMsg{tabId: id, seq: seq, err: err}
		}
		return lookupResultMsg{tabId: id, seq: seq, output: output}
	}
}

// ttlField matches a zone-format record line "name TTL CLASS TYPE ...", so TTL
// countdowns between runs are not reported as changes.
var ttlField = regexp.MustCompile(`^(\S+\s+)\d+(\s+(?:IN|CH|HS)\s)`)

// sdigTTLField matches an SDIG record line "place<TAB>name<TAB>TTL<TAB>...".
var sdigTTLField = regexp.MustCompile(`^([0-2]\t\S+\t)\d+(\t)`)

// volatilePrefixes are output lines that change on every run (timings, ids).
var volatilePrefixes = []string{";; Query time:", ";; WHEN:", ";; ->>HEADER<<-", ";; MSG SIZE"}

// diffKey normalizes a line for change detection; "" means "ignore".
func diffKey(line string) string {
	t := strings.TrimSpace(line)
	for _, p := range volatilePrefixes {
		if strings.HasPrefix(t, p) {
			return ""
		}
	}
	if k := sdigTTLField.ReplaceAllString(t, "${1}_${2}"); k != t {
		return k
	}
	return ttlField.ReplaceAllString(t, "${1}_${2}")
}

// diffLines compares two outputs line by line (as multisets, ignoring volatile
// lines). It returns the indices of lines in cur that are new and the lines of
// prev that are gone.
func diffLines(prev, cur string) (added map[int]bool, removed []string) {
	prevCount := make(map[string]int)
	prevLines := strings.Split(prev, "\n")
	for _, l := range prevLines {
		if k := diffKey(l); k != "" {
			prevCount[k]++
		}
	}
	added = make(map[int]bool)
	for i, l := range strings.Split(cur, "\n") {
		k := diffKey(l)
		if k == "" {
			continue
		}
		if prevCount[k] > 0 {
			prevCount[k]--
		} else {
			added[i] = true
		}
	}
	for _, l := range prevLines {
		k := diffKey(l)
		if k != "" && prevCount[k] > 0 {
			prevCount[k]--
			removed = append(removed, l)
		}
	}
	return added, removed
}

var unsafeFilenameChars = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// slug makes s safe for use in a filename.
func slug(s string) string {
	s = strings.Trim(unsafeFilenameChars.ReplaceAllString(strings.ToLower(s), "-"), "-.")
	if s == "" {
		return "lookup"
	}
	return s
}

// defaultExportFilename returns "<domain>-<lookup flag name or slug>-YYYYMMDD-HHMMSS.txt".
func defaultExportFilename(domain, lookupType string, t time.Time) string {
	kind := slug(lookupType)
	if p, ok := lookup.GetProvider(lookupType); ok && p.FlagName() != "" {
		kind = slug(p.FlagName())
	}
	return fmt.Sprintf("%s-%s-%s.txt", slug(domain), kind, t.Format("20060102-150405"))
}

// writeExportFile writes content to filename (expanding "~/"), creating parent
// directories. It returns the final path.
func writeExportFile(filename, content string) (string, error) {
	if filename == "~" || strings.HasPrefix(filename, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("error getting home dir: %w", err)
		}
		filename = filepath.Join(home, strings.TrimPrefix(filename[1:], "/"))
	}
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return "", fmt.Errorf("error creating dir %s: %w", dir, err)
	}
	if err := os.WriteFile(filename, []byte(content), 0644); err != nil {
		return "", fmt.Errorf("error saving to %s: %w", filename, err)
	}
	return filename, nil
}
