package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/atotto/clipboard"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
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
	stateInputDomain tabState = iota
	stateSelectLookup
	stateLoading
	stateViewResults
	stateError
	stateWatchIntervalInput
	stateExportFilenameInput
	stateServerInput
)

// isModal reports whether s is a modal overlay that returns to lastState.
func (s tabState) isModal() bool {
	return s == stateWatchIntervalInput || s == stateExportFilenameInput || s == stateServerInput
}

type lookupItem string

func (i lookupItem) FilterValue() string { return string(i) }
func (i lookupItem) Title() string       { return string(i) }
func (i lookupItem) Description() string { return "" }

type itemDelegate struct{}

func (d itemDelegate) Height() int                               { return 1 }
func (d itemDelegate) Spacing() int                              { return 0 }
func (d itemDelegate) Update(msg tea.Msg, m *list.Model) tea.Cmd { return nil }
func (d itemDelegate) Render(w io.Writer, m list.Model, index int, listItem list.Item) {
	i, ok := listItem.(lookupItem)
	if !ok {
		return
	}
	str := string(i)
	fn := listNormalTitle.Render
	if index == m.Index() {
		fn = listSelectedTitle.Render
	}
	fmt.Fprint(w, fn(" "+str))
	if index == m.Index() {
		fmt.Fprint(w, listSelectedTitle.Render("> "))
	}
}

var nextTabID = 0

type tabModel struct {
	id            int
	state         tabState
	lastState     tabState // state to return to when a modal closes
	textInput     textinput.Model
	intervalInput textinput.Model
	exportInput   textinput.Model
	serverInput   textinput.Model
	inputErr      string // validation message for the active input/modal
	viewport      viewport.Model
	lookupList    list.Model
	domain        string
	lookupType    string
	result        string
	hasResult     bool // result holds a successful run of the current domain+lookup
	err           error
	loadingMsg    string
	width         int
	height        int
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
}

// newTabModel creates a tab. If both initialDomain and initialLookupType are set
// (and the lookup type exists), the tab starts loading; the lookup itself is
// started by Init. opts are this tab's initial lookup options (e.g. DNS server).
func newTabModel(width, height int, initialDomain, initialLookupType string, opts lookup.Options) tabModel {
	ti := textinput.New()
	ti.Placeholder = "example.com or IP"
	ti.CharLimit = 256
	ti.Width = max(40, width-4)
	ti.PromptStyle = focusedStyle
	ti.TextStyle = focusedStyle
	ti.Cursor.Style = cursorStyle

	providers := lookup.AvailableProviders()
	sort.Slice(providers, func(i, j int) bool {
		return providers[i].Name() < providers[j].Name()
	})
	items := make([]list.Item, len(providers))
	for i, p := range providers {
		items[i] = lookupItem(p.Name())
	}

	lookupList := list.New(items, itemDelegate{}, width-4, 10)
	lookupList.Title = "Select Lookup Type:"
	lookupList.Styles.Title = listHeaderStyle
	lookupList.SetShowStatusBar(false)
	lookupList.SetFilteringEnabled(false)
	lookupList.SetShowHelp(false)

	intervalInput := textinput.New()
	intervalInput.Placeholder = "Seconds (e.g., 5)"
	intervalInput.CharLimit = 5
	intervalInput.Width = 20

	exportInput := textinput.New()
	exportInput.Placeholder = "path/to/filename.txt"
	exportInput.CharLimit = 256
	exportInput.Width = max(50, width-10)

	serverInput := textinput.New()
	serverInput.Placeholder = "e.g. 1.1.1.1 (empty = system default)"
	serverInput.CharLimit = 128
	serverInput.Width = 40

	ctx, cancel := context.WithCancel(context.Background())

	m := tabModel{
		id:            nextTabID,
		textInput:     ti,
		lookupList:    lookupList,
		width:         width,
		height:        height,
		domain:        initialDomain,
		intervalInput: intervalInput,
		exportInput:   exportInput,
		serverInput:   serverInput,
		lastState:     stateInputDomain,
		ctx:           ctx,
		cancel:        cancel,
		lookupOpts:    opts,
	}
	nextTabID++
	m.textInput.SetValue(initialDomain)

	m.state = stateInputDomain
	if initialDomain != "" && initialLookupType != "" {
		if _, exists := lookup.GetProvider(initialLookupType); exists {
			m.state = stateLoading
			m.lookupType = initialLookupType
			m.loadingMsg = fmt.Sprintf("Running %s on %s...", m.lookupType, m.domain)
			m.initCmd = m.startLookup()
		} else {
			log.Printf("Warning: Invalid initial lookup type provided: %s", initialLookupType)
		}
	}
	if m.state == stateInputDomain {
		m.textInput.Focus()
	}

	m.setSize(width, height)
	return m
}

func (m *tabModel) setSize(width, height int) {
	m.width = width
	m.height = height

	tabBarHeight := 1
	separatorHeight := 1
	helpHeight := 3

	var tabInternalHeaderHeight int
	if m.state == stateInputDomain {
		promptRendered := inputPromptStyle.Render("Enter Domain/IP:")
		m.textInput.Width = max(40, width-4)
		inputRendered := m.textInput.View()
		tabInternalHeaderHeight = lipgloss.Height(promptRendered) + lipgloss.Height(inputRendered) + 1
	} else {
		tabInternalHeaderHeight = 1 + 1
	}

	listHeight := 0
	if m.state == stateSelectLookup {
		listAvailableHeight := height - tabBarHeight - separatorHeight - tabInternalHeaderHeight - helpHeight
		listContentHeight := max(5, listAvailableHeight-listHeaderStyle.GetVerticalPadding())
		m.lookupList.SetSize(width-2, listContentHeight)
		listHeight = m.lookupList.Height()
	}

	nonViewportHeight := tabBarHeight + separatorHeight + tabInternalHeaderHeight + listHeight + helpHeight
	vpHeight := max(1, height-nonViewportHeight)

	m.textInput.Width = max(40, width-4)

	if !m.viewportReady {
		m.viewport = viewport.New(width-2, vpHeight)
		m.viewport.Style = lipgloss.NewStyle().Padding(0, 1)
		m.viewportReady = true
	} else {
		m.viewport.Width = width - 2
		m.viewport.Height = vpHeight
	}
	m.viewport.HighPerformanceRendering = false
}

// Init returns the tab's startup command: its initial lookup (if any) or a
// cursor blink. mainModel calls it exactly once per tab.
func (m tabModel) Init() tea.Cmd {
	if m.initCmd != nil {
		return m.initCmd
	}
	if m.state == stateInputDomain {
		return textinput.Blink
	}
	return nil
}

// textEntryActive reports whether the tab is in a state where keystrokes are
// typed into a text input (so printable global keys must not be intercepted).
func (m tabModel) textEntryActive() bool {
	switch m.state {
	case stateInputDomain, stateWatchIntervalInput, stateExportFilenameInput, stateServerInput:
		return true
	}
	return false
}

// watchAvailable reports whether watch mode applies to the tab's lookup.
func (m tabModel) watchAvailable() bool {
	return m.lookupType != "" && m.lookupType != lookup.ComprehensiveReportName
}

// resultsVisible reports whether results or an error are shown.
func (m tabModel) resultsVisible() bool {
	return m.state == stateViewResults || m.state == stateError
}

// baseState is the state underneath any open modal.
func (m tabModel) baseState() tabState {
	if m.state.isModal() {
		return m.lastState
	}
	return m.state
}

// setBaseState changes the underlying state without closing an open modal.
func (m *tabModel) setBaseState(s tabState) {
	if m.state.isModal() {
		m.lastState = s
	} else {
		m.state = s
	}
}

// isBackKey reports whether msg means "back/cancel". Esc always does; the
// configured Back key does too, except when it is a printable key typed into a
// text input.
func isBackKey(msg tea.KeyMsg, k Keybindings, textEntry bool) bool {
	if msg.Type == tea.KeyEsc {
		return true
	}
	if textEntry && (msg.Type == tea.KeyRunes || msg.Type == tea.KeySpace) {
		return false
	}
	return msg.String() == k.Back
}

// openModal switches to a modal state, remembering where to return.
func (m *tabModel) openModal(s tabState, input *textinput.Model, value string) tea.Cmd {
	m.lastState = m.state
	m.state = s
	m.inputErr = ""
	input.SetValue(value)
	input.CursorEnd()
	m.setSize(m.width, m.height)
	return input.Focus()
}

// closeModal returns from a modal to the previous state.
func (m *tabModel) closeModal() {
	m.intervalInput.Blur()
	m.exportInput.Blur()
	m.serverInput.Blur()
	m.inputErr = ""
	m.state = m.lastState
	m.setSize(m.width, m.height)
	m.renderContent()
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

// goToInput returns to the domain input, stopping watch and any lookup.
func (m *tabModel) goToInput() tea.Cmd {
	m.stopWatch()
	m.cancelLookup()
	m.state = stateInputDomain
	m.inputErr = ""
	m.textInput.SetValue(m.domain)
	m.textInput.CursorEnd()
	m.setSize(m.width, m.height)
	return m.textInput.Focus()
}

// setStatus shows a brief status message and schedules its removal.
func (m *tabModel) setStatus(text string) tea.Cmd {
	m.statusMsg = text
	m.statusSeq++
	id, seq := m.id, m.statusSeq
	return tickAfter(statusClearTimeout, func(time.Time) tea.Msg { return clearStatusMsg{tabId: id, seq: seq} })
}

func (m tabModel) Update(msg tea.Msg, k Keybindings) (tabModel, tea.Cmd) {
	var cmds []tea.Cmd

	if m.viewportReady && m.resultsVisible() {
		if km, ok := msg.(tea.KeyMsg); !ok || !m.isTabKey(km, k) {
			var cmd tea.Cmd
			m.viewport, cmd = m.viewport.Update(msg)
			cmds = append(cmds, cmd)
		}
	}

	switch msg := msg.(type) {
	case tea.KeyMsg:
		cmds = append(cmds, m.handleKey(msg, k))

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
		wasVisible := m.baseState() == stateViewResults
		m.result = msg.output
		m.hasResult = true
		m.err = nil
		m.loadingMsg = ""
		m.lastUpdated = now()
		m.setBaseState(stateViewResults)
		m.setSize(m.width, m.height)
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
		m.setBaseState(stateError)
		m.setSize(m.width, m.height)
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

	default:
		// Cursor blinks etc. go to whichever input is active.
		var cmd tea.Cmd
		switch m.state {
		case stateInputDomain:
			m.textInput, cmd = m.textInput.Update(msg)
		case stateWatchIntervalInput:
			m.intervalInput, cmd = m.intervalInput.Update(msg)
		case stateExportFilenameInput:
			m.exportInput, cmd = m.exportInput.Update(msg)
		case stateServerInput:
			m.serverInput, cmd = m.serverInput.Update(msg)
		}
		cmds = append(cmds, cmd)
	}
	return m, tea.Batch(cmds...)
}

// isTabKey reports whether km is one of the tab's configured action keys in the
// results view (so it is not also forwarded to the viewport).
func (m tabModel) isTabKey(km tea.KeyMsg, k Keybindings) bool {
	switch km.String() {
	case k.Back, k.WatchToggle, k.Export, k.Copy, k.Server:
		return true
	}
	return false
}

func (m *tabModel) handleKey(msg tea.KeyMsg, k Keybindings) tea.Cmd {
	key := msg.String()
	switch m.state {
	case stateViewResults, stateError:
		switch {
		case isBackKey(msg, k, false):
			return m.goToInput()
		case key == k.WatchToggle:
			if !m.watchAvailable() {
				return nil
			}
			if m.isWatching {
				m.stopWatch()
				m.renderContent()
				return m.setStatus("Watch stopped")
			}
			value := ""
			if m.watchInterval > 0 {
				value = strconv.Itoa(int(m.watchInterval / time.Second))
			}
			return m.openModal(stateWatchIntervalInput, &m.intervalInput, value)
		case key == k.Export:
			return m.openModal(stateExportFilenameInput, &m.exportInput, defaultExportFilename(m.domain, m.lookupType, now()))
		case key == k.Copy:
			content := m.plainContent()
			id := m.id
			return func() tea.Msg {
				if err := clipboardWriteAll(content); err != nil {
					return tabStatusMsg{tabId: id, text: fmt.Sprintf("Copy failed: %v", err)}
				}
				return tabStatusMsg{tabId: id, text: "Copied result to clipboard"}
			}
		case key == k.Server:
			return m.openModal(stateServerInput, &m.serverInput, m.lookupOpts.Server)
		case key == "home" || key == "g":
			m.viewport.GotoTop()
		case key == "end" || key == "G":
			m.viewport.GotoBottom()
		}
		return nil

	case stateInputDomain:
		if key == k.Confirm {
			trimmed := strings.TrimSpace(m.textInput.Value())
			if err := lookup.ValidateTarget(trimmed); err != nil {
				m.inputErr = fmt.Sprintf("Invalid target: %v", err)
				return nil
			}
			if trimmed != m.domain {
				m.hasResult = false
				m.result = ""
			}
			m.domain = trimmed
			m.inputErr = ""
			m.state = stateSelectLookup
			m.textInput.Blur()
			m.lookupList.ResetFilter()
			m.lookupList.Select(0)
			m.setSize(m.width, m.height)
			return nil
		}
		var cmd tea.Cmd
		m.textInput, cmd = m.textInput.Update(msg)
		m.inputErr = ""
		return cmd

	case stateSelectLookup:
		switch {
		case isBackKey(msg, k, false):
			return m.goToInput()
		case key == k.Server:
			return m.openModal(stateServerInput, &m.serverInput, m.lookupOpts.Server)
		case key == k.Confirm:
			selected := m.lookupList.SelectedItem()
			if selected == nil {
				return nil
			}
			m.stopWatch()
			m.lookupType = selected.(lookupItem).FilterValue()
			m.state = stateLoading
			m.loadingMsg = fmt.Sprintf("Running %s on %s...", m.lookupType, m.domain)
			m.err = nil
			m.result = ""
			m.hasResult = false
			m.viewport.GotoTop()
			m.setSize(m.width, m.height)
			return m.startLookup()
		}
		var cmd tea.Cmd
		m.lookupList, cmd = m.lookupList.Update(msg)
		return cmd

	case stateWatchIntervalInput:
		switch {
		case key == k.Confirm:
			sec, err := strconv.Atoi(strings.TrimSpace(m.intervalInput.Value()))
			if err != nil || sec <= 0 {
				m.inputErr = "Enter a whole number of seconds greater than 0"
				return nil
			}
			m.watchInterval = time.Duration(sec) * time.Second
			m.isWatching = true
			m.watchGen++
			m.closeModal()
			// Refresh in place right away, then on every tick.
			cmds := []tea.Cmd{m.watchTick()}
			if !m.inFlight {
				cmds = append(cmds, m.startLookup())
			}
			return tea.Batch(cmds...)
		case isBackKey(msg, k, true):
			m.closeModal()
			return nil
		}
		var cmd tea.Cmd
		m.intervalInput, cmd = m.intervalInput.Update(msg)
		m.inputErr = ""
		return cmd

	case stateServerInput:
		switch {
		case key == k.Confirm:
			server := strings.TrimSpace(m.serverInput.Value())
			if server != "" {
				if err := lookup.ValidateServer(server); err != nil {
					m.inputErr = fmt.Sprintf("Invalid server: %v", err)
					return nil
				}
			}
			changed := server != m.lookupOpts.Server
			m.lookupOpts.Server = server
			m.closeModal()
			label := server
			if label == "" {
				label = "system default"
			}
			cmds := []tea.Cmd{m.setStatus("DNS server: " + label)}
			if changed && m.resultsVisible() && m.lookupType != "" {
				m.cancelLookup()
				cmds = append(cmds, m.startLookup())
			}
			return tea.Batch(cmds...)
		case isBackKey(msg, k, true):
			m.closeModal()
			return nil
		}
		var cmd tea.Cmd
		m.serverInput, cmd = m.serverInput.Update(msg)
		m.inputErr = ""
		return cmd

	case stateExportFilenameInput:
		switch {
		case key == k.Confirm:
			filename := strings.TrimSpace(m.exportInput.Value())
			if filename == "" {
				m.inputErr = "Filename cannot be empty"
				return nil
			}
			path, err := writeExportFile(filename, m.plainContent())
			if err != nil {
				m.inputErr = err.Error()
				return nil
			}
			m.closeModal()
			return m.setStatus("Saved to " + path)
		case isBackKey(msg, k, true):
			m.closeModal()
			return nil
		}
		var cmd tea.Cmd
		m.exportInput, cmd = m.exportInput.Update(msg)
		m.inputErr = ""
		return cmd

	case stateLoading:
		if isBackKey(msg, k, false) {
			return m.goToInput()
		}
	}
	return nil
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
	if !m.viewportReady {
		return
	}
	var b strings.Builder
	switch m.baseState() {
	case stateViewResults:
		b.WriteString(resultHeaderStyle.Render(fmt.Sprintf("%s Results for %s%s", m.lookupType, m.domain, m.watchLabel())))
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
		header := fmt.Sprintf("Error running %s for %s%s", m.lookupType, m.domain, m.watchLabel())
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
	switch m.baseState() {
	case stateViewResults:
		return m.result
	case stateError:
		return fmt.Sprintf("Error running %s for %s%s\nError:\n%v", m.lookupType, m.domain, m.watchLabel(), m.err)
	case stateLoading:
		return "(lookup in progress)"
	}
	return "(no results)"
}

func (m tabModel) View() string {
	var b strings.Builder
	switch m.state {
	case stateInputDomain:
		b.WriteString(inputPromptStyle.Render("Enter Domain/IP:"))
		b.WriteString("\n")
		b.WriteString(lipgloss.NewStyle().Padding(0, 1).Render(m.textInput.View()))
		b.WriteString("\n")
		if m.inputErr != "" {
			b.WriteString(validationStyle.Render(m.inputErr))
		}
	case stateWatchIntervalInput, stateExportFilenameInput, stateServerInput:
		b.WriteString("\n")
	default:
		b.WriteString(m.compactHeader())
	}
	b.WriteString("\n")

	mainContentStyle := lipgloss.NewStyle().Padding(0, 1)
	switch m.state {
	case stateSelectLookup:
		b.WriteString(m.lookupList.View())
	case stateLoading:
		b.WriteString(loadingStyle.Render(m.loadingMsg))
	case stateError, stateViewResults:
		if m.viewportReady {
			b.WriteString(m.viewport.View())
		} else {
			b.WriteString(mainContentStyle.Render(errorStyle.Render(fmt.Sprintf("Error: %v", m.err))))
		}
	case stateWatchIntervalInput:
		b.WriteString(m.modal(40, colorPink, "Enter watch interval (seconds):", m.intervalInput.View(), "(Enter to start, Esc to cancel)"))
	case stateServerInput:
		b.WriteString(m.modal(50, colorLightBlue, "DNS server for this tab (empty = system default):", m.serverInput.View(), "(Enter to set, Esc to cancel)"))
	case stateExportFilenameInput:
		b.WriteString(m.modal(max(60, m.width/2), colorGreen, "Enter filename/path to export results:", m.exportInput.View(), "(Enter to save, Esc to cancel)"))
	}
	return b.String()
}

// compactHeader renders the one-line "Domain | Lookup | Server [Watching]" header.
func (m tabModel) compactHeader() string {
	watchStatus := m.watchLabel()
	if m.isWatching && m.inFlight {
		watchStatus += " ⟳"
	}
	maxDomain := max(10, m.width-25-lipgloss.Width(watchStatus))
	header := "Domain: " + truncateWidth(m.domain, maxDomain)
	if m.lookupType != "" {
		lookupStr := " | Lookup: " + m.lookupType
		if m.state == stateLoading {
			lookupStr = fmt.Sprintf(" | Running %s...", m.lookupType)
		}
		if lipgloss.Width(header+lookupStr+watchStatus) < m.width-2 {
			header += lookupStr
		}
	}
	if m.lookupOpts.Server != "" {
		serverStr := " | Server: " + m.lookupOpts.Server
		if lipgloss.Width(header+serverStr+watchStatus) < m.width-2 {
			header += serverStr
		}
	}
	header += watchStatus
	header = truncateWidth(header, max(1, m.width-4))
	return lipgloss.NewStyle().Foreground(colorLightGrey).Padding(0, 1).MaxHeight(1).Width(max(1, m.width-2)).Render(header)
}

// modal renders a centered bordered box with a prompt, an input and a hint;
// validation errors are shown on their own line, never inside the input.
func (m tabModel) modal(width int, border lipgloss.Color, prompt, input, hint string) string {
	lines := []string{prompt, input}
	if m.inputErr != "" {
		lines = append(lines, errorStyle.Render(m.inputErr))
	}
	lines = append(lines, hint)
	style := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(border).
		Padding(1, 2).Width(width)
	return lipgloss.Place(m.width, max(1, m.height-2), lipgloss.Center, lipgloss.Center, style.Render(strings.Join(lines, "\n")))
}

// startLookup starts a new lookup run for the tab's domain and lookup type,
// superseding any in-flight run.
func (m *tabModel) startLookup() tea.Cmd {
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
