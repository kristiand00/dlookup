package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"dlookup/lookup"
	"strconv"
)

var (
	lookupFlagValues = make(map[string]*string)
)

func init() {
	providers := lookup.AvailableProviders()
	sort.Slice(providers, func(i, j int) bool {
		return providers[i].FlagName() < providers[j].FlagName()
	})

	for _, p := range providers {
		flagName := p.FlagName()
		usage := p.Usage()
		lookupFlagValues[flagName] = flag.String(flagName, "", usage)
	}
}

var (
	colorPink       = lipgloss.Color("205")
	colorLightBlue  = lipgloss.Color("81")
	colorGrey       = lipgloss.Color("240")
	colorLightGrey  = lipgloss.Color("244")
	colorActiveGrey = lipgloss.Color("247")
	colorRed        = lipgloss.Color("196")
	colorOrange     = lipgloss.Color("214")
	colorGreen      = lipgloss.Color("78")
	colorHelpKey    = lipgloss.Color("81")
	colorHelpDesc   = lipgloss.Color("241")

	tabStyle = lipgloss.NewStyle().
			Foreground(colorLightGrey).
			Padding(0, 1)

	activeTabStyle = tabStyle.
			Foreground(colorPink).
			Background(colorActiveGrey).
			Bold(true)

	inputPromptStyle = lipgloss.NewStyle().Foreground(colorPink).Padding(0, 1)
	focusedStyle     = lipgloss.NewStyle().Foreground(colorPink)
	cursorStyle      = focusedStyle

	resultHeaderStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(colorLightBlue).
				Border(lipgloss.RoundedBorder()).
				BorderForeground(colorGrey).
				Padding(0, 1).
				Margin(0, 0, 1, 0)

	errorStyle   = lipgloss.NewStyle().Foreground(colorRed)
	loadingStyle = lipgloss.NewStyle().Foreground(colorOrange).Padding(1, 1)

	helpKeyStyle       = lipgloss.NewStyle().Foreground(colorHelpKey)
	helpDescStyle      = lipgloss.NewStyle().Foreground(colorHelpDesc)
	helpContainerStyle = lipgloss.NewStyle().Padding(1, 1)

	listHeaderStyle = lipgloss.NewStyle().
			Foreground(colorGreen).
			Padding(1, 0, 1, 1)

	listNormalTitle = lipgloss.NewStyle().
			Foreground(colorLightGrey).
			Padding(0, 0, 0, 1)

	listSelectedTitle = lipgloss.NewStyle().
				Foreground(colorPink).
				Border(lipgloss.NormalBorder(), false, false, false, true).
				BorderForeground(colorPink).
				Padding(0, 0, 0, 1)
)

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

type lookupResultMsg struct {
	tabId  int
	kind   string
	output string
}
type errorMsg struct {
	tabId int
	err   error
}

type tabState int

const (
	stateInputDomain tabState = iota
	stateSelectLookup
	stateLoading
	stateViewResults
	stateError
	stateWatchIntervalInput
)

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
	textInput     textinput.Model
	viewport      viewport.Model
	lookupList    list.Model
	domain        string
	lookupType    string
	result        string
	err           error
	loadingMsg    string
	width         int
	height        int
	viewportReady bool

	isWatching    bool
	watchInterval time.Duration
	intervalInput textinput.Model
	lastState     tabState
}

func newTabModel(width, height int, initialDomain string, initialLookupType string) tabModel {
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

	delegate := itemDelegate{}
	lookupList := list.New(items, delegate, width-4, 10)
	lookupList.Title = "Select Lookup Type:"
	lookupList.Styles.Title = listHeaderStyle
	lookupList.SetShowStatusBar(false)
	lookupList.SetFilteringEnabled(false)
	lookupList.SetShowHelp(false)

	vp := viewport.New(width, height-10)

	intervalInput := textinput.New()
	intervalInput.Placeholder = "Seconds (e.g., 5)"
	intervalInput.Focus()
	intervalInput.CharLimit = 5
	intervalInput.Width = 20

	m := tabModel{
		id:            nextTabID,
		textInput:     ti,
		viewport:      vp,
		lookupList:    lookupList,
		width:         width,
		height:        height,
		domain:        initialDomain,
		isWatching:    false,
		intervalInput: intervalInput,
		lastState:     stateInputDomain,
	}
	nextTabID++
	m.textInput.SetValue(initialDomain)

	if initialDomain != "" && initialLookupType != "" {
		if _, exists := lookup.GetProvider(initialLookupType); exists {
			m.state = stateLoading
			m.lookupType = initialLookupType
			m.loadingMsg = fmt.Sprintf("Running %s on %s...", m.lookupType, m.domain)
			m.textInput.Blur()
		} else {

			log.Printf("Warning: Invalid initial lookup type provided: %s", initialLookupType)
			m.state = stateInputDomain
			m.textInput.Focus()
		}
	} else {
		m.state = stateInputDomain
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
	vpHeight := height - nonViewportHeight
	if vpHeight < 1 {
		vpHeight = 1
	}

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

	if m.state == stateLoading && m.loadingMsg != "" {

	}
}

func (m tabModel) Init() tea.Cmd {
	switch m.state {
	case stateInputDomain:
		m.isWatching = false
		if m.textInput.Value() == "" {
			return textinput.Blink
		}
		return m.textInput.Focus()
	case stateLoading:

		return m.runSelectedLookup()

	default:
		return nil
	}
}

func (m tabModel) Update(msg tea.Msg, k Keybindings) (tabModel, tea.Cmd) {
	var cmds []tea.Cmd
	var cmd tea.Cmd

	isViewportActiveState := (m.state == stateViewResults || m.state == stateError)
	if m.viewportReady && isViewportActiveState {
		m.viewport, cmd = m.viewport.Update(msg)
		cmds = append(cmds, cmd)
	}

	switch msg := msg.(type) {
	case tea.KeyMsg:
		if isViewportActiveState && !m.textInput.Focused() && m.state != stateSelectLookup {
			switch msg.String() {
			case k.Back:
				m.isWatching = false
				m.state = stateInputDomain
				m.textInput.Focus()
				m.textInput.SetValue(m.domain)
				m.textInput.CursorEnd()
				cmds = append(cmds, textinput.Blink)
				m.setSize(m.width, m.height)
				return m, tea.Batch(cmds...)
			case k.WatchToggle:
				if m.lookupType != lookup.ComprehensiveReportName {
					m.lastState = m.state
					m.state = stateWatchIntervalInput
					m.intervalInput.Focus()
					m.intervalInput.CursorEnd()
					cmds = append(cmds, textinput.Blink)
					m.setSize(m.width, m.height)
					return m, tea.Batch(cmds...)
				}
			}
		}

		switch m.state {
		case stateInputDomain:
			switch msg.String() {
			case k.Confirm:
				trimmedDomain := strings.TrimSpace(m.textInput.Value())
				if trimmedDomain != "" {
					m.domain = trimmedDomain
					m.state = stateSelectLookup
					m.textInput.Blur()
					m.lookupList.ResetFilter()
					m.lookupList.Select(0)
					m.setSize(m.width, m.height)
				} else {
					m.textInput.SetValue("")
					cmd = textinput.Blink
				}
			case "ctrl+c":
				return m, tea.Quit
			default:
				m.textInput, cmd = m.textInput.Update(msg)
				cmds = append(cmds, cmd)
			}
		case stateSelectLookup:
			switch msg.String() {
			case k.Back:
				m.state = stateInputDomain
				m.isWatching = false
				m.textInput.Focus()
				m.textInput.CursorEnd()
				cmds = append(cmds, textinput.Blink)
				m.setSize(m.width, m.height)
				return m, tea.Batch(cmds...)
			}
			switch msg.Type {
			case tea.KeyEnter:
				selectedItem := m.lookupList.SelectedItem()
				if selectedItem != nil {
					m.lookupType = selectedItem.(lookupItem).FilterValue()
					m.state = stateLoading
					m.isWatching = false
					m.loadingMsg = fmt.Sprintf("Running %s on %s...", m.lookupType, m.domain)
					m.err = nil
					m.result = ""
					m.viewport.GotoTop()
					cmds = append(cmds, m.runSelectedLookup())
					m.setSize(m.width, m.height)
				}
			case tea.KeyEsc:
				m.state = stateInputDomain
				m.isWatching = false
				m.textInput.Focus()
				m.textInput.CursorEnd()
				cmds = append(cmds, textinput.Blink)
				m.setSize(m.width, m.height)
			default:
				m.lookupList, cmd = m.lookupList.Update(msg)
				cmds = append(cmds, cmd)
			}
		case stateWatchIntervalInput:
			switch msg.String() {
			case k.Confirm:
				intervalStr := m.intervalInput.Value()
				intervalSec, err := strconv.Atoi(intervalStr)
				if err == nil && intervalSec > 0 {
					m.watchInterval = time.Duration(intervalSec) * time.Second
					m.isWatching = true
					m.state = stateLoading
					m.loadingMsg = fmt.Sprintf("Watching %s on %s (every %ds)...", m.lookupType, m.domain, intervalSec)
					m.intervalInput.Blur()
					cmds = append(cmds, m.runSelectedLookup())

					m.setSize(m.width, m.height)
				} else {

					m.intervalInput.SetValue("Invalid!")
					cmd = textinput.Blink
				}
			case k.Back:
				m.state = m.lastState
				m.intervalInput.Blur()
				m.setSize(m.width, m.height)
			default:

				m.intervalInput, cmd = m.intervalInput.Update(msg)
				cmds = append(cmds, cmd)
			}
		case stateViewResults, stateError:
			break
		case stateLoading:
			if msg.String() == "ctrl+c" {
				return m, tea.Quit
			}
		}

	case time.Time:
		if m.isWatching {
			cmds = append(cmds, m.runSelectedLookup())

			cmds = append(cmds, tea.Tick(m.watchInterval, func(t time.Time) tea.Msg { return t }))
		}

	case lookupResultMsg:
		if msg.tabId == m.id {
			m.state = stateViewResults
			m.result = msg.output
			m.loadingMsg = ""
			m.err = nil
			header := resultHeaderStyle.Render(fmt.Sprintf("%s Results for %s", m.lookupType, m.domain))

			if m.isWatching {
				header += fmt.Sprintf(" [Watching: %s]", m.watchInterval)
			}
			fullContent := header + "\n" + m.result
			m.viewport.SetContent(fullContent)

			m.viewport.GotoTop()

		}
	case errorMsg:
		if msg.tabId == m.id {
			m.state = stateError
			m.err = msg.err
			m.loadingMsg = ""
			m.result = ""

			header := fmt.Sprintf("Error running %s for %s", m.lookupType, m.domain)
			if m.isWatching {
				header += fmt.Sprintf(" [Watching: %s]", m.watchInterval)
			}
			errorRendered := errorStyle.Render(fmt.Sprintf(`%s
Error:
%v`, header, m.err))
			m.viewport.SetContent(errorRendered)
			m.viewport.GotoTop()

		}
	}
	return m, tea.Batch(cmds...)
}

func (m tabModel) View() string {
	var b strings.Builder
	if m.state == stateInputDomain {
		b.WriteString(inputPromptStyle.Render("Enter Domain/IP:"))
		b.WriteString("\n")
		inputStyle := lipgloss.NewStyle().Padding(0, 1)
		b.WriteString(inputStyle.Render(m.textInput.View()))
	} else if m.state != stateWatchIntervalInput {
		domainStr := m.domain
		watchStatus := ""
		if m.isWatching {
			watchStatus = fmt.Sprintf(" [Watching: %s]", m.watchInterval)
		}

		maxHeaderContentLen := m.width - 25 - lipgloss.Width(watchStatus)
		if maxHeaderContentLen < 10 {
			maxHeaderContentLen = 10
		}

		if len(domainStr) > maxHeaderContentLen {
			domainStr = domainStr[:maxHeaderContentLen-3] + "..."
		}
		header := fmt.Sprintf("Domain: %s", domainStr)
		if m.lookupType != "" {
			lookupStr := fmt.Sprintf(" | Lookup: %s", m.lookupType)
			if m.state == stateLoading {
				lookupStr = fmt.Sprintf(" | Running %s...", m.lookupType)
			}

			if lipgloss.Width(header+lookupStr+watchStatus) < m.width-2 {
				header += lookupStr
			}
		}
		header += watchStatus

		compactHeaderStyle := lipgloss.NewStyle().
			Foreground(colorLightGrey).Padding(0, 1).MaxHeight(1).Width(m.width - 2)
		b.WriteString(compactHeaderStyle.Render(header))
	} else {

		b.WriteString("\n")
	}
	b.WriteString("\n")

	mainContentStyle := lipgloss.NewStyle().Padding(0, 1)
	switch m.state {
	case stateSelectLookup:
		b.WriteString(m.lookupList.View())
	case stateLoading:
		b.WriteString(loadingStyle.Render(m.loadingMsg))
	case stateError:
		if m.viewportReady {

			b.WriteString(m.viewport.View())
		} else {
			b.WriteString(mainContentStyle.Render(errorStyle.Render(fmt.Sprintf("Error: %v", m.err))))
		}
	case stateViewResults:
		if m.viewportReady {

			b.WriteString(m.viewport.View())
		} else {
			b.WriteString(mainContentStyle.Render("Viewport not ready..."))
		}
	case stateInputDomain:
		b.WriteString(mainContentStyle.Render(""))
	case stateWatchIntervalInput:

		modalWidth := 40
		modalHeight := 5
		modalContent := fmt.Sprintf("Enter watch interval (seconds):\n%s\n(Enter to confirm, Esc to cancel)", m.intervalInput.View())
		modalStyle := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorPink).
			Padding(1, 2).Width(modalWidth).Height(modalHeight)

		availableHeight := m.height - 2
		availableWidth := m.width

		modalView := modalStyle.Render(modalContent)
		centeredModal := lipgloss.Place(availableWidth, availableHeight, lipgloss.Center, lipgloss.Center, modalView)
		b.WriteString(centeredModal)
	}

	return b.String()
}

func (m *tabModel) runSelectedLookup() tea.Cmd {

	if m.lookupType == lookup.ComprehensiveReportName {
		return runComprehensiveLookup(m.id, m.domain)
	}

	provider, exists := lookup.GetProvider(m.lookupType)
	if !exists {
		return func() tea.Msg {
			return errorMsg{tabId: m.id, err: fmt.Errorf("internal error: unknown lookup type selected: %s", m.lookupType)}
		}
	}
	if !provider.CheckAvailability() {
		return func() tea.Msg {
			return errorMsg{tabId: m.id, err: fmt.Errorf("required command for %s not found", provider.Name())}
		}
	}
	return func() tea.Msg {
		output, err := provider.Execute(m.domain)
		if err != nil {
			return errorMsg{tabId: m.id, err: err}
		}
		return lookupResultMsg{tabId: m.id, kind: provider.Name(), output: output}
	}
}

func runComprehensiveLookup(tabId int, domain string) tea.Cmd {
	return func() tea.Msg {

		providers := lookup.AvailableProviders()
		providersToRun := make([]lookup.LookupProvider, 0, len(providers))
		for _, p := range providers {
			if p.Name() != lookup.ComprehensiveReportName {
				providersToRun = append(providersToRun, p)
			}
		}

		sort.Slice(providersToRun, func(i, j int) bool {

			return providersToRun[i].Name() < providersToRun[j].Name()
		})

		var wg sync.WaitGroup
		results := make(map[string]string)
		var resultsMutex sync.Mutex

		completedCount := 0

		for _, prov := range providersToRun {
			wg.Add(1)
			go func(p lookup.LookupProvider) {
				defer wg.Done()
				var output string
				if p.CheckAvailability() {
					var err error
					output, err = p.Execute(domain)
					if err != nil {
						output = fmt.Sprintf("Error executing %s: %v\n--- Raw Output (if any) ---\n%s", p.Name(), err, output)
					}
				} else {
					output = fmt.Sprintf("(Command for %s not available)", p.Name())
				}
				resultsMutex.Lock()
				results[p.Name()] = output
				completedCount++

				resultsMutex.Unlock()
			}(prov)
		}

		wg.Wait()

		providerOrder := lookup.GetComprehensiveReportOrder()

		finalOutput := lookup.FormatComprehensiveReport(domain, results, providerOrder)

		return lookupResultMsg{tabId: tabId, kind: lookup.ComprehensiveReportName, output: finalOutput}
	}
}

type mainModel struct {
	tabs      []tabModel
	activeTab int
	width     int
	height    int
	config    AppConfig
}

func initialMainModel(initialDomains []string, initialLookupType string, cfg AppConfig) mainModel {
	m := mainModel{
		activeTab: 0,
		width:     80,
		height:    24,
		config:    cfg,
	}

	if len(initialDomains) == 0 {
		m.tabs = []tabModel{newTabModel(m.width, m.height, "", "")}
	} else {
		m.tabs = make([]tabModel, 0, len(initialDomains))
		for _, domain := range initialDomains {
			m.tabs = append(m.tabs, newTabModel(m.width, m.height, domain, initialLookupType))
		}
	}

	if len(m.tabs) > 0 {
		m.activeTab = 0
	} else {
		m.tabs = []tabModel{newTabModel(m.width, m.height, "", "")}
		m.activeTab = 0
	}

	return m
}

func (m mainModel) Init() tea.Cmd {
	if len(m.tabs) > 0 && m.activeTab >= 0 && m.activeTab < len(m.tabs) {
		return m.tabs[m.activeTab].Init()
	}
	return nil
}

func (m mainModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		for i := range m.tabs {
			m.tabs[i].setSize(m.width, m.height)

			currentState := m.tabs[i].state
			if currentState == stateViewResults && m.tabs[i].result != "" {
				header := resultHeaderStyle.Render(fmt.Sprintf("%s Results for %s", m.tabs[i].lookupType, m.tabs[i].domain))
				fullContent := header + "\n" + m.tabs[i].result
				m.tabs[i].viewport.SetContent(fullContent)
			} else if currentState == stateError && m.tabs[i].err != nil {
				errorRendered := errorStyle.Render(fmt.Sprintf("Error:\n%v", m.tabs[i].err))
				m.tabs[i].viewport.SetContent(errorRendered)
			}
		}

	case tea.KeyMsg:
		keyHandledGlobally := false
		k := m.config.Keybindings

		// Ignore global hotkeys if text input is focused in the active tab
		if m.activeTab >= 0 && m.activeTab < len(m.tabs) && m.tabs[m.activeTab].textInput.Focused() {
			// Pass the key event to the tab's Update only
			var updatedTab tabModel
			updatedTab, cmd = m.tabs[m.activeTab].Update(msg, k)
			m.tabs[m.activeTab] = updatedTab
			cmds = append(cmds, cmd)
			return m, tea.Batch(cmds...)
		}

		switch msg.String() {
		case k.Quit:
			return m, tea.Quit
		case k.NewTab:
			newTab := newTabModel(m.width, m.height, "", "")
			m.tabs = append(m.tabs, newTab)
			if m.activeTab >= 0 && m.activeTab < len(m.tabs)-1 {
				if m.tabs[m.activeTab].textInput.Focused() {
					m.tabs[m.activeTab].textInput.Blur()
				}
			}
			m.activeTab = len(m.tabs) - 1
			cmds = append(cmds, newTab.Init())
			keyHandledGlobally = true
		case k.CloseTab:
			if len(m.tabs) > 1 {
				currentActive := m.activeTab
				m.tabs = append(m.tabs[:currentActive], m.tabs[currentActive+1:]...)
				if currentActive >= len(m.tabs) {
					m.activeTab = len(m.tabs) - 1
				} else {
					m.activeTab = currentActive
				}
				if m.activeTab >= 0 && m.activeTab < len(m.tabs) {
					cmds = append(cmds, m.tabs[m.activeTab].Init())
				}
			}
			keyHandledGlobally = true
		case k.NextTab:
			if len(m.tabs) > 1 {
				prevActiveTab := m.activeTab
				if m.tabs[prevActiveTab].textInput.Focused() {
					m.tabs[prevActiveTab].textInput.Blur()
				}
				m.activeTab = (m.activeTab + 1) % len(m.tabs)
				cmds = append(cmds, m.tabs[m.activeTab].Init())
			}
			keyHandledGlobally = true
		case k.PrevTab:
			if len(m.tabs) > 1 {
				prevActiveTab := m.activeTab
				if m.tabs[prevActiveTab].textInput.Focused() {
					m.tabs[prevActiveTab].textInput.Blur()
				}
				m.activeTab--
				if m.activeTab < 0 {
					m.activeTab = len(m.tabs) - 1
				}
				cmds = append(cmds, m.tabs[m.activeTab].Init())
			}
			keyHandledGlobally = true
		}

		if !keyHandledGlobally && m.activeTab >= 0 && m.activeTab < len(m.tabs) {
			var updatedTab tabModel
			updatedTab, cmd = m.tabs[m.activeTab].Update(msg, k)
			m.tabs[m.activeTab] = updatedTab
			cmds = append(cmds, cmd)
		}

	case lookupResultMsg, errorMsg:
		tabID := -1
		switch specificMsg := msg.(type) {
		case lookupResultMsg:
			tabID = specificMsg.tabId
		case errorMsg:
			tabID = specificMsg.tabId
		}
		if tabID != -1 {
			for i := range m.tabs {
				if m.tabs[i].id == tabID {
					var updatedTab tabModel
					updatedTab, cmd = m.tabs[i].Update(msg, m.config.Keybindings)
					m.tabs[i] = updatedTab
					cmds = append(cmds, cmd)
					break
				}
			}
		}

	default:
		if m.activeTab >= 0 && m.activeTab < len(m.tabs) {
			var updatedTab tabModel
			updatedTab, cmd = m.tabs[m.activeTab].Update(msg, m.config.Keybindings)
			m.tabs[m.activeTab] = updatedTab
			cmds = append(cmds, cmd)
		}
	}

	return m, tea.Batch(cmds...)
}

func (m mainModel) View() string {
	if m.width == 0 || m.height == 0 {
		return "Initializing..."
	}

	var tabViews []string
	numTabs := len(m.tabs)
	maxWidthPerTab := m.width / max(1, numTabs)
	maxTabNameWidth := max(10, min(25, maxWidthPerTab-2))

	for i, t := range m.tabs {
		tabName := fmt.Sprintf("Tab %d", i+1)
		dispValue := t.domain
		if dispValue == "" {
			dispValue = t.textInput.Value()
		}

		if dispValue != "" {
			if len(dispValue) > maxTabNameWidth {
				dispValue = dispValue[:maxTabNameWidth-1] + "…"
			}
			tabName = dispValue
		}

		style := tabStyle
		if i == m.activeTab {
			style = activeTabStyle
		}
		tabViews = append(tabViews, style.MaxWidth(maxTabNameWidth).Render(tabName))
	}

	tabBar := lipgloss.JoinHorizontal(lipgloss.Top, tabViews...)
	tabBar = lipgloss.NewStyle().MaxWidth(m.width).Render(tabBar)

	separator := lipgloss.NewStyle().
		Width(m.width).BorderStyle(lipgloss.NormalBorder()).BorderBottom(true).
		BorderForeground(colorGrey).Render("")

	activeTabView := "Error: No active tab found."
	if m.activeTab >= 0 && m.activeTab < len(m.tabs) {
		activeTabView = m.tabs[m.activeTab].View()
	}

	// --- Help View (Use configured keybindings) ---
	k := m.config.Keybindings // Get configured keys
	helpParts := []string{
		fmt.Sprintf("%s New", helpKeyStyle.Render(k.NewTab+":")),
		fmt.Sprintf("%s Close", helpKeyStyle.Render(k.CloseTab+":")),
		fmt.Sprintf("%s/%s Switch", helpKeyStyle.Render(k.PrevTab), helpKeyStyle.Render(k.NextTab+":")),
		fmt.Sprintf("%s Quit", helpKeyStyle.Render(k.Quit+":")),
		fmt.Sprintf("%s Interact", helpKeyStyle.Render("↑/↓/"+k.Confirm+":")),
		fmt.Sprintf("%s Back", helpKeyStyle.Render(k.Back+":")),
	}

	// Check if watch is available in the current active tab view
	if m.activeTab >= 0 && m.activeTab < len(m.tabs) {
		activeTabState := m.tabs[m.activeTab].state
		activeLookupType := m.tabs[m.activeTab].lookupType
		if (activeTabState == stateViewResults || activeTabState == stateError) &&
			activeLookupType != lookup.ComprehensiveReportName {
			helpParts = append(helpParts, fmt.Sprintf("%s Watch", helpKeyStyle.Render(k.WatchToggle+":")))
		}
	}

	helpSeparator := helpDescStyle.Render(" │ ")
	help := helpContainerStyle.Render(strings.Join(helpParts, helpSeparator))

	tabBarHeight := lipgloss.Height(tabBar)
	separatorHeight := lipgloss.Height(separator)
	helpHeight := lipgloss.Height(help)
	availableHeight := max(0, m.height-tabBarHeight-separatorHeight-helpHeight)

	tabContentContainer := lipgloss.NewStyle().Width(m.width).Height(availableHeight).Render(activeTabView)

	finalView := lipgloss.JoinVertical(lipgloss.Left, tabBar, separator, tabContentContainer, help)
	return finalView
}

func main() {
	// --- Load Configuration ---
	cfg, err := loadConfig()
	if err != nil {
		// If config loading fails critically, log and exit?
		// Or just log a warning and proceed with defaults (already handled in loadConfig)
		fmt.Fprintf(os.Stderr, "Error loading config: %v. Using defaults.\n", err)
		cfg = DefaultConfig() // Ensure we have defaults if loadConfig returned partial error
	}

	// --- Flag Parsing (flags defined in init() using lookup package) ---
	flag.Parse()

	providers := lookup.AvailableProviders()

	missingCommands := []string{}
	checkedCommands := make(map[string]bool)
	for _, p := range providers {

		baseCmd := ""
		if strings.Contains(p.FlagName(), "dig") {
			baseCmd = "dig"
		} else if strings.Contains(p.FlagName(), "nslookup") {
			baseCmd = "nslookup"
		} else if strings.Contains(p.FlagName(), "whois") {
			baseCmd = "whois"
		}

		if baseCmd != "" && !checkedCommands[baseCmd] {
			checkedCommands[baseCmd] = true
			if !p.CheckAvailability() {
				missingCommands = append(missingCommands, baseCmd)
			}
		}
	}
	if len(missingCommands) > 0 {
		sort.Strings(missingCommands)
		fmt.Fprintf(os.Stderr, "Warning: Required commands missing: %s\n", strings.Join(missingCommands, ", "))
		fmt.Fprintf(os.Stderr, "Please install them. Some lookup types may fail.\n")
	}

	initialDomains := []string{}
	selectedLookupProviderName := ""
	targetFilename := ""
	flagsSetCount := 0
	selectedFlagName := ""

	for flagName, flagValuePtr := range lookupFlagValues {
		if *flagValuePtr != "" {
			flagsSetCount++
			targetFilename = *flagValuePtr
			selectedFlagName = flagName
			if flagsSetCount > 1 {
				log.Fatal("Error: Please use only one lookup type flag (e.g., --nslookup, --dig-a) at a time.")
			}
		}
	}

	if flagsSetCount == 1 {
		provider, found := lookup.GetProviderByFlagName(selectedFlagName)
		if !found {

			log.Fatalf("Internal Error: Flag --%s was set, but no corresponding provider found.", selectedFlagName)
		}
		selectedLookupProviderName = provider.Name()

		if targetFilename == "" {

			log.Fatalf("Error: No filename provided for --%s flag.", selectedFlagName)
		}

		file, err := os.Open(targetFilename)
		if err != nil {
			log.Fatalf("Error opening file '%s': %v", targetFilename, err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			line := strings.TrimSpace(scanner.Text())

			if line != "" && !strings.HasPrefix(line, "#") {

				initialDomains = append(initialDomains, line)
			}
		}
		if err := scanner.Err(); err != nil {
			log.Fatalf("Error reading file '%s': %v", targetFilename, err)
		}
		if len(initialDomains) == 0 {
			fmt.Fprintf(os.Stderr, "Warning: File '%s' was empty or contained no valid domains/IPs.\n", targetFilename)

		}

		fmt.Printf("Attempting to run '%s' on %d domains/IPs from '%s'...\n", selectedLookupProviderName, len(initialDomains), targetFilename)
	}

	// --- Initialize and Run Bubble Tea Program ---
	// Pass domains, selected lookup provider name (if any), and loaded config
	m := initialMainModel(initialDomains, selectedLookupProviderName, cfg)
	p := tea.NewProgram(m, tea.WithMouseCellMotion())

	if _, err := p.Run(); err != nil {
		// Use log.Fatalf to print error and exit(1)
		log.Fatalf("Error running program: %v", err)
	}
}
