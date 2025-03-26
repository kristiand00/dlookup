package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"

	// "github.com/charmbracelet/bubbles/key" // Removed: Not used
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	lookupTypes = []string{
		"NSLOOKUP", "DIG (ANY)", "DIG (A)", "DIG (AAAA)", "DIG (MX)",
		"DIG (TXT)", "DIG (SOA)", "DIG (CNAME)", "WHOIS",
	}
	commandsAvailable = make(map[string]bool)
	initialCmdCheck   sync.Once
)

func checkCommands() {
	initialCmdCheck.Do(func() {
		for _, cmdName := range []string{"nslookup", "dig", "whois"} {
			_, err := exec.LookPath(cmdName)
			commandsAvailable[cmdName] = (err == nil)
		}
	})
}

var (
	colorMagenta    = lipgloss.Color("62")
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

	activeTabStyle = tabStyle.Copy().
			Foreground(colorPink).
			Background(colorActiveGrey).
			Bold(true)

	inputPromptStyle = lipgloss.NewStyle().Foreground(colorPink).Padding(0, 1)
	focusedStyle     = lipgloss.NewStyle().Foreground(colorPink)
	blurredStyle     = lipgloss.NewStyle().Foreground(colorLightGrey)
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
)

type lookupItem string

func (i lookupItem) FilterValue() string { return string(i) }
func (i lookupItem) Title() string       { return string(i) }
func (i lookupItem) Description() string { return "" }

type itemDelegate struct{}

func (d itemDelegate) Height() int                                     { return 1 }
func (d itemDelegate) Spacing() int                                    { return 0 }
func (d itemDelegate) Update(msg tea.Msg, m *list.Model) tea.Cmd       { return nil }
func (d itemDelegate) Render(w io.Writer, m list.Model, index int, listItem list.Item) {
	i, ok := listItem.(lookupItem)
	if !ok {
		return
	}
	str := string(i)
	var fn func(...string) string
	if index == m.Index() {
		fn = func(s ...string) string { return listSelectedTitle.Render("> " + strings.Join(s, " ")) }
	} else {
		fn = func(s ...string) string { return listNormalTitle.Render(" " + strings.Join(s, " ")) }
	}
	fmt.Fprint(w, fn(str))
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
}

func newTabModel(width, height int) tabModel {
	ti := textinput.New()
	ti.Placeholder = "example.com or IP"
	ti.Focus()
	ti.CharLimit = 156
	ti.Width = max(40, width-4)
	ti.PromptStyle = focusedStyle
	ti.TextStyle = focusedStyle
	ti.Cursor.Style = cursorStyle

	items := make([]list.Item, len(lookupTypes))
	for i, t := range lookupTypes {
		items[i] = lookupItem(t)
	}
	delegate := itemDelegate{}
	lookupList := list.New(items, delegate, width-4, 10)
	lookupList.Title = "Select Lookup Type:"
	lookupList.Styles.Title = listHeaderStyle
	lookupList.SetShowStatusBar(false)
	lookupList.SetFilteringEnabled(false)
	lookupList.SetShowHelp(false)

	vp := viewport.New(width, height-10)

	m := tabModel{
		id:          nextTabID,
		state:       stateInputDomain,
		textInput:   ti,
		viewport:    vp,
		lookupList:  lookupList,
		width:       width,
		height:      height,
	}
	nextTabID++
	m.setSize(width, height)
	return m
}

func (m *tabModel) setSize(width, height int) {
	m.width = width
	m.height = height

	tabBarHeight := 1
	separatorHeight := 1
	helpTextSample := fmt.Sprintf("%s %s", helpKeyStyle.Render("K:"), helpDescStyle.Render("Description"))
	helpLineCount := strings.Count(helpTextSample, "\n") + 1
	helpHeight := helpLineCount + helpContainerStyle.GetVerticalPadding()

	var tabInternalHeaderHeight int
	if m.state == stateInputDomain {
		promptRendered := inputPromptStyle.Render("Enter Domain/IP:")
		inputRendered := m.textInput.View()
		tabInternalHeaderHeight = lipgloss.Height(promptRendered) + lipgloss.Height(inputRendered) + 1
	} else {
		compactHeaderSample := fmt.Sprintf("Domain: %s | Lookup: %s", "DomainPlaceholder", "TypePlaceholder")
		compactHeaderRendered := lipgloss.NewStyle().Padding(0, 1).Render(compactHeaderSample)
		tabInternalHeaderHeight = lipgloss.Height(compactHeaderRendered) + 1
	}

	listHeight := 0
	if m.state == stateSelectLookup {
		listAvailableHeight := height - tabBarHeight - separatorHeight - tabInternalHeaderHeight - helpHeight
		listContentHeight := max(5, listAvailableHeight - 2)
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
		m.viewport = viewport.New(width, vpHeight)
		m.viewport.Style = lipgloss.NewStyle().Padding(0, 1)
		m.viewportReady = true
	} else {
		m.viewport.Width = width
		m.viewport.Height = vpHeight
	}
	m.viewport.HighPerformanceRendering = false
}

func (m tabModel) Init() tea.Cmd {
	if m.state == stateInputDomain {
		return textinput.Blink
	}
	return nil
}

func (m tabModel) Update(msg tea.Msg) (tabModel, tea.Cmd) {
	var cmds []tea.Cmd
	var cmd tea.Cmd

	isViewportActiveState := (m.state == stateViewResults || m.state == stateError)
	if m.viewportReady && isViewportActiveState {
		m.viewport, cmd = m.viewport.Update(msg)
		cmds = append(cmds, cmd)
	}

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch m.state {
		case stateInputDomain:
			switch msg.String() {
			case "enter":
				if m.textInput.Value() != "" {
					m.domain = m.textInput.Value()
					m.state = stateSelectLookup
					m.textInput.Blur()
					m.lookupList.ResetFilter()
					m.lookupList.Select(0)
					m.setSize(m.width, m.height)
				}
			default:
				m.textInput, cmd = m.textInput.Update(msg)
				cmds = append(cmds, cmd)
			}
		case stateSelectLookup:
			switch msg.Type {
			case tea.KeyEnter:
				selectedItem := m.lookupList.SelectedItem()
				if selectedItem != nil {
					m.lookupType = selectedItem.(lookupItem).FilterValue()
					m.state = stateLoading
					m.loadingMsg = fmt.Sprintf("Running %s on %s...", m.lookupType, m.domain)
					m.err = nil
					m.result = ""
					m.viewport.GotoTop()
					cmds = append(cmds, m.runSelectedLookup())
					m.setSize(m.width, m.height)
				}
			case tea.KeyEsc:
				m.state = stateInputDomain
				m.textInput.Focus()
				cmds = append(cmds, textinput.Blink)
				m.setSize(m.width, m.height)
			default:
				m.lookupList, cmd = m.lookupList.Update(msg)
				cmds = append(cmds, cmd)
			}
		case stateViewResults, stateError:
			switch msg.String() {
			case "esc", "q":
				m.state = stateInputDomain
				m.textInput.Focus()
				m.textInput.SetValue(m.domain)
				cmds = append(cmds, textinput.Blink)
				m.setSize(m.width, m.height)
			}
		case stateLoading:
			break
		}
	}

	return m, tea.Batch(cmds...)
}

func (m tabModel) View() string {
	var b strings.Builder

	if m.state == stateInputDomain {
		b.WriteString(inputPromptStyle.Render("Enter Domain/IP:"))
		b.WriteString("\n")
		b.WriteString(lipgloss.NewStyle().Padding(0, 1).Render(m.textInput.View()))
		b.WriteString("\n")
	} else {
		domainStr := m.domain
		maxDomainLen := m.width - 25
		if maxDomainLen < 5 { maxDomainLen = 5 }
		if len(domainStr) > maxDomainLen {
			domainStr = domainStr[:maxDomainLen-3] + "..."
		}

		header := fmt.Sprintf("Domain: %s", domainStr)
		if m.lookupType != "" && (m.state == stateViewResults || m.state == stateError || m.state == stateLoading) {
			if m.state == stateLoading {
				header += fmt.Sprintf(" | Running %s...", m.lookupType)
			} else {
				header += fmt.Sprintf(" | Lookup: %s", m.lookupType)
			}
		}
		compactHeaderStyle := lipgloss.NewStyle().
			Foreground(colorLightGrey).
			Padding(0, 1).
			MaxHeight(1).
			MaxWidth(m.width)
		b.WriteString(compactHeaderStyle.Render(header))
		b.WriteString("\n")
	}

	switch m.state {
	case stateSelectLookup:
		b.WriteString(m.lookupList.View())
	case stateLoading:
		b.WriteString(loadingStyle.Render(m.loadingMsg))
	case stateError:
		if m.viewportReady {
			b.WriteString(m.viewport.View())
		} else {
			b.WriteString(errorStyle.Render(fmt.Sprintf("Error: %v", m.err)))
		}
	case stateViewResults:
		if m.viewportReady {
			b.WriteString(m.viewport.View())
		} else {
			b.WriteString("Viewport not ready...")
		}
	case stateInputDomain:
		break
	}

	return b.String()
}

func (m *tabModel) runSelectedLookup() tea.Cmd {
	checkCommands()

	var cmdName string
	var args []string

	switch m.lookupType {
	case "NSLOOKUP":
		cmdName = "nslookup"
		args = []string{m.domain}
	case "WHOIS":
		cmdName = "whois"
		args = []string{m.domain}
	case "DIG (ANY)":
		cmdName = "dig"
		args = []string{m.domain, "ANY", "+noall", "+answer"}
	case "DIG (A)":
		cmdName = "dig"
		args = []string{m.domain, "A", "+short"}
	case "DIG (AAAA)":
		cmdName = "dig"
		args = []string{m.domain, "AAAA", "+short"}
	case "DIG (MX)":
		cmdName = "dig"
		args = []string{m.domain, "MX", "+short"}
	case "DIG (TXT)":
		cmdName = "dig"
		args = []string{m.domain, "TXT", "+noall", "+answer"}
	case "DIG (SOA)":
		cmdName = "dig"
		args = []string{m.domain, "SOA", "+noall", "+answer"}
	case "DIG (CNAME)":
		cmdName = "dig"
		args = []string{m.domain, "CNAME", "+short"}
	default:
		return func() tea.Msg {
			return errorMsg{tabId: m.id, err: fmt.Errorf("unknown lookup type: %s", m.lookupType)}
		}
	}

	if available, ok := commandsAvailable[cmdName]; !ok || !available {
		return func() tea.Msg {
			return errorMsg{tabId: m.id, err: fmt.Errorf("command not found: '%s'. Please install it", cmdName)}
		}
	}

	return func() tea.Msg {
		cmd := exec.Command(cmdName, args...)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		err := cmd.Run()

		output := strings.TrimSpace(stdout.String())
		errMsg := strings.TrimSpace(stderr.String())

		finalOutput := output
		if errMsg != "" {
			if output == "" {
				finalOutput = fmt.Sprintf("STDERR:\n%s", errMsg)
			} else {
				finalOutput = fmt.Sprintf("STDOUT:\n%s\n\nSTDERR:\n%s", output, errMsg)
			}
		}

		if err != nil {
			detailedErr := fmt.Errorf("command '%s %s' failed: %w", cmdName, strings.Join(args, " "), err)
			return errorMsg{tabId: m.id, err: detailedErr}
		}

		if finalOutput == "" {
			finalOutput = "(No results found)"
		}

		return lookupResultMsg{
			tabId:  m.id,
			kind:   cmdName,
			output: finalOutput,
		}
	}
}

// --- Main Model ---

type mainModel struct {
	tabs      []tabModel
	activeTab int
	width     int
	height    int
}

func initialMainModel() mainModel {
	m := mainModel{activeTab: 0, width: 80, height: 24}
	m.tabs = []tabModel{newTabModel(m.width, m.height)}
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
			if m.tabs[i].state == stateViewResults || m.tabs[i].state == stateError {
				if m.tabs[i].err != nil {
					errorRendered := errorStyle.Render(fmt.Sprintf("Error:\n%v", m.tabs[i].err))
					m.tabs[i].viewport.SetContent(errorRendered)
				} else {
					header := resultHeaderStyle.Render(fmt.Sprintf("%s Results for %s", m.tabs[i].lookupType, m.tabs[i].domain))
					fullContent := header + "\n" + m.tabs[i].result
					m.tabs[i].viewport.SetContent(fullContent)
				}
			}
		}

	case tea.KeyMsg:
		keyHandledGlobally := false
		switch msg.String() {
		case "ctrl+c":
			return m, tea.Quit
		case "ctrl+n":
			newTab := newTabModel(m.width, m.height)
			m.tabs = append(m.tabs, newTab)
			m.activeTab = len(m.tabs) - 1
			cmds = append(cmds, newTab.Init())
			keyHandledGlobally = true
		case "ctrl+w":
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
		case "ctrl+right", "ctrl+l":
			if len(m.tabs) > 0 {
				prevActiveTab := m.activeTab
				m.activeTab = (m.activeTab + 1) % len(m.tabs)
				if prevActiveTab != m.activeTab && prevActiveTab < len(m.tabs) {
					if m.tabs[prevActiveTab].textInput.Focused() {
						m.tabs[prevActiveTab].textInput.Blur()
					}
					cmds = append(cmds, m.tabs[m.activeTab].Init())
				}
			}
			keyHandledGlobally = true
		case "ctrl+left", "ctrl+h":
			if len(m.tabs) > 0 {
				prevActiveTab := m.activeTab
				m.activeTab--
				if m.activeTab < 0 {
					m.activeTab = len(m.tabs) - 1
				}
				if prevActiveTab != m.activeTab && prevActiveTab < len(m.tabs) {
					if m.tabs[prevActiveTab].textInput.Focused() {
						m.tabs[prevActiveTab].textInput.Blur()
					}
					cmds = append(cmds, m.tabs[m.activeTab].Init())
				}
			}
			keyHandledGlobally = true
		}

		if !keyHandledGlobally {
			isInputFocused := false
			if m.activeTab >= 0 && m.activeTab < len(m.tabs) {
				isInputFocused = m.tabs[m.activeTab].textInput.Focused()
			}

			if !isInputFocused {
				switch msg.Type {
				case tea.KeyRight:
					if len(m.tabs) > 0 {
						prevActiveTab := m.activeTab
						m.activeTab = (m.activeTab + 1) % len(m.tabs)
						if prevActiveTab != m.activeTab {
							cmds = append(cmds, m.tabs[m.activeTab].Init())
						}
						keyHandledGlobally = true
					}
				case tea.KeyLeft:
					if len(m.tabs) > 0 {
						prevActiveTab := m.activeTab
						m.activeTab--
						if m.activeTab < 0 {
							m.activeTab = len(m.tabs) - 1
						}
						if prevActiveTab != m.activeTab {
							cmds = append(cmds, m.tabs[m.activeTab].Init())
						}
						keyHandledGlobally = true
					}
				}
			}
		}

		if !keyHandledGlobally {
			if m.activeTab >= 0 && m.activeTab < len(m.tabs) {
				var updatedTab tabModel
				updatedTab, cmd = m.tabs[m.activeTab].Update(msg)
				m.tabs[m.activeTab] = updatedTab
				cmds = append(cmds, cmd)
			}
		}

	case lookupResultMsg:
		for i := range m.tabs {
			if m.tabs[i].id == msg.tabId {
				m.tabs[i].state = stateViewResults
				m.tabs[i].result = msg.output
				m.tabs[i].loadingMsg = ""
				m.tabs[i].err = nil
				m.tabs[i].setSize(m.width, m.height)
				header := resultHeaderStyle.Render(fmt.Sprintf("%s Results for %s", m.tabs[i].lookupType, m.tabs[i].domain))
				fullContent := header + "\n" + m.tabs[i].result
				m.tabs[i].viewport.SetContent(fullContent)
				m.tabs[i].viewport.GotoTop()
				break
			}
		}
	case errorMsg:
		for i := range m.tabs {
			if m.tabs[i].id == msg.tabId {
				m.tabs[i].state = stateError
				m.tabs[i].err = msg.err
				m.tabs[i].loadingMsg = ""
				m.tabs[i].result = ""
				m.tabs[i].setSize(m.width, m.height)
				errorRendered := errorStyle.Render(fmt.Sprintf("Error:\n%v", m.tabs[i].err))
				m.tabs[i].viewport.SetContent(errorRendered)
				m.tabs[i].viewport.GotoTop()
				break
			}
		}

	default:
		if m.activeTab >= 0 && m.activeTab < len(m.tabs) {
			var updatedTab tabModel
			updatedTab, cmd = m.tabs[m.activeTab].Update(msg)
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
	maxTabNameWidth := max(8, m.width/max(1, len(m.tabs))-2)

	for i, t := range m.tabs {
		tabName := fmt.Sprintf("Tab %d", i+1)
		if t.domain != "" {
			dispDomain := t.domain
			if len(dispDomain) > maxTabNameWidth {
				dispDomain = dispDomain[:maxTabNameWidth-3] + "..."
			}
			tabName = dispDomain
		}

		style := tabStyle
		if i == m.activeTab {
			style = activeTabStyle
		}
		tabViews = append(tabViews, style.Render(tabName))
	}

	tabBar := lipgloss.JoinHorizontal(lipgloss.Top, tabViews...)
	tabBar = lipgloss.NewStyle().MaxWidth(m.width).Render(tabBar)

	separator := lipgloss.NewStyle().
		Width(m.width).
		BorderStyle(lipgloss.NormalBorder()).
		BorderBottom(true).
		BorderForeground(colorGrey).
		Render("")

	activeTabView := "No active tabs. Press Ctrl+N to create one."
	if m.activeTab >= 0 && m.activeTab < len(m.tabs) {
		activeTabView = m.tabs[m.activeTab].View()
	}

	helpParts := []string{
		fmt.Sprintf("%s %s", helpKeyStyle.Render("Ctrl+N:"), helpDescStyle.Render("New")),
		fmt.Sprintf("%s %s", helpKeyStyle.Render("Ctrl+W:"), helpDescStyle.Render("Close")),
		fmt.Sprintf("%s %s", helpKeyStyle.Render("←/→/Ctrl:"), helpDescStyle.Render("Switch")),
		fmt.Sprintf("%s %s", helpKeyStyle.Render("Ctrl+C:"), helpDescStyle.Render("Quit")),
		fmt.Sprintf("%s %s", helpKeyStyle.Render("↑/↓/Enter:"), helpDescStyle.Render("Interact")),
		fmt.Sprintf("%s %s", helpKeyStyle.Render("Esc:"), helpDescStyle.Render("Back")),
	}
	help := helpContainerStyle.Render(strings.Join(helpParts, helpDescStyle.Render(" | ")))

	tabBarHeight := lipgloss.Height(tabBar)
	separatorHeight := lipgloss.Height(separator)
	helpHeight := lipgloss.Height(help)
	availableHeight := m.height - tabBarHeight - separatorHeight - helpHeight
	if availableHeight < 0 {
		availableHeight = 0
	}

	tabContentContainer := lipgloss.NewStyle().
		Width(m.width).
		Height(availableHeight).
		Render(activeTabView)

	finalView := lipgloss.JoinVertical(lipgloss.Left,
		tabBar,
		separator,
		tabContentContainer,
		help,
	)

	return finalView
}

// --- Main Function ---

func main() {
	checkCommands()
	missing := []string{}
	for cmd, found := range commandsAvailable {
		if !found {
			missing = append(missing, cmd)
		}
	}
	if len(missing) > 0 {
		fmt.Fprintf(os.Stderr, "Warning: Required commands missing: %s\n", strings.Join(missing, ", "))
		fmt.Fprintln(os.Stderr, "Please install them (e.g., 'sudo apt install dnsutils whois' or 'sudo yum install bind-utils whois')")
	}

	p := tea.NewProgram(
		initialMainModel(),
		tea.WithAltScreen(),
		tea.WithMouseCellMotion(),
	)

	if _, err := p.Run(); err != nil {
		log.Fatalf("Error running program: %v", err)
	}
}