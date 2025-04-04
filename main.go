package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"regexp" // Added for flag name conversion
	"strings"
	"sync"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// --- Constants and Types (mostly unchanged) ---
var (
	lookupTypes = []string{
		"NSLOOKUP", "DIG (ANY)", "DIG (A)", "DIG (AAAA)", "DIG (MX)",
		"DIG (TXT)", "DIG (SOA)", "DIG (CNAME)", "WHOIS",
	}
	commandsAvailable = make(map[string]bool)
	initialCmdCheck   sync.Once
)

// --- Helper to generate flag names from lookup types ---
var nonAlphanumericRegex = regexp.MustCompile(`[^a-zA-Z0-9]+`)

func generateFlagName(lookupType string) string {
	s := strings.ToLower(lookupType)
	s = nonAlphanumericRegex.ReplaceAllString(s, "-") // Replace non-alphanumeric with hyphen
	s = strings.Trim(s, "-")                          // Trim leading/trailing hyphens
	return s
}

// Map to store flag values and relate them back to lookup types
var lookupFlags = make(map[string]*string) // Map flag name -> pointer to flag value string
var flagToLookupType = make(map[string]string) // Map flag name -> original lookup type string

func init() {
	// Initialize flags based on lookupTypes
	for _, lt := range lookupTypes {
		flagName := generateFlagName(lt)
		if flagName != "" {
			usage := fmt.Sprintf("Run %s lookup on domains from <filename>", lt)
			// Store the pointer returned by flag.String in the map
			lookupFlags[flagName] = flag.String(flagName, "", usage)
			flagToLookupType[flagName] = lt
		}
	}
}

// --- Styling and Utility functions (min, max, checkCommands) remain the same ---
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
func checkCommands() {
	initialCmdCheck.Do(func() {
		for _, cmdName := range []string{"nslookup", "dig", "whois"} {
			_, err := exec.LookPath(cmdName)
			commandsAvailable[cmdName] = (err == nil)
		}
	})
}
func min(a, b int) int { if a < b { return a }; return b }
func max(a, b int) int { if a > b { return a }; return b }
// --- Message Types ---
type lookupResultMsg struct { tabId int; kind string; output string }
type errorMsg struct { tabId int; err error }

// --- Tab State ---
type tabState int
const (
	stateInputDomain tabState = iota
	stateSelectLookup
	stateLoading
	stateViewResults
	stateError
)

// --- List Item Types (lookupItem, itemDelegate) remain the same ---
type lookupItem string
func (i lookupItem) FilterValue() string { return string(i) }
func (i lookupItem) Title() string       { return string(i) }
func (i lookupItem) Description() string { return "" }
type itemDelegate struct{}
func (d itemDelegate) Height() int { return 1 }
func (d itemDelegate) Spacing() int { return 0 }
func (d itemDelegate) Update(msg tea.Msg, m *list.Model) tea.Cmd { return nil }
func (d itemDelegate) Render(w io.Writer, m list.Model, index int, listItem list.Item) {
	i, ok := listItem.(lookupItem)
	if !ok { return }
	str := string(i)
	fn := listNormalTitle.Render
	if index == m.Index() { fn = listSelectedTitle.Render }
	fmt.Fprint(w, fn(" "+str))
	if index == m.Index() { fmt.Fprint(w, listSelectedTitle.Render("> "))}
}


var nextTabID = 0

// --- tabModel Definition remains the same ---
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

// Modified: Added initialLookupType parameter and logic for auto-run
func newTabModel(width, height int, initialDomain string, initialLookupType string) tabModel {
	ti := textinput.New()
	ti.Placeholder = "example.com or IP"
	// Don't focus initially if we auto-run
	ti.CharLimit = 256
	ti.Width = max(40, width-4)
	ti.PromptStyle = focusedStyle
	ti.TextStyle = focusedStyle
	ti.Cursor.Style = cursorStyle

	items := make([]list.Item, len(lookupTypes))
	for i, t := range lookupTypes {
		items[i] = lookupItem(t)
	}
	delegate := itemDelegate{}
	lookupList := list.New(items, delegate, width-4, 10) // Adjust list size later in setSize
	lookupList.Title = "Select Lookup Type:"
	lookupList.Styles.Title = listHeaderStyle
	lookupList.SetShowStatusBar(false)
	lookupList.SetFilteringEnabled(false)
	lookupList.SetShowHelp(false)

	vp := viewport.New(width, height-10) // Adjust viewport size later

	m := tabModel{
		id:         nextTabID,
		// state determined below
		textInput:  ti,
		viewport:   vp,
		lookupList: lookupList,
		width:      width,
		height:     height,
		domain:     initialDomain, // Set domain regardless
	}
	nextTabID++
	m.textInput.SetValue(initialDomain) // Also set input value

	// Determine initial state based on whether a lookup type was provided
	if initialDomain != "" && initialLookupType != "" {
		m.state = stateLoading
		m.lookupType = initialLookupType
		m.loadingMsg = fmt.Sprintf("Running %s on %s...", m.lookupType, m.domain)
		m.textInput.Blur() // Don't need focus if auto-running
	} else {
		m.state = stateInputDomain // Default state
		m.textInput.Focus()       // Focus input if not auto-running
	}

	m.setSize(width, height) // Call setSize after setting initial state/values
	return m
}

// setSize remains largely the same, ensure it handles all states correctly
func (m *tabModel) setSize(width, height int) {
	m.width = width
	m.height = height

	tabBarHeight := 1
	separatorHeight := 1
	helpHeight := 3

	var tabInternalHeaderHeight int
	// Calculate header height based on state *after* potential initialization
	if m.state == stateInputDomain {
		promptRendered := inputPromptStyle.Render("Enter Domain/IP:")
		// Need to calculate potential input height even if value is empty initially
		m.textInput.Width = max(40, width-4) // Ensure width is set before measuring
		inputRendered := m.textInput.View() // Use the view to estimate height
		tabInternalHeaderHeight = lipgloss.Height(promptRendered) + lipgloss.Height(inputRendered) + 1
	} else {
		// Use a simpler calculation for compact header in other states
		tabInternalHeaderHeight = 1 + 1 // One line for header + one line padding/margin
	}

	listHeight := 0
	if m.state == stateSelectLookup {
		listAvailableHeight := height - tabBarHeight - separatorHeight - tabInternalHeaderHeight - helpHeight
		listContentHeight := max(5, listAvailableHeight - listHeaderStyle.GetVerticalPadding())
		m.lookupList.SetSize(width-2, listContentHeight)
		listHeight = m.lookupList.Height()
	}

	nonViewportHeight := tabBarHeight + separatorHeight + tabInternalHeaderHeight + listHeight + helpHeight
	vpHeight := height - nonViewportHeight
	if vpHeight < 1 { vpHeight = 1 }

	m.textInput.Width = max(40, width-4) // Ensure width is always updated

	if !m.viewportReady {
		m.viewport = viewport.New(width-2, vpHeight) // Use width-2 for padding
		m.viewport.Style = lipgloss.NewStyle().Padding(0, 1)
		m.viewportReady = true
	} else {
		m.viewport.Width = width - 2 // Use width-2 for padding
		m.viewport.Height = vpHeight
	}
	m.viewport.HighPerformanceRendering = false // Maybe disable for TTYs

	// If loading, ensure loading message is styled (though it's short here)
	if m.state == stateLoading && m.loadingMsg != ""{
		// Recalculate loading message style if needed, though simple here
	}
}


// Modified: Handle initial stateLoading
func (m tabModel) Init() tea.Cmd {
	switch m.state {
	case stateInputDomain:
		if m.textInput.Value() == "" {
			return textinput.Blink // Blink only if input is empty
		}
		return m.textInput.Focus() // Ensure focus if input has value
	case stateLoading:
		// If starting in loading state, immediately run the command
		return m.runSelectedLookup()
	default:
		return nil
	}
}

// Update and View remain largely the same, ensure they handle state transitions correctly
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
		if isViewportActiveState && !m.textInput.Focused() && m.state != stateSelectLookup {
			switch msg.String() {
			case "esc", "q":
				m.state = stateInputDomain
				m.textInput.Focus()
				m.textInput.SetValue(m.domain)
				m.textInput.CursorEnd()
				cmds = append(cmds, textinput.Blink)
				m.setSize(m.width, m.height)
				return m, tea.Batch(cmds...)
			}
		}

		switch m.state {
		case stateInputDomain:
			switch msg.String() {
			case "enter":
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
				m.textInput.CursorEnd()
				cmds = append(cmds, textinput.Blink)
				m.setSize(m.width, m.height)
			default:
				m.lookupList, cmd = m.lookupList.Update(msg)
				cmds = append(cmds, cmd)
			}
		case stateViewResults, stateError:
			break
		case stateLoading:
			// Prevent interaction while loading (e.g., ctrl+c handled globally)
			if msg.String() == "ctrl+c" { return m, tea.Quit }
			break
		}
	case lookupResultMsg:
		if msg.tabId == m.id {
			m.state = stateViewResults
			m.result = msg.output
			m.loadingMsg = ""
			m.err = nil
			header := resultHeaderStyle.Render(fmt.Sprintf("%s Results for %s", m.lookupType, m.domain))
			fullContent := header + "\n" + m.result
			m.viewport.SetContent(fullContent)
			m.viewport.GotoTop()
			// No need to call setSize here unless content significantly changes layout needs
		}
	case errorMsg:
		if msg.tabId == m.id {
			m.state = stateError
			m.err = msg.err
			m.loadingMsg = ""
			m.result = ""
			errorRendered := errorStyle.Render(fmt.Sprintf("Error:\n%v", m.err))
			m.viewport.SetContent(errorRendered)
			m.viewport.GotoTop()
			// No need to call setSize here
		}
	}

	return m, tea.Batch(cmds...)
}

func (m tabModel) View() string {
	var b strings.Builder

	// --- Header ---
	if m.state == stateInputDomain {
		b.WriteString(inputPromptStyle.Render("Enter Domain/IP:"))
		b.WriteString("\n")
		inputStyle := lipgloss.NewStyle().Padding(0, 1)
		b.WriteString(inputStyle.Render(m.textInput.View()))
	} else {
		domainStr := m.domain
		maxDomainLen := m.width - 25
		if maxDomainLen < 5 { maxDomainLen = 5 }
		if len(domainStr) > maxDomainLen {
			domainStr = domainStr[:maxDomainLen-3] + "..."
		}
		header := fmt.Sprintf("Domain: %s", domainStr)
		if m.lookupType != "" { // Show lookup type in all non-input states
			if m.state == stateLoading {
				header += fmt.Sprintf(" | Running %s...", m.lookupType)
			} else {
				header += fmt.Sprintf(" | Lookup: %s", m.lookupType)
			}
		}
		compactHeaderStyle := lipgloss.NewStyle().
			Foreground(colorLightGrey).Padding(0, 1).MaxHeight(1).Width(m.width - 2)
		b.WriteString(compactHeaderStyle.Render(header))
	}
	b.WriteString("\n") // Separator line

	// --- Main Content ---
	mainContentStyle := lipgloss.NewStyle().Padding(0, 1)
	switch m.state {
	case stateSelectLookup:
		b.WriteString(m.lookupList.View())
	case stateLoading:
		b.WriteString(loadingStyle.Render(m.loadingMsg)) // Use specific loading style
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
		b.WriteString(mainContentStyle.Render("")) // Empty content for input state
	}

	return b.String()
}

// runSelectedLookup remains the same
func (m *tabModel) runSelectedLookup() tea.Cmd {
	checkCommands()
	var cmdName string
	var args []string
	switch m.lookupType {
	case "NSLOOKUP":    cmdName, args = "nslookup", []string{m.domain}
	case "WHOIS":       cmdName, args = "whois", []string{m.domain}
	case "DIG (ANY)":   cmdName, args = "dig", []string{m.domain, "ANY", "+noall", "+answer"}
	case "DIG (A)":     cmdName, args = "dig", []string{m.domain, "A", "+short"}
	case "DIG (AAAA)":  cmdName, args = "dig", []string{m.domain, "AAAA", "+short"}
	case "DIG (MX)":    cmdName, args = "dig", []string{m.domain, "MX", "+short"}
	case "DIG (TXT)":   cmdName, args = "dig", []string{m.domain, "TXT", "+noall", "+answer"}
	case "DIG (SOA)":   cmdName, args = "dig", []string{m.domain, "SOA", "+noall", "+answer"}
	case "DIG (CNAME)": cmdName, args = "dig", []string{m.domain, "CNAME", "+short"}
	default:
		return func() tea.Msg { return errorMsg{tabId: m.id, err: fmt.Errorf("unknown lookup type: %s", m.lookupType)} }
	}
	if available, ok := commandsAvailable[cmdName]; !ok || !available {
		return func() tea.Msg { return errorMsg{tabId: m.id, err: fmt.Errorf("command not found: '%s'", cmdName)} }
	}
	return func() tea.Msg {
		cmd := exec.Command(cmdName, args...)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		output, errMsg := strings.TrimSpace(stdout.String()), strings.TrimSpace(stderr.String())
		finalOutput := output
		if errMsg != "" {
			if output != "" { finalOutput = fmt.Sprintf("STDERR:\n%s\n\nSTDOUT:\n%s", errMsg, output) } else { finalOutput = fmt.Sprintf("STDERR:\n%s", errMsg) }
		}
		if err != nil {
			detail := fmt.Errorf("command '%s %s' failed: %w", cmdName, strings.Join(args, " "), err)
			if errMsg != "" { detail = fmt.Errorf("%w\nSTDERR was:\n%s", detail, errMsg) }
			return errorMsg{tabId: m.id, err: detail}
		}
		if finalOutput == "" { finalOutput = "(No results found)" }
		return lookupResultMsg{tabId: m.id, kind: cmdName, output: finalOutput}
	}
}

// --- Main Model ---
type mainModel struct {
	tabs      []tabModel
	activeTab int
	width     int
	height    int
}

// Modified: Accept initial lookup type
func initialMainModel(initialDomains []string, initialLookupType string) mainModel {
	m := mainModel{activeTab: 0, width: 80, height: 24} // Default size

	if len(initialDomains) == 0 {
		// No domains from file, create one empty default tab, no lookup type
		m.tabs = []tabModel{newTabModel(m.width, m.height, "", "")}
	} else {
		// Create tabs from the file domains with the specified lookup type
		m.tabs = make([]tabModel, 0, len(initialDomains))
		for _, domain := range initialDomains {
			// Pass the domain AND the lookup type
			m.tabs = append(m.tabs, newTabModel(m.width, m.height, domain, initialLookupType))
		}
	}

	if len(m.tabs) > 0 {
		m.activeTab = 0
	} else { // Should not happen with above logic, but defensively...
		m.tabs = []tabModel{newTabModel(m.width, m.height, "", "")}
		m.activeTab = 0
	}

	return m
}


// Init: Initialize the first tab
func (m mainModel) Init() tea.Cmd {
	if len(m.tabs) > 0 && m.activeTab >= 0 && m.activeTab < len(m.tabs) {
		return m.tabs[m.activeTab].Init() // This will now trigger auto-run if needed
	}
	return nil
}

// Update: Handles global keys, forwards others to active tab
func (m mainModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
    var cmds []tea.Cmd
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		for i := range m.tabs {
			m.tabs[i].setSize(m.width, m.height)
			// Re-set content for tabs in view/error state after resize
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
		switch msg.String() {
		case "ctrl+c":
			return m, tea.Quit
		case "ctrl+n":
			// Create new empty tab with no auto-run lookup type
			newTab := newTabModel(m.width, m.height, "", "")
			m.tabs = append(m.tabs, newTab)
			if m.activeTab >= 0 && m.activeTab < len(m.tabs)-1 {
				if m.tabs[m.activeTab].textInput.Focused() { m.tabs[m.activeTab].textInput.Blur() }
			}
			m.activeTab = len(m.tabs) - 1
			cmds = append(cmds, newTab.Init()) // Init focuses input
			keyHandledGlobally = true
		case "ctrl+w":
			if len(m.tabs) > 1 {
				currentActive := m.activeTab
				m.tabs = append(m.tabs[:currentActive], m.tabs[currentActive+1:]...)
				if currentActive >= len(m.tabs) { m.activeTab = len(m.tabs) - 1 } else { m.activeTab = currentActive }
				if m.activeTab >= 0 && m.activeTab < len(m.tabs) { cmds = append(cmds, m.tabs[m.activeTab].Init()) }
			}
			keyHandledGlobally = true
		case "ctrl+right", "ctrl+l":
			if len(m.tabs) > 1 {
				prevActiveTab := m.activeTab
				if m.tabs[prevActiveTab].textInput.Focused() { m.tabs[prevActiveTab].textInput.Blur() }
				m.activeTab = (m.activeTab + 1) % len(m.tabs)
				cmds = append(cmds, m.tabs[m.activeTab].Init())
			}
			keyHandledGlobally = true
		case "ctrl+left", "ctrl+h":
			if len(m.tabs) > 1 {
				prevActiveTab := m.activeTab
				if m.tabs[prevActiveTab].textInput.Focused() { m.tabs[prevActiveTab].textInput.Blur() }
				m.activeTab--
				if m.activeTab < 0 { m.activeTab = len(m.tabs) - 1 }
				cmds = append(cmds, m.tabs[m.activeTab].Init())
			}
			keyHandledGlobally = true
		}

		if !keyHandledGlobally && m.activeTab >= 0 && m.activeTab < len(m.tabs) {
			var updatedTab tabModel
			updatedTab, cmd = m.tabs[m.activeTab].Update(msg)
			m.tabs[m.activeTab] = updatedTab
			cmds = append(cmds, cmd)
		}

	case lookupResultMsg, errorMsg: // Forward these to the correct tab
		tabID := -1
		switch specificMsg := msg.(type) {
		case lookupResultMsg: tabID = specificMsg.tabId
		case errorMsg: tabID = specificMsg.tabId
		}
		if tabID != -1 {
			for i := range m.tabs {
				if m.tabs[i].id == tabID {
					var updatedTab tabModel
					updatedTab, cmd = m.tabs[i].Update(msg)
					m.tabs[i] = updatedTab
					cmds = append(cmds, cmd)
					break
				}
			}
		}


	default: // Forward other messages (like ticks)
		if m.activeTab >= 0 && m.activeTab < len(m.tabs) {
			var updatedTab tabModel
			updatedTab, cmd = m.tabs[m.activeTab].Update(msg)
			m.tabs[m.activeTab] = updatedTab
			cmds = append(cmds, cmd)
		}
	}

	return m, tea.Batch(cmds...)
}

// View: Renders tabs, active tab content, help
func (m mainModel) View() string {
    if m.width == 0 || m.height == 0 { return "Initializing..." }

	var tabViews []string
	numTabs := len(m.tabs)
	maxWidthPerTab := m.width / max(1, numTabs)
	maxTabNameWidth := max(10, min(25, maxWidthPerTab - 2))

	for i, t := range m.tabs {
		tabName := fmt.Sprintf("Tab %d", i+1)
		dispValue := t.domain // Use domain primarily if set
		if dispValue == "" { dispValue = t.textInput.Value() } // Fallback to input

		if dispValue != "" {
			if len(dispValue) > maxTabNameWidth { dispValue = dispValue[:maxTabNameWidth-1] + "…" }
			tabName = dispValue
		}

		style := tabStyle
		if i == m.activeTab { style = activeTabStyle }
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

	helpParts := []string{
		fmt.Sprintf("%s New", helpKeyStyle.Render("Ctrl+N:")),
		fmt.Sprintf("%s Close", helpKeyStyle.Render("Ctrl+W:")),
		fmt.Sprintf("%s Switch", helpKeyStyle.Render("Ctrl+←/→:")),
		fmt.Sprintf("%s Quit", helpKeyStyle.Render("Ctrl+C:")),
		fmt.Sprintf("%s Interact", helpKeyStyle.Render("↑/↓/Enter:")),
		fmt.Sprintf("%s Back/View", helpKeyStyle.Render("Esc:")),
	}
	helpSeparator := helpDescStyle.Render(" │ ")
	help := helpContainerStyle.Render(strings.Join(helpParts, helpSeparator))

	tabBarHeight := lipgloss.Height(tabBar)
	separatorHeight := lipgloss.Height(separator)
	helpHeight := lipgloss.Height(help)
	availableHeight := max(0, m.height - tabBarHeight - separatorHeight - helpHeight)

	tabContentContainer := lipgloss.NewStyle().Width(m.width).Height(availableHeight).Render(activeTabView)

	finalView := lipgloss.JoinVertical(lipgloss.Left, tabBar, separator, tabContentContainer, help)
	return finalView
}

// --- Main Function ---
func main() {
	// --- Flag Parsing (flags defined in init()) ---
	flag.Parse()

	// --- Initial Setup ---
	checkCommands() // Check for nslookup, dig, whois

	// Display warnings for missing commands
	missing := []string{}
	for cmd, found := range commandsAvailable { if !found { missing = append(missing, cmd) } }
	if len(missing) > 0 {
		fmt.Fprintf(os.Stderr, "Warning: Required commands missing: %s\n", strings.Join(missing, ", "))
		fmt.Fprintf(os.Stderr, "Please install them. Some lookup types may fail.\n")
	}

	// --- Process Command Line Flags ---
	initialDomains := []string{}
	selectedLookupType := "" // The internal lookup type string (e.g., "DIG (A)")
	targetFilename := ""
	flagsSetCount := 0

	// Check which lookup flag was actually used
	for flagName, flagValuePtr := range lookupFlags {
		if *flagValuePtr != "" {
			flagsSetCount++
			targetFilename = *flagValuePtr // Get the filename
			selectedLookupType = flagToLookupType[flagName] // Get the corresponding lookup type
		}
	}

	// Enforce using only one lookup flag
	if flagsSetCount > 1 {
		log.Fatal("Error: Please use only one lookup type flag (e.g., --nslookup, --dig-a) at a time.")
	}

	// If one flag was set, read the file
	if flagsSetCount == 1 {
		if targetFilename == "" {
			log.Fatalf("Error: No filename provided for --%s flag.", generateFlagName(selectedLookupType)) // Should not happen if flag was set, but check defensively
		}
		file, err := os.Open(targetFilename)
		if err != nil {
			log.Fatalf("Error opening file '%s': %v", targetFilename, err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				initialDomains = append(initialDomains, line)
			}
		}
		if err := scanner.Err(); err != nil {
			log.Fatalf("Error reading file '%s': %v", targetFilename, err)
		}
		if len(initialDomains) == 0 {
			fmt.Fprintf(os.Stderr, "Warning: File '%s' was empty or contained no valid domains.\n", targetFilename)
            // Proceed with TUI showing empty tabs that ran the lookup (likely failing)
		}
        fmt.Printf("Attempting to run '%s' on %d domains from '%s'...\n", selectedLookupType, len(initialDomains), targetFilename)
	}

	// --- Initialize and Run Bubble Tea Program ---
	// Pass domains and the selected lookup type (if any)
	m := initialMainModel(initialDomains, selectedLookupType)
	p := tea.NewProgram(m, tea.WithAltScreen(), tea.WithMouseCellMotion())

	if _, err := p.Run(); err != nil {
		log.Fatalf("Error running program: %v", err)
	}
}