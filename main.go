package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"os" // Added for flag name conversion
	"sort"
	"sync" // Needed for comprehensive report goroutines
	"time"

	// Added for sorting providers
	"strings"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	// Import the new lookup package
	"dlookup/lookup"
	"strconv"
)

// --- Constants and Types (mostly unchanged) ---
var (
// lookupTypes = []string{ ... } // Removed
// commandsAvailable = make(map[string]bool) // Removed
// initialCmdCheck   sync.Once // Removed
)

// --- Helper to generate flag names from lookup types ---
// var nonAlphanumericRegex = regexp.MustCompile(`[^a-zA-Z0-9]+`) // Removed

/* // Removed unused function
func generateFlagName(lookupType string) string {
	s := strings.ToLower(lookupType)
	s = nonAlphanumericRegex.ReplaceAllString(s, "-") // Replace non-alphanumeric with hyphen
	s = strings.Trim(s, "-")                          // Trim leading/trailing hyphens
	return s
}
*/

// --- Flag Handling using lookup package ---
var (
	// Map to store flag values (filename) keyed by the *flag name*
	lookupFlagValues = make(map[string]*string)
)

func init() {
	// Initialize flags based on registered providers
	providers := lookup.AvailableProviders()
	// Sort providers by flag name for consistent help output
	sort.Slice(providers, func(i, j int) bool {
		return providers[i].FlagName() < providers[j].FlagName()
	})

	for _, p := range providers {
		flagName := p.FlagName()
		usage := p.Usage()
		// Store the pointer returned by flag.String in the map, keyed by flag name
		lookupFlagValues[flagName] = flag.String(flagName, "", usage)
	}
}

// --- Styling and Utility functions (min, max, checkCommands) remain the same ---
var (
	// colorMagenta    = lipgloss.Color("62") // Removed
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

// --- Message Types ---
type lookupResultMsg struct {
	tabId  int
	kind   string
	output string
}
type errorMsg struct {
	tabId int
	err   error
}

// --- New Message Type for Progress Updates ---
type lookupProgressMsg struct {
	tabId           int
	completedLookup string // Name of the provider that just finished
	totalLookups    int    // Total number of lookups planned
	completedCount  int    // Number of lookups completed so far
}

// --- Tab State ---
type tabState int

const (
	stateInputDomain tabState = iota
	stateSelectLookup
	stateLoading
	stateViewResults
	stateError
	stateWatchIntervalInput // New state for interval input modal
)

// --- List Item Types (lookupItem, itemDelegate) remain the same ---
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

// --- tabModel Definition remains the same ---
type tabModel struct {
	id            int
	state         tabState
	textInput     textinput.Model
	viewport      viewport.Model
	lookupList    list.Model
	domain        string
	lookupType    string // This now stores the Provider Name (e.g., "DIG (A)")
	result        string
	err           error
	loadingMsg    string
	width         int
	height        int
	viewportReady bool

	// Watch mode fields
	isWatching    bool
	watchInterval time.Duration
	intervalInput textinput.Model
	lastState     tabState // To know where to return after interval input
}

// Modified: Use lookup package for list items and init watch fields
func newTabModel(width, height int, initialDomain string, initialLookupType string) tabModel {
	ti := textinput.New()
	ti.Placeholder = "example.com or IP"
	ti.CharLimit = 256
	ti.Width = max(40, width-4)
	ti.PromptStyle = focusedStyle
	ti.TextStyle = focusedStyle
	ti.Cursor.Style = cursorStyle

	// Get providers from lookup package
	providers := lookup.AvailableProviders()
	// Sort providers by Name for display
	sort.Slice(providers, func(i, j int) bool {
		return providers[i].Name() < providers[j].Name()
	})
	items := make([]list.Item, len(providers))
	for i, p := range providers {
		items[i] = lookupItem(p.Name()) // Use provider's Name for the list
	}

	delegate := itemDelegate{}
	lookupList := list.New(items, delegate, width-4, 10) // Adjust list size later
	lookupList.Title = "Select Lookup Type:"
	lookupList.Styles.Title = listHeaderStyle
	lookupList.SetShowStatusBar(false)
	lookupList.SetFilteringEnabled(false) // Keep filtering simple for now
	lookupList.SetShowHelp(false)

	vp := viewport.New(width, height-10) // Adjust viewport size later

	// Interval Input setup
	intervalInput := textinput.New()
	intervalInput.Placeholder = "Seconds (e.g., 5)"
	intervalInput.Focus() // Focus when the modal appears
	intervalInput.CharLimit = 5
	intervalInput.Width = 20
	// Maybe add numeric validation later

	m := tabModel{
		id:         nextTabID,
		textInput:  ti,
		viewport:   vp,
		lookupList: lookupList,
		width:      width,
		height:     height,
		domain:     initialDomain,
		// Watch fields init
		isWatching:    false,
		intervalInput: intervalInput,
		lastState:     stateInputDomain, // Default initial last state
	}
	nextTabID++
	m.textInput.SetValue(initialDomain)

	// Determine initial state based on whether a lookup type (Provider Name) was provided
	if initialDomain != "" && initialLookupType != "" {
		// Validate if the initialLookupType corresponds to a known provider
		if _, exists := lookup.GetProvider(initialLookupType); exists {
			m.state = stateLoading
			m.lookupType = initialLookupType
			m.loadingMsg = fmt.Sprintf("Running %s on %s...", m.lookupType, m.domain)
			m.textInput.Blur() // Don't need focus if auto-running
		} else {
			// If the provided type is invalid, log a warning and start normally
			// TODO: Consider how to surface this warning better
			log.Printf("Warning: Invalid initial lookup type provided: %s", initialLookupType)
			m.state = stateInputDomain
			m.textInput.Focus()
		}
	} else {
		m.state = stateInputDomain // Default state
		m.textInput.Focus()        // Focus input if not auto-running
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
		inputRendered := m.textInput.View()  // Use the view to estimate height
		tabInternalHeaderHeight = lipgloss.Height(promptRendered) + lipgloss.Height(inputRendered) + 1
	} else {
		// Use a simpler calculation for compact header in other states
		tabInternalHeaderHeight = 1 + 1 // One line for header + one line padding/margin
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
	if m.state == stateLoading && m.loadingMsg != "" {
		// Recalculate loading message style if needed, though simple here
	}
}

// Modified: Handle initial stateLoading
func (m tabModel) Init() tea.Cmd {
	switch m.state {
	case stateInputDomain:
		m.isWatching = false // Ensure watching is off when entering domain input
		if m.textInput.Value() == "" {
			return textinput.Blink
		}
		return m.textInput.Focus()
	case stateLoading:
		// If starting in loading state (e.g., from flag or initial watch trigger)
		return m.runSelectedLookup()
	// No special init for watch input state, focus handled in Update transition
	default:
		return nil
	}
}

// Update and View remain largely the same, ensure they handle state transitions correctly
func (m tabModel) Update(msg tea.Msg) (tabModel, tea.Cmd) {
	var cmds []tea.Cmd
	var cmd tea.Cmd

	// Handle viewport updates only when it's visible and relevant
	isViewportActiveState := (m.state == stateViewResults || m.state == stateError)
	if m.viewportReady && isViewportActiveState {
		m.viewport, cmd = m.viewport.Update(msg)
		cmds = append(cmds, cmd)
	}

	switch msg := msg.(type) {
	case tea.KeyMsg:
		// --- Global exit or back-to-input from result/error views ---
		if isViewportActiveState && !m.textInput.Focused() && m.state != stateSelectLookup {
			switch msg.String() {
			case "esc", "q":
				m.isWatching = false // Stop watching when going back
				m.state = stateInputDomain
				m.textInput.Focus()
				m.textInput.SetValue(m.domain) // Keep domain in input
				m.textInput.CursorEnd()
				cmds = append(cmds, textinput.Blink)
				m.setSize(m.width, m.height) // Recalculate layout
				return m, tea.Batch(cmds...)
			case "w": // --- Trigger Watch Input ---
				// Allow watching only for non-comprehensive lookups
				if m.lookupType != lookup.ComprehensiveReportName {
					m.lastState = m.state // Remember if we were in results or error view
					m.state = stateWatchIntervalInput
					// Pre-fill with last interval if available
					if m.watchInterval > 0 {
						m.intervalInput.SetValue(strconv.Itoa(int(m.watchInterval.Seconds())))
					} else {
						m.intervalInput.SetValue("") // Clear if no previous interval
					}
					m.intervalInput.Focus()
					m.intervalInput.CursorEnd()
					cmds = append(cmds, textinput.Blink)
					m.setSize(m.width, m.height) // Recalculate layout for modal
					return m, tea.Batch(cmds...)
				}
			}
		}

		// --- State-Specific Key Handling ---
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
					m.isWatching = false // Ensure watch is off when starting a new lookup type
					m.loadingMsg = fmt.Sprintf("Running %s on %s...", m.lookupType, m.domain)
					m.err = nil
					m.result = ""
					m.viewport.GotoTop()
					cmds = append(cmds, m.runSelectedLookup())
					m.setSize(m.width, m.height)
				}
			case tea.KeyEsc:
				m.state = stateInputDomain
				m.isWatching = false // Ensure watch is off
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
			case "enter":
				intervalStr := m.intervalInput.Value()
				intervalSec, err := strconv.Atoi(intervalStr)
				if err == nil && intervalSec > 0 {
					m.watchInterval = time.Duration(intervalSec) * time.Second
					m.isWatching = true
					m.state = stateLoading // Go to loading for the first run
					m.loadingMsg = fmt.Sprintf("Watching %s on %s (every %ds)...", m.lookupType, m.domain, intervalSec)
					m.intervalInput.Blur()
					cmds = append(cmds, m.runSelectedLookup()) // Run first lookup
					// Start the ticker AFTER the first lookup completes (handled in TickMsg)
					m.setSize(m.width, m.height) // Recalculate layout
				} else {
					// Handle invalid input - maybe flash or just ignore for now
					m.intervalInput.SetValue("Invalid!") // Simple feedback
					cmd = textinput.Blink
				}
			case "esc":
				m.state = m.lastState // Return to results or error view
				m.intervalInput.Blur()
				m.setSize(m.width, m.height) // Recalculate layout
			default:
				// TODO: Add input validation (allow only numbers?)
				m.intervalInput, cmd = m.intervalInput.Update(msg)
				cmds = append(cmds, cmd)
			}

		case stateViewResults, stateError:
			// Key handling (esc, q, w) moved above this switch
			break // Prevent fallthrough
		case stateLoading:
			// Prevent interaction while loading (ctrl+c handled globally)
			if msg.String() == "ctrl+c" {
				return m, tea.Quit
			}
			break // Prevent fallthrough
		}
	// --- Tick Message Handling ---
	// Tick messages are sent as time.Time
	case time.Time:
		if m.isWatching {
			cmds = append(cmds, m.runSelectedLookup()) // Run the lookup again
			// Return the tick command to keep the timer going
			cmds = append(cmds, tea.Tick(m.watchInterval, func(t time.Time) tea.Msg { return t }))
		}

	// --- Other Message Handling (Results/Errors) ---
	case lookupResultMsg:
		if msg.tabId == m.id {
			m.state = stateViewResults
			m.result = msg.output
			m.loadingMsg = ""
			m.err = nil
			header := resultHeaderStyle.Render(fmt.Sprintf("%s Results for %s", m.lookupType, m.domain))
			// Add watch status to header if active
			if m.isWatching {
				header += fmt.Sprintf(" [Watching: %s]", m.watchInterval)
			}
			fullContent := header + "\n" + m.result
			m.viewport.SetContent(fullContent)
			// If watching, viewport might jump, maybe preserve position?
			// For now, always go to top on new result
			m.viewport.GotoTop()
			// If this result came from a watch tick, ensure the next tick is scheduled
			// We actually schedule the *next* tick when handling the time.Time message,
			// so no need to duplicate it here.
			// if m.isWatching { ... }
		}
	case errorMsg:
		if msg.tabId == m.id {
			m.state = stateError
			m.err = msg.err
			m.loadingMsg = ""
			m.result = ""
			// Add watch status to header if active
			header := fmt.Sprintf("Error running %s for %s", m.lookupType, m.domain)
			if m.isWatching {
				header += fmt.Sprintf(" [Watching: %s]", m.watchInterval)
			}
			errorRendered := errorStyle.Render(fmt.Sprintf(`%s
Error:
%v`, header, m.err))
			m.viewport.SetContent(errorRendered)
			m.viewport.GotoTop()
			// If this error came from a watch tick, ensure the next tick is scheduled
			// We actually schedule the *next* tick when handling the time.Time message,
			// so no need to duplicate it here.
			// if m.isWatching { ... }
		}
	}

	return m, tea.Batch(cmds...)
}

func (m tabModel) View() string {
	var b strings.Builder

	// --- Header (Modified to show watch status) ---
	if m.state == stateInputDomain {
		b.WriteString(inputPromptStyle.Render("Enter Domain/IP:"))
		b.WriteString("\n")
		inputStyle := lipgloss.NewStyle().Padding(0, 1)
		b.WriteString(inputStyle.Render(m.textInput.View()))
	} else if m.state != stateWatchIntervalInput { // Don't show standard header during interval input
		domainStr := m.domain
		watchStatus := ""
		if m.isWatching {
			watchStatus = fmt.Sprintf(" [Watching: %s]", m.watchInterval)
		}
		// Calculate available width for domain/lookup type, considering watch status
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
			// Check if adding lookup type exceeds max length
			if lipgloss.Width(header+lookupStr+watchStatus) < m.width-2 {
				header += lookupStr
			}
		}
		header += watchStatus // Add watch status at the end

		compactHeaderStyle := lipgloss.NewStyle().
			Foreground(colorLightGrey).Padding(0, 1).MaxHeight(1).Width(m.width - 2)
		b.WriteString(compactHeaderStyle.Render(header))
	} else {
		// Empty line placeholder for header during interval input
		b.WriteString("\n")
	}
	b.WriteString("\n") // Separator line

	// --- Main Content (Handle Watch Interval Input state) ---
	mainContentStyle := lipgloss.NewStyle().Padding(0, 1)
	switch m.state {
	case stateSelectLookup:
		b.WriteString(m.lookupList.View())
	case stateLoading:
		b.WriteString(loadingStyle.Render(m.loadingMsg))
	case stateError:
		if m.viewportReady {
			// Viewport content is set in Update, includes header now
			b.WriteString(m.viewport.View())
		} else {
			b.WriteString(mainContentStyle.Render(errorStyle.Render(fmt.Sprintf("Error: %v", m.err))))
		}
	case stateViewResults:
		if m.viewportReady {
			// Viewport content is set in Update, includes header now
			b.WriteString(m.viewport.View())
		} else {
			b.WriteString(mainContentStyle.Render("Viewport not ready..."))
		}
	case stateInputDomain:
		b.WriteString(mainContentStyle.Render("")) // Empty content for input state
	case stateWatchIntervalInput:
		// Render the interval input modal centered
		modalWidth := 40
		modalHeight := 5
		modalContent := fmt.Sprintf("Enter watch interval (seconds):\n%s\n(Enter to confirm, Esc to cancel)", m.intervalInput.View())
		modalStyle := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorPink).
			Padding(1, 2).Width(modalWidth).Height(modalHeight)

		// Calculate available space for centering (excluding header/separator)
		availableHeight := m.height - 2 // Subtract header and separator lines
		availableWidth := m.width

		modalView := modalStyle.Render(modalContent)
		centeredModal := lipgloss.Place(availableWidth, availableHeight, lipgloss.Center, lipgloss.Center, modalView)
		b.WriteString(centeredModal)
	}

	return b.String()
}

// Modified: Use lookup package provider and handle Comprehensive Report
func (m *tabModel) runSelectedLookup() tea.Cmd {
	// Special handling for Comprehensive Report
	if m.lookupType == lookup.ComprehensiveReportName {
		return runComprehensiveLookup(m.id, m.domain)
	}

	// --- Standard lookup for other providers ---
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

// runComprehensiveLookup returns a tea.Cmd that orchestrates all lookups
// and sends progress messages.
func runComprehensiveLookup(tabId int, domain string) tea.Cmd {
	return func() tea.Msg {
		// Fetch providers (excluding self)
		providers := lookup.AvailableProviders()
		providersToRun := make([]lookup.LookupProvider, 0, len(providers))
		for _, p := range providers {
			if p.Name() != lookup.ComprehensiveReportName {
				providersToRun = append(providersToRun, p)
			}
		}

		// Sort providers for consistent progress reporting/final output (optional but nice)
		sort.Slice(providersToRun, func(i, j int) bool {
			// Maybe use the explicit order from formatComprehensiveReport later?
			return providersToRun[i].Name() < providersToRun[j].Name()
		})

		var wg sync.WaitGroup
		results := make(map[string]string)
		var resultsMutex sync.Mutex
		// progressChan := make(chan lookupProgressMsg) // Removed for now
		// finalResultChan := make(chan lookupResultMsg) // Removed for now

		// numProviders := len(providersToRun) // Removed for now
		completedCount := 0 // Keep track of completed count internally if needed, but not used for progress msg

		/* // Removed progress listener goroutine for now
		go func() {
			for progress := range progressChan {
				// Send progress message back to the main Bubble Tea loop
				// How to do this? tea.Cmd returns a tea.Msg. It cannot directly send multiple.
				// WORKAROUND: We'll collect progress in this goroutine and format the final
				// result, sending only ONE final message.
				// TODO: Revisit this if a better pattern for multi-message commands emerges.
				// For now, we won't have live progress updates in the loading message.
			}
		}()
		*/

		// Launch goroutine for each provider
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
				completedCount++ // Increment count
				// Send progress (won't work directly as a tea.Msg)
				// progressChan <- lookupProgressMsg{ ... }
				resultsMutex.Unlock()
			}(prov)
		}

		// Wait for all lookups to complete
		wg.Wait()
		// close(progressChan) // Removed for now

		// Get the preferred order for formatting
		providerOrder := lookup.GetComprehensiveReportOrder() // Need to add this function

		// Format the final report
		finalOutput := lookup.FormatComprehensiveReport(domain, results, providerOrder)

		// Return the single final result message
		return lookupResultMsg{tabId: tabId, kind: lookup.ComprehensiveReportName, output: finalOutput}
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
				if m.tabs[m.activeTab].textInput.Focused() {
					m.tabs[m.activeTab].textInput.Blur()
				}
			}
			m.activeTab = len(m.tabs) - 1
			cmds = append(cmds, newTab.Init()) // Init focuses input
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
			if len(m.tabs) > 1 {
				prevActiveTab := m.activeTab
				if m.tabs[prevActiveTab].textInput.Focused() {
					m.tabs[prevActiveTab].textInput.Blur()
				}
				m.activeTab = (m.activeTab + 1) % len(m.tabs)
				cmds = append(cmds, m.tabs[m.activeTab].Init())
			}
			keyHandledGlobally = true
		case "ctrl+left", "ctrl+h":
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
			updatedTab, cmd = m.tabs[m.activeTab].Update(msg)
			m.tabs[m.activeTab] = updatedTab
			cmds = append(cmds, cmd)
		}

	case lookupResultMsg, errorMsg: // Forward these to the correct tab
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
	if m.width == 0 || m.height == 0 {
		return "Initializing..."
	}

	var tabViews []string
	numTabs := len(m.tabs)
	maxWidthPerTab := m.width / max(1, numTabs)
	maxTabNameWidth := max(10, min(25, maxWidthPerTab-2))

	for i, t := range m.tabs {
		tabName := fmt.Sprintf("Tab %d", i+1)
		dispValue := t.domain // Use domain primarily if set
		if dispValue == "" {
			dispValue = t.textInput.Value()
		} // Fallback to input

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

	// --- Help View (Dynamically add Watch help) ---
	helpParts := []string{
		fmt.Sprintf("%s New", helpKeyStyle.Render("Ctrl+N:")),
		fmt.Sprintf("%s Close", helpKeyStyle.Render("Ctrl+W:")),
		fmt.Sprintf("%s Switch", helpKeyStyle.Render("Ctrl+←/→:")),
		fmt.Sprintf("%s Quit", helpKeyStyle.Render("Ctrl+C:")),
		fmt.Sprintf("%s Interact", helpKeyStyle.Render("↑/↓/Enter:")),
		fmt.Sprintf("%s Back/View", helpKeyStyle.Render("Esc:")),
	}

	// Check if watch is available in the current active tab view
	if m.activeTab >= 0 && m.activeTab < len(m.tabs) {
		activeTabState := m.tabs[m.activeTab].state
		activeLookupType := m.tabs[m.activeTab].lookupType
		if (activeTabState == stateViewResults || activeTabState == stateError) &&
			activeLookupType != lookup.ComprehensiveReportName {
			helpParts = append(helpParts, fmt.Sprintf("%s Watch", helpKeyStyle.Render("W:")))
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

// --- Main Function ---
func main() {
	// --- Flag Parsing (flags defined in init() using lookup package) ---
	flag.Parse()

	// --- Initial Setup & Command Checks ---
	// Trigger command availability check (done implicitly by AvailableProviders in init, but good practice)
	providers := lookup.AvailableProviders()

	// Display warnings for unavailable commands based on providers
	missingCommands := []string{}
	checkedCommands := make(map[string]bool) // Avoid duplicate warnings for dig/nslookup/whois
	for _, p := range providers {
		// Need a way to get the underlying command (e.g., add a method to LookupProvider)
		// For now, deduce from name or flag:
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

	// --- Process Command Line Flags ---
	initialDomains := []string{}
	selectedLookupProviderName := "" // The Provider Name (e.g., "DIG (A)")
	targetFilename := ""
	flagsSetCount := 0
	selectedFlagName := ""

	// Check which lookup flag was actually used by iterating through the map defined in init()
	for flagName, flagValuePtr := range lookupFlagValues {
		if *flagValuePtr != "" {
			flagsSetCount++
			targetFilename = *flagValuePtr // Get the filename from the flag value
			selectedFlagName = flagName    // Keep track of which flag was set
			if flagsSetCount > 1 {         // Check for multiple flags immediately
				log.Fatal("Error: Please use only one lookup type flag (e.g., --nslookup, --dig-a) at a time.")
			}
		}
	}

	// If one flag was set, find the corresponding provider and read the file
	if flagsSetCount == 1 {
		provider, found := lookup.GetProviderByFlagName(selectedFlagName)
		if !found {
			// This should not happen if flags are generated correctly from providers
			log.Fatalf("Internal Error: Flag --%s was set, but no corresponding provider found.", selectedFlagName)
		}
		selectedLookupProviderName = provider.Name() // Get the user-facing name for messages

		if targetFilename == "" {
			// Should also not happen if flag was set and non-empty
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
			// Basic validation: skip empty lines and comments
			if line != "" && !strings.HasPrefix(line, "#") {
				// Could add more domain validation here if needed
				initialDomains = append(initialDomains, line)
			}
		}
		if err := scanner.Err(); err != nil {
			log.Fatalf("Error reading file '%s': %v", targetFilename, err)
		}
		if len(initialDomains) == 0 {
			fmt.Fprintf(os.Stderr, "Warning: File '%s' was empty or contained no valid domains/IPs.\n", targetFilename)
			// Proceed with TUI, tabs will likely show errors or "no results"
		}
		// Optional: Print message before starting TUI
		fmt.Printf("Attempting to run '%s' on %d domains/IPs from '%s'...\n", selectedLookupProviderName, len(initialDomains), targetFilename)
	}

	// --- Initialize and Run Bubble Tea Program ---
	// Pass domains and the selected lookup provider name (if any)
	m := initialMainModel(initialDomains, selectedLookupProviderName)
	p := tea.NewProgram(m, tea.WithAltScreen(), tea.WithMouseCellMotion())

	if _, err := p.Run(); err != nil {
		// Use log.Fatalf to print error and exit(1)
		log.Fatalf("Error running program: %v", err)
	}
}
