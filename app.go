package main

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"dlookup/lookup"
)

type mainModel struct {
	tabs        []tabModel
	activeTab   int
	width       int
	height      int
	config      AppConfig
	defaultOpts lookup.Options // options for new tabs (e.g. --server)
	status      string         // app-level status line (e.g. export all); cleared on next key
}

// newMainModel builds the main model. One tab is created per initial domain (or a
// single empty tab); every tab, including ones opened later, starts with opts.
// All initial lookups are started by Init.
func newMainModel(initialDomains []string, initialLookupType string, cfg AppConfig, opts lookup.Options) mainModel {
	m := mainModel{
		width:       80,
		height:      24,
		config:      cfg,
		defaultOpts: opts,
	}
	for _, domain := range initialDomains {
		m.tabs = append(m.tabs, newTabModel(m.width, m.height, domain, initialLookupType, opts))
	}
	if len(m.tabs) == 0 {
		m.tabs = []tabModel{newTabModel(m.width, m.height, "", "", opts)}
	}
	return m
}

// Init starts every tab's initial command (lookups are bounded by lookupSem).
func (m mainModel) Init() tea.Cmd {
	cmds := make([]tea.Cmd, 0, len(m.tabs))
	for i := range m.tabs {
		cmds = append(cmds, m.tabs[i].Init())
	}
	return tea.Batch(cmds...)
}

func (m mainModel) hasActive() bool {
	return m.activeTab >= 0 && m.activeTab < len(m.tabs)
}

// focus makes tab i active without re-running anything.
func (m *mainModel) focus(i int) tea.Cmd {
	m.activeTab = i
	m.tabs[i].changed = false
	if m.tabs[i].textEntryActive() {
		return m.tabs[i].textInput.Focus()
	}
	return nil
}

// updateTab forwards msg to tab i.
func (m *mainModel) updateTab(i int, msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	m.tabs[i], cmd = m.tabs[i].Update(msg, m.config.Keybindings)
	if i == m.activeTab {
		m.tabs[i].changed = false
	}
	return cmd
}

func (m mainModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		for i := range m.tabs {
			m.tabs[i].setSize(m.width, m.height)
			m.tabs[i].renderContent()
		}

	case tea.KeyMsg:
		m.status = ""
		k := m.config.Keybindings
		key := msg.String()
		textEntry := m.hasActive() && m.tabs[m.activeTab].textEntryActive()

		// Quit always works unless it is a printable key being typed.
		if key == k.Quit && !(textEntry && msg.Type == tea.KeyRunes) {
			return m, tea.Quit
		}
		if textEntry && !globalKeyUsableInTextEntry(msg) {
			// Printable and cursor-editing keys go to the focused input.
			if m.hasActive() {
				cmds = append(cmds, m.updateTab(m.activeTab, msg))
			}
			return m, tea.Batch(cmds...)
		}

		switch key {
		case k.NewTab:
			m.tabs = append(m.tabs, newTabModel(m.width, m.height, "", "", m.defaultOpts))
			cmds = append(cmds, m.focus(len(m.tabs)-1), m.tabs[len(m.tabs)-1].Init())
		case k.CloseTab:
			if len(m.tabs) > 1 && m.hasActive() {
				i := m.activeTab
				m.tabs[i].cancel()
				m.tabs = append(m.tabs[:i], m.tabs[i+1:]...)
				cmds = append(cmds, m.focus(min(i, len(m.tabs)-1)))
			}
		case k.NextTab:
			if len(m.tabs) > 1 {
				cmds = append(cmds, m.focus((m.activeTab+1)%len(m.tabs)))
			}
		case k.PrevTab:
			if len(m.tabs) > 1 {
				cmds = append(cmds, m.focus((m.activeTab-1+len(m.tabs))%len(m.tabs)))
			}
		case k.ExportAll:
			m.status = m.exportAll()
		default:
			if m.hasActive() {
				cmds = append(cmds, m.updateTab(m.activeTab, msg))
			}
		}

	case tabMsg:
		id := msg.targetTab()
		for i := range m.tabs {
			if m.tabs[i].id == id {
				cmds = append(cmds, m.updateTab(i, msg))
				break
			}
		}
		// Messages for closed tabs are dropped, which also ends their tick chains.

	default:
		if m.hasActive() {
			cmds = append(cmds, m.updateTab(m.activeTab, msg))
		}
	}

	return m, tea.Batch(cmds...)
}

// textEditingKeys are keys a text input uses itself, so global bindings on them
// are ignored while typing.
var textEditingKeys = map[string]bool{
	"left": true, "right": true, "up": true, "down": true, "home": true, "end": true,
	"backspace": true, "delete": true, "enter": true, "esc": true,
	"ctrl+a": true, "ctrl+e": true, "ctrl+b": true, "ctrl+f": true, "ctrl+h": true,
	"ctrl+d": true, "ctrl+k": true, "ctrl+u": true, "ctrl+w": true, "ctrl+v": true,
	"alt+left": true, "alt+right": true, "alt+b": true, "alt+f": true, "alt+backspace": true, "alt+d": true,
}

// globalKeyUsableInTextEntry reports whether a global binding may fire while a
// text input is focused: only non-printable keys the input doesn't use itself.
func globalKeyUsableInTextEntry(msg tea.KeyMsg) bool {
	if msg.Type == tea.KeyRunes || msg.Type == tea.KeySpace || msg.Paste {
		return false
	}
	return !textEditingKeys[msg.String()]
}

// exportAllContent concatenates every tab's result/error with a header.
func (m mainModel) exportAllContent() string {
	var b strings.Builder
	for i, t := range m.tabs {
		if i > 0 {
			b.WriteString("\n\n")
		}
		title := t.domain
		if title == "" {
			title = fmt.Sprintf("Tab %d", i+1)
		}
		if t.lookupType != "" {
			title += " — " + t.lookupType
		}
		if t.lookupOpts.Server != "" {
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

// exportAll writes all tabs into one timestamped file in the working directory
// and returns a status message.
func (m mainModel) exportAll() string {
	name := fmt.Sprintf("dlookup-all-%s.txt", now().Format("20060102-150405"))
	path, err := writeExportFile(name, m.exportAllContent())
	if err != nil {
		return "Export all failed: " + err.Error()
	}
	return fmt.Sprintf("Exported %d tabs to %s", len(m.tabs), path)
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
		prefix := ""
		if t.changed && i != m.activeTab {
			prefix = changedStyle.Render("● ")
		}
		if dispValue != "" {
			tabName = dispValue
		}
		// Padding takes 2 cells of maxTabNameWidth.
		tabName = prefix + truncateWidth(tabName, maxTabNameWidth-2-lipgloss.Width(prefix))

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
	if m.hasActive() {
		activeTabView = m.tabs[m.activeTab].View()
	}

	help := m.helpView()

	tabBarHeight := lipgloss.Height(tabBar)
	separatorHeight := lipgloss.Height(separator)
	helpHeight := lipgloss.Height(help)
	availableHeight := max(0, m.height-tabBarHeight-separatorHeight-helpHeight)

	tabContentContainer := lipgloss.NewStyle().Width(m.width).Height(availableHeight).Render(activeTabView)

	return lipgloss.JoinVertical(lipgloss.Left, tabBar, separator, tabContentContainer, help)
}

// helpView renders the (3-line) help area: an optional status line followed by
// the key hints applicable to the active tab's state.
func (m mainModel) helpView() string {
	k := m.config.Keybindings
	hint := func(key, desc string) string { return fmt.Sprintf("%s %s", helpKeyStyle.Render(key+":"), desc) }

	var parts []string
	status := m.status
	if m.hasActive() {
		t := m.tabs[m.activeTab]
		if status == "" {
			status = t.statusMsg
		}
		switch t.state {
		case stateInputDomain:
			parts = append(parts, hint(k.Confirm, "Lookup"))
		case stateSelectLookup:
			parts = append(parts, hint("↑/↓/"+k.Confirm, "Select"), hint(k.Back, "Back"), hint(k.Server, "Server"))
		case stateLoading:
			parts = append(parts, hint(k.Back, "Cancel"))
		case stateViewResults, stateError:
			parts = append(parts, hint("↑/↓/pgup/pgdn", "Scroll"), hint(k.Back, "Back"))
			if t.watchAvailable() {
				if t.isWatching {
					parts = append(parts, hint(k.WatchToggle, "Stop watch"))
				} else {
					parts = append(parts, hint(k.WatchToggle, "Watch"))
				}
			}
			parts = append(parts, hint(k.Export, "Export"), hint(k.Copy, "Copy"), hint(k.Server, "Server"))
		case stateWatchIntervalInput, stateExportFilenameInput, stateServerInput:
			parts = append(parts, hint(k.Confirm, "Confirm"), hint("esc", "Cancel"))
		}
		if !t.textEntryActive() {
			parts = append(parts,
				hint(k.NewTab, "New"),
				hint(k.CloseTab, "Close"),
				hint(k.PrevTab+"/"+k.NextTab, "Switch"),
				hint(k.ExportAll, "Export all"))
		}
	}
	parts = append(parts, hint(k.Quit, "Quit"))

	line := strings.Join(parts, helpDescStyle.Render(" │ "))
	line = truncateWidth(line, max(1, m.width-2))
	if status == "" {
		return helpContainerStyle.Render(line)
	}
	statusLine := statusStyle.Render(truncateWidth(status, max(1, m.width-2)))
	return lipgloss.JoinVertical(lipgloss.Left, statusLine, helpContainerStyle.Padding(0, 1, 1, 1).Render(line))
}
