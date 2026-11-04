package main

import (
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

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

	diffAddStyle    = lipgloss.NewStyle().Foreground(colorGreen)
	diffRemoveStyle = lipgloss.NewStyle().Foreground(colorRed)
	watchInfoStyle  = lipgloss.NewStyle().Foreground(colorOrange)
	statusStyle     = lipgloss.NewStyle().Foreground(colorGreen).Padding(0, 1)
	validationStyle = lipgloss.NewStyle().Foreground(colorRed).Padding(0, 1)
	changedStyle    = lipgloss.NewStyle().Foreground(colorOrange).Bold(true)
)

// truncateWidth shortens s to at most width terminal cells (grapheme and
// wide-character aware, ANSI-safe), ending with "…" when it was cut.
func truncateWidth(s string, width int) string {
	if width <= 0 {
		return ""
	}
	return ansi.Truncate(s, width, "…")
}
