package main

import (
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

var (
	colorLightBlue = lipgloss.Color("81")
	colorGrey      = lipgloss.Color("240")
	colorLightGrey = lipgloss.Color("244")
	colorYellow    = lipgloss.Color("221")
	colorBlack     = lipgloss.Color("16")
	colorRed       = lipgloss.Color("196")
	colorOrange    = lipgloss.Color("214")
	colorGreen     = lipgloss.Color("78")
	colorHelpKey   = lipgloss.Color("81")
	colorHelpDesc  = lipgloss.Color("241")
	colorCyan      = lipgloss.Color("45")

	resultHeaderStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(colorLightBlue).
				Border(lipgloss.RoundedBorder()).
				BorderForeground(colorGrey).
				Padding(0, 1).
				Margin(0, 0, 1, 0)

	errorStyle   = lipgloss.NewStyle().Foreground(colorRed)
	loadingStyle = lipgloss.NewStyle().Foreground(colorOrange).Padding(1, 1)

	helpKeyStyle  = lipgloss.NewStyle().Foreground(colorHelpKey)
	helpDescStyle = lipgloss.NewStyle().Foreground(colorHelpDesc)

	// Panel (the active tab's bordered box).
	panelBorderStyle = lipgloss.NewStyle().Foreground(colorCyan)
	panelTitleStyle  = lipgloss.NewStyle().Foreground(colorYellow).Bold(true)
	scrollTrackStyle = lipgloss.NewStyle().Foreground(colorGrey)
	scrollThumbStyle = lipgloss.NewStyle().Foreground(colorCyan)

	// Home / help screen.
	homeTitleStyle   = lipgloss.NewStyle().Foreground(colorCyan).Bold(true)
	homeSectionStyle = lipgloss.NewStyle().Foreground(colorYellow).Bold(true)
	homeButtonStyle  = lipgloss.NewStyle().Foreground(colorBlack).Background(colorCyan).Bold(true)

	hintStyle = lipgloss.NewStyle().Foreground(colorHelpDesc).Padding(0, 1)

	diffAddStyle    = lipgloss.NewStyle().Foreground(colorGreen)
	diffRemoveStyle = lipgloss.NewStyle().Foreground(colorRed)
	watchInfoStyle  = lipgloss.NewStyle().Foreground(colorOrange)
	statusStyle     = lipgloss.NewStyle().Foreground(colorGreen).Padding(0, 1)

	// Zone diff.
	zdMatchStyle   = lipgloss.NewStyle().Foreground(colorGreen)
	zdChangedStyle = lipgloss.NewStyle().Foreground(colorOrange)
	zdMissingStyle = lipgloss.NewStyle().Foreground(colorRed)
	zdExtraStyle   = lipgloss.NewStyle().Foreground(colorCyan)
	zdErrorStyle   = lipgloss.NewStyle().Foreground(colorRed).Bold(true)
	zdNoteStyle    = lipgloss.NewStyle().Foreground(colorGrey).Faint(true)
	zdLabelStyle   = lipgloss.NewStyle().Foreground(colorLightGrey)
	zdBannerStyle  = lipgloss.NewStyle().Foreground(colorGreen).Bold(true).
			Border(lipgloss.RoundedBorder()).BorderForeground(colorGreen).Padding(0, 1)
)

// truncateWidth shortens s to at most width terminal cells (grapheme and
// wide-character aware, ANSI-safe), ending with "…" when it was cut.
func truncateWidth(s string, width int) string {
	if width <= 0 {
		return ""
	}
	return ansi.Truncate(s, width, "…")
}
