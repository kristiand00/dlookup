package main

import (
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"

	"dlookup/ui"
)

// App-level styles. They are (re)built from the active theme's palette by
// applyAppStyles; never give them literal colours.
var (
	resultHeaderStyle lipgloss.Style

	errorStyle   lipgloss.Style
	loadingStyle lipgloss.Style

	helpKeyStyle  lipgloss.Style
	helpDescStyle lipgloss.Style

	// Panel (the active tab's bordered box).
	panelBorderStyle lipgloss.Style
	panelTitleStyle  lipgloss.Style
	scrollTrackStyle lipgloss.Style
	scrollThumbStyle lipgloss.Style

	// Home / help screen.
	homeTitleStyle   lipgloss.Style
	homeSectionStyle lipgloss.Style
	homeButtonStyle  lipgloss.Style

	hintStyle lipgloss.Style

	diffAddStyle    lipgloss.Style
	diffRemoveStyle lipgloss.Style
	watchInfoStyle  lipgloss.Style
	statusStyle     lipgloss.Style

	// Zone diff.
	zdMatchStyle   lipgloss.Style
	zdChangedStyle lipgloss.Style
	zdMissingStyle lipgloss.Style
	zdExtraStyle   lipgloss.Style
	zdErrorStyle   lipgloss.Style
	zdNoteStyle    lipgloss.Style
	zdLabelStyle   lipgloss.Style
	zdBannerStyle  lipgloss.Style
)

func init() {
	_, p, _ := ui.ThemeByName(ui.DefaultThemeName)
	applyAppStyles(p)
}

// applyAppStyles rebuilds the app-level style globals from palette p.
func applyAppStyles(p ui.Palette) {
	fg := func(c lipgloss.TerminalColor) lipgloss.Style {
		s := lipgloss.NewStyle()
		if c != nil {
			s = s.Foreground(c)
		}
		return s
	}
	borderFg := func(s lipgloss.Style, c lipgloss.TerminalColor) lipgloss.Style {
		if c != nil {
			s = s.BorderForeground(c)
		}
		return s
	}

	resultHeaderStyle = borderFg(fg(p.Primary).
		Bold(true).
		Border(lipgloss.RoundedBorder()), p.Border).
		Padding(0, 1).
		Margin(0, 0, 1, 0)

	errorStyle = fg(p.Error)
	loadingStyle = fg(p.Warning).Padding(1, 1)

	helpKeyStyle = fg(p.Primary)
	helpDescStyle = fg(p.TextMuted)

	panelBorderStyle = fg(p.BorderActive)
	panelTitleStyle = fg(p.Accent).Bold(true)
	scrollTrackStyle = fg(p.Border)
	scrollThumbStyle = fg(p.BorderActive)

	homeTitleStyle = fg(p.Title).Bold(true)
	homeSectionStyle = fg(p.Accent).Bold(true)
	homeButtonStyle = fg(p.ButtonFg).Bold(true)
	if p.ButtonBg != nil {
		homeButtonStyle = homeButtonStyle.Background(p.ButtonBg)
	}
	if p.Reverse {
		homeButtonStyle = lipgloss.NewStyle().Reverse(true).Bold(true)
	}

	hintStyle = fg(p.TextMuted).Padding(0, 1)

	diffAddStyle = fg(p.DiffAdd)
	diffRemoveStyle = fg(p.DiffRemove)
	watchInfoStyle = fg(p.Warning)
	statusStyle = fg(p.Success).Padding(0, 1)

	zdMatchStyle = fg(p.Success)
	zdChangedStyle = fg(p.Warning)
	zdMissingStyle = fg(p.Error)
	zdExtraStyle = fg(p.Info)
	zdErrorStyle = fg(p.Error).Bold(true)
	zdNoteStyle = fg(p.TextFaint)
	if p.Background == nil {
		zdNoteStyle = zdNoteStyle.Faint(true) // too dim on a painted background
	}
	zdLabelStyle = fg(p.TextSubtle)
	zdBannerStyle = borderFg(fg(p.Success).Bold(true).
		Border(lipgloss.RoundedBorder()), p.Success).Padding(0, 1)
}

// truncateWidth shortens s to at most width terminal cells (grapheme and
// wide-character aware, ANSI-safe), ending with "…" when it was cut.
func truncateWidth(s string, width int) string {
	if width <= 0 {
		return ""
	}
	return ansi.Truncate(s, width, "…")
}
