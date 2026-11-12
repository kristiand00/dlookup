package ui

import "github.com/charmbracelet/lipgloss"

// Theme holds every style used by the widgets in this package. All styles that
// are drawn on top of a coloured surface (menu bar, dropdowns, dialogs) carry
// their own background so that segments never "fall through" to the terminal
// background between ANSI resets.
type Theme struct {
	// Menu bar (top line).
	MenuBar          lipgloss.Style // the bar itself (background fill)
	MenuItem         lipgloss.Style // inactive menu title
	MenuItemActive   lipgloss.Style // open / highlighted menu title
	MenuHotkey       lipgloss.Style // hotkey letter in an inactive title
	MenuHotkeyActive lipgloss.Style // hotkey letter in the active title

	// Dropdown menus.
	Dropdown             lipgloss.Style // box: border + background
	DropdownItem         lipgloss.Style
	DropdownItemActive   lipgloss.Style
	DropdownDisabled     lipgloss.Style
	DropdownHotkey       lipgloss.Style // right-aligned shortcut text
	DropdownHotkeyActive lipgloss.Style
	DropdownSeparator    lipgloss.Style

	// Dialogs.
	Dialog             lipgloss.Style // body background/foreground
	DialogBorder       lipgloss.Style // frame characters
	DialogTitle        lipgloss.Style // title inside the top border
	Label              lipgloss.Style
	LabelFocused       lipgloss.Style
	Field              lipgloss.Style // input / select box (unfocused)
	FieldFocused       lipgloss.Style
	Placeholder        lipgloss.Style // placeholder text inside an unfocused field
	PlaceholderFocused lipgloss.Style
	Cursor             lipgloss.Style
	Info               lipgloss.Style // FieldInfo lines
	Button             lipgloss.Style
	ButtonFocused      lipgloss.Style
	CheckboxOn         lipgloss.Style
	CheckboxOff        lipgloss.Style
	CheckboxFocused    lipgloss.Style
	Error              lipgloss.Style
	Help               lipgloss.Style
	SelectList         lipgloss.Style // open select dropdown box
	SelectItem         lipgloss.Style
	SelectItemActive   lipgloss.Style

	// Function-key bar (bottom line).
	FKeyNum      lipgloss.Style
	FKeyLabel    lipgloss.Style
	FKeyDisabled lipgloss.Style

	// Tab bar.
	TabBar      lipgloss.Style // filler between/after tabs
	TabActive   lipgloss.Style
	TabInactive lipgloss.Style
	TabClose    lipgloss.Style // "×" (drawn with the tab's background)
	TabBadge    lipgloss.Style
	TabAdd      lipgloss.Style
	TabScroll   lipgloss.Style // ‹ › indicators

	// Standalone list.
	ListItem       lipgloss.Style
	ListItemActive lipgloss.Style
	ListDesc       lipgloss.Style
	ListDescActive lipgloss.Style
	ListDisabled   lipgloss.Style

	// Drop shadow cells (see OverlayShadowStyle).
	Shadow lipgloss.Style
}

func ac(light, dark string) lipgloss.AdaptiveColor {
	return lipgloss.AdaptiveColor{Light: light, Dark: dark}
}

// Palette (MC-inspired). The coloured surfaces use the same colours in light
// and dark terminals (they bring their own background), only the "loose" text
// drawn on the terminal background (tabs, lists, F-key labels) adapts.
var (
	cBlue       = lipgloss.Color("#1c3f94")
	cBlueDeep   = lipgloss.Color("#12296b")
	cCyan       = lipgloss.Color("#3fb6c4")
	cCyanLight  = lipgloss.Color("#9ee6ee")
	cBlack      = lipgloss.Color("#101010")
	cWhite      = lipgloss.Color("#f2f2f2")
	cYellow     = lipgloss.Color("#ffe066")
	cGrayOnCyan = lipgloss.Color("#2a6b73")
	cDimOnBlue  = lipgloss.Color("#9aa9d6")
	cRedOnBlue  = lipgloss.Color("#ff9a9a")
)

// DefaultTheme returns the MC-inspired default theme.
func DefaultTheme() Theme {
	s := lipgloss.NewStyle
	onCyan := s().Background(cCyan).Foreground(cBlack)
	onBlack := s().Background(cBlack).Foreground(cWhite)
	onBlue := s().Background(cBlue).Foreground(cWhite)

	return Theme{
		MenuBar:          onCyan,
		MenuItem:         onCyan,
		MenuItemActive:   onBlack,
		MenuHotkey:       onCyan.Foreground(lipgloss.Color("#fff6b0")).Bold(true).Underline(true),
		MenuHotkeyActive: onBlack.Foreground(cYellow).Bold(true).Underline(true),

		Dropdown:             onCyan.BorderForeground(cBlack).BorderBackground(cCyan),
		DropdownItem:         onCyan,
		DropdownItemActive:   onBlack,
		DropdownDisabled:     onCyan.Foreground(cGrayOnCyan),
		DropdownHotkey:       onCyan.Foreground(lipgloss.Color("#1d4a50")),
		DropdownHotkeyActive: onBlack.Foreground(cYellow),
		DropdownSeparator:    onCyan.Foreground(cBlack),

		Dialog:             onBlue,
		DialogBorder:       onBlue.Foreground(cCyanLight),
		DialogTitle:        onBlue.Foreground(cYellow).Bold(true),
		Label:              onBlue,
		LabelFocused:       onBlue.Foreground(cYellow).Bold(true),
		Field:              s().Background(cBlueDeep).Foreground(cWhite),
		FieldFocused:       onCyan,
		Placeholder:        s().Background(cBlueDeep).Foreground(cDimOnBlue),
		PlaceholderFocused: onCyan.Foreground(cGrayOnCyan),
		Cursor:             s().Background(cBlack).Foreground(cWhite),
		Info:               onBlue.Foreground(cCyanLight),
		Button:             onBlue,
		ButtonFocused:      onCyan.Bold(true),
		CheckboxOn:         onBlue,
		CheckboxOff:        onBlue,
		CheckboxFocused:    onCyan,
		Error:              onBlue.Foreground(cRedOnBlue).Bold(true),
		Help:               onBlue.Foreground(cDimOnBlue),
		SelectList:         onCyan.BorderForeground(cBlack).BorderBackground(cCyan),
		SelectItem:         onCyan,
		SelectItemActive:   onBlack,

		FKeyNum:      s().Foreground(ac("#101010", "#f2f2f2")).Bold(true),
		FKeyLabel:    onCyan,
		FKeyDisabled: onCyan.Foreground(cGrayOnCyan),

		TabBar:      s(),
		TabActive:   onBlue.Bold(true),
		TabInactive: s().Background(ac("#d0d4dc", "#30343c")).Foreground(ac("#303030", "#c8c8c8")),
		TabClose:    s().Foreground(ac("#b00020", "#ff8080")),
		TabBadge:    s().Foreground(ac("#b07000", "#ffd060")),
		TabAdd:      s().Foreground(ac("#1c3f94", "#7fd8e2")).Bold(true),
		TabScroll:   s().Foreground(ac("#1c3f94", "#7fd8e2")).Bold(true),

		ListItem:       s(),
		ListItemActive: onCyan,
		ListDesc:       s().Foreground(ac("#606060", "#8a8a8a")),
		ListDescActive: onCyan.Foreground(cGrayOnCyan),
		ListDisabled:   s().Foreground(ac("#a0a0a0", "#5a5a5a")),

		Shadow: s().Background(lipgloss.Color("#000000")).Foreground(lipgloss.Color("#5a5a5a")),
	}
}
