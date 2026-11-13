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

// DefaultTheme returns the classic Midnight Commander theme ("mc").
func DefaultTheme() Theme {
	return ThemeFromPalette(mcPalette())
}
