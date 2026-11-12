package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"

	"dlookup/lookup"
	"dlookup/ui"
)

// Home screen button zone ids and their actions.
var homeButtons = []struct{ id, label, action string }{
	{"dl-home-new", "[ New lookup ]", actNew},
	{"dl-home-zonediff", "[ Zone diff ]", actZoneDiff},
	{"dl-home-quit", "[ Quit ]", actQuit},
}

// homeButtonsView renders the clickable Home buttons row.
func homeButtonsView() string {
	parts := make([]string, 0, len(homeButtons))
	for _, b := range homeButtons {
		parts = append(parts, ui.Mark(b.id, homeButtonStyle.Render(b.label)))
	}
	return " " + strings.Join(parts, "  ")
}

// prettyKey renders a Bubble Tea key name for display.
func prettyKey(k string) string {
	switch k {
	case "right":
		return "→"
	case "left":
		return "←"
	case "up":
		return "↑"
	case "down":
		return "↓"
	case "enter":
		return "Enter"
	case "esc":
		return "Esc"
	case " ", "space":
		return "Space"
	}
	return k
}

// shortcut is one row of the shortcut table.
type shortcut struct{ action, keys, fkey string }

// shortcuts lists every action with its configured key and F-key alternate.
func shortcuts(k Keybindings) []shortcut {
	quit := prettyKey(k.Quit)
	if k.Quit != "ctrl+c" {
		quit += " / ctrl+c"
	}
	back := prettyKey(k.Back)
	if k.Back != "esc" {
		back += " / Esc"
	}
	return []shortcut{
		{"Help & shortcuts (this screen)", "?", "F1"},
		{"New lookup (opens a new tab)", prettyKey(k.NewTab), "F2"},
		{"Change lookup of this tab", prettyKey(k.Confirm), "F3"},
		{"Zone diff (DNS migration check)", prettyKey(k.ZoneDiff), "F4"},
		{"Re-run the lookup", "r", "F5"},
		{"Watch / stop watching", prettyKey(k.WatchToggle), "F6"},
		{"DNS server for this tab", prettyKey(k.Server), "F7"},
		{"Close tab", prettyKey(k.CloseTab), "F8"},
		{"Open the menu bar", "alt+L/T/V/O/H", "F9"},
		{"Quit", quit, "F10"},
		{"Previous / next tab", prettyKey(k.PrevTab) + " / " + prettyKey(k.NextTab), ""},
		{"Cancel lookup / stop watching", back, ""},
		{"Export result to a file", prettyKey(k.Export), ""},
		{"Export all tabs to one file", prettyKey(k.ExportAll), ""},
		{"Copy result to clipboard", prettyKey(k.Copy), ""},
		{"Scroll results", "↑ ↓ PgUp PgDn g G", ""},
		{"Zone diff: show/hide matches", prettyKey(k.ToggleMatches), ""},
		{"Zone diff: filter by status", "1-5 (0 clears)", ""},
	}
}

// helpContent renders the Home/help text for the given keybindings.
func helpContent(cfg AppConfig, width int) string {
	k := cfg.Keybindings
	var b strings.Builder
	section := func(title string) {
		b.WriteString("\n")
		b.WriteString(homeSectionStyle.Render(title))
		b.WriteString("\n")
	}
	line := func(s string) { b.WriteString(s + "\n") }
	key := func(s string) string { return helpKeyStyle.Render(s) }

	b.WriteString(homeTitleStyle.Render("dlookup " + versionString()))
	b.WriteString(helpDescStyle.Render(" — DNS, RDAP & WHOIS lookups in your terminal"))
	b.WriteString("\n")

	section("Get started")
	line(fmt.Sprintf("  Press %s or %s (or click [ New lookup ]) to look up a domain or IP.", key(prettyKey(k.NewTab)), key("F2")))
	line(fmt.Sprintf("  Press %s or %s for a zone diff before migrating DNS.", key(prettyKey(k.ZoneDiff)), key("F4")))
	line(fmt.Sprintf("  Press %s for the menu, %s for this help, %s to quit.", key("F9"), key("F1 / ?"), key("F10")))
	line(helpDescStyle.Render("  On a Mac laptop the F-keys need fn; every action also has a letter key."))

	section("Features")
	var names []string
	for _, p := range lookup.AvailableProviders() {
		names = append(names, p.Name())
	}
	sort.Strings(names)
	features := []string{
		"Native DNS lookups (no dig needed): A, AAAA, CNAME, MX, NS, SOA, TXT, CAA, PTR, SPF, DMARC, ANY",
		"RDAP registration data over HTTPS; NSLOOKUP and WHOIS via the system tools",
		"Comprehensive Report: every lookup for a target in one view",
		"Watch mode: re-run on an interval, changes highlighted (+/-), ● on background tabs",
		"Zone diff: compare a domain's records on its nameservers with a new DNS server",
		"Custom DNS server per tab (or --server for all tabs)",
		"Export a tab or all tabs to a file; copy a result to the clipboard",
		"Tabs: every lookup runs in its own tab, in parallel",
	}
	for _, f := range features {
		line("  • " + f)
	}
	wrapped := ansi.Wrap("Lookups: "+strings.Join(names, ", "), max(20, width-4), "")
	for _, l := range strings.Split(wrapped, "\n") {
		line(helpDescStyle.Render("  " + l))
	}

	section("Keyboard shortcuts")
	rows := shortcuts(k)
	keyW := lipgloss.Width("Key")
	for _, r := range rows {
		keyW = max(keyW, lipgloss.Width(r.keys))
	}
	pad := func(s string, w int) string { return s + strings.Repeat(" ", max(0, w-lipgloss.Width(s))) }
	line("  " + helpDescStyle.Render(pad("Action", 33)+pad("Key", keyW+2)+"F-key"))
	for _, r := range rows {
		line("  " + pad(r.action, 33) + key(pad(r.keys, keyW+2)) + key(r.fkey))
	}
	line("")
	line("  In dialogs: Tab/Shift+Tab move between fields, Enter runs, Space toggles")
	line("  a checkbox or opens a dropdown, Esc cancels.")

	section("Mouse")
	line("  Click menus, tabs (× closes, [+] opens a new lookup), F-keys, buttons and")
	line("  dialog fields/dropdowns. The wheel scrolls results and lists.")
	line("  To select text, hold Shift (Option on macOS Terminal/iTerm) while dragging,")
	line("  or turn the mouse off in Options → Mouse.")

	section("Command line")
	line("  dlookup example.com 1.1.1.1            a tab per target")
	line("  dlookup --dig-mx domains.txt           run a lookup on every target")
	line("  dlookup -o json --lookup rdap a.com    headless output (text or json)")
	line("  dlookup zonediff example.com --new ns1.newprovider.com")
	line("  dlookup --help                         all options")

	section("Configuration")
	path, err := getConfigPath()
	if err != nil {
		path = "~/.config/dlookup/config.yaml"
	}
	line("  " + path)
	line("  Keybindings and `mouse: true|false` can be changed there.")
	return strings.TrimRight(b.String(), "\n")
}
