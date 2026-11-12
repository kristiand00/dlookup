package main

import (
	"dlookup/ui"
)

// Actions dispatched by keys, the menu bar, the F-key bar and Home buttons.
const (
	actHelp       = "help"
	actNew        = "new"
	actChange     = "change"
	actZoneDiff   = "zonediff"
	actRerun      = "rerun"
	actReport     = "report"
	actWatch      = "watch"
	actServer     = "server"
	actClose      = "close"
	actMenu       = "menu"
	actQuit       = "quit"
	actExport     = "export"
	actExportAll  = "exportall"
	actCopy       = "copy"
	actNewTab     = "newtab"
	actNextTab    = "nexttab"
	actPrevTab    = "prevtab"
	actBack       = "back"
	actMatches    = "matches"
	actFilterAll  = "filter:0"
	actTop        = "top"
	actBottom     = "bottom"
	actMouse      = "mouse"
	actConfigInfo = "config"
	actAbout      = "about"
)

// filterActions are the zone diff filter menu actions ("filter:N" mirrors the
// number keys).
var filterActions = []struct{ label, action string }{
	{"Filter: all", actFilterAll},
	{"Filter: changed", "filter:1"},
	{"Filter: missing", "filter:2"},
	{"Filter: extra", "filter:3"},
	{"Filter: errors", "filter:4"},
	{"Filter: matches", "filter:5"},
}

func hk(key, fkey string) string {
	key = prettyKey(key)
	if fkey == "" {
		return key
	}
	if key == "" {
		return fkey
	}
	return key + " " + fkey
}

// buildMenuBar creates the menu bar, showing the configured key of each item.
func buildMenuBar(cfg AppConfig) ui.MenuBar {
	k := cfg.Keybindings
	off := false
	matches, mouse := off, cfg.Mouse
	view := []ui.MenuItem{
		{Label: "Show &matches", Hotkey: hk(k.ToggleMatches, ""), Action: actMatches, Checked: &matches},
		{Separator: true},
	}
	for i, f := range filterActions {
		view = append(view, ui.MenuItem{Label: f.label, Hotkey: string(rune('0' + i)), Action: f.action})
	}
	view = append(view,
		ui.MenuItem{Separator: true},
		ui.MenuItem{Label: "Scroll to &top", Hotkey: "g", Action: actTop},
		ui.MenuItem{Label: "Scroll to &bottom", Hotkey: "G", Action: actBottom},
	)
	menus := []ui.Menu{
		{Title: "&Lookup", Items: []ui.MenuItem{
			{Label: "&New lookup…", Hotkey: hk(k.NewTab, "F2"), Action: actNew},
			{Label: "&Change lookup…", Hotkey: hk(k.Confirm, "F3"), Action: actChange},
			{Label: "&Re-run", Hotkey: hk("r", "F5"), Action: actRerun},
			{Label: "&Zone diff…", Hotkey: hk(k.ZoneDiff, "F4"), Action: actZoneDiff},
			{Label: "Re&port", Action: actReport},
			{Separator: true},
			{Label: "&Export…", Hotkey: hk(k.Export, ""), Action: actExport},
			{Label: "Export &all", Hotkey: hk(k.ExportAll, ""), Action: actExportAll},
			{Label: "C&opy result", Hotkey: hk(k.Copy, ""), Action: actCopy},
			{Separator: true},
			{Label: "&Quit", Hotkey: "F10", Action: actQuit},
		}},
		{Title: "&Tab", Items: []ui.MenuItem{
			{Label: "&New tab", Hotkey: hk(k.NewTab, ""), Action: actNewTab},
			{Label: "&Close tab", Hotkey: hk(k.CloseTab, "F8"), Action: actClose},
			{Label: "Ne&xt", Hotkey: hk(k.NextTab, ""), Action: actNextTab},
			{Label: "&Previous", Hotkey: hk(k.PrevTab, ""), Action: actPrevTab},
			{Separator: true},
			{Label: "&Watch…", Hotkey: hk(k.WatchToggle, "F6"), Action: actWatch},
			{Label: "DNS &server…", Hotkey: hk(k.Server, "F7"), Action: actServer},
		}},
		{Title: "&View", Items: view},
		{Title: "&Options", Items: []ui.MenuItem{
			{Label: "&Mouse", Action: actMouse, Checked: &mouse},
			{Label: "&Config file…", Action: actConfigInfo},
		}},
		{Title: "&Help", Items: []ui.MenuItem{
			{Label: "&Help && shortcuts", Hotkey: "? F1", Action: actHelp},
			{Label: "&About", Action: actAbout},
		}},
	}
	return ui.NewMenuBar("dl-menu", menus, ui.DefaultTheme())
}

// fkeyDefs is the MC-style function key bar.
var fkeyDefs = []ui.FKey{
	{Key: "f1", Num: "1", Label: "Help", Action: actHelp},
	{Key: "f2", Num: "2", Label: "New", Action: actNew},
	{Key: "f3", Num: "3", Label: "Lookup", Action: actChange},
	{Key: "f4", Num: "4", Label: "ZoneDiff", Action: actZoneDiff},
	{Key: "f5", Num: "5", Label: "Re-run", Action: actRerun},
	{Key: "f6", Num: "6", Label: "Watch", Action: actWatch},
	{Key: "f7", Num: "7", Label: "Server", Action: actServer},
	{Key: "f8", Num: "8", Label: "Close", Action: actClose},
	{Key: "f9", Num: "9", Label: "Menu", Action: actMenu},
	{Key: "f10", Num: "10", Label: "Quit", Action: actQuit},
}

// fkeyAction returns the action of function key key ("f1".."f10").
func fkeyAction(key string) string {
	for _, f := range fkeyDefs {
		if f.Key == key {
			return f.Action
		}
	}
	return ""
}

// syncMenu updates disabled/checked state and labels for the current state.
func (m *mainModel) syncMenu() {
	var t *tabModel
	if m.hasActive() {
		t = &m.tabs[m.activeTab]
	}
	lookupTab := t != nil && !t.isHome()
	hasLookup := lookupTab && t.lookupType != ""
	results := lookupTab && t.resultsVisible()
	zdResults := results && t.isZoneDiff() && t.state == stateViewResults
	anyResults := false
	for i := range m.tabs {
		if !m.tabs[i].isHome() && m.tabs[i].resultsVisible() {
			anyResults = true
		}
	}
	set := func(action string, enabled bool) { m.menu.SetDisabled(action, !enabled) }
	set(actChange, lookupTab)
	set(actRerun, hasLookup)
	set(actExport, results)
	set(actCopy, results)
	set(actExportAll, anyResults)
	set(actClose, len(m.tabs) > 1 || lookupTab)
	set(actNextTab, len(m.tabs) > 1)
	set(actPrevTab, len(m.tabs) > 1)
	set(actWatch, t != nil && (t.isWatching || results && t.watchAvailable()))
	set(actServer, lookupTab && !t.isZoneDiff())
	set(actMatches, zdResults)
	for _, f := range filterActions {
		set(f.action, zdResults)
	}
	scroll := t != nil && t.scrollable()
	set(actTop, scroll)
	set(actBottom, scroll)
	m.menu.SetChecked(actMatches, t != nil && t.zd.showMatches)
	m.menu.SetChecked(actMouse, m.mouse)

	watchLabel := "&Watch…"
	if t != nil && t.isWatching {
		watchLabel = "Stop &watching"
	}
	for i := range m.menu.Menus {
		for j := range m.menu.Menus[i].Items {
			if m.menu.Menus[i].Items[j].Action == actWatch {
				m.menu.Menus[i].Items[j].Label = watchLabel
			}
		}
	}
}

// fkeys returns the F-key bar with the keys that don't apply greyed out.
func (m mainModel) fkeys() []ui.FKey {
	keys := make([]ui.FKey, len(fkeyDefs))
	copy(keys, fkeyDefs)
	for i := range keys {
		if it := m.menuItem(keys[i].Action); it != nil {
			keys[i].Disabled = it.Disabled
		}
	}
	return keys
}

// menuItem returns the first menu item with action, or nil.
func (m mainModel) menuItem(action string) *ui.MenuItem {
	for i := range m.menu.Menus {
		for j := range m.menu.Menus[i].Items {
			if m.menu.Menus[i].Items[j].Action == action {
				return &m.menu.Menus[i].Items[j]
			}
		}
	}
	return nil
}
