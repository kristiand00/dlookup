package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"dlookup/ui"
)

// dlgTheme is the Options → Theme… dialog (kept clear of the iota block in
// dialogs.go).
const dlgTheme dialogKind = 100

// btnApply applies the chosen theme.
const btnApply = "apply"

// initTheme activates cfg.Theme (and the matching app styles) at startup. An
// unknown name warns on stderr and falls back to "mc".
func initTheme(cfg AppConfig) {
	initThemeTo(os.Stderr, cfg)
}

func initThemeTo(w io.Writer, cfg AppConfig) {
	name := strings.TrimSpace(cfg.Theme)
	if name == "" {
		name = ui.DefaultThemeName
	}
	if err := activateTheme(name); err != nil {
		fmt.Fprintf(w, "Warning: config: %v; using %q.\n", err, ui.DefaultThemeName)
		_ = activateTheme(ui.DefaultThemeName)
	}
}

// activateTheme sets the active ui theme and rebuilds the app styles.
func activateTheme(name string) error {
	if err := ui.SetActiveTheme(name); err != nil {
		return err
	}
	applyAppStyles(ui.ActivePalette())
	return nil
}

// applyTheme switches to theme name at runtime and restyles everything that
// holds a copy of the theme or pre-rendered styled text.
func (m *mainModel) applyTheme(name string) error {
	if err := activateTheme(name); err != nil {
		return err
	}
	th := ui.ActiveTheme()
	m.menu.Theme = th
	m.tabBar.Theme = th
	m.fkeyBar.Theme = th
	if m.dlg != dlgNone {
		m.dialog.Theme = th
	}
	for i := range m.tabs {
		m.tabs[i].renderContent()
	}
	m.refreshHome()
	return nil
}

// currentThemeName is the active theme's name.
func currentThemeName() string { return ui.ActivePalette().Name }

// paintScreen paints the active theme's background (if it has one) behind the
// whole rendered screen.
func paintScreen(view string, width int) string {
	p := ui.ActivePalette()
	return ui.PaintBackground(view, width, p.Background, p.Text)
}

// openThemeDialog opens the theme chooser.
func (m *mainModel) openThemeDialog() tea.Cmd {
	names := ui.Themes()
	opts := make([]ui.Option, 0, len(names))
	for _, n := range names {
		label := n
		switch n {
		case ui.DefaultThemeName:
			label = n + " (Midnight Commander, default)"
		case "system":
			label = n + " (terminal colours)"
		}
		opts = append(opts, ui.Option{Label: label, Value: n})
	}
	d := ui.NewDialog("dl-dlg-theme", "Theme", []ui.Field{
		{Key: "theme", Label: "&Theme", Kind: ui.FieldSelect, Value: currentThemeName(), Options: opts},
	}, []ui.Button{
		{Label: "&Apply", Action: btnApply, Default: true},
		{Label: "&Cancel", Action: btnCancel},
	}, ui.ActiveTheme())
	d.Width = m.dialogWidth(56)
	d.Help = "↑↓ previews · Apply saves (theme: …) · Esc reverts"
	m.themeBefore = currentThemeName()
	return m.openDialog(dlgTheme, -1, d)
}

// previewTheme shows the theme highlighted in the open theme dropdown (or the
// field's current value) without saving it; revert restores the theme that was
// active when the dialog opened.
func (m *mainModel) previewTheme(revert bool) {
	name := m.dialog.Value("theme")
	if key, v, ok := m.dialog.Highlighted(); ok && key == "theme" {
		name = v
	}
	if revert {
		name = m.themeBefore
	}
	if name == "" || name == currentThemeName() {
		return
	}
	_ = m.applyTheme(name)
}

// submitThemeDialog applies and saves the chosen theme.
func (m *mainModel) submitThemeDialog(res ui.DialogResult) tea.Cmd {
	if res.Action != btnApply {
		m.previewTheme(true)
		m.closeDialog()
		return nil
	}
	name := res.Values["theme"]
	if err := m.applyTheme(name); err != nil {
		m.dialog.Err = err.Error()
		return nil
	}
	m.closeDialog()
	m.config.Theme = name
	if err := saveConfig(m.config); err != nil {
		m.status = fmt.Sprintf("Theme: %s (not saved: %v)", name, err)
		return nil
	}
	m.status = "Theme: " + name
	return nil
}
