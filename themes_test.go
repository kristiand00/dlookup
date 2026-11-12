package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
	"gopkg.in/yaml.v3"

	"dlookup/lookup"
	"dlookup/ui"
)

// themeTest forces colour output and restores the mc theme afterwards.
func themeTest(t *testing.T) {
	t.Helper()
	prev := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.TrueColor)
	t.Cleanup(func() {
		lipgloss.SetColorProfile(prev)
		if err := activateTheme(ui.DefaultThemeName); err != nil {
			t.Fatal(err)
		}
	})
}

// tempConfigHome points the config path at a temp dir.
func tempConfigHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, ".config"))
	return dir
}

// seq is the SGR parameter lipgloss emits for hex as foreground or background.
func seq(hex string, bg bool) string {
	st := lipgloss.NewStyle().Foreground(lipgloss.Color(hex))
	if bg {
		st = lipgloss.NewStyle().Background(lipgloss.Color(hex))
	}
	out := st.Render("X")
	return strings.TrimSuffix(strings.TrimPrefix(out[:strings.Index(out, "X")], "\x1b["), "m")
}

func TestMCAppStylesUnchanged(t *testing.T) {
	themeTest(t)
	if err := activateTheme("dracula"); err != nil {
		t.Fatal(err)
	}
	if err := activateTheme("mc"); err != nil {
		t.Fatal(err)
	}
	// The styles as they were defined before themes existed.
	c := func(s string) lipgloss.Color { return lipgloss.Color(s) }
	want := map[string][2]lipgloss.Style{
		"resultHeader": {resultHeaderStyle, lipgloss.NewStyle().Bold(true).Foreground(c("81")).Border(lipgloss.RoundedBorder()).BorderForeground(c("240")).Padding(0, 1).Margin(0, 0, 1, 0)},
		"error":        {errorStyle, lipgloss.NewStyle().Foreground(c("196"))},
		"loading":      {loadingStyle, lipgloss.NewStyle().Foreground(c("214")).Padding(1, 1)},
		"helpKey":      {helpKeyStyle, lipgloss.NewStyle().Foreground(c("81"))},
		"helpDesc":     {helpDescStyle, lipgloss.NewStyle().Foreground(c("241"))},
		"panelBorder":  {panelBorderStyle, lipgloss.NewStyle().Foreground(c("45"))},
		"panelTitle":   {panelTitleStyle, lipgloss.NewStyle().Foreground(c("221")).Bold(true)},
		"scrollTrack":  {scrollTrackStyle, lipgloss.NewStyle().Foreground(c("240"))},
		"scrollThumb":  {scrollThumbStyle, lipgloss.NewStyle().Foreground(c("45"))},
		"homeTitle":    {homeTitleStyle, lipgloss.NewStyle().Foreground(c("45")).Bold(true)},
		"homeSection":  {homeSectionStyle, lipgloss.NewStyle().Foreground(c("221")).Bold(true)},
		"homeButton":   {homeButtonStyle, lipgloss.NewStyle().Foreground(c("16")).Background(c("45")).Bold(true)},
		"hint":         {hintStyle, lipgloss.NewStyle().Foreground(c("241")).Padding(0, 1)},
		"diffAdd":      {diffAddStyle, lipgloss.NewStyle().Foreground(c("78"))},
		"diffRemove":   {diffRemoveStyle, lipgloss.NewStyle().Foreground(c("196"))},
		"watchInfo":    {watchInfoStyle, lipgloss.NewStyle().Foreground(c("214"))},
		"status":       {statusStyle, lipgloss.NewStyle().Foreground(c("78")).Padding(0, 1)},
		"zdMatch":      {zdMatchStyle, lipgloss.NewStyle().Foreground(c("78"))},
		"zdChanged":    {zdChangedStyle, lipgloss.NewStyle().Foreground(c("214"))},
		"zdMissing":    {zdMissingStyle, lipgloss.NewStyle().Foreground(c("196"))},
		"zdExtra":      {zdExtraStyle, lipgloss.NewStyle().Foreground(c("45"))},
		"zdError":      {zdErrorStyle, lipgloss.NewStyle().Foreground(c("196")).Bold(true)},
		"zdNote":       {zdNoteStyle, lipgloss.NewStyle().Foreground(c("240")).Faint(true)},
		"zdLabel":      {zdLabelStyle, lipgloss.NewStyle().Foreground(c("244"))},
		"zdBanner":     {zdBannerStyle, lipgloss.NewStyle().Foreground(c("78")).Bold(true).Border(lipgloss.RoundedBorder()).BorderForeground(c("78")).Padding(0, 1)},
	}
	for name, p := range want {
		if got, exp := p[0].Render("x\ny"), p[1].Render("x\ny"); got != exp {
			t.Errorf("%s: got %q, want %q", name, got, exp)
		}
	}
}

func TestEveryThemeStylesApp(t *testing.T) {
	themeTest(t)
	for _, name := range ui.Themes() {
		if err := activateTheme(name); err != nil {
			t.Fatal(err)
		}
		for what, st := range map[string]lipgloss.Style{"header": resultHeaderStyle, "diffAdd": diffAddStyle, "error": errorStyle, "panel": panelBorderStyle, "button": homeButtonStyle} {
			if out := st.Render("x"); out == "x" {
				t.Errorf("%s: %s style is unstyled", name, what)
			}
		}
	}
}

func TestConfigThemeRoundTrip(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Theme != "mc" {
		t.Fatalf("default theme = %q", cfg.Theme)
	}
	cfg.Theme = "nord"
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "theme: nord") {
		t.Errorf("marshalled config lacks theme:\n%s", data)
	}
	var back AppConfig
	if err := yaml.Unmarshal(data, &back); err != nil || back.Theme != "nord" {
		t.Fatalf("round trip: %q, %v", back.Theme, err)
	}

	tempConfigHome(t)
	if err := saveConfig(cfg); err != nil {
		t.Fatal(err)
	}
	got, err := loadConfig()
	if err != nil || got.Theme != "nord" {
		t.Fatalf("loadConfig theme = %q, %v", got.Theme, err)
	}

	// Configs that predate themes get the default.
	path, _ := getConfigPath()
	if err := os.WriteFile(path, []byte("mouse: false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err = loadConfig()
	if err != nil || got.Theme != "mc" {
		t.Fatalf("old config theme = %q, %v", got.Theme, err)
	}
}

func TestInitThemeUnknownFallsBack(t *testing.T) {
	themeTest(t)
	var buf bytes.Buffer
	cfg := DefaultConfig()
	cfg.Theme = "nord"
	initThemeTo(&buf, cfg)
	if currentThemeName() != "nord" || buf.Len() != 0 {
		t.Fatalf("theme %q, output %q", currentThemeName(), buf.String())
	}
	cfg.Theme = "no-such-theme"
	initThemeTo(&buf, cfg)
	if currentThemeName() != "mc" {
		t.Errorf("theme = %q, want mc fallback", currentThemeName())
	}
	if !strings.Contains(buf.String(), "no-such-theme") || !strings.Contains(buf.String(), "Warning") {
		t.Errorf("missing warning: %q", buf.String())
	}
}

func TestApplyThemeRestylesBars(t *testing.T) {
	themeTest(t)
	m := newMainModel(nil, "", DefaultConfig(), lookup.Options{})
	m.width, m.height = 100, 30
	if err := m.applyTheme("bogus"); err == nil {
		t.Fatal("expected error for unknown theme")
	}
	if err := m.applyTheme("dracula"); err != nil {
		t.Fatal(err)
	}
	_, p, _ := ui.ThemeByName("dracula")
	element := seq(ui.HexOf(p.MenuBg, false), true)
	primary := seq(ui.HexOf(p.TabActiveBg, false), true)
	if out := m.menu.View(m.width); !strings.Contains(out, element) {
		t.Errorf("menu bar not restyled: %q", out)
	}
	if out := m.fkeyBar.View(m.fkeys(), m.width); !strings.Contains(out, element) {
		t.Errorf("F-key bar not restyled: %q", out)
	}
	if out := m.tabBar.View(m.tabInfos(), m.activeTab, m.width); !strings.Contains(out, primary) {
		t.Errorf("tab bar not restyled: %q", out)
	}
	// The cached Home content is re-rendered with the new title colour.
	title := seq(ui.HexOf(p.Title, false), false)
	if out := m.tabs[0].viewport.View(); !strings.Contains(out, title) {
		t.Errorf("home content not re-rendered")
	}
	// The whole screen gets the theme background.
	bg := seq(ui.HexOf(p.Background, false), true)
	if out := paintScreen(m.render(), m.width); !strings.Contains(out, bg) {
		t.Errorf("screen background not painted")
	}

	// Back to mc: no background painting.
	if err := m.applyTheme("mc"); err != nil {
		t.Fatal(err)
	}
	if v := m.render(); paintScreen(v, m.width) != v {
		t.Error("mc theme must not paint the background")
	}
}

func TestThemeDialog(t *testing.T) {
	themeTest(t)
	tempConfigHome(t)
	m := newMainModel(nil, "", DefaultConfig(), lookup.Options{})
	m.openThemeDialog()
	if m.dlg != dlgTheme {
		t.Fatalf("dialog kind = %v", m.dlg)
	}
	f := m.dialog.Fields[0]
	if len(f.Options) != len(ui.Themes()) || f.Value != "mc" {
		t.Fatalf("options %d (want %d), value %q", len(f.Options), len(ui.Themes()), f.Value)
	}
	var vals []string
	for _, o := range f.Options {
		vals = append(vals, o.Value)
	}
	if !reflect.DeepEqual(vals, ui.Themes()) {
		t.Errorf("options %v", vals)
	}

	// Cancel leaves everything alone.
	m.submitThemeDialog(ui.DialogResult{Action: btnCancel})
	if m.dlg != dlgNone || currentThemeName() != "mc" {
		t.Fatal("cancel changed state")
	}

	m.openThemeDialog()
	m.submitThemeDialog(ui.DialogResult{Action: btnApply, Values: map[string]string{"theme": "gruvbox"}})
	if m.dlg != dlgNone || currentThemeName() != "gruvbox" || m.config.Theme != "gruvbox" {
		t.Fatalf("dlg %v theme %q config %q", m.dlg, currentThemeName(), m.config.Theme)
	}
	if !strings.Contains(m.status, "gruvbox") {
		t.Errorf("status = %q", m.status)
	}
	got, err := loadConfig()
	if err != nil || got.Theme != "gruvbox" {
		t.Errorf("saved theme = %q, %v", got.Theme, err)
	}
	// A new dialog preselects the active theme and uses its colours.
	m.openThemeDialog()
	if m.dialog.Fields[0].Value != "gruvbox" {
		t.Errorf("preselected %q", m.dialog.Fields[0].Value)
	}
	gb, _, _ := ui.ThemeByName("gruvbox")
	if !reflect.DeepEqual(m.dialog.Theme, gb) {
		t.Error("theme dialog not drawn with the active theme")
	}
}

func TestHomeListsThemes(t *testing.T) {
	out := helpContent(DefaultConfig(), 200)
	for _, n := range []string{"Theme…", "theme: <name>", "tokyonight", "catppuccin-latte", "solarized-light"} {
		if !strings.Contains(out, n) {
			t.Errorf("home screen lacks %q", n)
		}
	}
}
