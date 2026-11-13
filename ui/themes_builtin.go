package ui

import "github.com/charmbracelet/lipgloss"

// base is the compact OpenCode-style palette most built-in themes are defined
// with (see https://opencode.ai/docs/themes/); derive expands it.
type base struct {
	bg, panel, element          string
	text, muted                 string
	primary, secondary, accent  string
	border, borderActive        string
	success, warning, err, info string
	diffAdd, diffRemove         string
}

// derive expands b into a full palette: a painted screen background, menus on
// the element colour, the primary colour for selections/focus/active tab.
func derive(name string, light bool, b base) Palette {
	c := func(h string) lipgloss.TerminalColor { return lipgloss.Color(h) }
	onPrimary := readableOn(b.primary, b.bg, b.text, "#000000", "#ffffff")
	// Accent text on a surface: the primary colour unless it is too dark/light
	// there (e.g. Crush's Charple), then the most readable of the accents.
	vivid := func(surface string) string {
		for _, c := range []string{b.primary, b.secondary, b.accent} {
			if ContrastRatio(c, surface) >= 3.5 {
				return c
			}
		}
		return readableOn(surface, b.primary, b.secondary, b.accent, b.text)
	}
	shadow := "#000000"
	if light {
		shadow = blend(b.bg, "#000000", 0.35)
	}
	return Palette{
		Name:  name,
		Light: light,

		Background: c(b.bg),
		Panel:      c(b.panel),
		Element:    c(b.element),
		Text:       c(b.text),
		TextMuted:  c(b.muted),
		TextSubtle: c(blend(b.text, b.muted, 0.4)),
		TextFaint:  c(b.muted),

		Primary:   c(vivid(b.bg)),
		Secondary: c(b.secondary),
		Accent:    c(b.accent),
		Title:     c(vivid(b.bg)),

		Border:       c(b.border),
		BorderActive: c(b.borderActive),

		Success:    c(b.success),
		Warning:    c(b.warning),
		Error:      c(b.err),
		Info:       c(b.info),
		DiffAdd:    c(b.diffAdd),
		DiffRemove: c(b.diffRemove),

		MenuBg:       c(b.element),
		MenuFg:       c(b.text),
		MenuHotkey:   c(vivid(b.element)),
		MenuShortcut: c(b.muted),
		MenuMuted:    c(blend(b.muted, b.element, 0.3)),
		MenuBorder:   c(b.borderActive),

		SelectionBg:     c(b.primary),
		SelectionFg:     c(onPrimary),
		SelectionHotkey: c(onPrimary),

		DialogBg:     c(b.panel),
		DialogFg:     c(b.text),
		DialogBorder: c(b.borderActive),
		DialogTitle:  c(vivid(b.panel)),
		DialogInfo:   c(b.info),
		DialogMuted:  c(b.muted),
		DialogError:  c(b.err),
		FieldBg:      c(b.element),
		FieldFg:      c(b.text),
		FocusBg:      c(b.primary),
		FocusFg:      c(onPrimary),
		FocusMuted:   c(blend(onPrimary, b.primary, 0.45)),
		CursorBg:     c(b.text),
		CursorFg:     c(b.bg),

		TabActiveBg:   c(b.primary),
		TabActiveFg:   c(onPrimary),
		TabInactiveBg: c(b.element),
		TabInactiveFg: c(blend(b.text, b.muted, 0.5)),
		TabClose:      c(b.err),
		TabBadge:      c(b.warning),
		TabAdd:        c(vivid(b.bg)),

		FKeyNum:      c(b.text),
		ListMuted:    c(b.muted),
		ListDisabled: c(blend(b.muted, b.bg, 0.4)),

		ButtonBg: c(b.primary),
		ButtonFg: c(onPrimary),

		ShadowBg: c(shadow),
		ShadowFg: c(b.muted),
	}
}

// mcPalette is the classic Midnight Commander look (blue dialogs, cyan menus),
// drawn on the terminal's own background.
func mcPalette() Palette {
	var (
		blue       = lipgloss.Color("#1c3f94")
		blueDeep   = lipgloss.Color("#12296b")
		cyan       = lipgloss.Color("#3fb6c4")
		cyanLight  = lipgloss.Color("#9ee6ee")
		black      = lipgloss.Color("#101010")
		white      = lipgloss.Color("#f2f2f2")
		yellow     = lipgloss.Color("#ffe066")
		grayOnCyan = lipgloss.Color("#2a6b73")
		dimOnBlue  = lipgloss.Color("#9aa9d6")
		redOnBlue  = lipgloss.Color("#ff9a9a")
	)
	return Palette{
		Name: "mc",

		Panel:      blue,
		Element:    blueDeep,
		Text:       ac("#101010", "#f2f2f2"),
		TextMuted:  lipgloss.Color("241"),
		TextSubtle: lipgloss.Color("244"),
		TextFaint:  lipgloss.Color("240"),

		Primary:   lipgloss.Color("81"),
		Secondary: lipgloss.Color("45"),
		Accent:    lipgloss.Color("221"),
		Title:     lipgloss.Color("45"),

		Border:       lipgloss.Color("240"),
		BorderActive: lipgloss.Color("45"),

		Success:    lipgloss.Color("78"),
		Warning:    lipgloss.Color("214"),
		Error:      lipgloss.Color("196"),
		Info:       lipgloss.Color("45"),
		DiffAdd:    lipgloss.Color("78"),
		DiffRemove: lipgloss.Color("196"),

		MenuBg:       cyan,
		MenuFg:       black,
		MenuHotkey:   lipgloss.Color("#fff6b0"),
		MenuShortcut: lipgloss.Color("#1d4a50"),
		MenuMuted:    grayOnCyan,
		MenuBorder:   black,

		SelectionBg:     black,
		SelectionFg:     white,
		SelectionHotkey: yellow,

		DialogBg:     blue,
		DialogFg:     white,
		DialogBorder: cyanLight,
		DialogTitle:  yellow,
		DialogInfo:   cyanLight,
		DialogMuted:  dimOnBlue,
		DialogError:  redOnBlue,
		FieldBg:      blueDeep,
		FieldFg:      white,
		FocusBg:      cyan,
		FocusFg:      black,
		FocusMuted:   grayOnCyan,
		CursorBg:     black,
		CursorFg:     white,

		TabActiveBg:   blue,
		TabActiveFg:   white,
		TabInactiveBg: ac("#d0d4dc", "#30343c"),
		TabInactiveFg: ac("#303030", "#c8c8c8"),
		TabClose:      ac("#b00020", "#ff8080"),
		TabBadge:      ac("#b07000", "#ffd060"),
		TabAdd:        ac("#1c3f94", "#7fd8e2"),

		FKeyNum:      ac("#101010", "#f2f2f2"),
		ListMuted:    ac("#606060", "#8a8a8a"),
		ListDisabled: ac("#a0a0a0", "#5a5a5a"),

		ButtonBg: lipgloss.Color("45"),
		ButtonFg: lipgloss.Color("16"),

		ShadowBg: lipgloss.Color("#000000"),
		ShadowFg: lipgloss.Color("#5a5a5a"),
	}
}

// systemPalette uses only the terminal's 16 ANSI colours and no backgrounds;
// highlights use reverse video, so it follows the terminal's colour scheme.
func systemPalette() Palette {
	a := func(n string) lipgloss.TerminalColor { return lipgloss.Color(n) }
	return Palette{
		Name:    "system",
		Reverse: true,

		TextMuted:  a("8"),
		TextSubtle: a("8"),
		TextFaint:  a("8"),

		Primary:   a("4"),
		Secondary: a("5"),
		Accent:    a("3"),
		Title:     a("6"),

		Border:       a("8"),
		BorderActive: a("6"),

		Success:    a("2"),
		Warning:    a("3"),
		Error:      a("1"),
		Info:       a("6"),
		DiffAdd:    a("2"),
		DiffRemove: a("1"),

		MenuHotkey:   a("3"),
		MenuShortcut: a("8"),
		MenuMuted:    a("8"),
		MenuBorder:   a("8"),

		DialogBorder: a("6"),
		DialogTitle:  a("3"),
		DialogInfo:   a("6"),
		DialogMuted:  a("8"),
		DialogError:  a("1"),
		FieldFg:      a("6"),
		FocusMuted:   a("8"),

		TabInactiveFg: a("8"),
		TabClose:      a("1"),
		TabBadge:      a("3"),
		TabAdd:        a("6"),

		ListMuted:    a("8"),
		ListDisabled: a("8"),

		ButtonBg: a("6"),
		ButtonFg: a("0"),

		ShadowFg: a("8"),
	}
}

// claudeBase is a Claude Code style palette: terracotta accent on warm neutrals.
var claudeBase = base{
	bg: "#1f1e1d", panel: "#262624", element: "#30302e",
	text: "#faf9f5", muted: "#a3a29c",
	primary: "#d97757", secondary: "#b1b9f9", accent: "#e8a55a",
	border: "#4a4945", borderActive: "#d97757",
	success: "#4eba65", warning: "#ffc107", err: "#ff6b80", info: "#b1b9f9",
	diffAdd: "#4eba65", diffRemove: "#ff6b80",
}

func builtinPalettes() []Palette {
	return []Palette{
		mcPalette(),
		systemPalette(),
		derive("opencode", false, base{
			bg: "#0a0a0a", panel: "#141414", element: "#1e1e1e",
			text: "#eeeeee", muted: "#808080",
			primary: "#fab283", secondary: "#5c9cf5", accent: "#9d7cd8",
			border: "#484848", borderActive: "#606060",
			success: "#7fd88f", warning: "#f5a742", err: "#e06c75", info: "#56b6c2",
			diffAdd: "#4fd6be", diffRemove: "#e06c75",
		}),
		derive("claude", false, claudeBase),
		// Charm Crush: Charple/Dolly on Pepper.
		derive("crush", false, base{
			bg: "#201f26", panel: "#2d2c35", element: "#3a3943",
			text: "#dfdbdd", muted: "#858392",
			primary: "#6b50ff", secondary: "#ff60ff", accent: "#68ffd6",
			border: "#4d4c57", borderActive: "#6b50ff",
			success: "#00ffb2", warning: "#e8fe96", err: "#eb4268", info: "#00a4ff",
			diffAdd: "#00ffb2", diffRemove: "#eb4268",
		}),
		derive("tokyonight", false, base{
			bg: "#1a1b26", panel: "#1e2030", element: "#222436",
			text: "#c8d3f5", muted: "#828bb8",
			primary: "#82aaff", secondary: "#c099ff", accent: "#ff966c",
			border: "#737aa2", borderActive: "#9099b2",
			success: "#c3e88d", warning: "#ff966c", err: "#ff757f", info: "#82aaff",
			diffAdd: "#4fd6be", diffRemove: "#ff757f",
		}),
		derive("catppuccin", false, base{ // mocha
			bg: "#1e1e2e", panel: "#181825", element: "#313244",
			text: "#cdd6f4", muted: "#9399b2",
			primary: "#89b4fa", secondary: "#cba6f7", accent: "#f5c2e7",
			border: "#45475a", borderActive: "#585b70",
			success: "#a6e3a1", warning: "#f9e2af", err: "#f38ba8", info: "#94e2d5",
			diffAdd: "#a6e3a1", diffRemove: "#f38ba8",
		}),
		derive("catppuccin-latte", true, base{
			bg: "#eff1f5", panel: "#e6e9ef", element: "#dce0e8",
			text: "#4c4f69", muted: "#6c6f85",
			primary: "#1e66f5", secondary: "#8839ef", accent: "#ea76cb",
			border: "#bcc0cc", borderActive: "#9ca0b0",
			success: "#40a02b", warning: "#df8e1d", err: "#d20f39", info: "#179299",
			diffAdd: "#40a02b", diffRemove: "#d20f39",
		}),
		derive("gruvbox", false, base{
			bg: "#282828", panel: "#3c3836", element: "#504945",
			text: "#ebdbb2", muted: "#a89984",
			primary: "#83a598", secondary: "#d3869b", accent: "#8ec07c",
			border: "#665c54", borderActive: "#a89984",
			success: "#b8bb26", warning: "#fe8019", err: "#fb4934", info: "#fabd2f",
			diffAdd: "#b8bb26", diffRemove: "#fb4934",
		}),
		derive("nord", false, base{
			bg: "#2e3440", panel: "#3b4252", element: "#434c5e",
			text: "#eceff4", muted: "#a0a8b7",
			primary: "#88c0d0", secondary: "#81a1c1", accent: "#8fbcbb",
			border: "#4c566a", borderActive: "#81a1c1",
			success: "#a3be8c", warning: "#d08770", err: "#bf616a", info: "#88c0d0",
			diffAdd: "#a3be8c", diffRemove: "#bf616a",
		}),
		derive("dracula", false, base{
			bg: "#282a36", panel: "#21222c", element: "#44475a",
			text: "#f8f8f2", muted: "#9aa5ce",
			primary: "#bd93f9", secondary: "#ff79c6", accent: "#8be9fd",
			border: "#44475a", borderActive: "#bd93f9",
			success: "#50fa7b", warning: "#f1fa8c", err: "#ff5555", info: "#ffb86c",
			diffAdd: "#50fa7b", diffRemove: "#ff5555",
		}),
		derive("one-dark", false, base{
			bg: "#282c34", panel: "#21252b", element: "#353b45",
			text: "#abb2bf", muted: "#7f848e",
			primary: "#61afef", secondary: "#c678dd", accent: "#56b6c2",
			border: "#393f4a", borderActive: "#61afef",
			success: "#98c379", warning: "#e5c07b", err: "#e06c75", info: "#d19a66",
			diffAdd: "#98c379", diffRemove: "#e06c75",
		}),
		derive("everforest", false, base{
			bg: "#2d353b", panel: "#343f44", element: "#3d484d",
			text: "#d3c6aa", muted: "#9da9a0",
			primary: "#a7c080", secondary: "#7fbbb3", accent: "#d699b6",
			border: "#859289", borderActive: "#9da9a0",
			success: "#a7c080", warning: "#e69875", err: "#e67e80", info: "#83c092",
			diffAdd: "#a7c080", diffRemove: "#e67e80",
		}),
		derive("kanagawa", false, base{
			bg: "#1f1f28", panel: "#2a2a37", element: "#363646",
			text: "#dcd7ba", muted: "#938aa9",
			primary: "#7e9cd8", secondary: "#957fb8", accent: "#d27e99",
			border: "#54546d", borderActive: "#c38d9d",
			success: "#98bb6c", warning: "#e6c384", err: "#e82424", info: "#7fb4ca",
			diffAdd: "#98bb6c", diffRemove: "#e46876",
		}),
		derive("ayu", false, base{ // ayu dark
			bg: "#0b0e14", panel: "#0f131a", element: "#131721",
			text: "#bfbdb6", muted: "#6c7380",
			primary: "#59c2ff", secondary: "#d2a6ff", accent: "#e6b450",
			border: "#565b66", borderActive: "#6c7380",
			success: "#7fd962", warning: "#e6b673", err: "#d95757", info: "#39bae6",
			diffAdd: "#7fd962", diffRemove: "#f26d78",
		}),
		derive("rose-pine", false, base{
			bg: "#191724", panel: "#1f1d2e", element: "#26233a",
			text: "#e0def4", muted: "#908caa",
			primary: "#9ccfd8", secondary: "#c4a7e7", accent: "#ebbcba",
			border: "#403d52", borderActive: "#9ccfd8",
			success: "#31748f", warning: "#f6c177", err: "#eb6f92", info: "#9ccfd8",
			diffAdd: "#9ccfd8", diffRemove: "#eb6f92",
		}),
		derive("solarized-dark", false, base{
			bg: "#002b36", panel: "#073642", element: "#0b4452",
			text: "#93a1a1", muted: "#839496",
			primary: "#268bd2", secondary: "#6c71c4", accent: "#2aa198",
			border: "#586e75", borderActive: "#268bd2",
			success: "#859900", warning: "#b58900", err: "#dc322f", info: "#2aa198",
			diffAdd: "#859900", diffRemove: "#dc322f",
		}),
		derive("solarized-light", true, base{
			bg: "#fdf6e3", panel: "#eee8d5", element: "#e4ddc8",
			text: "#073642", muted: "#586e75",
			primary: "#268bd2", secondary: "#6c71c4", accent: "#2aa198",
			border: "#93a1a1", borderActive: "#268bd2",
			success: "#859900", warning: "#b58900", err: "#dc322f", info: "#2aa198",
			diffAdd: "#859900", diffRemove: "#dc322f",
		}),
		derive("monokai", false, base{
			bg: "#272822", panel: "#1e1f1c", element: "#3e3d32",
			text: "#f8f8f2", muted: "#a59f85",
			primary: "#66d9ef", secondary: "#ae81ff", accent: "#a6e22e",
			border: "#3e3d32", borderActive: "#66d9ef",
			success: "#a6e22e", warning: "#e6db74", err: "#f92672", info: "#fd971f",
			diffAdd: "#a6e22e", diffRemove: "#f92672",
		}),
		derive("matrix", false, base{
			bg: "#0a0e0a", panel: "#0e130d", element: "#141c12",
			text: "#62ff94", muted: "#8ca391",
			primary: "#2eff6a", secondary: "#00efff", accent: "#c770ff",
			border: "#1e2a1b", borderActive: "#2eff6a",
			success: "#62ff94", warning: "#e6ff57", err: "#ff4b4b", info: "#30b3ff",
			diffAdd: "#1cc24b", diffRemove: "#ff4b4b",
		}),
		derive("flexoki", false, base{
			bg: "#100f0f", panel: "#1c1b1a", element: "#282726",
			text: "#cecdc3", muted: "#878580",
			primary: "#da702c", secondary: "#4385be", accent: "#8b7ec8",
			border: "#575653", borderActive: "#6f6e69",
			success: "#879a39", warning: "#d0a215", err: "#d14d41", info: "#3aa99f",
			diffAdd: "#879a39", diffRemove: "#d14d41",
		}),
	}
}
