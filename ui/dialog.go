package ui

import (
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
)

// FieldKind selects the control used for a Field.
type FieldKind int

const (
	FieldText     FieldKind = iota // single-line text input
	FieldSelect                    // dropdown of Options
	FieldCheckbox                  // [x] toggle
	FieldInfo                      // read-only text line (not focusable)
)

// Option is one choice of a FieldSelect.
type Option struct{ Label, Value string }

// Field is a form control in a Dialog.
type Field struct {
	Key, Label  string // Label may contain "&x": alt+x focuses the field
	Kind        FieldKind
	Value       string // text value or selected option Value (FieldInfo: the text)
	Placeholder string
	Options     []Option // FieldSelect
	Checked     bool     // FieldCheckbox
	Validate    func(string) error
	CharLimit   int
	Width       int // field box width in cells (0 = fill)
}

// Button is a dialog button. Label may contain "&x" (alt+x presses it).
type Button struct {
	Label, Action string
	Default       bool // enter triggers it when focus is not on a button
}

// DialogResult is returned by Dialog.Update when the dialog is finished.
type DialogResult struct {
	Action string            // button action, or "cancel" on esc
	Values map[string]string // per field Key; checkbox → "true"/"false"
}

// ActionCancel is the action reported when the dialog is dismissed with esc.
// Validation is skipped for it.
const ActionCancel = "cancel"

const (
	ddMaxVisible       = 8
	defaultDialogWidth = 56
)

// Dialog is a modal form with an MC-style double-line frame.
//
// Zone ids: ID+"-f-<i>" field row i, ID+"-fb-<i>" field box i, ID+"-b-<i>"
// button i, ID+"-o-<j>" option j (index into Options) of the open dropdown,
// ID+"-dd" the open dropdown box, ID+"-box" the whole dialog.
type Dialog struct {
	ID, Title string
	Fields    []Field
	Buttons   []Button
	Width     int // outer width; 0 = 56
	Theme     Theme
	Err       string // shown in the error style above the buttons
	Help      string // dim footer

	focus  int // index into focusables()
	inputs []textinput.Model

	ddOpen   bool
	ddField  int
	ddSel    int // index into filtered options
	ddOff    int
	ddFilter string
}

// NewDialog builds a dialog. Focus starts on the first focusable field.
func NewDialog(id, title string, fields []Field, buttons []Button, th Theme) Dialog {
	d := Dialog{ID: id, Title: title, Fields: append([]Field(nil), fields...), Buttons: buttons, Theme: th}
	d.inputs = make([]textinput.Model, len(d.Fields))
	for i, f := range d.Fields {
		if f.Kind != FieldText {
			continue
		}
		ti := textinput.New()
		ti.Prompt = ""
		ti.Placeholder = f.Placeholder
		if f.CharLimit > 0 {
			ti.CharLimit = f.CharLimit
		} else {
			ti.CharLimit = 0
		}
		ti.SetValue(f.Value)
		ti.CursorEnd()
		d.inputs[i] = ti
	}
	d.setFocus(0)
	return d
}

// Init starts the cursor blink of the focused text field.
func (d Dialog) Init() tea.Cmd {
	if fi := d.focusedField(); fi >= 0 && d.Fields[fi].Kind == FieldText {
		return textinput.Blink
	}
	return nil
}

// ---- focus bookkeeping ----

func (d Dialog) focusableFields() []int {
	var out []int
	for i, f := range d.Fields {
		if f.Kind != FieldInfo {
			out = append(out, i)
		}
	}
	return out
}

func (d Dialog) nFocus() int { return len(d.focusableFields()) + len(d.Buttons) }

// focusedField returns the focused field index or -1 if a button has focus.
func (d Dialog) focusedField() int {
	ff := d.focusableFields()
	if d.focus >= 0 && d.focus < len(ff) {
		return ff[d.focus]
	}
	return -1
}

// focusedButton returns the focused button index or -1.
func (d Dialog) focusedButton() int {
	b := d.focus - len(d.focusableFields())
	if b >= 0 && b < len(d.Buttons) {
		return b
	}
	return -1
}

func (d *Dialog) setFocus(i int) tea.Cmd {
	n := d.nFocus()
	if n == 0 {
		return nil
	}
	i = ((i % n) + n) % n
	if fi := d.focusedField(); fi >= 0 && d.Fields[fi].Kind == FieldText {
		d.inputs[fi].Blur()
	}
	d.focus = i
	if fi := d.focusedField(); fi >= 0 && d.Fields[fi].Kind == FieldText {
		return d.inputs[fi].Focus()
	}
	return nil
}

func (d *Dialog) focusFieldIndex(fi int) tea.Cmd {
	for k, idx := range d.focusableFields() {
		if idx == fi {
			return d.setFocus(k)
		}
	}
	return nil
}

func (d Dialog) fieldIndex(key string) int {
	for i, f := range d.Fields {
		if f.Key == key {
			return i
		}
	}
	return -1
}

// FocusField focuses the field with the given key.
func (d *Dialog) FocusField(key string) {
	if i := d.fieldIndex(key); i >= 0 {
		d.focusFieldIndex(i)
	}
}

// Focused returns the key of the focused field ("" when a button is focused).
func (d Dialog) Focused() string {
	if fi := d.focusedField(); fi >= 0 {
		return d.Fields[fi].Key
	}
	return ""
}

// DropdownOpen reports whether a select dropdown is open.
func (d Dialog) DropdownOpen() bool { return d.ddOpen }

// SetValue sets a field's value (checkbox: "true"/"false"; select: option Value).
func (d *Dialog) SetValue(key, value string) {
	i := d.fieldIndex(key)
	if i < 0 {
		return
	}
	switch d.Fields[i].Kind {
	case FieldText:
		d.inputs[i].SetValue(value)
		d.inputs[i].CursorEnd()
	case FieldCheckbox:
		d.Fields[i].Checked = value == "true"
	}
	d.Fields[i].Value = value
}

// Value returns a field's current value (checkbox: "true"/"false").
func (d *Dialog) Value(key string) string {
	i := d.fieldIndex(key)
	if i < 0 {
		return ""
	}
	return d.fieldValue(i)
}

func (d Dialog) fieldValue(i int) string {
	f := d.Fields[i]
	switch f.Kind {
	case FieldText:
		return d.inputs[i].Value()
	case FieldCheckbox:
		return strconv.FormatBool(f.Checked)
	}
	return f.Value
}

// Values returns all field values keyed by Field.Key.
func (d Dialog) Values() map[string]string {
	m := make(map[string]string, len(d.Fields))
	for i, f := range d.Fields {
		if f.Key != "" {
			m[f.Key] = d.fieldValue(i)
		}
	}
	return m
}

// ---- dropdown helpers ----

func (d Dialog) filtered(fi int) []int {
	var out []int
	q := strings.ToLower(d.ddFilter)
	for j, o := range d.Fields[fi].Options {
		if q == "" || strings.Contains(strings.ToLower(o.Label), q) || strings.Contains(strings.ToLower(o.Value), q) {
			out = append(out, j)
		}
	}
	return out
}

func (d *Dialog) openDropdown(fi int, filter string) {
	d.ddOpen = true
	d.ddField = fi
	d.ddFilter = filter
	d.ddOff = 0
	d.ddSel = 0
	if filter == "" {
		for k, j := range d.filtered(fi) {
			if d.Fields[fi].Options[j].Value == d.Fields[fi].Value {
				d.ddSel = k
			}
		}
	}
	d.ddEnsureVisible()
}

func (d *Dialog) closeDropdown() {
	d.ddOpen = false
	d.ddFilter = ""
}

func (d *Dialog) ddEnsureVisible() {
	n := len(d.filtered(d.ddField))
	vis := d.ddVisible()
	d.ddSel = clamp(d.ddSel, 0, n-1)
	if d.ddSel < d.ddOff {
		d.ddOff = d.ddSel
	}
	if d.ddSel >= d.ddOff+vis {
		d.ddOff = d.ddSel - vis + 1
	}
	d.ddOff = clamp(d.ddOff, 0, max(0, n-vis))
}

func (d *Dialog) chooseOption(j int) {
	fi := d.ddField
	d.Fields[fi].Value = d.Fields[fi].Options[j].Value
	d.closeDropdown()
}

// ---- submit ----

func (d *Dialog) submit(action string) (*DialogResult, tea.Cmd) {
	if action != ActionCancel {
		for i, f := range d.Fields {
			if f.Validate == nil || (f.Kind != FieldText && f.Kind != FieldSelect) {
				continue
			}
			if err := f.Validate(d.fieldValue(i)); err != nil {
				d.Err = err.Error()
				return nil, d.focusFieldIndex(i)
			}
		}
		d.Err = ""
	}
	return &DialogResult{Action: action, Values: d.Values()}, nil
}

func (d Dialog) defaultButton() int {
	for i, b := range d.Buttons {
		if b.Default {
			return i
		}
	}
	return -1
}

// ---- Update ----

// Update handles keys, mouse and blink messages. A non-nil result means the
// dialog is finished (the caller closes it). The app should route every
// message to the dialog while it is open (it is modal).
func (d Dialog) Update(msg tea.Msg) (Dialog, *DialogResult, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		return d.updateKey(msg)
	case tea.MouseMsg:
		return d.updateMouse(msg)
	}
	if fi := d.focusedField(); fi >= 0 && d.Fields[fi].Kind == FieldText {
		var cmd tea.Cmd
		d.inputs[fi], cmd = d.inputs[fi].Update(msg)
		return d, nil, cmd
	}
	return d, nil, nil
}

func (d Dialog) updateDropdownKey(k tea.KeyMsg) (Dialog, *DialogResult, tea.Cmd) {
	opts := d.filtered(d.ddField)
	vis := d.ddVisible()
	switch k.String() {
	case "esc":
		d.closeDropdown()
	case "up", "ctrl+p":
		d.ddSel--
	case "down", "ctrl+n":
		d.ddSel++
	case "home":
		d.ddSel = 0
	case "end":
		d.ddSel = len(opts) - 1
	case "pgup":
		d.ddSel -= vis
	case "pgdown":
		d.ddSel += vis
	case "enter", "tab":
		if d.ddSel >= 0 && d.ddSel < len(opts) {
			d.chooseOption(opts[d.ddSel])
		} else {
			d.closeDropdown()
		}
		return d, nil, nil
	case "backspace":
		if d.ddFilter != "" {
			r := []rune(d.ddFilter)
			d.ddFilter = string(r[:len(r)-1])
			d.ddSel, d.ddOff = 0, 0
		}
	case " ":
		if d.ddFilter == "" {
			if d.ddSel >= 0 && d.ddSel < len(opts) {
				d.chooseOption(opts[d.ddSel])
			}
			return d, nil, nil
		}
		d.ddFilter += " "
		d.ddSel, d.ddOff = 0, 0
	default:
		if k.Type == tea.KeyRunes && !k.Alt {
			d.ddFilter += string(k.Runes)
			d.ddSel, d.ddOff = 0, 0
		}
	}
	d.ddEnsureVisible()
	return d, nil, nil
}

func (d Dialog) updateKey(k tea.KeyMsg) (Dialog, *DialogResult, tea.Cmd) {
	if d.ddOpen {
		return d.updateDropdownKey(k)
	}
	// alt+hotkey on buttons / field labels.
	if r, ok := altRune(k); ok {
		for i, b := range d.Buttons {
			if _, _, h := ParseHotkey(b.Label); h == r {
				cmd := d.setFocus(len(d.focusableFields()) + i)
				res, c2 := d.submit(b.Action)
				return d, res, tea.Batch(cmd, c2)
			}
		}
		for i, f := range d.Fields {
			if _, _, h := ParseHotkey(f.Label); h == r && f.Kind != FieldInfo {
				return d, nil, d.focusFieldIndex(i)
			}
		}
	}
	fi, bi := d.focusedField(), d.focusedButton()
	switch k.String() {
	case "tab", "down":
		return d, nil, d.setFocus(d.focus + 1)
	case "shift+tab", "up":
		return d, nil, d.setFocus(d.focus - 1)
	case "left":
		if bi >= 0 {
			return d, nil, d.setFocus(d.focus - 1)
		}
	case "right":
		if bi >= 0 {
			return d, nil, d.setFocus(d.focus + 1)
		}
	case "esc":
		res, cmd := d.submit(ActionCancel)
		return d, res, cmd
	case "enter":
		switch {
		case bi >= 0:
			res, cmd := d.submit(d.Buttons[bi].Action)
			return d, res, cmd
		case fi >= 0 && d.Fields[fi].Kind == FieldSelect:
			d.openDropdown(fi, "")
			return d, nil, nil
		default:
			if db := d.defaultButton(); db >= 0 {
				res, cmd := d.submit(d.Buttons[db].Action)
				return d, res, cmd
			}
			return d, nil, nil
		}
	case " ":
		switch {
		case bi >= 0:
			res, cmd := d.submit(d.Buttons[bi].Action)
			return d, res, cmd
		case fi >= 0 && d.Fields[fi].Kind == FieldCheckbox:
			d.Fields[fi].Checked = !d.Fields[fi].Checked
			return d, nil, nil
		case fi >= 0 && d.Fields[fi].Kind == FieldSelect:
			d.openDropdown(fi, "")
			return d, nil, nil
		}
	}
	if fi >= 0 {
		switch d.Fields[fi].Kind {
		case FieldText:
			var cmd tea.Cmd
			d.inputs[fi], cmd = d.inputs[fi].Update(k)
			return d, nil, cmd
		case FieldSelect:
			if k.Type == tea.KeyRunes && !k.Alt && len(d.Fields[fi].Options) > 0 {
				d.openDropdown(fi, string(k.Runes))
			}
		}
	}
	return d, nil, nil
}

func (d Dialog) optID(j int) string    { return d.ID + "-o-" + strconv.Itoa(j) }
func (d Dialog) rowID(i int) string    { return d.ID + "-f-" + strconv.Itoa(i) }
func (d Dialog) boxID(i int) string    { return d.ID + "-fb-" + strconv.Itoa(i) }
func (d Dialog) buttonID(i int) string { return d.ID + "-b-" + strconv.Itoa(i) }

func (d Dialog) updateMouse(ev tea.MouseMsg) (Dialog, *DialogResult, tea.Cmd) {
	if d.ddOpen {
		inDD := Hit(d.ID+"-dd", ev)
		switch {
		case inDD && IsWheelUp(ev):
			d.ddOff = max(0, d.ddOff-1)
			return d, nil, nil
		case inDD && IsWheelDown(ev):
			n := len(d.filtered(d.ddField))
			d.ddOff = clamp(d.ddOff+1, 0, max(0, n-d.ddVisible()))
			return d, nil, nil
		case inDD && (IsLeftClick(ev) || IsMotion(ev)):
			for k, j := range d.filtered(d.ddField) {
				if Hit(d.optID(j), ev) {
					if IsLeftClick(ev) {
						d.chooseOption(j)
					} else {
						d.ddSel = k
					}
					return d, nil, nil
				}
			}
			return d, nil, nil
		case IsLeftClick(ev):
			// Click outside the dropdown closes it; a click on the select's
			// own box should not immediately re-open it.
			fi := d.ddField
			d.closeDropdown()
			if Hit(d.boxID(fi), ev) || Hit(d.rowID(fi), ev) {
				return d, nil, nil
			}
		default:
			return d, nil, nil
		}
	}
	if !IsLeftClick(ev) {
		return d, nil, nil
	}
	for i, b := range d.Buttons {
		if Hit(d.buttonID(i), ev) {
			cmd := d.setFocus(len(d.focusableFields()) + i)
			res, c2 := d.submit(b.Action)
			return d, res, tea.Batch(cmd, c2)
		}
	}
	for i, f := range d.Fields {
		if f.Kind == FieldInfo || !Hit(d.rowID(i), ev) {
			continue
		}
		cmd := d.focusFieldIndex(i)
		switch f.Kind {
		case FieldCheckbox:
			d.Fields[i].Checked = !d.Fields[i].Checked
		case FieldSelect:
			d.openDropdown(i, "")
		case FieldText:
			if x, _, w, _, ok := ZonePos(d.boxID(i)); ok && ev.X >= x && ev.X < x+w {
				v := []rune(d.inputs[i].Value())
				if ansi.StringWidth(string(v)) < w-1 {
					// Value fits: place cursor at the clicked cell.
					col, pos := 0, 0
					for pos < len(v) && col+ansi.StringWidth(string(v[pos])) <= ev.X-x {
						col += ansi.StringWidth(string(v[pos]))
						pos++
					}
					d.inputs[i].SetCursor(pos)
				}
			}
		}
		return d, nil, cmd
	}
	return d, nil, nil
}

// ---- layout & View ----

type dlgRowKind int

const (
	rowBlank dlgRowKind = iota
	rowField
	rowText // pre-rendered text (error / help)
	rowButtons
)

type dlgRow struct {
	kind  dlgRowKind
	field int
	text  string
	err   bool
}

func (d Dialog) outerWidth() int {
	if d.Width > 0 {
		return max(d.Width, 16)
	}
	return defaultDialogWidth
}

// contentWidth is the width between the 2-cell paddings inside the frame.
func (d Dialog) contentWidth() int { return d.outerWidth() - 2 - 4 }

func (d Dialog) labelWidth() int {
	w := 0
	for _, f := range d.Fields {
		if f.Kind == FieldCheckbox || (f.Kind == FieldInfo && f.Label == "") {
			continue
		}
		t, _, _ := ParseHotkey(f.Label)
		w = max(w, ansi.StringWidth(t))
	}
	if w > 0 {
		w++ // gap
	}
	return min(w, d.contentWidth()/2)
}

func (d Dialog) fieldBoxWidth(f Field) int {
	avail := d.contentWidth() - d.labelWidth()
	if f.Width > 0 {
		return min(f.Width, avail)
	}
	return avail
}

func (d Dialog) rows() []dlgRow {
	cw := d.contentWidth()
	rows := []dlgRow{{kind: rowBlank}}
	for i := range d.Fields {
		rows = append(rows, dlgRow{kind: rowField, field: i})
	}
	rows = append(rows, dlgRow{kind: rowBlank})
	if d.Err != "" {
		for _, l := range strings.Split(ansi.Wrap(d.Err, cw, ""), "\n") {
			rows = append(rows, dlgRow{kind: rowText, text: l, err: true})
		}
	}
	if len(d.Buttons) > 0 {
		rows = append(rows, dlgRow{kind: rowButtons})
	}
	if d.Help != "" {
		for _, l := range strings.Split(ansi.Wrap(d.Help, cw, ""), "\n") {
			rows = append(rows, dlgRow{kind: rowText, text: l})
		}
	}
	return rows
}

// fieldLine returns the line index (0 = top border) of field fi.
func (d Dialog) fieldLine(fi int) int {
	for k, r := range d.rows() {
		if r.kind == rowField && r.field == fi {
			return k + 1
		}
	}
	return 0
}

func (d Dialog) ddVisible() int {
	return min(max(1, len(d.filtered(d.ddField))), ddMaxVisible)
}

// box renders the frame and contents without the select dropdown. extra
// blank rows are inserted above the bottom border.
func (d Dialog) box(extra int) string {
	th := d.Theme
	ow := d.outerWidth()
	iw := ow - 2
	cw := d.contentWidth()
	lw := d.labelWidth()
	bs := th.DialogBorder
	body := th.Dialog
	fi, bi := d.focusedField(), d.focusedButton()

	// Top border with centered title: ╔═══[ Title ]═══╗
	title := truncPlain(d.Title, max(0, iw-6))
	var top string
	if title != "" {
		tw := ansi.StringWidth(title) + 4 // "[ " + title + " ]"
		l := (iw - tw) / 2
		r := iw - tw - l
		top = bs.Render("╔"+strings.Repeat("═", l)+"[ ") + th.DialogTitle.Render(title) + bs.Render(" ]"+strings.Repeat("═", r)+"╗")
	} else {
		top = bs.Render("╔" + strings.Repeat("═", iw) + "╗")
	}
	lines := []string{top}
	wrap := func(content string) string {
		return bs.Render("║") + body.Render("  ") + padRight(content, cw, body) + body.Render("  ") + bs.Render("║")
	}
	for _, r := range d.rows() {
		switch r.kind {
		case rowBlank:
			lines = append(lines, wrap(""))
		case rowText:
			st := th.Help
			if r.err {
				st = th.Error
			}
			lines = append(lines, wrap(st.Render(r.text)))
		case rowButtons:
			lines = append(lines, wrap(d.buttonsView(cw, bi)))
		case rowField:
			lines = append(lines, wrap(d.fieldView(r.field, lw, fi == r.field)))
		}
	}
	for range extra {
		lines = append(lines, wrap(""))
	}
	lines = append(lines, bs.Render("╚"+strings.Repeat("═", iw)+"╝"))
	return strings.Join(lines, "\n")
}

// ddPos returns the open dropdown's top-left relative to the dialog's.
func (d Dialog) ddPos() (x, y int) {
	return 1 + 2 + d.labelWidth(), d.fieldLine(d.ddField) + 1
}

// Size returns the dialog's outer size (without shadow and dropdown).
func (d Dialog) Size() (w, h int) { return d.outerWidth(), len(d.rows()) + 2 }

// View renders the boxed dialog (no shadow; use OverlayShadow). If a select
// dropdown is open it is drawn inside the box, and the box temporarily grows
// downward when the list would not fit. Prefer Render, which lets the
// dropdown overhang the dialog instead.
func (d Dialog) View() string {
	if !d.ddOpen {
		return Mark(d.ID+"-box", d.box(0))
	}
	dd := d.dropdownView()
	x, y := d.ddPos()
	_, h := d.Size()
	need := y + strings.Count(dd, "\n") + 1 + 1 // + bottom border
	out := d.box(max(0, need-h))
	return Mark(d.ID+"-box", Overlay(out, dd, x, y))
}

// Render draws the dialog centered in a width×height screen bg, with a drop
// shadow; an open dropdown is drawn on top and may overhang the dialog (it
// flips above the field when there is no room below). This is the
// recommended way to show a dialog.
func (d Dialog) Render(bg string, width, height int) string {
	box := Mark(d.ID+"-box", d.box(0))
	bx, by := CenterPos(box, width, height)
	return d.RenderAt(bg, bx, by, height)
}

// RenderAt is Render with an explicit top-left position for the dialog.
func (d Dialog) RenderAt(bg string, bx, by, height int) string {
	box := Mark(d.ID+"-box", d.box(0))
	out := OverlayShadowStyle(bg, box, bx, by, d.Theme.Shadow)
	if d.ddOpen {
		dd := d.dropdownView()
		ddh := strings.Count(dd, "\n") + 1
		x, y := d.ddPos()
		x += bx
		y += by
		if y+ddh > height && y-1-ddh >= 0 {
			y = y - 1 - ddh // flip above the field
		}
		out = Overlay(out, dd, x, y)
	}
	return out
}

func (d Dialog) fieldView(i, lw int, focused bool) string {
	th := d.Theme
	f := d.Fields[i]
	body := th.Dialog
	text, hidx, _ := ParseHotkey(f.Label)
	ls := th.Label
	if focused {
		ls = th.LabelFocused
	}
	label := ""
	if lw > 0 {
		label = padRight(renderHot(truncPlain(text, lw-1), hidx, ls, ls.Underline(true)), lw, body)
	}
	fw := d.fieldBoxWidth(f)
	fs := th.Field
	if focused {
		fs = th.FieldFocused
	}
	var box string
	switch f.Kind {
	case FieldInfo:
		if f.Label == "" {
			return th.Info.Render(truncPlain(f.Value, d.contentWidth()))
		}
		return label + th.Info.Render(truncPlain(f.Value, fw))
	case FieldCheckbox:
		mark := "[ ] "
		cs := th.CheckboxOff
		if f.Checked {
			mark = "[x] "
			cs = th.CheckboxOn
		}
		if focused {
			cs = th.CheckboxFocused
		}
		ind := ""
		if lw > 0 {
			ind = body.Render(strings.Repeat(" ", lw))
		}
		box = cs.Render(mark) + renderHot(truncPlain(text, fw-4), hidx, ls, ls.Underline(true))
		return Mark(d.rowID(i), ind+Mark(d.boxID(i), box))
	case FieldSelect:
		cur := f.Value
		for _, o := range f.Options {
			if o.Value == f.Value {
				cur = o.Label
				break
			}
		}
		arrow := " ▾ "
		if d.ddOpen && d.ddField == i {
			arrow = " ▴ "
		}
		inner := fw - ansi.StringWidth(arrow) - 1
		if cur == "" {
			ps := th.Placeholder
			if focused {
				ps = th.PlaceholderFocused
			}
			box = fs.Render(" ") + ps.Render(fitPlain(f.Placeholder, max(0, inner)))
		} else {
			box = fs.Render(" " + fitPlain(cur, max(0, inner)))
		}
		box += fs.Render(arrow)
	case FieldText:
		ti := d.inputs[i]
		ti.TextStyle = fs
		ti.PromptStyle = fs
		ti.PlaceholderStyle = th.Placeholder
		if focused {
			ti.PlaceholderStyle = th.PlaceholderFocused
		}
		ti.CompletionStyle = ti.PlaceholderStyle
		ti.Cursor.Style = th.Cursor
		ti.Cursor.TextStyle = fs
		ti.Width = max(1, fw-2)
		box = fs.Render(" ") + padRight(ti.View(), fw-1, fs)
	}
	box = padRight(box, fw, fs)
	return Mark(d.rowID(i), label+Mark(d.boxID(i), box))
}

func (d Dialog) buttonsView(cw, focused int) string {
	th := d.Theme
	body := th.Dialog
	var parts []string
	total := 0
	for i, b := range d.Buttons {
		text, idx, _ := ParseHotkey(b.Label)
		st := th.Button
		if i == focused {
			st = th.ButtonFocused
		}
		open, close := "[ ", " ]"
		if b.Default {
			open, close = "[< ", " >]"
		}
		s := st.Render(open) + renderHot(text, idx, st, st.Foreground(th.DialogTitle.GetForeground()).Underline(true)) + st.Render(close)
		if i == focused {
			s = st.Render(open) + renderHot(text, idx, st, st.Underline(true)) + st.Render(close)
		}
		total += ansi.StringWidth(open+text+close) + 2
		parts = append(parts, Mark(d.buttonID(i), s))
	}
	total -= 2
	sep := body.Render("  ")
	left := max(0, (cw-total)/2)
	return body.Render(strings.Repeat(" ", left)) + strings.Join(parts, sep)
}

func (d Dialog) dropdownView() string {
	th := d.Theme
	f := d.Fields[d.ddField]
	fw := d.fieldBoxWidth(f)
	iw := max(4, fw-2)
	opts := d.filtered(d.ddField)
	vis := d.ddVisible()
	bs := th.SelectList

	// Top border shows the type-ahead filter.
	var top string
	if d.ddFilter != "" {
		ft := truncPlain("/"+d.ddFilter, max(1, iw-2))
		top = "┌ " + ft + " " + strings.Repeat("─", max(0, iw-ansi.StringWidth(ft)-2)) + "┐"
	} else {
		top = "┌" + strings.Repeat("─", iw) + "┐"
	}
	lines := []string{bs.Render(top)}
	scroll := len(opts) > vis
	for r := 0; r < vis; r++ {
		k := d.ddOff + r
		cw := iw
		var row string
		if k < len(opts) {
			j := opts[k]
			st := th.SelectItem
			if k == d.ddSel {
				st = th.SelectItemActive
			}
			row = Mark(d.optID(j), st.Render(" "+fitPlain(f.Options[j].Label, cw-1)))
		} else if len(opts) == 0 && r == 0 {
			row = th.SelectItem.Render(fitPlain(" (no match)", cw))
		} else {
			row = th.SelectItem.Render(strings.Repeat(" ", cw))
		}
		right := "│"
		if scroll {
			switch {
			case r == 0 && d.ddOff > 0:
				right = "▲"
			case r == vis-1 && d.ddOff+vis < len(opts):
				right = "▼"
			}
		}
		lines = append(lines, bs.Render("│")+row+bs.Render(right))
	}
	lines = append(lines, bs.Render("└"+strings.Repeat("─", iw)+"┘"))
	return Mark(d.ID+"-dd", strings.Join(lines, "\n"))
}
