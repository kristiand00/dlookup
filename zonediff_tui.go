package main

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"dlookup/lookup"
)

// zoneDiffName is the lookup-list entry (and tab lookupType) of the zone diff
// screen. It is not a lookup.Provider; the tab handles it itself.
const zoneDiffName = "Zone Diff"

// zoneDiffProgressInterval is how often the loading view polls diff progress.
const zoneDiffProgressInterval = 150 * time.Millisecond

// diffZoneFunc runs a zone diff; replaced in tests.
var diffZoneFunc = lookup.DiffZone

// Zone diff form fields, in tab order.
const (
	zdFieldNew = iota
	zdFieldOld
	zdFieldExtra
	zdFieldTTL
	zdFieldAXFR
	zdFieldCount
)

// zoneDiffForm holds the zone diff form inputs. It lives on the tab, so the last
// values are kept for quick re-runs.
type zoneDiffForm struct {
	newServer  textinput.Model
	oldServer  textinput.Model
	extraNames textinput.Model
	compareTTL bool
	tryAXFR    bool
	focus      int
}

func newZoneDiffForm() zoneDiffForm {
	mk := func(placeholder string, limit int) textinput.Model {
		ti := textinput.New()
		ti.Placeholder = placeholder
		ti.CharLimit = limit
		ti.Width = 36
		ti.Prompt = ""
		return ti
	}
	return zoneDiffForm{
		newServer:  mk("new server IP or hostname", 128),
		oldServer:  mk("authoritative NS (auto)", 128),
		extraNames: mk("e.g. www, mail, _dmarc", 512),
		compareTTL: false,
		tryAXFR:    true,
	}
}

// input returns the text input for field f, or nil for checkbox fields.
func (f *zoneDiffForm) input(field int) *textinput.Model {
	switch field {
	case zdFieldNew:
		return &f.newServer
	case zdFieldOld:
		return &f.oldServer
	case zdFieldExtra:
		return &f.extraNames
	}
	return nil
}

func (f *zoneDiffForm) blur() {
	f.newServer.Blur()
	f.oldServer.Blur()
	f.extraNames.Blur()
}

// setFocus moves focus to field (wrapping) and returns the cursor blink command.
func (f *zoneDiffForm) setFocus(field int) tea.Cmd {
	f.focus = (field%zdFieldCount + zdFieldCount) % zdFieldCount
	f.blur()
	if in := f.input(f.focus); in != nil {
		in.CursorEnd()
		return in.Focus()
	}
	return nil
}

// zoneDiffProgress is written by DiffZone's Progress callback (from any
// goroutine) and polled by the tab.
type zoneDiffProgress struct {
	done, total atomic.Int64
}

// zoneDiffState is the tab's zone diff state.
type zoneDiffState struct {
	form        zoneDiffForm
	opts        lookup.ZoneDiffOptions // options of the current/last run
	result      *lookup.ZoneDiffResult
	showMatches bool
	filter      lookup.DiffStatus // only meaningful when filtered
	filtered    bool
	progress    *zoneDiffProgress
}

// zoneDiffResultMsg carries a finished zone diff back to tab tabId.
type zoneDiffResultMsg struct {
	tabId  int
	seq    int
	result *lookup.ZoneDiffResult
}

// zoneDiffProgressMsg asks tab tabId to refresh run seq's progress.
type zoneDiffProgressMsg struct {
	tabId int
	seq   int
}

func (m zoneDiffResultMsg) targetTab() int   { return m.tabId }
func (m zoneDiffProgressMsg) targetTab() int { return m.tabId }

// isZoneDiff reports whether the tab's current lookup is a zone diff.
func (m tabModel) isZoneDiff() bool { return m.lookupType == zoneDiffName }

// openZoneDiffForm opens the zone diff form as a modal over the current state,
// keeping the values of the previous run.
func (m *tabModel) openZoneDiffForm() tea.Cmd {
	m.lastState = m.state
	m.state = stateZoneDiffForm
	m.inputErr = ""
	m.setSize(m.width, m.height)
	return m.zd.form.setFocus(zdFieldNew)
}

// parseExtraNames splits a comma (or whitespace) separated list of names.
func parseExtraNames(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// zoneDiffOptionsFromForm validates the form and builds the run options.
func (m tabModel) zoneDiffOptionsFromForm() (lookup.ZoneDiffOptions, error) {
	f := m.zd.form
	if m.domain == "" || net.ParseIP(m.domain) != nil {
		return lookup.ZoneDiffOptions{}, fmt.Errorf("zone diff needs a domain name, not %q", m.domain)
	}
	newServer := strings.TrimSpace(f.newServer.Value())
	if newServer == "" {
		return lookup.ZoneDiffOptions{}, fmt.Errorf("new server is required")
	}
	if err := lookup.ValidateServer(newServer); err != nil {
		return lookup.ZoneDiffOptions{}, fmt.Errorf("new server: %w", err)
	}
	oldServer := strings.TrimSpace(f.oldServer.Value())
	if oldServer != "" {
		if err := lookup.ValidateServer(oldServer); err != nil {
			return lookup.ZoneDiffOptions{}, fmt.Errorf("old server: %w", err)
		}
	}
	return lookup.ZoneDiffOptions{
		Domain:     m.domain,
		OldServer:  oldServer,
		NewServer:  newServer,
		ExtraNames: parseExtraNames(f.extraNames.Value()),
		CompareTTL: f.compareTTL,
		TryAXFR:    f.tryAXFR,
	}, nil
}

// handleZoneDiffFormKey handles keys while the zone diff form is open.
func (m *tabModel) handleZoneDiffFormKey(msg tea.KeyMsg, k Keybindings) tea.Cmd {
	f := &m.zd.form
	key := msg.String()
	switch {
	case key == k.Confirm:
		opts, err := m.zoneDiffOptionsFromForm()
		if err != nil {
			m.inputErr = err.Error()
			return nil
		}
		f.blur()
		m.inputErr = ""
		m.stopWatch()
		m.lookupType = zoneDiffName
		m.zd.opts = opts
		m.state = stateLoading
		m.err = nil
		m.result = ""
		m.hasResult = false
		m.viewport.GotoTop()
		m.setSize(m.width, m.height)
		return m.startZoneDiff()
	case isBackKey(msg, k, true):
		m.closeModal()
		return nil
	case key == "tab" || key == "down":
		m.inputErr = ""
		return f.setFocus(f.focus + 1)
	case key == "shift+tab" || key == "up":
		m.inputErr = ""
		return f.setFocus(f.focus - 1)
	}
	in := f.input(f.focus)
	if in == nil {
		if msg.Type == tea.KeySpace || key == " " || key == "x" {
			if f.focus == zdFieldTTL {
				f.compareTTL = !f.compareTTL
			} else {
				f.tryAXFR = !f.tryAXFR
			}
		}
		return nil
	}
	var cmd tea.Cmd
	*in, cmd = in.Update(msg)
	m.inputErr = ""
	return cmd
}

// zoneDiffLoadingMsg is the loading line for the current run.
func (m tabModel) zoneDiffLoadingMsg() string {
	s := fmt.Sprintf("Diffing %s against %s...", m.domain, m.zd.opts.NewServer)
	if p := m.zd.progress; p != nil {
		if total := p.total.Load(); total > 0 {
			s += fmt.Sprintf(" Checked %d/%d records", p.done.Load(), total)
		}
	}
	return s
}

// startZoneDiff starts a zone diff run with m.zd.opts, superseding any
// in-flight run, plus a progress polling chain.
func (m *tabModel) startZoneDiff() tea.Cmd {
	if m.lookupCancel != nil {
		m.lookupCancel()
	}
	m.lookupSeq++
	ctx, cancel := context.WithCancel(m.ctx)
	m.lookupCancel = cancel
	m.inFlight = true
	m.zd.progress = &zoneDiffProgress{}
	m.loadingMsg = m.zoneDiffLoadingMsg()
	return tea.Batch(
		zoneDiffCmd(ctx, m.id, m.lookupSeq, m.zd.opts, m.zd.progress),
		m.zoneDiffProgressTick(),
	)
}

func (m tabModel) zoneDiffProgressTick() tea.Cmd {
	id, seq := m.id, m.lookupSeq
	return tickAfter(zoneDiffProgressInterval, func(time.Time) tea.Msg { return zoneDiffProgressMsg{tabId: id, seq: seq} })
}

// zoneDiffCmd runs one zone diff. opts is a copy; progress is only touched
// atomically. It holds one lookupSem slot for the whole run.
func zoneDiffCmd(ctx context.Context, id, seq int, opts lookup.ZoneDiffOptions, progress *zoneDiffProgress) tea.Cmd {
	opts.ExtraNames = append([]string(nil), opts.ExtraNames...)
	return func() tea.Msg {
		select {
		case lookupSem <- struct{}{}:
		case <-ctx.Done():
			return errorMsg{tabId: id, seq: seq, err: ctx.Err()}
		}
		defer func() { <-lookupSem }()
		opts.Progress = func(done, total int) {
			progress.total.Store(int64(total))
			progress.done.Store(int64(done))
		}
		res, err := diffZoneFunc(ctx, opts)
		if err != nil {
			return errorMsg{tabId: id, seq: seq, err: err}
		}
		if res == nil {
			return errorMsg{tabId: id, seq: seq, err: fmt.Errorf("zone diff returned no result")}
		}
		return zoneDiffResultMsg{tabId: id, seq: seq, result: res}
	}
}

// handleZoneDiffMsg handles zone diff messages; ok is false for other messages.
func (m *tabModel) handleZoneDiffMsg(msg tea.Msg) (cmd tea.Cmd, ok bool) {
	switch msg := msg.(type) {
	case zoneDiffProgressMsg:
		if msg.tabId != m.id || msg.seq != m.lookupSeq || !m.inFlight {
			return nil, true // run finished or superseded: chain ends
		}
		m.loadingMsg = m.zoneDiffLoadingMsg()
		return m.zoneDiffProgressTick(), true
	case zoneDiffResultMsg:
		if msg.tabId != m.id || msg.seq != m.lookupSeq {
			return nil, true
		}
		m.inFlight = false
		m.lookupCancel = nil
		m.zd.result = msg.result
		m.zd.filtered = false
		m.result = ""
		m.hasResult = true
		m.err = nil
		m.loadingMsg = ""
		m.lastUpdated = now()
		m.setBaseState(stateViewResults)
		m.setSize(m.width, m.height)
		m.renderContent()
		m.viewport.GotoTop()
		return nil, true
	}
	return nil, false
}

// zoneDiffFilterKeys maps number keys to status filters ("0" clears).
var zoneDiffFilterKeys = map[string]lookup.DiffStatus{
	"1": lookup.DiffChanged,
	"2": lookup.DiffMissing,
	"3": lookup.DiffExtra,
	"4": lookup.DiffError,
	"5": lookup.DiffMatch,
}

// handleZoneDiffResultKey handles zone-diff-only keys in the results/error
// view. handled is false when the key is not one of them.
func (m *tabModel) handleZoneDiffResultKey(msg tea.KeyMsg, k Keybindings) (cmd tea.Cmd, handled bool) {
	key := msg.String()
	switch {
	case key == k.Confirm || key == "r":
		return m.openZoneDiffForm(), true
	case key == k.ToggleMatches:
		m.zd.showMatches = !m.zd.showMatches
		if !m.zd.showMatches && m.zd.filtered && m.zd.filter == lookup.DiffMatch {
			m.zd.filtered = false
		}
		m.renderContent()
		m.viewport.GotoTop()
		if m.zd.showMatches {
			return m.setStatus("Showing matching records"), true
		}
		return m.setStatus("Hiding matching records"), true
	case key == "0":
		m.zd.filtered = false
		m.renderContent()
		m.viewport.GotoTop()
		return nil, true
	}
	if st, ok := zoneDiffFilterKeys[key]; ok {
		if m.zd.filtered && m.zd.filter == st {
			m.zd.filtered = false
		} else {
			m.zd.filtered, m.zd.filter = true, st
		}
		m.renderContent()
		m.viewport.GotoTop()
		return nil, true
	}
	return nil, false
}

// goToSelect returns to the lookup list, stopping any run.
func (m *tabModel) goToSelect() tea.Cmd {
	m.stopWatch()
	m.cancelLookup()
	m.zd.form.blur()
	m.state = stateSelectLookup
	m.inputErr = ""
	m.loadingMsg = ""
	m.setSize(m.width, m.height)
	return nil
}

// zoneDiffStatusOrder is the display order of record groups.
var zoneDiffStatusOrder = []lookup.DiffStatus{lookup.DiffError, lookup.DiffMissing, lookup.DiffChanged, lookup.DiffExtra, lookup.DiffMatch}

func zoneDiffStatusRank(s lookup.DiffStatus) int {
	for i, o := range zoneDiffStatusOrder {
		if o == s {
			return i
		}
	}
	return len(zoneDiffStatusOrder)
}

func zoneDiffStatusStyle(s lookup.DiffStatus) lipgloss.Style {
	switch s {
	case lookup.DiffMatch:
		return zdMatchStyle
	case lookup.DiffChanged:
		return zdChangedStyle
	case lookup.DiffMissing:
		return zdMissingStyle
	case lookup.DiffExtra:
		return zdExtraStyle
	}
	return zdErrorStyle
}

func zoneDiffStatusSymbol(s lookup.DiffStatus) string {
	switch s {
	case lookup.DiffMatch:
		return "="
	case lookup.DiffChanged:
		return "~"
	case lookup.DiffMissing:
		return "-"
	case lookup.DiffExtra:
		return "+"
	}
	return "!"
}

// visibleZoneDiffRecords returns the records to show, grouped by status and
// sorted by name and type.
func (z zoneDiffState) visibleZoneDiffRecords() []lookup.RecordDiff {
	if z.result == nil {
		return nil
	}
	var out []lookup.RecordDiff
	for _, r := range z.result.Records {
		if z.filtered {
			if r.Status != z.filter {
				continue
			}
		} else if r.Status == lookup.DiffMatch && !z.showMatches {
			continue
		}
		out = append(out, r)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if ra, rb := zoneDiffStatusRank(a.Status), zoneDiffStatusRank(b.Status); ra != rb {
			return ra < rb
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Type < b.Type
	})
	return out
}

// zoneDiffSummary renders the colored "N match · N changed ..." counts.
func zoneDiffSummary(r *lookup.ZoneDiffResult) string {
	parts := make([]string, 0, 5)
	for _, s := range []lookup.DiffStatus{lookup.DiffMatch, lookup.DiffChanged, lookup.DiffMissing, lookup.DiffExtra, lookup.DiffError} {
		parts = append(parts, zoneDiffStatusStyle(s).Render(fmt.Sprintf("%d %s", r.Counts[s], s)))
	}
	return strings.Join(parts, helpDescStyle.Render(" · "))
}

// renderZoneDiff renders the zone diff result view.
func (m tabModel) renderZoneDiff() string {
	r := m.zd.result
	if r == nil {
		return "(no results)"
	}
	var b strings.Builder
	b.WriteString(resultHeaderStyle.Render("Zone Diff for " + r.Domain))
	b.WriteString("\n")
	label := func(s string) string { return zdLabelStyle.Render(fmt.Sprintf("%-12s", s)) }
	old := strings.Join(r.OldServers, ", ")
	if m.zd.opts.OldServer == "" {
		old += zdNoteStyle.Render(" (authoritative)")
	}
	fmt.Fprintf(&b, "%s%s\n", label("Old:"), old)
	fmt.Fprintf(&b, "%s%s\n", label("New:"), r.NewServer)
	if r.Enumeration != "" {
		fmt.Fprintf(&b, "%s%s\n", label("Enumerated:"), r.Enumeration)
	}
	fmt.Fprintf(&b, "%s%s\n", label("Summary:"), zoneDiffSummary(r))
	var view []string
	if m.zd.filtered {
		view = append(view, "only "+m.zd.filter.String())
	} else if m.zd.showMatches {
		view = append(view, "matches shown")
	} else {
		view = append(view, "matches hidden")
	}
	fmt.Fprintf(&b, "%s%s\n", label("View:"), zdNoteStyle.Render(strings.Join(view, ", ")))
	b.WriteString("\n")

	if !r.HasDifferences() {
		b.WriteString(zdBannerStyle.Render("✓ No differences — new server matches"))
		b.WriteString("\n\n")
	}

	recs := m.zd.visibleZoneDiffRecords()
	if len(recs) == 0 {
		b.WriteString(zdNoteStyle.Render("(no records to show)"))
		return b.String()
	}
	for i, rec := range recs {
		if i > 0 {
			b.WriteString("\n")
		}
		st := zoneDiffStatusStyle(rec.Status)
		b.WriteString(st.Render(fmt.Sprintf("%s %s %s", zoneDiffStatusSymbol(rec.Status), rec.Name, rec.Type)))
		b.WriteString(zdNoteStyle.Render("  [" + rec.Status.String() + "]"))
		if rec.Expected {
			b.WriteString(zdNoteStyle.Render(" [expected]"))
		}
		b.WriteString("\n")
		if rec.Status == lookup.DiffMatch {
			for _, v := range rec.Old {
				b.WriteString("    " + v + "\n")
			}
		} else {
			for _, v := range rec.Old {
				b.WriteString(diffRemoveStyle.Render("    - "+v) + "\n")
			}
			for _, v := range rec.New {
				b.WriteString(diffAddStyle.Render("    + "+v) + "\n")
			}
		}
		if rec.Err != "" {
			b.WriteString(zdErrorStyle.Render("    error: "+rec.Err) + "\n")
		}
		if rec.Note != "" {
			b.WriteString(zdNoteStyle.Render("    note: "+rec.Note) + "\n")
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

// zoneDiffPlain is the plain text of the zone diff result (export/copy).
func (m tabModel) zoneDiffPlain() string {
	if m.zd.result == nil {
		return "(no results)"
	}
	return lookup.FormatZoneDiff(m.zd.result, m.zd.showMatches)
}

// zoneDiffFormView renders the zone diff form modal.
func (m tabModel) zoneDiffFormView() string {
	f := m.zd.form
	row := func(field int, label, body string) string {
		marker := "  "
		ls := zdLabelStyle
		if f.focus == field {
			marker = focusedStyle.Render("> ")
			ls = focusedStyle
		}
		return marker + ls.Render(fmt.Sprintf("%-13s", label)) + body
	}
	check := func(field int, on bool, label string) string {
		box := "[ ]"
		if on {
			box = "[x]"
		}
		marker := "  "
		if f.focus == field {
			marker = focusedStyle.Render("> ")
			box = focusedStyle.Render(box)
		}
		return marker + box + " " + label
	}
	body := strings.Join([]string{
		row(zdFieldNew, "New server:", f.newServer.View()),
		row(zdFieldOld, "Old server:", f.oldServer.View()),
		row(zdFieldExtra, "Extra names:", f.extraNames.View()),
		check(zdFieldTTL, f.compareTTL, "Compare TTLs"),
		check(zdFieldAXFR, f.tryAXFR, "Try AXFR"),
	}, "\n")
	return m.modal(min(max(60, m.width/2), max(20, m.width-2)), colorCyan, "Zone diff for "+m.domain+"\n", body,
		"(tab/shift+tab move · space toggle · enter run · esc cancel)")
}
