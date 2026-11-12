package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"dlookup/lookup"
	"dlookup/zonefile"
)

// zoneDiffName is the lookup-list entry (and tab lookupType) of the zone diff
// screen. It is not a lookup.Provider; the tab handles it itself.
const zoneDiffName = "Zone Diff"

// zoneDiffProgressInterval is how often the loading view polls diff progress.
const zoneDiffProgressInterval = 150 * time.Millisecond

// diffZoneFunc runs a zone diff; replaced in tests.
var diffZoneFunc = lookup.DiffZone

// Zone diff dialog sources ("oldsrc" / "newsrc" select values).
const (
	zdSrcAuth   = "auth"   // the domain's authoritative nameservers
	zdSrcServer = "server" // a given server
	zdSrcFile   = "file"   // a zone file (provider export)
)

// zoneDiffForm holds the zone diff dialog values. It lives on the tab, so the
// last values are kept for quick re-runs.
type zoneDiffForm struct {
	newServer  string
	oldServer  string
	oldSource  string // zdSrcAuth (default), zdSrcServer or zdSrcFile
	newSource  string // zdSrcServer (default), zdSrcFile or zdSrcAuth (live, with an old file)
	oldFile    string
	newFile    string
	extraNames string
	compareTTL bool
	tryAXFR    bool
	probe      bool
}

func newZoneDiffForm() zoneDiffForm {
	return zoneDiffForm{tryAXFR: true, oldSource: zdSrcAuth, newSource: zdSrcServer}
}

// sources returns the form's old and new source with defaults applied.
func (f zoneDiffForm) sources() (old, nw string) {
	old, nw = f.oldSource, f.newSource
	if old == "" {
		old = zdSrcAuth
		if strings.TrimSpace(f.oldServer) != "" {
			old = zdSrcServer
		}
	}
	if nw == "" {
		nw = zdSrcServer
	}
	return old, nw
}

// expandHomePath expands a leading "~/" to the home directory.
func expandHomePath(p string) string {
	p = strings.TrimSpace(p)
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(p, "~"))
		}
	}
	return p
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

// zoneDiffOptions validates a zone diff request and builds the run options,
// reading and parsing zone files. The domain may be empty when a zone file
// names its origin.
func zoneDiffOptions(domain string, f zoneDiffForm) (lookup.ZoneDiffOptions, error) {
	var opts lookup.ZoneDiffOptions
	oldSrc, newSrc := f.sources()
	domain = strings.TrimSpace(domain)
	if domain == "" && oldSrc != zdSrcFile && newSrc != zdSrcFile {
		return opts, fmt.Errorf("domain is required")
	}
	if domain != "" {
		if net.ParseIP(domain) != nil {
			return opts, fmt.Errorf("zone diff needs a domain name, not %q", domain)
		}
		if err := lookup.ValidateTarget(domain); err != nil {
			return opts, fmt.Errorf("domain: %w", err)
		}
	}

	switch oldSrc {
	case zdSrcServer:
		opts.OldServer = strings.TrimSpace(f.oldServer)
		if opts.OldServer == "" {
			return opts, fmt.Errorf("old server is required (or choose Authoritative servers)")
		}
		if err := lookup.ValidateServer(opts.OldServer); err != nil {
			return opts, fmt.Errorf("old server: %w", err)
		}
	case zdSrcFile:
		z, label, err := loadDialogZoneFile("old", f.oldFile, domain)
		if err != nil {
			return opts, err
		}
		opts.OldZone, opts.OldZoneLabel = z, label
	}
	switch newSrc {
	case zdSrcFile:
		z, label, err := loadDialogZoneFile("new", f.newFile, domain)
		if err != nil {
			return opts, err
		}
		opts.NewZone, opts.NewZoneLabel = z, label
	case zdSrcAuth:
		if oldSrc != zdSrcFile {
			return opts, fmt.Errorf("live authoritative servers as the new side need an old zone file")
		}
	default:
		opts.NewServer = strings.TrimSpace(f.newServer)
		if opts.NewServer == "" {
			return opts, fmt.Errorf("new server is required")
		}
		if err := lookup.ValidateServer(opts.NewServer); err != nil {
			return opts, fmt.Errorf("new server: %w", err)
		}
	}
	if domain == "" {
		for _, z := range []*zonefile.Zone{opts.OldZone, opts.NewZone} {
			if z != nil && z.Origin != "" && z.Origin != "." {
				domain = strings.TrimSuffix(z.Origin, ".")
				break
			}
		}
		if domain == "" {
			return opts, fmt.Errorf("domain is required (the zone file does not name its origin)")
		}
	}
	opts.Domain = domain
	opts.ExtraNames = parseExtraNames(f.extraNames)
	opts.CompareTTL = f.compareTTL
	opts.TryAXFR = f.tryAXFR
	opts.Probe = f.probe
	return opts, nil
}

// loadDialogZoneFile reads and parses the zone file at path (format
// detected; origin defaults to domain).
func loadDialogZoneFile(which, path, domain string) (*zonefile.Zone, string, error) {
	label := strings.TrimSpace(path)
	if label == "" {
		return nil, "", fmt.Errorf("%s zone file: enter a file path", which)
	}
	full := expandHomePath(label)
	if st, err := os.Stat(full); err != nil {
		return nil, "", fmt.Errorf("%s zone file: %w", which, err)
	} else if st.IsDir() {
		return nil, "", fmt.Errorf("%s zone file: %s is a directory", which, label)
	}
	z, err := loadZoneFile(full, "", domain)
	if err != nil {
		return nil, "", fmt.Errorf("%s zone file: %w", which, err)
	}
	return z, label, nil
}

// runZoneDiff starts a zone diff with opts in this tab, replacing whatever it
// showed.
func (m *tabModel) runZoneDiff(opts lookup.ZoneDiffOptions) tea.Cmd {
	m.stopWatch()
	m.domain = opts.Domain
	m.lookupType = zoneDiffName
	m.zd.opts = opts
	m.state = stateLoading
	m.err = nil
	m.result = ""
	m.hasResult = false
	m.viewport.GotoTop()
	return m.startZoneDiff()
}

// zoneDiffLoadingMsg is the loading line for the current run.
func (m tabModel) zoneDiffLoadingMsg() string {
	against := m.zd.opts.NewServer
	switch {
	case m.zd.opts.NewZone != nil:
		against = m.zd.opts.NewZoneLabel
	case against == "":
		against = "the live zone"
	}
	s := fmt.Sprintf("Diffing %s against %s...", m.domain, against)
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
		m.state = stateViewResults
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

// toggleMatches shows/hides matching records in the zone diff view.
func (m *tabModel) toggleMatches() tea.Cmd {
	m.zd.showMatches = !m.zd.showMatches
	if !m.zd.showMatches && m.zd.filtered && m.zd.filter == lookup.DiffMatch {
		m.zd.filtered = false
	}
	m.renderContent()
	m.viewport.GotoTop()
	if m.zd.showMatches {
		return m.setStatus("Showing matching records")
	}
	return m.setStatus("Hiding matching records")
}

// setZoneDiffFilter shows only records with status key ("1"-"5"); "0" clears
// the filter and choosing the active filter again toggles it off.
func (m *tabModel) setZoneDiffFilter(key string) bool {
	if key == "0" {
		m.zd.filtered = false
	} else if st, ok := zoneDiffFilterKeys[key]; ok {
		if m.zd.filtered && m.zd.filter == st {
			m.zd.filtered = false
		} else {
			m.zd.filtered, m.zd.filter = true, st
		}
	} else {
		return false
	}
	m.renderContent()
	m.viewport.GotoTop()
	return true
}

// handleZoneDiffFilterKey handles the number filter keys in zone diff results.
func (m *tabModel) handleZoneDiffFilterKey(key string) (tea.Cmd, bool) {
	return nil, m.setZoneDiffFilter(key)
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
	old := r.OldSource()
	if r.OldFile == "" && m.zd.opts.OldServer == "" {
		old += zdNoteStyle.Render(" (authoritative)")
	}
	fmt.Fprintf(&b, "%s%s\n", label("Old:"), old)
	fmt.Fprintf(&b, "%s%s\n", label("New:"), r.NewSource())
	for _, w := range r.Warnings {
		fmt.Fprintf(&b, "%s%s\n", label("Warning:"), zdNoteStyle.Render(w))
	}
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
