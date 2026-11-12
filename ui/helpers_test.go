package ui

import (
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

var sentinelN atomic.Int64
var lastSentinel string

func TestMain(m *testing.M) {
	InitZones()
	m.Run()
}

// scan runs Scan on view and waits until the async bubblezone worker has
// stored every zone of this scan and dropped the previous scan's zones.
func scan(t *testing.T, view string) string {
	t.Helper()
	id := "sentinel-" + strconv.FormatInt(sentinelN.Add(1), 10)
	out := Scan(view + "\n" + Mark(id, "#"))
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_, _, _, _, ok := ZonePos(id)
		_, _, _, _, stale := ZonePos(lastSentinel)
		if ok && (lastSentinel == "" || !stale) {
			lastSentinel = id
			return out
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("zones never settled")
	return out
}

func keyRunes(s string) tea.KeyMsg { return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)} }
func keyAlt(r rune) tea.KeyMsg     { return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}, Alt: true} }
func key(k tea.KeyType) tea.KeyMsg { return tea.KeyMsg{Type: k} }

func mouseAt(x, y int, b tea.MouseButton, a tea.MouseAction) tea.MouseMsg {
	return tea.MouseMsg{X: x, Y: y, Button: b, Action: a}
}

// clickZone returns a left-press at the top-left cell of zone id (offset by dx).
func clickZone(t *testing.T, id string, dx int) tea.MouseMsg {
	t.Helper()
	x, y, _, _, ok := ZonePos(id)
	if !ok {
		t.Fatalf("zone %q not found", id)
	}
	return mouseAt(x+dx, y, tea.MouseButtonLeft, tea.MouseActionPress)
}

func zoneAt(t *testing.T, id string) tea.MouseMsg {
	return clickZone(t, id, 0)
}
