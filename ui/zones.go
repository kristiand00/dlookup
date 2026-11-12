package ui

import (
	tea "github.com/charmbracelet/bubbletea"
	zone "github.com/lrstanley/bubblezone"
)

// Mouse convention: every widget in this package reacts to a left-button
// PRESS (tea.MouseActionPress + tea.MouseButtonLeft). Releases are ignored.
// Press is reported reliably in both X10 and SGR mouse modes, whereas X10
// releases do not carry the button.

// InitZones initialises the global bubblezone manager. Safe to call many times.
func InitZones() { zone.NewGlobal() }

// Scan must be called exactly once on the final, fully composed View output
// (after all overlays). It records zone positions and strips the markers.
// If InitZones was never called, Scan returns the view unchanged.
func Scan(view string) string {
	if zone.DefaultManager == nil {
		return view
	}
	return zone.Scan(view)
}

// Mark wraps s in a clickable zone with the given id. It is a no-op when zones
// are not initialised, so widgets render fine in tests/headless mode.
func Mark(id, s string) string {
	if zone.DefaultManager == nil {
		return s
	}
	return zone.Mark(id, s)
}

// Hit reports whether the mouse event lies inside zone id (any action/button).
func Hit(id string, msg tea.MouseMsg) bool {
	if zone.DefaultManager == nil {
		return false
	}
	return zone.Get(id).InBounds(msg)
}

// ZonePos returns the top-left cell and size of zone id as of the last Scan.
func ZonePos(id string) (x, y, w, h int, ok bool) {
	if zone.DefaultManager == nil {
		return 0, 0, 0, 0, false
	}
	z := zone.Get(id)
	if z.IsZero() || z.StartX > z.EndX || z.StartY > z.EndY {
		return 0, 0, 0, 0, false
	}
	return z.StartX, z.StartY, z.EndX - z.StartX + 1, z.EndY - z.StartY + 1, true
}

// IsLeftClick reports a left-button press.
func IsLeftClick(msg tea.MouseMsg) bool {
	return msg.Action == tea.MouseActionPress && msg.Button == tea.MouseButtonLeft
}

// IsWheelUp reports a wheel-up event.
func IsWheelUp(msg tea.MouseMsg) bool {
	return msg.Button == tea.MouseButtonWheelUp && msg.Action == tea.MouseActionPress
}

// IsWheelDown reports a wheel-down event.
func IsWheelDown(msg tea.MouseMsg) bool {
	return msg.Button == tea.MouseButtonWheelDown && msg.Action == tea.MouseActionPress
}

// IsMotion reports a mouse motion event (with or without a held button).
func IsMotion(msg tea.MouseMsg) bool { return msg.Action == tea.MouseActionMotion }

// Clicked is shorthand for IsLeftClick(msg) && Hit(id, msg).
func Clicked(id string, msg tea.MouseMsg) bool { return IsLeftClick(msg) && Hit(id, msg) }
