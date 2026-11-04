package lookup

import "context"

// SetZoneDiffHooks replaces the discovery resolvers, host resolver and NS
// port used by DiffZone for the duration of a test; call the returned func
// to restore them.
func SetZoneDiffHooks(discovery []string, resolve func(ctx context.Context, host string) ([]string, error), nsPort string) func() {
	oldD, oldR, oldP := zoneDiscoveryServers, resolveHost, zoneNSPort
	zoneDiscoveryServers = func() []string { return discovery }
	if resolve != nil {
		resolveHost = resolve
	}
	zoneNSPort = nsPort
	return func() { zoneDiscoveryServers, resolveHost, zoneNSPort = oldD, oldR, oldP }
}
