package lookup

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"dlookup/zonefile"
)

// ZoneDumpOptions configures DumpZone.
type ZoneDumpOptions struct {
	Domain      string
	Server      string                // "" = the domain's authoritative nameservers
	ExtraNames  []string              // extra names to probe (relative or FQDN)
	Types       []uint16              // nil = DefaultZoneDiffTypes (plus types found via AXFR)
	TryAXFR     bool                  // try a zone transfer first
	Timeout     time.Duration         // per query; 0 = DefaultTimeout
	Concurrency int                   // 0 = 8
	Progress    func(done, total int) // optional, may be called from goroutines
}

// DumpZone reads the live zone of opts.Domain from its authoritative
// nameservers (or opts.Server). With TryAXFR a zone transfer is tried first
// and, if allowed, returns every record (except DNSSEC records). Otherwise
// the names are enumerated like DiffZone does: the apex, common labels, DKIM
// selectors, SRV names, a wildcard check (reported as "*.<domain>"), the
// ExtraNames and in-zone CNAME/MX/NS/SRV targets. The second result describes
// the method: "axfr from <server>" or "probe (N names)".
//
// A probed dump can only contain names that were guessed; names found only
// through the wildcard are left out.
func DumpZone(ctx context.Context, opts ZoneDumpOptions) (*zonefile.Zone, string, error) {
	domain, err := NormalizeTarget(opts.Domain)
	if err != nil {
		return nil, "", err
	}
	if net.ParseIP(domain) != nil {
		return nil, "", fmt.Errorf("invalid domain %q: an IP address is not a zone", opts.Domain)
	}
	if opts.Server != "" {
		if err := ValidateServer(opts.Server); err != nil {
			return nil, "", err
		}
	}
	d := &zoneDiffer{
		opts: ZoneDiffOptions{
			Domain: domain, Types: opts.Types, TryAXFR: opts.TryAXFR,
			Timeout: opts.Timeout, Concurrency: opts.Concurrency, Progress: opts.Progress,
		},
		zone:       dns.Fqdn(domain),
		types:      opts.Types,
		allowFound: opts.Types == nil,
		timeout:    opts.Timeout,
	}
	if d.types == nil {
		d.types = DefaultZoneDiffTypes
	}
	if d.timeout <= 0 {
		d.timeout = DefaultTimeout
	}
	extra := make([]string, 0, len(opts.ExtraNames))
	for _, n := range opts.ExtraNames {
		q, err := qualifyName(n, d.zone)
		if err != nil {
			return nil, "", err
		}
		extra = append(extra, q)
	}

	var servers []string
	if opts.Server != "" {
		s, err := resolveServer(ctx, opts.Server)
		if err != nil {
			return nil, "", fmt.Errorf("server: %w", err)
		}
		servers = []string{s}
	} else if servers, err = d.discoverServers(ctx); err != nil {
		return nil, "", err
	}
	used, err := d.checkServer(ctx, servers)
	if err != nil {
		return nil, "", fmt.Errorf("server %s: %w", strings.Join(servers, ", "), err)
	}
	servers = moveToFront(servers, used)

	if opts.TryAXFR {
		if rrs, from, err := axfrRecords(ctx, servers, d.zone, d.timeout); err == nil {
			if opts.Types != nil {
				kept := rrs[:0]
				for _, rr := range rrs {
					if containsType(opts.Types, rr.Header().Rrtype) {
						kept = append(kept, rr)
					}
				}
				rrs = kept
			}
			if opts.Progress != nil {
				opts.Progress(1, 1)
			}
			return zonefile.FromRRs(d.zone, rrs), "axfr from " + from, nil
		} else if ctx.Err() != nil {
			return nil, "", ctx.Err()
		}
	}

	names := append(d.probeNames(), extra...)
	d.maxNames = maxZoneDiffNames + len(names)
	var (
		mu      sync.Mutex
		found   = map[string]map[uint16][]dns.RR{} // name -> type -> records
		errs    int
		lastErr error
	)
	total, err := d.run(ctx, names, func(ctx context.Context, name string) []string {
		var more []string
		got := map[uint16][]dns.RR{}
		for _, t := range d.typesFor(name) {
			if ctx.Err() != nil {
				return nil
			}
			a := d.query(ctx, servers, name, t)
			if a.err != nil {
				mu.Lock()
				errs++
				lastErr = a.err
				mu.Unlock()
				continue
			}
			if a.nx {
				break
			}
			if len(a.rrs) > 0 {
				got[t] = a.rrs
				more = append(more, d.targets(a.rrs)...)
			}
		}
		if len(got) > 0 {
			mu.Lock()
			found[name] = got
			mu.Unlock()
		}
		return more
	})
	if err != nil {
		return nil, "", err
	}
	if len(found) == 0 && errs > 0 {
		return nil, "", fmt.Errorf("no records read: %w", lastErr)
	}

	// Names answered only by the wildcard are synthesized: report the
	// wildcard once as "*.<zone>" and drop identical answers elsewhere.
	wild := found[d.wildcard]
	delete(found, d.wildcard)
	var rrs []dns.RR
	for name, byType := range found {
		for t, set := range byType {
			if w := wild[t]; w != nil && !strings.HasPrefix(name, "*.") &&
				equalStrings(normalizeRRs(w, false), normalizeRRs(set, false)) {
				continue
			}
			rrs = append(rrs, set...)
		}
	}
	for _, set := range wild {
		for _, rr := range set {
			c := dns.Copy(rr)
			c.Header().Name = "*." + d.zone
			rrs = append(rrs, c)
		}
	}
	sort.SliceStable(rrs, func(i, j int) bool { return rrs[i].String() < rrs[j].String() })
	method := fmt.Sprintf("probe (%d names)", total)
	if errs > 0 {
		method += fmt.Sprintf(", %d failed queries", errs)
	}
	if len(rrs) == 0 {
		return nil, "", errors.New("no records found")
	}
	return zonefile.FromRRs(d.zone, rrs), method, nil
}
