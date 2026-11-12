package lookup

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

// OverviewName is the name of the quick-overview lookup, dlookup's default
// lookup. It mirrors the classic "sdig" helper script: where the name resolves
// (with TTL), the PTR of each address, and the domain's MX and NS records.
const OverviewName = "Overview"

// DefaultLookupName is the lookup used when none is chosen explicitly.
const DefaultLookupName = OverviewName

// OverviewProvider prints a short summary of a domain or IP.
type OverviewProvider struct{}

func (p *OverviewProvider) Name() string     { return OverviewName }
func (p *OverviewProvider) FlagName() string { return "overview" }
func (p *OverviewProvider) Command() string  { return "" }
func (p *OverviewProvider) Usage() string {
	return "Run Overview (IP + TTL, PTR, MX, NS; type from --qtype, default A) on domains from <filename>"
}
func (p *OverviewProvider) CheckAvailability() bool { return true }

// ExcludeFromReport keeps the Report from repeating records it already lists.
func (p *OverviewProvider) ExcludeFromReport() bool { return true }

// overviewAnswer is the result of one query: records owned by the queried
// name (plus any CNAMEs followed on the way) or an error.
type overviewAnswer struct {
	rrs []dns.RR
	err error
}

func overviewQuery(ctx context.Context, opts Options, name string, qtype uint16) overviewAnswer {
	resp, _, err := dnsQuery(ctx, opts, name, qtype)
	if err != nil {
		return overviewAnswer{err: err}
	}
	return overviewAnswer{rrs: resp.Answer}
}

func (p *OverviewProvider) Execute(ctx context.Context, target string, opts Options) (string, error) {
	name, err := NormalizeTarget(target)
	if err != nil {
		return "", err
	}
	if ip := net.ParseIP(name); ip != nil {
		return overviewIP(ctx, opts, ip)
	}

	qtype := dns.TypeA
	if opts.QType != "" {
		t, ok := dns.StringToType[strings.ToUpper(opts.QType)]
		if !ok {
			return "", fmt.Errorf("unknown query type %q", opts.QType)
		}
		qtype = t
	}
	typeName := dns.TypeToString[qtype]

	var (
		wg              sync.WaitGroup
		primary, mx, ns overviewAnswer
	)
	wg.Add(3)
	go func() { defer wg.Done(); primary = overviewQuery(ctx, opts, name, qtype) }()
	go func() { defer wg.Done(); mx = overviewQuery(ctx, opts, name, dns.TypeMX) }()
	go func() { defer wg.Done(); ns = overviewQuery(ctx, opts, name, dns.TypeNS) }()
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return "", err
	}

	// Values of the requested type, plus any CNAME chain that led there.
	var values, chain []string
	ttl := -1
	for _, rr := range primary.rrs {
		h := rr.Header()
		if h.Rrtype == dns.TypeCNAME && qtype != dns.TypeCNAME {
			chain = append(chain, strings.ToLower(h.Name)+" → "+rr.(*dns.CNAME).Target)
			continue
		}
		if h.Rrtype != qtype {
			continue
		}
		values = append(values, rrValue(rr))
		if ttl < 0 || int(h.Ttl) < ttl {
			ttl = int(h.Ttl)
		}
	}

	var b strings.Builder
	if len(values) == 0 {
		fmt.Fprintf(&b, "No results found for %s with record type %s.", name, typeName)
		if primary.err != nil {
			fmt.Fprintf(&b, " (%v)", primary.err)
		}
		b.WriteString("\n")
	} else {
		fmt.Fprintf(&b, "Domain %s is resolving on %s\n", name, strings.Join(values, ", "))
		if qtype != dns.TypeA {
			fmt.Fprintf(&b, "Type:          %s\n", typeName)
		}
		fmt.Fprintf(&b, "TTL:           %d\n", ttl)
	}
	for _, c := range chain {
		fmt.Fprintf(&b, "CNAME:         %s\n", c)
	}

	// PTR for every address the name resolves to.
	var ips []net.IP
	for _, rr := range primary.rrs {
		switch r := rr.(type) {
		case *dns.A:
			if qtype == dns.TypeA {
				ips = append(ips, r.A)
			}
		case *dns.AAAA:
			if qtype == dns.TypeAAAA {
				ips = append(ips, r.AAAA)
			}
		}
	}
	if len(ips) > 0 {
		ptrs := lookupPTRs(ctx, opts, ips)
		b.WriteString("Server (PTR):\n")
		for i, ip := range ips {
			fmt.Fprintf(&b, "  %-15s %s\n", ip, ptrs[i])
		}
	}

	writeSection(&b, "MX:", mx, dns.TypeMX)
	writeSection(&b, "NS:", ns, dns.TypeNS)
	return strings.TrimRight(b.String(), "\n"), nil
}

// overviewIP summarises an IP target: its PTR names and whether each of them
// resolves back to the same address (forward-confirmed reverse DNS).
func overviewIP(ctx context.Context, opts Options, ip net.IP) (string, error) {
	rev, err := ReverseName(ip.String())
	if err != nil {
		return "", err
	}
	ans := overviewQuery(ctx, opts, rev, dns.TypePTR)
	if err := ctx.Err(); err != nil {
		return "", err
	}
	var b strings.Builder
	var names []string
	for _, rr := range ans.rrs {
		if r, ok := rr.(*dns.PTR); ok {
			names = append(names, r.Ptr)
		}
	}
	if len(names) == 0 {
		fmt.Fprintf(&b, "No PTR record for %s.", ip)
		if ans.err != nil {
			fmt.Fprintf(&b, " (%v)", ans.err)
		}
		return b.String(), nil
	}
	fmt.Fprintf(&b, "IP %s points to %s\n", ip, strings.Join(names, ", "))
	qtype := dns.TypeA
	if ip.To4() == nil {
		qtype = dns.TypeAAAA
	}
	for _, n := range names {
		fwd := overviewQuery(ctx, opts, n, qtype)
		status := "does not resolve back to " + ip.String()
		for _, rr := range fwd.rrs {
			var got net.IP
			switch r := rr.(type) {
			case *dns.A:
				got = r.A
			case *dns.AAAA:
				got = r.AAAA
			}
			if got != nil && got.Equal(ip) {
				status = "resolves back (forward-confirmed)"
				break
			}
		}
		fmt.Fprintf(&b, "  %s %s\n", n, status)
	}
	return strings.TrimRight(b.String(), "\n"), nil
}

func lookupPTRs(ctx context.Context, opts Options, ips []net.IP) []string {
	out := make([]string, len(ips))
	var wg sync.WaitGroup
	for i, ip := range ips {
		wg.Add(1)
		go func(i int, ip net.IP) {
			defer wg.Done()
			rev, err := ReverseName(ip.String())
			if err != nil {
				out[i] = "(invalid address)"
				return
			}
			ans := overviewQuery(ctx, opts, rev, dns.TypePTR)
			var names []string
			for _, rr := range ans.rrs {
				if r, ok := rr.(*dns.PTR); ok {
					names = append(names, r.Ptr)
				}
			}
			switch {
			case len(names) > 0:
				out[i] = strings.Join(names, ", ")
			case ans.err != nil && !isNXDomain(ans.err):
				out[i] = fmt.Sprintf("(error: %v)", ans.err)
			default:
				out[i] = "(no PTR)"
			}
		}(i, ip)
	}
	wg.Wait()
	return out
}

func isNXDomain(err error) bool {
	var de *DNSError
	return errors.As(err, &de) && de.Rcode == "NXDOMAIN"
}

func writeSection(b *strings.Builder, title string, ans overviewAnswer, qtype uint16) {
	var lines []string
	for _, rr := range ans.rrs {
		if rr.Header().Rrtype == qtype {
			lines = append(lines, rrValue(rr))
		}
	}
	if qtype == dns.TypeMX {
		sort.SliceStable(lines, func(i, j int) bool {
			var pi, pj int
			fmt.Sscan(lines[i], &pi)
			fmt.Sscan(lines[j], &pj)
			return pi < pj
		})
	} else {
		sort.Strings(lines)
	}
	b.WriteString(title + "\n")
	switch {
	case len(lines) > 0:
		for _, l := range lines {
			b.WriteString("  " + l + "\n")
		}
	case ans.err != nil:
		fmt.Fprintf(b, "  (error: %v)\n", ans.err)
	default:
		b.WriteString("  (none)\n")
	}
}

// rrValue is the record data without owner, TTL, class and type.
func rrValue(rr dns.RR) string {
	s := rr.String()
	hdr := rr.Header().String()
	return strings.TrimSpace(strings.TrimPrefix(s, hdr))
}

func init() {
	RegisterProvider(&OverviewProvider{})
}
