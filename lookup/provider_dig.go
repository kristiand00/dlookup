package lookup

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/miekg/dns"
)

// dnsKind selects special handling on top of a plain record query.
type dnsKind int

const (
	kindPlain dnsKind = iota
	kindSPF           // TXT records starting with "v=spf1"
	kindDMARC         // TXT records at _dmarc.<domain> starting with "v=DMARC1"
	kindPTR           // reverse lookup
)

// DigProvider performs a DNS query natively (no external dig binary). The
// "DIG (...)" names and "dig-dig-..." flags are kept for compatibility.
type DigProvider struct {
	name          string
	flagName      string
	qtype         uint16
	kind          dnsKind
	excludeReport bool
}

var nonAlphanumericRegex = regexp.MustCompile(`[^a-zA-Z0-9]+`)

func digFlagName(name string) string {
	s := strings.ToLower(name)
	s = nonAlphanumericRegex.ReplaceAllString(s, "-")
	return strings.Trim(s, "-") // "DIG (MX)" -> "dig-mx"
}

func newDigProvider(name string, qtype uint16, kind dnsKind) *DigProvider {
	p := &DigProvider{name: name, flagName: digFlagName(name), qtype: qtype, kind: kind}
	RegisterProvider(p)
	return p
}

func (p *DigProvider) Name() string     { return p.name }
func (p *DigProvider) FlagName() string { return p.flagName }
func (p *DigProvider) Usage() string {
	return fmt.Sprintf("Run %s lookup on domains from <filename>", p.Name())
}

// Command returns "" because DNS queries are performed natively.
func (p *DigProvider) Command() string         { return "" }
func (p *DigProvider) CheckAvailability() bool { return true }

// ExcludeFromReport implements ReportExcluder (true for ANY, see RFC 8482).
func (p *DigProvider) ExcludeFromReport() bool { return p.excludeReport }

func (p *DigProvider) Execute(ctx context.Context, target string, opts Options) (string, error) {
	name, err := normalizeTarget(target)
	if err != nil {
		return "", err
	}
	switch p.kind {
	case kindPTR:
		return p.executePTR(ctx, name, opts)
	case kindDMARC:
		if net.ParseIP(name) != nil {
			return "", errors.New("DMARC lookup requires a domain name, not an IP address")
		}
		name = dmarcName(name)
	}

	resp, _, err := dnsQuery(ctx, opts, name, p.qtype)
	if err != nil {
		return "", err
	}
	rrs := resp.Answer
	switch p.kind {
	case kindSPF:
		rrs = filterTXT(rrs, "v=spf1")
	case kindDMARC:
		rrs = filterTXT(rrs, "v=DMARC1")
	}
	if len(rrs) == 0 {
		return "(No results found)", nil
	}
	return formatRRs(rrs), nil
}

// executePTR looks up PTR records. An IP target is converted to its
// in-addr.arpa / ip6.arpa name; a .arpa name is queried as-is; any other
// hostname is first resolved (A and AAAA) and each address is reverse-resolved.
func (p *DigProvider) executePTR(ctx context.Context, name string, opts Options) (string, error) {
	if net.ParseIP(name) != nil || strings.HasSuffix(name, ".arpa") {
		qname := name
		if net.ParseIP(name) != nil {
			var err error
			if qname, err = ReverseName(name); err != nil {
				return "", err
			}
		}
		resp, _, err := dnsQuery(ctx, opts, qname, dns.TypePTR)
		if err != nil {
			return "", err
		}
		if len(resp.Answer) == 0 {
			return "(No results found)", nil
		}
		return formatRRs(resp.Answer), nil
	}

	var addrs []string
	for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
		resp, _, err := dnsQuery(ctx, opts, name, qt)
		if err != nil {
			var dnsErr *DNSError
			if errors.As(err, &dnsErr) {
				continue
			}
			return "", err
		}
		for _, rr := range resp.Answer {
			switch r := rr.(type) {
			case *dns.A:
				addrs = append(addrs, r.A.String())
			case *dns.AAAA:
				addrs = append(addrs, r.AAAA.String())
			}
		}
	}
	if len(addrs) == 0 {
		return "(No addresses found to reverse-resolve)", nil
	}

	var b strings.Builder
	for i, addr := range addrs {
		if i > 0 {
			b.WriteString("\n")
		}
		rev, _ := ReverseName(addr)
		resp, _, err := dnsQuery(ctx, opts, rev, dns.TypePTR)
		switch {
		case ctx.Err() != nil:
			return "", ctx.Err()
		case err != nil:
			fmt.Fprintf(&b, "; %s: %v", addr, err)
		case len(resp.Answer) == 0:
			fmt.Fprintf(&b, "; %s: no PTR record", addr)
		default:
			fmt.Fprintf(&b, "; %s\n%s", addr, formatRRs(resp.Answer))
		}
	}
	return b.String(), nil
}

// ReverseName returns the in-addr.arpa / ip6.arpa name (without trailing dot)
// for an IPv4 or IPv6 address, e.g. "1.2.3.4" -> "4.3.2.1.in-addr.arpa".
func ReverseName(ip string) (string, error) {
	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("%q is not an IP address", ip)
	}
	r, err := dns.ReverseAddr(ip)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(r, "."), nil
}

func dmarcName(domain string) string {
	domain = strings.TrimSuffix(domain, ".")
	if strings.HasPrefix(strings.ToLower(domain), "_dmarc.") {
		return domain
	}
	return "_dmarc." + domain
}

// filterTXT keeps TXT records whose (concatenated) value starts with prefix,
// compared case-insensitively and requiring a word boundary after it
// (so "v=spf10" does not match "v=spf1").
func filterTXT(rrs []dns.RR, prefix string) []dns.RR {
	var out []dns.RR
	for _, rr := range rrs {
		txt, ok := rr.(*dns.TXT)
		if !ok {
			continue
		}
		v := strings.TrimSpace(strings.Join(txt.Txt, ""))
		if len(v) < len(prefix) || !strings.EqualFold(v[:len(prefix)], prefix) {
			continue
		}
		if rest := v[len(prefix):]; rest != "" && rest[0] != ' ' && rest[0] != ';' {
			continue
		}
		out = append(out, rr)
	}
	return out
}

func init() {
	newDigProvider("DIG (ANY)", dns.TypeANY, kindPlain).excludeReport = true
	newDigProvider("DIG (A)", dns.TypeA, kindPlain)
	newDigProvider("DIG (AAAA)", dns.TypeAAAA, kindPlain)
	newDigProvider("DIG (MX)", dns.TypeMX, kindPlain)
	newDigProvider("DIG (TXT)", dns.TypeTXT, kindPlain)
	newDigProvider("DIG (SOA)", dns.TypeSOA, kindPlain)
	newDigProvider("DIG (CNAME)", dns.TypeCNAME, kindPlain)
	newDigProvider("DIG (NS)", dns.TypeNS, kindPlain)
	newDigProvider("DIG (CAA)", dns.TypeCAA, kindPlain)
	newDigProvider("DIG (PTR)", dns.TypePTR, kindPTR)
	newDigProvider("DIG (SPF)", dns.TypeTXT, kindSPF)
	newDigProvider("DIG (DMARC)", dns.TypeTXT, kindDMARC)
}
