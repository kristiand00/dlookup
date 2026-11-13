package lookup

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// SDIGName is the name of the sdig-style lookup, dlookup's default lookup.
const SDIGName = "SDIG"

// SDIGProvider sends a single query (Options.QType, default A) natively and
// prints the reply in the format of PowerDNS's sdig: a "Reply to question"
// line, an "Rcode: ..." header line and one tab-separated line per record of
// the answer (0), authority (1) and additional (2) sections. EDNS option
// lines, which sdig writes to stderr, are appended at the end.
//
// Unlike real sdig, the RD bit is set unless Options.NoRecurse is true (sdig
// only sets it with "recurse"), the system resolvers are used when no server
// is given, and a truncated UDP reply is retried over TCP. A non-NOERROR
// rcode (e.g. NXDOMAIN) is part of the output, not an error.
type SDIGProvider struct{}

func (p *SDIGProvider) Name() string     { return SDIGName }
func (p *SDIGProvider) FlagName() string { return "sdig" }
func (p *SDIGProvider) Usage() string {
	return "Run SDIG (sdig-style query, type from --qtype, default A) on domains from <filename>"
}
func (p *SDIGProvider) Command() string         { return "" }
func (p *SDIGProvider) CheckAvailability() bool { return true }

// ExcludeFromReport implements ReportExcluder: the Report already has the DIG lookups.
func (p *SDIGProvider) ExcludeFromReport() bool { return true }

// SDIGQuery returns the name and type an SDIG lookup of target queries. With
// no (or a PTR) QType, an IP target is looked up as PTR on its reverse name;
// otherwise QType (default A) is queried for the target as given.
func SDIGQuery(target string, opts Options) (name, qtype string, err error) {
	name, err = normalizeTarget(target)
	if err != nil {
		return "", "", err
	}
	qtype = strings.ToUpper(strings.TrimSpace(opts.QType))
	if net.ParseIP(name) != nil && (qtype == "" || qtype == "PTR") {
		if name, err = ReverseName(name); err != nil {
			return "", "", err
		}
		qtype = "PTR"
	}
	if qtype == "" {
		qtype = "A"
	}
	return name, qtype, nil
}

// SDIGLabel is the display label of an SDIG lookup, e.g. "SDIG MX".
func SDIGLabel(target string, opts Options) string {
	if _, qt, err := SDIGQuery(target, opts); err == nil {
		return SDIGName + " " + qt
	}
	if qt := strings.ToUpper(strings.TrimSpace(opts.QType)); qt != "" {
		return SDIGName + " " + qt
	}
	return SDIGName
}

// sdigServerAddr normalises a server like serverAddr, defaulting the port to
// 853 for DNS over TLS.
func sdigServerAddr(server string, dot bool) string {
	addr := serverAddr(server)
	if dot {
		if _, _, err := net.SplitHostPort(strings.TrimSpace(server)); err != nil {
			host, _, _ := net.SplitHostPort(addr)
			addr = net.JoinHostPort(host, "853")
		}
	}
	return addr
}

func (p *SDIGProvider) Execute(ctx context.Context, target string, opts Options) (string, error) {
	name, qt, err := SDIGQuery(target, opts)
	if err != nil {
		return "", err
	}
	qtype, err := ParseQType(qt)
	if err != nil {
		return "", err
	}
	req := SDIGRequest{
		Name:       name,
		QType:      qtype,
		Class:      opts.Class,
		Recurse:    !opts.NoRecurse,
		DNSSEC:     opts.DNSSEC,
		TCP:        opts.TCP || opts.DoT,
		DoT:        opts.DoT,
		Insecure:   opts.Insecure,
		TCFallback: true,
	}
	if opts.EDNSSubnet != "" {
		if req.ECS, err = ParseNetmask(strings.TrimSpace(opts.EDNSSubnet)); err != nil {
			return "", err
		}
	}

	var servers []string
	if opts.Server != "" {
		if err := ValidateServer(opts.Server); err != nil {
			return "", err
		}
		servers = []string{sdigServerAddr(opts.Server, opts.DoT)}
	} else {
		for _, s := range SystemDNSServers() {
			if opts.DoT {
				host, _, _ := net.SplitHostPort(s)
				s = net.JoinHostPort(host, "853")
			}
			servers = append(servers, s)
		}
	}

	ctx, cancel := context.WithTimeout(ctx, opts.timeout())
	defer cancel()
	req.Timeout = opts.timeout() / time.Duration(len(servers))
	if req.Timeout < 2*time.Second {
		req.Timeout = 2 * time.Second
	}

	var lastErr error
	for _, server := range servers {
		if ctx.Err() != nil {
			break
		}
		req.Server = server
		resp, err := SDIGExchange(ctx, req)
		if err != nil {
			lastErr = fmt.Errorf("query to %s failed: %w", server, err)
			continue
		}
		out, ednsLines := FormatSDIG(resp, SDIGFormat{HideTTL: opts.HideTTL, HideSOADetails: opts.HideSOADetails, ShowFlags: opts.ShowFlags})
		out = strings.TrimRight(out, "\n")
		if len(ednsLines) > 0 {
			out += "\n" + strings.Join(ednsLines, "\n")
		}
		return out, nil
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if lastErr == nil {
		lastErr = errors.New("no DNS servers configured")
	}
	return "", lastErr
}

func init() {
	RegisterProvider(&SDIGProvider{})
}
