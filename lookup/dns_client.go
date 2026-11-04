package lookup

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Native DNS resolution (github.com/miekg/dns), used by the "DIG (...)" providers.
//
// Server selection:
//   - Options.Server, when set ("host" or "host:port"; port defaults to 53).
//   - Otherwise the nameservers listed in /etc/resolv.conf (Unix, macOS).
//   - If resolv.conf is missing or lists no servers (notably on Windows, where
//     the system resolver configuration is not exposed in a portable way), we
//     fall back to FallbackDNSServers (public resolvers 1.1.1.1 and 8.8.8.8).
//     Go's net.Resolver is not used as a fallback because it cannot return raw
//     SOA/CAA/ANY records or TTLs. Users who need a specific (e.g. internal)
//     resolver on Windows can set Options.Server.
//
// Queries go over UDP with EDNS0 (4096-byte buffer) and are retried over TCP
// when the response is truncated. Servers are tried in order; each attempt is
// bounded by a share of the overall timeout so one dead server cannot consume
// it entirely.

// FallbackDNSServers is used when no system resolver configuration is found.
var FallbackDNSServers = []string{"1.1.1.1:53", "8.8.8.8:53"}

// resolvConfPath is a variable so tests can point it elsewhere.
var resolvConfPath = "/etc/resolv.conf"

var (
	systemServersOnce sync.Once
	systemServers     []string
)

// SystemDNSServers returns the "host:port" resolvers used when Options.Server
// is empty (from /etc/resolv.conf, or FallbackDNSServers).
func SystemDNSServers() []string {
	systemServersOnce.Do(func() {
		systemServers = loadResolvConf(resolvConfPath)
	})
	if len(systemServers) == 0 {
		return append([]string(nil), FallbackDNSServers...)
	}
	return append([]string(nil), systemServers...)
}

func loadResolvConf(path string) []string {
	cfg, err := dns.ClientConfigFromFile(path)
	if err != nil || cfg == nil {
		return nil
	}
	port := cfg.Port
	if port == "" {
		port = "53"
	}
	out := make([]string, 0, len(cfg.Servers))
	for _, s := range cfg.Servers {
		s = strings.Trim(s, "[]")
		if s == "" {
			continue
		}
		out = append(out, net.JoinHostPort(s, port))
	}
	return out
}

// serverAddr normalises "host", "host:port", "[v6]", "[v6]:port" or a bare
// IPv6 address into "host:port", defaulting the port to 53.
func serverAddr(server string) string {
	server = strings.TrimSpace(server)
	if host, port, err := net.SplitHostPort(server); err == nil {
		return net.JoinHostPort(host, port)
	}
	return net.JoinHostPort(strings.Trim(server, "[]"), "53")
}

func dnsServers(opts Options) []string {
	// Validation of opts.Server happens in dnsQuery.
	if opts.Server != "" {
		return []string{serverAddr(opts.Server)}
	}
	return SystemDNSServers()
}

// dnsQuery sends a single recursive query for name/qtype and returns the response.
// A non-NOERROR rcode is returned as a *DNSError together with the response.
func dnsQuery(ctx context.Context, opts Options, name string, qtype uint16) (*dns.Msg, string, error) {
	if opts.Server != "" {
		if err := ValidateServer(opts.Server); err != nil {
			return nil, "", err
		}
	}
	ctx, cancel := context.WithTimeout(ctx, opts.timeout())
	defer cancel()

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true
	m.SetEdns0(4096, false)

	servers := dnsServers(opts)
	perAttempt := opts.timeout() / time.Duration(len(servers))
	if perAttempt < 2*time.Second {
		perAttempt = 2 * time.Second
	}

	var lastErr error
	for _, server := range servers {
		if ctx.Err() != nil {
			break
		}
		resp, err := exchange(ctx, perAttempt, m, server)
		if err != nil {
			lastErr = fmt.Errorf("query to %s failed: %w", server, err)
			continue
		}
		if resp.Rcode != dns.RcodeSuccess {
			return resp, server, &DNSError{Name: name, Type: dns.TypeToString[qtype], Rcode: dns.RcodeToString[resp.Rcode], Server: server}
		}
		return resp, server, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	if lastErr == nil {
		lastErr = errors.New("no DNS servers configured")
	}
	return nil, "", lastErr
}

func exchange(ctx context.Context, timeout time.Duration, m *dns.Msg, server string) (*dns.Msg, error) {
	actx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	c := &dns.Client{Net: "udp", Timeout: timeout}
	resp, _, err := c.ExchangeContext(actx, m, server)
	if err == nil && resp != nil && resp.Truncated {
		c.Net = "tcp"
		resp, _, err = c.ExchangeContext(actx, m, server)
	}
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, err
	}
	if resp == nil {
		return nil, errors.New("empty response")
	}
	return resp, nil
}

// DNSError reports a DNS response with a non-success rcode (NXDOMAIN, SERVFAIL, REFUSED, ...).
type DNSError struct {
	Name, Type, Rcode, Server string
}

func (e *DNSError) Error() string {
	return fmt.Sprintf("%s %s: %s (server %s)", e.Name, e.Type, e.Rcode, e.Server)
}

// formatRRs renders records one per line in dig's answer-section format
// ("name TTL class type data"), tabs replaced by single spaces for display.
func formatRRs(rrs []dns.RR) string {
	lines := make([]string, 0, len(rrs))
	for _, rr := range rrs {
		lines = append(lines, strings.ReplaceAll(rr.String(), "\t", " "))
	}
	return strings.Join(lines, "\n")
}
