package lookup

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

// sdig emulation: queries and output in the format of PowerDNS's sdig tool
// (pdns/sdig.cc). Record data is rendered like PowerDNS's
// getZoneRepresentation() so the output matches sdig byte for byte for the
// common record types.

// SDIGDefaultBufSize is the EDNS buffer size sdig advertises (unless
// $SDIGBUFSIZE is set).
const SDIGDefaultBufSize = 2800

// SDIGDefaultTimeout is sdig's fixed network timeout.
const SDIGDefaultTimeout = 10 * time.Second

// SDIGRequest describes one sdig-style query.
type SDIGRequest struct {
	// Server is "host:port", or an https:// URL for DNS over HTTPS.
	Server string
	Name   string // query name (relative names are made absolute)
	QType  uint16
	Class  uint16 // 0 = IN
	Opcode int

	Recurse bool // set the RD bit
	DNSSEC  bool // set the DO bit (adds EDNS)

	// ECS is the EDNS Client Subnet to send (nil = none).
	ECS *net.IPNet
	// Cookie is the EDNS cookie option payload to send (nil = none).
	Cookie []byte
	// BufSize is the advertised EDNS buffer size (0 = 2800). ForceEDNS adds
	// an OPT record even without DNSSEC/ECS/cookie (like $SDIGBUFSIZE).
	BufSize   uint16
	ForceEDNS bool

	TCP         bool
	DoT         bool // DNS over TLS (implies TCP)
	Insecure    bool // DoT/DoH: do not validate the certificate
	SubjectName string
	CAStore     string // PEM file with CA certificates

	Timeout time.Duration // 0 = SDIGDefaultTimeout
	// TCFallback retries over TCP when a UDP reply is truncated (real sdig
	// does not; dlookup's SDIG lookup does).
	TCFallback bool
}

func (r SDIGRequest) timeout() time.Duration {
	if r.Timeout <= 0 {
		return SDIGDefaultTimeout
	}
	return r.Timeout
}

// Msg builds the query message (ID 0; SDIGExchange randomises it except for DoH).
func (r SDIGRequest) Msg() (*dns.Msg, error) {
	name := r.Name
	if name == "" {
		name = "."
	}
	name = dns.Fqdn(name)
	if _, ok := dns.IsDomainName(name); !ok {
		return nil, fmt.Errorf("invalid name '%s'", r.Name)
	}
	class := r.Class
	if class == 0 {
		class = dns.ClassINET
	}
	m := &dns.Msg{}
	m.Question = []dns.Question{{Name: name, Qtype: r.QType, Qclass: class}}
	m.Opcode = r.Opcode
	m.RecursionDesired = r.Recurse
	if r.DNSSEC || r.ECS != nil || r.Cookie != nil || r.ForceEDNS {
		opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
		size := r.BufSize
		if size == 0 {
			size = SDIGDefaultBufSize
		}
		opt.SetUDPSize(size)
		if r.DNSSEC {
			opt.SetDo()
		}
		if r.ECS != nil {
			ones, bits := r.ECS.Mask.Size()
			e := &dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, SourceNetmask: uint8(ones), Address: r.ECS.IP}
			if bits == 32 {
				e.Family = 1
				e.Address = r.ECS.IP.To4()
			} else {
				e.Family = 2
			}
			opt.Option = append(opt.Option, e)
		}
		if r.Cookie != nil {
			opt.Option = append(opt.Option, &dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: hex.EncodeToString(r.Cookie)})
		}
		m.Extra = append(m.Extra, opt)
	}
	return m, nil
}

// SDIGExchange sends the query and returns the reply (any rcode).
func SDIGExchange(ctx context.Context, r SDIGRequest) (*dns.Msg, error) {
	m, err := r.Msg()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, r.timeout())
	defer cancel()

	if strings.HasPrefix(r.Server, "https://") || strings.HasPrefix(r.Server, "http://") {
		return sdigDoH(ctx, r, m)
	}

	m.Id = dns.Id()
	c := &dns.Client{Net: "udp", Timeout: r.timeout()}
	switch {
	case r.DoT:
		cfg, err := r.tlsConfig()
		if err != nil {
			return nil, err
		}
		c.Net, c.TLSConfig = "tcp-tls", cfg
	case r.TCP:
		c.Net = "tcp"
	}
	resp, _, err := c.ExchangeContext(ctx, m, r.Server)
	if err == nil && resp != nil && resp.Truncated && c.Net == "udp" && r.TCFallback {
		c.Net = "tcp"
		resp, _, err = c.ExchangeContext(ctx, m, r.Server)
	}
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			if errors.Is(ctxErr, context.DeadlineExceeded) {
				return nil, errors.New("Timeout waiting for data") //nolint:staticcheck // sdig's exact message
			}
			return nil, ctxErr
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return nil, errors.New("Timeout waiting for data") //nolint:staticcheck // sdig's exact message
		}
		return nil, err
	}
	if resp == nil {
		return nil, errors.New("empty response")
	}
	return resp, nil
}

func (r SDIGRequest) tlsConfig() (*tls.Config, error) {
	cfg := &tls.Config{InsecureSkipVerify: r.Insecure, MinVersion: tls.VersionTLS12} //nolint:gosec // "insecure" is an explicit user option
	cfg.ServerName = r.SubjectName
	if cfg.ServerName == "" {
		if host, _, err := net.SplitHostPort(r.Server); err == nil {
			cfg.ServerName = host
		}
	}
	if r.CAStore != "" {
		pem, err := os.ReadFile(r.CAStore)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates found in %s", r.CAStore)
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}

func sdigDoH(ctx context.Context, r SDIGRequest, m *dns.Msg) (*dns.Msg, error) {
	m.Id = 0
	packed, err := m.Pack()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.Server, bytes.NewReader(packed))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	tr := http.DefaultTransport.(*http.Transport).Clone()
	cfg, err := r.tlsConfig()
	if err != nil {
		return nil, err
	}
	if r.SubjectName == "" {
		cfg.ServerName = "" // let net/http use the URL host
	}
	tr.TLSClientConfig = cfg
	resp, err := (&http.Client{Transport: tr, Timeout: r.timeout()}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Error performing HTTP request: %s", resp.Status)
	}
	out := new(dns.Msg)
	if err := out.Unpack(body); err != nil {
		return nil, err
	}
	return out, nil
}

// SDIGFormat selects sdig's output options.
type SDIGFormat struct {
	HideTTL        bool // "[ttl]" instead of TTLs
	HideSOADetails bool // "[serial]" instead of the SOA serial
	ShowFlags      bool // show NSEC3 flags
}

// FormatSDIG renders a reply exactly like sdig's printReply: the text sdig
// writes to stdout, and the EDNS option lines it writes to stderr.
func FormatSDIG(m *dns.Msg, f SDIGFormat) (stdout string, stderrLines []string) {
	var b strings.Builder
	if m.Response {
		b.WriteString("Reply to question")
	} else {
		b.WriteString("Question")
	}
	b.WriteString(" for qname='")
	qtype := uint16(0)
	if len(m.Question) > 0 {
		b.WriteString(pdnsName(m.Question[0].Name))
		qtype = m.Question[0].Qtype
	}
	fmt.Fprintf(&b, "', qtype=%s\n", PDNSTypeName(qtype))

	opt := m.IsEdns0()
	hdrRcode := m.Rcode & 0xF
	if opt != nil {
		ercode := m.Rcode
		fmt.Fprintf(&b, "Rcode: %d (%s", ercode, ercodeString(ercode))
	} else {
		fmt.Fprintf(&b, "Rcode: %d (%s", hdrRcode, ercodeString(hdrRcode))
	}
	fmt.Fprintf(&b, "), RD: %d, QR: %d, TC: %d, AA: %d, opcode: %d\n",
		b2i(m.RecursionDesired), b2i(m.Response), b2i(m.Truncated), b2i(m.Authoritative), m.Opcode)

	sections := [][]dns.RR{m.Answer, m.Ns, m.Extra}
	for place, rrs := range sections {
		for _, rr := range rrs {
			b.WriteString(formatSDIGRecord(place, rr, f))
		}
	}

	if opt != nil {
		stderrLines = ednsOptionLines(rawRdata(opt))
	}
	return b.String(), stderrLines
}

func b2i(v bool) int {
	if v {
		return 1
	}
	return 0
}

func formatSDIGRecord(place int, rr dns.RR, f SDIGFormat) string {
	h := rr.Header()
	ttl := strconv.FormatUint(uint64(h.Ttl), 10)
	if f.HideTTL {
		ttl = "[ttl]"
	}
	class := pdnsClassName(h.Class)
	if h.Rrtype == dns.TypeOPT {
		class = "IN"
	}
	line := fmt.Sprintf("%d\t%s\t%s\t%s\t%s", place, pdnsName(h.Name), ttl, class, PDNSTypeName(h.Rrtype))
	rep := pdnsZoneRep(rr)
	if h.Class == dns.ClassINET && h.Rrtype != dns.TypeOPT {
		parts := strings.Fields(rep)
		switch {
		case h.Rrtype == dns.TypeRRSIG && len(parts) >= 8:
			return line + "\t" + parts[0] + " " + parts[1] + " " + parts[2] + " " + parts[3] +
				" [expiry] [inception] [keytag] " + parts[7] + " ...\n"
		case !f.ShowFlags && h.Rrtype == dns.TypeNSEC3 && len(parts) >= 5:
			s := line + "\t" + parts[0] + " [flags] " + parts[2] + " " + parts[3] + " " + parts[4]
			for _, p := range parts[5:] {
				s += " " + p
			}
			return s + "\n"
		case h.Rrtype == dns.TypeDNSKEY && len(parts) >= 3:
			return line + "\t" + parts[0] + " " + parts[1] + " " + parts[2] + " ...\n"
		case h.Rrtype == dns.TypeSOA && f.HideSOADetails && len(parts) >= 7:
			return line + "\t" + parts[0] + " " + parts[1] + " [serial] " + parts[3] + " " +
				parts[4] + " " + parts[5] + " " + parts[6] + "\n"
		}
	}
	return line + "\t" + rep + "\n"
}

// rcodeNames are PowerDNS's RCode::rcodes_s.
var rcodeNames = []string{
	"No Error",
	"Form Error",
	"Server Failure",
	"Non-Existent domain",
	"Not Implemented",
	"Query Refused",
	"Name Exists when it should not",
	"RR Set Exists when it should not",
	"RR Set that should exist does not",
	"Server Not Authoritative for zone / Not Authorized",
	"Name not contained in zone",
	"Err#11",
	"Err#12",
	"Err#13",
	"Err#14",
	"Err#15",
	"Bad OPT Version / TSIG Signature Failure",
	"Key not recognized",
	"Signature out of time window",
	"Bad TKEY Mode",
	"Duplicate key name",
	"Algorithm not supported",
	"Bad Truncation",
	"Bad/missing Server Cookie",
}

func ercodeString(rcode int) string {
	if rcode >= 0 && rcode < len(rcodeNames) {
		return rcodeNames[rcode]
	}
	return "Err#" + strconv.Itoa(rcode)
}

// pdnsTypes are PowerDNS's type names (QType::names) that differ from or are
// missing in miekg/dns.
var pdnsTypes = map[uint16]string{
	1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 7: "MB", 8: "MG", 9: "MR", 12: "PTR",
	13: "HINFO", 14: "MINFO", 15: "MX", 16: "TXT", 17: "RP", 18: "AFSDB", 24: "SIG",
	25: "KEY", 28: "AAAA", 29: "LOC", 33: "SRV", 35: "NAPTR", 36: "KX", 37: "CERT",
	38: "A6", 39: "DNAME", 41: "OPT", 42: "APL", 43: "DS", 44: "SSHFP", 45: "IPSECKEY",
	46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 49: "DHCID", 50: "NSEC3", 51: "NSEC3PARAM",
	52: "TLSA", 53: "SMIMEA", 57: "RKEY", 59: "CDS", 60: "CDNSKEY", 61: "OPENPGPKEY",
	62: "CSYNC", 63: "ZONEMD", 64: "SVCB", 65: "HTTPS", 67: "HHIT", 68: "BRID",
	99: "SPF", 104: "NID", 105: "L32", 106: "L64", 107: "LP", 108: "EUI48", 109: "EUI64",
	249: "TKEY", 250: "TSIG", 251: "IXFR", 252: "AXFR", 253: "MAILB", 254: "MAILA",
	255: "ANY", 256: "URI", 257: "CAA", 261: "RESINFO", 262: "WALLET", 32769: "DLV",
	65400: "ADDR", 65401: "ALIAS", 65402: "LUA",
}

var pdnsTypeNumbers = func() map[string]uint16 {
	m := make(map[string]uint16, len(pdnsTypes))
	for n, s := range pdnsTypes {
		m[s] = n
	}
	return m
}()

// PDNSTypeName returns the PowerDNS name of a type ("TYPE123" if unknown).
func PDNSTypeName(t uint16) string {
	if s, ok := pdnsTypes[t]; ok {
		return s
	}
	return "TYPE" + strconv.Itoa(int(t))
}

// ParseQType converts a type name (case-insensitive) or "TYPEnnn" to its
// number, like PowerDNS's DNSRecordContent::TypeToNumber.
func ParseQType(s string) (uint16, error) {
	u := strings.ToUpper(strings.TrimSpace(s))
	if n, ok := pdnsTypeNumbers[u]; ok {
		return n, nil
	}
	if n, ok := dns.StringToType[u]; ok {
		return n, nil
	}
	if rest, ok := strings.CutPrefix(u, "TYPE"); ok && rest != "" {
		if n, err := strconv.ParseUint(rest, 10, 16); err == nil {
			return uint16(n), nil
		}
	}
	return 0, fmt.Errorf("Unknown DNS type '%s'", s) //nolint:staticcheck // sdig's exact message
}

func pdnsClassName(c uint16) string {
	switch c {
	case dns.ClassINET:
		return "IN"
	case dns.ClassCHAOS:
		return "CHAOS"
	case dns.ClassNONE:
		return "NONE"
	case dns.ClassANY:
		return "ANY"
	}
	return "CLASS" + strconv.Itoa(int(c))
}

// pdnsName renders a (miekg presentation-format) name like DNSName::toString:
// trailing dot, '.' and '\' escaped, bytes outside 0x21-0x7e as \DDD.
func pdnsName(name string) string {
	buf := make([]byte, 256)
	off, err := dns.PackDomainName(dns.Fqdn(name), buf, 0, nil, false)
	if err != nil {
		return name
	}
	return pdnsWireName(buf[:off])
}

// pdnsWireName renders an uncompressed wire-format name.
func pdnsWireName(wire []byte) string {
	var b strings.Builder
	for i := 0; i < len(wire); {
		l := int(wire[i])
		if l == 0 || i+1+l > len(wire) {
			break
		}
		for _, c := range wire[i+1 : i+1+l] {
			switch {
			case c == '.':
				b.WriteString(`\.`)
			case c == '\\':
				b.WriteString(`\\`)
			case c > 0x20 && c < 0x7f:
				b.WriteByte(c)
			default:
				fmt.Fprintf(&b, "\\%03d", c)
			}
		}
		b.WriteByte('.')
		i += 1 + l
	}
	if b.Len() == 0 {
		return "."
	}
	return b.String()
}

// txtEscape is PowerDNS's txtEscape.
func txtEscape(s []byte) string {
	var b strings.Builder
	for _, c := range s {
		switch {
		case c >= 127 || c < 32:
			fmt.Fprintf(&b, "\\%03d", c)
		case c == '"' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// rawRdata returns the uncompressed wire-format RDATA of rr.
func rawRdata(rr dns.RR) []byte {
	buf := make([]byte, dns.Len(rr)+512)
	off, err := dns.PackRR(rr, buf, 0, nil, false)
	if err != nil {
		return nil
	}
	n := int(rr.Header().Rdlength)
	if n > off {
		return nil
	}
	return buf[off-n : off]
}

// rdataReader reads PowerDNS-style fields from raw RDATA.
type rdataReader struct {
	b   []byte
	pos int
	err bool
}

func (r *rdataReader) u8() uint8 {
	if r.pos+1 > len(r.b) {
		r.err = true
		return 0
	}
	v := r.b[r.pos]
	r.pos++
	return v
}

func (r *rdataReader) u16() uint16 {
	if r.pos+2 > len(r.b) {
		r.err = true
		return 0
	}
	v := binary.BigEndian.Uint16(r.b[r.pos:])
	r.pos += 2
	return v
}

func (r *rdataReader) u32() uint32 {
	if r.pos+4 > len(r.b) {
		r.err = true
		return 0
	}
	v := binary.BigEndian.Uint32(r.b[r.pos:])
	r.pos += 4
	return v
}

func (r *rdataReader) bytes(n int) []byte {
	if n < 0 || r.pos+n > len(r.b) {
		r.err = true
		return nil
	}
	v := r.b[r.pos : r.pos+n]
	r.pos += n
	return v
}

func (r *rdataReader) rest() []byte { return r.bytes(len(r.b) - r.pos) }

func (r *rdataReader) name() string {
	start := r.pos
	for r.pos < len(r.b) {
		l := int(r.b[r.pos])
		if l&0xC0 != 0 { // no compression in rawRdata output
			r.err = true
			return ""
		}
		r.pos += 1 + l
		if l == 0 {
			return pdnsWireName(r.b[start:r.pos])
		}
	}
	r.err = true
	return ""
}

// text reads one <character-string> and returns it quoted and escaped.
func (r *rdataReader) text() string {
	l := int(r.u8())
	return `"` + txtEscape(r.bytes(l)) + `"`
}

// texts reads character-strings up to the end (PowerDNS getText(multi)).
func (r *rdataReader) texts() string {
	var parts []string
	for r.pos < len(r.b) && !r.err {
		parts = append(parts, r.text())
	}
	if len(parts) == 0 {
		return `""`
	}
	return strings.Join(parts, " ")
}

func hexOrDash(b []byte) string {
	if len(b) == 0 {
		return "-"
	}
	return hex.EncodeToString(b)
}

func pdnsTime(v uint32) string {
	return time.Unix(int64(v), 0).UTC().Format("20060102150405")
}

func pdnsBitmap(r *rdataReader) string {
	var types []int
	for r.pos < len(r.b) && !r.err {
		window := int(r.u8())
		l := int(r.u8())
		bm := r.bytes(l)
		for i, octet := range bm {
			for bit := 0; bit < 8; bit++ {
				if octet&(0x80>>bit) != 0 {
					types = append(types, window*256+i*8+bit)
				}
			}
		}
	}
	sort.Ints(types)
	var b strings.Builder
	for _, t := range types {
		b.WriteString(" " + PDNSTypeName(uint16(t)))
	}
	return b.String()
}

func unknownRep(raw []byte) string {
	s := `\# ` + strconv.Itoa(len(raw))
	if len(raw) > 0 {
		s += " " + hex.EncodeToString(raw)
	}
	return s
}

// pdnsZoneRep renders rr's data like PowerDNS's getZoneRepresentation().
// Types not reproduced exactly fall back to miekg/dns's presentation format.
func pdnsZoneRep(rr dns.RR) string {
	h := rr.Header()
	raw := rawRdata(rr)
	class := h.Class
	if h.Rrtype == dns.TypeOPT {
		class = dns.ClassINET // class is the buffer size for OPT
	}
	if class != dns.ClassINET && !(class == dns.ClassCHAOS && h.Rrtype == dns.TypeTXT) {
		return unknownRep(raw)
	}
	if _, isRFC3597 := rr.(*dns.RFC3597); isRFC3597 {
		return unknownRep(raw)
	}
	r := &rdataReader{b: raw}
	var s string
	switch h.Rrtype {
	case dns.TypeA:
		ip := r.bytes(4)
		s = net.IP(ip).String()
	case dns.TypeAAAA:
		ip := net.IP(r.bytes(16))
		s = ip.String()
		if ip4 := ip.To4(); ip4 != nil && len(ip) == 16 {
			s = "::ffff:" + ip4.String()
		}
	case dns.TypeNS, dns.TypePTR, dns.TypeCNAME, dns.TypeDNAME, dns.TypeMB, dns.TypeMG, dns.TypeMR:
		s = r.name()
	case dns.TypeMINFO, dns.TypeRP:
		s = r.name()
		s += " " + r.name()
	case dns.TypeTXT, dns.TypeSPF, 261, 262: // RESINFO, WALLET
		s = r.texts()
	case dns.TypeHINFO:
		s = r.text()
		s += " " + r.text()
	case dns.TypeMX, dns.TypeKX, dns.TypeAFSDB:
		p := r.u16()
		s = fmt.Sprintf("%d %s", p, r.name())
	case dns.TypeSOA:
		mname, rname := r.name(), r.name()
		s = fmt.Sprintf("%s %s %d %d %d %d %d", mname, rname, r.u32(), r.u32(), r.u32(), r.u32(), r.u32())
	case dns.TypeSRV:
		p, w, port := r.u16(), r.u16(), r.u16()
		s = fmt.Sprintf("%d %d %d %s", p, w, port, r.name())
	case dns.TypeNAPTR:
		o, p := r.u16(), r.u16()
		fl, sv, re := r.text(), r.text(), r.text()
		s = fmt.Sprintf("%d %d %s %s %s %s", o, p, fl, sv, re, r.name())
	case dns.TypeCAA:
		fl := r.u8()
		tag := r.bytes(int(r.u8()))
		val := r.rest()
		s = fmt.Sprintf("%d %s \"%s\"", fl, tag, txtEscape(val))
	case dns.TypeURI:
		p, w := r.u16(), r.u16()
		s = fmt.Sprintf("%d %d \"%s\"", p, w, txtEscape(r.rest()))
	case dns.TypeDS, dns.TypeCDS, dns.TypeDLV:
		tag, alg, dt := r.u16(), r.u8(), r.u8()
		s = fmt.Sprintf("%d %d %d %s", tag, alg, dt, hexOrDash(r.rest()))
	case dns.TypeSSHFP:
		alg, fp := r.u8(), r.u8()
		s = fmt.Sprintf("%d %d %s", alg, fp, hexOrDash(r.rest()))
	case dns.TypeTLSA, dns.TypeSMIMEA:
		u, sel, mt := r.u8(), r.u8(), r.u8()
		s = fmt.Sprintf("%d %d %d %s", u, sel, mt, hexOrDash(r.rest()))
	case dns.TypeDNSKEY, dns.TypeCDNSKEY, dns.TypeKEY:
		fl, proto, alg := r.u16(), r.u8(), r.u8()
		s = fmt.Sprintf("%d %d %d %s", fl, proto, alg, base64.StdEncoding.EncodeToString(r.rest()))
	case dns.TypeRRSIG:
		tc, alg, labels, ottl := r.u16(), r.u8(), r.u8(), r.u32()
		exp, inc, tag := r.u32(), r.u32(), r.u16()
		signer := r.name()
		s = fmt.Sprintf("%s %d %d %d %s %s %d %s %s", PDNSTypeName(tc), alg, labels, ottl,
			pdnsTime(exp), pdnsTime(inc), tag, signer, base64.StdEncoding.EncodeToString(r.rest()))
	case dns.TypeNSEC:
		s = r.name() + pdnsBitmap(r)
	case dns.TypeNSEC3:
		alg, fl, it := r.u8(), r.u8(), r.u16()
		salt := r.bytes(int(r.u8()))
		next := r.bytes(int(r.u8()))
		s = fmt.Sprintf("%d %d %d %s %s", alg, fl, it, hexOrDash(salt), strings.ToUpper(base32HexNoPad(next))) + pdnsBitmap(r)
	case dns.TypeNSEC3PARAM:
		alg, fl, it := r.u8(), r.u8(), r.u16()
		s = fmt.Sprintf("%d %d %d %s", alg, fl, it, hexOrDash(r.bytes(int(r.u8()))))
	case dns.TypeOPT:
		s = base64.StdEncoding.EncodeToString(raw)
	default:
		if _, known := pdnsTypes[h.Rrtype]; !known {
			return unknownRep(raw)
		}
		// Approximation: miekg/dns presentation format of the data.
		full := rr.String()
		hdr := h.String()
		return strings.TrimPrefix(full, hdr)
	}
	if r.err {
		return unknownRep(raw)
	}
	return s
}

// base32HexNoPad is RFC 4648 base32hex without padding (NSEC3 hashes).
func base32HexNoPad(b []byte) string {
	const alphabet = "0123456789abcdefghijklmnopqrstuv"
	var out strings.Builder
	var buf uint64
	bits := 0
	for _, c := range b {
		buf = buf<<8 | uint64(c)
		bits += 8
		for bits >= 5 {
			out.WriteByte(alphabet[(buf>>(bits-5))&31])
			bits -= 5
		}
	}
	if bits > 0 {
		out.WriteByte(alphabet[(buf<<(5-bits))&31])
	}
	return out.String()
}

// ednsOptionLines renders the EDNS options of an OPT RDATA as sdig prints
// them on stderr.
func ednsOptionLines(raw []byte) []string {
	var lines []string
	for pos := 0; len(raw) >= pos+4; {
		code := binary.BigEndian.Uint16(raw[pos:])
		l := int(binary.BigEndian.Uint16(raw[pos+2:]))
		pos += 4
		if pos+l > len(raw) {
			break
		}
		data := raw[pos : pos+l]
		pos += l
		switch code {
		case dns.EDNS0SUBNET:
			if s, ok := ecsString(data); ok {
				lines = append(lines, "EDNS Subnet response: "+s)
			}
		case dns.EDNS0COOKIE:
			var client, server []byte
			if len(data) >= 8 {
				client, server = data[:8], data[8:]
			}
			dump := hex.EncodeToString(client) + hex.EncodeToString(server)
			if len(client) == 8 && (len(server) == 0 || (len(server) >= 8 && len(server) <= 32)) {
				lines = append(lines, "EDNS Cookie response: "+dump)
			} else {
				lines = append(lines, "EDNS Cookie response malformed: "+dump)
			}
		case dns.EDNS0PADDING:
			lines = append(lines, "EDNS Padding size: "+strconv.Itoa(l))
		case dns.EDNS0EDE:
			if len(data) >= 2 {
				lines = append(lines, fmt.Sprintf("EDNS Extended Error response: %d/%s", binary.BigEndian.Uint16(data), data[2:]))
			}
		default:
			lines = append(lines, "Have unknown option "+strconv.Itoa(int(code)))
		}
	}
	return lines
}

// ecsString formats an ECS option like sdig: "source, scope: scope, family = N".
func ecsString(data []byte) (string, bool) {
	if len(data) < 4 {
		return "", false
	}
	family := binary.BigEndian.Uint16(data)
	source, scope := int(data[2]), int(data[3])
	octets := 0
	if source > 0 {
		octets = (source-1)/8 + 1
	}
	if len(data) != 4+octets {
		return "", false
	}
	var ip net.IP
	var bits, af int
	switch family {
	case 1:
		if octets > 4 {
			return "", false
		}
		ip, bits, af = make(net.IP, 4), 32, syscall.AF_INET
	case 2:
		if octets > 16 {
			return "", false
		}
		ip, bits, af = make(net.IP, 16), 128, syscall.AF_INET6
	default:
		return "", false
	}
	copy(ip, data[4:])
	// Netmask(source) masks the address; the scope Netmask is built from
	// that masked network and masked again by the scope length.
	source, scope = min(source, bits), min(scope, bits)
	src := ip.Mask(net.CIDRMask(source, bits))
	scoped := src.Mask(net.CIDRMask(scope, bits))
	return fmt.Sprintf("%s/%d, scope: %s/%d, family = %d", src, source, scoped, scope, af), true
}

// ParseNetmask parses "addr/bits" or a bare address (full-length mask), like
// PowerDNS's Netmask.
func ParseNetmask(s string) (*net.IPNet, error) {
	if !strings.Contains(s, "/") {
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, fmt.Errorf("Unable to convert '%s' to a netmask", s) //nolint:staticcheck // sdig's exact message
		}
		if ip4 := ip.To4(); ip4 != nil {
			return &net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)}, nil
		}
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}, nil
	}
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		return nil, fmt.Errorf("Unable to convert '%s' to a netmask", s) //nolint:staticcheck // sdig's exact message
	}
	return n, nil
}

// RandomCookie returns an 8-byte random client cookie (sdig "cookie -").
func RandomCookie() []byte {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return b
}
