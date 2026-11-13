// Package zonefile models DNS zones and converts them between provider
// formats: BIND zone files, the Cloudflare DNS records API, Route 53
// (list-resource-record-sets output and change batches), Terraform, OctoDNS,
// DNSControl, CSV and dlookup's own JSON.
//
// Records are kept in RFC 1035 presentation format, so any format that can be
// expressed as standard DNS records converts losslessly. Provider-specific
// extras survive where the target can express them: the Cloudflare proxy flag
// (Record.Proxied) and Route 53 alias records (the pseudo type "ALIAS", see
// AliasType).
package zonefile

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

// Record is a single resource record in presentation form.
type Record struct {
	Name    string `json:"name"`              // FQDN, lowercase, trailing dot
	Type    string `json:"type"`              // "A", "MX", ...
	TTL     uint32 `json:"ttl,omitempty"`     // 0 = unspecified/auto
	Data    string `json:"data"`              // RDATA in RFC 1035 presentation format, e.g. "10 mail.example.com."
	Proxied *bool  `json:"proxied,omitempty"` // Cloudflare proxy flag, nil if unknown
	Comment string `json:"comment,omitempty"`
}

// Zone is a set of records under an origin.
type Zone struct {
	Origin  string   `json:"origin"` // FQDN with trailing dot
	Records []Record `json:"records"`
}

// Format identifies a zone file format.
type Format string

const (
	BIND                Format = "bind"
	Cloudflare          Format = "cloudflare"
	Route53             Format = "route53"
	Route53Change       Format = "route53-change"
	Terraform           Format = "terraform"
	TerraformCloudflare Format = "terraform-cloudflare"
	OctoDNS             Format = "octodns"
	DNSControl          Format = "dnscontrol"
	CSV                 Format = "csv"
	JSON                Format = "json" // dlookup's own: Zone as JSON
)

// AliasType is the pseudo record type of provider alias records (Route 53
// alias targets, ALIAS/ANAME/flattened CNAMEs). Data is the target FQDN. For
// Route 53 aliases the Comment carries "route53: alias-type=A
// alias-zone=Z2FDTNDATAQYW2 evaluate-target-health=false".
const AliasType = "ALIAS"

// FormatInfo describes a format.
type FormatInfo struct {
	Format      Format
	Read, Write bool
	Ext         string // default file extension, with dot
	Description string
}

var formatInfos = []FormatInfo{
	{BIND, true, true, ".zone", "RFC 1035 zone file (also Cloudflare dashboard import/export)"},
	{Cloudflare, true, true, ".json", "Cloudflare API dns_records JSON"},
	{Route53, true, true, ".json", "aws route53 list-resource-record-sets output"},
	{Route53Change, true, true, ".json", "aws route53 change-resource-record-sets change batch"},
	{Terraform, false, true, ".tf", "Terraform aws_route53_record resources"},
	{TerraformCloudflare, false, true, ".tf", "Terraform cloudflare_dns_record resources (provider v5)"},
	{OctoDNS, true, true, ".yaml", "OctoDNS YAML zone config"},
	{DNSControl, false, true, ".js", "DNSControl dnsconfig.js D() block"},
	{CSV, true, true, ".csv", "CSV: name,type,ttl,data,proxied,comment"},
	{JSON, true, true, ".json", "dlookup zone JSON"},
}

// Formats returns all formats in display order.
func Formats() []Format {
	out := make([]Format, len(formatInfos))
	for i, fi := range formatInfos {
		out[i] = fi.Format
	}
	return out
}

// Info returns the description of f.
func Info(f Format) (FormatInfo, bool) {
	for _, fi := range formatInfos {
		if fi.Format == f {
			return fi, true
		}
	}
	return FormatInfo{}, false
}

// CanRead reports whether Parse supports f.
func CanRead(f Format) bool { fi, ok := Info(f); return ok && fi.Read }

// CanWrite reports whether Write supports f.
func CanWrite(f Format) bool { fi, ok := Info(f); return ok && fi.Write }

// Extension returns the default file extension of f (".zone", ".json"...).
func Extension(f Format) string {
	fi, _ := Info(f)
	return fi.Ext
}

// ParseFormat parses a format name (case-insensitive; a few aliases such as
// "zone", "r53", "tf", "yaml" are accepted).
func ParseFormat(s string) (Format, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "zone", "zonefile", "rfc1035":
		return BIND, nil
	case "cf":
		return Cloudflare, nil
	case "r53", "aws":
		return Route53, nil
	case "r53-change", "route53change", "change-batch":
		return Route53Change, nil
	case "tf", "terraform-aws", "terraform-route53":
		return Terraform, nil
	case "tf-cloudflare", "terraform-cf", "tf-cf":
		return TerraformCloudflare, nil
	case "yaml", "yml", "octo":
		return OctoDNS, nil
	case "js", "dnsconfig":
		return DNSControl, nil
	}
	for _, f := range Formats() {
		if string(f) == s {
			return f, nil
		}
	}
	names := make([]string, 0, len(formatInfos))
	for _, f := range Formats() {
		names = append(names, string(f))
	}
	return "", fmt.Errorf("unknown format %q (want one of %s)", s, strings.Join(names, ", "))
}

// DefaultSkipApexNSSOA reports whether writing f should leave out the apex
// NS and SOA records by default: true for formats that drive a DNS provider,
// which owns those records itself.
func DefaultSkipApexNSSOA(f Format) bool {
	switch f {
	case Route53Change, Terraform, TerraformCloudflare, Cloudflare, DNSControl:
		return true
	}
	return false
}

// WriteOptions tune Write.
type WriteOptions struct {
	DefaultTTL       uint32 // TTL for records without one (0: per-format default)
	Route53ZoneID    string // hosted zone id, noted in change batch comments
	Route53Action    string // change batch action: UPSERT (default), CREATE or DELETE
	TerraformZoneRef string // zone_id expression or literal; default var.zone_id
	SkipApexNSSOA    bool   // leave out NS and SOA records at the origin
}

// Parse reads a zone in format f. origin may be "" when the format carries it
// ($ORIGIN or SOA in BIND, zone_name in Cloudflare, SOA/NS apex in Route 53,
// the origin field in JSON); otherwise it is inferred from the record names.
// The returned zone is normalized.
func Parse(r io.Reader, f Format, origin string) (*Zone, error) {
	if origin != "" {
		origin = Fqdn(origin)
	}
	var (
		z   *Zone
		err error
	)
	switch f {
	case BIND:
		z, err = parseBIND(r, origin)
	case Cloudflare:
		z, err = parseCloudflare(r, origin)
	case Route53, Route53Change:
		z, err = parseRoute53(r, origin)
	case OctoDNS:
		z, err = parseOctoDNS(r, origin)
	case CSV:
		z, err = parseCSV(r, origin)
	case JSON:
		z, err = parseJSON(r, origin)
	default:
		if _, ok := Info(f); ok {
			return nil, fmt.Errorf("format %s can only be written, not read", f)
		}
		return nil, fmt.Errorf("unknown format %q", f)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", f, err)
	}
	if z.Origin == "" {
		z.Origin = inferOrigin(z.Records)
	}
	if z.Origin == "" {
		return nil, fmt.Errorf("%s: cannot determine the zone origin; specify it", f)
	}
	if f != BIND {
		// Outside zone files, names in RDATA are absolute even without the
		// trailing dot ("mail.example.com").
		for i := range z.Records {
			r := &z.Records[i]
			r.Data = canonicalData(r.Name, strings.ToUpper(r.Type), strings.TrimSpace(r.Data), ".")
		}
	}
	z.Normalize()
	return z, nil
}

// Write writes z in format f. Records the format cannot express are skipped;
// use WriteWithWarnings to learn about them.
func Write(w io.Writer, z *Zone, f Format, opts WriteOptions) error {
	_, err := WriteWithWarnings(w, z, f, opts)
	return err
}

// WriteWithWarnings writes z in format f and returns warnings about records
// that were skipped or approximated.
func WriteWithWarnings(w io.Writer, z *Zone, f Format, opts WriteOptions) ([]string, error) {
	if z == nil {
		return nil, fmt.Errorf("nil zone")
	}
	zz := z.Clone()
	zz.Normalize()
	wr := &writer{opts: opts, origin: zz.Origin}
	recs := zz.Records
	if opts.SkipApexNSSOA {
		kept := recs[:0:0]
		for _, r := range recs {
			if r.Name == zz.Origin && (r.Type == "NS" || r.Type == "SOA") {
				continue
			}
			kept = append(kept, r)
		}
		recs = kept
	}
	zz.Records = recs
	switch f {
	case Route53, Route53Change, Terraform, CSV, JSON:
	default:
		for _, r := range recs {
			if m := parseR53Meta(r.Comment); m["set-id"] != "" {
				wr.warn("%s: Route 53 routing policies (set identifiers, weights, regions...) cannot be expressed; all values are written as plain records", f)
				break
			}
		}
	}
	var err error
	switch f {
	case BIND:
		err = writeBIND(w, zz, wr)
	case Cloudflare:
		err = writeCloudflare(w, zz, wr)
	case Route53:
		err = writeRoute53List(w, zz, wr)
	case Route53Change:
		err = writeRoute53Change(w, zz, wr)
	case Terraform:
		err = writeTerraformAWS(w, zz, wr)
	case TerraformCloudflare:
		err = writeTerraformCloudflare(w, zz, wr)
	case OctoDNS:
		err = writeOctoDNS(w, zz, wr)
	case DNSControl:
		err = writeDNSControl(w, zz, wr)
	case CSV:
		err = writeCSV(w, zz, wr)
	case JSON:
		err = writeJSON(w, zz)
	default:
		return nil, fmt.Errorf("unknown format %q", f)
	}
	return wr.warnings, err
}

// writer collects warnings while writing.
type writer struct {
	opts     WriteOptions
	origin   string
	warnings []string
}

func (w *writer) warn(format string, a ...any) {
	w.warnings = append(w.warnings, fmt.Sprintf(format, a...))
}

func (w *writer) skip(f Format, r Record, why string) {
	if why == "" {
		why = "type not supported"
	}
	w.warn("%s: skipped %s %s %s (%s)", f, r.Name, r.Type, r.Data, why)
}

// ttl returns the record's TTL, or the default for records without one.
func (w *writer) ttl(r Record, fallback uint32) uint32 {
	if r.TTL > 0 {
		return r.TTL
	}
	if w.opts.DefaultTTL > 0 {
		return w.opts.DefaultTTL
	}
	return fallback
}

// Clone returns a deep copy of z.
func (z *Zone) Clone() *Zone {
	out := &Zone{Origin: z.Origin, Records: make([]Record, len(z.Records))}
	copy(out.Records, z.Records)
	for i := range out.Records {
		if p := out.Records[i].Proxied; p != nil {
			v := *p
			out.Records[i].Proxied = &v
		}
	}
	return out
}

// Fqdn lowercases name and adds the trailing dot.
func Fqdn(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" || name == "." {
		return "."
	}
	return dns.Fqdn(name)
}

// absName makes name absolute under origin: "@" and "" are the origin,
// names ending in a dot are already absolute, others are relative.
func absName(name, origin string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	switch {
	case name == "" || name == "@":
		return origin
	case strings.HasSuffix(name, "."):
		return name
	case origin == "" || origin == ".":
		return name + "."
	case name == strings.TrimSuffix(origin, ".") || strings.HasSuffix(name, "."+strings.TrimSuffix(origin, ".")):
		// Already contains the origin (e.g. Cloudflare's "www.example.com").
		return name + "."
	}
	return name + "." + origin
}

// relName returns name relative to origin: "@" for the origin itself, the
// leading labels for names under it, the FQDN otherwise.
func relName(name, origin string) string {
	if name == origin {
		return "@"
	}
	if origin != "." && strings.HasSuffix(name, "."+origin) {
		return strings.TrimSuffix(name, "."+origin)
	}
	return name
}

// Normalize lowercases and qualifies owner names, upper-cases types,
// canonicalizes RDATA (relative names in RDATA are qualified with the origin),
// sorts the records (origin first, then by name, type and data) and removes
// duplicates.
func (z *Zone) Normalize() {
	if z.Origin != "" {
		z.Origin = Fqdn(z.Origin)
	}
	origin := z.Origin
	if origin == "" {
		origin = "."
	}
	for i := range z.Records {
		r := &z.Records[i]
		r.Name = absName(r.Name, origin)
		r.Type = strings.ToUpper(strings.TrimSpace(r.Type))
		r.Data = canonicalData(r.Name, r.Type, strings.TrimSpace(r.Data), origin)
		r.Comment = strings.TrimSpace(r.Comment)
	}
	sort.SliceStable(z.Records, func(i, j int) bool {
		a, b := z.Records[i], z.Records[j]
		if a.Name != b.Name {
			return nameLess(a.Name, b.Name, origin)
		}
		if a.Type != b.Type {
			return typeLess(a.Type, b.Type)
		}
		return a.Data < b.Data
	})
	out := z.Records[:0]
	seen := map[string]bool{}
	for _, r := range z.Records {
		k := r.Name + "\x00" + r.Type + "\x00" + r.Data
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, r)
	}
	z.Records = out
}

// nameLess orders the origin first, then names by their labels from the
// right (so a name sorts just after its parent), "*" before others.
func nameLess(a, b, origin string) bool {
	if a == origin || b == origin {
		return a == origin && b != origin
	}
	la, lb := dns.SplitDomainName(a), dns.SplitDomainName(b)
	for i, j := len(la)-1, len(lb)-1; i >= 0 && j >= 0; i, j = i-1, j-1 {
		if la[i] != lb[j] {
			return la[i] < lb[j]
		}
	}
	return len(la) < len(lb)
}

// typeOrder puts the zone's structural records first.
var typeOrder = map[string]int{"SOA": 0, "NS": 1}

func typeLess(a, b string) bool {
	oa, okA := typeOrder[a]
	ob, okB := typeOrder[b]
	switch {
	case okA && okB:
		return oa < ob
	case okA != okB:
		return okA
	}
	return a < b
}

// canonicalData re-renders data through miekg/dns when it parses as type typ,
// which qualifies relative names and normalizes spacing. Unparseable data and
// pseudo types are returned as given (ALIAS targets are qualified).
func canonicalData(name, typ, data, origin string) string {
	if typ == AliasType {
		return absName(data, origin)
	}
	if typ == "TXT" || typ == "SPF" {
		return QuoteTXT(splitLong(TXTStrings(data)))
	}
	rr, err := parseRR(name, 0, typ, data, origin)
	if err != nil {
		return data
	}
	return rdata(rr)
}

// parseRR parses one record from its parts; relative names in data are
// qualified with origin.
func parseRR(name string, ttl uint32, typ, data, origin string) (dns.RR, error) {
	if _, ok := dns.StringToType[typ]; !ok && !strings.HasPrefix(typ, "TYPE") {
		return nil, fmt.Errorf("unknown record type %q", typ)
	}
	if origin == "" {
		origin = "."
	}
	line := fmt.Sprintf("%s %d IN %s %s", name, ttl, typ, data)
	zp := dns.NewZoneParser(strings.NewReader(line), origin, "")
	rr, ok := zp.Next()
	if !ok {
		if err := zp.Err(); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("empty record")
	}
	if _, more := zp.Next(); more {
		return nil, fmt.Errorf("unexpected data after %s record", typ)
	}
	return rr, nil
}

// rdata returns rr's RDATA in presentation format.
func rdata(rr dns.RR) string {
	return strings.TrimSpace(strings.TrimPrefix(rr.String(), rr.Header().String()))
}

// RR parses r as a miekg/dns RR. ALIAS records have no DNS representation
// and return an error.
func (r Record) RR(origin string) (dns.RR, error) {
	if r.Type == AliasType {
		return nil, fmt.Errorf("%s %s is a provider alias, not a DNS record", r.Name, r.Type)
	}
	return parseRR(r.Name, r.TTL, r.Type, r.Data, origin)
}

// RRs converts the zone's records to miekg/dns RRs. Provider alias records
// (type ALIAS) are skipped; any other unparseable record is an error.
func (z *Zone) RRs() ([]dns.RR, error) {
	out := make([]dns.RR, 0, len(z.Records))
	for _, r := range z.Records {
		if r.Type == AliasType {
			continue
		}
		rr, err := r.RR(z.Origin)
		if err != nil {
			return out, fmt.Errorf("%s %s %s: %w", r.Name, r.Type, r.Data, err)
		}
		out = append(out, rr)
	}
	return out, nil
}

// FromRRs builds a normalized zone from miekg/dns RRs.
func FromRRs(origin string, rrs []dns.RR) *Zone {
	z := &Zone{Origin: origin}
	for _, rr := range rrs {
		if rr == nil {
			continue
		}
		h := rr.Header()
		z.Records = append(z.Records, Record{
			Name: Fqdn(h.Name),
			Type: dns.TypeToString[h.Rrtype],
			TTL:  h.Ttl,
			Data: rdata(rr),
		})
	}
	if z.Origin == "" {
		z.Origin = inferOrigin(z.Records)
	}
	z.Normalize()
	return z
}

// Names returns the zone's distinct owner names in zone order.
func (z *Zone) Names() []string {
	var out []string
	seen := map[string]bool{}
	for _, r := range z.Records {
		if !seen[r.Name] {
			seen[r.Name] = true
			out = append(out, r.Name)
		}
	}
	return out
}

// Lookup returns the records of name (relative names are qualified with the
// origin) and typ ("" or "ANY" for all types).
func (z *Zone) Lookup(name, typ string) []Record {
	origin := z.Origin
	if origin == "" {
		origin = "."
	}
	name = absName(name, origin)
	typ = strings.ToUpper(strings.TrimSpace(typ))
	var out []Record
	for _, r := range z.Records {
		if strings.EqualFold(r.Name, name) && (typ == "" || typ == "ANY" || r.Type == typ) {
			out = append(out, r)
		}
	}
	return out
}

// CountByType returns the number of records per type.
func (z *Zone) CountByType() map[string]int {
	out := map[string]int{}
	for _, r := range z.Records {
		out[r.Type]++
	}
	return out
}

// inferOrigin guesses the origin: the SOA owner, else the common suffix of
// the apex NS owners, else the longest common suffix of all names (at least
// two labels).
func inferOrigin(recs []Record) string {
	for _, r := range recs {
		if strings.EqualFold(r.Type, "SOA") && strings.HasSuffix(r.Name, ".") {
			return Fqdn(r.Name)
		}
	}
	var names []string
	for _, r := range recs {
		if r.Name != "" {
			names = append(names, Fqdn(r.Name))
		}
	}
	if len(names) == 0 {
		return ""
	}
	common := dns.SplitDomainName(names[0])
	for _, n := range names[1:] {
		labels := dns.SplitDomainName(n)
		k := 0
		for k < len(common) && k < len(labels) && common[len(common)-1-k] == labels[len(labels)-1-k] {
			k++
		}
		common = common[len(common)-k:]
	}
	if len(common) < 2 {
		if len(common) == 1 && len(names) == 1 {
			return dns.Fqdn(common[0])
		}
		return ""
	}
	return dns.Fqdn(strings.Join(common, "."))
}

// TXTStrings splits TXT presentation data into its unescaped character
// strings. Unquoted input that does not start with a quote is taken verbatim
// as a single string.
func TXTStrings(data string) []string {
	data = strings.TrimSpace(data)
	if data == "" {
		return []string{""}
	}
	if !strings.HasPrefix(data, `"`) {
		return []string{data}
	}
	var (
		out []string
		cur []byte
		in  bool
	)
	for i := 0; i < len(data); i++ {
		c := data[i]
		switch {
		case c == '\\' && i+1 < len(data):
			if i+3 < len(data) && isDigit(data[i+1]) && isDigit(data[i+2]) && isDigit(data[i+3]) {
				v := int(data[i+1]-'0')*100 + int(data[i+2]-'0')*10 + int(data[i+3]-'0')
				if v < 256 {
					cur = append(cur, byte(v))
					i += 3
					continue
				}
			}
			cur = append(cur, data[i+1])
			i++
		case c == '"':
			if in {
				out = append(out, string(cur))
				cur = cur[:0]
			}
			in = !in
		case !in && (c == ' ' || c == '\t'):
		default:
			cur = append(cur, c)
		}
	}
	if in || len(cur) > 0 {
		out = append(out, string(cur))
	}
	if len(out) == 0 {
		out = []string{""}
	}
	return out
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// QuoteTXT renders character strings as TXT presentation data.
func QuoteTXT(strs []string) string {
	parts := make([]string, len(strs))
	for i, s := range strs {
		var b strings.Builder
		b.WriteByte('"')
		for j := 0; j < len(s); j++ {
			c := s[j]
			switch {
			case c == '"' || c == '\\':
				b.WriteByte('\\')
				b.WriteByte(c)
			case c < 0x20 || c >= 0x7f:
				fmt.Fprintf(&b, "\\%03d", c)
			default:
				b.WriteByte(c)
			}
		}
		b.WriteByte('"')
		parts[i] = b.String()
	}
	return strings.Join(parts, " ")
}

// splitLong splits strings longer than 255 bytes into 255-byte chunks, as
// one DNS character string cannot be longer.
func splitLong(strs []string) []string {
	var out []string
	for _, s := range strs {
		for len(s) > 255 {
			out = append(out, s[:255])
			s = s[255:]
		}
		out = append(out, s)
	}
	return out
}

// TXTValue returns the TXT data as one unescaped string (its character
// strings concatenated).
func TXTValue(data string) string { return strings.Join(TXTStrings(data), "") }

// ---- JSON (dlookup's own format) ----

func parseJSON(r io.Reader, origin string) (*Zone, error) {
	var z Zone
	dec := json.NewDecoder(r)
	if err := dec.Decode(&z); err != nil {
		return nil, err
	}
	if origin != "" {
		z.Origin = origin
	}
	if z.Origin != "" {
		z.Origin = Fqdn(z.Origin)
	}
	return &z, nil
}

func writeJSON(w io.Writer, z *Zone) error {
	if z.Records == nil {
		z.Records = []Record{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(z)
}
