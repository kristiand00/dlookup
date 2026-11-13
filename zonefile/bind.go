package zonefile

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

var (
	originDirective = regexp.MustCompile(`(?m)^\$ORIGIN\s+(\S+)`)
	cfProxiedTag    = regexp.MustCompile(`\s*cf_tags=([^\s;]*)`)
)

func parseBIND(r io.Reader, origin string) (*Zone, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	text := string(raw)
	if origin == "" {
		if m := originDirective.FindStringSubmatch(text); m != nil {
			origin = Fqdn(m[1])
		}
	}
	if origin == "" {
		// Absolute names only? Take the SOA owner as the origin.
		z, err := parseBINDWith(text, ".")
		if err == nil {
			for _, rec := range z.Records {
				if rec.Type == "SOA" && rec.Name != "." {
					origin = rec.Name
					break
				}
			}
			if origin == "" {
				origin = inferOrigin(z.Records)
			}
		}
		if origin == "" || origin == "." {
			return nil, fmt.Errorf("the zone file has no $ORIGIN or SOA with an absolute name; specify the origin")
		}
	}
	return parseBINDWith(text, origin)
}

func parseBINDWith(text, origin string) (*Zone, error) {
	zp := dns.NewZoneParser(strings.NewReader(text), origin, "")
	zp.SetIncludeAllowed(false)
	z := &Zone{Origin: origin}
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		h := rr.Header()
		rec := Record{
			Name: Fqdn(h.Name),
			Type: dns.TypeToString[h.Rrtype],
			TTL:  h.Ttl,
			Data: rdata(rr),
		}
		if rec.Type == "" {
			rec.Type = fmt.Sprintf("TYPE%d", h.Rrtype)
		}
		c := strings.TrimSpace(strings.TrimLeft(zp.Comment(), "; \t"))
		// Cloudflare's export marks proxied records "cf_tags=cf-proxied:true".
		if m := cfProxiedTag.FindStringSubmatch(c); m != nil {
			for _, tag := range strings.Split(m[1], ",") {
				if v, ok := strings.CutPrefix(tag, "cf-proxied:"); ok {
					b := v == "true"
					rec.Proxied = &b
				}
			}
			c = strings.TrimSpace(cfProxiedTag.ReplaceAllString(c, ""))
		}
		if rec.Type != "SOA" { // SOA comments just label its fields
			rec.Comment = c
		}
		z.Records = append(z.Records, rec)
	}
	if err := zp.Err(); err != nil {
		return nil, err
	}
	return z, nil
}

// commonTTL is the most frequent non-zero TTL (ties: the smallest), or def.
func commonTTL(recs []Record, def uint32) uint32 {
	counts := map[uint32]int{}
	for _, r := range recs {
		if r.TTL > 0 {
			counts[r.TTL]++
		}
	}
	best, bestN := def, 0
	for ttl, n := range counts {
		if n > bestN || n == bestN && ttl < best {
			best, bestN = ttl, n
		}
	}
	return best
}

func writeBIND(w io.Writer, z *Zone, wr *writer) error {
	bw := bufio.NewWriter(w)
	defTTL := wr.opts.DefaultTTL
	if defTTL == 0 {
		defTTL = commonTTL(z.Records, 3600)
	}
	fmt.Fprintf(bw, "; Zone %s, written by dlookup\n", z.Origin)
	fmt.Fprintf(bw, "$ORIGIN %s\n$TTL %d\n", z.Origin, defTTL)

	nameW, ttlW, typeW := 1, 0, 1
	for _, r := range z.Records {
		nameW = max(nameW, min(len(relName(r.Name, z.Origin)), 32))
		if r.TTL != 0 && r.TTL != defTTL {
			ttlW = max(ttlW, len(strconv.FormatUint(uint64(r.TTL), 10)))
		}
		typeW = max(typeW, len(r.Type))
	}

	prev := ""
	for _, r := range z.Records {
		name := relName(r.Name, z.Origin)
		if r.Type == AliasType {
			wr.warn("bind: %s ALIAS %s written as a comment (no DNS record type for provider aliases)", r.Name, r.Data)
			fmt.Fprintf(bw, "; %s ALIAS %s", name, r.Data)
			if r.Comment != "" {
				fmt.Fprintf(bw, " (%s)", r.Comment)
			}
			_, _ = bw.WriteString("\n")
			continue
		}
		if _, ok := dns.StringToType[r.Type]; !ok && !strings.HasPrefix(r.Type, "TYPE") {
			wr.skip(BIND, r, "unknown record type")
			continue
		}
		owner := name
		if r.Name == prev {
			owner = ""
		} else if prev != "" {
			_, _ = bw.WriteString("\n")
		}
		prev = r.Name
		ttl := ""
		if r.TTL != 0 && r.TTL != defTTL {
			ttl = strconv.FormatUint(uint64(r.TTL), 10)
		}
		data := r.Data
		if r.Type == "SOA" {
			data = soaMultiline(data, nameW+ttlW+typeW+6)
		}
		line := fmt.Sprintf("%-*s ", nameW, owner)
		if ttlW > 0 {
			line += fmt.Sprintf("%*s ", ttlW, ttl)
		}
		line += fmt.Sprintf("IN %-*s %s", typeW, r.Type, data)
		var comment []string
		if r.Proxied != nil {
			comment = append(comment, "cf_tags=cf-proxied:"+strconv.FormatBool(*r.Proxied))
		}
		if r.Comment != "" {
			comment = append(comment, strings.ReplaceAll(r.Comment, "\n", " "))
		}
		if len(comment) > 0 && r.Type != "SOA" {
			line += " ; " + strings.Join(comment, " ")
		}
		_, _ = bw.WriteString(strings.TrimRight(line, " ") + "\n") // errors surface from Flush
	}
	return bw.Flush()
}

// soaMultiline lays out SOA data over several lines with field comments.
func soaMultiline(data string, indent int) string {
	f := strings.Fields(data)
	if len(f) != 7 {
		return data
	}
	pad := "\n" + strings.Repeat(" ", indent+2)
	labels := []string{"serial", "refresh", "retry", "expire", "minimum"}
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s (", f[0], f[1])
	for i, l := range labels {
		fmt.Fprintf(&b, "%s%-10s ; %s", pad, f[2+i], l)
	}
	b.WriteString(pad + ")")
	return b.String()
}
