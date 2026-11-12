package zonefile

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// hclString quotes s as an HCL string literal.
func hclString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c == '\n':
			b.WriteString(`\n`)
		case c == '\t':
			b.WriteString(`\t`)
		case (c == '$' || c == '%') && i+1 < len(s) && s[i+1] == '{':
			b.WriteByte(c)
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

var hclExpr = regexp.MustCompile(`^(var|local|data|module)\.[A-Za-z0-9_.\[\]"-]+$|^[a-z][a-z0-9_]*\.[A-Za-z0-9_]+\.[A-Za-z0-9_.]+$`)

// zoneRef renders the zone id: a Terraform expression as is, anything else
// (a literal zone id) quoted.
func zoneRef(ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		ref = "var.zone_id"
	}
	if hclExpr.MatchString(ref) {
		return ref
	}
	return hclString(ref)
}

var (
	nonIdent        = regexp.MustCompile(`[^a-z0-9_-]+`)
	multiUnderscore = regexp.MustCompile(`_{2,}`)
)

// resourceNamer hands out unique, valid Terraform resource names.
type resourceNamer map[string]int

func (n resourceNamer) name(owner, origin, typ string) string {
	rel := relName(owner, origin)
	switch {
	case rel == "@":
		rel = "apex"
	case rel == "*":
		rel = "wildcard"
	case strings.HasPrefix(rel, "*."):
		rel = "wildcard_" + rel[2:]
	}
	s := nonIdent.ReplaceAllString(strings.ToLower(strings.TrimSuffix(rel, ".")+"_"+typ), "_")
	s = strings.Trim(multiUnderscore.ReplaceAllString(s, "_"), "_-")
	if s == "" || !(s[0] >= 'a' && s[0] <= 'z' || s[0] == '_') {
		s = "r_" + s
	}
	n[s]++
	if c := n[s]; c > 1 {
		return s + "_" + strconv.Itoa(c)
	}
	return s
}

// hclBlock writes "key = value" lines aligned like terraform fmt.
type hclAttr struct{ k, v string }

func writeAttrs(w *bufio.Writer, indent string, attrs []hclAttr) {
	width := 0
	for _, a := range attrs {
		if !strings.Contains(a.v, "\n") {
			width = max(width, len(a.k))
		}
	}
	for _, a := range attrs {
		fmt.Fprintf(w, "%s%-*s = %s\n", indent, width, a.k, a.v)
	}
}

func writeHeader(w *bufio.Writer, z *Zone, ref string) {
	fmt.Fprintf(w, "# DNS records of %s, written by dlookup.\n", strings.TrimSuffix(z.Origin, "."))
	if strings.HasPrefix(ref, "var.") {
		fmt.Fprintf(w, "# Declare the zone id variable if your configuration doesn't already:\n# variable %q { type = string }\n", strings.TrimPrefix(ref, "var."))
	}
}

func writeTerraformAWS(w io.Writer, z *Zone, wr *writer) error {
	bw := bufio.NewWriter(w)
	ref := zoneRef(wr.opts.TerraformZoneRef)
	writeHeader(bw, z, ref)
	names := resourceNamer{}
	for _, s := range r53Sets(z, wr, Terraform, false) {
		fmt.Fprintf(bw, "\nresource \"aws_route53_record\" %q {\n", names.name(s.Name, z.Origin, s.Type))
		attrs := []hclAttr{
			{"zone_id", ref},
			{"name", hclString(strings.TrimSuffix(s.Name, "."))},
			{"type", hclString(s.Type)},
		}
		if s.SetIdentifier != "" {
			attrs = append(attrs, hclAttr{"set_identifier", hclString(s.SetIdentifier)})
		}
		if s.HealthCheckId != "" {
			attrs = append(attrs, hclAttr{"health_check_id", hclString(s.HealthCheckId)})
		}
		if s.MultiValueAnswer != nil {
			attrs = append(attrs, hclAttr{"multivalue_answer_routing_policy", strconv.FormatBool(*s.MultiValueAnswer)})
		}
		if s.AliasTarget == nil {
			attrs = append(attrs, hclAttr{"ttl", strconv.FormatUint(uint64(*s.TTL), 10)})
			vals := make([]string, len(s.ResourceRecords))
			for i, v := range s.ResourceRecords {
				val := v.Value
				if s.Type == "TXT" || s.Type == "SPF" {
					// The provider quotes the value; "" separates strings.
					val = strings.Join(TXTStrings(val), `""`)
				}
				vals[i] = hclString(val)
			}
			attrs = append(attrs, hclAttr{"records", "[" + strings.Join(vals, ", ") + "]"})
		}
		writeAttrs(bw, "  ", attrs)
		if a := s.AliasTarget; a != nil {
			bw.WriteString("\n  alias {\n")
			writeAttrs(bw, "    ", []hclAttr{
				{"name", hclString(a.DNSName)},
				{"zone_id", hclString(a.HostedZoneId)},
				{"evaluate_target_health", strconv.FormatBool(a.EvaluateTargetHealth)},
			})
			bw.WriteString("  }\n")
		}
		if s.Weight != nil {
			fmt.Fprintf(bw, "\n  weighted_routing_policy {\n    weight = %d\n  }\n", *s.Weight)
		}
		if s.Region != "" {
			fmt.Fprintf(bw, "\n  latency_routing_policy {\n    region = %s\n  }\n", hclString(s.Region))
		}
		if s.Failover != "" {
			fmt.Fprintf(bw, "\n  failover_routing_policy {\n    type = %s\n  }\n", hclString(s.Failover))
		}
		bw.WriteString("}\n")
	}
	return bw.Flush()
}

func writeTerraformCloudflare(w io.Writer, z *Zone, wr *writer) error {
	bw := bufio.NewWriter(w)
	ref := zoneRef(wr.opts.TerraformZoneRef)
	writeHeader(bw, z, ref)
	names := resourceNamer{}
	for _, r := range z.Records {
		c, ok := recordToCF(r, wr, TerraformCloudflare)
		if !ok {
			continue
		}
		fmt.Fprintf(bw, "\nresource \"cloudflare_dns_record\" %q {\n", names.name(r.Name, z.Origin, c.Type))
		attrs := []hclAttr{
			{"zone_id", ref},
			{"name", hclString(c.Name)},
			{"type", hclString(c.Type)},
		}
		if c.Data == nil {
			attrs = append(attrs, hclAttr{"content", hclString(c.Content)})
		}
		attrs = append(attrs, hclAttr{"ttl", strconv.FormatUint(uint64(c.TTL), 10)})
		if c.Proxied != nil {
			attrs = append(attrs, hclAttr{"proxied", strconv.FormatBool(*c.Proxied)})
		}
		if c.Priority != nil && c.Type != "SRV" {
			attrs = append(attrs, hclAttr{"priority", strconv.Itoa(int(*c.Priority))})
		}
		if c.Comment != "" {
			attrs = append(attrs, hclAttr{"comment", hclString(c.Comment)})
		}
		writeAttrs(bw, "  ", attrs)
		if c.Data != nil {
			keys := make([]string, 0, len(c.Data))
			for k := range c.Data {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			var da []hclAttr
			for _, k := range keys {
				switch v := c.Data[k].(type) {
				case string:
					da = append(da, hclAttr{k, hclString(v)})
				default:
					da = append(da, hclAttr{k, fmt.Sprint(v)})
				}
			}
			bw.WriteString("  data = {\n")
			writeAttrs(bw, "    ", da)
			bw.WriteString("  }\n")
		}
		bw.WriteString("}\n")
	}
	return bw.Flush()
}
