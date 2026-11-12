package zonefile

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/miekg/dns"
)

// jsString quotes s as a JavaScript string literal.
func jsString(s string) string {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return strings.TrimSpace(b.String())
}

func writeDNSControl(w io.Writer, z *Zone, wr *writer) error {
	bw := bufio.NewWriter(w)
	defTTL := wr.opts.DefaultTTL
	if defTTL == 0 {
		defTTL = commonTTL(z.Records, 300)
	}
	domain := strings.TrimSuffix(z.Origin, ".")
	fmt.Fprintf(bw, "// DNS records of %s, written by dlookup.\n", domain)
	bw.WriteString("// Replace REG_NONE and DSP_NONE with your registrar and DNS provider.\n")
	bw.WriteString("var REG_NONE = NewRegistrar(\"none\");\nvar DSP_NONE = NewDnsProvider(\"none\");\n\n")
	fmt.Fprintf(bw, "D(%s, REG_NONE, DnsProvider(DSP_NONE),\n", jsString(domain))
	fmt.Fprintf(bw, "    DefaultTTL(%d),\n", defTTL)
	for _, r := range z.Records {
		call, err := dnscontrolCall(r, z.Origin, wr.origin)
		if err != nil {
			wr.skip(DNSControl, r, err.Error())
			continue
		}
		var mods []string
		if r.TTL != 0 && r.TTL != defTTL {
			mods = append(mods, fmt.Sprintf("TTL(%d)", r.TTL))
		}
		if r.Proxied != nil && *r.Proxied {
			mods = append(mods, "CF_PROXY_ON")
		}
		if len(mods) > 0 {
			call = strings.TrimSuffix(call, ")") + ", " + strings.Join(mods, ", ") + ")"
		}
		fmt.Fprintf(bw, "    %s,\n", call)
	}
	bw.WriteString("END);\n")
	return bw.Flush()
}

// dnscontrolCall renders r as a DNSControl record function call.
func dnscontrolCall(r Record, origin, parseOrigin string) (string, error) {
	name := jsString(relName(r.Name, origin))
	q := jsString
	if r.Type == AliasType {
		return fmt.Sprintf("ALIAS(%s, %s)", name, q(r.Data)), nil
	}
	if r.Type == "TXT" {
		strs := TXTStrings(r.Data)
		if len(strs) == 1 {
			return fmt.Sprintf("TXT(%s, %s)", name, q(strs[0])), nil
		}
		parts := make([]string, len(strs))
		for i, s := range strs {
			parts[i] = q(s)
		}
		return fmt.Sprintf("TXT(%s, [%s])", name, strings.Join(parts, ", ")), nil
	}
	rr, err := parseRR(r.Name, r.TTL, r.Type, r.Data, parseOrigin)
	if err != nil {
		return "", err
	}
	switch v := rr.(type) {
	case *dns.A:
		return fmt.Sprintf("A(%s, %s)", name, q(v.A.String())), nil
	case *dns.AAAA:
		return fmt.Sprintf("AAAA(%s, %s)", name, q(v.AAAA.String())), nil
	case *dns.CNAME:
		return fmt.Sprintf("CNAME(%s, %s)", name, q(v.Target)), nil
	case *dns.NS:
		return fmt.Sprintf("NS(%s, %s)", name, q(v.Ns)), nil
	case *dns.PTR:
		return fmt.Sprintf("PTR(%s, %s)", name, q(v.Ptr)), nil
	case *dns.MX:
		return fmt.Sprintf("MX(%s, %d, %s)", name, v.Preference, q(v.Mx)), nil
	case *dns.SRV:
		return fmt.Sprintf("SRV(%s, %d, %d, %d, %s)", name, v.Priority, v.Weight, v.Port, q(v.Target)), nil
	case *dns.CAA:
		call := fmt.Sprintf("CAA(%s, %s, %s", name, q(v.Tag), q(v.Value))
		if v.Flag&128 != 0 {
			call += ", CAA_CRITICAL"
		}
		return call + ")", nil
	case *dns.DS:
		return fmt.Sprintf("DS(%s, %d, %d, %d, %s)", name, v.KeyTag, v.Algorithm, v.DigestType, q(v.Digest)), nil
	case *dns.TLSA:
		return fmt.Sprintf("TLSA(%s, %d, %d, %d, %s)", name, v.Usage, v.Selector, v.MatchingType, q(v.Certificate)), nil
	case *dns.SSHFP:
		return fmt.Sprintf("SSHFP(%s, %d, %d, %s)", name, v.Algorithm, v.Type, q(v.FingerPrint)), nil
	case *dns.NAPTR:
		return fmt.Sprintf("NAPTR(%s, %d, %d, %s, %s, %s, %s)", name, v.Order, v.Preference, q(v.Flags), q(v.Service), q(v.Regexp), q(v.Replacement)), nil
	}
	return "", fmt.Errorf("type not supported by DNSControl export")
}
