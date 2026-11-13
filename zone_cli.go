package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"dlookup/lookup"
	"dlookup/zonefile"
)

// Exit codes of "dlookup zone".
const (
	zoneExitOK      = 0
	zoneExitRuntime = 1
	zoneExitUsage   = 2
)

const defaultZoneExportTimeout = 5 * time.Second

// dumpZone is lookup.DumpZone; a variable so tests can substitute it.
var dumpZone = lookup.DumpZone

// runZone runs "dlookup zone <command> ...".
func runZone(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printZoneUsage(stderr)
		return zoneExitUsage
	}
	var run func([]string, io.Reader, io.Writer, io.Writer) error
	switch args[0] {
	case "-h", "-help", "--help", "help":
		printZoneUsage(stdout)
		return zoneExitOK
	case "convert":
		run = runZoneConvert
	case "formats":
		run = runZoneFormats
	case "show":
		run = runZoneShow
	case "export":
		run = runZoneExport
	default:
		fmt.Fprintf(stderr, "Error: unknown zone command %q\n", args[0])
		printZoneUsage(stderr)
		return zoneExitUsage
	}
	err := run(args[1:], stdin, stdout, stderr)
	switch {
	case err == nil:
		return zoneExitOK
	case errors.Is(err, flag.ErrHelp):
		return zoneExitOK
	case errors.Is(err, errUsage):
		fmt.Fprintf(stderr, "Error: %v\nRun 'dlookup zone %s --help' for usage.\n", err, args[0])
		return zoneExitUsage
	}
	fmt.Fprintf(stderr, "Error: %v\n", err)
	return zoneExitRuntime
}

func printZoneUsage(w io.Writer) {
	fmt.Fprint(w, `dlookup zone - import, export and convert DNS zones between provider formats

Usage:
  dlookup zone convert <in> [-o <out>] [--from FMT] [--to FMT] [options]
  dlookup zone export <domain> [--to FMT] [-o <out>] [--server S] [--names a,b]
  dlookup zone show <file> [--from FMT] [--origin DOMAIN]
  dlookup zone formats

"-" reads stdin / writes stdout. Formats are detected from file names and
content when not given. Run 'dlookup zone <command> --help' for options.

Exit status: 0 success, 1 error (I/O, parse, lookup), 2 usage error.
`)
}

// zoneFlags are the flags shared by commands that read or write zones.
type zoneFlags struct {
	from, to, origin, out  string
	zoneID, tfZone, action string
	keepApexNS             bool
	ttl                    uint
}

func (z *zoneFlags) registerRead(fs *flag.FlagSet) {
	fs.StringVar(&z.from, "from", "", "Input `format` (default: detected)")
	fs.StringVar(&z.origin, "origin", "", "Zone `domain` when the input doesn't name it (BIND without $ORIGIN, OctoDNS, CSV)")
}

func (z *zoneFlags) registerWrite(fs *flag.FlagSet) {
	fs.StringVar(&z.to, "to", "", "Output `format` (default: from the output file name; bind for stdout)")
	fs.StringVar(&z.out, "o", "-", "Output `file` (\"-\" = stdout)")
	fs.StringVar(&z.out, "output", "-", "Output `file` (\"-\" = stdout)")
	fs.StringVar(&z.zoneID, "zone-id", "", "Route 53 hosted zone `id` (change batch comment, in-zone aliases)")
	fs.StringVar(&z.tfZone, "tf-zone", "var.zone_id", "Terraform zone_id `expression` or literal zone id")
	fs.StringVar(&z.action, "action", "UPSERT", "Route 53 change batch `action`: UPSERT, CREATE or DELETE")
	fs.BoolVar(&z.keepApexNS, "keep-apex-ns", false, "Keep the apex NS and SOA records in provider formats (route53-change, terraform, cloudflare, dnscontrol)")
	fs.UintVar(&z.ttl, "ttl", 0, "Default `TTL` for records without one (0 = format default)")
}

// outFormat resolves the output format.
func (z *zoneFlags) outFormat() (zonefile.Format, error) {
	if z.to != "" {
		f, err := zonefile.ParseFormat(z.to)
		if err != nil {
			return "", usageError{"--to: " + err.Error()}
		}
		return f, nil
	}
	if z.out == "-" || z.out == "" {
		return zonefile.BIND, nil
	}
	f, err := zonefile.Detect(z.out, nil)
	if err != nil {
		return "", usageError{fmt.Sprintf("%v (use --to)", err)}
	}
	return f, nil
}

func (z *zoneFlags) writeOptions(f zonefile.Format) zonefile.WriteOptions {
	return zonefile.WriteOptions{
		DefaultTTL:       uint32(z.ttl),
		Route53ZoneID:    z.zoneID,
		Route53Action:    z.action,
		TerraformZoneRef: z.tfZone,
		SkipApexNSSOA:    zonefile.DefaultSkipApexNSSOA(f) && !z.keepApexNS,
	}
}

// newZoneFlagSet creates a flag set printing usage text for command cmd.
func newZoneFlagSet(cmd, usage string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("dlookup zone "+cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "%s\nOptions:\n", usage)
		fs.PrintDefaults()
	}
	return fs
}

// parseZoneFlags parses args and checks the positional argument count.
func parseZoneFlags(fs *flag.FlagSet, args []string, want int, what string) ([]string, error) {
	positional, err := parseInterspersed(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil, err
		}
		return nil, usageError{err.Error()}
	}
	if len(positional) != want {
		return nil, usageError{fmt.Sprintf("%s needs %s (got %d arguments)", fs.Name(), what, len(positional))}
	}
	return positional, nil
}

// readZoneInput reads and parses a zone from path ("-" = stdin).
func readZoneInput(path, from, origin string, stdin io.Reader) (*zonefile.Zone, zonefile.Format, error) {
	if from != "" {
		f, err := zonefile.ParseFormat(from)
		if err != nil {
			return nil, "", usageError{"--from: " + err.Error()}
		}
		if !zonefile.CanRead(f) {
			return nil, "", usageError{fmt.Sprintf("format %s can only be written, not read", f)}
		}
	}
	var (
		data []byte
		err  error
	)
	if path == "-" {
		data, err = io.ReadAll(stdin)
	} else {
		data, err = os.ReadFile(expandHome(path))
	}
	if err != nil {
		return nil, "", err
	}
	return parseZoneData(path, data, from, origin)
}

// parseZoneData parses data read from name in format from ("" = detect).
func parseZoneData(name string, data []byte, from, origin string) (*zonefile.Zone, zonefile.Format, error) {
	var f zonefile.Format
	var err error
	if from != "" {
		if f, err = zonefile.ParseFormat(from); err != nil {
			return nil, "", usageError{"--from: " + err.Error()}
		}
	} else if f, err = zonefile.Detect(name, data); err != nil {
		return nil, "", fmt.Errorf("%s: %w (use --from)", name, err)
	}
	if !zonefile.CanRead(f) {
		return nil, "", usageError{fmt.Sprintf("format %s can only be written, not read", f)}
	}
	if origin != "" {
		if origin, err = lookup.NormalizeTarget(origin); err != nil {
			return nil, "", usageError{"--origin: " + err.Error()}
		}
	}
	z, err := zonefile.Parse(bytes.NewReader(data), f, origin)
	if err != nil {
		return nil, f, fmt.Errorf("%s: %w", name, err)
	}
	return z, f, nil
}

// expandHome expands a leading "~/".
func expandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(p[1:], "/"))
		}
	}
	return p
}

// writeZoneOutput writes z as f to path ("-" = stdout). It returns the
// written path and the conversion warnings.
func writeZoneOutput(path string, stdout io.Writer, z *zonefile.Zone, f zonefile.Format, opts zonefile.WriteOptions) (string, []string, error) {
	var buf bytes.Buffer
	warns, err := zonefile.WriteWithWarnings(&buf, z, f, opts)
	if err != nil {
		return "", warns, err
	}
	if path == "-" || path == "" {
		_, err = stdout.Write(buf.Bytes())
		return "-", warns, err
	}
	written, err := writeExportFile(path, buf.String())
	return written, warns, err
}

func printWarnings(w io.Writer, warns []string) {
	for _, s := range warns {
		fmt.Fprintf(w, "Warning: %s\n", s)
	}
}

func runZoneConvert(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	var zf zoneFlags
	fs := newZoneFlagSet("convert", `dlookup zone convert - convert a zone between formats

Usage:
  dlookup zone convert <in> [-o <out>] [--from FMT] [--to FMT] [options]

Examples:
  dlookup zone convert example.com.zone -o changes.json --to route53-change
  dlookup zone convert cloudflare.json -o example.com.zone
  aws route53 list-resource-record-sets --hosted-zone-id Z1 | dlookup zone convert - --to terraform > dns.tf
`, stderr)
	zf.registerRead(fs)
	zf.registerWrite(fs)
	pos, err := parseZoneFlags(fs, args, 1, "exactly one input file")
	if err != nil {
		return err
	}
	to, err := zf.outFormat()
	if err != nil {
		return err
	}
	z, from, err := readZoneInput(pos[0], zf.from, zf.origin, stdin)
	if err != nil {
		return err
	}
	path, warns, err := writeZoneOutput(zf.out, stdout, z, to, zf.writeOptions(to))
	printWarnings(stderr, warns)
	if err != nil {
		return err
	}
	if path != "-" {
		fmt.Fprintf(stderr, "Converted %d records of %s (%s → %s) to %s\n", len(z.Records), strings.TrimSuffix(z.Origin, "."), from, to, path)
	}
	return nil
}

func runZoneFormats(args []string, _ io.Reader, stdout, stderr io.Writer) error {
	fs := newZoneFlagSet("formats", "dlookup zone formats - list the supported zone formats\n\nUsage:\n  dlookup zone formats\n", stderr)
	if _, err := parseZoneFlags(fs, args, 0, "no arguments"); err != nil {
		return err
	}
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "FORMAT\tREAD\tWRITE\tEXT\tDESCRIPTION")
	yes := func(b bool) string {
		if b {
			return "yes"
		}
		return "-"
	}
	for _, f := range zonefile.Formats() {
		fi, _ := zonefile.Info(f)
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", f, yes(fi.Read), yes(fi.Write), fi.Ext, fi.Description)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "\nCloudflare's dashboard imports and exports BIND zone files (proxied records carry \"cf_tags=cf-proxied:true\").")
	return nil
}

func runZoneShow(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	var zf zoneFlags
	fs := newZoneFlagSet("show", "dlookup zone show - print a zone file as a normalized table\n\nUsage:\n  dlookup zone show <file> [--from FMT] [--origin DOMAIN]\n", stderr)
	zf.registerRead(fs)
	pos, err := parseZoneFlags(fs, args, 1, "exactly one file")
	if err != nil {
		return err
	}
	z, f, err := readZoneInput(pos[0], zf.from, zf.origin, stdin)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Zone %s (%s, %s)\n\n", strings.TrimSuffix(z.Origin, "."), pos[0], f)
	_, err = io.WriteString(stdout, zoneTable(z))
	return err
}

func runZoneExport(args []string, _ io.Reader, stdout, stderr io.Writer) error {
	var (
		zf      zoneFlags
		server  string
		names   string
		noAXFR  bool
		timeout time.Duration
	)
	fs := newZoneFlagSet("export", `dlookup zone export - export a domain's live zone

Usage:
  dlookup zone export <domain> [--to FMT] [-o <out>] [--server S] [--names a,b]

The zone is transferred (AXFR) when the nameserver allows it; otherwise the
names are probed (apex, common labels, DKIM selectors, SRV names, --names),
so the export may be incomplete.
`, stderr)
	zf.registerWrite(fs)
	fs.StringVar(&server, "server", "", "Nameserver to query (default: the domain's authoritative nameservers)")
	fs.StringVar(&names, "names", "", "Extra comma-separated `names` to probe (relative like \"shop\" or FQDN)")
	fs.BoolVar(&noAXFR, "no-axfr", false, "Do not attempt a zone transfer")
	fs.DurationVar(&timeout, "timeout", defaultZoneExportTimeout, "Per-query `timeout`")
	pos, err := parseZoneFlags(fs, args, 1, "exactly one domain")
	if err != nil {
		return err
	}
	domain, err := lookup.NormalizeTarget(pos[0])
	if err != nil {
		return usageError{err.Error()}
	}
	if server != "" {
		if err := lookup.ValidateServer(server); err != nil {
			return usageError{"--server: " + err.Error()}
		}
	}
	if timeout <= 0 {
		return usageError{"--timeout must be positive"}
	}
	to, err := zf.outFormat()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	z, method, err := dumpZone(ctx, lookup.ZoneDumpOptions{
		Domain: domain, Server: server, ExtraNames: splitNames(names), TryAXFR: !noAXFR, Timeout: timeout,
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(stderr, "Exported %d records of %s via %s\n", len(z.Records), domain, method)
	if w := probeWarning(method); w != "" {
		fmt.Fprintf(stderr, "Warning: %s\n", w)
	}
	path, warns, err := writeZoneOutput(zf.out, stdout, z, to, zf.writeOptions(to))
	printWarnings(stderr, warns)
	if err != nil {
		return err
	}
	if path != "-" {
		fmt.Fprintf(stderr, "Saved %s to %s\n", to, path)
	}
	return nil
}

// probeWarning warns when the zone was enumerated by probing instead of AXFR.
func probeWarning(method string) string {
	if strings.HasPrefix(strings.ToLower(method), "axfr") {
		return ""
	}
	return "the nameserver refused a zone transfer, so names were probed; the export may be incomplete (add names with --names)"
}

// zoneTable renders z as an aligned NAME/TTL/TYPE/DATA table followed by
// the record counts per type. Names are relative to the origin.
func zoneTable(z *zonefile.Zone) string {
	var b strings.Builder
	tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tTTL\tTYPE\tDATA")
	for _, r := range z.Records {
		name := r.Name
		if name == z.Origin {
			name = "@"
		} else if s, ok := strings.CutSuffix(name, "."+z.Origin); ok {
			name = s
		}
		ttl := "auto"
		if r.TTL > 0 {
			ttl = fmt.Sprint(r.TTL)
		}
		data := r.Data
		if r.Proxied != nil && *r.Proxied {
			data += "  [proxied]"
		}
		if r.Comment != "" {
			data += "  ; " + r.Comment
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", name, ttl, r.Type, data)
	}
	tw.Flush()
	counts := z.CountByType()
	types := make([]string, 0, len(counts))
	for t := range counts {
		types = append(types, t)
	}
	sort.Strings(types)
	parts := make([]string, len(types))
	for i, t := range types {
		parts[i] = fmt.Sprintf("%s %d", t, counts[t])
	}
	fmt.Fprintf(&b, "\n%d records, %d names", len(z.Records), len(z.Names()))
	if len(parts) > 0 {
		fmt.Fprintf(&b, ": %s", strings.Join(parts, ", "))
	}
	b.WriteString("\n")
	return b.String()
}

// splitNames splits a comma- or space-separated name list.
func splitNames(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })
}
