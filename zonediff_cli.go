package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"

	"dlookup/lookup"
	"dlookup/zonefile"

	"github.com/miekg/dns"
)

// Exit codes of "dlookup zonediff".
const (
	zoneDiffExitSame    = 0
	zoneDiffExitDiffers = 1
	zoneDiffExitUsage   = 2
	zoneDiffExitRuntime = 3
)

const defaultZoneDiffTimeout = 5 * time.Second

// diffZone is lookup.DiffZone; a variable so tests can substitute it.
var diffZone = lookup.DiffZone

// zoneDiffConfig is the interpreted "zonediff" command line.
type zoneDiffConfig struct {
	Opts    lookup.ZoneDiffOptions
	Output  string // outputText or outputJSON
	ShowAll bool
}

// parseZoneDiffArgs parses the arguments after "zonediff". Flags may appear
// before or after the domain. Returns flag.ErrHelp for -h/--help, or an error
// wrapping errUsage.
func parseZoneDiffArgs(args []string, stdin io.Reader, stderr io.Writer) (*zoneDiffConfig, error) {
	fs := flag.NewFlagSet("dlookup zonediff", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		cfg       = &zoneDiffConfig{}
		newServer string
		oldServer string
		names     string
		namesFile string
		types     string
		output    string
		noAXFR    bool
		ttl       bool
		timeout   time.Duration
		conc      int
		oldFile   string
		newFile   string
		oldFormat string
		newFormat string
		origin    string
		probe     bool
	)
	fs.StringVar(&newServer, "new", "", "New DNS `server` to check: IP, host or host:port (required unless a zone file is given)")
	fs.StringVar(&oldServer, "old", "", "Current DNS `server` (default: the domain's authoritative nameservers)")
	fs.StringVar(&oldFile, "old-file", "", "Use the zone file `FILE` as the old side (a provider export); without --new/--new-file it is compared with the live zone")
	fs.StringVar(&newFile, "new-file", "", "Use the zone file `FILE` as the new side instead of --new")
	fs.StringVar(&oldFormat, "old-format", "", "Format of --old-file (default: detected): "+zoneFormatList())
	fs.StringVar(&newFormat, "new-format", "", "Format of --new-file (default: detected)")
	fs.StringVar(&origin, "origin", "", "Zone `origin` for files that do not name it (default: the domain)")
	fs.BoolVar(&probe, "probe", false, "With zone files: also probe common names (www, mail, _dmarc, ...)")
	fs.StringVar(&names, "names", "", "Extra comma-separated `names` to check (relative like \"shop\" or FQDN)")
	fs.StringVar(&namesFile, "names-file", "", "Read extra names from `FILE`, one per line (\"-\" = stdin)")
	fs.StringVar(&types, "types", "", "Comma-separated record `types` to compare (default A,AAAA,CNAME,MX,NS,TXT,SOA,CAA,SRV)")
	fs.BoolVar(&ttl, "ttl", false, "Also compare TTLs")
	fs.BoolVar(&noAXFR, "no-axfr", false, "Do not attempt a zone transfer (AXFR) to enumerate names")
	fs.BoolVar(&cfg.ShowAll, "all", false, "Text output: also list matching records")
	fs.StringVar(&output, "output", outputText, "Output `format`: text or json")
	fs.StringVar(&output, "o", outputText, "Shorthand for --output `format`")
	fs.DurationVar(&timeout, "timeout", defaultZoneDiffTimeout, "Per-query `timeout`")
	fs.IntVar(&conc, "concurrency", defaultConcurrency, "Max names checked in `parallel`")
	fs.Usage = func() { printZoneDiffUsage(fs) }

	positional, err := parseInterspersed(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil, err
		}
		return nil, usageError{err.Error()}
	}
	usageErr := func(format string, a ...any) error { return usageError{fmt.Sprintf(format, a...)} }

	if len(positional) > 1 || (len(positional) == 0 && oldFile == "" && newFile == "") {
		return nil, usageErr("zonediff needs exactly one domain (got %d arguments)", len(positional))
	}
	var domain string
	if len(positional) == 1 {
		if domain, err = lookup.NormalizeTarget(positional[0]); err != nil {
			return nil, usageErr("%v", err)
		}
	}
	switch {
	case oldFile != "" && oldServer != "":
		return nil, usageErr("--old and --old-file are mutually exclusive")
	case newFile != "" && newServer != "":
		return nil, usageErr("--new and --new-file are mutually exclusive")
	case oldFormat != "" && oldFile == "":
		return nil, usageErr("--old-format needs --old-file")
	case newFormat != "" && newFile == "":
		return nil, usageErr("--new-format needs --new-file")
	case newServer == "" && newFile == "" && oldFile == "":
		return nil, usageErr("--new <server> is required (or --new-file / --old-file)")
	}
	if newServer != "" {
		if err := lookup.ValidateServer(newServer); err != nil {
			return nil, usageErr("--new: %v", err)
		}
	}
	if origin == "" {
		origin = domain
	}
	if oldFile != "" {
		if cfg.Opts.OldZone, err = loadZoneFile(oldFile, oldFormat, origin); err != nil {
			return nil, usageErr("--old-file: %v", err)
		}
		cfg.Opts.OldZoneLabel = oldFile
	}
	if newFile != "" {
		if cfg.Opts.NewZone, err = loadZoneFile(newFile, newFormat, origin); err != nil {
			return nil, usageErr("--new-file: %v", err)
		}
		cfg.Opts.NewZoneLabel = newFile
	}
	if domain == "" {
		for _, z := range []*zonefile.Zone{cfg.Opts.OldZone, cfg.Opts.NewZone} {
			if z != nil && z.Origin != "" && z.Origin != "." {
				domain = strings.TrimSuffix(z.Origin, ".")
				break
			}
		}
		if domain == "" {
			return nil, usageErr("no domain given and the zone file does not name its origin; pass the domain or --origin")
		}
	}
	if oldServer != "" {
		if err := lookup.ValidateServer(oldServer); err != nil {
			return nil, usageErr("--old: %v", err)
		}
	}
	switch output {
	case outputText, outputJSON:
		cfg.Output = output
	default:
		return nil, usageErr("invalid --output %q (want text or json)", output)
	}
	if conc < 1 {
		return nil, usageErr("--concurrency must be at least 1")
	}
	if timeout <= 0 {
		return nil, usageErr("--timeout must be positive")
	}

	var extra []string
	for _, n := range strings.Split(names, ",") {
		if n = strings.TrimSpace(n); n == "" {
			continue
		}
		if n != "@" {
			if err := lookup.ValidateTarget(strings.TrimPrefix(n, "*.")); err != nil && n != "*" {
				return nil, usageErr("--names: %v", err)
			}
		}
		extra = append(extra, n)
	}
	if namesFile != "" {
		var fromFile []string
		if namesFile == "-" {
			fromFile, err = readTargets(stdin, "<stdin>", stderr)
		} else {
			fromFile, err = readTargetsFile(namesFile, stderr)
		}
		if err != nil {
			return nil, usageErr("%v", err)
		}
		extra = append(extra, fromFile...)
	}

	var qtypes []uint16
	for _, t := range strings.Split(types, ",") {
		if t = strings.ToUpper(strings.TrimSpace(t)); t == "" {
			continue
		}
		qt, ok := dns.StringToType[t]
		if !ok || qt == dns.TypeANY || qt == dns.TypeAXFR || qt == dns.TypeIXFR || qt == dns.TypeOPT {
			return nil, usageErr("--types: unknown or unsupported record type %q", t)
		}
		qtypes = append(qtypes, qt)
	}

	cfg.Opts.Domain = domain
	cfg.Opts.OldServer = oldServer
	cfg.Opts.NewServer = newServer
	cfg.Opts.ExtraNames = extra
	cfg.Opts.Types = qtypes
	cfg.Opts.CompareTTL = ttl
	cfg.Opts.TryAXFR = !noAXFR
	cfg.Opts.Timeout = timeout
	cfg.Opts.Concurrency = conc
	cfg.Opts.Probe = probe
	return cfg, nil
}

// zoneFormatList lists the readable zone file formats.
func zoneFormatList() string {
	var names []string
	for _, f := range zonefile.Formats() {
		if zonefile.CanRead(f) {
			names = append(names, string(f))
		}
	}
	return strings.Join(names, ", ")
}

// loadZoneFile reads and parses a zone file. format "" is detected from the
// file name and contents; origin "" means the file must name it.
func loadZoneFile(path, format, origin string) (*zonefile.Zone, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f zonefile.Format
	if format != "" {
		if f, err = zonefile.ParseFormat(format); err != nil {
			return nil, err
		}
	} else if f, err = zonefile.Detect(path, data); err != nil {
		return nil, err
	}
	if !zonefile.CanRead(f) {
		return nil, fmt.Errorf("format %s can only be written, not read", f)
	}
	z, err := zonefile.Parse(bytes.NewReader(data), f, origin)
	if err != nil {
		return nil, err
	}
	return z, nil
}

// runZoneDiff implements "dlookup zonediff". Exit codes: 0 no differences,
// 1 differences found, 2 usage error, 3 runtime error.
func runZoneDiff(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	cfg, err := parseZoneDiffArgs(args, stdin, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return zoneDiffExitSame
		}
		fmt.Fprintf(stderr, "Error: %v\n", err)
		fmt.Fprintln(stderr, "Run 'dlookup zonediff --help' for usage.")
		return zoneDiffExitUsage
	}

	progress := isTerminal(stderr)
	if progress {
		cfg.Opts.Progress = func(done, total int) {
			fmt.Fprintf(stderr, "\rChecking names: %d/%d ", done, total)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	res, err := diffZone(ctx, cfg.Opts)
	if progress {
		fmt.Fprint(stderr, "\r\033[K")
	}
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return zoneDiffExitRuntime
	}

	if cfg.Output == outputJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		err = enc.Encode(res)
	} else {
		_, err = io.WriteString(stdout, lookup.FormatZoneDiff(res, cfg.ShowAll))
	}
	if err != nil {
		fmt.Fprintf(stderr, "Error writing output: %v\n", err)
		return zoneDiffExitRuntime
	}
	if res.HasDifferences() {
		return zoneDiffExitDiffers
	}
	return zoneDiffExitSame
}

// isTerminal reports whether w is a character device (a terminal).
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func printZoneDiffUsage(fs *flag.FlagSet) {
	w := fs.Output()
	fmt.Fprint(w, `dlookup zonediff - compare a domain's records on two DNS servers or zone files

Usage:
  dlookup zonediff <domain> --new <server> [options]
  dlookup zonediff [<domain>] --old-file <export> [--new <server> | --new-file <file>] [options]

Checks that a new DNS server (e.g. a new provider, before switching the NS
delegation) serves the same records as the current one. Without --old, the
domain's current authoritative nameservers are discovered and queried.

Either side can be a zone file instead: a provider export (BIND zone file,
Cloudflare JSON, Route 53 JSON, OctoDNS YAML, CSV, dlookup JSON; the format
is detected unless --old-format/--new-format is given). Every record in a
file is checked, so nothing has to be guessed. --old-file without --new or
--new-file compares the export with the live zone (its authoritative
nameservers). Two files are compared offline. Route 53 ALIAS records are
compared by the addresses their target resolves to; differences caused by
Cloudflare's proxy (proxied records) are marked [expected].

Names are enumerated from zone files, by zone transfer (AXFR) if a server
allows it, otherwise by probing the apex, common names (www, mail, _dmarc,
DKIM selectors, SRV names, a wildcard check, ...) and in-zone CNAME/MX/NS/SRV
targets (with zone files only with --probe). Use --names / --names-file for
names that cannot be guessed. SOA serials and TTLs (unless --ttl) are ignored.

Exit codes: 0 no differences, 1 differences found, 2 usage error (including
unreadable zone files), 3 runtime error (e.g. a server could not be reached).

Options:
`)
	fs.VisitAll(func(f *flag.Flag) { printFlag(w, f) })
	fmt.Fprint(w, `
Output (text): "~" changed, "-" missing on new, "+" extra on new, "!" error,
"=" match (with --all). JSON: the full result object, statuses as strings.

Examples:
  dlookup zonediff example.com --new ns1.newprovider.net
  dlookup zonediff example.com --old 192.0.2.53 --new 198.51.100.53:5353 --names shop,intranet
  dlookup zonediff --new 198.51.100.53 --no-axfr --types A,MX,TXT -o json example.com

  # Cloudflare export vs the new Route 53 nameservers, before the NS switch
  dlookup zonediff example.com --old-file cloudflare-export.json --new ns-123.awsdns-45.com
  # Is the live zone what the export says? (e.g. after an import)
  dlookup zonediff example.com --old-file example.com.zone
  # Offline diff of two exports
  dlookup zonediff --old-file cloudflare.json --new-file route53.json --new-format route53 example.com
`)
}
