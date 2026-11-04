package main

import (
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
	)
	fs.StringVar(&newServer, "new", "", "New DNS `server` to check (required): IP, host or host:port")
	fs.StringVar(&oldServer, "old", "", "Current DNS `server` (default: the domain's authoritative nameservers)")
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

	if len(positional) != 1 {
		return nil, usageErr("zonediff needs exactly one domain (got %d arguments)", len(positional))
	}
	domain, err := lookup.NormalizeTarget(positional[0])
	if err != nil {
		return nil, usageErr("%v", err)
	}
	if newServer == "" {
		return nil, usageErr("--new <server> is required")
	}
	if err := lookup.ValidateServer(newServer); err != nil {
		return nil, usageErr("--new: %v", err)
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

	cfg.Opts = lookup.ZoneDiffOptions{
		Domain:      domain,
		OldServer:   oldServer,
		NewServer:   newServer,
		ExtraNames:  extra,
		Types:       qtypes,
		CompareTTL:  ttl,
		TryAXFR:     !noAXFR,
		Timeout:     timeout,
		Concurrency: conc,
	}
	return cfg, nil
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
	fmt.Fprint(w, `dlookup zonediff - compare a domain's records on two DNS servers

Usage:
  dlookup zonediff <domain> --new <server> [options]

Checks that a new DNS server (e.g. a new provider, before switching the NS
delegation) serves the same records as the current one. Without --old, the
domain's current authoritative nameservers are discovered and queried.

Names are enumerated by zone transfer (AXFR) if either server allows it,
otherwise by probing the apex, common names (www, mail, _dmarc, DKIM
selectors, SRV names, a wildcard check, ...) and in-zone CNAME/MX/NS/SRV
targets. Use --names / --names-file for names that cannot be guessed.
SOA serials and TTLs (unless --ttl) are ignored.

Exit codes: 0 no differences, 1 differences found, 2 usage error,
3 runtime error (e.g. a server could not be reached).

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
`)
}
