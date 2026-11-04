package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"dlookup/lookup"
)

// Output formats for headless mode.
const (
	outputNone = ""
	outputText = "text"
	outputJSON = "json"
)

const defaultConcurrency = 8

// validateTarget validates each target; a variable so tests can substitute it.
var validateTarget = lookup.ValidateTarget

// errUsage marks errors caused by invalid command-line usage (exit code 2).
// Match with errors.Is(err, errUsage).
var errUsage = errors.New("usage error")

// usageError is an errUsage with a human-readable message.
type usageError struct{ msg string }

func (e usageError) Error() string        { return e.msg }
func (e usageError) Is(target error) bool { return target == errUsage }

// cliConfig is the fully interpreted command line.
type cliConfig struct {
	ShowVersion bool
	Output      string // "", "text" or "json"; "" = start the TUI
	Concurrency int
	Opts        lookup.Options

	// Provider is the selected lookup provider, or nil if none was selected.
	Provider lookup.LookupProvider
	// Targets are the validated targets from files, stdin and positional args, in order.
	Targets []string
}

// Headless reports whether the TUI should be skipped.
func (c *cliConfig) Headless() bool { return c.Output != outputNone }

// LookupType returns the selected provider's name, or "".
func (c *cliConfig) LookupType() string {
	if c.Provider == nil {
		return ""
	}
	return c.Provider.Name()
}

// sortedProviders returns all providers sorted by flag name.
func sortedProviders() []lookup.LookupProvider {
	providers := lookup.AvailableProviders()
	sort.Slice(providers, func(i, j int) bool {
		return providers[i].FlagName() < providers[j].FlagName()
	})
	return providers
}

// parseArgs parses args (without the program name). Flags and positional targets
// may be interspersed; "--" ends flag parsing. stdin is used for the "-" filename,
// stderr receives warnings and usage text.
// Returns flag.ErrHelp for -h/--help, or an error wrapping errUsage for bad usage.
func parseArgs(args []string, stdin io.Reader, stderr io.Writer) (*cliConfig, error) {
	fs := flag.NewFlagSet("dlookup", flag.ContinueOnError)
	fs.SetOutput(stderr)

	cfg := &cliConfig{}
	var (
		output     string
		lookupName string
		server     string
		timeout    time.Duration
	)
	fs.BoolVar(&cfg.ShowVersion, "version", false, "Print version and exit")
	fs.StringVar(&output, "output", "", "Headless mode: print results as `format` (text|json) to stdout and exit")
	fs.StringVar(&output, "o", "", "Shorthand for --output `format`")
	fs.StringVar(&lookupName, "lookup", "", "Select lookup `type` by flag name (e.g. dig-mx) for positional targets")
	fs.StringVar(&server, "server", "", "DNS `server` to query, e.g. 1.1.1.1 or 1.1.1.1:53 (default: system resolver)")
	fs.DurationVar(&timeout, "timeout", 0, fmt.Sprintf("Per-lookup `timeout`, e.g. 5s (default %s)", lookup.DefaultTimeout))
	fs.IntVar(&cfg.Concurrency, "concurrency", defaultConcurrency, "Headless mode: max lookups run in `parallel`")

	providers := sortedProviders()
	fileFlags := make(map[string]*string, len(providers))
	for _, p := range providers {
		fileFlags[p.FlagName()] = fs.String(p.FlagName(), "", p.Usage()+" (\"-\" = stdin)")
	}
	fs.Usage = func() { printUsage(fs, providers) }

	positional, err := parseInterspersed(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil, err
		}
		return nil, usageError{err.Error()}
	}
	if cfg.ShowVersion {
		return cfg, nil
	}

	usageErr := func(format string, a ...any) error {
		return usageError{fmt.Sprintf(format, a...)}
	}

	switch output {
	case outputNone, outputText, outputJSON:
		cfg.Output = output
	default:
		return nil, usageErr("invalid --output %q (want text or json)", output)
	}
	if cfg.Concurrency < 1 {
		return nil, usageErr("--concurrency must be at least 1")
	}
	if timeout < 0 {
		return nil, usageErr("--timeout must not be negative")
	}
	cfg.Opts = lookup.Options{Server: server, Timeout: timeout}

	// Select the provider: at most one file flag, optionally consistent with --lookup.
	var fileFlagName, filename string
	for _, p := range providers {
		if v := *fileFlags[p.FlagName()]; v != "" {
			if fileFlagName != "" {
				return nil, usageErr("use only one lookup type flag at a time (got --%s and --%s)", fileFlagName, p.FlagName())
			}
			fileFlagName, filename = p.FlagName(), v
		}
	}
	if fileFlagName != "" {
		cfg.Provider, _ = lookup.GetProviderByFlagName(fileFlagName)
	}
	if lookupName != "" {
		p, ok := findProvider(lookupName)
		if !ok {
			return nil, usageErr("unknown --lookup %q (valid: %s)", lookupName, strings.Join(providerFlagNames(providers), ", "))
		}
		if cfg.Provider != nil && cfg.Provider.FlagName() != p.FlagName() {
			return nil, usageErr("--lookup %s conflicts with --%s", lookupName, fileFlagName)
		}
		cfg.Provider = p
	}

	// Collect targets: file (or stdin) first, then positional args.
	stdinUsed := false
	readStdin := func() ([]string, error) {
		if stdinUsed {
			return nil, nil // stdin can only be consumed once
		}
		stdinUsed = true
		return readTargets(stdin, "<stdin>", stderr)
	}
	if filename != "" {
		var targets []string
		if filename == "-" {
			targets, err = readStdin()
		} else {
			targets, err = readTargetsFile(filename, stderr)
		}
		if err != nil {
			return nil, err
		}
		if len(targets) == 0 {
			fmt.Fprintf(stderr, "Warning: '%s' was empty or contained no valid domains/IPs.\n", filename)
		}
		cfg.Targets = append(cfg.Targets, targets...)
	}
	for i, arg := range positional {
		if arg == "-" {
			targets, err := readStdin()
			if err != nil {
				return nil, err
			}
			cfg.Targets = append(cfg.Targets, targets...)
			continue
		}
		target := strings.TrimSpace(arg)
		if err := validateTarget(target); err != nil {
			fmt.Fprintf(stderr, "Warning: argument %d: skipping invalid target %q: %v\n", i+1, arg, err)
			continue
		}
		cfg.Targets = append(cfg.Targets, target)
	}

	if cfg.Headless() {
		if cfg.Provider == nil {
			return nil, usageErr("--output requires a lookup type (e.g. --lookup dig-a or --dig-a FILE)")
		}
		if len(cfg.Targets) == 0 {
			return nil, usageErr("no valid targets given")
		}
	}
	return cfg, nil
}

// parseInterspersed parses fs from args, allowing positional args between flags.
// Everything after a literal "--" is positional.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return positional, nil
		}
		consumed := len(args) - len(rest)
		if consumed > 0 && args[consumed-1] == "--" {
			return append(positional, rest...), nil
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
}

// findProvider resolves a --lookup value by flag name (with or without leading
// dashes) or by provider name (case-insensitive).
func findProvider(name string) (lookup.LookupProvider, bool) {
	name = strings.TrimLeft(name, "-")
	if p, ok := lookup.GetProviderByFlagName(name); ok {
		return p, true
	}
	for _, p := range lookup.AvailableProviders() {
		if strings.EqualFold(p.Name(), name) || strings.EqualFold(p.FlagName(), name) {
			return p, true
		}
	}
	return nil, false
}

func providerFlagNames(providers []lookup.LookupProvider) []string {
	names := make([]string, len(providers))
	for i, p := range providers {
		names[i] = p.FlagName()
	}
	return names
}

// printUsage writes the custom --help text.
func printUsage(fs *flag.FlagSet, providers []lookup.LookupProvider) {
	w := fs.Output()
	isLookupFlag := make(map[string]bool, len(providers))
	for _, p := range providers {
		isLookupFlag[p.FlagName()] = true
	}

	fmt.Fprint(w, `dlookup - interactive DNS / WHOIS lookup tool

Usage:
  dlookup [options] [target ...]
  dlookup [options] --<lookup> FILE [target ...]
  dlookup -o text|json --lookup <lookup> [options] target ...

Without --output, dlookup starts the interactive TUI with one tab per target.
With --output, it runs the lookup on every target, prints the results in
input order to stdout and exits (exit code 1 if any lookup failed, 2 on usage
errors). FILE contains one target per line; blank lines and '#' comments are
ignored. Use "-" as FILE (or as a target) to read targets from stdin.

Output formats:
  text   a "=== target [lookup] ===" header per target, followed by its output
  json   a single JSON array of objects:
         {"target": str, "lookup": str, "output": str, "error": str, "duration_ms": int}
         ("error" is "" on success)

Options:
`)
	fs.VisitAll(func(f *flag.Flag) {
		if !isLookupFlag[f.Name] {
			printFlag(w, f)
		}
	})
	fmt.Fprint(w, "\nLookup types (use as --<name> FILE, or --lookup <name>):\n")
	for _, p := range providers {
		fmt.Fprintf(w, "%-28s %s\n", "  --"+p.FlagName()+" FILE", p.Usage())
	}
	fmt.Fprint(w, `
Examples:
  dlookup                                   start the TUI
  dlookup example.com 1.1.1.1               open a tab per target, choose the lookup in the TUI
  dlookup --dig-a domains.txt extra.com     run DIG (A) in the TUI on the file's targets plus extra.com
  dlookup -o json --lookup dig-mx example.com
  cat domains.txt | dlookup -o text --lookup whois -
  dlookup -o text --dig-a domains.txt --server 1.1.1.1 --timeout 5s --concurrency 4
`)
}

func printFlag(w io.Writer, f *flag.Flag) {
	name, usage := flag.UnquoteUsage(f)
	dash := "--"
	if len(f.Name) == 1 {
		dash = "-"
	}
	line := "  " + dash + f.Name
	if name != "" {
		line += " " + name
	}
	if f.DefValue != "" && f.DefValue != "false" && f.DefValue != "0s" {
		usage += fmt.Sprintf(" (default %s)", f.DefValue)
	}
	fmt.Fprintf(w, "%-28s %s\n", line, usage)
}

// warnMissingCommands prints a warning to stderr for each external binary
// required by a provider that is not installed.
func warnMissingCommands(w io.Writer) {
	missing := []string{}
	checked := make(map[string]bool)
	for _, p := range lookup.AvailableProviders() {
		cmd := p.Command()
		if cmd == "" || checked[cmd] {
			continue
		}
		checked[cmd] = true
		if !p.CheckAvailability() {
			missing = append(missing, cmd)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		fmt.Fprintf(w, "Warning: Required commands missing: %s\n", strings.Join(missing, ", "))
		fmt.Fprintf(w, "Please install them. Some lookup types may fail.\n")
	}
}

// warnMissingCommandFor warns if the given provider's external command is missing.
func warnMissingCommandFor(w io.Writer, p lookup.LookupProvider) {
	if p.Command() != "" && !p.CheckAvailability() {
		fmt.Fprintf(w, "Warning: '%s' requires the '%s' command, which was not found. Lookups will fail.\n", p.Name(), p.Command())
	}
}

// readTargetsFile reads targets from the file at path; see readTargets.
func readTargetsFile(path string, stderr io.Writer) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("error opening file '%s': %w", path, err)
	}
	defer file.Close()
	return readTargets(file, path, stderr)
}

// readTargets reads one target per line, skipping blank lines and '#' comments.
// Invalid targets are skipped with a "name:line" warning written to stderr.
func readTargets(r io.Reader, name string, stderr io.Writer) ([]string, error) {
	var targets []string
	scanner := bufio.NewScanner(r)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if err := validateTarget(line); err != nil {
			fmt.Fprintf(stderr, "Warning: %s:%d: skipping invalid target %q: %v\n", name, lineNo, line, err)
			continue
		}
		targets = append(targets, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading '%s': %w", name, err)
	}
	return targets, nil
}
