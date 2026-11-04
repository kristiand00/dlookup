package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime/debug"

	tea "github.com/charmbracelet/bubbletea"
)

// version is set by release builds via -ldflags "-X main.version=...".
var version = "dev"

// versionString returns the build version, falling back to the module
// version from the build info (e.g. for `go install ...@vX.Y.Z`).
func versionString() string {
	if version != "dev" && version != "" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		if v := info.Main.Version; v != "" && v != "(devel)" {
			return v
		}
	}
	return "dev"
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// run executes dlookup and returns the process exit code:
// 0 success, 1 a lookup (or the TUI) failed, 2 usage error.
// "dlookup zonediff ..." has its own exit codes (see runZoneDiff).
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "zonediff" {
		return runZoneDiff(args[1:], stdin, stdout, stderr)
	}
	cli, err := parseArgs(args, stdin, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintf(stderr, "Error: %v\n", err)
		if errors.Is(err, errUsage) {
			fmt.Fprintln(stderr, "Run 'dlookup --help' for usage.")
			return 2
		}
		return 1
	}

	if cli.ShowVersion {
		fmt.Fprintf(stdout, "dlookup %s\n", versionString())
		return 0
	}

	if cli.Headless() {
		warnMissingCommandFor(stderr, cli.Provider)
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		failed, err := runHeadless(ctx, stdout, cli.Provider, cli.Targets, cli.Opts, cli.Output, cli.Concurrency)
		if err != nil {
			fmt.Fprintf(stderr, "Error writing output: %v\n", err)
			return 1
		}
		if failed > 0 {
			fmt.Fprintf(stderr, "%d of %d lookups failed.\n", failed, len(cli.Targets))
			return 1
		}
		return 0
	}

	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintf(stderr, "Error loading config: %v. Using defaults.\n", err)
		cfg = DefaultConfig()
	}
	warnMissingCommands(stderr)

	m := newMainModel(cli.Targets, cli.LookupType(), cfg, cli.Opts)
	p := tea.NewProgram(m, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(stderr, "Error running program: %v\n", err)
		return 1
	}
	return 0
}
