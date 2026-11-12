# DNS & WHOIS Lookup TUI

A terminal application built with Go and Bubble Tea for DNS lookups, RDAP/WHOIS queries and watching records change — in an interactive, tabbed TUI or headless for scripts.

![Screenshot Dlookup](https://github.com/kristiand00/dlookup/blob/main/preview.png?raw=true)

## Features

* **Midnight Commander-style TUI** — menu bar, clickable tabs, dialogs with dropdowns, an F-key bar and full mouse support. It opens on a Home screen listing every feature and shortcut. Every lookup gets its own tab, and lookups run in parallel (at most 8 at once).
* **Overview (default lookup)** — a quick summary of a domain: where it resolves (with TTL and any CNAME chain), the PTR of each address, and its MX and NS records. For an IP: its PTR names and whether they resolve back (forward-confirmed reverse DNS). Use `-t AAAA` (or another type) to summarise a different record type.
* **SDIG** — one DNS query of any type, printed exactly like PowerDNS's [`sdig`](https://doc.powerdns.com/authoritative/manpages/sdig.1.html): rcode and header flags, then every record of the answer, authority and additional sections. Choose the query type and toggle RD, DNSSEC (DO), TCP and Hide TTL in the lookup dialog. `dlookup sdig …` is a drop-in sdig replacement.
* **Native DNS** — A, AAAA, CNAME, MX, NS, SOA, TXT, CAA, PTR, SPF, DMARC and ANY are resolved in Go (no `dig` needed). PTR on an IP does a reverse lookup.
* **RDAP** — structured registration data over HTTPS (registrar, status, dates, nameservers; network/range/country for IPs).
* **NSLOOKUP / WHOIS** via the system tools, if installed.
* **Comprehensive Report** — runs every lookup for a target and combines the results.
* **Watch mode** — re-run a lookup on an interval; new lines are highlighted (`+`), removed ones listed (`-`), and background tabs that changed get a `●` marker.
* **Custom DNS server** — per tab in the TUI (`s` / F7) or with `--server`.
* **Zone diff** — compare a domain's records on its current nameservers against a new DNS server before migrating (`dlookup zonediff` or `D` in the TUI).
* **Headless mode** — `-o text|json` prints results and exits, for scripting and pipelines.
* **Export & copy** — save one tab or all tabs to a file, or copy the result to the clipboard.
* **Configurable keybindings** via YAML, with conflict detection.

## Prerequisites

DNS and RDAP lookups need nothing extra. The `NSLOOKUP` and `WHOIS` lookups need those commands on your `PATH`:

* **Debian/Ubuntu:** `sudo apt install dnsutils whois`
* **Fedora/RHEL:** `sudo dnf install bind-utils whois`
* **macOS:** both are included.

DNS queries go to the servers in `/etc/resolv.conf`. Where that file doesn't exist (Windows), dlookup falls back to `1.1.1.1` and `8.8.8.8` — pass `--server` to use a different resolver.

## Installation

### From GitHub Releases

Download the archive for your platform from the [Releases page](https://github.com/kristiand00/dlookup/releases), e.g. `dlookup_<version>_darwin_arm64.tar.gz`, `dlookup_<version>_linux_amd64.tar.gz` or `dlookup_<version>_windows_amd64.zip`. Verify it against `checksums.txt`, extract it, and put `dlookup` on your `PATH`.

> Releases before this change shipped raw binaries named like `dlookup-macos-arm64`; they are now archives with `darwin` instead of `macos`.

### From source

Requires Go 1.24.2 or newer.

```bash
git clone https://github.com/kristiand00/dlookup.git && cd dlookup && go build -o dlookup .
```

## Usage

```
dlookup [options] [target ...]
dlookup [options] --<lookup> FILE [target ...]
dlookup -o text|json [--lookup <lookup>] [options] target ...
dlookup sdig IP PORT QNAME QTYPE [option ...]
```

Without a lookup type, targets run the **Overview** lookup (`-t`/`--qtype` changes the record type it summarises). If you pass SDIG-only flags (`--dnssec`, `--tcp`, `--norecurse`, `--hidettl`) without a lookup, the **SDIG** lookup is used instead: an `A` query (`PTR` on the reverse name for IP targets) with the RD bit set. Real sdig leaves RD off unless you pass `recurse`, which makes the system resolver answer REFUSED or a referral, so dlookup turns it on by default. The lookup dialog shows this as a **Recurse (RD)** checkbox, and `--norecurse` turns it off. NXDOMAIN, SERVFAIL and REFUSED are part of the SDIG output (the `Rcode:` line), not errors.

Files contain one target per line; blank lines and `#` comments are ignored. Use `-` as the file (or as a target) to read from stdin. Invalid targets are skipped with a warning.

### Interactive

```bash
dlookup                                 # Home screen with help; press n (F2) for a lookup
dlookup example.com 1.1.1.1             # a tab per target, running the Overview
dlookup -t MX --dnssec example.com      # SDIG MX with the DNSSEC OK bit
dlookup --dig-a domains.txt extra.com   # run DIG (A) on every target, one tab each
dlookup --report domains.txt --server 1.1.1.1
```

### Headless

```bash
dlookup -o text example.com             # Overview
dlookup -o json --lookup dig-mx example.com
cat domains.txt | dlookup -o text --lookup rdap -
dlookup -o text --dig-a domains.txt --server 1.1.1.1 --timeout 5s --concurrency 4
```

Results are printed in input order. Exit code is `0` on success, `1` if any lookup failed, `2` on usage errors. JSON output is an array of `{"target", "lookup", "output", "error", "duration_ms"}`.

### Options

| Flag | Description |
| --- | --- |
| `--<lookup> FILE` | Run that lookup on targets from FILE (only one at a time) |
| `--lookup NAME` | Select the lookup by flag name (e.g. `dig-mx`) for positional targets (default `overview`) |
| `-t`, `--qtype TYPE` | Overview/SDIG query type, e.g. `MX`, `DNSKEY`, `TYPE65` (default `A`; `PTR` for IP targets) |
| `--dnssec` | SDIG: set the DNSSEC OK (DO) bit |
| `--tcp` | SDIG: query over TCP |
| `--norecurse`, `--recurse=false` | SDIG: clear the RD bit (it is set by default) |
| `--hidettl` | SDIG: print `[ttl]` instead of TTLs |
| `-o`, `--output text\|json` | Headless mode |
| `--server HOST[:PORT]` | DNS server to query (default: system resolver) |
| `--timeout DURATION` | Per-lookup timeout (default `15s`) |
| `--concurrency N` | Headless: parallel lookups (default 8) |
| `--version` | Print version |

**Lookup flags:** `--overview`, `--sdig`, `--dig-a`, `--dig-aaaa`, `--dig-any`, `--dig-caa`, `--dig-cname`, `--dig-dmarc`, `--dig-mx`, `--dig-ns`, `--dig-ptr`, `--dig-soa`, `--dig-spf`, `--dig-txt`, `--nslookup`, `--rdap`, `--whois`, `--report`. Run `dlookup --help` for the full list.

`DIG (ANY)` is available on its own but left out of the Report, since most resolvers refuse ANY queries (RFC 8482). `Overview` and `SDIG` are left out too, because the DIG lookups already cover them.

### sdig-compatible mode

`dlookup sdig` takes the same arguments as PowerDNS's `sdig` and prints the same output, so you can use it in place of sdig in scripts:

```bash
dlookup sdig 1.1.1.1 53 example.com A recurse
dlookup sdig @9.9.9.9 53 example.com DNSKEY dnssec recurse tcp hidettl
dlookup sdig 1.1.1.1 853 example.com AAAA recurse dot
dlookup sdig https://cloudflare-dns.com/dns-query 443 example.com MX recurse
```

```
Reply to question for qname='example.com.', qtype=A
Rcode: 0 (No Error), RD: 1, QR: 1, TC: 0, AA: 0, opcode: 0
0	example.com.	300	IN	A	93.184.216.34
```

Each record line is `section<TAB>name<TAB>ttl<TAB>class<TAB>type<TAB>data`, where section is `0` for answer, `1` for authority and `2` for additional (which includes the OPT record when EDNS is used). As in sdig:

* RD is **off** unless you pass `recurse`.
* EDNS is only added for `dnssec`, `ednssubnet` or `cookie` (buffer size 2800, or `$SDIGBUFSIZE`).
* RRSIG and DNSKEY data is shortened (`[expiry] [inception] [keytag]`, `...`), and NSEC3 flags show as `[flags]` unless you pass `showflags`.
* EDNS option lines (`EDNS Subnet response: …`, `EDNS Extended Error response: …`) go to stderr.
* The exit code is `0` whenever a reply was printed (also for NXDOMAIN), and for `Fatal: …` errors. It is `1` for usage errors and unknown arguments.

Supported options, in any order: `recurse`, `dnssec`, `tcp`, `dot`, `insecure`, `hidettl`, `hidesoadetails`, `showflags`, `ednssubnet SUBNET`, `class N`, `opcode N`, `cookie -/HEX`, `subjectName NAME`, `caStore FILE`, and `fastOpen` / `tlsProvider NAME` (accepted but ignored). Not supported: `proxy`, `dumpluaraw`, `traceid`, `stdin`. dlookup renders record data the way PowerDNS does (lower-case hex digests, escaped TXT, `\# len hex` for unknown types). A few rarer types (e.g. LOC, SVCB/HTTPS, CERT, IPSECKEY) use miekg/dns's text format, which can differ slightly from sdig's.

In the TUI and in headless mode, the SDIG lookup prints the same lines. EDNS option lines are appended at the end, because there is no separate stderr. If a UDP reply is truncated, the query is retried over TCP.

### Zone diff (DNS migrations)

Check that a new DNS provider serves the same records as the current one before you switch nameservers:

```bash
dlookup zonediff example.com --new ns1.newprovider.com
dlookup zonediff example.com --new 203.0.113.53 --old ns1.oldprovider.com --names shop,vpn -o json
```

The old side defaults to the domain's current authoritative nameservers. dlookup tries a zone transfer (AXFR) first. Most servers refuse it, so it then checks the apex, common names (www, mail, autodiscover, `_dmarc`, DKIM selectors, SRV records, a wildcard probe, …), any in-zone names those records point to, and names you add with `--names` / `--names-file`.

TTLs and the SOA serial are ignored unless you pass `--ttl`. Changes that are normal when switching provider (apex NS, SOA primary NS/contact) are shown as `[expected]` and don't count as differences.

| Flag | Description |
| --- | --- |
| `--new SERVER` | New DNS server, IP or hostname (required) |
| `--old SERVER` | Old server (default: authoritative NS) |
| `--names a,b` / `--names-file FILE` | Extra names to check |
| `--types A,MX,…` | Record types (default A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, SRV) |
| `--ttl` | Also compare TTLs |
| `--no-axfr` | Don't attempt a zone transfer |
| `--all` | Also list matching records |
| `-o text\|json` | Output format |

Exit codes: `0` no differences, `1` differences found, `2` usage error, `3` a server couldn't be queried.

In the TUI, press `D` / F4, or pick **Zone Diff** in the New lookup dialog's lookup dropdown. Fill in the new server (and optionally the old server, extra names and the TTL/AXFR checkboxes) and press Enter. In the results, `a` shows or hides matching records, and `1`–`5` filter by status (`0` clears). Both are also in the **View** menu. `r` / F5 re-runs, Enter / F3 edits the options, and export/copy work as usual.

## Using the TUI

The screen is laid out like Midnight Commander:

```
  Lookup   Tab   View   Options   Help          ← menu bar (F9, or alt+L/T/V/O/H)
 Home ×  example.com ×  [+]                     ← tabs: click to switch, × closes, [+] new lookup
┌─ example.com · DIG (MX) · @1.1.1.1 ─────────┐ ← the active tab: domain · lookup · server · [watching]
│ …results…                                   ▲
└─────────────────────────────────────────────┘
 Enter change · r re-run · w watch · …          ← status / context hints
1Help 2New 3Lookup 4ZoneDiff 5Re-run 6Watch 7Server 8Close 9Menu 10Quit
```

dlookup starts on the **Home** screen, which lists the features and a shortcut table built from *your* configured keys. No input is focused, so you can start straight away: press `n` / F2 (or click **[ New lookup ]**) to open the **New lookup** dialog. Enter a domain or IP, pick the lookup from the dropdown (Overview is preselected), optionally set a DNS server, then choose **Run**. For SDIG the dialog also shows a **Query type** dropdown and **Recurse (RD)**, **DNSSEC (DO)**, **TCP** and **Hide TTL** checkboxes; they are hidden for other lookups. The tab title shows the query type, e.g. `example.com · SDIG MX`. The lookup opens in a new tab. F1 or `?` returns to Home at any time.

All other input happens in dialogs: change lookup, zone diff, watch interval (presets or custom), export filename, DNS server, and confirmations when you quit or close a tab while lookups are running or being watched. In a dialog, Tab/Shift+Tab moves between fields and Space toggles a checkbox or opens a dropdown (type to filter it). Enter runs the dialog and Esc cancels it.

### Keybindings

F-keys are fixed; the letter keys are configurable (defaults shown). On a Mac laptop the F-keys need `fn`, so every F-key action also has a letter key. The Home screen and the menus always show your configured keys.

| Key | F-key | Action |
| --- | --- | --- |
| `?` | F1 | Help & shortcuts (Home) |
| `n` | F2 | New lookup (opens a new tab) |
| `enter` | F3 | Change the lookup of this tab (zone diff: edit its options) |
| `D` | F4 | Zone diff |
| `r` | F5 | Re-run |
| `w` | F6 | Watch (asks for the interval) / stop watching |
| `s` | F7 | DNS server for this tab (empty = system default) |
| `x` | F8 | Close tab (asks if it is being watched) |
| alt+letter | F9 | Open a menu |
| `ctrl+c` | F10 | Quit (F10 asks first if lookups are running or watched; `ctrl+c` always quits at once) |
| `←` / `→` | | Previous / next tab |
| `q` / `esc` | | Cancel a running lookup / stop watching |
| `↑` `↓` `PgUp` `PgDn` `g` `G` | | Scroll results |
| `y` | | Copy result to clipboard |
| `ctrl+x` | | Export this tab's result (filename pre-filled) |
| `ctrl+e` | | Export all tabs to `./dlookup-all-<timestamp>.txt` |
| `a` | | Zone diff: show/hide matching records |
| `1`–`5`, `0` | | Zone diff: filter by status / clear |

### Mouse

The mouse is on by default. You can click menus and their items, tabs, `×` and `[+]`, the F-key bar, the Home buttons, and dialog fields, dropdowns and buttons. The wheel scrolls results, Home and dropdown lists, and switches tabs when used over the tab bar.

While the mouse is on, the terminal doesn't select text by itself. Hold **Shift** (**Option** in macOS Terminal/iTerm2) while dragging to select. You can also turn the mouse off at runtime with **Options → Mouse**, or start with it off by setting `mouse: false` in the config. Copying with `y` works either way.

## Themes

dlookup ships with themes popular in coding-agent TUIs (OpenCode, Claude Code, Crush) and editors. Switch at runtime with **Options → Theme…** (F9 → Options), or set it in `~/.config/dlookup/config.yaml`:

```yaml
theme: tokyonight
```

Available: `mc` (classic Midnight Commander, default), `ayu`, `catppuccin`, `catppuccin-latte`, `claude`, `crush`, `dracula`, `everforest`, `flexoki`, `gruvbox`, `kanagawa`, `matrix`, `monokai`, `nord`, `one-dark`, `opencode`, `rose-pine`, `solarized-dark`, `solarized-light`, `system`, `tokyonight`.

`system` uses only your terminal's 16 ANSI colours and no backgrounds, so it follows your terminal's colour scheme. A theme chosen in the dialog is saved to the config file; an unknown name prints a warning and falls back to `mc`.

## Configuration

The config lives at `~/.config/dlookup/config.yaml` on Linux and macOS (`%AppData%\dlookup\config.yaml` on Windows) and is created with defaults on first run:

```yaml
mouse: true          # mouse support (toggle at runtime in Options → Mouse)
keybindings:
  quit: ctrl+c
  new_tab: "n"
  close_tab: x
  next_tab: right
  prev_tab: left
  back: q
  confirm: enter
  watch_toggle: w
  export: ctrl+x
  export_all: ctrl+e
  copy: "y"
  server: s
  zone_diff: D
  toggle_matches: a
```

Settings missing from the file use their defaults (so older configs get `mouse: true`). Empty or duplicate bindings are reported on startup, reset to defaults and the file is updated — configs from older versions (where `close_tab` and `watch_toggle` were both `w`) are fixed automatically. See the [Bubble Tea key names](https://github.com/charmbracelet/bubbletea) for supported keys (`ctrl+a`, `alt+b`, `f1`, `space`, …).

## Development

```bash
go vet ./...
go test -race ./...
```

CI runs vet, tests, golangci-lint and cross-platform builds on every PR. Releases are built by GoReleaser when a `v*.*.*` tag is pushed.

## License

MIT — see `LICENSE`.

## Acknowledgements

* [Charm](https://charm.sh/) — Bubble Tea, Bubbles and Lip Gloss.
* [miekg/dns](https://github.com/miekg/dns) — DNS library.
* [go-yaml/yaml](https://github.com/go-yaml/yaml) — YAML parsing.
