# DNS & WHOIS Lookup TUI

A terminal-based application built with Go and Bubble Tea for performing various DNS lookups (NSLOOKUP, DIG) and WHOIS queries in an interactive, tabbed interface or via command-line automation.

![Screenshot Dlookup](https://github.com/kristiand00/dlookup/blob/main/preview.png?raw=true)

## Features

* **Interactive TUI:** Built using the Charm Bubble Tea library for a rich terminal experience.
* **Command-Line Mode:** Run a specific lookup type on a list of domains/IPs from a file automatically.
* **Tabbed Interface:** Perform multiple lookups concurrently in different tabs when running interactively.
* **Multiple Lookup Types:** Supports NSLOOKUP, WHOIS, various DIG queries (ANY, A, AAAA, MX, TXT, SOA, CNAME), and a comprehensive report combining all types.
* **Comprehensive Report:** A special lookup type that runs all other available lookups for a given domain and presents a combined report.
* **Watch Mode:** Automatically re-run a single lookup (excluding the comprehensive report) at a specified interval.
* **Configurable Keybindings:** Customize key actions via a YAML configuration file.
* **Command Availability Check:** Warns if required external tools (`nslookup`, `dig`, `whois`) are missing.
* **Scrollable Results:** View lookup outputs in a scrollable viewport.
* **Keyboard Navigation:** Easy navigation using keyboard shortcuts in interactive mode (customizable).

## Prerequisites

1.  **Go:** Version 1.18 or higher recommended. ([Installation Guide](https://go.dev/doc/install))
2.  **External Tools:** The program relies on standard command-line utilities. You need to have `nslookup`, `dig`, and `whois` installed and available in your system's PATH.
    * **Debian/Ubuntu:**
        ```bash
        sudo apt update && sudo apt install dnsutils whois
        ```
    * **Fedora/CentOS/RHEL:**
        ```bash
        sudo yum update && sudo yum install bind-utils whois
        ```
    * **macOS:** `nslookup` and `whois` are typically included. `dig` might need to be installed (e.g., via Homebrew using the `bind` package which includes `dig`: `brew install bind`). Verify all three commands are accessible in your PATH.

## Installation

### From GitHub Releases

Pre-compiled binaries for various operating systems and architectures are available on the [GitHub Releases page](https://github.com/kristiand00/dlookup/releases).

1. Go to the [Releases page](https://github.com/kristiand00/dlookup/releases).
2. Download the appropriate binary for your system (e.g., `dlookup-linux-amd64`, `dlookup-windows-amd64.exe`).
3. (Optional but recommended) Rename the downloaded file to `dlookup` (or `dlookup.exe` on Windows) for easier use.
4. Make the binary executable (on Linux/macOS): `chmod +x dlookup`
5. You can now run the application, e.g., `./dlookup` or add it to your system's PATH.

### From Source

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/kristiand00/dlookup.git
    cd dlookup
    ```

2.  **Get Dependencies (if building from source):**
    ```bash
    go mod tidy
    ```

3.  **Build the binary (if building from source):**
    ```bash
    go build -o dlookup .
    ```
    This will create an executable file named `dlookup` in the current directory.

## Configuration

The application uses a configuration file located at `~/.config/dlookup/config.yaml` . The first time you run `dlookup`, if this file doesn't exist, it will be created with default settings.

You can edit this file to customize keybindings. The default configuration looks like this:

```yaml
keybindings:
  quit: c
  new_tab: n
  close_tab: w
  next_tab: right
  prev_tab: left
  back: q
  confirm: enter
  watch_toggle: w
```

Refer to the Bubble Tea documentation for supported key combinations (e.g., `ctrl+a`, `alt+b`, `f1`, `space`, etc.).

## Usage

You can run the application in two main ways:

**1. Command-Line Mode (Auto-Run Lookups)**

   Use flags to specify a lookup type and a file containing domains or IP addresses (one per line). The application will start, open a tab for each entry in the file, and automatically run the specified lookup.

   **Format:**
   ```bash
   ./dlookup --<lookup-type> <filename>
   ```

   **Available `<lookup-type>` flags:**
   * `--nslookup`
   * `--dig-any`
   * `--dig-a`
   * `--dig-aaaa`
   * `--dig-mx`
   * `--dig-txt`
   * `--dig-soa`
   * `--dig-cname`
   * `--whois`
   * `--report`

   **Examples:**
   ```bash
   # Run NSLOOKUP on all domains in domains.txt
   ./dlookup --nslookup domains.txt

   # Run DIG (A) lookup on hosts listed in targets.txt
   ./dlookup --dig-a targets.txt

   # Run WHOIS lookup on IPs in ip-list.txt
   ./dlookup --whois ip-list.txt

   # Run the comprehensive report on domains in list.txt
   ./dlookup --report list.txt
   ```
   **Note:** Only one lookup type flag (e.g., `--nslookup`, `--dig-a`) can be used at a time.

**2. Interactive Mode**

   Run the application without any arguments to start the interactive TUI.

   ```bash
   ./dlookup
   ```

**3. Using `go run` (for quick testing)**
   You can also run directly without building:
   ```bash
   # Interactive mode
   go run main.go config.go

   # Command-line mode
   go run main.go config.go --nslookup domains.txt
   ```

## Keybindings (Interactive Mode)

The keybindings listed below are the *defaults*. They can be changed by editing the configuration file (`~/.config/dlookup/config.yaml`). The help bar at the bottom of the TUI will always reflect the *currently configured* keybindings.

* **General:**
    * `C`: Quit (Default: `c`)
    * `N`: New Tab (Default: `n`)
    * `W`: Close Tab (Default: `w`)
    * `Right`: Next Tab (Default: `right`)
    * `Left`: Previous Tab (Default: `left`)
* **Input Domain/IP:**
    * Type the domain name or IP address.
    * `Enter`: Confirm Input (Default: `enter`)
* **Select Lookup Type:**
    * `↑` / `↓`: Navigate the list.
    * `Enter`: Confirm Selection (Default: `enter`)
    * `Q`: Back (Default: `q`)
* **View Results / Error:**
    * `↑` / `↓` / `PageUp` / `PageDown` / `j` / `k`: Scroll through the output.
    * `W`: Watch Mode Toggle (Default: `w`) - *Not available for Report*
    * `Q`: Back (Default: `q`) - Stops watch mode if active.
* **Watch Interval Input:**
    * Type the interval in seconds.
    * `Enter`: Confirm Interval (Default: `enter`)
    * `Q`: Cancel Watch (Default: `q`)

## License

This project is licensed under the MIT License - see the `LICENSE` file for details.

## Acknowledgements

* [Charm](https://charm.sh/) - For the excellent Bubble Tea and Lipgloss libraries that make building TUIs in Go enjoyable.
* [go-yaml/yaml](https://github.com/go-yaml/yaml) - For the YAML parsing library.
