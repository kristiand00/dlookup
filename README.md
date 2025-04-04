# DNS & WHOIS Lookup TUI

A terminal-based application built with Go and Bubble Tea for performing various DNS lookups (NSLOOKUP, DIG) and WHOIS queries in an interactive, tabbed interface or via command-line automation.

![Screenshot Placeholder](https://github.com/kristiand00/dlookup/blob/main/preview.png?raw=true)

## Features

* **Interactive TUI:** Built using the Charm Bubble Tea library for a rich terminal experience.
* **Command-Line Mode:** Run a specific lookup type on a list of domains/IPs from a file automatically (e.g., `./dlookup --dig-a domains.txt`).
* **Tabbed Interface:** Perform multiple lookups concurrently in different tabs when running interactively.
* **Multiple Lookup Types:** Supports NSLOOKUP, WHOIS, and various DIG queries (ANY, A, AAAA, MX, TXT, SOA, CNAME).
* **Command Availability Check:** Warns if required external tools (`nslookup`, `dig`, `whois`) are missing.
* **Scrollable Results:** View lookup outputs in a scrollable viewport.
* **Keyboard Navigation:** Easy navigation using keyboard shortcuts in interactive mode.

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

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/kristiand00/dlookup.git](https://github.com/kristiand00/dlookup.git)
    cd dlookup
    ```

2.  **Build the binary:**
    ```bash
    go build -o dlookup .
    ```
    This will create an executable file named `dlookup` in the current directory. (The `go build` command works the same way on macOS and Linux).

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

   **Examples:**
   ```bash
   # Run NSLOOKUP on all domains in domains.txt
   ./dlookup --nslookup domains.txt

   # Run DIG (A) lookup on hosts listed in targets.txt
   ./dlookup --dig-a targets.txt

   # Run WHOIS lookup on IPs in ip-list.txt
   ./dlookup --whois ip-list.txt
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
   go run main.go

   # Command-line mode
   go run main.go --nslookup domains.txt
   ```

## Keybindings (Interactive Mode)

* **General:**
    * `Ctrl+C`: Quit the application.
    * `Ctrl+N`: Open a new tab.
    * `Ctrl+W`: Close the current tab.
    * `Ctrl+L` / `Ctrl+Right`: Switch to the next tab.
    * `Ctrl+H` / `Ctrl+Left`: Switch to the previous tab.
* **Input Domain/IP:**
    * Type the domain name or IP address.
    * `Enter`: Proceed to lookup type selection.
* **Select Lookup Type:**
    * `↑` / `↓`: Navigate the list of lookup types.
    * `Enter`: Select the highlighted type and run the lookup.
    * `Esc`: Go back to the domain/IP input screen.
* **View Results / Error:**
    * `↑` / `↓` / `PageUp` / `PageDown` / `j` / `k`: Scroll through the output.
    * `Esc` / `q`: Go back to the domain/IP input screen for the current tab (keeps the domain).

## License

This project is licensed under the MIT License - see the `LICENSE` file for details.

## Acknowledgements

* [Charm](https://charm.sh/) - For the excellent Bubble Tea and Lipgloss libraries that make building TUIs in Go enjoyable.
