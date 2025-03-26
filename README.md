# DNS & WHOIS Lookup TUI

A terminal-based application built with Go and Bubble Tea for performing various DNS lookups (NSLOOKUP, DIG) and WHOIS queries in an interactive, tabbed interface.

![Screenshot Placeholder](https://via.placeholder.com/800x400.png/282a36/e0e0e0?text=Add+Screenshot+Here)
*(Suggestion: Replace the placeholder above with an actual screenshot or GIF of the application)*

## Features

* **Interactive TUI:** Built using the Charm Bubble Tea library.
* **Tabbed Interface:** Perform multiple lookups concurrently in different tabs.
* **Multiple Lookup Types:** Supports NSLOOKUP, WHOIS, and various DIG queries (ANY, A, AAAA, MX, TXT, SOA, CNAME).
* **Command Availability Check:** Warns if required external tools (`nslookup`, `dig`, `whois`) are missing.
* **Scrollable Results:** View lookup outputs in a scrollable viewport.
* **Keyboard Navigation:** Easy navigation using keyboard shortcuts.

## Prerequisites

1. **Go:** Version 1.18 or higher recommended. ([Installation Guide](https://go.dev/doc/install))
2. **External Tools:** The program relies on standard command-line utilities. You need to have `nslookup`, `dig`, and `whois` installed and available in your system's PATH.
    * **Debian/Ubuntu:**
  
        ```bash
        sudo apt update && sudo apt install dnsutils whois
  
        ```
  
    * **Fedora/CentOS/RHEL:**
  
        ```bash
        sudo yum update && sudo yum install bind-utils whois
        ```
  
    * **macOS:** These tools are typically included by default or can be installed via Homebrew (`brew install bind`).

## Installation

1. **Clone the repository:**

    ```bash
    git clone <repository-url> # Replace <repository-url> with the actual URL
    cd <repository-directory>   # Replace <repository-directory> with the folder name
    ```

2. **Build the binary:**
  
    ```bash
    go build -o dns-lookup-tui .
    ```
  
    This will create an executable file named `dns-lookup-tui` in the current directory.

## Usage

1. **Run the application:**

    ```bash
    ./dns-lookup-tui
    ```

    Alternatively, for quick testing without building, you can use:

    ```bash
    go run main.go
    ```

2. **Keybindings:**
    * **General:**
        * `Ctrl+C`: Quit the application.
        * `Ctrl+N`: Open a new tab.
        * `Ctrl+W`: Close the current tab.
        * `Ctrl+L` / `Ctrl+Right`: Switch to the next tab.
        * `Ctrl+H` / `Ctrl+Left`: Switch to the previous tab.
        * `←` / `→`: Switch tabs (only when *not* focused on the text input).
    * **Input Domain/IP:**
        * Type the domain name or IP address.
        * `Enter`: Proceed to lookup type selection.
    * **Select Lookup Type:**
        * `↑` / `↓`: Navigate the list of lookup types.
        * `Enter`: Select the highlighted type and run the lookup.
        * `Esc`: Go back to the domain/IP input screen.
    * **View Results / Error:**
        * `↑` / `↓` / `PageUp` / `PageDown`: Scroll through the output.
        * `Esc` / `q`: Go back to the domain/IP input screen for the current tab.

## License

This project is licensed under the MIT License - see the `LICENSE` file for details.

## Acknowledgements

* [Charm](https://charm.sh/) - For the excellent Bubble Tea and Lipgloss libraries that make building TUIs in Go enjoyable.
