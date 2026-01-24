# 🎯 Twenty-Three Scanner

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
- [Advanced Usage](#-advanced-usage)
- [Output Format](#-output-format)
- [Performance Tips](#-performance-tips)
- [Legal Disclaimer](#-legal-disclaimer)
- [Contributing](#-contributing)
- [License](#-license)

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
- GNU Inetutils telnetd <= 2.x
- Various embedded Linux distributions
- IoT devices with vulnerable telnetd implementations

### Attack Vector
The vulnerability exploits improper validation of the `USER` environment variable in the telnet NEW-ENVIRON (RFC 1572) option negotiation, allowing attackers to inject malicious values like `-f root` to bypass authentication.

### CVSS Score
**9.8 (Critical)** - CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

---

## 📦 Installation

### Quick Install

```bash
# Clone the repository
git clone https://github.com/madfxr/Twenty-Three-Scanner.git
cd twenty-three-scanner

# Make executable
chmod +x twenty-three-scanner.py
# Run
python3 twenty-three-scanner.py -h
