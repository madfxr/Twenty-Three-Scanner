# 🎯 Twenty-Three Scanner v1.0

**CVE-2026-24061 - GNU InetUtils Telnetd Remote Authentication Bypass**

A **Powerful**, **Fast**, and **Elegant** scanner for detecting vulnerable **[Telnetd](https://www.gnu.org/software/inetutils/manual/inetutils.html#telnetd-invocation)** services affected by **[CVE-2026-24061](https://nvd.nist.gov/vuln/detail/CVE-2026-24061)**. Built with pure **[Python](https://www.python.org)** standard library - zero external dependencies required.

[![Python](https://img.shields.io/badge/python-3.7+-blue?logo=python&logoColor=white)](https://www.python.org)
[![Linux](https://img.shields.io/badge/platform-linux-lightgrey?logo=linux&logoColor=white)](https://www.linux.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](https://github.com/madfxr/Twenty-Three-Scanner/tree/main?tab=MIT-1-ov-file)
[![OpenSource](https://img.shields.io/badge/OpenSource-yes-brightgreen)](https://opensource.org)
[![ReadTeam](https://img.shields.io/badge/RedTeam-Security-red?logo=shield)]()
[![Ethical Hacking](https://img.shields.io/badge/Ethical%20Hacking-Tools-purple?logo=hackthebox&logoColor=white)]()


---

## 🔗 Table of Contents

- 🧩 **[Features](#-features)**
- ☢️ **[Vulnerability Details](https://github.com/madfxr/Twenty-Three-Scanner/tree/main?tab=readme-ov-file#%EF%B8%8F-vulnerability-details)**
  - 🏷️ **[Affected Versions](https://github.com/madfxr/Twenty-Three-Scanner/tree/main?tab=readme-ov-file#%EF%B8%8F-affected-versions)**
  - ⚔️ **[Attack Vector](https://github.com/madfxr/Twenty-Three-Scanner/tree/main?tab=readme-ov-file#%EF%B8%8F-attack-vector)**
  - 🚨 **[CVSS Score](https://github.com/madfxr/Twenty-Three-Scanner/tree/main?tab=readme-ov-file#-cvss-score)**
- 🛠️ **[Installation](https://github.com/madfxr/Twenty-Three-Scanner/tree/main?tab=readme-ov-file#%EF%B8%8F-installation)**
- 📜 **[Usage](#-usage)**
- 🔬 **[Examples](#-examples)**
- ⚗️ **[Demos](https://github.com/madfxr/Twenty-Three-Scanner/tree/main?tab=readme-ov-file#%EF%B8%8F-demos)**
- ⚖️ **[License](https://github.com/madfxr/Twenty-Three-Scanner/tree/main?tab=MIT-1-ov-file)**
- 📖 **[References](#-references)**

---

## 🧩 Features

- 🚀 **High-Performance Scanning** - Multi-Threaded Architecture with Configurable Thread Count.
- 🌐 **Flexible Target Input** - Support for Single IPs, CIDR Ranges, ASN Lookups, and File-Based Lists.
- 📊 **Real-Time Progress** - Beautiful Unicode-Based UI with Live Progress Bars.
- 🤖 **ASN Intelligence** - Automatic Prefix Fetching from **[RADB](https://www.radb.net)**, **[BGPView](https://bgpview.docs.apiary.io)**, and **[HackerTarget](https://hackertarget.com)** APIs.
- 💾 **Graceful Interruption** - CTRL+C Handling with Automatic Result Saving.
- 📝 **Detailed Logging** - Configurable Verbosity Levels for Debugging.
- 🔐 **Safe Scanning** - Built-In Limits to Prevent Accidental Massive Scans.
- 🎨 **Clean Output** - Professional Bordered Tables with Scan Summaries.
- 📦 **Zero Dependencies** - Pure **[Python](https://www.python.org)** 3.7+ Standard Library Only.

---

## ☢️ Vulnerability Details

**[CVE-2026-24061](https://nvd.nist.gov/vuln/detail/CVE-2026-24061)** is a critical authentication bypass vulnerability in **[GNU InetUtils](https://www.gnu.org/software/inetutils)** **[Telnetd](https://www.gnu.org/software/inetutils/manual/inetutils.html#telnetd-invocation)** that allows unauthenticated remote attackers to gain root access by exploiting the **NEW-ENVIRON** option handling.

<p align="center">
  <img
    src="https://github.com/user-attachments/assets/d6b009b7-67d3-41b6-ace6-7fd5b29bd4a0"
    alt="image"
    style="max-width: 891px; width: 100%;"
  />
</p>

<p align="center">
  <img
    src="https://github.com/user-attachments/assets/2710b1b6-74cf-4f6a-87d3-981d7f1eaa6e"
    alt="image"
    style="max-width: 891px; width: 100%;"
  />
</p>

---

### 🏷️ Affected Versions
- **[GNU InetUtils](https://www.gnu.org/software/inetutils)** since version 1.9.3 up to and including version 2.7.
- Various embedded **[Linux](https://www.linux.org)** distributions.
- IoT devices with vulnerable **[Telnetd](https://www.gnu.org/software/inetutils/manual/inetutils.html#telnetd-invocation)** implementations.

---

### ⚔️ Attack Vector
The vulnerability exploits improper validation of the `USER` environment variable in the telnet **NEW-ENVIRON ([RFC 1572](https://www.rfc-editor.org/rfc/rfc1572.html))** option negotiation, allowing attackers to inject malicious values like `-f root` to bypass authentication.

---

### 🚨 CVSS Score
**9.8 (Critical)** - **[CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H](https://www.first.org/cvss/calculator/3-1#CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)**.

---

## 🛠️ Installation

```bash
# Clone the Repository
cd /opt
sudo git clone https://github.com/madfxr/Twenty-Three-Scanner.git
cd Twenty-Three-Scanner

# Make Executable
sudo chmod +x twenty-three-scanner.py

# Run the Script
sudo python3 twenty-three-scanner.py -h
```

---

## 📜 Usage

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

---

## 🔬 Examples

```bash
  # Scan Specific ASN with Multiple Ports
  sudo python3 twenty-three-scanner.py -a AS10111 -p 23,2323 --threads 100
  sudo python3 twenty-three-scanner.py -a 10111 -p 23,2323 --threads 100

  # Scan CIDR Range
  sudo python3 twenty-three-scanner.py -t 192.168.23.0/24 -p 23 -o results.txt

  # Scan Multiple IPs with Multiple Ports
  sudo python3 twenty-three-scanner.py -t 10.0.0.1,10.0.0.2,10.0.0.3 -p 23,2323

  # Scan Single IP, IPs, and CIDR Range from File
  sudo python3 twenty-three-scanner.py -f targets.txt -p 23 --threads 50 -o output.txt

  # Scan Specific ASN with Custom Limits
  sudo python3 twenty-three-scanner.py -a AS10111 --max-hosts-per-cidr 2048 --threads 200
```

---

## ⚗️ Demos

<p align="center">
  <img
    src="https://github.com/user-attachments/assets/b3a09dfd-58b9-4b32-ba42-80c5d6668c93"
    alt="image"
    style="max-width: 891px; width: 100%;"
  />
</p>

<p align="center">
  <img
    src="https://github.com/user-attachments/assets/7812a297-f662-49f7-b6fd-307c156073bd"
    alt="image"
    style="max-width: 891px; width: 100%;"
  />
</p>

---

## 📖 References
- **[NVD - CVE-2026-24061](https://nvd.nist.gov/vuln/detail/CVE-2026-24061)**
- **[CVE Record: CVE-2026-24061](https://www.cve.org/CVERecord?id=CVE-2026-24061)**
- **[Inetutils - GNU network utilities](https://www.gnu.org/software/inetutils)**
- **[[SECURITY] [DLA 4453-1] inetutils security update](https://lists.debian.org/debian-lts-announce/2026/01/msg00025.html)**
- **[GNU InetUtils Security Advisory: remote authentication by-pass in telnet](https://lists.gnu.org/archive/html/bug-inetutils/2026-01/msg00004.html)**
- **[GNU InetUtils Security Advisory: remote authentication by-pass in telnetd](https://www.openwall.com/lists/oss-security/2026/01/20/2)**
- **[GNU InetUtils Security Advisory: remote authentication by-pass in telnetd](https://www.openwall.com/lists/oss-security/2026/01/20/2#:~:text=root@...a%3A~%20USER=')**
- **[Re: GNU InetUtils Security Advisory: remote authentication by-pass in telnetd](https://www.openwall.com/lists/oss-security/2026/01/22/1)**
- **[Re: GNU InetUtils Security Advisory: remote authentication by-pass in telnetd](https://www.openwall.com/lists/oss-security/2026/01/20/8)**
- **[CVE-2026-24061 Telnet RCE Exploit - By SafeBreach Labs](https://github.com/SafeBreach-Labs/CVE-2026-24061)**
