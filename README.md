# ArqSOC

Full-featured SOC analysis terminal toolkit. Pure Python, no AI -- built for
security analysts, incident responders, and malware reverse engineers.

## Features

| Category | Capabilities |
|---|---|
| **Static Analysis** | Hash calculation, entropy analysis, string extraction/classification, PE import/export parsing, disassembly (x86/x64 via Capstone), YARA signature scanning |
| **Binary RE** | Packer detection, Rich header parsing, TLS callback extraction, overlay detection, IAT reconstruction, Authenticode signature check |
| **IOC Extraction** | IP addresses, domains, URLs, hashes, email addresses, registry paths, mutex names |
| **Log Parsing** | Syslog, auth.log, Windows EVTX XML, Suricata eve.json, Zeek TSV, JSON lines, plain text -- auto-detected |
| **Threat Intel** | VirusTotal, AbuseIPDB, Shodan lookup (API keys in config, never logged) |
| **Alert Correlation** | Cross-reference IOCs with log events, severity escalation, time-window correlation |
| **Timeline Analysis** | Build timelines from events and IOCs, detect gaps |
| **MITRE ATT&CK** | Map PE imports and strings to ATT&CK techniques, generate reports |
| **Triage** | Risk-score files based on indicators (entropy, YARA hits, unsigned, overlay, TLS callbacks) |
| **Encoding Utils** | ROT13, Caesar, XOR, hex, base64 encode/decode, multi-encoding detection |
| **SIEM Output** | CEF (Common Event Format) for Splunk, ArcSight, Elastic |
| **HTML Reports** | Dark-themed Jinja2 scan and incident reports (fallback to basic HTML) |
| **Plugins** | Extensible plugin system, auto-discover from `~/.arqsoc/plugins/` |

## Installation

```bash
pip install arqsoc
```

Or from source:

```bash
git clone https://github.com/ghostisanonymous007-sketch/arqsoc.git
cd arqsoc
pip install -e ".[dev]"
```

Requires Python 3.12+.

## Quick Start

```bash
# Full malware scan
arqsoc scan suspicious.exe

# Extract and classify strings
arqsoc strings suspicious.exe

# Disassemble a binary
arqsoc disasm suspicious.exe

# Hex dump with search
arqsoc hexdump suspicious.exe --search "MZ"

# Diff two binaries
arqsoc diff original.exe patched.exe

# Extract IOCs from a file
arqsoc extract-iocs suspicious.exe

# Parse security logs (auto-detects format)
arqsoc parse-logs /var/log/auth.log

# Correlate IOCs with log events
arqsoc correlate --iocs iocs.json --logs /var/log/

# Enrich IOCs with threat intel
arqsoc enrich --iocs iocs.json --vt-key YOUR_KEY

# Triage a directory by risk
arqsoc triage /mnt/samples/

# Generate incident report with MITRE mapping
arqsoc incident --binary malware.exe --title "APT29 Implant"

# Manage API keys (stored in ~/.arqsoc/config.json)
arqsoc config-cmd set vt_api_key YOUR_KEY
arqsoc config-cmd get vt_api_key
arqsoc config-cmd list

# Lookup an IOC
arqsoc lookup 8.8.8.8 --vt-key YOUR_KEY
```

All commands support `--json`, `--quiet`, and `--output <file>` flags.

## Project Structure

```
arqsoc/
  cli.py                  # Typer CLI (14 commands)
  config.py               # API key management
  core/
    analyzer.py            # Full malware scan orchestrator
    hashes.py              # MD5/SHA1/SHA256/SHA512/SSDeep
    entropy.py             # Section and block entropy
    strings.py             # String extraction and classification
    imports.py             # PE parsing via LIEF
    packer.py              # Packer detection heuristics
    signatures.py          # YARA rule loading and scanning
    disassembler.py         # Capstone disassembly
    diff.py                # Binary diffing
    ioc_extractor.py       # Regex-based IOC extraction
    log_parser.py          # Multi-format log parsing
    threat_intel.py        # Threat intel orchestration
    mitre_mapper.py        # ATT&CK technique mapping
    alert_correlator.py    # IOC-log correlation engine
    timeline.py            # Timeline builder and gap detection
    triage.py              # Risk scoring and prioritization
    formatter.py           # Rich terminal formatting
    rich_header.py         # PE Rich header parsing
    overlay.py             # Overlay data detection
    tls.py                 # TLS callback extraction
    signature.py           # Authenticode verification
    iat_reconstruct.py     # IAT reconstruction
  models/
    scan_result.py         # Pydantic scan result model
    ioc.py                 # IOC model
    log_event.py           # Log event model
    alert.py               # Alert model
    incident.py            # Incident report model
    batch.py               # Batch scan model
  formatters/
    cef.py                 # CEF output for SIEM
  reports/
    html_report.py         # HTML scan report generator
    incident_report.py     # HTML incident report generator
  templates/
    report.html.j2         # Dark-themed scan report template
    incident.html.j2       # Dark-themed incident report template
  utils/
    hexdump.py             # Hex dump utilities
    encoding.py            # Encoding/decoding utilities
    vt.py                  # VirusTotal client
    abuseipdb.py           # AbuseIPDB client
    shodan_client.py       # Shodan client
  plugins/
    loader.py              # Plugin registry and discovery
rules/
  packers.yar              # Packer detection YARA rules
  malware.yar              # Malware behavior YARA rules
  suspicious.yar           # Suspicious indicator YARA rules
tests/
  23 test files, 128 test cases
```

## Configuration

API keys are stored in `~/.arqsoc/config.json` with restricted file
permissions. Keys are never logged, printed, or included in output.

| Key | Service |
|---|---|
| `vt_api_key` | VirusTotal |
| `abuseipdb_key` | AbuseIPDB |
| `shodan_key` | Shodan |

CLI flags (`--vt-key`, `--abuseipdb-key`, `--shodan-key`) override config
values for single runs. Environment variables (`ARQSOC_VT_API_KEY`, etc.)
override both.

## YARA Rules

ArqSOC ships with 28 built-in YARA rules:

- **Packers** (10): UPX, ASPack, PECompact, Themida, VMProtect, MPRESS,
  NsPack, Enigma, PELock
- **Malware behaviors** (9): API injection combos, C2 indicators, keylogger,
  screen capture, credential harvesting, ransomware, reverse shell, dropper,
  process hollowing
- **Suspicious indicators** (9): High entropy sections, overlay data,
  anomalous sections, multiple PE headers, XOR decode loops, base64 payloads,
  anti-debug, anti-VM

Custom rules can be loaded via `--rules-dir`.

## Testing

```bash
pip install -e ".[dev]"
pytest
```

128 tests covering all modules. Tests auto-detect system binaries for
cross-platform compatibility (Kali Linux / Windows 11).

## License

MIT
