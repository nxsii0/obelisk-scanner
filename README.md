# Obelisk Scan
**Modern. Brutalist. Industrial-Grade Vulnerability Intelligence.**
<div align="center">
  <img src="https://i.imgur.com/2gxI28k.png" alt="Obelisk Scanner Logo" width="600">

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security: OSV+NVD](https://img.shields.io/badge/Security-OSV%20%2B%20NVD-red.svg)](https://nvd.nist.gov/)

**Obelisk** is a high-performance security tool engineered for rapid vulnerability mapping and deep dependency auditing. Designed with a focus on speed, tactical clarity, and developer experience, it delivers high-contrast terminal output and multi-format professional reports to identify security risks instantly.

---

## Core Capabilities

- **Deep Dependency Auditing**: Cross-references `requirements.txt`, local project directories, or PyPI packages against global intelligence (NVD, OSV, and Shodan).
- **Tactical Live Fingerprinting**: Directly probe URLs or IP addresses for active CVEs via protocol-aware fingerprinting (HTTP, common ports).
- **Brutalist Terminal UI**: Optimized for clarity. Severity-based color coding ensures critical threats stand out in industrial-style output.
- **Enterprise Reporting**: Export findings into actionable **PDF**, **HTML**, **JSON**, or **CSV** documents.

---

## Quick Start

### 1. Installation
```bash
git clone https://github.com/nxsii0/obelisk-scanner
cd obelisk-scanner
pip install -e .
```

### 2. Enter the Interface
For the best experience, simply type `obelisk` to enter the interactive guided menu:
```bash
obelisk
```
<p align="center">
  <img src="https://i.imgur.com/wMXeGuC.png" alt="OBELISK SCANNER Logo" width="800">
</p>

### 3. Advanced CLI Power
Bypass the menu for automation or quick scans:
```bash
# Scan a project file
obelisk scan -f requirements.txt

# Probe a live target
obelisk scan --target https://example.com --severity HIGH

# Check a specific package version
obelisk scan --package requests==2.27.1
```

---

## Command Reference

### Global Parameters

| Flag | Purpose | Default |
|------|---------|---------|
| `-f, --file` | Path to a requirements.txt file | - |
| `-d, --dir` | Recursive scan of a project directory | - |
| `--package` | Audit a specific PyPI package | - |
| `--target` | Scan a live URL or IP address | - |
| `--severity` | Minimum intensity (CRITICAL, HIGH, MEDIUM, LOW) | HIGH |
| `--format` | Export format (html, pdf, json, csv, all) | all |

---

## Advanced Workflows

### CI/CD Integration
Block builds if critical vulnerabilities are found:
```bash
obelisk scan -f requirements.txt --ci --severity CRITICAL
```

### Strategic Reporting
Batch export reports for compliance:
```bash
obelisk scan -d ./src --format html,pdf --output-dir ./security_audits
```

---

## Intelligence Sources

Obelisk integrates with leading vulnerability databases:
- **NVD** (National Vulnerability Database)
- **OSV** (Open Source Vulnerabilities)
- **Shodan** (Internet-wide intelligence)
- **PyPI** (Package metadata tracking)

---

## License & Disclaimer

**License**: Distributed under the MIT License. See `LICENSE` for more information.

**Disclaimer**: Obelisk is intended for authorized security testing only. Unauthorized scanning of third-party infrastructure is illegal and unethical. The authors assume no liability for misuse.

---
© 2026 OBELISK — PREPARE FOR DEPLOYMENT.
ade Vulnerability Intelligence
