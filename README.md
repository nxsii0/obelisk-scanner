# OBELISK SCANNER
**Fast hybrid vulnerability scanner (early Release)**

![OBELISK SCANNER Logo](https://files.manuscdn.com/user_upload_by_module/session_file/310519663454022070/AEWtLBwPNsFjEDNV.png)

---

## Overview
Obelisk Scanner is a high-performance security tool built for rapid vulnerability mapping and deep dependency auditing. Designed with a focus on speed and clarity, it delivers high-contrast terminal output and professional reports to help you identify and remediate security risks instantly.

---

## Core Capabilities

### Comprehensive Dependency Auditing
Scan `requirements.txt` files, local project directories, or specific PyPI packages. Obelisk cross-references multiple intelligence sources—including **NVD**, **OSV**, and **Shodan**—to ensure no vulnerability goes unnoticed.

### Real-Time Live Fingerprinting
Identify technologies and active CVEs on live targets via URLs or IP addresses. The scanner uses protocol-aware fingerprinting for HTTP and common ports to provide immediate threat detection.

### Professional Report Generation
Export findings into structured, actionable documents. Supported formats:
- PDF
- HTML
- JSON
- CSV  

Perfect for sharing results or integrating into compliance workflows.

### Brutalist Command-Line Interface
A terminal-first experience optimized for clarity and speed. Obelisk uses high-contrast, severity-based color coding to ensure critical threats stand out instantly.

---

## Installation

### Standard Setup
```bash
git clone https://github.com/nxsii0/obeliskscanner
cd obeliskscanner
python setup.py
```

**Requirement:** Python 3.8+

### Optional Enhancements
```bash
# PDF reporting support
pip install weasyprint

# Shodan integration
pip install shodan
```

---

## Quick Start

### Audit a Python project's dependencies
```bash
obeliskscan scan -f requirements.txt
```

### Recursively scan a local directory
```bash
obeliskscan scan -d ./myproject
```

### Check a specific package version
```bash
obeliskscan scan --package requests==2.27.0
```

### Fingerprint a live target
```bash
obeliskscan scan --target https://example.com --target-ports 80,443,22
```

---

## Command Reference

### Global Scan Options

| Option | Description |
|------|-------------|
| `-f, --file` | Path to a requirements.txt file |
| `-d, --dir` | Path to a project directory for recursive scanning |
| `--package` | Audit a specific package (e.g., `flask==2.0.1`) |
| `--target` | Scan a live URL or IP address |
| `--target-ports` | Ports for live target scanning (comma-separated) |

---

### Filtering & Output

| Option | Description |
|------|-------------|
| `--severity` | Filter results (CRITICAL, HIGH, MEDIUM, LOW, ALL) |
| `--format` | Export format (html, pdf, json, csv) |
| `--output-dir` | Directory for reports |
| `--ignore` | Ignore specific CVE IDs |
| `--limit` | Limit results to N vulnerabilities |

---

### System & Automation

| Option | Description |
|------|-------------|
| `--ci` | Enable CI/CD mode |
| `--timeout` | Set scan timeout |
| `--verbose` | Enable detailed logging |
| `--no-color` | Disable colored output |
| `--no-export` | Skip report generation |

---

## Advanced Workflows

### CI/CD Integration
Automate security checks in your pipeline:

```bash
obeliskscan scan -f requirements.txt --ci --severity CRITICAL
```

This will fail builds if critical vulnerabilities are detected.

---

### Multi-Format Reporting
Generate multiple report formats in one run:

```bash
obeliskscan scan -f requirements.txt --format html,pdf,json --output-dir ./security_audits
```

---

## Supported Data Sources

Obelisk Scanner integrates with:

- **NVD (National Vulnerability Database)** — Comprehensive CVE data  
- **OSV (Open Source Vulnerabilities)** — Project-specific risks  
- **Shodan** — Internet-wide device and service intelligence  
- **PyPI** — Package metadata and version tracking  

---

## Security Best Practices

1. **Shift Left** — Scan early in development  
2. **Prioritize** — Focus on **CRITICAL** and **HIGH** issues first  
3. **Automate** — Use `--ci` to block vulnerable builds  
4. **Update** — Keep dependencies current  

---

## License

Distributed under the **MIT License**.

---

## Disclaimer

Obelisk Scanner is intended for professional security auditing and authorized testing only.

Unauthorized scanning of third-party infrastructure is illegal.  
Users are responsible for ensuring they have proper permission before initiating scans.

---

© 2026 OBELISK SCANNER — Industrial-Grade Vulnerability Intelligence
