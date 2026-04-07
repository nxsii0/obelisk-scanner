![OBELISK SCANNER Logo](https://files.manuscdn.com/user_upload_by_module/session_file/310519663454022070/AEWtLBwPNsFjEDNV.png)

# OBELISK SCANNER

> **The Industrial-Grade Vulnerability Intelligence Platform.**

OBELISK SCANNER is a high-performance, brutalist-style security tool designed for rapid vulnerability mapping. It combines deep dependency auditing with protocol-aware live target fingerprinting, delivering high-contrast, actionable intelligence in the terminal and professional reports.

---

## 🎯 Key Features

### 🛡️ Pillar-Grade Auditing
Scan requirements.txt, local directories, or specific packages across PyPI and beyond. Comprehensive dependency analysis with support for multiple vulnerability data sources (NVD, OSV, Shodan).

### ⚡ Live Fingerprinting
Identify technologies and CVEs in real-time from URLs or IP addresses. Protocol-aware scanning with HTTP/port fingerprinting for instant threat detection.

### 📊 Monolith Reporting
Export professional, purple-branded reports in **PDF**, **HTML**, **JSON**, and **CSV** formats. Perfect for compliance documentation and stakeholder communication.

### 💻 Brutalist CLI
A terminal interface designed for speed, clarity, and glowing aesthetics. High-contrast output with severity-based color coding for immediate threat assessment.

---

## 📦 Installation

OBELISK SCANNER is easy to install and deploy:

```bash
git clone https://github.com/nxsii0/obeliskscanner
cd obeliskscanner
py setup.py
```

**Requirements:** Python 3.8+

### Optional Dependencies
- For enhanced reporting: `pip install weasyprint`
- For advanced scanning: `pip install shodan`

---

## 🚀 Quick Start

### Scan a Requirements File
```bash
obeliskscan scan -f requirements.txt
```
Audit all dependencies in your Python project for known vulnerabilities.

### Scan a Project Directory
```bash
obeliskscan scan -d ./myproject
```
Recursively scan all Python files and dependencies in a directory.

### Scan a Specific Package
```bash
obeliskscan scan --package requests==2.27.0
```
Check individual packages with version pinning for precise vulnerability detection.

### Scan a Live Target
```bash
obeliskscan scan --target scanme.nmap.org
obeliskscan scan --target https://example.com --target-ports 80,443,22
```
Fingerprint live targets and identify CVEs through HTTP/port scanning.

---

## 🔧 Advanced Usage

### Command-Line Options

```
usage: py main.py scan [-h]
                        [-f FILE | -d DIR | --package PKG | --target URL/IP]
                        [--target-ports PORTS]
                        [--severity {CRITICAL,HIGH,MEDIUM,LOW,ALL}]
                        [--ignore CVE_IDS] [--cve CVE_ID] [--limit N]
                        [--format FMT] [--output-dir DIR] [--timeout SEC]
                        [--insecure] [--no-color] [--verbose] [--ci]
                        [--no-export]
```

### Key Options

| Option | Description |
|--------|-------------|
| `-f, --file FILE` | Scan a requirements.txt file |
| `-d, --dir DIR` | Scan a project directory |
| `--package PKG` | Scan a specific package (e.g., `requests==2.27.0`) |
| `--target URL/IP` | Scan a live target for CVEs |
| `--target-ports PORTS` | Specify ports for live target scanning (comma-separated) |
| `--severity {CRITICAL,HIGH,MEDIUM,LOW,ALL}` | Filter results by severity level |
| `--ignore CVE_IDS` | Ignore specific CVE IDs (comma-separated) |
| `--cve CVE_ID` | Search for a specific CVE |
| `--limit N` | Limit results to N vulnerabilities |
| `--format FMT` | Export formats (comma-separated: html,pdf,json,csv) |
| `--output-dir DIR` | Specify output directory for reports |
| `--timeout SEC` | Set timeout for scanning operations |
| `--insecure` | Disable TLS certificate verification (not recommended) |
| `--no-color` | Disable colored output |
| `--verbose` | Enable verbose logging |
| `--ci` | CI/CD mode for automated pipelines |
| `--no-export` | Skip report generation |

### Examples

#### Scan with Severity Filtering
```bash
obeliskscan scan -f requirements.txt --severity CRITICAL,HIGH
```
Only show CRITICAL and HIGH severity vulnerabilities.

#### Generate Multiple Report Formats
```bash
obeliskscan scan -f requirements.txt --format html,pdf,json,csv --output-dir ./reports
```
Export results in all supported formats to a specific directory.

#### CI/CD Integration
```bash
obeliskscan scan -f requirements.txt --ci --severity CRITICAL
```
Use CI mode for automated security checks in your pipeline.

#### Verbose Scanning with Custom Timeout
```bash
obeliskscan scan --target example.com --verbose --timeout 60
```
Enable detailed logging with a 60-second timeout for live target scanning.

---

## 📊 Supported Data Sources

OBELISK SCANNER integrates with multiple vulnerability databases:

- **NVD (National Vulnerability Database)** - Comprehensive CVE information
- **OSV (Open Source Vulnerabilities)** - Open-source project vulnerabilities
- **Shodan** - Internet-wide device fingerprinting and vulnerability data
- **PyPI** - Python package metadata and version information

---

## 🎨 Report Formats

### HTML Reports
Interactive, browser-viewable reports with severity indicators, CVE details, and remediation guidance.

### PDF Reports
Professional, printable reports with purple branding, suitable for compliance and stakeholder communication.

### JSON Reports
Machine-readable format for integration with security tools and automation platforms.

### CSV Reports
Spreadsheet-compatible format for data analysis and reporting in tools like Excel or Google Sheets.

---

## 🔐 Security Best Practices

1. **Always scan before deployment** - Integrate OBELISK SCANNER into your CI/CD pipeline
2. **Review CRITICAL vulnerabilities immediately** - Prioritize high-severity issues
3. **Keep dependencies updated** - Regularly update packages to patch vulnerabilities
4. **Use severity filtering** - Focus on actionable vulnerabilities for your use case
5. **Verify scan results** - Cross-reference findings with official CVE databases

---

## 🛠️ Development

### Running Tests
```bash
pytest tests/
```

### Building from Source
```bash
python setup.py build
python setup.py install
```

### Contributing
See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to contribute to OBELISK SCANNER.

---

## 📄 License & Disclaimer

Distributed under the **MIT License**. For educational and professional security auditing purposes only. Use responsibly on authorized targets.

**Disclaimer:** OBELISK SCANNER is provided as-is without warranty. Users are responsible for ensuring they have proper authorization before scanning any targets. Unauthorized security testing is illegal.

---

## 📚 Resources

- **GitHub Repository**: [nxsii0/obeliskscanner](https://github.com/nxsii0/obeliskscanner)
- **Issue Tracker**: [Report bugs and request features](https://github.com/nxsii0/obeliskscanner/issues)
- **Security Advisories**: [NVD](https://nvd.nist.gov/), [OSV](https://osv.dev/)

---

## 🤝 Support

For issues, questions, or feature requests:
1. Check existing [GitHub Issues](https://github.com/nxsii0/obeliskscanner/issues)
2. Review the [CONTRIBUTING.md](CONTRIBUTING.md) guidelines
3. Open a new issue with detailed information about your problem

---

© 2026 OBELISK SCANNER — Industrial-Grade Vulnerability Intelligence
