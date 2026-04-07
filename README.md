```markdown
![OBELISK SCANNER Logo](https://files.manuscdn.com/user_upload_by_module/session_file/310519663454022070/AEWtLBwPNsFjEDNV.png)

# OBELISK SCANNER
**Industrial-Grade Vulnerability Intelligence**

Obelisk Scanner is a high-performance security tool built for rapid vulnerability mapping and deep dependency auditing. Designed with a focus on speed and clarity, it delivers high-contrast terminal output and professional reports to help you identify and remediate security risks instantly.

---

## Core Capabilities

### Comprehensive Dependency Auditing
Scan `requirements.txt` files, local project directories, or specific PyPI packages. Obelisk cross-references multiple intelligence sources—including NVD, OSV, and Shodan—to ensure no vulnerability goes unnoticed.

### Real-Time Live Fingerprinting
Identify technologies and active CVEs on live targets via URLs or IP addresses. The scanner uses protocol-aware fingerprinting for HTTP and common ports to provide immediate threat detection.

### Professional Report Generation
Export findings into structured, actionable documents. Support is included for PDF, HTML, JSON, and CSV formats, making it easy to share results with stakeholders or integrate them into compliance workflows.

### Brutalist Command-Line Interface
A terminal-first experience optimized for clarity and speed. Obelisk uses high-contrast, severity-based color coding to ensure critical threats stand out the moment they are detected.

---

## Installation

### Standard Setup
```bash
git clone [https://github.com/nxsii0/obeliskscanner](https://github.com/nxsii0/obeliskscanner)
cd obeliskscanner
python setup.py
```
*Requirement: Python 3.8+*

### Optional Enhancements
* **For PDF reporting:** `pip install weasyprint`
* **For Shodan integration:** `pip install shodan`

---

## Quick Start Guide

**Audit a Python project's dependencies:**
```bash
obeliskscan scan -f requirements.txt
```

**Recursively scan a local directory:**
```bash
obeliskscan scan -d ./myproject
```

**Check a specific package version:**
```bash
obeliskscan scan --package requests==2.27.0
```

**Fingerprint a live target:**
```bash
obeliskscan scan --target [https://example.com](https://example.com) --target-ports 80,443,22
```

---

## Command Reference

### Global Scan Options
| Option | Description |
| :--- | :--- |
| `-f, --file` | Path to a requirements.txt file. |
| `-d, --dir` | Path to a project directory for recursive scanning. |
| `--package` | Audit a specific package (e.g., `flask==2.0.1`). |
| `--target` | Scan a live URL or IP address for vulnerabilities. |
| `--target-ports` | Specify ports for live target scanning (comma-separated). |

### Filtering & Output
| Option | Description |
| :--- | :--- |
| `--severity` | Filter results (CRITICAL, HIGH, MEDIUM, LOW, ALL). |
| `--format` | Choose export formats (html, pdf, json, csv). |
| `--output-dir` | Define where to save generated reports. |
| `--ignore` | Ignore specific CVE IDs (comma-separated). |
| `--limit` | Limit results to N vulnerabilities. |

### System & Automation
| Option | Description |
| :--- | :--- |
| `--ci` | Enables CI/CD mode for automated pipeline integration. |
| `--timeout` | Set timeout for scanning operations. |
| `--verbose` | Enable detailed logging. |
| `--no-color` | Disable colored output. |
| `--no-export` | Skip report generation. |

---

## Advanced Workflows

### CI/CD Integration
Automate your security posture by integrating Obelisk into your build process. Use the `--ci` flag to fail builds based on a specific severity threshold:
```bash
obeliskscan scan -f requirements.txt --ci --severity CRITICAL
```

### Multi-Format Reporting
Generate a full suite of reports for documentation and audit trails:
```bash
obeliskscan scan -f requirements.txt --format html,pdf,json --output-dir ./security_audits
```

---

## Supported Data Sources
Obelisk Scanner integrates with industry-standard databases to provide accurate intelligence:
* **NVD:** National Vulnerability Database for comprehensive CVE data.
* **OSV:** Open Source Vulnerabilities database for project-specific risks.
* **Shodan:** For internet-wide device and protocol fingerprinting.
* **PyPI:** For Python package metadata and version tracking.

---

## Security Best Practices
1. **Shift Left:** Integrate scans early in your development lifecycle.
2. **Prioritize:** Focus on **CRITICAL** and **HIGH** severity findings first.
3. **Automate:** Use the `--ci` mode to prevent vulnerable code from reaching production.
4. **Update:** Regularly update your local dependencies to stay ahead of known exploits.

---

## License & Disclaimer
Distributed under the **MIT License**. 

**Disclaimer:** Obelisk Scanner is intended for professional security auditing and authorized testing only. Unauthorized scanning of third-party infrastructure is illegal. Users are responsible for ensuring they have permission before initiating any scan.

© 2026 OBELISK SCANNER — Industrial-Grade Vulnerability Intelligence
```
